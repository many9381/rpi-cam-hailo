#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/EncodedRing.hpp"
#include "camera_firmware/rtsp/GstRtspDigestAuth.hpp"
#include "camera_firmware/rtsp/RtspDigestCredentials.hpp"
#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"
#include "camera_firmware/rtsp/SecureRtspServer.hpp"

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include <gio/gio.h>
#include <gst/rtsp-server/rtsp-server.h>
#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <x264.h>

namespace {

using camera_firmware::common::SecureBytes;
using camera_firmware::config::RtspClientAuthConfig;
using camera_firmware::config::SecureRtspConfig;
using camera_firmware::rtsp::ComputeRtspDigestHa1;
using camera_firmware::rtsp::ComputeRtspDigestResponse;
using camera_firmware::rtsp::NewGstCfRtspDigestAuth;
using camera_firmware::rtsp::ProvisionRtspDigestCredential;
using camera_firmware::rtsp::RtspDigestAlgorithm;
using camera_firmware::rtsp::RtspDigestProvisionRequest;
using camera_firmware::rtsp::RtspDigestVerifierDependencies;
using camera_firmware::rtsp::SecureRtspServer;

constexpr std::string_view kUsername = "operator";
constexpr std::string_view kPassword = "live-test-password";
constexpr std::string_view kRealm = "rpi-camera";
constexpr std::string_view kNonceCount = "00000001";
constexpr std::string_view kCnonce = "cf-live-test-cnonce";
constexpr std::size_t kMaximumHeaderBytes = 64U * 1024U;
constexpr std::size_t kMaximumBodyBytes = 1024U * 1024U;

struct RtspTestResponse {
  RtspTestResponse() = default;
  ~RtspTestResponse() {
    if (!body.empty()) {
      OPENSSL_cleanse(body.data(), body.size());
    }
  }

  RtspTestResponse(const RtspTestResponse&) = delete;
  RtspTestResponse& operator=(const RtspTestResponse&) = delete;

  RtspTestResponse(RtspTestResponse&& other) noexcept
      : status_code(other.status_code),
        headers(std::move(other.headers)),
        body(std::move(other.body)) {}

  RtspTestResponse& operator=(RtspTestResponse&& other) noexcept {
    if (this != &other) {
      if (!body.empty()) {
        OPENSSL_cleanse(body.data(), body.size());
      }
      status_code = other.status_code;
      headers = std::move(other.headers);
      body = std::move(other.body);
    }
    return *this;
  }

  int status_code{0};
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;
};

class UniqueFd {
 public:
  explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}
  ~UniqueFd() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;

  UniqueFd(UniqueFd&& other) noexcept : fd_(other.release()) {}
  UniqueFd& operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
      reset(other.release());
    }
    return *this;
  }

  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] int release() noexcept {
    const int fd = fd_;
    fd_ = -1;
    return fd;
  }
  void reset(int fd = -1) noexcept {
    if (fd_ >= 0) {
      close(fd_);
    }
    fd_ = fd;
  }

 private:
  int fd_{-1};
};

struct SslContextDeleter {
  void operator()(SSL_CTX* context) const noexcept { SSL_CTX_free(context); }
};

struct SslDeleter {
  void operator()(SSL* ssl) const noexcept { SSL_free(ssl); }
};

using SslContextPtr = std::unique_ptr<SSL_CTX, SslContextDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;

std::string Lower(std::string_view value) {
  std::string result(value);
  for (char& byte : result) {
    if (byte >= 'A' && byte <= 'Z') {
      byte = static_cast<char>(byte - 'A' + 'a');
    }
  }
  return result;
}

std::string Trim(std::string_view value) {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
    value.remove_prefix(1U);
  }
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
    value.remove_suffix(1U);
  }
  return std::string(value);
}

std::vector<std::string> HeaderValues(const RtspTestResponse& response,
                                      std::string_view name) {
  const std::string expected = Lower(name);
  std::vector<std::string> values;
  for (const auto& [header_name, value] : response.headers) {
    if (Lower(header_name) == expected) {
      values.push_back(value);
    }
  }
  return values;
}

std::optional<std::string> DigestParameter(std::string_view value,
                                           std::string_view name) {
  if (!value.starts_with("Digest ")) {
    return std::nullopt;
  }
  value.remove_prefix(7U);
  while (!value.empty()) {
    while (!value.empty() &&
           (value.front() == ' ' || value.front() == '\t' ||
            value.front() == ',')) {
      value.remove_prefix(1U);
    }
    const std::size_t equals = value.find('=');
    if (equals == std::string_view::npos) {
      return std::nullopt;
    }
    const std::string key = Lower(Trim(value.substr(0U, equals)));
    value.remove_prefix(equals + 1U);

    std::string parsed;
    if (!value.empty() && value.front() == '"') {
      value.remove_prefix(1U);
      const std::size_t quote = value.find('"');
      if (quote == std::string_view::npos) {
        return std::nullopt;
      }
      parsed.assign(value.substr(0U, quote));
      value.remove_prefix(quote + 1U);
    } else {
      const std::size_t comma = value.find(',');
      parsed = Trim(value.substr(0U, comma));
      value = comma == std::string_view::npos
                  ? std::string_view{}
                  : value.substr(comma);
    }
    if (key == Lower(name)) {
      return parsed;
    }
    const std::size_t comma = value.find(',');
    value = comma == std::string_view::npos
                ? std::string_view{}
                : value.substr(comma + 1U);
  }
  return std::nullopt;
}

std::string ChallengeFor(const RtspTestResponse& response,
                         std::string_view algorithm) {
  for (const auto& challenge : HeaderValues(response, "WWW-Authenticate")) {
    const auto value = DigestParameter(challenge, "algorithm");
    if (value.has_value() && Lower(*value) == Lower(algorithm)) {
      return challenge;
    }
  }
  return {};
}

void ExpectOrdinarySha256Unauthorized(const RtspTestResponse& response) {
  EXPECT_EQ(response.status_code, 401);
  const std::string challenge = ChallengeFor(response, "SHA-256");
  ASSERT_FALSE(challenge.empty());
  EXPECT_FALSE(DigestParameter(challenge, "stale").has_value());
}

std::span<const unsigned char> Bytes(std::string_view value) {
  return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}

std::string SecureText(SecureBytes* bytes) {
  std::string value(reinterpret_cast<const char*>(bytes->data()), bytes->size());
  bytes->clear();
  return value;
}

std::string BuildAuthorization(RtspDigestAlgorithm algorithm,
                               std::string_view username,
                               std::string_view password,
                               std::string_view realm,
                               std::string_view method,
                               std::string_view uri,
                               std::string_view nonce) {
  auto ha1 = ComputeRtspDigestHa1(algorithm, username, realm, Bytes(password));
  if (!ha1.ok()) {
    throw std::runtime_error("failed to calculate test HA1");
  }
  auto response = ComputeRtspDigestResponse(
      algorithm,
      {ha1.value().data(), ha1.value().size()},
      method,
      uri,
      nonce,
      kNonceCount,
      kCnonce);
  ha1.value().clear();
  if (!response.ok()) {
    throw std::runtime_error("failed to calculate test Digest response");
  }
  auto encoded = camera_firmware::rtsp::EncodeRtspDigestLowerHex(
      {response.value().data(), response.value().size()});
  response.value().clear();
  if (!encoded.ok()) {
    throw std::runtime_error("failed to encode test Digest response");
  }
  const std::string response_text = SecureText(&encoded.value());
  return "Digest username=\"" + std::string(username) + "\", realm=\"" +
         std::string(realm) + "\", nonce=\"" + std::string(nonce) +
         "\", uri=\"" + std::string(uri) + "\", response=\"" +
         response_text + "\", algorithm=" +
         std::string(camera_firmware::rtsp::RtspDigestProtocolName(algorithm)) +
         ", qop=auth, nc=" + std::string(kNonceCount) + ", cnonce=\"" +
         std::string(kCnonce) + "\"";
}

class TlsRtspTestClient {
 public:
  static std::unique_ptr<TlsRtspTestClient> Connect(int port) {
    for (int attempt = 0; attempt < 100; ++attempt) {
      UniqueFd socket_fd(socket(AF_INET, SOCK_STREAM, 0));
      if (socket_fd.get() < 0) {
        return nullptr;
      }
      const timeval timeout{5, 0};
      if (setsockopt(socket_fd.get(),
                     SOL_SOCKET,
                     SO_RCVTIMEO,
                     &timeout,
                     sizeof(timeout)) != 0 ||
          setsockopt(socket_fd.get(),
                     SOL_SOCKET,
                     SO_SNDTIMEO,
                     &timeout,
                     sizeof(timeout)) != 0) {
        return nullptr;
      }
      sockaddr_in address{};
      address.sin_family = AF_INET;
      address.sin_port = htons(static_cast<std::uint16_t>(port));
      address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      if (connect(socket_fd.get(),
                  reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) != 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        continue;
      }

      SslContextPtr context(SSL_CTX_new(TLS_client_method()));
      if (!context) {
        return nullptr;
      }
      SSL_CTX_set_verify(context.get(), SSL_VERIFY_NONE, nullptr);
      SslPtr ssl(SSL_new(context.get()));
      if (!ssl || SSL_set_fd(ssl.get(), socket_fd.get()) != 1 ||
          SSL_connect(ssl.get()) != 1) {
        return nullptr;
      }
      return std::unique_ptr<TlsRtspTestClient>(
          new TlsRtspTestClient(std::move(socket_fd),
                                std::move(context),
                                std::move(ssl)));
    }
    return nullptr;
  }

  ~TlsRtspTestClient() {
    if (ssl_) {
      (void)SSL_shutdown(ssl_.get());
    }
  }

  TlsRtspTestClient(const TlsRtspTestClient&) = delete;
  TlsRtspTestClient& operator=(const TlsRtspTestClient&) = delete;

  RtspTestResponse Request(std::string_view method,
                           std::string_view uri,
                           std::string_view authorization = {}) {
    std::string request;
    request.reserve(method.size() + uri.size() + authorization.size() + 160U);
    request.append(method);
    request.push_back(' ');
    request.append(uri);
    request.append(" RTSP/1.0\r\nCSeq: ");
    request.append(std::to_string(next_cseq_++));
    request.append("\r\n");
    if (method == "DESCRIBE") {
      request.append("Accept: application/sdp\r\n");
    }
    if (!authorization.empty()) {
      request.append("Authorization: ");
      request.append(authorization);
      request.append("\r\n");
    }
    request.append("\r\n");
    return Send(request);
  }

  RtspTestResponse Send(std::string_view request) {
    std::size_t sent = 0U;
    while (sent < request.size()) {
      const int result = SSL_write(
          ssl_.get(), request.data() + sent,
          static_cast<int>(request.size() - sent));
      if (result <= 0) {
        throw std::runtime_error("TLS RTSP request write failed");
      }
      sent += static_cast<std::size_t>(result);
    }

    const std::string separator = "\r\n\r\n";
    while (pending_.find(separator) == std::string::npos) {
      ReadMore(kMaximumHeaderBytes);
    }
    const std::size_t header_end = pending_.find(separator);
    if (header_end > kMaximumHeaderBytes) {
      throw std::runtime_error("RTSP response headers exceeded bound");
    }
    const std::string header_block = pending_.substr(0U, header_end);
    pending_.erase(0U, header_end + separator.size());

    RtspTestResponse response;
    std::size_t line_start = 0U;
    const std::size_t status_end = header_block.find("\r\n");
    const std::string status_line =
        header_block.substr(0U, status_end == std::string::npos
                                    ? header_block.size()
                                    : status_end);
    if (!status_line.starts_with("RTSP/1.0 ") || status_line.size() < 13U ||
        status_line[12U] != ' ') {
      throw std::runtime_error("RTSP response status line is invalid");
    }
    const std::string code_text = status_line.substr(9U, 3U);
    if (code_text.find_first_not_of("0123456789") != std::string::npos) {
      throw std::runtime_error("RTSP response status code is invalid");
    }
    response.status_code = std::stoi(code_text);
    line_start = status_end == std::string::npos
                     ? header_block.size()
                     : status_end + 2U;

    std::size_t content_length = 0U;
    bool has_content_length = false;
    while (line_start < header_block.size()) {
      const std::size_t line_end = header_block.find("\r\n", line_start);
      const std::string_view line(
          header_block.data() + line_start,
          (line_end == std::string::npos ? header_block.size() : line_end) -
              line_start);
      const std::size_t colon = line.find(':');
      if (colon == std::string_view::npos || colon == 0U) {
        throw std::runtime_error("RTSP response header is invalid");
      }
      std::string name(line.substr(0U, colon));
      std::string value = Trim(line.substr(colon + 1U));
      if (Lower(name) == "content-length") {
        if (has_content_length || value.empty() ||
            value.find_first_not_of("0123456789") != std::string::npos) {
          throw std::runtime_error("RTSP Content-Length is invalid");
        }
        content_length = static_cast<std::size_t>(std::stoull(value));
        if (content_length > kMaximumBodyBytes) {
          throw std::runtime_error("RTSP response body exceeded bound");
        }
        has_content_length = true;
      }
      response.headers.emplace_back(std::move(name), std::move(value));
      if (line_end == std::string::npos) {
        break;
      }
      line_start = line_end + 2U;
    }
    while (pending_.size() < content_length) {
      ReadMore(kMaximumBodyBytes + kMaximumHeaderBytes);
    }
    response.body.assign(pending_.data(), content_length);
    if (content_length > 0U) {
      OPENSSL_cleanse(pending_.data(), content_length);
    }
    pending_.erase(0U, content_length);
    return response;
  }

 private:
  TlsRtspTestClient(UniqueFd socket_fd,
                    SslContextPtr context,
                    SslPtr ssl)
      : socket_(std::move(socket_fd)),
        context_(std::move(context)),
        ssl_(std::move(ssl)) {}

  void ReadMore(std::size_t maximum_total) {
    char buffer[4096]{};
    const int received = SSL_read(ssl_.get(), buffer, sizeof(buffer));
    if (received <= 0) {
      throw std::runtime_error("TLS RTSP response read failed");
    }
    pending_.append(buffer, static_cast<std::size_t>(received));
    if (pending_.size() > maximum_total) {
      throw std::runtime_error("RTSP response exceeded bound");
    }
  }

  UniqueFd socket_;
  SslContextPtr context_;
  SslPtr ssl_;
  std::string pending_;
  unsigned int next_cseq_{1U};
};

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    char pattern[] = "/tmp/cf-rtsp-digest-live-XXXXXX";
    char* created = mkdtemp(pattern);
    if (created == nullptr) {
      throw std::runtime_error("failed to create temporary directory");
    }
    path_ = created;
  }
  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  [[nodiscard]] std::filesystem::path File(std::string_view name) const {
    return path_ / name;
  }

 private:
  std::filesystem::path path_;
};

bool WriteAll(int fd, std::span<const unsigned char> bytes) {
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    const ssize_t written =
        write(fd, bytes.data() + offset, bytes.size() - offset);
    if (written > 0) {
      offset += static_cast<std::size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

class TestTlsMaterial {
 public:
  explicit TestTlsMaterial(const std::filesystem::path& pem_path)
      : pem_path_(pem_path) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> key_context(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY* raw_key = nullptr;
    if (!key_context || EVP_PKEY_keygen_init(key_context.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(key_context.get(), 2048) != 1 ||
        EVP_PKEY_keygen(key_context.get(), &raw_key) != 1) {
      throw std::runtime_error("failed to generate test TLS key");
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key,
                                                            EVP_PKEY_free);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(),
                                                            X509_free);
    if (!certificate || X509_set_version(certificate.get(), 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) != 1 ||
        X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0) == nullptr ||
        X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600) ==
            nullptr ||
        X509_set_pubkey(certificate.get(), key.get()) != 1) {
      throw std::runtime_error("failed to initialize test TLS certificate");
    }
    X509_NAME* subject = X509_get_subject_name(certificate.get());
    static constexpr unsigned char kCommonName[] = "cf-rtsp-live-test";
    if (subject == nullptr ||
        X509_NAME_add_entry_by_txt(subject,
                                   "CN",
                                   MBSTRING_ASC,
                                   kCommonName,
                                   -1,
                                   -1,
                                   0) != 1 ||
        X509_set_issuer_name(certificate.get(), subject) != 1 ||
        X509_sign(certificate.get(), key.get(), EVP_sha256()) <= 0) {
      throw std::runtime_error("failed to sign test TLS certificate");
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()),
                                                  BIO_free);
    if (!bio || PEM_write_bio_X509(bio.get(), certificate.get()) != 1 ||
        PEM_write_bio_PrivateKey(
            bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
      throw std::runtime_error("failed to serialize test TLS certificate");
    }
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(bio.get(), &memory);
    if (memory == nullptr || memory->data == nullptr || memory->length == 0U) {
      throw std::runtime_error("test TLS PEM is empty");
    }

    SecureBytes pem;
    pem.assign(reinterpret_cast<const unsigned char*>(memory->data),
               memory->length);
    OPENSSL_cleanse(memory->data, memory->length);
    UniqueFd output(open(pem_path_.c_str(),
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                         0600));
    if (output.get() < 0 ||
        !WriteAll(output.get(), {pem.data(), pem.size()}) ||
        fsync(output.get()) != 0) {
      pem.clear();
      throw std::runtime_error("failed to write test TLS PEM");
    }
    GError* error = nullptr;
    certificate_ = g_tls_certificate_new_from_pem(
        reinterpret_cast<const gchar*>(pem.data()),
        static_cast<gssize>(pem.size()),
        &error);
    pem.clear();
    if (certificate_ == nullptr) {
      if (error != nullptr) {
        g_error_free(error);
      }
      throw std::runtime_error("failed to construct test TLS certificate");
    }
  }

  ~TestTlsMaterial() {
    if (certificate_ != nullptr) {
      g_object_unref(certificate_);
    }
  }

  TestTlsMaterial(const TestTlsMaterial&) = delete;
  TestTlsMaterial& operator=(const TestTlsMaterial&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept {
    return pem_path_;
  }
  [[nodiscard]] GTlsCertificate* certificate() const noexcept {
    return certificate_;
  }

 private:
  std::filesystem::path pem_path_;
  GTlsCertificate* certificate_{nullptr};
};

int FindFreeLoopbackPort() {
  UniqueFd fd(socket(AF_INET, SOCK_STREAM, 0));
  if (fd.get() < 0) {
    throw std::runtime_error("failed to create port probe socket: " +
                             std::string(std::strerror(errno)));
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(fd.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) !=
      0) {
    throw std::runtime_error("failed to bind port probe socket");
  }
  socklen_t length = sizeof(address);
  if (getsockname(fd.get(), reinterpret_cast<sockaddr*>(&address), &length) !=
      0) {
    throw std::runtime_error("failed to inspect port probe socket");
  }
  return ntohs(address.sin_port);
}

void WriteSessionKey(const std::filesystem::path& path) {
  UniqueFd output(
      open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
  SecureBytes encoded;
  encoded.resize(60U);
  std::memset(encoded.data(), '4', encoded.size());
  const bool written = output.get() >= 0 &&
                       WriteAll(output.get(), {encoded.data(), encoded.size()}) &&
                       fsync(output.get()) == 0;
  encoded.clear();
  if (!written) {
    throw std::runtime_error("failed to write test SRTP key");
  }
}

void ProvisionCredentials(const std::filesystem::path& path, bool allow_md5) {
  RtspDigestProvisionRequest sha{
      path, std::string(kUsername), std::string(kRealm),
      RtspDigestAlgorithm::kSha256, allow_md5};
  auto provisioned = ProvisionRtspDigestCredential(sha, Bytes(kPassword));
  if (!provisioned.ok()) {
    throw std::runtime_error("failed to provision SHA-256 test credential");
  }
  if (allow_md5) {
    RtspDigestProvisionRequest md5{
        path, std::string(kUsername), std::string(kRealm),
        RtspDigestAlgorithm::kMd5, true};
    provisioned = ProvisionRtspDigestCredential(md5, Bytes(kPassword));
    if (!provisioned.ok()) {
      throw std::runtime_error("failed to provision MD5 test credential");
    }
  }
}

std::vector<std::uint8_t> EncodeTestKeyFrame() {
  x264_param_t parameters{};
  if (x264_param_default_preset(&parameters, "ultrafast", "zerolatency") < 0) {
    throw std::runtime_error("failed to initialize test x264 parameters");
  }
  parameters.i_width = 16;
  parameters.i_height = 16;
  parameters.i_csp = X264_CSP_I420;
  parameters.i_fps_num = 30;
  parameters.i_fps_den = 1;
  parameters.i_timebase_num = 1;
  parameters.i_timebase_den = 30;
  parameters.i_threads = 1;
  parameters.i_keyint_max = 1;
  parameters.i_keyint_min = 1;
  parameters.i_bframe = 0;
  parameters.b_annexb = 1;
  parameters.b_repeat_headers = 1;
  parameters.b_vfr_input = 0;
  parameters.i_log_level = X264_LOG_NONE;
  if (x264_param_apply_profile(&parameters, "baseline") < 0) {
    x264_param_cleanup(&parameters);
    throw std::runtime_error("failed to apply test x264 profile");
  }
  x264_t* encoder = x264_encoder_open(&parameters);
  x264_param_cleanup(&parameters);
  if (encoder == nullptr) {
    throw std::runtime_error("failed to open test x264 encoder");
  }

  x264_picture_t picture{};
  if (x264_picture_alloc(&picture, X264_CSP_I420, 16, 16) != 0) {
    x264_encoder_close(encoder);
    throw std::runtime_error("failed to allocate test x264 picture");
  }
  for (int row = 0; row < 16; ++row) {
    std::memset(picture.img.plane[0] + row * picture.img.i_stride[0], 16, 16);
  }
  for (int row = 0; row < 8; ++row) {
    std::memset(picture.img.plane[1] + row * picture.img.i_stride[1], 128, 8);
    std::memset(picture.img.plane[2] + row * picture.img.i_stride[2], 128, 8);
  }
  picture.i_pts = 0;
  picture.i_type = X264_TYPE_IDR;
  x264_nal_t* nals = nullptr;
  int nal_count = 0;
  x264_picture_t output{};
  const int encoded =
      x264_encoder_encode(encoder, &nals, &nal_count, &picture, &output);
  std::vector<std::uint8_t> access_unit;
  if (encoded > 0 && nals != nullptr) {
    access_unit.reserve(static_cast<std::size_t>(encoded));
    for (int index = 0; index < nal_count; ++index) {
      access_unit.insert(access_unit.end(),
                         nals[index].p_payload,
                         nals[index].p_payload + nals[index].i_payload);
    }
  }
  x264_picture_clean(&picture);
  x264_encoder_close(encoder);
  if (access_unit.empty()) {
    throw std::runtime_error("test x264 encoder produced no access unit");
  }
  return access_unit;
}

class LiveSecureServer {
 public:
  explicit LiveSecureServer(bool allow_md5 = false)
      : tls_(directory_.File("server.pem")),
        credentials_(directory_.File("users.credentials")),
        key_(directory_.File("session-key.hex")),
        port_(0) {
    ProvisionCredentials(credentials_, allow_md5);
    WriteSessionKey(key_);
    config_.enabled = true;
    config_.control_tls = true;
    config_.media_srtp = true;
    config_.keying = "sdes-over-rtsps";
    config_.bind_ip = "127.0.0.1";
    config_.mount = "/test/auth";
    config_.tls_certificate_path = tls_.path().string();
    config_.tls_private_key_path = tls_.path().string();
    config_.session_key.path = key_.string();
    config_.client_auth.enabled = true;
    config_.client_auth.realm = std::string(kRealm);
    config_.client_auth.credential_file = credentials_.string();
    config_.client_auth.algorithms =
        allow_md5 ? std::vector<std::string>{"sha-256", "md5"}
                  : std::vector<std::string>{"sha-256"};
    config_.client_auth.nonce_ttl_seconds = 30U;
    std::string start_error = "listener attach retries exhausted";
    bool running = false;
    for (int attempt = 0; attempt < 10; ++attempt) {
      port_ = FindFreeLoopbackPort();
      config_.port = port_;
      auto started = server_.Start(config_, ring_);
      if (started.ok()) {
        running = true;
        break;
      }
      start_error = started.error().message;
      if (started.error().code != "E_RTSP_ATTACH") {
        break;
      }
    }
    if (!running) {
      throw std::runtime_error("failed to start live secure RTSP server: " +
                               start_error);
    }
    url_ = "rtsps://127.0.0.1:" + std::to_string(port_) + config_.mount;
    producer_ = std::thread([this, key_frame = EncodeTestKeyFrame()] {
      std::uint64_t sequence = 0U;
      while (!stop_producer_.load(std::memory_order_acquire)) {
        camera_firmware::media::EncodedAccessUnit access_unit;
        access_unit.sequence = sequence;
        access_unit.timestamp = std::chrono::milliseconds(sequence * 33U);
        access_unit.is_key_frame = true;
        access_unit.bytes = key_frame;
        ring_.Publish(std::move(access_unit));
        ++sequence;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    });
  }

  ~LiveSecureServer() { Stop(); }

  [[nodiscard]] int port() const noexcept { return port_; }
  [[nodiscard]] const std::string& url() const noexcept { return url_; }
  [[nodiscard]] SecureRtspServer& server() noexcept { return server_; }
  void Stop() {
    stop_producer_.store(true, std::memory_order_release);
    if (producer_.joinable()) {
      producer_.join();
    }
    server_.Stop();
  }

 private:
  TemporaryDirectory directory_;
  TestTlsMaterial tls_;
  std::filesystem::path credentials_;
  std::filesystem::path key_;
  int port_;
  SecureRtspConfig config_;
  camera_firmware::media::EncodedRing ring_{4U};
  SecureRtspServer server_;
  std::string url_;
  std::atomic<bool> stop_producer_{false};
  std::thread producer_;
};

std::string AuthorizationFromChallenge(const std::string& challenge,
                                       RtspDigestAlgorithm algorithm,
                                       std::string_view username,
                                       std::string_view password,
                                       std::string_view uri) {
  const auto nonce = DigestParameter(challenge, "nonce");
  const auto realm = DigestParameter(challenge, "realm");
  if (!nonce.has_value() || !realm.has_value()) {
    throw std::runtime_error("Digest challenge is missing nonce or realm");
  }
  return BuildAuthorization(
      algorithm, username, password, *realm, "DESCRIBE", uri, *nonce);
}

class InjectedClockTlsServer {
 public:
  InjectedClockTlsServer()
      : tls_(directory_.File("server.pem")),
        credentials_(directory_.File("users.credentials")),
        port_(0),
        now_(std::make_shared<std::atomic<std::uint64_t>>(100U)) {
    gst_init(nullptr, nullptr);
    ProvisionCredentials(credentials_, false);
    RtspClientAuthConfig config;
    config.enabled = true;
    config.realm = std::string(kRealm);
    config.credential_file = credentials_.string();
    config.algorithms = {"sha-256"};
    config.nonce_ttl_seconds = 30U;
    RtspDigestVerifierDependencies dependencies;
    dependencies.nonce.now_seconds = [clock = now_]() {
      return clock->load(std::memory_order_relaxed);
    };
    auto created = NewGstCfRtspDigestAuth(config, std::move(dependencies));
    if (!created.ok()) {
      throw std::runtime_error("failed to create injected-clock auth");
    }
    auth_ = created.value();
    gst_rtsp_auth_set_tls_certificate(auth_, tls_.certificate());
    gst_rtsp_auth_set_tls_authentication_mode(auth_,
                                              G_TLS_AUTHENTICATION_NONE);

    server_ = gst_rtsp_server_new();
    gst_rtsp_server_set_address(server_, "127.0.0.1");
    gst_rtsp_server_set_auth(server_, auth_);
    mounts_ = gst_rtsp_server_get_mount_points(server_);
    GstRTSPMediaFactory* factory = gst_rtsp_media_factory_new();
    gst_rtsp_media_factory_set_launch(
        factory,
        "( appsrc name=feedsrc is-live=true format=time do-timestamp=true "
        "! h264parse ! rtph264pay name=pay0 pt=96 )");
    GstRTSPPermissions* permissions = gst_rtsp_permissions_new();
    gst_rtsp_permissions_add_role(
        permissions,
        "viewer",
        GST_RTSP_PERM_MEDIA_FACTORY_ACCESS,
        G_TYPE_BOOLEAN,
        TRUE,
        GST_RTSP_PERM_MEDIA_FACTORY_CONSTRUCT,
        G_TYPE_BOOLEAN,
        TRUE,
        nullptr);
    gst_rtsp_media_factory_set_permissions(factory, permissions);
    gst_rtsp_permissions_unref(permissions);
    gst_rtsp_mount_points_add_factory(mounts_, "/test/stale", factory);

    context_ = g_main_context_new();
    for (int attempt = 0; attempt < 10 && source_id_ == 0U; ++attempt) {
      port_ = FindFreeLoopbackPort();
      const std::string service = std::to_string(port_);
      gst_rtsp_server_set_service(server_, service.c_str());
      source_id_ = gst_rtsp_server_attach(server_, context_);
    }
    if (source_id_ == 0U) {
      throw std::runtime_error("failed to attach injected-clock RTSP server");
    }
    loop_ = g_main_loop_new(context_, FALSE);
    thread_ = std::thread([this] {
      g_main_context_push_thread_default(context_);
      g_main_loop_run(loop_);
      g_main_context_pop_thread_default(context_);
    });
    url_ = "rtsps://127.0.0.1:" + std::to_string(port_) + "/test/stale";
  }

  ~InjectedClockTlsServer() {
    if (loop_ != nullptr) {
      g_main_loop_quit(loop_);
    }
    if (context_ != nullptr) {
      g_main_context_wakeup(context_);
    }
    if (thread_.joinable()) {
      thread_.join();
    }
    if (source_id_ != 0U && context_ != nullptr) {
      GSource* source =
          g_main_context_find_source_by_id(context_, source_id_);
      if (source != nullptr) {
        g_source_destroy(source);
      }
    }
    if (mounts_ != nullptr) {
      gst_rtsp_mount_points_remove_factory(mounts_, "/test/stale");
      g_object_unref(mounts_);
    }
    if (server_ != nullptr) {
      gst_rtsp_server_set_auth(server_, nullptr);
    }
    if (auth_ != nullptr) {
      (void)camera_firmware::rtsp::ShutdownGstCfRtspDigestAuth(auth_);
      g_object_unref(auth_);
    }
    if (server_ != nullptr) {
      g_object_unref(server_);
    }
    if (loop_ != nullptr) {
      g_main_loop_unref(loop_);
    }
    if (context_ != nullptr) {
      g_main_context_unref(context_);
    }
  }

  [[nodiscard]] int port() const noexcept { return port_; }
  [[nodiscard]] const std::string& url() const noexcept { return url_; }
  void ExpireNonce() { now_->store(131U, std::memory_order_relaxed); }

 private:
  TemporaryDirectory directory_;
  TestTlsMaterial tls_;
  std::filesystem::path credentials_;
  int port_;
  std::shared_ptr<std::atomic<std::uint64_t>> now_;
  GstRTSPServer* server_{nullptr};
  GstRTSPMountPoints* mounts_{nullptr};
  GstRTSPAuth* auth_{nullptr};
  GMainContext* context_{nullptr};
  GMainLoop* loop_{nullptr};
  guint source_id_{0U};
  std::thread thread_;
  std::string url_;
};

TEST(RtspDigestAuthIntegrationTest,
     OptionsIsPublicButDescribeChallengesSha256) {
  LiveSecureServer server;
  auto client = TlsRtspTestClient::Connect(server.port());
  ASSERT_NE(client, nullptr);

  const auto options = client->Request("OPTIONS", server.url());
  const auto describe = client->Request("DESCRIBE", server.url());

  EXPECT_EQ(options.status_code, 200);
  EXPECT_TRUE(HeaderValues(options, "WWW-Authenticate").empty());
  EXPECT_EQ(describe.status_code, 401);
  const auto challenges = HeaderValues(describe, "WWW-Authenticate");
  ASSERT_EQ(challenges.size(), 1U);
  EXPECT_TRUE(challenges.front().starts_with("Digest "));
  EXPECT_EQ(DigestParameter(challenges.front(), "algorithm"), "SHA-256");
  EXPECT_EQ(DigestParameter(challenges.front(), "realm"), kRealm);
  EXPECT_EQ(DigestParameter(challenges.front(), "qop"), "auth");
  EXPECT_EQ(DigestParameter(challenges.front(), "charset"), "UTF-8");
  const auto nonce = DigestParameter(challenges.front(), "nonce");
  EXPECT_TRUE(nonce.has_value());
  EXPECT_FALSE(nonce.value_or("").empty());
  EXPECT_FALSE(DigestParameter(challenges.front(), "stale").has_value());
}

TEST(RtspDigestAuthIntegrationTest,
     CorrectSha256DescribeReturnsSecureSdp) {
  LiveSecureServer server;
  auto client = TlsRtspTestClient::Connect(server.port());
  ASSERT_NE(client, nullptr);
  const auto challenged = client->Request("DESCRIBE", server.url());
  const std::string challenge = ChallengeFor(challenged, "SHA-256");
  ASSERT_FALSE(challenge.empty());
  const std::string authorization = AuthorizationFromChallenge(
      challenge, RtspDigestAlgorithm::kSha256, kUsername, kPassword,
      server.url());

  const auto response =
      client->Request("DESCRIBE", server.url(), authorization);

  EXPECT_EQ(response.status_code, 200);
  EXPECT_NE(response.body.find("RTP/SAVPF"), std::string::npos);
  EXPECT_NE(response.body.find("a=crypto:"), std::string::npos);
  EXPECT_EQ(response.body.find("a=key-mgmt:mikey"), std::string::npos);
}

TEST(RtspDigestAuthIntegrationTest, ReplayedAuthorizationReturns401) {
  LiveSecureServer server;
  auto client = TlsRtspTestClient::Connect(server.port());
  ASSERT_NE(client, nullptr);
  const auto challenged = client->Request("DESCRIBE", server.url());
  const std::string challenge = ChallengeFor(challenged, "SHA-256");
  ASSERT_FALSE(challenge.empty());
  const std::string authorization = AuthorizationFromChallenge(
      challenge, RtspDigestAlgorithm::kSha256, kUsername, kPassword,
      server.url());
  ASSERT_EQ(client->Request("DESCRIBE", server.url(), authorization).status_code,
            200);
  const std::size_t allocations_before =
      server.server().PerMediaKeyAllocationCount();
  const std::size_t zeroizations_before =
      server.server().PerMediaKeyZeroizeCount();

  const auto replay =
      client->Request("DESCRIBE", server.url(), authorization);

  ExpectOrdinarySha256Unauthorized(replay);
  EXPECT_EQ(server.server().PerMediaKeyAllocationCount(), allocations_before);
  EXPECT_EQ(server.server().PerMediaKeyZeroizeCount(), zeroizations_before);
}

TEST(RtspDigestAuthIntegrationTest,
     WrongAndUnknownUsersHaveEquivalentFailureShape) {
  LiveSecureServer server;
  auto wrong_client = TlsRtspTestClient::Connect(server.port());
  auto unknown_client = TlsRtspTestClient::Connect(server.port());
  ASSERT_NE(wrong_client, nullptr);
  ASSERT_NE(unknown_client, nullptr);
  const auto wrong_challenge =
      wrong_client->Request("DESCRIBE", server.url());
  const auto unknown_challenge =
      unknown_client->Request("DESCRIBE", server.url());
  const std::string wrong_authorization = AuthorizationFromChallenge(
      ChallengeFor(wrong_challenge, "SHA-256"),
      RtspDigestAlgorithm::kSha256,
      kUsername,
      "wrong-password",
      server.url());
  const std::string unknown_authorization = AuthorizationFromChallenge(
      ChallengeFor(unknown_challenge, "SHA-256"),
      RtspDigestAlgorithm::kSha256,
      "unknown",
      kPassword,
      server.url());

  const auto wrong =
      wrong_client->Request("DESCRIBE", server.url(), wrong_authorization);
  const auto unknown = unknown_client->Request(
      "DESCRIBE", server.url(), unknown_authorization);

  ExpectOrdinarySha256Unauthorized(wrong);
  ExpectOrdinarySha256Unauthorized(unknown);
  EXPECT_EQ(wrong.body, unknown.body);
  EXPECT_EQ(HeaderValues(wrong, "WWW-Authenticate").size(),
            HeaderValues(unknown, "WWW-Authenticate").size());
  EXPECT_FALSE(ChallengeFor(wrong, "SHA-256").empty());
  EXPECT_FALSE(ChallengeFor(unknown, "SHA-256").empty());
  EXPECT_EQ(server.server().PerMediaKeyAllocationCount(), 0U);
  EXPECT_EQ(server.server().PerMediaKeyZeroizeCount(), 0U);
}

TEST(RtspDigestAuthIntegrationTest, BasicAndDefaultMd5AreRejected) {
  LiveSecureServer server;
  auto basic_client = TlsRtspTestClient::Connect(server.port());
  auto md5_client = TlsRtspTestClient::Connect(server.port());
  ASSERT_NE(basic_client, nullptr);
  ASSERT_NE(md5_client, nullptr);
  const auto basic =
      basic_client->Request("DESCRIBE", server.url(), "Basic Zm9vOmJhcg==");
  const auto challenged = md5_client->Request("DESCRIBE", server.url());
  const std::string sha_challenge = ChallengeFor(challenged, "SHA-256");
  ASSERT_FALSE(sha_challenge.empty());
  const auto nonce = DigestParameter(sha_challenge, "nonce");
  ASSERT_TRUE(nonce.has_value());
  const std::string md5_authorization = BuildAuthorization(
      RtspDigestAlgorithm::kMd5,
      kUsername,
      kPassword,
      kRealm,
      "DESCRIBE",
      server.url(),
      *nonce);

  const auto md5 =
      md5_client->Request("DESCRIBE", server.url(), md5_authorization);

  ExpectOrdinarySha256Unauthorized(basic);
  ExpectOrdinarySha256Unauthorized(md5);
  EXPECT_TRUE(ChallengeFor(basic, "MD5").empty());
  EXPECT_TRUE(ChallengeFor(md5, "MD5").empty());
  EXPECT_EQ(server.server().PerMediaKeyAllocationCount(), 0U);
  EXPECT_EQ(server.server().PerMediaKeyZeroizeCount(), 0U);
}

TEST(RtspDigestAuthIntegrationTest,
     ExplicitMd5CompatibilityAuthenticates) {
  LiveSecureServer server(true);
  auto client = TlsRtspTestClient::Connect(server.port());
  ASSERT_NE(client, nullptr);
  const auto challenged = client->Request("DESCRIBE", server.url());
  const std::string challenge = ChallengeFor(challenged, "MD5");
  ASSERT_FALSE(challenge.empty());
  const std::string authorization = AuthorizationFromChallenge(
      challenge, RtspDigestAlgorithm::kMd5, kUsername, kPassword,
      server.url());

  const auto response =
      client->Request("DESCRIBE", server.url(), authorization);

  EXPECT_EQ(response.status_code, 200);
}

TEST(RtspDigestAuthIntegrationTest,
     CorrectExpiredDigestGetsStaleChallenge) {
  InjectedClockTlsServer server;
  auto client = TlsRtspTestClient::Connect(server.port());
  ASSERT_NE(client, nullptr);
  const auto challenged = client->Request("DESCRIBE", server.url());
  const std::string challenge = ChallengeFor(challenged, "SHA-256");
  ASSERT_FALSE(challenge.empty());
  const std::string authorization = AuthorizationFromChallenge(
      challenge, RtspDigestAlgorithm::kSha256, kUsername, kPassword,
      server.url());
  server.ExpireNonce();

  const auto response =
      client->Request("DESCRIBE", server.url(), authorization);

  EXPECT_EQ(response.status_code, 401);
  const std::string stale = ChallengeFor(response, "SHA-256");
  ASSERT_FALSE(stale.empty());
  EXPECT_EQ(DigestParameter(stale, "stale"), "true");
}

TEST(RtspDigestAuthIntegrationTest, InvalidExpiredDigestDoesNotGetStale) {
  InjectedClockTlsServer server;
  auto client = TlsRtspTestClient::Connect(server.port());
  ASSERT_NE(client, nullptr);
  const auto challenged = client->Request("DESCRIBE", server.url());
  const std::string challenge = ChallengeFor(challenged, "SHA-256");
  ASSERT_FALSE(challenge.empty());
  const auto nonce = DigestParameter(challenge, "nonce");
  ASSERT_TRUE(nonce.has_value());
  const std::string authorization = AuthorizationFromChallenge(
      challenge, RtspDigestAlgorithm::kSha256, kUsername, "wrong-password",
      server.url());
  server.ExpireNonce();

  const auto response =
      client->Request("DESCRIBE", server.url(), authorization);

  ExpectOrdinarySha256Unauthorized(response);

  std::string forged_nonce = *nonce;
  ASSERT_FALSE(forged_nonce.empty());
  forged_nonce.back() = forged_nonce.back() == 'A' ? 'B' : 'A';
  const std::string forged_authorization = BuildAuthorization(
      RtspDigestAlgorithm::kSha256,
      kUsername,
      kPassword,
      kRealm,
      "DESCRIBE",
      server.url(),
      forged_nonce);
  const auto forged =
      client->Request("DESCRIBE", server.url(), forged_authorization);
  ExpectOrdinarySha256Unauthorized(forged);
}

TEST(RtspDigestAuthIntegrationTest,
     UnauthorizedDescribeNeverAllocatesPerMediaSrtpKey) {
  LiveSecureServer server;
  auto client = TlsRtspTestClient::Connect(server.port());
  ASSERT_NE(client, nullptr);

  const auto response = client->Request("DESCRIBE", server.url());

  ExpectOrdinarySha256Unauthorized(response);
  EXPECT_EQ(server.server().PerMediaKeyAllocationCount(), 0U);
  EXPECT_EQ(server.server().PerMediaKeyZeroizeCount(), 0U);
}

TEST(RtspDigestAuthIntegrationTest,
     AuthenticatedDescribeAllocatesAndLaterZeroizesPerMediaKey) {
  LiveSecureServer server;
  {
    auto client = TlsRtspTestClient::Connect(server.port());
    ASSERT_NE(client, nullptr);
    const auto challenged = client->Request("DESCRIBE", server.url());
    const std::string challenge = ChallengeFor(challenged, "SHA-256");
    ASSERT_FALSE(challenge.empty());
    const std::string authorization = AuthorizationFromChallenge(
        challenge, RtspDigestAlgorithm::kSha256, kUsername, kPassword,
        server.url());
    ASSERT_EQ(
        client->Request("DESCRIBE", server.url(), authorization).status_code,
        200);
    EXPECT_EQ(server.server().PerMediaKeyAllocationCount(), 1U);
  }

  server.Stop();

  EXPECT_EQ(server.server().PerMediaKeyAllocationCount(), 1U);
  EXPECT_EQ(server.server().PerMediaKeyZeroizeCount(), 1U);
}

}  // namespace
