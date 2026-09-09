#include "camera_firmware/boot/FirmwareBootCoordinator.hpp"
#include "camera_firmware/service/ServiceApp.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpClient.h>
#include <drogon/HttpRequest.h>
#include <gtest/gtest.h>
#include <json/reader.h>
#include <openssl/ssl.h>

#include "camera_firmware/crypto/OpenSslCryptoProvider.hpp"
#include "camera_firmware/integrity/IntegritySigner.hpp"
#include "camera_firmware/security/PasswordHasher.hpp"
#include "camera_firmware/security/SystemProtectionService.hpp"
#include "camera_firmware/security/UserManagementService.hpp"
#include "camera_firmware/service/RuntimeSettingsHttp.hpp"
#include "camera_firmware/service/SecurityRequestGate.hpp"
#include "camera_firmware/settings/RuntimeSettingsStore.hpp"
#include "unit/integrity/IntegrityTestSupport.hpp"

namespace camera_firmware::service::internal {
void SetLiveMp4StartPublicationPauseForTesting(
    std::promise<void>* published,
    std::shared_future<void> release_publication) noexcept;
std::size_t LiveMp4StopCallsDuringStartForTesting() noexcept;
void FailNextDetectionSseEventMergeForTesting() noexcept;
void FailNextRuntimeCallbackLeaseAllocationForTesting() noexcept;
void SetSessionStreamBatchMarkPauseForTesting(
    std::promise<void>* first_marked,
    std::shared_future<void> release_marking) noexcept;
bool HasRetainedUserManagementServiceForTesting() noexcept;
common::Result<std::vector<security::ManagedUser>>
ListRetainedUsersForTesting();
void ForceNextLoginRoleInvalidForTesting() noexcept;
using UserManagementRequestBodyCleanupObserverForTesting =
    void (*)(std::size_t source_size, bool source_cleansed,
             bool copied_to_secure_owner) noexcept;
void SetUserManagementRequestBodyCleanupObserverForTesting(
    UserManagementRequestBodyCleanupObserverForTesting observer) noexcept;
void ResetUserManagementRequestBodyCleanupObserverForTesting() noexcept;
void FailNextUserManagementPreSubmitForTesting() noexcept;
void ResetUserManagementPreSubmitFailureForTesting() noexcept;
void FailNextAuthorizationDispatchQueueForTesting() noexcept;
void ResetAuthorizationDispatchQueueFailureForTesting() noexcept;
void FailNextTerminalResponseQueueForTesting() noexcept;
void ResetTerminalResponseQueueFailureForTesting() noexcept;
std::shared_ptr<BoundedWorker> ReplaceAuditAuthorizationWorkerForTesting(
    std::shared_ptr<BoundedWorker> worker) noexcept;
std::shared_ptr<security::SecurityStore>
ReplaceAuditAuthorizationStoreForTesting(
    std::shared_ptr<security::SecurityStore> store) noexcept;
std::shared_ptr<security::AuthService>
ReplaceAuditAuthorizationServiceForTesting(
    std::shared_ptr<security::AuthService> auth_service) noexcept;
bool ReplaceAuditAuthorizationShutdownForTesting(bool shutting_down) noexcept;
}  // namespace camera_firmware::service::internal

namespace {

// A single self-tested provider shared by every in-process ServiceApp test in
// this file (as opposed to the FirmwareProcess-based tests, which exercise
// the real camera-firmware(-integration) binary and its own main.cpp-owned
// provider). ServiceInitArgs::provider must be set explicitly by every test
// that enables HTTP TLS without a pre-resolved tls_material, because
// ServiceApp itself never constructs a CryptoProvider of its own.
camera_firmware::crypto::CryptoProvider& TestCryptoProvider() {
  static camera_firmware::crypto::OpenSslCryptoProvider provider;
  static const bool initialized = [] {
    const auto self_test = provider.SelfTest();
    if (!self_test.ok() || !self_test.value().passed) {
      throw std::runtime_error("crypto provider self-test failed");
    }
    return true;
  }();
  (void)initialized;
  return provider;
}

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 48> pattern{"/tmp/cf-https-auth-XXXXXX"};
    char* created = ::mkdtemp(pattern.data());
    if (created == nullptr) {
      throw std::system_error(errno, std::generic_category(), "mkdtemp");
    }
    path_ = created;
  }

  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  [[nodiscard]] const std::filesystem::path& path() const noexcept {
    return path_;
  }

 private:
  std::filesystem::path path_;
};

class PromiseReleaseGuard {
 public:
  explicit PromiseReleaseGuard(std::promise<void>& promise) noexcept
      : promise_(promise) {}

  ~PromiseReleaseGuard() { Release(); }

  PromiseReleaseGuard(const PromiseReleaseGuard&) = delete;
  PromiseReleaseGuard& operator=(const PromiseReleaseGuard&) = delete;

  void Release() noexcept {
    if (released_) {
      return;
    }
    released_ = true;
    try {
      promise_.set_value();
    } catch (...) {
    }
  }

 private:
  std::promise<void>& promise_;
  bool released_{false};
};

template <typename T, auto Replace>
class ScopedAuditAuthorizationDependency {
 public:
  explicit ScopedAuditAuthorizationDependency(std::shared_ptr<T> replacement)
      : original_(Replace(std::move(replacement))) {}

  ~ScopedAuditAuthorizationDependency() { (void)Replace(std::move(original_)); }

  ScopedAuditAuthorizationDependency(
      const ScopedAuditAuthorizationDependency&) = delete;
  ScopedAuditAuthorizationDependency& operator=(
      const ScopedAuditAuthorizationDependency&) = delete;

 private:
  std::shared_ptr<T> original_;
};

using AuditAuthorizationWorkerScope = ScopedAuditAuthorizationDependency<
    camera_firmware::service::BoundedWorker,
    camera_firmware::service::internal::
        ReplaceAuditAuthorizationWorkerForTesting>;
using AuditAuthorizationStoreScope = ScopedAuditAuthorizationDependency<
    camera_firmware::security::SecurityStore,
    camera_firmware::service::internal::
        ReplaceAuditAuthorizationStoreForTesting>;
using AuditAuthorizationServiceScope = ScopedAuditAuthorizationDependency<
    camera_firmware::security::AuthService,
    camera_firmware::service::internal::
        ReplaceAuditAuthorizationServiceForTesting>;

class AuditAuthorizationShutdownScope {
 public:
  explicit AuditAuthorizationShutdownScope(bool shutting_down) noexcept
      : original_(
            camera_firmware::service::internal::
                ReplaceAuditAuthorizationShutdownForTesting(shutting_down)) {}

  ~AuditAuthorizationShutdownScope() {
    (void)camera_firmware::service::internal::
        ReplaceAuditAuthorizationShutdownForTesting(original_);
  }

  AuditAuthorizationShutdownScope(const AuditAuthorizationShutdownScope&) =
      delete;
  AuditAuthorizationShutdownScope& operator=(
      const AuditAuthorizationShutdownScope&) = delete;

 private:
  bool original_;
};

// Reserve an ephemeral loopback port and HOLD it open for the life of the
// process. Closing the reservation socket before the server binds (as the old
// version did) leaves a window in which the kernel can hand the same port to
// another socket -- a client's ephemeral connection, a prior test's TIME_WAIT
// entry -- and the server's later bind() then fails. trantor's
// Socket::bindAddress calls exit(1) on bind failure, so that window silently
// kills the whole test process and shows up as a flaky "Bad server address"
// client error. Keeping the reservation socket bound (SO_REUSEADDR, never
// listened on) holds the port so no other socket can take it, while
// SO_REUSEADDR lets the server bind the same port. The fd is intentionally
// leaked: the process is short-lived and binds a bounded number of ports, and
// the reservation must outlive every server that uses it.
std::uint16_t ReserveLoopbackPort() {
  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    throw std::system_error(errno, std::generic_category(), "socket");
  }
  const int reuse = 1;
  if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
    const int error = errno;
    (void)::close(fd);
    throw std::system_error(error, std::generic_category(), "setsockopt");
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (::bind(fd, reinterpret_cast<const sockaddr*>(&address),
             sizeof(address)) != 0) {
    const int error = errno;
    (void)::close(fd);
    throw std::system_error(error, std::generic_category(), "bind");
  }
  socklen_t size = sizeof(address);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
    const int error = errno;
    (void)::close(fd);
    throw std::system_error(error, std::generic_category(), "getsockname");
  }
  // Hold the reservation open (leaked) so the port cannot be reused before the
  // server binds it. Not listened on, so all connections go to the server.
  return ntohs(address.sin_port);
}

struct HttpResult {
  drogon::ReqResult result{drogon::ReqResult::BadResponse};
  drogon::HttpResponsePtr response;
};

struct UserManagementBodyCleanupState {
  std::atomic_size_t calls{0U};
  std::atomic_size_t over_limit_without_copy{0U};
  std::atomic_size_t copied_to_secure_owner{0U};
  std::atomic_bool source_cleansed{true};
};

UserManagementBodyCleanupState& UserManagementBodyCleanupForTesting() {
  static UserManagementBodyCleanupState state;
  return state;
}

void ResetUserManagementBodyCleanupForTesting() noexcept {
  auto& state = UserManagementBodyCleanupForTesting();
  state.calls.store(0U, std::memory_order_relaxed);
  state.over_limit_without_copy.store(0U, std::memory_order_relaxed);
  state.copied_to_secure_owner.store(0U, std::memory_order_relaxed);
  state.source_cleansed.store(true, std::memory_order_relaxed);
}

void RecordUserManagementBodyCleanupForTesting(
    std::size_t source_size, bool source_cleansed,
    bool copied_to_secure_owner) noexcept {
  auto& state = UserManagementBodyCleanupForTesting();
  state.calls.fetch_add(1U, std::memory_order_relaxed);
  if (source_size > camera_firmware::service::kMaximumSecurityBodyBytes &&
      !copied_to_secure_owner) {
    state.over_limit_without_copy.fetch_add(1U, std::memory_order_relaxed);
  }
  if (copied_to_secure_owner) {
    state.copied_to_secure_owner.fetch_add(1U, std::memory_order_relaxed);
  }
  if (!source_cleansed) {
    state.source_cleansed.store(false, std::memory_order_relaxed);
  }
}

class UserManagementPreSubmitFailureScope {
 public:
  UserManagementPreSubmitFailureScope() noexcept {
    ResetUserManagementBodyCleanupForTesting();
    camera_firmware::service::internal::
        SetUserManagementRequestBodyCleanupObserverForTesting(
            RecordUserManagementBodyCleanupForTesting);
    camera_firmware::service::internal::
        FailNextUserManagementPreSubmitForTesting();
  }

  ~UserManagementPreSubmitFailureScope() {
    camera_firmware::service::internal::
        ResetUserManagementPreSubmitFailureForTesting();
    camera_firmware::service::internal::
        ResetUserManagementRequestBodyCleanupObserverForTesting();
  }

  UserManagementPreSubmitFailureScope(
      const UserManagementPreSubmitFailureScope&) = delete;
  UserManagementPreSubmitFailureScope& operator=(
      const UserManagementPreSubmitFailureScope&) = delete;
};

drogon::HttpClientPtr NewClient(std::uint16_t port,
                                std::string source_ip = {}) {
  auto client = drogon::HttpClient::newHttpClient("127.0.0.1", port, true,
                                                  nullptr, false, false);
  if (!source_ip.empty()) {
    client->setSockOptCallback([source_ip = std::move(source_ip)](int fd) {
      sockaddr_in source{};
      source.sin_family = AF_INET;
      source.sin_port = 0;
      if (::inet_pton(AF_INET, source_ip.c_str(), &source.sin_addr) != 1 ||
          ::bind(fd, reinterpret_cast<const sockaddr*>(&source),
                 sizeof(source)) != 0) {
        throw std::runtime_error("unable to bind integration client source");
      }
    });
  }
  return client;
}

HttpResult Send(const drogon::HttpClientPtr& client, drogon::HttpMethod method,
                std::string path, std::string body = {},
                std::string origin = {}, std::string cookie = {},
                bool management_header = false, double timeout_seconds = 15.0,
                std::vector<std::pair<std::string, std::string>> headers = {}) {
  auto request = drogon::HttpRequest::newHttpRequest();
  request->setMethod(method);
  request->setPath(std::move(path));
  if (!body.empty()) {
    request->setContentTypeString("application/json");
    request->setBody(std::move(body));
  }
  if (!origin.empty()) {
    request->addHeader("Origin", std::move(origin));
  }
  if (!cookie.empty()) {
    request->addHeader("Cookie", std::move(cookie));
  }
  if (management_header) {
    request->addHeader("X-Camera-Request", "management");
  }
  for (auto& [name, value] : headers) {
    request->addHeader(std::move(name), std::move(value));
  }
  auto [result, response] = client->sendRequest(request, timeout_seconds);
  return {result, std::move(response)};
}

void ExpectStatus(const HttpResult& result, drogon::HttpStatusCode status) {
  ASSERT_EQ(result.result, drogon::ReqResult::Ok);
  ASSERT_NE(result.response, nullptr);
  EXPECT_EQ(result.response->statusCode(), status)
      << result.response->getBody();
}

// The initial account's password is drawn at random from the printable ASCII
// range, so it can legitimately contain a quote or a backslash. Building the
// login body by concatenation without this would produce a malformed request
// on roughly one boot in three.
std::string JsonQuoted(std::string_view value) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string quoted = "\"";
  for (const char character : value) {
    const auto byte = static_cast<unsigned char>(character);
    if (character == '"' || character == '\\') {
      quoted.push_back('\\');
      quoted.push_back(character);
    } else if (byte < 0x20U) {
      quoted += "\\u00";
      quoted.push_back(kHex[(byte >> 4) & 0x0FU]);
      quoted.push_back(kHex[byte & 0x0FU]);
    } else {
      quoted.push_back(character);
    }
  }
  quoted.push_back('"');
  return quoted;
}

std::string InitialAccountLoginBody(std::string_view username,
                                    std::string_view password) {
  return "{\"username\":" + JsonQuoted(username) +
         ",\"password\":" + JsonQuoted(password) + "}";
}

// Signs in with the per-device account the firmware minted at first boot and
// returns the Cookie header for the session, or an empty string if any step
// failed. POST /api/v1/setup/initialize requires that session, so every caller
// that expects setup to run goes through this first; an empty return surfaces
// as the caller's own status assertion failing.
std::string InitialAccountCookie(const drogon::HttpClientPtr& client,
                                 const std::string& origin) {
  const auto status = Send(client, drogon::Get, "/api/v1/setup/status");
  if (status.result != drogon::ReqResult::Ok || !status.response ||
      status.response->statusCode() != drogon::k200OK ||
      status.response->getJsonObject() == nullptr) {
    return {};
  }
  const auto& body = *status.response->getJsonObject();
  if (!body.isMember("initial_username") ||
      !body.isMember("initial_password")) {
    return {};
  }
  const auto login =
      Send(client, drogon::Post, "/api/v1/auth/login",
           InitialAccountLoginBody(body["initial_username"].asString(),
                                   body["initial_password"].asString()),
           origin, {}, true);
  if (login.result != drogon::ReqResult::Ok || !login.response ||
      login.response->statusCode() != drogon::k200OK) {
    return {};
  }
  const auto& cookie = login.response->getCookie("camera_session");
  if (cookie.value().empty()) {
    return {};
  }
  return "camera_session=" + cookie.value();
}

void ExpectJsonKeys(const Json::Value& value,
                    std::initializer_list<std::string_view> expected) {
  ASSERT_TRUE(value.isObject());
  auto actual = value.getMemberNames();
  std::sort(actual.begin(), actual.end());
  std::vector<std::string> expected_keys;
  expected_keys.reserve(expected.size());
  for (const auto key : expected) {
    expected_keys.emplace_back(key);
  }
  std::sort(expected_keys.begin(), expected_keys.end());
  EXPECT_EQ(actual, expected_keys);
}

void ExpectSecurityHeaders(const drogon::HttpResponsePtr& response) {
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->getHeader("Cache-Control"), "no-store");
  EXPECT_EQ(response->getHeader("Strict-Transport-Security"),
            "max-age=31536000");
  EXPECT_EQ(response->getHeader("X-Content-Type-Options"), "nosniff");
  EXPECT_EQ(response->getHeader("Referrer-Policy"), "no-referrer");
  EXPECT_EQ(response->getHeader("X-Frame-Options"), "DENY");
  EXPECT_EQ(response->getHeader("Content-Security-Policy"),
            "default-src 'self'; img-src 'self' blob:; object-src 'none'; "
            "media-src 'self' blob:; "
            "base-uri 'none'; "
            "frame-ancestors 'none'");
}

struct RawHttpsResponse {
  enum class ReadEnd {
    kEof,
    kByteLimit,
    kComplete,
    kTimeout,
    kTlsError,
  };

  int status{-1};
  std::string bytes;
  ReadEnd read_end{ReadEnd::kTlsError};

  [[nodiscard]] std::string Header(std::string_view name) const {
    std::string prefix(name);
    std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                   [](unsigned char value) {
                     return static_cast<char>(std::tolower(value));
                   });
    prefix += ':';
    const std::size_t status_end = bytes.find("\r\n");
    if (status_end == std::string::npos) {
      return {};
    }
    std::size_t line_begin = status_end + 2U;
    while (line_begin != std::string::npos && line_begin < bytes.size()) {
      const std::size_t line_end = bytes.find("\r\n", line_begin);
      if (line_end == std::string::npos || line_end == line_begin) {
        break;
      }
      std::string line = bytes.substr(line_begin, line_end - line_begin);
      std::transform(line.begin(), line.end(), line.begin(),
                     [](unsigned char value) {
                       return static_cast<char>(std::tolower(value));
                     });
      if (line.starts_with(prefix)) {
        std::size_t value_begin = prefix.size();
        while (value_begin < line_end - line_begin &&
               bytes[line_begin + value_begin] == ' ') {
          ++value_begin;
        }
        return bytes.substr(line_begin + value_begin,
                            line_end - line_begin - value_begin);
      }
      line_begin = line_end + 2U;
    }
    return {};
  }
};

class ScopedSocket {
 public:
  explicit ScopedSocket(int fd) noexcept : fd_(fd) {}
  ~ScopedSocket() {
    if (fd_ >= 0) {
      (void)::close(fd_);
    }
  }

  ScopedSocket(const ScopedSocket&) = delete;
  ScopedSocket& operator=(const ScopedSocket&) = delete;

  [[nodiscard]] int get() const noexcept { return fd_; }

 private:
  int fd_{-1};
};

struct ChunkedBodyParseResult {
  std::string decoded;
  std::optional<std::size_t> complete_encoded_size;
  bool valid{true};
};

ChunkedBodyParseResult ParseAvailableChunkedBody(std::string_view encoded) {
  ChunkedBodyParseResult result;
  std::size_t offset = 0U;
  while (offset < encoded.size()) {
    const std::size_t size_end = encoded.find("\r\n", offset);
    if (size_end == std::string_view::npos) {
      return result;
    }
    std::string_view size_text = encoded.substr(offset, size_end - offset);
    const std::size_t extension = size_text.find(';');
    if (extension != std::string_view::npos) {
      size_text = size_text.substr(0U, extension);
    }
    std::size_t chunk_size = 0U;
    const auto parsed = std::from_chars(
        size_text.data(), size_text.data() + size_text.size(), chunk_size, 16);
    if (size_text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != size_text.data() + size_text.size()) {
      result.valid = false;
      return result;
    }

    const std::size_t data_begin = size_end + 2U;
    if (chunk_size == 0U) {
      std::size_t trailer_begin = data_begin;
      for (;;) {
        const std::size_t trailer_end = encoded.find("\r\n", trailer_begin);
        if (trailer_end == std::string_view::npos) {
          return result;
        }
        if (trailer_end == trailer_begin) {
          result.complete_encoded_size = trailer_end + 2U;
          return result;
        }
        trailer_begin = trailer_end + 2U;
      }
    }
    if (data_begin > encoded.size() ||
        chunk_size > encoded.size() - data_begin) {
      return result;
    }
    const std::size_t data_end = data_begin + chunk_size;
    if (encoded.size() - data_end < 2U) {
      return result;
    }
    if (encoded.substr(data_end, 2U) != "\r\n") {
      result.valid = false;
      return result;
    }
    result.decoded.append(encoded.substr(data_begin, chunk_size));
    offset = data_end + 2U;
  }
  return result;
}

std::optional<std::size_t> CompleteRawResponseSize(
    const RawHttpsResponse& response) {
  const std::size_t header_end = response.bytes.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    return std::nullopt;
  }
  const std::size_t body_begin = header_end + 4U;
  std::string transfer_encoding = response.Header("Transfer-Encoding");
  std::transform(transfer_encoding.begin(), transfer_encoding.end(),
                 transfer_encoding.begin(), [](unsigned char value) {
                   return static_cast<char>(std::tolower(value));
                 });
  if (transfer_encoding == "chunked") {
    const std::string_view encoded(response.bytes.data() + body_begin,
                                   response.bytes.size() - body_begin);
    const auto parsed = ParseAvailableChunkedBody(encoded);
    if (!parsed.valid || !parsed.complete_encoded_size.has_value()) {
      return std::nullopt;
    }
    return body_begin + *parsed.complete_encoded_size;
  }

  const std::string content_length = response.Header("Content-Length");
  if (content_length.empty()) {
    return std::nullopt;
  }
  std::size_t body_size = 0U;
  const auto parsed =
      std::from_chars(content_length.data(),
                      content_length.data() + content_length.size(), body_size);
  if (parsed.ec != std::errc{} ||
      parsed.ptr != content_length.data() + content_length.size() ||
      body_size > std::numeric_limits<std::size_t>::max() - body_begin) {
    return std::nullopt;
  }
  const std::size_t complete_size = body_begin + body_size;
  return response.bytes.size() >= complete_size
             ? std::optional<std::size_t>(complete_size)
             : std::nullopt;
}

void ParseRawStatus(RawHttpsResponse& response) {
  const std::size_t first_space = response.bytes.find(' ');
  if (!response.bytes.starts_with("HTTP/") ||
      first_space == std::string::npos ||
      first_space + 4U > response.bytes.size()) {
    return;
  }
  try {
    response.status = std::stoi(response.bytes.substr(first_space + 1U, 3U));
  } catch (...) {
    response.status = -1;
  }
}

class RawHttpsConnection {
 public:
  explicit RawHttpsConnection(
      std::uint16_t port,
      std::chrono::milliseconds receive_timeout = std::chrono::seconds(15))
      : socket_fd_(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)),
        context_(::SSL_CTX_new(::TLS_client_method()), &::SSL_CTX_free),
        ssl_(context_ ? ::SSL_new(context_.get()) : nullptr, &::SSL_free) {
    if (socket_fd_.get() < 0 || !ssl_ || !SetReceiveTimeout(receive_timeout)) {
      return;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(socket_fd_.get(), reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) != 0) {
      return;
    }
    ::SSL_CTX_set_verify(context_.get(), SSL_VERIFY_NONE, nullptr);
    ::SSL_set_fd(ssl_.get(), socket_fd_.get());
    connected_ = ::SSL_connect(ssl_.get()) == 1;
  }

  ~RawHttpsConnection() {
    if (connected_) {
      (void)::SSL_shutdown(ssl_.get());
    }
  }

  RawHttpsConnection(const RawHttpsConnection&) = delete;
  RawHttpsConnection& operator=(const RawHttpsConnection&) = delete;

  [[nodiscard]] bool connected() const noexcept { return connected_; }

  RawHttpsResponse Exchange(
      std::string_view request,
      std::size_t receive_byte_limit = std::numeric_limits<std::size_t>::max(),
      std::chrono::milliseconds receive_timeout = std::chrono::seconds(15),
      bool stop_at_complete_response = false) {
    RawHttpsResponse response;
    if (!connected_) {
      return response;
    }
    if (!SetReceiveTimeout(receive_timeout)) {
      connected_ = false;
      return response;
    }

    std::size_t written = 0U;
    while (written < request.size()) {
      const std::size_t write_size = std::min<std::size_t>(
          request.size() - written, std::numeric_limits<int>::max());
      const int count = ::SSL_write(ssl_.get(), request.data() + written,
                                    static_cast<int>(write_size));
      if (count <= 0) {
        connected_ = false;
        return response;
      }
      written += static_cast<std::size_t>(count);
    }

    std::array<char, 2048> buffer{};
    for (;;) {
      if (stop_at_complete_response) {
        const auto complete_size = CompleteRawResponseSize(response);
        if (complete_size.has_value()) {
          if (*complete_size < response.bytes.size()) {
            response.bytes.resize(*complete_size);
            connected_ = false;
          }
          response.read_end = RawHttpsResponse::ReadEnd::kComplete;
          break;
        }
      }
      if (response.bytes.size() >= receive_byte_limit) {
        if (response.bytes.size() > receive_byte_limit) {
          response.bytes.resize(receive_byte_limit);
        }
        response.read_end = RawHttpsResponse::ReadEnd::kByteLimit;
        connected_ = false;
        break;
      }
      const std::size_t remaining = receive_byte_limit - response.bytes.size();
      const auto read_capacity =
          static_cast<int>(std::min<std::size_t>(buffer.size(), remaining));
      const int count = ::SSL_read(ssl_.get(), buffer.data(), read_capacity);
      if (count > 0) {
        response.bytes.append(buffer.data(), static_cast<std::size_t>(count));
        continue;
      }

      const int socket_error = errno;
      const int ssl_error = ::SSL_get_error(ssl_.get(), count);
      if (ssl_error == SSL_ERROR_ZERO_RETURN ||
          (ssl_error == SSL_ERROR_SYSCALL && count == 0 && socket_error == 0)) {
        response.read_end = RawHttpsResponse::ReadEnd::kEof;
        connected_ = false;
      } else if (ssl_error == SSL_ERROR_WANT_READ ||
                 ssl_error == SSL_ERROR_WANT_WRITE ||
                 (ssl_error == SSL_ERROR_SYSCALL &&
                  (socket_error == EAGAIN || socket_error == EWOULDBLOCK ||
                   socket_error == ETIMEDOUT))) {
        response.read_end = RawHttpsResponse::ReadEnd::kTimeout;
        connected_ = false;
      } else {
        response.read_end = RawHttpsResponse::ReadEnd::kTlsError;
        connected_ = false;
      }
      break;
    }
    ParseRawStatus(response);
    return response;
  }

  RawHttpsResponse Get(
      std::string_view path, const std::vector<std::string>& cookie_fields,
      std::size_t receive_byte_limit = std::numeric_limits<std::size_t>::max(),
      std::chrono::milliseconds receive_timeout = std::chrono::seconds(15),
      bool stop_at_complete_response = true) {
    std::string request =
        "GET " + std::string(path) + " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
    for (const auto& field : cookie_fields) {
      request += "Cookie: " + field + "\r\n";
    }
    request += "Connection: keep-alive\r\n\r\n";
    return Exchange(request, receive_byte_limit, receive_timeout,
                    stop_at_complete_response);
  }

 private:
  bool SetReceiveTimeout(std::chrono::milliseconds receive_timeout) {
    const auto timeout_milliseconds =
        std::max<std::int64_t>(1, receive_timeout.count());
    const timeval socket_timeout{
        .tv_sec = static_cast<time_t>(timeout_milliseconds / 1000),
        .tv_usec =
            static_cast<suseconds_t>((timeout_milliseconds % 1000) * 1000)};
    return socket_fd_.get() >= 0 &&
           ::setsockopt(socket_fd_.get(), SOL_SOCKET, SO_RCVTIMEO,
                        &socket_timeout, sizeof(socket_timeout)) == 0;
  }

  ScopedSocket socket_fd_;
  std::unique_ptr<SSL_CTX, decltype(&::SSL_CTX_free)> context_;
  std::unique_ptr<SSL, decltype(&::SSL_free)> ssl_;
  bool connected_{false};
};

RawHttpsResponse RawHttpsExchange(
    std::uint16_t port, std::string_view request,
    std::size_t receive_byte_limit = std::numeric_limits<std::size_t>::max(),
    std::chrono::milliseconds receive_timeout = std::chrono::seconds(15)) {
  RawHttpsConnection connection(port, receive_timeout);
  return connection.Exchange(request, receive_byte_limit, receive_timeout);
}

std::optional<std::string> DecodeAvailableRawBody(
    const RawHttpsResponse& response) {
  const std::size_t header_end = response.bytes.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    return std::nullopt;
  }
  const std::string_view encoded(response.bytes.data() + header_end + 4U,
                                 response.bytes.size() - header_end - 4U);
  std::string transfer_encoding = response.Header("Transfer-Encoding");
  std::transform(transfer_encoding.begin(), transfer_encoding.end(),
                 transfer_encoding.begin(), [](unsigned char value) {
                   return static_cast<char>(std::tolower(value));
                 });
  if (transfer_encoding != "chunked") {
    return std::string(encoded);
  }
  auto parsed = ParseAvailableChunkedBody(encoded);
  if (!parsed.valid) {
    return std::nullopt;
  }
  return std::move(parsed.decoded);
}

std::optional<Json::Value> DecodeRawJsonBody(const RawHttpsResponse& response) {
  const auto body = DecodeAvailableRawBody(response);
  if (!body.has_value()) {
    return std::nullopt;
  }

  Json::CharReaderBuilder builder;
  Json::Value parsed;
  std::string errors;
  const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  if (!reader->parse(body->data(), body->data() + body->size(), &parsed,
                     &errors)) {
    return std::nullopt;
  }
  return parsed;
}

bool IsBoundedRuntimeSettingsInvalidResponse(const RawHttpsResponse& response,
                                             std::string_view private_marker) {
  const auto body = DecodeAvailableRawBody(response);
  const auto json = DecodeRawJsonBody(response);
  return response.status == 400 && body.has_value() && body->size() <= 256U &&
         body->find(private_marker) == std::string::npos && json.has_value() &&
         json->isObject() && json->size() == 2U &&
         (*json)["code"].asString() == "E_SETTINGS_REQUEST_INVALID" &&
         (*json)["message"].asString() == "runtime settings request is invalid";
}

constexpr std::string_view kRuntimeSettingsScenarioArgument =
    "--cf-runtime-settings-scenario=";
constexpr std::string_view kRuntimeSettingsStateArgument =
    "--cf-runtime-settings-state=";

std::optional<std::string> ProcessArgumentValue(std::string_view prefix) {
  std::ifstream arguments("/proc/self/cmdline", std::ios::binary);
  if (!arguments.is_open()) {
    return std::nullopt;
  }

  std::string argument;
  while (std::getline(arguments, argument, '\0')) {
    if (argument.starts_with(prefix)) {
      return argument.substr(prefix.size());
    }
  }
  return std::nullopt;
}

int RunFreshRuntimeSettingsScenario(
    std::string_view test_name, std::string_view scenario,
    const std::filesystem::path& state_directory,
    unsigned int timeout_seconds = 45U) {
  const std::string executable = "/proc/self/exe";
  const std::string filter = "--gtest_filter=" + std::string(test_name);
  const std::string scenario_argument =
      std::string(kRuntimeSettingsScenarioArgument) + std::string(scenario);
  const std::string state_argument =
      std::string(kRuntimeSettingsStateArgument) + state_directory.string();

  const pid_t child = ::fork();
  if (child < 0) {
    return -1;
  }
  if (child == 0) {
    (void)::alarm(timeout_seconds);
    ::execl(executable.c_str(), executable.c_str(), filter.c_str(),
            scenario_argument.c_str(), state_argument.c_str(), nullptr);
    _exit(127);
  }

  int status = 0;
  if (::waitpid(child, &status, 0) != child) {
    return -1;
  }
  return status;
}

std::optional<std::filesystem::path> RuntimeSettingsScenarioStateDirectory() {
  const auto state = ProcessArgumentValue(kRuntimeSettingsStateArgument);
  if (!state.has_value() || state->empty()) {
    return std::nullopt;
  }
  return std::filesystem::path(*state);
}

RawHttpsResponse RawHttpsGet(
    std::uint16_t port, std::string_view path,
    const std::vector<std::string>& cookie_fields,
    std::size_t receive_byte_limit = std::numeric_limits<std::size_t>::max(),
    std::chrono::milliseconds receive_timeout = std::chrono::seconds(15)) {
  std::string request =
      "GET " + std::string(path) + " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
  for (const auto& field : cookie_fields) {
    request += "Cookie: " + field + "\r\n";
  }
  request += "Connection: close\r\n\r\n";
  return RawHttpsExchange(port, request, receive_byte_limit, receive_timeout);
}

RawHttpsResponse RawHttpsJsonRequest(
    std::uint16_t port, std::string_view method, std::string_view path,
    std::string_view body, std::string_view origin = {},
    std::string_view cookie = {}, bool management_header = false) {
  std::string request = std::string(method) + " " + std::string(path) +
                        " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
  if (!origin.empty()) {
    request += "Origin: " + std::string(origin) + "\r\n";
  }
  if (!cookie.empty()) {
    request += "Cookie: " + std::string(cookie) + "\r\n";
  }
  if (management_header) {
    request += "X-Camera-Request: management\r\n";
  }
  if (!body.empty()) {
    request += "Content-Type: application/json\r\n";
  }
  request += "Content-Length: " + std::to_string(body.size()) +
             "\r\nConnection: close\r\n\r\n";
  request.append(body);
  return RawHttpsExchange(port, request);
}

// InitialAccountCookie for the callers that drive a real firmware process over
// raw TLS instead of a drogon client. Same contract: empty string on failure.
std::string RawInitialAccountCookie(std::uint16_t port,
                                    const std::string& origin) {
  const auto status = RawHttpsGet(port, "/api/v1/setup/status", {});
  if (status.status != 200) {
    return {};
  }
  const auto body = DecodeRawJsonBody(status);
  if (!body.has_value() || !body->isMember("initial_username") ||
      !body->isMember("initial_password")) {
    return {};
  }
  const auto login = RawHttpsJsonRequest(
      port, "POST", "/api/v1/auth/login",
      InitialAccountLoginBody((*body)["initial_username"].asString(),
                              (*body)["initial_password"].asString()),
      origin, {}, true);
  if (login.status != 200) {
    return {};
  }
  const std::string set_cookie = login.Header("Set-Cookie");
  if (!set_cookie.starts_with("camera_session=")) {
    return {};
  }
  return set_cookie.substr(0U, set_cookie.find(';'));
}

void ExpectRawSecurityHeaders(const RawHttpsResponse& response) {
  EXPECT_EQ(response.Header("Cache-Control"), "no-store");
  EXPECT_EQ(response.Header("Strict-Transport-Security"), "max-age=31536000");
  EXPECT_EQ(response.Header("X-Content-Type-Options"), "nosniff");
  EXPECT_EQ(response.Header("Referrer-Policy"), "no-referrer");
  EXPECT_EQ(response.Header("X-Frame-Options"), "DENY");
  EXPECT_EQ(response.Header("Content-Security-Policy"),
            "default-src 'self'; img-src 'self' blob:; object-src 'none'; "
            "media-src 'self' blob:; "
            "base-uri 'none'; "
            "frame-ancestors 'none'");
}

camera_firmware::config::AiModelConfig MakePersistenceModel(
    std::string id, std::string labels, unsigned int width, unsigned int height,
    bool letterbox, float confidence_threshold) {
  camera_firmware::config::AiModelConfig model;
  model.id = std::move(id);
  model.kind = "object_detection";
  model.hef_path = "/private/models/" + model.id + ".hef";
  model.output_name = model.id + "/private-output";
  model.input.width = width;
  model.input.height = height;
  model.input.format = "rgb8";
  model.input.letterbox = letterbox;
  model.confidence_threshold = confidence_threshold;
  model.labels = std::move(labels);
  return model;
}

camera_firmware::config::AppConfig MakePersistenceConfig(
    const std::filesystem::path& state_directory, std::uint16_t port) {
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = state_directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "camera-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (state_directory / "rtsp.credentials").string();
  config.camera.video.width = 1920U;
  config.camera.video.height = 1080U;
  config.camera.video.fps = 50U;
  config.camera.encoder.bitrate_kbps = 6000U;
  config.camera.encoder.gop = 25U;
  config.ai.enabled = true;
  config.ai.backend = "hailo";
  config.ai.models = {
      MakePersistenceModel("objects", "coco80", 640U, 640U, true, 0.40F),
      MakePersistenceModel("pose", "pose17", 320U, 256U, false, 0.35F),
  };
  config.camera.ai.enabled = true;
  config.camera.ai.model_ids = {"objects", "pose"};
  return config;
}

bool HasExpectedPersistedPendingSettings(const HttpResult& response) {
  if (response.result != drogon::ReqResult::Ok || !response.response ||
      response.response->statusCode() != drogon::k200OK ||
      response.response->getJsonObject() == nullptr ||
      response.response->getBody().find("/private/") != std::string::npos) {
    return false;
  }
  const auto& root = *response.response->getJsonObject();
  const auto& pending = root["pending"];
  const auto& camera = pending["camera"];
  const auto& models = pending["models"];
  const auto& sub_stream = pending["sub_stream"];
  const auto& osd = pending["osd"];
  return root["schema_version"].asUInt() == 1U &&
         root["revision"].asUInt64() == 1U &&
         root["state"].asString() == "pending" && pending.isObject() &&
         pending.size() == 4U && camera.isObject() && camera.size() == 3U &&
         camera["profile_id"].asString() == "imx708-1080p30" &&
         camera["bitrate_kbps"].asUInt() == 8000U &&
         camera["gop"].asUInt() == 30U && models.isArray() &&
         models.size() == 2U && models[0U].size() == 3U &&
         models[0U]["id"].asString() == "objects" &&
         models[0U]["enabled"].asBool() &&
         std::abs(models[0U]["confidence_threshold"].asDouble() - 0.55) <
             0.0001 &&
         models[1U].size() == 3U && models[1U]["id"].asString() == "pose" &&
         !models[1U]["enabled"].asBool() &&
         std::abs(models[1U]["confidence_threshold"].asDouble() - 0.25) <
             0.0001 &&
         sub_stream.isObject() && sub_stream.size() == 5U &&
         !sub_stream["enabled"].asBool() &&
         sub_stream["width"].asUInt() == 640U &&
         sub_stream["height"].asUInt() == 360U &&
         sub_stream["fps"].asUInt() == 15U &&
         sub_stream["bitrate_kbps"].asUInt() == 1000U && osd.isObject() &&
         osd.size() == 2U && !osd["enabled"].asBool() &&
         osd["items"].isArray() && osd["items"].empty();
}

int RunRuntimeSettingsPersistenceLifecycle(
    const std::filesystem::path& state_directory, bool save_pending) {
  const std::uint16_t port = ReserveLoopbackPort();
  auto config = MakePersistenceConfig(state_directory, port);
  auto security_opened = camera_firmware::security::SecurityStore::Open(
      {config.security.state_directory});
  if (!security_opened.ok()) {
    return 2;
  }
  auto security_store =
      std::shared_ptr<camera_firmware::security::SecurityStore>(
          std::move(security_opened).value());
  const auto security_state = security_store->State();
  const auto expected_security_state =
      save_pending ? camera_firmware::security::DeviceState::kDefault
                   : camera_firmware::security::DeviceState::kOperational;
  if (!security_state.ok() ||
      security_state.value() != expected_security_state) {
    return 3;
  }

  auto profiles = camera_firmware::settings::CameraProfileCatalog::Rpi5Imx708();
  auto base_active =
      camera_firmware::settings::DeriveRuntimeSettings(config, profiles);
  if (!base_active.ok()) {
    return 4;
  }
  auto runtime_store_opened =
      camera_firmware::settings::RuntimeSettingsStore::Open(
          state_directory, std::move(base_active).value(), config, profiles);
  if (!runtime_store_opened.ok()) {
    return 5;
  }
  auto runtime_store = std::move(runtime_store_opened).value();
  camera_firmware::runtime::ManagedFirmwareRuntime managed_runtime(
      config, [](const camera_firmware::config::AppConfig&) {
        return camera_firmware::common::Result<
            std::shared_ptr<camera_firmware::runtime::FirmwareRuntime>>::
            Err({"E_TEST_RUNTIME_UNUSED", "runtime factory is unused"});
      });
  camera_firmware::settings::RuntimeSettingsService runtime_settings(
      config, std::move(profiles), *runtime_store, managed_runtime,
      [](const camera_firmware::config::AppConfig&) {
        return camera_firmware::common::Result<void>::Ok();
      });

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.protection_runtime_allowed_callback = [] { return true; };
  args.protection_runtime_control_gate =
      [](const std::function<void()>& command) {
        command();
        return true;
      };
  args.runtime_settings_snapshot_callback = [&runtime_settings] {
    return runtime_settings.Snapshot();
  };
  args.runtime_settings_save_callback =
      [&runtime_settings](std::uint64_t expected_revision,
                          camera_firmware::settings::RuntimeSettings settings) {
        return runtime_settings.Save(expected_revision, std::move(settings));
      };
  args.runtime_settings_apply_callback =
      [&runtime_settings](std::uint64_t expected_revision) {
        return runtime_settings.Apply(expected_revision);
      };
  args.runtime_settings_discard_callback =
      [&runtime_settings](std::uint64_t expected_revision) {
        return runtime_settings.Discard(expected_revision);
      };
  args.security_store = security_store;

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  if (!started.ok()) {
    return 6;
  }
  const auto fail = [&service](int code) {
    service.Stop();
    return code;
  };
  auto client = NewClient(port);
  if (save_pending) {
    const auto setup = Send(
        client, drogon::Post, "/api/v1/setup/initialize",
        R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
        config.http.public_base_url,
        InitialAccountCookie(client, config.http.public_base_url), true);
    if (!setup.response || setup.response->statusCode() != drogon::k200OK) {
      return fail(7);
    }
  }

  const auto login = Send(client, drogon::Post, "/api/v1/auth/login",
                          R"({"username":"owner1","password":"StrongPass9!"})",
                          config.http.public_base_url, {}, true);
  if (login.result != drogon::ReqResult::Ok || !login.response ||
      login.response->statusCode() != drogon::k200OK) {
    return fail(8);
  }
  const std::string cookie =
      "camera_session=" + login.response->getCookie("camera_session").value();

  HttpResult response;
  if (save_pending) {
    response = Send(
        client, drogon::Put, "/api/v1/settings/runtime",
        R"({"expected_revision":0,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30},"models":[{"id":"objects","enabled":true,"confidence_threshold":0.55},{"id":"pose","enabled":false,"confidence_threshold":0.25}]}})",
        config.http.public_base_url, cookie, true);
  } else {
    response =
        Send(client, drogon::Get, "/api/v1/settings/runtime", {}, {}, cookie);
  }
  if (!HasExpectedPersistedPendingSettings(response)) {
    return fail(9);
  }
  if (save_pending) {
    const auto logout = Send(client, drogon::Post, "/api/v1/auth/logout", {},
                             config.http.public_base_url, cookie, true);
    if (!logout.response || logout.response->statusCode() != drogon::k200OK) {
      return fail(10);
    }
  }
  service.Stop();
  return 0;
}

bool RunParentOwnedWatchdogCleanupProbe() {
  std::filesystem::path path;
  bool alarm_terminated = false;
  {
    TemporaryDirectory directory;
    path = directory.path();
    const pid_t child = ::fork();
    if (child < 0) {
      return false;
    }
    if (child == 0) {
      (void)std::filesystem::create_directory(path / "child-started");
      (void)::alarm(1U);
      (void)::pause();
      _exit(2);
    }

    int status = 0;
    if (::waitpid(child, &status, 0) != child) {
      return false;
    }
    alarm_terminated = WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM;
  }
  return alarm_terminated && !std::filesystem::exists(path);
}

class FirmwareProcess final {
 public:
  explicit FirmwareProcess(const std::filesystem::path& config_path,
                           std::string_view integrity_public_key_pem = {}) {
    child_ = ::fork();
    if (child_ < 0) {
      throw std::system_error(errno, std::generic_category(), "fork");
    }
    if (child_ == 0) {
      if (!integrity_public_key_pem.empty() &&
          ::setenv("CF_TEST_INTEGRITY_PUBLIC_KEY_PEM",
                   std::string(integrity_public_key_pem).c_str(), 1) != 0) {
        _exit(126);
      }
      ::execl(CF_CAMERA_FIRMWARE_BIN, CF_CAMERA_FIRMWARE_BIN,
              config_path.c_str(), nullptr);
      _exit(127);
    }
  }

  ~FirmwareProcess() { Stop(); }

  FirmwareProcess(const FirmwareProcess&) = delete;
  FirmwareProcess& operator=(const FirmwareProcess&) = delete;

  void Stop() noexcept {
    if (child_ <= 0) {
      return;
    }
    (void)::kill(child_, SIGTERM);
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
      int status = 0;
      const pid_t waited = ::waitpid(child_, &status, WNOHANG);
      if (waited == child_) {
        child_ = -1;
        return;
      }
      if (waited < 0 && errno != EINTR) {
        child_ = -1;
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    (void)::kill(child_, SIGKILL);
    while (::waitpid(child_, nullptr, 0) < 0 && errno == EINTR) {
    }
    child_ = -1;
  }

 private:
  pid_t child_{-1};
};

std::string WriteTestIntegrityArtifacts(
    const std::filesystem::path& config_path,
    const std::filesystem::path& state_directory) {
  const auto integrity_directory = state_directory / "integrity";
  std::filesystem::create_directories(integrity_directory);
  std::filesystem::permissions(state_directory,
                               std::filesystem::perms::owner_all,
                               std::filesystem::perm_options::replace);
  std::filesystem::permissions(integrity_directory,
                               std::filesystem::perms::owner_all,
                               std::filesystem::perm_options::replace);

  const auto kernel_path = integrity_directory / "kernel.fixture";
  {
    std::ofstream kernel(kernel_path, std::ios::binary | std::ios::trunc);
    kernel << "integration test kernel identity\n";
    if (!kernel.good()) {
      throw std::runtime_error("unable to write integrity kernel fixture");
    }
  }

  const auto executable_path =
      std::filesystem::canonical(CF_CAMERA_FIRMWARE_BIN);
  const auto active_config =
      std::filesystem::absolute(config_path).lexically_normal();
  const auto digest = [](const std::filesystem::path& path) {
    auto result = camera_firmware::integrity::DigestRegularFile(path);
    if (!result.ok()) {
      throw std::runtime_error("unable to digest integrity fixture: " +
                               result.error().code);
    }
    return std::move(result).value();
  };

  camera_firmware::integrity::IntegrityManifest manifest{
      1U,
      "camera-firmware",
      "2026-01-01T00:00:00Z",
      {{"configuration",
        camera_firmware::integrity::IntegrityCategory::kConfiguration,
        active_config, digest(active_config)},
       {"firmware", camera_firmware::integrity::IntegrityCategory::kFirmware,
        executable_path, digest(executable_path)},
       {"kernel", camera_firmware::integrity::IntegrityCategory::kKernel,
        kernel_path, digest(kernel_path)}}};
  auto serialized =
      camera_firmware::integrity::SerializeIntegrityManifest(manifest);
  if (!serialized.ok()) {
    throw std::runtime_error("unable to serialize integrity fixture: " +
                             serialized.error().code);
  }

  camera_firmware::integrity::testing::EphemeralEd25519Key key;
  const auto signature = key.Sign(serialized.value());
  const auto manifest_bytes = std::span<const unsigned char>(
      reinterpret_cast<const unsigned char*>(serialized.value().data()),
      serialized.value().size());
  auto manifest_written =
      camera_firmware::integrity::WriteIntegrityArtifactAtomically(
          integrity_directory / "manifest.yaml", manifest_bytes);
  auto signature_written =
      camera_firmware::integrity::WriteIntegrityArtifactAtomically(
          integrity_directory / "manifest.sig", signature);
  if (!manifest_written.ok() || !signature_written.ok()) {
    throw std::runtime_error("unable to write signed integrity fixture");
  }
  return key.PublicPem();
}

std::string WriteManagedFirmwareConfig(
    const std::filesystem::path& config_path,
    const std::filesystem::path& state_directory, std::uint16_t https_port,
    std::uint16_t rtsp_port, bool security_enabled = true) {
  std::ofstream config(config_path);
  if (!config.is_open()) {
    throw std::runtime_error("unable to write firmware process config");
  }
  config << "camera:\n"
            "  source:\n"
            "    backend: libcamera\n"
            "    camera_index: 999\n"
            "http:\n"
            "  enabled: true\n"
            "  bind_ip: 127.0.0.1\n"
            "  port: "
         << https_port
         << "\n"
            "  web_root: " CF_SOURCE_DIR
            "/web/dist\n"
            "  public_base_url: https://127.0.0.1:"
         << https_port
         << "\n"
            "  tls:\n"
            "    enabled: true\n"
            "    allow_development_self_signed_tls: true\n"
            "security:\n"
            "  enabled: "
         << (security_enabled ? "true" : "false")
         << "\n"
            "  state_directory: "
         << state_directory.string()
         << "\n"
            "self_protection:\n"
            "  manifest_path: "
         << (state_directory / "integrity" / "manifest.yaml").string()
         << "\n"
            "  signature_path: "
         << (state_directory / "integrity" / "manifest.sig").string()
         << "\n"
            "secure_rtsp:\n"
            "  enabled: true\n"
            "  control_tls: true\n"
            "  media_srtp: false\n"
            "  allow_development_self_signed_tls: true\n"
            "  bind_ip: 127.0.0.1\n"
            "  port: "
         << rtsp_port
         << "\n"
            "  client_auth:\n"
            "    enabled: true\n"
            "    realm: firmware-process-test\n"
            "    credential_file: "
         << (state_directory / "rtsp.credentials").string()
         << "\n"
            "    algorithms: [sha-256]\n";
  if (!config.good()) {
    throw std::runtime_error("unable to flush firmware process config");
  }
  config.close();
  if (!config) {
    throw std::runtime_error("unable to close firmware process config");
  }
  if (!security_enabled) {
    return {};
  }
  return WriteTestIntegrityArtifacts(config_path, state_directory);
}

bool WaitForSetupService(std::uint16_t port,
                         std::string_view path = "/api/v1/setup/status") {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (std::chrono::steady_clock::now() < deadline) {
    const auto response =
        RawHttpsGet(port, path, {}, 4096U, std::chrono::milliseconds(250));
    if (response.status == 200) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return false;
}

bool InitializeOperationalFirmwareState(
    const std::filesystem::path& config_path, std::uint16_t port,
    std::string_view integrity_public_key_pem) {
  FirmwareProcess process(config_path, integrity_public_key_pem);
  if (!WaitForSetupService(port)) {
    return false;
  }
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  const auto setup = RawHttpsJsonRequest(
      port, "POST", "/api/v1/setup/initialize",
      R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
      origin, RawInitialAccountCookie(port, origin), true);
  return setup.status == 503;
}

std::optional<std::string> LoginToFirmware(std::uint16_t port) {
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  const auto login = RawHttpsJsonRequest(
      port, "POST", "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
  if (login.status != 200) {
    return std::nullopt;
  }
  const std::string set_cookie = login.Header("Set-Cookie");
  if (!set_cookie.starts_with("camera_session=")) {
    return std::nullopt;
  }
  return set_cookie.substr(0U, set_cookie.find(';'));
}

void WriteRuntimeSettingsFile(const std::filesystem::path& state_directory,
                              std::string_view contents) {
  const auto path = state_directory / "runtime-settings.json";
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    throw std::runtime_error("unable to write runtime settings test file");
  }
  output << contents;
  output.close();
  std::filesystem::permissions(
      path,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace);
}

std::string RuntimeSettingsDocument(
    std::string_view active_profile, unsigned int active_bitrate,
    unsigned int active_gop,
    std::optional<std::string_view> pending_profile = std::nullopt) {
  std::string pending = "null";
  if (pending_profile.has_value()) {
    pending = std::string(R"({"camera":{"profile_id":")") +
              std::string(*pending_profile) +
              R"(","bitrate_kbps":7000,"gop":30},"models":[]})";
  }
  return std::string(
             R"({"schema_version":1,"revision":7,"active":{"camera":{"profile_id":")") +
         std::string(active_profile) + R"(","bitrate_kbps":)" +
         std::to_string(active_bitrate) + R"(,"gop":)" +
         std::to_string(active_gop) + R"(},"models":[]},"pending":)" + pending +
         R"(,"last_apply":{"status":"never","code":"","restored":false}})";
}

TEST(HttpsAuthIntegrationTest, ParentOwnedWatchdogRemovesDirectoryAfterAlarm) {
  EXPECT_TRUE(RunParentOwnedWatchdogCleanupProbe());
}

TEST(FirmwareProcessRuntimeSettingsIntegrationTest,
     BaseSettingsRemainManageableWhenInitialRuntimeStartFails) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t https_port = ReserveLoopbackPort();
  const auto integrity_public_key = WriteManagedFirmwareConfig(
      config_path, state_directory, https_port, https_port);

  const std::string origin = "https://127.0.0.1:" + std::to_string(https_port);
  {
    FirmwareProcess setup_process(config_path, integrity_public_key);
    ASSERT_TRUE(WaitForSetupService(https_port));
    const auto setup = RawHttpsJsonRequest(
        https_port, "POST", "/api/v1/setup/initialize",
        R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
        origin, RawInitialAccountCookie(https_port, origin), true);
    ASSERT_EQ(setup.status, 503) << setup.bytes;
  }

  FirmwareProcess process(config_path, integrity_public_key);
  ASSERT_TRUE(WaitForSetupService(https_port));
  const auto login = RawHttpsJsonRequest(
      https_port, "POST", "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
  ASSERT_EQ(login.status, 200) << login.bytes;
  const std::string set_cookie = login.Header("Set-Cookie");
  ASSERT_TRUE(set_cookie.starts_with("camera_session=")) << set_cookie;
  const std::string cookie = set_cookie.substr(0U, set_cookie.find(';'));

  const auto settings =
      RawHttpsGet(https_port, "/api/v1/settings/runtime", {cookie});
  ASSERT_EQ(settings.status, 200) << settings.bytes;
  const auto response_body = DecodeRawJsonBody(settings);
  ASSERT_TRUE(response_body.has_value()) << settings.bytes;
  EXPECT_EQ((*response_body)["revision"].asUInt64(), 0U);
  EXPECT_EQ((*response_body)["state"].asString(), "failed");
  EXPECT_EQ((*response_body)["active"]["camera"]["profile_id"].asString(),
            "imx708-1080p50");
  EXPECT_EQ((*response_body)["active"]["camera"]["bitrate_kbps"].asUInt(),
            6000U);
  EXPECT_EQ((*response_body)["active"]["camera"]["gop"].asUInt(), 25U);
  EXPECT_FALSE(
      std::filesystem::exists(state_directory / "runtime-settings.json"));
}

TEST(FirmwareProcessRuntimeSettingsIntegrationTest,
     StoredActiveSettingsSelectTheBootRuntimeConfiguration) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t port = ReserveLoopbackPort();
  const auto integrity_public_key =
      WriteManagedFirmwareConfig(config_path, state_directory, port, port);
  ASSERT_TRUE(InitializeOperationalFirmwareState(config_path, port,
                                                 integrity_public_key));
  WriteRuntimeSettingsFile(
      state_directory, RuntimeSettingsDocument("imx708-1080p30", 8000U, 30U));

  FirmwareProcess process(config_path, integrity_public_key);
  ASSERT_TRUE(WaitForSetupService(port));
  const auto cookie = LoginToFirmware(port);
  ASSERT_TRUE(cookie.has_value());
  const auto settings =
      RawHttpsGet(port, "/api/v1/settings/runtime", {*cookie});
  ASSERT_EQ(settings.status, 200) << settings.bytes;
  const auto settings_body = DecodeRawJsonBody(settings);
  ASSERT_TRUE(settings_body.has_value());
  EXPECT_EQ((*settings_body)["revision"].asUInt64(), 7U);
  EXPECT_EQ((*settings_body)["active"]["camera"]["profile_id"].asString(),
            "imx708-1080p30");

  const auto cameras = RawHttpsGet(port, "/api/v1/cameras", {*cookie});
  ASSERT_EQ(cameras.status, 200) << cameras.bytes;
  const auto cameras_body = DecodeRawJsonBody(cameras);
  ASSERT_TRUE(cameras_body.has_value());
  ASSERT_TRUE((*cameras_body)["cameras"].isArray());
  ASSERT_EQ((*cameras_body)["cameras"].size(), 1U);
  EXPECT_EQ((*cameras_body)["cameras"][0U]["configured_fps"].asUInt(), 30U);
}

TEST(FirmwareProcessRuntimeSettingsIntegrationTest,
     StoredPendingSettingsSurviveWhileActiveSettingsRemainSelected) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t port = ReserveLoopbackPort();
  const auto integrity_public_key =
      WriteManagedFirmwareConfig(config_path, state_directory, port, port);
  ASSERT_TRUE(InitializeOperationalFirmwareState(config_path, port,
                                                 integrity_public_key));
  WriteRuntimeSettingsFile(
      state_directory,
      RuntimeSettingsDocument("imx708-1080p30", 8000U, 30U, "imx708-1080p50"));

  FirmwareProcess process(config_path, integrity_public_key);
  ASSERT_TRUE(WaitForSetupService(port));
  const auto cookie = LoginToFirmware(port);
  ASSERT_TRUE(cookie.has_value());
  const auto settings =
      RawHttpsGet(port, "/api/v1/settings/runtime", {*cookie});
  ASSERT_EQ(settings.status, 200) << settings.bytes;
  const auto body = DecodeRawJsonBody(settings);
  ASSERT_TRUE(body.has_value());
  EXPECT_EQ((*body)["revision"].asUInt64(), 7U);
  EXPECT_EQ((*body)["active"]["camera"]["profile_id"].asString(),
            "imx708-1080p30");
  EXPECT_EQ((*body)["pending"]["camera"]["profile_id"].asString(),
            "imx708-1080p50");

  const auto cameras = RawHttpsGet(port, "/api/v1/cameras", {*cookie});
  ASSERT_EQ(cameras.status, 200) << cameras.bytes;
  const auto cameras_body = DecodeRawJsonBody(cameras);
  ASSERT_TRUE(cameras_body.has_value());
  EXPECT_EQ((*cameras_body)["cameras"][0U]["configured_fps"].asUInt(), 30U);
}

TEST(FirmwareProcessRuntimeSettingsIntegrationTest,
     MalformedSettingsRemainOnDiskAndBootIntoRecovery) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t port = ReserveLoopbackPort();
  const auto integrity_public_key =
      WriteManagedFirmwareConfig(config_path, state_directory, port, port);
  ASSERT_TRUE(InitializeOperationalFirmwareState(config_path, port,
                                                 integrity_public_key));
  constexpr std::string_view kMalformedDocument = "not-json-private-marker";
  WriteRuntimeSettingsFile(state_directory, kMalformedDocument);

  FirmwareProcess process(config_path, integrity_public_key);
  ASSERT_TRUE(WaitForSetupService(port));
  const auto cookie = LoginToFirmware(port);
  ASSERT_TRUE(cookie.has_value());
  const auto settings =
      RawHttpsGet(port, "/api/v1/settings/runtime", {*cookie});
  ASSERT_EQ(settings.status, 200) << settings.bytes;
  const auto body = DecodeRawJsonBody(settings);
  ASSERT_TRUE(body.has_value());
  EXPECT_EQ((*body)["revision"].asUInt64(), 0U);
  EXPECT_EQ((*body)["state"].asString(), "recovery_required");
  EXPECT_EQ((*body)["active"]["camera"]["profile_id"].asString(),
            "imx708-1080p50");
  EXPECT_EQ(settings.bytes.find(kMalformedDocument), std::string::npos);

  std::ifstream persisted(state_directory / "runtime-settings.json",
                          std::ios::binary);
  ASSERT_TRUE(persisted.is_open());
  const std::string persisted_text{std::istreambuf_iterator<char>(persisted),
                                   std::istreambuf_iterator<char>()};
  EXPECT_EQ(persisted_text, kMalformedDocument);
}

TEST(FirmwareProcessRuntimeSettingsIntegrationTest,
     SavedPendingSettingsSurviveARealFirmwareRestart) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  const auto integrity_public_key =
      WriteManagedFirmwareConfig(config_path, state_directory, port, port);
  ASSERT_TRUE(InitializeOperationalFirmwareState(config_path, port,
                                                 integrity_public_key));

  {
    FirmwareProcess first_process(config_path, integrity_public_key);
    ASSERT_TRUE(WaitForSetupService(port));
    const auto cookie = LoginToFirmware(port);
    ASSERT_TRUE(cookie.has_value());
    const auto saved = RawHttpsJsonRequest(
        port, "PUT", "/api/v1/settings/runtime",
        R"({"expected_revision":0,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30},"models":[]}})",
        origin, *cookie, true);
    ASSERT_EQ(saved.status, 200) << saved.bytes;
    const auto body = DecodeRawJsonBody(saved);
    ASSERT_TRUE(body.has_value());
    EXPECT_EQ((*body)["revision"].asUInt64(), 1U);
    EXPECT_EQ((*body)["pending"]["camera"]["profile_id"].asString(),
              "imx708-1080p30");
    const auto logout = RawHttpsJsonRequest(port, "POST", "/api/v1/auth/logout",
                                            {}, origin, *cookie, true);
    ASSERT_EQ(logout.status, 200) << logout.bytes;
  }

  FirmwareProcess second_process(config_path, integrity_public_key);
  ASSERT_TRUE(WaitForSetupService(port));
  const auto cookie = LoginToFirmware(port);
  ASSERT_TRUE(cookie.has_value());
  const auto settings =
      RawHttpsGet(port, "/api/v1/settings/runtime", {*cookie});
  ASSERT_EQ(settings.status, 200) << settings.bytes;
  const auto body = DecodeRawJsonBody(settings);
  ASSERT_TRUE(body.has_value());
  EXPECT_EQ((*body)["revision"].asUInt64(), 1U);
  EXPECT_EQ((*body)["active"]["camera"]["profile_id"].asString(),
            "imx708-1080p50");
  EXPECT_EQ((*body)["pending"]["camera"]["profile_id"].asString(),
            "imx708-1080p30");
}

TEST(FirmwareProcessRuntimeSettingsIntegrationTest,
     ApplyStartFailureKeepsTheAdministratorSessionUsable) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  const auto integrity_public_key =
      WriteManagedFirmwareConfig(config_path, state_directory, port, port);
  ASSERT_TRUE(InitializeOperationalFirmwareState(config_path, port,
                                                 integrity_public_key));

  FirmwareProcess process(config_path, integrity_public_key);
  ASSERT_TRUE(WaitForSetupService(port));
  const auto cookie = LoginToFirmware(port);
  ASSERT_TRUE(cookie.has_value());
  const auto saved = RawHttpsJsonRequest(
      port, "PUT", "/api/v1/settings/runtime",
      R"({"expected_revision":0,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30},"models":[]}})",
      origin, *cookie, true);
  ASSERT_EQ(saved.status, 200) << saved.bytes;

  const auto applied =
      RawHttpsJsonRequest(port, "POST", "/api/v1/settings/runtime/apply",
                          R"({"expected_revision":1})", origin, *cookie, true);
  ASSERT_EQ(applied.status, 503) << applied.bytes;
  const auto apply_body = DecodeRawJsonBody(applied);
  ASSERT_TRUE(apply_body.has_value());
  EXPECT_EQ((*apply_body)["code"].asString(), "E_SETTINGS_APPLY_FAILED");
  const auto raw_apply_body = DecodeAvailableRawBody(applied);
  ASSERT_TRUE(raw_apply_body.has_value());
  EXPECT_LE(raw_apply_body->size(),
            camera_firmware::service::kMaximumRuntimeSettingsBodyBytes);
  EXPECT_EQ((*apply_body)["message"].asString(),
            "runtime settings apply failed");
  EXPECT_EQ(raw_apply_body->find("/private/"), std::string::npos);

  const auto after_failure =
      RawHttpsGet(port, "/api/v1/settings/runtime", {*cookie});
  ASSERT_EQ(after_failure.status, 200) << after_failure.bytes;
  const auto body = DecodeRawJsonBody(after_failure);
  ASSERT_TRUE(body.has_value());
  EXPECT_EQ((*body)["state"].asString(), "failed");
  EXPECT_EQ((*body)["pending"]["camera"]["profile_id"].asString(),
            "imx708-1080p30");
  EXPECT_EQ((*body)["last_apply"]["status"].asString(), "failed");
}

TEST(FirmwareProcessRuntimeSettingsIntegrationTest,
     SecurityDisabledModeDoesNotCreateRuntimeSettingsPersistence) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "development-state";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t port = ReserveLoopbackPort();
  ASSERT_TRUE(std::filesystem::create_directory(state_directory));
  std::filesystem::permissions(state_directory,
                               std::filesystem::perms::owner_all,
                               std::filesystem::perm_options::replace);
  const auto integrity_public_key = WriteManagedFirmwareConfig(
      config_path, state_directory, port, port, false);

  {
    FirmwareProcess process(config_path, integrity_public_key);
    ASSERT_TRUE(WaitForSetupService(port, "/api/v1/health"));
    const auto settings = RawHttpsGet(port, "/api/v1/settings/runtime", {});
    ASSERT_EQ(settings.status, 503) << settings.bytes;
    const auto body = DecodeRawJsonBody(settings);
    ASSERT_TRUE(body.has_value());
    EXPECT_EQ((*body)["code"].asString(), "E_SETTINGS_UNAVAILABLE");
  }
  EXPECT_FALSE(
      std::filesystem::exists(state_directory / "runtime-settings.json"));
}

TEST(FirmwareProcessSignalIntegrationTest,
     SigtermStopsFirmwareWithinFiveSeconds) {
  TemporaryDirectory directory;
  const std::uint16_t port = ReserveLoopbackPort();
  const auto config_path = directory.path() / "signal-test.yaml";
  {
    std::ofstream config(config_path);
    ASSERT_TRUE(config.is_open());
    config << "http:\n"
              "  enabled: true\n"
              "  bind_ip: 127.0.0.1\n"
              "  port: "
           << port
           << "\n"
              "  web_root: " CF_SOURCE_DIR
              "/web/dist\n"
              "  public_base_url: https://127.0.0.1:"
           << port
           << "\n"
              "  tls:\n"
              "    enabled: true\n"
              "    allow_development_self_signed_tls: true\n"
              "security:\n"
              "  enabled: true\n"
              "  state_directory: "
           << (directory.path() / "security").string()
           << "\n"
              "self_protection:\n"
              "  manifest_path: "
           << (directory.path() / "security" / "integrity" / "manifest.yaml")
                  .string()
           << "\n"
              "  signature_path: "
           << (directory.path() / "security" / "integrity" / "manifest.sig")
                  .string()
           << "\n"
              "secure_rtsp:\n"
              "  enabled: true\n"
              "  control_tls: true\n"
              "  media_srtp: false\n"
              "  allow_development_self_signed_tls: true\n"
              "  client_auth:\n"
              "    enabled: true\n"
              "    realm: signal-test\n"
              "    credential_file: "
           << (directory.path() / "security" / "rtsp.credentials").string()
           << "\n"
              "    algorithms: [sha-256]\n";
    ASSERT_TRUE(config.good());
  }

  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    ::execl(CF_CAMERA_FIRMWARE_BIN, CF_CAMERA_FIRMWARE_BIN, config_path.c_str(),
            nullptr);
    _exit(127);
  }

  bool ready = false;
  const auto ready_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (std::chrono::steady_clock::now() < ready_deadline) {
    const auto status = RawHttpsGet(port, "/api/v1/setup/status", {}, 4096U,
                                    std::chrono::milliseconds(200));
    if (status.status == 200) {
      ready = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  if (!ready) {
    (void)::kill(child, SIGKILL);
    (void)::waitpid(child, nullptr, 0);
  }
  ASSERT_TRUE(ready);

  ASSERT_EQ(::kill(child, SIGTERM), 0);
  int status = 0;
  bool exited = false;
  const auto exit_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (std::chrono::steady_clock::now() < exit_deadline) {
    const pid_t waited = ::waitpid(child, &status, WNOHANG);
    if (waited == child) {
      exited = true;
      break;
    }
    ASSERT_GE(waited, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  if (!exited) {
    (void)::kill(child, SIGKILL);
    (void)::waitpid(child, &status, 0);
  }

  ASSERT_TRUE(exited);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(FirmwareProcessCryptoSelfTestIntegrationTest,
     ForcedSelfTestFailureExitsNonZeroWithoutOpeningSetupService) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t port = ReserveLoopbackPort();
  (void)WriteManagedFirmwareConfig(config_path, state_directory, port, port);

  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    if (::setenv("CAMERA_FIRMWARE_FORCE_CRYPTO_SELF_TEST_FAILURE", "1", 1) !=
        0) {
      _exit(126);
    }
    ::execl(CF_CAMERA_FIRMWARE_BIN, CF_CAMERA_FIRMWARE_BIN, config_path.c_str(),
            nullptr);
    _exit(127);
  }

  EXPECT_FALSE(WaitForSetupService(port));

  int status = 0;
  bool exited = false;
  const auto exit_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (std::chrono::steady_clock::now() < exit_deadline) {
    const pid_t waited = ::waitpid(child, &status, WNOHANG);
    if (waited == child) {
      exited = true;
      break;
    }
    ASSERT_GE(waited, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  if (!exited) {
    (void)::kill(child, SIGKILL);
    (void)::waitpid(child, &status, 0);
  }

  ASSERT_TRUE(exited);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_NE(WEXITSTATUS(status), 0);
}

// security.enabled=false takes RunFirmware's "if (security_store) {...}"
// branch out of play entirely, so this configuration is the one place TLS
// material generation (SelectServiceTlsMaterial, via ServiceApp::Init) can
// be reached without ever touching that branch. Before main.cpp threaded
// crypto_provider into service_args.provider unconditionally, ServiceApp had
// its own ad hoc, un-owned CryptoProvider it constructed just for this case;
// now that ad hoc construction is gone and SelectServiceTlsMaterial fails
// closed without an injected provider, so this configuration only starts at
// all if main.cpp's single boot-gated provider is the one actually reaching
// ServiceApp. If it is not threaded through, the HTTPS listener never opens
// and this test's WaitForSetupService call times out, exactly like the
// forced-self-test-failure test above.
TEST(FirmwareProcessCryptoSelfTestIntegrationTest,
     SecurityDisabledDevelopmentTlsUsesMainOwnedProvider) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "development-state";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t port = ReserveLoopbackPort();
  ASSERT_TRUE(std::filesystem::create_directory(state_directory));
  std::filesystem::permissions(state_directory,
                               std::filesystem::perms::owner_all,
                               std::filesystem::perm_options::replace);
  (void)WriteManagedFirmwareConfig(config_path, state_directory, port, port,
                                   /*security_enabled=*/false);

  FirmwareProcess process(config_path);

  ASSERT_TRUE(WaitForSetupService(port, "/api/v1/health"));
}

TEST(HttpsAuthIntegrationTest, ProductionDefaultsWireSecurityServices) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    const std::uint16_t port = ReserveLoopbackPort();
    const std::string origin = "https://127.0.0.1:" + std::to_string(port);
    camera_firmware::config::AppConfig config;
    config.security.enabled = true;
    config.security.state_directory = directory.path().string();
    config.http.enabled = true;
    config.http.bind_ip = "127.0.0.1";
    config.http.port = port;
    config.http.public_base_url = origin;
    config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
    config.http.tls.enabled = true;
    config.http.tls.allow_development_self_signed_tls = true;
    config.secure_rtsp.client_auth.enabled = true;
    config.secure_rtsp.client_auth.realm = "camera-test";
    config.secure_rtsp.client_auth.algorithms = {"sha-256"};
    config.secure_rtsp.client_auth.credential_file =
        (directory.path() / "rtsp.credentials").string();

    camera_firmware::service::ServiceInitArgs args;
    args.app_config = &config;
    args.provider = &TestCryptoProvider();
    args.document_root = config.http.web_root;
    args.public_base_url = origin;
    std::atomic<int> runtime_start_calls{0};
    args.runtime_start_callback = [&] {
      runtime_start_calls.fetch_add(1);
      return camera_firmware::common::Result<void>::Ok();
    };
    camera_firmware::service::ServiceApp service;
    auto started = service.Init(args);
    if (!started.ok()) {
      _exit(2);
    }
    auto client = NewClient(port);
    auto status = Send(client, drogon::Get, "/api/v1/setup/status");
    if (status.result != drogon::ReqResult::Ok || !status.response ||
        status.response->statusCode() != drogon::k200OK) {
      _exit(3);
    }
    const std::string setup_body =
        R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})";
    auto setup =
        Send(client, drogon::Post, "/api/v1/setup/initialize", setup_body,
             origin, InitialAccountCookie(client, origin), true);
    if (setup.result != drogon::ReqResult::Ok || !setup.response ||
        setup.response->statusCode() != drogon::k200OK ||
        setup.response->getJsonObject() == nullptr ||
        (*setup.response->getJsonObject())["required"].asBool() ||
        (*setup.response->getJsonObject())["runtime"].asString() != "running" ||
        runtime_start_calls.load() != 1) {
      _exit(4);
    }
    auto login = Send(client, drogon::Post, "/api/v1/auth/login",
                      R"({"username":"owner1","password":"StrongPass9!"})",
                      origin, {}, true);
    if (login.result != drogon::ReqResult::Ok || !login.response ||
        login.response->statusCode() != drogon::k200OK ||
        login.response->getCookie("camera_session").value().empty()) {
      _exit(5);
    }
    service.Stop();
    _exit(0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest,
     ProductionInvalidRoleLoginRejectsBeforeSessionCommit) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    const std::uint16_t port = ReserveLoopbackPort();
    const std::string origin = "https://127.0.0.1:" + std::to_string(port);
    camera_firmware::config::AppConfig config;
    config.security.enabled = true;
    config.security.state_directory = directory.path().string();
    config.http.enabled = true;
    config.http.bind_ip = "127.0.0.1";
    config.http.port = port;
    config.http.public_base_url = origin;
    config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
    config.http.tls.enabled = true;
    config.http.tls.allow_development_self_signed_tls = true;
    config.secure_rtsp.client_auth.enabled = true;
    config.secure_rtsp.client_auth.realm = "camera-test";
    config.secure_rtsp.client_auth.algorithms = {"sha-256"};
    config.secure_rtsp.client_auth.credential_file =
        (directory.path() / "rtsp.credentials").string();

    camera_firmware::service::ServiceInitArgs args;
    args.app_config = &config;
    args.provider = &TestCryptoProvider();
    args.document_root = config.http.web_root;
    args.public_base_url = origin;
    args.runtime_start_callback = [] {
      return camera_firmware::common::Result<void>::Ok();
    };
    camera_firmware::service::ServiceApp service;
    if (!service.Init(args).ok()) {
      _exit(2);
    }
    const auto fail = [&service](int code) {
      service.Stop();
      _exit(code);
    };
    auto client = NewClient(port);
    const auto setup = Send(
        client, drogon::Post, "/api/v1/setup/initialize",
        R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
        origin, InitialAccountCookie(client, origin), true);
    if (!setup.response || setup.response->statusCode() != drogon::k200OK) {
      fail(3);
    }

    camera_firmware::service::internal::ForceNextLoginRoleInvalidForTesting();
    const auto rejected = Send(
        client, drogon::Post, "/api/v1/auth/login",
        R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
    if (!rejected.response ||
        rejected.response->statusCode() != drogon::k503ServiceUnavailable ||
        rejected.response->getJsonObject() == nullptr ||
        !rejected.response->getCookie("camera_session").value().empty()) {
      fail(4);
    }
    const auto& error = *rejected.response->getJsonObject();
    if (!error.isObject() || error.size() != 2U ||
        error["code"].asString() != "E_SECURITY_UNAVAILABLE" ||
        error["message"].asString() != "security service unavailable") {
      fail(5);
    }

    const auto retried = Send(
        client, drogon::Post, "/api/v1/auth/login",
        R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
    if (!retried.response || retried.response->statusCode() != drogon::k200OK ||
        retried.response->getJsonObject() == nullptr ||
        (*retried.response->getJsonObject())["role"].asString() !=
            "administrator" ||
        retried.response->getCookie("camera_session").value().empty()) {
      fail(6);
    }
    service.Stop();
    _exit(0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest,
     ProductionUserManagementWiringReturnsRealRolesAndExactPrincipalFields) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    const std::uint16_t port = ReserveLoopbackPort();
    const std::string origin = "https://127.0.0.1:" + std::to_string(port);
    camera_firmware::config::AppConfig config;
    config.security.enabled = true;
    config.security.state_directory = directory.path().string();
    config.http.enabled = true;
    config.http.bind_ip = "127.0.0.1";
    config.http.port = port;
    config.http.public_base_url = origin;
    config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
    config.http.tls.enabled = true;
    config.http.tls.allow_development_self_signed_tls = true;
    config.secure_rtsp.client_auth.enabled = true;
    config.secure_rtsp.client_auth.realm = "camera-test";
    config.secure_rtsp.client_auth.algorithms = {"sha-256"};
    config.secure_rtsp.client_auth.credential_file =
        (directory.path() / "rtsp.credentials").string();

    auto opened = camera_firmware::security::SecurityStore::Open(
        {config.security.state_directory});
    if (!opened.ok()) {
      _exit(2);
    }
    auto store = std::shared_ptr<camera_firmware::security::SecurityStore>(
        std::move(opened).value());
    camera_firmware::service::ServiceInitArgs args;
    args.app_config = &config;
    args.provider = &TestCryptoProvider();
    args.document_root = config.http.web_root;
    args.public_base_url = origin;
    args.security_store = store;
    args.runtime_start_callback = [] {
      return camera_firmware::common::Result<void>::Ok();
    };

    camera_firmware::service::ServiceApp service;
    if (!service.Init(args).ok()) {
      _exit(3);
    }
    if (!camera_firmware::service::internal::
            HasRetainedUserManagementServiceForTesting()) {
      service.Stop();
      _exit(4);
    }
    const auto fail = [&service](int code) {
      service.Stop();
      _exit(code);
    };
    auto client = NewClient(port);
    const auto setup = Send(
        client, drogon::Post, "/api/v1/setup/initialize",
        R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
        origin, InitialAccountCookie(client, origin), true);
    if (!setup.response || setup.response->statusCode() != drogon::k200OK) {
      fail(5);
    }

    camera_firmware::security::UserManagementService users(
        *store, camera_firmware::security::BuildReservedIdentities(config));
    const auto managed = users.ListUsers();
    if (!managed.ok() || managed.value().size() != 1U) {
      fail(6);
    }
    camera_firmware::security::UserMutationContext administrator;
    administrator.actor.user_id = managed.value().front().id;
    administrator.actor.username = "owner1";
    administrator.actor.role =
        camera_firmware::security::UserRole::kAdministrator;
    administrator.normalized_peer_ip = "127.0.0.1";
    camera_firmware::common::SecureBytes viewer_password;
    constexpr std::string_view kViewerPassword = "ViewerPass9!";
    viewer_password.assign(
        reinterpret_cast<const unsigned char*>(kViewerPassword.data()),
        kViewerPassword.size());
    const auto created = users.CreateViewer(
        "viewer1", std::move(viewer_password), administrator);
    if (!created.ok()) {
      fail(7);
    }
    const auto viewer_management_ip =
        users.AddManagementIp(camera_firmware::security::UserRole::kViewer,
                              "127.0.0.2", administrator);
    if (!viewer_management_ip.ok()) {
      fail(8);
    }
    const auto retained_users =
        camera_firmware::service::internal::ListRetainedUsersForTesting();
    if (!retained_users.ok() || retained_users.value().size() != 2U) {
      fail(9);
    }
    const auto has_user = [&retained_users](
                              std::string_view username,
                              camera_firmware::security::UserRole role) {
      return std::any_of(
          retained_users.value().begin(), retained_users.value().end(),
          [username, role](const camera_firmware::security::ManagedUser& user) {
            return user.username == username && user.role == role;
          });
    };
    if (!has_user("owner1",
                  camera_firmware::security::UserRole::kAdministrator) ||
        !has_user("viewer1", camera_firmware::security::UserRole::kViewer)) {
      fail(10);
    }

    const auto assert_login_and_me =
        [&origin](const drogon::HttpClientPtr& login_client,
                  std::string_view username, std::string_view password,
                  std::string_view expected_role) -> bool {
      const auto login =
          Send(login_client, drogon::Post, "/api/v1/auth/login",
               "{\"username\":\"" + std::string(username) +
                   "\",\"password\":\"" + std::string(password) + "\"}",
               origin, {}, true);
      if (!login.response || login.response->statusCode() != drogon::k200OK ||
          login.response->getJsonObject() == nullptr ||
          (*login.response->getJsonObject())["role"].asString() !=
              expected_role) {
        return false;
      }
      const auto& session_cookie = login.response->getCookie("camera_session");
      if (session_cookie.value().empty()) {
        return false;
      }
      const auto me = Send(login_client, drogon::Get, "/api/v1/auth/me", {}, {},
                           "camera_session=" + session_cookie.value());
      if (!me.response || me.response->statusCode() != drogon::k200OK ||
          me.response->getJsonObject() == nullptr) {
        return false;
      }
      const auto& principal = *me.response->getJsonObject();
      return principal.isObject() && principal.size() == 2U &&
             principal.isMember("username") && principal.isMember("role") &&
             principal["username"].asString() == username &&
             principal["role"].asString() == expected_role;
    };

    if (!assert_login_and_me(client, "owner1", "StrongPass9!",
                             "administrator")) {
      fail(11);
    }
    auto viewer_client = NewClient(port, "127.0.0.2");
    if (!assert_login_and_me(viewer_client, "viewer1", "ViewerPass9!",
                             "viewer")) {
      fail(12);
    }
    service.Stop();
    if (camera_firmware::service::internal::
            HasRetainedUserManagementServiceForTesting()) {
      _exit(13);
    }
    if (camera_firmware::service::internal::ListRetainedUsersForTesting()
            .ok()) {
      _exit(14);
    }
    _exit(0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunAdministratorUserLifecycleScenario(
    const std::filesystem::path& state_directory,
    bool force_pre_submit_failure = false) {
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = state_directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "camera-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (state_directory / "rtsp.credentials").string();
  auto opened_store = camera_firmware::security::SecurityStore::Open(
      {config.security.state_directory});
  ASSERT_TRUE(opened_store.ok()) << opened_store.error().message;
  auto store = std::shared_ptr<camera_firmware::security::SecurityStore>(
      std::move(opened_store).value());

  struct StreamState {
    std::mutex mutex;
    std::condition_variable changed;
    bool live_read_started{false};
    bool live_cancelled{false};
    std::size_t live_cancel_calls{0U};
  };
  auto stream_state = std::make_shared<StreamState>();
  std::promise<void> sse_subscribed;
  auto sse_subscribed_future = sse_subscribed.get_future();
  std::atomic_bool sse_subscription_published{false};

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.security_store = store;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.cancellable_live_stream_callback = [stream_state](const std::string&) {
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read =
            [stream_state](char*, std::size_t) {
              std::unique_lock lock(stream_state->mutex);
              stream_state->live_read_started = true;
              stream_state->changed.notify_all();
              stream_state->changed.wait(
                  lock, [&] { return stream_state->live_cancelled; });
              return std::size_t{0U};
            },
        .cancel =
            [stream_state] {
              std::lock_guard lock(stream_state->mutex);
              ++stream_state->live_cancel_calls;
              stream_state->live_cancelled = true;
              stream_state->changed.notify_all();
            },
    });
  };
  args.detection_event_subscriber =
      [&sse_subscribed, &sse_subscription_published](
          camera_firmware::ai::DetectionBus::Handler) {
        if (!sse_subscription_published.exchange(true)) {
          sse_subscribed.set_value();
        }
        return camera_firmware::ai::DetectionBus::Subscription{};
      };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  const auto stop_service = [&service] { service.Stop(); };
  auto client = NewClient(port);

  const auto expect_fields = [](const Json::Value& value,
                                std::vector<std::string> expected) {
    ASSERT_TRUE(value.isObject());
    auto actual = value.getMemberNames();
    std::sort(actual.begin(), actual.end());
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(actual, expected);
  };
  const auto expect_error = [&expect_fields](const HttpResult& result,
                                             drogon::HttpStatusCode status,
                                             std::string_view code) {
    ExpectStatus(result, status);
    ASSERT_NE(result.response->getJsonObject(), nullptr);
    expect_fields(*result.response->getJsonObject(), {"code", "message"});
    EXPECT_EQ((*result.response->getJsonObject())["code"].asString(), code);
  };
  const auto user_fields =
      std::vector<std::string>{"created_at_seconds",
                               "enabled",
                               "id",
                               "last_login_at_seconds",
                               "lock_until_seconds",
                               "password_changed_at_seconds",
                               "role",
                               "username"};

  auto setup = Send(
      client, drogon::Post, "/api/v1/setup/initialize",
      R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
      origin, InitialAccountCookie(client, origin), true);
  ExpectStatus(setup, drogon::k200OK);

  auto administrator_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
  ExpectStatus(administrator_login, drogon::k200OK);
  const std::string administrator_cookie =
      "camera_session=" +
      administrator_login.response->getCookie("camera_session").value();

  camera_firmware::service::internal::
      FailNextAuthorizationDispatchQueueForTesting();
  const auto authorization_dispatch_failure =
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, administrator_cookie,
           false, 1.0);
  camera_firmware::service::internal::
      ResetAuthorizationDispatchQueueFailureForTesting();
  expect_error(authorization_dispatch_failure, drogon::k503ServiceUnavailable,
               "E_SECURITY_UNAVAILABLE");

  camera_firmware::service::internal::FailNextTerminalResponseQueueForTesting();
  const auto terminal_queue_failure =
      Send(client, drogon::Get, "/api/v1/security/users", {}, {},
           administrator_cookie, false, 1.0);
  camera_firmware::service::internal::
      ResetTerminalResponseQueueFailureForTesting();
  expect_error(terminal_queue_failure, drogon::k503ServiceUnavailable,
               "E_USER_MANAGEMENT_UNAVAILABLE");

  ResetUserManagementBodyCleanupForTesting();
  camera_firmware::service::internal::
      SetUserManagementRequestBodyCleanupObserverForTesting(
          RecordUserManagementBodyCleanupForTesting);
  const std::string denied_create_secret = "DeniedCreatePass9!";
  const auto denied_create =
      Send(client, drogon::Post, "/api/v1/security/users",
           "{\"username\":\"denied-viewer\",\"password\":\"" +
               denied_create_secret + "\"}",
           origin, {}, true);
  expect_error(denied_create, drogon::k401Unauthorized,
               "E_AUTHENTICATION_REQUIRED");
  const std::string denied_reset_secret = "DeniedResetPass9!";
  const auto denied_reset =
      Send(client, drogon::Put, "/api/v1/security/users/1/password",
           "{\"password\":\"" + denied_reset_secret + "\"}", origin, {}, true);
  expect_error(denied_reset, drogon::k401Unauthorized,
               "E_AUTHENTICATION_REQUIRED");
  ASSERT_NE(denied_create.response, nullptr);
  ASSERT_NE(denied_reset.response, nullptr);
  EXPECT_EQ(denied_create.response->getBody().find(denied_create_secret),
            std::string::npos);
  EXPECT_EQ(denied_reset.response->getBody().find(denied_reset_secret),
            std::string::npos);
  const auto& denied_cleanup = UserManagementBodyCleanupForTesting();
  EXPECT_EQ(denied_cleanup.calls.load(std::memory_order_relaxed), 2U);
  EXPECT_EQ(
      denied_cleanup.copied_to_secure_owner.load(std::memory_order_relaxed),
      2U);
  EXPECT_TRUE(denied_cleanup.source_cleansed.load(std::memory_order_relaxed));
  camera_firmware::service::internal::
      ResetUserManagementRequestBodyCleanupObserverForTesting();

  expect_error(Send(client, drogon::Get, "/api/v1/security/users"),
               drogon::k401Unauthorized, "E_AUTHENTICATION_REQUIRED");

  const std::string viewer_body =
      R"({"username":"viewer1","password":"ViewerPass9!"})";
  if (force_pre_submit_failure) {
    UserManagementPreSubmitFailureScope failure_scope;
    const auto failed = Send(client, drogon::Post, "/api/v1/security/users",
                             viewer_body, origin, administrator_cookie, true);
    expect_error(failed, drogon::k503ServiceUnavailable,
                 "E_USER_MANAGEMENT_UNAVAILABLE");
    if (failed.response) {
      EXPECT_TRUE(failed.response->getHeader("Set-Cookie").empty());
      EXPECT_EQ(failed.response->getBody().find("ViewerPass9!"),
                std::string::npos);
    }
    const auto& failure_cleanup = UserManagementBodyCleanupForTesting();
    EXPECT_EQ(failure_cleanup.calls.load(std::memory_order_relaxed), 1U);
    EXPECT_EQ(
        failure_cleanup.copied_to_secure_owner.load(std::memory_order_relaxed),
        1U);
    EXPECT_TRUE(
        failure_cleanup.source_cleansed.load(std::memory_order_relaxed));
  }

  auto created = Send(client, drogon::Post, "/api/v1/security/users",
                      viewer_body, origin, administrator_cookie, true);
  ExpectStatus(created, drogon::k201Created);
  ASSERT_NE(created.response->getJsonObject(), nullptr);
  expect_fields(*created.response->getJsonObject(), {"user"});
  const auto& created_user = (*created.response->getJsonObject())["user"];
  expect_fields(created_user, user_fields);
  EXPECT_EQ(created_user["username"].asString(), "viewer1");
  EXPECT_EQ(created_user["role"].asString(), "viewer");
  const std::int64_t viewer_id = created_user["id"].asInt64();

  ResetUserManagementBodyCleanupForTesting();
  camera_firmware::service::internal::
      SetUserManagementRequestBodyCleanupObserverForTesting(
          RecordUserManagementBodyCleanupForTesting);
  const std::string oversized_user_body(
      camera_firmware::service::kMaximumSecurityBodyBytes + 1U, 'x');
  expect_error(Send(client, drogon::Post, "/api/v1/security/users",
                    oversized_user_body, origin, administrator_cookie, true),
               drogon::k413RequestEntityTooLarge, "E_REQUEST_TOO_LARGE");
  expect_error(
      Send(client, drogon::Put,
           "/api/v1/security/users/" + std::to_string(viewer_id) + "/password",
           oversized_user_body, origin, administrator_cookie, true),
      drogon::k413RequestEntityTooLarge, "E_REQUEST_TOO_LARGE");
  const auto& body_cleanup = UserManagementBodyCleanupForTesting();
  EXPECT_EQ(body_cleanup.calls.load(std::memory_order_relaxed), 2U);
  EXPECT_EQ(
      body_cleanup.over_limit_without_copy.load(std::memory_order_relaxed), 2U);
  EXPECT_TRUE(body_cleanup.source_cleansed.load(std::memory_order_relaxed));
  camera_firmware::service::internal::
      ResetUserManagementRequestBodyCleanupObserverForTesting();

  ResetUserManagementBodyCleanupForTesting();
  camera_firmware::service::internal::
      SetUserManagementRequestBodyCleanupObserverForTesting(
          RecordUserManagementBodyCleanupForTesting);
  for (const auto& [method, path] :
       std::array<std::pair<drogon::HttpMethod, std::string>, 5>{{
           {drogon::Put, "/api/v1/security/users/0/enabled"},
           {drogon::Put, "/api/v1/security/users/+7/password"},
           {drogon::Delete, "/api/v1/security/users/07"},
           {drogon::Delete, "/api/v1/security/users/9223372036854775808"},
           {drogon::Delete, "/api/v1/security/users/7x"},
       }}) {
    const std::string body =
        path.ends_with("/enabled")
            ? R"({"enabled":false})"
            : (method == drogon::Put ? R"({"password":"ViewerPass9!"})"
                                     : std::string{});
    expect_error(
        Send(client, method, path, body, origin, administrator_cookie, true),
        drogon::k400BadRequest, "E_INVALID_REQUEST");
  }
  EXPECT_EQ(body_cleanup.calls.load(std::memory_order_relaxed), 1U);
  EXPECT_EQ(body_cleanup.copied_to_secure_owner.load(std::memory_order_relaxed),
            1U);
  EXPECT_TRUE(body_cleanup.source_cleansed.load(std::memory_order_relaxed));
  camera_firmware::service::internal::
      ResetUserManagementRequestBodyCleanupObserverForTesting();
  expect_error(
      Send(client, drogon::Put, "/api/v1/security/users/7/enabled/extra",
           R"({"enabled":false})", origin, administrator_cookie, true),
      drogon::k404NotFound, "E_NOT_FOUND");
  const auto malformed_list =
      Send(client, drogon::Get, "/api/v1/security/users", {}, {},
           administrator_cookie);
  ExpectStatus(malformed_list, drogon::k200OK);
  ASSERT_NE(malformed_list.response->getJsonObject(), nullptr);
  ASSERT_EQ((*malformed_list.response->getJsonObject())["users"].size(), 2U);

  expect_error(Send(client, drogon::Post, "/api/v1/security/users",
                    R"({"username":"viewer1","password":"ViewerPass9!"})",
                    origin, administrator_cookie, true),
               drogon::k409Conflict, "E_USER_DUPLICATE");

  auto listed = Send(client, drogon::Get, "/api/v1/security/users", {}, {},
                     administrator_cookie);
  ExpectStatus(listed, drogon::k200OK);
  ASSERT_NE(listed.response->getJsonObject(), nullptr);
  expect_fields(*listed.response->getJsonObject(), {"users"});
  const auto& users = (*listed.response->getJsonObject())["users"];
  ASSERT_TRUE(users.isArray());
  ASSERT_EQ(users.size(), 2U);
  expect_fields(users[0U], user_fields);
  expect_fields(users[1U], user_fields);
  EXPECT_EQ(users[0U]["username"].asString(), "owner1");
  EXPECT_EQ(users[1U]["username"].asString(), "viewer1");
  const auto repeated_list = Send(client, drogon::Get, "/api/v1/security/users",
                                  {}, {}, administrator_cookie);
  ExpectStatus(repeated_list, drogon::k200OK);
  ASSERT_NE(repeated_list.response->getJsonObject(), nullptr);
  EXPECT_EQ((*repeated_list.response->getJsonObject())["users"], users);

  camera_firmware::security::UserManagementService user_management(
      *store, camera_firmware::security::BuildReservedIdentities(config));
  camera_firmware::security::UserMutationContext administrator_context;
  administrator_context.actor.user_id = users[0U]["id"].asInt64();
  administrator_context.actor.username = "owner1";
  administrator_context.actor.role =
      camera_firmware::security::UserRole::kAdministrator;
  administrator_context.normalized_peer_ip = "127.0.0.1";
  const auto viewer_management_ip = user_management.AddManagementIp(
      camera_firmware::security::UserRole::kViewer, "127.0.0.1",
      administrator_context);
  ASSERT_TRUE(viewer_management_ip.ok())
      << viewer_management_ip.error().message;

  auto viewer_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"viewer1","password":"ViewerPass9!"})", origin, {}, true);
  ExpectStatus(viewer_login, drogon::k200OK);
  const std::string viewer_cookie =
      "camera_session=" +
      viewer_login.response->getCookie("camera_session").value();
  expect_error(Send(client, drogon::Get, "/api/v1/security/users", {}, {},
                    viewer_cookie),
               drogon::k403Forbidden, "E_AUTHORIZATION_REQUIRED");

  auto live_request = std::async(std::launch::async, [port, viewer_cookie] {
    return RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4",
                       {viewer_cookie});
  });
  {
    std::unique_lock lock(stream_state->mutex);
    ASSERT_TRUE(stream_state->changed.wait_for(
        lock, std::chrono::seconds(5),
        [&] { return stream_state->live_read_started; }));
  }
  auto sse_request = std::async(std::launch::async, [port, viewer_cookie] {
    return RawHttpsGet(port, "/api/v1/ai/detections/stream", {viewer_cookie});
  });
  ASSERT_EQ(sse_subscribed_future.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);

  auto disabled =
      Send(client, drogon::Put,
           "/api/v1/security/users/" + std::to_string(viewer_id) + "/enabled",
           R"({"enabled":false})", origin, administrator_cookie, true);
  ExpectStatus(disabled, drogon::k200OK);
  ASSERT_NE(disabled.response->getJsonObject(), nullptr);
  expect_fields(*disabled.response->getJsonObject(), {"updated"});
  EXPECT_TRUE((*disabled.response->getJsonObject())["updated"].asBool());
  ASSERT_EQ(live_request.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  EXPECT_EQ(live_request.get().status, 200);
  ASSERT_EQ(sse_request.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  EXPECT_EQ(sse_request.get().status, 200);
  {
    std::lock_guard lock(stream_state->mutex);
    EXPECT_EQ(stream_state->live_cancel_calls, 1U);
  }
  expect_error(
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, viewer_cookie),
      drogon::k401Unauthorized, "E_AUTHENTICATION_REQUIRED");
  expect_error(Send(client, drogon::Post, "/api/v1/auth/login",
                    R"({"username":"viewer1","password":"ViewerPass9!"})",
                    origin, {}, true),
               drogon::k401Unauthorized, "E_AUTHENTICATION_FAILED");

  auto enabled =
      Send(client, drogon::Put,
           "/api/v1/security/users/" + std::to_string(viewer_id) + "/enabled",
           R"({"enabled":true})", origin, administrator_cookie, true);
  ExpectStatus(enabled, drogon::k200OK);
  ASSERT_NE(enabled.response->getJsonObject(), nullptr);
  expect_fields(*enabled.response->getJsonObject(), {"updated"});
  EXPECT_TRUE((*enabled.response->getJsonObject())["updated"].asBool());

  auto reenabled_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"viewer1","password":"ViewerPass9!"})", origin, {}, true);
  ExpectStatus(reenabled_login, drogon::k200OK);
  const std::string reenabled_cookie =
      "camera_session=" +
      reenabled_login.response->getCookie("camera_session").value();
  auto reset = Send(
      client, drogon::Put,
      "/api/v1/security/users/" + std::to_string(viewer_id) + "/password",
      R"({"password":"ChangedPass9!"})", origin, administrator_cookie, true);
  ExpectStatus(reset, drogon::k200OK);
  ASSERT_NE(reset.response->getJsonObject(), nullptr);
  expect_fields(*reset.response->getJsonObject(), {"password_reset"});
  EXPECT_TRUE((*reset.response->getJsonObject())["password_reset"].asBool());
  expect_error(
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, reenabled_cookie),
      drogon::k401Unauthorized, "E_AUTHENTICATION_REQUIRED");
  expect_error(Send(client, drogon::Post, "/api/v1/auth/login",
                    R"({"username":"viewer1","password":"ViewerPass9!"})",
                    origin, {}, true),
               drogon::k401Unauthorized, "E_AUTHENTICATION_FAILED");
  auto replacement_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"viewer1","password":"ChangedPass9!"})", origin, {}, true);
  ExpectStatus(replacement_login, drogon::k200OK);
  const std::string replacement_cookie =
      "camera_session=" +
      replacement_login.response->getCookie("camera_session").value();

  for (std::size_t index = 2U;
       index <= camera_firmware::security::kMaximumViewerUsers; ++index) {
    const auto created_viewer =
        Send(client, drogon::Post, "/api/v1/security/users",
             "{\"username\":\"viewer" + std::to_string(index) +
                 "\",\"password\":\"ViewerPass9!\"}",
             origin, administrator_cookie, true);
    ExpectStatus(created_viewer, drogon::k201Created);
  }
  expect_error(
      Send(client, drogon::Post, "/api/v1/security/users",
           R"({"username":"viewer-over-limit","password":"ViewerPass9!"})",
           origin, administrator_cookie, true),
      drogon::k409Conflict, "E_VIEWER_LIMIT");
  expect_error(Send(client, drogon::Delete,
                    "/api/v1/security/users/" +
                        std::to_string(users[0U]["id"].asInt64()),
                    {}, origin, administrator_cookie, true),
               drogon::k409Conflict, "E_USER_PROTECTED");

  auto deleted = Send(client, drogon::Delete,
                      "/api/v1/security/users/" + std::to_string(viewer_id), {},
                      origin, administrator_cookie, true);
  ExpectStatus(deleted, drogon::k200OK);
  ASSERT_NE(deleted.response->getJsonObject(), nullptr);
  expect_fields(*deleted.response->getJsonObject(), {"deleted"});
  EXPECT_TRUE((*deleted.response->getJsonObject())["deleted"].asBool());
  expect_error(
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, replacement_cookie),
      drogon::k401Unauthorized, "E_AUTHENTICATION_REQUIRED");
  expect_error(Send(client, drogon::Delete,
                    "/api/v1/security/users/" + std::to_string(viewer_id), {},
                    origin, administrator_cookie, true),
               drogon::k404NotFound, "E_USER_NOT_FOUND");

  stop_service();
}

TEST(HttpsAuthIntegrationTest,
     AdministratorUserLifecycleUsesExactContractsAndRevokesViewerLeases) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(90U);
    RunAdministratorUserLifecycleScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest,
     AdministratorUserPreSubmitFailureIsSanitizedAndDoesNotCreateUser) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(90U);
    RunAdministratorUserLifecycleScenario(directory.path(), true);
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunAdministratorManagementIpLifecycleScenario(
    const std::filesystem::path& state_directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = state_directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "camera-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (state_directory / "rtsp.credentials").string();

  struct LiveHandleState {
    std::mutex mutex;
    std::condition_variable changed;
    bool read_started{false};
    bool cancelled{false};
    std::size_t cancel_calls{0U};
  };
  struct LiveStreamState {
    std::mutex mutex;
    std::condition_variable changed;
    std::vector<std::pair<std::string, std::shared_ptr<LiveHandleState>>>
        handles;
  };
  auto live_streams = std::make_shared<LiveStreamState>();
  struct SseStreamState {
    std::mutex mutex;
    std::condition_variable changed;
    std::size_t subscriptions{0U};
  };
  auto sse_streams = std::make_shared<SseStreamState>();

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.cancellable_live_stream_callback =
      [live_streams](const std::string& camera_id) {
        auto handle = std::make_shared<LiveHandleState>();
        {
          std::lock_guard lock(live_streams->mutex);
          live_streams->handles.emplace_back(camera_id, handle);
        }
        live_streams->changed.notify_all();
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamHandle>::Ok({
            .read =
                [handle](char*, std::size_t) {
                  std::unique_lock lock(handle->mutex);
                  handle->read_started = true;
                  handle->changed.notify_all();
                  handle->changed.wait(lock, [&] { return handle->cancelled; });
                  return std::size_t{0U};
                },
            .cancel =
                [handle] {
                  std::lock_guard lock(handle->mutex);
                  ++handle->cancel_calls;
                  handle->cancelled = true;
                  handle->changed.notify_all();
                },
        });
      };
  args.detection_event_subscriber =
      [sse_streams](camera_firmware::ai::DetectionBus::Handler) {
        {
          std::lock_guard lock(sse_streams->mutex);
          ++sse_streams->subscriptions;
        }
        sse_streams->changed.notify_all();
        return camera_firmware::ai::DetectionBus::Subscription{};
      };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);

  const auto expect_fields = [](const Json::Value& value,
                                std::vector<std::string> expected) {
    ASSERT_TRUE(value.isObject());
    auto actual = value.getMemberNames();
    std::sort(actual.begin(), actual.end());
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(actual, expected);
  };
  const auto expect_error = [&expect_fields](const HttpResult& result,
                                             drogon::HttpStatusCode status,
                                             std::string_view code) {
    ExpectStatus(result, status);
    ASSERT_NE(result.response->getJsonObject(), nullptr);
    expect_fields(*result.response->getJsonObject(), {"code", "message"});
    EXPECT_EQ((*result.response->getJsonObject())["code"].asString(), code);
  };
  const std::vector<std::string> management_ip_fields = {
      "address", "created_at_seconds", "id", "role"};
  const auto wait_for_live_start = [live_streams](std::string_view camera_id) {
    std::shared_ptr<LiveHandleState> handle;
    {
      std::unique_lock lock(live_streams->mutex);
      const bool published =
          live_streams->changed.wait_for(lock, std::chrono::seconds(5), [&] {
            return std::any_of(live_streams->handles.begin(),
                               live_streams->handles.end(),
                               [camera_id](const auto& entry) {
                                 return entry.first == camera_id;
                               });
          });
      EXPECT_TRUE(published);
      if (!published) {
        return handle;
      }
      handle = std::find_if(live_streams->handles.begin(),
                            live_streams->handles.end(),
                            [camera_id](const auto& entry) {
                              return entry.first == camera_id;
                            })
                   ->second;
    }
    std::unique_lock lock(handle->mutex);
    EXPECT_TRUE(handle->changed.wait_for(lock, std::chrono::seconds(5),
                                         [&] { return handle->read_started; }));
    return handle;
  };
  const auto wait_for_sse_subscriptions = [sse_streams](std::size_t expected) {
    std::unique_lock lock(sse_streams->mutex);
    EXPECT_TRUE(sse_streams->changed.wait_for(
        lock, std::chrono::seconds(5),
        [&] { return sse_streams->subscriptions >= expected; }));
  };

  ExpectStatus(
      Send(
          client, drogon::Post, "/api/v1/setup/initialize",
          R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
          origin, InitialAccountCookie(client, origin), true),
      drogon::k200OK);
  const auto administrator_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
  ExpectStatus(administrator_login, drogon::k200OK);
  const std::string administrator_cookie =
      "camera_session=" +
      administrator_login.response->getCookie("camera_session").value();

  const auto initial_list =
      Send(client, drogon::Get, "/api/v1/security/management-ips", {}, {},
           administrator_cookie);
  ExpectStatus(initial_list, drogon::k200OK);
  ASSERT_NE(initial_list.response->getJsonObject(), nullptr);
  expect_fields(*initial_list.response->getJsonObject(),
                {"management_ips", "current_peer_ip"});
  EXPECT_EQ(
      (*initial_list.response->getJsonObject())["current_peer_ip"].asString(),
      "127.0.0.1");
  const auto& initial_entries =
      (*initial_list.response->getJsonObject())["management_ips"];
  ASSERT_TRUE(initial_entries.isArray());
  ASSERT_EQ(initial_entries.size(), 1U);
  expect_fields(initial_entries[0U], management_ip_fields);
  EXPECT_EQ(initial_entries[0U]["address"].asString(), "127.0.0.1");
  EXPECT_EQ(initial_entries[0U]["role"].asString(), "administrator");
  const std::int64_t initial_administrator_ip_id =
      initial_entries[0U]["id"].asInt64();
  const auto spoofed_list =
      Send(client, drogon::Get, "/api/v1/security/management-ips", {}, {},
           administrator_cookie, false, 15.0,
           {{"X-Forwarded-For", "203.0.113.9"},
            {"Forwarded", "for=203.0.113.10"},
            {"Host", "203.0.113.11"}});
  ExpectStatus(spoofed_list, drogon::k200OK);
  ASSERT_NE(spoofed_list.response->getJsonObject(), nullptr);
  EXPECT_EQ(
      (*spoofed_list.response->getJsonObject())["current_peer_ip"].asString(),
      "127.0.0.1");
  expect_error(Send(client, drogon::Get, "/api/v1/security/management-ips",
                    "{}", {}, administrator_cookie),
               drogon::k400BadRequest, "E_INVALID_REQUEST");

  for (const std::string& path : {
           "/api/v1/security/management-ips/operator",
           "/api/v1/security/management-ips/viewer/0",
           "/api/v1/security/management-ips/viewer/+7",
           "/api/v1/security/management-ips/viewer/07",
           "/api/v1/security/management-ips/viewer/9223372036854775808",
           "/api/v1/security/management-ips/viewer/7x",
       }) {
    const auto method = path.ends_with("operator") ? drogon::Post : drogon::Put;
    expect_error(Send(client, method, path, R"({"address":"192.0.2.20"})",
                      origin, administrator_cookie, true),
                 drogon::k400BadRequest, "E_INVALID_REQUEST");
  }
  expect_error(
      Send(client, drogon::Put,
           "/api/v1/security/management-ips/viewer/7/extra",
           R"({"address":"192.0.2.20"})", origin, administrator_cookie, true),
      drogon::k404NotFound, "E_NOT_FOUND");

  const auto add_management_ip = [&](std::string_view role,
                                     std::string_view address) {
    return Send(client, drogon::Post,
                "/api/v1/security/management-ips/" + std::string(role),
                "{\"address\":\"" + std::string(address) + "\"}", origin,
                administrator_cookie, true);
  };
  const auto update_management_ip = [&](std::string_view role, std::int64_t id,
                                        std::string_view address) {
    return Send(client, drogon::Put,
                "/api/v1/security/management-ips/" + std::string(role) + "/" +
                    std::to_string(id),
                "{\"address\":\"" + std::string(address) + "\"}", origin,
                administrator_cookie, true);
  };
  const auto delete_management_ip = [&](std::string_view role, std::int64_t id,
                                        std::string body = {}) {
    return Send(client, drogon::Delete,
                "/api/v1/security/management-ips/" + std::string(role) + "/" +
                    std::to_string(id),
                std::move(body), origin, administrator_cookie, true);
  };

  const auto viewer_ipv4 = add_management_ip("viewer", "127.0.0.1");
  ExpectStatus(viewer_ipv4, drogon::k201Created);
  ASSERT_NE(viewer_ipv4.response->getJsonObject(), nullptr);
  expect_fields(*viewer_ipv4.response->getJsonObject(), {"management_ip"});
  const auto& viewer_ipv4_entry =
      (*viewer_ipv4.response->getJsonObject())["management_ip"];
  expect_fields(viewer_ipv4_entry, management_ip_fields);
  EXPECT_EQ(viewer_ipv4_entry["address"].asString(), "127.0.0.1");
  EXPECT_EQ(viewer_ipv4_entry["role"].asString(), "viewer");
  const std::int64_t viewer_ipv4_id = viewer_ipv4_entry["id"].asInt64();

  const auto viewer_ipv6 =
      add_management_ip("viewer", "2001:0db8:0:0:0:0:0:20");
  ExpectStatus(viewer_ipv6, drogon::k201Created);
  ASSERT_NE(viewer_ipv6.response->getJsonObject(), nullptr);
  const auto& viewer_ipv6_entry =
      (*viewer_ipv6.response->getJsonObject())["management_ip"];
  expect_fields(viewer_ipv6_entry, management_ip_fields);
  EXPECT_EQ(viewer_ipv6_entry["address"].asString(), "2001:db8::20");
  const std::int64_t viewer_ipv6_id = viewer_ipv6_entry["id"].asInt64();

  expect_error(add_management_ip("viewer", "2001:db8::20"),
               drogon::k409Conflict, "E_MANAGEMENT_IP_DUPLICATE");
  for (const std::string& invalid : {"not-an-ip", "0.0.0.0", "::"}) {
    expect_error(add_management_ip("viewer", invalid), drogon::k400BadRequest,
                 "E_MANAGEMENT_IP_INVALID");
  }
  expect_error(
      update_management_ip("administrator", viewer_ipv6_id, "2001:db8::21"),
      drogon::k409Conflict, "E_MANAGEMENT_IP_ROLE_MISMATCH");
  expect_error(delete_management_ip("administrator", viewer_ipv6_id),
               drogon::k409Conflict, "E_MANAGEMENT_IP_ROLE_MISMATCH");
  expect_error(delete_management_ip("viewer", viewer_ipv6_id, "{}"),
               drogon::k400BadRequest, "E_INVALID_REQUEST");

  expect_error(update_management_ip("administrator",
                                    initial_administrator_ip_id, "192.0.2.10"),
               drogon::k409Conflict, "E_MANAGEMENT_IP_PROTECTED");
  expect_error(
      delete_management_ip("administrator", initial_administrator_ip_id),
      drogon::k409Conflict, "E_MANAGEMENT_IP_PROTECTED");
  const auto second_administrator =
      add_management_ip("administrator", "192.0.2.10");
  ExpectStatus(second_administrator, drogon::k201Created);
  ASSERT_NE(second_administrator.response->getJsonObject(), nullptr);
  const std::int64_t second_administrator_id =
      (*second_administrator.response->getJsonObject())["management_ip"]["id"]
          .asInt64();
  expect_error(
      delete_management_ip("administrator", initial_administrator_ip_id),
      drogon::k409Conflict, "E_MANAGEMENT_IP_PROTECTED");
  ExpectStatus(delete_management_ip("administrator", second_administrator_id),
               drogon::k200OK);

  const auto viewer_user =
      Send(client, drogon::Post, "/api/v1/security/users",
           R"({"username":"viewer1","password":"ViewerPass9!"})", origin,
           administrator_cookie, true);
  ExpectStatus(viewer_user, drogon::k201Created);
  const auto viewer_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"viewer1","password":"ViewerPass9!"})", origin, {}, true);
  ExpectStatus(viewer_login, drogon::k200OK);
  const std::string viewer_cookie =
      "camera_session=" +
      viewer_login.response->getCookie("camera_session").value();

  const auto canonical_no_op =
      update_management_ip("viewer", viewer_ipv6_id, "2001:0db8:0:0:0:0:0:20");
  ExpectStatus(canonical_no_op, drogon::k200OK);
  const auto no_op =
      update_management_ip("viewer", viewer_ipv4_id, "127.0.0.1");
  ExpectStatus(no_op, drogon::k200OK);
  ASSERT_NE(no_op.response->getJsonObject(), nullptr);
  expect_fields(*no_op.response->getJsonObject(), {"updated"});
  EXPECT_TRUE((*no_op.response->getJsonObject())["updated"].asBool());
  ExpectStatus(
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, viewer_cookie),
      drogon::k200OK);

  auto viewer_update_live =
      std::async(std::launch::async, [port, viewer_cookie] {
        return RawHttpsGet(port, "/api/v1/cameras/viewer-update/live.mp4",
                           {viewer_cookie});
      });
  const auto viewer_update_live_state = wait_for_live_start("viewer-update");
  ASSERT_NE(viewer_update_live_state, nullptr);
  auto administrator_live =
      std::async(std::launch::async, [port, administrator_cookie] {
        return RawHttpsGet(port,
                           "/api/v1/cameras/administrator-retained/live.mp4",
                           {administrator_cookie});
      });
  const auto administrator_live_state =
      wait_for_live_start("administrator-retained");
  ASSERT_NE(administrator_live_state, nullptr);
  auto viewer_update_sse = std::async(std::launch::async, [port,
                                                           viewer_cookie] {
    return RawHttpsGet(port, "/api/v1/ai/detections/stream", {viewer_cookie});
  });
  wait_for_sse_subscriptions(1U);
  auto administrator_sse =
      std::async(std::launch::async, [port, administrator_cookie] {
        return RawHttpsGet(port, "/api/v1/ai/detections/stream",
                           {administrator_cookie});
      });
  wait_for_sse_subscriptions(2U);

  ExpectStatus(update_management_ip("viewer", viewer_ipv4_id, "198.51.100.250"),
               drogon::k200OK);
  ASSERT_EQ(viewer_update_live.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  EXPECT_EQ(viewer_update_live.get().status, 200);
  ASSERT_EQ(viewer_update_sse.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  EXPECT_EQ(viewer_update_sse.get().status, 200);
  {
    std::lock_guard lock(viewer_update_live_state->mutex);
    EXPECT_TRUE(viewer_update_live_state->cancelled);
    EXPECT_EQ(viewer_update_live_state->cancel_calls, 1U);
  }
  EXPECT_EQ(administrator_live.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  EXPECT_EQ(administrator_sse.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  {
    std::lock_guard lock(administrator_live_state->mutex);
    EXPECT_FALSE(administrator_live_state->cancelled);
    EXPECT_EQ(administrator_live_state->cancel_calls, 0U);
  }
  ExpectStatus(update_management_ip("viewer", viewer_ipv4_id, "127.0.0.1"),
               drogon::k200OK);
  expect_error(
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, viewer_cookie),
      drogon::k401Unauthorized, "E_AUTHENTICATION_REQUIRED");
  ExpectStatus(Send(client, drogon::Get, "/api/v1/auth/me", {}, {},
                    administrator_cookie),
               drogon::k200OK);

  const auto second_viewer_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"viewer1","password":"ViewerPass9!"})", origin, {}, true);
  ExpectStatus(second_viewer_login, drogon::k200OK);
  const std::string second_viewer_cookie =
      "camera_session=" +
      second_viewer_login.response->getCookie("camera_session").value();
  auto viewer_delete_live =
      std::async(std::launch::async, [port, second_viewer_cookie] {
        return RawHttpsGet(port, "/api/v1/cameras/viewer-delete/live.mp4",
                           {second_viewer_cookie});
      });
  const auto viewer_delete_live_state = wait_for_live_start("viewer-delete");
  ASSERT_NE(viewer_delete_live_state, nullptr);
  auto viewer_delete_sse =
      std::async(std::launch::async, [port, second_viewer_cookie] {
        return RawHttpsGet(port, "/api/v1/ai/detections/stream",
                           {second_viewer_cookie});
      });
  wait_for_sse_subscriptions(3U);
  const auto deleted_viewer_ip = delete_management_ip("viewer", viewer_ipv4_id);
  ExpectStatus(deleted_viewer_ip, drogon::k200OK);
  ASSERT_NE(deleted_viewer_ip.response->getJsonObject(), nullptr);
  expect_fields(*deleted_viewer_ip.response->getJsonObject(), {"deleted"});
  EXPECT_TRUE(
      (*deleted_viewer_ip.response->getJsonObject())["deleted"].asBool());
  ASSERT_EQ(viewer_delete_live.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  EXPECT_EQ(viewer_delete_live.get().status, 200);
  ASSERT_EQ(viewer_delete_sse.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  EXPECT_EQ(viewer_delete_sse.get().status, 200);
  {
    std::lock_guard lock(viewer_delete_live_state->mutex);
    EXPECT_TRUE(viewer_delete_live_state->cancelled);
    EXPECT_EQ(viewer_delete_live_state->cancel_calls, 1U);
  }
  EXPECT_EQ(administrator_live.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  EXPECT_EQ(administrator_sse.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  const auto replacement_viewer_ip = add_management_ip("viewer", "127.0.0.1");
  ExpectStatus(replacement_viewer_ip, drogon::k201Created);
  expect_error(Send(client, drogon::Get, "/api/v1/auth/me", {}, {},
                    second_viewer_cookie),
               drogon::k401Unauthorized, "E_AUTHENTICATION_REQUIRED");

  for (std::size_t index = 1U;
       index < camera_firmware::security::kMaximumManagementIpsPerRole - 1U;
       ++index) {
    ExpectStatus(
        add_management_ip("viewer", "198.51.100." + std::to_string(index)),
        drogon::k201Created);
  }
  expect_error(add_management_ip("viewer", "198.51.100.200"),
               drogon::k409Conflict, "E_MANAGEMENT_IP_LIMIT");

  const auto final_list =
      Send(client, drogon::Get, "/api/v1/security/management-ips", {}, {},
           administrator_cookie);
  ExpectStatus(final_list, drogon::k200OK);
  ASSERT_NE(final_list.response->getJsonObject(), nullptr);
  expect_fields(*final_list.response->getJsonObject(),
                {"management_ips", "current_peer_ip"});
  EXPECT_EQ(
      (*final_list.response->getJsonObject())["current_peer_ip"].asString(),
      "127.0.0.1");
  const auto& final_entries =
      (*final_list.response->getJsonObject())["management_ips"];
  ASSERT_TRUE(final_entries.isArray());
  ASSERT_EQ(final_entries.size(),
            camera_firmware::security::kMaximumManagementIpsPerRole + 1U);
  std::int64_t previous_id = 0;
  for (const auto& entry : final_entries) {
    expect_fields(entry, management_ip_fields);
    EXPECT_GT(entry["id"].asInt64(), previous_id);
    previous_id = entry["id"].asInt64();
  }

  service.Stop();
  ASSERT_EQ(administrator_live.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  EXPECT_EQ(administrator_live.get().status, 200);
  ASSERT_EQ(administrator_sse.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  EXPECT_EQ(administrator_sse.get().status, 200);
  {
    std::lock_guard lock(administrator_live_state->mutex);
    EXPECT_TRUE(administrator_live_state->cancelled);
    EXPECT_EQ(administrator_live_state->cancel_calls, 1U);
  }
}

TEST(HttpsAuthIntegrationTest,
     AdministratorManagementIpLifecycleIsRoleScopedAndRevokesSessions) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(90U);
    RunAdministratorManagementIpLifecycleScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunViewerOwnPasswordLifecycleScenario(
    const std::filesystem::path& state_directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = state_directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "camera-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (state_directory / "rtsp.credentials").string();

  struct LiveState {
    std::mutex mutex;
    std::condition_variable changed;
    bool read_started{false};
    bool cancelled{false};
    std::size_t cancel_calls{0U};
  };
  auto live_state = std::make_shared<LiveState>();
  std::promise<void> sse_subscribed;
  auto sse_subscribed_future = sse_subscribed.get_future();
  std::atomic_bool sse_published{false};
  std::atomic_int ai_restart_calls{0};
  std::atomic_int runtime_restart_calls{0};

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.runtime_start_callback = [&runtime_restart_calls] {
    runtime_restart_calls.fetch_add(1);
    return camera_firmware::common::Result<void>::Ok();
  };
  args.camera_status_provider = [] {
    return std::vector<camera_firmware::service::CameraStatus>{
        {.id = "imx708-main",
         .state = "streaming",
         .snapshot_available = true,
         .width = 1920U,
         .height = 1080U},
    };
  };
  args.ai_status_provider = [] {
    return camera_firmware::service::AiServiceStatus{};
  };
  args.ai_restart_callback = [&ai_restart_calls] {
    ai_restart_calls.fetch_add(1);
    return camera_firmware::common::Result<void>::Ok();
  };
  args.snapshot_callback = [](const std::string&) {
    return std::optional<camera_firmware::media::JpegBytes>{
        std::string("\xff\xd8\xff\xd9", 4U)};
  };
  args.secure_stream_diagnostics_provider = [] {
    return camera_firmware::service::SecureStreamDiagnostics{};
  };
  args.detection_snapshot_provider = [] {
    return std::vector<camera_firmware::ai::DetectionEvent>{};
  };
  args.detection_event_subscriber =
      [&sse_subscribed,
       &sse_published](camera_firmware::ai::DetectionBus::Handler) {
        if (!sse_published.exchange(true)) {
          sse_subscribed.set_value();
        }
        return camera_firmware::ai::DetectionBus::Subscription{};
      };
  args.cancellable_live_stream_callback = [live_state](const std::string&) {
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read =
            [live_state](char*, std::size_t) {
              std::unique_lock lock(live_state->mutex);
              live_state->read_started = true;
              live_state->changed.notify_all();
              live_state->changed.wait(lock,
                                       [&] { return live_state->cancelled; });
              return std::size_t{0U};
            },
        .cancel =
            [live_state] {
              std::lock_guard lock(live_state->mutex);
              ++live_state->cancel_calls;
              live_state->cancelled = true;
              live_state->changed.notify_all();
            },
    });
  };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);

  const auto expect_fields = [](const Json::Value& value,
                                std::vector<std::string> expected) {
    ASSERT_TRUE(value.isObject());
    auto actual = value.getMemberNames();
    std::sort(actual.begin(), actual.end());
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(actual, expected);
  };
  const auto expect_error = [&expect_fields](const HttpResult& result,
                                             drogon::HttpStatusCode status,
                                             std::string_view code) {
    ExpectStatus(result, status);
    ASSERT_NE(result.response->getJsonObject(), nullptr);
    expect_fields(*result.response->getJsonObject(), {"code", "message"});
    EXPECT_EQ((*result.response->getJsonObject())["code"].asString(), code);
  };

  ExpectStatus(
      Send(
          client, drogon::Post, "/api/v1/setup/initialize",
          R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
          origin, InitialAccountCookie(client, origin), true),
      drogon::k200OK);
  const auto administrator_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
  ExpectStatus(administrator_login, drogon::k200OK);
  const std::string administrator_cookie =
      "camera_session=" +
      administrator_login.response->getCookie("camera_session").value();
  ExpectStatus(Send(client, drogon::Post, "/api/v1/security/users",
                    R"({"username":"viewer1","password":"ViewerPass9!"})",
                    origin, administrator_cookie, true),
               drogon::k201Created);
  ExpectStatus(
      Send(client, drogon::Post, "/api/v1/security/management-ips/viewer",
           R"({"address":"127.0.0.1"})", origin, administrator_cookie, true),
      drogon::k201Created);

  const auto viewer_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"viewer1","password":"ViewerPass9!"})", origin, {}, true);
  ExpectStatus(viewer_login, drogon::k200OK);
  ASSERT_NE(viewer_login.response->getJsonObject(), nullptr);
  EXPECT_EQ((*viewer_login.response->getJsonObject())["role"].asString(),
            "viewer");
  const std::string viewer_cookie =
      "camera_session=" +
      viewer_login.response->getCookie("camera_session").value();

  ResetUserManagementBodyCleanupForTesting();
  camera_firmware::service::internal::
      SetUserManagementRequestBodyCleanupObserverForTesting(
          RecordUserManagementBodyCleanupForTesting);
  const auto missing_session_password = Send(
      client, drogon::Put, "/api/v1/auth/password",
      R"({"current_password":"ViewerPass9!","replacement_password":"ChangedPass9!"})",
      origin, {}, true);
  expect_error(missing_session_password, drogon::k401Unauthorized,
               "E_AUTHENTICATION_REQUIRED");
  const auto& authorization_cleanup = UserManagementBodyCleanupForTesting();
  EXPECT_EQ(authorization_cleanup.calls.load(std::memory_order_relaxed), 1U);
  EXPECT_EQ(authorization_cleanup.copied_to_secure_owner.load(
                std::memory_order_relaxed),
            1U);
  EXPECT_TRUE(
      authorization_cleanup.source_cleansed.load(std::memory_order_relaxed));
  camera_firmware::service::internal::
      ResetUserManagementRequestBodyCleanupObserverForTesting();

  const auto me =
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, viewer_cookie);
  ExpectStatus(me, drogon::k200OK);
  ASSERT_NE(me.response->getJsonObject(), nullptr);
  expect_fields(*me.response->getJsonObject(), {"role", "username"});
  EXPECT_EQ((*me.response->getJsonObject())["username"].asString(), "viewer1");
  EXPECT_EQ((*me.response->getJsonObject())["role"].asString(), "viewer");
  expect_error(
      Send(client, drogon::Get, "/api/v1/auth/me", "{}", {}, viewer_cookie),
      drogon::k400BadRequest, "E_INVALID_REQUEST");

  expect_error(Send(client, drogon::Get, "/api/v1/monitoring/cameras"),
               drogon::k401Unauthorized, "E_AUTHENTICATION_REQUIRED");
  const auto monitoring = Send(
      client, drogon::Get, "/api/v1/monitoring/cameras", {}, {}, viewer_cookie);
  ExpectStatus(monitoring, drogon::k200OK);
  ASSERT_NE(monitoring.response->getJsonObject(), nullptr);
  expect_fields(*monitoring.response->getJsonObject(), {"cameras"});
  const auto& cameras = (*monitoring.response->getJsonObject())["cameras"];
  ASSERT_EQ(cameras.size(), 1U);
  expect_fields(cameras[0],
                {"height", "id", "snapshot_available", "state", "width"});
  EXPECT_EQ(cameras[0]["id"].asString(), "imx708-main");
  EXPECT_EQ(cameras[0]["width"].asUInt(), 1920U);
  EXPECT_EQ(cameras[0]["height"].asUInt(), 1080U);

  for (const std::string& path : {
           "/api/v1/cameras/imx708-main/snapshot.jpg",
           "/api/v1/ai/detections",
       }) {
    ExpectStatus(Send(client, drogon::Get, path, {}, {}, viewer_cookie),
                 drogon::k200OK);
  }

  for (const std::string& path : {
           "/api/v1/health",
           "/api/v1/cameras",
           "/api/v1/stream",
       }) {
    expect_error(Send(client, drogon::Get, path, {}, {}, viewer_cookie),
                 drogon::k403Forbidden, "E_AUTHORIZATION_REQUIRED");
  }

  expect_error(Send(client, drogon::Get, "/api/v1/security/users", {}, {},
                    viewer_cookie),
               drogon::k403Forbidden, "E_AUTHORIZATION_REQUIRED");
  expect_error(Send(client, drogon::Get, "/api/v1/security/management-ips", {},
                    {}, viewer_cookie),
               drogon::k403Forbidden, "E_AUTHORIZATION_REQUIRED");
  expect_error(Send(client, drogon::Get, "/api/v1/settings/runtime", {}, {},
                    viewer_cookie),
               drogon::k403Forbidden, "E_AUTHORIZATION_REQUIRED");
  for (const auto& [method, path, body] :
       std::array<std::tuple<drogon::HttpMethod, const char*, const char*>, 12>{
           {{drogon::Post, "/api/v1/security/users",
             R"({"username":"viewer2","password":"ViewerPass9!"})"},
            {drogon::Put, "/api/v1/security/users/1/enabled",
             R"({"enabled":false})"},
            {drogon::Put, "/api/v1/security/users/1/password",
             R"({"password":"ViewerPass9!"})"},
            {drogon::Delete, "/api/v1/security/users/1", ""},
            {drogon::Post, "/api/v1/security/management-ips/viewer",
             R"({"address":"192.0.2.20"})"},
            {drogon::Put, "/api/v1/security/management-ips/viewer/1",
             R"({"address":"192.0.2.20"})"},
            {drogon::Delete, "/api/v1/security/management-ips/viewer/1", ""},
            {drogon::Post, "/api/v1/ai/restart", ""},
            {drogon::Post, "/api/v1/runtime/restart", "{}"},
            {drogon::Put, "/api/v1/settings/runtime", "{}"},
            {drogon::Post, "/api/v1/settings/runtime/apply",
             R"({"revision":1})"},
            {drogon::Post, "/api/v1/settings/runtime/discard",
             R"({"revision":1})"}}}) {
    expect_error(Send(client, method, path, body, origin, viewer_cookie, true),
                 drogon::k403Forbidden, "E_AUTHORIZATION_REQUIRED");
  }
  EXPECT_EQ(ai_restart_calls.load(), 0);
  EXPECT_EQ(runtime_restart_calls.load(), 1);

  const auto wrong_current = Send(
      client, drogon::Put, "/api/v1/auth/password",
      R"({"current_password":"WrongPass9!","replacement_password":"ChangedPass9!"})",
      origin, viewer_cookie, true);
  ASSERT_NE(wrong_current.response, nullptr);
  ASSERT_EQ(wrong_current.response->statusCode(), drogon::k400BadRequest)
      << wrong_current.response->getBody();
  expect_error(wrong_current, drogon::k400BadRequest, "E_CURRENT_PASSWORD");
  EXPECT_EQ(wrong_current.response->getBody().find("WrongPass9!"),
            std::string::npos);
  EXPECT_EQ(wrong_current.response->getBody().find("ChangedPass9!"),
            std::string::npos);
  ExpectStatus(
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, viewer_cookie),
      drogon::k200OK);

  auto live_request = std::async(std::launch::async, [port, viewer_cookie] {
    return RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4",
                       {viewer_cookie});
  });
  {
    std::unique_lock lock(live_state->mutex);
    ASSERT_TRUE(
        live_state->changed.wait_for(lock, std::chrono::seconds(5),
                                     [&] { return live_state->read_started; }));
  }
  auto sse_request = std::async(std::launch::async, [port, viewer_cookie] {
    return RawHttpsGet(port, "/api/v1/ai/detections/stream", {viewer_cookie});
  });
  ASSERT_EQ(sse_subscribed_future.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);

  const auto changed = Send(
      client, drogon::Put, "/api/v1/auth/password",
      R"({"current_password":"ViewerPass9!","replacement_password":"ChangedPass9!"})",
      origin, viewer_cookie, true);
  ExpectStatus(changed, drogon::k200OK);
  ASSERT_NE(changed.response->getJsonObject(), nullptr);
  expect_fields(*changed.response->getJsonObject(),
                {"logged_out", "password_changed"});
  EXPECT_TRUE(
      (*changed.response->getJsonObject())["password_changed"].asBool());
  EXPECT_TRUE((*changed.response->getJsonObject())["logged_out"].asBool());
  EXPECT_EQ(changed.response->getBody().find("ViewerPass9!"),
            std::string::npos);
  EXPECT_EQ(changed.response->getBody().find("ChangedPass9!"),
            std::string::npos);
  const auto& cleared = changed.response->getCookie("camera_session");
  EXPECT_EQ(cleared.value(), "");
  ASSERT_TRUE(cleared.maxAge().has_value());
  EXPECT_EQ(*cleared.maxAge(), 0);
  EXPECT_TRUE(cleared.isSecure());
  EXPECT_TRUE(cleared.isHttpOnly());
  EXPECT_EQ(cleared.sameSite(), drogon::Cookie::SameSite::kStrict);
  EXPECT_EQ(cleared.path(), "/");

  ASSERT_EQ(live_request.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  EXPECT_EQ(live_request.get().status, 200);
  ASSERT_EQ(sse_request.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  EXPECT_EQ(sse_request.get().status, 200);
  {
    std::lock_guard lock(live_state->mutex);
    EXPECT_TRUE(live_state->cancelled);
    EXPECT_EQ(live_state->cancel_calls, 1U);
  }
  expect_error(
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, viewer_cookie),
      drogon::k401Unauthorized, "E_AUTHENTICATION_REQUIRED");
  expect_error(Send(client, drogon::Post, "/api/v1/auth/login",
                    R"({"username":"viewer1","password":"ViewerPass9!"})",
                    origin, {}, true),
               drogon::k401Unauthorized, "E_AUTHENTICATION_FAILED");
  const auto replacement_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"viewer1","password":"ChangedPass9!"})", origin, {}, true);
  ExpectStatus(replacement_login, drogon::k200OK);
  ASSERT_NE(replacement_login.response->getJsonObject(), nullptr);
  EXPECT_EQ((*replacement_login.response->getJsonObject())["role"].asString(),
            "viewer");
  const std::string replacement_cookie =
      "camera_session=" +
      replacement_login.response->getCookie("camera_session").value();
  const auto viewer_logout = Send(client, drogon::Post, "/api/v1/auth/logout",
                                  {}, origin, replacement_cookie, true);
  ExpectStatus(viewer_logout, drogon::k200OK);
  ASSERT_NE(viewer_logout.response->getJsonObject(), nullptr);
  expect_fields(*viewer_logout.response->getJsonObject(), {"logged_out"});
  EXPECT_TRUE(
      (*viewer_logout.response->getJsonObject())["logged_out"].asBool());

  service.Stop();
}

TEST(HttpsAuthIntegrationTest,
     ViewerMonitoringAndOwnPasswordChangeRevokesSessionAndStreams) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(90U);
    RunViewerOwnPasswordLifecycleScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest, DefaultWebRootServesProductionArtifacts) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    const std::uint16_t port = ReserveLoopbackPort();
    camera_firmware::config::AppConfig config;
    config.security.enabled = false;
    config.security.state_directory = directory.path().string();
    config.http.enabled = true;
    config.http.bind_ip = "127.0.0.1";
    config.http.port = port;
    config.http.tls.enabled = true;
    config.http.tls.allow_development_self_signed_tls = true;

    camera_firmware::service::ServiceInitArgs args;
    args.app_config = &config;
    args.provider = &TestCryptoProvider();
    camera_firmware::service::ServiceApp service;
    auto started = service.Init(args);
    if (!started.ok()) {
      _exit(2);
    }

    auto client = NewClient(port);
    for (const std::string path : {"/", "/app.js", "/styles.css"}) {
      const auto response = Send(client, drogon::Get, path);
      if (response.result != drogon::ReqResult::Ok || !response.response ||
          response.response->statusCode() != drogon::k200OK) {
        _exit(3);
      }
    }
    service.Stop();
    _exit(0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest, EventLoopStopDeliversAcceptedResponseAndExits) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    const std::uint16_t port = ReserveLoopbackPort();
    const std::string origin = "https://127.0.0.1:" + std::to_string(port);
    camera_firmware::config::AppConfig config;
    config.security.enabled = true;
    config.security.state_directory = directory.path().string();
    config.http.enabled = true;
    config.http.bind_ip = "127.0.0.1";
    config.http.port = port;
    config.http.public_base_url = origin;
    config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
    config.http.tls.enabled = true;
    config.http.tls.allow_development_self_signed_tls = true;
    config.secure_rtsp.client_auth.enabled = true;
    config.secure_rtsp.client_auth.realm = "camera-test";
    config.secure_rtsp.client_auth.algorithms = {"sha-256"};
    config.secure_rtsp.client_auth.credential_file =
        (directory.path() / "rtsp.credentials").string();

    std::atomic<int> provider_calls{0};
    std::atomic<long long> provider_stop_milliseconds{-1};
    camera_firmware::service::ServiceApp service;
    camera_firmware::service::ServiceInitArgs args;
    args.app_config = &config;
    args.provider = &TestCryptoProvider();
    args.document_root = config.http.web_root;
    args.public_base_url = origin;
    args.camera_status_provider = [&] {
      provider_calls.fetch_add(1);
      const auto before_stop = std::chrono::steady_clock::now();
      service.Stop();
      provider_stop_milliseconds.store(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - before_stop)
              .count());
      return std::vector<camera_firmware::service::CameraStatus>{
          {"imx708-main", "running", true}};
    };
    args.runtime_start_callback = [] {
      return camera_firmware::common::Result<void>::Ok();
    };
    auto started = service.Init(args);
    if (!started.ok()) {
      _exit(2);
    }

    auto client = NewClient(port);
    const std::string setup_body =
        R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})";
    auto setup =
        Send(client, drogon::Post, "/api/v1/setup/initialize", setup_body,
             origin, InitialAccountCookie(client, origin), true);
    if (setup.result != drogon::ReqResult::Ok || !setup.response ||
        setup.response->statusCode() != drogon::k200OK) {
      _exit(3);
    }
    auto login = Send(client, drogon::Post, "/api/v1/auth/login",
                      R"({"username":"owner1","password":"StrongPass9!"})",
                      origin, {}, true);
    if (login.result != drogon::ReqResult::Ok || !login.response ||
        login.response->statusCode() != drogon::k200OK) {
      _exit(4);
    }
    const std::string cookie =
        "camera_session=" + login.response->getCookie("camera_session").value();
    const auto response =
        RawHttpsGet(port, "/api/v1/monitoring/cameras", {cookie});
    if (response.status != 200 || provider_calls.load() != 1 ||
        provider_stop_milliseconds.load() < 0 ||
        provider_stop_milliseconds.load() >= 500) {
      _exit(5);
    }
    std::size_t status_lines = 0U;
    for (std::size_t offset = 0U;
         (offset = response.bytes.find("HTTP/1.1 ", offset)) !=
         std::string::npos;
         offset += 9U) {
      ++status_lines;
    }
    if (status_lines != 1U) {
      _exit(6);
    }
    service.Stop();
    _exit(0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunQueuedAuthorizationShutdownScenario(
    const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "camera-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (directory / "rtsp.credentials").string();

  std::atomic_bool block_verification{false};
  std::atomic_bool block_reported{false};
  std::promise<void> verification_blocked;
  std::promise<void> release_verification;
  PromiseReleaseGuard release_guard(release_verification);
  auto release_verification_future = release_verification.get_future().share();
  std::atomic<unsigned int> random_counter{0U};
  camera_firmware::security::AuthServiceDependencies auth_dependencies;
  auth_dependencies.now_seconds = [] {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
  };
  auth_dependencies.random_bytes = [&](std::size_t size) {
    camera_firmware::common::SecureBytes bytes;
    bytes.resize(size);
    const auto seed =
        static_cast<unsigned char>(0x40U + random_counter.fetch_add(1U));
    std::fill(bytes.data(), bytes.data() + bytes.size(), seed);
    return camera_firmware::common::Result<
        camera_firmware::common::SecureBytes>::Ok(std::move(bytes));
  };
  auth_dependencies.firmware_log_random_bytes = auth_dependencies.random_bytes;
  auth_dependencies.verify_password =
      [&](const camera_firmware::common::SecureBytes& password,
          const camera_firmware::security::PasswordRecord& record) {
        if (block_verification.load()) {
          if (!block_reported.exchange(true)) {
            verification_blocked.set_value();
          }
          release_verification_future.wait();
          return camera_firmware::common::Result<bool>::Ok(false);
        }
        return camera_firmware::security::VerifyPassword(password, record);
      };
  auth_dependencies.high_severity_log = [](std::string_view, std::string_view) {
  };

  struct LiveState {
    std::mutex mutex;
    std::condition_variable changed;
    bool cancelled{false};
    std::size_t opened{0U};
    std::size_t read_started{0U};
    std::size_t read_finished{0U};
    std::size_t cancel_calls{0U};
  };
  auto live_state = std::make_shared<LiveState>();
  auto registry =
      std::make_shared<camera_firmware::service::SessionStreamRegistry>();
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.stream_registry = registry;
  args.auth_service_dependencies_provider = [auth_dependencies =
                                                 std::move(auth_dependencies)] {
    return auth_dependencies;
  };
  args.cancellable_live_stream_callback = [live_state](const std::string&) {
    {
      std::lock_guard lock(live_state->mutex);
      ++live_state->opened;
      live_state->changed.notify_all();
    }
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read =
            [live_state](char* output, std::size_t capacity) {
              std::unique_lock lock(live_state->mutex);
              ++live_state->read_started;
              live_state->changed.notify_all();
              live_state->changed.wait(lock,
                                       [&] { return live_state->cancelled; });
              ++live_state->read_finished;
              live_state->changed.notify_all();
              const auto count = std::min(capacity, std::size_t{4U});
              std::fill_n(output, count, 'x');
              return count;
            },
        .cancel =
            [live_state] {
              std::lock_guard lock(live_state->mutex);
              ++live_state->cancel_calls;
              live_state->cancelled = true;
              live_state->changed.notify_all();
            },
    });
  };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);
  const std::string setup_body =
      R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})";
  ExpectStatus(
      Send(client, drogon::Post, "/api/v1/setup/initialize", setup_body, origin,
           InitialAccountCookie(client, origin), true),
      drogon::k200OK);
  auto login = Send(client, drogon::Post, "/api/v1/auth/login",
                    R"({"username":"owner1","password":"StrongPass9!"})",
                    origin, {}, true);
  ExpectStatus(login, drogon::k200OK);
  const std::string cookie =
      "camera_session=" + login.response->getCookie("camera_session").value();

  auto active_live = std::async(std::launch::async, [port, cookie] {
    return RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4", {cookie});
  });
  {
    std::unique_lock lock(live_state->mutex);
    ASSERT_TRUE(live_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return live_state->read_started == 1U; }));
  }

  block_verification.store(true);
  auto blocked_login = std::async(std::launch::async, [&] {
    return Send(NewClient(port), drogon::Post, "/api/v1/auth/login",
                R"({"username":"missing","password":"StrongPass9!"})", origin,
                {}, true);
  });
  ASSERT_EQ(verification_blocked.get_future().wait_for(std::chrono::seconds(2)),
            std::future_status::ready);

  constexpr std::size_t kLiveRequests = 20U;
  std::vector<std::future<RawHttpsResponse>> live_requests;
  live_requests.reserve(kLiveRequests);
  for (std::size_t index = 0U; index < kLiveRequests; ++index) {
    live_requests.push_back(std::async(std::launch::async, [&, index] {
      return RawHttpsGet(port,
                         "/api/v1/cameras/imx708-main/live.mp4?request=" +
                             std::to_string(index),
                         {cookie});
    }));
  }
  bool queue_saturated = false;
  const auto saturation_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (!queue_saturated &&
         std::chrono::steady_clock::now() < saturation_deadline) {
    for (auto& request : live_requests) {
      if (request.valid() && request.wait_for(std::chrono::milliseconds(0)) ==
                                 std::future_status::ready) {
        const auto response = request.get();
        queue_saturated = response.status == 503;
      }
    }
    if (!queue_saturated) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }
  ASSERT_TRUE(queue_saturated);

  auto shutting_down =
      std::async(std::launch::async, [&] { service.BeginShutdown(); });
  EXPECT_EQ(shutting_down.wait_for(std::chrono::milliseconds(30)),
            std::future_status::timeout);
  {
    std::unique_lock lock(live_state->mutex);
    EXPECT_TRUE(live_state->changed.wait_for(
        lock, std::chrono::milliseconds(250),
        [&] { return live_state->cancel_calls >= 1U; }));
  }
  release_guard.Release();
  ASSERT_EQ(shutting_down.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  shutting_down.get();
  ExpectStatus(blocked_login.get(), drogon::k401Unauthorized);
  ASSERT_EQ(active_live.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  EXPECT_EQ(active_live.get().status, 200);

  for (auto& request : live_requests) {
    if (!request.valid()) {
      continue;
    }
    ASSERT_EQ(request.wait_for(std::chrono::seconds(5)),
              std::future_status::ready);
    const auto response = request.get();
    EXPECT_TRUE(response.status == 200 || response.status == 503)
        << response.status;
  }
  {
    std::unique_lock lock(live_state->mutex);
    ASSERT_TRUE(live_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return live_state->cancel_calls == live_state->opened; }));
    EXPECT_EQ(live_state->opened, 1U);
    EXPECT_EQ(live_state->read_finished, live_state->read_started);
  }
  service.Stop();
}

TEST(HttpsAuthIntegrationTest,
     BeginShutdownRevokesLeasesAcquiredByDrainedAuthorizationTasks) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    RunQueuedAuthorizationShutdownScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunNoLeaseLiveShutdownScenario(const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  struct StreamState {
    std::mutex mutex;
    std::condition_variable changed;
    bool read_started{false};
    bool cancelled{false};
    bool read_finished{false};
    std::size_t cancel_calls{0U};
  };
  auto stream_state = std::make_shared<StreamState>();
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.cancellable_live_stream_callback = [stream_state](const std::string&) {
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read =
            [stream_state](char* output, std::size_t capacity) {
              std::unique_lock lock(stream_state->mutex);
              stream_state->read_started = true;
              stream_state->changed.notify_all();
              stream_state->changed.wait(
                  lock, [&] { return stream_state->cancelled; });
              stream_state->read_finished = true;
              stream_state->changed.notify_all();
              const auto count = std::min(capacity, std::size_t{4U});
              std::fill_n(output, count, 'x');
              return count;
            },
        .cancel =
            [stream_state] {
              std::lock_guard lock(stream_state->mutex);
              ++stream_state->cancel_calls;
              stream_state->cancelled = true;
              stream_state->changed.notify_all();
            },
    });
  };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto blocked_live = std::async(std::launch::async, [port] {
    return RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4", {});
  });
  {
    std::unique_lock lock(stream_state->mutex);
    ASSERT_TRUE(stream_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return stream_state->read_started; }));
  }

  service.BeginShutdown();

  {
    std::lock_guard lock(stream_state->mutex);
    EXPECT_TRUE(stream_state->read_finished);
    EXPECT_EQ(stream_state->cancel_calls, 1U);
  }
  ASSERT_EQ(blocked_live.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  EXPECT_EQ(blocked_live.get().status, 200);
  service.Stop();
}

TEST(HttpsAuthIntegrationTest,
     BeginShutdownReclaimsBlockedLiveReadWithoutSecurityLease) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunNoLeaseLiveShutdownScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunConcurrentLiveShutdownBarrierScenario(
    const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  struct StreamState {
    std::mutex mutex;
    std::condition_variable changed;
    bool read_started{false};
    bool cancel_called{false};
    bool release_read{false};
  };
  auto stream_state = std::make_shared<StreamState>();
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.cancellable_live_stream_callback = [stream_state](const std::string&) {
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read =
            [stream_state](char*, std::size_t) {
              std::unique_lock lock(stream_state->mutex);
              stream_state->read_started = true;
              stream_state->changed.notify_all();
              stream_state->changed.wait(
                  lock, [&] { return stream_state->release_read; });
              return std::size_t{0U};
            },
        .cancel =
            [stream_state] {
              std::lock_guard lock(stream_state->mutex);
              stream_state->cancel_called = true;
              stream_state->changed.notify_all();
            },
    });
  };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto blocked_live = std::async(std::launch::async, [port] {
    return RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4", {});
  });
  {
    std::unique_lock lock(stream_state->mutex);
    ASSERT_TRUE(stream_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return stream_state->read_started; }));
  }

  auto first_shutdown =
      std::async(std::launch::async, [&] { service.BeginShutdown(); });
  {
    std::unique_lock lock(stream_state->mutex);
    ASSERT_TRUE(stream_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return stream_state->cancel_called; }));
  }
  auto second_shutdown =
      std::async(std::launch::async, [&] { service.BeginShutdown(); });
  EXPECT_EQ(second_shutdown.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  {
    std::lock_guard lock(stream_state->mutex);
    stream_state->release_read = true;
    stream_state->changed.notify_all();
  }
  ASSERT_EQ(first_shutdown.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  ASSERT_EQ(second_shutdown.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  first_shutdown.get();
  second_shutdown.get();
  ASSERT_EQ(blocked_live.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  EXPECT_EQ(blocked_live.get().status, 200);
  service.Stop();
}

TEST(HttpsAuthIntegrationTest, ConcurrentBeginShutdownWaitsForLivePumpJoin) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunConcurrentLiveShutdownBarrierScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunConcurrentShutdownDuringLiveStartPublicationScenario(
    const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  struct StreamState {
    std::mutex mutex;
    std::condition_variable changed;
    bool read_started{false};
    bool cancel_called{false};
    bool release_read{false};
  };
  auto stream_state = std::make_shared<StreamState>();
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.cancellable_live_stream_callback = [stream_state](const std::string&) {
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read =
            [stream_state](char*, std::size_t) {
              std::unique_lock lock(stream_state->mutex);
              stream_state->read_started = true;
              stream_state->changed.notify_all();
              stream_state->changed.wait(
                  lock, [&] { return stream_state->release_read; });
              return std::size_t{0U};
            },
        .cancel =
            [stream_state] {
              std::lock_guard lock(stream_state->mutex);
              stream_state->cancel_called = true;
              stream_state->changed.notify_all();
            },
    });
  };

  std::promise<void> start_published;
  auto start_published_future = start_published.get_future();
  std::promise<void> release_publication;
  PromiseReleaseGuard release_publication_guard(release_publication);
  camera_firmware::service::internal::SetLiveMp4StartPublicationPauseForTesting(
      &start_published, release_publication.get_future().share());

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto blocked_live = std::async(std::launch::async, [port] {
    return RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4", {});
  });
  ASSERT_EQ(start_published_future.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  {
    std::unique_lock lock(stream_state->mutex);
    ASSERT_TRUE(stream_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return stream_state->read_started; }));
  }

  auto first_shutdown =
      std::async(std::launch::async, [&] { service.BeginShutdown(); });
  auto second_shutdown =
      std::async(std::launch::async, [&] { service.BeginShutdown(); });
  const auto stop_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (camera_firmware::service::internal::
                 LiveMp4StopCallsDuringStartForTesting() < 2U &&
         std::chrono::steady_clock::now() < stop_deadline) {
    std::this_thread::yield();
  }
  ASSERT_EQ(camera_firmware::service::internal::
                LiveMp4StopCallsDuringStartForTesting(),
            2U);

  release_publication_guard.Release();
  {
    std::unique_lock lock(stream_state->mutex);
    ASSERT_TRUE(stream_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return stream_state->cancel_called; }));
  }
  EXPECT_EQ(first_shutdown.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  EXPECT_EQ(second_shutdown.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);

  {
    std::lock_guard lock(stream_state->mutex);
    stream_state->release_read = true;
    stream_state->changed.notify_all();
  }
  ASSERT_EQ(first_shutdown.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  ASSERT_EQ(second_shutdown.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  first_shutdown.get();
  second_shutdown.get();
  ASSERT_EQ(blocked_live.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  EXPECT_EQ(blocked_live.get().status, 200);
  service.Stop();
}

TEST(HttpsAuthIntegrationTest,
     ConcurrentBeginShutdownDuringStartPublicationWaitsForPumpJoin) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunConcurrentShutdownDuringLiveStartPublicationScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunBlockedLiveOpenShutdownScenario(
    const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  struct OpenState {
    std::mutex mutex;
    std::condition_variable changed;
    bool entered{false};
    bool release{false};
    bool returned{false};
    std::size_t cancel_calls{0U};
  };
  auto open_state = std::make_shared<OpenState>();
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.cancellable_live_stream_callback = [open_state](const std::string&) {
    {
      std::unique_lock lock(open_state->mutex);
      open_state->entered = true;
      open_state->changed.notify_all();
      open_state->changed.wait(lock, [&] { return open_state->release; });
      open_state->returned = true;
      open_state->changed.notify_all();
    }
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read = [](char*, std::size_t) { return std::size_t{0U}; },
        .cancel =
            [open_state] {
              std::lock_guard lock(open_state->mutex);
              ++open_state->cancel_calls;
              open_state->changed.notify_all();
            },
    });
  };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto request = std::async(std::launch::async, [port] {
    return RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4", {});
  });
  {
    std::unique_lock lock(open_state->mutex);
    ASSERT_TRUE(open_state->changed.wait_for(
        lock, std::chrono::seconds(2), [&] { return open_state->entered; }));
  }

  auto shutting_down =
      std::async(std::launch::async, [&] { service.BeginShutdown(); });
  EXPECT_EQ(shutting_down.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  {
    std::lock_guard lock(open_state->mutex);
    open_state->release = true;
    open_state->changed.notify_all();
  }
  ASSERT_EQ(shutting_down.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  shutting_down.get();
  {
    std::unique_lock lock(open_state->mutex);
    EXPECT_TRUE(open_state->returned);
    EXPECT_TRUE(open_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return open_state->cancel_calls == 1U; }));
  }
  ASSERT_EQ(request.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  EXPECT_EQ(request.get().status, 200);
  service.Stop();
}

TEST(HttpsAuthIntegrationTest, BeginShutdownWaitsForAdmittedLiveOpen) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunBlockedLiveOpenShutdownScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunLiveOpenStopsServiceScenario(const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  struct CallbackState {
    std::mutex mutex;
    std::condition_variable changed;
    bool stop_returned{false};
  };
  auto callback_state = std::make_shared<CallbackState>();
  camera_firmware::service::ServiceApp service;
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.cancellable_live_stream_callback = [&service,
                                           callback_state](const std::string&) {
    service.Stop();
    {
      std::lock_guard lock(callback_state->mutex);
      callback_state->stop_returned = true;
      callback_state->changed.notify_all();
    }
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read = [](char*, std::size_t) { return std::size_t{0U}; },
        .cancel = [] {},
    });
  };

  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  std::thread request([port] {
    (void)RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4", {});
  });
  bool stop_returned = false;
  {
    std::unique_lock lock(callback_state->mutex);
    stop_returned = callback_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return callback_state->stop_returned; });
  }
  if (!stop_returned) {
    ADD_FAILURE() << "Stop did not return from the live open callback";
    _exit(1);
  }
  service.Stop();
  request.join();
}

TEST(HttpsAuthIntegrationTest, LiveOpenCallbackMayStopService) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(10U);
    RunLiveOpenStopsServiceScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunRuntimeCallbackLeaseAllocationFailureScenario(
    const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  camera_firmware::service::ServiceApp service;
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.cancellable_live_stream_callback = [](const std::string&) {
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read = [](char*, std::size_t) { return std::size_t{0U}; },
        .cancel = [] {},
    });
  };

  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  camera_firmware::service::internal::
      FailNextRuntimeCallbackLeaseAllocationForTesting();
  auto response = Send(NewClient(port), drogon::Get,
                       "/api/v1/cameras/imx708-main/live.mp4");
  ExpectStatus(response, drogon::k503ServiceUnavailable);

  const auto before_shutdown = std::chrono::steady_clock::now();
  service.BeginShutdown();
  EXPECT_LT(std::chrono::steady_clock::now() - before_shutdown,
            std::chrono::seconds(1));
  service.Stop();
}

TEST(HttpsAuthIntegrationTest,
     RuntimeCallbackLeaseAllocationFailureDoesNotChargeLifecycle) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(10U);
    RunRuntimeCallbackLeaseAllocationFailureScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunLiveReadStopsServiceScenario(const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  struct ReadState {
    ReadState()
        : peer_read_entered_signal(peer_read_entered.get_future().share()) {}

    std::mutex callback_mutex;
    std::promise<void> read_entered;
    std::promise<void> stop_returned;
    std::promise<void> peer_read_entered;
    std::shared_future<void> peer_read_entered_signal;
    std::mutex peer_mutex;
    std::condition_variable peer_changed;
    bool release_peer_read{false};
    std::atomic_size_t cancel_calls{0U};
    std::atomic_size_t peer_cancel_calls{0U};
    std::atomic_bool peer_cancel_observed_before_stop_return{false};
  };
  auto read_state = std::make_shared<ReadState>();
  auto read_entered = read_state->read_entered.get_future();
  auto stop_returned = read_state->stop_returned.get_future();
  camera_firmware::service::ServiceApp service;
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.cancellable_live_stream_callback = [&service, read_state](
                                              const std::string& camera_id) {
    if (camera_id == "peer") {
      return camera_firmware::common::Result<
          camera_firmware::service::LiveMp4StreamHandle>::Ok({
          .read =
              [read_state](char*, std::size_t) {
                read_state->peer_read_entered.set_value();
                std::unique_lock lock(read_state->peer_mutex);
                read_state->peer_changed.wait(
                    lock, [&] { return read_state->release_peer_read; });
                return std::size_t{0U};
              },
          .cancel =
              [read_state] {
                read_state->peer_cancel_calls.fetch_add(
                    1U, std::memory_order_relaxed);
                {
                  std::lock_guard lock(read_state->peer_mutex);
                  read_state->release_peer_read = true;
                }
                read_state->peer_changed.notify_all();
              },
      });
    }
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read =
            [&service, read_state](char*, std::size_t) {
              std::lock_guard callback_lock(read_state->callback_mutex);
              read_state->read_entered.set_value();
              read_state->peer_read_entered_signal.wait();
              service.Stop();
              read_state->peer_cancel_observed_before_stop_return.store(
                  read_state->peer_cancel_calls.load(
                      std::memory_order_relaxed) != 0U,
                  std::memory_order_release);
              read_state->stop_returned.set_value();
              return std::size_t{0U};
            },
        .cancel =
            [read_state] {
              std::lock_guard callback_lock(read_state->callback_mutex);
              read_state->cancel_calls.fetch_add(1U, std::memory_order_relaxed);
            },
    });
  };

  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto peer_request = std::async(std::launch::async, [port] {
    return RawHttpsGet(port, "/api/v1/cameras/peer/live.mp4", {});
  });
  auto request = std::async(std::launch::async, [port] {
    return RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4", {});
  });
  ASSERT_EQ(read_entered.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  if (stop_returned.wait_for(std::chrono::seconds(2)) !=
      std::future_status::ready) {
    ADD_FAILURE() << "Stop did not return from the locked read callback";
    _exit(1);
  }
  service.Stop();
  EXPECT_EQ(read_state->cancel_calls.load(std::memory_order_relaxed), 1U);
  EXPECT_EQ(read_state->peer_cancel_calls.load(std::memory_order_relaxed), 1U);
  EXPECT_TRUE(read_state->peer_cancel_observed_before_stop_return.load(
      std::memory_order_acquire));
  ASSERT_EQ(request.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  ASSERT_EQ(peer_request.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
}

TEST(HttpsAuthIntegrationTest, LiveReadMayStopServiceWithoutSelfJoin) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunLiveReadStopsServiceScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunLiveCancelStopsBeforeUnblockingReadScenario(
    const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  struct StreamState {
    std::mutex mutex;
    std::condition_variable changed;
    std::promise<void> read_entered;
    bool release_read{false};
    std::atomic_size_t cancel_calls{0U};
    std::atomic_bool nested_stop_returned{false};
  };
  auto stream_state = std::make_shared<StreamState>();
  auto read_entered = stream_state->read_entered.get_future();
  camera_firmware::service::ServiceApp service;
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.cancellable_live_stream_callback = [&service,
                                           stream_state](const std::string&) {
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read =
            [stream_state](char*, std::size_t) {
              stream_state->read_entered.set_value();
              std::unique_lock lock(stream_state->mutex);
              stream_state->changed.wait(
                  lock, [&] { return stream_state->release_read; });
              return std::size_t{0U};
            },
        .cancel =
            [&service, stream_state] {
              stream_state->cancel_calls.fetch_add(1U,
                                                   std::memory_order_relaxed);
              service.Stop();
              stream_state->nested_stop_returned.store(
                  true, std::memory_order_release);
              {
                std::lock_guard lock(stream_state->mutex);
                stream_state->release_read = true;
              }
              stream_state->changed.notify_all();
            },
    });
  };

  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto request = std::async(std::launch::async, [port] {
    return RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4", {});
  });
  ASSERT_EQ(read_entered.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);

  const auto before_shutdown = std::chrono::steady_clock::now();
  service.BeginShutdown();
  EXPECT_LT(std::chrono::steady_clock::now() - before_shutdown,
            std::chrono::seconds(1));
  EXPECT_TRUE(
      stream_state->nested_stop_returned.load(std::memory_order_acquire));
  EXPECT_EQ(stream_state->cancel_calls.load(std::memory_order_relaxed), 1U);
  service.Stop();
  ASSERT_EQ(request.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
}

TEST(HttpsAuthIntegrationTest,
     LiveCancelCallbackMayStopServiceBeforeUnblockingRead) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunLiveCancelStopsBeforeUnblockingReadScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunServiceInitLiveCallbackSelectionScenario(
    const std::filesystem::path& directory, bool configure_cancellable) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  std::atomic<unsigned int> legacy_opens{0U};
  std::atomic<unsigned int> legacy_cancels{0U};
  std::atomic<unsigned int> cancellable_opens{0U};
  std::atomic<unsigned int> cancellable_cancels{0U};
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  camera_firmware::service::LiveMp4OpenCallback legacy =
      [&](const std::string&) {
        legacy_opens.fetch_add(1U);
        auto sent = std::make_shared<bool>(false);
        camera_firmware::service::LiveMp4StreamCallback stream =
            [sent, &legacy_cancels](char* output, std::size_t capacity) {
              if (output == nullptr) {
                legacy_cancels.fetch_add(1U);
                return std::size_t{0U};
              }
              if (*sent) {
                return std::size_t{0U};
              }
              *sent = true;
              constexpr std::string_view bytes{"legacy"};
              const auto count = std::min(capacity, bytes.size());
              std::copy_n(bytes.data(), count, output);
              return count;
            };
        return camera_firmware::common::
            Result<camera_firmware::service::LiveMp4StreamCallback>::Ok(
                std::move(stream));
      };
  args.live_stream_callback = legacy;
  if (configure_cancellable) {
    args.cancellable_live_stream_callback = [&](const std::string&) {
      cancellable_opens.fetch_add(1U);
      auto sent = std::make_shared<bool>(false);
      return camera_firmware::common::Result<
          camera_firmware::service::LiveMp4StreamHandle>::Ok({
          .read =
              [sent](char* output, std::size_t capacity) {
                if (*sent) {
                  return std::size_t{0U};
                }
                *sent = true;
                constexpr std::string_view bytes{"cancellable"};
                const auto count = std::min(capacity, bytes.size());
                std::copy_n(bytes.data(), count, output);
                return count;
              },
          .cancel =
              [&cancellable_cancels] { cancellable_cancels.fetch_add(1U); },
      });
    };
  }

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto response = Send(NewClient(port), drogon::Get,
                       "/api/v1/cameras/imx708-main/live.mp4");
  ExpectStatus(response, drogon::k200OK);
  EXPECT_EQ(response.response->body(),
            configure_cancellable ? "cancellable" : "legacy");
  service.Stop();
  EXPECT_EQ(legacy_opens.load(), configure_cancellable ? 0U : 1U);
  EXPECT_EQ(legacy_cancels.load(), configure_cancellable ? 0U : 1U);
  EXPECT_EQ(cancellable_opens.load(), configure_cancellable ? 1U : 0U);
  EXPECT_EQ(cancellable_cancels.load(), configure_cancellable ? 1U : 0U);
}

TEST(HttpsAuthIntegrationTest,
     ServiceInitLiveRoutePrefersCancellableAndFallsBackToLegacy) {
  for (const bool configure_cancellable : {false, true}) {
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
      (void)::alarm(30U);
      TemporaryDirectory directory;
      RunServiceInitLiveCallbackSelectionScenario(directory.path(),
                                                  configure_cancellable);
      _exit(::testing::Test::HasFailure() ? 1 : 0);
    }

    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
  }
}

void RunSecurityDisabledSseShutdownScenario(
    const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  camera_firmware::ai::DetectionBus detection_bus;
  struct SubscriptionState {
    std::mutex mutex;
    std::condition_variable changed;
    bool snapshot_after_attach{false};
    bool released{false};
  };
  struct ReleaseProbe {
    std::shared_ptr<SubscriptionState> state;
    ~ReleaseProbe() {
      std::lock_guard lock(state->mutex);
      state->released = true;
      state->changed.notify_all();
    }
  };
  auto subscription_state = std::make_shared<SubscriptionState>();
  std::atomic<unsigned int> delivered_events{0U};
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.detection_snapshot_provider = [subscription_state] {
    std::lock_guard lock(subscription_state->mutex);
    subscription_state->snapshot_after_attach = true;
    subscription_state->changed.notify_all();
    return std::vector<camera_firmware::ai::DetectionEvent>{};
  };
  args.detection_event_subscriber =
      [&](camera_firmware::ai::DetectionBus::Handler handler) {
        auto release_probe = std::make_shared<ReleaseProbe>();
        release_probe->state = subscription_state;
        auto subscription = detection_bus.Subscribe(
            [handler = std::move(handler), &delivered_events,
             release_probe = std::move(release_probe)](
                const camera_firmware::ai::DetectionEvent& event) {
              delivered_events.fetch_add(1U);
              handler(event);
            });
        return subscription;
      };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto pending = std::async(std::launch::async, [port] {
    return RawHttpsExchange(port,
                            "GET /api/v1/ai/detections/stream HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\nLast-Event-ID: empty\r\n"
                            "Connection: close\r\n\r\n");
  });
  {
    std::unique_lock lock(subscription_state->mutex);
    ASSERT_TRUE(subscription_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return subscription_state->snapshot_after_attach; }));
  }

  const auto shutdown_started = std::chrono::steady_clock::now();
  service.BeginShutdown();
  const auto completion_deadline = shutdown_started + std::chrono::seconds(1);
  const bool completed =
      pending.wait_until(completion_deadline) == std::future_status::ready;
  EXPECT_TRUE(completed);
  if (!completed) {
    detection_bus.Publish({});
  }
  ASSERT_EQ(pending.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  EXPECT_EQ(pending.get().status, 200);
  {
    std::unique_lock lock(subscription_state->mutex);
    EXPECT_TRUE(subscription_state->changed.wait_until(
        lock, completion_deadline,
        [&] { return subscription_state->released; }));
  }
  if (completed) {
    EXPECT_LT(std::chrono::steady_clock::now() - shutdown_started,
              std::chrono::seconds(1));
  }

  const auto delivered_after_shutdown = delivered_events.load();
  detection_bus.Publish({});
  EXPECT_EQ(delivered_events.load(), delivered_after_shutdown);
  auto client = NewClient(port);
  ExpectStatus(Send(client, drogon::Get, "/api/v1/health"),
               drogon::k503ServiceUnavailable);
  service.Stop();
}

TEST(HttpsAuthIntegrationTest,
     SecurityDisabledDetectionSseStopsAtBeginShutdown) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunSecurityDisabledSseShutdownScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest,
     DetectionSseRetriesTerminalResponseAfterQueueFailure) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    const std::uint16_t port = ReserveLoopbackPort();
    camera_firmware::config::AppConfig config;
    config.security.enabled = false;
    config.security.state_directory = directory.path().string();
    config.http.enabled = true;
    config.http.bind_ip = "127.0.0.1";
    config.http.port = port;
    config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
    config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
    config.http.tls.enabled = true;
    config.http.tls.allow_development_self_signed_tls = true;

    camera_firmware::service::ServiceInitArgs args;
    args.app_config = &config;
    args.provider = &TestCryptoProvider();
    args.document_root = config.http.web_root;
    args.public_base_url = config.http.public_base_url;
    args.detection_snapshot_provider = [] {
      camera_firmware::ai::DetectionEvent event;
      event.camera_id = "imx708-main";
      event.model_id = "objects";
      event.result_state = "decoded";
      event.frame_sequence = 42U;
      return std::vector<camera_firmware::ai::DetectionEvent>{std::move(event)};
    };

    camera_firmware::service::ServiceApp service;
    if (!service.Init(args).ok()) {
      _exit(2);
    }
    camera_firmware::service::internal::
        FailNextTerminalResponseQueueForTesting();
    const auto response =
        Send(NewClient(port), drogon::Get, "/api/v1/ai/detections/stream", {},
             {}, {}, false, 1.0);
    camera_firmware::service::internal::
        ResetTerminalResponseQueueFailureForTesting();
    service.Stop();
    if (response.result != drogon::ReqResult::Ok || !response.response ||
        response.response->statusCode() != drogon::k200OK ||
        response.response->getHeader("Content-Type")
                .find("text/event-stream") == std::string::npos ||
        response.response->body().find("\"frame_sequence\":42") ==
            std::string::npos) {
      _exit(3);
    }
    _exit(0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunDetectionSseMarkedRevokeWinsEventScenario(
    const std::filesystem::path& directory, bool publish_event) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  camera_firmware::ai::DetectionBus detection_bus;
  auto registry =
      std::make_shared<camera_firmware::service::SessionStreamRegistry>();
  std::promise<void> initial_snapshot_called;
  auto initial_snapshot = initial_snapshot_called.get_future();
  std::atomic_size_t provider_calls{0U};
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.stream_registry = registry;
  args.detection_snapshot_provider = [&] {
    if (provider_calls.fetch_add(1U, std::memory_order_relaxed) == 0U) {
      initial_snapshot_called.set_value();
    }
    return std::vector<camera_firmware::ai::DetectionEvent>{};
  };
  args.detection_event_subscriber =
      [&](camera_firmware::ai::DetectionBus::Handler handler) {
        return detection_bus.Subscribe(std::move(handler));
      };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto pending = std::async(std::launch::async, [port] {
    return RawHttpsExchange(port,
                            "GET /api/v1/ai/detections/stream HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\nLast-Event-ID: empty\r\n"
                            "Connection: close\r\n\r\n",
                            std::numeric_limits<std::size_t>::max(),
                            std::chrono::seconds(22));
  });
  ASSERT_EQ(initial_snapshot.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);

  std::promise<void> first_marked;
  auto first_marked_future = first_marked.get_future();
  std::promise<void> release_marking;
  auto release_marking_future = release_marking.get_future().share();
  camera_firmware::service::internal::SetSessionStreamBatchMarkPauseForTesting(
      &first_marked, release_marking_future);
  auto revoking =
      std::async(std::launch::async, [&] { registry->RevokeAll(); });
  ASSERT_EQ(first_marked_future.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);

  if (publish_event) {
    camera_firmware::ai::DetectionEvent event;
    event.camera_id = "imx708-main";
    event.model_id = "objects";
    event.result_state = "decoded";
    event.frame_sequence = 88U;
    detection_bus.Publish(event);
  } else {
    EXPECT_EQ(pending.wait_for(std::chrono::milliseconds(15500)),
              std::future_status::ready);
  }
  EXPECT_EQ(provider_calls.load(std::memory_order_relaxed), 1U);

  release_marking.set_value();
  ASSERT_EQ(revoking.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  revoking.get();
  ASSERT_EQ(pending.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  const auto response = pending.get();
  EXPECT_EQ(response.status, 200);
  EXPECT_EQ(response.bytes.find("\"frame_sequence\":88"), std::string::npos);
  camera_firmware::service::internal::SetSessionStreamBatchMarkPauseForTesting(
      nullptr, {});
  service.Stop();
}

TEST(HttpsAuthIntegrationTest,
     DetectionSseMarkedRevokeWinsBeforeHandlerDispatch) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunDetectionSseMarkedRevokeWinsEventScenario(directory.path(), true);
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest,
     DetectionSseMarkedRevokeWinsBeforeTimeoutCompletion) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(25U);
    RunDetectionSseMarkedRevokeWinsEventScenario(directory.path(), false);
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunDetectionSseShutdownBarrierScenario(
    const std::filesystem::path& directory, bool block_subscriber) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  struct CallbackState {
    std::mutex mutex;
    std::condition_variable changed;
    bool subscriber_entered{false};
    bool subscriber_attached{false};
    bool provider_entered{false};
    bool release_callback{false};
    unsigned int provider_calls{0U};
  };
  auto callback_state = std::make_shared<CallbackState>();
  camera_firmware::ai::DetectionBus detection_bus;
  auto registry =
      std::make_shared<camera_firmware::service::SessionStreamRegistry>();
  std::atomic<unsigned int> delivered_events{0U};
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.stream_registry = registry;
  args.detection_snapshot_provider = [callback_state, block_subscriber] {
    std::unique_lock lock(callback_state->mutex);
    ++callback_state->provider_calls;
    if (!block_subscriber && callback_state->provider_calls == 2U) {
      callback_state->provider_entered = true;
      callback_state->changed.notify_all();
      callback_state->changed.wait(
          lock, [&] { return callback_state->release_callback; });
    }
    return std::vector<camera_firmware::ai::DetectionEvent>{};
  };
  args.detection_event_subscriber =
      [&, callback_state,
       block_subscriber](camera_firmware::ai::DetectionBus::Handler handler) {
        if (block_subscriber) {
          std::unique_lock lock(callback_state->mutex);
          callback_state->subscriber_entered = true;
          callback_state->changed.notify_all();
          callback_state->changed.wait(
              lock, [&] { return callback_state->release_callback; });
        }
        auto subscription = detection_bus.Subscribe(
            [handler = std::move(handler), &delivered_events](
                const camera_firmware::ai::DetectionEvent& event) {
              delivered_events.fetch_add(1U);
              handler(event);
            });
        {
          std::lock_guard lock(callback_state->mutex);
          callback_state->subscriber_attached = true;
        }
        callback_state->changed.notify_all();
        return subscription;
      };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto pending = std::async(std::launch::async, [port] {
    return RawHttpsExchange(port,
                            "GET /api/v1/ai/detections/stream HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\nLast-Event-ID: empty\r\n"
                            "Connection: close\r\n\r\n");
  });

  std::future<void> publishing;
  if (block_subscriber) {
    std::unique_lock lock(callback_state->mutex);
    ASSERT_TRUE(callback_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return callback_state->subscriber_entered; }));
  } else {
    {
      std::unique_lock lock(callback_state->mutex);
      ASSERT_TRUE(callback_state->changed.wait_for(
          lock, std::chrono::seconds(2),
          [&] { return callback_state->subscriber_attached; }));
    }
    publishing = std::async(std::launch::async, [&] {
      camera_firmware::ai::DetectionEvent event;
      event.camera_id = "imx708-main";
      event.model_id = "objects";
      event.result_state = "decoded";
      event.frame_sequence = 77U;
      detection_bus.Publish(event);
    });
    std::unique_lock lock(callback_state->mutex);
    ASSERT_TRUE(callback_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return callback_state->provider_entered; }));
  }

  camera_firmware::security::SessionIdentity later_identity;
  later_identity.bytes.fill(0xffU);
  auto later_lease = registry->Acquire(later_identity);
  std::promise<void> later_signalled;
  auto later_signalled_future = later_signalled.get_future();
  later_lease->SetRevocationHandler(
      [&later_signalled] { later_signalled.set_value(); });
  auto revoking =
      std::async(std::launch::async, [&] { registry->RevokeAll(); });
  const auto later_status =
      later_signalled_future.wait_for(std::chrono::milliseconds(100));
  EXPECT_EQ(later_status, std::future_status::ready);
  EXPECT_TRUE(later_lease->revoked());
  EXPECT_EQ(revoking.wait_for(std::chrono::milliseconds(100)),
            std::future_status::ready);

  auto shutting_down =
      std::async(std::launch::async, [&] { service.BeginShutdown(); });
  EXPECT_EQ(shutting_down.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  {
    std::lock_guard lock(callback_state->mutex);
    callback_state->release_callback = true;
    callback_state->changed.notify_all();
  }
  if (publishing.valid()) {
    ASSERT_EQ(publishing.wait_for(std::chrono::seconds(2)),
              std::future_status::ready);
    publishing.get();
  }
  ASSERT_EQ(revoking.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  revoking.get();
  ASSERT_EQ(shutting_down.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  shutting_down.get();
  ASSERT_EQ(pending.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  const auto response = pending.get();
  EXPECT_EQ(response.status, 200);
  if (!block_subscriber) {
    EXPECT_NE(response.bytes.find("\"frame_sequence\":77"), std::string::npos);
  }
  const auto delivered_after_shutdown = delivered_events.load();
  detection_bus.Publish({});
  EXPECT_EQ(delivered_events.load(), delivered_after_shutdown);
  service.Stop();
}

TEST(HttpsAuthIntegrationTest,
     BeginShutdownWaitsForDetectionSubscriberCallback) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunDetectionSseShutdownBarrierScenario(directory.path(), true);
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest, BeginShutdownWaitsForWinningDetectionProvider) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunDetectionSseShutdownBarrierScenario(directory.path(), false);
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

enum class DetectionSseStopReentryPoint {
  kSubscriber,
  kProvider,
};

void RunDetectionSseStopsServiceScenario(
    const std::filesystem::path& directory,
    DetectionSseStopReentryPoint reentry_point) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  struct CallbackState {
    std::mutex mutex;
    std::condition_variable changed;
    bool stop_returned{false};
  };
  auto callback_state = std::make_shared<CallbackState>();
  camera_firmware::ai::DetectionBus detection_bus;
  camera_firmware::service::ServiceApp service;
  const auto stop_from_callback = [&] {
    service.Stop();
    std::lock_guard lock(callback_state->mutex);
    callback_state->stop_returned = true;
    callback_state->changed.notify_all();
  };
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.detection_snapshot_provider = [&, reentry_point] {
    if (reentry_point == DetectionSseStopReentryPoint::kProvider) {
      stop_from_callback();
    }
    return std::vector<camera_firmware::ai::DetectionEvent>{};
  };
  args.detection_event_subscriber =
      [&, reentry_point](camera_firmware::ai::DetectionBus::Handler handler) {
        if (reentry_point == DetectionSseStopReentryPoint::kSubscriber) {
          stop_from_callback();
        }
        return detection_bus.Subscribe(std::move(handler));
      };

  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  std::thread request([port] {
    (void)RawHttpsExchange(port,
                           "GET /api/v1/ai/detections/stream HTTP/1.1\r\n"
                           "Host: 127.0.0.1\r\nLast-Event-ID: empty\r\n"
                           "Connection: close\r\n\r\n");
  });
  bool stop_returned = false;
  {
    std::unique_lock lock(callback_state->mutex);
    stop_returned = callback_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return callback_state->stop_returned; });
  }
  if (!stop_returned) {
    ADD_FAILURE() << "Stop did not return from the detection SSE callback";
    _exit(1);
  }
  service.Stop();
  request.join();
}

TEST(HttpsAuthIntegrationTest, DetectionSseSubscriberMayStopService) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(10U);
    RunDetectionSseStopsServiceScenario(
        directory.path(), DetectionSseStopReentryPoint::kSubscriber);
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest, DetectionSseProviderMayStopService) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(10U);
    RunDetectionSseStopsServiceScenario(
        directory.path(), DetectionSseStopReentryPoint::kProvider);
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunDetectionSseMergeFailureScenario(
    const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  camera_firmware::config::AppConfig config;
  config.security.enabled = false;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = "https://127.0.0.1:" + std::to_string(port);
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;

  struct CallbackState {
    std::mutex mutex;
    std::condition_variable changed;
    std::size_t provider_calls{0U};
    std::atomic_size_t delivered_events{0U};
  };
  auto callback_state = std::make_shared<CallbackState>();
  camera_firmware::ai::DetectionBus detection_bus;
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.detection_snapshot_provider = [callback_state] {
    std::lock_guard lock(callback_state->mutex);
    ++callback_state->provider_calls;
    callback_state->changed.notify_all();
    return std::vector<camera_firmware::ai::DetectionEvent>{};
  };
  args.detection_event_subscriber =
      [&](camera_firmware::ai::DetectionBus::Handler handler) {
        return detection_bus.Subscribe(
            [handler = std::move(handler),
             callback_state](const camera_firmware::ai::DetectionEvent& event) {
              callback_state->delivered_events.fetch_add(
                  1U, std::memory_order_relaxed);
              handler(event);
            });
      };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto pending = std::async(std::launch::async, [port] {
    return RawHttpsExchange(port,
                            "GET /api/v1/ai/detections/stream HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\nLast-Event-ID: empty\r\n"
                            "Connection: close\r\n\r\n");
  });
  {
    std::unique_lock lock(callback_state->mutex);
    ASSERT_TRUE(callback_state->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return callback_state->provider_calls == 1U; }));
  }

  camera_firmware::service::internal::
      FailNextDetectionSseEventMergeForTesting();
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.model_id = "objects";
  event.result_state = "decoded";
  event.frame_sequence = 99U;
  EXPECT_NO_THROW(detection_bus.Publish(event));
  if (pending.wait_for(std::chrono::seconds(1)) != std::future_status::ready) {
    ADD_FAILURE() << "merge failure did not complete the pending SSE";
    _exit(1);
  }
  EXPECT_EQ(pending.get().status, 200);

  auto shutting_down =
      std::async(std::launch::async, [&] { service.BeginShutdown(); });
  if (shutting_down.wait_for(std::chrono::seconds(1)) !=
      std::future_status::ready) {
    ADD_FAILURE() << "merge failure leaked the runtime callback lease";
    _exit(1);
  }
  shutting_down.get();
  const auto delivered =
      callback_state->delivered_events.load(std::memory_order_relaxed);
  detection_bus.Publish(event);
  EXPECT_EQ(callback_state->delivered_events.load(std::memory_order_relaxed),
            delivered);
  service.Stop();
}

TEST(HttpsAuthIntegrationTest,
     DetectionSseMergeFailureCompletesAndReleasesLifecycle) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(10U);
    RunDetectionSseMergeFailureScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunAuthenticatedLiveMp4Scenario(const std::filesystem::path& directory,
                                     bool use_custom_auth_dependencies,
                                     bool stop_from_cancel = false) {
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);

  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "camera-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (directory / "rtsp.credentials").string();

  const std::string fmp4_payload{"ftyp-moov-moof-mdat"};
  struct BlockingLiveState {
    std::mutex mutex;
    std::condition_variable changed;
    std::size_t reads_started{0U};
    bool cancelled{false};
    std::size_t reads_finished{0U};
    std::size_t cancel_calls{0U};
  };
  std::atomic<unsigned int> provider_calls{0U};
  std::atomic<unsigned int> release_calls{0U};
  std::atomic_bool block_live_read{false};
  auto blocking_live = std::make_shared<BlockingLiveState>();
  auto registry =
      std::make_shared<camera_firmware::service::SessionStreamRegistry>();
  std::atomic<unsigned int> dependencies_provider_calls{0U};
  camera_firmware::ai::DetectionBus detection_bus;
  std::mutex subscription_mutex;
  std::condition_variable subscription_changed;
  bool subscribed = false;
  std::size_t snapshots_after_attach{0U};
  std::size_t released_subscriptions{0U};
  struct SubscriptionReleaseProbe {
    std::mutex* mutex{nullptr};
    std::condition_variable* changed{nullptr};
    std::size_t* released{nullptr};
    ~SubscriptionReleaseProbe() {
      std::lock_guard lock(*mutex);
      ++*released;
      changed->notify_all();
    }
  };
  std::atomic_bool revoke_before_subscription_attach{false};
  std::atomic<unsigned int> delivered_events{0U};
  std::atomic<unsigned int> detection_snapshot_calls{0U};
  camera_firmware::service::ServiceApp* service_for_cancel = nullptr;
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.stream_registry = registry;
  if (use_custom_auth_dependencies) {
    args.auth_service_dependencies_provider = [&dependencies_provider_calls] {
      dependencies_provider_calls.fetch_add(1U);
      return camera_firmware::security::AuthServiceDependencies{};
    };
  }
  args.detection_snapshot_provider = [&] {
    detection_snapshot_calls.fetch_add(1U);
    {
      std::lock_guard lock(subscription_mutex);
      ++snapshots_after_attach;
      subscription_changed.notify_all();
    }
    return std::vector<camera_firmware::ai::DetectionEvent>{};
  };
  args.detection_event_subscriber =
      [&](camera_firmware::ai::DetectionBus::Handler handler) {
        auto release_probe = std::make_shared<SubscriptionReleaseProbe>();
        release_probe->mutex = &subscription_mutex;
        release_probe->changed = &subscription_changed;
        release_probe->released = &released_subscriptions;
        auto subscription = detection_bus.Subscribe(
            [handler = std::move(handler), &delivered_events,
             release_probe = std::move(release_probe)](
                const camera_firmware::ai::DetectionEvent& event) {
              delivered_events.fetch_add(1U);
              handler(event);
            });
        if (revoke_before_subscription_attach.exchange(false)) {
          registry->RevokeAll();
        }
        {
          std::lock_guard lock(subscription_mutex);
          subscribed = true;
          subscription_changed.notify_all();
        }
        return subscription;
      };
  args.cancellable_live_stream_callback = [&](const std::string& camera_id) {
    ++provider_calls;
    if (camera_id != "imx708-main") {
      return camera_firmware::common::
          Result<camera_firmware::service::LiveMp4StreamHandle>::Err(
              {"E_LIVE_NOT_FOUND", "private camera detail"});
    }
    if (block_live_read.load()) {
      return camera_firmware::common::Result<
          camera_firmware::service::LiveMp4StreamHandle>::Ok({
          .read =
              [blocking_live](char* output, std::size_t capacity) {
                std::unique_lock lock(blocking_live->mutex);
                ++blocking_live->reads_started;
                blocking_live->changed.notify_all();
                blocking_live->changed.wait(
                    lock, [&] { return blocking_live->cancelled; });
                ++blocking_live->reads_finished;
                blocking_live->changed.notify_all();
                const auto count = std::min(capacity, std::size_t{4U});
                std::fill_n(output, count, 'x');
                return count;
              },
          .cancel =
              [blocking_live, &service_for_cancel, stop_from_cancel] {
                if (stop_from_cancel && service_for_cancel != nullptr) {
                  service_for_cancel->Stop();
                }
                std::lock_guard lock(blocking_live->mutex);
                ++blocking_live->cancel_calls;
                blocking_live->cancelled = true;
                blocking_live->changed.notify_all();
              },
      });
    }
    auto offset = std::make_shared<std::size_t>(0U);
    camera_firmware::service::LiveMp4StreamHandle stream{
        .read =
            [offset, &fmp4_payload](char* output, std::size_t capacity) {
              if (*offset >= fmp4_payload.size()) {
                return std::size_t{0};
              }
              const auto count =
                  std::min(capacity, fmp4_payload.size() - *offset);
              std::copy_n(fmp4_payload.data() + *offset, count, output);
              *offset += count;
              return count;
            },
        .cancel = [&release_calls] { ++release_calls; },
    };
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok(std::move(stream));
  };

  camera_firmware::service::ServiceApp service;
  service_for_cancel = &service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  EXPECT_EQ(dependencies_provider_calls.load(),
            use_custom_auth_dependencies ? 1U : 0U);
  auto client = NewClient(port);

  auto denied =
      Send(client, drogon::Get, "/api/v1/cameras/imx708-main/live.mp4");
  ExpectStatus(denied, drogon::k403Forbidden);
  EXPECT_EQ(provider_calls.load(), 0U);

  const std::string setup_body =
      R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})";
  auto setup =
      Send(client, drogon::Post, "/api/v1/setup/initialize", setup_body, origin,
           InitialAccountCookie(client, origin), true);
  ExpectStatus(setup, drogon::k200OK);
  auto login = Send(client, drogon::Post, "/api/v1/auth/login",
                    R"({"username":"owner1","password":"StrongPass9!"})",
                    origin, {}, true);
  ExpectStatus(login, drogon::k200OK);
  const auto& session_cookie = login.response->getCookie("camera_session");
  ASSERT_FALSE(session_cookie.value().empty());
  std::string cookie = "camera_session=" + session_cookie.value();

  auto live = Send(client, drogon::Get, "/api/v1/cameras/imx708-main/live.mp4",
                   {}, {}, cookie);
  ExpectStatus(live, drogon::k200OK);
  ExpectSecurityHeaders(live.response);
  EXPECT_EQ(live.response->contentTypeString(), "video/mp4");
  EXPECT_EQ(live.response->getHeader("Content-Encoding"), "identity");
  EXPECT_EQ(live.response->body(), fmp4_payload);
  EXPECT_EQ(provider_calls.load(), 1U);

  auto unknown = Send(client, drogon::Get, "/api/v1/cameras/unknown/live.mp4",
                      {}, {}, cookie);
  ExpectStatus(unknown, drogon::k503ServiceUnavailable);
  const auto unknown_json = unknown.response->jsonObject();
  ASSERT_NE(unknown_json, nullptr);
  EXPECT_EQ((*unknown_json)["code"].asString(), "E_LIVE_UNAVAILABLE");
  EXPECT_EQ((*unknown_json)["message"].asString(),
            "live preview is unavailable");
  EXPECT_EQ(provider_calls.load(), 2U);

  if (!use_custom_auth_dependencies) {
    block_live_read.store(true);
    const std::size_t blocked_stream_count = stop_from_cancel ? 2U : 1U;
    std::vector<std::future<RawHttpsResponse>> blocked_streams;
    blocked_streams.reserve(blocked_stream_count);
    for (std::size_t index = 0U; index < blocked_stream_count; ++index) {
      blocked_streams.push_back(std::async(std::launch::async, [&] {
        return RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4",
                           {cookie});
      }));
    }
    {
      std::unique_lock lock(blocking_live->mutex);
      ASSERT_TRUE(
          blocking_live->changed.wait_for(lock, std::chrono::seconds(2), [&] {
            return blocking_live->reads_started == blocked_stream_count;
          }));
    }

    const auto logout_started = std::chrono::steady_clock::now();
    const auto logout_deadline = logout_started + std::chrono::seconds(1);
    auto logout = Send(client, drogon::Post, "/api/v1/auth/logout", {}, origin,
                       cookie, true);
    ExpectStatus(logout, drogon::k200OK);
    bool completed_promptly = true;
    for (auto& blocked_stream : blocked_streams) {
      completed_promptly = blocked_stream.wait_until(logout_deadline) ==
                               std::future_status::ready &&
                           completed_promptly;
    }
    EXPECT_TRUE(completed_promptly);
    for (auto& blocked_stream : blocked_streams) {
      if (!completed_promptly) {
        ASSERT_EQ(blocked_stream.wait_for(std::chrono::seconds(2)),
                  std::future_status::ready);
      }
      EXPECT_EQ(blocked_stream.get().status, 200);
    }
    if (completed_promptly) {
      EXPECT_LT(std::chrono::steady_clock::now() - logout_started,
                std::chrono::seconds(1));
    }
    std::unique_lock lock(blocking_live->mutex);
    EXPECT_TRUE(blocking_live->changed.wait_for(
        lock, std::chrono::seconds(2),
        [&] { return blocking_live->reads_finished == blocked_stream_count; }));
    EXPECT_EQ(blocking_live->cancel_calls, blocked_stream_count);
  } else {
    const auto build_sse_request = [&cookie] {
      return "GET /api/v1/ai/detections/stream HTTP/1.1\r\n"
             "Host: 127.0.0.1\r\nLast-Event-ID: empty\r\nCookie: " +
             cookie + "\r\nConnection: close\r\n\r\n";
    };
    const auto wait_for_subscription = [&] {
      std::unique_lock lock(subscription_mutex);
      return subscription_changed.wait_for(lock, std::chrono::seconds(2),
                                           [&] { return subscribed; });
    };
    const auto snapshot_target = [&] {
      std::lock_guard lock(subscription_mutex);
      return snapshots_after_attach + 1U;
    };
    const auto release_target = [&] {
      std::lock_guard lock(subscription_mutex);
      return released_subscriptions + 1U;
    };
    const auto wait_for_snapshot_after_attach = [&](std::size_t target) {
      std::unique_lock lock(subscription_mutex);
      return subscription_changed.wait_for(lock, std::chrono::seconds(2), [&] {
        return snapshots_after_attach >= target;
      });
    };
    const auto wait_for_release_until =
        [&](std::size_t target,
            std::chrono::steady_clock::time_point deadline) {
          std::unique_lock lock(subscription_mutex);
          return subscription_changed.wait_until(
              lock, deadline, [&] { return released_subscriptions >= target; });
        };

    const auto late_release_target = release_target();
    revoke_before_subscription_attach.store(true);
    auto revoke_before_attach = std::async(std::launch::async, [&] {
      return RawHttpsExchange(port, build_sse_request());
    });
    ASSERT_TRUE(wait_for_subscription());
    ASSERT_EQ(revoke_before_attach.wait_for(std::chrono::seconds(2)),
              std::future_status::ready);
    EXPECT_EQ(revoke_before_attach.get().status, 200);
    EXPECT_TRUE(wait_for_release_until(
        late_release_target,
        std::chrono::steady_clock::now() + std::chrono::seconds(1)));
    const auto delivered_before_late = delivered_events.load();
    detection_bus.Publish({});
    EXPECT_EQ(delivered_events.load(), delivered_before_late);

    const auto logout_snapshot_target = snapshot_target();
    const auto logout_release_target = release_target();
    auto logout_pending = std::async(std::launch::async, [&] {
      return RawHttpsExchange(port, build_sse_request());
    });
    ASSERT_TRUE(wait_for_snapshot_after_attach(logout_snapshot_target));
    const auto logout_started = std::chrono::steady_clock::now();
    const auto logout_deadline = logout_started + std::chrono::seconds(1);
    auto logout = Send(client, drogon::Post, "/api/v1/auth/logout", {}, origin,
                       cookie, true);
    ExpectStatus(logout, drogon::k200OK);
    const bool completed_promptly =
        logout_pending.wait_until(logout_deadline) == std::future_status::ready;
    EXPECT_TRUE(completed_promptly);
    if (!completed_promptly) {
      ASSERT_EQ(logout_pending.wait_for(std::chrono::seconds(2)),
                std::future_status::ready);
    }
    EXPECT_EQ(logout_pending.get().status, 200);
    if (completed_promptly) {
      EXPECT_LT(std::chrono::steady_clock::now() - logout_started,
                std::chrono::seconds(1));
    }
    EXPECT_TRUE(wait_for_release_until(logout_release_target, logout_deadline));
    const auto delivered_after_logout = delivered_events.load();
    detection_bus.Publish({});
    EXPECT_EQ(delivered_events.load(), delivered_after_logout);

    auto second_login = Send(
        client, drogon::Post, "/api/v1/auth/login",
        R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
    ExpectStatus(second_login, drogon::k200OK);
    cookie = "camera_session=" +
             second_login.response->getCookie("camera_session").value();

    const auto competition_snapshot_target = snapshot_target();
    auto competing_pending = std::async(std::launch::async, [&] {
      return RawHttpsExchange(port, build_sse_request());
    });
    ASSERT_TRUE(wait_for_snapshot_after_attach(competition_snapshot_target));
    std::promise<void> compete;
    auto compete_now = compete.get_future().share();
    auto revoke = std::async(std::launch::async, [&] {
      compete_now.wait();
      registry->RevokeAll();
    });
    auto event = std::async(std::launch::async, [&] {
      compete_now.wait();
      camera_firmware::ai::DetectionEvent detection;
      detection.camera_id = "imx708-main";
      detection.model_id = "objects";
      detection.result_state = "decoded";
      detection.frame_sequence = 101U;
      detection_bus.Publish(detection);
    });
    compete.set_value();
    event.get();
    revoke.get();
    ASSERT_EQ(competing_pending.wait_for(std::chrono::seconds(2)),
              std::future_status::ready);
    EXPECT_EQ(competing_pending.get().status, 200);
    const auto delivered_after_competition = delivered_events.load();
    detection_bus.Publish({});
    EXPECT_EQ(delivered_events.load(), delivered_after_competition);

    const auto timeout_snapshot_target = snapshot_target();
    const auto snapshots_before_timeout = detection_snapshot_calls.load();
    auto timeout_pending = std::async(std::launch::async, [&] {
      return RawHttpsExchange(port, build_sse_request());
    });
    ASSERT_TRUE(wait_for_snapshot_after_attach(timeout_snapshot_target));
    ASSERT_EQ(timeout_pending.wait_for(std::chrono::seconds(18)),
              std::future_status::ready);
    EXPECT_EQ(timeout_pending.get().status, 200);
    EXPECT_GE(detection_snapshot_calls.load(), snapshots_before_timeout + 2U);
    const auto delivered_after_timeout = delivered_events.load();
    detection_bus.Publish({});
    EXPECT_EQ(delivered_events.load(), delivered_after_timeout);
  }

  service.Stop();
  EXPECT_GE(release_calls.load(), 1U);
}

void RunSessionExpiryRevokesBlockedLiveStreamScenario(
    const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "camera-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (directory / "rtsp.credentials").string();

  struct BlockingLiveState {
    std::mutex mutex;
    std::condition_variable changed;
    bool read_started{false};
    bool cancelled{false};
    std::size_t cancel_calls{0U};
  };
  auto live_state = std::make_shared<BlockingLiveState>();
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.auth_service_dependencies_provider = [] {
    camera_firmware::security::AuthServiceDependencies dependencies;
    dependencies.session_idle_timeout_seconds = 1;
    return dependencies;
  };
  args.cancellable_live_stream_callback = [live_state](const std::string&) {
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamHandle>::Ok({
        .read =
            [live_state](char*, std::size_t) {
              std::unique_lock lock(live_state->mutex);
              live_state->read_started = true;
              live_state->changed.notify_all();
              live_state->changed.wait(lock,
                                       [&] { return live_state->cancelled; });
              return std::size_t{0U};
            },
        .cancel =
            [live_state] {
              std::lock_guard lock(live_state->mutex);
              ++live_state->cancel_calls;
              live_state->cancelled = true;
              live_state->changed.notify_all();
            },
    });
  };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);
  ExpectStatus(
      Send(
          client, drogon::Post, "/api/v1/setup/initialize",
          R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
          origin, InitialAccountCookie(client, origin), true),
      drogon::k200OK);
  const auto login = Send(client, drogon::Post, "/api/v1/auth/login",
                          R"({"username":"owner1","password":"StrongPass9!"})",
                          origin, {}, true);
  ExpectStatus(login, drogon::k200OK);
  const std::string cookie =
      "camera_session=" + login.response->getCookie("camera_session").value();

  auto live = std::async(std::launch::async, [port, cookie] {
    return RawHttpsGet(port, "/api/v1/cameras/imx708-main/live.mp4", {cookie});
  });
  {
    std::unique_lock lock(live_state->mutex);
    ASSERT_TRUE(
        live_state->changed.wait_for(lock, std::chrono::seconds(2),
                                     [&] { return live_state->read_started; }));
  }

  const bool expired_without_request =
      live.wait_for(std::chrono::seconds(3)) == std::future_status::ready;
  if (!expired_without_request) {
    service.BeginShutdown();
  }
  ASSERT_EQ(live.wait_for(std::chrono::seconds(2)), std::future_status::ready);
  EXPECT_EQ(live.get().status, 200);
  EXPECT_TRUE(expired_without_request);
  {
    std::lock_guard lock(live_state->mutex);
    EXPECT_TRUE(live_state->cancelled);
    EXPECT_EQ(live_state->cancel_calls, 1U);
  }
  if (expired_without_request) {
    const auto me =
        Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, cookie);
    ExpectStatus(me, drogon::k401Unauthorized);
    ASSERT_NE(me.response->getJsonObject(), nullptr);
    EXPECT_EQ((*me.response->getJsonObject())["code"].asString(),
              "E_AUTHENTICATION_REQUIRED");
  }
  service.Stop();
}

TEST(HttpsAuthIntegrationTest,
     SessionExpiryRevokesBlockedLiveStreamWithoutAnotherRequest) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunSessionExpiryRevokesBlockedLiveStreamScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest, AuthenticatedLiveMp4UsesSessionAndStreamsBytes) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunAuthenticatedLiveMp4Scenario(directory.path(), false);
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest, MultiLeaseLogoutCancelCallbacksMayStopService) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunAuthenticatedLiveMp4Scenario(directory.path(), false, true);
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest,
     CustomAuthDependenciesRevokeDetectionSseThroughInjectedRegistry) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunAuthenticatedLiveMp4Scenario(directory.path(), true);
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunProtectionStartShutdownDrainScenario(
    const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);

  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "protection-shutdown-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (directory / "rtsp.credentials").string();

  struct BlockingStartState {
    std::mutex mutex;
    std::condition_variable changed;
    bool entered{false};
    bool release{false};
    camera_firmware::security::ProtectionSuite suite{
        camera_firmware::security::ProtectionSuite::kSelfTest};
    camera_firmware::security::ProtectionActor actor;
  } start_state;

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.protection_snapshot_callback = [] {
    camera_firmware::security::SystemProtectionSnapshot snapshot;
    snapshot.state = camera_firmware::security::ProtectionState::kOperational;
    return snapshot;
  };
  args.protection_start_check_callback =
      [&start_state](camera_firmware::security::ProtectionSuite suite,
                     camera_firmware::security::ProtectionActor actor) {
        {
          std::unique_lock lock(start_state.mutex);
          start_state.suite = suite;
          start_state.actor = std::move(actor);
          start_state.entered = true;
          start_state.changed.notify_all();
          start_state.changed.wait(lock, [&] { return start_state.release; });
        }
        camera_firmware::security::SystemProtectionSnapshot snapshot;
        snapshot.state = camera_firmware::security::ProtectionState::kChecking;
        snapshot.check_running = true;
        return camera_firmware::common::
            Result<camera_firmware::security::SystemProtectionSnapshot>::Ok(
                std::move(snapshot));
      };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);
  ExpectStatus(
      Send(
          client, drogon::Post, "/api/v1/setup/initialize",
          R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
          origin, InitialAccountCookie(client, origin), true),
      drogon::k200OK);
  const auto login = Send(client, drogon::Post, "/api/v1/auth/login",
                          R"({"username":"owner1","password":"StrongPass9!"})",
                          origin, {}, true);
  ExpectStatus(login, drogon::k200OK);
  const std::string cookie =
      "camera_session=" + login.response->getCookie("camera_session").value();

  auto request = std::async(std::launch::async, [&] {
    return Send(client, drogon::Post, "/api/v1/system/integrity-checks", "{}",
                origin, cookie, true);
  });
  {
    std::unique_lock lock(start_state.mutex);
    ASSERT_TRUE(start_state.changed.wait_for(
        lock, std::chrono::seconds(2), [&] { return start_state.entered; }));
  }

  auto shutdown =
      std::async(std::launch::async, [&] { service.BeginShutdown(); });
  EXPECT_EQ(shutdown.wait_for(std::chrono::milliseconds(150)),
            std::future_status::timeout);
  {
    std::lock_guard lock(start_state.mutex);
    start_state.release = true;
    start_state.changed.notify_all();
  }

  ASSERT_EQ(request.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  ExpectStatus(request.get(), drogon::k202Accepted);
  ASSERT_EQ(shutdown.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  shutdown.get();
  EXPECT_EQ(start_state.suite,
            camera_firmware::security::ProtectionSuite::kIntegrity);
  EXPECT_EQ(start_state.actor.username, "owner1");
  EXPECT_EQ(start_state.actor.peer_ip, "127.0.0.1");
  service.Stop();
}

TEST(HttpsAuthIntegrationTest, ProtectionStartAdmissionDrainsBeforeShutdown) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(30U);
    RunProtectionStartShutdownDrainScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

void RunProtectionBusyAdmissionScenario(
    const std::filesystem::path& directory) {
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "protection-busy-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (directory / "rtsp.credentials").string();

  camera_firmware::security::SystemProtectionDependencies
      protection_dependencies;
  protection_dependencies.run_self_tests = [] {
    return camera_firmware::common::Result<
        camera_firmware::security::SelfTestReport>::Ok({true,
                                                        {{"crypto.sha256", true,
                                                          "OK"}}});
  };
  protection_dependencies.run_integrity = [] {
    return camera_firmware::common::
        Result<camera_firmware::integrity::IntegrityVerificationReport>::Ok(
            {true,
             {{"camera-firmware",
               camera_firmware::integrity::IntegrityCategory::kFirmware, true,
               "OK"}}});
  };
  protection_dependencies.append_system_audit = [](auto, auto, auto) {
    return camera_firmware::common::Result<void>::Ok();
  };
  protection_dependencies.append_administrator_audit = [](auto const&, auto,
                                                          auto, auto) {
    return camera_firmware::common::Result<void>::Ok();
  };
  protection_dependencies.read_device_state = [] {
    return camera_firmware::common::
        Result<camera_firmware::security::DeviceState>::Ok(
            camera_firmware::security::DeviceState::kOperational);
  };
  camera_firmware::security::SystemProtectionService protection(
      std::move(protection_dependencies));
  ASSERT_EQ(protection.RunStartupChecks().state,
            camera_firmware::security::ProtectionState::kOperational);

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.protection_snapshot_callback = [&] { return protection.Snapshot(); };
  args.protection_start_check_callback =
      [&](camera_firmware::security::ProtectionSuite suite,
          camera_firmware::security::ProtectionActor actor) {
        return protection.StartManualCheck(suite, std::move(actor));
      };
  args.protection_runtime_allowed_callback = [&] {
    return protection.RuntimeAllowed();
  };
  args.protection_runtime_control_gate =
      [&](const std::function<void()>& command) {
        return protection.RunRuntimeControlIfAllowed(command);
      };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);
  ExpectStatus(
      Send(
          client, drogon::Post, "/api/v1/setup/initialize",
          R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
          origin, InitialAccountCookie(client, origin), true),
      drogon::k200OK);
  const auto login = Send(client, drogon::Post, "/api/v1/auth/login",
                          R"({"username":"owner1","password":"StrongPass9!"})",
                          origin, {}, true);
  ExpectStatus(login, drogon::k200OK);
  const std::string cookie =
      "camera_session=" + login.response->getCookie("camera_session").value();

  std::promise<void> command_entered;
  std::promise<void> release_command;
  auto release_command_future = release_command.get_future().share();
  PromiseReleaseGuard release_command_guard(release_command);
  auto command = std::async(std::launch::async, [&] {
    return protection.RunRuntimeControlIfAllowed([&] {
      command_entered.set_value();
      release_command_future.wait();
    });
  });
  ASSERT_EQ(command_entered.get_future().wait_for(std::chrono::seconds(2)),
            std::future_status::ready);

  auto request = std::async(std::launch::async, [&] {
    return Send(NewClient(port), drogon::Post,
                "/api/v1/system/integrity-checks", "{}", origin, cookie, true);
  });
  const auto prompt_status = request.wait_for(std::chrono::milliseconds(500));
  release_command_guard.Release();
  ASSERT_TRUE(command.get());
  ASSERT_EQ(request.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  const auto busy = request.get();
  EXPECT_EQ(prompt_status, std::future_status::ready);
  ExpectStatus(busy, drogon::k409Conflict);
  ASSERT_NE(busy.response->getJsonObject(), nullptr);
  EXPECT_EQ((*busy.response->getJsonObject())["code"].asString(),
            "E_PROTECTION_TRANSITION_BUSY");

  const auto accepted =
      Send(client, drogon::Post, "/api/v1/system/integrity-checks", "{}",
           origin, cookie, true);
  ExpectStatus(accepted, drogon::k202Accepted);
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (protection.Snapshot().check_running &&
         std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  EXPECT_FALSE(protection.Snapshot().check_running);
  service.Stop();
  protection.Stop();
}

TEST(HttpsAuthIntegrationTest,
     ProtectionBusyAdmissionReturnsPromptConflictWithoutBlockingEventLoop) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    RunProtectionBusyAdmissionScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(HttpsAuthIntegrationTest,
     AuditApiListsRealEventsWithStrictAuthorizationAndWireContracts) {
  TemporaryDirectory directory;
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);

  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = directory.path().string();
  config.security.audit.max_events = 50U;
  config.security.audit.warning_percent = 80U;
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "audit-api-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (directory.path() / "rtsp.credentials").string();

  auto opened = camera_firmware::security::SecurityStore::Open(
      {config.security.state_directory, config.security.audit.max_events,
       config.security.audit.warning_percent});
  ASSERT_TRUE(opened.ok()) << opened.error().message;
  auto store = std::shared_ptr<camera_firmware::security::SecurityStore>(
      std::move(opened).value());
  auto bootstrap =
      std::make_shared<camera_firmware::security::BootstrapService>(
          *store, config,
          camera_firmware::security::BuildReservedIdentities(config));

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.security_store = store;
  args.bootstrap_service = bootstrap;

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);

  ExpectStatus(
      Send(
          client, drogon::Post, "/api/v1/setup/initialize",
          R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
          origin, InitialAccountCookie(client, origin), true),
      drogon::k200OK);
  const auto unauthenticated =
      Send(client, drogon::Get, "/api/v1/audit/status");
  ExpectStatus(unauthenticated, drogon::k401Unauthorized);
  ASSERT_NE(unauthenticated.response->getJsonObject(), nullptr);
  EXPECT_EQ((*unauthenticated.response->getJsonObject())["code"].asString(),
            "E_AUTHENTICATION_REQUIRED");

  const auto administrator_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
  ExpectStatus(administrator_login, drogon::k200OK);
  const std::string administrator_cookie =
      "camera_session=" +
      administrator_login.response->getCookie("camera_session").value();

  const auto expect_audit_unavailable = [&](std::string_view path) {
    const auto unavailable = Send(client, drogon::Get, std::string(path), {},
                                  {}, administrator_cookie);
    ExpectStatus(unavailable, drogon::k503ServiceUnavailable);
    ASSERT_NE(unavailable.response->getJsonObject(), nullptr);
    ExpectJsonKeys(*unavailable.response->getJsonObject(), {"code", "message"});
    EXPECT_EQ((*unavailable.response->getJsonObject())["code"].asString(),
              "E_AUDIT_UNAVAILABLE");
    EXPECT_EQ((*unavailable.response->getJsonObject())["message"].asString(),
              "Audit records are temporarily unavailable.");
  };
  const auto expect_both_audit_routes_unavailable = [&] {
    for (const std::string_view path :
         {"/api/v1/audit/status", "/api/v1/audit/events"}) {
      expect_audit_unavailable(path);
    }
  };

  for (const std::string_view path :
       {"/api/v1/audit/status", "/api/v1/audit/events"}) {
    camera_firmware::service::internal::
        FailNextAuthorizationDispatchQueueForTesting();
    expect_audit_unavailable(path);
    camera_firmware::service::internal::
        ResetAuthorizationDispatchQueueFailureForTesting();
  }
  {
    AuditAuthorizationWorkerScope missing_worker(nullptr);
    expect_both_audit_routes_unavailable();
  }
  {
    auto stopped_worker =
        std::make_shared<camera_firmware::service::BoundedWorker>(1U);
    stopped_worker->Stop();
    AuditAuthorizationWorkerScope stopped(std::move(stopped_worker));
    expect_both_audit_routes_unavailable();
  }
  {
    auto saturated_worker =
        std::make_shared<camera_firmware::service::BoundedWorker>(1U);
    std::promise<void> blocker_started;
    std::promise<void> release_blocker;
    PromiseReleaseGuard release_guard(release_blocker);
    auto release_future = release_blocker.get_future().share();
    ASSERT_TRUE(saturated_worker
                    ->Submit([&blocker_started, release_future] {
                      blocker_started.set_value();
                      release_future.wait();
                    })
                    .ok());
    ASSERT_EQ(blocker_started.get_future().wait_for(std::chrono::seconds(2)),
              std::future_status::ready);
    ASSERT_TRUE(saturated_worker->Submit([] {}).ok());
    {
      AuditAuthorizationWorkerScope saturated(saturated_worker);
      expect_both_audit_routes_unavailable();
    }
    release_guard.Release();
    saturated_worker->Stop();
  }
  {
    AuditAuthorizationShutdownScope shutting_down(true);
    expect_both_audit_routes_unavailable();
  }
  {
    AuditAuthorizationStoreScope missing_store(nullptr);
    expect_both_audit_routes_unavailable();
  }
  {
    AuditAuthorizationServiceScope missing_auth_service(nullptr);
    expect_both_audit_routes_unavailable();
  }

  const auto created_viewer =
      Send(client, drogon::Post, "/api/v1/security/users",
           R"({"username":"viewer1","password":"ViewerPass9!"})", origin,
           administrator_cookie, true);
  ExpectStatus(created_viewer, drogon::k201Created);
  ExpectStatus(
      Send(client, drogon::Post, "/api/v1/security/management-ips/viewer",
           R"({"address":"127.0.0.1"})", origin, administrator_cookie, true),
      drogon::k201Created);
  const auto viewer_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"viewer1","password":"ViewerPass9!"})", origin, {}, true);
  ExpectStatus(viewer_login, drogon::k200OK);
  const std::string viewer_cookie =
      "camera_session=" +
      viewer_login.response->getCookie("camera_session").value();

  for (const std::string path :
       {"/api/v1/audit/status", "/api/v1/audit/events"}) {
    const auto denied = Send(client, drogon::Get, path, {}, {}, viewer_cookie);
    ExpectStatus(denied, drogon::k403Forbidden);
    ASSERT_NE(denied.response->getJsonObject(), nullptr);
    EXPECT_EQ((*denied.response->getJsonObject())["code"].asString(),
              "E_AUTHORIZATION_REQUIRED");
  }

  const auto status = Send(client, drogon::Get, "/api/v1/audit/status", {}, {},
                           administrator_cookie);
  ExpectStatus(status, drogon::k200OK);
  ASSERT_NE(status.response->getJsonObject(), nullptr);
  const auto& status_json = *status.response->getJsonObject();
  ExpectJsonKeys(status_json,
                 {"current_events", "max_events", "usage_percent", "warning",
                  "rotated_event_count", "last_rotation_at_seconds",
                  "last_rotated_sequence"});
  const auto event_count_before_reads =
      status_json["current_events"].asUInt64();
  EXPECT_GT(event_count_before_reads, 0U);
  EXPECT_EQ(status_json["max_events"].asUInt64(), 50U);
  EXPECT_TRUE(status_json["last_rotation_at_seconds"].isNull());
  EXPECT_TRUE(status_json["last_rotated_sequence"].isNull());

  const auto filtered = RawHttpsGet(
      port,
      "/api/v1/audit/events?event_type=viewer_created&actor_identity=owner1&"
      "subject_type=user&subject_identity=viewer1",
      {administrator_cookie});
  EXPECT_EQ(filtered.status, 200);
  const auto filtered_json = DecodeRawJsonBody(filtered);
  ASSERT_TRUE(filtered_json.has_value());
  ExpectJsonKeys(*filtered_json, {"events", "next_cursor"});
  ASSERT_TRUE((*filtered_json)["events"].isArray());
  ASSERT_EQ((*filtered_json)["events"].size(), 1U);
  const auto& filtered_event = (*filtered_json)["events"][0U];
  ExpectJsonKeys(filtered_event,
                 {"sequence", "server_timestamp_seconds", "event_type",
                  "outcome", "actor_identity", "peer_ip", "detail_code",
                  "subject_type", "subject_identity"});
  EXPECT_EQ(filtered_event["event_type"].asString(), "viewer_created");
  EXPECT_EQ(filtered_event["outcome"].asString(), "success");
  EXPECT_EQ(filtered_event["actor_identity"].asString(), "owner1");
  EXPECT_EQ(filtered_event["subject_type"].asString(), "user");
  EXPECT_EQ(filtered_event["subject_identity"].asString(), "viewer1");
  EXPECT_FALSE(filtered_event.isMember("actor_user_id"));

  const auto first_page = RawHttpsGet(
      port, "/api/v1/audit/events?sort_by=timestamp&sort_direction=asc&limit=2",
      {administrator_cookie});
  EXPECT_EQ(first_page.status, 200);
  const auto first_page_json = DecodeRawJsonBody(first_page);
  ASSERT_TRUE(first_page_json.has_value());
  ASSERT_EQ((*first_page_json)["events"].size(), 2U);
  ASSERT_TRUE((*first_page_json)["next_cursor"].isString());
  const auto collect_event_identities = [](const Json::Value& events) {
    std::vector<std::pair<std::int64_t, std::int64_t>> identities;
    identities.reserve(events.size());
    for (const auto& event : events) {
      identities.emplace_back(event["server_timestamp_seconds"].asInt64(),
                              event["sequence"].asInt64());
    }
    return identities;
  };
  const auto first_page_identities =
      collect_event_identities((*first_page_json)["events"]);
  ASSERT_EQ(first_page_identities.size(), 2U);
  EXPECT_TRUE(std::is_sorted(first_page_identities.begin(),
                             first_page_identities.end()));
  const std::string cursor = (*first_page_json)["next_cursor"].asString();
  ASSERT_FALSE(cursor.empty());

  const auto second_page = RawHttpsGet(
      port,
      "/api/v1/audit/events?sort_by=timestamp&sort_direction=asc&limit=2&"
      "cursor=" +
          cursor,
      {administrator_cookie});
  EXPECT_EQ(second_page.status, 200);
  const auto second_page_json = DecodeRawJsonBody(second_page);
  ASSERT_TRUE(second_page_json.has_value());
  ASSERT_FALSE((*second_page_json)["events"].empty());
  const auto second_page_identities =
      collect_event_identities((*second_page_json)["events"]);
  EXPECT_TRUE(std::is_sorted(second_page_identities.begin(),
                             second_page_identities.end()));
  for (const auto& identity : second_page_identities) {
    EXPECT_EQ(std::find(first_page_identities.begin(),
                        first_page_identities.end(), identity),
              first_page_identities.end());
  }
  EXPECT_LT(first_page_identities.back(), second_page_identities.front());

  for (const std::string path : {
           "/api/v1/audit/events?limit=1&limit=2",
           "/api/v1/audit/events?unknown=value",
           "/api/v1/audit/status?limit=1",
       }) {
    const auto malformed = RawHttpsGet(port, path, {administrator_cookie});
    EXPECT_EQ(malformed.status, 400) << path;
    const auto json = DecodeRawJsonBody(malformed);
    ASSERT_TRUE(json.has_value()) << path;
    ExpectJsonKeys(*json, {"code", "message"});
    EXPECT_EQ((*json)["code"].asString(), "E_AUDIT_QUERY_INVALID") << path;
    EXPECT_EQ((*json)["message"].asString(), "Audit query is invalid.") << path;
  }

  const auto body_rejected = RawHttpsJsonRequest(
      port, "GET", "/api/v1/audit/events", "{}", {}, administrator_cookie);
  EXPECT_EQ(body_rejected.status, 400);
  const auto body_error = DecodeRawJsonBody(body_rejected);
  ASSERT_TRUE(body_error.has_value());
  EXPECT_EQ((*body_error)["code"].asString(), "E_AUDIT_QUERY_INVALID");

  for (const auto& [method, path] :
       std::array<std::pair<std::string_view, std::string_view>, 4>{
           {{"POST", "/api/v1/audit/status"},
            {"PUT", "/api/v1/audit/events"},
            {"GET", "/api/v1/audit/status/"},
            {"GET", "/api/v1/audit/events/extra"}}}) {
    const auto unknown =
        RawHttpsJsonRequest(port, method, path, {}, {}, administrator_cookie);
    EXPECT_EQ(unknown.status, 404) << method << ' ' << path;
    const auto json = DecodeRawJsonBody(unknown);
    ASSERT_TRUE(json.has_value());
    EXPECT_EQ((*json)["code"].asString(), "E_NOT_FOUND");
  }

  const auto status_after_reads =
      Send(client, drogon::Get, "/api/v1/audit/status", {}, {},
           administrator_cookie);
  ExpectStatus(status_after_reads, drogon::k200OK);
  ASSERT_NE(status_after_reads.response->getJsonObject(), nullptr);
  EXPECT_EQ((*status_after_reads.response->getJsonObject())["current_events"]
                .asUInt64(),
            event_count_before_reads);

  service.Stop();
}

TEST(HttpsAuthIntegrationTest, SetupLoginSessionCsrfLogoutAndOverflowFlow) {
  TemporaryDirectory directory;
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);

  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = directory.path().string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "camera-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (directory.path() / "rtsp.credentials").string();

  std::atomic<int> camera_provider_calls{0};
  std::atomic<bool> throw_camera_provider{false};
  std::atomic<int> ai_status_calls{0};
  std::atomic<int> snapshot_calls{0};
  std::atomic<int> detection_snapshot_calls{0};
  std::atomic<int> detection_subscribe_calls{0};
  std::atomic<int> stream_diagnostics_calls{0};
  std::atomic<int> restart_calls{0};
  std::atomic<int> runtime_start_calls{0};
  std::atomic<bool> runtime_start_should_fail{true};
  std::atomic<bool> complete_sse_then_throw{false};
  std::atomic<bool> flood_mode{false};
  std::atomic<bool> flood_started_once{false};
  std::atomic<bool> shutdown_block_mode{false};
  std::atomic<unsigned int> random_counter{0U};
  std::promise<void> flood_started;
  std::promise<void> release_flood;
  auto release_flood_future = release_flood.get_future().share();
  std::promise<void> shutdown_block_started;
  std::promise<void> release_shutdown_block;
  auto release_shutdown_block_future =
      release_shutdown_block.get_future().share();

  auto opened = camera_firmware::security::SecurityStore::Open(
      {config.security.state_directory});
  ASSERT_TRUE(opened.ok()) << opened.error().message;
  auto store = std::shared_ptr<camera_firmware::security::SecurityStore>(
      std::move(opened).value());
  auto bootstrap =
      std::make_shared<camera_firmware::security::BootstrapService>(
          *store, config,
          camera_firmware::security::BuildReservedIdentities(config));
  camera_firmware::security::AuthServiceDependencies auth_dependencies;
  auth_dependencies.now_seconds = [] {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
  };
  auth_dependencies.random_bytes = [&](std::size_t size) {
    camera_firmware::common::SecureBytes bytes;
    bytes.resize(size);
    const auto seed =
        static_cast<unsigned char>(0x20U + random_counter.fetch_add(1U));
    std::fill(bytes.data(), bytes.data() + bytes.size(), seed);
    return camera_firmware::common::Result<
        camera_firmware::common::SecureBytes>::Ok(std::move(bytes));
  };
  auth_dependencies.firmware_log_random_bytes = auth_dependencies.random_bytes;
  auth_dependencies.verify_password =
      [&](const camera_firmware::common::SecureBytes& password,
          const camera_firmware::security::PasswordRecord& record) {
        if (flood_mode.load()) {
          if (!flood_started_once.exchange(true)) {
            flood_started.set_value();
          }
          release_flood_future.wait();
          return camera_firmware::common::Result<bool>::Ok(false);
        }
        if (shutdown_block_mode.load()) {
          shutdown_block_started.set_value();
          release_shutdown_block_future.wait();
          return camera_firmware::common::Result<bool>::Ok(false);
        }
        return camera_firmware::security::VerifyPassword(password, record);
      };
  auth_dependencies.high_severity_log = [](std::string_view, std::string_view) {
  };
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.camera_status_provider = [&] {
    camera_provider_calls.fetch_add(1);
    if (throw_camera_provider.load()) {
      throw std::runtime_error("provider failure detail");
    }
    return std::vector<camera_firmware::service::CameraStatus>{};
  };
  args.ai_restart_callback = [&] {
    restart_calls.fetch_add(1);
    return camera_firmware::common::Result<void>::Ok();
  };
  args.ai_status_provider = [&] {
    ai_status_calls.fetch_add(1);
    return camera_firmware::service::AiServiceStatus{};
  };
  args.snapshot_callback = [&](const std::string&) {
    snapshot_calls.fetch_add(1);
    return std::optional<camera_firmware::media::JpegBytes>{
        std::string("\xff\xd8\xff\xd9", 4U)};
  };
  args.detection_snapshot_provider = [&] {
    detection_snapshot_calls.fetch_add(1);
    return std::vector<camera_firmware::ai::DetectionEvent>{};
  };
  args.detection_event_subscriber =
      [&](camera_firmware::ai::DetectionBus::Handler handler) {
        detection_subscribe_calls.fetch_add(1);
        if (complete_sse_then_throw.load()) {
          camera_firmware::ai::DetectionEvent event;
          event.camera_id = "imx708-main";
          event.model_id = "detector";
          event.model_kind = "yolo";
          event.result_state = "ready";
          event.frame_sequence = 1U;
          handler(event);
          throw std::runtime_error("subscriber failure detail");
        }
        return camera_firmware::ai::DetectionBus::Subscription{};
      };
  args.secure_stream_diagnostics_provider = [&] {
    stream_diagnostics_calls.fetch_add(1);
    return camera_firmware::service::SecureStreamDiagnostics{};
  };
  args.runtime_start_callback = [&] {
    runtime_start_calls.fetch_add(1);
    if (runtime_start_should_fail.load()) {
      return camera_firmware::common::Result<void>::Err(
          {"E_RUNTIME_START", "runtime failure detail"});
    }
    return camera_firmware::common::Result<void>::Ok();
  };
  args.protection_runtime_allowed_callback = [] { return true; };
  args.protection_runtime_control_gate =
      [](const std::function<void()>& command) {
        command();
        return true;
      };
  args.security_store = store;
  args.bootstrap_service = bootstrap;
  args.auth_service_dependencies_provider = [auth_dependencies =
                                                 std::move(auth_dependencies)] {
    return auth_dependencies;
  };

  camera_firmware::service::ServiceApp service;
  auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);

  for (const std::string path :
       {"/", "/index.html", "/app.js", "/styles.css"}) {
    auto response = Send(client, drogon::Get, path);
    ExpectStatus(response, drogon::k200OK);
    ExpectSecurityHeaders(response.response);
  }
  for (const std::string path : {"/app.js.map", "/assets/app.js", "/dashboard",
                                 "/index.html/", "/%2e%2e/etc/passwd"}) {
    auto response = Send(client, drogon::Get, path);
    ExpectStatus(response, drogon::k404NotFound);
    ExpectSecurityHeaders(response.response);
  }

  auto setup_status = Send(client, drogon::Get, "/api/v1/setup/status");
  ExpectStatus(setup_status, drogon::k200OK);
  ExpectSecurityHeaders(setup_status.response);
  ASSERT_NE(setup_status.response->getJsonObject(), nullptr);
  EXPECT_TRUE((*setup_status.response->getJsonObject())["required"].asBool());
  EXPECT_EQ((*setup_status.response->getJsonObject())["phase"].asString(),
            "administrator");
  EXPECT_EQ((*setup_status.response->getJsonObject())["peer_ip"].asString(),
            "127.0.0.1");
  // The administrator phase serves the per-device initial account so the
  // operator can sign in to run setup.
  ASSERT_TRUE(
      setup_status.response->getJsonObject()->isMember("initial_username"));
  ASSERT_TRUE(
      setup_status.response->getJsonObject()->isMember("initial_password"));
  EXPECT_FALSE((*setup_status.response->getJsonObject())["initial_username"]
                   .asString()
                   .empty());
  EXPECT_FALSE((*setup_status.response->getJsonObject())["initial_password"]
                   .asString()
                   .empty());

  const std::string initial_username =
      (*setup_status.response->getJsonObject())["initial_username"].asString();
  const std::string initial_password =
      (*setup_status.response->getJsonObject())["initial_password"].asString();

  // The credential the login screen shows is the only one that opens a session
  // on an uninitialized device. The administrator account this setup is about
  // to create does not exist yet, and no account other than the initial one
  // can sign in even once it does.
  auto unknown_account_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
  ExpectStatus(unknown_account_login, drogon::k401Unauthorized);

  auto wrong_password_login =
      Send(client, drogon::Post, "/api/v1/auth/login",
           InitialAccountLoginBody(initial_username, "NotTheMintedPassword9!"),
           origin, {}, true);
  ExpectStatus(wrong_password_login, drogon::k401Unauthorized);

  auto initial_login =
      Send(client, drogon::Post, "/api/v1/auth/login",
           InitialAccountLoginBody(initial_username, initial_password), origin,
           {}, true);
  ExpectStatus(initial_login, drogon::k200OK);
  ASSERT_NE(initial_login.response->getJsonObject(), nullptr);
  EXPECT_EQ((*initial_login.response->getJsonObject())["role"].asString(),
            "viewer");
  const auto& initial_session =
      initial_login.response->getCookie("camera_session");
  ASSERT_FALSE(initial_session.value().empty());
  const std::string initial_cookie =
      "camera_session=" + initial_session.value();

  auto initial_me =
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, initial_cookie);
  ExpectStatus(initial_me, drogon::k200OK);
  ASSERT_NE(initial_me.response->getJsonObject(), nullptr);
  EXPECT_EQ((*initial_me.response->getJsonObject())["username"].asString(),
            initial_username);
  EXPECT_EQ((*initial_me.response->getJsonObject())["role"].asString(),
            "viewer");

  // The initial account's session is real and authenticated, but the
  // administrative surface is not part of the six-route default-state
  // allowlist at all: GET /api/v1/security/users is refused with the same
  // E_ACCESS_DENIED a wholly unauthenticated caller would get for any path
  // outside that list (compare denied_health below), not the
  // E_AUTHORIZATION_REQUIRED an operational device would give a viewer role
  // hitting an administrator-only route. The initial account never has a
  // credential that reaches further than setup itself.
  auto initial_security_users = Send(
      client, drogon::Get, "/api/v1/security/users", {}, {}, initial_cookie);
  ExpectStatus(initial_security_users, drogon::k403Forbidden);
  ASSERT_NE(initial_security_users.response->getJsonObject(), nullptr);
  EXPECT_EQ(
      (*initial_security_users.response->getJsonObject())["code"].asString(),
      "E_ACCESS_DENIED");

  auto initial_logout = Send(client, drogon::Post, "/api/v1/auth/logout", {},
                             origin, initial_cookie, true);
  ExpectStatus(initial_logout, drogon::k200OK);
  auto me_after_logout =
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, initial_cookie);
  ExpectStatus(me_after_logout, drogon::k401Unauthorized);

  auto denied_health = Send(client, drogon::Get, "/api/v1/health");
  ExpectStatus(denied_health, drogon::k403Forbidden);
  ExpectSecurityHeaders(denied_health.response);
  EXPECT_EQ(camera_provider_calls.load(), 0);

  const auto declared_oversized = RawHttpsExchange(
      port,
      "POST /api/v1/setup/initialize HTTP/1.1\r\nHost: 127.0.0.1\r\n"
      "Content-Length: 65537\r\nConnection: close\r\n\r\n");
  EXPECT_EQ(declared_oversized.status, 413);
  ExpectRawSecurityHeaders(declared_oversized);

  const auto chunked_oversized = RawHttpsExchange(
      port,
      "POST /api/v1/setup/initialize HTTP/1.1\r\nHost: 127.0.0.1\r\n"
      "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n10001\r\n");
  EXPECT_EQ(chunked_oversized.status, 413);
  ExpectRawSecurityHeaders(chunked_oversized);

  const std::string setup_body =
      R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})";
  auto setup_without_csrf =
      Send(client, drogon::Post, "/api/v1/setup/initialize", setup_body);
  ExpectStatus(setup_without_csrf, drogon::k403Forbidden);
  EXPECT_EQ(runtime_start_calls.load(), 0);

  // Without this, the displayed credential would protect nothing: any peer that
  // can reach the device could claim the administrator account without ever
  // knowing it. The session just logged out is no longer usable either.
  auto setup_without_session =
      Send(client, drogon::Post, "/api/v1/setup/initialize", setup_body, origin,
           {}, true);
  ExpectStatus(setup_without_session, drogon::k401Unauthorized);
  EXPECT_EQ(runtime_start_calls.load(), 0);

  auto setup_with_ended_session =
      Send(client, drogon::Post, "/api/v1/setup/initialize", setup_body, origin,
           initial_cookie, true);
  ExpectStatus(setup_with_ended_session, drogon::k401Unauthorized);
  EXPECT_EQ(runtime_start_calls.load(), 0);

  const std::string setup_cookie = InitialAccountCookie(client, origin);
  ASSERT_FALSE(setup_cookie.empty());

  auto oversized_setup =
      Send(client, drogon::Post, "/api/v1/setup/initialize",
           std::string(4097U, 'x'), origin, setup_cookie, true);
  ExpectStatus(oversized_setup, drogon::k413RequestEntityTooLarge);
  EXPECT_EQ(runtime_start_calls.load(), 0);

  auto setup = Send(client, drogon::Post, "/api/v1/setup/initialize",
                    setup_body, origin, setup_cookie, true);
  ExpectStatus(setup, drogon::k503ServiceUnavailable);
  ExpectSecurityHeaders(setup.response);
  EXPECT_EQ(setup.response->getBody().find("runtime failure detail"),
            std::string_view::npos);
  EXPECT_EQ(runtime_start_calls.load(), 1);

  auto pending_status = Send(client, drogon::Get, "/api/v1/setup/status");
  ExpectStatus(pending_status, drogon::k200OK);
  ASSERT_NE(pending_status.response->getJsonObject(), nullptr);
  EXPECT_TRUE((*pending_status.response->getJsonObject())["required"].asBool());
  EXPECT_EQ((*pending_status.response->getJsonObject())["phase"].asString(),
            "runtime_pending");
  EXPECT_EQ((*pending_status.response->getJsonObject())["peer_ip"].asString(),
            "127.0.0.1");
  // The administrator already exists and the initial account is deleted by this
  // point, so the credential must not be served even though `required` is still
  // true. This is the only site that exercises the phase half of the handler's
  // guard: once the device is operational `required` is false and the whole
  // block is skipped, so the operational assertions below cannot catch its
  // loss.
  EXPECT_FALSE(
      pending_status.response->getJsonObject()->isMember("initial_username"));
  EXPECT_FALSE(
      pending_status.response->getJsonObject()->isMember("initial_password"));

  auto different_peer = NewClient(port, "127.0.0.2");
  auto rejected_peer = Send(different_peer, drogon::Post,
                            "/api/v1/setup/runtime", "{}", origin, {}, true);
  ExpectStatus(rejected_peer, drogon::k403Forbidden);
  EXPECT_EQ(rejected_peer.response->getBody().find("127.0.0.1"),
            std::string_view::npos);
  EXPECT_EQ(rejected_peer.response->getBody().find("127.0.0.2"),
            std::string_view::npos);
  EXPECT_EQ(runtime_start_calls.load(), 1);

  // The device already has the real administrator account and management-ip
  // entry Initialize() created, and the setup surface admits auth/login,
  // auth/logout and auth/me while runtime_pending_peer is set. A peer other
  // than the one who confirmed setup must not be able to reach any of them:
  // otherwise, until this operator retries runtime start (which may never
  // happen if the failure persists), any host on the network can flood
  // /api/v1/auth/login, paying for a password verification and writing an
  // audit row per attempt without rate limiting, potentially evicting the
  // bootstrap_completed / initial_account_deleted rows from the audit ring
  // buffer. None of this should even reach AuthService for a non-pinned peer.
  auto rejected_login = Send(
      different_peer, drogon::Post, "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
  ExpectStatus(rejected_login, drogon::k403Forbidden);

  auto rejected_me = Send(different_peer, drogon::Get, "/api/v1/auth/me");
  ExpectStatus(rejected_me, drogon::k403Forbidden);

  auto rejected_logout = Send(different_peer, drogon::Post,
                              "/api/v1/auth/logout", {}, origin, {}, true);
  ExpectStatus(rejected_logout, drogon::k403Forbidden);

  // The other half of that pin: the peer who confirmed setup keeps all three
  // auth routes while the runtime is still pending, so an operator whose
  // runtime start failed is not locked out of the device they just set up.
  // Initialize() has already created the administrator and its management-ip
  // entry, so this is the ordinary operational credential path reached through
  // a state the gate still reports as default.
  auto runtime_pending_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
  ExpectStatus(runtime_pending_login, drogon::k200OK);
  const auto& runtime_pending_session =
      runtime_pending_login.response->getCookie("camera_session");
  ASSERT_FALSE(runtime_pending_session.value().empty());
  const std::string runtime_pending_cookie =
      "camera_session=" + runtime_pending_session.value();

  auto runtime_pending_me = Send(client, drogon::Get, "/api/v1/auth/me", {}, {},
                                 runtime_pending_cookie);
  ExpectStatus(runtime_pending_me, drogon::k200OK);
  ASSERT_NE(runtime_pending_me.response->getJsonObject(), nullptr);
  EXPECT_EQ(
      (*runtime_pending_me.response->getJsonObject())["username"].asString(),
      "owner1");
  EXPECT_EQ((*runtime_pending_me.response->getJsonObject())["role"].asString(),
            "administrator");

  // The initial account is gone, so no session can satisfy setup/initialize
  // any more — not even the administrator's.
  auto runtime_pending_setup =
      Send(client, drogon::Post, "/api/v1/setup/initialize", setup_body, origin,
           runtime_pending_cookie, true);
  ExpectStatus(runtime_pending_setup, drogon::k403Forbidden);
  EXPECT_EQ(runtime_start_calls.load(), 1);

  auto runtime_pending_logout =
      Send(client, drogon::Post, "/api/v1/auth/logout", {}, origin,
           runtime_pending_cookie, true);
  ExpectStatus(runtime_pending_logout, drogon::k200OK);

  runtime_start_should_fail.store(false);
  auto retry = Send(client, drogon::Post, "/api/v1/setup/runtime", "{}", origin,
                    {}, true);
  ExpectStatus(retry, drogon::k200OK);
  ASSERT_NE(retry.response->getJsonObject(), nullptr);
  EXPECT_FALSE((*retry.response->getJsonObject())["required"].asBool());
  EXPECT_EQ((*retry.response->getJsonObject())["runtime"].asString(),
            "running");
  EXPECT_EQ(runtime_start_calls.load(), 2);

  auto operational_status = Send(client, drogon::Get, "/api/v1/setup/status");
  ExpectStatus(operational_status, drogon::k200OK);
  ASSERT_NE(operational_status.response->getJsonObject(), nullptr);
  EXPECT_FALSE(
      (*operational_status.response->getJsonObject())["required"].asBool());
  EXPECT_FALSE(
      operational_status.response->getJsonObject()->isMember("peer_ip"));
  EXPECT_FALSE(operational_status.response->getJsonObject()->isMember("phase"));
  // The initial account was deleted when setup completed: both members must be
  // absent from the object, not present and empty, so no live credential can be
  // read from this unauthenticated endpoint afterwards.
  EXPECT_FALSE(operational_status.response->getJsonObject()->isMember(
      "initial_username"));
  EXPECT_FALSE(operational_status.response->getJsonObject()->isMember(
      "initial_password"));

  // The session that ran setup belonged to the initial account, and that
  // account was deleted inside Initialize()'s transaction. This is the
  // end-to-end end of that: the cookie an operator still holds in their
  // browser when the device goes operational buys them nothing. The row-level
  // proof that the session went with the account is
  // AuthServiceTest.InitialAccountSessionDiesWhenSetupCompletes.
  auto setup_session_after_transition =
      Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, setup_cookie);
  ExpectStatus(setup_session_after_transition, drogon::k401Unauthorized);
  auto setup_after_transition =
      Send(client, drogon::Post, "/api/v1/setup/initialize", setup_body, origin,
           setup_cookie, true);
  ExpectStatus(setup_after_transition, drogon::k403Forbidden);

  ResetUserManagementBodyCleanupForTesting();
  camera_firmware::service::internal::
      SetUserManagementRequestBodyCleanupObserverForTesting(
          RecordUserManagementBodyCleanupForTesting);
  auto repeated_setup = Send(client, drogon::Post, "/api/v1/setup/initialize",
                             setup_body, origin, {}, true);
  ExpectStatus(repeated_setup, drogon::k403Forbidden);
  EXPECT_EQ(repeated_setup.response->getBody().find("StrongPass9!"),
            std::string::npos);
  EXPECT_EQ(runtime_start_calls.load(), 2);

  auto unauthenticated = Send(client, drogon::Get, "/api/v1/cameras");
  ExpectStatus(unauthenticated, drogon::k401Unauthorized);
  ExpectStatus(
      Send(client, drogon::Get, "/api/v1/cameras/imx708-main/snapshot.jpg"),
      drogon::k401Unauthorized);
  ExpectStatus(Send(client, drogon::Get, "/api/v1/ai/detections"),
               drogon::k401Unauthorized);
  ExpectStatus(Send(client, drogon::Get, "/api/v1/ai/detections/stream"),
               drogon::k401Unauthorized);
  ExpectStatus(Send(client, drogon::Get, "/api/v1/stream"),
               drogon::k401Unauthorized);
  ExpectStatus(Send(client, drogon::Post, "/api/v1/ai/restart"),
               drogon::k401Unauthorized);
  ExpectStatus(Send(client, drogon::Post, "/api/v1/runtime/restart"),
               drogon::k401Unauthorized);
  EXPECT_EQ(camera_provider_calls.load(), 0);
  EXPECT_EQ(ai_status_calls.load(), 0);
  EXPECT_EQ(snapshot_calls.load(), 0);
  EXPECT_EQ(detection_snapshot_calls.load(), 0);
  EXPECT_EQ(detection_subscribe_calls.load(), 0);
  EXPECT_EQ(stream_diagnostics_calls.load(), 0);
  EXPECT_EQ(restart_calls.load(), 0);

  const std::string login_body =
      R"({"username":"owner1","password":"StrongPass9!"})";
  auto cross_origin_login =
      Send(client, drogon::Post, "/api/v1/auth/login", login_body,
           "https://attacker.example", {}, true);
  ExpectStatus(cross_origin_login, drogon::k403Forbidden);
  EXPECT_EQ(cross_origin_login.response->getBody().find("StrongPass9!"),
            std::string::npos);
  const auto& denied_secret_cleanup = UserManagementBodyCleanupForTesting();
  EXPECT_EQ(denied_secret_cleanup.calls.load(std::memory_order_relaxed), 2U);
  EXPECT_EQ(denied_secret_cleanup.copied_to_secure_owner.load(
                std::memory_order_relaxed),
            2U);
  EXPECT_TRUE(
      denied_secret_cleanup.source_cleansed.load(std::memory_order_relaxed));

  std::atomic<int> unavailable{0};
  std::vector<std::thread> flood;
  flood_mode.store(true);
  for (int index = 0; index < 20; ++index) {
    flood.emplace_back([&, index] {
      auto flood_client = NewClient(port);
      auto response = Send(flood_client, drogon::Post, "/api/v1/auth/login",
                           "{\"username\":\"missing" + std::to_string(index) +
                               "\",\"password\":\"StrongPass9!\"}",
                           origin, {}, true);
      if (response.result == drogon::ReqResult::Ok && response.response &&
          response.response->statusCode() == drogon::k503ServiceUnavailable) {
        unavailable.fetch_add(1);
      }
    });
  }
  ASSERT_EQ(flood_started.get_future().wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  auto status_during_blocked_kdf =
      Send(client, drogon::Get, "/api/v1/setup/status");
  ExpectStatus(status_during_blocked_kdf, drogon::k200OK);
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  release_flood.set_value();
  for (auto& thread : flood) {
    thread.join();
  }
  flood_mode.store(false);
  EXPECT_GT(unavailable.load(), 0);
  EXPECT_GE(denied_secret_cleanup.calls.load(std::memory_order_relaxed),
            2U + static_cast<std::size_t>(unavailable.load()));
  EXPECT_EQ(denied_secret_cleanup.copied_to_secure_owner.load(
                std::memory_order_relaxed),
            denied_secret_cleanup.calls.load(std::memory_order_relaxed));
  EXPECT_TRUE(
      denied_secret_cleanup.source_cleansed.load(std::memory_order_relaxed));
  camera_firmware::service::internal::
      ResetUserManagementRequestBodyCleanupObserverForTesting();

  const std::string wrong_password = "LeakProbe9!";
  auto wrong_login =
      Send(client, drogon::Post, "/api/v1/auth/login",
           "{\"username\":\"owner1\",\"password\":\"" + wrong_password + "\"}",
           origin, {}, true);
  ExpectStatus(wrong_login, drogon::k401Unauthorized);
  EXPECT_EQ(wrong_login.response->getBody().find("owner1"),
            std::string_view::npos);
  EXPECT_EQ(wrong_login.response->getBody().find(wrong_password),
            std::string_view::npos);

  auto login = Send(client, drogon::Post, "/api/v1/auth/login", login_body,
                    origin, {}, true);
  ExpectStatus(login, drogon::k200OK);
  const auto& session_cookie = login.response->getCookie("camera_session");
  ASSERT_FALSE(session_cookie.value().empty());
  EXPECT_TRUE(session_cookie.isSecure());
  EXPECT_TRUE(session_cookie.isHttpOnly());
  EXPECT_EQ(session_cookie.sameSite(), drogon::Cookie::SameSite::kStrict);
  EXPECT_EQ(session_cookie.path(), "/");
  const std::string cookie = "camera_session=" + session_cookie.value();

  EXPECT_EQ(RawHttpsGet(port, "/api/v1/auth/me", {cookie}).status, 200);
  EXPECT_EQ(RawHttpsGet(port, "/api/v1/auth/me", {cookie, cookie}).status, 401);

  auto me = Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, cookie);
  ExpectStatus(me, drogon::k200OK);
  ExpectSecurityHeaders(me.response);
  ASSERT_NE(me.response->getJsonObject(), nullptr);
  EXPECT_EQ((*me.response->getJsonObject())["username"].asString(), "owner1");
  EXPECT_EQ((*me.response->getJsonObject())["role"].asString(),
            "administrator");

  // Browsers scope cookies per host and ignore the port, so a cookie set by
  // any other service on this address rides the same Cookie line; the
  // session must survive that. Two camera_session pairs are ambiguous and
  // still fail closed.
  auto coexisting_cookie = Send(client, drogon::Get, "/api/v1/auth/me", {}, {},
                                cookie + "; theme=dark");
  ExpectStatus(coexisting_cookie, drogon::k200OK);
  ASSERT_NE(coexisting_cookie.response->getJsonObject(), nullptr);
  EXPECT_EQ(
      (*coexisting_cookie.response->getJsonObject())["username"].asString(),
      "owner1");
  auto duplicated_session = Send(client, drogon::Get, "/api/v1/auth/me", {}, {},
                                 cookie + "; " + cookie);
  ExpectStatus(duplicated_session, drogon::k401Unauthorized);

  auto cameras = Send(client, drogon::Get, "/api/v1/cameras", {}, {}, cookie);
  ExpectStatus(cameras, drogon::k200OK);
  ExpectSecurityHeaders(cameras.response);
  EXPECT_EQ(camera_provider_calls.load(), 1);

  auto snapshot =
      Send(client, drogon::Get, "/api/v1/cameras/imx708-main/snapshot.jpg", {},
           {}, cookie);
  ExpectStatus(snapshot, drogon::k200OK);
  ExpectSecurityHeaders(snapshot.response);

  complete_sse_then_throw.store(true);
  auto retained_sse =
      Send(client, drogon::Get, "/api/v1/ai/detections/stream", {}, {}, cookie);
  ExpectStatus(retained_sse, drogon::k200OK);
  ExpectSecurityHeaders(retained_sse.response);
  EXPECT_EQ(retained_sse.response->getBody().find("subscriber failure detail"),
            std::string_view::npos);
  complete_sse_then_throw.store(false);

  throw_camera_provider.store(true);
  auto provider_failure =
      Send(client, drogon::Get, "/api/v1/cameras", {}, {}, cookie);
  ExpectStatus(provider_failure, drogon::k503ServiceUnavailable);
  EXPECT_EQ(provider_failure.response->getBody().find("provider failure"),
            std::string_view::npos);
  throw_camera_provider.store(false);

  auto no_csrf_restart =
      Send(client, drogon::Post, "/api/v1/ai/restart", {}, {}, cookie);
  ExpectStatus(no_csrf_restart, drogon::k403Forbidden);
  EXPECT_EQ(restart_calls.load(), 0);

  auto valid_restart = Send(client, drogon::Post, "/api/v1/ai/restart", {},
                            origin, cookie, true);
  ExpectStatus(valid_restart, drogon::k200OK);
  EXPECT_EQ(restart_calls.load(), 1);

  auto no_csrf_runtime_restart =
      Send(client, drogon::Post, "/api/v1/runtime/restart", "{}", {}, cookie);
  ExpectStatus(no_csrf_runtime_restart, drogon::k403Forbidden);
  EXPECT_EQ(runtime_start_calls.load(), 2);

  runtime_start_should_fail.store(true);
  auto failed_runtime_restart =
      Send(client, drogon::Post, "/api/v1/runtime/restart", "{}", origin,
           cookie, true);
  ExpectStatus(failed_runtime_restart, drogon::k503ServiceUnavailable);
  EXPECT_EQ(
      failed_runtime_restart.response->getBody().find("runtime failure detail"),
      std::string_view::npos);
  EXPECT_EQ(runtime_start_calls.load(), 3);
  ExpectStatus(Send(client, drogon::Get, "/api/v1/health", {}, {}, cookie),
               drogon::k200OK);

  runtime_start_should_fail.store(false);
  auto recovered_runtime = Send(client, drogon::Post, "/api/v1/runtime/restart",
                                "{}", origin, cookie, true);
  ExpectStatus(recovered_runtime, drogon::k200OK);
  ASSERT_NE(recovered_runtime.response->getJsonObject(), nullptr);
  EXPECT_EQ(
      (*recovered_runtime.response->getJsonObject())["runtime"].asString(),
      "running");
  EXPECT_EQ(runtime_start_calls.load(), 4);

  auto forwarded = drogon::HttpRequest::newHttpRequest();
  forwarded->setMethod(drogon::Get);
  forwarded->setPath("/api/v1/auth/me");
  forwarded->addHeader("Cookie", cookie);
  forwarded->addHeader("Forwarded", "for=203.0.113.9");
  forwarded->addHeader("X-Forwarded-For", "203.0.113.9");
  auto [forwarded_result, forwarded_response] =
      client->sendRequest(forwarded, 15.0);
  ExpectStatus({forwarded_result, forwarded_response}, drogon::k200OK);

  auto logout = Send(client, drogon::Post, "/api/v1/auth/logout", {}, origin,
                     cookie, true);
  ExpectStatus(logout, drogon::k200OK);
  const auto& cleared = logout.response->getCookie("camera_session");
  EXPECT_EQ(cleared.value(), "");
  ASSERT_TRUE(cleared.maxAge().has_value());
  EXPECT_EQ(*cleared.maxAge(), 0);
  EXPECT_TRUE(cleared.isSecure());
  EXPECT_TRUE(cleared.isHttpOnly());
  EXPECT_EQ(cleared.sameSite(), drogon::Cookie::SameSite::kStrict);
  EXPECT_EQ(cleared.path(), "/");

  auto replay = Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, cookie);
  ExpectStatus(replay, drogon::k401Unauthorized);

  ResetUserManagementBodyCleanupForTesting();
  camera_firmware::service::internal::
      SetUserManagementRequestBodyCleanupObserverForTesting(
          RecordUserManagementBodyCleanupForTesting);
  shutdown_block_mode.store(true);
  HttpResult shutdown_login;
  std::thread pending_login([&] {
    auto shutdown_client = NewClient(port);
    shutdown_login = Send(shutdown_client, drogon::Post, "/api/v1/auth/login",
                          login_body, origin, {}, true);
  });
  ASSERT_EQ(
      shutdown_block_started.get_future().wait_for(std::chrono::seconds(5)),
      std::future_status::ready);
  auto stopping = std::async(std::launch::async, [&] { service.Stop(); });
  EXPECT_EQ(stopping.wait_for(std::chrono::milliseconds(50)),
            std::future_status::timeout);
  release_shutdown_block.set_value();
  pending_login.join();
  ExpectStatus(shutdown_login, drogon::k401Unauthorized);
  EXPECT_EQ(stopping.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
  const auto& shutdown_cleanup = UserManagementBodyCleanupForTesting();
  EXPECT_EQ(shutdown_cleanup.calls.load(std::memory_order_relaxed), 1U);
  EXPECT_EQ(
      shutdown_cleanup.copied_to_secure_owner.load(std::memory_order_relaxed),
      1U);
  EXPECT_TRUE(shutdown_cleanup.source_cleansed.load(std::memory_order_relaxed));
  camera_firmware::service::internal::
      ResetUserManagementRequestBodyCleanupObserverForTesting();
}

TEST(HttpsAuthIntegrationTest, RuntimeSettingsAreUnavailableWithoutSecurity) {
  const auto scenario = ProcessArgumentValue(kRuntimeSettingsScenarioArgument);
  if (!scenario.has_value()) {
    TemporaryDirectory directory;
    const int status = RunFreshRuntimeSettingsScenario(
        "HttpsAuthIntegrationTest.RuntimeSettingsAreUnavailableWithoutSecurity",
        "unavailable-without-security", directory.path());
    ASSERT_NE(status, -1);
    ASSERT_TRUE(WIFEXITED(status))
        << "child signal " << (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    EXPECT_EQ(WEXITSTATUS(status), 0);
    return;
  }

  const auto state_directory = RuntimeSettingsScenarioStateDirectory();
  if (*scenario == "unavailable-without-security" &&
      state_directory.has_value()) {
    const std::uint16_t port = ReserveLoopbackPort();
    camera_firmware::config::AppConfig config;
    config.security.enabled = false;
    config.security.state_directory = state_directory->string();
    config.http.enabled = true;
    config.http.bind_ip = "127.0.0.1";
    config.http.port = port;
    config.http.tls.enabled = true;
    config.http.tls.allow_development_self_signed_tls = true;

    camera_firmware::settings::RuntimeSettingsSnapshot snapshot;
    camera_firmware::service::ServiceInitArgs args;
    args.app_config = &config;
    args.provider = &TestCryptoProvider();
    args.runtime_settings_snapshot_callback = [snapshot] { return snapshot; };
    args.runtime_settings_save_callback =
        [snapshot](std::uint64_t, camera_firmware::settings::RuntimeSettings) {
          return camera_firmware::common::Result<
              camera_firmware::settings::RuntimeSettingsSnapshot>::Ok(snapshot);
        };
    args.runtime_settings_apply_callback = [snapshot](std::uint64_t) {
      return camera_firmware::settings::SettingsApplyResult{
          snapshot, true, false, {}};
    };
    args.runtime_settings_discard_callback = [snapshot](std::uint64_t) {
      return camera_firmware::common::Result<
          camera_firmware::settings::RuntimeSettingsSnapshot>::Ok(snapshot);
    };

    camera_firmware::service::ServiceApp service;
    const auto started = service.Init(args);
    if (!started.ok()) {
      _exit(2);
    }
    camera_firmware::service::internal::
        FailNextAuthorizationDispatchQueueForTesting();
    const auto queue_failure =
        Send(NewClient(port), drogon::Get, "/api/v1/settings/runtime", {}, {},
             {}, false, 1.0);
    camera_firmware::service::internal::
        ResetAuthorizationDispatchQueueFailureForTesting();
    if (queue_failure.result != drogon::ReqResult::Ok ||
        !queue_failure.response ||
        queue_failure.response->statusCode() !=
            drogon::k503ServiceUnavailable ||
        queue_failure.response->getJsonObject() == nullptr ||
        (*queue_failure.response->getJsonObject())["code"].asString() !=
            "E_SECURITY_UNAVAILABLE") {
      _exit(3);
    }
    const auto response =
        Send(NewClient(port), drogon::Get, "/api/v1/settings/runtime");
    if (response.result != drogon::ReqResult::Ok || !response.response ||
        response.response->statusCode() != drogon::k503ServiceUnavailable ||
        response.response->getJsonObject() == nullptr ||
        (*response.response->getJsonObject())["code"].asString() !=
            "E_SETTINGS_UNAVAILABLE") {
      _exit(4);
    }
    service.Stop();
    _exit(0);
  }
  _exit(124);
}

TEST(HttpsAuthIntegrationTest,
     RuntimeSettingsPendingSaveSurvivesSecurityAndServiceRestart) {
  const auto scenario = ProcessArgumentValue(kRuntimeSettingsScenarioArgument);
  if (scenario.has_value()) {
    const auto state_directory = RuntimeSettingsScenarioStateDirectory();
    if (!state_directory.has_value()) {
      _exit(124);
    }
    if (*scenario == "persistence-save") {
      _exit(RunRuntimeSettingsPersistenceLifecycle(*state_directory, true));
    }
    if (*scenario == "persistence-read") {
      _exit(RunRuntimeSettingsPersistenceLifecycle(*state_directory, false));
    }
    _exit(125);
  }

  TemporaryDirectory directory;
  const int first_status = RunFreshRuntimeSettingsScenario(
      "HttpsAuthIntegrationTest."
      "RuntimeSettingsPendingSaveSurvivesSecurityAndServiceRestart",
      "persistence-save", directory.path());
  ASSERT_NE(first_status, -1);
  ASSERT_TRUE(WIFEXITED(first_status))
      << "child signal "
      << (WIFSIGNALED(first_status) ? WTERMSIG(first_status) : 0);
  ASSERT_EQ(WEXITSTATUS(first_status), 0);

  const int second_status = RunFreshRuntimeSettingsScenario(
      "HttpsAuthIntegrationTest."
      "RuntimeSettingsPendingSaveSurvivesSecurityAndServiceRestart",
      "persistence-read", directory.path());
  ASSERT_NE(second_status, -1);
  ASSERT_TRUE(WIFEXITED(second_status))
      << "child signal "
      << (WIFSIGNALED(second_status) ? WTERMSIG(second_status) : 0);
  EXPECT_EQ(WEXITSTATUS(second_status), 0);
}

TEST(HttpsAuthIntegrationTest,
     RuntimeSettingsIncompleteCallbacksAreUnavailableAfterAuthorization) {
  const auto scenario = ProcessArgumentValue(kRuntimeSettingsScenarioArgument);
  if (!scenario.has_value()) {
    TemporaryDirectory directory;
    const int status = RunFreshRuntimeSettingsScenario(
        "HttpsAuthIntegrationTest."
        "RuntimeSettingsIncompleteCallbacksAreUnavailableAfterAuthorization",
        "incomplete-callbacks", directory.path());
    ASSERT_NE(status, -1);
    ASSERT_TRUE(WIFEXITED(status))
        << "child signal " << (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    EXPECT_EQ(WEXITSTATUS(status), 0);
    return;
  }

  const auto state_directory = RuntimeSettingsScenarioStateDirectory();
  if (*scenario == "incomplete-callbacks" && state_directory.has_value()) {
    const std::uint16_t port = ReserveLoopbackPort();
    const std::string origin = "https://127.0.0.1:" + std::to_string(port);
    camera_firmware::config::AppConfig config;
    config.security.enabled = true;
    config.security.state_directory = state_directory->string();
    config.http.enabled = true;
    config.http.bind_ip = "127.0.0.1";
    config.http.port = port;
    config.http.public_base_url = origin;
    config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
    config.http.tls.enabled = true;
    config.http.tls.allow_development_self_signed_tls = true;
    config.secure_rtsp.client_auth.enabled = true;
    config.secure_rtsp.client_auth.realm = "camera-test";
    config.secure_rtsp.client_auth.algorithms = {"sha-256"};
    config.secure_rtsp.client_auth.credential_file =
        (*state_directory / "rtsp.credentials").string();

    camera_firmware::service::ServiceInitArgs args;
    args.app_config = &config;
    args.provider = &TestCryptoProvider();
    args.document_root = config.http.web_root;
    args.public_base_url = origin;
    args.runtime_start_callback = [] {
      return camera_firmware::common::Result<void>::Ok();
    };
    args.protection_runtime_allowed_callback = [] { return true; };
    args.protection_runtime_control_gate =
        [](const std::function<void()>& command) {
          command();
          return true;
        };
    args.runtime_settings_snapshot_callback = [] {
      return camera_firmware::settings::RuntimeSettingsSnapshot{};
    };

    camera_firmware::service::ServiceApp service;
    const auto started = service.Init(args);
    if (!started.ok()) {
      _exit(2);
    }
    auto client = NewClient(port);
    const auto setup = Send(
        client, drogon::Post, "/api/v1/setup/initialize",
        R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
        origin, InitialAccountCookie(client, origin), true);
    if (!setup.response || setup.response->statusCode() != drogon::k200OK) {
      _exit(3);
    }
    const auto login = Send(
        client, drogon::Post, "/api/v1/auth/login",
        R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
    if (!login.response || login.response->statusCode() != drogon::k200OK) {
      _exit(4);
    }
    const std::string cookie =
        "camera_session=" + login.response->getCookie("camera_session").value();

    const auto get =
        Send(client, drogon::Get, "/api/v1/settings/runtime", {}, {}, cookie);
    const auto put = Send(client, drogon::Put, "/api/v1/settings/runtime", "{}",
                          origin, cookie, true);
    const auto unavailable = [](const HttpResult& response) {
      return response.result == drogon::ReqResult::Ok && response.response &&
             response.response->statusCode() ==
                 drogon::k503ServiceUnavailable &&
             response.response->getJsonObject() != nullptr &&
             (*response.response->getJsonObject())["code"].asString() ==
                 "E_SETTINGS_UNAVAILABLE";
    };
    const bool passed = unavailable(get) && unavailable(put);
    service.Stop();
    _exit(passed ? 0 : 5);
  }
  _exit(124);
}

TEST(HttpsAuthIntegrationTest,
     RuntimeSettingsRoutesEnforceAuthCsrfQueueCapacityAndShutdownDrain) {
  const auto scenario = ProcessArgumentValue(kRuntimeSettingsScenarioArgument);
  if (!scenario.has_value()) {
    TemporaryDirectory directory;
    const int status = RunFreshRuntimeSettingsScenario(
        "HttpsAuthIntegrationTest."
        "RuntimeSettingsRoutesEnforceAuthCsrfQueueCapacityAndShutdownDrain",
        "routes-and-shutdown", directory.path(), 60U);
    ASSERT_NE(status, -1);
    ASSERT_TRUE(WIFEXITED(status))
        << "child signal " << (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    EXPECT_EQ(WEXITSTATUS(status), 0);
    return;
  }

  const auto state_directory = RuntimeSettingsScenarioStateDirectory();
  if (*scenario == "routes-and-shutdown" && state_directory.has_value()) {
    const std::uint16_t port = ReserveLoopbackPort();
    const std::string origin = "https://127.0.0.1:" + std::to_string(port);
    camera_firmware::config::AppConfig config;
    config.security.enabled = true;
    config.security.state_directory = state_directory->string();
    config.http.enabled = true;
    config.http.bind_ip = "127.0.0.1";
    config.http.port = port;
    config.http.public_base_url = origin;
    config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
    config.http.tls.enabled = true;
    config.http.tls.allow_development_self_signed_tls = true;
    config.secure_rtsp.client_auth.enabled = true;
    config.secure_rtsp.client_auth.realm = "camera-test";
    config.secure_rtsp.client_auth.algorithms = {"sha-256"};
    config.secure_rtsp.client_auth.credential_file =
        (*state_directory / "rtsp.credentials").string();

    camera_firmware::settings::RuntimeSettingsSnapshot snapshot;
    snapshot.revision = 7U;
    snapshot.state = camera_firmware::settings::RuntimeSettingsState::kClean;
    snapshot.active.camera = {"imx708-1080p50", 6000U, 25U};
    snapshot.active.models = {{"objects", true, 0.40F}, {"pose", true, 0.35F}};
    snapshot.camera_profiles = {
        {"imx708-1080p50", "1080p 50 fps", 1920U, 1080U, 50U},
        {"imx708-1080p30", "1080p 30 fps", 1920U, 1080U, 30U},
    };
    snapshot.model_capabilities = {
        {"objects", "object_detection", 640U, 640U, "rgb8", true, "coco80"},
        {"pose", "pose_estimation", 640U, 640U, "rgb8", false, "pose17"},
    };

    std::mutex snapshot_mutex;
    std::atomic<bool> block_save{false};
    std::atomic<bool> save_started_once{false};
    std::promise<void> save_started;
    std::promise<void> release_save;
    auto release_save_future = release_save.get_future().share();
    PromiseReleaseGuard release_save_guard(release_save);
    std::atomic<bool> saturate_apply{false};
    std::atomic<unsigned int> saturated_apply_calls{0U};
    std::promise<void> apply_started;
    std::promise<void> release_apply;
    auto release_apply_future = release_apply.get_future().share();
    PromiseReleaseGuard release_apply_guard(release_apply);
    std::atomic<bool> runtime_control_allowed{true};

    camera_firmware::service::ServiceInitArgs args;
    args.app_config = &config;
    args.provider = &TestCryptoProvider();
    args.document_root = config.http.web_root;
    args.public_base_url = origin;
    args.runtime_start_callback = [] {
      return camera_firmware::common::Result<void>::Ok();
    };
    args.protection_runtime_allowed_callback = [&] {
      return runtime_control_allowed.load();
    };
    args.protection_runtime_control_gate =
        [&](const std::function<void()>& command) {
          if (!runtime_control_allowed.load()) {
            return false;
          }
          command();
          return true;
        };
    args.runtime_settings_snapshot_callback = [&] {
      std::lock_guard lock(snapshot_mutex);
      return snapshot;
    };
    args.runtime_settings_save_callback =
        [&](std::uint64_t expected_revision,
            camera_firmware::settings::RuntimeSettings settings) {
          if (block_save.load()) {
            if (!save_started_once.exchange(true)) {
              save_started.set_value();
            }
            release_save_future.wait();
          }
          std::lock_guard lock(snapshot_mutex);
          if (expected_revision != snapshot.revision) {
            return camera_firmware::common::
                Result<camera_firmware::settings::RuntimeSettingsSnapshot>::Err(
                    {"E_RUNTIME_SETTINGS_REVISION", "private stale detail"});
          }
          snapshot.pending = std::move(settings);
          snapshot.state =
              camera_firmware::settings::RuntimeSettingsState::kPending;
          ++snapshot.revision;
          return camera_firmware::common::Result<
              camera_firmware::settings::RuntimeSettingsSnapshot>::Ok(snapshot);
        };
    args.runtime_settings_apply_callback = [&](std::uint64_t) {
      if (saturate_apply.load()) {
        if (saturated_apply_calls.fetch_add(1U) == 0U) {
          apply_started.set_value();
          release_apply_future.wait();
        }
        std::lock_guard lock(snapshot_mutex);
        return camera_firmware::settings::SettingsApplyResult{
            snapshot, true, false, {}};
      }
      std::lock_guard lock(snapshot_mutex);
      return camera_firmware::settings::SettingsApplyResult{
          snapshot,
          false,
          true,
          {"E_RUNTIME_SETTINGS_APPLY",
           "private /opt/models/model.hef backend detail"}};
    };
    args.runtime_settings_discard_callback =
        [&](std::uint64_t expected_revision) {
          std::lock_guard lock(snapshot_mutex);
          if (expected_revision != snapshot.revision) {
            return camera_firmware::common::
                Result<camera_firmware::settings::RuntimeSettingsSnapshot>::Err(
                    {"E_RUNTIME_SETTINGS_REVISION", "private stale detail"});
          }
          snapshot.pending.reset();
          snapshot.state =
              camera_firmware::settings::RuntimeSettingsState::kClean;
          ++snapshot.revision;
          return camera_firmware::common::Result<
              camera_firmware::settings::RuntimeSettingsSnapshot>::Ok(snapshot);
        };

    camera_firmware::service::ServiceApp service;
    const auto started = service.Init(args);
    if (!started.ok()) {
      _exit(2);
    }
    auto client = NewClient(port);
    const auto default_denied =
        Send(client, drogon::Get, "/api/v1/settings/runtime");
    if (!default_denied.response ||
        default_denied.response->statusCode() != drogon::k403Forbidden) {
      _exit(3);
    }

    const std::string setup_body =
        R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})";
    const auto setup =
        Send(client, drogon::Post, "/api/v1/setup/initialize", setup_body,
             origin, InitialAccountCookie(client, origin), true);
    if (!setup.response || setup.response->statusCode() != drogon::k200OK) {
      _exit(4);
    }
    const auto operational_unauthenticated =
        Send(client, drogon::Get, "/api/v1/settings/runtime");
    if (!operational_unauthenticated.response ||
        operational_unauthenticated.response->statusCode() !=
            drogon::k401Unauthorized) {
      _exit(17);
    }
    const auto login = Send(
        client, drogon::Post, "/api/v1/auth/login",
        R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
    if (!login.response || login.response->statusCode() != drogon::k200OK) {
      _exit(5);
    }
    const std::string cookie =
        "camera_session=" + login.response->getCookie("camera_session").value();

    const std::string private_marker =
        "/private/models/runtime-settings-secret.hef";
    std::string oversized_settings_body(
        camera_firmware::service::kMaximumRuntimeSettingsBodyBytes + 1U, 'x');
    oversized_settings_body.replace(0U, private_marker.size(), private_marker);

    const std::string declared_prefix =
        "PUT /api/v1/settings/runtime HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Content-Type: application/json\r\nContent-Length: " +
        std::to_string(oversized_settings_body.size()) + "\r\n";
    const auto oversized_unauthenticated =
        RawHttpsExchange(port, declared_prefix + "Connection: close\r\n\r\n" +
                                   oversized_settings_body);
    const auto oversized_without_origin =
        RawHttpsExchange(port, declared_prefix + "Cookie: " + cookie +
                                   "\r\nX-Camera-Request: management\r\n"
                                   "Connection: close\r\n\r\n" +
                                   oversized_settings_body);
    if (oversized_unauthenticated.status != 401 ||
        oversized_without_origin.status != 403 ||
        oversized_unauthenticated.bytes.find(private_marker) !=
            std::string::npos ||
        oversized_without_origin.bytes.find(private_marker) !=
            std::string::npos) {
      service.Stop();
      _exit(20);
    }

    const std::string declared_request =
        declared_prefix + "Origin: " + origin + "\r\nCookie: " + cookie +
        "\r\nX-Camera-Request: management\r\nConnection: close\r\n\r\n" +
        oversized_settings_body;
    const auto declared_response = RawHttpsExchange(port, declared_request);

    const std::string chunked_request =
        "POST /api/v1/settings/runtime/apply HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\nContent-Type: application/json\r\n"
        "Transfer-Encoding: chunked\r\nOrigin: " +
        origin + "\r\nCookie: " + cookie +
        "\r\nX-Camera-Request: management\r\nConnection: close\r\n\r\n"
        "4001\r\n" +
        oversized_settings_body + "\r\n0\r\n\r\n";
    const auto chunked_response = RawHttpsExchange(port, chunked_request);
    if (!IsBoundedRuntimeSettingsInvalidResponse(declared_response,
                                                 private_marker) ||
        !IsBoundedRuntimeSettingsInvalidResponse(chunked_response,
                                                 private_marker)) {
      service.Stop();
      _exit(19);
    }

    const auto get =
        Send(client, drogon::Get, "/api/v1/settings/runtime", {}, {}, cookie);
    if (!get.response || get.response->statusCode() != drogon::k200OK ||
        get.response->getJsonObject() == nullptr ||
        (*get.response->getJsonObject())["revision"].asUInt64() != 7U) {
      _exit(6);
    }

    const std::string update =
        R"({"expected_revision":7,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30},"models":[{"id":"objects","enabled":true,"confidence_threshold":0.55},{"id":"pose","enabled":false,"confidence_threshold":0.25}]}})";
    const auto no_origin = Send(client, drogon::Put, "/api/v1/settings/runtime",
                                update, {}, cookie, true);
    if (!no_origin.response ||
        no_origin.response->statusCode() != drogon::k403Forbidden) {
      _exit(7);
    }

    auto wrong_content_request = drogon::HttpRequest::newHttpRequest();
    wrong_content_request->setMethod(drogon::Put);
    wrong_content_request->setPath("/api/v1/settings/runtime");
    wrong_content_request->setContentTypeString("text/plain");
    wrong_content_request->setBody(update);
    wrong_content_request->addHeader("Origin", origin);
    wrong_content_request->addHeader("Cookie", cookie);
    wrong_content_request->addHeader("X-Camera-Request", "management");
    const auto [wrong_content_result, wrong_content_response] =
        client->sendRequest(wrong_content_request, 15.0);
    if (wrong_content_result != drogon::ReqResult::Ok ||
        !wrong_content_response ||
        wrong_content_response->statusCode() != drogon::k400BadRequest) {
      _exit(8);
    }

    const auto saved = Send(client, drogon::Put, "/api/v1/settings/runtime",
                            update, origin, cookie, true);
    if (!saved.response || saved.response->statusCode() != drogon::k200OK ||
        saved.response->getJsonObject() == nullptr ||
        (*saved.response->getJsonObject())["revision"].asUInt64() != 8U) {
      _exit(9);
    }
    const auto stale = Send(client, drogon::Put, "/api/v1/settings/runtime",
                            update, origin, cookie, true);
    if (!stale.response ||
        stale.response->statusCode() != drogon::k409Conflict ||
        stale.response->getBody().find("private") != std::string::npos) {
      _exit(10);
    }

    const auto apply =
        Send(client, drogon::Post, "/api/v1/settings/runtime/apply",
             R"({"expected_revision":8})", origin, cookie, true);
    if (!apply.response ||
        apply.response->statusCode() != drogon::k503ServiceUnavailable ||
        apply.response->getJsonObject() == nullptr ||
        !(*apply.response->getJsonObject())["restored"].asBool() ||
        apply.response->getBody().find("/opt/") != std::string::npos) {
      _exit(11);
    }
    const auto after_apply =
        Send(client, drogon::Get, "/api/v1/settings/runtime", {}, {}, cookie);
    if (!after_apply.response ||
        after_apply.response->statusCode() != drogon::k200OK) {
      _exit(12);
    }

    const auto wrong_method =
        Send(client, drogon::Patch, "/api/v1/settings/runtime", update, origin,
             cookie, true);
    if (!wrong_method.response ||
        wrong_method.response->statusCode() != drogon::k404NotFound) {
      _exit(13);
    }

    saturate_apply.store(true);
    auto executing_apply = std::async(std::launch::async, [&] {
      return Send(NewClient(port), drogon::Post,
                  "/api/v1/settings/runtime/apply",
                  R"({"expected_revision":8})", origin, cookie, true);
    });
    const auto apply_started_status =
        apply_started.get_future().wait_for(std::chrono::seconds(5));
    std::optional<std::future<HttpResult>> contender_one;
    std::optional<std::future<HttpResult>> contender_two;
    std::optional<HttpResult> contender_one_response;
    std::optional<HttpResult> contender_two_response;
    bool busy_completed_before_release = false;
    if (apply_started_status == std::future_status::ready) {
      contender_one.emplace(std::async(std::launch::async, [&] {
        return Send(NewClient(port), drogon::Post,
                    "/api/v1/settings/runtime/apply",
                    R"({"expected_revision":8})", origin, cookie, true);
      }));
      contender_two.emplace(std::async(std::launch::async, [&] {
        return Send(NewClient(port), drogon::Post,
                    "/api/v1/settings/runtime/apply",
                    R"({"expected_revision":8})", origin, cookie, true);
      }));

      const auto deadline =
          std::chrono::steady_clock::now() + std::chrono::seconds(5);
      while (std::chrono::steady_clock::now() < deadline) {
        if (contender_one->wait_for(std::chrono::milliseconds(10)) ==
            std::future_status::ready) {
          contender_one_response = contender_one->get();
          break;
        }
        if (contender_two->wait_for(std::chrono::milliseconds(10)) ==
            std::future_status::ready) {
          contender_two_response = contender_two->get();
          break;
        }
      }
      const auto is_busy = [](const std::optional<HttpResult>& response) {
        return response.has_value() && response->response &&
               response->response->statusCode() == drogon::k409Conflict &&
               response->response->getJsonObject() != nullptr &&
               (*response->response->getJsonObject())["code"].asString() ==
                   "E_SETTINGS_BUSY";
      };
      busy_completed_before_release =
          is_busy(contender_one_response) || is_busy(contender_two_response);
    }
    runtime_control_allowed.store(false);
    release_apply_guard.Release();
    const auto executing_apply_response = executing_apply.get();
    if (contender_one.has_value() && !contender_one_response.has_value()) {
      contender_one_response = contender_one->get();
    }
    if (contender_two.has_value() && !contender_two_response.has_value()) {
      contender_two_response = contender_two->get();
    }
    saturate_apply.store(false);
    runtime_control_allowed.store(true);

    const auto status_count = [&](drogon::HttpStatusCode status) {
      unsigned int count = 0U;
      for (const auto* response :
           {&contender_one_response, &contender_two_response}) {
        if (response->has_value() && (*response)->response &&
            (*response)->response->statusCode() == status) {
          ++count;
        }
      }
      return count;
    };

    const bool saturation_passed =
        apply_started_status == std::future_status::ready &&
        busy_completed_before_release && executing_apply_response.response &&
        executing_apply_response.response->statusCode() == drogon::k200OK &&
        status_count(drogon::k423Locked) == 1U &&
        status_count(drogon::k409Conflict) == 1U &&
        saturated_apply_calls.load() == 1U;
    if (!saturation_passed) {
      service.Stop();
      _exit(18);
    }

    block_save.store(true);
    const std::string blocking_update =
        R"({"expected_revision":8,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":9000,"gop":30},"models":[{"id":"objects","enabled":true,"confidence_threshold":0.60},{"id":"pose","enabled":false,"confidence_threshold":0.25}]}})";
    auto accepted = std::async(std::launch::async, [&] {
      return Send(NewClient(port), drogon::Put, "/api/v1/settings/runtime",
                  blocking_update, origin, cookie, true);
    });
    const auto save_started_status =
        save_started.get_future().wait_for(std::chrono::seconds(5));
    std::optional<std::future<void>> stopping;
    bool stop_waited_for_save = false;
    if (save_started_status == std::future_status::ready) {
      stopping.emplace(std::async(std::launch::async, [&] { service.Stop(); }));
      stop_waited_for_save =
          stopping->wait_for(std::chrono::milliseconds(50)) ==
          std::future_status::timeout;
    }
    release_save_guard.Release();
    const auto accepted_response = accepted.get();
    bool stop_completed = false;
    if (stopping.has_value()) {
      stop_completed = stopping->wait_for(std::chrono::seconds(5)) ==
                       std::future_status::ready;
      stopping->get();
    }
    if (save_started_status != std::future_status::ready) {
      service.Stop();
      _exit(14);
    }
    if (!stop_waited_for_save) {
      service.Stop();
      _exit(15);
    }
    if (!accepted_response.response ||
        accepted_response.response->statusCode() != drogon::k200OK ||
        !stop_completed) {
      service.Stop();
      _exit(16);
    }
    service.Stop();
    _exit(0);
  }
  _exit(124);
}

// The initial account is deleted inside Initialize()'s transaction, so the
// process must drop its copy of the credential there and not at the end of the
// transition: when runtime_start() fails, the runtime_pending window never
// closes on its own.
//
// The observable consequence is the setup/initialize identity check. An
// operator may name the administrator after the credential the login screen
// displayed — 12 lowercase alphanumerics is a legal username, and Initialize()
// removes the initial row in the same transaction, so there is no collision to
// stop them. If the process is still holding that name, the administrator's own
// session satisfies a check whose whole point is that no session can satisfy it
// once the account is gone. A malformed body separates the two outcomes:
// reaching the body parse at all proves the identity check let the session
// through. The request is refused downstream either way by transition_allowed,
// so this was never exploitable — the guard had simply stopped meaning
// anything.
TEST(HttpsAuthIntegrationTest, InitialAccountIdentityDiesWithTheAccount) {
  TemporaryDirectory directory;
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = directory.path().string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "initial-identity-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (directory.path() / "rtsp.credentials").string();

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  // Fails, so the device stays in runtime_pending: that is the window under
  // test, and it is the one that never closes by itself.
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Err(
        {"E_RUNTIME_START", "runtime failure detail"});
  };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);

  const auto status = Send(client, drogon::Get, "/api/v1/setup/status");
  ExpectStatus(status, drogon::k200OK);
  ASSERT_NE(status.response->getJsonObject(), nullptr);
  const std::string initial_username =
      (*status.response->getJsonObject())["initial_username"].asString();
  const std::string initial_password =
      (*status.response->getJsonObject())["initial_password"].asString();
  ASSERT_FALSE(initial_username.empty());

  const auto initial_login =
      Send(client, drogon::Post, "/api/v1/auth/login",
           InitialAccountLoginBody(initial_username, initial_password), origin,
           {}, true);
  ExpectStatus(initial_login, drogon::k200OK);
  const std::string initial_cookie =
      "camera_session=" +
      initial_login.response->getCookie("camera_session").value();

  const std::string setup_body =
      "{\"username\":" + JsonQuoted(initial_username) +
      ",\"password\":\"StrongPass9!\",\"peer_ip\":\"127.0.0.1\"}";
  const auto setup = Send(client, drogon::Post, "/api/v1/setup/initialize",
                          setup_body, origin, initial_cookie, true);
  ExpectStatus(setup, drogon::k503ServiceUnavailable);

  const auto pending_status = Send(client, drogon::Get, "/api/v1/setup/status");
  ExpectStatus(pending_status, drogon::k200OK);
  ASSERT_NE(pending_status.response->getJsonObject(), nullptr);
  EXPECT_EQ((*pending_status.response->getJsonObject())["phase"].asString(),
            "runtime_pending");

  const auto administrator_login =
      Send(client, drogon::Post, "/api/v1/auth/login",
           InitialAccountLoginBody(initial_username, "StrongPass9!"), origin,
           {}, true);
  ExpectStatus(administrator_login, drogon::k200OK);
  ASSERT_NE(administrator_login.response->getJsonObject(), nullptr);
  EXPECT_EQ((*administrator_login.response->getJsonObject())["role"].asString(),
            "administrator");
  const std::string administrator_cookie =
      "camera_session=" +
      administrator_login.response->getCookie("camera_session").value();

  const auto refused = Send(client, drogon::Post, "/api/v1/setup/initialize",
                            "{", origin, administrator_cookie, true);
  ExpectStatus(refused, drogon::k403Forbidden);
  ASSERT_NE(refused.response->getJsonObject(), nullptr);
  EXPECT_EQ((*refused.response->getJsonObject())["code"].asString(),
            "E_ACCESS_DENIED");

  service.Stop();
}

TEST(HttpsAuthIntegrationTest,
     MonitoringPollingDoesNotExtendManagementAuthority) {
  TemporaryDirectory directory;
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = directory.path().string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "camera-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (directory.path() / "rtsp.credentials").string();

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.auth_service_dependencies_provider = [] {
    camera_firmware::security::AuthServiceDependencies dependencies;
    dependencies.session_idle_timeout_seconds = 2;
    return dependencies;
  };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);

  ExpectStatus(
      Send(
          client, drogon::Post, "/api/v1/setup/initialize",
          R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
          origin, InitialAccountCookie(client, origin), true),
      drogon::k200OK);
  const auto login = Send(client, drogon::Post, "/api/v1/auth/login",
                          R"({"username":"owner1","password":"StrongPass9!"})",
                          origin, {}, true);
  ExpectStatus(login, drogon::k200OK);
  const std::string cookie =
      "camera_session=" + login.response->getCookie("camera_session").value();

  for (int poll = 0; poll < 9; ++poll) {
    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    const auto monitoring =
        Send(client, drogon::Get, "/api/v1/monitoring/cameras", {}, {}, cookie);
    ASSERT_NE(monitoring.response, nullptr);
    EXPECT_NE(monitoring.response->statusCode(), drogon::k401Unauthorized);
  }

  const auto refused =
      Send(client, drogon::Get, "/api/v1/security/users", {}, {}, cookie);
  ASSERT_NE(refused.response, nullptr);
  EXPECT_EQ(refused.response->statusCode(), drogon::k401Unauthorized);
  ASSERT_NE(refused.response->getJsonObject(), nullptr);
  EXPECT_EQ((*refused.response->getJsonObject())["code"].asString(),
            "E_MANAGEMENT_REAUTHENTICATION_REQUIRED");

  const auto still_monitoring =
      Send(client, drogon::Get, "/api/v1/monitoring/cameras", {}, {}, cookie);
  ASSERT_NE(still_monitoring.response, nullptr);
  EXPECT_NE(still_monitoring.response->statusCode(), drogon::k401Unauthorized);

  const auto reauthenticated =
      Send(client, drogon::Post, "/api/v1/auth/reauthenticate",
           R"({"password":"StrongPass9!"})", origin, cookie, true);
  ExpectStatus(reauthenticated, drogon::k200OK);

  const auto allowed =
      Send(client, drogon::Get, "/api/v1/security/users", {}, {}, cookie);
  ASSERT_NE(allowed.response, nullptr);
  EXPECT_EQ(allowed.response->statusCode(), drogon::k200OK);

  service.Stop();
}

std::vector<std::string> ListedManagementIps(const Json::Value& body) {
  std::vector<std::string> addresses;
  if (!body.isObject() || !body["management_ips"].isArray()) {
    return addresses;
  }
  for (const auto& entry : body["management_ips"]) {
    addresses.push_back(entry["address"].asString() + "/" +
                        entry["role"].asString());
  }
  std::sort(addresses.begin(), addresses.end());
  return addresses;
}

TEST(HttpsAuthIntegrationTest, SetupRegistersEveryConfirmedManagementIp) {
  TemporaryDirectory directory;
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = directory.path().string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url = origin;
  config.http.web_root = std::string(CF_SOURCE_DIR) + "/web/dist";
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "management-ip-setup-test";
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  config.secure_rtsp.client_auth.credential_file =
      (directory.path() / "rtsp.credentials").string();

  std::atomic<int> runtime_start_calls{0};
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.runtime_start_callback = [&runtime_start_calls] {
    runtime_start_calls.fetch_add(1);
    return camera_firmware::common::Result<void>::Ok();
  };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);

  // One session for the whole wizard, as the browser has: the operator signs
  // in with the initial account once and stays signed in across a correction.
  const std::string setup_cookie = InitialAccountCookie(client, origin);
  ASSERT_FALSE(setup_cookie.empty());

  // A valid entry ahead of an invalid one: setup is all-or-nothing, so the
  // valid entry must not survive the rejection either.
  const auto rejected = Send(
      client, drogon::Post, "/api/v1/setup/initialize",
      R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1",)"
      R"("management_ips":["198.51.100.7","198.51.100.0/24"]})",
      origin, setup_cookie, true);
  ExpectStatus(rejected, drogon::k400BadRequest);
  ASSERT_NE(rejected.response->getJsonObject(), nullptr);
  EXPECT_EQ((*rejected.response->getJsonObject())["code"].asString(),
            "E_MANAGEMENT_IP_INVALID");
  EXPECT_EQ(runtime_start_calls.load(), 0);

  // The device is still in default state with the initial account intact, so
  // the operator can correct the entry and try again.
  const auto still_required = Send(client, drogon::Get, "/api/v1/setup/status");
  ExpectStatus(still_required, drogon::k200OK);
  ASSERT_NE(still_required.response->getJsonObject(), nullptr);
  EXPECT_TRUE((*still_required.response->getJsonObject())["required"].asBool());
  EXPECT_TRUE(
      still_required.response->getJsonObject()->isMember("initial_username"));

  // The submitted list names neither 127.0.0.1 nor anything else this client
  // holds, and repeats one address. Setup must still complete, and the peer
  // that confirmed it must still be able to reach the device afterwards.
  const auto setup = Send(
      client, drogon::Post, "/api/v1/setup/initialize",
      R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1",)"
      R"("management_ips":["198.51.100.7","198.51.100.8","198.51.100.7"]})",
      origin, setup_cookie, true);
  ExpectStatus(setup, drogon::k200OK);
  ASSERT_NE(setup.response->getJsonObject(), nullptr);
  EXPECT_FALSE((*setup.response->getJsonObject())["required"].asBool());
  EXPECT_EQ(runtime_start_calls.load(), 1);

  // This login is the anti-lockout assertion. The device is operational now,
  // so the request gate refuses every peer that is not a registered management
  // IP — including this one, had the submitted list been taken as the whole
  // truth. A 403 here is a bricked device, not a failed test case.
  const auto administrator_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {}, true);
  ExpectStatus(administrator_login, drogon::k200OK);
  const std::string administrator_cookie =
      "camera_session=" +
      administrator_login.response->getCookie("camera_session").value();

  const auto listed =
      Send(client, drogon::Get, "/api/v1/security/management-ips", {}, {},
           administrator_cookie);
  ExpectStatus(listed, drogon::k200OK);
  ASSERT_NE(listed.response->getJsonObject(), nullptr);
  EXPECT_EQ((*listed.response->getJsonObject())["current_peer_ip"].asString(),
            "127.0.0.1");
  EXPECT_EQ(ListedManagementIps(*listed.response->getJsonObject()),
            (std::vector<std::string>{"127.0.0.1/administrator",
                                      "198.51.100.7/administrator",
                                      "198.51.100.8/administrator"}));

  service.Stop();
}

}  // namespace
