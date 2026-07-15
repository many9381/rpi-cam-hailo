#include "camera_firmware/service/ServiceApp.hpp"
#include "camera_firmware/boot/FirmwareBootCoordinator.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cctype>
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
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

#include "camera_firmware/security/PasswordHasher.hpp"
#include "camera_firmware/service/RuntimeSettingsHttp.hpp"
#include "camera_firmware/settings/RuntimeSettingsStore.hpp"

namespace camera_firmware::security {

class AuthServiceTestAccess {
 public:
  static std::unique_ptr<AuthService> Create(
      SecurityStore& store,
      AuthServiceDependencies dependencies) {
    return std::unique_ptr<AuthService>(
        new AuthService(store, std::move(dependencies)));
  }
};

}  // namespace camera_firmware::security

namespace {

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

std::uint16_t ReserveLoopbackPort() {
  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    throw std::system_error(errno, std::generic_category(), "socket");
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
  const std::uint16_t port = ntohs(address.sin_port);
  (void)::close(fd);
  return port;
}

struct HttpResult {
  drogon::ReqResult result{drogon::ReqResult::BadResponse};
  drogon::HttpResponsePtr response;
};

drogon::HttpClientPtr NewClient(std::uint16_t port,
                                std::string source_ip = {}) {
  auto client = drogon::HttpClient::newHttpClient(
      "127.0.0.1", port, true, nullptr, false, false);
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

HttpResult Send(const drogon::HttpClientPtr& client,
                drogon::HttpMethod method,
                std::string path,
                std::string body = {},
                std::string origin = {},
                std::string cookie = {},
                bool management_header = false) {
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
  auto [result, response] = client->sendRequest(request, 15.0);
  return {result, std::move(response)};
}

void ExpectStatus(const HttpResult& result, drogon::HttpStatusCode status) {
  ASSERT_EQ(result.result, drogon::ReqResult::Ok);
  ASSERT_NE(result.response, nullptr);
  EXPECT_EQ(result.response->statusCode(), status)
      << result.response->getBody();
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
    const auto parsed = std::from_chars(size_text.data(),
                                        size_text.data() + size_text.size(),
                                        chunk_size, 16);
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
  const auto parsed = std::from_chars(
      content_length.data(), content_length.data() + content_length.size(),
      body_size);
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
    response.status =
        std::stoi(response.bytes.substr(first_space + 1U, 3U));
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
    if (socket_fd_.get() < 0 || !ssl_ ||
        !SetReceiveTimeout(receive_timeout)) {
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
      std::size_t receive_byte_limit =
          std::numeric_limits<std::size_t>::max(),
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
      const std::size_t write_size =
          std::min<std::size_t>(request.size() - written,
                                std::numeric_limits<int>::max());
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
      const std::size_t remaining =
          receive_byte_limit - response.bytes.size();
      const auto read_capacity = static_cast<int>(
          std::min<std::size_t>(buffer.size(), remaining));
      const int count =
          ::SSL_read(ssl_.get(), buffer.data(), read_capacity);
      if (count > 0) {
        response.bytes.append(buffer.data(), static_cast<std::size_t>(count));
        continue;
      }

      const int socket_error = errno;
      const int ssl_error = ::SSL_get_error(ssl_.get(), count);
      if (ssl_error == SSL_ERROR_ZERO_RETURN ||
          (ssl_error == SSL_ERROR_SYSCALL && count == 0 &&
           socket_error == 0)) {
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
      std::string_view path,
      const std::vector<std::string>& cookie_fields,
      std::size_t receive_byte_limit =
          std::numeric_limits<std::size_t>::max(),
      std::chrono::milliseconds receive_timeout = std::chrono::seconds(15),
      bool stop_at_complete_response = true) {
    std::string request = "GET " + std::string(path) +
                          " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
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
        .tv_usec = static_cast<suseconds_t>(
            (timeout_milliseconds % 1000) * 1000)};
    return socket_fd_.get() >= 0 &&
           ::setsockopt(socket_fd_.get(), SOL_SOCKET, SO_RCVTIMEO,
                        &socket_timeout, sizeof(socket_timeout)) == 0;
  }

  ScopedSocket socket_fd_;
  std::unique_ptr<SSL_CTX, decltype(&::SSL_CTX_free)> context_;
  std::unique_ptr<SSL, decltype(&::SSL_free)> ssl_;
  bool connected_{false};
};

RawHttpsResponse RawHttpsExchange(std::uint16_t port,
                                  std::string_view request,
                                  std::size_t receive_byte_limit =
                                      std::numeric_limits<std::size_t>::max(),
                                  std::chrono::milliseconds receive_timeout =
                                      std::chrono::seconds(15)) {
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

std::optional<Json::Value> DecodeRawJsonBody(
    const RawHttpsResponse& response) {
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

bool IsBoundedRuntimeSettingsInvalidResponse(
    const RawHttpsResponse& response,
    std::string_view private_marker) {
  const auto body = DecodeAvailableRawBody(response);
  const auto json = DecodeRawJsonBody(response);
  return response.status == 400 && body.has_value() && body->size() <= 256U &&
         body->find(private_marker) == std::string::npos && json.has_value() &&
         json->isObject() && json->size() == 2U &&
         (*json)["code"].asString() == "E_SETTINGS_REQUEST_INVALID" &&
         (*json)["message"].asString() ==
             "runtime settings request is invalid";
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
    std::string_view test_name,
    std::string_view scenario,
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
    std::uint16_t port,
    std::string_view path,
    const std::vector<std::string>& cookie_fields,
    std::size_t receive_byte_limit =
        std::numeric_limits<std::size_t>::max(),
    std::chrono::milliseconds receive_timeout = std::chrono::seconds(15)) {
  std::string request = "GET " + std::string(path) +
                        " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
  for (const auto& field : cookie_fields) {
    request += "Cookie: " + field + "\r\n";
  }
  request += "Connection: close\r\n\r\n";
  return RawHttpsExchange(port, request, receive_byte_limit, receive_timeout);
}

RawHttpsResponse RawHttpsJsonRequest(
    std::uint16_t port,
    std::string_view method,
    std::string_view path,
    std::string_view body,
    std::string_view origin = {},
    std::string_view cookie = {},
    bool management_header = false) {
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

void ExpectRawSecurityHeaders(const RawHttpsResponse& response) {
  EXPECT_EQ(response.Header("Cache-Control"), "no-store");
  EXPECT_EQ(response.Header("Strict-Transport-Security"),
            "max-age=31536000");
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
    std::string id,
    std::string labels,
    unsigned int width,
    unsigned int height,
    bool letterbox,
    float confidence_threshold) {
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
    const std::filesystem::path& state_directory,
    std::uint16_t port) {
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = state_directory.string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = port;
  config.http.public_base_url =
      "https://127.0.0.1:" + std::to_string(port);
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
  return root["schema_version"].asUInt() == 1U &&
         root["revision"].asUInt64() == 1U &&
         root["state"].asString() == "pending" && pending.isObject() &&
         pending.size() == 2U && camera.isObject() && camera.size() == 3U &&
         camera["profile_id"].asString() == "imx708-1080p30" &&
         camera["bitrate_kbps"].asUInt() == 8000U &&
         camera["gop"].asUInt() == 30U && models.isArray() &&
         models.size() == 2U && models[0U].size() == 3U &&
         models[0U]["id"].asString() == "objects" &&
         models[0U]["enabled"].asBool() &&
         std::abs(models[0U]["confidence_threshold"].asDouble() - 0.55) <
             0.0001 &&
         models[1U].size() == 3U &&
         models[1U]["id"].asString() == "pose" &&
         !models[1U]["enabled"].asBool() &&
         std::abs(models[1U]["confidence_threshold"].asDouble() - 0.25) <
             0.0001;
}

int RunRuntimeSettingsPersistenceLifecycle(
    const std::filesystem::path& state_directory,
    bool save_pending) {
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

  auto profiles =
      camera_firmware::settings::CameraProfileCatalog::Rpi5Imx708();
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
            std::shared_ptr<camera_firmware::runtime::FirmwareRuntime>>::Err(
            {"E_TEST_RUNTIME_UNUSED", "runtime factory is unused"});
      });
  camera_firmware::settings::RuntimeSettingsService runtime_settings(
      config, std::move(profiles), *runtime_store, managed_runtime,
      [](const camera_firmware::config::AppConfig&) {
        return camera_firmware::common::Result<void>::Ok();
      });

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.document_root = config.http.web_root;
  args.public_base_url = config.http.public_base_url;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.runtime_settings_snapshot_callback = [&runtime_settings] {
    return runtime_settings.Snapshot();
  };
  args.runtime_settings_save_callback =
      [&runtime_settings](
          std::uint64_t expected_revision,
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
        config.http.public_base_url, {}, true);
    if (!setup.response || setup.response->statusCode() != drogon::k200OK) {
      return fail(7);
    }
  }

  const auto login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})",
      config.http.public_base_url, {}, true);
  if (login.result != drogon::ReqResult::Ok || !login.response ||
      login.response->statusCode() != drogon::k200OK) {
    return fail(8);
  }
  const std::string cookie =
      "camera_session=" +
      login.response->getCookie("camera_session").value();

  HttpResult response;
  if (save_pending) {
    response = Send(
        client, drogon::Put, "/api/v1/settings/runtime",
        R"({"expected_revision":0,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30},"models":[{"id":"objects","enabled":true,"confidence_threshold":0.55},{"id":"pose","enabled":false,"confidence_threshold":0.25}]}})",
        config.http.public_base_url, cookie, true);
  } else {
    response = Send(client, drogon::Get, "/api/v1/settings/runtime", {}, {},
                    cookie);
  }
  if (!HasExpectedPersistedPendingSettings(response)) {
    return fail(9);
  }
  if (save_pending) {
    const auto logout =
        Send(client, drogon::Post, "/api/v1/auth/logout", {},
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
  explicit FirmwareProcess(const std::filesystem::path& config_path) {
    child_ = ::fork();
    if (child_ < 0) {
      throw std::system_error(errno, std::generic_category(), "fork");
    }
    if (child_ == 0) {
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

void WriteManagedFirmwareConfig(const std::filesystem::path& config_path,
                                const std::filesystem::path& state_directory,
                                std::uint16_t https_port,
                                std::uint16_t rtsp_port,
                                bool security_enabled = true) {
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
            "  web_root: " CF_SOURCE_DIR "/web/dist\n"
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
}

bool WaitForSetupService(
    std::uint16_t port,
    std::string_view path = "/api/v1/setup/status") {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (std::chrono::steady_clock::now() < deadline) {
    const auto response = RawHttpsGet(
        port, path, {}, 4096U,
        std::chrono::milliseconds(250));
    if (response.status == 200) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return false;
}

bool InitializeOperationalFirmwareState(
    const std::filesystem::path& config_path,
    std::uint16_t port) {
  FirmwareProcess process(config_path);
  if (!WaitForSetupService(port)) {
    return false;
  }
  const std::string origin =
      "https://127.0.0.1:" + std::to_string(port);
  const auto setup = RawHttpsJsonRequest(
      port, "POST", "/api/v1/setup/initialize",
      R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
      origin, {}, true);
  return setup.status == 503;
}

std::optional<std::string> LoginToFirmware(std::uint16_t port) {
  const std::string origin =
      "https://127.0.0.1:" + std::to_string(port);
  const auto login = RawHttpsJsonRequest(
      port, "POST", "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {},
      true);
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
      std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace);
}

std::string RuntimeSettingsDocument(
    std::string_view active_profile,
    unsigned int active_bitrate,
    unsigned int active_gop,
    std::optional<std::string_view> pending_profile = std::nullopt) {
  std::string pending = "null";
  if (pending_profile.has_value()) {
    pending =
        std::string(R"({"camera":{"profile_id":")") +
        std::string(*pending_profile) +
        R"(","bitrate_kbps":7000,"gop":30},"models":[]})";
  }
  return std::string(R"({"schema_version":1,"revision":7,"active":{"camera":{"profile_id":")") +
         std::string(active_profile) + R"(","bitrate_kbps":)" +
         std::to_string(active_bitrate) + R"(,"gop":)" +
         std::to_string(active_gop) + R"(},"models":[]},"pending":)" +
         pending +
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
  WriteManagedFirmwareConfig(config_path, state_directory, https_port,
                             https_port);

  const std::string origin =
      "https://127.0.0.1:" + std::to_string(https_port);
  {
    FirmwareProcess setup_process(config_path);
    ASSERT_TRUE(WaitForSetupService(https_port));
    const auto setup = RawHttpsJsonRequest(
        https_port, "POST", "/api/v1/setup/initialize",
        R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
        origin, {}, true);
    ASSERT_EQ(setup.status, 503) << setup.bytes;
  }

  FirmwareProcess process(config_path);
  ASSERT_TRUE(WaitForSetupService(https_port));
  const auto login = RawHttpsJsonRequest(
      https_port, "POST", "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {},
      true);
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
  EXPECT_FALSE(std::filesystem::exists(state_directory /
                                       "runtime-settings.json"));
}

TEST(FirmwareProcessRuntimeSettingsIntegrationTest,
     StoredActiveSettingsSelectTheBootRuntimeConfiguration) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t port = ReserveLoopbackPort();
  WriteManagedFirmwareConfig(config_path, state_directory, port, port);
  ASSERT_TRUE(InitializeOperationalFirmwareState(config_path, port));
  WriteRuntimeSettingsFile(
      state_directory,
      RuntimeSettingsDocument("imx708-1080p30", 8000U, 30U));

  FirmwareProcess process(config_path);
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
  WriteManagedFirmwareConfig(config_path, state_directory, port, port);
  ASSERT_TRUE(InitializeOperationalFirmwareState(config_path, port));
  WriteRuntimeSettingsFile(
      state_directory,
      RuntimeSettingsDocument("imx708-1080p30", 8000U, 30U,
                              "imx708-1080p50"));

  FirmwareProcess process(config_path);
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
  WriteManagedFirmwareConfig(config_path, state_directory, port, port);
  ASSERT_TRUE(InitializeOperationalFirmwareState(config_path, port));
  constexpr std::string_view kMalformedDocument = "not-json-private-marker";
  WriteRuntimeSettingsFile(state_directory, kMalformedDocument);

  FirmwareProcess process(config_path);
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
  const std::string persisted_text{
      std::istreambuf_iterator<char>(persisted),
      std::istreambuf_iterator<char>()};
  EXPECT_EQ(persisted_text, kMalformedDocument);
}

TEST(FirmwareProcessRuntimeSettingsIntegrationTest,
     SavedPendingSettingsSurviveARealFirmwareRestart) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t port = ReserveLoopbackPort();
  const std::string origin =
      "https://127.0.0.1:" + std::to_string(port);
  WriteManagedFirmwareConfig(config_path, state_directory, port, port);
  ASSERT_TRUE(InitializeOperationalFirmwareState(config_path, port));

  {
    FirmwareProcess first_process(config_path);
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
    const auto logout = RawHttpsJsonRequest(
        port, "POST", "/api/v1/auth/logout", {}, origin, *cookie, true);
    ASSERT_EQ(logout.status, 200) << logout.bytes;
  }

  FirmwareProcess second_process(config_path);
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
  const std::string origin =
      "https://127.0.0.1:" + std::to_string(port);
  WriteManagedFirmwareConfig(config_path, state_directory, port, port);
  ASSERT_TRUE(InitializeOperationalFirmwareState(config_path, port));

  FirmwareProcess process(config_path);
  ASSERT_TRUE(WaitForSetupService(port));
  const auto cookie = LoginToFirmware(port);
  ASSERT_TRUE(cookie.has_value());
  const auto saved = RawHttpsJsonRequest(
      port, "PUT", "/api/v1/settings/runtime",
      R"({"expected_revision":0,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30},"models":[]}})",
      origin, *cookie, true);
  ASSERT_EQ(saved.status, 200) << saved.bytes;

  const auto applied = RawHttpsJsonRequest(
      port, "POST", "/api/v1/settings/runtime/apply",
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
  std::filesystem::permissions(
      state_directory, std::filesystem::perms::owner_all,
      std::filesystem::perm_options::replace);
  WriteManagedFirmwareConfig(config_path, state_directory, port, port, false);

  {
    FirmwareProcess process(config_path);
    ASSERT_TRUE(WaitForSetupService(port, "/api/v1/health"));
    const auto settings =
        RawHttpsGet(port, "/api/v1/settings/runtime", {});
    ASSERT_EQ(settings.status, 503) << settings.bytes;
    const auto body = DecodeRawJsonBody(settings);
    ASSERT_TRUE(body.has_value());
    EXPECT_EQ((*body)["code"].asString(), "E_SETTINGS_UNAVAILABLE");
  }
  EXPECT_FALSE(std::filesystem::exists(state_directory /
                                       "runtime-settings.json"));
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
              "  web_root: " CF_SOURCE_DIR "/web/dist\n"
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
    ::execl(CF_CAMERA_FIRMWARE_BIN, CF_CAMERA_FIRMWARE_BIN,
            config_path.c_str(), nullptr);
    _exit(127);
  }

  bool ready = false;
  const auto ready_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (std::chrono::steady_clock::now() < ready_deadline) {
    const auto status = RawHttpsGet(
        port, "/api/v1/setup/status", {}, 4096U,
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

TEST(HttpsAuthIntegrationTest, ProductionDefaultsWireSecurityServices) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    const std::uint16_t port = ReserveLoopbackPort();
    const std::string origin =
        "https://127.0.0.1:" + std::to_string(port);
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
    auto setup = Send(client, drogon::Post, "/api/v1/setup/initialize",
                      setup_body, origin, {}, true);
    if (setup.result != drogon::ReqResult::Ok || !setup.response ||
        setup.response->statusCode() != drogon::k200OK ||
        setup.response->getJsonObject() == nullptr ||
        (*setup.response->getJsonObject())["required"].asBool() ||
        (*setup.response->getJsonObject())["runtime"].asString() != "running" ||
        runtime_start_calls.load() != 1) {
      _exit(4);
    }
    auto login = Send(
        client, drogon::Post, "/api/v1/auth/login",
        R"({"username":"owner1","password":"StrongPass9!"})", origin,
        {}, true);
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
    const std::string origin =
        "https://127.0.0.1:" + std::to_string(port);
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
    auto setup = Send(client, drogon::Post, "/api/v1/setup/initialize",
                      setup_body, origin, {}, true);
    if (setup.result != drogon::ReqResult::Ok || !setup.response ||
        setup.response->statusCode() != drogon::k200OK) {
      _exit(3);
    }
    auto login = Send(
        client, drogon::Post, "/api/v1/auth/login",
        R"({"username":"owner1","password":"StrongPass9!"})", origin,
        {}, true);
    if (login.result != drogon::ReqResult::Ok || !login.response ||
        login.response->statusCode() != drogon::k200OK) {
      _exit(4);
    }
    const std::string cookie = "camera_session=" +
                               login.response->getCookie("camera_session")
                                   .value();
    const auto response = RawHttpsGet(port, "/api/v1/cameras", {cookie});
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

void RunAuthenticatedLiveMp4Scenario(
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

  const std::string fmp4_payload{"ftyp-moov-moof-mdat"};
  std::atomic<unsigned int> provider_calls{0U};
  std::atomic<unsigned int> release_calls{0U};
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.live_stream_callback = [&](const std::string& camera_id) {
    ++provider_calls;
    if (camera_id != "imx708-main") {
      return camera_firmware::common::Result<
          camera_firmware::service::LiveMp4StreamCallback>::Err(
          {"E_LIVE_NOT_FOUND", "private camera detail"});
    }
    auto offset = std::make_shared<std::size_t>(0U);
    camera_firmware::service::LiveMp4StreamCallback stream =
        [offset, &fmp4_payload, &release_calls](char* output,
                                               std::size_t capacity) {
          if (output == nullptr) {
            ++release_calls;
            return std::size_t{0};
          }
          if (*offset >= fmp4_payload.size()) {
            return std::size_t{0};
          }
          const auto count =
              std::min(capacity, fmp4_payload.size() - *offset);
          std::copy_n(fmp4_payload.data() + *offset, count, output);
          *offset += count;
          return count;
        };
    return camera_firmware::common::Result<
        camera_firmware::service::LiveMp4StreamCallback>::Ok(
        std::move(stream));
  };

  camera_firmware::service::ServiceApp service;
  const auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);

  auto denied = Send(client, drogon::Get,
                     "/api/v1/cameras/imx708-main/live.mp4");
  ExpectStatus(denied, drogon::k403Forbidden);
  EXPECT_EQ(provider_calls.load(), 0U);

  const std::string setup_body =
      R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})";
  auto setup = Send(client, drogon::Post, "/api/v1/setup/initialize",
                    setup_body, origin, {}, true);
  ExpectStatus(setup, drogon::k200OK);
  auto login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      R"({"username":"owner1","password":"StrongPass9!"})", origin, {},
      true);
  ExpectStatus(login, drogon::k200OK);
  const auto& session_cookie = login.response->getCookie("camera_session");
  ASSERT_FALSE(session_cookie.value().empty());
  const std::string cookie = "camera_session=" + session_cookie.value();

  auto live = Send(client, drogon::Get,
                   "/api/v1/cameras/imx708-main/live.mp4", {}, {}, cookie);
  ExpectStatus(live, drogon::k200OK);
  ExpectSecurityHeaders(live.response);
  EXPECT_EQ(live.response->contentTypeString(), "video/mp4");
  EXPECT_EQ(live.response->getHeader("Content-Encoding"), "identity");
  EXPECT_EQ(live.response->body(), fmp4_payload);
  EXPECT_EQ(provider_calls.load(), 1U);

  auto unknown = Send(client, drogon::Get,
                      "/api/v1/cameras/unknown/live.mp4", {}, {}, cookie);
  ExpectStatus(unknown, drogon::k503ServiceUnavailable);
  const auto unknown_json = unknown.response->jsonObject();
  ASSERT_NE(unknown_json, nullptr);
  EXPECT_EQ((*unknown_json)["code"].asString(), "E_LIVE_UNAVAILABLE");
  EXPECT_EQ((*unknown_json)["message"].asString(),
            "live preview is unavailable");
  EXPECT_EQ(provider_calls.load(), 2U);

  service.Stop();
  EXPECT_GE(release_calls.load(), 1U);
}

TEST(HttpsAuthIntegrationTest,
     AuthenticatedLiveMp4UsesSessionAndStreamsBytes) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(15U);
    RunAuthenticatedLiveMp4Scenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
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
    const auto seed = static_cast<unsigned char>(
        0x20U + random_counter.fetch_add(1U));
    std::fill(bytes.data(), bytes.data() + bytes.size(), seed);
    return camera_firmware::common::Result<
        camera_firmware::common::SecureBytes>::Ok(std::move(bytes));
  };
  auth_dependencies.firmware_log_random_bytes =
      auth_dependencies.random_bytes;
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
  auth_dependencies.high_severity_log = [](std::string_view,
                                           std::string_view) {};
  auto auth = std::shared_ptr<camera_firmware::security::AuthService>(
      camera_firmware::security::AuthServiceTestAccess::Create(
          *store, std::move(auth_dependencies)));

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
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
    return std::optional<std::vector<std::uint8_t>>{
        std::vector<std::uint8_t>{0xffU, 0xd8U, 0xffU, 0xd9U}};
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
  args.security_store = store;
  args.bootstrap_service = bootstrap;
  args.auth_service = auth;

  camera_firmware::service::ServiceApp service;
  auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto client = NewClient(port);

  for (const std::string path : {"/", "/index.html", "/app.js",
                                 "/styles.css"}) {
    auto response = Send(client, drogon::Get, path);
    ExpectStatus(response, drogon::k200OK);
    ExpectSecurityHeaders(response.response);
  }
  for (const std::string path : {"/app.js.map", "/assets/app.js",
                                 "/dashboard", "/index.html/",
                                 "/%2e%2e/etc/passwd"}) {
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
  auto setup_without_csrf = Send(client, drogon::Post,
                                 "/api/v1/setup/initialize", setup_body);
  ExpectStatus(setup_without_csrf, drogon::k403Forbidden);
  EXPECT_EQ(runtime_start_calls.load(), 0);

  auto oversized_setup = Send(client, drogon::Post,
                              "/api/v1/setup/initialize",
                              std::string(4097U, 'x'), origin, {}, true);
  ExpectStatus(oversized_setup, drogon::k413RequestEntityTooLarge);
  EXPECT_EQ(runtime_start_calls.load(), 0);

  auto setup = Send(client, drogon::Post, "/api/v1/setup/initialize",
                    setup_body, origin, {}, true);
  ExpectStatus(setup, drogon::k503ServiceUnavailable);
  ExpectSecurityHeaders(setup.response);
  EXPECT_EQ(setup.response->getBody().find("runtime failure detail"),
            std::string_view::npos);
  EXPECT_EQ(runtime_start_calls.load(), 1);

  auto pending_status =
      Send(client, drogon::Get, "/api/v1/setup/status");
  ExpectStatus(pending_status, drogon::k200OK);
  ASSERT_NE(pending_status.response->getJsonObject(), nullptr);
  EXPECT_TRUE((*pending_status.response->getJsonObject())["required"].asBool());
  EXPECT_EQ((*pending_status.response->getJsonObject())["phase"].asString(),
            "runtime_pending");
  EXPECT_EQ((*pending_status.response->getJsonObject())["peer_ip"].asString(),
            "127.0.0.1");

  auto different_peer = NewClient(port, "127.0.0.2");
  auto rejected_peer = Send(different_peer, drogon::Post,
                            "/api/v1/setup/runtime", "{}",
                            origin, {}, true);
  ExpectStatus(rejected_peer, drogon::k403Forbidden);
  EXPECT_EQ(rejected_peer.response->getBody().find("127.0.0.1"),
            std::string_view::npos);
  EXPECT_EQ(rejected_peer.response->getBody().find("127.0.0.2"),
            std::string_view::npos);
  EXPECT_EQ(runtime_start_calls.load(), 1);

  runtime_start_should_fail.store(false);
  auto retry = Send(client, drogon::Post, "/api/v1/setup/runtime",
                    "{}", origin, {}, true);
  ExpectStatus(retry, drogon::k200OK);
  ASSERT_NE(retry.response->getJsonObject(), nullptr);
  EXPECT_FALSE((*retry.response->getJsonObject())["required"].asBool());
  EXPECT_EQ((*retry.response->getJsonObject())["runtime"].asString(),
            "running");
  EXPECT_EQ(runtime_start_calls.load(), 2);

  auto operational_status =
      Send(client, drogon::Get, "/api/v1/setup/status");
  ExpectStatus(operational_status, drogon::k200OK);
  ASSERT_NE(operational_status.response->getJsonObject(), nullptr);
  EXPECT_FALSE(
      (*operational_status.response->getJsonObject())["required"].asBool());
  EXPECT_FALSE(
      operational_status.response->getJsonObject()->isMember("peer_ip"));
  EXPECT_FALSE(
      operational_status.response->getJsonObject()->isMember("phase"));

  auto repeated_setup = Send(client, drogon::Post,
                             "/api/v1/setup/initialize", setup_body, origin,
                             {}, true);
  ExpectStatus(repeated_setup, drogon::k403Forbidden);
  EXPECT_EQ(runtime_start_calls.load(), 2);

  auto unauthenticated = Send(client, drogon::Get, "/api/v1/cameras");
  ExpectStatus(unauthenticated, drogon::k401Unauthorized);
  ExpectStatus(Send(client, drogon::Get,
                    "/api/v1/cameras/imx708-main/snapshot.jpg"),
               drogon::k401Unauthorized);
  ExpectStatus(Send(client, drogon::Get, "/api/v1/ai/detections"),
               drogon::k401Unauthorized);
  ExpectStatus(Send(client, drogon::Get,
                    "/api/v1/ai/detections/stream"),
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
  auto cross_origin_login = Send(client, drogon::Post, "/api/v1/auth/login",
                                 login_body, "https://attacker.example", {},
                                 true);
  ExpectStatus(cross_origin_login, drogon::k403Forbidden);

  std::atomic<int> unavailable{0};
  std::vector<std::thread> flood;
  flood_mode.store(true);
  for (int index = 0; index < 32; ++index) {
    flood.emplace_back([&, index] {
      auto flood_client = NewClient(port);
      auto response = Send(
          flood_client, drogon::Post, "/api/v1/auth/login",
          "{\"username\":\"missing" + std::to_string(index) +
              "\",\"password\":\"StrongPass9!\"}",
          origin, {}, true);
      if (response.result == drogon::ReqResult::Ok && response.response &&
          response.response->statusCode() ==
              drogon::k503ServiceUnavailable) {
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

  const std::string wrong_password = "LeakProbe9!";
  auto wrong_login = Send(
      client, drogon::Post, "/api/v1/auth/login",
      "{\"username\":\"owner1\",\"password\":\"" + wrong_password +
          "\"}",
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
  const std::string cookie =
      "camera_session=" + session_cookie.value();

  EXPECT_EQ(RawHttpsGet(port, "/api/v1/auth/me", {cookie}).status, 200);
  EXPECT_EQ(RawHttpsGet(port, "/api/v1/auth/me", {cookie, cookie}).status,
            401);

  auto me = Send(client, drogon::Get, "/api/v1/auth/me", {}, {}, cookie);
  ExpectStatus(me, drogon::k200OK);
  ExpectSecurityHeaders(me.response);
  ASSERT_NE(me.response->getJsonObject(), nullptr);
  EXPECT_EQ((*me.response->getJsonObject())["username"].asString(), "owner1");
  EXPECT_EQ((*me.response->getJsonObject())["role"].asString(),
            "administrator");

  auto ambiguous_cookie = Send(client, drogon::Get, "/api/v1/auth/me", {}, {},
                               cookie + "; theme=dark");
  ExpectStatus(ambiguous_cookie, drogon::k401Unauthorized);

  auto cameras =
      Send(client, drogon::Get, "/api/v1/cameras", {}, {}, cookie);
  ExpectStatus(cameras, drogon::k200OK);
  ExpectSecurityHeaders(cameras.response);
  EXPECT_EQ(camera_provider_calls.load(), 1);

  auto snapshot = Send(client, drogon::Get,
                       "/api/v1/cameras/imx708-main/snapshot.jpg", {}, {},
                       cookie);
  ExpectStatus(snapshot, drogon::k200OK);
  ExpectSecurityHeaders(snapshot.response);

  complete_sse_then_throw.store(true);
  auto retained_sse = Send(client, drogon::Get,
                           "/api/v1/ai/detections/stream", {}, {}, cookie);
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

  auto no_csrf_runtime_restart = Send(
      client, drogon::Post, "/api/v1/runtime/restart", "{}", {}, cookie);
  ExpectStatus(no_csrf_runtime_restart, drogon::k403Forbidden);
  EXPECT_EQ(runtime_start_calls.load(), 2);

  runtime_start_should_fail.store(true);
  auto failed_runtime_restart = Send(
      client, drogon::Post, "/api/v1/runtime/restart", "{}", origin,
      cookie, true);
  ExpectStatus(failed_runtime_restart, drogon::k503ServiceUnavailable);
  EXPECT_EQ(failed_runtime_restart.response->getBody().find(
                "runtime failure detail"),
            std::string_view::npos);
  EXPECT_EQ(runtime_start_calls.load(), 3);
  ExpectStatus(Send(client, drogon::Get, "/api/v1/health", {}, {}, cookie),
               drogon::k200OK);

  runtime_start_should_fail.store(false);
  auto recovered_runtime = Send(
      client, drogon::Post, "/api/v1/runtime/restart", "{}", origin,
      cookie, true);
  ExpectStatus(recovered_runtime, drogon::k200OK);
  ASSERT_NE(recovered_runtime.response->getJsonObject(), nullptr);
  EXPECT_EQ((*recovered_runtime.response->getJsonObject())["runtime"].asString(),
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

  shutdown_block_mode.store(true);
  HttpResult shutdown_login;
  std::thread pending_login([&] {
    auto shutdown_client = NewClient(port);
    shutdown_login = Send(shutdown_client, drogon::Post, "/api/v1/auth/login",
                          login_body, origin, {}, true);
  });
  ASSERT_EQ(shutdown_block_started.get_future().wait_for(
                std::chrono::seconds(5)),
            std::future_status::ready);
  auto stopping = std::async(std::launch::async, [&] { service.Stop(); });
  EXPECT_EQ(stopping.wait_for(std::chrono::milliseconds(50)),
            std::future_status::timeout);
  release_shutdown_block.set_value();
  pending_login.join();
  ExpectStatus(shutdown_login, drogon::k401Unauthorized);
  EXPECT_EQ(stopping.wait_for(std::chrono::seconds(5)),
            std::future_status::ready);
}

TEST(HttpsAuthIntegrationTest, RuntimeSettingsAreUnavailableWithoutSecurity) {
  const auto scenario =
      ProcessArgumentValue(kRuntimeSettingsScenarioArgument);
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
    args.runtime_settings_snapshot_callback = [snapshot] { return snapshot; };
    args.runtime_settings_save_callback =
        [snapshot](std::uint64_t,
                   camera_firmware::settings::RuntimeSettings) {
          return camera_firmware::common::Result<
              camera_firmware::settings::RuntimeSettingsSnapshot>::Ok(
              snapshot);
        };
    args.runtime_settings_apply_callback =
        [snapshot](std::uint64_t) {
          return camera_firmware::settings::SettingsApplyResult{
              snapshot, true, false, {}};
        };
    args.runtime_settings_discard_callback =
        [snapshot](std::uint64_t) {
          return camera_firmware::common::Result<
              camera_firmware::settings::RuntimeSettingsSnapshot>::Ok(
              snapshot);
        };

    camera_firmware::service::ServiceApp service;
    const auto started = service.Init(args);
    if (!started.ok()) {
      _exit(2);
    }
    const auto response = Send(NewClient(port), drogon::Get,
                               "/api/v1/settings/runtime");
    if (response.result != drogon::ReqResult::Ok || !response.response ||
        response.response->statusCode() != drogon::k503ServiceUnavailable ||
        response.response->getJsonObject() == nullptr ||
        (*response.response->getJsonObject())["code"].asString() !=
            "E_SETTINGS_UNAVAILABLE") {
      _exit(3);
    }
    service.Stop();
    _exit(0);
  }
  _exit(124);
}

TEST(HttpsAuthIntegrationTest,
     RuntimeSettingsPendingSaveSurvivesSecurityAndServiceRestart) {
  const auto scenario =
      ProcessArgumentValue(kRuntimeSettingsScenarioArgument);
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
  const auto scenario =
      ProcessArgumentValue(kRuntimeSettingsScenarioArgument);
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
  if (*scenario == "incomplete-callbacks" &&
      state_directory.has_value()) {
    const std::uint16_t port = ReserveLoopbackPort();
    const std::string origin =
        "https://127.0.0.1:" + std::to_string(port);
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
    args.document_root = config.http.web_root;
    args.public_base_url = origin;
    args.runtime_start_callback = [] {
      return camera_firmware::common::Result<void>::Ok();
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
        origin, {}, true);
    if (!setup.response || setup.response->statusCode() != drogon::k200OK) {
      _exit(3);
    }
    const auto login = Send(
        client, drogon::Post, "/api/v1/auth/login",
        R"({"username":"owner1","password":"StrongPass9!"})", origin,
        {}, true);
    if (!login.response || login.response->statusCode() != drogon::k200OK) {
      _exit(4);
    }
    const std::string cookie =
        "camera_session=" + login.response->getCookie("camera_session").value();

    const auto get = Send(client, drogon::Get,
                          "/api/v1/settings/runtime", {}, {}, cookie);
    const auto put = Send(client, drogon::Put,
                          "/api/v1/settings/runtime", "{}", origin,
                          cookie, true);
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
  const auto scenario =
      ProcessArgumentValue(kRuntimeSettingsScenarioArgument);
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
  if (*scenario == "routes-and-shutdown" &&
      state_directory.has_value()) {
    const std::uint16_t port = ReserveLoopbackPort();
    const std::string origin =
        "https://127.0.0.1:" + std::to_string(port);
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
    snapshot.state =
        camera_firmware::settings::RuntimeSettingsState::kClean;
    snapshot.active.camera = {"imx708-1080p50", 6000U, 25U};
    snapshot.active.models = {{"objects", true, 0.40F},
                              {"pose", true, 0.35F}};
    snapshot.camera_profiles = {
        {"imx708-1080p50", "1080p 50 fps", 1920U, 1080U, 50U},
        {"imx708-1080p30", "1080p 30 fps", 1920U, 1080U, 30U},
    };
    snapshot.model_capabilities = {
        {"objects", "object_detection", 640U, 640U, "rgb8", true,
         "coco80"},
        {"pose", "pose_estimation", 640U, 640U, "rgb8", false,
         "pose17"},
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

    camera_firmware::service::ServiceInitArgs args;
    args.app_config = &config;
    args.document_root = config.http.web_root;
    args.public_base_url = origin;
    args.runtime_start_callback = [] {
      return camera_firmware::common::Result<void>::Ok();
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
            return camera_firmware::common::Result<
                camera_firmware::settings::RuntimeSettingsSnapshot>::Err(
                {"E_RUNTIME_SETTINGS_REVISION", "private stale detail"});
          }
          snapshot.pending = std::move(settings);
          snapshot.state =
              camera_firmware::settings::RuntimeSettingsState::kPending;
          ++snapshot.revision;
          return camera_firmware::common::Result<
              camera_firmware::settings::RuntimeSettingsSnapshot>::Ok(
              snapshot);
        };
    args.runtime_settings_apply_callback =
        [&](std::uint64_t) {
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
              snapshot, false, true,
              {"E_RUNTIME_SETTINGS_APPLY",
               "private /opt/models/model.hef backend detail"}};
        };
    args.runtime_settings_discard_callback =
        [&](std::uint64_t expected_revision) {
          std::lock_guard lock(snapshot_mutex);
          if (expected_revision != snapshot.revision) {
            return camera_firmware::common::Result<
                camera_firmware::settings::RuntimeSettingsSnapshot>::Err(
                {"E_RUNTIME_SETTINGS_REVISION", "private stale detail"});
          }
          snapshot.pending.reset();
          snapshot.state =
              camera_firmware::settings::RuntimeSettingsState::kClean;
          ++snapshot.revision;
          return camera_firmware::common::Result<
              camera_firmware::settings::RuntimeSettingsSnapshot>::Ok(
              snapshot);
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
    const auto setup = Send(client, drogon::Post, "/api/v1/setup/initialize",
                            setup_body, origin, {}, true);
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
        R"({"username":"owner1","password":"StrongPass9!"})", origin,
        {}, true);
    if (!login.response || login.response->statusCode() != drogon::k200OK) {
      _exit(5);
    }
    const std::string cookie =
        "camera_session=" +
        login.response->getCookie("camera_session").value();

    const std::string private_marker =
        "/private/models/runtime-settings-secret.hef";
    std::string oversized_settings_body(
        camera_firmware::service::kMaximumRuntimeSettingsBodyBytes + 1U,
        'x');
    oversized_settings_body.replace(0U, private_marker.size(), private_marker);

    const std::string declared_prefix =
        "PUT /api/v1/settings/runtime HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Content-Type: application/json\r\nContent-Length: " +
        std::to_string(oversized_settings_body.size()) + "\r\n";
    const auto oversized_unauthenticated = RawHttpsExchange(
        port, declared_prefix + "Connection: close\r\n\r\n" +
                  oversized_settings_body);
    const auto oversized_without_origin = RawHttpsExchange(
        port, declared_prefix + "Cookie: " + cookie +
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
        "Transfer-Encoding: chunked\r\nOrigin: " + origin +
        "\r\nCookie: " + cookie +
        "\r\nX-Camera-Request: management\r\nConnection: close\r\n\r\n"
        "4001\r\n" + oversized_settings_body + "\r\n0\r\n\r\n";
    const auto chunked_response = RawHttpsExchange(port, chunked_request);
    if (!IsBoundedRuntimeSettingsInvalidResponse(declared_response,
                                                 private_marker) ||
        !IsBoundedRuntimeSettingsInvalidResponse(chunked_response,
                                                 private_marker)) {
      service.Stop();
      _exit(19);
    }

    const auto get = Send(client, drogon::Get,
                          "/api/v1/settings/runtime", {}, {}, cookie);
    if (!get.response || get.response->statusCode() != drogon::k200OK ||
        get.response->getJsonObject() == nullptr ||
        (*get.response->getJsonObject())["revision"].asUInt64() != 7U) {
      _exit(6);
    }

    const std::string update =
        R"({"expected_revision":7,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30},"models":[{"id":"objects","enabled":true,"confidence_threshold":0.55},{"id":"pose","enabled":false,"confidence_threshold":0.25}]}})";
    const auto no_origin = Send(client, drogon::Put,
                                "/api/v1/settings/runtime", update, {},
                                cookie, true);
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

    const auto saved = Send(client, drogon::Put,
                            "/api/v1/settings/runtime", update, origin,
                            cookie, true);
    if (!saved.response || saved.response->statusCode() != drogon::k200OK ||
        saved.response->getJsonObject() == nullptr ||
        (*saved.response->getJsonObject())["revision"].asUInt64() != 8U) {
      _exit(9);
    }
    const auto stale = Send(client, drogon::Put,
                            "/api/v1/settings/runtime", update, origin,
                            cookie, true);
    if (!stale.response ||
        stale.response->statusCode() != drogon::k409Conflict ||
        stale.response->getBody().find("private") != std::string::npos) {
      _exit(10);
    }

    const auto apply = Send(
        client, drogon::Post, "/api/v1/settings/runtime/apply",
        R"({"expected_revision":8})", origin, cookie, true);
    if (!apply.response ||
        apply.response->statusCode() != drogon::k503ServiceUnavailable ||
        apply.response->getJsonObject() == nullptr ||
        !(*apply.response->getJsonObject())["restored"].asBool() ||
        apply.response->getBody().find("/opt/") != std::string::npos) {
      _exit(11);
    }
    const auto after_apply = Send(client, drogon::Get,
                                  "/api/v1/settings/runtime", {}, {}, cookie);
    if (!after_apply.response ||
        after_apply.response->statusCode() != drogon::k200OK) {
      _exit(12);
    }

    const auto wrong_method = Send(client, drogon::Patch,
                                   "/api/v1/settings/runtime", update,
                                   origin, cookie, true);
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
    release_apply_guard.Release();
    const auto executing_apply_response = executing_apply.get();
    if (contender_one.has_value() && !contender_one_response.has_value()) {
      contender_one_response = contender_one->get();
    }
    if (contender_two.has_value() && !contender_two_response.has_value()) {
      contender_two_response = contender_two->get();
    }
    saturate_apply.store(false);

    const auto status_count = [&](drogon::HttpStatusCode status) {
      unsigned int count = 0U;
      for (const auto* response : {&contender_one_response,
                                   &contender_two_response}) {
        if (response->has_value() && (*response)->response &&
            (*response)->response->statusCode() == status) {
          ++count;
        }
      }
      return count;
    };

    const bool saturation_passed =
        apply_started_status == std::future_status::ready &&
        busy_completed_before_release &&
        executing_apply_response.response &&
        executing_apply_response.response->statusCode() == drogon::k200OK &&
        status_count(drogon::k200OK) == 1U &&
        status_count(drogon::k409Conflict) == 1U &&
        saturated_apply_calls.load() == 2U;
    if (!saturation_passed) {
      service.Stop();
      _exit(18);
    }

    block_save.store(true);
    const std::string blocking_update =
        R"({"expected_revision":8,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":9000,"gop":30},"models":[{"id":"objects","enabled":true,"confidence_threshold":0.60},{"id":"pose","enabled":false,"confidence_threshold":0.25}]}})";
    auto accepted = std::async(std::launch::async, [&] {
      return Send(NewClient(port), drogon::Put,
                  "/api/v1/settings/runtime", blocking_update, origin,
                  cookie, true);
    });
    const auto save_started_status =
        save_started.get_future().wait_for(std::chrono::seconds(5));
    std::optional<std::future<void>> stopping;
    bool stop_waited_for_save = false;
    if (save_started_status == std::future_status::ready) {
      stopping.emplace(
          std::async(std::launch::async, [&] { service.Stop(); }));
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

}  // namespace
