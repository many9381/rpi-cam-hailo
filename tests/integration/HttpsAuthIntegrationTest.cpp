#include "camera_firmware/service/ServiceApp.hpp"
#include "camera_firmware/boot/FirmwareBootCoordinator.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cctype>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <future>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
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
#include <openssl/ssl.h>

#include "camera_firmware/security/PasswordHasher.hpp"

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

class DeterministicMjpegProvider {
 public:
  static constexpr std::size_t kMaximumReaders = 2U;

  explicit DeterministicMjpegProvider(std::string jpeg_payload)
      : state_(std::make_shared<State>(std::move(jpeg_payload))) {}

  camera_firmware::common::Result<
      camera_firmware::service::MjpegPreviewStreamCallback>
  Open(const std::string& camera_id) {
    if (camera_id.starts_with("loop-probe-")) {
      state_->probe_opens.fetch_add(1U, std::memory_order_relaxed);
      auto reader = std::make_shared<ProbeReader>();
      auto state = state_;
      camera_firmware::service::MjpegPreviewStreamCallback stream =
          [state = std::move(state), camera_id,
           reader = std::move(reader)](char* output, std::size_t capacity) {
            if (output == nullptr) {
              return std::size_t{0};
            }
            if (!reader->recorded.exchange(true, std::memory_order_acq_rel)) {
              std::scoped_lock lock(state->mutex);
              state->probe_assignments[camera_id] =
                  std::this_thread::get_id();
            }
            std::scoped_lock reader_lock(reader->mutex);
            if (reader->offset == state->part.size()) {
              return std::size_t{0};
            }
            const std::size_t count =
                std::min(capacity, state->part.size() - reader->offset);
            std::copy_n(state->part.data() + reader->offset, count, output);
            reader->offset += count;
            return count;
          };
      return camera_firmware::common::Result<
          camera_firmware::service::MjpegPreviewStreamCallback>::Ok(
          std::move(stream));
    }

    state_->provider_calls.fetch_add(1U, std::memory_order_relaxed);
    if (camera_id != "imx708-main") {
      return camera_firmware::common::Result<
          camera_firmware::service::MjpegPreviewStreamCallback>::Err(
          {"E_PREVIEW_UNAVAILABLE", "integration camera unavailable"});
    }
    if (!state_->blocking_mode.load(std::memory_order_acquire)) {
      return camera_firmware::common::Result<
          camera_firmware::service::MjpegPreviewStreamCallback>::Err(
          {"E_PREVIEW_UNAVAILABLE", "integration provider not blocking"});
    }

    std::size_t active =
        state_->active_readers.load(std::memory_order_acquire);
    while (active < kMaximumReaders &&
           !state_->active_readers.compare_exchange_weak(
               active, active + 1U, std::memory_order_acq_rel,
               std::memory_order_acquire)) {
    }
    if (active >= kMaximumReaders) {
      return camera_firmware::common::Result<
          camera_firmware::service::MjpegPreviewStreamCallback>::Err(
          {"E_PREVIEW_CAPACITY", "integration reader capacity full"});
    }

    auto reader = std::make_shared<Reader>();
    reader->deadline = std::chrono::steady_clock::now() +
                       std::chrono::seconds(12);
    auto state = state_;
    camera_firmware::service::MjpegPreviewStreamCallback stream =
        [state = std::move(state), reader = std::move(reader)](
            char* output, std::size_t capacity) {
          if (output == nullptr) {
            if (!reader->cleaned.exchange(true, std::memory_order_acq_rel)) {
              state->active_readers.fetch_sub(1U, std::memory_order_acq_rel);
              state->cleanup_calls.fetch_add(1U, std::memory_order_release);
              state->changed.notify_all();
            }
            return std::size_t{0};
          }
          if (reader->cleaned.load(std::memory_order_acquire)) {
            return std::size_t{0};
          }

          bool entered_gate = false;
          {
            std::scoped_lock reader_lock(reader->mutex);
            if (reader->offset < state->part.size()) {
              const std::size_t count =
                  std::min(capacity, state->part.size() - reader->offset);
              std::copy_n(state->part.data() + reader->offset, count, output);
              reader->offset += count;
              return count;
            }
            if (!reader->gate_entered) {
              reader->gate_entered = true;
              entered_gate = true;
            }
          }
          if (entered_gate) {
            {
              std::scoped_lock lock(state->mutex);
              state->blocked_threads.push_back(std::this_thread::get_id());
              state->blocked_callbacks.fetch_add(1U,
                                                 std::memory_order_release);
            }
            state->changed.notify_all();
          } else {
            return std::size_t{0};
          }

          std::unique_lock lock(state->mutex);
          const bool released = state->changed.wait_until(
              lock, reader->deadline, [&] { return state->released; });
          state->blocked_callbacks.fetch_sub(1U, std::memory_order_acq_rel);
          if (!released) {
            state->watchdog_timeouts.fetch_add(1U,
                                               std::memory_order_release);
          }
          lock.unlock();
          state->changed.notify_all();
          return std::size_t{0};
        };
    return camera_firmware::common::Result<
        camera_firmware::service::MjpegPreviewStreamCallback>::Ok(
        std::move(stream));
  }

  [[nodiscard]] const std::string& expected_part() const noexcept {
    return state_->part;
  }

  [[nodiscard]] std::size_t provider_calls() const noexcept {
    return state_->provider_calls.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::size_t probe_opens() const noexcept {
    return state_->probe_opens.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::size_t active_readers() const noexcept {
    return state_->active_readers.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::size_t blocked_callbacks() const noexcept {
    return state_->blocked_callbacks.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::size_t cleanup_calls() const noexcept {
    return state_->cleanup_calls.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::size_t watchdog_timeouts() const noexcept {
    return state_->watchdog_timeouts.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::vector<std::thread::id> blocked_threads() const {
    std::scoped_lock lock(state_->mutex);
    return state_->blocked_threads;
  }

  [[nodiscard]] std::optional<std::thread::id> ProbeThreadFor(
      const std::string& camera_id) const {
    std::scoped_lock lock(state_->mutex);
    const auto found = state_->probe_assignments.find(camera_id);
    if (found == state_->probe_assignments.end()) {
      return std::nullopt;
    }
    return found->second;
  }

  bool WaitForBlocked(std::size_t expected,
                      std::chrono::steady_clock::time_point deadline) const {
    std::unique_lock lock(state_->mutex);
    return state_->changed.wait_until(lock, deadline, [&] {
      return state_->blocked_callbacks.load(std::memory_order_acquire) ==
             expected;
    });
  }

  bool WaitForCleanup(std::size_t expected,
                      std::chrono::steady_clock::time_point deadline) const {
    std::unique_lock lock(state_->mutex);
    return state_->changed.wait_until(lock, deadline, [&] {
      return state_->cleanup_calls.load(std::memory_order_acquire) == expected &&
             state_->active_readers.load(std::memory_order_acquire) == 0U &&
             state_->blocked_callbacks.load(std::memory_order_acquire) == 0U;
    });
  }

  void Release() {
    {
      std::scoped_lock lock(state_->mutex);
      state_->released = true;
    }
    state_->changed.notify_all();
  }

  void EnableBlockingMode() {
    state_->blocking_mode.store(true, std::memory_order_release);
  }

 private:
  struct State {
    explicit State(std::string jpeg_payload)
        : part("--cf-frame\r\nContent-Type: image/jpeg\r\nContent-Length: " +
               std::to_string(jpeg_payload.size()) + "\r\n\r\n" +
               std::move(jpeg_payload) + "\r\n") {}

    const std::string part;
    std::atomic<std::size_t> provider_calls{0U};
    std::atomic<std::size_t> probe_opens{0U};
    std::atomic<std::size_t> active_readers{0U};
    std::atomic<std::size_t> blocked_callbacks{0U};
    std::atomic<std::size_t> cleanup_calls{0U};
    std::atomic<std::size_t> watchdog_timeouts{0U};
    std::atomic<bool> blocking_mode{false};
    mutable std::mutex mutex;
    mutable std::condition_variable changed;
    std::vector<std::thread::id> blocked_threads;
    std::map<std::string, std::thread::id> probe_assignments;
    bool released{false};
  };

  struct ProbeReader {
    std::mutex mutex;
    std::size_t offset{0U};
    std::atomic<bool> recorded{false};
  };

  struct Reader {
    std::mutex mutex;
    std::size_t offset{0U};
    bool gate_entered{false};
    std::atomic<bool> cleaned{false};
    std::chrono::steady_clock::time_point deadline;
  };

  std::shared_ptr<State> state_;
};

class PreviewReleaseGuard {
 public:
  explicit PreviewReleaseGuard(DeterministicMjpegProvider& provider)
      : provider_(&provider) {}
  ~PreviewReleaseGuard() { provider_->Release(); }

  PreviewReleaseGuard(const PreviewReleaseGuard&) = delete;
  PreviewReleaseGuard& operator=(const PreviewReleaseGuard&) = delete;

 private:
  DeterministicMjpegProvider* provider_;
};

void ExpectMjpegResponse(const RawHttpsResponse& response,
                         std::string_view expected_part) {
  EXPECT_EQ(response.status, 200);
  EXPECT_EQ(response.Header("Content-Type"),
            "multipart/x-mixed-replace; boundary=cf-frame");
  EXPECT_EQ(response.Header("Content-Encoding"), "identity");
  ExpectRawSecurityHeaders(response);
  const auto body = DecodeAvailableRawBody(response);
  ASSERT_TRUE(body.has_value());
  EXPECT_EQ(*body, expected_part);
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

TEST(HttpsAuthIntegrationTest, ParentOwnedWatchdogRemovesDirectoryAfterAlarm) {
  EXPECT_TRUE(RunParentOwnedWatchdogCleanupProbe());
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

void RunAuthenticatedMjpegScenario(
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

  const std::string jpeg_payload("\xff\xd8\xff\xd9", 4U);
  DeterministicMjpegProvider preview_provider(jpeg_payload);
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.document_root = config.http.web_root;
  args.public_base_url = origin;
  args.runtime_start_callback = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  args.preview_stream_callback = [&](const std::string& camera_id) {
    return preview_provider.Open(camera_id);
  };

  camera_firmware::service::ServiceApp service;
  auto started = service.Init(args);
  ASSERT_TRUE(started.ok()) << started.error().message;
  EXPECT_EQ(drogon::app().getThreadNum(), 4U);
  auto client = NewClient(port);

  auto denied = Send(client, drogon::Get,
                     "/api/v1/cameras/imx708-main/preview.mjpeg");
  ExpectStatus(denied, drogon::k403Forbidden);
  ExpectSecurityHeaders(denied.response);
  EXPECT_EQ(preview_provider.provider_calls(), 0U);

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

  struct MappedConnection {
    std::unique_ptr<RawHttpsConnection> connection;
    std::thread::id server_thread;
  };
  constexpr std::size_t kMaximumCandidates = 16U;
  constexpr std::size_t kReceiveByteLimit = 4096U;
  constexpr auto kFiniteReceiveTimeout = std::chrono::seconds(2);

  {
    constexpr std::size_t kTinyReceiveByteLimit = 64U;
    const std::string tiny_limit_camera_id = "loop-probe-tiny-limit";
    const std::string rejected_reuse_camera_id =
        "loop-probe-rejected-reuse";
    RawHttpsConnection tiny_limit_connection(port, kFiniteReceiveTimeout);
    ASSERT_TRUE(tiny_limit_connection.connected());
    const auto tiny_limit_response = tiny_limit_connection.Get(
        "/api/v1/cameras/" + tiny_limit_camera_id + "/preview.mjpeg",
        {cookie}, kTinyReceiveByteLimit, kFiniteReceiveTimeout, true);
    EXPECT_EQ(tiny_limit_response.bytes.size(), kTinyReceiveByteLimit);
    EXPECT_EQ(tiny_limit_response.read_end,
              RawHttpsResponse::ReadEnd::kByteLimit);
    EXPECT_FALSE(tiny_limit_connection.connected());
    EXPECT_EQ(preview_provider.probe_opens(), 1U);

    const std::size_t probe_opens_before_reuse =
        preview_provider.probe_opens();
    const auto rejected_reuse = tiny_limit_connection.Get(
        "/api/v1/cameras/" + rejected_reuse_camera_id + "/preview.mjpeg",
        {cookie}, kReceiveByteLimit, kFiniteReceiveTimeout, true);
    EXPECT_TRUE(rejected_reuse.bytes.empty());
    EXPECT_EQ(rejected_reuse.status, -1);
    EXPECT_EQ(preview_provider.probe_opens(), probe_opens_before_reuse);
    EXPECT_FALSE(preview_provider.ProbeThreadFor(rejected_reuse_camera_id)
                     .has_value());
  }

  std::vector<MappedConnection> mapped_connections;
  std::set<std::thread::id> mapped_threads;
  for (std::size_t index = 0U;
       index < kMaximumCandidates && mapped_connections.size() < 3U;
       ++index) {
    auto candidate =
        std::make_unique<RawHttpsConnection>(port, kFiniteReceiveTimeout);
    ASSERT_TRUE(candidate->connected());
    const std::string camera_id = "loop-probe-" + std::to_string(index);
    const auto probe = candidate->Get(
        "/api/v1/cameras/" + camera_id + "/preview.mjpeg", {cookie},
        kReceiveByteLimit, kFiniteReceiveTimeout, true);
    EXPECT_EQ(probe.read_end, RawHttpsResponse::ReadEnd::kComplete);
    EXPECT_TRUE(candidate->connected());
    ExpectMjpegResponse(probe, preview_provider.expected_part());
    const auto server_thread = preview_provider.ProbeThreadFor(camera_id);
    ASSERT_TRUE(server_thread.has_value());
    if (mapped_threads.insert(*server_thread).second) {
      mapped_connections.push_back(
          {std::move(candidate), *server_thread});
    }
  }
  ASSERT_EQ(mapped_connections.size(), 3U);
  EXPECT_EQ(preview_provider.active_readers(), 0U);
  EXPECT_EQ(preview_provider.cleanup_calls(), 0U);
  EXPECT_EQ(preview_provider.provider_calls(), 0U);
  preview_provider.EnableBlockingMode();

  constexpr auto kStreamReceiveTimeout = std::chrono::milliseconds(500);
  const std::string preview_path =
      "/api/v1/cameras/imx708-main/preview.mjpeg";
  std::future<RawHttpsResponse> first_stream;
  std::future<RawHttpsResponse> second_stream;
  PreviewReleaseGuard release_on_exit(preview_provider);
  first_stream = std::async(std::launch::async, [&] {
    return mapped_connections[0].connection->Get(
        preview_path, {cookie}, kReceiveByteLimit, kStreamReceiveTimeout,
        false);
  });
  second_stream = std::async(std::launch::async, [&] {
    return mapped_connections[1].connection->Get(
        preview_path, {cookie}, kReceiveByteLimit, kStreamReceiveTimeout,
        false);
  });

  const auto stream_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(3);
  ASSERT_TRUE(preview_provider.WaitForBlocked(2U, stream_deadline));
  EXPECT_EQ(preview_provider.active_readers(), 2U);
  EXPECT_EQ(preview_provider.blocked_callbacks(), 2U);
  EXPECT_EQ(preview_provider.provider_calls(), 2U);
  const auto blocked_threads = preview_provider.blocked_threads();
  ASSERT_EQ(blocked_threads.size(), 2U);
  EXPECT_NE(blocked_threads[0], blocked_threads[1]);
  EXPECT_NE(std::find(blocked_threads.begin(), blocked_threads.end(),
                      mapped_connections[0].server_thread),
            blocked_threads.end());
  EXPECT_NE(std::find(blocked_threads.begin(), blocked_threads.end(),
                      mapped_connections[1].server_thread),
            blocked_threads.end());

  ASSERT_EQ(first_stream.wait_until(stream_deadline),
            std::future_status::ready);
  ASSERT_EQ(second_stream.wait_until(stream_deadline),
            std::future_status::ready);
  const RawHttpsResponse first_response = first_stream.get();
  const RawHttpsResponse second_response = second_stream.get();
  EXPECT_EQ(first_response.read_end, RawHttpsResponse::ReadEnd::kTimeout);
  EXPECT_EQ(second_response.read_end, RawHttpsResponse::ReadEnd::kTimeout);
  EXPECT_LT(first_response.bytes.size(), kReceiveByteLimit);
  EXPECT_LT(second_response.bytes.size(), kReceiveByteLimit);
  ExpectMjpegResponse(first_response, preview_provider.expected_part());
  ExpectMjpegResponse(second_response, preview_provider.expected_part());

  auto health = std::async(std::launch::async, [&] {
    return mapped_connections[2].connection->Get(
        "/api/v1/health", {cookie}, kReceiveByteLimit,
        kFiniteReceiveTimeout, true);
  });
  const auto health_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(2);
  const auto health_wait = health.wait_until(health_deadline);
  if (health_wait != std::future_status::ready) {
    preview_provider.Release();
  }
  ASSERT_EQ(health_wait, std::future_status::ready);
  const RawHttpsResponse health_response = health.get();
  EXPECT_EQ(health_response.read_end, RawHttpsResponse::ReadEnd::kComplete);
  EXPECT_EQ(health_response.status, 200);
  EXPECT_TRUE(mapped_connections[2].connection->connected());
  ExpectRawSecurityHeaders(health_response);
  EXPECT_EQ(preview_provider.blocked_callbacks(), 2U);
  EXPECT_EQ(preview_provider.watchdog_timeouts(), 0U);

  const auto capacity = mapped_connections[2].connection->Get(
      preview_path, {cookie}, kReceiveByteLimit, kFiniteReceiveTimeout, true);
  EXPECT_EQ(capacity.read_end, RawHttpsResponse::ReadEnd::kComplete);
  EXPECT_EQ(capacity.status, 503);
  EXPECT_TRUE(mapped_connections[2].connection->connected());
  ExpectRawSecurityHeaders(capacity);
  const auto capacity_body = DecodeAvailableRawBody(capacity);
  ASSERT_TRUE(capacity_body.has_value());
  Json::CharReaderBuilder json_builder;
  std::unique_ptr<Json::CharReader> json_reader(json_builder.newCharReader());
  Json::Value capacity_json;
  std::string json_errors;
  ASSERT_TRUE(json_reader->parse(
      capacity_body->data(), capacity_body->data() + capacity_body->size(),
      &capacity_json, &json_errors));
  EXPECT_EQ(capacity_json["code"].asString(), "E_PREVIEW_CAPACITY");
  EXPECT_EQ(capacity_json["message"].asString(),
            "MJPEG preview reader capacity is full");
  EXPECT_EQ(preview_provider.provider_calls(), 3U);
  EXPECT_EQ(preview_provider.active_readers(), 2U);
  EXPECT_EQ(preview_provider.blocked_callbacks(), 2U);
  EXPECT_EQ(preview_provider.watchdog_timeouts(), 0U);

  camera_firmware::boot::FirmwareBootDependencies shutdown_dependencies;
  shutdown_dependencies.start_runtime = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  shutdown_dependencies.stop_runtime = [&] { preview_provider.Release(); };
  shutdown_dependencies.start_service = [](
                                            camera_firmware::boot::RuntimeStartCallback) {
    return camera_firmware::common::Result<void>::Ok();
  };
  shutdown_dependencies.quiesce_service = [&] { service.BeginShutdown(); };
  shutdown_dependencies.stop_service = [&] { service.Stop(); };
  camera_firmware::boot::FirmwareBootCoordinator shutdown(
      {false, true}, std::move(shutdown_dependencies));
  ASSERT_TRUE(shutdown.Start().ok());

  auto stopped = std::async(std::launch::async, [&] { shutdown.Stop(); });
  const auto stop_status = stopped.wait_for(std::chrono::seconds(3));
  if (stop_status != std::future_status::ready) {
    preview_provider.Release();
  }
  EXPECT_EQ(stop_status, std::future_status::ready);
  stopped.wait();

  const auto cleanup_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(3);
  ASSERT_TRUE(preview_provider.WaitForCleanup(2U, cleanup_deadline));
  EXPECT_EQ(preview_provider.cleanup_calls(), 2U);
  EXPECT_EQ(preview_provider.active_readers(), 0U);
  EXPECT_EQ(preview_provider.blocked_callbacks(), 0U);
  EXPECT_EQ(preview_provider.watchdog_timeouts(), 0U);
  mapped_connections.clear();

}

TEST(HttpsAuthIntegrationTest,
     AuthenticatedMjpegPreviewStreamsRemainBoundedAndResponsive) {
  TemporaryDirectory directory;
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    RunAuthenticatedMjpegScenario(directory.path());
    _exit(::testing::Test::HasFailure() ? 1 : 0);
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
      "Content-Length: 4097\r\nConnection: close\r\n\r\n");
  EXPECT_EQ(declared_oversized.status, 413);
  ExpectRawSecurityHeaders(declared_oversized);

  const auto chunked_oversized = RawHttpsExchange(
      port,
      "POST /api/v1/setup/initialize HTTP/1.1\r\nHost: 127.0.0.1\r\n"
      "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n1001\r\n");
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

}  // namespace
