#include "camera_firmware/service/ServiceApp.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <future>
#include <memory>
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
            "base-uri 'none'; "
            "frame-ancestors 'none'");
}

struct RawHttpsResponse {
  int status{-1};
  std::string bytes;

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

RawHttpsResponse RawHttpsExchange(std::uint16_t port,
                                  std::string_view request) {
  const int socket_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (socket_fd < 0) {
    return {};
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::connect(socket_fd, reinterpret_cast<sockaddr*>(&address),
                sizeof(address)) != 0) {
    (void)::close(socket_fd);
    return {};
  }

  SSL_CTX* context = ::SSL_CTX_new(::TLS_client_method());
  SSL* ssl = context == nullptr ? nullptr : ::SSL_new(context);
  if (ssl == nullptr) {
    if (context != nullptr) {
      ::SSL_CTX_free(context);
    }
    (void)::close(socket_fd);
    return {};
  }
  ::SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nullptr);
  ::SSL_set_fd(ssl, socket_fd);
  if (::SSL_connect(ssl) != 1) {
    ::SSL_free(ssl);
    ::SSL_CTX_free(context);
    (void)::close(socket_fd);
    return {};
  }

  std::size_t written = 0U;
  while (written < request.size()) {
    const int count = ::SSL_write(
        ssl, request.data() + written,
        static_cast<int>(request.size() - written));
    if (count <= 0) {
      break;
    }
    written += static_cast<std::size_t>(count);
  }

  RawHttpsResponse response;
  std::array<char, 2048> buffer{};
  for (;;) {
    const int count =
        ::SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()));
    if (count <= 0) {
      break;
    }
    response.bytes.append(buffer.data(), static_cast<std::size_t>(count));
  }
  (void)::SSL_shutdown(ssl);
  ::SSL_free(ssl);
  ::SSL_CTX_free(context);
  (void)::close(socket_fd);

  const std::size_t first_space = response.bytes.find(' ');
  if (!response.bytes.starts_with("HTTP/") ||
      first_space == std::string::npos ||
      first_space + 4U > response.bytes.size()) {
    return response;
  }
  try {
    response.status =
        std::stoi(response.bytes.substr(first_space + 1U, 3U));
  } catch (...) {
    response.status = -1;
  }
  return response;
}

RawHttpsResponse RawHttpsGet(
    std::uint16_t port,
    std::string_view path,
    const std::vector<std::string>& cookie_fields) {
  std::string request = "GET " + std::string(path) +
                        " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
  for (const auto& field : cookie_fields) {
    request += "Cookie: " + field + "\r\n";
  }
  request += "Connection: close\r\n\r\n";
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
            "base-uri 'none'; "
            "frame-ancestors 'none'");
}

TEST(HttpsAuthIntegrationTest, ProductionDefaultsWireSecurityServices) {
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    TemporaryDirectory directory;
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
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    TemporaryDirectory directory;
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
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(20U);
    TemporaryDirectory directory;
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
