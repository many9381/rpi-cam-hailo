#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <json/reader.h>
#include <openssl/ssl.h>

#include "camera_firmware/integrity/IntegritySigner.hpp"
#include "camera_firmware/integrity/SafeFileDigest.hpp"
#include "unit/integrity/IntegrityTestSupport.hpp"

namespace {

constexpr std::string_view kTrustedKernel = "trusted kernel fixture\n";

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 56> pattern{"/tmp/cf-system-protection-XXXXXX"};
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

  const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

class ScopedFd {
 public:
  explicit ScopedFd(int fd = -1) noexcept : fd_(fd) {}
  ~ScopedFd() {
    if (fd_ >= 0) {
      (void)::close(fd_);
    }
  }
  ScopedFd(const ScopedFd&) = delete;
  ScopedFd& operator=(const ScopedFd&) = delete;
  int get() const noexcept { return fd_; }
  void Reset(int fd = -1) noexcept {
    if (fd_ >= 0) {
      (void)::close(fd_);
    }
    fd_ = fd;
  }

 private:
  int fd_;
};

// Reserve an ephemeral loopback port and HOLD it open (leaked fd) for the life
// of the process. Closing the reservation before the server binds leaves a
// window where the kernel can reassign the port; the server's later bind() then
// fails and trantor's Socket::bindAddress calls exit(1), killing the process --
// a flaky "Bad server address". Holding the socket bound (SO_REUSEADDR, never
// listened on) reserves the port, and SO_REUSEADDR lets the server bind it too.
// The fd is deliberately not wrapped in ScopedFd: it must outlive this scope.
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
  // Leak the reservation socket so the port stays held until the server binds.
  return ntohs(address.sin_port);
}

struct HttpsResponse {
  int status{-1};
  std::string bytes;

  std::string Header(std::string_view name) const {
    std::string expected(name);
    std::transform(expected.begin(), expected.end(), expected.begin(),
                   [](unsigned char value) {
                     return static_cast<char>(std::tolower(value));
                   });
    expected += ':';
    std::size_t begin = bytes.find("\r\n");
    if (begin == std::string::npos) {
      return {};
    }
    begin += 2U;
    while (begin < bytes.size()) {
      const std::size_t end = bytes.find("\r\n", begin);
      if (end == std::string::npos || end == begin) {
        return {};
      }
      std::string line = bytes.substr(begin, end - begin);
      std::transform(line.begin(), line.end(), line.begin(),
                     [](unsigned char value) {
                       return static_cast<char>(std::tolower(value));
                     });
      if (line.starts_with(expected)) {
        std::size_t value = expected.size();
        while (value < line.size() && bytes[begin + value] == ' ') {
          ++value;
        }
        return bytes.substr(begin + value, end - begin - value);
      }
      begin = end + 2U;
    }
    return {};
  }

  std::optional<Json::Value> JsonBody() const {
    const std::size_t body_begin = bytes.find("\r\n\r\n");
    if (body_begin == std::string::npos) {
      return std::nullopt;
    }
    const std::string_view body(bytes.data() + body_begin + 4U,
                                bytes.size() - body_begin - 4U);
    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    Json::Value json;
    std::string errors;
    const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(body.data(), body.data() + body.size(), &json,
                       &errors)) {
      return std::nullopt;
    }
    return json;
  }
};

HttpsResponse Request(std::uint16_t port,
                      std::string_view method,
                      std::string_view path,
                      std::string_view body = {},
                      std::string_view origin = {},
                      std::string_view cookie = {},
                      bool management_header = false) {
  HttpsResponse response;
  ScopedFd socket_fd(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (socket_fd.get() < 0) {
    return response;
  }
  const timeval timeout{.tv_sec = 10, .tv_usec = 0};
  (void)::setsockopt(socket_fd.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout,
                     sizeof(timeout));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::connect(socket_fd.get(), reinterpret_cast<sockaddr*>(&address),
                sizeof(address)) != 0) {
    return response;
  }

  std::unique_ptr<SSL_CTX, decltype(&::SSL_CTX_free)> context(
      ::SSL_CTX_new(::TLS_client_method()), &::SSL_CTX_free);
  std::unique_ptr<SSL, decltype(&::SSL_free)> ssl(
      context ? ::SSL_new(context.get()) : nullptr, &::SSL_free);
  if (!context || !ssl) {
    return response;
  }
  ::SSL_CTX_set_verify(context.get(), SSL_VERIFY_NONE, nullptr);
  ::SSL_set_fd(ssl.get(), socket_fd.get());
  if (::SSL_connect(ssl.get()) != 1) {
    return response;
  }

  std::string wire = std::string(method) + " " + std::string(path) +
                     " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
  if (!origin.empty()) {
    wire += "Origin: " + std::string(origin) + "\r\n";
  }
  if (!cookie.empty()) {
    wire += "Cookie: " + std::string(cookie) + "\r\n";
  }
  if (management_header) {
    wire += "X-Camera-Request: management\r\n";
  }
  if (!body.empty()) {
    wire += "Content-Type: application/json\r\n";
  }
  wire += "Content-Length: " + std::to_string(body.size()) +
          "\r\nConnection: close\r\n\r\n";
  wire.append(body);

  std::size_t sent = 0U;
  while (sent < wire.size()) {
    const int count = ::SSL_write(ssl.get(), wire.data() + sent,
                                  static_cast<int>(wire.size() - sent));
    if (count <= 0) {
      return response;
    }
    sent += static_cast<std::size_t>(count);
  }
  std::array<char, 4096U> buffer{};
  for (;;) {
    const int count = ::SSL_read(ssl.get(), buffer.data(), buffer.size());
    if (count <= 0) {
      break;
    }
    response.bytes.append(buffer.data(), static_cast<std::size_t>(count));
  }
  (void)::SSL_shutdown(ssl.get());

  const std::size_t first_space = response.bytes.find(' ');
  if (response.bytes.starts_with("HTTP/") &&
      first_space != std::string::npos &&
      first_space + 4U <= response.bytes.size()) {
    response.status = std::stoi(response.bytes.substr(first_space + 1U, 3U));
  }
  return response;
}

class FirmwareProcess {
 public:
  FirmwareProcess(const std::filesystem::path& config_path,
                  std::string_view public_key,
                  bool enable_runtime_start_probe = false) {
    std::array<int, 2U> probe_pipe{-1, -1};
    if (enable_runtime_start_probe &&
        ::pipe2(probe_pipe.data(), O_CLOEXEC) != 0) {
      throw std::system_error(errno, std::generic_category(), "pipe2");
    }
    child_ = ::fork();
    if (child_ < 0) {
      if (enable_runtime_start_probe) {
        (void)::close(probe_pipe[0]);
        (void)::close(probe_pipe[1]);
      }
      throw std::system_error(errno, std::generic_category(), "fork");
    }
    if (child_ == 0) {
      if (enable_runtime_start_probe) {
        (void)::close(probe_pipe[0]);
        const int descriptor_flags = ::fcntl(probe_pipe[1], F_GETFD);
        const std::string descriptor = std::to_string(probe_pipe[1]);
        if (descriptor_flags < 0 ||
            ::fcntl(probe_pipe[1], F_SETFD,
                    descriptor_flags & ~FD_CLOEXEC) != 0 ||
            ::setenv("CF_TEST_PROTECTION_RUNTIME_START_FD",
                     descriptor.c_str(), 1) != 0) {
          _exit(126);
        }
      } else if (::unsetenv("CF_TEST_PROTECTION_RUNTIME_START_FD") != 0) {
        _exit(126);
      }
      if (::setenv("CF_TEST_INTEGRITY_PUBLIC_KEY_PEM",
                   std::string(public_key).c_str(), 1) != 0) {
        _exit(126);
      }
      ::execl(CF_CAMERA_FIRMWARE_BIN, CF_CAMERA_FIRMWARE_BIN,
              config_path.c_str(), nullptr);
      _exit(127);
    }
    if (enable_runtime_start_probe) {
      (void)::close(probe_pipe[1]);
      runtime_start_probe_.Reset(probe_pipe[0]);
    }
  }

  ~FirmwareProcess() { Stop(); }
  FirmwareProcess(const FirmwareProcess&) = delete;
  FirmwareProcess& operator=(const FirmwareProcess&) = delete;

  bool WaitForRuntimeStartProbe(std::chrono::milliseconds timeout) {
    if (runtime_start_observed_) {
      return true;
    }
    if (runtime_start_probe_.get() < 0) {
      throw std::logic_error("runtime start probe is not enabled");
    }
    pollfd descriptor{.fd = runtime_start_probe_.get(),
                      .events = POLLIN,
                      .revents = 0};
    int ready = 0;
    do {
      ready = ::poll(&descriptor, 1, static_cast<int>(timeout.count()));
    } while (ready < 0 && errno == EINTR);
    if (ready < 0) {
      throw std::system_error(errno, std::generic_category(), "poll");
    }
    if (ready == 0) {
      return false;
    }
    char signal = '\0';
    ssize_t count = 0;
    do {
      count = ::read(runtime_start_probe_.get(), &signal, 1U);
    } while (count < 0 && errno == EINTR);
    if (count != 1 || signal != 'R') {
      throw std::runtime_error("invalid runtime start probe signal");
    }
    runtime_start_observed_ = true;
    return true;
  }

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
      if (waited == child_ || (waited < 0 && errno != EINTR)) {
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
  ScopedFd runtime_start_probe_;
  bool runtime_start_observed_{false};
};

void WriteFile(const std::filesystem::path& path, std::string_view contents) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    throw std::runtime_error("unable to open fixture file");
  }
  output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  output.close();
  if (!output) {
    throw std::runtime_error("unable to write fixture file");
  }
}

struct ProcessFixture {
  std::filesystem::path config_path;
  std::filesystem::path state_directory;
  std::filesystem::path kernel_path;
  std::string public_key;
  std::string kernel_digest;
  std::uint16_t port{0U};
  std::uint16_t rtsp_port{0U};
  std::string origin;
};

ProcessFixture WriteProcessFixture(const std::filesystem::path& root) {
  ProcessFixture fixture;
  fixture.config_path = root / "firmware.yaml";
  fixture.state_directory = root / "security";
  fixture.kernel_path = fixture.state_directory / "integrity/kernel.fixture";
  fixture.port = ReserveLoopbackPort();
  fixture.rtsp_port = ReserveLoopbackPort();
  fixture.origin = "https://127.0.0.1:" + std::to_string(fixture.port);
  const auto integrity_directory = fixture.kernel_path.parent_path();
  std::filesystem::create_directories(integrity_directory);
  std::filesystem::permissions(
      fixture.state_directory, std::filesystem::perms::owner_all,
      std::filesystem::perm_options::replace);
  std::filesystem::permissions(
      integrity_directory, std::filesystem::perms::owner_all,
      std::filesystem::perm_options::replace);

  std::ofstream config(fixture.config_path);
  config << "camera:\n"
            "  source:\n"
            "    backend: libcamera\n"
            "    camera_index: 999\n"
            "http:\n"
            "  enabled: true\n"
            "  bind_ip: 127.0.0.1\n"
            "  port: "
         << fixture.port
         << "\n"
            "  web_root: " CF_SOURCE_DIR "/web/dist\n"
            "  public_base_url: "
         << fixture.origin
         << "\n"
            "  tls:\n"
            "    enabled: true\n"
            "    allow_development_self_signed_tls: true\n"
            "security:\n"
            "  enabled: true\n"
            "  state_directory: "
         << fixture.state_directory.string()
         << "\n"
            "self_protection:\n"
            "  manifest_path: "
         << (integrity_directory / "manifest.yaml").string()
         << "\n"
            "  signature_path: "
         << (integrity_directory / "manifest.sig").string()
         << "\n"
            "  interval_hours: 24\n"
            "secure_rtsp:\n"
            "  enabled: true\n"
            "  control_tls: true\n"
            "  media_srtp: false\n"
            "  allow_development_self_signed_tls: true\n"
            "  bind_ip: 127.0.0.1\n"
            "  port: "
         << fixture.rtsp_port
         << "\n"
            "  client_auth:\n"
            "    enabled: true\n"
            "    realm: system-protection-test\n"
            "    credential_file: "
         << (fixture.state_directory / "rtsp.credentials").string()
         << "\n"
            "    algorithms: [sha-256]\n";
  config.close();
  if (!config) {
    throw std::runtime_error("unable to write process config");
  }
  WriteFile(fixture.kernel_path, kTrustedKernel);

  const auto executable = std::filesystem::canonical(CF_CAMERA_FIRMWARE_BIN);
  const auto active_config =
      std::filesystem::absolute(fixture.config_path).lexically_normal();
  const auto digest = [](const std::filesystem::path& path) {
    auto result = camera_firmware::integrity::DigestRegularFile(path);
    if (!result.ok()) {
      throw std::runtime_error("unable to digest fixture");
    }
    return std::move(result).value();
  };
  const auto kernel_digest = digest(fixture.kernel_path);
  fixture.kernel_digest =
      camera_firmware::integrity::HexSha256(kernel_digest);
  camera_firmware::integrity::IntegrityManifest manifest{
      1U,
      "camera-firmware",
      "2026-07-20T00:00:00Z",
      {{"configuration",
        camera_firmware::integrity::IntegrityCategory::kConfiguration,
        active_config, digest(active_config)},
       {"firmware", camera_firmware::integrity::IntegrityCategory::kFirmware,
        executable, digest(executable)},
       {"kernel", camera_firmware::integrity::IntegrityCategory::kKernel,
        fixture.kernel_path, kernel_digest}}};
  auto serialized =
      camera_firmware::integrity::SerializeIntegrityManifest(manifest);
  if (!serialized.ok()) {
    throw std::runtime_error("unable to serialize fixture manifest");
  }
  camera_firmware::integrity::testing::EphemeralEd25519Key key;
  const auto signature = key.Sign(serialized.value());
  const auto bytes = std::span<const unsigned char>(
      reinterpret_cast<const unsigned char*>(serialized.value().data()),
      serialized.value().size());
  if (!camera_firmware::integrity::WriteIntegrityArtifactAtomically(
           integrity_directory / "manifest.yaml", bytes)
           .ok() ||
      !camera_firmware::integrity::WriteIntegrityArtifactAtomically(
           integrity_directory / "manifest.sig", signature)
           .ok()) {
    throw std::runtime_error("unable to write signed fixture manifest");
  }
  fixture.public_key = key.PublicPem();
  return fixture;
}

bool WaitForService(const ProcessFixture& fixture) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (std::chrono::steady_clock::now() < deadline) {
    if (Request(fixture.port, "GET", "/api/v1/setup/status").status == 200) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return false;
}

std::optional<std::string> Login(const ProcessFixture& fixture,
                                 std::string_view username,
                                 std::string_view password,
                                 HttpsResponse* observed = nullptr) {
  const auto response = Request(
      fixture.port, "POST", "/api/v1/auth/login",
      "{\"username\":\"" + std::string(username) +
          "\",\"password\":\"" + std::string(password) + "\"}",
      fixture.origin, {}, true);
  if (observed != nullptr) {
    *observed = response;
  }
  if (response.status != 200) {
    return std::nullopt;
  }
  const std::string set_cookie = response.Header("Set-Cookie");
  if (!set_cookie.starts_with("camera_session=")) {
    return std::nullopt;
  }
  return set_cookie.substr(0U, set_cookie.find(';'));
}

// Signs in with the per-device account the firmware mints at first boot.
// POST /api/v1/setup/initialize requires that session, so the setup call below
// has to obtain one first. The generated password is drawn from the printable
// ASCII range and can contain a quote or a backslash, so the request body is
// escaped rather than concatenated the way Login() above can afford to be.
std::optional<std::string> InitialAccountCookie(
    const ProcessFixture& fixture) {
  const auto status = Request(fixture.port, "GET", "/api/v1/setup/status");
  if (status.status != 200) {
    return std::nullopt;
  }
  const auto json = status.JsonBody();
  if (!json.has_value() || !json->isMember("initial_username") ||
      !json->isMember("initial_password")) {
    return std::nullopt;
  }
  const auto quoted = [](std::string_view value) {
    std::string escaped = "\"";
    for (const char character : value) {
      if (character == '"' || character == '\\') {
        escaped.push_back('\\');
      }
      escaped.push_back(character);
    }
    escaped.push_back('"');
    return escaped;
  };
  const auto response = Request(
      fixture.port, "POST", "/api/v1/auth/login",
      "{\"username\":" + quoted((*json)["initial_username"].asString()) +
          ",\"password\":" + quoted((*json)["initial_password"].asString()) +
          "}",
      fixture.origin, {}, true);
  if (response.status != 200) {
    return std::nullopt;
  }
  const std::string set_cookie = response.Header("Set-Cookie");
  if (!set_cookie.starts_with("camera_session=")) {
    return std::nullopt;
  }
  return set_cookie.substr(0U, set_cookie.find(';'));
}

void ExpectExactKeys(const Json::Value& json,
                     std::initializer_list<std::string_view> keys) {
  ASSERT_TRUE(json.isObject());
  auto actual = json.getMemberNames();
  std::sort(actual.begin(), actual.end());
  std::vector<std::string> expected;
  expected.reserve(keys.size());
  for (const auto key : keys) {
    expected.emplace_back(key);
  }
  std::sort(expected.begin(), expected.end());
  EXPECT_EQ(actual, expected);
}

bool IsProtectionAuditEvent(std::string_view event_type) noexcept {
  return event_type == "self_test.started" ||
         event_type == "self_test.succeeded" ||
         event_type == "self_test.failed" ||
         event_type == "integrity_check.started" ||
         event_type == "integrity_check.succeeded" ||
         event_type == "integrity_check.failed" ||
         event_type == "protection.restricted" ||
         event_type == "protection.recovered";
}

TEST(SystemProtectionIntegrationTest,
     RealProcessRestrictsGuardsAndRecoversAfterManualIntegrityCheck) {
  TemporaryDirectory directory;
  auto fixture = WriteProcessFixture(directory.path());
  std::int64_t restricted_startup_boundary = 0;

  {
    FirmwareProcess process(fixture.config_path, fixture.public_key);
    ASSERT_TRUE(WaitForService(fixture));
    const auto setup_cookie = InitialAccountCookie(fixture);
    ASSERT_TRUE(setup_cookie.has_value());
    const auto setup = Request(
        fixture.port, "POST", "/api/v1/setup/initialize",
        R"({"username":"owner1","password":"StrongPass9!","peer_ip":"127.0.0.1"})",
        fixture.origin, *setup_cookie, true);
    ASSERT_EQ(setup.status, 503) << setup.bytes;
  }

  {
    FirmwareProcess process(fixture.config_path, fixture.public_key);
    ASSERT_TRUE(WaitForService(fixture));
    const auto administrator = Login(fixture, "owner1", "StrongPass9!");
    ASSERT_TRUE(administrator.has_value());
    const auto startup = Request(fixture.port, "GET",
                                 "/api/v1/system/protection", {}, {},
                                 *administrator);
    ASSERT_EQ(startup.status, 200) << startup.bytes;
    const auto json = startup.JsonBody();
    ASSERT_TRUE(json.has_value());
    EXPECT_EQ((*json)["state"].asString(), "operational");
    EXPECT_TRUE((*json)["self_test"]["passed"].asBool());
    EXPECT_TRUE((*json)["integrity"]["passed"].asBool());
    EXPECT_EQ((*json)["self_test"]["trigger"].asString(), "startup");
    EXPECT_EQ((*json)["integrity"]["trigger"].asString(), "startup");
    const auto baseline_audit = Request(
        fixture.port, "GET",
        "/api/v1/audit/events?sort_by=timestamp&sort_direction=asc&limit=100",
        {}, {}, *administrator);
    ASSERT_EQ(baseline_audit.status, 200) << baseline_audit.bytes;
    const auto baseline_events = baseline_audit.JsonBody();
    ASSERT_TRUE(baseline_events.has_value());
    ASSERT_TRUE((*baseline_events)["next_cursor"].isNull());
    for (const auto& event : (*baseline_events)["events"]) {
      ASSERT_TRUE(event["sequence"].isInt64() ||
                  event["sequence"].isUInt64());
      restricted_startup_boundary = std::max(
          restricted_startup_boundary, event["sequence"].asInt64());
    }
    const auto logout = Request(fixture.port, "POST", "/api/v1/auth/logout",
                                {}, fixture.origin, *administrator, true);
    ASSERT_EQ(logout.status, 200) << logout.bytes;
  }

  WriteFile(fixture.kernel_path, "tampered kernel fixture\n");
  FirmwareProcess process(fixture.config_path, fixture.public_key, true);
  ASSERT_TRUE(WaitForService(fixture));
  EXPECT_FALSE(process.WaitForRuntimeStartProbe(std::chrono::milliseconds(0)));
  HttpsResponse restricted_login;
  const auto administrator =
      Login(fixture, "owner1", "StrongPass9!", &restricted_login);
  ASSERT_TRUE(administrator.has_value()) << restricted_login.status << '\n'
                                         << restricted_login.bytes;

  EXPECT_EQ(Request(fixture.port, "GET", "/api/v1/system/protection").status,
            401);
  const auto created_viewer = Request(
      fixture.port, "POST", "/api/v1/security/users",
      R"({"username":"viewer1","password":"ViewerPass9!"})",
      fixture.origin, *administrator, true);
  ASSERT_EQ(created_viewer.status, 201) << created_viewer.bytes;
  const auto viewer_ip = Request(
      fixture.port, "POST", "/api/v1/security/management-ips/viewer",
      R"({"address":"127.0.0.1"})", fixture.origin, *administrator, true);
  ASSERT_EQ(viewer_ip.status, 201) << viewer_ip.bytes;
  const auto viewer = Login(fixture, "viewer1", "ViewerPass9!");
  ASSERT_TRUE(viewer.has_value());
  EXPECT_EQ(Request(fixture.port, "GET", "/api/v1/system/protection", {},
                    {}, *viewer)
                .status,
            403);

  const auto restricted = Request(fixture.port, "GET",
                                  "/api/v1/system/protection", {}, {},
                                  *administrator);
  ASSERT_EQ(restricted.status, 200) << restricted.bytes;
  const auto restricted_json = restricted.JsonBody();
  ASSERT_TRUE(restricted_json.has_value());
  ExpectExactKeys(*restricted_json,
                  {"state", "check_running", "next_periodic_at_seconds",
                   "self_test", "integrity"});
  EXPECT_EQ((*restricted_json)["state"].asString(), "restricted");
  EXPECT_TRUE((*restricted_json)["self_test"]["passed"].asBool());
  EXPECT_FALSE((*restricted_json)["integrity"]["passed"].asBool());
  ASSERT_EQ((*restricted_json)["integrity"]["items"].size(), 3U);
  const auto& failed = (*restricted_json)["integrity"]["items"][2U];
  EXPECT_EQ(failed["id"].asString(), "kernel");
  EXPECT_EQ(failed["category"].asString(), "kernel");
  EXPECT_FALSE(failed["passed"].asBool());
  EXPECT_EQ(failed["code"].asString(), "E_INTEGRITY_DIGEST_MISMATCH");
  const std::string restricted_body = restricted.bytes;
  EXPECT_EQ(restricted_body.find(fixture.kernel_path.string()),
            std::string::npos);
  EXPECT_EQ(restricted_body.find(fixture.kernel_digest), std::string::npos);
  EXPECT_EQ(restricted_body.find("tampered kernel fixture"),
            std::string::npos);

  for (const auto& [path, body] :
       std::array<std::pair<std::string_view, std::string_view>, 3U>{
           {{"/api/v1/runtime/restart", "{}"},
            {"/api/v1/ai/restart", "{}"},
            {"/api/v1/settings/runtime/apply",
             R"({"expected_revision":0})"}}}) {
    const auto guarded = Request(fixture.port, "POST", path, body,
                                 fixture.origin, *administrator, true);
    ASSERT_EQ(guarded.status, 423) << path << '\n' << guarded.bytes;
    const auto error = guarded.JsonBody();
    ASSERT_TRUE(error.has_value());
    EXPECT_EQ((*error)["code"].asString(), "E_PROTECTION_RESTRICTED");
  }

  const auto startup_audit = Request(
      fixture.port, "GET",
      "/api/v1/audit/events?sort_by=timestamp&sort_direction=asc&limit=100",
      {}, {}, *administrator);
  ASSERT_EQ(startup_audit.status, 200) << startup_audit.bytes;
  const auto startup_events = startup_audit.JsonBody();
  ASSERT_TRUE(startup_events.has_value());
  ASSERT_TRUE((*startup_events)["next_cursor"].isNull());
  std::vector<const Json::Value*> startup_protection_events;
  for (const auto& event : (*startup_events)["events"]) {
    if (event["sequence"].asInt64() <= restricted_startup_boundary) {
      continue;
    }
    const std::string event_type = event["event_type"].asString();
    if (IsProtectionAuditEvent(event_type)) {
      startup_protection_events.push_back(&event);
    }
  }
  ASSERT_EQ(startup_protection_events.size(), 5U) << startup_audit.bytes;
  const std::array<std::string_view, 5U> expected_startup_events{
      "self_test.started", "self_test.succeeded",
      "integrity_check.started", "integrity_check.failed",
      "protection.restricted"};
  for (std::size_t index = 0; index < expected_startup_events.size(); ++index) {
    const auto& event = *startup_protection_events[index];
    ASSERT_EQ(event["event_type"].asString(), expected_startup_events[index]);
    ASSERT_EQ(event["actor_identity"].asString(), "system");
    EXPECT_EQ(event["subject_type"].asString(), "startup");
    const std::string subject_identity =
        event["subject_identity"].asString();
    EXPECT_TRUE(subject_identity.starts_with("d_ms="));
    if (event["event_type"].asString() == "integrity_check.failed" ||
        event["event_type"].asString() == "protection.restricted") {
      EXPECT_NE(subject_identity.find(";n=1;ids=kernel"),
                std::string::npos);
    } else {
      EXPECT_NE(subject_identity.find(";n=0;ids=-"), std::string::npos);
    }
    if (index > 0U) {
      EXPECT_LT((*startup_protection_events[index - 1U])["sequence"].asInt64(),
                event["sequence"].asInt64());
    }
  }

  WriteFile(fixture.kernel_path, kTrustedKernel);
  const auto manual_boundary_audit = Request(
      fixture.port, "GET",
      "/api/v1/audit/events?sort_by=timestamp&sort_direction=asc&limit=100",
      {}, {}, *administrator);
  ASSERT_EQ(manual_boundary_audit.status, 200)
      << manual_boundary_audit.bytes;
  const auto manual_boundary_events = manual_boundary_audit.JsonBody();
  ASSERT_TRUE(manual_boundary_events.has_value());
  ASSERT_TRUE((*manual_boundary_events)["next_cursor"].isNull());
  std::int64_t manual_boundary_sequence = 0;
  for (const auto& event : (*manual_boundary_events)["events"]) {
    ASSERT_TRUE(event["sequence"].isInt64() || event["sequence"].isUInt64());
    manual_boundary_sequence =
        std::max(manual_boundary_sequence, event["sequence"].asInt64());
  }

  const auto accepted = Request(fixture.port, "POST",
                                "/api/v1/system/integrity-checks", "{}",
                                fixture.origin, *administrator, true);
  ASSERT_EQ(accepted.status, 202) << accepted.bytes;
  const auto accepted_json = accepted.JsonBody();
  ASSERT_TRUE(accepted_json.has_value());
  EXPECT_EQ((*accepted_json)["state"].asString(), "checking");
  EXPECT_TRUE((*accepted_json)["check_running"].asBool());
  ASSERT_TRUE(
      process.WaitForRuntimeStartProbe(std::chrono::seconds(10)));

  std::optional<HttpsResponse> recovered;
  const auto recovery_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (std::chrono::steady_clock::now() < recovery_deadline) {
    auto status = Request(fixture.port, "GET",
                          "/api/v1/system/protection", {}, {},
                          *administrator);
    const auto json = status.JsonBody();
    if (status.status == 200 && json.has_value() &&
        !(*json)["check_running"].asBool()) {
      recovered = std::move(status);
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  ASSERT_TRUE(recovered.has_value());
  const auto recovered_json = recovered->JsonBody();
  ASSERT_TRUE(recovered_json.has_value());
  EXPECT_EQ((*recovered_json)["state"].asString(), "operational");
  EXPECT_TRUE((*recovered_json)["integrity"]["passed"].asBool());
  EXPECT_EQ((*recovered_json)["integrity"]["trigger"].asString(), "manual");

  const auto recovery_audit = Request(
      fixture.port, "GET",
      "/api/v1/audit/events?sort_by=timestamp&sort_direction=asc&limit=100",
      {}, {}, *administrator);
  ASSERT_EQ(recovery_audit.status, 200) << recovery_audit.bytes;
  const auto recovery_events = recovery_audit.JsonBody();
  ASSERT_TRUE(recovery_events.has_value());
  ASSERT_TRUE((*recovery_events)["next_cursor"].isNull());
  std::vector<const Json::Value*> manual_protection_events;
  for (const auto& event : (*recovery_events)["events"]) {
    if (event["sequence"].asInt64() <= manual_boundary_sequence) {
      continue;
    }
    const std::string event_type = event["event_type"].asString();
    if (IsProtectionAuditEvent(event_type)) {
      manual_protection_events.push_back(&event);
    }
  }
  ASSERT_EQ(manual_protection_events.size(), 3U) << recovery_audit.bytes;
  const std::array<std::string_view, 3U> expected_manual_events{
      "integrity_check.started", "integrity_check.succeeded",
      "protection.recovered"};
  for (std::size_t index = 0; index < expected_manual_events.size(); ++index) {
    const auto& event = *manual_protection_events[index];
    ASSERT_EQ(event["event_type"].asString(), expected_manual_events[index]);
    ASSERT_EQ(event["actor_identity"].asString(), "owner1");
    EXPECT_EQ(event["subject_type"].asString(), "manual");
    const std::string subject_identity =
        event["subject_identity"].asString();
    EXPECT_TRUE(subject_identity.starts_with("d_ms="));
    EXPECT_NE(subject_identity.find(";n=0;ids=-"), std::string::npos);
    if (index == 0U) {
      ASSERT_EQ(event["detail_code"].asString(), "OK");
    }
    if (index > 0U) {
      EXPECT_LT((*manual_protection_events[index - 1U])["sequence"].asInt64(),
                event["sequence"].asInt64());
    }
  }
}

}  // namespace
