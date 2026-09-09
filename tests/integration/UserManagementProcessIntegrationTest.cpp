#include "camera_firmware/security/PasswordHasher.hpp"

#include <algorithm>
#include <array>
#include <barrier>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <json/reader.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <sqlite3.h>

#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/security/SecurityStore.hpp"

namespace {

using namespace std::chrono_literals;

constexpr std::string_view kAdministratorUsername = "operator.one";
constexpr std::string_view kAdministratorPassword = "Revision2Pass9!";

class TemporaryDirectory final {
 public:
  TemporaryDirectory() {
    std::array<char, 64> pattern{"/tmp/cf-user-process-XXXXXX"};
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

  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept {
    return path_;
  }

 private:
  std::filesystem::path path_;
};

class SqliteDatabase final {
 public:
  SqliteDatabase(const std::filesystem::path& path, int flags) {
    sqlite3* opened = nullptr;
    const int result = ::sqlite3_open_v2(path.c_str(), &opened, flags, nullptr);
    database_.reset(opened);
    if (result != SQLITE_OK || database_ == nullptr) {
      throw std::runtime_error("unable to open process integration database");
    }
  }

  SqliteDatabase(const SqliteDatabase&) = delete;
  SqliteDatabase& operator=(const SqliteDatabase&) = delete;

  [[nodiscard]] sqlite3* get() const noexcept { return database_.get(); }

  void Execute(const char* sql) {
    char* error_message = nullptr;
    const int result =
        ::sqlite3_exec(database_.get(), sql, nullptr, nullptr, &error_message);
    if (error_message != nullptr) {
      ::sqlite3_free(error_message);
    }
    if (result != SQLITE_OK) {
      throw std::runtime_error(
          "unable to prepare process integration database");
    }
  }

 private:
  struct Closer {
    void operator()(sqlite3* database) const noexcept {
      if (database != nullptr) {
        (void)::sqlite3_close_v2(database);
      }
    }
  };

  std::unique_ptr<sqlite3, Closer> database_;
};

camera_firmware::common::SecureBytes SecureBytes(std::string_view value) {
  camera_firmware::common::SecureBytes bytes;
  bytes.assign(reinterpret_cast<const unsigned char*>(value.data()),
               value.size());
  return bytes;
}

constexpr const char* kRevisionTwoOperationalSchema = R"sql(
CREATE TABLE schema_version (
  version INTEGER NOT NULL CHECK (version = 2)
);
INSERT INTO schema_version (version) VALUES (2);
CREATE TABLE device_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL CHECK (state IN ('default', 'operational')),
  schema_revision INTEGER NOT NULL CHECK (schema_revision = 2),
  setup_completed_at_seconds INTEGER,
  CHECK (
    (state = 'default' AND setup_completed_at_seconds IS NULL) OR
    (state = 'operational' AND setup_completed_at_seconds IS NOT NULL AND
     setup_completed_at_seconds >= 0)
  )
);
INSERT INTO device_state
  (id, state, schema_revision, setup_completed_at_seconds)
VALUES (1, 'operational', 2, 1720000000);
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  canonical_username TEXT NOT NULL
    CHECK (length(canonical_username) BETWEEN 5 AND 32)
    CHECK (canonical_username = lower(canonical_username)),
  display_username TEXT NOT NULL
    CHECK (length(display_username) BETWEEN 5 AND 32),
  role TEXT NOT NULL CHECK (role IN ('administrator', 'viewer')),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  password_algorithm TEXT NOT NULL
    CHECK (password_algorithm = 'pbkdf2-hmac-sha256'),
  password_iterations INTEGER NOT NULL
    CHECK (password_iterations BETWEEN 1000 AND 2000000),
  password_salt BLOB NOT NULL CHECK (length(password_salt) = 16),
  password_derived BLOB NOT NULL CHECK (length(password_derived) = 32),
  password_changed_at_seconds INTEGER NOT NULL
    CHECK (password_changed_at_seconds >= 0),
  failed_login_count INTEGER NOT NULL DEFAULT 0
    CHECK (failed_login_count BETWEEN 0 AND 5),
  lock_until_seconds INTEGER CHECK (lock_until_seconds >= 0),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0),
  last_login_at_seconds INTEGER CHECK (last_login_at_seconds >= 0)
);
CREATE UNIQUE INDEX users_canonical_username_unique
  ON users(canonical_username COLLATE NOCASE);
CREATE UNIQUE INDEX users_single_administrator_unique
  ON users(role) WHERE role = 'administrator';
CREATE TABLE management_ips (
  id INTEGER PRIMARY KEY,
  normalized_ip TEXT NOT NULL CHECK (length(normalized_ip) BETWEEN 2 AND 45),
  role_scope TEXT NOT NULL CHECK (role_scope IN ('administrator')),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0)
);
CREATE UNIQUE INDEX management_ips_normalized_ip_unique
  ON management_ips(normalized_ip);
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,
  token_hash BLOB NOT NULL CHECK (length(token_hash) = 32),
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('administrator', 'viewer')),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0),
  last_activity_at_seconds INTEGER NOT NULL
    CHECK (last_activity_at_seconds >= created_at_seconds),
  expires_at_seconds INTEGER NOT NULL
    CHECK (expires_at_seconds >= last_activity_at_seconds),
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45)
);
CREATE UNIQUE INDEX sessions_token_hash_unique ON sessions(token_hash);
CREATE UNIQUE INDEX sessions_single_administrator_unique
  ON sessions(role) WHERE role = 'administrator';
CREATE INDEX sessions_expiry_index ON sessions(expires_at_seconds);
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY,
  server_timestamp_seconds INTEGER NOT NULL
    CHECK (server_timestamp_seconds >= 0),
  event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45),
  detail_code TEXT NOT NULL CHECK (length(detail_code) <= 64)
);
CREATE INDEX audit_events_timestamp_index
  ON audit_events(server_timestamp_seconds);
CREATE TABLE firmware_log_outbox (
  id INTEGER PRIMARY KEY,
  category TEXT NOT NULL CHECK (length(category) BETWEEN 1 AND 64),
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0),
  dirty INTEGER NOT NULL DEFAULT 0 CHECK (dirty IN (0, 1)),
  lease_owner BLOB,
  lease_token BLOB,
  lease_expires_at_seconds INTEGER,
  CHECK (
    (lease_owner IS NULL AND lease_token IS NULL AND
     lease_expires_at_seconds IS NULL) OR
    (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND
     lease_expires_at_seconds IS NOT NULL AND
     length(lease_owner) = 16 AND length(lease_token) = 32 AND
     lease_expires_at_seconds >= 0)
  )
);
CREATE UNIQUE INDEX firmware_log_outbox_category_peer_unique
  ON firmware_log_outbox(category, peer_ip);
CREATE INDEX firmware_log_outbox_lease_expiry_index
  ON firmware_log_outbox(lease_expires_at_seconds);
INSERT INTO users
  (id, canonical_username, display_username, role, enabled,
   password_algorithm, password_iterations, password_salt, password_derived,
   password_changed_at_seconds, failed_login_count, created_at_seconds,
   last_login_at_seconds)
VALUES
  (11, 'operator.one', 'Operator.One', 'administrator', 1,
   'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), 1720000000, 0,
   1720000000, NULL);
INSERT INTO management_ips
  (id, normalized_ip, role_scope, enabled, created_at_seconds)
VALUES (21, '127.0.0.1', 'administrator', 1, 1720000000);
INSERT INTO audit_events
  (sequence, server_timestamp_seconds, event_type, outcome, actor_user_id,
   peer_ip, detail_code)
VALUES
  (41, 1720000000, 'bootstrap_completed', 'success', 11,
   '127.0.0.1', 'initial_administrator');
)sql";

void BindAdministratorPassword(sqlite3* database) {
  auto derived = camera_firmware::security::DerivePassword(
      SecureBytes(kAdministratorPassword));
  if (!derived.ok()) {
    throw std::runtime_error("unable to derive fixture password");
  }
  auto record = std::move(derived).value();

  sqlite3_stmt* raw_statement = nullptr;
  constexpr const char* kUpdate =
      "UPDATE users SET password_algorithm = ?1, password_iterations = ?2, "
      "password_salt = ?3, password_derived = ?4 WHERE id = 11;";
  if (::sqlite3_prepare_v2(database, kUpdate, -1, &raw_statement, nullptr) !=
      SQLITE_OK) {
    throw std::runtime_error("unable to prepare fixture password update");
  }
  const auto finalize = [](sqlite3_stmt* statement) noexcept {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
  };
  std::unique_ptr<sqlite3_stmt, decltype(finalize)> statement(raw_statement,
                                                              finalize);
  if (::sqlite3_bind_text(statement.get(), 1, record.algorithm.c_str(), -1,
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_int(statement.get(), 2,
                         static_cast<int>(record.iterations)) != SQLITE_OK ||
      ::sqlite3_bind_blob(statement.get(), 3, record.salt.data(),
                          static_cast<int>(record.salt.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_blob(statement.get(), 4, record.derived.data(),
                          static_cast<int>(record.derived.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_step(statement.get()) != SQLITE_DONE) {
    throw std::runtime_error("unable to write fixture password");
  }
  if (::sqlite3_changes(database) != 1) {
    throw std::runtime_error("fixture administrator password was not unique");
  }
}

void CreateRevisionTwoFixture(const std::filesystem::path& state_directory) {
  if (::mkdir(state_directory.c_str(), 0700) != 0) {
    throw std::system_error(errno, std::generic_category(), "mkdir");
  }
  const auto database_path = state_directory / "security.db";
  SqliteDatabase database(database_path, SQLITE_OPEN_READWRITE |
                                             SQLITE_OPEN_CREATE |
                                             SQLITE_OPEN_NOFOLLOW);
  database.Execute("PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;");
  database.Execute("BEGIN IMMEDIATE;");
  try {
    database.Execute(kRevisionTwoOperationalSchema);
    BindAdministratorPassword(database.get());
    database.Execute("COMMIT;");
  } catch (...) {
    try {
      database.Execute("ROLLBACK;");
    } catch (...) {
    }
    throw;
  }
  if (::chmod(database_path.c_str(), 0600) != 0) {
    throw std::system_error(errno, std::generic_category(), "chmod");
  }
}

int QueryInt(const std::filesystem::path& path, std::string_view sql) {
  SqliteDatabase database(path, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW);
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(database.get(), sql.data(),
                           static_cast<int>(sql.size()), &statement,
                           nullptr) != SQLITE_OK) {
    throw std::runtime_error("unable to prepare process integration query");
  }
  const int step = ::sqlite3_step(statement);
  if (step != SQLITE_ROW) {
    (void)::sqlite3_finalize(statement);
    throw std::runtime_error("process integration query did not return a row");
  }
  const int value = ::sqlite3_column_int(statement, 0);
  if (::sqlite3_finalize(statement) != SQLITE_OK) {
    throw std::runtime_error("unable to finalize process integration query");
  }
  return value;
}

std::string QueryText(const std::filesystem::path& path, const char* sql) {
  SqliteDatabase database(path, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW);
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(database.get(), sql, -1, &statement, nullptr) !=
      SQLITE_OK) {
    throw std::runtime_error("unable to prepare process integration query");
  }
  if (::sqlite3_step(statement) != SQLITE_ROW) {
    (void)::sqlite3_finalize(statement);
    throw std::runtime_error("process integration query did not return a row");
  }
  const unsigned char* text = ::sqlite3_column_text(statement, 0);
  const std::string value =
      text == nullptr ? std::string{} : reinterpret_cast<const char*>(text);
  if (::sqlite3_finalize(statement) != SQLITE_OK) {
    throw std::runtime_error("unable to finalize process integration query");
  }
  return value;
}

// Reserve an ephemeral loopback port and HOLD it open (leaked fd) for the life
// of the process. Closing the reservation before the server binds leaves a
// window where the kernel can reassign the port; the server's later bind() then
// fails and trantor's Socket::bindAddress calls exit(1), killing the process --
// a flaky "Bad server address". Holding the socket bound (SO_REUSEADDR, never
// listened on) reserves the port, and SO_REUSEADDR lets the server bind it too.
std::uint16_t ReserveLoopbackPort() {
  const int descriptor = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) {
    throw std::system_error(errno, std::generic_category(), "socket");
  }
  const int reuse = 1;
  if (::setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse,
                   sizeof(reuse)) != 0) {
    const int error = errno;
    (void)::close(descriptor);
    throw std::system_error(error, std::generic_category(), "setsockopt");
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (::bind(descriptor, reinterpret_cast<const sockaddr*>(&address),
             sizeof(address)) != 0) {
    const int error = errno;
    (void)::close(descriptor);
    throw std::system_error(error, std::generic_category(), "bind");
  }
  socklen_t size = sizeof(address);
  if (::getsockname(descriptor, reinterpret_cast<sockaddr*>(&address), &size) !=
      0) {
    const int error = errno;
    (void)::close(descriptor);
    throw std::system_error(error, std::generic_category(), "getsockname");
  }
  // Leak the reservation socket so the port stays held until the server binds.
  return ntohs(address.sin_port);
}

std::uint16_t ReserveDistinctLoopbackPort(std::uint16_t excluded) {
  for (std::size_t attempt = 0U; attempt < 16U; ++attempt) {
    const std::uint16_t port = ReserveLoopbackPort();
    if (port != excluded) {
      return port;
    }
  }
  throw std::runtime_error("unable to reserve distinct loopback ports");
}

struct HttpsResponse {
  HttpsResponse() = default;
  ~HttpsResponse() { ::OPENSSL_cleanse(bytes.data(), bytes.size()); }

  HttpsResponse(const HttpsResponse&) = delete;
  HttpsResponse& operator=(const HttpsResponse&) = delete;
  HttpsResponse(HttpsResponse&&) noexcept = default;
  HttpsResponse& operator=(HttpsResponse&&) noexcept = default;

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
    while (line_begin < bytes.size()) {
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
        while (value_begin < line.size() && line[value_begin] == ' ') {
          ++value_begin;
        }
        return bytes.substr(line_begin + value_begin,
                            line.size() - value_begin);
      }
      line_begin = line_end + 2U;
    }
    return {};
  }
};

class SocketHandle final {
 public:
  explicit SocketHandle(int descriptor) noexcept : descriptor_(descriptor) {}
  ~SocketHandle() {
    if (descriptor_ >= 0) {
      (void)::close(descriptor_);
    }
  }

  SocketHandle(const SocketHandle&) = delete;
  SocketHandle& operator=(const SocketHandle&) = delete;

  [[nodiscard]] int get() const noexcept { return descriptor_; }

 private:
  int descriptor_{-1};
};

class HttpsConnection final {
 public:
  explicit HttpsConnection(std::uint16_t port,
                           std::chrono::milliseconds timeout = 2s)
      : socket_(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)),
        context_(::SSL_CTX_new(::TLS_client_method()), &::SSL_CTX_free),
        ssl_(nullptr, &::SSL_free) {
    if (socket_.get() < 0 || !context_) {
      return;
    }
    const auto timeout_value = timeval{
        .tv_sec = static_cast<time_t>(timeout.count() / 1000),
        .tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000)};
    if (::setsockopt(socket_.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout_value,
                     sizeof(timeout_value)) != 0) {
      return;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (::connect(socket_.get(), reinterpret_cast<const sockaddr*>(&address),
                  sizeof(address)) != 0) {
      return;
    }
    ::SSL_CTX_set_verify(context_.get(), SSL_VERIFY_NONE, nullptr);
    ssl_.reset(::SSL_new(context_.get()));
    if (!ssl_ || ::SSL_set_fd(ssl_.get(), socket_.get()) != 1 ||
        ::SSL_connect(ssl_.get()) != 1) {
      return;
    }
    connected_ = true;
  }

  HttpsConnection(const HttpsConnection&) = delete;
  HttpsConnection& operator=(const HttpsConnection&) = delete;

  [[nodiscard]] bool connected() const noexcept { return connected_; }

  HttpsResponse Exchange(std::string_view request) {
    HttpsResponse response;
    if (!connected_) {
      return response;
    }
    std::size_t written = 0U;
    while (written < request.size()) {
      const auto remaining = std::min<std::size_t>(
          request.size() - written, static_cast<std::size_t>(INT_MAX));
      const int count = ::SSL_write(ssl_.get(), request.data() + written,
                                    static_cast<int>(remaining));
      if (count <= 0) {
        connected_ = false;
        return response;
      }
      written += static_cast<std::size_t>(count);
    }

    std::array<char, 2048> buffer{};
    for (;;) {
      const int count = ::SSL_read(ssl_.get(), buffer.data(),
                                   static_cast<int>(buffer.size()));
      if (count <= 0) {
        break;
      }
      response.bytes.append(buffer.data(), static_cast<std::size_t>(count));
      if (response.bytes.size() > 1024U * 1024U) {
        break;
      }
    }
    connected_ = false;
    const std::size_t first_space = response.bytes.find(' ');
    if (response.bytes.starts_with("HTTP/") &&
        first_space != std::string::npos &&
        first_space + 4U <= response.bytes.size()) {
      try {
        response.status =
            std::stoi(response.bytes.substr(first_space + 1U, 3U));
      } catch (...) {
        response.status = -1;
      }
    }
    return response;
  }

 private:
  SocketHandle socket_;
  std::unique_ptr<SSL_CTX, decltype(&::SSL_CTX_free)> context_;
  std::unique_ptr<SSL, decltype(&::SSL_free)> ssl_;
  bool connected_{false};
};

std::string BuildHttpsRequest(std::string_view method, std::string_view path,
                              std::string_view body = {},
                              std::string_view origin = {},
                              std::string_view cookie = {},
                              bool management_request = false) {
  std::string request = std::string(method) + " " + std::string(path) +
                        " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
  if (!origin.empty()) {
    request += "Origin: " + std::string(origin) + "\r\n";
  }
  if (!cookie.empty()) {
    request += "Cookie: " + std::string(cookie) + "\r\n";
  }
  if (management_request) {
    request += "X-Camera-Request: management\r\n";
  }
  if (!body.empty()) {
    request += "Content-Type: application/json\r\n";
  }
  request += "Content-Length: " + std::to_string(body.size()) +
             "\r\nConnection: close\r\n\r\n";
  request.append(body);
  return request;
}

HttpsResponse ExchangePreparedRequest(
    const std::shared_ptr<HttpsConnection>& connection, std::string request) {
  auto response = connection->Exchange(request);
  ::OPENSSL_cleanse(request.data(), request.size());
  return response;
}

HttpsResponse HttpsRequest(std::uint16_t port, std::string_view method,
                           std::string_view path, std::string_view body = {},
                           std::string_view origin = {},
                           std::string_view cookie = {},
                           bool management_request = false) {
  auto connection = std::make_shared<HttpsConnection>(port);
  auto request =
      BuildHttpsRequest(method, path, body, origin, cookie, management_request);
  return ExchangePreparedRequest(connection, std::move(request));
}

std::optional<Json::Value> DecodeJsonBody(const HttpsResponse& response) {
  const std::size_t header_end = response.bytes.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    return std::nullopt;
  }
  const std::string_view body(response.bytes.data() + header_end + 4U,
                              response.bytes.size() - header_end - 4U);
  Json::CharReaderBuilder builder;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  Json::Value parsed;
  std::string errors;
  if (!reader->parse(body.data(), body.data() + body.size(), &parsed,
                     &errors)) {
    return std::nullopt;
  }
  return parsed;
}

bool HasJsonError(const HttpsResponse& response, int expected_status,
                  std::string_view expected_code) {
  const auto body = DecodeJsonBody(response);
  return response.status == expected_status && body.has_value() &&
         (*body)["code"].isString() &&
         (*body)["code"].asString() == expected_code;
}

class FirmwareProcess final {
 public:
  explicit FirmwareProcess(const std::filesystem::path& config_path) {
    const pid_t parent = ::getpid();
    child_ = ::fork();
    if (child_ < 0) {
      throw std::system_error(errno, std::generic_category(), "fork");
    }
    if (child_ == 0) {
      if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || ::getppid() != parent) {
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

  bool RequestTerminate() noexcept {
    return child_ > 0 && ::kill(child_, SIGTERM) == 0;
  }

  bool WaitForCleanExit(std::chrono::milliseconds timeout) noexcept {
    if (child_ <= 0) {
      return true;
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      int status = 0;
      const pid_t waited = ::waitpid(child_, &status, WNOHANG);
      if (waited == child_) {
        child_ = -1;
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
      }
      if (waited < 0 && errno != EINTR) {
        child_ = -1;
        return false;
      }
      std::this_thread::sleep_for(25ms);
    }
    return false;
  }

  bool StopCleanly() noexcept {
    if (child_ <= 0) {
      return true;
    }
    const bool requested = RequestTerminate();
    const bool exited = WaitForCleanExit(5s);
    return requested && exited;
  }

  void Stop() noexcept {
    if (child_ <= 0) {
      return;
    }
    (void)RequestTerminate();
    if (WaitForCleanExit(5s)) {
      return;
    }
    if (child_ <= 0) {
      return;
    }
    (void)::kill(child_, SIGKILL);
    while (::waitpid(child_, nullptr, 0) < 0 && errno == EINTR) {
    }
    child_ = -1;
  }

 private:
  pid_t child_{-1};
};

void WriteFirmwareConfig(const std::filesystem::path& config_path,
                         const std::filesystem::path& state_directory,
                         std::uint16_t https_port, std::uint16_t rtsp_port) {
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
            "  enabled: true\n"
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
            "    realm: user-process-test\n"
            "    credential_file: "
         << (state_directory / "rtsp.credentials").string()
         << "\n"
            "    algorithms: [sha-256]\n";
  if (!config.good()) {
    throw std::runtime_error("unable to flush firmware process config");
  }
}

bool WaitForFirmware(std::uint16_t port) {
  const auto deadline = std::chrono::steady_clock::now() + 10s;
  while (std::chrono::steady_clock::now() < deadline) {
    if (HttpsRequest(port, "GET", "/api/v1/setup/status", {}, {}, {}, false)
            .status == 200) {
      return true;
    }
    std::this_thread::sleep_for(50ms);
  }
  return false;
}

std::optional<std::string> LoginAs(std::uint16_t port,
                                   std::string_view username,
                                   std::string_view password) {
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  std::string body = "{\"username\":\"" + std::string(username) +
                     "\",\"password\":\"" + std::string(password) + "\"}";
  auto response =
      HttpsRequest(port, "POST", "/api/v1/auth/login", body, origin, {}, true);
  ::OPENSSL_cleanse(body.data(), body.size());
  if (response.status != 200) {
    return std::nullopt;
  }
  const std::string set_cookie = response.Header("Set-Cookie");
  if (!set_cookie.starts_with("camera_session=")) {
    return std::nullopt;
  }
  return set_cookie.substr(0U, set_cookie.find(';'));
}

std::optional<std::string> ResponseCookie(const HttpsResponse& response) {
  if (response.status != 200) {
    return std::nullopt;
  }
  const std::string set_cookie = response.Header("Set-Cookie");
  if (!set_cookie.starts_with("camera_session=")) {
    return std::nullopt;
  }
  return set_cookie.substr(0U, set_cookie.find(';'));
}

std::optional<std::string> Login(std::uint16_t port) {
  return LoginAs(port, kAdministratorUsername, kAdministratorPassword);
}

int Logout(std::uint16_t port, std::string_view cookie) {
  const std::string origin = "https://127.0.0.1:" + std::to_string(port);
  return HttpsRequest(port, "POST", "/api/v1/auth/logout", {}, origin, cookie,
                      true)
      .status;
}

struct ProvisionedViewer {
  std::int64_t user_id{0};
  std::int64_t management_ip_id{0};
};

std::optional<ProvisionedViewer> ProvisionViewer(
    std::uint16_t port, std::string_view origin,
    std::string_view administrator_cookie) {
  const auto created =
      HttpsRequest(port, "POST", "/api/v1/security/users",
                   R"({"username":"viewer1","password":"ViewerPass9!"})",
                   origin, administrator_cookie, true);
  const auto created_body = DecodeJsonBody(created);
  if (created.status != 201 || !created_body.has_value() ||
      !(*created_body)["user"]["id"].isInt64()) {
    return std::nullopt;
  }

  const auto management_ip = HttpsRequest(
      port, "POST", "/api/v1/security/management-ips/viewer",
      R"({"address":"127.0.0.1"})", origin, administrator_cookie, true);
  const auto management_ip_body = DecodeJsonBody(management_ip);
  if (management_ip.status != 201 || !management_ip_body.has_value() ||
      !(*management_ip_body)["management_ip"]["id"].isInt64()) {
    return std::nullopt;
  }
  return ProvisionedViewer{
      (*created_body)["user"]["id"].asInt64(),
      (*management_ip_body)["management_ip"]["id"].asInt64()};
}

bool HasStatus(const HttpsResponse& response,
               std::initializer_list<int> expected) {
  return std::find(expected.begin(), expected.end(), response.status) !=
         expected.end();
}

TEST(FirmwareProcessUserManagementIntegrationTest,
     MigratesRevisionTwoAndPreservesAdministratorAcrossRestart) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto database_path = state_directory / "security.db";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t https_port = ReserveLoopbackPort();
  const std::uint16_t rtsp_port = ReserveDistinctLoopbackPort(https_port);
  CreateRevisionTwoFixture(state_directory);
  WriteFirmwareConfig(config_path, state_directory, https_port, rtsp_port);

  {
    FirmwareProcess process(config_path);
    ASSERT_TRUE(WaitForFirmware(https_port));
    const auto cookie = Login(https_port);
    ASSERT_TRUE(cookie.has_value());
    EXPECT_EQ(
        HttpsRequest(https_port, "GET", "/api/v1/auth/me", {}, {}, *cookie)
            .status,
        200);
    EXPECT_EQ(Logout(https_port, *cookie), 200);
    EXPECT_TRUE(process.StopCleanly());
  }

  EXPECT_EQ(QueryInt(database_path, "SELECT version FROM schema_version;"),
            camera_firmware::security::kSecuritySchemaRevision);
  EXPECT_EQ(QueryInt(database_path,
                     "SELECT schema_revision FROM device_state WHERE id = 1;"),
            camera_firmware::security::kSecuritySchemaRevision);
  EXPECT_EQ(QueryText(database_path,
                      "SELECT canonical_username FROM users WHERE id = 11;"),
            kAdministratorUsername);
  EXPECT_EQ(QueryInt(database_path,
                     "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' "
                     "AND name = 'password_history';"),
            1);

  {
    FirmwareProcess process(config_path);
    ASSERT_TRUE(WaitForFirmware(https_port));
    const auto cookie = Login(https_port);
    ASSERT_TRUE(cookie.has_value());
    EXPECT_EQ(
        HttpsRequest(https_port, "GET", "/api/v1/auth/me", {}, {}, *cookie)
            .status,
        200);
    EXPECT_TRUE(process.StopCleanly());
  }
}

TEST(FirmwareProcessUserManagementIntegrationTest,
     PersistsManagedStateAndRejectsRevokedSessionAfterRestart) {
  constexpr std::string_view kViewerUsername = "viewer1";
  constexpr std::string_view kInitialPassword = "ViewerPass9!";
  constexpr std::string_view kReplacementPassword = "ChangedPass9!";

  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto database_path = state_directory / "security.db";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t https_port = ReserveLoopbackPort();
  const std::uint16_t rtsp_port = ReserveDistinctLoopbackPort(https_port);
  const std::string origin = "https://127.0.0.1:" + std::to_string(https_port);
  CreateRevisionTwoFixture(state_directory);
  WriteFirmwareConfig(config_path, state_directory, https_port, rtsp_port);

  std::int64_t viewer_id = 0;
  std::string revoked_viewer_cookie;
  {
    FirmwareProcess process(config_path);
    ASSERT_TRUE(WaitForFirmware(https_port));
    const auto administrator_cookie = Login(https_port);
    ASSERT_TRUE(administrator_cookie.has_value());

    const auto created =
        HttpsRequest(https_port, "POST", "/api/v1/security/users",
                     R"({"username":"viewer1","password":"ViewerPass9!"})",
                     origin, *administrator_cookie, true);
    ASSERT_EQ(created.status, 201);
    const auto created_body = DecodeJsonBody(created);
    ASSERT_TRUE(created_body.has_value());
    ASSERT_TRUE((*created_body)["user"]["id"].isInt64());
    viewer_id = (*created_body)["user"]["id"].asInt64();
    ASSERT_GT(viewer_id, 0);

    EXPECT_EQ(HttpsRequest(https_port, "POST",
                           "/api/v1/security/management-ips/viewer",
                           R"({"address":"127.0.0.1"})", origin,
                           *administrator_cookie, true)
                  .status,
              201);
    const auto viewer_cookie =
        LoginAs(https_port, kViewerUsername, kInitialPassword);
    ASSERT_TRUE(viewer_cookie.has_value());
    revoked_viewer_cookie = *viewer_cookie;

    EXPECT_EQ(HttpsRequest(https_port, "PUT",
                           "/api/v1/security/users/" +
                               std::to_string(viewer_id) + "/password",
                           R"({"password":"ChangedPass9!"})", origin,
                           *administrator_cookie, true)
                  .status,
              200);
    EXPECT_EQ(HttpsRequest(https_port, "GET", "/api/v1/auth/me", {}, {},
                           revoked_viewer_cookie)
                  .status,
              401);
    EXPECT_EQ(
        HttpsRequest(
            https_port, "PUT",
            "/api/v1/security/users/" + std::to_string(viewer_id) + "/enabled",
            R"({"enabled":false})", origin, *administrator_cookie, true)
            .status,
        200);
    EXPECT_EQ(Logout(https_port, *administrator_cookie), 200);
    EXPECT_TRUE(process.StopCleanly());
  }

  EXPECT_EQ(QueryInt(database_path,
                     "SELECT enabled FROM users WHERE canonical_username = "
                     "'viewer1';"),
            0);
  EXPECT_EQ(QueryInt(database_path,
                     "SELECT COUNT(*) FROM management_ips WHERE "
                     "normalized_ip = '127.0.0.1' AND role_scope = 'viewer' "
                     "AND enabled = 1;"),
            1);
  EXPECT_EQ(QueryInt(database_path,
                     "SELECT COUNT(*) FROM password_history WHERE user_id = " +
                         std::to_string(viewer_id) + ";"),
            1);
  EXPECT_EQ(QueryInt(database_path, "SELECT COUNT(*) FROM sessions;"), 0);

  {
    FirmwareProcess process(config_path);
    ASSERT_TRUE(WaitForFirmware(https_port));
    const auto administrator_cookie = Login(https_port);
    ASSERT_TRUE(administrator_cookie.has_value());

    const auto users = HttpsRequest(https_port, "GET", "/api/v1/security/users",
                                    {}, {}, *administrator_cookie);
    ASSERT_EQ(users.status, 200);
    const auto users_body = DecodeJsonBody(users);
    ASSERT_TRUE(users_body.has_value());
    bool found_disabled_viewer = false;
    for (const auto& user : (*users_body)["users"]) {
      if (user["id"].asInt64() == viewer_id &&
          user["username"].asString() == kViewerUsername) {
        found_disabled_viewer = !user["enabled"].asBool();
      }
    }
    EXPECT_TRUE(found_disabled_viewer);
    EXPECT_EQ(HttpsRequest(https_port, "GET", "/api/v1/auth/me", {}, {},
                           revoked_viewer_cookie)
                  .status,
              401);
    EXPECT_FALSE(
        LoginAs(https_port, kViewerUsername, kInitialPassword).has_value());
    EXPECT_FALSE(
        LoginAs(https_port, kViewerUsername, kReplacementPassword).has_value());

    EXPECT_EQ(
        HttpsRequest(
            https_port, "PUT",
            "/api/v1/security/users/" + std::to_string(viewer_id) + "/enabled",
            R"({"enabled":true})", origin, *administrator_cookie, true)
            .status,
        200);
    const auto current_reuse = HttpsRequest(
        https_port, "PUT",
        "/api/v1/security/users/" + std::to_string(viewer_id) + "/password",
        R"({"password":"ChangedPass9!"})", origin, *administrator_cookie, true);
    EXPECT_TRUE(HasJsonError(current_reuse, 409, "E_PASSWORD_REUSE"));
    const auto previous_reuse = HttpsRequest(
        https_port, "PUT",
        "/api/v1/security/users/" + std::to_string(viewer_id) + "/password",
        R"({"password":"ViewerPass9!"})", origin, *administrator_cookie, true);
    EXPECT_TRUE(HasJsonError(previous_reuse, 409, "E_PASSWORD_REUSE"));
    EXPECT_FALSE(
        LoginAs(https_port, kViewerUsername, kInitialPassword).has_value());
    const auto replacement_cookie =
        LoginAs(https_port, kViewerUsername, kReplacementPassword);
    ASSERT_TRUE(replacement_cookie.has_value());
    EXPECT_EQ(Logout(https_port, *replacement_cookie), 200);
    EXPECT_EQ(Logout(https_port, *administrator_cookie), 200);
    EXPECT_TRUE(process.StopCleanly());
  }
}

TEST(FirmwareProcessUserManagementConcurrencyTest,
     ViewerLoginRacingDisableCannotLeaveUsableSession) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t https_port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(https_port);
  CreateRevisionTwoFixture(state_directory);
  WriteFirmwareConfig(config_path, state_directory, https_port,
                      ReserveDistinctLoopbackPort(https_port));

  FirmwareProcess process(config_path);
  ASSERT_TRUE(WaitForFirmware(https_port));
  const auto administrator_cookie = Login(https_port);
  ASSERT_TRUE(administrator_cookie.has_value());
  const auto viewer =
      ProvisionViewer(https_port, origin, *administrator_cookie);
  ASSERT_TRUE(viewer.has_value());

  auto login_connection = std::make_shared<HttpsConnection>(https_port);
  auto disable_connection = std::make_shared<HttpsConnection>(https_port);
  ASSERT_TRUE(login_connection->connected());
  ASSERT_TRUE(disable_connection->connected());
  auto login_request = BuildHttpsRequest(
      "POST", "/api/v1/auth/login",
      R"({"username":"viewer1","password":"ViewerPass9!"})", origin, {}, true);
  auto disable_request = BuildHttpsRequest(
      "PUT",
      "/api/v1/security/users/" + std::to_string(viewer->user_id) + "/enabled",
      R"({"enabled":false})", origin, *administrator_cookie, true);
  std::barrier release(3);
  auto login = std::async(
      std::launch::async,
      [&, login_connection, request = std::move(login_request)]() mutable {
        release.arrive_and_wait();
        return ExchangePreparedRequest(login_connection, std::move(request));
      });
  auto disable = std::async(
      std::launch::async,
      [&, disable_connection, request = std::move(disable_request)]() mutable {
        release.arrive_and_wait();
        return ExchangePreparedRequest(disable_connection, std::move(request));
      });
  release.arrive_and_wait();

  const auto login_result = login.get();
  const auto disable_result = disable.get();
  EXPECT_EQ(disable_result.status, 200);
  EXPECT_TRUE(HasStatus(login_result, {200, 401}));
  const auto raced_cookie = ResponseCookie(login_result);
  if (raced_cookie.has_value()) {
    EXPECT_EQ(HttpsRequest(https_port, "GET", "/api/v1/auth/me", {}, {},
                           *raced_cookie)
                  .status,
              401);
  }
  EXPECT_FALSE(LoginAs(https_port, "viewer1", "ViewerPass9!").has_value());

  const auto users = HttpsRequest(https_port, "GET", "/api/v1/security/users",
                                  {}, {}, *administrator_cookie);
  const auto users_body = DecodeJsonBody(users);
  ASSERT_EQ(users.status, 200);
  ASSERT_TRUE(users_body.has_value());
  bool viewer_is_disabled = false;
  for (const auto& user : (*users_body)["users"]) {
    if (user["id"].asInt64() == viewer->user_id) {
      viewer_is_disabled = !user["enabled"].asBool();
    }
  }
  EXPECT_TRUE(viewer_is_disabled);
  EXPECT_EQ(Logout(https_port, *administrator_cookie), 200);
  EXPECT_TRUE(process.StopCleanly());
}

TEST(FirmwareProcessUserManagementConcurrencyTest,
     PasswordResetRacingLiveOpenRevokesOldAuthorization) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t https_port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(https_port);
  CreateRevisionTwoFixture(state_directory);
  WriteFirmwareConfig(config_path, state_directory, https_port,
                      ReserveDistinctLoopbackPort(https_port));

  FirmwareProcess process(config_path);
  ASSERT_TRUE(WaitForFirmware(https_port));
  const auto administrator_cookie = Login(https_port);
  ASSERT_TRUE(administrator_cookie.has_value());
  const auto viewer =
      ProvisionViewer(https_port, origin, *administrator_cookie);
  ASSERT_TRUE(viewer.has_value());
  const auto viewer_cookie = LoginAs(https_port, "viewer1", "ViewerPass9!");
  ASSERT_TRUE(viewer_cookie.has_value());

  auto live_connection = std::make_shared<HttpsConnection>(https_port);
  auto reset_connection = std::make_shared<HttpsConnection>(https_port);
  ASSERT_TRUE(live_connection->connected());
  ASSERT_TRUE(reset_connection->connected());
  auto live_request = BuildHttpsRequest(
      "GET", "/api/v1/cameras/imx708-main/live.mp4", {}, {}, *viewer_cookie);
  auto reset_request = BuildHttpsRequest(
      "PUT",
      "/api/v1/security/users/" + std::to_string(viewer->user_id) + "/password",
      R"({"password":"ChangedPass9!"})", origin, *administrator_cookie, true);
  std::barrier release(3);
  auto live_open = std::async(
      std::launch::async,
      [&, live_connection, request = std::move(live_request)]() mutable {
        release.arrive_and_wait();
        return ExchangePreparedRequest(live_connection, std::move(request));
      });
  auto password_reset = std::async(
      std::launch::async,
      [&, reset_connection, request = std::move(reset_request)]() mutable {
        release.arrive_and_wait();
        return ExchangePreparedRequest(reset_connection, std::move(request));
      });
  release.arrive_and_wait();

  const auto live_result = live_open.get();
  const auto reset_result = password_reset.get();
  EXPECT_TRUE(HasStatus(live_result, {200, 401, 503}));
  EXPECT_EQ(reset_result.status, 200);
  for (const std::string_view path : {
           "/api/v1/auth/me",
           "/api/v1/cameras",
           "/api/v1/cameras/imx708-main/snapshot.jpg",
           "/api/v1/cameras/imx708-main/live.mp4",
       }) {
    EXPECT_EQ(
        HttpsRequest(https_port, "GET", path, {}, {}, *viewer_cookie).status,
        401);
  }
  EXPECT_FALSE(LoginAs(https_port, "viewer1", "ViewerPass9!").has_value());
  const auto replacement_cookie =
      LoginAs(https_port, "viewer1", "ChangedPass9!");
  ASSERT_TRUE(replacement_cookie.has_value());
  EXPECT_EQ(Logout(https_port, *replacement_cookie), 200);
  EXPECT_EQ(Logout(https_port, *administrator_cookie), 200);
  EXPECT_TRUE(process.StopCleanly());
}

TEST(FirmwareProcessUserManagementConcurrencyTest,
     ViewerIpUpdateRacingSseAuthorizationRevokesOldSession) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t https_port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(https_port);
  CreateRevisionTwoFixture(state_directory);
  WriteFirmwareConfig(config_path, state_directory, https_port,
                      ReserveDistinctLoopbackPort(https_port));

  FirmwareProcess process(config_path);
  ASSERT_TRUE(WaitForFirmware(https_port));
  const auto administrator_cookie = Login(https_port);
  ASSERT_TRUE(administrator_cookie.has_value());
  const auto viewer =
      ProvisionViewer(https_port, origin, *administrator_cookie);
  ASSERT_TRUE(viewer.has_value());
  const auto viewer_cookie = LoginAs(https_port, "viewer1", "ViewerPass9!");
  ASSERT_TRUE(viewer_cookie.has_value());

  auto sse_connection = std::make_shared<HttpsConnection>(https_port);
  auto update_connection = std::make_shared<HttpsConnection>(https_port);
  ASSERT_TRUE(sse_connection->connected());
  ASSERT_TRUE(update_connection->connected());
  auto sse_request = BuildHttpsRequest("GET", "/api/v1/ai/detections/stream",
                                       {}, {}, *viewer_cookie);
  auto update_request = BuildHttpsRequest(
      "PUT",
      "/api/v1/security/management-ips/viewer/" +
          std::to_string(viewer->management_ip_id),
      R"({"address":"127.0.0.2"})", origin, *administrator_cookie, true);
  std::barrier release(3);
  auto sse_open = std::async(
      std::launch::async,
      [&, sse_connection, request = std::move(sse_request)]() mutable {
        release.arrive_and_wait();
        return ExchangePreparedRequest(sse_connection, std::move(request));
      });
  auto ip_update = std::async(
      std::launch::async,
      [&, update_connection, request = std::move(update_request)]() mutable {
        release.arrive_and_wait();
        return ExchangePreparedRequest(update_connection, std::move(request));
      });
  release.arrive_and_wait();

  const auto sse_result = sse_open.get();
  const auto update_result = ip_update.get();
  EXPECT_TRUE(HasStatus(sse_result, {200, 401}));
  EXPECT_EQ(update_result.status, 200);
  for (const std::string_view path : {
           "/api/v1/auth/me",
           "/api/v1/cameras",
           "/api/v1/ai/detections/stream",
       }) {
    EXPECT_EQ(
        HttpsRequest(https_port, "GET", path, {}, {}, *viewer_cookie).status,
        401);
  }
  EXPECT_FALSE(LoginAs(https_port, "viewer1", "ViewerPass9!").has_value());
  EXPECT_EQ(Logout(https_port, *administrator_cookie), 200);
  EXPECT_TRUE(process.StopCleanly());
}

TEST(FirmwareProcessUserManagementShutdownTest,
     SigtermAfterAuthenticatedManagementExitsCleanly) {
  TemporaryDirectory directory;
  const auto state_directory = directory.path() / "security";
  const auto config_path = directory.path() / "firmware.yaml";
  const std::uint16_t https_port = ReserveLoopbackPort();
  const std::string origin = "https://127.0.0.1:" + std::to_string(https_port);
  CreateRevisionTwoFixture(state_directory);
  WriteFirmwareConfig(config_path, state_directory, https_port,
                      ReserveDistinctLoopbackPort(https_port));

  FirmwareProcess process(config_path);
  ASSERT_TRUE(WaitForFirmware(https_port));
  const auto administrator_cookie = Login(https_port);
  ASSERT_TRUE(administrator_cookie.has_value());
  ASSERT_TRUE(
      ProvisionViewer(https_port, origin, *administrator_cookie).has_value());
  const auto viewer_cookie = LoginAs(https_port, "viewer1", "ViewerPass9!");
  ASSERT_TRUE(viewer_cookie.has_value());
  ASSERT_EQ(
      HttpsRequest(https_port, "GET", "/api/v1/auth/me", {}, {}, *viewer_cookie)
          .status,
      200);
  ASSERT_TRUE(process.RequestTerminate());
  EXPECT_TRUE(process.WaitForCleanExit(5s));
}

}  // namespace
