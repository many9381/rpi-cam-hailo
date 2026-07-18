#include "camera_firmware/security/SecurityStore.hpp"

#include "AuditLogServiceTestAccess.hpp"

#include "camera_firmware/security/AuthService.hpp"
#include "camera_firmware/security/PasswordHasher.hpp"
#include "camera_firmware/security/SecurityTypes.hpp"
#include "camera_firmware/security/UserManagementService.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <future>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <poll.h>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <sqlite3.h>

extern "C" int __real_lstat(const char* path, struct stat* status);
extern "C" int __real_sqlite3_open_v2(const char* filename,
                                       sqlite3** database,
                                       int flags,
                                       const char* vfs_name);
extern "C" int __real_sqlite3_busy_timeout(sqlite3* database, int milliseconds);
extern "C" int __real_sqlite3_close_v2(sqlite3* database);
extern "C" int __real_sqlite3_exec(sqlite3* database,
                                    const char* statement,
                                    int (*callback)(void*, int, char**, char**),
                                    void* context,
                                    char** error_message);

namespace {

using camera_firmware::security::DeviceState;
using camera_firmware::security::AuthService;
using camera_firmware::security::AuditLogServiceTestAccess;
using camera_firmware::security::BootstrapRecord;
using camera_firmware::security::LoginRequest;
using camera_firmware::security::PasswordRecord;
using camera_firmware::security::SecurityStore;
using camera_firmware::security::SecurityStoreConfig;
using camera_firmware::security::SecurityMutationContext;
using camera_firmware::security::SessionIdentity;
using camera_firmware::security::StoredManagedUser;
using camera_firmware::security::UserManagementDependencies;
using camera_firmware::security::UserManagementService;
using camera_firmware::security::UserMutationContext;
using camera_firmware::security::UserRole;
using camera_firmware::security::kSessionIdentityBytes;

static_assert(!std::is_trivially_destructible_v<SessionIdentity>);

template <typename T>
concept HasPublicSetDeviceState = requires(T& transaction) {
  transaction.SetDeviceState(DeviceState::kOperational);
};

TEST(SecurityTypesTest, SessionIdentityDestructorCleansesObjectStorage) {
  alignas(SessionIdentity)
      std::array<unsigned char, sizeof(SessionIdentity)> storage{};
  auto* identity =
      std::construct_at(reinterpret_cast<SessionIdentity*>(storage.data()));
  identity->bytes.fill(0xa5U);

  std::destroy_at(identity);

  EXPECT_TRUE(std::all_of(storage.begin(), storage.end(),
                          [](unsigned char value) { return value == 0U; }));
}

TEST(SecurityTypesTest,
     SessionIdentityCopyMoveAndAssignmentCleanseMovedFromStorage) {
  SessionIdentity original;
  original.bytes.fill(0x51U);
  SessionIdentity copied(original);
  EXPECT_EQ(copied, original);

  SessionIdentity moved(std::move(original));
  EXPECT_EQ(moved, copied);
  EXPECT_TRUE(std::all_of(original.bytes.begin(), original.bytes.end(),
                          [](unsigned char value) { return value == 0U; }));

  SessionIdentity copy_assigned;
  copy_assigned.bytes.fill(0x72U);
  copy_assigned = copied;
  EXPECT_EQ(copy_assigned, copied);

  SessionIdentity move_assigned;
  move_assigned.bytes.fill(0x83U);
  move_assigned = std::move(copied);
  EXPECT_EQ(move_assigned, moved);
  EXPECT_TRUE(std::all_of(copied.bytes.begin(), copied.bytes.end(),
                          [](unsigned char value) { return value == 0U; }));

  SessionIdentity greater;
  greater.bytes.fill(0xffU);
  EXPECT_LT(move_assigned, greater);
  EXPECT_EQ(sizeof(SessionIdentity), kSessionIdentityBytes);
}

std::optional<std::filesystem::path> spoofed_owner_path;
std::function<void(const char*, int)> before_sqlite_open;
bool fail_busy_timeout{false};
int last_sqlite_open_flags{0};
sqlite3* last_opened_database{nullptr};
int sqlite_close_calls{0};
bool fail_commit{false};
bool fail_rollback{false};
int rollback_calls{0};
std::optional<std::string> fail_sqlite_exec_exact;
int fail_sqlite_exec_exact_after_matches{0};

enum class MigrationExecPhase {
  kInactive,
  kRevisionTwoValidation,
  kRevisionThreeMigration,
  kRevisionThreeValidation,
  kRevisionFourMigration,
  kRevisionFourValidation,
  kReadyToCommit,
  kComplete,
};

bool observe_migration_exec{false};
MigrationExecPhase migration_exec_phase{MigrationExecPhase::kInactive};
std::vector<std::string> observed_migration_statements;
std::optional<std::size_t> fail_migration_statement_ordinal;
std::optional<std::string> expected_migration_statement;
bool migration_statement_fault_injected{false};
bool fail_next_vfs_sync{false};
int vfs_sync_calls{0};
int vfs_sync_failures{0};
bool vfs_sync_failed_during_migration_commit{false};
int delegated_open_failure_close_calls{0};

class SqliteTransactionBoundaryGate {
 public:
  SqliteTransactionBoundaryGate(std::ptrdiff_t writers,
                                int boundary_descriptor)
      : writers_(writers), boundary_descriptor_(boundary_descriptor) {}

  void ArriveAndWait() noexcept {
    const int arrival = arrivals_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (arrival == 1) {
      constexpr char kBoundaryReached = 'B';
      ssize_t written = 0;
      do {
        written = ::write(boundary_descriptor_, &kBoundaryReached, 1);
      } while (written < 0 && errno == EINTR);
    }
    writers_.arrive_and_wait();
  }

  [[nodiscard]] int arrivals() const noexcept {
    return arrivals_.load(std::memory_order_relaxed);
  }

 private:
  std::barrier<> writers_;
  int boundary_descriptor_{-1};
  std::atomic<int> arrivals_{0};
};

SqliteTransactionBoundaryGate* transaction_boundary_gate{nullptr};

void ResetSqliteHooks() {
  spoofed_owner_path.reset();
  before_sqlite_open = {};
  fail_busy_timeout = false;
  last_sqlite_open_flags = 0;
  last_opened_database = nullptr;
  sqlite_close_calls = 0;
  fail_commit = false;
  fail_rollback = false;
  rollback_calls = 0;
  fail_sqlite_exec_exact.reset();
  fail_sqlite_exec_exact_after_matches = 0;
  observe_migration_exec = false;
  migration_exec_phase = MigrationExecPhase::kInactive;
  observed_migration_statements.clear();
  fail_migration_statement_ordinal.reset();
  expected_migration_statement.reset();
  migration_statement_fault_injected = false;
  fail_next_vfs_sync = false;
  vfs_sync_calls = 0;
  vfs_sync_failures = 0;
  vfs_sync_failed_during_migration_commit = false;
  delegated_open_failure_close_calls = 0;
  transaction_boundary_gate = nullptr;
}

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 40> pattern{"/tmp/cf-security-store-XXXXXX"};
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

  [[nodiscard]] std::filesystem::path Path(std::string_view name) const {
    return path_ / name;
  }

 private:
  std::filesystem::path path_;
};

class ScopedUmask {
 public:
  explicit ScopedUmask(mode_t mode) : previous_(::umask(mode)) {}
  ~ScopedUmask() { ::umask(previous_); }

  ScopedUmask(const ScopedUmask&) = delete;
  ScopedUmask& operator=(const ScopedUmask&) = delete;

 private:
  mode_t previous_;
};

mode_t FileMode(const std::filesystem::path& path) {
  struct stat status {};
  if (::lstat(path.c_str(), &status) != 0) {
    return 0;
  }
  return status.st_mode & 0777;
}

void MakeDirectory(const std::filesystem::path& path) {
  if (::mkdir(path.c_str(), 0700) != 0) {
    throw std::system_error(errno, std::generic_category(), "mkdir");
  }
}

void MakeFile(const std::filesystem::path& path, mode_t mode) {
  const int descriptor =
      ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
  if (descriptor < 0) {
    throw std::system_error(errno, std::generic_category(), "open");
  }
  if (::fchmod(descriptor, mode) != 0) {
    const int error = errno;
    (void)::close(descriptor);
    throw std::system_error(error, std::generic_category(), "fchmod");
  }
  if (::close(descriptor) != 0) {
    throw std::system_error(errno, std::generic_category(), "close");
  }
}

int QueryInt(sqlite3* database, const char* sql) {
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_prepare_v2 failed");
  }
  const int step = ::sqlite3_step(statement);
  if (step != SQLITE_ROW) {
    (void)::sqlite3_finalize(statement);
    throw std::runtime_error("sqlite3_step did not return a row");
  }
  const int value = ::sqlite3_column_int(statement, 0);
  if (::sqlite3_finalize(statement) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_finalize failed");
  }
  return value;
}

camera_firmware::common::SecureBytes FilledBytes(std::size_t size,
                                                  unsigned char value) {
  camera_firmware::common::SecureBytes bytes;
  bytes.resize(size);
  std::fill_n(bytes.data(), size, value);
  return bytes;
}

camera_firmware::common::SecureBytes Secret(std::string_view value) {
  camera_firmware::common::SecureBytes bytes;
  bytes.assign(reinterpret_cast<const unsigned char*>(value.data()),
               value.size());
  return bytes;
}

BootstrapRecord MakeBootstrapRecord() {
  PasswordRecord password;
  password.salt = FilledBytes(camera_firmware::security::kPasswordSaltBytes,
                              0x31U);
  password.derived = FilledBytes(
      camera_firmware::security::kPasswordDerivedBytes, 0xa7U);
  return {"operator.one", "Operator.One", std::move(password),
          "2001:db8::10", 1720000000};
}

std::string QueryText(sqlite3* database, const char* sql) {
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_prepare_v2 failed");
  }
  const int step = ::sqlite3_step(statement);
  if (step != SQLITE_ROW) {
    (void)::sqlite3_finalize(statement);
    throw std::runtime_error("sqlite3_step did not return a row");
  }
  const unsigned char* raw_value = ::sqlite3_column_text(statement, 0);
  const std::string value =
      raw_value == nullptr ? "" : reinterpret_cast<const char*>(raw_value);
  if (::sqlite3_finalize(statement) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_finalize failed");
  }
  return value;
}

std::vector<std::string> QueryTextRows(sqlite3* database, const char* sql) {
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_prepare_v2 failed");
  }
  std::vector<std::string> values;
  while (::sqlite3_step(statement) == SQLITE_ROW) {
    const unsigned char* raw_value = ::sqlite3_column_text(statement, 0);
    values.emplace_back(raw_value == nullptr
                            ? ""
                            : reinterpret_cast<const char*>(raw_value));
  }
  if (::sqlite3_finalize(statement) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_finalize failed");
  }
  return values;
}

void CreateDatabaseWithSql(const std::filesystem::path& path, const char* sql) {
  MakeFile(path, 0600);
  sqlite3* database = nullptr;
  if (__real_sqlite3_open_v2(path.c_str(), &database,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW,
                             nullptr) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_open_v2 failed");
  }
  char* error_message = nullptr;
  const int execute =
      __real_sqlite3_exec(database, sql, nullptr, nullptr, &error_message);
  if (error_message != nullptr) {
    ::sqlite3_free(error_message);
  }
  const int close = __real_sqlite3_close_v2(database);
  if (execute != SQLITE_OK || close != SQLITE_OK) {
    throw std::runtime_error("failed to prepare test database");
  }
}

void ExecuteDatabaseSql(const std::filesystem::path& path, const char* sql) {
  sqlite3* database = nullptr;
  if (__real_sqlite3_open_v2(path.c_str(), &database,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW,
                             nullptr) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_open_v2 failed");
  }
  char* error_message = nullptr;
  const int execute =
      __real_sqlite3_exec(database, sql, nullptr, nullptr, &error_message);
  if (error_message != nullptr) {
    ::sqlite3_free(error_message);
  }
  const int close = __real_sqlite3_close_v2(database);
  if (execute != SQLITE_OK || close != SQLITE_OK) {
    throw std::runtime_error("failed to mutate test database");
  }
}

int QueryDatabaseInt(const std::filesystem::path& path, const char* sql) {
  sqlite3* database = nullptr;
  if (__real_sqlite3_open_v2(path.c_str(), &database,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW,
                             nullptr) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_open_v2 failed");
  }
  const int value = QueryInt(database, sql);
  if (__real_sqlite3_close_v2(database) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_close_v2 failed");
  }
  return value;
}

std::vector<std::string> QueryDatabaseTextRows(
    const std::filesystem::path& path,
    const char* sql) {
  sqlite3* database = nullptr;
  if (__real_sqlite3_open_v2(path.c_str(), &database,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW,
                             nullptr) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_open_v2 failed");
  }
  auto values = QueryTextRows(database, sql);
  if (__real_sqlite3_close_v2(database) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_close_v2 failed");
  }
  return values;
}

bool DatabaseStatementIsRejected(const std::filesystem::path& path,
                                 const char* sql) {
  sqlite3* database = nullptr;
  if (__real_sqlite3_open_v2(path.c_str(), &database,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW,
                             nullptr) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_open_v2 failed");
  }
  char* error_message = nullptr;
  const int execute =
      __real_sqlite3_exec(database, sql, nullptr, nullptr, &error_message);
  if (error_message != nullptr) {
    ::sqlite3_free(error_message);
  }
  if (__real_sqlite3_close_v2(database) != SQLITE_OK) {
    throw std::runtime_error("sqlite3_close_v2 failed");
  }
  return (execute & 0xff) == SQLITE_CONSTRAINT;
}

constexpr const char* kRevisionTwoOperationalSchema = R"sql(
PRAGMA foreign_keys=ON;
PRAGMA secure_delete=ON;
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
   1720000000, 1720000010),
  (12, 'viewer.one', 'Viewer.One', 'viewer', 1,
   'pbkdf2-hmac-sha256', 600000,
   x'0102030405060708090a0b0c0d0e0f10',
   x'0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
   1720000001, 2,
   1720000001, 1720000011);
INSERT INTO management_ips
  (id, normalized_ip, role_scope, enabled, created_at_seconds)
VALUES (21, '2001:db8::10', 'administrator', 1, 1720000000);
INSERT INTO sessions
  (id, token_hash, user_id, role, created_at_seconds,
   last_activity_at_seconds, expires_at_seconds, peer_ip)
VALUES
  (31,
   x'2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40',
   11, 'administrator', 1720000010, 1720000011,
   1720001011, '2001:db8::10'),
  (32,
   x'4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60',
   12, 'viewer', 1720000012, 1720000013,
   1720001013, '198.51.100.10');
INSERT INTO audit_events
  (sequence, server_timestamp_seconds, event_type, outcome, actor_user_id,
   peer_ip, detail_code)
VALUES
  (41, 1720000000, 'bootstrap_completed', 'success', 11,
   '2001:db8::10', 'initial_administrator'),
  (42, 1720000010, 'login_completed', 'success', 12,
   '198.51.100.10', 'session_created');
INSERT INTO firmware_log_outbox
  (id, category, peer_ip, created_at_seconds, dirty)
VALUES (51, 'authentication_limit_reached', '198.51.100.10', 1720000020, 1);
)sql";

class RevisionTwoOperationalFixture {
 public:
  RevisionTwoOperationalFixture() {
    MakeDirectory(state_directory());
    CreateDatabaseWithSql(database_path(), kRevisionTwoOperationalSchema);
  }

  [[nodiscard]] std::filesystem::path state_directory() const {
    return root_.Path("security");
  }

  [[nodiscard]] std::filesystem::path database_path() const {
    return state_directory() / "security.db";
  }

  [[nodiscard]] std::vector<std::string> evidence() const {
    return QueryDatabaseTextRows(database_path(), R"sql(
SELECT 'users|' || id || '|' || canonical_username || '|' || display_username ||
       '|' || role || '|' || enabled || '|' || password_algorithm || '|' ||
       password_iterations || '|' || length(password_salt) || '|' ||
       length(password_derived) || '|' || password_changed_at_seconds || '|' ||
       failed_login_count || '|' || COALESCE(lock_until_seconds, -1) || '|' ||
       created_at_seconds || '|' || COALESCE(last_login_at_seconds, -1)
FROM users
UNION ALL
SELECT 'password_material|' || id || '|' ||
       (password_salt = CASE id
          WHEN 11 THEN zeroblob(16)
          WHEN 12 THEN x'0102030405060708090a0b0c0d0e0f10'
        END) || '|' ||
       (password_derived = CASE id
          WHEN 11 THEN zeroblob(32)
          WHEN 12 THEN
            x'0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'
        END)
FROM users
UNION ALL
SELECT 'management_ips|' || id || '|' || normalized_ip || '|' || role_scope ||
       '|' || enabled || '|' || created_at_seconds
FROM management_ips
UNION ALL
SELECT 'sessions|' || id || '|' || user_id || '|' || role || '|' ||
       (token_hash = CASE id
          WHEN 31 THEN
            x'2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40'
          WHEN 32 THEN
            x'4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60'
        END) || '|' || created_at_seconds || '|' ||
       last_activity_at_seconds || '|' || expires_at_seconds || '|' || peer_ip
FROM sessions
UNION ALL
SELECT 'audit_events|' || sequence || '|' || server_timestamp_seconds || '|' ||
       event_type || '|' || outcome || '|' || COALESCE(actor_user_id, -1) ||
       '|' || peer_ip || '|' || detail_code
FROM audit_events
UNION ALL
SELECT 'firmware_log_outbox|' || id || '|' || category || '|' || peer_ip ||
       '|' || created_at_seconds || '|' || dirty || '|' ||
       COALESCE(length(lease_owner), -1) || '|' ||
       COALESCE(length(lease_token), -1) || '|' ||
       COALESCE(lease_expires_at_seconds, -1)
FROM firmware_log_outbox
ORDER BY 1;
)sql");
  }

 private:
  TemporaryDirectory root_;
};

constexpr const char* kRevisionTwoToThreeFixtureMigration = R"sql(
BEGIN IMMEDIATE;
ALTER TABLE schema_version RENAME TO schema_version_revision_two;
CREATE TABLE schema_version (
  version INTEGER NOT NULL CHECK (version = 3)
);
INSERT INTO schema_version (version) VALUES (3);
DROP TABLE schema_version_revision_two;
ALTER TABLE device_state RENAME TO device_state_revision_two;
CREATE TABLE device_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL CHECK (state IN ('default', 'operational')),
  schema_revision INTEGER NOT NULL CHECK (schema_revision = 3),
  setup_completed_at_seconds INTEGER,
  CHECK (
    (state = 'default' AND setup_completed_at_seconds IS NULL) OR
    (state = 'operational' AND setup_completed_at_seconds IS NOT NULL AND
     setup_completed_at_seconds >= 0)
  )
);
INSERT INTO device_state
  (id, state, schema_revision, setup_completed_at_seconds)
SELECT id, state, 3, setup_completed_at_seconds
FROM device_state_revision_two;
DROP TABLE device_state_revision_two;
ALTER TABLE management_ips RENAME TO management_ips_revision_two;
CREATE TABLE management_ips (
  id INTEGER PRIMARY KEY,
  normalized_ip TEXT NOT NULL CHECK (length(normalized_ip) BETWEEN 2 AND 45),
  role_scope TEXT NOT NULL
    CHECK (role_scope IN ('administrator', 'viewer')),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0)
);
INSERT INTO management_ips
  (id, normalized_ip, role_scope, enabled, created_at_seconds)
SELECT id, normalized_ip, role_scope, enabled, created_at_seconds
FROM management_ips_revision_two;
DROP TABLE management_ips_revision_two;
CREATE UNIQUE INDEX management_ips_role_ip_unique
  ON management_ips(role_scope, normalized_ip);
CREATE TABLE password_history (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_algorithm TEXT NOT NULL
    CHECK (password_algorithm = 'pbkdf2-hmac-sha256'),
  password_iterations INTEGER NOT NULL
    CHECK (password_iterations BETWEEN 1000 AND 2000000),
  password_salt BLOB NOT NULL CHECK (length(password_salt) = 16),
  password_derived BLOB NOT NULL CHECK (length(password_derived) = 32),
  replaced_at_seconds INTEGER NOT NULL CHECK (replaced_at_seconds >= 0)
);
CREATE UNIQUE INDEX password_history_user_id_unique
  ON password_history(user_id);
CREATE UNIQUE INDEX sessions_user_id_unique ON sessions(user_id);
ALTER TABLE audit_events RENAME TO audit_events_revision_two;
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY,
  server_timestamp_seconds INTEGER NOT NULL
    CHECK (server_timestamp_seconds >= 0),
  event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45),
  detail_code TEXT NOT NULL CHECK (length(detail_code) <= 64),
  subject_type TEXT NOT NULL DEFAULT ''
    CHECK (length(subject_type) <= 64),
  subject_identity TEXT NOT NULL DEFAULT ''
    CHECK (length(subject_identity) <= 64)
);
INSERT INTO audit_events
  (sequence, server_timestamp_seconds, event_type, outcome, actor_user_id,
   peer_ip, detail_code, subject_type, subject_identity)
SELECT sequence, server_timestamp_seconds, event_type, outcome, actor_user_id,
       peer_ip, detail_code, '', ''
FROM audit_events_revision_two;
DROP TABLE audit_events_revision_two;
CREATE INDEX audit_events_timestamp_index
  ON audit_events(server_timestamp_seconds);
UPDATE users
SET canonical_username = 'cameraowner', display_username = 'CameraOwner'
WHERE id = 11;
INSERT INTO audit_events
  (sequence, server_timestamp_seconds, event_type, outcome, actor_user_id,
   peer_ip, detail_code, subject_type, subject_identity)
VALUES (73, 1720000025, 'viewer_disabled', 'failure', NULL,
        '198.51.100.11', 'legacy_deleted_actor', 'user', 'viewer.one');
COMMIT;
)sql";

class RevisionThreeOperationalFixture {
 public:
  RevisionThreeOperationalFixture() {
    MakeDirectory(state_directory());
    CreateDatabaseWithSql(database_path(), kRevisionTwoOperationalSchema);
    ExecuteDatabaseSql(database_path(), kRevisionTwoToThreeFixtureMigration);
  }

  [[nodiscard]] std::filesystem::path state_directory() const {
    return root_.Path("security");
  }

  [[nodiscard]] std::filesystem::path database_path() const {
    return state_directory() / "security.db";
  }

 private:
  TemporaryDirectory root_;
};

class RevisionThreeOrphanedAuditActorFixture {
 public:
  RevisionThreeOrphanedAuditActorFixture() {
    MakeDirectory(state_directory());
    CreateDatabaseWithSql(database_path(), kRevisionTwoOperationalSchema);
    ExecuteDatabaseSql(database_path(), kRevisionTwoToThreeFixtureMigration);
    ExecuteDatabaseSql(database_path(), R"sql(
PRAGMA foreign_keys=OFF;
INSERT INTO audit_events
  (sequence, server_timestamp_seconds, event_type, outcome, actor_user_id,
   peer_ip, detail_code, subject_type, subject_identity)
VALUES (74, 1720000030, 'viewer_deleted', 'failure', 999,
        '203.0.113.7', 'legacy_orphan_actor', 'user', 'retired.viewer');
)sql");
  }

  [[nodiscard]] std::filesystem::path state_directory() const {
    return root_.Path("security");
  }

  [[nodiscard]] std::filesystem::path database_path() const {
    return state_directory() / "security.db";
  }

 private:
  TemporaryDirectory root_;
};

int ClosePartiallyOpenedDelegate(sqlite3_file*) {
  ++delegated_open_failure_close_calls;
  return SQLITE_OK;
}

const sqlite3_io_methods kPartiallyOpenedDelegateMethods = {
    1,       ClosePartiallyOpenedDelegate, nullptr, nullptr, nullptr,
    nullptr, nullptr,                      nullptr, nullptr, nullptr,
    nullptr, nullptr,                      nullptr, nullptr, nullptr,
    nullptr, nullptr,                      nullptr, nullptr};

int FailDelegateOpen(sqlite3_vfs*,
                     sqlite3_filename,
                     sqlite3_file* file,
                     int,
                     int*) {
  file->pMethods = &kPartiallyOpenedDelegateMethods;
  return SQLITE_CANTOPEN;
}

class ScopedSyncFaultVfs {
 public:
  ScopedSyncFaultVfs()
      : ScopedSyncFaultVfs(::sqlite3_vfs_find(nullptr), true) {}

  explicit ScopedSyncFaultVfs(sqlite3_vfs* delegate)
      : ScopedSyncFaultVfs(delegate, false) {}

  ~ScopedSyncFaultVfs() {
    if (registered_) {
      (void)::sqlite3_vfs_unregister(&wrapper_);
      (void)::sqlite3_vfs_register(original_, 1);
    }
  }

  ScopedSyncFaultVfs(const ScopedSyncFaultVfs&) = delete;
  ScopedSyncFaultVfs& operator=(const ScopedSyncFaultVfs&) = delete;

  [[nodiscard]] bool registered() const noexcept { return registered_; }

  [[nodiscard]] sqlite3_vfs* vfs_for_test() noexcept { return &wrapper_; }

 private:
  ScopedSyncFaultVfs(sqlite3_vfs* delegate, bool register_as_default)
      : original_(delegate) {
    if (original_ == nullptr) {
      return;
    }
    wrapper_ = *original_;
    wrapper_.pNext = nullptr;
    wrapper_.szOsFile =
        static_cast<int>(kWrappedFileBytes + original_->szOsFile);
    wrapper_.zName = "camera-firmware-sync-fault";
    wrapper_.pAppData = original_;
    wrapper_.xOpen = Open;
    wrapper_.xDelete = Delete;
    wrapper_.xAccess = Access;
    wrapper_.xFullPathname = FullPathname;
    wrapper_.xDlOpen = DlOpen;
    wrapper_.xDlError = DlError;
    wrapper_.xDlSym = DlSym;
    wrapper_.xDlClose = DlClose;
    wrapper_.xRandomness = Randomness;
    wrapper_.xSleep = Sleep;
    wrapper_.xCurrentTime = CurrentTime;
    wrapper_.xGetLastError = GetLastError;
    wrapper_.xCurrentTimeInt64 = CurrentTimeInt64;
    wrapper_.xSetSystemCall = SetSystemCall;
    wrapper_.xGetSystemCall = GetSystemCall;
    wrapper_.xNextSystemCall = NextSystemCall;
    if (register_as_default) {
      registered_ = ::sqlite3_vfs_register(&wrapper_, 1) == SQLITE_OK;
    }
  }

  struct WrappedFile {
    sqlite3_file base;
    sqlite3_file* real{nullptr};
    const sqlite3_io_methods* real_methods{nullptr};
  };

  static constexpr std::size_t kWrappedFileBytes =
      ((sizeof(WrappedFile) + alignof(sqlite3_file) - 1U) /
       alignof(sqlite3_file)) *
      alignof(sqlite3_file);

  static sqlite3_vfs* Original(sqlite3_vfs* vfs) {
    return static_cast<sqlite3_vfs*>(vfs->pAppData);
  }

  static WrappedFile* Wrapped(sqlite3_file* file) {
    return reinterpret_cast<WrappedFile*>(file);
  }

  static sqlite3_file* RealStorage(sqlite3_file* file) {
    return reinterpret_cast<sqlite3_file*>(
        reinterpret_cast<unsigned char*>(file) + kWrappedFileBytes);
  }

  static int Open(sqlite3_vfs* vfs,
                  sqlite3_filename name,
                  sqlite3_file* file,
                  int flags,
                  int* output_flags) {
    auto* wrapped = Wrapped(file);
    wrapped->base.pMethods = nullptr;
    wrapped->real = nullptr;
    wrapped->real_methods = nullptr;
    auto* real = RealStorage(file);
    real->pMethods = nullptr;
    wrapped->real = real;
    const int result = Original(vfs)->xOpen(Original(vfs), name, real, flags,
                                            output_flags);
    if (result != SQLITE_OK) {
      if (real->pMethods != nullptr) {
        (void)real->pMethods->xClose(real);
      }
      real->pMethods = nullptr;
      wrapped->real = nullptr;
      wrapped->real_methods = nullptr;
      return result;
    }
    wrapped->real_methods = real->pMethods;
    wrapped->base.pMethods =
        wrapped->real_methods->iVersion >= 3
            ? &kIoMethodsVersionThree
            : (wrapped->real_methods->iVersion == 2 ? &kIoMethodsVersionTwo
                                                     : &kIoMethodsVersionOne);
    return SQLITE_OK;
  }

  static int Close(sqlite3_file* file) {
    auto* wrapped = Wrapped(file);
    const int result = wrapped->real_methods->xClose(wrapped->real);
    wrapped->base.pMethods = nullptr;
    return result;
  }

  static int Read(sqlite3_file* file,
                  void* buffer,
                  int amount,
                  sqlite3_int64 offset) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xRead(wrapped->real, buffer, amount, offset);
  }

  static int Write(sqlite3_file* file,
                   const void* buffer,
                   int amount,
                   sqlite3_int64 offset) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xWrite(wrapped->real, buffer, amount, offset);
  }

  static int Truncate(sqlite3_file* file, sqlite3_int64 size) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xTruncate(wrapped->real, size);
  }

  static int Sync(sqlite3_file* file, int flags) {
    ++vfs_sync_calls;
    if (fail_next_vfs_sync) {
      fail_next_vfs_sync = false;
      ++vfs_sync_failures;
      vfs_sync_failed_during_migration_commit =
          migration_exec_phase == MigrationExecPhase::kComplete;
      return SQLITE_IOERR_FSYNC;
    }
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xSync(wrapped->real, flags);
  }

  static int FileSize(sqlite3_file* file, sqlite3_int64* size) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xFileSize(wrapped->real, size);
  }

  static int Lock(sqlite3_file* file, int lock) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xLock(wrapped->real, lock);
  }

  static int Unlock(sqlite3_file* file, int lock) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xUnlock(wrapped->real, lock);
  }

  static int CheckReservedLock(sqlite3_file* file, int* result) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xCheckReservedLock(wrapped->real, result);
  }

  static int FileControl(sqlite3_file* file, int operation, void* argument) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xFileControl(wrapped->real, operation,
                                                argument);
  }

  static int SectorSize(sqlite3_file* file) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xSectorSize(wrapped->real);
  }

  static int DeviceCharacteristics(sqlite3_file* file) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xDeviceCharacteristics(wrapped->real);
  }

  static int ShmMap(sqlite3_file* file,
                    int page,
                    int page_size,
                    int extend,
                    void volatile** output) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xShmMap(wrapped->real, page, page_size,
                                          extend, output);
  }

  static int ShmLock(sqlite3_file* file,
                     int offset,
                     int count,
                     int flags) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xShmLock(wrapped->real, offset, count, flags);
  }

  static void ShmBarrier(sqlite3_file* file) {
    auto* wrapped = Wrapped(file);
    wrapped->real_methods->xShmBarrier(wrapped->real);
  }

  static int ShmUnmap(sqlite3_file* file, int delete_flag) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xShmUnmap(wrapped->real, delete_flag);
  }

  static int Fetch(sqlite3_file* file,
                   sqlite3_int64 offset,
                   int amount,
                   void** output) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xFetch(wrapped->real, offset, amount, output);
  }

  static int Unfetch(sqlite3_file* file,
                     sqlite3_int64 offset,
                     void* pointer) {
    auto* wrapped = Wrapped(file);
    return wrapped->real_methods->xUnfetch(wrapped->real, offset, pointer);
  }

  inline static const sqlite3_io_methods kIoMethodsVersionOne = {
      1, Close, Read, Write, Truncate, Sync, FileSize, Lock, Unlock,
      CheckReservedLock, FileControl, SectorSize, DeviceCharacteristics,
      nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
  inline static const sqlite3_io_methods kIoMethodsVersionTwo = {
      2, Close, Read, Write, Truncate, Sync, FileSize, Lock, Unlock,
      CheckReservedLock, FileControl, SectorSize, DeviceCharacteristics,
      ShmMap, ShmLock, ShmBarrier, ShmUnmap, nullptr, nullptr};
  inline static const sqlite3_io_methods kIoMethodsVersionThree = {
      3, Close, Read, Write, Truncate, Sync, FileSize, Lock, Unlock,
      CheckReservedLock, FileControl, SectorSize, DeviceCharacteristics,
      ShmMap, ShmLock, ShmBarrier, ShmUnmap, Fetch, Unfetch};

  static int Delete(sqlite3_vfs* vfs, const char* name, int sync_directory) {
    return Original(vfs)->xDelete(Original(vfs), name, sync_directory);
  }

  static int Access(sqlite3_vfs* vfs,
                    const char* name,
                    int flags,
                    int* result) {
    return Original(vfs)->xAccess(Original(vfs), name, flags, result);
  }

  static int FullPathname(sqlite3_vfs* vfs,
                          const char* name,
                          int output_size,
                          char* output) {
    return Original(vfs)->xFullPathname(Original(vfs), name, output_size,
                                         output);
  }

  static void* DlOpen(sqlite3_vfs* vfs, const char* name) {
    return Original(vfs)->xDlOpen(Original(vfs), name);
  }

  static void DlError(sqlite3_vfs* vfs, int size, char* message) {
    Original(vfs)->xDlError(Original(vfs), size, message);
  }

  static void (*DlSym(sqlite3_vfs* vfs,
                      void* handle,
                      const char* symbol))(void) {
    return Original(vfs)->xDlSym(Original(vfs), handle, symbol);
  }

  static void DlClose(sqlite3_vfs* vfs, void* handle) {
    Original(vfs)->xDlClose(Original(vfs), handle);
  }

  static int Randomness(sqlite3_vfs* vfs, int size, char* output) {
    return Original(vfs)->xRandomness(Original(vfs), size, output);
  }

  static int Sleep(sqlite3_vfs* vfs, int microseconds) {
    return Original(vfs)->xSleep(Original(vfs), microseconds);
  }

  static int CurrentTime(sqlite3_vfs* vfs, double* time) {
    return Original(vfs)->xCurrentTime(Original(vfs), time);
  }

  static int GetLastError(sqlite3_vfs* vfs, int size, char* message) {
    return Original(vfs)->xGetLastError(Original(vfs), size, message);
  }

  static int CurrentTimeInt64(sqlite3_vfs* vfs, sqlite3_int64* time) {
    return Original(vfs)->xCurrentTimeInt64(Original(vfs), time);
  }

  static int SetSystemCall(sqlite3_vfs* vfs,
                           const char* name,
                           sqlite3_syscall_ptr call) {
    return Original(vfs)->xSetSystemCall(Original(vfs), name, call);
  }

  static sqlite3_syscall_ptr GetSystemCall(sqlite3_vfs* vfs,
                                           const char* name) {
    return Original(vfs)->xGetSystemCall(Original(vfs), name);
  }

  static const char* NextSystemCall(sqlite3_vfs* vfs, const char* name) {
    return Original(vfs)->xNextSystemCall(Original(vfs), name);
  }

  sqlite3_vfs* original_{nullptr};
  sqlite3_vfs wrapper_{};
  bool registered_{false};
};

std::vector<std::string> CaptureActualMigrationStatements() {
  ResetSqliteHooks();
  RevisionTwoOperationalFixture fixture;
  observe_migration_exec = true;

  auto opened = SecurityStore::Open({fixture.state_directory()});

  observe_migration_exec = false;
  if (!opened.ok() || migration_exec_phase != MigrationExecPhase::kComplete ||
      observed_migration_statements.empty()) {
    throw std::runtime_error("failed to capture migration execution");
  }
  return observed_migration_statements;
}

bool ObserveMigrationExec(std::string_view sql) {
  const auto capture_statement = [sql]() {
    const std::size_t ordinal = observed_migration_statements.size();
    observed_migration_statements.emplace_back(sql);
    if (fail_migration_statement_ordinal == ordinal &&
        expected_migration_statement.has_value() &&
        sql == *expected_migration_statement) {
      migration_statement_fault_injected = true;
      return true;
    }
    return false;
  };

  if (!observe_migration_exec) {
    return false;
  }
  if (migration_exec_phase == MigrationExecPhase::kInactive) {
    if (sql == "BEGIN IMMEDIATE;") {
      migration_exec_phase = MigrationExecPhase::kRevisionTwoValidation;
    }
    return false;
  }
  if (migration_exec_phase == MigrationExecPhase::kRevisionTwoValidation) {
    if (sql == "RELEASE schema_validation;") {
      migration_exec_phase = MigrationExecPhase::kRevisionThreeMigration;
    } else if (sql == "ROLLBACK;") {
      migration_exec_phase = MigrationExecPhase::kInactive;
    }
    return false;
  }
  if (migration_exec_phase == MigrationExecPhase::kRevisionThreeMigration) {
    if (sql == "SAVEPOINT schema_validation;") {
      migration_exec_phase = MigrationExecPhase::kRevisionThreeValidation;
      return false;
    }
    if (sql == "ROLLBACK;") {
      migration_exec_phase = MigrationExecPhase::kInactive;
      return false;
    }
    return capture_statement();
  }
  if (migration_exec_phase == MigrationExecPhase::kRevisionThreeValidation) {
    if (sql == "RELEASE schema_validation;") {
      migration_exec_phase = MigrationExecPhase::kRevisionFourMigration;
    } else if (sql == "ROLLBACK;") {
      migration_exec_phase = MigrationExecPhase::kInactive;
    }
    return false;
  }
  if (migration_exec_phase == MigrationExecPhase::kRevisionFourMigration) {
    if (sql == "SAVEPOINT schema_validation;") {
      migration_exec_phase = MigrationExecPhase::kRevisionFourValidation;
      return false;
    }
    if (sql == "ROLLBACK;") {
      migration_exec_phase = MigrationExecPhase::kInactive;
      return false;
    }
    return capture_statement();
  }
  if (migration_exec_phase == MigrationExecPhase::kRevisionFourValidation) {
    if (sql == "RELEASE schema_validation;") {
      migration_exec_phase = MigrationExecPhase::kReadyToCommit;
    } else if (sql == "ROLLBACK;") {
      migration_exec_phase = MigrationExecPhase::kInactive;
    }
    return false;
  }
  if (migration_exec_phase == MigrationExecPhase::kReadyToCommit) {
    if (sql == "COMMIT;") {
      migration_exec_phase = MigrationExecPhase::kComplete;
      return false;
    }
    if (sql == "ROLLBACK;") {
      migration_exec_phase = MigrationExecPhase::kInactive;
      return false;
    }
    return capture_statement();
  }
  return false;
}

bool GitIgnores(std::string_view path) {
  const pid_t child = ::fork();
  if (child < 0) {
    throw std::system_error(errno, std::generic_category(), "fork");
  }
  if (child == 0) {
    const std::string path_string(path);
    ::execlp("git", "git", "-C", CF_SOURCE_DIR, "check-ignore", "--no-index",
             "--quiet", path_string.c_str(), nullptr);
    ::_exit(127);
  }
  int status = 0;
  if (::waitpid(child, &status, 0) != child) {
    throw std::system_error(errno, std::generic_category(), "waitpid");
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

void ExpectStoreErrorWithSymlink(std::string_view code) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  const auto target = root.Path("target");
  MakeDirectory(state);
  MakeFile(target, 0600);
  ASSERT_EQ(::symlink(target.c_str(), (state / "security.db").c_str()), 0);

  const auto store = SecurityStore::Open({state});

  ASSERT_FALSE(store.ok());
  EXPECT_EQ(store.error().code, code);
}

void ExpectStoreErrorWithMode(mode_t mode, std::string_view code) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  MakeDirectory(state);
  MakeFile(state / "security.db", mode);

  const auto store = SecurityStore::Open({state});

  ASSERT_FALSE(store.ok());
  EXPECT_EQ(store.error().code, code);
}

void ExpectReopenRejectsSchemaMutation(const char* mutation) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
  }
  ExecuteDatabaseSql(state / "security.db", mutation);

  auto reopened = SecurityStore::Open({state});

  ASSERT_FALSE(reopened.ok());
  EXPECT_EQ(reopened.error().code, "E_SECURITY_DB_SCHEMA");
}

void ExpectOperationalReopenRejectsDataMutation(const char* mutation) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    ASSERT_TRUE(store.value()
                    ->InitializeDevice(MakeBootstrapRecord(), [] {
                      return camera_firmware::common::Result<void>::Ok();
                    })
                    .ok());
  }
  ExecuteDatabaseSql(state / "security.db", mutation);

  auto reopened = SecurityStore::Open({state});

  ASSERT_FALSE(reopened.ok());
  EXPECT_EQ(reopened.error().code, "E_SECURITY_DB_SCHEMA");
}

enum class AuditRetentionFailurePoint {
  kDatabaseTrigger,
  kActorSnapshotLookup,
  kCallerCommit,
};

enum class BoundedSubprocessOutcome {
  kExited,
  kTimedOutBeforeBoundary,
  kTimedOutAfterBoundary,
};

struct BoundedSubprocessResult {
  BoundedSubprocessOutcome outcome{BoundedSubprocessOutcome::kExited};
  pid_t child{-1};
  int status{0};
  bool boundary_observed{false};
};

BoundedSubprocessResult RunBoundedSubprocessAtBoundary(
    const std::function<void(int)>& scenario,
    std::chrono::milliseconds setup_timeout,
    std::chrono::milliseconds completion_timeout) {
  int boundary_pipe[2] = {-1, -1};
  if (::pipe(boundary_pipe) != 0) {
    throw std::system_error(errno, std::generic_category(), "pipe");
  }

  const pid_t child = ::fork();
  if (child < 0) {
    const int error = errno;
    (void)::close(boundary_pipe[0]);
    (void)::close(boundary_pipe[1]);
    throw std::system_error(error, std::generic_category(), "fork");
  }
  if (child == 0) {
    (void)::close(boundary_pipe[0]);
    try {
      scenario(boundary_pipe[1]);
    } catch (...) {
      (void)::close(boundary_pipe[1]);
      ::_exit(2);
    }
    (void)::close(boundary_pipe[1]);
    ::_exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  (void)::close(boundary_pipe[1]);
  bool boundary_observed = false;
  auto deadline = std::chrono::steady_clock::now() + setup_timeout;
  for (;;) {
    int status = 0;
    const pid_t waited = ::waitpid(child, &status, WNOHANG);
    if (waited == child) {
      if (!boundary_observed) {
        char marker = 0;
        ssize_t bytes_read = 0;
        do {
          bytes_read = ::read(boundary_pipe[0], &marker, 1);
        } while (bytes_read < 0 && errno == EINTR);
        boundary_observed = bytes_read == 1;
      }
      (void)::close(boundary_pipe[0]);
      return {BoundedSubprocessOutcome::kExited, child, status,
              boundary_observed};
    }
    if (waited < 0 && errno != EINTR) {
      const int error = errno;
      (void)::close(boundary_pipe[0]);
      throw std::system_error(error, std::generic_category(), "waitpid");
    }

    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      (void)::kill(child, SIGKILL);
      while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
      }
      (void)::close(boundary_pipe[0]);
      return {boundary_observed
                  ? BoundedSubprocessOutcome::kTimedOutAfterBoundary
                  : BoundedSubprocessOutcome::kTimedOutBeforeBoundary,
              child, status, boundary_observed};
    }

    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    const int poll_timeout = static_cast<int>(
        std::clamp(remaining.count(), std::int64_t{1}, std::int64_t{10}));
    pollfd descriptor{boundary_pipe[0], POLLIN, 0};
    const int polled = ::poll(&descriptor, 1, poll_timeout);
    if (polled < 0 && errno != EINTR) {
      const int error = errno;
      (void)::kill(child, SIGKILL);
      while (::waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
      }
      (void)::close(boundary_pipe[0]);
      throw std::system_error(error, std::generic_category(), "poll");
    }
    if (!boundary_observed && polled > 0 &&
        (descriptor.revents & POLLIN) != 0) {
      char marker = 0;
      ssize_t bytes_read = 0;
      do {
        bytes_read = ::read(boundary_pipe[0], &marker, 1);
      } while (bytes_read < 0 && errno == EINTR);
      if (bytes_read == 1) {
        boundary_observed = true;
        deadline = std::chrono::steady_clock::now() + completion_timeout;
      }
    }
  }
}

void ExpectAuditRetentionFailureRollsBackViewerCreation(
    const char* retention_trigger,
    AuditRetentionFailurePoint failure_point =
        AuditRetentionFailurePoint::kDatabaseTrigger) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state, 5U, 80U});
  ASSERT_TRUE(store.ok()) << store.error().message;
  ASSERT_TRUE(store.value()
                  ->InitializeDevice(MakeBootstrapRecord(), [] {
                    return camera_firmware::common::Result<void>::Ok();
                  })
                  .ok());
  ExecuteDatabaseSql(store.value()->database_path(), R"sql(
INSERT INTO audit_events
  (server_timestamp_seconds, event_type, outcome, actor_user_id,
   actor_identity, peer_ip, detail_code)
VALUES
  (1720000001, 'seed_one', 'success', NULL, 'system', '192.0.2.1', ''),
  (1720000002, 'seed_two', 'success', NULL, 'system', '192.0.2.2', ''),
  (1720000003, 'seed_three', 'success', NULL, 'system', '192.0.2.3', ''),
  (1720000004, 'seed_four', 'success', NULL, 'system', '192.0.2.4', '');
)sql");
  if (retention_trigger[0] != '\0') {
    ExecuteDatabaseSql(store.value()->database_path(), retention_trigger);
  }

  std::int64_t administrator_id = QueryDatabaseInt(
      store.value()->database_path(),
      "SELECT id FROM users WHERE role = 'administrator';");
  if (failure_point == AuditRetentionFailurePoint::kActorSnapshotLookup) {
    administrator_id = QueryDatabaseInt(
        store.value()->database_path(),
        "SELECT COALESCE(MAX(id), 0) + 2 FROM users;");
  }
  UserManagementDependencies dependencies;
  dependencies.now_seconds = [] { return 1720000100; };
  dependencies.random_bytes = [](std::size_t size) {
    return camera_firmware::common::Result<
        camera_firmware::common::SecureBytes>::Ok(FilledBytes(size, 0x5aU));
  };
  UserManagementService service(*store.value(), {}, std::move(dependencies));
  UserMutationContext administrator{
      {administrator_id, "operator.one", UserRole::kAdministrator, {}},
      "2001:db8::10"};

  fail_commit = failure_point == AuditRetentionFailurePoint::kCallerCommit;
  auto created = service.CreateViewer("Monitor.West", Secret("SouthMoon!8"),
                                      administrator);
  fail_commit = false;

  ASSERT_FALSE(created.ok());
  EXPECT_EQ(created.error().code, "E_USER_MANAGEMENT_UNAVAILABLE");
  EXPECT_EQ(store.value()->State().value(), DeviceState::kOperational);
  EXPECT_EQ(QueryDatabaseInt(store.value()->database_path(),
                             "SELECT COUNT(*) FROM users;"),
            1);
  EXPECT_EQ(QueryDatabaseInt(
                store.value()->database_path(),
                "SELECT COUNT(*) FROM users WHERE canonical_username = "
                "'monitor.west';"),
            0);
  EXPECT_EQ(QueryDatabaseInt(store.value()->database_path(),
                             "SELECT COUNT(*) FROM audit_events;"),
            5);
  EXPECT_EQ(QueryDatabaseTextRows(
                store.value()->database_path(),
                "SELECT sequence || '|' || event_type FROM audit_events "
                "ORDER BY sequence;"),
            (std::vector<std::string>{"1|bootstrap_completed", "2|seed_one",
                                      "3|seed_two", "4|seed_three",
                                      "5|seed_four"}));
  EXPECT_EQ(QueryDatabaseInt(store.value()->database_path(),
                             "SELECT rotated_event_count FROM audit_state;"),
            0);
  EXPECT_EQ(QueryDatabaseInt(
                store.value()->database_path(),
                "SELECT last_rotation_at_seconds IS NULL AND "
                "last_rotated_sequence IS NULL FROM audit_state;"),
            1);
  EXPECT_EQ(QueryDatabaseInt(
                store.value()->database_path(),
                "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                "'viewer_created';"),
            0);
}

PasswordRecord MakePrecomputedPasswordRecord(unsigned char salt_byte,
                                             unsigned char derived_byte) {
  PasswordRecord password;
  password.salt =
      FilledBytes(camera_firmware::security::kPasswordSaltBytes, salt_byte);
  password.derived = FilledBytes(
      camera_firmware::security::kPasswordDerivedBytes, derived_byte);
  return password;
}

void RunAuditRetentionConcurrentStoreWriters(
    const std::filesystem::path& state,
    int boundary_descriptor) {
  ResetSqliteHooks();
  auto first_store = SecurityStore::Open({state, 5U, 80U});
  ASSERT_TRUE(first_store.ok()) << first_store.error().message;
  ASSERT_TRUE(first_store.value()
                  ->InitializeDevice(MakeBootstrapRecord(), [] {
                    return camera_firmware::common::Result<void>::Ok();
                  })
                  .ok());
  ExecuteDatabaseSql(first_store.value()->database_path(), R"sql(
INSERT INTO audit_events
  (server_timestamp_seconds, event_type, outcome, actor_user_id,
   actor_identity, peer_ip, detail_code)
VALUES
  (1720000001, 'seed_one', 'success', NULL, 'system', '192.0.2.1', ''),
  (1720000002, 'seed_two', 'success', NULL, 'system', '192.0.2.2', ''),
  (1720000003, 'seed_three', 'success', NULL, 'system', '192.0.2.3', ''),
  (1720000004, 'seed_four', 'success', NULL, 'system', '192.0.2.4', '');
)sql");
  auto second_store = SecurityStore::Open({state, 5U, 80U});
  ASSERT_TRUE(second_store.ok()) << second_store.error().message;

  const std::int64_t administrator_id = QueryDatabaseInt(
      first_store.value()->database_path(),
      "SELECT id FROM users WHERE role = 'administrator';");
  const SecurityMutationContext administrator{
      administrator_id, "operator.one", UserRole::kAdministrator,
      "2001:db8::10"};
  auto first_password = MakePrecomputedPasswordRecord(0x61U, 0x71U);
  auto second_password = MakePrecomputedPasswordRecord(0x62U, 0x72U);
  std::optional<camera_firmware::common::Result<StoredManagedUser>>
      first_result;
  std::optional<camera_firmware::common::Result<StoredManagedUser>>
      second_result;
  SqliteTransactionBoundaryGate gate(2, boundary_descriptor);
  transaction_boundary_gate = &gate;
  std::thread first([&] {
    first_result.emplace(AuditLogServiceTestAccess::InsertViewer(
        *first_store.value(), "monitor.east", "Monitor.East",
        std::move(first_password), 1720000101, administrator));
  });
  std::thread second([&] {
    second_result.emplace(AuditLogServiceTestAccess::InsertViewer(
        *second_store.value(), "monitor.west", "Monitor.West",
        std::move(second_password), 1720000102, administrator));
  });

  first.join();
  second.join();
  transaction_boundary_gate = nullptr;

  ASSERT_EQ(gate.arrivals(), 2);
  ASSERT_TRUE(first_result.has_value());
  ASSERT_TRUE(second_result.has_value());
  ASSERT_TRUE(first_result->ok()) << first_result->error().message;
  ASSERT_TRUE(second_result->ok()) << second_result->error().message;
}

}  // namespace

void ConfigureSecurityStoreTransactionFailuresForTest(bool commit,
                                                       bool rollback) {
  fail_commit = commit;
  fail_rollback = rollback;
}

extern "C" int __wrap_lstat(const char* path, struct stat* status) {
  const int result = __real_lstat(path, status);
  if (result == 0 && spoofed_owner_path.has_value() &&
      std::filesystem::path(path) == *spoofed_owner_path) {
    status->st_uid = ::geteuid() == 0 ? 1 : 0;
  }
  return result;
}

extern "C" int __wrap_sqlite3_open_v2(const char* filename,
                                       sqlite3** database,
                                       int flags,
                                       const char* vfs_name) {
  last_sqlite_open_flags = flags;
  if (before_sqlite_open) {
    before_sqlite_open(filename, flags);
  }
  const int result =
      __real_sqlite3_open_v2(filename, database, flags, vfs_name);
  last_opened_database = database == nullptr ? nullptr : *database;
  return result;
}

extern "C" int __wrap_sqlite3_busy_timeout(sqlite3* database,
                                            int milliseconds) {
  if (fail_busy_timeout) {
    return SQLITE_ERROR;
  }
  return __real_sqlite3_busy_timeout(database, milliseconds);
}

extern "C" int __wrap_sqlite3_close_v2(sqlite3* database) {
  ++sqlite_close_calls;
  return __real_sqlite3_close_v2(database);
}

extern "C" int __wrap_sqlite3_exec(
    sqlite3* database,
    const char* statement,
    int (*callback)(void*, int, char**, char**),
    void* context,
    char** error_message) {
  const std::string_view sql = statement == nullptr ? "" : statement;
  if (sql == "BEGIN IMMEDIATE;" && transaction_boundary_gate != nullptr) {
    transaction_boundary_gate->ArriveAndWait();
  }
  if (sql == "ROLLBACK;") {
    ++rollback_calls;
  }
  if (ObserveMigrationExec(sql)) {
    if (error_message != nullptr) {
      *error_message = ::sqlite3_mprintf("injected migration statement failure");
    }
    return SQLITE_IOERR;
  }
  if (fail_sqlite_exec_exact.has_value() &&
      sql == *fail_sqlite_exec_exact) {
    if (fail_sqlite_exec_exact_after_matches > 0) {
      --fail_sqlite_exec_exact_after_matches;
    } else {
      if (error_message != nullptr) {
        *error_message = ::sqlite3_mprintf("injected statement failure");
      }
      return SQLITE_IOERR;
    }
  }
  if ((sql == "COMMIT;" && fail_commit) ||
      (sql == "ROLLBACK;" && fail_rollback)) {
    if (error_message != nullptr) {
      *error_message = ::sqlite3_mprintf("injected transaction failure");
    }
    return SQLITE_IOERR;
  }
  return __real_sqlite3_exec(database, statement, callback, context,
                             error_message);
}

TEST(SecurityStoreTest, CreatesProtectedStateAndSchema) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = [&state] {
    ScopedUmask restrictive_umask(0777);
    return SecurityStore::Open({state});
  }();
  ASSERT_TRUE(store.ok()) << store.error().message;
  EXPECT_EQ(FileMode(state), 0700);
  EXPECT_EQ(FileMode(state / "security.db"), 0600);

  auto device_state = store.value()->State();
  ASSERT_TRUE(device_state.ok()) << device_state.error().message;
  EXPECT_EQ(device_state.value(), DeviceState::kDefault);
}

TEST(SecurityStoreTest, RejectsSymlinkAndPermissiveDatabase) {
  ExpectStoreErrorWithSymlink("E_SECURITY_DB_PATH");
  ExpectStoreErrorWithMode(0640, "E_SECURITY_DB_MODE");
}

TEST(SecurityStoreTest, RejectsSymlinkAndPermissiveStateDirectory) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  const auto target = root.Path("target");
  MakeDirectory(target);
  ASSERT_EQ(::symlink(target.c_str(), state.c_str()), 0);
  auto store = SecurityStore::Open({state});
  ASSERT_FALSE(store.ok());
  EXPECT_EQ(store.error().code, "E_SECURITY_DB_PATH");

  TemporaryDirectory permissive_root;
  const auto permissive_state = permissive_root.Path("security");
  ASSERT_EQ(::mkdir(permissive_state.c_str(), 0750), 0);
  store = SecurityStore::Open({permissive_state});
  ASSERT_FALSE(store.ok());
  EXPECT_EQ(store.error().code, "E_SECURITY_STATE_MODE");
}

TEST(SecurityStoreTest, RejectsStateDirectoryNotOwnedByEffectiveUser) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  MakeDirectory(state);
  spoofed_owner_path = state;

  const auto store = SecurityStore::Open({state});

  ResetSqliteHooks();
  ASSERT_FALSE(store.ok());
  EXPECT_EQ(store.error().code, "E_SECURITY_STATE_OWNER");
}

TEST(SecurityStoreTest, RejectsDatabaseNotOwnedByEffectiveUser) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  MakeDirectory(state);
  const auto database = state / "security.db";
  MakeFile(database, 0600);
  spoofed_owner_path = database;

  const auto store = SecurityStore::Open({state});

  ResetSqliteHooks();
  ASSERT_FALSE(store.ok());
  EXPECT_EQ(store.error().code, "E_SECURITY_DB_OWNER");
}

TEST(SecurityStoreTest, SQLiteOpenRejectsPathReplacedBySymlink) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  MakeDirectory(state);
  const auto database = state / "security.db";
  const auto target = root.Path("target.db");
  MakeFile(database, 0600);
  MakeFile(target, 0600);
  before_sqlite_open = [&](const char* filename, int) {
    ASSERT_EQ(std::filesystem::path(filename), database);
    ASSERT_EQ(::unlink(database.c_str()), 0);
    ASSERT_EQ(::symlink(target.c_str(), database.c_str()), 0);
  };

  const auto store = SecurityStore::Open({state});
  const int open_flags = last_sqlite_open_flags;

  ResetSqliteHooks();
  ASSERT_FALSE(store.ok());
  EXPECT_NE(open_flags & SQLITE_OPEN_NOFOLLOW, 0);
  EXPECT_EQ(store.error().code, "E_SECURITY_DB_OPEN");
}

TEST(SecurityStoreTest, BusyTimeoutFailureClosesOpenedDatabase) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  fail_busy_timeout = true;

  const auto store = SecurityStore::Open({root.Path("security")});
  const int close_calls = sqlite_close_calls;

  ResetSqliteHooks();
  ASSERT_FALSE(store.ok());
  EXPECT_EQ(store.error().code, "E_SECURITY_DB_OPEN");
  EXPECT_EQ(close_calls, 1);
}

TEST(SecurityStoreTest, GenericTransactionCommitPreservesDefaultState) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto started = store.value()->BeginTransaction();
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto transaction = std::move(started).value();

  ASSERT_TRUE(transaction.Commit().ok());
  EXPECT_FALSE(transaction.active());
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
}

TEST(SecurityStoreTest, TransactionMoveContractIsConstructionOnly) {
  EXPECT_TRUE(std::is_move_constructible_v<SecurityStore::Transaction>);
  EXPECT_FALSE(std::is_move_assignable_v<SecurityStore::Transaction>);
}

TEST(SecurityStoreTest, GenericTransactionCannotSetOperationalState) {
  EXPECT_FALSE(HasPublicSetDeviceState<SecurityStore::Transaction>);
}

TEST(SecurityStoreTest, StateWaitsForBootstrapConnectionLease) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  std::promise<void> installer_entered;
  std::promise<void> release_installer;
  auto release = release_installer.get_future().share();
  auto initialization = std::async(std::launch::async, [&] {
    return store.value()->InitializeDevice(MakeBootstrapRecord(), [&] {
      installer_entered.set_value();
      release.wait();
      return camera_firmware::common::Result<void>::Ok();
    });
  });
  installer_entered.get_future().wait();

  auto state = std::async(std::launch::async,
                          [&] { return store.value()->State(); });
  auto contender = std::async(std::launch::async, [&] {
    return store.value()->InitializeDevice(MakeBootstrapRecord(), [] {
      return camera_firmware::common::Result<void>::Ok();
    });
  });

  EXPECT_EQ(state.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  EXPECT_EQ(contender.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  release_installer.set_value();
  ASSERT_TRUE(initialization.get().ok());
  auto losing_result = contender.get();
  ASSERT_FALSE(losing_result.ok());
  EXPECT_EQ(losing_result.error().code, "E_BOOTSTRAP_UNAVAILABLE");
  auto committed_state = state.get();
  ASSERT_TRUE(committed_state.ok()) << committed_state.error().message;
  EXPECT_EQ(committed_state.value(), DeviceState::kOperational);
}

TEST(SecurityStoreTest, RollbackFailurePoisonsStoreAndHidesLocalState) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  fail_commit = true;
  fail_rollback = true;

  auto initialized = store.value()->InitializeDevice(
      MakeBootstrapRecord(), [] {
        return camera_firmware::common::Result<void>::Ok();
      });

  fail_commit = false;
  fail_rollback = false;
  ASSERT_FALSE(initialized.ok());
  auto state = store.value()->State();
  ASSERT_FALSE(state.ok());
  EXPECT_EQ(state.error().code, "E_SECURITY_DB_POISONED");
  auto transaction = store.value()->BeginTransaction();
  ASSERT_FALSE(transaction.ok());
  EXPECT_EQ(transaction.error().code, "E_SECURITY_DB_POISONED");
}

TEST(SecurityStoreTest, TransactionCanCommitAfterStoreIsDestroyed) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  std::optional<SecurityStore::Transaction> transaction;
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    auto started = store.value()->BeginTransaction();
    ASSERT_TRUE(started.ok()) << started.error().message;
    transaction.emplace(std::move(started).value());
    store.value().reset();
  }

  ASSERT_TRUE(transaction->Commit().ok());
  transaction.reset();

  auto reopened = SecurityStore::Open({state});
  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  EXPECT_EQ(reopened.value()->State().value(), DeviceState::kDefault);
}

TEST(SecurityStoreTest, TransactionDestructorRollsBackAfterStoreIsDestroyed) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  std::optional<SecurityStore::Transaction> transaction;
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    auto started = store.value()->BeginTransaction();
    ASSERT_TRUE(started.ok()) << started.error().message;
    transaction.emplace(std::move(started).value());
    store.value().reset();
  }

  transaction.reset();

  EXPECT_EQ(rollback_calls, 1);
  auto reopened = SecurityStore::Open({state});
  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  EXPECT_EQ(reopened.value()->State().value(), DeviceState::kDefault);
}

TEST(SecurityStoreTest, GenericTransactionCanRollback) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto started = store.value()->BeginTransaction();
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto transaction = std::move(started).value();

  ASSERT_TRUE(transaction.Rollback().ok());
  EXPECT_FALSE(transaction.active());
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
}

TEST(SecurityStoreTest, TransactionDestructorRollsBackActiveWork) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  {
    auto started = store.value()->BeginTransaction();
    ASSERT_TRUE(started.ok()) << started.error().message;
    auto transaction = std::move(started).value();
  }

  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_EQ(rollback_calls, 1);
}

TEST(SecurityStoreTest, CommitFailureRetainsLeaseUntilRollback) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto started = store.value()->BeginTransaction();
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto transaction = std::move(started).value();
  fail_commit = true;
  const auto commit = transaction.Commit();
  fail_commit = false;
  ASSERT_FALSE(commit.ok());
  EXPECT_EQ(commit.error().code, "E_SECURITY_DB_TRANSACTION");
  EXPECT_TRUE(transaction.active());

  auto state = std::async(std::launch::async,
                          [&] { return store.value()->State(); });
  EXPECT_EQ(state.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);

  ASSERT_TRUE(transaction.Rollback().ok());
  EXPECT_FALSE(transaction.active());
  auto released_state = state.get();
  ASSERT_TRUE(released_state.ok()) << released_state.error().message;
  EXPECT_EQ(released_state.value(), DeviceState::kDefault);
}

TEST(SecurityStoreTest, CreatesExactRevisionFourSchemaAndConfiguresConnection) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  ASSERT_NE(last_opened_database, nullptr);

  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name FROM sqlite_schema "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name;"),
            std::vector<std::string>({"audit_events", "audit_state",
                                      "device_state",
                                      "firmware_log_outbox",
                                      "management_ips", "password_history",
                                      "schema_version", "sessions", "users"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk "
                "FROM pragma_table_info('schema_version') ORDER BY cid;"),
            std::vector<std::string>({"version:INTEGER:1:0"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk "
                "FROM pragma_table_info('device_state') ORDER BY cid;"),
            std::vector<std::string>({
                "id:INTEGER:0:1", "state:TEXT:1:0",
                "schema_revision:INTEGER:1:0",
                "setup_completed_at_seconds:INTEGER:0:0"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk "
                "FROM pragma_table_info('users') ORDER BY cid;"),
            std::vector<std::string>({
                "id:INTEGER:0:1", "canonical_username:TEXT:1:0",
                "display_username:TEXT:1:0", "role:TEXT:1:0",
                "enabled:INTEGER:1:0", "password_algorithm:TEXT:1:0",
                "password_iterations:INTEGER:1:0", "password_salt:BLOB:1:0",
                "password_derived:BLOB:1:0",
                "password_changed_at_seconds:INTEGER:1:0",
                "failed_login_count:INTEGER:1:0",
                "lock_until_seconds:INTEGER:0:0",
                "created_at_seconds:INTEGER:1:0",
                "last_login_at_seconds:INTEGER:0:0"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk "
                "FROM pragma_table_info('management_ips') ORDER BY cid;"),
            std::vector<std::string>({
                "id:INTEGER:0:1", "normalized_ip:TEXT:1:0",
                "role_scope:TEXT:1:0", "enabled:INTEGER:1:0",
                "created_at_seconds:INTEGER:1:0"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk "
                "FROM pragma_table_info('password_history') ORDER BY cid;"),
            std::vector<std::string>({
                "id:INTEGER:0:1", "user_id:INTEGER:1:0",
                "password_algorithm:TEXT:1:0",
                "password_iterations:INTEGER:1:0",
                "password_salt:BLOB:1:0", "password_derived:BLOB:1:0",
                "replaced_at_seconds:INTEGER:1:0"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk "
                "FROM pragma_table_info('sessions') ORDER BY cid;"),
            std::vector<std::string>({
                "id:INTEGER:0:1", "token_hash:BLOB:1:0",
                "user_id:INTEGER:1:0", "role:TEXT:1:0",
                "created_at_seconds:INTEGER:1:0",
                "last_activity_at_seconds:INTEGER:1:0",
                "expires_at_seconds:INTEGER:1:0", "peer_ip:TEXT:1:0"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk "
                "FROM pragma_table_info('audit_events') ORDER BY cid;"),
            std::vector<std::string>({
                "sequence:INTEGER:0:1", "server_timestamp_seconds:INTEGER:1:0",
                "event_type:TEXT:1:0", "outcome:TEXT:1:0",
                "actor_user_id:INTEGER:0:0", "actor_identity:TEXT:1:0",
                "peer_ip:TEXT:1:0",
                "detail_code:TEXT:1:0", "subject_type:TEXT:1:0",
                "subject_identity:TEXT:1:0"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk "
                "FROM pragma_table_info('audit_state') ORDER BY cid;"),
            std::vector<std::string>({
                "id:INTEGER:0:1", "rotated_event_count:INTEGER:1:0",
                "last_rotation_at_seconds:INTEGER:0:0",
                "last_rotated_sequence:INTEGER:0:0"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk "
                "FROM pragma_table_info('firmware_log_outbox') ORDER BY cid;"),
            std::vector<std::string>({
                "id:INTEGER:0:1", "category:TEXT:1:0", "peer_ip:TEXT:1:0",
                "created_at_seconds:INTEGER:1:0", "dirty:INTEGER:1:0",
                "lease_owner:BLOB:0:0", "lease_token:BLOB:0:0",
                "lease_expires_at_seconds:INTEGER:0:0"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name FROM sqlite_schema WHERE type = 'index' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name;"),
            std::vector<std::string>({
                "audit_events_timestamp_index",
                "firmware_log_outbox_category_peer_unique",
                "firmware_log_outbox_lease_expiry_index",
                "management_ips_role_ip_unique",
                "password_history_user_id_unique",
                "sessions_expiry_index",
                "sessions_single_administrator_unique",
                "sessions_token_hash_unique",
                "sessions_user_id_unique",
                "users_canonical_username_unique",
                "users_single_administrator_unique"}));
  EXPECT_NE(QueryText(last_opened_database,
                      "SELECT sql FROM sqlite_schema "
                      "WHERE type = 'table' AND name = 'device_state';")
                .find("CHECK (id = 1)"),
            std::string::npos);
  EXPECT_NE(QueryText(last_opened_database,
                      "SELECT sql FROM sqlite_schema "
                      "WHERE type = 'table' AND name = 'device_state';")
                .find("CHECK (state IN ('default', 'operational'))"),
            std::string::npos);
  EXPECT_EQ(QueryInt(last_opened_database, "SELECT COUNT(*) FROM schema_version;"),
            1);
  EXPECT_EQ(QueryInt(last_opened_database, "SELECT version FROM schema_version;"),
            4);
  EXPECT_EQ(QueryInt(last_opened_database,
                     "SELECT schema_revision FROM device_state WHERE id = 1;"),
            4);
  EXPECT_EQ(QueryText(last_opened_database,
                      "SELECT id || '|' || rotated_event_count || '|' || "
                      "COALESCE(last_rotation_at_seconds, -1) || '|' || "
                      "COALESCE(last_rotated_sequence, -1) FROM audit_state;"),
            "1|0|-1|-1");
  EXPECT_EQ(QueryInt(last_opened_database, "PRAGMA foreign_keys;"), 1);
  EXPECT_EQ(QueryInt(last_opened_database, "PRAGMA secure_delete;"), 1);
  EXPECT_EQ(QueryInt(last_opened_database, "PRAGMA busy_timeout;"), 1000);
}

TEST(SecurityStoreTest, BootstrapTransactionCommitsAllSecurityRows) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  int installer_calls = 0;

  auto initialized = store.value()->InitializeDevice(
      MakeBootstrapRecord(), [&installer_calls] {
        ++installer_calls;
        return camera_firmware::common::Result<void>::Ok();
      });

  ASSERT_TRUE(initialized.ok()) << initialized.error().message;
  EXPECT_EQ(installer_calls, 1);
  EXPECT_EQ(store.value()->State().value(), DeviceState::kOperational);
  EXPECT_EQ(QueryInt(last_opened_database, "SELECT COUNT(*) FROM users;"), 1);
  EXPECT_EQ(QueryInt(last_opened_database,
                     "SELECT COUNT(*) FROM management_ips;"),
            1);
  EXPECT_EQ(QueryInt(last_opened_database,
                     "SELECT COUNT(*) FROM sessions;"),
            0);
  EXPECT_EQ(QueryInt(last_opened_database,
                     "SELECT COUNT(*) FROM audit_events "
                     "WHERE event_type = 'bootstrap_completed' "
                     "AND outcome = 'success';"),
            1);
  EXPECT_EQ(QueryText(last_opened_database,
                      "SELECT canonical_username || '|' || display_username || "
                      "'|' || role || '|' || enabled FROM users;"),
            "operator.one|Operator.One|administrator|1");
  EXPECT_EQ(QueryText(last_opened_database,
                      "SELECT normalized_ip || '|' || role_scope || '|' || "
                      "enabled FROM management_ips;"),
            "2001:db8::10|administrator|1");
  EXPECT_EQ(QueryInt(last_opened_database,
                     "SELECT setup_completed_at_seconds FROM device_state;"),
            1720000000);
  EXPECT_EQ(QueryInt(last_opened_database,
                     "SELECT length(password_salt) FROM users;"),
            16);
  EXPECT_EQ(QueryInt(last_opened_database,
                     "SELECT length(password_derived) FROM users;"),
            32);
  EXPECT_EQ(QueryText(last_opened_database,
                      "SELECT typeof(password_salt) || '|' || "
                      "typeof(password_derived) FROM users;"),
            "blob|blob");
  EXPECT_EQ(QueryText(last_opened_database,
                      "SELECT actor_identity FROM audit_events WHERE "
                      "event_type = 'bootstrap_completed';"),
            "operator.one");
}

TEST(SecurityStoreTest, InstallerFailureRollsBackBootstrapRowsAndState) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;

  auto initialized = store.value()->InitializeDevice(
      MakeBootstrapRecord(), [] {
        return camera_firmware::common::Result<void>::Err(
            {"E_TEST", "installer failed with secret material"});
      });

  ASSERT_FALSE(initialized.ok());
  EXPECT_EQ(initialized.error().code, "E_BOOTSTRAP_CREDENTIAL");
  EXPECT_EQ(initialized.error().message.find("secret"), std::string::npos);
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_EQ(QueryInt(last_opened_database, "SELECT COUNT(*) FROM users;"), 0);
  EXPECT_EQ(QueryInt(last_opened_database,
                     "SELECT COUNT(*) FROM management_ips;"),
            0);
  EXPECT_EQ(QueryInt(last_opened_database,
                     "SELECT COUNT(*) FROM audit_events;"),
            0);
}

TEST(SecurityStoreTest, InstallerExceptionRollsBackBootstrapRowsAndState) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;

  auto initialized = store.value()->InitializeDevice(
      MakeBootstrapRecord(), []() -> camera_firmware::common::Result<void> {
        throw std::runtime_error("secret callback exception");
      });

  ASSERT_FALSE(initialized.ok());
  EXPECT_EQ(initialized.error().code, "E_BOOTSTRAP_CREDENTIAL");
  EXPECT_EQ(initialized.error().message.find("secret"), std::string::npos);
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_EQ(QueryInt(last_opened_database, "SELECT COUNT(*) FROM users;"), 0);
}

TEST(SecurityStoreTest, OperationalStateRejectsBootstrapBeforeInstaller) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  ASSERT_TRUE(store.value()
                  ->InitializeDevice(MakeBootstrapRecord(), [] {
                    return camera_firmware::common::Result<void>::Ok();
                  })
                  .ok());
  int installer_calls = 0;

  auto repeated = store.value()->InitializeDevice(
      MakeBootstrapRecord(), [&installer_calls] {
        ++installer_calls;
        return camera_firmware::common::Result<void>::Ok();
      });

  ASSERT_FALSE(repeated.ok());
  EXPECT_EQ(repeated.error().code, "E_BOOTSTRAP_UNAVAILABLE");
  EXPECT_EQ(installer_calls, 0);
  EXPECT_EQ(QueryInt(last_opened_database, "SELECT COUNT(*) FROM users;"), 1);
}

TEST(SecurityStoreTest, ReopensInitializedSchemaWithoutChangingState) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto first = SecurityStore::Open({state});
    ASSERT_TRUE(first.ok()) << first.error().message;
    ASSERT_TRUE(first.value()
                    ->InitializeDevice(MakeBootstrapRecord(), [] {
                      return camera_firmware::common::Result<void>::Ok();
                    })
                    .ok());
  }

  auto reopened = SecurityStore::Open({state});

  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  EXPECT_EQ(reopened.value()->State().value(), DeviceState::kOperational);
  EXPECT_EQ(QueryInt(last_opened_database, "SELECT COUNT(*) FROM schema_version;"),
            1);
}

TEST(SecurityStoreTest,
     ReopensOperationalSchemaAfterBootstrapAuditEvidenceRotates) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto store = SecurityStore::Open({state, 1U, 80U});
    ASSERT_TRUE(store.ok()) << store.error().message;
    ASSERT_TRUE(store.value()
                    ->InitializeDevice(MakeBootstrapRecord(), [] {
                      return camera_firmware::common::Result<void>::Ok();
                    })
                    .ok());
    AuthService auth(*store.value());

    auto login = auth.Login(
        LoginRequest{"missing.user", Secret("BadSecret!9"), "192.0.2.20"});

    ASSERT_FALSE(login.ok());
    EXPECT_EQ(QueryInt(last_opened_database,
                       "SELECT COUNT(*) FROM audit_events;"),
              1);
    EXPECT_EQ(QueryInt(last_opened_database,
                       "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                       "'bootstrap_completed' AND outcome = 'success';"),
              0);
    EXPECT_EQ(QueryTextRows(last_opened_database,
                            "SELECT rotated_event_count || '|' || "
                            "last_rotated_sequence FROM audit_state;"),
              std::vector<std::string>({"1|1"}));
  }

  auto reopened = SecurityStore::Open({state, 1U, 80U});

  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  EXPECT_EQ(reopened.value()->State().value(), DeviceState::kOperational);
}

TEST(SecurityStoreTest, MigratesExactRevisionTwoDatabaseToRevisionFour) {
  ResetSqliteHooks();
  RevisionTwoOperationalFixture fixture;
  const auto before = fixture.evidence();

  auto opened = SecurityStore::Open({fixture.state_directory()});

  ASSERT_TRUE(opened.ok()) << opened.error().message;
  opened.value().reset();
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT version FROM schema_version;"),
            4);
  EXPECT_EQ(QueryDatabaseInt(
                fixture.database_path(),
                "SELECT schema_revision FROM device_state WHERE id = 1;"),
            4);
  EXPECT_EQ(fixture.evidence(), before);
  EXPECT_EQ(QueryDatabaseInt(
                fixture.database_path(),
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' "
                "AND name = 'password_history';"),
            1);
  EXPECT_EQ(QueryDatabaseInt(
                fixture.database_path(),
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'index' "
                "AND name IN ('password_history_user_id_unique', "
                "'management_ips_role_ip_unique', "
                "'sessions_user_id_unique');"),
            3);
  EXPECT_EQ(QueryDatabaseInt(
                fixture.database_path(),
                "SELECT COUNT(*) FROM audit_events "
                "WHERE subject_type = '' AND subject_identity = '';"),
            2);
  EXPECT_EQ(QueryDatabaseTextRows(
                fixture.database_path(),
                "SELECT actor_identity FROM audit_events ORDER BY sequence;"),
            std::vector<std::string>({"operator.one", "viewer.one"}));
  EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
}

TEST(SecurityStoreTest, MigratesExactRevisionThreeDatabaseToRevisionFour) {
  ResetSqliteHooks();
  RevisionThreeOperationalFixture fixture;

  auto opened = SecurityStore::Open({fixture.state_directory()});

  ASSERT_TRUE(opened.ok()) << opened.error().message;
  opened.value().reset();
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT version FROM schema_version;"),
            4);
  EXPECT_EQ(QueryDatabaseInt(
                fixture.database_path(),
                "SELECT schema_revision FROM device_state WHERE id = 1;"),
            4);
  EXPECT_EQ(QueryDatabaseTextRows(
                fixture.database_path(),
                "SELECT sequence || '|' || server_timestamp_seconds || '|' || "
                "event_type || '|' || outcome || '|' || "
                "COALESCE(actor_user_id, -1) || '|' || actor_identity || '|' || "
                "peer_ip || '|' || detail_code || '|' || subject_type || '|' || "
                "subject_identity FROM audit_events ORDER BY sequence;"),
            std::vector<std::string>({
                "41|1720000000|bootstrap_completed|success|11|cameraowner|"
                "2001:db8::10|initial_administrator||",
                "42|1720000010|login_completed|success|12|viewer.one|"
                "198.51.100.10|session_created||",
                "73|1720000025|viewer_disabled|failure|-1|unknown|"
                "198.51.100.11|legacy_deleted_actor|user|viewer.one"}));
  EXPECT_EQ(QueryDatabaseTextRows(
                fixture.database_path(),
                "SELECT id || '|' || rotated_event_count || '|' || "
                "COALESCE(last_rotation_at_seconds, -1) || '|' || "
                "COALESCE(last_rotated_sequence, -1) FROM audit_state;"),
            std::vector<std::string>({"1|0|-1|-1"}));
  EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
}

TEST(SecurityStoreTest,
     MigratesRevisionThreeOrphanedAuditActorToUnknownIdentity) {
  ResetSqliteHooks();
  RevisionThreeOrphanedAuditActorFixture fixture;
  EXPECT_EQ(QueryDatabaseTextRows(
                fixture.database_path(),
                "SELECT \"table\" || '|' || rowid || '|' || parent || '|' || "
                "fkid FROM pragma_foreign_key_check;"),
            std::vector<std::string>({"audit_events|74|users|0"}));

  auto opened = SecurityStore::Open({fixture.state_directory()});

  ASSERT_TRUE(opened.ok()) << opened.error().message;
  opened.value().reset();
  EXPECT_EQ(QueryDatabaseTextRows(
                fixture.database_path(),
                "SELECT sequence || '|' || server_timestamp_seconds || '|' || "
                "event_type || '|' || outcome || '|' || "
                "COALESCE(actor_user_id, -1) || '|' || actor_identity || '|' || "
                "peer_ip || '|' || detail_code || '|' || subject_type || '|' || "
                "subject_identity FROM audit_events WHERE sequence = 74;"),
            std::vector<std::string>({
                "74|1720000030|viewer_deleted|failure|-1|unknown|"
                "203.0.113.7|legacy_orphan_actor|user|retired.viewer"}));
  EXPECT_EQ(QueryDatabaseTextRows(
                fixture.database_path(),
                "SELECT sequence || '|' || actor_user_id || '|' || "
                "actor_identity FROM audit_events "
                "WHERE sequence IN (41, 42) ORDER BY sequence;"),
            (std::vector<std::string>{"41|11|cameraowner",
                                      "42|12|viewer.one"}));
  EXPECT_EQ(QueryDatabaseInt(
                fixture.database_path(),
                "SELECT COUNT(*) FROM pragma_foreign_key_check;"),
            0);
  EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
}

TEST(SecurityStoreTest,
     RevisionThreeMigrationRejectsNonAuditForeignKeyViolation) {
  ResetSqliteHooks();
  RevisionThreeOperationalFixture fixture;
  ExecuteDatabaseSql(fixture.database_path(), R"sql(
PRAGMA foreign_keys=OFF;
UPDATE sessions SET user_id = 999 WHERE id = 32;
)sql");

  auto opened = SecurityStore::Open({fixture.state_directory()});

  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_SECURITY_DB_SCHEMA");
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT version FROM schema_version;"),
            3);
}

TEST(SecurityStoreTest, RevisionThreeSchemaEnforcesUserManagementConstraints) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    ASSERT_TRUE(store.value()
                    ->InitializeDevice(MakeBootstrapRecord(), [] {
                      return camera_firmware::common::Result<void>::Ok();
                    })
                    .ok());
  }
  const auto database = state / "security.db";
  ExecuteDatabaseSql(database, R"sql(
INSERT INTO users
  (canonical_username, display_username, role, enabled,
   password_algorithm, password_iterations, password_salt, password_derived,
   password_changed_at_seconds, failed_login_count, created_at_seconds)
VALUES ('viewer.one', 'Viewer.One', 'viewer', 1, 'pbkdf2-hmac-sha256',
        600000, zeroblob(16), zeroblob(32), 2, 0, 2);
INSERT INTO password_history
  (user_id, password_algorithm, password_iterations, password_salt,
   password_derived, replaced_at_seconds)
SELECT id, 'pbkdf2-hmac-sha256', 600000, randomblob(16), randomblob(32), 3
FROM users WHERE canonical_username = 'viewer.one';
INSERT INTO management_ips
  (normalized_ip, role_scope, enabled, created_at_seconds)
VALUES ('2001:db8::10', 'viewer', 1, 3);
INSERT INTO sessions
  (token_hash, user_id, role, created_at_seconds, last_activity_at_seconds,
   expires_at_seconds, peer_ip)
SELECT randomblob(32), id, 'viewer', 3, 3, 4, '2001:db8::10'
FROM users WHERE canonical_username = 'viewer.one';
INSERT INTO audit_events
  (server_timestamp_seconds, event_type, outcome, actor_user_id,
   actor_identity, peer_ip, detail_code)
SELECT 3, 'viewer_created', 'success', id, canonical_username,
       '2001:db8::10', 'created'
FROM users WHERE canonical_username = 'operator.one';
)sql");

  EXPECT_TRUE(DatabaseStatementIsRejected(database, R"sql(
INSERT INTO management_ips
  (normalized_ip, role_scope, enabled, created_at_seconds)
VALUES ('2001:db8::10', 'viewer', 1, 4);
)sql"));
  EXPECT_TRUE(DatabaseStatementIsRejected(database, R"sql(
INSERT INTO password_history
  (user_id, password_algorithm, password_iterations, password_salt,
   password_derived, replaced_at_seconds)
SELECT id, 'pbkdf2-hmac-sha256', 600000, randomblob(16), randomblob(32), 4
FROM users WHERE canonical_username = 'viewer.one';
)sql"));
  EXPECT_TRUE(DatabaseStatementIsRejected(database, R"sql(
INSERT INTO sessions
  (token_hash, user_id, role, created_at_seconds, last_activity_at_seconds,
   expires_at_seconds, peer_ip)
SELECT randomblob(32), id, 'viewer', 4, 4, 5, '2001:db8::10'
FROM users WHERE canonical_username = 'viewer.one';
)sql"));
  EXPECT_TRUE(DatabaseStatementIsRejected(database, R"sql(
INSERT INTO audit_events
  (server_timestamp_seconds, event_type, outcome, actor_identity, peer_ip,
   detail_code, subject_type, subject_identity)
VALUES (4, 'viewer_created', 'success', 'system', '2001:db8::10', 'created',
        printf('%065d', 0), 'viewer.one');
)sql"));
  EXPECT_TRUE(DatabaseStatementIsRejected(database, R"sql(
INSERT INTO audit_events
  (server_timestamp_seconds, event_type, outcome, actor_identity, peer_ip,
   detail_code, subject_type, subject_identity)
VALUES (4, 'viewer_created', 'success', 'system', '2001:db8::10', 'created',
        'user', printf('%065d', 0));
)sql"));
  EXPECT_EQ(QueryDatabaseInt(
                database,
                "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                "'viewer_created' AND subject_type = '' AND "
                "subject_identity = '';"),
            1);
  EXPECT_TRUE(SecurityStore::Open({state}).ok());
}

TEST(SecurityStoreTest,
     ManagementIpSchemaScopesUniquenessByRoleRegardlessOfEnabledState) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    ASSERT_TRUE(store.value()
                    ->InitializeDevice(MakeBootstrapRecord(), [] {
                      return camera_firmware::common::Result<void>::Ok();
                    })
                    .ok());
  }
  const auto database = state / "security.db";

  ExecuteDatabaseSql(database, R"sql(
INSERT INTO management_ips
  (normalized_ip, role_scope, enabled, created_at_seconds)
VALUES ('2001:db8::10', 'viewer', 0, 1720000001);
)sql");

  EXPECT_TRUE(DatabaseStatementIsRejected(database, R"sql(
INSERT INTO management_ips
  (normalized_ip, role_scope, enabled, created_at_seconds)
VALUES ('2001:db8::10', 'viewer', 1, 1720000002);
)sql"));
  EXPECT_EQ(QueryDatabaseInt(
                database,
                "SELECT COUNT(*) FROM management_ips WHERE normalized_ip = "
                "'2001:db8::10';"),
            2);
  EXPECT_TRUE(SecurityStore::Open({state}).ok());
}

TEST(SecurityStoreTest,
     ManagementIpValidatorCountsDisabledRowsTowardPerRoleLimit) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    ASSERT_TRUE(store.value()
                    ->InitializeDevice(MakeBootstrapRecord(), [] {
                      return camera_firmware::common::Result<void>::Ok();
                    })
                    .ok());
  }
  ExecuteDatabaseSql(state / "security.db", R"sql(
WITH RECURSIVE numbers(value) AS (
  SELECT 1 UNION ALL SELECT value + 1 FROM numbers WHERE value < 33
)
INSERT INTO management_ips
  (normalized_ip, role_scope, enabled, created_at_seconds)
SELECT '198.51.100.' || value, 'viewer', 0, 1720000001 FROM numbers;
)sql");

  auto reopened = SecurityStore::Open({state});

  ASSERT_FALSE(reopened.ok());
  EXPECT_EQ(reopened.error().code, "E_SECURITY_DB_SCHEMA");
}

TEST(SecurityStoreTest, RevisionThreeValidatorRejectsMoreThanThirtyTwoViewers) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    ASSERT_TRUE(store.value()
                    ->InitializeDevice(MakeBootstrapRecord(), [] {
                      return camera_firmware::common::Result<void>::Ok();
                    })
                    .ok());
  }
  ExecuteDatabaseSql(state / "security.db", R"sql(
WITH RECURSIVE numbers(value) AS (
  SELECT 1 UNION ALL SELECT value + 1 FROM numbers WHERE value < 33
)
INSERT INTO users
  (canonical_username, display_username, role, enabled,
   password_algorithm, password_iterations, password_salt, password_derived,
   password_changed_at_seconds, failed_login_count, created_at_seconds)
SELECT printf('viewer.%02d', value), printf('Viewer.%02d', value), 'viewer', 1,
       'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), 2, 0, 2
FROM numbers;
)sql");

  auto reopened = SecurityStore::Open({state});

  ASSERT_FALSE(reopened.ok());
  EXPECT_EQ(reopened.error().code, "E_SECURITY_DB_SCHEMA");
}

TEST(SecurityStoreTest,
     RevisionThreeValidatorRejectsMoreThanThirtyTwoManagementIpsPerRole) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    ASSERT_TRUE(store.value()
                    ->InitializeDevice(MakeBootstrapRecord(), [] {
                      return camera_firmware::common::Result<void>::Ok();
                    })
                    .ok());
  }
  ExecuteDatabaseSql(state / "security.db", R"sql(
WITH RECURSIVE numbers(value) AS (
  SELECT 1 UNION ALL SELECT value + 1 FROM numbers WHERE value < 33
)
INSERT INTO management_ips
  (normalized_ip, role_scope, enabled, created_at_seconds)
SELECT '192.0.2.' || value, 'viewer', 1, 2 FROM numbers;
)sql");

  auto reopened = SecurityStore::Open({state});

  ASSERT_FALSE(reopened.ok());
  EXPECT_EQ(reopened.error().code, "E_SECURITY_DB_SCHEMA");
}

TEST(SecurityStoreTest, RevisionThreeValidatorRejectsMutatedManagementIndexes) {
  ExpectReopenRejectsSchemaMutation(R"sql(
DROP INDEX management_ips_role_ip_unique;
CREATE UNIQUE INDEX management_ips_role_ip_unique
  ON management_ips(normalized_ip);
)sql");
  ExpectReopenRejectsSchemaMutation(R"sql(
DROP INDEX password_history_user_id_unique;
CREATE INDEX password_history_user_id_unique ON password_history(user_id);
)sql");
  ExpectReopenRejectsSchemaMutation(
      "DROP INDEX sessions_user_id_unique;");
}

TEST(SecurityStoreTest, FreshAndMigratedRevisionFourUseExactSameSchema) {
  ResetSqliteHooks();
  TemporaryDirectory fresh_root;
  const auto fresh_state = fresh_root.Path("security");
  {
    auto fresh = SecurityStore::Open({fresh_state});
    ASSERT_TRUE(fresh.ok()) << fresh.error().message;
  }
  RevisionTwoOperationalFixture migrated_fixture;
  {
    auto migrated =
        SecurityStore::Open({migrated_fixture.state_directory()});
    ASSERT_TRUE(migrated.ok()) << migrated.error().message;
  }
  constexpr const char* kSchemaInventorySql =
      "SELECT type || '|' || name || '|' || tbl_name || '|' || sql "
      "FROM sqlite_schema ORDER BY type, name;";

  EXPECT_EQ(QueryDatabaseTextRows(fresh_state / "security.db",
                                  kSchemaInventorySql),
            QueryDatabaseTextRows(migrated_fixture.database_path(),
                                  kSchemaInventorySql));
}

TEST(SecurityStoreTest,
     RevisionFourValidatorRejectsMutatedActorIdentityConstraint) {
  ExpectReopenRejectsSchemaMutation(R"sql(
PRAGMA foreign_keys=OFF;
ALTER TABLE audit_events RENAME TO audit_events_old;
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY,
  server_timestamp_seconds INTEGER NOT NULL
    CHECK (server_timestamp_seconds >= 0),
  event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  actor_identity TEXT NOT NULL,
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45),
  detail_code TEXT NOT NULL CHECK (length(detail_code) <= 64),
  subject_type TEXT NOT NULL DEFAULT '' CHECK (length(subject_type) <= 64),
  subject_identity TEXT NOT NULL DEFAULT ''
    CHECK (length(subject_identity) <= 64)
);
INSERT INTO audit_events SELECT * FROM audit_events_old;
DROP TABLE audit_events_old;
CREATE INDEX audit_events_timestamp_index
  ON audit_events(server_timestamp_seconds);
)sql");
}

TEST(SecurityStoreTest, RevisionFourValidatorRejectsMutatedAuditForeignKey) {
  ExpectReopenRejectsSchemaMutation(R"sql(
PRAGMA foreign_keys=OFF;
ALTER TABLE audit_events RENAME TO audit_events_old;
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY,
  server_timestamp_seconds INTEGER NOT NULL
    CHECK (server_timestamp_seconds >= 0),
  event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
  actor_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  actor_identity TEXT NOT NULL
    CHECK (length(actor_identity) BETWEEN 1 AND 64),
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45),
  detail_code TEXT NOT NULL CHECK (length(detail_code) <= 64),
  subject_type TEXT NOT NULL DEFAULT '' CHECK (length(subject_type) <= 64),
  subject_identity TEXT NOT NULL DEFAULT ''
    CHECK (length(subject_identity) <= 64)
);
INSERT INTO audit_events SELECT * FROM audit_events_old;
DROP TABLE audit_events_old;
CREATE INDEX audit_events_timestamp_index
  ON audit_events(server_timestamp_seconds);
)sql");
}

TEST(SecurityStoreTest, RevisionFourValidatorRejectsOrphanedAuditActor) {
  ExpectOperationalReopenRejectsDataMutation(R"sql(
PRAGMA foreign_keys=OFF;
INSERT INTO audit_events
  (server_timestamp_seconds, event_type, outcome, actor_user_id,
   actor_identity, peer_ip, detail_code)
VALUES (1720000001, 'login_completed', 'success', 999, 'unknown',
        '192.0.2.20', 'legacy_orphan_actor');
)sql");
}

TEST(SecurityStoreTest, RevisionFourValidatorRejectsMutatedTimestampIndex) {
  ExpectReopenRejectsSchemaMutation(R"sql(
DROP INDEX audit_events_timestamp_index;
CREATE INDEX audit_events_timestamp_index ON audit_events(sequence);
)sql");
}

TEST(SecurityStoreTest, RevisionFourValidatorRejectsMutatedAuditStateCheck) {
  ExpectReopenRejectsSchemaMutation(R"sql(
ALTER TABLE audit_state RENAME TO audit_state_old;
CREATE TABLE audit_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  rotated_event_count INTEGER NOT NULL DEFAULT 0
    CHECK (rotated_event_count >= 0),
  last_rotation_at_seconds INTEGER
    CHECK (last_rotation_at_seconds >= 0),
  last_rotated_sequence INTEGER
    CHECK (last_rotated_sequence >= 0)
);
INSERT INTO audit_state SELECT * FROM audit_state_old;
DROP TABLE audit_state_old;
)sql");
}

TEST(SecurityStoreTest,
     RevisionFourValidatorRejectsMissingExtraAndInvalidAuditStateRows) {
  ExpectReopenRejectsSchemaMutation("DELETE FROM audit_state;");
  ExpectReopenRejectsSchemaMutation(R"sql(
PRAGMA ignore_check_constraints=ON;
INSERT INTO audit_state (id) VALUES (2);
)sql");
  ExpectReopenRejectsSchemaMutation(R"sql(
PRAGMA ignore_check_constraints=ON;
UPDATE audit_state SET rotated_event_count = -1 WHERE id = 1;
)sql");
  ExpectReopenRejectsSchemaMutation(R"sql(
PRAGMA ignore_check_constraints=ON;
UPDATE audit_state SET last_rotation_at_seconds = 1,
                       last_rotated_sequence = NULL
WHERE id = 1;
)sql");
}

TEST(SecurityStoreTest, ProductionAuditWritesSnapshotActorIdentities) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  ASSERT_TRUE(store.value()
                  ->InitializeDevice(MakeBootstrapRecord(), [] {
                    return camera_firmware::common::Result<void>::Ok();
                  })
                  .ok());
  const auto administrator_id = QueryInt(
      last_opened_database,
      "SELECT id FROM users WHERE canonical_username = 'operator.one';");
  std::int64_t now_seconds = 1720000100;
  int verification_calls = 0;
  UserManagementDependencies dependencies;
  dependencies.now_seconds = [&now_seconds] { return now_seconds++; };
  dependencies.random_bytes = [](std::size_t size) {
    return camera_firmware::common::Result<
        camera_firmware::common::SecureBytes>::Ok(FilledBytes(size, 0x44U));
  };
  dependencies.verify_password =
      [&verification_calls](const camera_firmware::common::SecureBytes&,
                            const PasswordRecord&) {
        return camera_firmware::common::Result<bool>::Ok(
            ++verification_calls == 1);
      };
  UserManagementService service(*store.value(), {}, std::move(dependencies));
  UserMutationContext administrator{
      {administrator_id, "spoofed.administrator", UserRole::kAdministrator,
       {}},
      "2001:db8::10"};

  auto created = service.CreateViewer("Monitor.East", Secret("SouthMoon!8"),
                                      administrator);
  ASSERT_TRUE(created.ok()) << created.error().message;
  const std::int64_t viewer_id = created.value().id;
  EXPECT_EQ(QueryText(last_opened_database,
                      "SELECT actor_identity FROM audit_events WHERE "
                      "event_type = 'viewer_created' AND outcome = 'success';"),
            "operator.one");

  UserMutationContext viewer{
      {viewer_id, "spoofed.viewer", UserRole::kViewer, {}}, "192.0.2.22"};
  auto changed = service.ChangeOwnPassword(
      Secret("SouthMoon!8"), Secret("Crimson!7"), viewer);
  ASSERT_TRUE(changed.ok()) << changed.error().message;
  EXPECT_EQ(QueryText(last_opened_database,
                      "SELECT actor_user_id || '|' || actor_identity FROM "
                      "audit_events WHERE event_type = 'password_changed' "
                      "AND outcome = 'success';"),
            std::to_string(viewer_id) + "|monitor.east");

  ASSERT_TRUE(service.DeleteViewer(viewer_id, administrator).ok());
  EXPECT_EQ(QueryText(last_opened_database,
                      "SELECT COALESCE(actor_user_id, -1) || '|' || "
                      "actor_identity FROM audit_events WHERE event_type = "
                      "'password_changed' AND outcome = 'success';"),
            "-1|monitor.east");
  EXPECT_EQ(QueryText(last_opened_database,
                      "SELECT actor_identity FROM audit_events WHERE "
                      "event_type = 'viewer_deleted' AND outcome = 'success';"),
            "operator.one");
}

TEST(SecurityStoreTest, ProductionNullActorWriteSnapshotsSystemIdentity) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  ASSERT_TRUE(store.value()
                  ->InitializeDevice(MakeBootstrapRecord(), [] {
                    return camera_firmware::common::Result<void>::Ok();
                  })
                  .ok());
  AuthService auth(*store.value());

  auto login = auth.Login(
      LoginRequest{"missing.user", Secret("BadSecret!9"), "2001:db8::10"});

  ASSERT_FALSE(login.ok());
  EXPECT_EQ(QueryText(last_opened_database,
                      "SELECT COALESCE(actor_user_id, -1) || '|' || "
                      "actor_identity FROM audit_events WHERE event_type = "
                      "'authentication_failed';"),
            "-1|system");
}

TEST(SecurityStoreTest,
     AuditRetentionDeleteTriggerFailureRollsBackCallerMutation) {
  ExpectAuditRetentionFailureRollsBackViewerCreation(R"sql(
CREATE TRIGGER reject_audit_delete
BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'injected audit deletion failure');
END;
)sql");
}

TEST(SecurityStoreTest,
     AuditRetentionDeleteCountMismatchRollsBackCallerMutation) {
  ExpectAuditRetentionFailureRollsBackViewerCreation(R"sql(
CREATE TRIGGER ignore_audit_delete
BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(IGNORE);
END;
)sql");
}

TEST(SecurityStoreTest,
     AuditRetentionStateTriggerFailureRollsBackCallerMutationAndDeletion) {
  ExpectAuditRetentionFailureRollsBackViewerCreation(R"sql(
CREATE TRIGGER reject_audit_state_update
BEFORE UPDATE OF rotated_event_count ON audit_state
BEGIN
  SELECT RAISE(ABORT, 'injected audit state failure');
END;
)sql");
}

TEST(SecurityStoreTest,
     AuditRetentionStateCountMismatchRollsBackCallerMutationAndDeletion) {
  ExpectAuditRetentionFailureRollsBackViewerCreation(R"sql(
CREATE TRIGGER ignore_audit_state_update
BEFORE UPDATE OF rotated_event_count ON audit_state
BEGIN
  SELECT RAISE(IGNORE);
END;
)sql");
}

TEST(SecurityStoreTest,
     AuditRetentionActorSnapshotFailureRollsBackCallerMutation) {
  ExpectAuditRetentionFailureRollsBackViewerCreation(
      "", AuditRetentionFailurePoint::kActorSnapshotLookup);
}

TEST(SecurityStoreTest,
     AuditRetentionFinalInsertFailureRollsBackMutationDeletionAndState) {
  ExpectAuditRetentionFailureRollsBackViewerCreation(R"sql(
CREATE TRIGGER reject_final_audit_insert
BEFORE INSERT ON audit_events
WHEN NEW.event_type = 'viewer_created'
BEGIN
  SELECT RAISE(ABORT, 'injected final audit insertion failure');
END;
)sql");
}

TEST(SecurityStoreTest,
     AuditRetentionCallerCommitFailureRollsBackMutationDeletionAndState) {
  ExpectAuditRetentionFailureRollsBackViewerCreation(
      "", AuditRetentionFailurePoint::kCallerCommit);
}

TEST(SecurityStoreTest,
     BoundedSubprocessKillsAndReapsChildHungAfterBoundary) {
  const auto result = RunBoundedSubprocessAtBoundary(
      [](int boundary_descriptor) {
        constexpr char kBoundaryReached = 'B';
        ASSERT_EQ(::write(boundary_descriptor, &kBoundaryReached, 1), 1);
        for (;;) {
          (void)::pause();
        }
      },
      std::chrono::seconds(1), std::chrono::milliseconds(50));

  EXPECT_EQ(result.outcome,
            BoundedSubprocessOutcome::kTimedOutAfterBoundary);
  ASSERT_TRUE(WIFSIGNALED(result.status));
  EXPECT_EQ(WTERMSIG(result.status), SIGKILL);
  errno = 0;
  EXPECT_EQ(::waitpid(result.child, nullptr, WNOHANG), -1);
  EXPECT_EQ(errno, ECHILD);
}

TEST(SecurityStoreTest,
     TransactionBoundaryGateBlocksUntilEveryWriterArrives) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  const auto result = RunBoundedSubprocessAtBoundary(
      [state](int boundary_descriptor) {
        auto store = SecurityStore::Open({state});
        ASSERT_TRUE(store.ok()) << store.error().message;
        SqliteTransactionBoundaryGate gate(2, boundary_descriptor);
        transaction_boundary_gate = &gate;

        auto transaction = store.value()->BeginTransaction();

        transaction_boundary_gate = nullptr;
        ASSERT_TRUE(transaction.ok()) << transaction.error().message;
        ASSERT_TRUE(transaction.value().Rollback().ok());
      },
      std::chrono::seconds(1), std::chrono::milliseconds(50));

  EXPECT_EQ(result.outcome,
            BoundedSubprocessOutcome::kTimedOutAfterBoundary);
  EXPECT_TRUE(result.boundary_observed);
  ASSERT_TRUE(WIFSIGNALED(result.status));
  EXPECT_EQ(WTERMSIG(result.status), SIGKILL);
}

TEST(SecurityStoreTest,
     AuditRetentionConcurrentStoresSerializeRotationAtCapacity) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  const auto result = RunBoundedSubprocessAtBoundary(
      [state](int boundary_descriptor) {
        RunAuditRetentionConcurrentStoreWriters(state, boundary_descriptor);
      },
      std::chrono::seconds(5), std::chrono::seconds(5));

  ASSERT_EQ(result.outcome, BoundedSubprocessOutcome::kExited);
  ASSERT_TRUE(result.boundary_observed);
  ASSERT_TRUE(WIFEXITED(result.status));
  ASSERT_EQ(WEXITSTATUS(result.status), 0);
  const auto database_path = state / "security.db";
  EXPECT_EQ(QueryDatabaseTextRows(
                database_path,
                "SELECT canonical_username FROM users "
                "ORDER BY canonical_username;"),
            (std::vector<std::string>{"monitor.east", "monitor.west",
                                      "operator.one"}));
  const int final_count = QueryDatabaseInt(
      database_path, "SELECT COUNT(*) FROM audit_events;");
  EXPECT_EQ(final_count, 5);
  EXPECT_LE(final_count, 5);
  EXPECT_EQ(QueryDatabaseInt(
                database_path,
                "SELECT COUNT(DISTINCT sequence) FROM audit_events;"),
            5);
  const auto retained = QueryDatabaseTextRows(
      database_path,
      "SELECT sequence || '|' || server_timestamp_seconds || '|' || "
      "event_type || '|' || outcome || '|' || actor_identity || '|' || "
      "subject_identity FROM audit_events ORDER BY sequence;");
  const std::vector<std::string> first_then_second{
      "3|1720000002|seed_two|success|system|",
      "4|1720000003|seed_three|success|system|",
      "5|1720000004|seed_four|success|system|",
      "6|1720000101|viewer_created|success|operator.one|monitor.east",
      "7|1720000102|viewer_created|success|operator.one|monitor.west"};
  const std::vector<std::string> second_then_first{
      "3|1720000002|seed_two|success|system|",
      "4|1720000003|seed_three|success|system|",
      "5|1720000004|seed_four|success|system|",
      "6|1720000102|viewer_created|success|operator.one|monitor.west",
      "7|1720000101|viewer_created|success|operator.one|monitor.east"};
  ASSERT_EQ(retained.size(), 5U);
  const auto& expected_retained = retained[3] == first_then_second[3]
                                      ? first_then_second
                                      : second_then_first;
  EXPECT_EQ(retained, expected_retained);
  EXPECT_EQ(QueryDatabaseTextRows(database_path,
                                  "SELECT sequence FROM audit_events "
                                  "ORDER BY sequence;"),
            (std::vector<std::string>{"3", "4", "5", "6", "7"}));
  EXPECT_EQ(QueryDatabaseTextRows(
                database_path,
                "SELECT rotated_event_count || '|' || "
                "last_rotated_sequence FROM audit_state;"),
            (std::vector<std::string>{"2|2"}));
  EXPECT_EQ(QueryDatabaseInt(
                database_path,
                "SELECT last_rotation_at_seconds FROM audit_state;"),
            QueryDatabaseInt(database_path,
                             "SELECT server_timestamp_seconds FROM "
                             "audit_events WHERE sequence = 7;"));
}

TEST(SecurityStoreTest,
     MigrationObserverFaultsUnexpectedExecuteAfterFinalValidation) {
  ResetSqliteHooks();
  observe_migration_exec = true;

  EXPECT_FALSE(ObserveMigrationExec("BEGIN IMMEDIATE;"));
  EXPECT_FALSE(ObserveMigrationExec("RELEASE schema_validation;"));
  EXPECT_FALSE(ObserveMigrationExec("CREATE TABLE migrated(value INTEGER);"));
  EXPECT_FALSE(ObserveMigrationExec("SAVEPOINT schema_validation;"));
  EXPECT_FALSE(ObserveMigrationExec("RELEASE schema_validation;"));
  EXPECT_FALSE(
      ObserveMigrationExec("CREATE TABLE migrated_again(value INTEGER);"));
  EXPECT_FALSE(ObserveMigrationExec("SAVEPOINT schema_validation;"));
  EXPECT_FALSE(ObserveMigrationExec("RELEASE schema_validation;"));

  ASSERT_EQ(migration_exec_phase, MigrationExecPhase::kReadyToCommit);
  fail_migration_statement_ordinal = observed_migration_statements.size();
  expected_migration_statement = "PRAGMA unexpected_precommit;";

  EXPECT_TRUE(ObserveMigrationExec("PRAGMA unexpected_precommit;"));
  ASSERT_EQ(observed_migration_statements.size(), 3U);
  EXPECT_EQ(observed_migration_statements.back(),
            "PRAGMA unexpected_precommit;");
  EXPECT_TRUE(migration_statement_fault_injected);
}

TEST(SecurityStoreTest, SyncFaultVfsCleansPartiallyOpenedDelegateOnFailure) {
  ResetSqliteHooks();
  sqlite3_vfs delegate{};
  delegate.iVersion = 1;
  delegate.szOsFile = sizeof(sqlite3_file);
  delegate.mxPathname = 512;
  delegate.zName = "camera-firmware-failing-open-delegate";
  delegate.xOpen = FailDelegateOpen;
  ScopedSyncFaultVfs sync_fault_vfs(&delegate);
  sqlite3_vfs* wrapper = sync_fault_vfs.vfs_for_test();
  const auto storage_slots =
      (static_cast<std::size_t>(wrapper->szOsFile) +
       sizeof(std::max_align_t) - 1U) /
      sizeof(std::max_align_t);
  std::vector<std::max_align_t> storage(storage_slots);
  auto* outer = reinterpret_cast<sqlite3_file*>(storage.data());
  outer->pMethods = &kPartiallyOpenedDelegateMethods;
  auto* real = reinterpret_cast<sqlite3_file*>(
      reinterpret_cast<unsigned char*>(outer) + wrapper->szOsFile -
      delegate.szOsFile);
  int output_flags = 0;

  const int result = wrapper->xOpen(wrapper, "unused", outer,
                                    SQLITE_OPEN_READWRITE, &output_flags);

  EXPECT_EQ(result, SQLITE_CANTOPEN);
  EXPECT_EQ(outer->pMethods, nullptr);
  EXPECT_EQ(real->pMethods, nullptr);
  EXPECT_EQ(delegated_open_failure_close_calls, 1);
}

TEST(SecurityStoreTest, MigrationStatementFailuresRollBackToRevisionTwo) {
  const auto statements = CaptureActualMigrationStatements();
  ASSERT_FALSE(statements.empty());
  for (std::size_t ordinal = 0; ordinal < statements.size(); ++ordinal) {
    SCOPED_TRACE(::testing::Message()
                 << "migration statement " << ordinal << ": "
                 << statements[ordinal]);
    ResetSqliteHooks();
    RevisionTwoOperationalFixture fixture;
    const auto before = fixture.evidence();
    observe_migration_exec = true;
    fail_migration_statement_ordinal = ordinal;
    expected_migration_statement = statements[ordinal];

    auto opened = SecurityStore::Open({fixture.state_directory()});

    observe_migration_exec = false;
    ASSERT_FALSE(opened.ok());
    EXPECT_EQ(opened.error().code, "E_SECURITY_DB_SCHEMA");
    EXPECT_TRUE(migration_statement_fault_injected);
    fail_migration_statement_ordinal.reset();
    expected_migration_statement.reset();
    EXPECT_EQ(rollback_calls, 1);
    EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                               "SELECT version FROM schema_version;"),
              2);
    EXPECT_EQ(fixture.evidence(), before);
    EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
  }
}

TEST(SecurityStoreTest, MigrationBeginFailureLeavesRevisionTwoUnchanged) {
  ResetSqliteHooks();
  RevisionTwoOperationalFixture fixture;
  const auto before = fixture.evidence();
  fail_sqlite_exec_exact = "BEGIN IMMEDIATE;";

  auto opened = SecurityStore::Open({fixture.state_directory()});

  ASSERT_FALSE(opened.ok());
  fail_sqlite_exec_exact.reset();
  EXPECT_EQ(rollback_calls, 0);
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT version FROM schema_version;"),
            2);
  EXPECT_EQ(fixture.evidence(), before);
  EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
}

TEST(SecurityStoreTest, MigrationValidationFailureRollsBackToRevisionTwo) {
  ResetSqliteHooks();
  RevisionTwoOperationalFixture fixture;
  const auto before = fixture.evidence();
  fail_sqlite_exec_exact = "SAVEPOINT schema_validation;";
  fail_sqlite_exec_exact_after_matches = 1;

  auto opened = SecurityStore::Open({fixture.state_directory()});

  ASSERT_FALSE(opened.ok());
  fail_sqlite_exec_exact.reset();
  EXPECT_EQ(rollback_calls, 1);
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT version FROM schema_version;"),
            2);
  EXPECT_EQ(fixture.evidence(), before);
  EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
}

TEST(SecurityStoreTest,
     RevisionFourMigrationStatementFailureRollsBackToRevisionThree) {
  ResetSqliteHooks();
  RevisionThreeOperationalFixture fixture;
  constexpr const char* kSchemaInventorySql =
      "SELECT type || '|' || name || '|' || tbl_name || '|' || sql "
      "FROM sqlite_schema ORDER BY type, name;";
  constexpr const char* kAuditEvidenceSql =
      "SELECT sequence || '|' || server_timestamp_seconds || '|' || "
      "event_type || '|' || outcome || '|' || "
      "COALESCE(actor_user_id, -1) || '|' || peer_ip || '|' || detail_code || "
      "'|' || subject_type || '|' || subject_identity "
      "FROM audit_events ORDER BY sequence;";
  const auto before_schema =
      QueryDatabaseTextRows(fixture.database_path(), kSchemaInventorySql);
  const auto before_audit =
      QueryDatabaseTextRows(fixture.database_path(), kAuditEvidenceSql);
  fail_sqlite_exec_exact = "DROP TABLE audit_events_revision_three;";

  auto opened = SecurityStore::Open({fixture.state_directory()});

  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_SECURITY_DB_SCHEMA");
  fail_sqlite_exec_exact.reset();
  EXPECT_EQ(rollback_calls, 1);
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT version FROM schema_version;"),
            3);
  EXPECT_EQ(QueryDatabaseTextRows(fixture.database_path(), kSchemaInventorySql),
            before_schema);
  EXPECT_EQ(QueryDatabaseTextRows(fixture.database_path(), kAuditEvidenceSql),
            before_audit);
  EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
}

TEST(SecurityStoreTest,
     RevisionFourFinalValidationFailureRollsBackToRevisionThree) {
  ResetSqliteHooks();
  RevisionThreeOperationalFixture fixture;
  constexpr const char* kSchemaInventorySql =
      "SELECT type || '|' || name || '|' || tbl_name || '|' || sql "
      "FROM sqlite_schema ORDER BY type, name;";
  const auto before_schema =
      QueryDatabaseTextRows(fixture.database_path(), kSchemaInventorySql);
  fail_sqlite_exec_exact = "SAVEPOINT schema_validation;";
  fail_sqlite_exec_exact_after_matches = 1;

  auto opened = SecurityStore::Open({fixture.state_directory()});

  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_SECURITY_DB_SCHEMA");
  fail_sqlite_exec_exact.reset();
  EXPECT_EQ(rollback_calls, 1);
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT version FROM schema_version;"),
            3);
  EXPECT_EQ(QueryDatabaseTextRows(fixture.database_path(), kSchemaInventorySql),
            before_schema);
  EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
}

TEST(SecurityStoreTest, MigrationCommitFailureRollsBackToRevisionTwo) {
  ResetSqliteHooks();
  RevisionTwoOperationalFixture fixture;
  const auto before = fixture.evidence();
  fail_commit = true;

  auto opened = SecurityStore::Open({fixture.state_directory()});

  ASSERT_FALSE(opened.ok());
  fail_commit = false;
  EXPECT_EQ(rollback_calls, 1);
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT version FROM schema_version;"),
            2);
  EXPECT_EQ(fixture.evidence(), before);
  EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
}

TEST(SecurityStoreTest, MigrationVfsSyncFailureRollsBackToRevisionTwo) {
  ResetSqliteHooks();
  RevisionTwoOperationalFixture fixture;
  const auto before = fixture.evidence();
  {
    ScopedSyncFaultVfs sync_fault_vfs;
    ASSERT_TRUE(sync_fault_vfs.registered());
    observe_migration_exec = true;
    fail_next_vfs_sync = true;

    auto opened = SecurityStore::Open({fixture.state_directory()});

    observe_migration_exec = false;
    EXPECT_FALSE(opened.ok());
    if (!opened.ok()) {
      EXPECT_EQ(opened.error().code, "E_SECURITY_DB_SCHEMA");
    }
    EXPECT_GT(vfs_sync_calls, 0);
    EXPECT_EQ(vfs_sync_failures, 1);
    EXPECT_TRUE(vfs_sync_failed_during_migration_commit);
    EXPECT_EQ(rollback_calls, 1);
  }
  fail_next_vfs_sync = false;
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT version FROM schema_version;"),
            2);
  EXPECT_EQ(fixture.evidence(), before);
  EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
}

TEST(SecurityStoreTest, MigrationRollbackFailureClosesPoisonedConnection) {
  const auto statements = CaptureActualMigrationStatements();
  ASSERT_FALSE(statements.empty());
  ResetSqliteHooks();
  RevisionTwoOperationalFixture fixture;
  observe_migration_exec = true;
  fail_migration_statement_ordinal = 0;
  expected_migration_statement = statements.front();
  fail_rollback = true;

  auto opened = SecurityStore::Open({fixture.state_directory()});

  observe_migration_exec = false;
  ASSERT_FALSE(opened.ok());
  EXPECT_TRUE(migration_statement_fault_injected);
  EXPECT_EQ(rollback_calls, 1);
  EXPECT_GE(sqlite_close_calls, 1);
  fail_migration_statement_ordinal.reset();
  expected_migration_statement.reset();
  fail_rollback = false;
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT version FROM schema_version;"),
            2);
  EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
}

TEST(SecurityStoreTest, MigrationRejectsDuplicateSessionsForOneUser) {
  ResetSqliteHooks();
  RevisionTwoOperationalFixture fixture;
  const auto before = fixture.evidence();
  ExecuteDatabaseSql(fixture.database_path(), R"sql(
INSERT INTO sessions
  (id, token_hash, user_id, role, created_at_seconds,
   last_activity_at_seconds, expires_at_seconds, peer_ip)
VALUES (33, randomblob(32), 12, 'viewer', 1720000020, 1720000021,
        1720001021, '198.51.100.10');
)sql");

  auto opened = SecurityStore::Open({fixture.state_directory()});

  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_SECURITY_DB_SCHEMA");
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT version FROM schema_version;"),
            2);
  EXPECT_EQ(QueryDatabaseInt(fixture.database_path(),
                             "SELECT COUNT(*) FROM sessions;"),
            3);
  ExecuteDatabaseSql(fixture.database_path(), "DELETE FROM sessions WHERE id = 33;");
  EXPECT_EQ(fixture.evidence(), before);
  EXPECT_TRUE(SecurityStore::Open({fixture.state_directory()}).ok());
}

TEST(SecurityStoreTest, RejectsPartialPreexistingSchema) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  MakeDirectory(state);
  CreateDatabaseWithSql(state / "security.db", R"sql(
CREATE TABLE schema_version (version INTEGER NOT NULL);
INSERT INTO schema_version (version) VALUES (1);
)sql");

  const auto store = SecurityStore::Open({state});

  ASSERT_FALSE(store.ok());
  EXPECT_EQ(store.error().code, "E_SECURITY_DB_SCHEMA");
}

TEST(SecurityStoreTest, RejectsMalformedPreexistingSchema) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  MakeDirectory(state);
  CreateDatabaseWithSql(state / "security.db", R"sql(
CREATE TABLE schema_version (version TEXT NOT NULL);
INSERT INTO schema_version (version) VALUES ('1');
CREATE TABLE device_state (
  id INTEGER PRIMARY KEY,
  state TEXT NOT NULL
);
INSERT INTO device_state (id, state) VALUES (1, 'default');
)sql");

  const auto store = SecurityStore::Open({state});

  ASSERT_FALSE(store.ok());
  EXPECT_EQ(store.error().code, "E_SECURITY_DB_SCHEMA");
}

TEST(SecurityStoreTest, RejectsNamedIndexesWithWrongSecurityDefinition) {
  ExpectReopenRejectsSchemaMutation(R"sql(
DROP INDEX users_canonical_username_unique;
CREATE INDEX users_canonical_username_unique ON users(canonical_username);
)sql");
  ExpectReopenRejectsSchemaMutation(R"sql(
DROP INDEX users_canonical_username_unique;
CREATE UNIQUE INDEX users_canonical_username_unique
  ON users(canonical_username COLLATE BINARY);
)sql");
  ExpectReopenRejectsSchemaMutation(R"sql(
DROP INDEX users_single_administrator_unique;
CREATE UNIQUE INDEX users_single_administrator_unique
  ON users(role) WHERE role = 'disabled';
)sql");
}

TEST(SecurityStoreTest, RejectsWrongSessionForeignKeyDefinition) {
  ExpectReopenRejectsSchemaMutation(R"sql(
PRAGMA foreign_keys=OFF;
ALTER TABLE sessions RENAME TO sessions_old;
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,
  token_hash BLOB NOT NULL CHECK (length(token_hash) = 32),
  user_id INTEGER NOT NULL REFERENCES management_ips(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('administrator')),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0),
  last_activity_at_seconds INTEGER NOT NULL
    CHECK (last_activity_at_seconds >= created_at_seconds),
  expires_at_seconds INTEGER NOT NULL
    CHECK (expires_at_seconds >= last_activity_at_seconds),
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45)
);
DROP TABLE sessions_old;
CREATE UNIQUE INDEX sessions_token_hash_unique ON sessions(token_hash);
CREATE UNIQUE INDEX sessions_single_administrator_unique
  ON sessions(role) WHERE role = 'administrator';
CREATE INDEX sessions_expiry_index ON sessions(expires_at_seconds);
)sql");
}

TEST(SecurityStoreTest, RejectsMissingSessionTokenLengthConstraint) {
  ExpectReopenRejectsSchemaMutation(R"sql(
PRAGMA foreign_keys=OFF;
ALTER TABLE sessions RENAME TO sessions_old;
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,
  token_hash BLOB NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('administrator')),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0),
  last_activity_at_seconds INTEGER NOT NULL
    CHECK (last_activity_at_seconds >= created_at_seconds),
  expires_at_seconds INTEGER NOT NULL
    CHECK (expires_at_seconds >= last_activity_at_seconds),
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45)
);
DROP TABLE sessions_old;
CREATE UNIQUE INDEX sessions_token_hash_unique ON sessions(token_hash);
CREATE UNIQUE INDEX sessions_single_administrator_unique
  ON sessions(role) WHERE role = 'administrator';
CREATE INDEX sessions_expiry_index ON sessions(expires_at_seconds);
)sql");
}

TEST(SecurityStoreTest, RejectsMalformedFirmwareLogOutboxLeaseDefinition) {
  ExpectReopenRejectsSchemaMutation(R"sql(
ALTER TABLE firmware_log_outbox RENAME TO firmware_log_outbox_old;
CREATE TABLE firmware_log_outbox (
  id INTEGER PRIMARY KEY,
  category TEXT NOT NULL CHECK (length(category) BETWEEN 1 AND 64),
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0),
  dirty INTEGER NOT NULL DEFAULT 0 CHECK (dirty IN (0, 1)),
  lease_owner BLOB,
  lease_token BLOB,
  lease_expires_at_seconds INTEGER
);
DROP TABLE firmware_log_outbox_old;
CREATE UNIQUE INDEX firmware_log_outbox_category_peer_unique
  ON firmware_log_outbox(category, peer_ip);
CREATE INDEX firmware_log_outbox_lease_expiry_index
  ON firmware_log_outbox(lease_expires_at_seconds);
)sql");
}

TEST(SecurityStoreTest, RejectsUnexpectedTriggerAndViewObjects) {
  ExpectOperationalReopenRejectsDataMutation(R"sql(
CREATE TRIGGER remove_bootstrap_admin
AFTER UPDATE OF state ON device_state
WHEN NEW.state = 'operational' AND
     NEW.setup_completed_at_seconds IS NOT NULL
BEGIN
  DELETE FROM users WHERE role = 'administrator';
END;
)sql");
  ExpectReopenRejectsSchemaMutation(R"sql(
CREATE VIEW bootstrap_usernames AS
SELECT canonical_username FROM users;
)sql");

  TemporaryDirectory root;
  const auto state = root.Path("security");
  MakeDirectory(state);
  const auto database = state / "security.db";
  CreateDatabaseWithSql(database,
                        "CREATE VIEW unexpected_view AS SELECT 1 AS value;");

  auto store = SecurityStore::Open({state});

  ASSERT_FALSE(store.ok());
  EXPECT_EQ(store.error().code, "E_SECURITY_DB_SCHEMA");
  EXPECT_EQ(QueryDatabaseInt(database, "SELECT COUNT(*) FROM sqlite_schema;"),
            1);
}

TEST(SecurityStoreTest, RejectsDefaultStateWithStaleBootstrapRows) {
  ExpectReopenRejectsSchemaMutation(R"sql(
INSERT INTO users
  (canonical_username, display_username, role, enabled,
   password_algorithm, password_iterations, password_salt,
   password_derived, password_changed_at_seconds, failed_login_count,
   created_at_seconds)
VALUES
  ('operator.one', 'Operator.One', 'administrator', 1,
   'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), 1, 0, 1);
)sql");
  ExpectReopenRejectsSchemaMutation(R"sql(
INSERT INTO management_ips
  (normalized_ip, role_scope, enabled, created_at_seconds)
VALUES ('192.0.2.10', 'administrator', 1, 1);
)sql");
  ExpectReopenRejectsSchemaMutation(R"sql(
INSERT INTO sessions
  (token_hash, user_id, role, created_at_seconds,
   last_activity_at_seconds, expires_at_seconds, peer_ip)
VALUES (zeroblob(32), 999, 'administrator', 1, 1, 2, '192.0.2.10');
)sql");
  ExpectReopenRejectsSchemaMutation(R"sql(
INSERT INTO audit_events
  (server_timestamp_seconds, event_type, outcome, actor_user_id,
   actor_identity, peer_ip, detail_code)
VALUES (1, 'bootstrap_completed', 'success', NULL, 'system',
        '192.0.2.10', 'initial_administrator');
)sql");
}

TEST(SecurityStoreTest, RejectsOperationalStateMissingRequiredBootstrapRows) {
  ExpectOperationalReopenRejectsDataMutation("DELETE FROM users;");
  ExpectOperationalReopenRejectsDataMutation("DELETE FROM management_ips;");
  ExpectOperationalReopenRejectsDataMutation(
      "DELETE FROM audit_events WHERE event_type = 'bootstrap_completed' "
      "AND outcome = 'success';");
  ExpectOperationalReopenRejectsDataMutation(
      "UPDATE users SET enabled = 0 WHERE role = 'administrator';");
  ExpectOperationalReopenRejectsDataMutation(
      "UPDATE management_ips SET enabled = 0;");
}

TEST(SecurityStoreTest, RejectsOperationalStateWithBrokenBootstrapLinks) {
  ExpectOperationalReopenRejectsDataMutation(
      "UPDATE audit_events SET actor_user_id = NULL "
      "WHERE event_type = 'bootstrap_completed' AND outcome = 'success';");
  ExpectOperationalReopenRejectsDataMutation(
      "UPDATE audit_events SET peer_ip = '198.51.100.20' "
      "WHERE event_type = 'bootstrap_completed' AND outcome = 'success';");
  ExpectOperationalReopenRejectsDataMutation(R"sql(
INSERT INTO audit_events
  (server_timestamp_seconds, event_type, outcome, actor_user_id,
   actor_identity, peer_ip, detail_code)
SELECT 2, 'bootstrap_completed', 'success', id, canonical_username,
       '2001:db8::10', 'duplicate_bootstrap'
FROM users WHERE role = 'administrator';
)sql");
}

TEST(SecurityStoreTest, OperationalStateAllowsLaterNonBootstrapRows) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    ASSERT_TRUE(store.value()
                    ->InitializeDevice(MakeBootstrapRecord(), [] {
                      return camera_firmware::common::Result<void>::Ok();
                    })
                    .ok());
  }
  ExecuteDatabaseSql(state / "security.db", R"sql(
INSERT INTO management_ips
  (normalized_ip, role_scope, enabled, created_at_seconds)
VALUES ('192.0.2.20', 'administrator', 1, 2);
INSERT INTO sessions
  (token_hash, user_id, role, created_at_seconds,
   last_activity_at_seconds, expires_at_seconds, peer_ip)
SELECT randomblob(32), id, 'administrator', 2, 2, 3, '192.0.2.20'
FROM users WHERE role = 'administrator';
INSERT INTO audit_events
  (server_timestamp_seconds, event_type, outcome, actor_user_id,
   actor_identity, peer_ip, detail_code)
SELECT 2, 'login_completed', 'success', id, canonical_username,
       '192.0.2.20', 'session_created'
FROM users WHERE role = 'administrator';
)sql");

  auto reopened = SecurityStore::Open({state});

  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  EXPECT_EQ(reopened.value()->State().value(), DeviceState::kOperational);
}

TEST(SecurityStoreTest, ProtectsNestedGeneratedSecurityFilesFromGit) {
  EXPECT_TRUE(GitIgnores("var/security/security.db"));
  EXPECT_TRUE(GitIgnores("var/security/security.db-wal"));
  EXPECT_TRUE(GitIgnores("config/security/security.db-shm"));
  EXPECT_TRUE(GitIgnores("var/security/rtsp.credentials"));
  EXPECT_TRUE(GitIgnores("config/nested/device.credentials"));
}
