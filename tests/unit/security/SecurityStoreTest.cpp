#include "camera_firmware/security/SecurityStore.hpp"

#include <array>
#include <cerrno>
#include <filesystem>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
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
using camera_firmware::security::SecurityStore;
using camera_firmware::security::SecurityStoreConfig;

std::optional<std::filesystem::path> spoofed_owner_path;
std::function<void(const char*, int)> before_sqlite_open;
bool fail_busy_timeout{false};
int last_sqlite_open_flags{0};
sqlite3* last_opened_database{nullptr};
int sqlite_close_calls{0};
bool fail_commit{false};
bool fail_rollback{false};
int rollback_calls{0};

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

}  // namespace

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
  if (sql == "ROLLBACK;") {
    ++rollback_calls;
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

TEST(SecurityStoreTest, TransactionCommitPersistsTypedStateChange) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto started = store.value()->BeginTransaction();
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto transaction = std::move(started).value();

  ASSERT_TRUE(transaction.SetDeviceState(DeviceState::kOperational).ok());
  ASSERT_TRUE(transaction.Commit().ok());
  EXPECT_FALSE(transaction.active());
  EXPECT_EQ(store.value()->State().value(), DeviceState::kOperational);
}

TEST(SecurityStoreTest, TransactionMoveContractIsConstructionOnly) {
  EXPECT_TRUE(std::is_move_constructible_v<SecurityStore::Transaction>);
  EXPECT_FALSE(std::is_move_assignable_v<SecurityStore::Transaction>);
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

  ASSERT_TRUE(transaction->SetDeviceState(DeviceState::kOperational).ok());
  ASSERT_TRUE(transaction->Commit().ok());
  transaction.reset();

  auto reopened = SecurityStore::Open({state});
  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  EXPECT_EQ(reopened.value()->State().value(), DeviceState::kOperational);
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
    ASSERT_TRUE(
        transaction->SetDeviceState(DeviceState::kOperational).ok());
    store.value().reset();
  }

  transaction.reset();

  EXPECT_EQ(rollback_calls, 1);
  auto reopened = SecurityStore::Open({state});
  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  EXPECT_EQ(reopened.value()->State().value(), DeviceState::kDefault);
}

TEST(SecurityStoreTest, TransactionRollbackDiscardsTypedStateChange) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto started = store.value()->BeginTransaction();
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto transaction = std::move(started).value();

  ASSERT_TRUE(transaction.SetDeviceState(DeviceState::kOperational).ok());
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
    ASSERT_TRUE(transaction.SetDeviceState(DeviceState::kOperational).ok());
  }

  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_EQ(rollback_calls, 1);
}

TEST(SecurityStoreTest, TransactionErrorsRemainActiveForCleanupRetry) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  auto store = SecurityStore::Open({root.Path("security")});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto started = store.value()->BeginTransaction();
  ASSERT_TRUE(started.ok()) << started.error().message;
  auto transaction = std::move(started).value();
  ASSERT_TRUE(transaction.SetDeviceState(DeviceState::kOperational).ok());

  fail_commit = true;
  const auto commit = transaction.Commit();
  fail_commit = false;
  ASSERT_FALSE(commit.ok());
  EXPECT_EQ(commit.error().code, "E_SECURITY_DB_TRANSACTION");
  EXPECT_TRUE(transaction.active());

  fail_rollback = true;
  const auto first_rollback = transaction.Rollback();
  fail_rollback = false;
  ASSERT_FALSE(first_rollback.ok());
  EXPECT_TRUE(transaction.active());

  ASSERT_TRUE(transaction.Rollback().ok());
  EXPECT_FALSE(transaction.active());
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
}

TEST(SecurityStoreTest, CreatesExactSchemaAndConfiguresLiveConnection) {
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
            std::vector<std::string>({"device_state", "schema_version"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk "
                "FROM pragma_table_info('schema_version') ORDER BY cid;"),
            std::vector<std::string>({"version:INTEGER:1:0"}));
  EXPECT_EQ(QueryTextRows(
                last_opened_database,
                "SELECT name || ':' || type || ':' || \"notnull\" || ':' || pk "
                "FROM pragma_table_info('device_state') ORDER BY cid;"),
            std::vector<std::string>({"id:INTEGER:0:1", "state:TEXT:1:0"}));
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
            1);
  EXPECT_EQ(QueryInt(last_opened_database, "PRAGMA foreign_keys;"), 1);
  EXPECT_EQ(QueryInt(last_opened_database, "PRAGMA secure_delete;"), 1);
  EXPECT_EQ(QueryInt(last_opened_database, "PRAGMA busy_timeout;"), 1000);
}

TEST(SecurityStoreTest, ReopensInitializedSchemaWithoutChangingState) {
  ResetSqliteHooks();
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto first = SecurityStore::Open({state});
    ASSERT_TRUE(first.ok()) << first.error().message;
    auto started = first.value()->BeginTransaction();
    ASSERT_TRUE(started.ok()) << started.error().message;
    auto transaction = std::move(started).value();
    ASSERT_TRUE(transaction.SetDeviceState(DeviceState::kOperational).ok());
    ASSERT_TRUE(transaction.Commit().ok());
  }

  auto reopened = SecurityStore::Open({state});

  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  EXPECT_EQ(reopened.value()->State().value(), DeviceState::kOperational);
  EXPECT_EQ(QueryInt(last_opened_database, "SELECT COUNT(*) FROM schema_version;"),
            1);
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

TEST(SecurityStoreTest, ProtectsNestedGeneratedSecurityFilesFromGit) {
  EXPECT_TRUE(GitIgnores("var/security/security.db"));
  EXPECT_TRUE(GitIgnores("var/security/security.db-wal"));
  EXPECT_TRUE(GitIgnores("config/security/security.db-shm"));
  EXPECT_TRUE(GitIgnores("var/security/rtsp.credentials"));
  EXPECT_TRUE(GitIgnores("config/nested/device.credentials"));
}
