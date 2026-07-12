#include "camera_firmware/security/SecurityStore.hpp"

#include "camera_firmware/security/PasswordHasher.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <future>
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
using camera_firmware::security::BootstrapRecord;
using camera_firmware::security::PasswordRecord;
using camera_firmware::security::SecurityStore;
using camera_firmware::security::SecurityStoreConfig;

template <typename T>
concept HasPublicSetDeviceState = requires(T& transaction) {
  transaction.SetDeviceState(DeviceState::kOperational);
};

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

camera_firmware::common::SecureBytes FilledBytes(std::size_t size,
                                                  unsigned char value) {
  camera_firmware::common::SecureBytes bytes;
  bytes.resize(size);
  std::fill_n(bytes.data(), size, value);
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
            std::vector<std::string>({"audit_events", "device_state",
                                      "firmware_log_outbox",
                                      "management_ips", "schema_version",
                                      "sessions", "users"}));
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
                "actor_user_id:INTEGER:0:0", "peer_ip:TEXT:1:0",
                "detail_code:TEXT:1:0"}));
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
                "management_ips_normalized_ip_unique",
                "sessions_expiry_index",
                "sessions_single_administrator_unique",
                "sessions_token_hash_unique",
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
            2);
  EXPECT_EQ(QueryInt(last_opened_database,
                     "SELECT schema_revision FROM device_state WHERE id = 1;"),
            2);
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
   peer_ip, detail_code)
VALUES (1, 'bootstrap_completed', 'success', NULL,
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
   peer_ip, detail_code)
SELECT 2, 'bootstrap_completed', 'success', id,
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
   peer_ip, detail_code)
SELECT 2, 'login_completed', 'success', id,
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
