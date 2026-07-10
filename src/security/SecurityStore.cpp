#include "camera_firmware/security/SecurityStore.hpp"

#include <cerrno>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

namespace camera_firmware::security {
namespace {

constexpr mode_t kStateDirectoryMode = 0700;
constexpr mode_t kDatabaseMode = 0600;
constexpr int kBusyTimeoutMilliseconds = 1000;

template <typename T>
common::Result<T> StoreError(std::string code, std::string message) {
  return common::Result<T>::Err({std::move(code), std::move(message)});
}

common::Result<void> StoreError(std::string code, std::string message) {
  return common::Result<void>::Err({std::move(code), std::move(message)});
}

bool HasExactMode(const struct stat& status, mode_t expected) {
  return (status.st_mode & 0777) == expected;
}

common::Result<void> EnsureStateDirectory(
    const std::filesystem::path& state_directory,
    uid_t expected_owner) {
  if (state_directory.empty()) {
    return StoreError("E_SECURITY_DB_PATH", "security state directory is empty");
  }

  struct stat status {};
  if (::lstat(state_directory.c_str(), &status) != 0) {
    if (errno != ENOENT ||
        ::mkdir(state_directory.c_str(), kStateDirectoryMode) != 0) {
      return StoreError("E_SECURITY_DB_PATH",
                        "failed to create security state directory");
    }
    if (::chmod(state_directory.c_str(), kStateDirectoryMode) != 0) {
      return StoreError("E_SECURITY_DB_PATH",
                        "failed to protect security state directory");
    }
    if (::lstat(state_directory.c_str(), &status) != 0) {
      return StoreError("E_SECURITY_DB_PATH",
                        "failed to inspect security state directory");
    }
  }

  if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {
    return StoreError("E_SECURITY_DB_PATH",
                      "security state directory must be a directory");
  }
  if (!HasExactMode(status, kStateDirectoryMode)) {
    return StoreError("E_SECURITY_STATE_MODE",
                      "security state directory must have mode 0700");
  }
  if (status.st_uid != expected_owner) {
    return StoreError("E_SECURITY_STATE_OWNER",
                      "security state directory must be owned by the effective user");
  }
  return common::Result<void>::Ok();
}

common::Result<void> CreateOrValidateDatabase(
    const std::filesystem::path& database_path,
    uid_t expected_owner) {
  struct stat status {};
  if (::lstat(database_path.c_str(), &status) != 0) {
    if (errno != ENOENT) {
      return StoreError("E_SECURITY_DB_PATH", "failed to inspect security database");
    }

    const int descriptor = ::open(database_path.c_str(),
                                  O_RDWR | O_NOFOLLOW | O_CREAT | O_EXCL |
                                      O_CLOEXEC,
                                  kDatabaseMode);
    if (descriptor < 0) {
      return StoreError("E_SECURITY_DB_PATH", "failed to create security database");
    }
    if (::fchmod(descriptor, kDatabaseMode) != 0) {
      (void)::close(descriptor);
      return StoreError("E_SECURITY_DB_PATH",
                        "failed to protect security database");
    }
    const int close_result = ::close(descriptor);
    if (close_result != 0) {
      return StoreError("E_SECURITY_DB_PATH", "failed to close security database");
    }
    if (::lstat(database_path.c_str(), &status) != 0) {
      return StoreError("E_SECURITY_DB_PATH", "failed to inspect security database");
    }
  }

  if (!S_ISREG(status.st_mode) || S_ISLNK(status.st_mode)) {
    return StoreError("E_SECURITY_DB_PATH",
                      "security database must be a regular file");
  }
  if (!HasExactMode(status, kDatabaseMode)) {
    return StoreError("E_SECURITY_DB_MODE",
                      "security database must have mode 0600");
  }
  if (status.st_uid != expected_owner) {
    return StoreError("E_SECURITY_DB_OWNER",
                      "security database must be owned by the effective user");
  }

  const int descriptor =
      ::open(database_path.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  if (descriptor < 0) {
    return StoreError("E_SECURITY_DB_PATH", "failed to open security database");
  }
  const int close_result = ::close(descriptor);
  if (close_result != 0) {
    return StoreError("E_SECURITY_DB_PATH", "failed to close security database");
  }
  return common::Result<void>::Ok();
}

common::Result<void> Execute(sqlite3* database,
                             const char* statement,
                             std::string code,
                             std::string message) {
  char* error_message = nullptr;
  const int result = ::sqlite3_exec(database, statement, nullptr, nullptr,
                                    &error_message);
  if (result == SQLITE_OK) {
    return common::Result<void>::Ok();
  }
  if (error_message != nullptr) {
    ::sqlite3_free(error_message);
  }
  return StoreError(std::move(code), std::move(message));
}

bool QuerySingleInt(sqlite3* database, const char* sql, int& value) {
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) {
    return false;
  }
  const int step = ::sqlite3_step(statement);
  if (step != SQLITE_ROW) {
    (void)::sqlite3_finalize(statement);
    return false;
  }
  value = ::sqlite3_column_int(statement, 0);
  const bool has_one_row = ::sqlite3_step(statement) == SQLITE_DONE;
  const bool finalized = ::sqlite3_finalize(statement) == SQLITE_OK;
  return has_one_row && finalized;
}

struct ColumnInfo {
  std::string name;
  std::string type;
  int not_null{0};
  int primary_key{0};

  bool operator==(const ColumnInfo&) const = default;
};

bool ReadColumns(sqlite3* database,
                 const char* table_name,
                 std::vector<ColumnInfo>& columns) {
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "SELECT name, type, \"notnull\", pk "
      "FROM pragma_table_info(?1) ORDER BY cid;";
  if (::sqlite3_prepare_v2(database, kSql, -1, &statement, nullptr) !=
          SQLITE_OK ||
      ::sqlite3_bind_text(statement, 1, table_name, -1, SQLITE_STATIC) !=
          SQLITE_OK) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return false;
  }

  int step = SQLITE_ROW;
  while ((step = ::sqlite3_step(statement)) == SQLITE_ROW) {
    const auto* name = ::sqlite3_column_text(statement, 0);
    const auto* type = ::sqlite3_column_text(statement, 1);
    if (name == nullptr || type == nullptr) {
      (void)::sqlite3_finalize(statement);
      return false;
    }
    columns.push_back(
        {reinterpret_cast<const char*>(name), reinterpret_cast<const char*>(type),
         ::sqlite3_column_int(statement, 2),
         ::sqlite3_column_int(statement, 3)});
  }
  return step == SQLITE_DONE && ::sqlite3_finalize(statement) == SQLITE_OK;
}

bool StatementIsRejectedByConstraint(sqlite3* database, const char* sql) {
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) {
    return false;
  }
  const int step = ::sqlite3_step(statement);
  const bool rejected = (step & 0xff) == SQLITE_CONSTRAINT;
  (void)::sqlite3_finalize(statement);
  return rejected;
}

common::Result<void> ValidateSchema(sqlite3* database) {
  int value = 0;
  if (!QuerySingleInt(database, "PRAGMA foreign_keys;", value) || value != 1 ||
      !QuerySingleInt(database, "PRAGMA secure_delete;", value) || value != 1 ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM sqlite_schema "
          "WHERE type = 'table' AND name NOT LIKE 'sqlite_%';",
          value) ||
      value != 2 ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM sqlite_schema "
          "WHERE type = 'table' "
          "AND name IN ('schema_version', 'device_state');",
          value) ||
      value != 2) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  std::vector<ColumnInfo> schema_version_columns;
  std::vector<ColumnInfo> device_state_columns;
  if (!ReadColumns(database, "schema_version", schema_version_columns) ||
      schema_version_columns !=
          std::vector<ColumnInfo>{{"version", "INTEGER", 1, 0}} ||
      !ReadColumns(database, "device_state", device_state_columns) ||
      device_state_columns !=
          std::vector<ColumnInfo>{{"id", "INTEGER", 0, 1},
                                  {"state", "TEXT", 1, 0}} ||
      !QuerySingleInt(database,
                      "SELECT COUNT(*) FROM schema_version WHERE version = 1;",
                      value) ||
      value != 1 ||
      !QuerySingleInt(database, "SELECT COUNT(*) FROM schema_version;", value) ||
      value != 1 ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM device_state "
          "WHERE id = 1 AND state IN ('default', 'operational');",
          value) ||
      value != 1 ||
      !QuerySingleInt(database, "SELECT COUNT(*) FROM device_state;", value) ||
      value != 1) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  auto savepoint = Execute(database, "SAVEPOINT schema_validation;",
                           "E_SECURITY_DB_SCHEMA",
                           "failed to validate security database schema");
  if (!savepoint.ok()) {
    return savepoint;
  }
  const bool constraints_valid =
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO schema_version (version) VALUES (NULL);") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO device_state (id, state) VALUES (2, 'default');") &&
      StatementIsRejectedByConstraint(
          database,
          "UPDATE device_state SET state = 'invalid' WHERE id = 1;");
  auto rollback = Execute(database, "ROLLBACK TO schema_validation;",
                          "E_SECURITY_DB_SCHEMA",
                          "failed to validate security database schema");
  auto release = Execute(database, "RELEASE schema_validation;",
                         "E_SECURITY_DB_SCHEMA",
                         "failed to validate security database schema");
  if (!constraints_valid || !rollback.ok() || !release.ok()) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }
  return common::Result<void>::Ok();
}

}  // namespace

struct SecurityStore::Impl {
  struct DatabaseCloser {
    void operator()(sqlite3* database) const noexcept {
      if (database != nullptr) {
        (void)::sqlite3_close_v2(database);
      }
    }
  };

  std::filesystem::path state_directory;
  std::filesystem::path database_path;
  std::unique_ptr<sqlite3, DatabaseCloser> database;
};

SecurityStore::SecurityStore(std::shared_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

SecurityStore::~SecurityStore() = default;

SecurityStore::Transaction::Transaction(std::shared_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)), active_(true) {}

SecurityStore::Transaction::~Transaction() {
  if (active_ && impl_ != nullptr) {
    (void)Rollback();
  }
}

SecurityStore::Transaction::Transaction(Transaction&& other) noexcept
    : impl_(std::move(other.impl_)),
      active_(std::exchange(other.active_, false)) {}

common::Result<void> SecurityStore::Transaction::SetDeviceState(
    DeviceState state) {
  if (!active_ || impl_ == nullptr) {
    return StoreError("E_SECURITY_DB_TRANSACTION",
                      "security transaction is not active");
  }

  sqlite3_stmt* raw_statement = nullptr;
  if (::sqlite3_prepare_v2(impl_->database.get(),
                           "UPDATE device_state SET state = ? WHERE id = 1;", -1,
                           &raw_statement, nullptr) != SQLITE_OK) {
    return StoreError("E_SECURITY_DB_TRANSACTION",
                      "failed to update device state");
  }
  const auto finalize = [](sqlite3_stmt* statement) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
  };
  std::unique_ptr<sqlite3_stmt, decltype(finalize)> statement(raw_statement,
                                                              finalize);
  const char* value =
      state == DeviceState::kOperational ? "operational" : "default";
  if (::sqlite3_bind_text(statement.get(), 1, value, -1, SQLITE_STATIC) !=
          SQLITE_OK ||
      ::sqlite3_step(statement.get()) != SQLITE_DONE ||
      ::sqlite3_changes(impl_->database.get()) != 1) {
    return StoreError("E_SECURITY_DB_TRANSACTION",
                      "failed to update device state");
  }
  return common::Result<void>::Ok();
}

common::Result<void> SecurityStore::Transaction::Commit() {
  if (!active_ || impl_ == nullptr) {
    return StoreError("E_SECURITY_DB_TRANSACTION",
                      "security transaction is not active");
  }
  auto result = Execute(impl_->database.get(), "COMMIT;",
                        "E_SECURITY_DB_TRANSACTION",
                        "failed to commit security transaction");
  if (result.ok()) {
    active_ = false;
    impl_.reset();
  }
  return result;
}

common::Result<void> SecurityStore::Transaction::Rollback() {
  if (!active_ || impl_ == nullptr) {
    return StoreError("E_SECURITY_DB_TRANSACTION",
                      "security transaction is not active");
  }
  auto result = Execute(impl_->database.get(), "ROLLBACK;",
                        "E_SECURITY_DB_TRANSACTION",
                        "failed to roll back security transaction");
  if (result.ok()) {
    active_ = false;
    impl_.reset();
  }
  return result;
}

bool SecurityStore::Transaction::active() const noexcept { return active_; }

common::Result<std::unique_ptr<SecurityStore>> SecurityStore::Open(
    SecurityStoreConfig config) {
  auto state_directory = std::move(config.state_directory);
  const uid_t effective_user_id = ::geteuid();
  auto state_directory_result =
      EnsureStateDirectory(state_directory, effective_user_id);
  if (!state_directory_result.ok()) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        state_directory_result.error().code, state_directory_result.error().message);
  }

  auto impl = std::make_shared<Impl>();
  impl->state_directory = std::move(state_directory);
  impl->database_path = impl->state_directory / "security.db";
  auto database_result =
      CreateOrValidateDatabase(impl->database_path, effective_user_id);
  if (!database_result.ok()) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        database_result.error().code, database_result.error().message);
  }

  sqlite3* opened_database = nullptr;
  const int open_result = ::sqlite3_open_v2(
      impl->database_path.c_str(), &opened_database,
      SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW,
      nullptr);
  impl->database.reset(opened_database);
  if (open_result != SQLITE_OK) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_OPEN", "failed to open security database");
  }
  database_result =
      CreateOrValidateDatabase(impl->database_path, effective_user_id);
  if (!database_result.ok()) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        database_result.error().code, database_result.error().message);
  }
  if (::sqlite3_busy_timeout(impl->database.get(), kBusyTimeoutMilliseconds) !=
      SQLITE_OK) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_OPEN", "failed to configure security database");
  }

  auto store = std::unique_ptr<SecurityStore>(new SecurityStore(std::move(impl)));
  auto schema_result = store->InitializeSchema();
  if (!schema_result.ok()) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        schema_result.error().code, schema_result.error().message);
  }
  return common::Result<std::unique_ptr<SecurityStore>>::Ok(std::move(store));
}

common::Result<void> SecurityStore::InitializeSchema() {
  auto pragmas = Execute(impl_->database.get(),
                         "PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;",
                         "E_SECURITY_DB_SCHEMA",
                         "failed to configure security database");
  if (!pragmas.ok()) {
    return pragmas;
  }

  int table_count = 0;
  if (!QuerySingleInt(
          impl_->database.get(),
          "SELECT COUNT(*) FROM sqlite_schema "
          "WHERE type = 'table' AND name NOT LIKE 'sqlite_%';",
          table_count)) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "failed to inspect security database schema");
  }
  if (table_count != 0) {
    return ValidateSchema(impl_->database.get());
  }

  constexpr const char* kSchema = R"sql(
CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER NOT NULL
);
INSERT INTO schema_version (version) VALUES (1);
CREATE TABLE IF NOT EXISTS device_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL CHECK (state IN ('default', 'operational'))
);
INSERT INTO device_state (id, state) VALUES (1, 'default');
)sql";
  auto begin = Execute(impl_->database.get(), "BEGIN IMMEDIATE;",
                       "E_SECURITY_DB_SCHEMA",
                       "failed to initialize security database");
  if (!begin.ok()) {
    return begin;
  }
  auto create = Execute(impl_->database.get(), kSchema, "E_SECURITY_DB_SCHEMA",
                        "failed to initialize security database");
  if (!create.ok()) {
    (void)Execute(impl_->database.get(), "ROLLBACK;", "E_SECURITY_DB_SCHEMA",
                  "failed to roll back security database initialization");
    return create;
  }
  auto commit = Execute(impl_->database.get(), "COMMIT;", "E_SECURITY_DB_SCHEMA",
                        "failed to initialize security database");
  if (!commit.ok()) {
    (void)Execute(impl_->database.get(), "ROLLBACK;", "E_SECURITY_DB_SCHEMA",
                  "failed to roll back security database initialization");
    return commit;
  }
  return ValidateSchema(impl_->database.get());
}

common::Result<SecurityStore::Transaction> SecurityStore::BeginTransaction() {
  auto result = Execute(impl_->database.get(), "BEGIN IMMEDIATE;",
                        "E_SECURITY_DB_TRANSACTION",
                        "failed to begin security transaction");
  if (!result.ok()) {
    return common::Result<Transaction>::Err(result.error());
  }
  return common::Result<Transaction>::Ok(Transaction(impl_));
}

common::Result<DeviceState> SecurityStore::State() const {
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(impl_->database.get(),
                           "SELECT state FROM device_state WHERE id = 1;", -1,
                           &statement, nullptr) != SQLITE_OK) {
    return StoreError<DeviceState>("E_SECURITY_DB_STATE",
                                   "failed to read device state");
  }

  const int result = ::sqlite3_step(statement);
  if (result != SQLITE_ROW) {
    (void)::sqlite3_finalize(statement);
    return StoreError<DeviceState>("E_SECURITY_DB_STATE",
                                   "device state is unavailable");
  }
  const unsigned char* value = ::sqlite3_column_text(statement, 0);
  const std::string state =
      value == nullptr ? std::string() : reinterpret_cast<const char*>(value);
  (void)::sqlite3_finalize(statement);

  if (state == "default") {
    return common::Result<DeviceState>::Ok(DeviceState::kDefault);
  }
  if (state == "operational") {
    return common::Result<DeviceState>::Ok(DeviceState::kOperational);
  }
  return StoreError<DeviceState>("E_SECURITY_DB_STATE", "device state is invalid");
}

const std::filesystem::path& SecurityStore::state_directory() const noexcept {
  return impl_->state_directory;
}

const std::filesystem::path& SecurityStore::database_path() const noexcept {
  return impl_->database_path;
}

}  // namespace camera_firmware::security
