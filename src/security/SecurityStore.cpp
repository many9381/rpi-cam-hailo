#include "camera_firmware/security/SecurityStore.hpp"

#include <array>
#include <cerrno>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <openssl/rand.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/rtsp/RtspDigestCredentials.hpp"

namespace camera_firmware::security {
namespace {

constexpr mode_t kStateDirectoryMode = 0700;
constexpr mode_t kDatabaseMode = 0600;
constexpr int kBusyTimeoutMilliseconds = 1000;

class UniqueFd {
 public:
  UniqueFd() = default;
  explicit UniqueFd(int descriptor) noexcept : descriptor_(descriptor) {}
  ~UniqueFd() { Reset(); }

  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;

  UniqueFd(UniqueFd&& other) noexcept
      : descriptor_(std::exchange(other.descriptor_, -1)) {}
  UniqueFd& operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
      Reset();
      descriptor_ = std::exchange(other.descriptor_, -1);
    }
    return *this;
  }

  [[nodiscard]] int get() const noexcept { return descriptor_; }
  [[nodiscard]] bool valid() const noexcept { return descriptor_ >= 0; }

  void Reset(int descriptor = -1) noexcept {
    if (descriptor_ >= 0) {
      (void)::close(descriptor_);
    }
    descriptor_ = descriptor;
  }

 private:
  int descriptor_{-1};
};

int OpenDirectoryNoFollow(const std::filesystem::path& path) noexcept {
  int descriptor;
  do {
    descriptor = ::open(path.c_str(),
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (descriptor < 0 && errno == EINTR);
  return descriptor;
}

int OpenDirectoryAtNoFollow(int parent_fd, const char* name) noexcept {
  int descriptor;
  do {
    descriptor = ::openat(parent_fd, name,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (descriptor < 0 && errno == EINTR);
  return descriptor;
}

bool IsProtectedDirectoryFd(int descriptor, uid_t expected_owner) noexcept {
  struct stat status {};
  return ::fstat(descriptor, &status) == 0 && S_ISDIR(status.st_mode) &&
         status.st_uid == expected_owner &&
         (status.st_mode & 0777) == kStateDirectoryMode;
}

int DuplicateFd(int descriptor) noexcept {
  int duplicate;
  do {
    duplicate = ::fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
  } while (duplicate < 0 && errno == EINTR);
  return duplicate;
}

bool FsyncFd(int descriptor) noexcept {
  int result;
  do {
    result = ::fsync(descriptor);
  } while (result != 0 && errno == EINTR);
  return result == 0;
}

void UnlinkAt(int parent_fd, const char* name) noexcept {
  int result;
  do {
    result = ::unlinkat(parent_fd, name, 0);
  } while (result != 0 && errno == EINTR);
}

class AnchoredStage {
 public:
  AnchoredStage(int parent_fd, std::string name)
      : parent_fd_(parent_fd), name_(std::move(name)) {}
  ~AnchoredStage() {
    if (linked_) {
      UnlinkAt(parent_fd_, name_.c_str());
    }
  }

  AnchoredStage(const AnchoredStage&) = delete;
  AnchoredStage& operator=(const AnchoredStage&) = delete;

  [[nodiscard]] const std::string& name() const noexcept { return name_; }
  void MarkRenamed() noexcept { linked_ = false; }

 private:
  int parent_fd_;
  std::string name_;
  bool linked_{true};
};

common::Result<std::string> GenerateCredentialStageName(
    std::string_view live_name) {
  common::SecureBytes random;
  try {
    random.resize(16U);
  } catch (...) {
    return common::Result<std::string>::Err(
        {"E_RTSP_AUTH_CREDENTIALS", "credential installation failed"});
  }
  if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
    return common::Result<std::string>::Err(
        {"E_RTSP_AUTH_CREDENTIALS", "credential installation failed"});
  }
  static constexpr char kHex[] = "0123456789abcdef";
  std::string name = "." + std::string(live_name) + ".bootstrap-";
  name.reserve(name.size() + random.size() * 2U);
  for (std::size_t index = 0; index < random.size(); ++index) {
    name.push_back(kHex[random.data()[index] >> 4U]);
    name.push_back(kHex[random.data()[index] & 0x0fU]);
  }
  return common::Result<std::string>::Ok(std::move(name));
}

bool SameDirectory(int first, int second) noexcept {
  struct stat first_status {};
  struct stat second_status {};
  return ::fstat(first, &first_status) == 0 &&
         ::fstat(second, &second_status) == 0 &&
         first_status.st_dev == second_status.st_dev &&
         first_status.st_ino == second_status.st_ino;
}

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

bool StatementSucceeds(sqlite3* database, const char* sql) {
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) {
    return false;
  }
  const bool succeeded = ::sqlite3_step(statement) == SQLITE_DONE;
  const bool finalized = ::sqlite3_finalize(statement) == SQLITE_OK;
  return succeeded && finalized;
}

std::string NormalizeSchemaSql(std::string_view sql) {
  std::string normalized;
  normalized.reserve(sql.size());
  bool in_string = false;
  for (std::size_t index = 0; index < sql.size(); ++index) {
    const unsigned char value = static_cast<unsigned char>(sql[index]);
    if (value == '\'' && in_string && index + 1U < sql.size() &&
        sql[index + 1U] == '\'') {
      normalized.push_back('\'');
      normalized.push_back('\'');
      ++index;
      continue;
    }
    if (value == '\'') {
      in_string = !in_string;
      normalized.push_back('\'');
      continue;
    }
    if (!in_string &&
        (value == ' ' || value == '\t' || value == '\r' || value == '\n')) {
      continue;
    }
    normalized.push_back(static_cast<char>(
        !in_string && value >= 'A' && value <= 'Z'
            ? value + ('a' - 'A')
            : value));
  }
  return normalized;
}

bool ReadSchemaSql(sqlite3* database,
                   const char* object_name,
                   std::string& sql) {
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "SELECT sql FROM sqlite_schema WHERE name = ?1;";
  if (::sqlite3_prepare_v2(database, kSql, -1, &statement, nullptr) !=
          SQLITE_OK ||
      ::sqlite3_bind_text(statement, 1, object_name, -1, SQLITE_STATIC) !=
          SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_ROW) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return false;
  }
  const auto* value = ::sqlite3_column_text(statement, 0);
  if (value == nullptr) {
    (void)::sqlite3_finalize(statement);
    return false;
  }
  sql = reinterpret_cast<const char*>(value);
  const bool one_row = ::sqlite3_step(statement) == SQLITE_DONE;
  return one_row && ::sqlite3_finalize(statement) == SQLITE_OK;
}

bool ValidateSchemaObjectSql(sqlite3* database,
                             const char* object_name,
                             std::string_view expected_sql) {
  std::string actual_sql;
  return ReadSchemaSql(database, object_name, actual_sql) &&
         NormalizeSchemaSql(actual_sql) == NormalizeSchemaSql(expected_sql);
}

bool ValidateIndex(sqlite3* database,
                   const char* table_name,
                   const char* index_name,
                   bool expected_unique,
                   bool expected_partial,
                   const char* expected_column,
                   const char* expected_collation,
                   std::string_view expected_sql) {
  sqlite3_stmt* list = nullptr;
  constexpr const char* kListSql =
      "SELECT \"unique\", origin, partial FROM pragma_index_list(?1) "
      "WHERE name = ?2;";
  if (::sqlite3_prepare_v2(database, kListSql, -1, &list, nullptr) !=
          SQLITE_OK ||
      ::sqlite3_bind_text(list, 1, table_name, -1, SQLITE_STATIC) != SQLITE_OK ||
      ::sqlite3_bind_text(list, 2, index_name, -1, SQLITE_STATIC) != SQLITE_OK ||
      ::sqlite3_step(list) != SQLITE_ROW) {
    if (list != nullptr) {
      (void)::sqlite3_finalize(list);
    }
    return false;
  }
  const auto* origin = ::sqlite3_column_text(list, 1);
  const bool list_fields_valid =
      ::sqlite3_column_int(list, 0) == (expected_unique ? 1 : 0) &&
      origin != nullptr &&
      std::string_view(reinterpret_cast<const char*>(origin)) == "c" &&
      ::sqlite3_column_int(list, 2) == (expected_partial ? 1 : 0);
  const bool list_has_one_row = ::sqlite3_step(list) == SQLITE_DONE;
  const bool list_finalized = ::sqlite3_finalize(list) == SQLITE_OK;
  if (!list_fields_valid || !list_has_one_row || !list_finalized) {
    return false;
  }

  sqlite3_stmt* columns = nullptr;
  constexpr const char* kColumnsSql =
      "SELECT name, coll, desc FROM pragma_index_xinfo(?1) "
      "WHERE key = 1 ORDER BY seqno;";
  if (::sqlite3_prepare_v2(database, kColumnsSql, -1, &columns, nullptr) !=
          SQLITE_OK ||
      ::sqlite3_bind_text(columns, 1, index_name, -1, SQLITE_STATIC) !=
          SQLITE_OK ||
      ::sqlite3_step(columns) != SQLITE_ROW) {
    if (columns != nullptr) {
      (void)::sqlite3_finalize(columns);
    }
    return false;
  }
  const auto* column = ::sqlite3_column_text(columns, 0);
  const auto* collation = ::sqlite3_column_text(columns, 1);
  const bool column_fields_valid =
      column != nullptr && collation != nullptr &&
      std::string_view(reinterpret_cast<const char*>(column)) ==
          expected_column &&
      std::string_view(reinterpret_cast<const char*>(collation)) ==
          expected_collation &&
      ::sqlite3_column_int(columns, 2) == 0;
  const bool columns_have_one_row = ::sqlite3_step(columns) == SQLITE_DONE;
  const bool columns_finalized = ::sqlite3_finalize(columns) == SQLITE_OK;
  if (!column_fields_valid || !columns_have_one_row || !columns_finalized) {
    return false;
  }

  return ValidateSchemaObjectSql(database, index_name, expected_sql);
}

struct ForeignKeyInfo {
  std::string referenced_table;
  std::string from_column;
  std::string to_column;
  std::string on_update;
  std::string on_delete;
  std::string match;

  bool operator==(const ForeignKeyInfo&) const = default;
};

bool ReadForeignKeys(sqlite3* database,
                     const char* table_name,
                     std::vector<ForeignKeyInfo>& foreign_keys) {
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "SELECT \"table\", \"from\", \"to\", on_update, on_delete, match "
      "FROM pragma_foreign_key_list(?1) ORDER BY id, seq;";
  if (::sqlite3_prepare_v2(database, kSql, -1, &statement, nullptr) !=
          SQLITE_OK ||
      ::sqlite3_bind_text(statement, 1, table_name, -1, SQLITE_STATIC) !=
          SQLITE_OK) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return false;
  }
  int step;
  while ((step = ::sqlite3_step(statement)) == SQLITE_ROW) {
    const auto* table = ::sqlite3_column_text(statement, 0);
    const auto* from = ::sqlite3_column_text(statement, 1);
    const auto* to = ::sqlite3_column_text(statement, 2);
    const auto* on_update = ::sqlite3_column_text(statement, 3);
    const auto* on_delete = ::sqlite3_column_text(statement, 4);
    const auto* match = ::sqlite3_column_text(statement, 5);
    if (table == nullptr || from == nullptr || to == nullptr ||
        on_update == nullptr || on_delete == nullptr || match == nullptr) {
      (void)::sqlite3_finalize(statement);
      return false;
    }
    foreign_keys.push_back(
        {reinterpret_cast<const char*>(table),
         reinterpret_cast<const char*>(from),
         reinterpret_cast<const char*>(to),
         reinterpret_cast<const char*>(on_update),
         reinterpret_cast<const char*>(on_delete),
         reinterpret_cast<const char*>(match)});
  }
  return step == SQLITE_DONE && ::sqlite3_finalize(statement) == SQLITE_OK;
}

bool HasExactSchemaObjectInventory(sqlite3* database) {
  int value = 0;
  // Revision 1 has no SQLite-generated autoindexes: all approved uniqueness is
  // represented by the named indexes below. Requiring the complete inventory
  // rejects internal autoindexes as well as application triggers and views.
  constexpr const char* kUnexpectedObjectCount = R"sql(
SELECT COUNT(*)
FROM sqlite_schema
WHERE NOT (
  (type = 'table' AND (
    (name = 'schema_version' AND tbl_name = 'schema_version') OR
    (name = 'device_state' AND tbl_name = 'device_state') OR
    (name = 'users' AND tbl_name = 'users') OR
    (name = 'management_ips' AND tbl_name = 'management_ips') OR
    (name = 'sessions' AND tbl_name = 'sessions') OR
    (name = 'audit_events' AND tbl_name = 'audit_events')
  )) OR
  (type = 'index' AND (
    (name = 'users_canonical_username_unique' AND tbl_name = 'users') OR
    (name = 'users_single_administrator_unique' AND tbl_name = 'users') OR
    (name = 'management_ips_normalized_ip_unique' AND
     tbl_name = 'management_ips') OR
    (name = 'sessions_token_hash_unique' AND tbl_name = 'sessions') OR
    (name = 'sessions_single_administrator_unique' AND
     tbl_name = 'sessions') OR
    (name = 'sessions_expiry_index' AND tbl_name = 'sessions') OR
    (name = 'audit_events_timestamp_index' AND tbl_name = 'audit_events')
  ))
);
)sql";
  return QuerySingleInt(database, kUnexpectedObjectCount, value) && value == 0 &&
         QuerySingleInt(database, "SELECT COUNT(*) FROM sqlite_schema;", value) &&
         value == 13;
}

bool HasValidCommittedState(sqlite3* database) {
  int value = 0;
  if (!QuerySingleInt(database,
                      "SELECT COUNT(*) FROM pragma_foreign_key_check;", value) ||
      value != 0) {
    return false;
  }

  constexpr const char* kStateInvariant = R"sql(
SELECT CASE state
  WHEN 'default' THEN
    (SELECT COUNT(*) FROM users) = 0 AND
    (SELECT COUNT(*) FROM management_ips) = 0 AND
    (SELECT COUNT(*) FROM sessions) = 0 AND
    (SELECT COUNT(*) FROM audit_events
      WHERE event_type = 'bootstrap_completed' AND outcome = 'success') = 0
  WHEN 'operational' THEN
    (SELECT COUNT(*) FROM users
      WHERE role = 'administrator' AND enabled = 1) = 1 AND
    (SELECT COUNT(*) FROM audit_events
      WHERE event_type = 'bootstrap_completed' AND outcome = 'success') = 1 AND
    EXISTS (
      SELECT 1
      FROM audit_events AS audit
      JOIN users AS administrator
        ON administrator.id = audit.actor_user_id
      JOIN management_ips AS management_ip
        ON management_ip.normalized_ip = audit.peer_ip
      WHERE audit.event_type = 'bootstrap_completed'
        AND audit.outcome = 'success'
        AND administrator.role = 'administrator'
        AND administrator.enabled = 1
        AND management_ip.role_scope = 'administrator'
        AND management_ip.enabled = 1
    )
  ELSE 0
END
FROM device_state
WHERE id = 1;
)sql";
  return QuerySingleInt(database, kStateInvariant, value) && value == 1;
}

common::Result<void> ValidateSchema(sqlite3* database) {
  int value = 0;
  // The complete object inventory is read before any validation DML so an
  // unapproved trigger cannot run from the destructive constraint probes.
  if (!HasExactSchemaObjectInventory(database) ||
      !QuerySingleInt(database, "PRAGMA foreign_keys;", value) || value != 1 ||
      !QuerySingleInt(database, "PRAGMA secure_delete;", value) || value != 1 ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM sqlite_schema "
          "WHERE type = 'table' AND name NOT LIKE 'sqlite_%';",
          value) ||
      value != 6 ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM sqlite_schema "
          "WHERE type = 'table' "
          "AND name IN ('schema_version', 'device_state', 'users', "
          "'management_ips', 'sessions', 'audit_events');",
          value) ||
      value != 6 ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'index' "
          "AND name NOT LIKE 'sqlite_%';",
          value) ||
      value != 7 ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'index' AND name IN "
          "('users_canonical_username_unique', "
          "'users_single_administrator_unique', "
          "'management_ips_normalized_ip_unique', "
          "'sessions_token_hash_unique', "
          "'sessions_single_administrator_unique', "
          "'sessions_expiry_index', 'audit_events_timestamp_index');",
          value) ||
      value != 7) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  if (!ValidateIndex(database, "users", "users_canonical_username_unique",
                     true, false, "canonical_username", "NOCASE",
                     "CREATE UNIQUE INDEX users_canonical_username_unique "
                     "ON users(canonical_username COLLATE NOCASE)") ||
      !ValidateIndex(database, "users",
                     "users_single_administrator_unique", true, true, "role",
                     "BINARY",
                     "CREATE UNIQUE INDEX users_single_administrator_unique "
                     "ON users(role) WHERE role = 'administrator'") ||
      !ValidateIndex(database, "management_ips",
                     "management_ips_normalized_ip_unique", true, false,
                     "normalized_ip", "BINARY",
                     "CREATE UNIQUE INDEX management_ips_normalized_ip_unique "
                     "ON management_ips(normalized_ip)") ||
      !ValidateIndex(database, "sessions", "sessions_token_hash_unique", true,
                     false, "token_hash", "BINARY",
                     "CREATE UNIQUE INDEX sessions_token_hash_unique "
                     "ON sessions(token_hash)") ||
      !ValidateIndex(database, "sessions",
                     "sessions_single_administrator_unique", true, true,
                     "role", "BINARY",
                     "CREATE UNIQUE INDEX sessions_single_administrator_unique "
                     "ON sessions(role) WHERE role = 'administrator'") ||
      !ValidateIndex(database, "sessions", "sessions_expiry_index", false,
                     false, "expires_at_seconds", "BINARY",
                     "CREATE INDEX sessions_expiry_index "
                     "ON sessions(expires_at_seconds)") ||
      !ValidateIndex(database, "audit_events", "audit_events_timestamp_index",
                     false, false, "server_timestamp_seconds", "BINARY",
                     "CREATE INDEX audit_events_timestamp_index "
                     "ON audit_events(server_timestamp_seconds)")) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  std::vector<ForeignKeyInfo> schema_version_foreign_keys;
  std::vector<ForeignKeyInfo> state_foreign_keys;
  std::vector<ForeignKeyInfo> user_foreign_keys;
  std::vector<ForeignKeyInfo> management_foreign_keys;
  std::vector<ForeignKeyInfo> session_foreign_keys;
  std::vector<ForeignKeyInfo> audit_foreign_keys;
  if (!ReadForeignKeys(database, "schema_version",
                       schema_version_foreign_keys) ||
      !schema_version_foreign_keys.empty() ||
      !ReadForeignKeys(database, "device_state", state_foreign_keys) ||
      !state_foreign_keys.empty() ||
      !ReadForeignKeys(database, "users", user_foreign_keys) ||
      !user_foreign_keys.empty() ||
      !ReadForeignKeys(database, "management_ips", management_foreign_keys) ||
      !management_foreign_keys.empty() ||
      !ReadForeignKeys(database, "sessions", session_foreign_keys) ||
      session_foreign_keys !=
          std::vector<ForeignKeyInfo>{{"users", "user_id", "id", "NO ACTION",
                                       "CASCADE", "NONE"}} ||
      !ReadForeignKeys(database, "audit_events", audit_foreign_keys) ||
      audit_foreign_keys !=
          std::vector<ForeignKeyInfo>{{"users", "actor_user_id", "id",
                                       "NO ACTION", "SET NULL", "NONE"}}) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  std::vector<ColumnInfo> schema_version_columns;
  std::vector<ColumnInfo> device_state_columns;
  std::vector<ColumnInfo> users_columns;
  std::vector<ColumnInfo> management_ip_columns;
  std::vector<ColumnInfo> sessions_columns;
  std::vector<ColumnInfo> audit_columns;
  if (!ReadColumns(database, "schema_version", schema_version_columns) ||
      schema_version_columns !=
          std::vector<ColumnInfo>{{"version", "INTEGER", 1, 0}} ||
      !ReadColumns(database, "device_state", device_state_columns) ||
      device_state_columns !=
          std::vector<ColumnInfo>{{"id", "INTEGER", 0, 1},
                                  {"state", "TEXT", 1, 0},
                                  {"schema_revision", "INTEGER", 1, 0},
                                  {"setup_completed_at_seconds", "INTEGER", 0,
                                   0}} ||
      !ReadColumns(database, "users", users_columns) ||
      users_columns !=
          std::vector<ColumnInfo>{
              {"id", "INTEGER", 0, 1},
              {"canonical_username", "TEXT", 1, 0},
              {"display_username", "TEXT", 1, 0},
              {"role", "TEXT", 1, 0},
              {"enabled", "INTEGER", 1, 0},
              {"password_algorithm", "TEXT", 1, 0},
              {"password_iterations", "INTEGER", 1, 0},
              {"password_salt", "BLOB", 1, 0},
              {"password_derived", "BLOB", 1, 0},
              {"password_changed_at_seconds", "INTEGER", 1, 0},
              {"failed_login_count", "INTEGER", 1, 0},
              {"lock_until_seconds", "INTEGER", 0, 0},
              {"created_at_seconds", "INTEGER", 1, 0},
              {"last_login_at_seconds", "INTEGER", 0, 0}} ||
      !ReadColumns(database, "management_ips", management_ip_columns) ||
      management_ip_columns !=
          std::vector<ColumnInfo>{{"id", "INTEGER", 0, 1},
                                  {"normalized_ip", "TEXT", 1, 0},
                                  {"role_scope", "TEXT", 1, 0},
                                  {"enabled", "INTEGER", 1, 0},
                                  {"created_at_seconds", "INTEGER", 1, 0}} ||
      !ReadColumns(database, "sessions", sessions_columns) ||
      sessions_columns !=
          std::vector<ColumnInfo>{{"id", "INTEGER", 0, 1},
                                  {"token_hash", "BLOB", 1, 0},
                                  {"user_id", "INTEGER", 1, 0},
                                  {"role", "TEXT", 1, 0},
                                  {"created_at_seconds", "INTEGER", 1, 0},
                                  {"last_activity_at_seconds", "INTEGER", 1,
                                   0},
                                  {"expires_at_seconds", "INTEGER", 1, 0},
                                  {"peer_ip", "TEXT", 1, 0}} ||
      !ReadColumns(database, "audit_events", audit_columns) ||
      audit_columns !=
          std::vector<ColumnInfo>{{"sequence", "INTEGER", 0, 1},
                                  {"server_timestamp_seconds", "INTEGER", 1,
                                   0},
                                  {"event_type", "TEXT", 1, 0},
                                  {"outcome", "TEXT", 1, 0},
                                  {"actor_user_id", "INTEGER", 0, 0},
                                  {"peer_ip", "TEXT", 1, 0},
                                  {"detail_code", "TEXT", 1, 0}} ||
      !QuerySingleInt(database,
                      "SELECT COUNT(*) FROM schema_version WHERE version = 1;",
                      value) ||
      value != 1 ||
      !QuerySingleInt(database, "SELECT COUNT(*) FROM schema_version;", value) ||
      value != 1 ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM device_state "
          "WHERE id = 1 AND schema_revision = 1 AND "
          "((state = 'default' AND setup_completed_at_seconds IS NULL) OR "
          "(state = 'operational' AND setup_completed_at_seconds >= 0));",
          value) ||
      value != 1 ||
      !QuerySingleInt(database, "SELECT COUNT(*) FROM device_state;", value) ||
      value != 1) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  const std::array<std::pair<const char*, std::string_view>, 6>
      expected_table_definitions = {{
          {"schema_version", R"sql(
CREATE TABLE schema_version (
  version INTEGER NOT NULL CHECK (version = 1)
))sql"},
          {"device_state", R"sql(
CREATE TABLE device_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL CHECK (state IN ('default', 'operational')),
  schema_revision INTEGER NOT NULL CHECK (schema_revision = 1),
  setup_completed_at_seconds INTEGER,
  CHECK (
    (state = 'default' AND setup_completed_at_seconds IS NULL) OR
    (state = 'operational' AND setup_completed_at_seconds IS NOT NULL AND
     setup_completed_at_seconds >= 0)
  )
))sql"},
          {"users", R"sql(
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  canonical_username TEXT NOT NULL
    CHECK (length(canonical_username) BETWEEN 5 AND 32)
    CHECK (canonical_username = lower(canonical_username)),
  display_username TEXT NOT NULL
    CHECK (length(display_username) BETWEEN 5 AND 32),
  role TEXT NOT NULL CHECK (role IN ('administrator')),
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
    CHECK (failed_login_count >= 0),
  lock_until_seconds INTEGER CHECK (lock_until_seconds >= 0),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0),
  last_login_at_seconds INTEGER CHECK (last_login_at_seconds >= 0)
))sql"},
          {"management_ips", R"sql(
CREATE TABLE management_ips (
  id INTEGER PRIMARY KEY,
  normalized_ip TEXT NOT NULL CHECK (length(normalized_ip) BETWEEN 2 AND 45),
  role_scope TEXT NOT NULL CHECK (role_scope IN ('administrator')),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0)
))sql"},
          {"sessions", R"sql(
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,
  token_hash BLOB NOT NULL CHECK (length(token_hash) = 32),
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('administrator')),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0),
  last_activity_at_seconds INTEGER NOT NULL
    CHECK (last_activity_at_seconds >= created_at_seconds),
  expires_at_seconds INTEGER NOT NULL
    CHECK (expires_at_seconds >= last_activity_at_seconds),
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45)
))sql"},
          {"audit_events", R"sql(
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY,
  server_timestamp_seconds INTEGER NOT NULL
    CHECK (server_timestamp_seconds >= 0),
  event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45),
  detail_code TEXT NOT NULL CHECK (length(detail_code) <= 64)
))sql"},
      }};
  for (const auto& [table_name, expected_sql] : expected_table_definitions) {
    if (!ValidateSchemaObjectSql(database, table_name, expected_sql)) {
      return StoreError("E_SECURITY_DB_SCHEMA",
                        "security database schema is invalid");
    }
  }

  if (!HasValidCommittedState(database)) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  auto savepoint = Execute(database, "SAVEPOINT schema_validation;",
                           "E_SECURITY_DB_SCHEMA",
                           "failed to validate security database schema");
  if (!savepoint.ok()) {
    return savepoint;
  }
  const auto preparation = Execute(
      database,
      "DELETE FROM audit_events; DELETE FROM sessions; "
      "DELETE FROM management_ips; DELETE FROM users; "
      "UPDATE device_state SET state = 'default', "
      "setup_completed_at_seconds = NULL WHERE id = 1;",
      "E_SECURITY_DB_SCHEMA", "failed to validate security database schema");
  const bool prepared = preparation.ok();
  const bool constraints_valid =
      prepared &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO schema_version (version) VALUES (NULL);") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO schema_version (version) VALUES (2);") &&
      StatementIsRejectedByConstraint(
          database, "INSERT INTO device_state "
                    "(id, state, schema_revision) VALUES (2, 'default', 1);") &&
      StatementIsRejectedByConstraint(
          database,
          "UPDATE device_state SET state = 'invalid' WHERE id = 1;") &&
      StatementIsRejectedByConstraint(
          database,
          "UPDATE device_state SET state = 'operational', "
          "setup_completed_at_seconds = NULL WHERE id = 1;") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO users "
          "(canonical_username, display_username, role, enabled, "
          "password_algorithm, password_iterations, password_salt, "
          "password_derived, password_changed_at_seconds, "
          "failed_login_count, created_at_seconds) VALUES "
          "('Upper', 'Upper', 'administrator', 1, "
          "'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), 1, 0, 1);") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO users "
          "(canonical_username, display_username, role, enabled, "
          "password_algorithm, password_iterations, password_salt, "
          "password_derived, password_changed_at_seconds, "
          "failed_login_count, created_at_seconds) VALUES "
          "('short.salt', 'short.salt', 'administrator', 1, "
          "'pbkdf2-hmac-sha256', 600000, zeroblob(15), zeroblob(32), 1, 0, 1);") &&
      StatementSucceeds(
          database,
          "INSERT INTO users "
          "(canonical_username, display_username, role, enabled, "
          "password_algorithm, password_iterations, password_salt, "
          "password_derived, password_changed_at_seconds, "
          "failed_login_count, created_at_seconds) VALUES "
          "('operator.one', 'Operator.One', 'administrator', 1, "
          "'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), 1, 0, 1);") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO users "
          "(canonical_username, display_username, role, enabled, "
          "password_algorithm, password_iterations, password_salt, "
          "password_derived, password_changed_at_seconds, "
          "failed_login_count, created_at_seconds) VALUES "
          "('operator.two', 'Operator.Two', 'administrator', 1, "
          "'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), 1, 0, 1);") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO management_ips "
          "(normalized_ip, role_scope, enabled, created_at_seconds) "
          "VALUES ('192.0.2.1', 'invalid', 1, 1);") &&
      StatementSucceeds(
          database,
          "INSERT INTO management_ips "
          "(normalized_ip, role_scope, enabled, created_at_seconds) "
          "VALUES ('192.0.2.1', 'administrator', 1, 1);") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO management_ips "
          "(normalized_ip, role_scope, enabled, created_at_seconds) "
          "VALUES ('192.0.2.1', 'administrator', 1, 1);") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO sessions "
          "(token_hash, user_id, role, created_at_seconds, "
          "last_activity_at_seconds, expires_at_seconds, peer_ip) "
          "VALUES (zeroblob(31), (SELECT id FROM users LIMIT 1), "
          "'administrator', 1, 1, 2, '192.0.2.1');") &&
      StatementSucceeds(
          database,
          "INSERT INTO sessions "
          "(token_hash, user_id, role, created_at_seconds, "
          "last_activity_at_seconds, expires_at_seconds, peer_ip) "
          "VALUES (zeroblob(32), (SELECT id FROM users LIMIT 1), "
          "'administrator', 1, 1, 2, '192.0.2.1');") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO sessions "
          "(token_hash, user_id, role, created_at_seconds, "
          "last_activity_at_seconds, expires_at_seconds, peer_ip) "
          "VALUES (zeroblob(32), (SELECT id FROM users LIMIT 1), "
          "'administrator', 1, 1, 2, '192.0.2.1');") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO sessions "
          "(token_hash, user_id, role, created_at_seconds, "
          "last_activity_at_seconds, expires_at_seconds, peer_ip) "
          "VALUES (randomblob(32), (SELECT id FROM users LIMIT 1), "
          "'administrator', 1, 1, 2, '192.0.2.1');") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO audit_events "
          "(server_timestamp_seconds, event_type, outcome, actor_user_id, "
          "peer_ip, detail_code) "
          "VALUES (1, 'event', 'invalid', "
          "(SELECT id FROM users LIMIT 1), '192.0.2.1', 'detail');") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO audit_events "
          "(server_timestamp_seconds, event_type, outcome, actor_user_id, "
          "peer_ip, detail_code) "
          "VALUES (1, 'event', 'success', 999999, '192.0.2.1', 'detail');");
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
  UniqueFd state_directory_fd;
  std::unique_ptr<sqlite3, DatabaseCloser> database;
  std::mutex connection_mutex;
  bool poisoned{false};
};

SecurityStore::SecurityStore(std::shared_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

SecurityStore::~SecurityStore() = default;

SecurityStore::Transaction::Transaction(
    std::shared_ptr<Impl> impl,
    std::unique_lock<std::mutex> connection_lease) noexcept
    : impl_(std::move(impl)),
      connection_lease_(std::move(connection_lease)),
      active_(true) {}

SecurityStore::Transaction::~Transaction() {
  if (active_ && impl_ != nullptr) {
    (void)Rollback();
  }
}

SecurityStore::Transaction::Transaction(Transaction&& other) noexcept
    : impl_(std::move(other.impl_)),
      connection_lease_(std::move(other.connection_lease_)),
      active_(std::exchange(other.active_, false)) {}

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
    connection_lease_.unlock();
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
    connection_lease_.unlock();
    impl_.reset();
  } else {
    impl_->poisoned = true;
    impl_->database.reset();
    active_ = false;
    connection_lease_.unlock();
    impl_.reset();
  }
  return result;
}

bool SecurityStore::Transaction::active() const noexcept { return active_; }

common::Result<std::unique_ptr<SecurityStore>> SecurityStore::Open(
    SecurityStoreConfig config) {
  auto state_directory = std::move(config.state_directory);
  if (state_directory.empty()) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_PATH", "security state directory is empty");
  }
  std::error_code path_error;
  state_directory =
      std::filesystem::absolute(state_directory, path_error).lexically_normal();
  if (path_error) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_PATH", "security state directory is invalid");
  }
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
  impl->state_directory_fd.Reset(
      OpenDirectoryNoFollow(impl->state_directory));
  if (!impl->state_directory_fd.valid() ||
      !IsProtectedDirectoryFd(impl->state_directory_fd.get(),
                              effective_user_id)) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_PATH", "failed to anchor security state directory");
  }
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
  UniqueFd current_state_directory(
      OpenDirectoryNoFollow(impl->state_directory));
  if (!current_state_directory.valid() ||
      !IsProtectedDirectoryFd(current_state_directory.get(),
                              effective_user_id) ||
      !SameDirectory(impl->state_directory_fd.get(),
                     current_state_directory.get())) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_PATH", "security state directory changed during open");
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
  std::unique_lock connection_lease(impl_->connection_mutex);
  auto pragmas = Execute(impl_->database.get(),
                         "PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;",
                         "E_SECURITY_DB_SCHEMA",
                         "failed to configure security database");
  if (!pragmas.ok()) {
    return pragmas;
  }

  int schema_object_count = 0;
  if (!QuerySingleInt(
          impl_->database.get(),
          "SELECT COUNT(*) FROM sqlite_schema;", schema_object_count)) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "failed to inspect security database schema");
  }
  if (schema_object_count != 0) {
    return ValidateSchema(impl_->database.get());
  }

  constexpr const char* kSchema = R"sql(
CREATE TABLE schema_version (
  version INTEGER NOT NULL CHECK (version = 1)
);
INSERT INTO schema_version (version) VALUES (1);
CREATE TABLE device_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL CHECK (state IN ('default', 'operational')),
  schema_revision INTEGER NOT NULL CHECK (schema_revision = 1),
  setup_completed_at_seconds INTEGER,
  CHECK (
    (state = 'default' AND setup_completed_at_seconds IS NULL) OR
    (state = 'operational' AND setup_completed_at_seconds IS NOT NULL AND
     setup_completed_at_seconds >= 0)
  )
);
INSERT INTO device_state (id, state, schema_revision)
VALUES (1, 'default', 1);

CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  canonical_username TEXT NOT NULL
    CHECK (length(canonical_username) BETWEEN 5 AND 32)
    CHECK (canonical_username = lower(canonical_username)),
  display_username TEXT NOT NULL
    CHECK (length(display_username) BETWEEN 5 AND 32),
  role TEXT NOT NULL CHECK (role IN ('administrator')),
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
    CHECK (failed_login_count >= 0),
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
  role TEXT NOT NULL CHECK (role IN ('administrator')),
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
  std::unique_lock<std::mutex> connection_lease;
  try {
    connection_lease = std::unique_lock(impl_->connection_mutex);
  } catch (...) {
    return common::Result<Transaction>::Err(
        {"E_SECURITY_DB_TRANSACTION", "failed to lease security connection"});
  }
  if (impl_->poisoned || impl_->database == nullptr) {
    return common::Result<Transaction>::Err(
        {"E_SECURITY_DB_POISONED", "security store is unavailable"});
  }
  auto result = Execute(impl_->database.get(), "BEGIN IMMEDIATE;",
                        "E_SECURITY_DB_TRANSACTION",
                        "failed to begin security transaction");
  if (!result.ok()) {
    return common::Result<Transaction>::Err(result.error());
  }
  return common::Result<Transaction>::Ok(
      Transaction(impl_, std::move(connection_lease)));
}

common::Result<void> SecurityStore::InitializeDevice(
    BootstrapRecord record,
    const CredentialInstaller& install_credential) {
  auto started = BeginTransaction();
  if (!started.ok()) {
    return StoreError(started.error().code == "E_SECURITY_DB_POISONED"
                          ? "E_SECURITY_DB_POISONED"
                          : "E_BOOTSTRAP_STORE",
                      started.error().code == "E_SECURITY_DB_POISONED"
                          ? "security store is unavailable"
                          : "bootstrap transaction failed");
  }
  auto transaction = std::move(started).value();
  const auto fail = [&transaction](std::string code, std::string message) {
    auto rollback = transaction.Rollback();
    if (!rollback.ok()) {
      return StoreError("E_BOOTSTRAP_STORE", "bootstrap rollback failed");
    }
    return StoreError(std::move(code), std::move(message));
  };

  try {
    auto state = StateUnderConnectionLease();
    if (!state.ok()) {
      return fail("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
    }
    if (state.value() != DeviceState::kDefault) {
      return fail("E_BOOTSTRAP_UNAVAILABLE", "device setup is unavailable");
    }

    sqlite3_stmt* raw_user = nullptr;
    constexpr const char* kInsertUser =
        "INSERT INTO users "
        "(canonical_username, display_username, role, enabled, "
        "password_algorithm, password_iterations, password_salt, "
        "password_derived, password_changed_at_seconds, "
        "failed_login_count, created_at_seconds) "
        "VALUES (?1, ?2, 'administrator', 1, ?3, ?4, ?5, ?6, ?7, 0, ?7);";
    if (::sqlite3_prepare_v2(impl_->database.get(), kInsertUser, -1, &raw_user,
                             nullptr) != SQLITE_OK) {
      return fail("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
    }
    const auto finalize = [](sqlite3_stmt* statement) {
      if (statement != nullptr) {
        (void)::sqlite3_finalize(statement);
      }
    };
    std::unique_ptr<sqlite3_stmt, decltype(finalize)> user(raw_user, finalize);
    if (::sqlite3_bind_text(user.get(), 1, record.canonical_username.data(),
                            static_cast<int>(record.canonical_username.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_text(user.get(), 2, record.display_username.data(),
                            static_cast<int>(record.display_username.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_text(user.get(), 3, record.password.algorithm.data(),
                            static_cast<int>(record.password.algorithm.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int64(user.get(), 4, record.password.iterations) !=
            SQLITE_OK ||
        ::sqlite3_bind_blob(
            user.get(), 5, record.password.salt.data(),
            static_cast<int>(record.password.salt.size()), SQLITE_TRANSIENT) !=
            SQLITE_OK ||
        ::sqlite3_bind_blob(
            user.get(), 6, record.password.derived.data(),
            static_cast<int>(record.password.derived.size()),
            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int64(user.get(), 7, record.completed_at_seconds) !=
            SQLITE_OK ||
        ::sqlite3_step(user.get()) != SQLITE_DONE) {
      return fail("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
    }
    const sqlite3_int64 user_id =
        ::sqlite3_last_insert_rowid(impl_->database.get());
    user.reset();

    sqlite3_stmt* raw_management_ip = nullptr;
    constexpr const char* kInsertManagementIp =
        "INSERT INTO management_ips "
        "(normalized_ip, role_scope, enabled, created_at_seconds) "
        "VALUES (?1, 'administrator', 1, ?2);";
    if (::sqlite3_prepare_v2(impl_->database.get(), kInsertManagementIp, -1,
                             &raw_management_ip, nullptr) != SQLITE_OK) {
      return fail("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
    }
    std::unique_ptr<sqlite3_stmt, decltype(finalize)> management_ip(
        raw_management_ip, finalize);
    if (::sqlite3_bind_text(management_ip.get(), 1,
                            record.normalized_peer_ip.data(),
                            static_cast<int>(record.normalized_peer_ip.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int64(management_ip.get(), 2,
                             record.completed_at_seconds) != SQLITE_OK ||
        ::sqlite3_step(management_ip.get()) != SQLITE_DONE) {
      return fail("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
    }
    management_ip.reset();

    sqlite3_stmt* raw_audit = nullptr;
    constexpr const char* kInsertAudit =
        "INSERT INTO audit_events "
        "(server_timestamp_seconds, event_type, outcome, actor_user_id, "
        "peer_ip, detail_code) "
        "VALUES (?1, 'bootstrap_completed', 'success', ?2, ?3, "
        "'initial_administrator');";
    if (::sqlite3_prepare_v2(impl_->database.get(), kInsertAudit, -1,
                             &raw_audit, nullptr) != SQLITE_OK) {
      return fail("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
    }
    std::unique_ptr<sqlite3_stmt, decltype(finalize)> audit(raw_audit, finalize);
    if (::sqlite3_bind_int64(audit.get(), 1, record.completed_at_seconds) !=
            SQLITE_OK ||
        ::sqlite3_bind_int64(audit.get(), 2, user_id) != SQLITE_OK ||
        ::sqlite3_bind_text(audit.get(), 3, record.normalized_peer_ip.data(),
                            static_cast<int>(record.normalized_peer_ip.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_step(audit.get()) != SQLITE_DONE) {
      return fail("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
    }
    audit.reset();

    common::Result<void> installed = common::Result<void>::Err(
        {"E_BOOTSTRAP_CREDENTIAL", "credential installation failed"});
    try {
      if (install_credential) {
        installed = install_credential();
      }
    } catch (...) {
      return fail("E_BOOTSTRAP_CREDENTIAL",
                  "credential installation failed");
    }
    if (!installed.ok()) {
      return fail("E_BOOTSTRAP_CREDENTIAL",
                  "credential installation failed");
    }

    sqlite3_stmt* raw_state = nullptr;
    constexpr const char* kSetOperational =
        "UPDATE device_state SET state = 'operational', "
        "setup_completed_at_seconds = ?1 WHERE id = 1 AND state = 'default';";
    if (::sqlite3_prepare_v2(impl_->database.get(), kSetOperational, -1,
                             &raw_state, nullptr) != SQLITE_OK) {
      return fail("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
    }
    std::unique_ptr<sqlite3_stmt, decltype(finalize)> state_statement(raw_state,
                                                                      finalize);
    if (::sqlite3_bind_int64(state_statement.get(), 1,
                             record.completed_at_seconds) != SQLITE_OK ||
        ::sqlite3_step(state_statement.get()) != SQLITE_DONE ||
        ::sqlite3_changes(impl_->database.get()) != 1) {
      return fail("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
    }
    state_statement.reset();

    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return fail("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
    }
    return common::Result<void>::Ok();
  } catch (...) {
    if (transaction.active()) {
      (void)transaction.Rollback();
    }
    return StoreError("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
  }
}

common::Result<void> SecurityStore::InstallBootstrapRtspCredential(
    const std::filesystem::path& configured_path,
    std::string_view username,
    std::string_view realm,
    std::span<const unsigned char> password) const {
  const auto failure = [] {
    return StoreError("E_RTSP_AUTH_CREDENTIALS",
                      "credential installation failed");
  };
  try {
    if (configured_path.empty() ||
        configured_path.native().find('\0') != std::string::npos) {
      return failure();
    }
    std::error_code path_error;
    const auto destination =
        std::filesystem::absolute(configured_path, path_error).lexically_normal();
    if (path_error) {
      return failure();
    }
    const auto relative = destination.lexically_relative(impl_->state_directory);
    if (relative.empty() || relative.is_absolute()) {
      return failure();
    }

    std::vector<std::string> components;
    for (const auto& component : relative) {
      const std::string value = component.string();
      if (value.empty() || value == "." || value == ".." ||
          value.find('/') != std::string::npos ||
          value.find('\0') != std::string::npos) {
        return failure();
      }
      components.push_back(value);
    }
    if (components.empty()) {
      return failure();
    }
    const std::string live_name = components.back();
    if (live_name == "." || live_name == ".." ||
        (components.size() == 1U && live_name.starts_with("security.db"))) {
      return failure();
    }

    const uid_t effective_user_id = ::geteuid();
    UniqueFd parent(DuplicateFd(impl_->state_directory_fd.get()));
    if (!parent.valid() ||
        !IsProtectedDirectoryFd(parent.get(), effective_user_id)) {
      return failure();
    }
    for (std::size_t index = 0; index + 1U < components.size(); ++index) {
      UniqueFd child(
          OpenDirectoryAtNoFollow(parent.get(), components[index].c_str()));
      if (!child.valid() ||
          !IsProtectedDirectoryFd(child.get(), effective_user_id)) {
        return failure();
      }
      parent = std::move(child);
    }

    const std::filesystem::path proc_parent =
        std::filesystem::path("/proc/self/fd") /
        std::to_string(parent.get());
    UniqueFd proc_check(::open(proc_parent.c_str(),
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (!proc_check.valid() || !SameDirectory(parent.get(), proc_check.get()) ||
        !IsProtectedDirectoryFd(proc_check.get(), effective_user_id)) {
      return failure();
    }

    auto generated_name = GenerateCredentialStageName(live_name);
    if (!generated_name.ok()) {
      return failure();
    }
    AnchoredStage stage(parent.get(), std::move(generated_name).value());
    struct stat preexisting {};
    if (::fstatat(parent.get(), stage.name().c_str(), &preexisting,
                  AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
      return failure();
    }

    rtsp::RtspDigestProvisionRequest request{
        proc_parent / stage.name(), std::string(username), std::string(realm),
        rtsp::RtspDigestAlgorithm::kSha256, false};
    auto provisioned = rtsp::ProvisionRtspDigestCredential(request, password);
    if (!provisioned.ok()) {
      return failure();
    }

    struct stat staged_status {};
    if (::fstatat(parent.get(), stage.name().c_str(), &staged_status,
                  AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(staged_status.st_mode) || S_ISLNK(staged_status.st_mode) ||
        staged_status.st_uid != effective_user_id ||
        (staged_status.st_mode & 0777) != kDatabaseMode) {
      return failure();
    }
    if (::renameat(parent.get(), stage.name().c_str(), parent.get(),
                   live_name.c_str()) != 0) {
      return failure();
    }
    stage.MarkRenamed();
    if (!FsyncFd(parent.get())) {
      return failure();
    }
    return common::Result<void>::Ok();
  } catch (...) {
    return failure();
  }
}

common::Result<DeviceState> SecurityStore::StateUnderConnectionLease() const {
  if (impl_->poisoned || impl_->database == nullptr) {
    return StoreError<DeviceState>("E_SECURITY_DB_POISONED",
                                   "security store is unavailable");
  }
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

common::Result<DeviceState> SecurityStore::State() const {
  std::unique_lock<std::mutex> connection_lease;
  try {
    connection_lease = std::unique_lock(impl_->connection_mutex);
  } catch (...) {
    return StoreError<DeviceState>("E_SECURITY_DB_STATE",
                                   "failed to lease security connection");
  }
  return StateUnderConnectionLease();
}

const std::filesystem::path& SecurityStore::state_directory() const noexcept {
  return impl_->state_directory;
}

const std::filesystem::path& SecurityStore::database_path() const noexcept {
  return impl_->database_path;
}

}  // namespace camera_firmware::security
