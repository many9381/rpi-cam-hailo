#include "camera_firmware/security/SecurityStore.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <glib.h>
#include <openssl/crypto.h>
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
constexpr int kRevisionTwoSecuritySchema = 2;
constexpr int kRevisionThreeSecuritySchema = 3;
constexpr int kMaximumViewerUsers = 32;
constexpr int kMaximumManagementIpsPerRole = 32;

enum class ForeignKeyValidation {
  kStrict,
  kAllowLegacyAuditActorOrphans,
};

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

bool IsProtectedDatabaseStatus(const struct stat& status,
                               uid_t expected_owner) noexcept {
  return S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
         status.st_uid == expected_owner && status.st_nlink == 1 &&
         (status.st_mode & 0777) == kDatabaseMode;
}

bool SameFileIdentity(const struct stat& first,
                      const struct stat& second) noexcept {
  return first.st_dev == second.st_dev && first.st_ino == second.st_ino;
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

class PreparedStatement {
 public:
  PreparedStatement(sqlite3* database, const char* sql) {
    if (::sqlite3_prepare_v2(database, sql, -1, &statement_, nullptr) !=
        SQLITE_OK) {
      statement_ = nullptr;
    }
  }
  ~PreparedStatement() {
    if (statement_ != nullptr) {
      (void)::sqlite3_finalize(statement_);
    }
  }

  PreparedStatement(const PreparedStatement&) = delete;
  PreparedStatement& operator=(const PreparedStatement&) = delete;

  [[nodiscard]] sqlite3_stmt* get() const noexcept { return statement_; }
  [[nodiscard]] bool valid() const noexcept { return statement_ != nullptr; }

 private:
  sqlite3_stmt* statement_{nullptr};
};

bool CheckedMultiply(std::uint64_t left,
                     std::uint64_t right,
                     std::uint64_t& product) noexcept {
  if (left != 0U &&
      right > std::numeric_limits<std::uint64_t>::max() / left) {
    return false;
  }
  product = left * right;
  return true;
}

struct AuditInsertionState {
  std::uint64_t current_events{0U};
  std::int64_t next_sequence{1};
  std::uint64_t rotated_event_count{0U};
};

common::Result<AuditInsertionState> ReadAuditInsertionState(
    sqlite3* database) {
  PreparedStatement statement(
      database,
      "SELECT (SELECT COUNT(*) FROM audit_events), "
      "(SELECT MAX(sequence) FROM audit_events), rotated_event_count, "
      "last_rotated_sequence FROM audit_state WHERE id = 1;");
  if (!statement.valid() || ::sqlite3_step(statement.get()) != SQLITE_ROW ||
      ::sqlite3_column_type(statement.get(), 0) != SQLITE_INTEGER ||
      (::sqlite3_column_type(statement.get(), 1) != SQLITE_NULL &&
       ::sqlite3_column_type(statement.get(), 1) != SQLITE_INTEGER) ||
      ::sqlite3_column_type(statement.get(), 2) != SQLITE_INTEGER ||
      (::sqlite3_column_type(statement.get(), 3) != SQLITE_NULL &&
       ::sqlite3_column_type(statement.get(), 3) != SQLITE_INTEGER)) {
    return StoreError<AuditInsertionState>("E_SECURITY_DB_AUDIT",
                                           "audit transaction failed");
  }

  const std::int64_t current_events =
      ::sqlite3_column_int64(statement.get(), 0);
  const std::int64_t rotated_event_count =
      ::sqlite3_column_int64(statement.get(), 2);
  std::optional<std::int64_t> highest_sequence;
  if (::sqlite3_column_type(statement.get(), 1) == SQLITE_INTEGER) {
    highest_sequence = ::sqlite3_column_int64(statement.get(), 1);
  }
  std::optional<std::int64_t> last_rotated_sequence;
  if (::sqlite3_column_type(statement.get(), 3) == SQLITE_INTEGER) {
    last_rotated_sequence = ::sqlite3_column_int64(statement.get(), 3);
  }
  if (current_events < 0 || rotated_event_count < 0 ||
      (highest_sequence.has_value() && *highest_sequence < 0) ||
      (last_rotated_sequence.has_value() && *last_rotated_sequence < 0) ||
      ::sqlite3_step(statement.get()) != SQLITE_DONE) {
    return StoreError<AuditInsertionState>("E_SECURITY_DB_AUDIT",
                                           "audit transaction failed");
  }

  std::optional<std::int64_t> sequence_floor = highest_sequence;
  if (last_rotated_sequence.has_value() &&
      (!sequence_floor.has_value() ||
       *last_rotated_sequence > *sequence_floor)) {
    sequence_floor = last_rotated_sequence;
  }
  if (sequence_floor == std::numeric_limits<std::int64_t>::max()) {
    return StoreError<AuditInsertionState>("E_SECURITY_DB_AUDIT",
                                           "audit transaction failed");
  }

  AuditInsertionState state;
  state.current_events = static_cast<std::uint64_t>(current_events);
  state.rotated_event_count =
      static_cast<std::uint64_t>(rotated_event_count);
  state.next_sequence = sequence_floor.has_value() ? *sequence_floor + 1 : 1;
  return common::Result<AuditInsertionState>::Ok(std::move(state));
}

common::Result<void> RotateAuditEvents(sqlite3* database,
                                       const AuditInsertionState& state,
                                       std::uint64_t max_events,
                                       std::int64_t now_seconds) {
  if (state.current_events < max_events) {
    return common::Result<void>::Ok();
  }

  const std::uint64_t remove_count =
      state.current_events - max_events + 1U;
  constexpr std::uint64_t kMaximumSqliteInteger =
      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  if (remove_count > kMaximumSqliteInteger ||
      state.rotated_event_count > kMaximumSqliteInteger - remove_count) {
    return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
  }

  std::int64_t last_rotated_sequence = 0;
  {
    PreparedStatement boundary(
        database,
        "SELECT sequence FROM audit_events ORDER BY sequence LIMIT 1 "
        "OFFSET ?1;");
    if (!boundary.valid() ||
        ::sqlite3_bind_int64(
            boundary.get(), 1,
            static_cast<std::int64_t>(remove_count - 1U)) != SQLITE_OK ||
        ::sqlite3_step(boundary.get()) != SQLITE_ROW ||
        ::sqlite3_column_type(boundary.get(), 0) != SQLITE_INTEGER) {
      return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
    }
    last_rotated_sequence = ::sqlite3_column_int64(boundary.get(), 0);
    if (last_rotated_sequence < 0 ||
        ::sqlite3_step(boundary.get()) != SQLITE_DONE) {
      return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
    }
  }

  {
    PreparedStatement remove(
        database,
        "DELETE FROM audit_events WHERE sequence IN "
        "(SELECT sequence FROM audit_events ORDER BY sequence LIMIT ?1);");
    if (!remove.valid() ||
        ::sqlite3_bind_int64(remove.get(), 1,
                             static_cast<std::int64_t>(remove_count)) !=
            SQLITE_OK ||
        ::sqlite3_step(remove.get()) != SQLITE_DONE ||
        ::sqlite3_changes64(database) !=
            static_cast<sqlite3_int64>(remove_count)) {
      return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
    }
  }

  const std::uint64_t updated_rotation_count =
      state.rotated_event_count + remove_count;
  PreparedStatement update(
      database,
      "UPDATE audit_state SET rotated_event_count = ?1, "
      "last_rotation_at_seconds = ?2, last_rotated_sequence = ?3 "
      "WHERE id = 1 AND rotated_event_count = ?4;");
  if (!update.valid() ||
      ::sqlite3_bind_int64(
          update.get(), 1,
          static_cast<std::int64_t>(updated_rotation_count)) != SQLITE_OK ||
      ::sqlite3_bind_int64(update.get(), 2, now_seconds) != SQLITE_OK ||
      ::sqlite3_bind_int64(update.get(), 3, last_rotated_sequence) !=
          SQLITE_OK ||
      ::sqlite3_bind_int64(
          update.get(), 4,
          static_cast<std::int64_t>(state.rotated_event_count)) != SQLITE_OK ||
      ::sqlite3_step(update.get()) != SQLITE_DONE ||
      ::sqlite3_changes64(database) != 1) {
    return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
  }
  return common::Result<void>::Ok();
}

std::optional<UserRole> ReadUserRole(sqlite3_stmt* statement, int column) {
  const auto* value = ::sqlite3_column_text(statement, column);
  if (value == nullptr) {
    return std::nullopt;
  }
  const std::string_view role(reinterpret_cast<const char*>(value));
  if (role == "administrator") {
    return UserRole::kAdministrator;
  }
  if (role == "viewer") {
    return UserRole::kViewer;
  }
  return std::nullopt;
}

std::string_view RoleText(UserRole role) {
  return role == UserRole::kAdministrator ? "administrator" : "viewer";
}

common::Result<common::SecureBytes> ReadSecureBlob(sqlite3_stmt* statement,
                                                   int column) {
  const auto* data = static_cast<const unsigned char*>(
      ::sqlite3_column_blob(statement, column));
  const int size = ::sqlite3_column_bytes(statement, column);
  if (size < 0 || (size != 0 && data == nullptr)) {
    return StoreError<common::SecureBytes>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  common::SecureBytes bytes;
  try {
    bytes.assign(data, static_cast<std::size_t>(size));
  } catch (...) {
    return StoreError<common::SecureBytes>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  return common::Result<common::SecureBytes>::Ok(std::move(bytes));
}

bool BindPasswordRecord(sqlite3_stmt* statement,
                        int first_parameter,
                        const PasswordRecord& password) {
  return ::sqlite3_bind_text(statement, first_parameter,
                             password.algorithm.data(),
                             static_cast<int>(password.algorithm.size()),
                             SQLITE_TRANSIENT) == SQLITE_OK &&
         ::sqlite3_bind_int64(statement, first_parameter + 1,
                              password.iterations) == SQLITE_OK &&
         ::sqlite3_bind_blob(statement, first_parameter + 2,
                             password.salt.data(),
                             static_cast<int>(password.salt.size()),
                             SQLITE_TRANSIENT) == SQLITE_OK &&
         ::sqlite3_bind_blob(statement, first_parameter + 3,
                             password.derived.data(),
                             static_cast<int>(password.derived.size()),
                             SQLITE_TRANSIENT) == SQLITE_OK;
}

common::Result<PasswordRecord> ReadPasswordRecord(sqlite3_stmt* statement,
                                                   int first_column) {
  const auto* algorithm = ::sqlite3_column_text(statement, first_column);
  if (algorithm == nullptr) {
    return StoreError<PasswordRecord>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  auto salt = ReadSecureBlob(statement, first_column + 2);
  auto derived = ReadSecureBlob(statement, first_column + 3);
  if (!salt.ok() || !derived.ok()) {
    return StoreError<PasswordRecord>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  PasswordRecord record;
  record.algorithm = reinterpret_cast<const char*>(algorithm);
  record.iterations = static_cast<std::uint32_t>(
      ::sqlite3_column_int64(statement, first_column + 1));
  record.salt = std::move(salt).value();
  record.derived = std::move(derived).value();
  return common::Result<PasswordRecord>::Ok(std::move(record));
}

bool SameSecureBytes(const common::SecureBytes& first,
                     const common::SecureBytes& second) noexcept {
  return first.size() == second.size() &&
         (first.size() == 0U ||
          ::CRYPTO_memcmp(first.data(), second.data(), first.size()) == 0);
}

bool SamePasswordRecord(const PasswordRecord& first,
                        const PasswordRecord& second) noexcept {
  return first.algorithm == second.algorithm &&
         first.iterations == second.iterations &&
         SameSecureBytes(first.salt, second.salt) &&
         SameSecureBytes(first.derived, second.derived);
}

common::Result<std::vector<SessionIdentity>> ReadSessionIdentities(
    sqlite3* database,
    std::int64_t user_id) {
  PreparedStatement statement(
      database,
      "SELECT token_hash FROM sessions WHERE user_id = ?1 ORDER BY id;");
  if (!statement.valid() ||
      ::sqlite3_bind_int64(statement.get(), 1, user_id) != SQLITE_OK) {
    return StoreError<std::vector<SessionIdentity>>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  std::vector<SessionIdentity> identities;
  int step = SQLITE_ROW;
  while ((step = ::sqlite3_step(statement.get())) == SQLITE_ROW) {
    const auto* bytes = static_cast<const unsigned char*>(
        ::sqlite3_column_blob(statement.get(), 0));
    const int size = ::sqlite3_column_bytes(statement.get(), 0);
    if (bytes == nullptr ||
        size != static_cast<int>(kSessionIdentityBytes)) {
      return StoreError<std::vector<SessionIdentity>>(
          "E_USER_MANAGEMENT_STORE", "user management transaction failed");
    }
    SessionIdentity identity;
    std::copy_n(bytes, kSessionIdentityBytes, identity.bytes.begin());
    identities.emplace_back(std::move(identity));
  }
  if (step != SQLITE_DONE) {
    return StoreError<std::vector<SessionIdentity>>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  return common::Result<std::vector<SessionIdentity>>::Ok(
      std::move(identities));
}

bool DeleteSessionsForUser(sqlite3* database, std::int64_t user_id) {
  PreparedStatement statement(database,
                              "DELETE FROM sessions WHERE user_id = ?1;");
  return statement.valid() &&
         ::sqlite3_bind_int64(statement.get(), 1, user_id) == SQLITE_OK &&
         ::sqlite3_step(statement.get()) == SQLITE_DONE;
}

common::Result<std::vector<SessionIdentity>> ReadManagementIpSessionIdentities(
    sqlite3* database,
    UserRole role,
    std::string_view normalized_ip) {
  PreparedStatement statement(
      database,
      "SELECT token_hash FROM sessions WHERE role = ?1 AND peer_ip = ?2 "
      "ORDER BY id;");
  const std::string_view role_text = RoleText(role);
  if (!statement.valid() ||
      ::sqlite3_bind_text(statement.get(), 1, role_text.data(),
                          static_cast<int>(role_text.size()), SQLITE_TRANSIENT) !=
          SQLITE_OK ||
      ::sqlite3_bind_text(statement.get(), 2, normalized_ip.data(),
                          static_cast<int>(normalized_ip.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK) {
    return StoreError<std::vector<SessionIdentity>>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  std::vector<SessionIdentity> identities;
  int step = SQLITE_ROW;
  while ((step = ::sqlite3_step(statement.get())) == SQLITE_ROW) {
    const auto* bytes = static_cast<const unsigned char*>(
        ::sqlite3_column_blob(statement.get(), 0));
    const int size = ::sqlite3_column_bytes(statement.get(), 0);
    if (bytes == nullptr || size != static_cast<int>(kSessionIdentityBytes)) {
      return StoreError<std::vector<SessionIdentity>>(
          "E_USER_MANAGEMENT_STORE", "user management transaction failed");
    }
    SessionIdentity identity;
    std::copy_n(bytes, kSessionIdentityBytes, identity.bytes.begin());
    identities.emplace_back(std::move(identity));
  }
  if (step != SQLITE_DONE) {
    return StoreError<std::vector<SessionIdentity>>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  return common::Result<std::vector<SessionIdentity>>::Ok(
      std::move(identities));
}

bool DeleteManagementIpSessions(sqlite3* database,
                                UserRole role,
                                std::string_view normalized_ip) {
  PreparedStatement statement(
      database, "DELETE FROM sessions WHERE role = ?1 AND peer_ip = ?2;");
  const std::string_view role_text = RoleText(role);
  return statement.valid() &&
         ::sqlite3_bind_text(statement.get(), 1, role_text.data(),
                             static_cast<int>(role_text.size()),
                             SQLITE_TRANSIENT) == SQLITE_OK &&
         ::sqlite3_bind_text(statement.get(), 2, normalized_ip.data(),
                             static_cast<int>(normalized_ip.size()),
                             SQLITE_TRANSIENT) == SQLITE_OK &&
         ::sqlite3_step(statement.get()) == SQLITE_DONE;
}

template <typename T>
common::Result<T> UserMutationUnavailable(
    SecurityStore::Transaction& transaction) {
  if (transaction.active()) {
    (void)transaction.Rollback();
  }
  return StoreError<T>("E_USER_MANAGEMENT_STORE",
                       "user management transaction failed");
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

common::Result<UniqueFd> OpenAnchoredDatabase(int state_directory_fd,
                                              uid_t expected_owner) {
  struct stat observed_entry {};
  const bool entry_exists =
      ::fstatat(state_directory_fd, "security.db", &observed_entry,
                AT_SYMLINK_NOFOLLOW) == 0;
  if (!entry_exists && errno != ENOENT) {
    return StoreError<UniqueFd>("E_SECURITY_DB_PATH",
                                "failed to inspect security database");
  }
  if (entry_exists) {
    if (!S_ISREG(observed_entry.st_mode) || S_ISLNK(observed_entry.st_mode) ||
        observed_entry.st_nlink != 1) {
      return StoreError<UniqueFd>("E_SECURITY_DB_PATH",
                                  "security database must be a regular file");
    }
    if (!HasExactMode(observed_entry, kDatabaseMode)) {
      return StoreError<UniqueFd>("E_SECURITY_DB_MODE",
                                  "security database must have mode 0600");
    }
    if (observed_entry.st_uid != expected_owner) {
      return StoreError<UniqueFd>(
          "E_SECURITY_DB_OWNER",
          "security database must be owned by the effective user");
    }
  }

  int flags = O_RDWR | O_NOFOLLOW | O_CLOEXEC;
  if (!entry_exists) {
    flags |= O_CREAT | O_EXCL;
  }
  int descriptor;
  do {
    descriptor = ::openat(state_directory_fd, "security.db", flags,
                          kDatabaseMode);
  } while (descriptor < 0 && errno == EINTR);
  UniqueFd anchored_database(descriptor);
  if (!anchored_database.valid()) {
    return StoreError<UniqueFd>(
        "E_SECURITY_DB_PATH",
        entry_exists ? "failed to open security database"
                     : "failed to create security database");
  }
  if (!entry_exists &&
      ::fchmod(anchored_database.get(), kDatabaseMode) != 0) {
    return StoreError<UniqueFd>("E_SECURITY_DB_PATH",
                                "failed to protect security database");
  }

  struct stat anchor_status {};
  struct stat current_entry {};
  if (::fstat(anchored_database.get(), &anchor_status) != 0 ||
      !S_ISREG(anchor_status.st_mode) || S_ISLNK(anchor_status.st_mode) ||
      anchor_status.st_nlink != 1) {
    return StoreError<UniqueFd>("E_SECURITY_DB_PATH",
                                "security database must be a regular file");
  }
  if (!HasExactMode(anchor_status, kDatabaseMode)) {
    return StoreError<UniqueFd>("E_SECURITY_DB_MODE",
                                "security database must have mode 0600");
  }
  if (anchor_status.st_uid != expected_owner) {
    return StoreError<UniqueFd>(
        "E_SECURITY_DB_OWNER",
        "security database must be owned by the effective user");
  }
  if (::fstatat(state_directory_fd, "security.db", &current_entry,
                AT_SYMLINK_NOFOLLOW) != 0 ||
      !IsProtectedDatabaseStatus(current_entry, expected_owner) ||
      !SameFileIdentity(anchor_status, current_entry) ||
      (entry_exists && !SameFileIdentity(observed_entry, anchor_status))) {
    return StoreError<UniqueFd>("E_SECURITY_DB_PATH",
                                "security database changed during open");
  }
  return common::Result<UniqueFd>::Ok(std::move(anchored_database));
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

bool ValidateTwoColumnIndex(sqlite3* database,
                            const char* table_name,
                            const char* index_name,
                            bool expected_unique,
                            const std::array<const char*, 2>& expected_columns,
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
  const bool list_valid =
      ::sqlite3_column_int(list, 0) == (expected_unique ? 1 : 0) &&
      origin != nullptr &&
      std::string_view(reinterpret_cast<const char*>(origin)) == "c" &&
      ::sqlite3_column_int(list, 2) == 0 &&
      ::sqlite3_step(list) == SQLITE_DONE;
  const bool list_finalized = ::sqlite3_finalize(list) == SQLITE_OK;
  if (!list_valid || !list_finalized) {
    return false;
  }

  sqlite3_stmt* columns = nullptr;
  constexpr const char* kColumnsSql =
      "SELECT name, coll, desc FROM pragma_index_xinfo(?1) "
      "WHERE key = 1 ORDER BY seqno;";
  if (::sqlite3_prepare_v2(database, kColumnsSql, -1, &columns, nullptr) !=
          SQLITE_OK ||
      ::sqlite3_bind_text(columns, 1, index_name, -1, SQLITE_STATIC) !=
          SQLITE_OK) {
    if (columns != nullptr) {
      (void)::sqlite3_finalize(columns);
    }
    return false;
  }
  bool columns_valid = true;
  for (const char* expected_column : expected_columns) {
    if (::sqlite3_step(columns) != SQLITE_ROW) {
      columns_valid = false;
      break;
    }
    const auto* column = ::sqlite3_column_text(columns, 0);
    const auto* collation = ::sqlite3_column_text(columns, 1);
    columns_valid = column != nullptr && collation != nullptr &&
                    std::string_view(reinterpret_cast<const char*>(column)) ==
                        expected_column &&
                    std::string_view(reinterpret_cast<const char*>(collation)) ==
                        "BINARY" &&
                    ::sqlite3_column_int(columns, 2) == 0;
    if (!columns_valid) {
      break;
    }
  }
  columns_valid = columns_valid && ::sqlite3_step(columns) == SQLITE_DONE;
  const bool columns_finalized = ::sqlite3_finalize(columns) == SQLITE_OK;
  return columns_valid && columns_finalized &&
         ValidateSchemaObjectSql(database, index_name, expected_sql);
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

bool HasExactSchemaObjectInventory(sqlite3* database, int schema_revision) {
  int value = 0;
  // Approved schemas have no SQLite-generated autoindexes: all uniqueness is
  // represented by the named indexes below. Requiring the complete inventory
  // rejects internal autoindexes as well as application triggers and views.
  constexpr const char* kRevisionTwoUnexpectedObjectCount = R"sql(
SELECT COUNT(*)
FROM sqlite_schema
WHERE NOT (
  (type = 'table' AND (
    (name = 'schema_version' AND tbl_name = 'schema_version') OR
    (name = 'device_state' AND tbl_name = 'device_state') OR
    (name = 'users' AND tbl_name = 'users') OR
    (name = 'management_ips' AND tbl_name = 'management_ips') OR
    (name = 'sessions' AND tbl_name = 'sessions') OR
    (name = 'audit_events' AND tbl_name = 'audit_events') OR
    (name = 'firmware_log_outbox' AND tbl_name = 'firmware_log_outbox')
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
    (name = 'audit_events_timestamp_index' AND tbl_name = 'audit_events') OR
    (name = 'firmware_log_outbox_category_peer_unique' AND
     tbl_name = 'firmware_log_outbox') OR
    (name = 'firmware_log_outbox_lease_expiry_index' AND
     tbl_name = 'firmware_log_outbox')
  ))
);
)sql";
  constexpr const char* kRevisionThreeUnexpectedObjectCount = R"sql(
SELECT COUNT(*)
FROM sqlite_schema
WHERE NOT (
  (type = 'table' AND (
    (name = 'schema_version' AND tbl_name = 'schema_version') OR
    (name = 'device_state' AND tbl_name = 'device_state') OR
    (name = 'users' AND tbl_name = 'users') OR
    (name = 'password_history' AND tbl_name = 'password_history') OR
    (name = 'management_ips' AND tbl_name = 'management_ips') OR
    (name = 'sessions' AND tbl_name = 'sessions') OR
    (name = 'audit_events' AND tbl_name = 'audit_events') OR
    (name = 'firmware_log_outbox' AND tbl_name = 'firmware_log_outbox')
  )) OR
  (type = 'index' AND (
    (name = 'users_canonical_username_unique' AND tbl_name = 'users') OR
    (name = 'users_single_administrator_unique' AND tbl_name = 'users') OR
    (name = 'password_history_user_id_unique' AND
     tbl_name = 'password_history') OR
    (name = 'management_ips_role_ip_unique' AND
     tbl_name = 'management_ips') OR
    (name = 'sessions_token_hash_unique' AND tbl_name = 'sessions') OR
    (name = 'sessions_single_administrator_unique' AND
     tbl_name = 'sessions') OR
    (name = 'sessions_user_id_unique' AND tbl_name = 'sessions') OR
    (name = 'sessions_expiry_index' AND tbl_name = 'sessions') OR
    (name = 'audit_events_timestamp_index' AND tbl_name = 'audit_events') OR
    (name = 'firmware_log_outbox_category_peer_unique' AND
     tbl_name = 'firmware_log_outbox') OR
    (name = 'firmware_log_outbox_lease_expiry_index' AND
     tbl_name = 'firmware_log_outbox')
  ))
);
)sql";
  constexpr const char* kRevisionFourUnexpectedObjectCount = R"sql(
SELECT COUNT(*)
FROM sqlite_schema
WHERE NOT (
  (type = 'table' AND (
    (name = 'schema_version' AND tbl_name = 'schema_version') OR
    (name = 'device_state' AND tbl_name = 'device_state') OR
    (name = 'users' AND tbl_name = 'users') OR
    (name = 'password_history' AND tbl_name = 'password_history') OR
    (name = 'management_ips' AND tbl_name = 'management_ips') OR
    (name = 'sessions' AND tbl_name = 'sessions') OR
    (name = 'audit_events' AND tbl_name = 'audit_events') OR
    (name = 'audit_state' AND tbl_name = 'audit_state') OR
    (name = 'firmware_log_outbox' AND tbl_name = 'firmware_log_outbox')
  )) OR
  (type = 'index' AND (
    (name = 'users_canonical_username_unique' AND tbl_name = 'users') OR
    (name = 'users_single_administrator_unique' AND tbl_name = 'users') OR
    (name = 'password_history_user_id_unique' AND
     tbl_name = 'password_history') OR
    (name = 'management_ips_role_ip_unique' AND
     tbl_name = 'management_ips') OR
    (name = 'sessions_token_hash_unique' AND tbl_name = 'sessions') OR
    (name = 'sessions_single_administrator_unique' AND
     tbl_name = 'sessions') OR
    (name = 'sessions_user_id_unique' AND tbl_name = 'sessions') OR
    (name = 'sessions_expiry_index' AND tbl_name = 'sessions') OR
    (name = 'audit_events_timestamp_index' AND tbl_name = 'audit_events') OR
    (name = 'firmware_log_outbox_category_peer_unique' AND
     tbl_name = 'firmware_log_outbox') OR
    (name = 'firmware_log_outbox_lease_expiry_index' AND
     tbl_name = 'firmware_log_outbox')
  ))
);
)sql";
  const char* unexpected_object_count = kRevisionTwoUnexpectedObjectCount;
  int expected_count = 16;
  if (schema_revision == kRevisionThreeSecuritySchema) {
    unexpected_object_count = kRevisionThreeUnexpectedObjectCount;
    expected_count = 19;
  } else if (schema_revision == kSecuritySchemaRevision) {
    unexpected_object_count = kRevisionFourUnexpectedObjectCount;
    expected_count = 20;
  }
  return QuerySingleInt(database, unexpected_object_count, value) && value == 0 &&
         QuerySingleInt(database, "SELECT COUNT(*) FROM sqlite_schema;", value) &&
         value == expected_count;
}

bool HasValidCommittedState(sqlite3* database,
                            int schema_revision,
                            ForeignKeyValidation foreign_key_validation) {
  int value = 0;
  const bool allow_legacy_audit_actor_orphans =
      foreign_key_validation ==
          ForeignKeyValidation::kAllowLegacyAuditActorOrphans &&
      schema_revision < kSecuritySchemaRevision;
  const char* foreign_key_check =
      allow_legacy_audit_actor_orphans
          ? "SELECT COUNT(*) FROM pragma_foreign_key_check "
            "WHERE \"table\" IS NOT 'audit_events' OR parent IS NOT 'users' "
            "OR fkid IS NOT 0;"
          : "SELECT COUNT(*) FROM pragma_foreign_key_check;";
  if (!QuerySingleInt(database, foreign_key_check, value) ||
      value != 0 ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM users WHERE failed_login_count < 0 OR "
          "failed_login_count > 5;",
          value) ||
      value != 0 ||
      (schema_revision >= kRevisionThreeSecuritySchema &&
       (!QuerySingleInt(database,
                        "SELECT COUNT(*) FROM users WHERE role = 'viewer';",
                        value) ||
        value > kMaximumViewerUsers ||
        !QuerySingleInt(
            database,
            "SELECT COUNT(*) FROM (SELECT role_scope FROM management_ips "
            "GROUP BY role_scope HAVING COUNT(*) > 32);",
            value) ||
        value != 0))) {
    return false;
  }

  constexpr const char* kLegacyStateInvariant = R"sql(
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
  constexpr const char* kRevisionFourStateInvariant = R"sql(
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
    (
      (
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
      ) OR (
        (SELECT COUNT(*) FROM audit_events
          WHERE event_type = 'bootstrap_completed' AND outcome = 'success') = 0 AND
        EXISTS (
          SELECT 1
          FROM audit_state
          WHERE id = 1
            AND rotated_event_count > 0
            AND last_rotation_at_seconds IS NOT NULL
            AND last_rotated_sequence IS NOT NULL
        )
      )
    )
  ELSE 0
END
FROM device_state
WHERE id = 1;
)sql";
  const char* state_invariant =
      schema_revision == kSecuritySchemaRevision
          ? kRevisionFourStateInvariant
          : kLegacyStateInvariant;
  if (!QuerySingleInt(database, state_invariant, value) || value != 1) {
    return false;
  }
  return schema_revision != kSecuritySchemaRevision ||
         (QuerySingleInt(
              database,
              "SELECT COUNT(*) FROM audit_state WHERE id = 1 AND "
              "rotated_event_count >= 0 AND "
              "((last_rotation_at_seconds IS NULL AND "
              "last_rotated_sequence IS NULL) OR "
              "(last_rotation_at_seconds >= 0 AND "
              "last_rotated_sequence >= 0));",
              value) &&
          value == 1 &&
          QuerySingleInt(database, "SELECT COUNT(*) FROM audit_state;", value) &&
          value == 1);
}

common::Result<void> ValidateSchema(
    sqlite3* database,
    int schema_revision,
    ForeignKeyValidation foreign_key_validation =
        ForeignKeyValidation::kStrict) {
  if (schema_revision != kRevisionTwoSecuritySchema &&
      schema_revision != kRevisionThreeSecuritySchema &&
      schema_revision != kSecuritySchemaRevision) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }
  int value = 0;
  // The complete object inventory is read before any validation DML so an
  // unapproved trigger cannot run from the destructive constraint probes.
  const bool revision_three_or_later =
      schema_revision >= kRevisionThreeSecuritySchema;
  const bool revision_four = schema_revision == kSecuritySchemaRevision;
  const int expected_table_count =
      revision_four ? 9 : (revision_three_or_later ? 8 : 7);
  const int expected_index_count = revision_three_or_later ? 11 : 9;
  if (!HasExactSchemaObjectInventory(database, schema_revision) ||
      !QuerySingleInt(database, "PRAGMA foreign_keys;", value) || value != 1 ||
      !QuerySingleInt(database, "PRAGMA secure_delete;", value) || value != 1 ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM sqlite_schema "
          "WHERE type = 'table' AND name NOT LIKE 'sqlite_%';",
          value) ||
      value != expected_table_count ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM sqlite_schema "
          "WHERE type = 'table' "
          "AND name IN ('schema_version', 'device_state', 'users', "
          "'management_ips', 'password_history', 'sessions', 'audit_events', "
          "'audit_state', 'firmware_log_outbox');",
          value) ||
      value != expected_table_count ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'index' "
          "AND name NOT LIKE 'sqlite_%';",
          value) ||
      value != expected_index_count ||
      !QuerySingleInt(
          database,
          "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'index' AND name IN "
          "('users_canonical_username_unique', "
          "'users_single_administrator_unique', "
          "'management_ips_normalized_ip_unique', "
          "'management_ips_role_ip_unique', "
          "'password_history_user_id_unique', "
          "'sessions_token_hash_unique', "
          "'sessions_single_administrator_unique', "
          "'sessions_user_id_unique', 'sessions_expiry_index', "
          "'audit_events_timestamp_index', "
          "'firmware_log_outbox_category_peer_unique', "
          "'firmware_log_outbox_lease_expiry_index');",
          value) ||
      value != expected_index_count) {
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
      (!revision_three_or_later &&
       !ValidateIndex(database, "management_ips",
                      "management_ips_normalized_ip_unique", true, false,
                      "normalized_ip", "BINARY",
                      "CREATE UNIQUE INDEX management_ips_normalized_ip_unique "
                      "ON management_ips(normalized_ip)")) ||
      (revision_three_or_later &&
       (!ValidateTwoColumnIndex(
            database, "management_ips", "management_ips_role_ip_unique", true,
            {"role_scope", "normalized_ip"},
            "CREATE UNIQUE INDEX management_ips_role_ip_unique "
            "ON management_ips(role_scope, normalized_ip)") ||
        !ValidateIndex(database, "password_history",
                       "password_history_user_id_unique", true, false,
                       "user_id", "BINARY",
                       "CREATE UNIQUE INDEX password_history_user_id_unique "
                       "ON password_history(user_id)"))) ||
      !ValidateIndex(database, "sessions", "sessions_token_hash_unique", true,
                     false, "token_hash", "BINARY",
                     "CREATE UNIQUE INDEX sessions_token_hash_unique "
                     "ON sessions(token_hash)") ||
      !ValidateIndex(database, "sessions",
                     "sessions_single_administrator_unique", true, true,
                     "role", "BINARY",
                     "CREATE UNIQUE INDEX sessions_single_administrator_unique "
                     "ON sessions(role) WHERE role = 'administrator'") ||
      (revision_three_or_later &&
       !ValidateIndex(database, "sessions", "sessions_user_id_unique", true,
                      false, "user_id", "BINARY",
                      "CREATE UNIQUE INDEX sessions_user_id_unique "
                      "ON sessions(user_id)")) ||
      !ValidateIndex(database, "sessions", "sessions_expiry_index", false,
                     false, "expires_at_seconds", "BINARY",
                     "CREATE INDEX sessions_expiry_index "
                     "ON sessions(expires_at_seconds)") ||
      !ValidateIndex(database, "audit_events", "audit_events_timestamp_index",
                     false, false, "server_timestamp_seconds", "BINARY",
                     "CREATE INDEX audit_events_timestamp_index "
                     "ON audit_events(server_timestamp_seconds)") ||
      !ValidateTwoColumnIndex(
          database, "firmware_log_outbox",
          "firmware_log_outbox_category_peer_unique", true,
          {"category", "peer_ip"},
          "CREATE UNIQUE INDEX firmware_log_outbox_category_peer_unique "
          "ON firmware_log_outbox(category, peer_ip)") ||
      !ValidateIndex(database, "firmware_log_outbox",
                     "firmware_log_outbox_lease_expiry_index", false, false,
                     "lease_expires_at_seconds", "BINARY",
                     "CREATE INDEX firmware_log_outbox_lease_expiry_index "
                     "ON firmware_log_outbox(lease_expires_at_seconds)")) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  std::vector<ForeignKeyInfo> schema_version_foreign_keys;
  std::vector<ForeignKeyInfo> state_foreign_keys;
  std::vector<ForeignKeyInfo> user_foreign_keys;
  std::vector<ForeignKeyInfo> password_history_foreign_keys;
  std::vector<ForeignKeyInfo> management_foreign_keys;
  std::vector<ForeignKeyInfo> session_foreign_keys;
  std::vector<ForeignKeyInfo> audit_foreign_keys;
  std::vector<ForeignKeyInfo> audit_state_foreign_keys;
  std::vector<ForeignKeyInfo> outbox_foreign_keys;
  if (!ReadForeignKeys(database, "schema_version",
                       schema_version_foreign_keys) ||
      !schema_version_foreign_keys.empty() ||
      !ReadForeignKeys(database, "device_state", state_foreign_keys) ||
      !state_foreign_keys.empty() ||
      !ReadForeignKeys(database, "users", user_foreign_keys) ||
      !user_foreign_keys.empty() ||
      (revision_three_or_later &&
       (!ReadForeignKeys(database, "password_history",
                         password_history_foreign_keys) ||
        password_history_foreign_keys !=
            std::vector<ForeignKeyInfo>{{"users", "user_id", "id",
                                         "NO ACTION", "CASCADE", "NONE"}})) ||
      !ReadForeignKeys(database, "management_ips", management_foreign_keys) ||
      !management_foreign_keys.empty() ||
      !ReadForeignKeys(database, "sessions", session_foreign_keys) ||
      session_foreign_keys !=
          std::vector<ForeignKeyInfo>{{"users", "user_id", "id", "NO ACTION",
                                       "CASCADE", "NONE"}} ||
      !ReadForeignKeys(database, "audit_events", audit_foreign_keys) ||
      audit_foreign_keys !=
          std::vector<ForeignKeyInfo>{{"users", "actor_user_id", "id",
                                       "NO ACTION", "SET NULL", "NONE"}} ||
      (revision_four &&
       (!ReadForeignKeys(database, "audit_state", audit_state_foreign_keys) ||
        !audit_state_foreign_keys.empty())) ||
      !ReadForeignKeys(database, "firmware_log_outbox",
                       outbox_foreign_keys) ||
      !outbox_foreign_keys.empty()) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  std::vector<ColumnInfo> schema_version_columns;
  std::vector<ColumnInfo> device_state_columns;
  std::vector<ColumnInfo> users_columns;
  std::vector<ColumnInfo> password_history_columns;
  std::vector<ColumnInfo> management_ip_columns;
  std::vector<ColumnInfo> sessions_columns;
  std::vector<ColumnInfo> audit_columns;
  std::vector<ColumnInfo> audit_state_columns;
  std::vector<ColumnInfo> outbox_columns;
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
      (revision_three_or_later &&
       (!ReadColumns(database, "password_history", password_history_columns) ||
        password_history_columns !=
            std::vector<ColumnInfo>{
                {"id", "INTEGER", 0, 1},
                {"user_id", "INTEGER", 1, 0},
                {"password_algorithm", "TEXT", 1, 0},
                {"password_iterations", "INTEGER", 1, 0},
                {"password_salt", "BLOB", 1, 0},
                {"password_derived", "BLOB", 1, 0},
                {"replaced_at_seconds", "INTEGER", 1, 0}})) ||
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
          (revision_four
               ? std::vector<ColumnInfo>{
                     {"sequence", "INTEGER", 0, 1},
                     {"server_timestamp_seconds", "INTEGER", 1, 0},
                     {"event_type", "TEXT", 1, 0},
                     {"outcome", "TEXT", 1, 0},
                     {"actor_user_id", "INTEGER", 0, 0},
                     {"actor_identity", "TEXT", 1, 0},
                     {"peer_ip", "TEXT", 1, 0},
                     {"detail_code", "TEXT", 1, 0},
                     {"subject_type", "TEXT", 1, 0},
                     {"subject_identity", "TEXT", 1, 0}}
               : revision_three_or_later
               ? std::vector<ColumnInfo>{
                     {"sequence", "INTEGER", 0, 1},
                     {"server_timestamp_seconds", "INTEGER", 1, 0},
                     {"event_type", "TEXT", 1, 0},
                     {"outcome", "TEXT", 1, 0},
                     {"actor_user_id", "INTEGER", 0, 0},
                     {"peer_ip", "TEXT", 1, 0},
                     {"detail_code", "TEXT", 1, 0},
                     {"subject_type", "TEXT", 1, 0},
                     {"subject_identity", "TEXT", 1, 0}}
               : std::vector<ColumnInfo>{
                     {"sequence", "INTEGER", 0, 1},
                     {"server_timestamp_seconds", "INTEGER", 1, 0},
                     {"event_type", "TEXT", 1, 0},
                     {"outcome", "TEXT", 1, 0},
                     {"actor_user_id", "INTEGER", 0, 0},
                     {"peer_ip", "TEXT", 1, 0},
                     {"detail_code", "TEXT", 1, 0}}) ||
      (revision_four &&
       (!ReadColumns(database, "audit_state", audit_state_columns) ||
        audit_state_columns !=
            std::vector<ColumnInfo>{
                {"id", "INTEGER", 0, 1},
                {"rotated_event_count", "INTEGER", 1, 0},
                {"last_rotation_at_seconds", "INTEGER", 0, 0},
                {"last_rotated_sequence", "INTEGER", 0, 0}})) ||
      !ReadColumns(database, "firmware_log_outbox", outbox_columns) ||
      outbox_columns !=
          std::vector<ColumnInfo>{{"id", "INTEGER", 0, 1},
                                  {"category", "TEXT", 1, 0},
                                  {"peer_ip", "TEXT", 1, 0},
                                  {"created_at_seconds", "INTEGER", 1, 0},
                                  {"dirty", "INTEGER", 1, 0},
                                  {"lease_owner", "BLOB", 0, 0},
                                  {"lease_token", "BLOB", 0, 0},
                                  {"lease_expires_at_seconds", "INTEGER", 0,
                                   0}} ||
      !QuerySingleInt(database,
                      revision_four
                          ? "SELECT COUNT(*) FROM schema_version "
                            "WHERE version = 4;"
                          : revision_three_or_later
                                ? "SELECT COUNT(*) FROM schema_version "
                                  "WHERE version = 3;"
                                : "SELECT COUNT(*) FROM schema_version "
                                  "WHERE version = 2;",
                      value) ||
      value != 1 ||
      !QuerySingleInt(database, "SELECT COUNT(*) FROM schema_version;", value) ||
      value != 1 ||
      !QuerySingleInt(
          database,
          revision_four
              ? "SELECT COUNT(*) FROM device_state "
                "WHERE id = 1 AND schema_revision = 4 AND "
                "((state = 'default' AND setup_completed_at_seconds IS NULL) "
                "OR (state = 'operational' AND "
                "setup_completed_at_seconds >= 0));"
              : revision_three_or_later
                    ? "SELECT COUNT(*) FROM device_state "
                      "WHERE id = 1 AND schema_revision = 3 AND "
                      "((state = 'default' AND "
                      "setup_completed_at_seconds IS NULL) OR "
                      "(state = 'operational' AND "
                      "setup_completed_at_seconds >= 0));"
                    : "SELECT COUNT(*) FROM device_state "
                      "WHERE id = 1 AND schema_revision = 2 AND "
                      "((state = 'default' AND "
                      "setup_completed_at_seconds IS NULL) OR "
                      "(state = 'operational' AND "
                      "setup_completed_at_seconds >= 0));",
          value) ||
      value != 1 ||
      !QuerySingleInt(database, "SELECT COUNT(*) FROM device_state;", value) ||
      value != 1) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  constexpr std::string_view kRevisionTwoSchemaVersionSql = R"sql(
CREATE TABLE schema_version (
  version INTEGER NOT NULL CHECK (version = 2)
))sql";
  constexpr std::string_view kRevisionThreeSchemaVersionSql = R"sql(
CREATE TABLE schema_version (
  version INTEGER NOT NULL CHECK (version = 3)
))sql";
  constexpr std::string_view kRevisionFourSchemaVersionSql = R"sql(
CREATE TABLE schema_version (
  version INTEGER NOT NULL CHECK (version = 4)
))sql";
  constexpr std::string_view kRevisionTwoDeviceStateSql = R"sql(
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
))sql";
  constexpr std::string_view kRevisionThreeDeviceStateSql = R"sql(
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
))sql";
  constexpr std::string_view kRevisionFourDeviceStateSql = R"sql(
CREATE TABLE device_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL CHECK (state IN ('default', 'operational')),
  schema_revision INTEGER NOT NULL CHECK (schema_revision = 4),
  setup_completed_at_seconds INTEGER,
  CHECK (
    (state = 'default' AND setup_completed_at_seconds IS NULL) OR
    (state = 'operational' AND setup_completed_at_seconds IS NOT NULL AND
     setup_completed_at_seconds >= 0)
  )
))sql";
  constexpr std::string_view kRevisionTwoManagementIpsSql = R"sql(
CREATE TABLE management_ips (
  id INTEGER PRIMARY KEY,
  normalized_ip TEXT NOT NULL CHECK (length(normalized_ip) BETWEEN 2 AND 45),
  role_scope TEXT NOT NULL CHECK (role_scope IN ('administrator')),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0)
))sql";
  constexpr std::string_view kRevisionThreeManagementIpsSql = R"sql(
CREATE TABLE management_ips (
  id INTEGER PRIMARY KEY,
  normalized_ip TEXT NOT NULL CHECK (length(normalized_ip) BETWEEN 2 AND 45),
  role_scope TEXT NOT NULL
    CHECK (role_scope IN ('administrator', 'viewer')),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0)
))sql";
  constexpr std::string_view kRevisionTwoAuditEventsSql = R"sql(
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY,
  server_timestamp_seconds INTEGER NOT NULL
    CHECK (server_timestamp_seconds >= 0),
  event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45),
  detail_code TEXT NOT NULL CHECK (length(detail_code) <= 64)
))sql";
  constexpr std::string_view kRevisionThreeAuditEventsSql = R"sql(
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
))sql";
  constexpr std::string_view kRevisionFourAuditEventsSql = R"sql(
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY,
  server_timestamp_seconds INTEGER NOT NULL
    CHECK (server_timestamp_seconds >= 0),
  event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  actor_identity TEXT NOT NULL
    CHECK (length(actor_identity) BETWEEN 1 AND 64),
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45),
  detail_code TEXT NOT NULL CHECK (length(detail_code) <= 64),
  subject_type TEXT NOT NULL DEFAULT ''
    CHECK (length(subject_type) <= 64),
  subject_identity TEXT NOT NULL DEFAULT ''
    CHECK (length(subject_identity) <= 64)
))sql";
  constexpr std::string_view kAuditStateSql = R"sql(
CREATE TABLE audit_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  rotated_event_count INTEGER NOT NULL DEFAULT 0
    CHECK (rotated_event_count >= 0),
  last_rotation_at_seconds INTEGER
    CHECK (last_rotation_at_seconds >= 0),
  last_rotated_sequence INTEGER
    CHECK (last_rotated_sequence >= 0),
  CHECK (
    (last_rotation_at_seconds IS NULL AND last_rotated_sequence IS NULL) OR
    (last_rotation_at_seconds IS NOT NULL AND
     last_rotated_sequence IS NOT NULL)
  )
))sql";
  constexpr std::string_view kPasswordHistorySql = R"sql(
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
))sql";

  const std::array<std::pair<const char*, std::string_view>, 7>
      expected_table_definitions = {{
          {"schema_version",
           revision_four ? kRevisionFourSchemaVersionSql
                         : revision_three_or_later
                               ? kRevisionThreeSchemaVersionSql
                               : kRevisionTwoSchemaVersionSql},
          {"device_state",
           revision_four ? kRevisionFourDeviceStateSql
                         : revision_three_or_later
                               ? kRevisionThreeDeviceStateSql
                               : kRevisionTwoDeviceStateSql},
          {"users", R"sql(
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
))sql"},
          {"management_ips",
           revision_three_or_later ? kRevisionThreeManagementIpsSql
                                   : kRevisionTwoManagementIpsSql},
          {"sessions", R"sql(
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
))sql"},
          {"audit_events",
           revision_four ? kRevisionFourAuditEventsSql
                         : revision_three_or_later
                               ? kRevisionThreeAuditEventsSql
                               : kRevisionTwoAuditEventsSql},
          {"firmware_log_outbox", R"sql(
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
))sql"},
      }};
  for (const auto& [table_name, expected_sql] : expected_table_definitions) {
    if (!ValidateSchemaObjectSql(database, table_name, expected_sql)) {
      return StoreError("E_SECURITY_DB_SCHEMA",
                        "security database schema is invalid");
    }
  }

  if (revision_three_or_later &&
      !ValidateSchemaObjectSql(database, "password_history",
                               kPasswordHistorySql)) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }
  if (revision_four &&
      !ValidateSchemaObjectSql(database, "audit_state", kAuditStateSql)) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  if (!HasValidCommittedState(database, schema_revision,
                              foreign_key_validation)) {
    return StoreError("E_SECURITY_DB_SCHEMA",
                      "security database schema is invalid");
  }

  auto savepoint = Execute(database, "SAVEPOINT schema_validation;",
                           "E_SECURITY_DB_SCHEMA",
                           "failed to validate security database schema");
  if (!savepoint.ok()) {
    return savepoint;
  }
  const char* preparation_sql =
      revision_three_or_later
          ? "DELETE FROM firmware_log_outbox; DELETE FROM audit_events; "
            "DELETE FROM sessions; DELETE FROM password_history; "
            "DELETE FROM management_ips; DELETE FROM users; "
            "UPDATE device_state SET state = 'default', "
            "setup_completed_at_seconds = NULL WHERE id = 1;"
          : "DELETE FROM firmware_log_outbox; DELETE FROM audit_events; "
            "DELETE FROM sessions; DELETE FROM management_ips; "
            "DELETE FROM users; UPDATE device_state SET state = 'default', "
            "setup_completed_at_seconds = NULL WHERE id = 1;";
  const auto preparation = Execute(
      database, preparation_sql,
      "E_SECURITY_DB_SCHEMA", "failed to validate security database schema");
  const bool prepared = preparation.ok();
  const bool constraints_valid =
      prepared &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO schema_version (version) VALUES (NULL);") &&
      StatementIsRejectedByConstraint(
          database,
          revision_four
              ? "INSERT INTO schema_version (version) VALUES (3);"
              : revision_three_or_later
                    ? "INSERT INTO schema_version (version) VALUES (2);"
                    : "INSERT INTO schema_version (version) VALUES (3);") &&
      StatementIsRejectedByConstraint(
          database,
          revision_four
              ? "INSERT INTO device_state "
                "(id, state, schema_revision) VALUES (2, 'default', 4);"
              : revision_three_or_later
                    ? "INSERT INTO device_state "
                      "(id, state, schema_revision) "
                      "VALUES (2, 'default', 3);"
                    : "INSERT INTO device_state "
                      "(id, state, schema_revision) "
                      "VALUES (2, 'default', 2);") &&
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
      StatementSucceeds(
          database,
          "INSERT INTO users "
          "(canonical_username, display_username, role, enabled, "
          "password_algorithm, password_iterations, password_salt, "
          "password_derived, password_changed_at_seconds, "
          "failed_login_count, created_at_seconds) VALUES "
          "('viewer.one', 'Viewer.One', 'viewer', 1, "
          "'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), 1, 0, 1);") &&
      StatementIsRejectedByConstraint(
          database,
          "UPDATE users SET failed_login_count = 6 "
          "WHERE canonical_username = 'operator.one';") &&
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
      (!revision_three_or_later ||
       (StatementSucceeds(
            database,
            "INSERT INTO management_ips "
            "(normalized_ip, role_scope, enabled, created_at_seconds) "
            "VALUES ('192.0.2.1', 'viewer', 1, 1);") &&
        StatementIsRejectedByConstraint(
            database,
            "INSERT INTO management_ips "
            "(normalized_ip, role_scope, enabled, created_at_seconds) "
            "VALUES ('192.0.2.1', 'viewer', 1, 1);") &&
        StatementIsRejectedByConstraint(
            database,
            "INSERT INTO password_history "
            "(user_id, password_algorithm, password_iterations, "
            "password_salt, password_derived, replaced_at_seconds) "
            "VALUES ((SELECT id FROM users WHERE role = 'viewer'), "
            "'pbkdf2-hmac-sha256', 600000, zeroblob(15), zeroblob(32), 1);") &&
        StatementSucceeds(
            database,
            "INSERT INTO password_history "
            "(user_id, password_algorithm, password_iterations, "
            "password_salt, password_derived, replaced_at_seconds) "
            "VALUES ((SELECT id FROM users WHERE role = 'viewer'), "
            "'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), 1);") &&
        StatementIsRejectedByConstraint(
            database,
            "INSERT INTO password_history "
            "(user_id, password_algorithm, password_iterations, "
            "password_salt, password_derived, replaced_at_seconds) "
            "VALUES ((SELECT id FROM users WHERE role = 'viewer'), "
            "'pbkdf2-hmac-sha256', 600000, randomblob(16), randomblob(32), 2);"))) &&
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
      (!revision_three_or_later ||
       (StatementSucceeds(
            database,
            "INSERT INTO sessions "
            "(token_hash, user_id, role, created_at_seconds, "
            "last_activity_at_seconds, expires_at_seconds, peer_ip) "
            "VALUES (randomblob(32), "
            "(SELECT id FROM users WHERE role = 'viewer'), "
            "'viewer', 1, 1, 2, '192.0.2.1');") &&
        StatementIsRejectedByConstraint(
            database,
            "INSERT INTO sessions "
            "(token_hash, user_id, role, created_at_seconds, "
            "last_activity_at_seconds, expires_at_seconds, peer_ip) "
            "VALUES (randomblob(32), "
            "(SELECT id FROM users WHERE role = 'viewer'), "
            "'viewer', 1, 1, 2, '192.0.2.1');"))) &&
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
          "VALUES (1, 'event', 'success', 999999, '192.0.2.1', 'detail');") &&
      (!revision_three_or_later ||
       StatementIsRejectedByConstraint(
           database,
           "INSERT INTO audit_events "
           "(server_timestamp_seconds, event_type, outcome, peer_ip, "
           "detail_code, subject_type, subject_identity) "
           "VALUES (1, 'event', 'success', '192.0.2.1', 'detail', "
           "printf('%065d', 0), 'viewer.one');")) &&
      (!revision_four ||
       (StatementIsRejectedByConstraint(
            database,
            "INSERT INTO audit_events "
            "(server_timestamp_seconds, event_type, outcome, actor_identity, "
            "peer_ip, detail_code) VALUES "
            "(1, 'event', 'success', '', '192.0.2.1', 'detail');") &&
        StatementIsRejectedByConstraint(
            database,
            "INSERT INTO audit_events "
            "(server_timestamp_seconds, event_type, outcome, actor_identity, "
            "peer_ip, detail_code) VALUES "
            "(1, 'event', 'success', printf('%065d', 0), "
            "'192.0.2.1', 'detail');") &&
        StatementIsRejectedByConstraint(
            database,
            "INSERT INTO audit_state (id) VALUES (2);") &&
        StatementIsRejectedByConstraint(
            database,
            "UPDATE audit_state SET rotated_event_count = -1 WHERE id = 1;") &&
        StatementIsRejectedByConstraint(
            database,
            "UPDATE audit_state SET last_rotation_at_seconds = 1, "
            "last_rotated_sequence = NULL WHERE id = 1;"))) &&
      StatementSucceeds(
          database,
          "INSERT INTO firmware_log_outbox "
          "(category, peer_ip, created_at_seconds) "
          "VALUES ('authentication_limit_reached', '192.0.2.1', 1);") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO firmware_log_outbox "
          "(category, peer_ip, created_at_seconds) "
          "VALUES ('authentication_limit_reached', '192.0.2.1', 2);") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO firmware_log_outbox "
          "(category, peer_ip, created_at_seconds, dirty) "
          "VALUES ('event', '192.0.2.2', 1, 2);") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO firmware_log_outbox "
          "(category, peer_ip, created_at_seconds, lease_owner) "
          "VALUES ('event', '192.0.2.2', 1, zeroblob(16));") &&
      StatementIsRejectedByConstraint(
          database,
          "INSERT INTO firmware_log_outbox "
          "(category, peer_ip, created_at_seconds, lease_owner, lease_token, "
          "lease_expires_at_seconds) VALUES "
          "('event', '192.0.2.2', 1, zeroblob(15), zeroblob(32), 2);") &&
      StatementSucceeds(
          database,
          "INSERT INTO firmware_log_outbox "
          "(category, peer_ip, created_at_seconds, lease_owner, lease_token, "
          "lease_expires_at_seconds) VALUES "
          "('event', '192.0.2.2', 1, zeroblob(16), zeroblob(32), 2);");
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

constexpr const char* kRevisionThreeMigrationStatements[] = {
    "ALTER TABLE schema_version RENAME TO schema_version_revision_two;",
    R"sql(CREATE TABLE schema_version (
  version INTEGER NOT NULL CHECK (version = 3)
);)sql",
    "INSERT INTO schema_version (version) VALUES (3);",
    "DROP TABLE schema_version_revision_two;",
    "ALTER TABLE device_state RENAME TO device_state_revision_two;",
    R"sql(CREATE TABLE device_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL CHECK (state IN ('default', 'operational')),
  schema_revision INTEGER NOT NULL CHECK (schema_revision = 3),
  setup_completed_at_seconds INTEGER,
  CHECK (
    (state = 'default' AND setup_completed_at_seconds IS NULL) OR
    (state = 'operational' AND setup_completed_at_seconds IS NOT NULL AND
     setup_completed_at_seconds >= 0)
  )
);)sql",
    "INSERT INTO device_state "
    "(id, state, schema_revision, setup_completed_at_seconds) "
    "SELECT id, state, 3, setup_completed_at_seconds "
    "FROM device_state_revision_two;",
    "DROP TABLE device_state_revision_two;",
    "ALTER TABLE management_ips RENAME TO management_ips_revision_two;",
    R"sql(CREATE TABLE management_ips (
  id INTEGER PRIMARY KEY,
  normalized_ip TEXT NOT NULL CHECK (length(normalized_ip) BETWEEN 2 AND 45),
  role_scope TEXT NOT NULL
    CHECK (role_scope IN ('administrator', 'viewer')),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0)
);)sql",
    "INSERT INTO management_ips "
    "(id, normalized_ip, role_scope, enabled, created_at_seconds) "
    "SELECT id, normalized_ip, role_scope, enabled, created_at_seconds "
    "FROM management_ips_revision_two;",
    "DROP TABLE management_ips_revision_two;",
    R"sql(CREATE UNIQUE INDEX management_ips_role_ip_unique
  ON management_ips(role_scope, normalized_ip);)sql",
    R"sql(CREATE TABLE password_history (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_algorithm TEXT NOT NULL
    CHECK (password_algorithm = 'pbkdf2-hmac-sha256'),
  password_iterations INTEGER NOT NULL
    CHECK (password_iterations BETWEEN 1000 AND 2000000),
  password_salt BLOB NOT NULL CHECK (length(password_salt) = 16),
  password_derived BLOB NOT NULL CHECK (length(password_derived) = 32),
  replaced_at_seconds INTEGER NOT NULL CHECK (replaced_at_seconds >= 0)
);)sql",
    R"sql(CREATE UNIQUE INDEX password_history_user_id_unique
  ON password_history(user_id);)sql",
    "CREATE UNIQUE INDEX sessions_user_id_unique ON sessions(user_id);",
    "ALTER TABLE audit_events RENAME TO audit_events_revision_two;",
    R"sql(CREATE TABLE audit_events (
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
);)sql",
    "INSERT INTO audit_events "
    "(sequence, server_timestamp_seconds, event_type, outcome, actor_user_id, "
    "peer_ip, detail_code, subject_type, subject_identity) "
    "SELECT sequence, server_timestamp_seconds, event_type, outcome, "
    "actor_user_id, peer_ip, detail_code, '', '' "
    "FROM audit_events_revision_two;",
    "DROP TABLE audit_events_revision_two;",
    R"sql(CREATE INDEX audit_events_timestamp_index
  ON audit_events(server_timestamp_seconds);)sql"};

constexpr const char* kRevisionFourMigrationStatements[] = {
    "ALTER TABLE schema_version RENAME TO schema_version_revision_three;",
    R"sql(CREATE TABLE schema_version (
  version INTEGER NOT NULL CHECK (version = 4)
);)sql",
    "INSERT INTO schema_version (version) VALUES (4);",
    "DROP TABLE schema_version_revision_three;",
    "ALTER TABLE device_state RENAME TO device_state_revision_three;",
    R"sql(CREATE TABLE device_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL CHECK (state IN ('default', 'operational')),
  schema_revision INTEGER NOT NULL CHECK (schema_revision = 4),
  setup_completed_at_seconds INTEGER,
  CHECK (
    (state = 'default' AND setup_completed_at_seconds IS NULL) OR
    (state = 'operational' AND setup_completed_at_seconds IS NOT NULL AND
     setup_completed_at_seconds >= 0)
  )
);)sql",
    "INSERT INTO device_state "
    "(id, state, schema_revision, setup_completed_at_seconds) "
    "SELECT id, state, 4, setup_completed_at_seconds "
    "FROM device_state_revision_three;",
    "DROP TABLE device_state_revision_three;",
    "ALTER TABLE audit_events RENAME TO audit_events_revision_three;",
    R"sql(CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY,
  server_timestamp_seconds INTEGER NOT NULL
    CHECK (server_timestamp_seconds >= 0),
  event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  actor_identity TEXT NOT NULL
    CHECK (length(actor_identity) BETWEEN 1 AND 64),
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45),
  detail_code TEXT NOT NULL CHECK (length(detail_code) <= 64),
  subject_type TEXT NOT NULL DEFAULT ''
    CHECK (length(subject_type) <= 64),
  subject_identity TEXT NOT NULL DEFAULT ''
    CHECK (length(subject_identity) <= 64)
);)sql",
    R"sql(INSERT INTO audit_events
  (sequence, server_timestamp_seconds, event_type, outcome, actor_user_id,
   actor_identity, peer_ip, detail_code, subject_type, subject_identity)
SELECT old.sequence, old.server_timestamp_seconds, old.event_type, old.outcome,
       (SELECT id FROM users WHERE id = old.actor_user_id),
       CASE
         WHEN old.actor_user_id IS NULL THEN 'unknown'
         ELSE COALESCE(
           (SELECT canonical_username FROM users
            WHERE id = old.actor_user_id),
           'unknown')
       END,
       old.peer_ip, old.detail_code, old.subject_type, old.subject_identity
FROM audit_events_revision_three AS old;)sql",
    "DROP TABLE audit_events_revision_three;",
    R"sql(CREATE INDEX audit_events_timestamp_index
  ON audit_events(server_timestamp_seconds);)sql",
    R"sql(CREATE TABLE audit_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  rotated_event_count INTEGER NOT NULL DEFAULT 0
    CHECK (rotated_event_count >= 0),
  last_rotation_at_seconds INTEGER
    CHECK (last_rotation_at_seconds >= 0),
  last_rotated_sequence INTEGER
    CHECK (last_rotated_sequence >= 0),
  CHECK (
    (last_rotation_at_seconds IS NULL AND last_rotated_sequence IS NULL) OR
    (last_rotation_at_seconds IS NOT NULL AND
     last_rotated_sequence IS NOT NULL)
  )
);)sql",
    "INSERT INTO audit_state (id) VALUES (1);"};

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
  UniqueFd database_anchor_fd;
  std::unique_ptr<sqlite3, DatabaseCloser> database;
  dev_t database_device{0};
  ino_t database_inode{0};
  bool database_identity_captured{false};
  std::mutex connection_mutex;
  std::uint64_t max_audit_events{50000U};
  std::uint32_t audit_warning_percent{90U};
  bool poisoned{false};
};

namespace {

bool ValidateStoreAnchors(const std::filesystem::path& state_directory,
                          int state_directory_fd,
                          int database_anchor_fd,
                          dev_t database_device,
                          ino_t database_inode,
                          uid_t expected_owner) noexcept {
  if (!IsProtectedDirectoryFd(state_directory_fd, expected_owner)) {
    return false;
  }
  UniqueFd current_state_directory(OpenDirectoryNoFollow(state_directory));
  if (!current_state_directory.valid() ||
      !IsProtectedDirectoryFd(current_state_directory.get(), expected_owner) ||
      !SameDirectory(state_directory_fd, current_state_directory.get())) {
    return false;
  }

  struct stat anchor_status {};
  struct stat entry_status {};
  if (::fstat(database_anchor_fd, &anchor_status) != 0 ||
      !IsProtectedDatabaseStatus(anchor_status, expected_owner) ||
      anchor_status.st_dev != database_device ||
      anchor_status.st_ino != database_inode ||
      ::fstatat(state_directory_fd, "security.db", &entry_status,
                AT_SYMLINK_NOFOLLOW) != 0 ||
      !IsProtectedDatabaseStatus(entry_status, expected_owner) ||
      !SameFileIdentity(anchor_status, entry_status)) {
    return false;
  }

  int descriptor;
  do {
    descriptor = ::openat(state_directory_fd, "security.db",
                          O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (descriptor < 0 && errno == EINTR);
  UniqueFd current_database(descriptor);
  struct stat current_status {};
  return current_database.valid() &&
         ::fstat(current_database.get(), &current_status) == 0 &&
         IsProtectedDatabaseStatus(current_status, expected_owner) &&
         SameFileIdentity(anchor_status, current_status);
}

}  // namespace

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
  impl->max_audit_events = config.max_audit_events;
  impl->audit_warning_percent = config.audit_warning_percent;
  impl->state_directory_fd.Reset(
      OpenDirectoryNoFollow(impl->state_directory));
  if (!impl->state_directory_fd.valid() ||
      !IsProtectedDirectoryFd(impl->state_directory_fd.get(),
                              effective_user_id)) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_PATH", "failed to anchor security state directory");
  }
  auto database_result =
      OpenAnchoredDatabase(impl->state_directory_fd.get(), effective_user_id);
  if (!database_result.ok()) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        database_result.error().code, database_result.error().message);
  }
  impl->database_anchor_fd = std::move(database_result).value();
  struct stat database_status {};
  if (::fstat(impl->database_anchor_fd.get(), &database_status) != 0 ||
      !IsProtectedDatabaseStatus(database_status, effective_user_id)) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_PATH", "failed to anchor security database");
  }
  impl->database_device = database_status.st_dev;
  impl->database_inode = database_status.st_ino;
  impl->database_identity_captured = true;
  if (!ValidateStoreAnchors(
          impl->state_directory, impl->state_directory_fd.get(),
          impl->database_anchor_fd.get(), impl->database_device,
          impl->database_inode, effective_user_id)) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_PATH", "security database changed during open");
  }

  sqlite3* opened_database = nullptr;
  const std::string sqlite_path =
      "/proc/self/fd/" + std::to_string(impl->database_anchor_fd.get());
  const int open_result = ::sqlite3_open_v2(
      sqlite_path.c_str(), &opened_database,
      SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr);
  impl->database.reset(opened_database);
  if (open_result != SQLITE_OK) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_OPEN", "failed to open security database");
  }
  if (!ValidateStoreAnchors(
          impl->state_directory, impl->state_directory_fd.get(),
          impl->database_anchor_fd.get(), impl->database_device,
          impl->database_inode, effective_user_id)) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_PATH", "security database changed during open");
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
  if (!ValidateStoreAnchors(
          store->impl_->state_directory,
          store->impl_->state_directory_fd.get(),
          store->impl_->database_anchor_fd.get(),
          store->impl_->database_device, store->impl_->database_inode,
          effective_user_id)) {
    return StoreError<std::unique_ptr<SecurityStore>>(
        "E_SECURITY_DB_PATH", "security database changed during open");
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
    auto current =
        ValidateSchema(impl_->database.get(), kSecuritySchemaRevision);
    if (current.ok()) {
      return current;
    }
    int source_revision = 0;
    if (!QuerySingleInt(
            impl_->database.get(),
            "SELECT version FROM schema_version;", source_revision) ||
        (source_revision != kRevisionTwoSecuritySchema &&
         source_revision != kRevisionThreeSecuritySchema)) {
      return StoreError("E_SECURITY_DB_SCHEMA",
                        "security database schema is invalid");
    }
    return MigrateToRevisionFour(source_revision);
  }

  constexpr const char* kSchema = R"sql(
CREATE TABLE schema_version (
  version INTEGER NOT NULL CHECK (version = 4)
);
INSERT INTO schema_version (version) VALUES (4);
CREATE TABLE device_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL CHECK (state IN ('default', 'operational')),
  schema_revision INTEGER NOT NULL CHECK (schema_revision = 4),
  setup_completed_at_seconds INTEGER,
  CHECK (
    (state = 'default' AND setup_completed_at_seconds IS NULL) OR
    (state = 'operational' AND setup_completed_at_seconds IS NOT NULL AND
     setup_completed_at_seconds >= 0)
  )
);
INSERT INTO device_state (id, state, schema_revision)
VALUES (1, 'default', 4);

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

CREATE TABLE management_ips (
  id INTEGER PRIMARY KEY,
  normalized_ip TEXT NOT NULL CHECK (length(normalized_ip) BETWEEN 2 AND 45),
  role_scope TEXT NOT NULL
    CHECK (role_scope IN ('administrator', 'viewer')),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0)
);
CREATE UNIQUE INDEX management_ips_role_ip_unique
  ON management_ips(role_scope, normalized_ip);

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
CREATE UNIQUE INDEX sessions_user_id_unique ON sessions(user_id);
CREATE INDEX sessions_expiry_index ON sessions(expires_at_seconds);

CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY,
  server_timestamp_seconds INTEGER NOT NULL
    CHECK (server_timestamp_seconds >= 0),
  event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  actor_identity TEXT NOT NULL
    CHECK (length(actor_identity) BETWEEN 1 AND 64),
  peer_ip TEXT NOT NULL CHECK (length(peer_ip) BETWEEN 2 AND 45),
  detail_code TEXT NOT NULL CHECK (length(detail_code) <= 64),
  subject_type TEXT NOT NULL DEFAULT ''
    CHECK (length(subject_type) <= 64),
  subject_identity TEXT NOT NULL DEFAULT ''
    CHECK (length(subject_identity) <= 64)
);
CREATE INDEX audit_events_timestamp_index
  ON audit_events(server_timestamp_seconds);

CREATE TABLE audit_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  rotated_event_count INTEGER NOT NULL DEFAULT 0
    CHECK (rotated_event_count >= 0),
  last_rotation_at_seconds INTEGER
    CHECK (last_rotation_at_seconds >= 0),
  last_rotated_sequence INTEGER
    CHECK (last_rotated_sequence >= 0),
  CHECK (
    (last_rotation_at_seconds IS NULL AND last_rotated_sequence IS NULL) OR
    (last_rotation_at_seconds IS NOT NULL AND
     last_rotated_sequence IS NOT NULL)
  )
);
INSERT INTO audit_state (id) VALUES (1);

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
    (void)RollbackSchemaTransaction();
    return create;
  }
  auto validation =
      ValidateSchema(impl_->database.get(), kSecuritySchemaRevision);
  if (!validation.ok()) {
    (void)RollbackSchemaTransaction();
    return validation;
  }
  auto commit = Execute(impl_->database.get(), "COMMIT;", "E_SECURITY_DB_SCHEMA",
                        "failed to initialize security database");
  if (!commit.ok()) {
    (void)RollbackSchemaTransaction();
    return commit;
  }
  return common::Result<void>::Ok();
}

common::Result<void> SecurityStore::RollbackSchemaTransaction() {
  auto rollback = Execute(impl_->database.get(), "ROLLBACK;",
                          "E_SECURITY_DB_SCHEMA",
                          "failed to roll back security database schema");
  if (!rollback.ok()) {
    impl_->poisoned = true;
    impl_->database.reset();
  }
  return rollback;
}

common::Result<void> SecurityStore::MigrateToRevisionFour(int source_revision) {
  auto begin = Execute(impl_->database.get(), "BEGIN IMMEDIATE;",
                       "E_SECURITY_DB_SCHEMA",
                       "failed to migrate security database");
  if (!begin.ok()) {
    return begin;
  }

  auto source = ValidateSchema(
      impl_->database.get(), source_revision,
      ForeignKeyValidation::kAllowLegacyAuditActorOrphans);
  if (!source.ok()) {
    (void)RollbackSchemaTransaction();
    return source;
  }

  if (source_revision == kRevisionTwoSecuritySchema) {
    int duplicate_session_users = 0;
    if (!QuerySingleInt(
            impl_->database.get(),
            "SELECT COUNT(*) FROM (SELECT user_id FROM sessions "
            "GROUP BY user_id HAVING COUNT(*) > 1);",
            duplicate_session_users) ||
        duplicate_session_users != 0) {
      (void)RollbackSchemaTransaction();
      return StoreError("E_SECURITY_DB_SCHEMA",
                        "security database schema is invalid");
    }

    for (const char* statement : kRevisionThreeMigrationStatements) {
      auto migrated = Execute(impl_->database.get(), statement,
                              "E_SECURITY_DB_SCHEMA",
                              "failed to migrate security database");
      if (!migrated.ok()) {
        (void)RollbackSchemaTransaction();
        return migrated;
      }
    }

    auto revision_three = ValidateSchema(
        impl_->database.get(), kRevisionThreeSecuritySchema,
        ForeignKeyValidation::kAllowLegacyAuditActorOrphans);
    if (!revision_three.ok()) {
      (void)RollbackSchemaTransaction();
      return revision_three;
    }
  }

  for (const char* statement : kRevisionFourMigrationStatements) {
    auto migrated = Execute(impl_->database.get(), statement,
                            "E_SECURITY_DB_SCHEMA",
                            "failed to migrate security database");
    if (!migrated.ok()) {
      (void)RollbackSchemaTransaction();
      return migrated;
    }
  }

  auto revision_four =
      ValidateSchema(impl_->database.get(), kSecuritySchemaRevision);
  if (!revision_four.ok()) {
    (void)RollbackSchemaTransaction();
    return revision_four;
  }

  auto commit = Execute(impl_->database.get(), "COMMIT;",
                        "E_SECURITY_DB_SCHEMA",
                        "failed to commit security database migration");
  if (!commit.ok()) {
    (void)RollbackSchemaTransaction();
    return commit;
  }
  return common::Result<void>::Ok();
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

common::Result<SecurityStore::Transaction>
SecurityStore::BeginReadTransaction() const {
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
  auto result = Execute(impl_->database.get(), "BEGIN;",
                        "E_SECURITY_DB_TRANSACTION",
                        "failed to begin security read transaction");
  if (!result.ok()) {
    return common::Result<Transaction>::Err(result.error());
  }
  return common::Result<Transaction>::Ok(
      Transaction(impl_, std::move(connection_lease)));
}

common::Result<void> SecurityStore::CheckHealth() const {
  const auto failure = [] {
    return StoreError("E_SECURITY_DB_HEALTH",
                      "security store health check failed");
  };
  try {
    std::unique_lock<std::mutex> connection_lease(impl_->connection_mutex);
    if (impl_->poisoned || impl_->database == nullptr ||
        !impl_->database_identity_captured) {
      return failure();
    }

    const uid_t effective_user_id = ::geteuid();
    if (!ValidateStoreAnchors(
            impl_->state_directory, impl_->state_directory_fd.get(),
            impl_->database_anchor_fd.get(), impl_->database_device,
            impl_->database_inode, effective_user_id)) {
      return failure();
    }

    PreparedStatement quick_check(impl_->database.get(), "PRAGMA quick_check;");
    if (!quick_check.valid() || ::sqlite3_step(quick_check.get()) != SQLITE_ROW ||
        ::sqlite3_column_type(quick_check.get(), 0) != SQLITE_TEXT) {
      return failure();
    }
    const auto* quick_check_text = ::sqlite3_column_text(quick_check.get(), 0);
    const int quick_check_length = ::sqlite3_column_bytes(quick_check.get(), 0);
    if (quick_check_text == nullptr || quick_check_length != 2 ||
        quick_check_text[0] != 'o' || quick_check_text[1] != 'k' ||
        ::sqlite3_step(quick_check.get()) != SQLITE_DONE) {
      return failure();
    }

    auto schema = ValidateSchema(impl_->database.get(), kSecuritySchemaRevision);
    if (!schema.ok() ||
        !ValidateStoreAnchors(
            impl_->state_directory, impl_->state_directory_fd.get(),
            impl_->database_anchor_fd.get(), impl_->database_device,
            impl_->database_inode, effective_user_id)) {
      return failure();
    }
    return common::Result<void>::Ok();
  } catch (...) {
    return failure();
  }
}

common::Result<SecurityStore::AuditStatusSnapshot>
SecurityStore::ReadAuditStatus() const {
  auto started = BeginReadTransaction();
  if (!started.ok()) {
    return StoreError<AuditStatusSnapshot>("E_SECURITY_DB_AUDIT",
                                           "audit status read failed");
  }
  auto transaction = std::move(started).value();
  const auto failure = [&transaction] {
    if (transaction.active()) {
      (void)transaction.Rollback();
    }
    return StoreError<AuditStatusSnapshot>("E_SECURITY_DB_AUDIT",
                                           "audit status read failed");
  };

  AuditStatusSnapshot snapshot;
  {
    PreparedStatement statement(
        impl_->database.get(),
        "SELECT (SELECT COUNT(*) FROM audit_events), rotated_event_count, "
        "last_rotation_at_seconds, last_rotated_sequence "
        "FROM audit_state WHERE id = 1;");
    if (!statement.valid() ||
        ::sqlite3_step(statement.get()) != SQLITE_ROW ||
        ::sqlite3_column_type(statement.get(), 0) != SQLITE_INTEGER ||
        ::sqlite3_column_type(statement.get(), 1) != SQLITE_INTEGER) {
      return failure();
    }
    const int rotation_time_type =
        ::sqlite3_column_type(statement.get(), 2);
    const int rotation_sequence_type =
        ::sqlite3_column_type(statement.get(), 3);
    const bool rotation_values_are_null =
        rotation_time_type == SQLITE_NULL &&
        rotation_sequence_type == SQLITE_NULL;
    const bool rotation_values_are_integers =
        rotation_time_type == SQLITE_INTEGER &&
        rotation_sequence_type == SQLITE_INTEGER;
    if (!rotation_values_are_null && !rotation_values_are_integers) {
      return failure();
    }

    const std::int64_t current_events =
        ::sqlite3_column_int64(statement.get(), 0);
    const std::int64_t rotated_event_count =
        ::sqlite3_column_int64(statement.get(), 1);
    if (current_events < 0 || rotated_event_count < 0) {
      return failure();
    }
    snapshot.current_events = static_cast<std::uint64_t>(current_events);
    snapshot.rotated_event_count =
        static_cast<std::uint64_t>(rotated_event_count);
    if (rotation_values_are_integers) {
      const std::int64_t last_rotation_at_seconds =
          ::sqlite3_column_int64(statement.get(), 2);
      const std::int64_t last_rotated_sequence =
          ::sqlite3_column_int64(statement.get(), 3);
      if (last_rotation_at_seconds < 0 || last_rotated_sequence < 0) {
        return failure();
      }
      snapshot.last_rotation_at_seconds = last_rotation_at_seconds;
      snapshot.last_rotated_sequence = last_rotated_sequence;
    }
    if (::sqlite3_step(statement.get()) != SQLITE_DONE) {
      return failure();
    }
  }

  snapshot.max_events = impl_->max_audit_events;
  std::uint64_t scaled_current = 0U;
  const bool current_product_is_valid =
      CheckedMultiply(snapshot.current_events, 100U, scaled_current);
  std::uint64_t warning_boundary = 0U;
  if (snapshot.max_events == 0U ||
      !CheckedMultiply(snapshot.max_events, impl_->audit_warning_percent,
                       warning_boundary)) {
    return failure();
  }
  if (snapshot.current_events >= snapshot.max_events ||
      !current_product_is_valid) {
    snapshot.usage_percent = 100U;
  } else {
    snapshot.usage_percent = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(100U,
                                scaled_current / snapshot.max_events));
  }
  snapshot.warning =
      !current_product_is_valid || scaled_current >= warning_boundary;

  auto committed = transaction.Commit();
  if (!committed.ok()) {
    return failure();
  }
  return common::Result<AuditStatusSnapshot>::Ok(std::move(snapshot));
}

common::Result<SecurityStore::AuditEventQueryResult>
SecurityStore::ReadAuditEvents(const AuditEventQuery& query) const {
  const auto store_failure = [] {
    return StoreError<AuditEventQueryResult>("E_SECURITY_DB_AUDIT",
                                             "audit event read failed");
  };
  if (query.limit < 1U || query.limit > 100U ||
      (query.from_seconds.has_value() && *query.from_seconds < 0) ||
      (query.to_seconds.has_value() && *query.to_seconds < 0) ||
      (query.from_seconds.has_value() && query.to_seconds.has_value() &&
       *query.from_seconds > *query.to_seconds)) {
    return store_failure();
  }

  const char* sort_column = nullptr;
  switch (query.sort_field) {
    case AuditEventSortField::kTimestamp:
      sort_column = "server_timestamp_seconds";
      break;
    case AuditEventSortField::kEventType:
      sort_column = "event_type";
      break;
    case AuditEventSortField::kOutcome:
      sort_column = "outcome";
      break;
    case AuditEventSortField::kActor:
      sort_column = "actor_identity";
      break;
    case AuditEventSortField::kPeerIp:
      sort_column = "peer_ip";
      break;
    case AuditEventSortField::kSubject:
      sort_column = "subject_identity";
      break;
  }
  if (sort_column == nullptr) {
    return store_failure();
  }
  const bool ascending =
      query.sort_direction == AuditEventSortDirection::kAscending;
  if (!ascending &&
      query.sort_direction != AuditEventSortDirection::kDescending) {
    return store_failure();
  }
  if (query.cursor.has_value()) {
    const bool integer_sort =
        query.sort_field == AuditEventSortField::kTimestamp;
    if (query.cursor->sequence <= 0 ||
        integer_sort != query.cursor->integer_key.has_value() ||
        integer_sort == query.cursor->text_key.has_value() ||
        (query.cursor->integer_key.has_value() &&
         *query.cursor->integer_key < 0)) {
      return store_failure();
    }
  }

  std::string sql =
      "SELECT sequence, server_timestamp_seconds, event_type, outcome, "
      "actor_identity, peer_ip, detail_code, subject_type, subject_identity "
      "FROM audit_events WHERE 1 = 1";
  if (query.from_seconds.has_value()) {
    sql += " AND server_timestamp_seconds >= ?";
  }
  if (query.to_seconds.has_value()) {
    sql += " AND server_timestamp_seconds <= ?";
  }
  if (query.event_type.has_value()) {
    sql += " AND event_type = ?";
  }
  if (query.outcome.has_value()) {
    sql += " AND outcome = ?";
  }
  if (query.actor_identity.has_value()) {
    sql += " AND actor_identity = ?";
  }
  if (query.peer_ip.has_value()) {
    sql += " AND peer_ip = ?";
  }
  if (query.subject_type.has_value()) {
    sql += " AND subject_type = ?";
  }
  if (query.subject_identity.has_value()) {
    sql += " AND subject_identity = ?";
  }
  if (query.cursor.has_value()) {
    sql += " AND (";
    sql += sort_column;
    sql += ascending ? " > ? OR (" : " < ? OR (";
    sql += sort_column;
    sql += ascending ? " = ? AND sequence > ?))"
                     : " = ? AND sequence < ?))";
  }
  sql += " ORDER BY ";
  sql += sort_column;
  sql += ascending ? " ASC, sequence ASC LIMIT ?;"
                   : " DESC, sequence DESC LIMIT ?;";

  auto started = BeginReadTransaction();
  if (!started.ok()) {
    return store_failure();
  }
  auto transaction = std::move(started).value();
  const auto failure = [&transaction, &store_failure] {
    if (transaction.active()) {
      (void)transaction.Rollback();
    }
    return store_failure();
  };

  PreparedStatement statement(impl_->database.get(), sql.c_str());
  if (!statement.valid()) {
    return failure();
  }
  int parameter = 1;
  const auto bind_integer = [&statement, &parameter](std::int64_t value) {
    return ::sqlite3_bind_int64(statement.get(), parameter++, value) ==
           SQLITE_OK;
  };
  const auto bind_text = [&statement, &parameter](const std::string& value) {
    return ::sqlite3_bind_text(statement.get(), parameter++, value.data(),
                               static_cast<int>(value.size()),
                               SQLITE_TRANSIENT) == SQLITE_OK;
  };
  if ((query.from_seconds.has_value() &&
       !bind_integer(*query.from_seconds)) ||
      (query.to_seconds.has_value() && !bind_integer(*query.to_seconds)) ||
      (query.event_type.has_value() && !bind_text(*query.event_type)) ||
      (query.outcome.has_value() && !bind_text(*query.outcome)) ||
      (query.actor_identity.has_value() &&
       !bind_text(*query.actor_identity)) ||
      (query.peer_ip.has_value() && !bind_text(*query.peer_ip)) ||
      (query.subject_type.has_value() && !bind_text(*query.subject_type)) ||
      (query.subject_identity.has_value() &&
       !bind_text(*query.subject_identity))) {
    return failure();
  }
  if (query.cursor.has_value()) {
    if (query.cursor->integer_key.has_value()) {
      if (!bind_integer(*query.cursor->integer_key) ||
          !bind_integer(*query.cursor->integer_key)) {
        return failure();
      }
    } else if (query.cursor->text_key.has_value()) {
      if (!bind_text(*query.cursor->text_key) ||
          !bind_text(*query.cursor->text_key)) {
        return failure();
      }
    } else {
      return failure();
    }
    if (!bind_integer(query.cursor->sequence)) {
      return failure();
    }
  }
  if (!bind_integer(static_cast<std::int64_t>(query.limit) + 1) ||
      parameter - 1 != ::sqlite3_bind_parameter_count(statement.get())) {
    return failure();
  }

  const auto read_text = [&statement](int column,
                                      std::size_t minimum_bytes,
                                      std::size_t maximum_bytes,
                                      std::string& output) {
    if (::sqlite3_column_type(statement.get(), column) != SQLITE_TEXT) {
      return false;
    }
    const int byte_count = ::sqlite3_column_bytes(statement.get(), column);
    const auto* value = ::sqlite3_column_text(statement.get(), column);
    if (byte_count < 0 ||
        static_cast<std::size_t>(byte_count) < minimum_bytes ||
        static_cast<std::size_t>(byte_count) > maximum_bytes ||
        (byte_count > 0 && value == nullptr)) {
      return false;
    }
    const std::string_view view(
        value == nullptr ? "" : reinterpret_cast<const char*>(value),
        static_cast<std::size_t>(byte_count));
    if (view.find('\0') != std::string_view::npos ||
        !g_utf8_validate(view.data(), static_cast<gssize>(view.size()),
                         nullptr)) {
      return false;
    }
    output.assign(view);
    return true;
  };

  AuditEventQueryResult result;
  result.events.reserve(static_cast<std::size_t>(query.limit) + 1U);
  int step = SQLITE_ROW;
  while ((step = ::sqlite3_step(statement.get())) == SQLITE_ROW) {
    if (::sqlite3_column_type(statement.get(), 0) != SQLITE_INTEGER ||
        ::sqlite3_column_type(statement.get(), 1) != SQLITE_INTEGER) {
      return failure();
    }
    AuditEventRecord event;
    event.sequence = ::sqlite3_column_int64(statement.get(), 0);
    event.server_timestamp_seconds =
        ::sqlite3_column_int64(statement.get(), 1);
    if (event.sequence <= 0 || event.server_timestamp_seconds < 0 ||
        !read_text(2, 1U, 64U, event.event_type) ||
        !read_text(3, 1U, 7U, event.outcome) ||
        (event.outcome != "success" && event.outcome != "failure") ||
        !read_text(4, 1U, 64U, event.actor_identity) ||
        !read_text(5, 2U, 45U, event.peer_ip) ||
        !read_text(6, 0U, 64U, event.detail_code) ||
        !read_text(7, 0U, 64U, event.subject_type) ||
        !read_text(8, 0U, 64U, event.subject_identity)) {
      return failure();
    }
    result.events.push_back(std::move(event));
    if (result.events.size() > static_cast<std::size_t>(query.limit) + 1U) {
      return failure();
    }
  }
  if (step != SQLITE_DONE) {
    return failure();
  }
  result.has_more = result.events.size() > query.limit;
  if (result.has_more) {
    result.events.pop_back();
  }
  auto committed = transaction.Commit();
  if (!committed.ok()) {
    return failure();
  }
  return common::Result<AuditEventQueryResult>::Ok(std::move(result));
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

    auto audited = InsertAuditEvent(
        transaction, record.completed_at_seconds, "bootstrap_completed",
        "success", user_id, record.normalized_peer_ip,
        "initial_administrator");
    if (!audited.ok()) {
      return fail("E_BOOTSTRAP_STORE", "bootstrap transaction failed");
    }

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

common::Result<SecurityStore::AuthenticationContext>
SecurityStore::ReadAuthenticationContext(
    Transaction& transaction,
    std::string_view canonical_username,
    std::string_view normalized_peer_ip) const {
  const auto failure = [] {
    return StoreError<AuthenticationContext>(
        "E_AUTHENTICATION_STORE", "authentication transaction failed");
  };
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return failure();
  }

  AuthenticationContext context;
  auto state = StateUnderConnectionLease();
  if (!state.ok()) {
    return failure();
  }
  context.state = state.value();

  const auto finalize = [](sqlite3_stmt* statement) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
  };
  const auto read_peer_for_role =
      [this, normalized_peer_ip, &failure, &finalize](
          std::string_view role_scope) -> common::Result<bool> {
    sqlite3_stmt* raw_peer = nullptr;
    constexpr const char* kReadPeer =
        "SELECT EXISTS(SELECT 1 FROM management_ips "
        "WHERE normalized_ip = ?1 AND role_scope = ?2 AND enabled = 1);";
    if (::sqlite3_prepare_v2(impl_->database.get(), kReadPeer, -1, &raw_peer,
                             nullptr) != SQLITE_OK) {
      return common::Result<bool>::Err(failure().error());
    }
    std::unique_ptr<sqlite3_stmt, decltype(finalize)> peer(raw_peer, finalize);
    if (::sqlite3_bind_text(peer.get(), 1, normalized_peer_ip.data(),
                            static_cast<int>(normalized_peer_ip.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_text(peer.get(), 2, role_scope.data(),
                            static_cast<int>(role_scope.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_step(peer.get()) != SQLITE_ROW) {
      return common::Result<bool>::Err(failure().error());
    }
    const bool registered = ::sqlite3_column_int(peer.get(), 0) == 1;
    if (::sqlite3_step(peer.get()) != SQLITE_DONE) {
      return common::Result<bool>::Err(failure().error());
    }
    return common::Result<bool>::Ok(registered);
  };

  sqlite3_stmt* raw_user = nullptr;
  constexpr const char* kReadUser =
      "SELECT id, display_username, role, enabled, password_algorithm, "
      "password_iterations, password_salt, password_derived, "
      "failed_login_count, lock_until_seconds, created_at_seconds, "
      "last_login_at_seconds FROM users "
      "WHERE canonical_username = ?1 COLLATE NOCASE;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kReadUser, -1, &raw_user,
                           nullptr) != SQLITE_OK) {
    return failure();
  }
  std::unique_ptr<sqlite3_stmt, decltype(finalize)> user(raw_user, finalize);
  if (::sqlite3_bind_text(user.get(), 1, canonical_username.data(),
                          static_cast<int>(canonical_username.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK) {
    return failure();
  }
  const int user_step = ::sqlite3_step(user.get());
  if (user_step == SQLITE_DONE) {
    user.reset();
    auto peer_registered = read_peer_for_role("administrator");
    if (!peer_registered.ok()) {
      return failure();
    }
    context.peer_registered = peer_registered.value();
    return common::Result<AuthenticationContext>::Ok(std::move(context));
  }
  if (user_step != SQLITE_ROW) {
    return failure();
  }

  const auto* display_username = ::sqlite3_column_text(user.get(), 1);
  const auto* role = ::sqlite3_column_text(user.get(), 2);
  const auto* algorithm = ::sqlite3_column_text(user.get(), 4);
  const auto* salt = static_cast<const unsigned char*>(
      ::sqlite3_column_blob(user.get(), 6));
  const auto* derived = static_cast<const unsigned char*>(
      ::sqlite3_column_blob(user.get(), 7));
  const int salt_size = ::sqlite3_column_bytes(user.get(), 6);
  const int derived_size = ::sqlite3_column_bytes(user.get(), 7);
  if (display_username == nullptr || role == nullptr || algorithm == nullptr ||
      salt == nullptr || derived == nullptr || salt_size < 0 ||
      derived_size < 0) {
    return failure();
  }

  AuthenticationUser loaded;
  loaded.id = ::sqlite3_column_int64(user.get(), 0);
  loaded.display_username =
      reinterpret_cast<const char*>(display_username);
  loaded.role = reinterpret_cast<const char*>(role);
  loaded.enabled = ::sqlite3_column_int(user.get(), 3) == 1;
  loaded.password.algorithm = reinterpret_cast<const char*>(algorithm);
  loaded.password.iterations =
      static_cast<std::uint32_t>(::sqlite3_column_int64(user.get(), 5));
  loaded.password.salt.assign(salt, static_cast<std::size_t>(salt_size));
  loaded.password.derived.assign(derived,
                                 static_cast<std::size_t>(derived_size));
  loaded.failed_login_count = ::sqlite3_column_int64(user.get(), 8);
  if (::sqlite3_column_type(user.get(), 9) != SQLITE_NULL) {
    loaded.lock_until_seconds = ::sqlite3_column_int64(user.get(), 9);
  }
  loaded.created_at_seconds = ::sqlite3_column_int64(user.get(), 10);
  if (::sqlite3_column_type(user.get(), 11) != SQLITE_NULL) {
    loaded.last_login_at_seconds = ::sqlite3_column_int64(user.get(), 11);
  }
  if (::sqlite3_step(user.get()) != SQLITE_DONE) {
    return failure();
  }
  user.reset();
  auto peer_registered = read_peer_for_role(loaded.role);
  if (!peer_registered.ok()) {
    return failure();
  }
  context.peer_registered = peer_registered.value();
  context.user.emplace(std::move(loaded));
  return common::Result<AuthenticationContext>::Ok(std::move(context));
}

common::Result<bool> SecurityStore::IsManagementPeer(
    std::string_view normalized_peer_ip) {
  const auto failure = [] {
    return StoreError<bool>("E_AUTHENTICATION_STORE",
                            "authentication transaction failed");
  };
  auto started = BeginReadTransaction();
  if (!started.ok()) {
    return failure();
  }
  auto transaction = std::move(started).value();
  sqlite3_stmt* raw_peer = nullptr;
  constexpr const char* kReadPeer =
      "SELECT EXISTS(SELECT 1 FROM management_ips "
      "WHERE normalized_ip = ?1 AND enabled = 1);";
  if (::sqlite3_prepare_v2(impl_->database.get(), kReadPeer, -1, &raw_peer,
                           nullptr) != SQLITE_OK) {
    (void)transaction.Rollback();
    return failure();
  }
  const auto finalize = [](sqlite3_stmt* statement) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
  };
  std::unique_ptr<sqlite3_stmt, decltype(finalize)> peer(raw_peer, finalize);
  if (::sqlite3_bind_text(peer.get(), 1, normalized_peer_ip.data(),
                          static_cast<int>(normalized_peer_ip.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_step(peer.get()) != SQLITE_ROW) {
    (void)transaction.Rollback();
    return failure();
  }
  const bool enabled = ::sqlite3_column_int(peer.get(), 0) == 1;
  if (::sqlite3_step(peer.get()) != SQLITE_DONE) {
    (void)transaction.Rollback();
    return failure();
  }
  peer.reset();
  auto committed = transaction.Commit();
  return committed.ok() ? common::Result<bool>::Ok(enabled) : failure();
}

common::Result<void> SecurityStore::SetLoginFailureState(
    Transaction& transaction,
    std::int64_t user_id,
    std::int64_t failed_login_count,
    std::optional<std::int64_t> lock_until_seconds) {
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "UPDATE users SET failed_login_count = ?1, lock_until_seconds = ?2 "
      "WHERE id = ?3;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kSql, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 1, failed_login_count) != SQLITE_OK ||
      (lock_until_seconds.has_value()
           ? ::sqlite3_bind_int64(statement, 2, *lock_until_seconds)
           : ::sqlite3_bind_null(statement, 2)) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 3, user_id) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_DONE ||
      ::sqlite3_changes(impl_->database.get()) != 1) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  const bool finalized = ::sqlite3_finalize(statement) == SQLITE_OK;
  return finalized
             ? common::Result<void>::Ok()
             : StoreError("E_AUTHENTICATION_STORE",
                          "authentication transaction failed");
}

common::Result<void> SecurityStore::SetLoginSuccessState(
    Transaction& transaction,
    std::int64_t user_id,
    std::int64_t now_seconds) {
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "UPDATE users SET failed_login_count = 0, lock_until_seconds = NULL, "
      "last_login_at_seconds = ?1 WHERE id = ?2;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kSql, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 1, now_seconds) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 2, user_id) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_DONE ||
      ::sqlite3_changes(impl_->database.get()) != 1) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  const bool finalized = ::sqlite3_finalize(statement) == SQLITE_OK;
  return finalized
             ? common::Result<void>::Ok()
             : StoreError("E_AUTHENTICATION_STORE",
                          "authentication transaction failed");
}

common::Result<void> SecurityStore::InsertAuditEvent(
    Transaction& transaction,
    std::int64_t now_seconds,
    std::string_view event_type,
    std::string_view outcome,
    std::optional<std::int64_t> actor_user_id,
    std::string_view normalized_peer_ip,
    std::string_view detail_code,
    std::string_view subject_type,
    std::string_view subject_identity) {
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
  }
  std::string actor_identity{"system"};
  if (actor_user_id.has_value()) {
    PreparedStatement actor(
        impl_->database.get(),
        "SELECT canonical_username FROM users WHERE id = ?1;");
    if (!actor.valid() ||
        ::sqlite3_bind_int64(actor.get(), 1, *actor_user_id) != SQLITE_OK ||
        ::sqlite3_step(actor.get()) != SQLITE_ROW) {
      return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
    }
    const auto* identity = ::sqlite3_column_text(actor.get(), 0);
    if (identity == nullptr) {
      return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
    }
    actor_identity = reinterpret_cast<const char*>(identity);
    if (::sqlite3_step(actor.get()) != SQLITE_DONE) {
      return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
    }
  }

  auto insertion_state = ReadAuditInsertionState(impl_->database.get());
  if (!insertion_state.ok()) {
    return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
  }
  auto rotated = RotateAuditEvents(impl_->database.get(),
                                   insertion_state.value(),
                                   impl_->max_audit_events, now_seconds);
  if (!rotated.ok()) {
    return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
  }

  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "INSERT INTO audit_events "
      "(sequence, server_timestamp_seconds, event_type, outcome, "
      "actor_user_id, actor_identity, peer_ip, detail_code, subject_type, "
      "subject_identity) "
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);";
  if (::sqlite3_prepare_v2(impl_->database.get(), kSql, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 1,
                           insertion_state.value().next_sequence) !=
          SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 2, now_seconds) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 3, event_type.data(),
                          static_cast<int>(event_type.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 4, outcome.data(),
                          static_cast<int>(outcome.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      (actor_user_id.has_value()
           ? ::sqlite3_bind_int64(statement, 5, *actor_user_id)
           : ::sqlite3_bind_null(statement, 5)) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 6, actor_identity.data(),
                          static_cast<int>(actor_identity.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 7, normalized_peer_ip.data(),
                          static_cast<int>(normalized_peer_ip.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 8, detail_code.data(),
                          static_cast<int>(detail_code.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 9,
                          subject_type.empty() ? "" : subject_type.data(),
                          static_cast<int>(subject_type.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 10,
                          subject_identity.empty() ? ""
                                                   : subject_identity.data(),
                          static_cast<int>(subject_identity.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_DONE ||
      ::sqlite3_changes64(impl_->database.get()) != 1) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return StoreError("E_SECURITY_DB_AUDIT", "audit transaction failed");
  }
  const bool finalized = ::sqlite3_finalize(statement) == SQLITE_OK;
  return finalized
             ? common::Result<void>::Ok()
             : StoreError("E_SECURITY_DB_AUDIT",
                          "audit transaction failed");
}

common::Result<void> SecurityStore::CoalesceFirmwareLogOutbox(
    Transaction& transaction,
    std::int64_t now_seconds,
    std::string_view category,
    std::string_view normalized_peer_ip) {
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "INSERT INTO firmware_log_outbox "
      "(category, peer_ip, created_at_seconds) VALUES (?1, ?2, ?3) "
      "ON CONFLICT(category, peer_ip) DO UPDATE SET "
      "created_at_seconds = excluded.created_at_seconds, "
      "dirty = CASE WHEN firmware_log_outbox.lease_token IS NULL "
      "THEN firmware_log_outbox.dirty ELSE 1 END;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kSql, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 1, category.data(),
                          static_cast<int>(category.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 2, normalized_peer_ip.data(),
                          static_cast<int>(normalized_peer_ip.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 3, now_seconds) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_DONE) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  const bool finalized = ::sqlite3_finalize(statement) == SQLITE_OK;
  return finalized
             ? common::Result<void>::Ok()
             : StoreError("E_AUTHENTICATION_STORE",
                          "authentication transaction failed");
}

common::Result<bool> SecurityStore::HasClaimableFirmwareLogOutbox(
    std::int64_t now_seconds) {
  auto started = BeginReadTransaction();
  if (!started.ok()) {
    return StoreError<bool>("E_AUTHENTICATION_STORE",
                            "authentication transaction failed");
  }
  auto transaction = std::move(started).value();
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "SELECT EXISTS(SELECT 1 FROM firmware_log_outbox "
      "WHERE lease_token IS NULL OR lease_expires_at_seconds <= ?1);";
  if (::sqlite3_prepare_v2(impl_->database.get(), kSql, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 1, now_seconds) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_ROW) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    (void)transaction.Rollback();
    return StoreError<bool>("E_AUTHENTICATION_STORE",
                            "authentication transaction failed");
  }
  const bool claimable = ::sqlite3_column_int(statement, 0) == 1;
  const bool one_row = ::sqlite3_step(statement) == SQLITE_DONE;
  const bool finalized = ::sqlite3_finalize(statement) == SQLITE_OK;
  const bool valid = one_row && finalized;
  if (!valid) {
    (void)transaction.Rollback();
    return StoreError<bool>("E_AUTHENTICATION_STORE",
                            "authentication transaction failed");
  }
  auto committed = transaction.Commit();
  if (!committed.ok()) {
    if (transaction.active()) {
      (void)transaction.Rollback();
    }
    return StoreError<bool>("E_AUTHENTICATION_STORE",
                            "authentication transaction failed");
  }
  return common::Result<bool>::Ok(claimable);
}

common::Result<std::optional<SecurityStore::FirmwareLogOutboxEntry>>
SecurityStore::ClaimFirmwareLogOutbox(
    std::span<const unsigned char> lease_owner,
    std::span<const unsigned char> lease_token,
    std::int64_t now_seconds,
    std::int64_t lease_expires_at_seconds) {
  const auto failure = [] {
    return StoreError<std::optional<FirmwareLogOutboxEntry>>(
        "E_AUTHENTICATION_STORE", "authentication transaction failed");
  };
  if (lease_owner.size() != 16U || lease_token.size() != 32U ||
      now_seconds < 0 || lease_expires_at_seconds < now_seconds) {
    return failure();
  }
  auto started = BeginTransaction();
  if (!started.ok()) {
    return failure();
  }
  auto transaction = std::move(started).value();
  const auto rollback_failure = [&transaction, &failure] {
    if (transaction.active()) {
      (void)transaction.Rollback();
    }
    return failure();
  };

  sqlite3_stmt* raw_read = nullptr;
  constexpr const char* kRead =
      "SELECT id, category, peer_ip FROM firmware_log_outbox "
      "WHERE lease_token IS NULL OR lease_expires_at_seconds <= ?1 "
      "ORDER BY created_at_seconds, id LIMIT 1;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kRead, -1, &raw_read,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_int64(raw_read, 1, now_seconds) != SQLITE_OK) {
    if (raw_read != nullptr) {
      (void)::sqlite3_finalize(raw_read);
    }
    return rollback_failure();
  }
  const auto finalize = [](sqlite3_stmt* statement) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
  };
  std::unique_ptr<sqlite3_stmt, decltype(finalize)> read(raw_read, finalize);
  const int read_step = ::sqlite3_step(read.get());
  if (read_step == SQLITE_DONE) {
    read.reset();
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return rollback_failure();
    }
    return common::Result<std::optional<FirmwareLogOutboxEntry>>::Ok(
        std::nullopt);
  }
  if (read_step != SQLITE_ROW) {
    return rollback_failure();
  }
  const auto* category = ::sqlite3_column_text(read.get(), 1);
  const auto* peer_ip = ::sqlite3_column_text(read.get(), 2);
  if (category == nullptr || peer_ip == nullptr) {
    return rollback_failure();
  }
  FirmwareLogOutboxEntry entry;
  entry.id = ::sqlite3_column_int64(read.get(), 0);
  entry.category = reinterpret_cast<const char*>(category);
  entry.peer_ip = reinterpret_cast<const char*>(peer_ip);
  if (::sqlite3_step(read.get()) != SQLITE_DONE) {
    return rollback_failure();
  }
  read.reset();

  sqlite3_stmt* update = nullptr;
  constexpr const char* kClaim =
      "UPDATE firmware_log_outbox SET lease_owner = ?1, lease_token = ?2, "
      "lease_expires_at_seconds = ?3, dirty = 0 WHERE id = ?4 AND "
      "(lease_token IS NULL OR lease_expires_at_seconds <= ?5);";
  if (::sqlite3_prepare_v2(impl_->database.get(), kClaim, -1, &update,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_blob(update, 1, lease_owner.data(),
                          static_cast<int>(lease_owner.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_blob(update, 2, lease_token.data(),
                          static_cast<int>(lease_token.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_int64(update, 3, lease_expires_at_seconds) != SQLITE_OK ||
      ::sqlite3_bind_int64(update, 4, entry.id) != SQLITE_OK ||
      ::sqlite3_bind_int64(update, 5, now_seconds) != SQLITE_OK ||
      ::sqlite3_step(update) != SQLITE_DONE ||
      ::sqlite3_changes(impl_->database.get()) != 1) {
    if (update != nullptr) {
      (void)::sqlite3_finalize(update);
    }
    return rollback_failure();
  }
  if (::sqlite3_finalize(update) != SQLITE_OK) {
    return rollback_failure();
  }
  auto committed = transaction.Commit();
  if (!committed.ok()) {
    return rollback_failure();
  }
  return common::Result<std::optional<FirmwareLogOutboxEntry>>::Ok(
      std::optional<FirmwareLogOutboxEntry>(std::move(entry)));
}

common::Result<void> SecurityStore::AcknowledgeFirmwareLogOutbox(
    std::int64_t outbox_id,
    std::span<const unsigned char> lease_owner,
    std::span<const unsigned char> lease_token) {
  auto started = BeginTransaction();
  if (!started.ok()) {
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  auto transaction = std::move(started).value();
  const auto rollback_failure = [&transaction] {
    if (transaction.active()) {
      (void)transaction.Rollback();
    }
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  };
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kDelete =
      "DELETE FROM firmware_log_outbox WHERE id = ?1 AND lease_owner = ?2 "
      "AND lease_token = ?3 AND dirty = 0;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kDelete, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 1, outbox_id) != SQLITE_OK ||
      ::sqlite3_bind_blob(statement, 2, lease_owner.data(),
                          static_cast<int>(lease_owner.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_blob(statement, 3, lease_token.data(),
                          static_cast<int>(lease_token.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_DONE) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return rollback_failure();
  }
  const int deleted = ::sqlite3_changes(impl_->database.get());
  if (::sqlite3_finalize(statement) != SQLITE_OK) {
    return rollback_failure();
  }
  if (deleted == 0) {
    constexpr const char* kRetainDirty =
        "UPDATE firmware_log_outbox SET dirty = 0, lease_owner = NULL, "
        "lease_token = NULL, lease_expires_at_seconds = NULL "
        "WHERE id = ?1 AND lease_owner = ?2 AND lease_token = ?3 "
        "AND dirty = 1;";
    statement = nullptr;
    if (::sqlite3_prepare_v2(impl_->database.get(), kRetainDirty, -1,
                             &statement, nullptr) != SQLITE_OK ||
        ::sqlite3_bind_int64(statement, 1, outbox_id) != SQLITE_OK ||
        ::sqlite3_bind_blob(statement, 2, lease_owner.data(),
                            static_cast<int>(lease_owner.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_blob(statement, 3, lease_token.data(),
                            static_cast<int>(lease_token.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_step(statement) != SQLITE_DONE) {
      if (statement != nullptr) {
        (void)::sqlite3_finalize(statement);
      }
      return rollback_failure();
    }
    if (::sqlite3_finalize(statement) != SQLITE_OK) {
      return rollback_failure();
    }
  }
  auto committed = transaction.Commit();
  if (!committed.ok()) {
    return rollback_failure();
  }
  return common::Result<void>::Ok();
}

common::Result<void> SecurityStore::ReleaseFirmwareLogOutbox(
    std::int64_t outbox_id,
    std::span<const unsigned char> lease_owner,
    std::span<const unsigned char> lease_token) {
  auto started = BeginTransaction();
  if (!started.ok()) {
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  auto transaction = std::move(started).value();
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kRelease =
      "UPDATE firmware_log_outbox SET lease_owner = NULL, lease_token = NULL, "
      "lease_expires_at_seconds = NULL WHERE id = ?1 AND lease_owner = ?2 "
      "AND lease_token = ?3;";
  const bool prepared =
      ::sqlite3_prepare_v2(impl_->database.get(), kRelease, -1, &statement,
                           nullptr) == SQLITE_OK;
  const bool executed =
      prepared && ::sqlite3_bind_int64(statement, 1, outbox_id) == SQLITE_OK &&
      ::sqlite3_bind_blob(statement, 2, lease_owner.data(),
                          static_cast<int>(lease_owner.size()),
                          SQLITE_TRANSIENT) == SQLITE_OK &&
      ::sqlite3_bind_blob(statement, 3, lease_token.data(),
                          static_cast<int>(lease_token.size()),
                          SQLITE_TRANSIENT) == SQLITE_OK &&
      ::sqlite3_step(statement) == SQLITE_DONE;
  const bool finalized =
      statement == nullptr || ::sqlite3_finalize(statement) == SQLITE_OK;
  if (!executed || !finalized) {
    if (transaction.active()) {
      (void)transaction.Rollback();
    }
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  auto committed = transaction.Commit();
  if (!committed.ok()) {
    if (transaction.active()) {
      (void)transaction.Rollback();
    }
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  return common::Result<void>::Ok();
}

common::Result<std::vector<SessionIdentity>>
SecurityStore::DeleteExpiredSessions(
    Transaction& transaction,
    std::int64_t now_seconds) {
  const auto failure = [] {
    return StoreError<std::vector<SessionIdentity>>(
        "E_AUTHENTICATION_STORE", "authentication transaction failed");
  };
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return failure();
  }
  struct ExpiredSession {
    std::int64_t user_id;
    std::string peer_ip;
  };
  std::vector<ExpiredSession> expired;
  std::vector<SessionIdentity> identities;
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kRead =
      "SELECT token_hash, user_id, peer_ip FROM sessions "
      "WHERE expires_at_seconds <= ?1 ORDER BY id;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kRead, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 1, now_seconds) != SQLITE_OK) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return failure();
  }
  int step;
  while ((step = ::sqlite3_step(statement)) == SQLITE_ROW) {
    const auto* token_hash = static_cast<const unsigned char*>(
        ::sqlite3_column_blob(statement, 0));
    const int token_hash_size = ::sqlite3_column_bytes(statement, 0);
    const auto* peer = ::sqlite3_column_text(statement, 2);
    if (token_hash == nullptr ||
        token_hash_size != static_cast<int>(kSessionIdentityBytes) ||
        peer == nullptr) {
      (void)::sqlite3_finalize(statement);
      return failure();
    }
    expired.push_back({::sqlite3_column_int64(statement, 1),
                       reinterpret_cast<const char*>(peer)});
    SessionIdentity identity;
    std::copy_n(token_hash, kSessionIdentityBytes, identity.bytes.begin());
    identities.emplace_back(std::move(identity));
  }
  if (step != SQLITE_DONE || ::sqlite3_finalize(statement) != SQLITE_OK) {
    return failure();
  }

  sqlite3_stmt* remove = nullptr;
  constexpr const char* kDelete =
      "DELETE FROM sessions WHERE expires_at_seconds <= ?1;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kDelete, -1, &remove,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_int64(remove, 1, now_seconds) != SQLITE_OK ||
      ::sqlite3_step(remove) != SQLITE_DONE) {
    if (remove != nullptr) {
      (void)::sqlite3_finalize(remove);
    }
    return failure();
  }
  if (::sqlite3_finalize(remove) != SQLITE_OK) {
    return failure();
  }
  for (const auto& session : expired) {
    auto audit = InsertAuditEvent(
        transaction, now_seconds, "session_expired", "success",
        session.user_id, session.peer_ip, "idle_timeout");
    if (!audit.ok()) {
      return failure();
    }
  }
  return common::Result<std::vector<SessionIdentity>>::Ok(
      std::move(identities));
}

common::Result<std::optional<std::int64_t>>
SecurityStore::ReadNextSessionExpiry(Transaction& transaction) const {
  const auto failure = [] {
    return StoreError<std::optional<std::int64_t>>(
        "E_AUTHENTICATION_STORE", "authentication transaction failed");
  };
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return failure();
  }
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kRead =
      "SELECT MIN(expires_at_seconds) FROM sessions;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kRead, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_ROW) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return failure();
  }
  std::optional<std::int64_t> next_expiry;
  if (::sqlite3_column_type(statement, 0) != SQLITE_NULL) {
    if (::sqlite3_column_type(statement, 0) != SQLITE_INTEGER) {
      (void)::sqlite3_finalize(statement);
      return failure();
    }
    next_expiry = ::sqlite3_column_int64(statement, 0);
  }
  if (::sqlite3_step(statement) != SQLITE_DONE ||
      ::sqlite3_finalize(statement) != SQLITE_OK) {
    return failure();
  }
  return common::Result<std::optional<std::int64_t>>::Ok(next_expiry);
}

common::Result<std::optional<SecurityStore::StoredSession>>
SecurityStore::ReadSessionByUserId(Transaction& transaction,
                                   std::int64_t user_id) const {
  const auto failure = [] {
    return StoreError<std::optional<StoredSession>>(
        "E_AUTHENTICATION_STORE", "authentication transaction failed");
  };
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return failure();
  }
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "SELECT sessions.id, sessions.token_hash, sessions.user_id, "
      "users.display_username, sessions.role, sessions.created_at_seconds, "
      "sessions.last_activity_at_seconds, sessions.expires_at_seconds, "
      "sessions.peer_ip FROM sessions JOIN users ON users.id = "
      "sessions.user_id WHERE sessions.user_id = ?1;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kSql, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 1, user_id) != SQLITE_OK) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return failure();
  }
  const int step = ::sqlite3_step(statement);
  if (step == SQLITE_DONE) {
    (void)::sqlite3_finalize(statement);
    return common::Result<std::optional<StoredSession>>::Ok(std::nullopt);
  }
  if (step != SQLITE_ROW) {
    (void)::sqlite3_finalize(statement);
    return failure();
  }
  const auto* token_hash = static_cast<const unsigned char*>(
      ::sqlite3_column_blob(statement, 1));
  const int token_hash_size = ::sqlite3_column_bytes(statement, 1);
  const auto* username = ::sqlite3_column_text(statement, 3);
  const auto* role = ::sqlite3_column_text(statement, 4);
  const auto* peer = ::sqlite3_column_text(statement, 8);
  if (token_hash == nullptr || token_hash_size < 0 || username == nullptr ||
      role == nullptr || peer == nullptr) {
    (void)::sqlite3_finalize(statement);
    return failure();
  }
  StoredSession session;
  session.id = ::sqlite3_column_int64(statement, 0);
  session.token_hash.assign(token_hash,
                            static_cast<std::size_t>(token_hash_size));
  session.user_id = ::sqlite3_column_int64(statement, 2);
  session.username = reinterpret_cast<const char*>(username);
  session.role = reinterpret_cast<const char*>(role);
  session.created_at_seconds = ::sqlite3_column_int64(statement, 5);
  session.last_activity_at_seconds = ::sqlite3_column_int64(statement, 6);
  session.expires_at_seconds = ::sqlite3_column_int64(statement, 7);
  session.peer_ip = reinterpret_cast<const char*>(peer);
  if (::sqlite3_step(statement) != SQLITE_DONE ||
      ::sqlite3_finalize(statement) != SQLITE_OK) {
    return failure();
  }
  return common::Result<std::optional<StoredSession>>::Ok(
      std::optional<StoredSession>(std::move(session)));
}

common::Result<std::optional<SecurityStore::StoredSession>>
SecurityStore::ReadSessionByTokenHash(
    Transaction& transaction,
    std::span<const unsigned char> token_hash,
    std::string_view normalized_peer_ip,
    std::int64_t now_seconds) const {
  const auto failure = [] {
    return StoreError<std::optional<StoredSession>>(
        "E_AUTHENTICATION_STORE", "authentication transaction failed");
  };
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return failure();
  }
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "SELECT sessions.id, sessions.token_hash, sessions.user_id, "
      "users.display_username, sessions.role, sessions.created_at_seconds, "
      "sessions.last_activity_at_seconds, sessions.expires_at_seconds, "
      "sessions.peer_ip FROM sessions JOIN users ON users.id = "
      "sessions.user_id JOIN management_ips ON "
      "management_ips.normalized_ip = ?2 AND "
      "management_ips.role_scope = sessions.role AND "
      "management_ips.enabled = 1 WHERE sessions.token_hash = ?1 AND "
      "sessions.peer_ip = ?2 AND sessions.expires_at_seconds > ?3 AND "
      "users.enabled = 1 AND users.role = sessions.role;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kSql, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_blob(statement, 1, token_hash.data(),
                          static_cast<int>(token_hash.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 2, normalized_peer_ip.data(),
                          static_cast<int>(normalized_peer_ip.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 3, now_seconds) != SQLITE_OK) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return failure();
  }
  const int step = ::sqlite3_step(statement);
  if (step == SQLITE_DONE) {
    (void)::sqlite3_finalize(statement);
    return common::Result<std::optional<StoredSession>>::Ok(std::nullopt);
  }
  if (step != SQLITE_ROW) {
    (void)::sqlite3_finalize(statement);
    return failure();
  }
  const auto* stored_hash = static_cast<const unsigned char*>(
      ::sqlite3_column_blob(statement, 1));
  const int stored_hash_size = ::sqlite3_column_bytes(statement, 1);
  const auto* username = ::sqlite3_column_text(statement, 3);
  const auto* role = ::sqlite3_column_text(statement, 4);
  const auto* peer = ::sqlite3_column_text(statement, 8);
  if (stored_hash == nullptr || stored_hash_size < 0 || username == nullptr ||
      role == nullptr || peer == nullptr) {
    (void)::sqlite3_finalize(statement);
    return failure();
  }
  StoredSession session;
  session.id = ::sqlite3_column_int64(statement, 0);
  session.token_hash.assign(stored_hash,
                            static_cast<std::size_t>(stored_hash_size));
  session.user_id = ::sqlite3_column_int64(statement, 2);
  session.username = reinterpret_cast<const char*>(username);
  session.role = reinterpret_cast<const char*>(role);
  session.created_at_seconds = ::sqlite3_column_int64(statement, 5);
  session.last_activity_at_seconds = ::sqlite3_column_int64(statement, 6);
  session.expires_at_seconds = ::sqlite3_column_int64(statement, 7);
  session.peer_ip = reinterpret_cast<const char*>(peer);
  if (::sqlite3_step(statement) != SQLITE_DONE ||
      ::sqlite3_finalize(statement) != SQLITE_OK) {
    return failure();
  }
  return common::Result<std::optional<StoredSession>>::Ok(
      std::optional<StoredSession>(std::move(session)));
}

common::Result<bool> SecurityStore::SessionTokenHashExists(
    Transaction& transaction,
    std::span<const unsigned char> token_hash) const {
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return StoreError<bool>("E_AUTHENTICATION_STORE",
                            "authentication transaction failed");
  }
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash = ?1);";
  if (::sqlite3_prepare_v2(impl_->database.get(), kSql, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_blob(statement, 1, token_hash.data(),
                          static_cast<int>(token_hash.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_ROW) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return StoreError<bool>("E_AUTHENTICATION_STORE",
                            "authentication transaction failed");
  }
  const bool exists = ::sqlite3_column_int(statement, 0) == 1;
  if (::sqlite3_step(statement) != SQLITE_DONE ||
      ::sqlite3_finalize(statement) != SQLITE_OK) {
    return StoreError<bool>("E_AUTHENTICATION_STORE",
                            "authentication transaction failed");
  }
  return common::Result<bool>::Ok(exists);
}

common::Result<void> SecurityStore::InsertSession(
    Transaction& transaction,
    std::span<const unsigned char> token_hash,
    std::int64_t user_id,
    std::string_view role,
    std::int64_t now_seconds,
    std::int64_t expires_at_seconds,
    std::string_view normalized_peer_ip) {
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "INSERT INTO sessions "
      "(token_hash, user_id, role, created_at_seconds, "
      "last_activity_at_seconds, expires_at_seconds, peer_ip) "
      "VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6);";
  if (::sqlite3_prepare_v2(impl_->database.get(), kSql, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_blob(statement, 1, token_hash.data(),
                          static_cast<int>(token_hash.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 2, user_id) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 3, role.data(),
                          static_cast<int>(role.size()), SQLITE_TRANSIENT) !=
          SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 4, now_seconds) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 5, expires_at_seconds) != SQLITE_OK ||
      ::sqlite3_bind_text(statement, 6, normalized_peer_ip.data(),
                          static_cast<int>(normalized_peer_ip.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_DONE) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  const bool finalized = ::sqlite3_finalize(statement) == SQLITE_OK;
  return finalized
             ? common::Result<void>::Ok()
             : StoreError("E_AUTHENTICATION_STORE",
                          "authentication transaction failed");
}

common::Result<void> SecurityStore::RefreshSession(
    Transaction& transaction,
    std::int64_t session_id,
    std::int64_t now_seconds,
    std::int64_t expires_at_seconds) {
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "UPDATE sessions SET last_activity_at_seconds = ?1, "
      "expires_at_seconds = ?2 WHERE id = ?3;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kSql, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 1, now_seconds) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 2, expires_at_seconds) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 3, session_id) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_DONE ||
      ::sqlite3_changes(impl_->database.get()) != 1) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  const bool finalized = ::sqlite3_finalize(statement) == SQLITE_OK;
  return finalized
             ? common::Result<void>::Ok()
             : StoreError("E_AUTHENTICATION_STORE",
                          "authentication transaction failed");
}

common::Result<void> SecurityStore::DeleteSession(Transaction& transaction,
                                                   std::int64_t session_id) {
  if (!transaction.active_ || transaction.impl_ != impl_ ||
      impl_->database == nullptr) {
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql = "DELETE FROM sessions WHERE id = ?1;";
  if (::sqlite3_prepare_v2(impl_->database.get(), kSql, -1, &statement,
                           nullptr) != SQLITE_OK ||
      ::sqlite3_bind_int64(statement, 1, session_id) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_DONE ||
      ::sqlite3_changes(impl_->database.get()) != 1) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    return StoreError("E_AUTHENTICATION_STORE",
                      "authentication transaction failed");
  }
  const bool finalized = ::sqlite3_finalize(statement) == SQLITE_OK;
  return finalized
             ? common::Result<void>::Ok()
             : StoreError("E_AUTHENTICATION_STORE",
                          "authentication transaction failed");
}

common::Result<std::vector<StoredManagedUser>>
SecurityStore::ReadManagedUsers() const {
  auto started = BeginReadTransaction();
  if (!started.ok()) {
    return StoreError<std::vector<StoredManagedUser>>(
        "E_USER_MANAGEMENT_STORE", "failed to read managed users");
  }
  auto transaction = std::move(started).value();
  try {
    PreparedStatement statement(
        impl_->database.get(),
        "SELECT id, canonical_username, display_username, role, enabled, "
        "lock_until_seconds, created_at_seconds, "
        "password_changed_at_seconds, last_login_at_seconds FROM users "
        "ORDER BY id;");
    if (!statement.valid()) {
      return UserMutationUnavailable<std::vector<StoredManagedUser>>(
          transaction);
    }
    std::vector<StoredManagedUser> users;
    int step = SQLITE_ROW;
    while ((step = ::sqlite3_step(statement.get())) == SQLITE_ROW) {
      const auto* canonical = ::sqlite3_column_text(statement.get(), 1);
      const auto* display = ::sqlite3_column_text(statement.get(), 2);
      const auto role = ReadUserRole(statement.get(), 3);
      if (canonical == nullptr || display == nullptr || !role.has_value()) {
        return UserMutationUnavailable<std::vector<StoredManagedUser>>(
            transaction);
      }
      StoredManagedUser user;
      user.id = ::sqlite3_column_int64(statement.get(), 0);
      user.canonical_username = reinterpret_cast<const char*>(canonical);
      user.display_username = reinterpret_cast<const char*>(display);
      user.role = *role;
      user.enabled = ::sqlite3_column_int(statement.get(), 4) == 1;
      if (::sqlite3_column_type(statement.get(), 5) != SQLITE_NULL) {
        user.lock_until_seconds =
            ::sqlite3_column_int64(statement.get(), 5);
      }
      user.created_at_seconds = ::sqlite3_column_int64(statement.get(), 6);
      user.password_changed_at_seconds =
          ::sqlite3_column_int64(statement.get(), 7);
      if (::sqlite3_column_type(statement.get(), 8) != SQLITE_NULL) {
        user.last_login_at_seconds =
            ::sqlite3_column_int64(statement.get(), 8);
      }
      users.emplace_back(std::move(user));
    }
    if (step != SQLITE_DONE) {
      return UserMutationUnavailable<std::vector<StoredManagedUser>>(
          transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<std::vector<StoredManagedUser>>(
          transaction);
    }
    return common::Result<std::vector<StoredManagedUser>>::Ok(
        std::move(users));
  } catch (...) {
    return UserMutationUnavailable<std::vector<StoredManagedUser>>(
        transaction);
  }
}

common::Result<StoredManagedUser> SecurityStore::InsertViewer(
    std::string canonical_username,
    std::string display_username,
    PasswordRecord password,
    std::int64_t now_seconds,
    const SecurityMutationContext& context) {
  auto started = BeginTransaction();
  if (!started.ok()) {
    return StoreError<StoredManagedUser>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  auto transaction = std::move(started).value();
  const auto reject = [&](std::string code, std::string detail) {
    auto audited = InsertAuditEvent(
        transaction, now_seconds, "viewer_created", "failure",
        context.actor_user_id, context.normalized_peer_ip, detail, "user",
        canonical_username);
    if (!audited.ok()) {
      return UserMutationUnavailable<StoredManagedUser>(transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<StoredManagedUser>(transaction);
    }
    return StoreError<StoredManagedUser>(std::move(code),
                                         "viewer creation was rejected");
  };
  try {
    PreparedStatement checks(
        impl_->database.get(),
        "SELECT EXISTS(SELECT 1 FROM users WHERE canonical_username = ?1 "
        "COLLATE NOCASE), (SELECT COUNT(*) FROM users WHERE role = 'viewer');");
    if (!checks.valid() ||
        ::sqlite3_bind_text(checks.get(), 1, canonical_username.data(),
                            static_cast<int>(canonical_username.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_step(checks.get()) != SQLITE_ROW) {
      return UserMutationUnavailable<StoredManagedUser>(transaction);
    }
    if (::sqlite3_column_int(checks.get(), 0) != 0) {
      return reject("E_USER_DUPLICATE", "duplicate_username");
    }
    if (::sqlite3_column_int64(checks.get(), 1) >=
        static_cast<sqlite3_int64>(kMaximumViewerUsers)) {
      return reject("E_VIEWER_LIMIT", "viewer_limit");
    }

    PreparedStatement insert(
        impl_->database.get(),
        "INSERT INTO users (canonical_username, display_username, role, "
        "enabled, password_algorithm, password_iterations, password_salt, "
        "password_derived, password_changed_at_seconds, failed_login_count, "
        "created_at_seconds) VALUES (?1, ?2, 'viewer', 1, ?3, ?4, ?5, ?6, "
        "?7, 0, ?7);");
    if (!insert.valid() ||
        ::sqlite3_bind_text(insert.get(), 1, canonical_username.data(),
                            static_cast<int>(canonical_username.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_text(insert.get(), 2, display_username.data(),
                            static_cast<int>(display_username.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        !BindPasswordRecord(insert.get(), 3, password) ||
        ::sqlite3_bind_int64(insert.get(), 7, now_seconds) != SQLITE_OK ||
        ::sqlite3_step(insert.get()) != SQLITE_DONE) {
      return UserMutationUnavailable<StoredManagedUser>(transaction);
    }
    const std::int64_t user_id =
        ::sqlite3_last_insert_rowid(impl_->database.get());
    auto audited = InsertAuditEvent(
        transaction, now_seconds, "viewer_created", "success",
        context.actor_user_id, context.normalized_peer_ip, "created", "user",
        canonical_username);
    if (!audited.ok()) {
      return UserMutationUnavailable<StoredManagedUser>(transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<StoredManagedUser>(transaction);
    }
    StoredManagedUser user;
    user.id = user_id;
    user.canonical_username = std::move(canonical_username);
    user.display_username = std::move(display_username);
    user.role = UserRole::kViewer;
    user.enabled = true;
    user.created_at_seconds = now_seconds;
    user.password_changed_at_seconds = now_seconds;
    return common::Result<StoredManagedUser>::Ok(std::move(user));
  } catch (...) {
    return UserMutationUnavailable<StoredManagedUser>(transaction);
  }
}

common::Result<CommittedRevocation> SecurityStore::SetViewerEnabled(
    std::int64_t user_id,
    bool enabled,
    std::int64_t now_seconds,
    const SecurityMutationContext& context) {
  auto started = BeginTransaction();
  if (!started.ok()) {
    return StoreError<CommittedRevocation>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  auto transaction = std::move(started).value();
  try {
    PreparedStatement read(
        impl_->database.get(),
        "SELECT canonical_username, role FROM users WHERE id = ?1;");
    if (!read.valid() ||
        ::sqlite3_bind_int64(read.get(), 1, user_id) != SQLITE_OK) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    const int row = ::sqlite3_step(read.get());
    std::string subject = std::to_string(user_id);
    std::optional<UserRole> role;
    if (row == SQLITE_ROW) {
      const auto* canonical = ::sqlite3_column_text(read.get(), 0);
      role = ReadUserRole(read.get(), 1);
      if (canonical == nullptr || !role.has_value()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      subject = reinterpret_cast<const char*>(canonical);
    } else if (row != SQLITE_DONE) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    const std::string_view event = enabled ? "viewer_enabled" : "viewer_disabled";
    const auto reject = [&](std::string code, std::string detail) {
      auto audited = InsertAuditEvent(
          transaction, now_seconds, event, "failure", context.actor_user_id,
          context.normalized_peer_ip, detail, "user", subject);
      if (!audited.ok()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      return StoreError<CommittedRevocation>(std::move(code),
                                               "viewer update was rejected");
    };
    if (!role.has_value()) {
      return reject("E_USER_NOT_FOUND", "user_not_found");
    }
    if (*role != UserRole::kViewer) {
      return reject("E_USER_PROTECTED", "protected_administrator");
    }

    PreparedStatement update(impl_->database.get(),
                             "UPDATE users SET enabled = ?1 WHERE id = ?2 "
                             "AND role = 'viewer';");
    if (!update.valid() ||
        ::sqlite3_bind_int(update.get(), 1, enabled ? 1 : 0) != SQLITE_OK ||
        ::sqlite3_bind_int64(update.get(), 2, user_id) != SQLITE_OK ||
        ::sqlite3_step(update.get()) != SQLITE_DONE ||
        ::sqlite3_changes(impl_->database.get()) != 1) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    std::vector<SessionIdentity> identities;
    if (!enabled) {
      auto collected = ReadSessionIdentities(impl_->database.get(), user_id);
      if (!collected.ok() ||
          !DeleteSessionsForUser(impl_->database.get(), user_id)) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      identities = std::move(collected).value();
    }
    auto audited = InsertAuditEvent(
        transaction, now_seconds, event, "success", context.actor_user_id,
        context.normalized_peer_ip, enabled ? "enabled" : "disabled", "user",
        subject);
    if (!audited.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    return common::Result<CommittedRevocation>::Ok(
        {std::move(identities)});
  } catch (...) {
    return UserMutationUnavailable<CommittedRevocation>(transaction);
  }
}

common::Result<PasswordMutationSnapshot>
SecurityStore::ReadPasswordMutationSnapshot(std::int64_t user_id) const {
  auto started = BeginReadTransaction();
  if (!started.ok()) {
    return StoreError<PasswordMutationSnapshot>(
        "E_USER_MANAGEMENT_STORE", "failed to read password state");
  }
  auto transaction = std::move(started).value();
  try {
    PreparedStatement read(
        impl_->database.get(),
        "SELECT users.id, users.canonical_username, "
        "users.password_algorithm, users.password_iterations, "
        "users.password_salt, users.password_derived, "
        "users.password_changed_at_seconds, history.password_algorithm, "
        "history.password_iterations, history.password_salt, "
        "history.password_derived FROM users LEFT JOIN password_history AS "
        "history ON history.user_id = users.id WHERE users.id = ?1;");
    if (!read.valid() ||
        ::sqlite3_bind_int64(read.get(), 1, user_id) != SQLITE_OK) {
      return UserMutationUnavailable<PasswordMutationSnapshot>(transaction);
    }
    const int row = ::sqlite3_step(read.get());
    if (row == SQLITE_DONE) {
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return UserMutationUnavailable<PasswordMutationSnapshot>(transaction);
      }
      return StoreError<PasswordMutationSnapshot>("E_USER_NOT_FOUND",
                                                   "user was not found");
    }
    const auto* canonical = ::sqlite3_column_text(read.get(), 1);
    if (row != SQLITE_ROW || canonical == nullptr) {
      return UserMutationUnavailable<PasswordMutationSnapshot>(transaction);
    }
    auto current = ReadPasswordRecord(read.get(), 2);
    if (!current.ok()) {
      return UserMutationUnavailable<PasswordMutationSnapshot>(transaction);
    }
    PasswordMutationSnapshot snapshot;
    snapshot.user_id = ::sqlite3_column_int64(read.get(), 0);
    snapshot.canonical_username = reinterpret_cast<const char*>(canonical);
    snapshot.current = std::move(current).value();
    snapshot.password_changed_at_seconds =
        ::sqlite3_column_int64(read.get(), 6);
    if (::sqlite3_column_type(read.get(), 7) != SQLITE_NULL) {
      auto previous = ReadPasswordRecord(read.get(), 7);
      if (!previous.ok()) {
        return UserMutationUnavailable<PasswordMutationSnapshot>(transaction);
      }
      snapshot.previous.emplace(std::move(previous).value());
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<PasswordMutationSnapshot>(transaction);
    }
    return common::Result<PasswordMutationSnapshot>::Ok(std::move(snapshot));
  } catch (...) {
    return UserMutationUnavailable<PasswordMutationSnapshot>(transaction);
  }
}

common::Result<CommittedRevocation>
SecurityStore::ReplacePasswordIfCurrent(
    const PasswordMutationSnapshot& expected,
    PasswordRecord replacement,
    PasswordMutationKind kind,
    std::int64_t now_seconds,
    const SecurityMutationContext& context) {
  auto started = BeginTransaction();
  if (!started.ok()) {
    return StoreError<CommittedRevocation>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  auto transaction = std::move(started).value();
  const std::string_view event =
      kind == PasswordMutationKind::kAdministratorReset
          ? "viewer_password_reset"
          : "password_changed";
  const auto reject = [&](std::string code, std::string detail) {
    auto audited = InsertAuditEvent(
        transaction, now_seconds, event, "failure", context.actor_user_id,
        context.normalized_peer_ip, detail, "user",
        expected.canonical_username);
    if (!audited.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    return StoreError<CommittedRevocation>(std::move(code),
                                             "password update was rejected");
  };
  try {
    PreparedStatement target(
        impl_->database.get(),
        "SELECT canonical_username, role FROM users WHERE id = ?1;");
    if (!target.valid() ||
        ::sqlite3_bind_int64(target.get(), 1, expected.user_id) != SQLITE_OK) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    const int target_row = ::sqlite3_step(target.get());
    if (target_row != SQLITE_ROW) {
      if (target_row == SQLITE_DONE) {
        return reject("E_USER_CONFLICT", "optimistic_conflict");
      }
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    const auto* current_canonical = ::sqlite3_column_text(target.get(), 0);
    const auto role = ReadUserRole(target.get(), 1);
    if (current_canonical == nullptr || !role.has_value()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    if (kind == PasswordMutationKind::kAdministratorReset &&
        *role != UserRole::kViewer) {
      return reject("E_USER_PROTECTED", "protected_administrator");
    }
    if ((kind == PasswordMutationKind::kSelfChange &&
         (context.actor_user_id != expected.user_id ||
          context.actor_role != *role)) ||
        expected.canonical_username !=
            reinterpret_cast<const char*>(current_canonical)) {
      return reject("E_USER_CONFLICT", "optimistic_conflict");
    }

    bool history_matches = false;
    {
      PreparedStatement history_check(
          impl_->database.get(),
          "SELECT password_algorithm, password_iterations, password_salt, "
          "password_derived FROM password_history WHERE user_id = ?1;");
      if (!history_check.valid() ||
          ::sqlite3_bind_int64(history_check.get(), 1, expected.user_id) !=
              SQLITE_OK) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      const int history_row = ::sqlite3_step(history_check.get());
      if (history_row == SQLITE_DONE) {
        history_matches = !expected.previous.has_value();
      } else if (history_row == SQLITE_ROW) {
        auto actual_previous = ReadPasswordRecord(history_check.get(), 0);
        if (!actual_previous.ok()) {
          return UserMutationUnavailable<CommittedRevocation>(transaction);
        }
        history_matches =
            expected.previous.has_value() &&
            SamePasswordRecord(*expected.previous, actual_previous.value());
      } else {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
    }
    if (!history_matches) {
      return reject("E_USER_CONFLICT", "optimistic_conflict");
    }

    PreparedStatement update(
        impl_->database.get(),
        "UPDATE users SET password_algorithm = ?1, password_iterations = ?2, "
        "password_salt = ?3, password_derived = ?4, "
        "password_changed_at_seconds = ?5, failed_login_count = 0, "
        "lock_until_seconds = NULL WHERE id = ?6 AND canonical_username = ?7 "
        "AND password_algorithm = ?8 AND password_iterations = ?9 AND "
        "password_salt = ?10 AND password_derived = ?11 AND "
        "password_changed_at_seconds = ?12;");
    if (!update.valid() || !BindPasswordRecord(update.get(), 1, replacement) ||
        ::sqlite3_bind_int64(update.get(), 5, now_seconds) != SQLITE_OK ||
        ::sqlite3_bind_int64(update.get(), 6, expected.user_id) != SQLITE_OK ||
        ::sqlite3_bind_text(update.get(), 7, expected.canonical_username.data(),
                            static_cast<int>(expected.canonical_username.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        !BindPasswordRecord(update.get(), 8, expected.current) ||
        ::sqlite3_bind_int64(update.get(), 12,
                             expected.password_changed_at_seconds) != SQLITE_OK ||
        ::sqlite3_step(update.get()) != SQLITE_DONE) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    if (::sqlite3_changes(impl_->database.get()) != 1) {
      return reject("E_USER_CONFLICT", "optimistic_conflict");
    }

    PreparedStatement history(
        impl_->database.get(),
        "INSERT INTO password_history (user_id, password_algorithm, "
        "password_iterations, password_salt, password_derived, "
        "replaced_at_seconds) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT "
        "(user_id) DO UPDATE SET password_algorithm = excluded.password_algorithm, "
        "password_iterations = excluded.password_iterations, password_salt = "
        "excluded.password_salt, password_derived = excluded.password_derived, "
        "replaced_at_seconds = excluded.replaced_at_seconds;");
    if (!history.valid() ||
        ::sqlite3_bind_int64(history.get(), 1, expected.user_id) != SQLITE_OK ||
        !BindPasswordRecord(history.get(), 2, expected.current) ||
        ::sqlite3_bind_int64(history.get(), 6, now_seconds) != SQLITE_OK ||
        ::sqlite3_step(history.get()) != SQLITE_DONE) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    auto collected =
        ReadSessionIdentities(impl_->database.get(), expected.user_id);
    if (!collected.ok() ||
        !DeleteSessionsForUser(impl_->database.get(), expected.user_id)) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    auto audited = InsertAuditEvent(
        transaction, now_seconds, event, "success", context.actor_user_id,
        context.normalized_peer_ip,
        kind == PasswordMutationKind::kAdministratorReset ? "password_reset"
                                                           : "password_changed",
        "user", expected.canonical_username);
    if (!audited.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    return common::Result<CommittedRevocation>::Ok(
        {std::move(collected).value()});
  } catch (...) {
    return UserMutationUnavailable<CommittedRevocation>(transaction);
  }
}

common::Result<CommittedRevocation> SecurityStore::DeleteViewer(
    std::int64_t user_id,
    std::int64_t now_seconds,
    const SecurityMutationContext& context) {
  auto started = BeginTransaction();
  if (!started.ok()) {
    return StoreError<CommittedRevocation>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  auto transaction = std::move(started).value();
  try {
    PreparedStatement read(
        impl_->database.get(),
        "SELECT canonical_username, role FROM users WHERE id = ?1;");
    if (!read.valid() ||
        ::sqlite3_bind_int64(read.get(), 1, user_id) != SQLITE_OK) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    const int row = ::sqlite3_step(read.get());
    std::string subject = std::to_string(user_id);
    std::optional<UserRole> role;
    if (row == SQLITE_ROW) {
      const auto* canonical = ::sqlite3_column_text(read.get(), 0);
      role = ReadUserRole(read.get(), 1);
      if (canonical == nullptr || !role.has_value()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      subject = reinterpret_cast<const char*>(canonical);
    } else if (row != SQLITE_DONE) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    const auto reject = [&](std::string code, std::string detail) {
      auto audited = InsertAuditEvent(
          transaction, now_seconds, "viewer_deleted", "failure",
          context.actor_user_id, context.normalized_peer_ip, detail, "user",
          subject);
      if (!audited.ok()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      return StoreError<CommittedRevocation>(std::move(code),
                                               "viewer deletion was rejected");
    };
    if (!role.has_value()) {
      return reject("E_USER_NOT_FOUND", "user_not_found");
    }
    if (*role != UserRole::kViewer) {
      return reject("E_USER_PROTECTED", "protected_administrator");
    }
    auto collected = ReadSessionIdentities(impl_->database.get(), user_id);
    if (!collected.ok() ||
        !DeleteSessionsForUser(impl_->database.get(), user_id)) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    PreparedStatement remove(
        impl_->database.get(),
        "DELETE FROM users WHERE id = ?1 AND role = 'viewer';");
    if (!remove.valid() ||
        ::sqlite3_bind_int64(remove.get(), 1, user_id) != SQLITE_OK ||
        ::sqlite3_step(remove.get()) != SQLITE_DONE ||
        ::sqlite3_changes(impl_->database.get()) != 1) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    auto audited = InsertAuditEvent(
        transaction, now_seconds, "viewer_deleted", "success",
        context.actor_user_id, context.normalized_peer_ip, "deleted", "user",
        subject);
    if (!audited.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    return common::Result<CommittedRevocation>::Ok(
        {std::move(collected).value()});
  } catch (...) {
    return UserMutationUnavailable<CommittedRevocation>(transaction);
  }
}

common::Result<std::vector<StoredManagementIp>>
SecurityStore::ReadManagementIps() const {
  auto started = BeginReadTransaction();
  if (!started.ok()) {
    return StoreError<std::vector<StoredManagementIp>>(
        "E_USER_MANAGEMENT_STORE", "failed to read management IPs");
  }
  auto transaction = std::move(started).value();
  try {
    PreparedStatement statement(
        impl_->database.get(),
        "SELECT id, normalized_ip, role_scope, created_at_seconds FROM "
        "management_ips ORDER BY id;");
    if (!statement.valid()) {
      return UserMutationUnavailable<std::vector<StoredManagementIp>>(
          transaction);
    }
    std::vector<StoredManagementIp> entries;
    int step = SQLITE_ROW;
    while ((step = ::sqlite3_step(statement.get())) == SQLITE_ROW) {
      const auto* normalized_ip = ::sqlite3_column_text(statement.get(), 1);
      const auto role = ReadUserRole(statement.get(), 2);
      if (normalized_ip == nullptr || !role.has_value()) {
        return UserMutationUnavailable<std::vector<StoredManagementIp>>(
            transaction);
      }
      entries.push_back(
          {::sqlite3_column_int64(statement.get(), 0),
           reinterpret_cast<const char*>(normalized_ip), *role,
           ::sqlite3_column_int64(statement.get(), 3)});
    }
    if (step != SQLITE_DONE) {
      return UserMutationUnavailable<std::vector<StoredManagementIp>>(
          transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<std::vector<StoredManagementIp>>(
          transaction);
    }
    return common::Result<std::vector<StoredManagementIp>>::Ok(
        std::move(entries));
  } catch (...) {
    return UserMutationUnavailable<std::vector<StoredManagementIp>>(
        transaction);
  }
}

common::Result<StoredManagementIp> SecurityStore::InsertManagementIp(
    UserRole role,
    std::string normalized_ip,
    std::int64_t now_seconds,
    const SecurityMutationContext& context) {
  auto started = BeginTransaction();
  if (!started.ok()) {
    return StoreError<StoredManagementIp>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  auto transaction = std::move(started).value();
  const auto reject = [&](std::string code, std::string detail) {
    auto audited = InsertAuditEvent(
        transaction, now_seconds, "management_ip_created", "failure",
        context.actor_user_id, context.normalized_peer_ip, detail,
        "management_ip", normalized_ip);
    if (!audited.ok()) {
      return UserMutationUnavailable<StoredManagementIp>(transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<StoredManagementIp>(transaction);
    }
    return StoreError<StoredManagementIp>(std::move(code),
                                          "management IP creation was rejected");
  };
  try {
    if (context.actor_role != UserRole::kAdministrator) {
      return reject("E_MANAGEMENT_IP_FORBIDDEN", "role_forbidden");
    }
    const std::string_view role_text = RoleText(role);
    sqlite3_int64 count = 0;
    bool duplicate = false;
    {
      PreparedStatement checks(
          impl_->database.get(),
          "SELECT (SELECT COUNT(*) FROM management_ips WHERE role_scope = ?1), "
          "EXISTS(SELECT 1 FROM management_ips WHERE role_scope = ?1 AND "
          "normalized_ip = ?2);");
      if (!checks.valid() ||
          ::sqlite3_bind_text(checks.get(), 1, role_text.data(),
                              static_cast<int>(role_text.size()),
                              SQLITE_TRANSIENT) != SQLITE_OK ||
          ::sqlite3_bind_text(checks.get(), 2, normalized_ip.data(),
                              static_cast<int>(normalized_ip.size()),
                              SQLITE_TRANSIENT) != SQLITE_OK ||
          ::sqlite3_step(checks.get()) != SQLITE_ROW) {
        return UserMutationUnavailable<StoredManagementIp>(transaction);
      }
      count = ::sqlite3_column_int64(checks.get(), 0);
      duplicate = ::sqlite3_column_int(checks.get(), 1) != 0;
    }
    if (duplicate) {
      return reject("E_MANAGEMENT_IP_DUPLICATE", "duplicate_ip");
    }
    if (count >= kMaximumManagementIpsPerRole) {
      return reject("E_MANAGEMENT_IP_LIMIT", "role_limit");
    }
    PreparedStatement insert(
        impl_->database.get(),
        "INSERT INTO management_ips (normalized_ip, role_scope, enabled, "
        "created_at_seconds) VALUES (?1, ?2, 1, ?3);");
    if (!insert.valid() ||
        ::sqlite3_bind_text(insert.get(), 1, normalized_ip.data(),
                            static_cast<int>(normalized_ip.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_text(insert.get(), 2, role_text.data(),
                            static_cast<int>(role_text.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int64(insert.get(), 3, now_seconds) != SQLITE_OK ||
        ::sqlite3_step(insert.get()) != SQLITE_DONE) {
      return UserMutationUnavailable<StoredManagementIp>(transaction);
    }
    const std::int64_t management_ip_id =
        ::sqlite3_last_insert_rowid(impl_->database.get());
    auto audited = InsertAuditEvent(
        transaction, now_seconds, "management_ip_created", "success",
        context.actor_user_id, context.normalized_peer_ip, "created",
        "management_ip", normalized_ip);
    if (!audited.ok()) {
      return UserMutationUnavailable<StoredManagementIp>(transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<StoredManagementIp>(transaction);
    }
    return common::Result<StoredManagementIp>::Ok(
        {management_ip_id, std::move(normalized_ip), role, now_seconds});
  } catch (...) {
    return UserMutationUnavailable<StoredManagementIp>(transaction);
  }
}

common::Result<CommittedRevocation> SecurityStore::UpdateManagementIp(
    std::int64_t management_ip_id,
    UserRole role,
    std::string normalized_replacement,
    std::int64_t now_seconds,
    const SecurityMutationContext& context) {
  auto started = BeginTransaction();
  if (!started.ok()) {
    return StoreError<CommittedRevocation>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  auto transaction = std::move(started).value();
  try {
    std::optional<UserRole> stored_role;
    std::string old_normalized_ip;
    {
      PreparedStatement target(
          impl_->database.get(),
          "SELECT normalized_ip, role_scope FROM management_ips WHERE id = ?1;");
      if (!target.valid() ||
          ::sqlite3_bind_int64(target.get(), 1, management_ip_id) != SQLITE_OK) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      const int row = ::sqlite3_step(target.get());
      if (row == SQLITE_ROW) {
        const auto* normalized_ip = ::sqlite3_column_text(target.get(), 0);
        stored_role = ReadUserRole(target.get(), 1);
        if (normalized_ip == nullptr || !stored_role.has_value()) {
          return UserMutationUnavailable<CommittedRevocation>(transaction);
        }
        old_normalized_ip = reinterpret_cast<const char*>(normalized_ip);
      } else if (row != SQLITE_DONE) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
    }
    std::string audit_subject = stored_role.has_value()
                                    ? old_normalized_ip
                                    : std::to_string(management_ip_id);
    const auto reject = [&](std::string code, std::string detail,
                            std::string_view subject) {
      auto audited = InsertAuditEvent(
          transaction, now_seconds, "management_ip_updated", "failure",
          context.actor_user_id, context.normalized_peer_ip, detail,
          "management_ip", subject);
      if (!audited.ok()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      return StoreError<CommittedRevocation>(
          std::move(code), "management IP update was rejected");
    };
    if (context.actor_role != UserRole::kAdministrator) {
      return reject("E_MANAGEMENT_IP_FORBIDDEN", "role_forbidden",
                    audit_subject);
    }
    if (!stored_role.has_value()) {
      return reject("E_MANAGEMENT_IP_NOT_FOUND", "ip_not_found",
                    audit_subject);
    }
    if (*stored_role != role) {
      return reject("E_MANAGEMENT_IP_ROLE_MISMATCH", "role_mismatch",
                    audit_subject);
    }

    const std::string_view role_text = RoleText(role);
    sqlite3_int64 count = 0;
    bool duplicate = false;
    {
      PreparedStatement checks(
          impl_->database.get(),
          "SELECT (SELECT COUNT(*) FROM management_ips WHERE role_scope = ?1), "
          "EXISTS(SELECT 1 FROM management_ips WHERE role_scope = ?1 AND "
          "normalized_ip = ?2 AND id <> ?3);");
      if (!checks.valid() ||
          ::sqlite3_bind_text(checks.get(), 1, role_text.data(),
                              static_cast<int>(role_text.size()),
                              SQLITE_TRANSIENT) != SQLITE_OK ||
          ::sqlite3_bind_text(checks.get(), 2, normalized_replacement.data(),
                              static_cast<int>(normalized_replacement.size()),
                              SQLITE_TRANSIENT) != SQLITE_OK ||
          ::sqlite3_bind_int64(checks.get(), 3, management_ip_id) != SQLITE_OK ||
          ::sqlite3_step(checks.get()) != SQLITE_ROW) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      count = ::sqlite3_column_int64(checks.get(), 0);
      duplicate = ::sqlite3_column_int(checks.get(), 1) != 0;
    }
    if (count > kMaximumManagementIpsPerRole) {
      return reject("E_MANAGEMENT_IP_LIMIT", "role_limit",
                    normalized_replacement);
    }
    if (duplicate) {
      return reject("E_MANAGEMENT_IP_DUPLICATE", "duplicate_ip",
                    normalized_replacement);
    }
    if (role == UserRole::kAdministrator &&
        old_normalized_ip == context.normalized_peer_ip) {
      return reject("E_MANAGEMENT_IP_PROTECTED", "current_peer",
                    old_normalized_ip);
    }
    if (role == UserRole::kAdministrator && count <= 1) {
      return reject("E_MANAGEMENT_IP_PROTECTED", "final_administrator_ip",
                    old_normalized_ip);
    }
    if (old_normalized_ip == normalized_replacement) {
      auto audited = InsertAuditEvent(
          transaction, now_seconds, "management_ip_updated", "success",
          context.actor_user_id, context.normalized_peer_ip, "unchanged",
          "management_ip", old_normalized_ip);
      if (!audited.ok()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      return common::Result<CommittedRevocation>::Ok({});
    }

    auto collected = ReadManagementIpSessionIdentities(
        impl_->database.get(), role, old_normalized_ip);
    if (!collected.ok() ||
        !DeleteManagementIpSessions(impl_->database.get(), role,
                                    old_normalized_ip)) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    PreparedStatement update(
        impl_->database.get(),
        "UPDATE management_ips SET normalized_ip = ?1 WHERE id = ?2 AND "
        "role_scope = ?3;");
    if (!update.valid() ||
        ::sqlite3_bind_text(update.get(), 1, normalized_replacement.data(),
                            static_cast<int>(normalized_replacement.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int64(update.get(), 2, management_ip_id) != SQLITE_OK ||
        ::sqlite3_bind_text(update.get(), 3, role_text.data(),
                            static_cast<int>(role_text.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_step(update.get()) != SQLITE_DONE ||
        ::sqlite3_changes(impl_->database.get()) != 1) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    auto audited = InsertAuditEvent(
        transaction, now_seconds, "management_ip_updated", "success",
        context.actor_user_id, context.normalized_peer_ip, "updated",
        "management_ip", normalized_replacement);
    if (!audited.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    return common::Result<CommittedRevocation>::Ok(
        {std::move(collected).value()});
  } catch (...) {
    return UserMutationUnavailable<CommittedRevocation>(transaction);
  }
}

common::Result<CommittedRevocation> SecurityStore::DeleteManagementIp(
    std::int64_t management_ip_id,
    UserRole role,
    std::int64_t now_seconds,
    const SecurityMutationContext& context) {
  auto started = BeginTransaction();
  if (!started.ok()) {
    return StoreError<CommittedRevocation>(
        "E_USER_MANAGEMENT_STORE", "user management transaction failed");
  }
  auto transaction = std::move(started).value();
  try {
    std::optional<UserRole> stored_role;
    std::string old_normalized_ip;
    {
      PreparedStatement target(
          impl_->database.get(),
          "SELECT normalized_ip, role_scope FROM management_ips WHERE id = ?1;");
      if (!target.valid() ||
          ::sqlite3_bind_int64(target.get(), 1, management_ip_id) != SQLITE_OK) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      const int row = ::sqlite3_step(target.get());
      if (row == SQLITE_ROW) {
        const auto* normalized_ip = ::sqlite3_column_text(target.get(), 0);
        stored_role = ReadUserRole(target.get(), 1);
        if (normalized_ip == nullptr || !stored_role.has_value()) {
          return UserMutationUnavailable<CommittedRevocation>(transaction);
        }
        old_normalized_ip = reinterpret_cast<const char*>(normalized_ip);
      } else if (row != SQLITE_DONE) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
    }
    const std::string audit_subject = stored_role.has_value()
                                          ? old_normalized_ip
                                          : std::to_string(management_ip_id);
    const auto reject = [&](std::string code, std::string detail) {
      auto audited = InsertAuditEvent(
          transaction, now_seconds, "management_ip_deleted", "failure",
          context.actor_user_id, context.normalized_peer_ip, detail,
          "management_ip", audit_subject);
      if (!audited.ok()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      return StoreError<CommittedRevocation>(
          std::move(code), "management IP deletion was rejected");
    };
    if (context.actor_role != UserRole::kAdministrator) {
      return reject("E_MANAGEMENT_IP_FORBIDDEN", "role_forbidden");
    }
    if (!stored_role.has_value()) {
      return reject("E_MANAGEMENT_IP_NOT_FOUND", "ip_not_found");
    }
    if (*stored_role != role) {
      return reject("E_MANAGEMENT_IP_ROLE_MISMATCH", "role_mismatch");
    }
    const std::string_view role_text = RoleText(role);
    sqlite3_int64 count = 0;
    {
      PreparedStatement count_statement(
          impl_->database.get(),
          "SELECT COUNT(*) FROM management_ips WHERE role_scope = ?1;");
      if (!count_statement.valid() ||
          ::sqlite3_bind_text(count_statement.get(), 1, role_text.data(),
                              static_cast<int>(role_text.size()),
                              SQLITE_TRANSIENT) != SQLITE_OK ||
          ::sqlite3_step(count_statement.get()) != SQLITE_ROW) {
        return UserMutationUnavailable<CommittedRevocation>(transaction);
      }
      count = ::sqlite3_column_int64(count_statement.get(), 0);
    }
    if (count > kMaximumManagementIpsPerRole) {
      return reject("E_MANAGEMENT_IP_LIMIT", "role_limit");
    }
    if (role == UserRole::kAdministrator &&
        old_normalized_ip == context.normalized_peer_ip) {
      return reject("E_MANAGEMENT_IP_PROTECTED", "current_peer");
    }
    if (role == UserRole::kAdministrator && count <= 1) {
      return reject("E_MANAGEMENT_IP_PROTECTED", "final_administrator_ip");
    }

    auto collected = ReadManagementIpSessionIdentities(
        impl_->database.get(), role, old_normalized_ip);
    if (!collected.ok() ||
        !DeleteManagementIpSessions(impl_->database.get(), role,
                                    old_normalized_ip)) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    PreparedStatement remove(
        impl_->database.get(),
        "DELETE FROM management_ips WHERE id = ?1 AND role_scope = ?2;");
    if (!remove.valid() ||
        ::sqlite3_bind_int64(remove.get(), 1, management_ip_id) != SQLITE_OK ||
        ::sqlite3_bind_text(remove.get(), 2, role_text.data(),
                            static_cast<int>(role_text.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_step(remove.get()) != SQLITE_DONE ||
        ::sqlite3_changes(impl_->database.get()) != 1) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    auto audited = InsertAuditEvent(
        transaction, now_seconds, "management_ip_deleted", "success",
        context.actor_user_id, context.normalized_peer_ip, "deleted",
        "management_ip", old_normalized_ip);
    if (!audited.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return UserMutationUnavailable<CommittedRevocation>(transaction);
    }
    return common::Result<CommittedRevocation>::Ok(
        {std::move(collected).value()});
  } catch (...) {
    return UserMutationUnavailable<CommittedRevocation>(transaction);
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
