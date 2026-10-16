#include "camera_firmware/security/UserManagementService.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <sqlite3.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/security/PasswordHasher.hpp"
#include "camera_firmware/security/SecurityStore.hpp"

void ConfigureSecurityStoreTransactionFailuresForTest(bool commit,
                                                      bool rollback);

namespace camera_firmware::security {
namespace {

using common::SecureBytes;

common::SecureBytes Secret(std::string_view text) {
  common::SecureBytes value;
  value.assign(reinterpret_cast<const unsigned char*>(text.data()),
               text.size());
  return value;
}

SessionIdentity Identity(unsigned char fill) {
  SessionIdentity identity;
  identity.bytes.fill(fill);
  return identity;
}

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 52> pattern{"/tmp/cf-user-management-service-XXXXXX"};
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

class Database {
 public:
  explicit Database(const std::filesystem::path& path, int flags) {
    if (::sqlite3_open_v2(path.c_str(), &database_,
                          flags | SQLITE_OPEN_NOFOLLOW, nullptr) != SQLITE_OK) {
      throw std::runtime_error("failed to open test database");
    }
    (void)::sqlite3_busy_timeout(database_, 1000);
  }

  ~Database() {
    if (database_ != nullptr) {
      (void)::sqlite3_close_v2(database_);
    }
  }

  Database(const Database&) = delete;
  Database& operator=(const Database&) = delete;

  [[nodiscard]] sqlite3* get() const noexcept { return database_; }

 private:
  sqlite3* database_{nullptr};
};

class Statement {
 public:
  Statement(sqlite3* database, const char* sql) {
    if (::sqlite3_prepare_v2(database, sql, -1, &statement_, nullptr) !=
        SQLITE_OK) {
      throw std::runtime_error("failed to prepare test statement");
    }
  }

  ~Statement() {
    if (statement_ != nullptr) {
      (void)::sqlite3_finalize(statement_);
    }
  }

  Statement(const Statement&) = delete;
  Statement& operator=(const Statement&) = delete;

  [[nodiscard]] sqlite3_stmt* get() const noexcept { return statement_; }

 private:
  sqlite3_stmt* statement_{nullptr};
};

void ExecuteSql(const std::filesystem::path& path, const char* sql) {
  Database database(path, SQLITE_OPEN_READWRITE);
  char* error_message = nullptr;
  const int result =
      ::sqlite3_exec(database.get(), sql, nullptr, nullptr, &error_message);
  if (error_message != nullptr) {
    ::sqlite3_free(error_message);
  }
  if (result != SQLITE_OK) {
    throw std::runtime_error("failed to execute test SQL");
  }
}

int QueryInt(const std::filesystem::path& path, const char* sql) {
  Database database(path, SQLITE_OPEN_READONLY);
  Statement statement(database.get(), sql);
  if (::sqlite3_step(statement.get()) != SQLITE_ROW) {
    throw std::runtime_error("failed to query test integer");
  }
  return ::sqlite3_column_int(statement.get(), 0);
}

std::string QueryText(const std::filesystem::path& path, const char* sql) {
  Database database(path, SQLITE_OPEN_READONLY);
  Statement statement(database.get(), sql);
  if (::sqlite3_step(statement.get()) != SQLITE_ROW) {
    throw std::runtime_error("failed to query test text");
  }
  const auto* raw = ::sqlite3_column_text(statement.get(), 0);
  return raw == nullptr ? "" : reinterpret_cast<const char*>(raw);
}

SecureBytes ColumnBytes(sqlite3_stmt* statement, int column) {
  SecureBytes bytes;
  const auto* data = static_cast<const unsigned char*>(
      ::sqlite3_column_blob(statement, column));
  const int size = ::sqlite3_column_bytes(statement, column);
  if (size < 0 || (size != 0 && data == nullptr)) {
    throw std::runtime_error("failed to query test bytes");
  }
  bytes.assign(data, static_cast<std::size_t>(size));
  return bytes;
}

PasswordRecord ReadPassword(const std::filesystem::path& path,
                            std::int64_t user_id, bool history = false) {
  Database database(path, SQLITE_OPEN_READONLY);
  Statement statement(
      database.get(),
      history
          ? "SELECT password_algorithm, password_iterations, password_salt, "
            "password_derived FROM password_history WHERE user_id = ?1;"
          : "SELECT password_algorithm, password_iterations, password_salt, "
            "password_derived FROM users WHERE id = ?1;");
  if (::sqlite3_bind_int64(statement.get(), 1, user_id) != SQLITE_OK ||
      ::sqlite3_step(statement.get()) != SQLITE_ROW) {
    throw std::runtime_error("failed to query test password record");
  }
  const auto* algorithm = ::sqlite3_column_text(statement.get(), 0);
  if (algorithm == nullptr) {
    throw std::runtime_error("failed to query test password algorithm");
  }
  PasswordRecord record;
  record.algorithm = reinterpret_cast<const char*>(algorithm);
  record.iterations =
      static_cast<std::uint32_t>(::sqlite3_column_int64(statement.get(), 1));
  record.salt = ColumnBytes(statement.get(), 2);
  record.derived = ColumnBytes(statement.get(), 3);
  return record;
}

SecureBytes FilledBytes(std::size_t size, unsigned char fill) {
  SecureBytes bytes;
  bytes.resize(size);
  std::fill_n(bytes.data(), size, fill);
  return bytes;
}

bool SameBytes(const SecureBytes& first, const SecureBytes& second) {
  return first.size() == second.size() &&
         std::equal(first.data(), first.data() + first.size(), second.data());
}

PasswordRecord DeriveForTest(std::string_view password, unsigned char salt) {
  auto plaintext = Secret(password);
  auto derived = DerivePassword(
      plaintext, PasswordHasherDependencies{[salt](std::size_t size) {
        return common::Result<SecureBytes>::Ok(FilledBytes(size, salt));
      }});
  if (!derived.ok()) {
    throw std::runtime_error("failed to derive test password");
  }
  return std::move(derived).value();
}

class ScopedTransactionFailureReset {
 public:
  ~ScopedTransactionFailureReset() {
    ConfigureSecurityStoreTransactionFailuresForTest(false, false);
  }
};

class UserManagementServiceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto opened = SecurityStore::Open({temporary_.path() / "security"});
    ASSERT_TRUE(opened.ok());
    store_ = std::move(opened).value();

    BootstrapRecord administrator{"operator.one", "Operator.One",
                                  DeriveForTest("NorthStar!9", 0x11U),
                                  "192.0.2.10", 1720000000};
    auto initialized = store_->InitializeDevice(
        std::move(administrator), [] { return common::Result<void>::Ok(); });
    ASSERT_TRUE(initialized.ok());
    administrator_id_ = QueryInt(
        database_path(), "SELECT id FROM users WHERE role = 'administrator';");
    administrator_management_ip_id_ = QueryInt(
        database_path(),
        "SELECT id FROM management_ips WHERE role_scope = 'administrator';");

    dependencies_.now_seconds = [this] { return now_seconds_; };
    dependencies_.random_bytes = [this](std::size_t size) {
      return common::Result<SecureBytes>::Ok(FilledBytes(size, next_salt_++));
    };
    dependencies_.verify_password = [](const SecureBytes& password,
                                       const PasswordRecord& record) {
      return VerifyPassword(password, record);
    };
    dependencies_.revoke_sessions =
        [this](std::span<const SessionIdentity> identities) {
          ++exact_revocation_calls_;
          revoked_.assign(identities.begin(), identities.end());
        };
    dependencies_.revoke_all_streams = [this] { ++global_revocation_calls_; };
  }

  void StartService() {
    ASSERT_EQ(service_, nullptr);
    service_ = std::make_unique<UserManagementService>(
        *store_, std::vector<std::string>{"imx708", "camera-main"},
        std::move(dependencies_));
  }

  [[nodiscard]] const std::filesystem::path& database_path() const {
    return store_->database_path();
  }

  UserMutationContext AdministratorContext() const {
    return {{administrator_id_, "operator.one", UserRole::kAdministrator,
             Identity(0xa1U)},
            "192.0.2.10"};
  }

  UserMutationContext ViewerContext(std::int64_t id,
                                    std::string username) const {
    return {{id, std::move(username), UserRole::kViewer, Identity(0xb2U)},
            "192.0.2.22"};
  }

  std::int64_t SeedViewer(
      std::string_view canonical, std::string_view display,
      std::string_view password = "NorthStar!9", bool enabled = true,
      int failed_count = 0,
      std::optional<std::int64_t> lock_until = std::nullopt) {
    PasswordRecord record = DeriveForTest(password, next_salt_++);
    Database database(database_path(), SQLITE_OPEN_READWRITE);
    Statement statement(
        database.get(),
        "INSERT INTO users (canonical_username, display_username, role, "
        "enabled, password_algorithm, password_iterations, password_salt, "
        "password_derived, password_changed_at_seconds, failed_login_count, "
        "lock_until_seconds, created_at_seconds) VALUES "
        "(?1, ?2, 'viewer', ?3, ?4, ?5, ?6, ?7, 1720000001, ?8, ?9, "
        "1720000001);");
    const int lock_result =
        lock_until.has_value()
            ? ::sqlite3_bind_int64(statement.get(), 9, *lock_until)
            : ::sqlite3_bind_null(statement.get(), 9);
    if (::sqlite3_bind_text(statement.get(), 1, canonical.data(),
                            static_cast<int>(canonical.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_text(statement.get(), 2, display.data(),
                            static_cast<int>(display.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int(statement.get(), 3, enabled ? 1 : 0) != SQLITE_OK ||
        ::sqlite3_bind_text(statement.get(), 4, record.algorithm.data(),
                            static_cast<int>(record.algorithm.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int64(statement.get(), 5, record.iterations) !=
            SQLITE_OK ||
        ::sqlite3_bind_blob(statement.get(), 6, record.salt.data(),
                            static_cast<int>(record.salt.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_blob(statement.get(), 7, record.derived.data(),
                            static_cast<int>(record.derived.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int(statement.get(), 8, failed_count) != SQLITE_OK ||
        lock_result != SQLITE_OK ||
        ::sqlite3_step(statement.get()) != SQLITE_DONE) {
      throw std::runtime_error("failed to seed viewer");
    }
    return ::sqlite3_last_insert_rowid(database.get());
  }

  void SeedHistory(std::int64_t user_id, std::string_view password) {
    PasswordRecord record = DeriveForTest(password, next_salt_++);
    Database database(database_path(), SQLITE_OPEN_READWRITE);
    Statement statement(
        database.get(),
        "INSERT INTO password_history (user_id, password_algorithm, "
        "password_iterations, password_salt, password_derived, "
        "replaced_at_seconds) VALUES (?1, ?2, ?3, ?4, ?5, 1720000002);");
    if (::sqlite3_bind_int64(statement.get(), 1, user_id) != SQLITE_OK ||
        ::sqlite3_bind_text(statement.get(), 2, record.algorithm.data(),
                            static_cast<int>(record.algorithm.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int64(statement.get(), 3, record.iterations) !=
            SQLITE_OK ||
        ::sqlite3_bind_blob(statement.get(), 4, record.salt.data(),
                            static_cast<int>(record.salt.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_blob(statement.get(), 5, record.derived.data(),
                            static_cast<int>(record.derived.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_step(statement.get()) != SQLITE_DONE) {
      throw std::runtime_error("failed to seed password history");
    }
  }

  void ReplaceHistory(std::int64_t user_id, const PasswordRecord& record) {
    Database database(database_path(), SQLITE_OPEN_READWRITE);
    Statement statement(
        database.get(),
        "UPDATE password_history SET password_algorithm = ?1, "
        "password_iterations = ?2, password_salt = ?3, "
        "password_derived = ?4, replaced_at_seconds = 1720000004 "
        "WHERE user_id = ?5;");
    if (::sqlite3_bind_text(statement.get(), 1, record.algorithm.data(),
                            static_cast<int>(record.algorithm.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int64(statement.get(), 2, record.iterations) !=
            SQLITE_OK ||
        ::sqlite3_bind_blob(statement.get(), 3, record.salt.data(),
                            static_cast<int>(record.salt.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_blob(statement.get(), 4, record.derived.data(),
                            static_cast<int>(record.derived.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int64(statement.get(), 5, user_id) != SQLITE_OK ||
        ::sqlite3_step(statement.get()) != SQLITE_DONE ||
        ::sqlite3_changes(database.get()) != 1) {
      throw std::runtime_error("failed to replace password history");
    }
  }

  void SeedSession(std::int64_t user_id, UserRole role,
                   unsigned char identity_fill,
                   std::string_view peer_ip = "192.0.2.22") {
    auto identity = Identity(identity_fill);
    Database database(database_path(), SQLITE_OPEN_READWRITE);
    Statement statement(
        database.get(),
        "INSERT INTO sessions (token_hash, user_id, role, created_at_seconds, "
        "last_activity_at_seconds, expires_at_seconds, peer_ip, "
        "management_expires_at_seconds) VALUES "
        "(?1, ?2, ?3, 1720000003, 1720000003, 1720003603, ?4, 0);");
    const std::string_view role_text =
        role == UserRole::kAdministrator ? "administrator" : "viewer";
    if (::sqlite3_bind_blob(statement.get(), 1, identity.bytes.data(),
                            static_cast<int>(identity.bytes.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int64(statement.get(), 2, user_id) != SQLITE_OK ||
        ::sqlite3_bind_text(statement.get(), 3, role_text.data(),
                            static_cast<int>(role_text.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_text(statement.get(), 4, peer_ip.data(),
                            static_cast<int>(peer_ip.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_step(statement.get()) != SQLITE_DONE) {
      throw std::runtime_error("failed to seed session");
    }
  }

  std::int64_t SeedManagementIp(UserRole role, std::string_view normalized_ip,
                                bool enabled = true) {
    Database database(database_path(), SQLITE_OPEN_READWRITE);
    Statement statement(
        database.get(),
        "INSERT INTO management_ips (normalized_ip, role_scope, enabled, "
        "created_at_seconds) VALUES (?1, ?2, ?3, 1720000002);");
    const std::string_view role_text =
        role == UserRole::kAdministrator ? "administrator" : "viewer";
    if (::sqlite3_bind_text(statement.get(), 1, normalized_ip.data(),
                            static_cast<int>(normalized_ip.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_text(statement.get(), 2, role_text.data(),
                            static_cast<int>(role_text.size()),
                            SQLITE_TRANSIENT) != SQLITE_OK ||
        ::sqlite3_bind_int(statement.get(), 3, enabled ? 1 : 0) != SQLITE_OK ||
        ::sqlite3_step(statement.get()) != SQLITE_DONE) {
      throw std::runtime_error("failed to seed management IP");
    }
    return ::sqlite3_last_insert_rowid(database.get());
  }

  TemporaryDirectory temporary_;
  std::unique_ptr<SecurityStore> store_;
  std::unique_ptr<UserManagementService> service_;
  UserManagementDependencies dependencies_;
  std::int64_t administrator_id_{0};
  std::int64_t administrator_management_ip_id_{0};
  std::int64_t now_seconds_{1720000100};
  unsigned char next_salt_{0x31U};
  int exact_revocation_calls_{0};
  int global_revocation_calls_{0};
  std::vector<SessionIdentity> revoked_;
};

TEST_F(UserManagementServiceTest,
       DisablingIpRestrictionPersistsAndRevokesAllSessions) {
  const auto viewer_id = SeedViewer("monitor.east", "Monitor.East");
  SeedSession(viewer_id, UserRole::kViewer, 0x51U);
  SeedSession(administrator_id_, UserRole::kAdministrator, 0x52U, "192.0.2.10");
  StartService();
  auto changed = service_->SetManagementIpRestrictionEnabled(
      false, AdministratorContext());
  ASSERT_TRUE(changed.ok()) << changed.error().message;
  ASSERT_TRUE(service_->ManagementIpRestrictionEnabled().ok());
  EXPECT_FALSE(service_->ManagementIpRestrictionEnabled().value());
  EXPECT_TRUE(store_->IsManagementPeer("198.51.100.44").value());
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 0);
  EXPECT_EQ(exact_revocation_calls_, 1);
  EXPECT_EQ(revoked_,
            (std::vector<SessionIdentity>{Identity(0x51U), Identity(0x52U)}));
  EXPECT_EQ(
      QueryText(database_path(),
                "SELECT detail_code FROM audit_events WHERE event_type = "
                "'management_ip_policy_changed' AND outcome = 'success';"),
      "disabled");
  service_.reset();
  const auto state_directory = store_->state_directory();
  store_.reset();
  auto reopened = SecurityStore::Open({state_directory});
  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  EXPECT_FALSE(reopened.value()->ManagementIpRestrictionEnabled().value());
  EXPECT_TRUE(reopened.value()->IsManagementPeer("198.51.100.44").value());
}

TEST_F(UserManagementServiceTest, EnablingIpRestrictionRejectsActorLockout) {
  StartService();
  ASSERT_TRUE(
      service_->SetManagementIpRestrictionEnabled(false, AdministratorContext())
          .ok());
  auto roaming = AdministratorContext();
  roaming.normalized_peer_ip = "198.51.100.44";
  auto denied = service_->SetManagementIpRestrictionEnabled(true, roaming);
  ASSERT_FALSE(denied.ok());
  EXPECT_EQ(denied.error().code, "E_MANAGEMENT_IP_LOCKOUT");
  EXPECT_FALSE(service_->ManagementIpRestrictionEnabled().value());
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'management_ip_policy_changed' AND outcome = 'failure';"),
            1);
  ASSERT_TRUE(service_
                  ->AddManagementIp(UserRole::kAdministrator, "198.51.100.44",
                                    AdministratorContext())
                  .ok());
  ASSERT_TRUE(service_->SetManagementIpRestrictionEnabled(true, roaming).ok());
  EXPECT_TRUE(service_->ManagementIpRestrictionEnabled().value());
  EXPECT_TRUE(store_->IsManagementPeer("198.51.100.44").value());
  EXPECT_FALSE(store_->IsManagementPeer("198.51.100.45").value());
}

TEST_F(UserManagementServiceTest, ViewerCannotChangeIpRestriction) {
  const auto viewer_id = SeedViewer("monitor.east", "Monitor.East");
  StartService();
  auto changed = service_->SetManagementIpRestrictionEnabled(
      false, ViewerContext(viewer_id, "monitor.east"));
  ASSERT_FALSE(changed.ok());
  EXPECT_EQ(changed.error().code, "E_MANAGEMENT_IP_FORBIDDEN");
  EXPECT_TRUE(service_->ManagementIpRestrictionEnabled().value());
}

TEST_F(UserManagementServiceTest,
       EnablingIpRestrictionRequiresEnabledAdministratorAddress) {
  StartService();
  ASSERT_TRUE(
      service_->SetManagementIpRestrictionEnabled(false, AdministratorContext())
          .ok());
  auto roaming = AdministratorContext();
  roaming.normalized_peer_ip = "198.51.100.44";
  SeedManagementIp(UserRole::kViewer, roaming.normalized_peer_ip);
  auto viewer_only = service_->SetManagementIpRestrictionEnabled(true, roaming);
  ASSERT_FALSE(viewer_only.ok());
  EXPECT_EQ(viewer_only.error().code, "E_MANAGEMENT_IP_LOCKOUT");
  SeedManagementIp(UserRole::kAdministrator, roaming.normalized_peer_ip, false);
  auto disabled = service_->SetManagementIpRestrictionEnabled(true, roaming);
  ASSERT_FALSE(disabled.ok());
  EXPECT_EQ(disabled.error().code, "E_MANAGEMENT_IP_LOCKOUT");
  EXPECT_FALSE(service_->ManagementIpRestrictionEnabled().value());
}

TEST_F(UserManagementServiceTest,
       PolicyCommitFailurePreservesSessionsAndRestriction) {
  SeedSession(administrator_id_, UserRole::kAdministrator, 0x52U, "192.0.2.10");
  StartService();
  ScopedTransactionFailureReset reset;
  ConfigureSecurityStoreTransactionFailuresForTest(true, false);
  auto changed = service_->SetManagementIpRestrictionEnabled(
      false, AdministratorContext());
  ConfigureSecurityStoreTransactionFailuresForTest(false, false);
  EXPECT_FALSE(changed.ok());
  EXPECT_TRUE(service_->ManagementIpRestrictionEnabled().value());
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 1);
  EXPECT_EQ(exact_revocation_calls_, 0);
  EXPECT_EQ(global_revocation_calls_, 0);
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'management_ip_policy_changed';"),
            0);
}

TEST_F(UserManagementServiceTest, CreatesCanonicalViewerAndListsStableIdOrder) {
  StartService();
  auto east = service_->CreateViewer("Monitor.East", Secret("SouthMoon!8"),
                                     AdministratorContext());
  ASSERT_TRUE(east.ok());
  auto west = service_->CreateViewer("Monitor.West", Secret("Crimson!7"),
                                     AdministratorContext());
  ASSERT_TRUE(west.ok());

  auto users = service_->ListUsers();

  ASSERT_TRUE(users.ok());
  ASSERT_EQ(users.value().size(), 3U);
  EXPECT_EQ(users.value()[0].username, "Operator.One");
  EXPECT_EQ(users.value()[0].role, UserRole::kAdministrator);
  EXPECT_EQ(users.value()[1].username, "Monitor.East");
  EXPECT_EQ(users.value()[2].username, "Monitor.West");
  EXPECT_LT(users.value()[0].id, users.value()[1].id);
  EXPECT_LT(users.value()[1].id, users.value()[2].id);
  EXPECT_EQ(
      QueryText(database_path(),
                "SELECT subject_identity FROM audit_events WHERE "
                "event_type = 'viewer_created' ORDER BY sequence LIMIT 1;"),
      "monitor.east");
}

TEST_F(UserManagementServiceTest,
       RejectsCanonicalDuplicateAndReservedIdentityWithFailureAudit) {
  StartService();
  ASSERT_TRUE(service_
                  ->CreateViewer("Monitor.East", Secret("SouthMoon!8"),
                                 AdministratorContext())
                  .ok());

  auto duplicate = service_->CreateViewer("MONITOR.EAST", Secret("Crimson!7"),
                                          AdministratorContext());
  auto reserved = service_->CreateViewer("ops-imx708", Secret("Crimson!7"),
                                         AdministratorContext());

  ASSERT_FALSE(duplicate.ok());
  EXPECT_EQ(duplicate.error().code, "E_USER_DUPLICATE");
  ASSERT_FALSE(reserved.ok());
  EXPECT_EQ(reserved.error().code, "E_USERNAME_RESERVED");
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE outcome = "
                     "'failure' AND subject_type = 'user' AND "
                     "subject_identity IN ('monitor.east', 'ops-imx708');"),
            2);
}

TEST_F(UserManagementServiceTest, CountsEnabledAndDisabledViewersTowardLimit) {
  for (int index = 0; index < 32; ++index) {
    const std::string username = "view" + std::to_string(1000 + index);
    (void)SeedViewer(username, username, "NorthStar!9", index % 2 == 0);
  }
  StartService();

  auto result = service_->CreateViewer("monitor.extra", Secret("SouthMoon!8"),
                                       AdministratorContext());

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_VIEWER_LIMIT");
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM users WHERE role = 'viewer';"),
            32);
  EXPECT_EQ(QueryText(database_path(),
                      "SELECT outcome FROM audit_events WHERE event_type = "
                      "'viewer_created' ORDER BY sequence DESC LIMIT 1;"),
            "failure");
}

TEST_F(UserManagementServiceTest,
       AdministratorIsImmutableThroughViewerCommands) {
  StartService();

  auto disabled = service_->SetViewerEnabled(administrator_id_, false,
                                             AdministratorContext());
  auto reset = service_->ResetViewerPassword(
      administrator_id_, Secret("SouthMoon!8"), AdministratorContext());
  auto deleted =
      service_->DeleteViewer(administrator_id_, AdministratorContext());

  ASSERT_FALSE(disabled.ok());
  EXPECT_EQ(disabled.error().code, "E_USER_PROTECTED");
  ASSERT_FALSE(reset.ok());
  EXPECT_EQ(reset.error().code, "E_USER_PROTECTED");
  ASSERT_FALSE(deleted.ok());
  EXPECT_EQ(deleted.error().code, "E_USER_PROTECTED");
  EXPECT_EQ(
      QueryInt(database_path(), "SELECT enabled FROM users WHERE id = 1;"), 1);
}

TEST_F(UserManagementServiceTest,
       DisableEnableAndDeletePublishOnlyCommittedExactSessions) {
  const std::int64_t viewer_id = SeedViewer("monitor.east", "Monitor.East");
  SeedSession(viewer_id, UserRole::kViewer, 0x51U);
  dependencies_.revoke_sessions =
      [this](std::span<const SessionIdentity> identities) {
        ++exact_revocation_calls_;
        revoked_.assign(identities.begin(), identities.end());
        EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"),
                  0);
      };
  StartService();

  ASSERT_TRUE(
      service_->SetViewerEnabled(viewer_id, false, AdministratorContext())
          .ok());
  ASSERT_EQ(exact_revocation_calls_, 1);
  ASSERT_EQ(revoked_.size(), 1U);
  EXPECT_EQ(revoked_[0], Identity(0x51U));

  ASSERT_TRUE(
      service_->SetViewerEnabled(viewer_id, true, AdministratorContext()).ok());
  EXPECT_EQ(exact_revocation_calls_, 1);
  SeedSession(viewer_id, UserRole::kViewer, 0x52U);
  ASSERT_TRUE(service_->DeleteViewer(viewer_id, AdministratorContext()).ok());
  EXPECT_EQ(exact_revocation_calls_, 2);
  ASSERT_EQ(revoked_.size(), 1U);
  EXPECT_EQ(revoked_[0], Identity(0x52U));
  EXPECT_EQ(
      QueryInt(database_path(), "SELECT COUNT(*) FROM users WHERE id = 2;"), 0);
}

TEST_F(UserManagementServiceTest,
       PasswordChangeRejectsCurrentAndRetainedPreviousPassword) {
  const std::int64_t viewer_id =
      SeedViewer("monitor.east", "Monitor.East", "NorthStar!9");
  StartService();
  auto context = ViewerContext(viewer_id, "monitor.east");

  auto changed = service_->ChangeOwnPassword(Secret("NorthStar!9"),
                                             Secret("SouthMoon!8"), context);
  ASSERT_TRUE(changed.ok());
  auto current_reuse = service_->ChangeOwnPassword(
      Secret("SouthMoon!8"), Secret("SouthMoon!8"), context);
  auto previous_reuse = service_->ChangeOwnPassword(
      Secret("SouthMoon!8"), Secret("NorthStar!9"), context);

  ASSERT_FALSE(current_reuse.ok());
  EXPECT_EQ(current_reuse.error().code, "E_PASSWORD_REUSE");
  ASSERT_FALSE(previous_reuse.ok());
  EXPECT_EQ(previous_reuse.error().code, "E_PASSWORD_REUSE");
  EXPECT_EQ(
      QueryInt(database_path(),
               "SELECT COUNT(*) FROM password_history WHERE user_id = 2;"),
      1);
}

TEST_F(UserManagementServiceTest,
       ResetReplacesOneHistoryClearsLockoutDeletesSessionAndRevokes) {
  const std::int64_t viewer_id = SeedViewer("monitor.east", "Monitor.East",
                                            "NorthStar!9", true, 5, 1720000500);
  SeedHistory(viewer_id, "OldHarbor!6");
  SeedSession(viewer_id, UserRole::kViewer, 0x61U);
  StartService();

  auto reset = service_->ResetViewerPassword(viewer_id, Secret("SouthMoon!8"),
                                             AdministratorContext());

  ASSERT_TRUE(reset.ok());
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT failed_login_count FROM users WHERE id = 2;"),
            0);
  EXPECT_EQ(
      QueryInt(database_path(),
               "SELECT lock_until_seconds IS NULL FROM users WHERE id = 2;"),
      1);
  EXPECT_EQ(
      QueryInt(database_path(),
               "SELECT COUNT(*) FROM password_history WHERE user_id = 2;"),
      1);
  auto new_password = Secret("SouthMoon!8");
  auto old_password = Secret("NorthStar!9");
  ASSERT_TRUE(
      VerifyPassword(new_password, ReadPassword(database_path(), viewer_id))
          .value());
  ASSERT_TRUE(VerifyPassword(old_password,
                             ReadPassword(database_path(), viewer_id, true))
                  .value());
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 0);
  ASSERT_EQ(exact_revocation_calls_, 1);
  ASSERT_EQ(revoked_.size(), 1U);
  EXPECT_EQ(revoked_[0], Identity(0x61U));
}

TEST_F(UserManagementServiceTest, ResetRejectsCurrentAndPreviousPassword) {
  const std::int64_t viewer_id =
      SeedViewer("monitor.east", "Monitor.East", "NorthStar!9");
  SeedHistory(viewer_id, "OldHarbor!6");
  StartService();

  auto current = service_->ResetViewerPassword(viewer_id, Secret("NorthStar!9"),
                                               AdministratorContext());
  auto previous = service_->ResetViewerPassword(
      viewer_id, Secret("OldHarbor!6"), AdministratorContext());

  ASSERT_FALSE(current.ok());
  EXPECT_EQ(current.error().code, "E_PASSWORD_REUSE");
  ASSERT_FALSE(previous.ok());
  EXPECT_EQ(previous.error().code, "E_PASSWORD_REUSE");
}

TEST_F(UserManagementServiceTest,
       WrongCurrentPasswordIsAuditedAndLeavesCredentialUnchanged) {
  const std::int64_t viewer_id =
      SeedViewer("monitor.east", "Monitor.East", "NorthStar!9");
  StartService();

  auto changed =
      service_->ChangeOwnPassword(Secret("WrongLake!4"), Secret("SouthMoon!8"),
                                  ViewerContext(viewer_id, "monitor.east"));

  ASSERT_FALSE(changed.ok());
  EXPECT_EQ(changed.error().code, "E_CURRENT_PASSWORD");
  auto original = Secret("NorthStar!9");
  EXPECT_TRUE(VerifyPassword(original, ReadPassword(database_path(), viewer_id))
                  .value());
  EXPECT_EQ(QueryText(database_path(),
                      "SELECT subject_identity FROM audit_events WHERE "
                      "event_type = 'password_changed' AND outcome = 'failure' "
                      "ORDER BY sequence DESC LIMIT 1;"),
            "monitor.east");
}

TEST_F(UserManagementServiceTest,
       OptimisticPasswordConflictAppliesNoHistoryOrSessionMutation) {
  const std::int64_t viewer_id =
      SeedViewer("monitor.east", "Monitor.East", "NorthStar!9");
  SeedSession(viewer_id, UserRole::kViewer, 0x71U);
  dependencies_.random_bytes = [this](std::size_t size) {
    ExecuteSql(database_path(),
               "UPDATE users SET password_changed_at_seconds = "
               "password_changed_at_seconds + 1 WHERE id = 2;");
    return common::Result<SecureBytes>::Ok(FilledBytes(size, 0x72U));
  };
  StartService();

  auto changed =
      service_->ChangeOwnPassword(Secret("NorthStar!9"), Secret("SouthMoon!8"),
                                  ViewerContext(viewer_id, "monitor.east"));

  ASSERT_FALSE(changed.ok());
  EXPECT_EQ(changed.error().code, "E_USER_CONFLICT");
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM password_history;"),
            0);
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 1);
  EXPECT_EQ(exact_revocation_calls_, 0);
}

TEST_F(UserManagementServiceTest,
       OptimisticHistoryConflictPreservesRacedHistoryUserAndSession) {
  const std::int64_t viewer_id =
      SeedViewer("monitor.east", "Monitor.East", "NorthStar!9");
  SeedHistory(viewer_id, "OldHarbor!6");
  SeedSession(viewer_id, UserRole::kViewer, 0x73U);
  auto raced_history =
      std::make_shared<PasswordRecord>(DeriveForTest("SouthMoon!8", 0x74U));
  dependencies_.random_bytes = [this, viewer_id,
                                raced_history](std::size_t size) {
    ReplaceHistory(viewer_id, *raced_history);
    return common::Result<SecureBytes>::Ok(FilledBytes(size, 0x75U));
  };
  StartService();

  auto changed =
      service_->ChangeOwnPassword(Secret("NorthStar!9"), Secret("SouthMoon!8"),
                                  ViewerContext(viewer_id, "monitor.east"));

  ASSERT_FALSE(changed.ok());
  EXPECT_EQ(changed.error().code, "E_USER_CONFLICT");
  auto current = ReadPassword(database_path(), viewer_id);
  auto history = ReadPassword(database_path(), viewer_id, true);
  auto original = Secret("NorthStar!9");
  EXPECT_TRUE(VerifyPassword(original, current).value());
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT password_changed_at_seconds FROM users "
                     "WHERE id = 2;"),
            1720000001);
  EXPECT_EQ(history.algorithm, raced_history->algorithm);
  EXPECT_EQ(history.iterations, raced_history->iterations);
  EXPECT_TRUE(SameBytes(history.salt, raced_history->salt));
  EXPECT_TRUE(SameBytes(history.derived, raced_history->derived));
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 1);
  EXPECT_EQ(exact_revocation_calls_, 0);
  EXPECT_EQ(QueryText(database_path(),
                      "SELECT detail_code FROM audit_events WHERE "
                      "event_type = 'password_changed' ORDER BY sequence "
                      "DESC LIMIT 1;"),
            "optimistic_conflict");
}

TEST_F(UserManagementServiceTest,
       CryptographicFailureIsAuditedAndLeavesPasswordUnchanged) {
  const std::int64_t viewer_id =
      SeedViewer("monitor.east", "Monitor.East", "NorthStar!9");
  dependencies_.random_bytes = [](std::size_t) {
    return common::Result<SecureBytes>::Err(
        {"E_TEST_RANDOM", "test random failure"});
  };
  StartService();

  auto reset = service_->ResetViewerPassword(viewer_id, Secret("SouthMoon!8"),
                                             AdministratorContext());

  ASSERT_FALSE(reset.ok());
  EXPECT_EQ(reset.error().code, "E_USER_MANAGEMENT_UNAVAILABLE");
  auto original = Secret("NorthStar!9");
  EXPECT_TRUE(VerifyPassword(original, ReadPassword(database_path(), viewer_id))
                  .value());
  EXPECT_EQ(
      QueryText(database_path(),
                "SELECT outcome FROM audit_events WHERE event_type = "
                "'viewer_password_reset' ORDER BY sequence DESC LIMIT 1;"),
      "failure");
}

TEST_F(UserManagementServiceTest,
       VerificationExceptionIsAuditedAndLeavesPasswordUnchanged) {
  const std::int64_t viewer_id =
      SeedViewer("monitor.east", "Monitor.East", "NorthStar!9");
  dependencies_.verify_password =
      [](const SecureBytes&, const PasswordRecord&) -> common::Result<bool> {
    throw std::runtime_error("verification failed");
  };
  StartService();

  auto reset = service_->ResetViewerPassword(viewer_id, Secret("SouthMoon!8"),
                                             AdministratorContext());

  ASSERT_FALSE(reset.ok());
  EXPECT_EQ(reset.error().code, "E_USER_MANAGEMENT_UNAVAILABLE");
  EXPECT_EQ(
      QueryText(database_path(),
                "SELECT outcome FROM audit_events WHERE event_type = "
                "'viewer_password_reset' ORDER BY sequence DESC LIMIT 1;"),
      "failure");
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM password_history;"),
            0);
}

TEST_F(UserManagementServiceTest,
       AuditInsertionFailureReturnsUnavailableAndRollsBackMutation) {
  StartService();
  auto invalid_actor = AdministratorContext();
  invalid_actor.actor.user_id = 9999;

  auto created = service_->CreateViewer("monitor.east", Secret("SouthMoon!8"),
                                        invalid_actor);

  ASSERT_FALSE(created.ok());
  EXPECT_EQ(created.error().code, "E_USER_MANAGEMENT_UNAVAILABLE");
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM users WHERE role = 'viewer';"),
            0);
}

TEST_F(UserManagementServiceTest,
       CommitFailureRollsBackDisableAndNeverPublishesRevocation) {
  const std::int64_t viewer_id =
      SeedViewer("monitor.east", "Monitor.East", "NorthStar!9");
  SeedSession(viewer_id, UserRole::kViewer, 0x81U);
  StartService();
  ScopedTransactionFailureReset reset;
  ConfigureSecurityStoreTransactionFailuresForTest(true, false);

  auto disabled =
      service_->SetViewerEnabled(viewer_id, false, AdministratorContext());

  ASSERT_FALSE(disabled.ok());
  EXPECT_EQ(disabled.error().code, "E_USER_MANAGEMENT_UNAVAILABLE");
  EXPECT_EQ(
      QueryInt(database_path(), "SELECT enabled FROM users WHERE id = 2;"), 1);
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 1);
  EXPECT_EQ(exact_revocation_calls_, 0);
}

TEST_F(UserManagementServiceTest,
       ExactRevocationThrowUsesGlobalFallbackAfterCommittedMutation) {
  const std::int64_t viewer_id =
      SeedViewer("monitor.east", "Monitor.East", "NorthStar!9");
  SeedSession(viewer_id, UserRole::kViewer, 0x91U);
  dependencies_.revoke_sessions = [](std::span<const SessionIdentity>) {
    throw std::runtime_error("exact revocation failed");
  };
  StartService();

  auto disabled =
      service_->SetViewerEnabled(viewer_id, false, AdministratorContext());

  EXPECT_TRUE(disabled.ok());
  EXPECT_EQ(global_revocation_calls_, 1);
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 0);
}

TEST_F(UserManagementServiceTest,
       PasswordAndDerivedMaterialNeverEnterAuditText) {
  const std::int64_t viewer_id =
      SeedViewer("monitor.east", "Monitor.East", "NorthStar!9");
  StartService();

  ASSERT_TRUE(service_
                  ->ResetViewerPassword(viewer_id, Secret("SouthMoon!8"),
                                        AdministratorContext())
                  .ok());

  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE "
                     "event_type = 'viewer_password_reset' AND "
                     "(detail_code LIKE '%SouthMoon%' OR "
                     "subject_identity LIKE '%SouthMoon%');"),
            0);
}

TEST_F(UserManagementServiceTest,
       ManagementIpCanonicalizesIpv4AndIpv6AndListsStableIdOrder) {
  StartService();

  auto ipv4 = service_->AddManagementIp(UserRole::kViewer, "198.51.100.42",
                                        AdministratorContext());
  auto ipv6 = service_->AddManagementIp(
      UserRole::kViewer, "2001:0DB8:0000:0000:0000:0000:0000:002A",
      AdministratorContext());
  auto equivalent_ipv6 = service_->AddManagementIp(
      UserRole::kViewer, "2001:db8::2a", AdministratorContext());

  ASSERT_TRUE(ipv4.ok());
  ASSERT_TRUE(ipv6.ok());
  ASSERT_FALSE(equivalent_ipv6.ok());
  EXPECT_EQ(equivalent_ipv6.error().code, "E_MANAGEMENT_IP_DUPLICATE");
  EXPECT_EQ(ipv4.value().normalized_ip, "198.51.100.42");
  EXPECT_EQ(ipv6.value().normalized_ip, "2001:db8::2a");
  auto listed = service_->ListManagementIps();
  ASSERT_TRUE(listed.ok());
  ASSERT_EQ(listed.value().size(), 3U);
  EXPECT_EQ(listed.value()[0].id, administrator_management_ip_id_);
  EXPECT_EQ(listed.value()[1].id, ipv4.value().id);
  EXPECT_EQ(listed.value()[2].id, ipv6.value().id);
  EXPECT_EQ(exact_revocation_calls_, 0);
}

TEST_F(UserManagementServiceTest,
       ManagementIpAllowsSameAddressPerRoleAndAuditsDuplicateRole) {
  StartService();

  auto viewer = service_->AddManagementIp(UserRole::kViewer, "192.0.2.10",
                                          AdministratorContext());
  auto duplicate = service_->AddManagementIp(UserRole::kViewer, "192.0.2.10",
                                             AdministratorContext());

  ASSERT_TRUE(viewer.ok());
  ASSERT_FALSE(duplicate.ok());
  EXPECT_EQ(duplicate.error().code, "E_MANAGEMENT_IP_DUPLICATE");
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM management_ips WHERE "
                     "normalized_ip = '192.0.2.10';"),
            2);
  EXPECT_EQ(
      QueryText(database_path(),
                "SELECT subject_type || '|' || subject_identity || '|' || "
                "outcome FROM audit_events WHERE event_type = "
                "'management_ip_created' ORDER BY sequence DESC LIMIT 1;"),
      "management_ip|192.0.2.10|failure");
}

TEST_F(UserManagementServiceTest,
       ManagementIpRejectsNonHostAndUnspecifiedInputsWithFailureAudits) {
  StartService();
  const std::vector<std::string> invalid{"",
                                         "192.0.2.0/24",
                                         "192.0.2.1-192.0.2.4",
                                         "*",
                                         "camera.local",
                                         "0.0.0.0",
                                         "::",
                                         std::string("192.0.2.1\0junk", 14)};

  for (const auto& input : invalid) {
    auto added = service_->AddManagementIp(UserRole::kViewer, input,
                                           AdministratorContext());
    ASSERT_FALSE(added.ok()) << input;
    EXPECT_EQ(added.error().code, "E_MANAGEMENT_IP_INVALID") << input;
  }

  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM management_ips WHERE "
                     "role_scope = 'viewer';"),
            0);
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'management_ip_created' AND outcome = 'failure';"),
            static_cast<int>(invalid.size()));
}

TEST_F(UserManagementServiceTest,
       ManagementIpCountsEnabledAndDisabledRowsTowardPerRoleLimit) {
  for (int index = 1; index <= 32; ++index) {
    SeedManagementIp(UserRole::kViewer, "198.51.100." + std::to_string(index),
                     index % 2 == 0);
  }
  StartService();

  auto rejected = service_->AddManagementIp(UserRole::kViewer, "198.51.100.99",
                                            AdministratorContext());
  auto administrator = service_->AddManagementIp(
      UserRole::kAdministrator, "198.51.100.99", AdministratorContext());

  ASSERT_FALSE(rejected.ok());
  EXPECT_EQ(rejected.error().code, "E_MANAGEMENT_IP_LIMIT");
  EXPECT_TRUE(administrator.ok());
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM management_ips WHERE "
                     "role_scope = 'viewer';"),
            32);
}

TEST_F(UserManagementServiceTest,
       ManagementIpMutationsRequireAdministratorAndAuditTheSubject) {
  const auto viewer_id = SeedViewer("monitor.east", "Monitor.East");
  const auto management_ip_id =
      SeedManagementIp(UserRole::kViewer, "198.51.100.20");
  StartService();
  const auto viewer_context = ViewerContext(viewer_id, "monitor.east");

  auto added = service_->AddManagementIp(UserRole::kViewer, "198.51.100.21",
                                         viewer_context);
  auto updated = service_->UpdateManagementIp(
      management_ip_id, UserRole::kViewer, "198.51.100.22", viewer_context);
  auto deleted = service_->DeleteManagementIp(
      management_ip_id, UserRole::kViewer, viewer_context);

  ASSERT_FALSE(added.ok());
  ASSERT_FALSE(updated.ok());
  ASSERT_FALSE(deleted.ok());
  EXPECT_EQ(added.error().code, "E_MANAGEMENT_IP_FORBIDDEN");
  EXPECT_EQ(updated.error().code, "E_MANAGEMENT_IP_FORBIDDEN");
  EXPECT_EQ(deleted.error().code, "E_MANAGEMENT_IP_FORBIDDEN");
  EXPECT_EQ(QueryText(database_path(),
                      "SELECT subject_type || '|' || subject_identity FROM "
                      "audit_events WHERE event_type = 'management_ip_deleted' "
                      "ORDER BY sequence DESC LIMIT 1;"),
            "management_ip|198.51.100.20");
}

TEST_F(UserManagementServiceTest,
       ManagementIpProtectsCurrentAdministratorPeerWithAnotherAdminIp) {
  SeedManagementIp(UserRole::kAdministrator, "192.0.2.20");
  StartService();

  auto updated = service_->UpdateManagementIp(
      administrator_management_ip_id_, UserRole::kAdministrator, "192.0.2.10",
      AdministratorContext());
  auto deleted = service_->DeleteManagementIp(administrator_management_ip_id_,
                                              UserRole::kAdministrator,
                                              AdministratorContext());

  ASSERT_FALSE(updated.ok());
  ASSERT_FALSE(deleted.ok());
  EXPECT_EQ(updated.error().code, "E_MANAGEMENT_IP_PROTECTED");
  EXPECT_EQ(deleted.error().code, "E_MANAGEMENT_IP_PROTECTED");
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM management_ips WHERE "
                     "role_scope = 'administrator';"),
            2);
}

TEST_F(UserManagementServiceTest,
       ManagementIpProtectsFinalAdministratorFromUpdateAndDelete) {
  StartService();
  auto off_peer = AdministratorContext();
  off_peer.normalized_peer_ip = "192.0.2.99";

  auto updated = service_->UpdateManagementIp(administrator_management_ip_id_,
                                              UserRole::kAdministrator,
                                              "192.0.2.10", off_peer);
  auto deleted = service_->DeleteManagementIp(
      administrator_management_ip_id_, UserRole::kAdministrator, off_peer);

  ASSERT_FALSE(updated.ok());
  ASSERT_FALSE(deleted.ok());
  EXPECT_EQ(updated.error().code, "E_MANAGEMENT_IP_PROTECTED");
  EXPECT_EQ(deleted.error().code, "E_MANAGEMENT_IP_PROTECTED");
  EXPECT_EQ(QueryText(database_path(),
                      "SELECT normalized_ip FROM management_ips WHERE "
                      "role_scope = 'administrator';"),
            "192.0.2.10");
}

TEST_F(UserManagementServiceTest,
       ManagementIpAllowsReplacingNonCurrentAdminAfterSecondHostIsAdded) {
  SeedManagementIp(UserRole::kAdministrator, "192.0.2.20");
  StartService();
  auto replacement_peer = AdministratorContext();
  replacement_peer.normalized_peer_ip = "192.0.2.20";

  auto updated = service_->UpdateManagementIp(administrator_management_ip_id_,
                                              UserRole::kAdministrator,
                                              "192.0.2.30", replacement_peer);
  auto deleted =
      service_->DeleteManagementIp(administrator_management_ip_id_,
                                   UserRole::kAdministrator, replacement_peer);

  ASSERT_TRUE(updated.ok());
  ASSERT_TRUE(deleted.ok());
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM management_ips WHERE "
                     "role_scope = 'administrator';"),
            1);
  EXPECT_EQ(QueryText(database_path(),
                      "SELECT normalized_ip FROM management_ips WHERE "
                      "role_scope = 'administrator';"),
            "192.0.2.20");
}

TEST_F(UserManagementServiceTest, ManagementIpAllowsDeletingFinalViewerIp) {
  const auto management_ip_id =
      SeedManagementIp(UserRole::kViewer, "198.51.100.20");
  StartService();

  auto deleted = service_->DeleteManagementIp(
      management_ip_id, UserRole::kViewer, AdministratorContext());

  EXPECT_TRUE(deleted.ok());
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM management_ips WHERE "
                     "role_scope = 'viewer';"),
            0);
}

TEST_F(UserManagementServiceTest,
       ManagementIpRejectsTargetRoleMismatchWithoutChangingTarget) {
  const auto management_ip_id =
      SeedManagementIp(UserRole::kViewer, "198.51.100.20");
  StartService();

  auto updated =
      service_->UpdateManagementIp(management_ip_id, UserRole::kAdministrator,
                                   "198.51.100.21", AdministratorContext());
  auto deleted = service_->DeleteManagementIp(
      management_ip_id, UserRole::kAdministrator, AdministratorContext());

  ASSERT_FALSE(updated.ok());
  ASSERT_FALSE(deleted.ok());
  EXPECT_EQ(updated.error().code, "E_MANAGEMENT_IP_ROLE_MISMATCH");
  EXPECT_EQ(deleted.error().code, "E_MANAGEMENT_IP_ROLE_MISMATCH");
  EXPECT_EQ(QueryText(database_path(),
                      "SELECT normalized_ip FROM management_ips WHERE id = 2;"),
            "198.51.100.20");
}

TEST_F(UserManagementServiceTest,
       ManagementIpUpdateDeletesAndRevokesOnlyOldRoleAndIpSessions) {
  const auto management_ip_id =
      SeedManagementIp(UserRole::kViewer, "198.51.100.20");
  const auto first = SeedViewer("monitor.east", "Monitor.East");
  const auto second = SeedViewer("monitor.west", "Monitor.West");
  const auto third = SeedViewer("monitor.north", "Monitor.North");
  SeedSession(first, UserRole::kViewer, 0x51U, "198.51.100.20");
  SeedSession(second, UserRole::kViewer, 0x52U, "198.51.100.21");
  SeedSession(third, UserRole::kViewer, 0x53U, "198.51.100.20");
  SeedSession(administrator_id_, UserRole::kAdministrator, 0x54U,
              "198.51.100.20");
  StartService();

  auto updated =
      service_->UpdateManagementIp(management_ip_id, UserRole::kViewer,
                                   "198.51.100.21", AdministratorContext());

  ASSERT_TRUE(updated.ok());
  ASSERT_EQ(exact_revocation_calls_, 1);
  ASSERT_EQ(revoked_.size(), 2U);
  EXPECT_EQ(revoked_[0], Identity(0x51U));
  EXPECT_EQ(revoked_[1], Identity(0x53U));
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM sessions WHERE role = 'viewer' "
                     "AND peer_ip = '198.51.100.20';"),
            0);
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 2);
  EXPECT_EQ(QueryText(database_path(),
                      "SELECT subject_type || '|' || subject_identity FROM "
                      "audit_events WHERE event_type = 'management_ip_updated' "
                      "ORDER BY sequence DESC LIMIT 1;"),
            "management_ip|198.51.100.21");
}

TEST_F(UserManagementServiceTest,
       ManagementIpEquivalentIpv6UpdatePreservesSessionWithoutRevocation) {
  const auto management_ip_id =
      SeedManagementIp(UserRole::kViewer, "2001:db8::20");
  const auto viewer = SeedViewer("monitor.east", "Monitor.East");
  SeedSession(viewer, UserRole::kViewer, 0x59U, "2001:db8::20");
  StartService();

  auto updated = service_->UpdateManagementIp(
      management_ip_id, UserRole::kViewer,
      "2001:0DB8:0000:0000:0000:0000:0000:0020", AdministratorContext());

  ASSERT_TRUE(updated.ok());
  EXPECT_EQ(QueryText(database_path(),
                      "SELECT normalized_ip FROM management_ips WHERE id = 2;"),
            "2001:db8::20");
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 1);
  EXPECT_EQ(exact_revocation_calls_, 0);
  EXPECT_EQ(global_revocation_calls_, 0);
  EXPECT_TRUE(revoked_.empty());
  EXPECT_EQ(
      QueryText(database_path(),
                "SELECT detail_code || '|' || subject_identity || '|' || "
                "outcome FROM audit_events WHERE event_type = "
                "'management_ip_updated' ORDER BY sequence DESC LIMIT 1;"),
      "unchanged|2001:db8::20|success");
}

TEST_F(UserManagementServiceTest,
       ManagementIpDeleteRevokesOnlyMatchingOldRoleAndIp) {
  const auto management_ip_id =
      SeedManagementIp(UserRole::kViewer, "198.51.100.20");
  const auto viewer = SeedViewer("monitor.east", "Monitor.East");
  SeedSession(viewer, UserRole::kViewer, 0x61U, "198.51.100.20");
  SeedSession(administrator_id_, UserRole::kAdministrator, 0x62U,
              "198.51.100.20");
  StartService();

  auto deleted = service_->DeleteManagementIp(
      management_ip_id, UserRole::kViewer, AdministratorContext());

  ASSERT_TRUE(deleted.ok());
  ASSERT_EQ(exact_revocation_calls_, 1);
  ASSERT_EQ(revoked_.size(), 1U);
  EXPECT_EQ(revoked_[0], Identity(0x61U));
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 1);
}

TEST_F(UserManagementServiceTest,
       ManagementIpAuditFailureRollsBackIpAndSessionWithoutRevocation) {
  const auto management_ip_id =
      SeedManagementIp(UserRole::kViewer, "198.51.100.20");
  const auto viewer = SeedViewer("monitor.east", "Monitor.East");
  SeedSession(viewer, UserRole::kViewer, 0x71U, "198.51.100.20");
  StartService();
  auto invalid_actor = AdministratorContext();
  invalid_actor.actor.user_id = 9999;

  auto updated = service_->UpdateManagementIp(
      management_ip_id, UserRole::kViewer, "198.51.100.21", invalid_actor);

  ASSERT_FALSE(updated.ok());
  EXPECT_EQ(updated.error().code, "E_USER_MANAGEMENT_UNAVAILABLE");
  EXPECT_EQ(QueryText(database_path(),
                      "SELECT normalized_ip FROM management_ips WHERE id = 2;"),
            "198.51.100.20");
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 1);
  EXPECT_EQ(exact_revocation_calls_, 0);
}

TEST_F(UserManagementServiceTest,
       ManagementIpCommitFailureRollsBackDeleteAndPublishesNothing) {
  const auto management_ip_id =
      SeedManagementIp(UserRole::kViewer, "198.51.100.20");
  const auto viewer = SeedViewer("monitor.east", "Monitor.East");
  SeedSession(viewer, UserRole::kViewer, 0x81U, "198.51.100.20");
  StartService();
  ScopedTransactionFailureReset reset;
  ConfigureSecurityStoreTransactionFailuresForTest(true, false);

  auto deleted = service_->DeleteManagementIp(
      management_ip_id, UserRole::kViewer, AdministratorContext());

  ASSERT_FALSE(deleted.ok());
  EXPECT_EQ(deleted.error().code, "E_USER_MANAGEMENT_UNAVAILABLE");
  EXPECT_EQ(QueryInt(database_path(),
                     "SELECT COUNT(*) FROM management_ips WHERE id = 2;"),
            1);
  EXPECT_EQ(QueryInt(database_path(), "SELECT COUNT(*) FROM sessions;"), 1);
  EXPECT_EQ(exact_revocation_calls_, 0);
}

}  // namespace
}  // namespace camera_firmware::security
