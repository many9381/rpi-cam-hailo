#include "camera_firmware/security/AuthService.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
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

class AuthServiceTestAccess {
 public:
  static std::unique_ptr<AuthService> Create(
      SecurityStore& store,
      AuthServiceDependencies dependencies) {
    return std::unique_ptr<AuthService>(
        new AuthService(store, std::move(dependencies)));
  }

  static std::unique_ptr<AuthService> CreateWithBeforeAck(
      SecurityStore& store,
      AuthServiceDependencies dependencies,
      std::function<void()> before_ack) {
    return std::unique_ptr<AuthService>(new AuthService(
        store, std::move(dependencies), std::move(before_ack)));
  }
};

namespace {

using common::SecureBytes;

static_assert(std::is_constructible_v<AuthService, SecurityStore&>);
static_assert(
    !std::is_constructible_v<AuthService, SecurityStore&,
                             AuthServiceDependencies>);

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 48> pattern{"/tmp/cf-auth-service-XXXXXX"};
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

SecureBytes Bytes(std::string_view value) {
  SecureBytes bytes;
  bytes.assign(reinterpret_cast<const unsigned char*>(value.data()),
               value.size());
  return bytes;
}

SecureBytes FilledBytes(std::size_t size, unsigned char value) {
  SecureBytes bytes;
  bytes.resize(size);
  std::fill_n(bytes.data(), size, value);
  return bytes;
}

PasswordRecord StoredPassword() {
  PasswordRecord record;
  record.salt = FilledBytes(kPasswordSaltBytes, 0x31U);
  record.derived = FilledBytes(kPasswordDerivedBytes, 0xa7U);
  return record;
}

BootstrapRecord AdministratorRecord(std::string peer = "192.0.2.10") {
  return {"operator.one", "Operator.One", StoredPassword(), std::move(peer),
          1720000000};
}

void ExecuteSql(const std::filesystem::path& database_path, const char* sql) {
  sqlite3* database = nullptr;
  if (::sqlite3_open_v2(database_path.c_str(), &database,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW,
                        nullptr) != SQLITE_OK) {
    throw std::runtime_error("failed to open test database");
  }
  (void)::sqlite3_busy_timeout(database, 1000);
  char* error_message = nullptr;
  const int executed =
      ::sqlite3_exec(database, sql, nullptr, nullptr, &error_message);
  if (error_message != nullptr) {
    ::sqlite3_free(error_message);
  }
  const int closed = ::sqlite3_close_v2(database);
  if (executed != SQLITE_OK || closed != SQLITE_OK) {
    throw std::runtime_error("failed to mutate test database");
  }
}

int QueryInt(const std::filesystem::path& database_path, const char* sql) {
  sqlite3* database = nullptr;
  if (::sqlite3_open_v2(database_path.c_str(), &database,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW,
                        nullptr) != SQLITE_OK) {
    throw std::runtime_error("failed to open test database");
  }
  (void)::sqlite3_busy_timeout(database, 1000);
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) !=
          SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_ROW) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    (void)::sqlite3_close_v2(database);
    throw std::runtime_error("failed to query test database");
  }
  const int value = ::sqlite3_column_int(statement, 0);
  (void)::sqlite3_finalize(statement);
  (void)::sqlite3_close_v2(database);
  return value;
}

std::string QueryText(const std::filesystem::path& database_path,
                      const char* sql) {
  sqlite3* database = nullptr;
  if (::sqlite3_open_v2(database_path.c_str(), &database,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW,
                        nullptr) != SQLITE_OK) {
    throw std::runtime_error("failed to open test database");
  }
  (void)::sqlite3_busy_timeout(database, 1000);
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) !=
          SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_ROW) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    (void)::sqlite3_close_v2(database);
    throw std::runtime_error("failed to query test database");
  }
  const auto* raw = ::sqlite3_column_text(statement, 0);
  const std::string value =
      raw == nullptr ? "" : reinterpret_cast<const char*>(raw);
  (void)::sqlite3_finalize(statement);
  (void)::sqlite3_close_v2(database);
  return value;
}

std::string ReadFile(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input),
          std::istreambuf_iterator<char>()};
}

bool StateDirectoryContains(const std::filesystem::path& state,
                            std::string_view needle) {
  for (const auto& entry : std::filesystem::directory_iterator(state)) {
    if (entry.is_regular_file() &&
        ReadFile(entry.path()).find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

std::string StringFromBytes(const SecureBytes& bytes) {
  return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

class ScopedTransactionFailureReset {
 public:
  ~ScopedTransactionFailureReset() {
    ConfigureSecurityStoreTransactionFailuresForTest(false, false);
  }

  ScopedTransactionFailureReset() = default;
  ScopedTransactionFailureReset(const ScopedTransactionFailureReset&) = delete;
  ScopedTransactionFailureReset& operator=(
      const ScopedTransactionFailureReset&) = delete;
};

class TimedBarrier {
 public:
  explicit TimedBarrier(int participants) : participants_(participants) {}

  bool ArriveAndWait(std::chrono::milliseconds timeout) {
    std::unique_lock lock(mutex_);
    ++arrived_;
    condition_.notify_all();
    return condition_.wait_for(lock, timeout,
                               [this] { return arrived_ == participants_; });
  }

 private:
  std::mutex mutex_;
  std::condition_variable condition_;
  int participants_;
  int arrived_{0};
};

class BlockingLogger {
 public:
  void Invoke(std::string_view category, std::string_view normalized_peer) {
    std::unique_lock lock(mutex_);
    ++calls_;
    category_ = category;
    peer_ = normalized_peer;
    callback_thread_ = std::this_thread::get_id();
    started_ = true;
    condition_.notify_all();
    condition_.wait(lock, [this] { return released_; });
  }

  bool WaitUntilStarted(std::chrono::milliseconds timeout) {
    std::unique_lock lock(mutex_);
    return condition_.wait_for(lock, timeout, [this] { return started_; });
  }

  void Release() {
    std::lock_guard lock(mutex_);
    released_ = true;
    condition_.notify_all();
  }

  int calls() const {
    std::lock_guard lock(mutex_);
    return calls_;
  }

  std::string category() const {
    std::lock_guard lock(mutex_);
    return category_;
  }

  std::string peer() const {
    std::lock_guard lock(mutex_);
    return peer_;
  }

  std::thread::id callback_thread() const {
    std::lock_guard lock(mutex_);
    return callback_thread_;
  }

 private:
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  bool started_{false};
  bool released_{false};
  int calls_{0};
  std::string category_;
  std::string peer_;
  std::thread::id callback_thread_;
};

class BlockingLoggerReleaseGuard {
 public:
  explicit BlockingLoggerReleaseGuard(BlockingLogger& logger)
      : logger_(logger) {}
  ~BlockingLoggerReleaseGuard() { logger_.Release(); }

  BlockingLoggerReleaseGuard(const BlockingLoggerReleaseGuard&) = delete;
  BlockingLoggerReleaseGuard& operator=(const BlockingLoggerReleaseGuard&) =
      delete;

 private:
  BlockingLogger& logger_;
};

class CountingLogger {
 public:
  int Record(std::string_view category, std::string_view peer) {
    std::lock_guard lock(mutex_);
    category_ = category;
    peer_ = peer;
    ++calls_;
    condition_.notify_all();
    return calls_;
  }

  bool WaitForCalls(int expected, std::chrono::milliseconds timeout) {
    std::unique_lock lock(mutex_);
    return condition_.wait_for(lock, timeout,
                               [this, expected] { return calls_ >= expected; });
  }

  int calls() const {
    std::lock_guard lock(mutex_);
    return calls_;
  }

  std::string category() const {
    std::lock_guard lock(mutex_);
    return category_;
  }

  std::string peer() const {
    std::lock_guard lock(mutex_);
    return peer_;
  }

 private:
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  int calls_{0};
  std::string category_;
  std::string peer_;
};

class AuthServiceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto opened = SecurityStore::Open({temporary_.path() / "security"});
    ASSERT_TRUE(opened.ok()) << opened.error().message;
    store_ = std::move(opened).value();
    ASSERT_TRUE(store_
                    ->InitializeDevice(AdministratorRecord(), [] {
                      return common::Result<void>::Ok();
                    })
                    .ok());
    RecreateService();
  }

  void RecreateService() {
    AuthServiceDependencies dependencies;
    dependencies.now_seconds = [this] { return now_seconds_; };
    dependencies.random_bytes = [this](std::size_t size) {
      ++random_calls_;
      return common::Result<SecureBytes>::Ok(
          FilledBytes(size, static_cast<unsigned char>(0x40U + random_calls_)));
    };
    dependencies.verify_password =
        [this](const SecureBytes& password, const PasswordRecord&) {
          ++kdf_calls_;
          const auto expected = Bytes("NorthStar!9");
          const bool matches =
              password.size() == expected.size() &&
              std::equal(password.data(), password.data() + password.size(),
                         expected.data());
          return common::Result<bool>::Ok(matches);
        };
    dependencies.high_severity_log =
        [this](std::string_view category, std::string_view normalized_peer) {
          RecordHighSeverityLog(category, normalized_peer);
        };
    service_ = AuthServiceTestAccess::Create(*store_,
                                             std::move(dependencies));
  }

  std::unique_ptr<AuthService> DecisionFailureService(
      bool password_matches,
      bool rollback_failure) {
    AuthServiceDependencies dependencies;
    dependencies.now_seconds = [this] { return now_seconds_; };
    dependencies.random_bytes = [](std::size_t size) {
      return common::Result<SecureBytes>::Ok(FilledBytes(size, 0x73U));
    };
    dependencies.verify_password =
        [password_matches, rollback_failure](const SecureBytes&,
                                             const PasswordRecord&) {
          ConfigureSecurityStoreTransactionFailuresForTest(true,
                                                           rollback_failure);
          return common::Result<bool>::Ok(password_matches);
        };
    dependencies.high_severity_log =
        [this](std::string_view category, std::string_view normalized_peer) {
          RecordHighSeverityLog(category, normalized_peer);
        };
    return AuthServiceTestAccess::Create(*store_, std::move(dependencies));
  }

  LoginRequest Login(std::string username = "Operator.One",
                     std::string_view password = "NorthStar!9",
                     std::string peer = "192.0.2.10") {
    return {std::move(username), Bytes(password), std::move(peer)};
  }

  void ExpectAuthenticationFailure(
      const common::Result<LoginResult>& result) {
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_AUTHENTICATION_FAILED");
    EXPECT_EQ(result.error().message, "authentication failed");
  }

  void RecordHighSeverityLog(std::string_view category,
                             std::string_view normalized_peer) {
    std::lock_guard lock(high_severity_log_mutex_);
    high_severity_logs_.emplace_back(std::string(category) + "|" +
                                     std::string(normalized_peer));
    high_severity_log_condition_.notify_all();
  }

  bool WaitForHighSeverityLogCount(
      std::size_t expected,
      std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) {
    std::unique_lock lock(high_severity_log_mutex_);
    return high_severity_log_condition_.wait_for(
        lock, timeout,
        [this, expected] { return high_severity_logs_.size() >= expected; });
  }

  std::vector<std::string> HighSeverityLogs() const {
    std::lock_guard lock(high_severity_log_mutex_);
    return high_severity_logs_;
  }

  TemporaryDirectory temporary_;
  mutable std::mutex high_severity_log_mutex_;
  std::condition_variable high_severity_log_condition_;
  std::vector<std::string> high_severity_logs_;
  std::unique_ptr<SecurityStore> store_;
  std::unique_ptr<AuthService> service_;
  std::int64_t now_seconds_{1720000100};
  int kdf_calls_{0};
  int random_calls_{0};
};

TEST_F(AuthServiceTest, UnknownAndWrongPasswordUseSameKdfAndError) {
  const auto unknown =
      service_->Login(Login("missing.user", "BadSecret!9"));
  const int unknown_kdf_calls = kdf_calls_;
  const auto wrong = service_->Login(Login("Operator.One", "BadSecret!9"));

  ExpectAuthenticationFailure(unknown);
  ExpectAuthenticationFailure(wrong);
  EXPECT_EQ(unknown_kdf_calls, 1);
  EXPECT_EQ(kdf_calls_ - unknown_kdf_calls, unknown_kdf_calls);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_failed' AND actor_user_id IS NULL;"),
            1);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_failed' AND actor_user_id IS NOT NULL;"),
            1);
}

TEST_F(AuthServiceTest, UnknownAndCurrentUserRunEquivalentRealKdfPolicy) {
  struct ObservedPolicy {
    std::string algorithm;
    std::uint32_t iterations;
    std::size_t salt_size;
    std::size_t derived_size;

    bool operator==(const ObservedPolicy&) const = default;
  };
  std::vector<ObservedPolicy> observed;
  AuthServiceDependencies dependencies;
  dependencies.now_seconds = [this] { return now_seconds_; };
  dependencies.verify_password =
      [&observed](const SecureBytes& password, const PasswordRecord& record) {
        observed.push_back({record.algorithm, record.iterations,
                            record.salt.size(), record.derived.size()});
        return VerifyPassword(password, record);
      };
  auto real_kdf_service = AuthServiceTestAccess::Create(
      *store_, std::move(dependencies));

  ExpectAuthenticationFailure(real_kdf_service->Login(
      Login("missing.user", "BadSecret!9")));
  ExpectAuthenticationFailure(real_kdf_service->Login(
      Login("Operator.One", "BadSecret!9")));

  ASSERT_EQ(observed.size(), 2U);
  EXPECT_EQ(observed[0], observed[1]);
  EXPECT_EQ(observed[0].algorithm, "pbkdf2-hmac-sha256");
  EXPECT_EQ(observed[0].iterations, kPasswordKdfIterations);
  EXPECT_EQ(observed[0].salt_size, kPasswordSaltBytes);
  EXPECT_EQ(observed[0].derived_size, kPasswordDerivedBytes);
}

TEST_F(AuthServiceTest, RequiresOperationalStateAndRegisteredNormalizedPeer) {
  const auto wrong_peer =
      service_->Login(Login("Operator.One", "NorthStar!9", "192.0.2.11"));
  ExpectAuthenticationFailure(wrong_peer);

  TemporaryDirectory default_root;
  auto default_store =
      SecurityStore::Open({default_root.path() / "security"});
  ASSERT_TRUE(default_store.ok()) << default_store.error().message;
  AuthServiceDependencies dependencies;
  dependencies.now_seconds = [this] { return now_seconds_; };
  dependencies.verify_password =
      [this](const SecureBytes&, const PasswordRecord&) {
        ++kdf_calls_;
        return common::Result<bool>::Ok(true);
      };
  auto default_service = AuthServiceTestAccess::Create(
      *default_store.value(), std::move(dependencies));
  const auto default_login = default_service->Login(Login());
  ExpectAuthenticationFailure(default_login);

  auto ipv6_store = SecurityStore::Open(
      {temporary_.path() / "ipv6-security"});
  ASSERT_TRUE(ipv6_store.ok()) << ipv6_store.error().message;
  ASSERT_TRUE(ipv6_store.value()
                  ->InitializeDevice(AdministratorRecord("2001:db8::10"), [] {
                    return common::Result<void>::Ok();
                  })
                  .ok());
  AuthServiceDependencies ipv6_dependencies;
  ipv6_dependencies.now_seconds = [this] { return now_seconds_; };
  ipv6_dependencies.random_bytes = [](std::size_t size) {
    return common::Result<SecureBytes>::Ok(FilledBytes(size, 0x55U));
  };
  ipv6_dependencies.verify_password =
      [](const SecureBytes&, const PasswordRecord&) {
        return common::Result<bool>::Ok(true);
      };
  auto ipv6_service = AuthServiceTestAccess::Create(
      *ipv6_store.value(), std::move(ipv6_dependencies));
  EXPECT_TRUE(ipv6_service
                  ->Login(Login("Operator.One", "NorthStar!9",
                                "2001:0db8:0:0:0:0:0:10"))
                  .ok());
}

TEST_F(AuthServiceTest, DisabledAccountUsesGenericFailure) {
  ExecuteSql(store_->database_path(), "UPDATE users SET enabled = 0;");

  const auto result = service_->Login(Login());

  ExpectAuthenticationFailure(result);
  EXPECT_EQ(kdf_calls_, 1);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT failed_login_count FROM users;"),
            0);
}

TEST_F(AuthServiceTest, ViewerLoginAndVerificationUseStoredRole) {
  ExecuteSql(
      store_->database_path(),
      "INSERT INTO users "
      "(canonical_username, display_username, role, enabled, "
      "password_algorithm, password_iterations, password_salt, "
      "password_derived, password_changed_at_seconds, failed_login_count, "
      "created_at_seconds) VALUES "
      "('viewer.one', 'Viewer.One', 'viewer', 1, "
      "'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), "
      "1720000000, 0, 1720000000);");

  auto viewer = service_->Login(Login("Viewer.One"));

  ASSERT_TRUE(viewer.ok()) << viewer.error().message;
  EXPECT_EQ(viewer.value().role, UserRole::kViewer);
  auto principal = service_->Verify(
      {viewer.value().session_token.data(), viewer.value().session_token.size()},
      "192.0.2.10");
  ASSERT_TRUE(principal.ok()) << principal.error().message;
  EXPECT_EQ(principal.value().role, UserRole::kViewer);
  EXPECT_EQ(principal.value().username, "Viewer.One");
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_succeeded' AND detail_code = "
                     "'authenticated_login';"),
            1);

  auto administrator = service_->Login(Login());
  ASSERT_TRUE(administrator.ok()) << administrator.error().message;
  EXPECT_EQ(administrator.value().role, UserRole::kAdministrator);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            2);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions WHERE role = "
                     "'administrator';"),
            1);
}

TEST_F(AuthServiceTest, FifthFailureLocksForExactFiveMinutesAndLogsOnce) {
  for (int attempt = 1; attempt <= 4; ++attempt) {
    ExpectAuthenticationFailure(
        service_->Login(Login("Operator.One", "BadSecret!9")));
    EXPECT_EQ(QueryInt(store_->database_path(),
                       "SELECT failed_login_count FROM users;"),
              attempt);
    EXPECT_TRUE(HighSeverityLogs().empty());
  }

  ExpectAuthenticationFailure(
      service_->Login(Login("Operator.One", "BadSecret!9")));
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT failed_login_count FROM users;"),
            5);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_limit_reached';"),
            1);
  ASSERT_TRUE(WaitForHighSeverityLogCount(1U));
  const auto lockout_logs = HighSeverityLogs();
  ASSERT_EQ(lockout_logs.size(), 1U);
  EXPECT_EQ(lockout_logs.front(),
            "authentication_limit_reached|192.0.2.10");

  now_seconds_ += 299;
  ExpectAuthenticationFailure(service_->Login(Login()));
  now_seconds_ += 1;
  EXPECT_TRUE(service_->Login(Login()).ok());
}

TEST_F(AuthServiceTest, FailureCounterSaturatesAtFiveAndLocksExactlyOnce) {
  ExecuteSql(store_->database_path(),
             "UPDATE users SET failed_login_count = 5, "
             "lock_until_seconds = NULL;");

  const auto result =
      service_->Login(Login("Operator.One", "BadSecret!9"));

  ExpectAuthenticationFailure(result);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT failed_login_count FROM users;"),
            5);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM users WHERE lock_until_seconds = "
                     "1720000400;"),
            1);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_limit_reached';"),
            1);
  EXPECT_TRUE(WaitForHighSeverityLogCount(1U));
  EXPECT_EQ(HighSeverityLogs().size(), 1U);
}

TEST_F(AuthServiceTest, ReopenRejectsMalformedUnboundedFailureCounter) {
  service_.reset();
  const auto database_path = store_->database_path();
  store_.reset();
  ExecuteSql(database_path,
             "PRAGMA ignore_check_constraints = ON; "
             "UPDATE users SET failed_login_count = 2147483647;");

  auto reopened = SecurityStore::Open({temporary_.path() / "security"});

  ASSERT_FALSE(reopened.ok());
  EXPECT_EQ(reopened.error().code, "E_SECURITY_DB_SCHEMA");
}

TEST_F(AuthServiceTest, SuccessfulAuthenticationResetsFailureState) {
  for (int attempt = 0; attempt < 4; ++attempt) {
    ExpectAuthenticationFailure(
        service_->Login(Login("Operator.One", "BadSecret!9")));
  }

  const auto result = service_->Login(Login());

  ASSERT_TRUE(result.ok()) << result.error().message;
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT failed_login_count FROM users;"),
            0);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM users WHERE lock_until_seconds "
                     "IS NULL;"),
            1);
}

TEST_F(AuthServiceTest, SessionStoresOnlyHashAndDuplicateLoginIsGeneric) {
  auto first = service_->Login(Login());
  ASSERT_TRUE(first.ok()) << first.error().message;
  ASSERT_EQ(first.value().session_token.size(), 32U);
  const std::string raw_token = StringFromBytes(first.value().session_token);

  const auto duplicate = service_->Login(Login());

  ExpectAuthenticationFailure(duplicate);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            1);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT length(token_hash) FROM sessions;"),
            32);
  EXPECT_FALSE(StateDirectoryContains(temporary_.path() / "security",
                                      raw_token));
  EXPECT_FALSE(StateDirectoryContains(temporary_.path() / "security",
                                      "NorthStar!9"));
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE detail_code = "
                     "'active_administrator_session';"),
            1);
}

TEST_F(AuthServiceTest, VerifyIsPeerBoundAndRefreshesSlidingIdleDeadline) {
  auto login = service_->Login(Login());
  ASSERT_TRUE(login.ok()) << login.error().message;
  const auto token = std::span<const unsigned char>(
      login.value().session_token.data(), login.value().session_token.size());
  EXPECT_EQ(login.value().idle_expires_at_seconds, now_seconds_ + 600);

  now_seconds_ += 599;
  auto principal = service_->Verify(token, "192.0.2.10");
  ASSERT_TRUE(principal.ok()) << principal.error().message;
  EXPECT_EQ(principal.value().username, "Operator.One");
  EXPECT_EQ(QueryText(store_->database_path(),
                      "SELECT last_activity_at_seconds || '|' || "
                      "expires_at_seconds FROM sessions;"),
            std::to_string(now_seconds_) + "|" +
                std::to_string(now_seconds_ + 600));

  now_seconds_ += 1;
  EXPECT_FALSE(service_->Verify(token, "192.0.2.11").ok());
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT expires_at_seconds FROM sessions;"),
            static_cast<int>(now_seconds_ + 599));

  now_seconds_ += 599;
  EXPECT_FALSE(service_->Verify(token, "192.0.2.10").ok());
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            0);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'session_expired';"),
            1);
}

TEST_F(AuthServiceTest, LogoutRequiresExactPeerAndInvalidatesAtomically) {
  auto login = service_->Login(Login());
  ASSERT_TRUE(login.ok()) << login.error().message;
  const auto token = std::span<const unsigned char>(
      login.value().session_token.data(), login.value().session_token.size());

  EXPECT_FALSE(service_->Logout(token, "192.0.2.11").ok());
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            1);
  ASSERT_TRUE(service_->Logout(token, "192.0.2.10").ok());
  EXPECT_FALSE(service_->Verify(token, "192.0.2.10").ok());
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            0);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'session_logout';"),
            1);
}

TEST_F(AuthServiceTest, ExpiredSessionIsRemovedBeforeNextLogin) {
  auto first = service_->Login(Login());
  ASSERT_TRUE(first.ok()) << first.error().message;
  const std::string first_token = StringFromBytes(first.value().session_token);

  now_seconds_ += 600;
  auto second = service_->Login(Login());

  ASSERT_TRUE(second.ok()) << second.error().message;
  EXPECT_NE(StringFromBytes(second.value().session_token), first_token);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            1);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'session_expired';"),
            1);
}

TEST_F(AuthServiceTest, TokenCollisionRetriesThenCreatesUniqueSession) {
  ExecuteSql(
      store_->database_path(),
      "INSERT INTO users "
      "(canonical_username, display_username, role, enabled, "
      "password_algorithm, password_iterations, password_salt, "
      "password_derived, password_changed_at_seconds, failed_login_count, "
      "created_at_seconds) VALUES "
      "('viewer.one', 'Viewer.One', 'viewer', 1, "
      "'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), "
      "1720000000, 0, 1720000000);");
  auto viewer = service_->Login(Login("Viewer.One"));
  ASSERT_TRUE(viewer.ok()) << viewer.error().message;
  random_calls_ = 0;

  auto administrator = service_->Login(Login());

  ASSERT_TRUE(administrator.ok()) << administrator.error().message;
  EXPECT_EQ(random_calls_, 2);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(DISTINCT token_hash) FROM sessions;"),
            2);
}

TEST_F(AuthServiceTest,
       RepeatedTokenCollisionIsGenericWithoutSessionOrSuccessAuditLeak) {
  ExecuteSql(
      store_->database_path(),
      "INSERT INTO users "
      "(canonical_username, display_username, role, enabled, "
      "password_algorithm, password_iterations, password_salt, "
      "password_derived, password_changed_at_seconds, failed_login_count, "
      "created_at_seconds) VALUES "
      "('viewer.one', 'Viewer.One', 'viewer', 1, "
      "'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), "
      "1720000000, 0, 1720000000);");
  auto viewer = service_->Login(Login("Viewer.One"));
  ASSERT_TRUE(viewer.ok()) << viewer.error().message;
  const int audit_count_before = QueryInt(
      store_->database_path(), "SELECT COUNT(*) FROM audit_events;");
  AuthServiceDependencies dependencies;
  dependencies.now_seconds = [this] { return now_seconds_; };
  dependencies.random_bytes = [](std::size_t size) {
    return common::Result<SecureBytes>::Ok(FilledBytes(size, 0x41U));
  };
  dependencies.verify_password =
      [](const SecureBytes&, const PasswordRecord&) {
        return common::Result<bool>::Ok(true);
      };
  auto collision_service = AuthServiceTestAccess::Create(
      *store_, std::move(dependencies));

  const auto result = collision_service->Login(Login());

  ExpectAuthenticationFailure(result);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            1);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions WHERE role = "
                     "'administrator';"),
            0);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events;"),
            audit_count_before + 1);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_succeeded';"),
            1);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE detail_code "
                     "LIKE '%token%';"),
            0);
}

TEST_F(AuthServiceTest, BackwardClockCannotRefreshOrBypassSessionExpiry) {
  auto login = service_->Login(Login());
  ASSERT_TRUE(login.ok()) << login.error().message;
  const auto token = std::span<const unsigned char>(
      login.value().session_token.data(), login.value().session_token.size());
  const auto original_expiry = login.value().idle_expires_at_seconds;

  --now_seconds_;
  auto backward = service_->Verify(token, "192.0.2.10");
  ASSERT_FALSE(backward.ok());
  EXPECT_EQ(backward.error().code, "E_AUTHENTICATION_UNAVAILABLE");
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT expires_at_seconds FROM sessions;"),
            static_cast<int>(original_expiry));

  now_seconds_ = original_expiry;
  auto expired = service_->Verify(token, "192.0.2.10");
  ASSERT_FALSE(expired.ok());
  EXPECT_EQ(expired.error().code, "E_AUTHENTICATION_FAILED");
  EXPECT_EQ(expired.error().message, "authentication failed");
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            0);
}

TEST_F(AuthServiceTest, BackwardClockBeforeUserCreationFailsClosed) {
  now_seconds_ = 1719999999;

  const auto result = service_->Login(Login());

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_AUTHENTICATION_UNAVAILABLE");
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            0);
}

TEST_F(AuthServiceTest, BackwardClockCannotShortenOrBypassAccountLock) {
  for (int attempt = 0; attempt < 5; ++attempt) {
    ExpectAuthenticationFailure(
        service_->Login(Login("Operator.One", "BadSecret!9")));
  }
  now_seconds_ -= 100;

  ExpectAuthenticationFailure(service_->Login(Login()));
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT lock_until_seconds FROM users;"),
            1720000400);
  now_seconds_ = 1720000400;
  EXPECT_TRUE(service_->Login(Login()).ok());
}

TEST_F(AuthServiceTest, ConcurrentAdministratorLoginsHaveExactlyOneWinner) {
  std::atomic<int> random_sequence{0};
  std::atomic<int> kdf_calls{0};
  AuthServiceDependencies dependencies;
  dependencies.now_seconds = [this] { return now_seconds_; };
  dependencies.random_bytes = [&random_sequence](std::size_t size) {
    const int sequence = ++random_sequence;
    return common::Result<SecureBytes>::Ok(
        FilledBytes(size, static_cast<unsigned char>(0x60 + sequence)));
  };
  dependencies.verify_password = [&kdf_calls](const SecureBytes&,
                                               const PasswordRecord&) {
    ++kdf_calls;
    return common::Result<bool>::Ok(true);
  };
  auto concurrent_service = AuthServiceTestAccess::Create(
      *store_, std::move(dependencies));
  std::barrier start(3);
  std::array<std::optional<common::Result<LoginResult>>, 2> results;
  std::array<std::thread, 2> workers;
  for (std::size_t index = 0; index < workers.size(); ++index) {
    workers[index] = std::thread([&, index] {
      start.arrive_and_wait();
      results[index].emplace(concurrent_service->Login(Login()));
    });
  }
  start.arrive_and_wait();
  for (auto& worker : workers) {
    worker.join();
  }

  const int winners = static_cast<int>(results[0]->ok()) +
                      static_cast<int>(results[1]->ok());
  EXPECT_EQ(winners, 1);
  EXPECT_EQ(kdf_calls.load(), 2);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            1);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_succeeded';"),
            1);
}

TEST_F(AuthServiceTest,
       IndependentStoresCompleteKdfBeforeSingleWinnerDecision) {
  auto second_store =
      SecurityStore::Open({temporary_.path() / "security"});
  ASSERT_TRUE(second_store.ok()) << second_store.error().message;
  TimedBarrier kdf_barrier(2);
  std::atomic<int> barrier_timeouts{0};
  const auto dependencies = [&](unsigned char token_byte) {
    AuthServiceDependencies value;
    value.now_seconds = [this] { return now_seconds_; };
    value.random_bytes = [token_byte](std::size_t size) {
      return common::Result<SecureBytes>::Ok(FilledBytes(size, token_byte));
    };
    value.verify_password = [&](const SecureBytes&, const PasswordRecord&) {
      if (!kdf_barrier.ArriveAndWait(std::chrono::milliseconds(1500))) {
        ++barrier_timeouts;
      }
      return common::Result<bool>::Ok(true);
    };
    return value;
  };
  auto first_service =
      AuthServiceTestAccess::Create(*store_, dependencies(0x81U));
  auto second_service = AuthServiceTestAccess::Create(
      *second_store.value(), dependencies(0x82U));
  std::barrier start(3);
  std::array<std::optional<common::Result<LoginResult>>, 2> results;
  std::thread first([&] {
    start.arrive_and_wait();
    results[0].emplace(first_service->Login(Login()));
  });
  std::thread second([&] {
    start.arrive_and_wait();
    results[1].emplace(second_service->Login(Login()));
  });
  start.arrive_and_wait();
  first.join();
  second.join();

  EXPECT_EQ(barrier_timeouts.load(), 0);
  const int winners = static_cast<int>(results[0]->ok()) +
                      static_cast<int>(results[1]->ok());
  EXPECT_EQ(winners, 1);
  const auto& rejected = results[0]->ok() ? *results[1] : *results[0];
  ASSERT_FALSE(rejected.ok());
  EXPECT_EQ(rejected.error().code, "E_AUTHENTICATION_FAILED");
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions WHERE role = "
                     "'administrator';"),
            1);
}

TEST_F(AuthServiceTest,
       ParallelWrongPasswordsCountFiveAndEmitOneCommittedLockout) {
  service_.reset();
  constexpr std::size_t kAttempts = 6U;
  std::vector<std::unique_ptr<SecurityStore>> additional_stores;
  std::array<SecurityStore*, kAttempts> stores{};
  stores[0] = store_.get();
  for (std::size_t index = 1; index < kAttempts; ++index) {
    auto opened = SecurityStore::Open({temporary_.path() / "security"});
    ASSERT_TRUE(opened.ok()) << opened.error().message;
    additional_stores.push_back(std::move(opened).value());
    stores[index] = additional_stores.back().get();
  }

  TimedBarrier kdf_barrier(static_cast<int>(kAttempts));
  std::atomic<int> barrier_timeouts{0};
  std::atomic<int> lockout_logs{0};
  std::atomic<int> invalid_logs{0};
  std::vector<std::unique_ptr<AuthService>> services;
  services.reserve(kAttempts);
  for (std::size_t index = 0; index < kAttempts; ++index) {
    AuthServiceDependencies dependencies;
    dependencies.now_seconds = [this] { return now_seconds_; };
    dependencies.verify_password =
        [&](const SecureBytes&, const PasswordRecord&) {
          if (!kdf_barrier.ArriveAndWait(std::chrono::milliseconds(3000))) {
            ++barrier_timeouts;
          }
          return common::Result<bool>::Ok(false);
        };
    dependencies.high_severity_log =
        [&](std::string_view category, std::string_view normalized_peer) {
          if (category == "authentication_limit_reached" &&
              normalized_peer == "192.0.2.10") {
            ++lockout_logs;
          } else {
            ++invalid_logs;
          }
        };
    services.push_back(AuthServiceTestAccess::Create(
        *stores[index], std::move(dependencies)));
  }

  std::array<std::optional<common::Result<LoginResult>>, kAttempts> results;
  std::array<std::thread, kAttempts> workers;
  for (std::size_t index = 0; index < kAttempts; ++index) {
    workers[index] = std::thread([&, index] {
      results[index].emplace(
          services[index]->Login(Login("Operator.One", "BadSecret!9")));
    });
  }
  for (auto& worker : workers) {
    worker.join();
  }
  services.clear();

  EXPECT_EQ(barrier_timeouts.load(), 0);
  for (const auto& result : results) {
    ASSERT_TRUE(result.has_value());
    ExpectAuthenticationFailure(*result);
  }
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT failed_login_count FROM users;"),
            5);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_limit_reached';"),
            1);
  EXPECT_EQ(lockout_logs.load(), 1);
  EXPECT_EQ(invalid_logs.load(), 0);
}

TEST_F(AuthServiceTest,
       LockoutLoggerRunsAsynchronouslyAndDestructorDrains) {
  service_.reset();
  BlockingLogger logger;
  AuthServiceDependencies dependencies;
  dependencies.now_seconds = [this] { return now_seconds_; };
  dependencies.verify_password =
      [](const SecureBytes&, const PasswordRecord&) {
        return common::Result<bool>::Ok(false);
      };
  dependencies.high_severity_log =
      [&logger](std::string_view category, std::string_view normalized_peer) {
        logger.Invoke(category, normalized_peer);
      };
  auto async_service = AuthServiceTestAccess::Create(
      *store_, std::move(dependencies));
  for (int attempt = 0; attempt < 4; ++attempt) {
    ExpectAuthenticationFailure(
        async_service->Login(Login("Operator.One", "BadSecret!9")));
  }

  std::thread::id login_thread;
  auto fifth = std::async(std::launch::async, [&] {
    login_thread = std::this_thread::get_id();
    return async_service->Login(Login("Operator.One", "BadSecret!9"));
  });
  ASSERT_TRUE(logger.WaitUntilStarted(std::chrono::milliseconds(2000)));
  const bool returned_before_release =
      fifth.wait_for(std::chrono::milliseconds(500)) ==
      std::future_status::ready;
  EXPECT_TRUE(returned_before_release);
  if (!returned_before_release) {
    logger.Release();
    (void)fifth.get();
    async_service.reset();
    return;
  }

  auto result = fifth.get();
  ExpectAuthenticationFailure(result);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_limit_reached';"),
            1);
  EXPECT_EQ(logger.calls(), 1);
  EXPECT_EQ(logger.category(), "authentication_limit_reached");
  EXPECT_EQ(logger.peer(), "192.0.2.10");
  EXPECT_NE(logger.callback_thread(), login_thread);

  auto destruction = std::async(std::launch::async, [&] {
    async_service.reset();
  });
  EXPECT_EQ(destruction.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  logger.Release();
  EXPECT_EQ(destruction.wait_for(std::chrono::milliseconds(2000)),
            std::future_status::ready);
  destruction.get();
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM firmware_log_outbox;"),
            0);
}

TEST_F(AuthServiceTest,
       BlockedLoggerCannotPreventRepeatedLockoutCommits) {
  service_.reset();
  BlockingLogger logger;
  AuthServiceDependencies dependencies;
  dependencies.now_seconds = [this] { return now_seconds_; };
  std::atomic<unsigned char> token_byte{0x80U};
  dependencies.random_bytes = [&token_byte](std::size_t size) {
    return common::Result<SecureBytes>::Ok(
        FilledBytes(size, ++token_byte));
  };
  dependencies.verify_password =
      [](const SecureBytes& password, const PasswordRecord&) {
        const auto expected = Bytes("NorthStar!9");
        return common::Result<bool>::Ok(
            password.size() == expected.size() &&
            std::equal(password.data(), password.data() + password.size(),
                       expected.data()));
      };
  dependencies.high_severity_log =
      [&logger](std::string_view category, std::string_view normalized_peer) {
        logger.Invoke(category, normalized_peer);
      };
  auto durable_service = AuthServiceTestAccess::Create(
      *store_, std::move(dependencies));
  BlockingLoggerReleaseGuard release_guard(logger);

  for (int attempt = 0; attempt < 5; ++attempt) {
    ExpectAuthenticationFailure(
        durable_service->Login(Login("Operator.One", "BadSecret!9")));
  }
  ASSERT_TRUE(logger.WaitUntilStarted(std::chrono::milliseconds(2000)));

  for (int cycle = 1; cycle < 9; ++cycle) {
    now_seconds_ += 300;
    auto login = durable_service->Login(Login());
    EXPECT_TRUE(login.ok()) << login.error().message;
    if (!login.ok()) {
      break;
    }
    EXPECT_TRUE(durable_service
                    ->Logout({login.value().session_token.data(),
                              login.value().session_token.size()},
                             "192.0.2.10")
                    .ok());
    for (int attempt = 0; attempt < 5; ++attempt) {
      ExpectAuthenticationFailure(
          durable_service->Login(Login("Operator.One", "BadSecret!9")));
    }
  }

  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT failed_login_count FROM users;"),
            5);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_limit_reached';"),
            9);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM firmware_log_outbox WHERE "
                     "category = 'authentication_limit_reached' AND "
                     "peer_ip = '192.0.2.10';"),
            1);
  ExpectAuthenticationFailure(durable_service->Login(Login()));
}

TEST_F(AuthServiceTest, PendingLockoutLogSurvivesServiceAndStoreRestart) {
  service_.reset();
  AuthServiceDependencies disabled_worker_dependencies;
  disabled_worker_dependencies.now_seconds = [this] { return now_seconds_; };
  disabled_worker_dependencies.verify_password =
      [](const SecureBytes&, const PasswordRecord&) {
        return common::Result<bool>::Ok(false);
      };
  disabled_worker_dependencies.firmware_log_random_bytes =
      [](std::size_t) {
        return common::Result<SecureBytes>::Err(
            {"E_TEST_RANDOM", "test worker unavailable"});
      };
  auto disabled_worker = AuthServiceTestAccess::Create(
      *store_, std::move(disabled_worker_dependencies));
  for (int attempt = 0; attempt < 5; ++attempt) {
    ExpectAuthenticationFailure(
        disabled_worker->Login(Login("Operator.One", "BadSecret!9")));
  }
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM firmware_log_outbox;"),
            1);

  disabled_worker.reset();
  store_.reset();
  auto reopened = SecurityStore::Open({temporary_.path() / "security"});
  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  store_ = std::move(reopened).value();
  CountingLogger logger;
  AuthServiceDependencies recovery_dependencies;
  recovery_dependencies.now_seconds = [this] { return now_seconds_; };
  recovery_dependencies.high_severity_log =
      [&logger](std::string_view category, std::string_view peer) {
        (void)logger.Record(category, peer);
      };
  auto recovery = AuthServiceTestAccess::Create(
      *store_, std::move(recovery_dependencies));

  ASSERT_TRUE(logger.WaitForCalls(1, std::chrono::milliseconds(2000)));
  recovery.reset();
  EXPECT_EQ(logger.calls(), 1);
  EXPECT_EQ(logger.category(), "authentication_limit_reached");
  EXPECT_EQ(logger.peer(), "192.0.2.10");
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM firmware_log_outbox;"),
            0);
}

TEST_F(AuthServiceTest, LoggerExceptionReleasesLeaseAndRetriesWithoutLoss) {
  service_.reset();
  CountingLogger logger;
  AuthServiceDependencies dependencies;
  dependencies.now_seconds = [this] { return now_seconds_; };
  dependencies.verify_password =
      [](const SecureBytes&, const PasswordRecord&) {
        return common::Result<bool>::Ok(false);
      };
  dependencies.high_severity_log =
      [&logger](std::string_view category, std::string_view peer) {
        if (logger.Record(category, peer) == 1) {
          throw std::runtime_error("injected logger failure");
        }
      };
  auto retrying_service =
      AuthServiceTestAccess::Create(*store_, std::move(dependencies));
  for (int attempt = 0; attempt < 5; ++attempt) {
    ExpectAuthenticationFailure(
        retrying_service->Login(Login("Operator.One", "BadSecret!9")));
  }

  ASSERT_TRUE(logger.WaitForCalls(2, std::chrono::milliseconds(2000)));
  retrying_service.reset();
  EXPECT_EQ(logger.calls(), 2);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM firmware_log_outbox;"),
            0);
}

TEST_F(AuthServiceTest, IndependentWorkersDoNotShareOneLiveLease) {
  service_.reset();
  AuthServiceDependencies seed_dependencies;
  seed_dependencies.now_seconds = [this] { return now_seconds_; };
  seed_dependencies.verify_password =
      [](const SecureBytes&, const PasswordRecord&) {
        return common::Result<bool>::Ok(false);
      };
  seed_dependencies.firmware_log_random_bytes = [](std::size_t) {
    return common::Result<SecureBytes>::Err(
        {"E_TEST_RANDOM", "test worker unavailable"});
  };
  auto seed = AuthServiceTestAccess::Create(*store_,
                                            std::move(seed_dependencies));
  for (int attempt = 0; attempt < 5; ++attempt) {
    ExpectAuthenticationFailure(
        seed->Login(Login("Operator.One", "BadSecret!9")));
  }
  seed.reset();

  auto second_store = SecurityStore::Open({temporary_.path() / "security"});
  ASSERT_TRUE(second_store.ok()) << second_store.error().message;
  BlockingLogger logger;
  BlockingLoggerReleaseGuard release_guard(logger);
  const auto dependencies = [this, &logger] {
    AuthServiceDependencies value;
    value.now_seconds = [this] { return now_seconds_; };
    value.high_severity_log =
        [&logger](std::string_view category, std::string_view peer) {
          logger.Invoke(category, peer);
        };
    return value;
  };
  auto first = AuthServiceTestAccess::Create(*store_, dependencies());
  auto second = AuthServiceTestAccess::Create(*second_store.value(),
                                               dependencies());

  ASSERT_TRUE(logger.WaitUntilStarted(std::chrono::milliseconds(2000)));
  EXPECT_EQ(logger.calls(), 1);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM firmware_log_outbox WHERE "
                     "length(lease_owner) = 16 AND length(lease_token) = 32 "
                     "AND lease_expires_at_seconds > 1720000100;"),
            1);
  logger.Release();
  first.reset();
  second.reset();
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM firmware_log_outbox;"),
            0);
}

TEST_F(AuthServiceTest, CallbackBeforeAckCrashWindowIsAtLeastOnce) {
  service_.reset();
  AuthServiceDependencies seed_dependencies;
  seed_dependencies.now_seconds = [this] { return now_seconds_; };
  seed_dependencies.verify_password =
      [](const SecureBytes&, const PasswordRecord&) {
        return common::Result<bool>::Ok(false);
      };
  seed_dependencies.firmware_log_random_bytes = [](std::size_t) {
    return common::Result<SecureBytes>::Err(
        {"E_TEST_RANDOM", "test worker unavailable"});
  };
  auto seed = AuthServiceTestAccess::Create(*store_,
                                            std::move(seed_dependencies));
  for (int attempt = 0; attempt < 5; ++attempt) {
    ExpectAuthenticationFailure(
        seed->Login(Login("Operator.One", "BadSecret!9")));
  }
  seed.reset();

  CountingLogger logger;
  AuthServiceDependencies crash_dependencies;
  crash_dependencies.now_seconds = [this] { return now_seconds_; };
  crash_dependencies.high_severity_log =
      [&logger](std::string_view category, std::string_view peer) {
        (void)logger.Record(category, peer);
      };
  auto crashing = AuthServiceTestAccess::CreateWithBeforeAck(
      *store_, std::move(crash_dependencies), [] {
        throw std::runtime_error("injected crash before ack");
      });
  ASSERT_TRUE(logger.WaitForCalls(1, std::chrono::milliseconds(2000)));
  crashing.reset();
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM firmware_log_outbox WHERE "
                     "lease_expires_at_seconds = 1720000130;"),
            1);

  now_seconds_ += 30;
  AuthServiceDependencies recovery_dependencies;
  recovery_dependencies.now_seconds = [this] { return now_seconds_; };
  recovery_dependencies.high_severity_log =
      [&logger](std::string_view category, std::string_view peer) {
        (void)logger.Record(category, peer);
      };
  auto recovery = AuthServiceTestAccess::Create(
      *store_, std::move(recovery_dependencies));
  ASSERT_TRUE(logger.WaitForCalls(2, std::chrono::milliseconds(2000)));
  recovery.reset();
  EXPECT_EQ(logger.calls(), 2);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM firmware_log_outbox;"),
            0);
}

TEST_F(AuthServiceTest, CommitFailureRollsBackSessionAuditAndCounterReset) {
  ExpectAuthenticationFailure(
      service_->Login(Login("Operator.One", "BadSecret!9")));
  const int audit_count_before = QueryInt(
      store_->database_path(), "SELECT COUNT(*) FROM audit_events;");
  ScopedTransactionFailureReset failure_reset;
  auto failing_service = DecisionFailureService(true, false);
  auto result = failing_service->Login(Login());

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_AUTHENTICATION_UNAVAILABLE");
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT failed_login_count FROM users;"),
            1);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            0);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events;"),
            audit_count_before);
}

TEST_F(AuthServiceTest, FailedFifthAttemptCommitEmitsNoLimitAuditOrLog) {
  for (int attempt = 0; attempt < 4; ++attempt) {
    ExpectAuthenticationFailure(
        service_->Login(Login("Operator.One", "BadSecret!9")));
  }
  auto failed_commit = [&] {
    ScopedTransactionFailureReset failure_reset;
    auto failing_service = DecisionFailureService(false, false);
    return failing_service->Login(Login("Operator.One", "BadSecret!9"));
  }();

  ASSERT_FALSE(failed_commit.ok());
  EXPECT_EQ(failed_commit.error().code, "E_AUTHENTICATION_UNAVAILABLE");
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT failed_login_count FROM users;"),
            4);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_limit_reached';"),
            0);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM firmware_log_outbox;"),
            0);
  EXPECT_TRUE(HighSeverityLogs().empty());

  ExpectAuthenticationFailure(
      service_->Login(Login("Operator.One", "BadSecret!9")));
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events WHERE event_type = "
                     "'authentication_limit_reached';"),
            1);
  EXPECT_TRUE(WaitForHighSeverityLogCount(1U));
  EXPECT_EQ(HighSeverityLogs().size(), 1U);
}

TEST_F(AuthServiceTest, RollbackFailurePoisonsStoreAndDiscardsDecision) {
  ScopedTransactionFailureReset failure_reset;
  auto failing_service = DecisionFailureService(false, true);
  auto result =
      failing_service->Login(Login("Operator.One", "BadSecret!9"));

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_AUTHENTICATION_UNAVAILABLE");
  auto state = store_->State();
  ASSERT_FALSE(state.ok());
  EXPECT_EQ(state.error().code, "E_SECURITY_DB_POISONED");
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT failed_login_count FROM users;"),
            0);
  EXPECT_EQ(QueryInt(store_->database_path(),
                     "SELECT COUNT(*) FROM audit_events;"),
            1);
}

TEST_F(AuthServiceTest, SchemaValidationAcceptsCommittedSessionAndAuditRows) {
  auto login = service_->Login(Login());
  ASSERT_TRUE(login.ok()) << login.error().message;
  service_.reset();
  store_.reset();

  auto reopened = SecurityStore::Open({temporary_.path() / "security"});

  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  EXPECT_EQ(QueryInt(reopened.value()->database_path(),
                     "SELECT COUNT(*) FROM sessions;"),
            1);
}

TEST_F(AuthServiceTest, AuditAndHighSeverityLogContainNoSubmittedSecrets) {
  const std::string submitted_username = "Submitted.Secret.User";
  const std::string submitted_password = "SubmittedPassword!9";
  ExpectAuthenticationFailure(service_->Login(
      Login(submitted_username, submitted_password, "192.0.2.10")));
  for (int attempt = 0; attempt < 5; ++attempt) {
    ExpectAuthenticationFailure(service_->Login(
        Login("Operator.One", submitted_password, "192.0.2.10")));
  }
  ASSERT_TRUE(WaitForHighSeverityLogCount(1U));

  const std::string audit = QueryText(
      store_->database_path(),
      "SELECT group_concat(event_type || '|' || outcome || '|' || peer_ip "
      "|| '|' || detail_code, ',') FROM audit_events;");
  EXPECT_EQ(audit.find(submitted_username), std::string::npos);
  EXPECT_EQ(audit.find(submitted_password), std::string::npos);
  const std::string outbox = QueryText(
      store_->database_path(),
      "SELECT group_concat(category || '|' || peer_ip || '|' || "
      "created_at_seconds, ',') FROM firmware_log_outbox;");
  EXPECT_EQ(outbox.find(submitted_username), std::string::npos);
  EXPECT_EQ(outbox.find(submitted_password), std::string::npos);
  for (const auto& log : HighSeverityLogs()) {
    EXPECT_EQ(log.find(submitted_username), std::string::npos);
    EXPECT_EQ(log.find(submitted_password), std::string::npos);
  }
  EXPECT_FALSE(StateDirectoryContains(temporary_.path() / "security",
                                      submitted_username));
  EXPECT_FALSE(StateDirectoryContains(temporary_.path() / "security",
                                      submitted_password));
}

}  // namespace
}  // namespace camera_firmware::security
