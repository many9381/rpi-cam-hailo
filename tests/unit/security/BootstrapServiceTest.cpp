#include "camera_firmware/security/BootstrapService.hpp"

#include <algorithm>
#include <array>
#include <barrier>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/rtsp/RtspDigestCredentials.hpp"
#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"
#include "camera_firmware/security/PasswordHasher.hpp"
#include "camera_firmware/security/PasswordPolicy.hpp"
#include "camera_firmware/security/SecurityStore.hpp"

void ConfigureSecurityStoreTransactionFailuresForTest(bool commit,
                                                       bool rollback);

namespace camera_firmware::security {
namespace {

using common::SecureBytes;
using rtsp::RtspDigestAlgorithm;
using rtsp::RtspDigestConstantTimeEqual;
using rtsp::RtspDigestCredentialPolicy;
using rtsp::RtspDigestCredentialStore;

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 48> pattern{"/tmp/cf-bootstrap-service-XXXXXX"};
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

SecureBytes Bytes(std::string_view value) {
  SecureBytes bytes;
  bytes.assign(reinterpret_cast<const unsigned char*>(value.data()),
               value.size());
  return bytes;
}

std::string StringFromBytes(const SecureBytes& bytes) {
  return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

std::vector<std::string_view> ReservedViews(
    const std::vector<std::string>& identities) {
  std::vector<std::string_view> views;
  views.reserve(identities.size());
  for (const auto& identity : identities) {
    views.emplace_back(identity);
  }
  return views;
}

config::AppConfig BootstrapConfig(const std::filesystem::path& state,
                                  const std::filesystem::path& credential) {
  config::AppConfig config;
  config.camera.id = "imx708-main";
  config.security.state_directory = state.string();
  config.secure_rtsp.client_auth.enabled = true;
  config.secure_rtsp.client_auth.realm = "rpi-camera";
  config.secure_rtsp.client_auth.credential_file = credential.string();
  config.secure_rtsp.client_auth.algorithms = {"sha-256"};
  return config;
}

BootstrapRequest Request(std::string username,
                         std::string_view password,
                         std::string confirmed_peer,
                         std::string actual_peer) {
  return {std::move(username), Bytes(password), std::move(confirmed_peer),
          std::move(actual_peer)};
}

BootstrapRequest RequestWithIps(std::string username,
                                std::string_view password,
                                std::string confirmed_peer,
                                std::string actual_peer,
                                std::vector<std::string> management_ips) {
  return {std::move(username), Bytes(password), std::move(confirmed_peer),
          std::move(actual_peer), std::move(management_ips)};
}

mode_t FileMode(const std::filesystem::path& path) {
  struct stat status {};
  if (::lstat(path.c_str(), &status) != 0) {
    return 0;
  }
  return status.st_mode & 0777;
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

void ExecuteDatabaseSql(const std::filesystem::path& database_path,
                        const char* sql) {
  sqlite3* database = nullptr;
  if (::sqlite3_open_v2(database_path.c_str(), &database,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW,
                        nullptr) != SQLITE_OK) {
    if (database != nullptr) {
      (void)::sqlite3_close_v2(database);
    }
    throw std::runtime_error("failed to open test database");
  }
  char* error_message = nullptr;
  const int status = ::sqlite3_exec(database, sql, nullptr, nullptr,
                                    &error_message);
  std::string message;
  if (error_message != nullptr) {
    message = error_message;
    ::sqlite3_free(error_message);
  }
  (void)::sqlite3_close_v2(database);
  if (status != SQLITE_OK) {
    throw std::runtime_error("test database SQL failed: " + message);
  }
}

std::string QueryText(const std::filesystem::path& database_path,
                      const char* sql) {
  sqlite3* database = nullptr;
  if (::sqlite3_open_v2(database_path.c_str(), &database,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW,
                        nullptr) != SQLITE_OK) {
    if (database != nullptr) {
      (void)::sqlite3_close_v2(database);
    }
    throw std::runtime_error("failed to open test database");
  }
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_ROW) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    (void)::sqlite3_close_v2(database);
    throw std::runtime_error("failed to query test database");
  }
  const unsigned char* value = ::sqlite3_column_text(statement, 0);
  const std::string result =
      value == nullptr ? "" : reinterpret_cast<const char*>(value);
  (void)::sqlite3_finalize(statement);
  (void)::sqlite3_close_v2(database);
  return result;
}

PasswordRecord LoadPasswordRecord(const std::filesystem::path& database_path) {
  sqlite3* database = nullptr;
  if (::sqlite3_open_v2(database_path.c_str(), &database,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW,
                        nullptr) != SQLITE_OK) {
    throw std::runtime_error("failed to open test database");
  }
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "SELECT password_algorithm, password_iterations, password_salt, "
      "password_derived FROM users;";
  if (::sqlite3_prepare_v2(database, kSql, -1, &statement, nullptr) !=
          SQLITE_OK ||
      ::sqlite3_step(statement) != SQLITE_ROW) {
    if (statement != nullptr) {
      (void)::sqlite3_finalize(statement);
    }
    (void)::sqlite3_close_v2(database);
    throw std::runtime_error("failed to load password record");
  }
  PasswordRecord record;
  record.algorithm = reinterpret_cast<const char*>(
      ::sqlite3_column_text(statement, 0));
  record.iterations =
      static_cast<std::uint32_t>(::sqlite3_column_int64(statement, 1));
  const auto* salt = static_cast<const unsigned char*>(
      ::sqlite3_column_blob(statement, 2));
  const auto salt_size = static_cast<std::size_t>(
      ::sqlite3_column_bytes(statement, 2));
  const auto* derived = static_cast<const unsigned char*>(
      ::sqlite3_column_blob(statement, 3));
  const auto derived_size = static_cast<std::size_t>(
      ::sqlite3_column_bytes(statement, 3));
  record.salt.assign(salt, salt_size);
  record.derived.assign(derived, derived_size);
  (void)::sqlite3_finalize(statement);
  (void)::sqlite3_close_v2(database);
  return record;
}

class ScopedTransactionFailures {
 public:
  ScopedTransactionFailures(bool commit, bool rollback) {
    ConfigureSecurityStoreTransactionFailuresForTest(commit, rollback);
  }
  ~ScopedTransactionFailures() {
    ConfigureSecurityStoreTransactionFailuresForTest(false, false);
  }

  ScopedTransactionFailures(const ScopedTransactionFailures&) = delete;
  ScopedTransactionFailures& operator=(const ScopedTransactionFailures&) =
      delete;
};

TEST(BootstrapServiceTest,
     InitializesAdminAndLoadableSha256RtspCredentialWithoutPlaintext) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  const auto credential = state / "rtsp.credentials";
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, credential);
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto initialized = service.Initialize(Request(
      "Operator.One", "NorthStar!9", "192.0.2.10", "192.0.2.10"));

  ASSERT_TRUE(initialized.ok()) << initialized.error().message;
  EXPECT_EQ(initialized.value().state, DeviceState::kOperational);
  EXPECT_EQ(store.value()->State().value(), DeviceState::kOperational);
  EXPECT_EQ(FileMode(credential), 0600);
  EXPECT_FALSE(StateDirectoryContains(state, "NorthStar!9"));
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT canonical_username || '|' || "
                      "display_username FROM users;"),
            "operator.one|Operator.One");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT normalized_ip FROM management_ips;"),
            "192.0.2.10");
  // Two rows, not one: registering the confirming peer is a grant of
  // management access and is recorded as one, ahead of the completion record.
  // Widened from asserting only the first row so the whole trail is pinned.
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT group_concat(event_type || '|' || outcome || "
                      "'|' || peer_ip || '|' || subject_identity, ' ') "
                      "FROM (SELECT * FROM audit_events ORDER BY sequence);"),
            "management_ip_created|success|192.0.2.10|192.0.2.10 "
            "bootstrap_completed|success|192.0.2.10|");

  auto credential_store = RtspDigestCredentialStore::Create(
      RtspDigestCredentialPolicy{config.secure_rtsp.client_auth.realm,
                                 {RtspDigestAlgorithm::kSha256}});
  ASSERT_TRUE(credential_store.ok()) << credential_store.error().message;
  ASSERT_TRUE(credential_store.value()->Reload(credential).ok());
  auto lookup = credential_store.value()->Lookup(
      "Operator.One", RtspDigestAlgorithm::kSha256);
  auto rtsp_password = Bytes("NorthStar!9");
  auto expected = rtsp::ComputeRtspDigestHa1(
      RtspDigestAlgorithm::kSha256, "Operator.One",
      config.secure_rtsp.client_auth.realm,
      {rtsp_password.data(), rtsp_password.size()});
  ASSERT_TRUE(lookup.ok()) << lookup.error().message;
  ASSERT_TRUE(expected.ok()) << expected.error().message;
  EXPECT_TRUE(lookup.value().matched);
  EXPECT_TRUE(RtspDigestConstantTimeEqual(
      {lookup.value().ha1.data(), lookup.value().ha1.size()},
      {expected.value().data(), expected.value().size()}));
  EXPECT_EQ(ReadFile(credential).find(":md5:"), std::string::npos);

  auto password_record = LoadPasswordRecord(store.value()->database_path());
  auto verified = VerifyPassword(Bytes("NorthStar!9"), password_record);
  ASSERT_TRUE(verified.ok()) << verified.error().message;
  EXPECT_TRUE(verified.value());
}

TEST(BootstrapServiceTest, NormalizesEquivalentIpv6ToExactStoredPeer) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto initialized = service.Initialize(Request(
      "operator.one", "NorthStar!9", "2001:0db8:0:0:0:0:0:1",
      "2001:db8::1"));

  ASSERT_TRUE(initialized.ok()) << initialized.error().message;
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT normalized_ip FROM management_ips;"),
            "2001:db8::1");
}

TEST(BootstrapServiceTest, ReplacesStaleCredentialWithOnlyNewSha256Admin) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  const auto credential = state / "rtsp.credentials";
  auto config = BootstrapConfig(state, credential);
  rtsp::RtspDigestProvisionRequest stale_sha{
      credential, "stale-user", config.secure_rtsp.client_auth.realm,
      RtspDigestAlgorithm::kSha256, true};
  rtsp::RtspDigestProvisionRequest stale_md5{
      credential, "stale-user", config.secure_rtsp.client_auth.realm,
      RtspDigestAlgorithm::kMd5, true};
  auto stale_password = Bytes("stale-password");
  ASSERT_TRUE(rtsp::ProvisionRtspDigestCredential(
                  stale_sha,
                  {stale_password.data(), stale_password.size()})
                  .ok());
  ASSERT_TRUE(rtsp::ProvisionRtspDigestCredential(
                  stale_md5,
                  {stale_password.data(), stale_password.size()})
                  .ok());
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto initialized = service.Initialize(Request(
      "operator.one", "NorthStar!9", "192.0.2.10", "192.0.2.10"));

  ASSERT_TRUE(initialized.ok()) << initialized.error().message;
  const std::string installed = ReadFile(credential);
  EXPECT_EQ(installed.find("stale-user"), std::string::npos);
  EXPECT_EQ(installed.find(":md5:"), std::string::npos);
  EXPECT_NE(installed.find("operator.one:rpi-camera:sha-256:"),
            std::string::npos);
}

TEST(BootstrapServiceTest, RejectsIpv4Ipv6MismatchAndNonAddressPeerText) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));
  const std::array<std::pair<std::string, std::string>, 7> peers = {{
      {"192.0.2.10", "192.0.2.11"},
      {"2001:db8::1", "2001:db8::2"},
      {"192.0.2.10", "::ffff:192.0.2.10"},
      {"192.0.2.10:443", "192.0.2.10"},
      {"fe80::1%eth0", "fe80::1"},
      {" 192.0.2.10", "192.0.2.10"},
      {"forwarded=192.0.2.10", "192.0.2.10"},
  }};

  for (const auto& [confirmed, actual] : peers) {
    auto rejected = service.Initialize(Request(
        "operator.one", "NorthStar!9", confirmed, actual));
    ASSERT_FALSE(rejected.ok()) << confirmed;
    EXPECT_EQ(rejected.error().code, "E_BOOTSTRAP_PEER") << confirmed;
    EXPECT_EQ(rejected.error().message.find(confirmed), std::string::npos);
  }
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_FALSE(std::filesystem::exists(state / "rtsp.credentials"));
}

TEST(BootstrapServiceTest, AppliesReservedIdentityAndPasswordPolicy) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto reserved = service.Initialize(Request(
      "imx708-main", "NorthStar!9", "192.0.2.10", "192.0.2.10"));
  auto weak = service.Initialize(Request(
      "operator.one", "SecretAAA!9", "192.0.2.10", "192.0.2.10"));

  ASSERT_FALSE(reserved.ok());
  ASSERT_FALSE(weak.ok());
  EXPECT_EQ(reserved.error().code, "E_USERNAME_RESERVED");
  EXPECT_EQ(weak.error().code, "E_PASSWORD_REPEAT");
  EXPECT_EQ(reserved.error().message.find("imx708-main"), std::string::npos);
  EXPECT_EQ(weak.error().message.find("SecretAAA!9"), std::string::npos);
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_FALSE(std::filesystem::exists(state / "rtsp.credentials"));
}

TEST(BootstrapServiceTest, ConcurrentInitializationHasOneWinner) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto first_store = SecurityStore::Open({state});
  ASSERT_TRUE(first_store.ok()) << first_store.error().message;
  auto second_store = SecurityStore::Open({state});
  ASSERT_TRUE(second_store.ok()) << second_store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService first_service(*first_store.value(), config,
                                 BuildReservedIdentities(config));
  BootstrapService second_service(*second_store.value(), config,
                                  BuildReservedIdentities(config));
  std::barrier start(3);
  std::array<bool, 2> succeeded{false, false};
  std::array<std::string, 2> errors;
  std::array<std::thread, 2> threads;
  for (std::size_t index = 0; index < threads.size(); ++index) {
    threads[index] = std::thread([&, index] {
      start.arrive_and_wait();
      auto& service = index == 0 ? first_service : second_service;
      auto result = service.Initialize(Request(
          index == 0 ? "operator.one" : "operator.two",
          index == 0 ? "NorthStar!9" : "SouthMoon!8", "192.0.2.10",
          "192.0.2.10"));
      succeeded[index] = result.ok();
      if (!result.ok()) {
        errors[index] = result.error().code;
      }
    });
  }
  start.arrive_and_wait();
  for (auto& thread : threads) {
    thread.join();
  }

  EXPECT_EQ(std::count(succeeded.begin(), succeeded.end(), true), 1);
  EXPECT_EQ(std::count(errors.begin(), errors.end(),
                       std::string("E_BOOTSTRAP_UNAVAILABLE")),
            1);
  EXPECT_EQ(QueryText(first_store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "1");
  EXPECT_EQ(QueryText(first_store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM management_ips;"),
            "1");
  // The winner's grant of the confirming peer plus its completion record. The
  // point of the assertion is unchanged: the loser wrote nothing.
  EXPECT_EQ(QueryText(first_store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM audit_events;"),
            "2");
  EXPECT_EQ(first_store.value()->State().value(), DeviceState::kOperational);
  EXPECT_EQ(second_store.value()->State().value(), DeviceState::kOperational);
}

TEST(BootstrapServiceTest, InstallerFailureLeavesSqliteAuthoritativeDefault) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "missing" / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto failed = service.Initialize(Request(
      "operator.one", "NorthStar!9", "192.0.2.10", "192.0.2.10"));

  ASSERT_FALSE(failed.ok());
  EXPECT_EQ(failed.error().code, "E_BOOTSTRAP_CREDENTIAL");
  EXPECT_EQ(failed.error().message.find("operator.one"), std::string::npos);
  EXPECT_EQ(failed.error().message.find("NorthStar!9"), std::string::npos);
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "0");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM audit_events;"),
            "0");
}

TEST(BootstrapServiceTest,
     CommitFailureRollsBackRowsAndRetryReplacesOrphanCredential) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  const auto credential = state / "rtsp.credentials";
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, credential);
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));
  common::Result<BootstrapResult> failed = [&] {
    ScopedTransactionFailures failures(true, false);
    return service.Initialize(Request(
        "operator.one", "NorthStar!9", "192.0.2.10", "192.0.2.10"));
  }();

  ASSERT_FALSE(failed.ok());
  EXPECT_EQ(failed.error().code, "E_BOOTSTRAP_STORE");
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "0");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM management_ips;"),
            "0");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM audit_events;"),
            "0");
  ASSERT_TRUE(std::filesystem::exists(credential));
  EXPECT_NE(ReadFile(credential).find("operator.one:rpi-camera:sha-256:"),
            std::string::npos);

  auto retried = service.Initialize(Request(
      "operator.two", "SouthMoon!8", "192.0.2.10", "192.0.2.10"));

  ASSERT_TRUE(retried.ok()) << retried.error().message;
  EXPECT_EQ(store.value()->State().value(), DeviceState::kOperational);
  const std::string installed = ReadFile(credential);
  EXPECT_EQ(installed.find("operator.one"), std::string::npos);
  EXPECT_NE(installed.find("operator.two:rpi-camera:sha-256:"),
            std::string::npos);
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "1");
}

TEST(BootstrapServiceTest,
     RollbackFailurePoisonsStoreAndFreshStoreRecoversDefaultDatabase) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  const auto credential = state / "rtsp.credentials";
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, credential);
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));
  common::Result<BootstrapResult> failed = [&] {
    ScopedTransactionFailures failures(true, true);
    return service.Initialize(Request(
        "operator.one", "NorthStar!9", "192.0.2.10", "192.0.2.10"));
  }();

  ASSERT_FALSE(failed.ok());
  EXPECT_EQ(failed.error().code, "E_BOOTSTRAP_STORE");
  auto poisoned_state = store.value()->State();
  ASSERT_FALSE(poisoned_state.ok());
  EXPECT_EQ(poisoned_state.error().code, "E_SECURITY_DB_POISONED");
  store.value().reset();

  auto recovered_store = SecurityStore::Open({state});
  ASSERT_TRUE(recovered_store.ok()) << recovered_store.error().message;
  EXPECT_EQ(recovered_store.value()->State().value(), DeviceState::kDefault);
  EXPECT_EQ(QueryText(recovered_store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "0");
  BootstrapService recovered_service(*recovered_store.value(), config,
                                     BuildReservedIdentities(config));
  auto retried = recovered_service.Initialize(Request(
      "operator.two", "SouthMoon!8", "192.0.2.10", "192.0.2.10"));

  ASSERT_TRUE(retried.ok()) << retried.error().message;
  EXPECT_EQ(recovered_store.value()->State().value(),
            DeviceState::kOperational);
  const std::string installed = ReadFile(credential);
  EXPECT_EQ(installed.find("operator.one"), std::string::npos);
  EXPECT_NE(installed.find("operator.two:rpi-camera:sha-256:"),
            std::string::npos);
}

TEST(BootstrapServiceTest, RejectsCredentialPathOutsideActualStoreBoundary) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  const auto other_state = root.Path("other-security");
  ASSERT_EQ(::mkdir(other_state.c_str(), 0700), 0);
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(other_state, other_state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto result = service.Initialize(Request(
      "operator.one", "NorthStar!9", "192.0.2.10", "192.0.2.10"));

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_BOOTSTRAP_CREDENTIAL");
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_FALSE(std::filesystem::exists(other_state / "rtsp.credentials"));
}

TEST(BootstrapServiceTest, RejectsCredentialDestinationAtSecurityDatabase) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, store.value()->database_path());
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto result = service.Initialize(Request(
      "operator.one", "NorthStar!9", "192.0.2.10", "192.0.2.10"));

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_BOOTSTRAP_CREDENTIAL");
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT state FROM device_state WHERE id = 1;"),
            "default");
}

TEST(BootstrapServiceTest, RejectsSymlinkedCredentialParentBeforeReplacement) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  const auto outside = root.Path("outside");
  ASSERT_EQ(::mkdir(outside.c_str(), 0700), 0);
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  ASSERT_EQ(::symlink(outside.c_str(), (state / "nested").c_str()), 0);
  auto config = BootstrapConfig(state, state / "nested" / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto result = service.Initialize(Request(
      "operator.one", "NorthStar!9", "192.0.2.10", "192.0.2.10"));

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_BOOTSTRAP_CREDENTIAL");
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_FALSE(std::filesystem::exists(outside / "rtsp.credentials"));
}

TEST(BootstrapServiceTest, RequiresProtectedNestedCredentialDirectories) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  const auto nested = state / "nested";
  ASSERT_EQ(::mkdir(nested.c_str(), 0750), 0);
  auto config = BootstrapConfig(state, nested / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto result = service.Initialize(Request(
      "operator.one", "NorthStar!9", "192.0.2.10", "192.0.2.10"));

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_BOOTSTRAP_CREDENTIAL");
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_FALSE(std::filesystem::exists(nested / "rtsp.credentials"));
}

TEST(BootstrapServiceTest, InstallsThroughProtectedNestedDirectory) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  const auto nested = state / "nested";
  ASSERT_EQ(::mkdir(nested.c_str(), 0700), 0);
  auto config = BootstrapConfig(state, nested / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto result = service.Initialize(Request(
      "operator.one", "NorthStar!9", "192.0.2.10", "192.0.2.10"));

  ASSERT_TRUE(result.ok()) << result.error().message;
  EXPECT_EQ(FileMode(nested / "rtsp.credentials"), 0600);
}

TEST(BootstrapServiceTest, ReservedIdentitiesIncludeProductAndCameraTerms) {
  config::AppConfig config;
  config.camera.id = "custom-sensor-main";

  const auto identities = BuildReservedIdentities(config);

  for (const std::string_view required :
       {"root", "admin", "administrator", "camera", "camera-firmware",
        "raspberry-pi", "hailo", "imx708", "custom-sensor-main"}) {
    EXPECT_NE(std::find(identities.begin(), identities.end(), required),
              identities.end())
        << required;
  }
}

TEST(BootstrapServiceTest, FirstBootCreatesInitialViewerAccount) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  const auto reserved_identities = BuildReservedIdentities(config);
  BootstrapService service(*store.value(), config, reserved_identities);

  const auto credential = service.EnsureInitialAccount();
  ASSERT_TRUE(credential.ok()) << credential.error().message;

  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "1");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT role FROM users;"),
            "viewer");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(enabled AS TEXT) FROM users;"),
            "1");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT state FROM device_state;"),
            "default");

  // The generated name must satisfy the same policy a human name must, against
  // the reserved list this very service enforces.
  const auto reserved = ReservedViews(reserved_identities);
  EXPECT_TRUE(
      ValidateInitialUsername(credential.value().username, reserved).ok());

  // The generated password must satisfy the product's own policy.
  EXPECT_TRUE(ValidatePassword(credential.value().username,
                               credential.value().password)
                  .ok());

  // The stored hash must verify against the plaintext handed back, otherwise
  // the account the operator is shown is not the account that exists.
  auto password_record = LoadPasswordRecord(store.value()->database_path());
  auto verified = VerifyPassword(credential.value().password, password_record);
  ASSERT_TRUE(verified.ok()) << verified.error().message;
  EXPECT_TRUE(verified.value());
}

TEST(BootstrapServiceTest, InitialPasswordIsNeverPersistedInPlaintext) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  const auto credential = service.EnsureInitialAccount();
  ASSERT_TRUE(credential.ok()) << credential.error().message;

  const std::string plaintext = StringFromBytes(credential.value().password);
  EXPECT_FALSE(StateDirectoryContains(state, plaintext));
}

TEST(BootstrapServiceTest, SecondCallReplacesTheInitialAccount) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  const auto first = service.EnsureInitialAccount();
  ASSERT_TRUE(first.ok()) << first.error().message;
  const auto second = service.EnsureInitialAccount();
  ASSERT_TRUE(second.ok()) << second.error().message;

  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "1");
  EXPECT_NE(StringFromBytes(first.value().password),
            StringFromBytes(second.value().password));
  EXPECT_NE(first.value().username, second.value().username);
}

TEST(BootstrapServiceTest, SetupDeletesTheInitialAccountAtomically) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));
  ASSERT_TRUE(service.EnsureInitialAccount().ok());

  auto initialized = service.Initialize(Request(
      "Operator.One", "NorthStar!9", "192.0.2.10", "192.0.2.10"));
  ASSERT_TRUE(initialized.ok()) << initialized.error().message;

  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "1");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT canonical_username FROM users;"),
            "operator.one");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT state FROM device_state;"),
            "operational");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM audit_events "
                      "WHERE event_type = 'initial_account_deleted' "
                      "AND outcome = 'success';"),
            "1");
}

TEST(BootstrapServiceTest, FailedSetupLeavesTheInitialAccountUsable) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  const auto credential = service.EnsureInitialAccount();
  ASSERT_TRUE(credential.ok()) << credential.error().message;

  // "short" fails the password policy, so setup must abort before any write.
  auto rejected = service.Initialize(Request(
      "Operator.One", "short", "192.0.2.10", "192.0.2.10"));
  EXPECT_FALSE(rejected.ok());

  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "1");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT role FROM users;"),
            "viewer");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT state FROM device_state;"),
            "default");

  // Usable means the credential still authenticates, not merely that a row
  // survived.
  auto password_record = LoadPasswordRecord(store.value()->database_path());
  auto verified = VerifyPassword(credential.value().password, password_record);
  ASSERT_TRUE(verified.ok()) << verified.error().message;
  EXPECT_TRUE(verified.value());
}

TEST(BootstrapServiceTest, StoreFailureDuringSetupKeepsTheInitialAccount) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  const auto credential = service.EnsureInitialAccount();
  ASSERT_TRUE(credential.ok()) << credential.error().message;

  // A commit failure part way through setup must roll the deletion back too.
  // The submitted address is here so the audit assertion below covers the
  // grant records as well: a record of access that was never granted is as
  // wrong as a grant that was never recorded.
  common::Result<BootstrapResult> failed = [&] {
    ScopedTransactionFailures failures(true, false);
    return service.Initialize(RequestWithIps(
        "operator.one", "NorthStar!9", "192.0.2.10", "192.0.2.10",
        {"198.51.100.7"}));
  }();

  ASSERT_FALSE(failed.ok());
  EXPECT_EQ(failed.error().code, "E_BOOTSTRAP_STORE");
  EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "1");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT role FROM users;"),
            "viewer");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM audit_events;"),
            "0");

  auto password_record = LoadPasswordRecord(store.value()->database_path());
  auto verified = VerifyPassword(credential.value().password, password_record);
  ASSERT_TRUE(verified.ok()) << verified.error().message;
  EXPECT_TRUE(verified.value());
}

TEST(BootstrapServiceTest, RegistersEverySubmittedManagementIpAtSetup) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto initialized = service.Initialize(RequestWithIps(
      "Operator.One", "NorthStar!9", "192.0.2.10", "192.0.2.10",
      {"198.51.100.7", "2001:0db8:0:0:0:0:0:2"}));
  ASSERT_TRUE(initialized.ok()) << initialized.error().message;

  // Order is the confirming peer first, then the submitted list in the order
  // the operator entered it. Normalization is the same one the post-setup
  // management-IP routes apply, so 2001:0db8:... lands compressed.
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT group_concat(normalized_ip || '/' || role_scope "
                      "|| '/' || enabled, ' ') FROM "
                      "(SELECT * FROM management_ips ORDER BY id);"),
            "192.0.2.10/administrator/1 198.51.100.7/administrator/1 "
            "2001:db8::2/administrator/1");
  EXPECT_EQ(store.value()->State().value(), DeviceState::kOperational);
}

// The anti-lockout rule. If the operator's list names only addresses they do
// not hold, registering the list alone would leave the device operational and
// unreachable, with no password reset and no recovery short of reflashing it.
TEST(BootstrapServiceTest, RegistersTheConfirmingPeerEvenWhenTheListOmitsIt) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  auto initialized = service.Initialize(RequestWithIps(
      "Operator.One", "NorthStar!9", "192.0.2.10", "192.0.2.10",
      {"198.51.100.7"}));
  ASSERT_TRUE(initialized.ok()) << initialized.error().message;

  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT group_concat(normalized_ip, ' ') FROM "
                      "(SELECT * FROM management_ips ORDER BY id);"),
            "192.0.2.10 198.51.100.7");
  // Registered is not enough on its own: the peer must satisfy the same lookup
  // the request gate runs on every operational request.
  auto reachable = store.value()->IsManagementPeer("192.0.2.10");
  ASSERT_TRUE(reachable.ok()) << reachable.error().message;
  EXPECT_TRUE(reachable.value());
}

TEST(BootstrapServiceTest, DeduplicatesManagementIpsIncludingTheSetupPeer) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  // The wizard shows the current peer as already registered, so an operator
  // re-entering it is expected rather than exceptional. Both the literal repeat
  // and the differently-spelled repeat must collapse instead of tripping
  // management_ips_role_ip_unique and aborting the whole transaction.
  auto initialized = service.Initialize(RequestWithIps(
      "Operator.One", "NorthStar!9", "2001:db8::1", "2001:0db8::1",
      {"2001:0db8:0:0:0:0:0:1", "198.51.100.7", "198.51.100.7",
       "2001:db8::1"}));
  ASSERT_TRUE(initialized.ok()) << initialized.error().message;

  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM management_ips;"),
            "2");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT group_concat(normalized_ip, ' ') FROM "
                      "(SELECT * FROM management_ips ORDER BY id);"),
            "2001:db8::1 198.51.100.7");
}

TEST(BootstrapServiceTest, RejectsManagementIpsThatAreNotSingleHosts) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));
  const auto credential = service.EnsureInitialAccount();
  ASSERT_TRUE(credential.ok()) << credential.error().message;

  // The browser rejects all of these with a visible reason, but the browser is
  // a convenience. Nothing stops a caller posting the body directly.
  const std::vector<std::string> not_single_hosts = {
      "198.51.100.0/24", "198.51.100.*", "198.51.100.1-198.51.100.9",
      "0.0.0.0",         "::",           "any",
      "",                "localhost",    "198.51.100.7 ",
  };
  for (const auto& entry : not_single_hosts) {
    // A valid entry first, so the failure is proven to abort the whole
    // submission rather than to stop at the first element.
    auto rejected = service.Initialize(RequestWithIps(
        "Operator.One", "NorthStar!9", "192.0.2.10", "192.0.2.10",
        {"198.51.100.7", entry}));
    ASSERT_FALSE(rejected.ok()) << entry;
    EXPECT_EQ(rejected.error().code, "E_MANAGEMENT_IP_INVALID") << entry;

    // Setup stays all-or-nothing: no administrator, no management_ips row, no
    // state change, and the initial account still standing.
    EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault) << entry;
    EXPECT_EQ(QueryText(store.value()->database_path(),
                        "SELECT CAST(COUNT(*) AS TEXT) FROM management_ips;"),
              "0")
        << entry;
    EXPECT_EQ(QueryText(store.value()->database_path(),
                        "SELECT role FROM users;"),
              "viewer")
        << entry;
  }

  auto password_record = LoadPasswordRecord(store.value()->database_path());
  auto verified = VerifyPassword(credential.value().password, password_record);
  ASSERT_TRUE(verified.ok()) << verified.error().message;
  EXPECT_TRUE(verified.value());

  // And the rejections left setup runnable rather than poisoned.
  auto accepted = service.Initialize(RequestWithIps(
      "Operator.One", "NorthStar!9", "192.0.2.10", "192.0.2.10",
      {"198.51.100.7"}));
  ASSERT_TRUE(accepted.ok()) << accepted.error().message;
}

TEST(BootstrapServiceTest, AuditsEveryManagementIpGrantedDuringSetup) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));
  ASSERT_TRUE(service.EnsureInitialAccount().ok());

  auto initialized = service.Initialize(RequestWithIps(
      "Operator.One", "NorthStar!9", "192.0.2.10", "192.0.2.10",
      {"198.51.100.7", "2001:0db8:0:0:0:0:0:2", "198.51.100.7"}));
  ASSERT_TRUE(initialized.ok()) << initialized.error().message;

  // Each granted address in its own row, named in subject_identity, in the
  // order it was granted — not a count, and not one summary row standing in
  // for all of them. Same event type, detail code, subject type and actor
  // columns the post-setup grant writes, so one query over the audit trail
  // answers "which addresses were ever allowed in" for the life of the device.
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT group_concat(event_type || '|' || outcome || "
                      "'|' || actor_identity || '|' || peer_ip || '|' || "
                      "detail_code || '|' || subject_type || '|' || "
                      "subject_identity, ' ') FROM (SELECT * FROM audit_events "
                      "WHERE event_type = 'management_ip_created' "
                      "ORDER BY sequence);"),
            "management_ip_created|success|operator.one|192.0.2.10|created|"
            "management_ip|192.0.2.10 "
            "management_ip_created|success|operator.one|192.0.2.10|created|"
            "management_ip|198.51.100.7 "
            "management_ip_created|success|operator.one|192.0.2.10|created|"
            "management_ip|2001:db8::2");

  // No grant without a record and no record without a grant, stated as the
  // property rather than as a row count: a duplicate that collapsed must not
  // leave a record of an address that was never registered.
  EXPECT_EQ(
      QueryText(store.value()->database_path(),
                "SELECT (SELECT COUNT(*) FROM management_ips AS ip WHERE NOT "
                "EXISTS (SELECT 1 FROM audit_events AS event WHERE "
                "event.event_type = 'management_ip_created' AND "
                "event.subject_identity = ip.normalized_ip)) || '/' || "
                "(SELECT COUNT(*) FROM audit_events AS event WHERE "
                "event.event_type = 'management_ip_created' AND NOT EXISTS "
                "(SELECT 1 FROM management_ips AS ip WHERE ip.normalized_ip = "
                "event.subject_identity));"),
      "0/0");

  // bootstrap_completed stays the terminal record of the transaction, so the
  // grants read as things setup did on its way to completing.
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT event_type FROM audit_events "
                      "ORDER BY sequence DESC LIMIT 1;"),
            "bootstrap_completed");
}

TEST(BootstrapServiceTest, BoundsRegisteredManagementIpsAtThePerRoleLimit) {
  const auto addresses = [](std::size_t count) {
    std::vector<std::string> entries;
    entries.reserve(count);
    for (std::size_t index = 0U; index < count; ++index) {
      entries.push_back("198.51.100." + std::to_string(index + 1U));
    }
    return entries;
  };

  {
    TemporaryDirectory root;
    const auto state = root.Path("security");
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    auto config = BootstrapConfig(state, state / "rtsp.credentials");
    BootstrapService service(*store.value(), config,
                             BuildReservedIdentities(config));

    // 32 distinct entries plus the confirming peer is 33 administrator rows,
    // one past what SecurityStore allows per role scope. The peer is never the
    // one dropped to make room.
    auto rejected = service.Initialize(RequestWithIps(
        "Operator.One", "NorthStar!9", "192.0.2.10", "192.0.2.10",
        addresses(32U)));
    ASSERT_FALSE(rejected.ok());
    EXPECT_EQ(rejected.error().code, "E_MANAGEMENT_IP_LIMIT");
    EXPECT_EQ(store.value()->State().value(), DeviceState::kDefault);
    EXPECT_EQ(QueryText(store.value()->database_path(),
                        "SELECT CAST(COUNT(*) AS TEXT) FROM management_ips;"),
              "0");
  }

  {
    TemporaryDirectory root;
    const auto state = root.Path("security");
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    auto config = BootstrapConfig(state, state / "rtsp.credentials");
    BootstrapService service(*store.value(), config,
                             BuildReservedIdentities(config));

    auto accepted = service.Initialize(RequestWithIps(
        "Operator.One", "NorthStar!9", "192.0.2.10", "192.0.2.10",
        addresses(31U)));
    ASSERT_TRUE(accepted.ok()) << accepted.error().message;
    EXPECT_EQ(QueryText(store.value()->database_path(),
                        "SELECT CAST(COUNT(*) AS TEXT) FROM management_ips;"),
              "32");
  }
}

// A power cycle before setup completes must not brick the device. The store's
// committed-state validation runs on every reopen, and until this test existed
// its default-state arm asserted zero users — written before the initial
// account, which legitimately leaves one viewer row in default state.
TEST(BootstrapServiceTest, ReopensTheStoreWhileTheInitialAccountExists) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
    auto config = BootstrapConfig(state, state / "rtsp.credentials");
    BootstrapService service(*store.value(), config,
                             BuildReservedIdentities(config));
    ASSERT_TRUE(service.EnsureInitialAccount().ok());
  }

  auto reopened = SecurityStore::Open({state});

  ASSERT_TRUE(reopened.ok()) << reopened.error().message;
  EXPECT_EQ(reopened.value()->State().value(), DeviceState::kDefault);
  EXPECT_EQ(QueryText(reopened.value()->database_path(),
                      "SELECT role FROM users;"),
            "viewer");

  // And the next boot's replacement still works against the reopened store.
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*reopened.value(), config,
                           BuildReservedIdentities(config));
  ASSERT_TRUE(service.EnsureInitialAccount().ok());
  EXPECT_EQ(QueryText(reopened.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "1");
}

// The committed-state validator admits one viewer row and one viewer session
// in default state because this replacement destroys them at every boot,
// before any listener exists. A planted session's token hash is
// attacker-chosen, so if EnsureInitialAccount ever skips replacement when an
// account already exists, that relaxation becomes a live pre-setup session.
// This test is the pin the validator's comment points at.
TEST(BootstrapServiceTest, EnsureInitialAccountDestroysPlantedRows) {
  TemporaryDirectory root;
  const auto state = root.Path("security");
  {
    auto store = SecurityStore::Open({state});
    ASSERT_TRUE(store.ok()) << store.error().message;
  }
  ExecuteDatabaseSql(state / "security.db", R"sql(
INSERT INTO users
  (canonical_username, display_username, role, enabled,
   password_algorithm, password_iterations, password_salt, password_derived,
   password_changed_at_seconds, failed_login_count, created_at_seconds)
VALUES ('planted.viewer', 'Planted.Viewer', 'viewer', 1,
        'pbkdf2-hmac-sha256', 600000, zeroblob(16), zeroblob(32), 2, 0, 2);
INSERT INTO sessions
  (token_hash, user_id, role, created_at_seconds, last_activity_at_seconds,
   expires_at_seconds, peer_ip, management_expires_at_seconds)
VALUES (zeroblob(32), (SELECT id FROM users), 'viewer', 2, 2, 999999999999,
        '192.0.2.10', 999999999999);
)sql");

  auto store = SecurityStore::Open({state});
  ASSERT_TRUE(store.ok()) << store.error().message;
  auto config = BootstrapConfig(state, state / "rtsp.credentials");
  BootstrapService service(*store.value(), config,
                           BuildReservedIdentities(config));

  const auto credential = service.EnsureInitialAccount();
  ASSERT_TRUE(credential.ok()) << credential.error().message;

  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users;"),
            "1");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM users "
                      "WHERE canonical_username = 'planted.viewer';"),
            "0");
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM sessions;"),
            "0");
}

}  // namespace
}  // namespace camera_firmware::security
