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
  EXPECT_EQ(QueryText(store.value()->database_path(),
                      "SELECT event_type || '|' || outcome || '|' || peer_ip "
                      "FROM audit_events;"),
            "bootstrap_completed|success|192.0.2.10");

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
  EXPECT_EQ(QueryText(first_store.value()->database_path(),
                      "SELECT CAST(COUNT(*) AS TEXT) FROM audit_events;"),
            "1");
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

}  // namespace
}  // namespace camera_firmware::security
