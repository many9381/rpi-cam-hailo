#include "camera_firmware/security/SecuritySelfTest.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "camera_firmware/crypto/OpenSslCryptoProvider.hpp"

namespace {

using camera_firmware::common::Result;
using camera_firmware::crypto::CryptoProvider;
using camera_firmware::crypto::OpenSslCryptoProvider;
using camera_firmware::security::CryptoSelfTestOperation;
using camera_firmware::security::ResetSecuritySelfTestHooksForTest;
using camera_firmware::security::RunSecuritySelfTests;
using camera_firmware::security::SecuritySelfTestDependencies;
using camera_firmware::security::SecuritySelfTestSensitiveBuffer;
using camera_firmware::security::SecuritySelfTestZeroizationObservationsForTest;
using camera_firmware::security::SetSecuritySelfTestCryptoFailureForTest;

// A single self-tested provider, shared by every test in this file. Its
// self-test is real OpenSSL work (PBKDF2/Ed25519/AES-GCM known-answer
// checks), so it is initialized exactly once (C++11 "magic statics" make
// this thread-safe) rather than repeated per test.
CryptoProvider& TestCryptoProvider() {
  static OpenSslCryptoProvider provider;
  static const bool initialized = [] {
    const auto self_test = provider.SelfTest();
    if (!self_test.ok() || !self_test.value().passed) {
      throw std::runtime_error("crypto provider self-test failed");
    }
    return true;
  }();
  (void)initialized;
  return provider;
}

SecuritySelfTestDependencies PassingDependencies(
    std::vector<std::string>* calls = nullptr) {
  const auto passed = [calls](std::string_view name) {
    if (calls != nullptr) {
      calls->emplace_back(name);
    }
    return Result<void>::Ok();
  };
  SecuritySelfTestDependencies dependencies;
  dependencies.database_check = [passed] { return passed("database"); };
  dependencies.tls_identity_check = [passed] { return passed("tls"); };
  dependencies.audit_append_check = [passed] { return passed("audit"); };
  dependencies.provider = &TestCryptoProvider();
  return dependencies;
}

// Stable item order: the five checks this file still owns directly (SHA-256,
// HMAC-SHA256, then the three dependency checks), followed by whatever
// crypto::CryptoProvider::SelfTest() reports (pbkdf2_hmac_sha256,
// random_bytes, random_bytes_private, ed25519, aes_256_gcm), appended in the
// order it returns them.
TEST(SecuritySelfTestTest, ReportsEveryCheckInThePublishedStableOrder) {
  ResetSecuritySelfTestHooksForTest();
  std::vector<std::string> calls;

  const auto result = RunSecuritySelfTests(PassingDependencies(&calls));

  ASSERT_TRUE(result.ok()) << result.error().message;
  EXPECT_TRUE(result.value().passed);
  ASSERT_EQ(result.value().items.size(), 10U);
  const std::array<std::string, 10> expected_ids{"crypto.sha256",
                                                 "crypto.hmac_sha256",
                                                 "security.database",
                                                 "security.tls_identity",
                                                 "security.audit_append",
                                                 "pbkdf2_hmac_sha256",
                                                 "random_bytes",
                                                 "random_bytes_private",
                                                 "ed25519",
                                                 "aes_256_gcm"};
  for (std::size_t index = 0; index < expected_ids.size(); ++index) {
    EXPECT_EQ(result.value().items[index].id, expected_ids[index]);
    EXPECT_TRUE(result.value().items[index].passed);
    EXPECT_EQ(result.value().items[index].code, "OK");
  }
  EXPECT_EQ(calls, (std::vector<std::string>{"database", "tls", "audit"}));
}

TEST(SecuritySelfTestTest, ReportIncludesProviderItemsExactlyOnce) {
  OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  SecuritySelfTestDependencies dependencies;
  dependencies.provider = &provider;
  dependencies.database_check = [] { return Result<void>::Ok(); };
  dependencies.tls_identity_check = [] { return Result<void>::Ok(); };
  dependencies.audit_append_check = [] { return Result<void>::Ok(); };

  const auto report = RunSecuritySelfTests(dependencies);
  ASSERT_TRUE(report.ok()) << report.error().message;
  EXPECT_TRUE(report.value().passed);

  const auto count_id = [&report](std::string_view id) {
    return std::count_if(report.value().items.begin(),
                         report.value().items.end(),
                         [id](const auto& item) { return item.id == id; });
  };
  EXPECT_EQ(count_id("aes_256_gcm"), 1);
  EXPECT_EQ(count_id("pbkdf2_hmac_sha256"), 1);
  EXPECT_EQ(count_id("ed25519"), 1);
  EXPECT_EQ(count_id("random_bytes"), 1);
  EXPECT_EQ(count_id("random_bytes_private"), 1);
  EXPECT_GE(count_id("crypto.sha256"), 1);
  EXPECT_GE(count_id("crypto.hmac_sha256"), 1);
}

TEST(SecuritySelfTestTest, MissingProviderFailsRatherThanShrinkingTheReport) {
  ResetSecuritySelfTestHooksForTest();
  std::vector<std::string> calls;

  auto dependencies = PassingDependencies(&calls);
  dependencies.provider = nullptr;
  const auto result = RunSecuritySelfTests(dependencies);

  ASSERT_TRUE(result.ok()) << result.error().message;
  EXPECT_FALSE(result.value().passed);
  ASSERT_EQ(result.value().items.size(), 6U);
  EXPECT_EQ(result.value().items[5].id, "crypto_provider");
  EXPECT_FALSE(result.value().items[5].passed);
  EXPECT_EQ(result.value().items[5].code, "E_CRYPTO_UNAVAILABLE");
  for (std::size_t index = 0; index < 5U; ++index) {
    EXPECT_TRUE(result.value().items[index].passed) << index;
  }
  EXPECT_EQ(calls, (std::vector<std::string>{"database", "tls", "audit"}));
}

TEST(SecuritySelfTestTest, ContinuesAfterEachInjectedCryptoFailure) {
  const std::array<std::pair<CryptoSelfTestOperation, std::size_t>, 3>
      operations{{{CryptoSelfTestOperation::kSha256, 0U},
                  {CryptoSelfTestOperation::kHmacSha256, 1U},
                  {CryptoSelfTestOperation::kAes256Gcm, 9U}}};

  for (const auto [operation, failed_index] : operations) {
    ResetSecuritySelfTestHooksForTest();
    SetSecuritySelfTestCryptoFailureForTest(operation);
    std::vector<std::string> calls;

    const auto result = RunSecuritySelfTests(PassingDependencies(&calls));

    ASSERT_TRUE(result.ok()) << result.error().message;
    ASSERT_EQ(result.value().items.size(), 10U);
    EXPECT_FALSE(result.value().passed);
    EXPECT_FALSE(result.value().items[failed_index].passed);
    EXPECT_NE(result.value().items[failed_index].code, "OK");
    for (std::size_t index = 0; index < result.value().items.size(); ++index) {
      if (index != failed_index) {
        EXPECT_TRUE(result.value().items[index].passed) << index;
      }
    }
    EXPECT_EQ(calls, (std::vector<std::string>{"database", "tls", "audit"}));
  }
}

TEST(SecuritySelfTestTest,
     DependencyErrorThrowAndAbsenceContinueWithExactStableCodes) {
  {
    auto dependencies = PassingDependencies();
    bool tls_called = false;
    bool audit_called = false;
    dependencies.database_check = [] {
      return Result<void>::Err({"internal", "sensitive database detail"});
    };
    dependencies.tls_identity_check = [&] {
      tls_called = true;
      return Result<void>::Ok();
    };
    dependencies.audit_append_check = [&] {
      audit_called = true;
      return Result<void>::Ok();
    };
    const auto result = RunSecuritySelfTests(dependencies);
    ASSERT_TRUE(result.ok()) << result.error().message;
    EXPECT_FALSE(result.value().items[2].passed);
    EXPECT_EQ(result.value().items[2].code, "E_SELF_TEST_DATABASE");
    EXPECT_TRUE(tls_called);
    EXPECT_TRUE(audit_called);
  }

  {
    auto dependencies = PassingDependencies();
    bool audit_called = false;
    dependencies.tls_identity_check = []() -> Result<void> {
      throw std::runtime_error("sensitive TLS detail");
    };
    dependencies.audit_append_check = [&] {
      audit_called = true;
      return Result<void>::Ok();
    };
    const auto result = RunSecuritySelfTests(dependencies);
    ASSERT_TRUE(result.ok()) << result.error().message;
    EXPECT_FALSE(result.value().items[3].passed);
    EXPECT_EQ(result.value().items[3].code, "E_SELF_TEST_TLS_IDENTITY");
    EXPECT_TRUE(audit_called);
  }

  {
    auto dependencies = PassingDependencies();
    dependencies.audit_append_check = {};
    const auto result = RunSecuritySelfTests(dependencies);
    ASSERT_TRUE(result.ok()) << result.error().message;
    EXPECT_FALSE(result.value().items[4].passed);
    EXPECT_EQ(result.value().items[4].code, "E_SELF_TEST_AUDIT_APPEND");
  }
}

void ExpectZeroized(SecuritySelfTestSensitiveBuffer expected_buffer,
                    std::size_t expected_size) {
  const auto observations = SecuritySelfTestZeroizationObservationsForTest();
  const auto matches =
      std::count_if(observations.begin(), observations.end(),
                    [expected_buffer](const auto& observation) {
                      return observation.buffer == expected_buffer;
                    });
  ASSERT_EQ(matches, 1U);
  const auto observation =
      std::find_if(observations.begin(), observations.end(),
                   [expected_buffer](const auto& candidate) {
                     return candidate.buffer == expected_buffer;
                   });
  ASSERT_NE(observation, observations.end());
  EXPECT_EQ(observation->allocation_size, expected_size);
  EXPECT_TRUE(observation->all_zero);
}

// AES buffer zeroization (kAesKey/kAesPlaintext/kAesCiphertext/
// kAesDecryptedPlaintext/kAesRejectedPlaintext) used to be asserted here
// because the AES-256-GCM known-answer test ran in this file. That test, and
// the buffers it scratched into, moved to
// crypto::CryptoProvider::SelfTest() (src/crypto/OpenSslCryptoProvider.cpp's
// RunAes256GcmSelfTest), which does cleanse its own ciphertext/tag/decrypted
// scratch via common::SecureBytes. But this file's assertion did not move
// with it: crypto::CryptoProvider is a deliberately clean leaf library (see
// Task 1) with no CAMERA_FIRMWARE_SECURITY_SELF_TESTING-style test hook, so
// there is no way to observe that cleansing from outside the library, here
// or from tests/unit/crypto/CryptoProviderTest.cpp. This file now only ever
// allocates the HMAC-SHA256 key buffer itself, so that is the only buffer
// left to assert zeroized below.
TEST(SecuritySelfTestTest, CleansesEverySensitiveCryptoBufferOnSuccess) {
  ResetSecuritySelfTestHooksForTest();

  const auto success = RunSecuritySelfTests(PassingDependencies());

  ASSERT_TRUE(success.ok()) << success.error().message;
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kHmacKey, 20U);
}

TEST(SecuritySelfTestTest,
     CleansesEveryAllocatedCryptoBufferOnRelevantInjectedFailures) {
  ResetSecuritySelfTestHooksForTest();
  SetSecuritySelfTestCryptoFailureForTest(CryptoSelfTestOperation::kHmacSha256);
  const auto hmac_failure = RunSecuritySelfTests(PassingDependencies());
  ASSERT_TRUE(hmac_failure.ok()) << hmac_failure.error().message;
  EXPECT_FALSE(hmac_failure.value().items[1].passed);
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kHmacKey, 20U);

  // The injected AES failure now only overrides the folded-in provider item
  // (see RunSecuritySelfTests); it does not run any local AES buffer code,
  // so there is nothing of this file's own to assert zeroized here.
  ResetSecuritySelfTestHooksForTest();
  SetSecuritySelfTestCryptoFailureForTest(CryptoSelfTestOperation::kAes256Gcm);
  const auto aes_failure = RunSecuritySelfTests(PassingDependencies());
  ASSERT_TRUE(aes_failure.ok()) << aes_failure.error().message;
  ASSERT_EQ(aes_failure.value().items.size(), 10U);
  EXPECT_EQ(aes_failure.value().items[9].id, "aes_256_gcm");
  EXPECT_FALSE(aes_failure.value().items[9].passed);
}

}  // namespace
