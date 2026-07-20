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

namespace {

using camera_firmware::common::Result;
using camera_firmware::security::CryptoSelfTestOperation;
using camera_firmware::security::ResetSecuritySelfTestHooksForTest;
using camera_firmware::security::RunSecuritySelfTests;
using camera_firmware::security::SecuritySelfTestDependencies;
using camera_firmware::security::SecuritySelfTestSensitiveBuffer;
using camera_firmware::security::SetSecuritySelfTestCryptoFailureForTest;
using camera_firmware::security::SecuritySelfTestZeroizationObservationsForTest;

SecuritySelfTestDependencies PassingDependencies(
    std::vector<std::string>* calls = nullptr) {
  const auto passed = [calls](std::string_view name) {
    if (calls != nullptr) {
      calls->emplace_back(name);
    }
    return Result<void>::Ok();
  };
  return {
      [passed] { return passed("database"); },
      [passed] { return passed("tls"); },
      [passed] { return passed("audit"); },
  };
}

TEST(SecuritySelfTestTest, ReportsEveryCheckInThePublishedStableOrder) {
  ResetSecuritySelfTestHooksForTest();
  std::vector<std::string> calls;

  const auto result = RunSecuritySelfTests(PassingDependencies(&calls));

  ASSERT_TRUE(result.ok()) << result.error().message;
  EXPECT_TRUE(result.value().passed);
  ASSERT_EQ(result.value().items.size(), 6U);
  const std::array<std::string, 6> expected_ids{
      "crypto.sha256", "crypto.hmac_sha256", "crypto.aes_256_gcm",
      "security.database", "security.tls_identity", "security.audit_append"};
  for (std::size_t index = 0; index < expected_ids.size(); ++index) {
    EXPECT_EQ(result.value().items[index].id, expected_ids[index]);
    EXPECT_TRUE(result.value().items[index].passed);
    EXPECT_EQ(result.value().items[index].code, "OK");
  }
  EXPECT_EQ(calls, (std::vector<std::string>{"database", "tls", "audit"}));
}

TEST(SecuritySelfTestTest, ContinuesAfterEachInjectedCryptoFailure) {
  const std::array<std::pair<CryptoSelfTestOperation, std::size_t>, 3>
      operations{{{CryptoSelfTestOperation::kSha256, 0U},
                  {CryptoSelfTestOperation::kHmacSha256, 1U},
                  {CryptoSelfTestOperation::kAes256Gcm, 2U}}};

  for (const auto [operation, failed_index] : operations) {
    ResetSecuritySelfTestHooksForTest();
    SetSecuritySelfTestCryptoFailureForTest(operation);
    std::vector<std::string> calls;

    const auto result = RunSecuritySelfTests(PassingDependencies(&calls));

    ASSERT_TRUE(result.ok()) << result.error().message;
    ASSERT_EQ(result.value().items.size(), 6U);
    EXPECT_FALSE(result.value().passed);
    EXPECT_FALSE(result.value().items[failed_index].passed);
    EXPECT_NE(result.value().items[failed_index].code, "OK");
    for (std::size_t index = 0; index < result.value().items.size(); ++index) {
      if (index != failed_index) {
        EXPECT_TRUE(result.value().items[index].passed) << index;
      }
    }
    EXPECT_EQ(calls,
              (std::vector<std::string>{"database", "tls", "audit"}));
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
    EXPECT_FALSE(result.value().items[3].passed);
    EXPECT_EQ(result.value().items[3].code, "E_SELF_TEST_DATABASE");
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
    EXPECT_FALSE(result.value().items[4].passed);
    EXPECT_EQ(result.value().items[4].code, "E_SELF_TEST_TLS_IDENTITY");
    EXPECT_TRUE(audit_called);
  }

  {
    auto dependencies = PassingDependencies();
    dependencies.audit_append_check = {};
    const auto result = RunSecuritySelfTests(dependencies);
    ASSERT_TRUE(result.ok()) << result.error().message;
    EXPECT_FALSE(result.value().items[5].passed);
    EXPECT_EQ(result.value().items[5].code, "E_SELF_TEST_AUDIT_APPEND");
  }
}

void ExpectZeroized(SecuritySelfTestSensitiveBuffer expected_buffer,
                    std::size_t expected_size) {
  const auto observations =
      SecuritySelfTestZeroizationObservationsForTest();
  const auto matches = std::count_if(
      observations.begin(), observations.end(),
      [expected_buffer](const auto& observation) {
        return observation.buffer == expected_buffer;
      });
  ASSERT_EQ(matches, 1U);
  const auto observation = std::find_if(
      observations.begin(), observations.end(),
      [expected_buffer](const auto& candidate) {
        return candidate.buffer == expected_buffer;
      });
  ASSERT_NE(observation, observations.end());
  EXPECT_EQ(observation->allocation_size, expected_size);
  EXPECT_TRUE(observation->all_zero);
}

TEST(SecuritySelfTestTest, CleansesEverySensitiveCryptoBufferOnSuccess) {
  ResetSecuritySelfTestHooksForTest();

  const auto success = RunSecuritySelfTests(PassingDependencies());

  ASSERT_TRUE(success.ok()) << success.error().message;
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kHmacKey, 20U);
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kAesKey, 32U);
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kAesPlaintext, 16U);
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kAesCiphertext, 16U);
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kAesDecryptedPlaintext, 16U);
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kAesRejectedPlaintext, 16U);
}

TEST(SecuritySelfTestTest,
     CleansesEveryAllocatedCryptoBufferOnRelevantInjectedFailures) {
  ResetSecuritySelfTestHooksForTest();
  SetSecuritySelfTestCryptoFailureForTest(
      CryptoSelfTestOperation::kHmacSha256);
  const auto hmac_failure = RunSecuritySelfTests(PassingDependencies());
  ASSERT_TRUE(hmac_failure.ok()) << hmac_failure.error().message;
  EXPECT_FALSE(hmac_failure.value().items[1].passed);
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kHmacKey, 20U);

  ResetSecuritySelfTestHooksForTest();
  SetSecuritySelfTestCryptoFailureForTest(CryptoSelfTestOperation::kAes256Gcm);
  const auto aes_failure = RunSecuritySelfTests(PassingDependencies());
  ASSERT_TRUE(aes_failure.ok()) << aes_failure.error().message;
  EXPECT_FALSE(aes_failure.value().items[2].passed);
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kAesKey, 32U);
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kAesPlaintext, 16U);
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kAesCiphertext, 16U);
  ExpectZeroized(SecuritySelfTestSensitiveBuffer::kAesDecryptedPlaintext, 16U);
  const auto observations =
      SecuritySelfTestZeroizationObservationsForTest();
  EXPECT_EQ(std::count_if(
                observations.begin(), observations.end(), [](const auto& item) {
                  return item.buffer == SecuritySelfTestSensitiveBuffer::
                                            kAesRejectedPlaintext;
                }),
            0U);
}

}  // namespace
