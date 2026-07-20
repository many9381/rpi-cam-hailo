#include "camera_firmware/security/SecuritySelfTest.hpp"

#include <array>
#include <string_view>

#include <gtest/gtest.h>

namespace {

TEST(SecuritySelfTestProductionLinkTest, RunsThroughProductionSecurityArchive) {
  camera_firmware::security::SecuritySelfTestDependencies dependencies;
  dependencies.database_check = [] {
    return camera_firmware::common::Result<void>::Ok();
  };
  dependencies.tls_identity_check = dependencies.database_check;
  dependencies.audit_append_check = dependencies.database_check;

  const auto result =
      camera_firmware::security::RunSecuritySelfTests(dependencies);

  ASSERT_TRUE(result.ok()) << result.error().message;
  ASSERT_EQ(result.value().items.size(), 6U);
  constexpr std::array<std::string_view, 6> kExpectedIds{
      "crypto.sha256",         "crypto.hmac_sha256",
      "crypto.aes_256_gcm",   "security.database",
      "security.tls_identity", "security.audit_append"};
  for (std::size_t index = 0; index < kExpectedIds.size(); ++index) {
    EXPECT_EQ(result.value().items[index].id, kExpectedIds[index]);
    EXPECT_TRUE(result.value().items[index].passed);
    EXPECT_EQ(result.value().items[index].code, "OK");
  }
  EXPECT_TRUE(result.value().passed);
}

}  // namespace
