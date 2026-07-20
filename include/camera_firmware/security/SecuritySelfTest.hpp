#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::security {

struct SelfTestItemResult {
  std::string id;
  bool passed{false};
  std::string code;
};

struct SelfTestReport {
  bool passed{false};
  std::vector<SelfTestItemResult> items;
};

struct SecuritySelfTestDependencies {
  std::function<common::Result<void>()> database_check;
  std::function<common::Result<void>()> tls_identity_check;
  std::function<common::Result<void>()> audit_append_check;
};

common::Result<SelfTestReport> RunSecuritySelfTests(
    const SecuritySelfTestDependencies& dependencies);

#ifdef CAMERA_FIRMWARE_SECURITY_SELF_TESTING
enum class CryptoSelfTestOperation { kSha256, kHmacSha256, kAes256Gcm };
enum class SecuritySelfTestSensitiveBuffer {
  kHmacKey,
  kAesKey,
  kAesPlaintext,
  kAesCiphertext,
  kAesDecryptedPlaintext,
  kAesRejectedPlaintext,
};

struct SecuritySelfTestZeroizationObservation {
  SecuritySelfTestSensitiveBuffer buffer;
  std::size_t allocation_size{0U};
  bool all_zero{false};
};

void SetSecuritySelfTestCryptoFailureForTest(CryptoSelfTestOperation operation);
void ResetSecuritySelfTestHooksForTest();
[[nodiscard]] std::vector<SecuritySelfTestZeroizationObservation>
SecuritySelfTestZeroizationObservationsForTest();
#endif

}  // namespace camera_firmware::security
