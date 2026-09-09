#include "camera_firmware/security/SecuritySelfTest.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "camera_firmware/common/SecureBytes.hpp"

namespace camera_firmware::security {
namespace {

constexpr std::array<unsigned char, 32> kSha256Abc{
    0xbaU, 0x78U, 0x16U, 0xbfU, 0x8fU, 0x01U, 0xcfU, 0xeaU,
    0x41U, 0x41U, 0x40U, 0xdeU, 0x5dU, 0xaeU, 0x22U, 0x23U,
    0xb0U, 0x03U, 0x61U, 0xa3U, 0x96U, 0x17U, 0x7aU, 0x9cU,
    0xb4U, 0x10U, 0xffU, 0x61U, 0xf2U, 0x00U, 0x15U, 0xadU};
constexpr std::array<unsigned char, 20> kHmacKey{
    0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
    0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU,
    0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU, 0x0bU};
constexpr std::array<unsigned char, 32> kHmacSha256CaseOne{
    0xb0U, 0x34U, 0x4cU, 0x61U, 0xd8U, 0xdbU, 0x38U, 0x53U,
    0x5cU, 0xa8U, 0xafU, 0xceU, 0xafU, 0x0bU, 0xf1U, 0x2bU,
    0x88U, 0x1dU, 0xc2U, 0x00U, 0xc9U, 0x83U, 0x3dU, 0xa7U,
    0x26U, 0xe9U, 0x37U, 0x6cU, 0x2eU, 0x32U, 0xcfU, 0xf7U};

// AES-256-GCM's known-answer test used to live here; it now runs inside
// crypto::CryptoProvider::SelfTest() (see src/crypto/OpenSslCryptoProvider.cpp,
// which carries the exact same vectors) and its "aes_256_gcm" item is folded
// into this report by RunSecuritySelfTests below. kAes256Gcm stays in
// CryptoOperation/CryptoSelfTestOperation purely so the existing
// CAMERA_FIRMWARE_SECURITY_SELF_TESTING fault-injection hook can still force
// that folded-in item to fail.
enum class CryptoOperation { kSha256, kHmacSha256, kAes256Gcm };
enum class SensitiveBuffer {
  kHmacKey,
  kAesKey,
  kAesPlaintext,
  kAesCiphertext,
  kAesDecryptedPlaintext,
  kAesRejectedPlaintext,
};

struct MacContextDeleter {
  void operator()(EVP_MAC_CTX* context) const noexcept {
    EVP_MAC_CTX_free(context);
  }
};

struct MacDeleter {
  void operator()(EVP_MAC* mac) const noexcept { EVP_MAC_free(mac); }
};

#ifdef CAMERA_FIRMWARE_SECURITY_SELF_TESTING
void RecordZeroization(SensitiveBuffer buffer,
                       std::size_t allocation_size,
                       bool all_zero) noexcept;
#endif

class SensitiveBytes {
 public:
  explicit SensitiveBytes(SensitiveBuffer buffer) : buffer_(buffer) {}
  ~SensitiveBytes() { Cleanse(); }

  SensitiveBytes(const SensitiveBytes&) = delete;
  SensitiveBytes& operator=(const SensitiveBytes&) = delete;

  void assign(const unsigned char* data, std::size_t size) {
    bytes_.assign(data, size);
  }
  void resize(std::size_t size) { bytes_.resize(size); }
  [[nodiscard]] unsigned char* data() noexcept { return bytes_.data(); }
  [[nodiscard]] const unsigned char* data() const noexcept {
    return bytes_.data();
  }
  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }

 private:
  void Cleanse() noexcept {
    if (bytes_.size() != 0U) {
      OPENSSL_cleanse(bytes_.data(), bytes_.size());
#ifdef CAMERA_FIRMWARE_SECURITY_SELF_TESTING
      const std::size_t allocation_size = bytes_.size();
      const bool all_zero =
          std::all_of(bytes_.data(), bytes_.data() + bytes_.size(),
                      [](unsigned char value) { return value == 0U; });
      RecordZeroization(buffer_, allocation_size, all_zero);
#endif
      bytes_.clear();
    }
  }

  SensitiveBuffer buffer_;
  common::SecureBytes bytes_;
};

#ifdef CAMERA_FIRMWARE_SECURITY_SELF_TESTING
std::mutex& TestHookMutex() {
  static std::mutex mutex;
  return mutex;
}

std::optional<CryptoOperation>& InjectedOperation() {
  static std::optional<CryptoOperation> operation;
  return operation;
}

std::vector<SecuritySelfTestZeroizationObservation>& ZeroizationObservations() {
  static std::vector<SecuritySelfTestZeroizationObservation> observations;
  return observations;
}

SecuritySelfTestSensitiveBuffer PublicBuffer(SensitiveBuffer buffer) noexcept {
  switch (buffer) {
    case SensitiveBuffer::kHmacKey:
      return SecuritySelfTestSensitiveBuffer::kHmacKey;
    case SensitiveBuffer::kAesKey:
      return SecuritySelfTestSensitiveBuffer::kAesKey;
    case SensitiveBuffer::kAesPlaintext:
      return SecuritySelfTestSensitiveBuffer::kAesPlaintext;
    case SensitiveBuffer::kAesCiphertext:
      return SecuritySelfTestSensitiveBuffer::kAesCiphertext;
    case SensitiveBuffer::kAesDecryptedPlaintext:
      return SecuritySelfTestSensitiveBuffer::kAesDecryptedPlaintext;
    case SensitiveBuffer::kAesRejectedPlaintext:
      return SecuritySelfTestSensitiveBuffer::kAesRejectedPlaintext;
  }
  return SecuritySelfTestSensitiveBuffer::kHmacKey;
}

void RecordZeroization(SensitiveBuffer buffer,
                       std::size_t allocation_size,
                       bool all_zero) noexcept {
  std::lock_guard lock(TestHookMutex());
  try {
    ZeroizationObservations().push_back(
        {PublicBuffer(buffer), allocation_size, all_zero});
  } catch (...) {
    // swallowed: test-hook bookkeeping must not throw out of the zeroization
    // path
  }
}
#endif

bool ShouldInjectFailure(CryptoOperation operation) noexcept {
#ifdef CAMERA_FIRMWARE_SECURITY_SELF_TESTING
  std::lock_guard lock(TestHookMutex());
  const auto& injected = InjectedOperation();
  return injected.has_value() && *injected == operation;
#else
  (void)operation;
  return false;
#endif
}

bool RunSha256Kat() noexcept {
  try {
    constexpr std::array<unsigned char, 3> kInput{'a', 'b', 'c'};
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0U;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    return context != nullptr &&
           !ShouldInjectFailure(CryptoOperation::kSha256) &&
           EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1 &&
           EVP_DigestUpdate(context.get(), kInput.data(), kInput.size()) == 1 &&
           EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) == 1 &&
           digest_size == kSha256Abc.size() &&
           CRYPTO_memcmp(digest.data(), kSha256Abc.data(), digest_size) == 0;
  } catch (...) {
    return false;
  }
}

bool RunHmacSha256Kat() noexcept {
  try {
    constexpr std::array<unsigned char, 8> kInput{'H', 'i', ' ', 'T',
                                                    'h', 'e', 'r', 'e'};
    SensitiveBytes key(SensitiveBuffer::kHmacKey);
    key.assign(kHmacKey.data(), kHmacKey.size());
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    std::size_t digest_size = 0U;
    std::unique_ptr<EVP_MAC, MacDeleter> mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
    std::unique_ptr<EVP_MAC_CTX, MacContextDeleter> context(
        mac == nullptr ? nullptr : EVP_MAC_CTX_new(mac.get()));
    char digest_name[] = "SHA256";
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name,
                                         0U),
        OSSL_PARAM_construct_end()};
    return mac != nullptr && context != nullptr &&
           !ShouldInjectFailure(CryptoOperation::kHmacSha256) &&
           EVP_MAC_init(context.get(), key.data(), key.size(), parameters) == 1 &&
           EVP_MAC_update(context.get(), kInput.data(), kInput.size()) == 1 &&
           EVP_MAC_final(context.get(), digest.data(), &digest_size,
                         digest.size()) == 1 &&
           digest_size == kHmacSha256CaseOne.size() &&
           CRYPTO_memcmp(digest.data(), kHmacSha256CaseOne.data(), digest_size) ==
               0;
  } catch (...) {
    return false;
  }
}

bool RunDependency(const std::function<common::Result<void>()>& dependency) {
  try {
    return dependency && dependency().ok();
  } catch (...) {
    return false;
  }
}

}  // namespace

common::Result<SelfTestReport> RunSecuritySelfTests(
    const SecuritySelfTestDependencies& dependencies) {
  try {
    SelfTestReport report;
    report.items.reserve(9U);
    const auto append = [&report](std::string id, bool passed,
                                  std::string failure_code) {
      report.items.push_back(
          {std::move(id), passed, passed ? "OK" : std::move(failure_code)});
    };
    append("crypto.sha256", RunSha256Kat(), "E_SELF_TEST_SHA256");
    append("crypto.hmac_sha256", RunHmacSha256Kat(), "E_SELF_TEST_HMAC_SHA256");
    append("security.database", RunDependency(dependencies.database_check),
           "E_SELF_TEST_DATABASE");
    append("security.tls_identity",
           RunDependency(dependencies.tls_identity_check),
           "E_SELF_TEST_TLS_IDENTITY");
    append("security.audit_append", RunDependency(dependencies.audit_append_check),
           "E_SELF_TEST_AUDIT_APPEND");

    // The AES-256-GCM known-answer test moved into crypto::CryptoProvider
    // (Task 1). Hand off to it here instead of shrinking the report if it is
    // missing: a null or failing provider must fail the self-test, not
    // silently produce a smaller passing one.
    if (dependencies.provider == nullptr) {
      append("crypto_provider", false, "E_CRYPTO_UNAVAILABLE");
    } else {
      auto provider_report = dependencies.provider->SelfTest();
      if (!provider_report.ok()) {
        append("crypto_provider", false, provider_report.error().code);
      } else {
        for (const auto& item : provider_report.value().items) {
          bool passed = item.passed;
          std::string code = item.code;
          if (item.id == "aes_256_gcm" &&
              ShouldInjectFailure(CryptoOperation::kAes256Gcm)) {
            passed = false;
            code = "E_SELF_TEST_AES_256_GCM";
          }
          report.items.push_back(
              {item.id, passed, passed ? "OK" : std::move(code)});
        }
      }
    }

    report.passed = true;
    for (const auto& item : report.items) {
      report.passed = report.passed && item.passed;
    }
    return common::Result<SelfTestReport>::Ok(std::move(report));
  } catch (...) {
    return common::Result<SelfTestReport>::Err(
        {"E_SELF_TEST_REPORT", "security self-test report is unavailable"});
  }
}

#ifdef CAMERA_FIRMWARE_SECURITY_SELF_TESTING
void SetSecuritySelfTestCryptoFailureForTest(
    CryptoSelfTestOperation operation) {
  std::lock_guard lock(TestHookMutex());
  switch (operation) {
    case CryptoSelfTestOperation::kSha256:
      InjectedOperation() = CryptoOperation::kSha256;
      break;
    case CryptoSelfTestOperation::kHmacSha256:
      InjectedOperation() = CryptoOperation::kHmacSha256;
      break;
    case CryptoSelfTestOperation::kAes256Gcm:
      InjectedOperation() = CryptoOperation::kAes256Gcm;
      break;
  }
}

void ResetSecuritySelfTestHooksForTest() {
  std::lock_guard lock(TestHookMutex());
  InjectedOperation().reset();
  ZeroizationObservations().clear();
}

std::vector<SecuritySelfTestZeroizationObservation>
SecuritySelfTestZeroizationObservationsForTest() {
  std::lock_guard lock(TestHookMutex());
  return ZeroizationObservations();
}
#endif

}  // namespace camera_firmware::security
