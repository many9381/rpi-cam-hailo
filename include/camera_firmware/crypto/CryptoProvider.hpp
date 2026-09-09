#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"

namespace camera_firmware::crypto {

inline constexpr std::size_t kEd25519SignatureBytes = 64U;
inline constexpr std::size_t kEd25519SeedBytes = 32U;
inline constexpr std::size_t kEd25519PublicKeyBytes = 32U;
inline constexpr std::size_t kAesGcmKeyBytes = 32U;
inline constexpr std::size_t kAesGcmNonceBytes = 12U;
inline constexpr std::size_t kAesGcmTagBytes = 16U;

enum class ProviderStatus { kUninitialized, kOperational, kFailed };

struct SelfTestItem {
  std::string id;
  bool passed{false};
  std::string code;
};

struct SelfTestReport {
  bool passed{false};
  std::vector<SelfTestItem> items;
};

class CryptoProvider {
 public:
  virtual ~CryptoProvider() = default;

  CryptoProvider(const CryptoProvider&) = delete;
  CryptoProvider& operator=(const CryptoProvider&) = delete;
  CryptoProvider(CryptoProvider&&) = delete;
  CryptoProvider& operator=(CryptoProvider&&) = delete;

  [[nodiscard]] virtual common::Result<SelfTestReport> SelfTest() = 0;
  [[nodiscard]] virtual ProviderStatus Status() const noexcept = 0;

  [[nodiscard]] virtual common::Result<common::SecureBytes> RandomBytes(
      std::size_t output_size) = 0;
  // Draws from the platform's private (non-public) DRBG instance, distinct
  // from RandomBytes's public-DRBG output. Reserved for material that must
  // not share a randomness pool with anything else in the process, such as
  // AuthService's session tokens and firmware-log nonces.
  [[nodiscard]] virtual common::Result<common::SecureBytes> RandomBytesPrivate(
      std::size_t output_size) = 0;
  [[nodiscard]] virtual common::Result<common::SecureBytes> DeriveKeyPbkdf2(
      const common::SecureBytes& password, std::span<const unsigned char> salt,
      std::uint32_t iterations, std::size_t output_size) = 0;
  [[nodiscard]] virtual common::Result<
      std::array<unsigned char, kEd25519SignatureBytes>>
  SignEd25519(std::span<const unsigned char> message,
              std::span<const unsigned char> private_key_seed) = 0;
  [[nodiscard]] virtual common::Result<bool> VerifyEd25519(
      std::span<const unsigned char> message,
      std::span<const unsigned char> signature,
      std::span<const unsigned char> public_key) = 0;
  [[nodiscard]] virtual common::Result<void> SealAesGcm(
      std::span<const unsigned char> key, std::span<const unsigned char> nonce,
      std::span<const unsigned char> plaintext,
      std::span<const unsigned char> associated_data,
      std::span<unsigned char> ciphertext_out,
      std::span<unsigned char> tag_out) = 0;
  [[nodiscard]] virtual common::Result<void> OpenAesGcm(
      std::span<const unsigned char> key, std::span<const unsigned char> nonce,
      std::span<const unsigned char> ciphertext,
      std::span<const unsigned char> associated_data,
      std::span<const unsigned char> tag,
      std::span<unsigned char> plaintext_out) = 0;

 protected:
  CryptoProvider() = default;
};

}  // namespace camera_firmware::crypto
