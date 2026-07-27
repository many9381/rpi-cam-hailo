#pragma once

#include <atomic>

#include "camera_firmware/crypto/CryptoProvider.hpp"

namespace camera_firmware::crypto {

class OpenSslCryptoProvider final : public CryptoProvider {
 public:
  OpenSslCryptoProvider() = default;

  [[nodiscard]] common::Result<SelfTestReport> SelfTest() override;
  [[nodiscard]] ProviderStatus Status() const noexcept override;

  [[nodiscard]] common::Result<common::SecureBytes> RandomBytes(
      std::size_t output_size) override;
  [[nodiscard]] common::Result<common::SecureBytes> RandomBytesPrivate(
      std::size_t output_size) override;
  [[nodiscard]] common::Result<common::SecureBytes> DeriveKeyPbkdf2(
      const common::SecureBytes& password,
      std::span<const unsigned char> salt,
      std::uint32_t iterations,
      std::size_t output_size) override;
  [[nodiscard]] common::Result<
      std::array<unsigned char, kEd25519SignatureBytes>>
  SignEd25519(std::span<const unsigned char> message,
              std::span<const unsigned char> private_key_seed) override;
  [[nodiscard]] common::Result<bool> VerifyEd25519(
      std::span<const unsigned char> message,
      std::span<const unsigned char> signature,
      std::span<const unsigned char> public_key) override;
  [[nodiscard]] common::Result<void> SealAesGcm(
      std::span<const unsigned char> key,
      std::span<const unsigned char> nonce,
      std::span<const unsigned char> plaintext,
      std::span<const unsigned char> associated_data,
      std::span<unsigned char> ciphertext_out,
      std::span<unsigned char> tag_out) override;
  [[nodiscard]] common::Result<void> OpenAesGcm(
      std::span<const unsigned char> key,
      std::span<const unsigned char> nonce,
      std::span<const unsigned char> ciphertext,
      std::span<const unsigned char> associated_data,
      std::span<const unsigned char> tag,
      std::span<unsigned char> plaintext_out) override;

 private:
  std::atomic<ProviderStatus> status_{ProviderStatus::kUninitialized};
};

}  // namespace camera_firmware::crypto
