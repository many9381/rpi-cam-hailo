#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <utility>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/crypto/CryptoProvider.hpp"

namespace camera_firmware::security {

inline constexpr std::uint32_t kPasswordKdfIterations = 600000U;
inline constexpr std::uint32_t kPasswordMinAcceptedIterations = 1000U;
inline constexpr std::uint32_t kPasswordMaxAcceptedIterations = 2000000U;
inline constexpr std::size_t kPasswordSaltBytes = 16U;
inline constexpr std::size_t kPasswordDerivedBytes = 32U;

using PasswordRandomCallback =
    std::function<common::Result<common::SecureBytes>(std::size_t output_size)>;
using PasswordKdfCallback = std::function<common::Result<common::SecureBytes>(
    const common::SecureBytes& password, std::span<const unsigned char> salt,
    std::uint32_t iterations, std::size_t output_size)>;
using PasswordScratchAuditCallback =
    std::function<void(common::ZeroizeAudit audit)>;

struct PasswordHasherDependencies {
  PasswordHasherDependencies() = default;
  PasswordHasherDependencies(PasswordRandomCallback random_callback)
      : random_bytes(std::move(random_callback)) {}

  PasswordRandomCallback random_bytes;
  PasswordKdfCallback derive_bytes;
  PasswordScratchAuditCallback scratch_audit;
  crypto::CryptoProvider* provider{nullptr};
};

struct PasswordRecord {
  std::string algorithm{"pbkdf2-hmac-sha256"};
  std::uint32_t iterations{kPasswordKdfIterations};
  common::SecureBytes salt;
  common::SecureBytes derived;
};

[[nodiscard]] common::Result<PasswordRecord> DerivePassword(
    const common::SecureBytes& password,
    PasswordHasherDependencies dependencies = {});

[[nodiscard]] common::Result<bool> VerifyPassword(
    const common::SecureBytes& password, const PasswordRecord& record);

}  // namespace camera_firmware::security
