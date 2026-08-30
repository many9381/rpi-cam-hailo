#pragma once

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/crypto/CryptoProvider.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace camera_firmware::rtsp {

struct RtspDigestNonceDependencies {
  std::function<std::uint64_t()> now_seconds;
  std::function<common::Result<common::SecureBytes>(std::size_t)>
      random_bytes;
  crypto::CryptoProvider* provider{nullptr};
};

enum class RtspDigestNonceStatus { kValid, kExpired, kInvalid };

struct RtspDigestNonceValidation {
  RtspDigestNonceStatus status{RtspDigestNonceStatus::kInvalid};
  std::array<unsigned char, 32> nonce_id{};
  std::uint64_t expires_at{0};
};

class RtspDigestNonceManager {
 public:
  static common::Result<std::unique_ptr<RtspDigestNonceManager>> Create(
      std::chrono::seconds ttl,
      RtspDigestNonceDependencies dependencies = {},
      std::size_t replay_capacity = 4096);

  ~RtspDigestNonceManager();

  RtspDigestNonceManager(const RtspDigestNonceManager&) = delete;
  RtspDigestNonceManager& operator=(const RtspDigestNonceManager&) = delete;

  common::Result<std::string> Issue();
  common::Result<RtspDigestNonceValidation> Validate(
      std::string_view nonce) const;
  // with_qop=false is a legacy RFC 2069 authorization, which carries no nonce
  // count; a zero nonce_count is then accepted and the nonce becomes
  // single-use (a second use of the same nonce fails the monotonic check).
  common::Result<bool> Commit(
      std::string_view username,
      const RtspDigestNonceValidation& validation,
      std::uint32_t nonce_count,
      bool with_qop = true);
  void Clear() noexcept;
  [[nodiscard]] common::ZeroizeAudit zeroize_audit() const noexcept;

 private:
  struct Impl;

  explicit RtspDigestNonceManager(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::rtsp
