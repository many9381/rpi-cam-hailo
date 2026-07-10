#pragma once

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"
#include "camera_firmware/rtsp/RtspDigestNonce.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace camera_firmware::rtsp {

struct RtspDigestAuthorization {
  std::string username;
  std::string realm;
  std::string nonce;
  std::string uri;
  std::string cnonce;
  std::array<char, 8> nonce_count_text{};
  std::uint32_t nonce_count{0};
  RtspDigestAlgorithm algorithm{RtspDigestAlgorithm::kSha256};
  common::SecureBytes response;
};

common::Result<RtspDigestAuthorization> ParseRtspDigestAuthorization(
    std::string_view header);

struct RtspDigestVerifyRequest {
  std::string_view method;
  std::string_view request_uri;
  std::string_view authorization;
};

enum class RtspDigestVerifyStatus { kAuthenticated, kRejected, kStale };

struct RtspDigestVerifierDependencies {
  RtspDigestNonceDependencies nonce;
};

class RtspDigestVerifier {
 public:
  static common::Result<std::unique_ptr<RtspDigestVerifier>> Create(
      const config::RtspClientAuthConfig& config,
      RtspDigestVerifierDependencies dependencies = {});

  ~RtspDigestVerifier();

  RtspDigestVerifier(const RtspDigestVerifier&) = delete;
  RtspDigestVerifier& operator=(const RtspDigestVerifier&) = delete;

  common::Result<RtspDigestVerifyStatus> Verify(
      const RtspDigestVerifyRequest& request);
  common::Result<std::vector<std::string>> BuildChallenges(bool stale);
  common::Result<void> ReloadCredentials();
  void Clear() noexcept;
  [[nodiscard]] common::ZeroizeAudit zeroize_audit() const noexcept;

 private:
  struct Impl;

  explicit RtspDigestVerifier(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::rtsp
