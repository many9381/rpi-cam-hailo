#pragma once

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"

#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace camera_firmware::rtsp {

struct RtspDigestCredentialPolicy {
  std::string realm;
  std::vector<RtspDigestAlgorithm> algorithms;
};

struct RtspDigestCredentialLookup {
  common::SecureBytes ha1;
  bool matched{false};
};

class RtspDigestCredentialStore {
 public:
  static common::Result<std::unique_ptr<RtspDigestCredentialStore>> Create(
      RtspDigestCredentialPolicy policy);

  ~RtspDigestCredentialStore();

  RtspDigestCredentialStore(const RtspDigestCredentialStore&) = delete;
  RtspDigestCredentialStore& operator=(const RtspDigestCredentialStore&) =
      delete;

  common::Result<void> Reload(const std::filesystem::path& path);
  common::Result<RtspDigestCredentialLookup> Lookup(
      std::string_view username, RtspDigestAlgorithm algorithm) const;
  void Clear() noexcept;
  [[nodiscard]] common::ZeroizeAudit zeroize_audit() const noexcept;

 private:
  struct Impl;

  explicit RtspDigestCredentialStore(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

struct RtspDigestProvisionRequest {
  std::filesystem::path path;
  std::string username;
  std::string realm;
  RtspDigestAlgorithm algorithm{RtspDigestAlgorithm::kSha256};
  bool allow_md5{false};
};

common::Result<void> ProvisionRtspDigestCredential(
    const RtspDigestProvisionRequest& request,
    std::span<const unsigned char> password);

}  // namespace camera_firmware::rtsp
