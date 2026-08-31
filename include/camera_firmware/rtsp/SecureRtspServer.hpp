#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/EncodedRing.hpp"

namespace camera_firmware::media {

// Describes an optional second ("sub-stream") RTSP mount fed from its own
// EncodedRing, activated on demand as clients attach/detach.
struct SubMountDescriptor {
  std::string mount;
  EncodedRing* ring;
  // Called on the sub media's first-client edge (media-configure/prepared).
  std::function<void()> on_activate;
  // Called on the last-client edge (unprepared).
  std::function<void()> on_deactivate;
};

}  // namespace camera_firmware::media

namespace camera_firmware::rtsp {

std::string BuildRtspUrl(const config::SecureRtspConfig& config);

struct SecureEncoderHookProbe {
  std::string rtp_element_factory_name;
  std::string rtcp_element_factory_name;
  std::size_t per_media_key_zeroize_count{0};
};

struct SecureMediaDescription {
  std::string control_scheme;
  std::string media_profile;
  std::string keying;
  bool requires_tls_control_channel{false};
};

SecureMediaDescription DescribeSecureMedia(
    const config::SecureRtspConfig& config);
common::Result<void> ValidateSecureRtspConfigFiles(
    const config::SecureRtspConfig& config);
common::Result<void> RegisterBuildTreeSecureSrtpPluginPath(
    const std::string& path);
common::Result<void> VerifySecureMediaPath();
common::Result<SecureEncoderHookProbe> VerifySecureEncoderHooks();

class SecureRtspServer {
 public:
  SecureRtspServer();
  ~SecureRtspServer();

  SecureRtspServer(const SecureRtspServer&) = delete;
  SecureRtspServer& operator=(const SecureRtspServer&) = delete;
  SecureRtspServer(SecureRtspServer&&) = delete;
  SecureRtspServer& operator=(SecureRtspServer&&) = delete;

  [[nodiscard]] common::Result<void> Start(
      const config::SecureRtspConfig& config,
      media::EncodedRing& main_ring,
      const media::SubMountDescriptor* sub = nullptr);
  [[nodiscard]] common::Result<void> ReloadClientCredentials();
  void Stop();
  [[nodiscard]] std::size_t PerMediaKeyAllocationCount() const noexcept;
  [[nodiscard]] std::size_t PerMediaKeyZeroizeCount() const noexcept;

 private:
  struct Impl;

  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::rtsp
