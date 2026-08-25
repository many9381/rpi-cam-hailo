#pragma once

#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"

namespace camera_firmware::settings {

inline constexpr unsigned int kMinBitrateKbps = 500U;
inline constexpr unsigned int kMaxBitrateKbps = 20000U;
inline constexpr unsigned int kMinGop = 1U;
inline constexpr unsigned int kMaxGop = 300U;

struct CameraProfile {
  std::string id;
  std::string label;
  unsigned int width;
  unsigned int height;
  unsigned int fps;
};

class CameraProfileCatalog final {
 public:
  static CameraProfileCatalog Rpi5Imx708();

  std::span<const CameraProfile> Profiles() const noexcept;
  const CameraProfile* Find(std::string_view id) const noexcept;
  const CameraProfile* Match(unsigned int width,
                             unsigned int height,
                             unsigned int fps) const noexcept;

 private:
  explicit CameraProfileCatalog(std::vector<CameraProfile> profiles);

  std::vector<CameraProfile> profiles_;
};

struct CameraRuntimeSettings {
  std::string profile_id;
  unsigned int bitrate_kbps;
  unsigned int gop;
};

struct SubStreamRuntimeSettings {
  // Default member initializers mirror the AppConfig sub_stream default and keep
  // the NON-ZERO GEOMETRY INVARIANT true even for a value-initialized/omitted
  // sub_stream: a designated-init RuntimeSettings that omits `.sub_stream` yields
  // a valid disabled sub with real geometry, never all-zero (which the settings
  // validator now rejects and the web client refuses to render).
  bool enabled{false};
  unsigned int width{640};
  unsigned int height{360};
  unsigned int fps{15};
  unsigned int bitrate_kbps{1000};
};

struct ModelRuntimeSettings {
  std::string id;
  bool enabled;
  float confidence_threshold;
};

struct RuntimeSettings {
  CameraRuntimeSettings camera;
  SubStreamRuntimeSettings sub_stream;
  std::vector<ModelRuntimeSettings> models;
};

common::Result<RuntimeSettings> DeriveRuntimeSettings(
    const config::AppConfig& base,
    const CameraProfileCatalog& profiles);
common::Result<void> ValidateRuntimeSettings(
    const RuntimeSettings& settings,
    const config::AppConfig& base,
    const CameraProfileCatalog& profiles);
common::Result<config::AppConfig> BuildEffectiveConfig(
    const config::AppConfig& base,
    const RuntimeSettings& settings,
    const CameraProfileCatalog& profiles);

}  // namespace camera_firmware::settings
