#include "camera_firmware/settings/RuntimeSettings.hpp"

#include <cstddef>
#include <cmath>
#include <unordered_set>
#include <utility>

namespace camera_firmware::settings {
namespace {

common::Result<void> CaptureModeError() {
  return common::Result<void>::Err(
      {"E_RUNTIME_SETTINGS_CAPTURE_MODE", "camera profile is unsupported"});
}

common::Result<void> ValidateModelSettings(
    const RuntimeSettings& settings,
    const config::AppConfig& base) {
  std::unordered_set<std::string> base_ids;
  base_ids.reserve(base.ai.models.size());
  for (const auto& model : base.ai.models) {
    base_ids.insert(model.id);
  }

  std::unordered_set<std::string> settings_ids;
  settings_ids.reserve(settings.models.size());
  for (const auto& model : settings.models) {
    if (!settings_ids.insert(model.id).second) {
      return common::Result<void>::Err(
          {"E_RUNTIME_SETTINGS_MODEL_DUPLICATE",
           "runtime settings contain a duplicate model id: " + model.id});
    }
    if (!base_ids.contains(model.id)) {
      return common::Result<void>::Err(
          {"E_RUNTIME_SETTINGS_MODEL_UNKNOWN",
           "runtime settings reference an unknown model id: " + model.id});
    }
    if (!std::isfinite(model.confidence_threshold) ||
        model.confidence_threshold < 0.0F ||
        model.confidence_threshold > 1.0F) {
      return common::Result<void>::Err(
          {"E_RUNTIME_SETTINGS_MODEL_THRESHOLD",
           "runtime model confidence threshold must be finite and between 0 "
           "and 1"});
    }
    if (!base.ai.enabled && model.enabled) {
      return common::Result<void>::Err(
          {"E_RUNTIME_SETTINGS_AI_DISABLED",
           "runtime models cannot be enabled when base AI is disabled"});
    }
  }

  if (settings.models.size() != base.ai.models.size()) {
    return common::Result<void>::Err(
        {"E_RUNTIME_SETTINGS_MODEL_MISSING",
         "runtime settings must contain every configured model id"});
  }

  for (std::size_t index = 0; index < base.ai.models.size(); ++index) {
    if (settings.models[index].id != base.ai.models[index].id) {
      return common::Result<void>::Err(
          {"E_RUNTIME_SETTINGS_MODEL_ORDER",
           "runtime settings model order must match the base configuration"});
    }
  }

  return common::Result<void>::Ok();
}

}  // namespace

CameraProfileCatalog::CameraProfileCatalog(std::vector<CameraProfile> profiles)
    : profiles_(std::move(profiles)) {}

CameraProfileCatalog CameraProfileCatalog::Rpi5Imx708() {
  return CameraProfileCatalog({
      {"imx708-1080p50", "1920x1080 at 50 fps", 1920U, 1080U, 50U},
      {"imx708-1080p30", "1920x1080 at 30 fps", 1920U, 1080U, 30U},
      {"imx708-720p50", "1280x720 at 50 fps", 1280U, 720U, 50U},
  });
}

std::span<const CameraProfile> CameraProfileCatalog::Profiles() const noexcept {
  return profiles_;
}

const CameraProfile* CameraProfileCatalog::Find(
    std::string_view id) const noexcept {
  for (const auto& profile : profiles_) {
    if (profile.id == id) {
      return &profile;
    }
  }
  return nullptr;
}

const CameraProfile* CameraProfileCatalog::Match(
    unsigned int width,
    unsigned int height,
    unsigned int fps) const noexcept {
  for (const auto& profile : profiles_) {
    if (profile.width == width && profile.height == height && profile.fps == fps) {
      return &profile;
    }
  }
  return nullptr;
}

common::Result<RuntimeSettings> DeriveRuntimeSettings(
    const config::AppConfig& base,
    const CameraProfileCatalog& profiles) {
  const auto* profile = profiles.Match(base.camera.video.width,
                                       base.camera.video.height,
                                       base.camera.video.fps);
  if (profile == nullptr) {
    return common::Result<RuntimeSettings>::Err(
        {"E_RUNTIME_SETTINGS_CAPTURE_MODE", "camera profile is unsupported"});
  }

  std::unordered_set<std::string> enabled_model_ids;
  if (base.ai.enabled && base.camera.ai.enabled) {
    enabled_model_ids.insert(base.camera.ai.model_ids.begin(),
                             base.camera.ai.model_ids.end());
  }

  RuntimeSettings settings{
      .camera = {profile->id, base.camera.encoder.bitrate_kbps,
                 base.camera.encoder.gop},
  };
  settings.models.reserve(base.ai.models.size());
  for (const auto& model : base.ai.models) {
    settings.models.push_back({model.id, enabled_model_ids.contains(model.id),
                               model.confidence_threshold});
  }
  return common::Result<RuntimeSettings>::Ok(std::move(settings));
}

common::Result<void> ValidateRuntimeSettings(
    const RuntimeSettings& settings,
    const config::AppConfig& base,
    const CameraProfileCatalog& profiles) {
  if (profiles.Find(settings.camera.profile_id) == nullptr) {
    return CaptureModeError();
  }
  if (settings.camera.bitrate_kbps < kMinBitrateKbps ||
      settings.camera.bitrate_kbps > kMaxBitrateKbps) {
    return common::Result<void>::Err(
        {"E_RUNTIME_SETTINGS_BITRATE",
         "camera bitrate must be between 500 and 20000 kbps"});
  }
  if (settings.camera.gop < kMinGop || settings.camera.gop > kMaxGop) {
    return common::Result<void>::Err(
        {"E_RUNTIME_SETTINGS_GOP", "camera GOP must be between 1 and 300"});
  }
  return ValidateModelSettings(settings, base);
}

common::Result<config::AppConfig> BuildEffectiveConfig(
    const config::AppConfig& base,
    const RuntimeSettings& settings,
    const CameraProfileCatalog& profiles) {
  const auto validated = ValidateRuntimeSettings(settings, base, profiles);
  if (!validated.ok()) {
    return common::Result<config::AppConfig>::Err(validated.error());
  }

  const auto* profile = profiles.Find(settings.camera.profile_id);
  config::AppConfig effective = base;
  effective.camera.video.width = profile->width;
  effective.camera.video.height = profile->height;
  effective.camera.video.fps = profile->fps;
  effective.camera.encoder.bitrate_kbps = settings.camera.bitrate_kbps;
  effective.camera.encoder.gop = settings.camera.gop;

  effective.camera.ai.model_ids.clear();
  for (std::size_t index = 0; index < effective.ai.models.size(); ++index) {
    auto& model = effective.ai.models[index];
    const auto& runtime_model = settings.models[index];
    model.confidence_threshold = runtime_model.confidence_threshold;
    if (runtime_model.enabled) {
      effective.camera.ai.model_ids.push_back(model.id);
    }
  }
  effective.ai.enabled = base.ai.enabled;
  effective.camera.ai.enabled = !effective.camera.ai.model_ids.empty();

  const auto semantics = config::ValidateAppConfigSemantics(effective);
  if (!semantics.ok()) {
    return common::Result<config::AppConfig>::Err(semantics.error());
  }
  return common::Result<config::AppConfig>::Ok(std::move(effective));
}

}  // namespace camera_firmware::settings
