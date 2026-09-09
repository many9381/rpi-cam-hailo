#pragma once

#include <string>
#include <string_view>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/settings/RuntimeSettingsStore.hpp"

namespace camera_firmware::settings::internal {

common::Result<RuntimeSettingsDocument> DecodeRuntimeSettingsDocument(
    std::string_view input, const config::AppConfig& base_config,
    const CameraProfileCatalog& profiles);

common::Result<std::string> EncodeRuntimeSettingsDocument(
    const RuntimeSettingsDocument& document,
    const config::AppConfig& base_config, const CameraProfileCatalog& profiles);

}  // namespace camera_firmware::settings::internal
