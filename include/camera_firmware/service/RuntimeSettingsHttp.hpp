#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include <drogon/HttpResponse.h>
#include <json/value.h>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/settings/RuntimeSettingsService.hpp"

namespace camera_firmware::service {

inline constexpr std::size_t kMaximumRuntimeSettingsBodyBytes =
    std::size_t{16} * 1024U;

struct RuntimeSettingsUpdateRequest {
  std::uint64_t expected_revision;
  settings::RuntimeSettings settings;
};

struct RuntimeSettingsCommandRequest {
  std::uint64_t expected_revision;
};

[[nodiscard]] common::Result<RuntimeSettingsUpdateRequest>
ParseRuntimeSettingsUpdateJson(std::string_view body,
                               std::string_view content_type);
[[nodiscard]] common::Result<RuntimeSettingsCommandRequest>
ParseRuntimeSettingsCommandJson(std::string_view body,
                                std::string_view content_type);

Json::Value BuildRuntimeSettingsSnapshotJson(
    const settings::RuntimeSettingsSnapshot& snapshot);
drogon::HttpResponsePtr BuildRuntimeSettingsSnapshotResponse(
    const settings::RuntimeSettingsSnapshot& snapshot);
drogon::HttpResponsePtr BuildRuntimeSettingsErrorResponse(
    const common::Error& error);
drogon::HttpResponsePtr BuildRuntimeSettingsApplyResponse(
    const settings::SettingsApplyResult& result);
drogon::HttpResponsePtr BuildProtectionRestrictedResponse();

}  // namespace camera_firmware::service
