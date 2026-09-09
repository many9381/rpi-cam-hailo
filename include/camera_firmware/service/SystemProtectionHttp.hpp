#pragma once

#include <cstddef>
#include <functional>

#include <drogon/HttpResponse.h>
#include <json/value.h>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/security/SystemProtectionService.hpp"

namespace camera_firmware::service {

inline constexpr std::size_t kMaximumProtectionResultItems = 4096U;
inline constexpr std::size_t kMaximumProtectionResultTextBytes =
    integrity::kMaximumIntegrityIdBytes;

using SystemProtectionSnapshotProvider =
    std::function<security::SystemProtectionSnapshot()>;
using SystemProtectionStartProvider =
    std::function<common::Result<security::SystemProtectionSnapshot>()>;

[[nodiscard]] common::Result<Json::Value> BuildSystemProtectionJson(
    const security::SystemProtectionSnapshot& snapshot);
[[nodiscard]] drogon::HttpResponsePtr BuildSystemProtectionStatusResponse(
    const SystemProtectionSnapshotProvider& snapshot_provider);
[[nodiscard]] drogon::HttpResponsePtr BuildSystemProtectionStartResponse(
    const SystemProtectionStartProvider& start_provider);

}  // namespace camera_firmware::service
