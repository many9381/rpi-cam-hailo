#pragma once

#include <string_view>

#include <drogon/HttpResponse.h>
#include <json/value.h>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/security/AuditLogService.hpp"

namespace camera_firmware::service {

inline constexpr std::size_t kMaximumAuditRawQueryBytes = 4096U;

[[nodiscard]] common::Result<security::AuditQueryParameters>
ParseAuditEventQuery(std::string_view raw_query);
[[nodiscard]] common::Result<void> ValidateEmptyAuditStatusQuery(
    std::string_view raw_query);
Json::Value BuildAuditStatusJson(const security::AuditStatus& status);
Json::Value BuildAuditEventPageJson(const security::AuditEventPage& page);
[[nodiscard]] drogon::HttpResponsePtr BuildAuditLogErrorResponse(
    const common::Error& error);

}  // namespace camera_firmware::service
