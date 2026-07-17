#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <json/value.h>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/security/UserManagementService.hpp"

namespace camera_firmware::service {

struct ParsedCreateViewerRequest {
  std::string username;
  common::SecureBytes password;
};

struct ParsedSetViewerEnabledRequest {
  bool enabled{false};
};

struct ParsedPasswordResetRequest {
  common::SecureBytes password;
};

struct ParsedOwnPasswordRequest {
  common::SecureBytes current_password;
  common::SecureBytes replacement_password;
};

struct ParsedManagementIpRequest {
  std::string address;
};

[[nodiscard]] common::Result<ParsedCreateViewerRequest> ParseCreateViewerJson(
    common::SecureBytes body,
    std::string_view content_type);
[[nodiscard]] common::Result<ParsedSetViewerEnabledRequest>
ParseSetViewerEnabledJson(std::string_view body, std::string_view content_type);
[[nodiscard]] common::Result<ParsedPasswordResetRequest> ParsePasswordResetJson(
    common::SecureBytes body,
    std::string_view content_type);
[[nodiscard]] common::Result<ParsedOwnPasswordRequest> ParseOwnPasswordJson(
    common::SecureBytes body,
    std::string_view content_type);
[[nodiscard]] common::Result<ParsedManagementIpRequest> ParseManagementIpJson(
    std::string_view body,
    std::string_view content_type);
[[nodiscard]] common::Result<void> ValidateEmptyRequestBody(
    std::string_view body);

[[nodiscard]] common::Result<std::int64_t> ParseManagedResourceId(
    std::string_view value);
[[nodiscard]] common::Result<security::UserRole> ParseManagedRole(
    std::string_view value);
Json::Value BuildManagedUserJson(const security::ManagedUser& user);
Json::Value BuildManagementIpJson(const security::ManagementIpEntry& entry);
[[nodiscard]] drogon::HttpResponsePtr BuildUserManagementErrorResponse(
    const common::Error& error);
[[nodiscard]] drogon::HttpStatusCode UserManagementErrorStatus(
    std::string_view code);

}  // namespace camera_firmware::service
