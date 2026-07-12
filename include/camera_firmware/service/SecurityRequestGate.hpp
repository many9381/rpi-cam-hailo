#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/security/AuthService.hpp"
#include "camera_firmware/security/SecurityStore.hpp"

namespace camera_firmware::service {

inline constexpr std::string_view kSessionCookieName = "camera_session";
inline constexpr std::size_t kMaximumSecurityBodyBytes = 4096U;

struct SecurityRequestContext {
  security::DeviceState state{security::DeviceState::kDefault};
  std::string path;
  std::string method;
  std::string normalized_peer_ip;
  bool peer_is_management{false};
  std::string origin;
  std::string expected_origin;
  bool has_management_header{false};
  std::optional<security::Principal> principal;
};

struct ParsedLoginRequest {
  std::string username;
  common::SecureBytes password;
};

struct ParsedSetupRequest {
  std::string username;
  common::SecureBytes password;
  std::string confirmed_peer_ip;
};

[[nodiscard]] common::Result<void> AuthorizeSecurityRequest(
    const SecurityRequestContext& context);
[[nodiscard]] common::Result<std::string> NormalizePeerIp(
    std::string_view peer_ip);
[[nodiscard]] common::Result<common::SecureBytes> ParseSessionCookie(
    std::string_view cookie_header);
[[nodiscard]] common::Result<common::SecureBytes> ParseSessionCookieHeaders(
    std::span<const std::string> cookie_headers);
[[nodiscard]] common::Result<ParsedLoginRequest> ParseLoginJson(
    std::string_view body,
    std::string_view content_type);
[[nodiscard]] common::Result<ParsedLoginRequest> ParseLoginJson(
    common::SecureBytes body,
    std::string_view content_type);
[[nodiscard]] common::Result<ParsedSetupRequest> ParseSetupJson(
    std::string_view body,
    std::string_view content_type);
[[nodiscard]] common::Result<ParsedSetupRequest> ParseSetupJson(
    common::SecureBytes body,
    std::string_view content_type);
[[nodiscard]] common::Result<void> ValidateEmptyJsonObject(
    std::string_view body,
    std::string_view content_type);

}  // namespace camera_firmware::service
