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
#include "camera_firmware/security/UserManagementService.hpp"

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

// The largest `management_ips` array `ParseSetupJson` will read. It matches
// security::kMaximumManagementIpsPerRole, the store's ceiling on rows per role
// scope: setup writes administrator-scope rows only, so a body naming more
// addresses than that could never be applied in full and is refused before any
// of it is trusted. Bounding it here also keeps the parse allocation-bounded
// independently of kMaximumSecurityBodyBytes.
inline constexpr std::size_t kMaximumSetupManagementIps = 32U;

// "It matches" above is a claim about two numbers in two headers, and a claim
// is what silently stopped being true the last time one of them was edited
// alone. Raising the store's ceiling without raising this one would make the
// gate reject bodies the store would have accepted; lowering it without
// lowering this one would let the gate admit a list setup cannot finish
// applying. Either way the divergence is now a compile error rather than a
// behaviour to discover in the field.
static_assert(kMaximumSetupManagementIps ==
                  security::kMaximumManagementIpsPerRole,
              "the setup body's management_ips ceiling must track the store's "
              "per-role limit");

struct ParsedSetupRequest {
  std::string username;
  common::SecureBytes password;
  std::string confirmed_peer_ip;
  // Additional addresses the operator asked to admit. Optional on the wire and
  // empty when the key is absent. These are candidates, not the whole answer:
  // `confirmed_peer_ip` is registered whatever this contains.
  std::vector<std::string> management_ips;
};

[[nodiscard]] common::Result<void> AuthorizeSecurityRequest(
    const SecurityRequestContext& context);
[[nodiscard]] bool RouteRefreshesManagementDeadline(std::string_view path,
                                                    std::string_view method);
[[nodiscard]] common::Result<std::string> NormalizePeerIp(
    std::string_view peer_ip);
[[nodiscard]] common::Result<common::SecureBytes> ParseSessionCookie(
    std::string_view cookie_header);
[[nodiscard]] common::Result<common::SecureBytes> ParseSessionCookieHeaders(
    std::span<const std::string> cookie_headers);
[[nodiscard]] common::Result<ParsedLoginRequest> ParseLoginJson(
    std::string_view body, std::string_view content_type);
[[nodiscard]] common::Result<ParsedLoginRequest> ParseLoginJson(
    common::SecureBytes body, std::string_view content_type);
[[nodiscard]] common::Result<common::SecureBytes> ParseReauthenticateJson(
    common::SecureBytes body, std::string_view content_type);
[[nodiscard]] common::Result<ParsedSetupRequest> ParseSetupJson(
    std::string_view body, std::string_view content_type);
[[nodiscard]] common::Result<ParsedSetupRequest> ParseSetupJson(
    common::SecureBytes body, std::string_view content_type);
[[nodiscard]] common::Result<void> ValidateEmptyJsonObject(
    std::string_view body, std::string_view content_type);

}  // namespace camera_firmware::service
