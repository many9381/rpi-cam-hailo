#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/security/AuthService.hpp"
#include "camera_firmware/security/PasswordHasher.hpp"
#include "camera_firmware/security/SecurityTypes.hpp"

namespace camera_firmware::security {

class SecurityStore;

inline constexpr std::size_t kMaximumViewerUsers = 32U;
inline constexpr std::size_t kMaximumManagementIpsPerRole = 32U;

// The single answer to "is this text one management host?", shared by the
// administrator-only management-IP routes and by setup. Returns the canonical
// spelling of `input`, or E_MANAGEMENT_IP_INVALID for anything that is not a
// literal single address — CIDR, ranges, wildcards, hostnames, and the
// wildcard addresses 0.0.0.0 and :: included.
[[nodiscard]] common::Result<std::string> NormalizeManagementIp(
    std::string_view input);

struct ManagedUser {
  std::int64_t id{0};
  std::string username;
  UserRole role{UserRole::kViewer};
  bool enabled{false};
  std::optional<std::int64_t> lock_until_seconds;
  std::int64_t created_at_seconds{0};
  std::int64_t password_changed_at_seconds{0};
  std::optional<std::int64_t> last_login_at_seconds;
};

struct ManagementIpEntry {
  std::int64_t id{0};
  std::string normalized_ip;
  UserRole role{UserRole::kViewer};
  std::int64_t created_at_seconds{0};
};

struct UserMutationContext {
  Principal actor;
  std::string normalized_peer_ip;
};

struct UserManagementDependencies {
  AuthClockCallback now_seconds;
  PasswordRandomCallback random_bytes;
  AuthPasswordVerifyCallback verify_password;
  SessionRevocationCallback revoke_sessions;
  GlobalStreamRevocationCallback revoke_all_streams;
};

class UserManagementService {
 public:
  UserManagementService(
      SecurityStore& store,
      std::vector<std::string> reserved_identities,
      UserManagementDependencies dependencies = {});

  common::Result<std::vector<ManagedUser>> ListUsers() const;
  common::Result<ManagedUser> CreateViewer(
      std::string username,
      common::SecureBytes password,
      const UserMutationContext& context);
  common::Result<void> SetViewerEnabled(
      std::int64_t user_id,
      bool enabled,
      const UserMutationContext& context);
  common::Result<void> ResetViewerPassword(
      std::int64_t user_id,
      common::SecureBytes password,
      const UserMutationContext& context);
  common::Result<void> DeleteViewer(
      std::int64_t user_id,
      const UserMutationContext& context);
  common::Result<void> ChangeOwnPassword(
      common::SecureBytes current_password,
      common::SecureBytes replacement_password,
      const UserMutationContext& context);
  common::Result<std::vector<ManagementIpEntry>> ListManagementIps() const;
  common::Result<ManagementIpEntry> AddManagementIp(
      UserRole role,
      std::string address,
      const UserMutationContext& context);
  common::Result<void> UpdateManagementIp(
      std::int64_t management_ip_id,
      UserRole role,
      std::string replacement_address,
      const UserMutationContext& context);
  common::Result<void> DeleteManagementIp(
      std::int64_t management_ip_id,
      UserRole role,
      const UserMutationContext& context);

 private:
  common::Result<void> RecordFailure(
      std::int64_t now_seconds,
      std::string_view event_type,
      std::string_view detail_code,
      std::string_view subject_identity,
      const UserMutationContext& context) const;
  common::Result<void> RecordManagementIpFailure(
      std::int64_t now_seconds,
      std::string_view event_type,
      std::string_view detail_code,
      std::string_view subject_identity,
      const UserMutationContext& context) const;

  SecurityStore& store_;
  std::vector<std::string> reserved_identities_;
  UserManagementDependencies dependencies_;
};

}  // namespace camera_firmware::security
