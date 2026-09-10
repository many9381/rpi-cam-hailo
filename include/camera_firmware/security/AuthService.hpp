#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/crypto/CryptoProvider.hpp"
#include "camera_firmware/security/PasswordHasher.hpp"
#include "camera_firmware/security/SecurityTypes.hpp"

namespace camera_firmware::service {
class ServiceApp;
}

namespace camera_firmware::security {

class SecurityStore;
class AuthServiceTestAccess;

inline constexpr std::int64_t kDefaultSessionIdleTimeoutSeconds =
    std::int64_t{10} * 60;

struct LoginRequest {
  std::string username;
  common::SecureBytes password;
  std::string peer_ip;
};

struct LoginResult {
  common::SecureBytes session_token;
  UserRole role{UserRole::kAdministrator};
  std::int64_t idle_expires_at_seconds{0};
};

enum class ManagementActivity { kNone, kManagement };

// The static analyzer cannot see through Result<T>::value() && (a
// std::variant move) and reports the default-initialised user_id as garbage
// in the implicit move constructor.
struct Principal {  // NOLINT(clang-analyzer-core.uninitialized.Assign)
  std::int64_t user_id{0};
  std::string username;
  UserRole role{UserRole::kAdministrator};
  SessionIdentity session_identity;
  bool management_authority_valid{false};
};

using AuthClockCallback = std::function<std::int64_t()>;
using AuthRandomCallback =
    std::function<common::Result<common::SecureBytes>(std::size_t output_size)>;
using AuthPasswordVerifyCallback = std::function<common::Result<bool>(
    const common::SecureBytes& password, const PasswordRecord& record)>;
using AuthHighSeverityLogCallback = std::function<void(
    std::string_view category, std::string_view normalized_peer_ip)>;

struct AuthServiceDependencies {
  AuthClockCallback now_seconds;
  AuthRandomCallback random_bytes;
  AuthPasswordVerifyCallback verify_password;
  AuthHighSeverityLogCallback high_severity_log;
  AuthRandomCallback firmware_log_random_bytes;
  std::int64_t session_idle_timeout_seconds{kDefaultSessionIdleTimeoutSeconds};
  crypto::CryptoProvider* provider{nullptr};
  // The account BootstrapService minted for this boot, and the only account
  // Login() will accept while the device is in `default` state. Engaged only
  // on a device that has never been set up; a device that boots operational
  // has no initial account and leaves this empty, which closes the
  // default-state branch a second time. Canonicalized by the constructor, so
  // callers may pass the display form.
  std::optional<std::string> initial_account_username;
};

struct AuthServiceRuntimeHooks {
  SessionRevocationCallback revoke_sessions;
  GlobalStreamRevocationCallback revoke_all_streams;
};

class AuthService {
 public:
  // Test-only: blocks until the background session-expiry worker has
  // processed every pending wake and parked. Lets tests advance fake
  // clocks without racing an in-flight sweep.
  void WaitForSessionExpiryIdleForTesting();

  explicit AuthService(SecurityStore& store,
                       AuthServiceRuntimeHooks hooks = {});
  ~AuthService();

  common::Result<LoginResult> Login(LoginRequest request);
  common::Result<Principal> Verify(std::span<const unsigned char> token,
                                   std::string_view peer_ip,
                                   ManagementActivity activity);
  common::Result<void> Logout(std::span<const unsigned char> token,
                              std::string_view peer_ip);
  common::Result<std::int64_t> Reauthenticate(
      std::span<const unsigned char> token, std::string_view peer_ip,
      common::SecureBytes password);

 private:
  friend class AuthServiceTestAccess;
  friend class camera_firmware::service::ServiceApp;

  class FirmwareLogWorker;
  class SessionExpiryWorker;
  using FirmwareLogBeforeAckCallback = std::function<void()>;
  using LoginRoleValidatorCallback = std::function<bool(UserRole)>;

  AuthService(SecurityStore& store, AuthServiceDependencies dependencies);
  AuthService(SecurityStore& store, AuthServiceDependencies dependencies,
              FirmwareLogBeforeAckCallback firmware_log_before_ack);
  AuthService(SecurityStore& store, AuthServiceDependencies dependencies,
              AuthServiceRuntimeHooks hooks);
  AuthService(SecurityStore& store, AuthServiceDependencies dependencies,
              AuthServiceRuntimeHooks hooks,
              FirmwareLogBeforeAckCallback firmware_log_before_ack);
  AuthService(SecurityStore& store, AuthServiceDependencies dependencies,
              AuthServiceRuntimeHooks hooks,
              FirmwareLogBeforeAckCallback firmware_log_before_ack,
              LoginRoleValidatorCallback login_role_validator);

  SecurityStore& store_;
  AuthServiceDependencies dependencies_;
  AuthServiceRuntimeHooks hooks_;
  LoginRoleValidatorCallback login_role_validator_;
  std::unique_ptr<FirmwareLogWorker> firmware_log_worker_;
  std::unique_ptr<SessionExpiryWorker> session_expiry_worker_;
};

}  // namespace camera_firmware::security
