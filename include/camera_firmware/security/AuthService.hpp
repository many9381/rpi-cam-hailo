#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/security/PasswordHasher.hpp"

namespace camera_firmware::security {

class SecurityStore;
class AuthServiceTestAccess;

enum class UserRole { kAdministrator, kViewer };

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

struct Principal {
  std::int64_t user_id{0};
  std::string username;
  UserRole role{UserRole::kAdministrator};
};

using AuthClockCallback = std::function<std::int64_t()>;
using AuthRandomCallback = std::function<common::Result<common::SecureBytes>(
    std::size_t output_size)>;
using AuthPasswordVerifyCallback =
    std::function<common::Result<bool>(const common::SecureBytes& password,
                                      const PasswordRecord& record)>;
using AuthHighSeverityLogCallback =
    std::function<void(std::string_view category,
                       std::string_view normalized_peer_ip)>;

struct AuthServiceDependencies {
  AuthClockCallback now_seconds;
  AuthRandomCallback random_bytes;
  AuthPasswordVerifyCallback verify_password;
  AuthHighSeverityLogCallback high_severity_log;
  AuthRandomCallback firmware_log_random_bytes;
};

class AuthService {
 public:
  explicit AuthService(SecurityStore& store);
  ~AuthService();

  common::Result<LoginResult> Login(LoginRequest request);
  common::Result<Principal> Verify(std::span<const unsigned char> token,
                                   std::string_view peer_ip);
  common::Result<void> Logout(std::span<const unsigned char> token,
                              std::string_view peer_ip);

 private:
  friend class AuthServiceTestAccess;

  class FirmwareLogWorker;
  using FirmwareLogBeforeAckCallback = std::function<void()>;

  AuthService(SecurityStore& store, AuthServiceDependencies dependencies);
  AuthService(SecurityStore& store,
              AuthServiceDependencies dependencies,
              FirmwareLogBeforeAckCallback firmware_log_before_ack);

  SecurityStore& store_;
  AuthServiceDependencies dependencies_;
  std::unique_ptr<FirmwareLogWorker> firmware_log_worker_;
};

}  // namespace camera_firmware::security
