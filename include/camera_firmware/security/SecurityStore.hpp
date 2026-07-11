#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/security/PasswordHasher.hpp"

namespace camera_firmware::security {

class BootstrapService;
class AuthService;

enum class DeviceState { kDefault, kOperational };

struct SecurityStoreConfig {
  std::filesystem::path state_directory;
};

struct BootstrapRecord {
  std::string canonical_username;
  std::string display_username;
  PasswordRecord password;
  std::string normalized_peer_ip;
  std::int64_t completed_at_seconds{0};
};

using CredentialInstaller = std::function<common::Result<void>()>;

class SecurityStore {
 private:
  struct Impl;

 public:
  class Transaction {
   public:
    ~Transaction();

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    Transaction(Transaction&& other) noexcept;
    Transaction& operator=(Transaction&& other) = delete;

    common::Result<void> Commit();
    common::Result<void> Rollback();
    [[nodiscard]] bool active() const noexcept;

   private:
    friend class SecurityStore;
    Transaction(std::shared_ptr<Impl> impl,
                std::unique_lock<std::mutex> connection_lease) noexcept;

    std::shared_ptr<Impl> impl_;
    std::unique_lock<std::mutex> connection_lease_;
    bool active_{false};
  };

  static common::Result<std::unique_ptr<SecurityStore>> Open(
      SecurityStoreConfig config);
  ~SecurityStore();

  SecurityStore(const SecurityStore&) = delete;
  SecurityStore& operator=(const SecurityStore&) = delete;

  common::Result<Transaction> BeginTransaction();
  // Lock order: BootstrapService mutex, connection lease, credential installer.
  common::Result<void> InitializeDevice(
      BootstrapRecord record,
      const CredentialInstaller& install_credential);
  common::Result<DeviceState> State() const;
  [[nodiscard]] const std::filesystem::path& state_directory() const noexcept;
  [[nodiscard]] const std::filesystem::path& database_path() const noexcept;

 private:
  friend class BootstrapService;
  friend class AuthService;

  struct AuthenticationUser {
    std::int64_t id{0};
    std::string display_username;
    std::string role;
    bool enabled{false};
    PasswordRecord password;
    std::int64_t failed_login_count{0};
    std::optional<std::int64_t> lock_until_seconds;
    std::int64_t created_at_seconds{0};
    std::optional<std::int64_t> last_login_at_seconds;
  };

  struct AuthenticationContext {
    DeviceState state{DeviceState::kDefault};
    bool peer_registered{false};
    std::optional<AuthenticationUser> user;
  };

  struct StoredSession {
    std::int64_t id{0};
    common::SecureBytes token_hash;
    std::int64_t user_id{0};
    std::string username;
    std::string role;
    std::int64_t created_at_seconds{0};
    std::int64_t last_activity_at_seconds{0};
    std::int64_t expires_at_seconds{0};
    std::string peer_ip;
  };

  struct FirmwareLogOutboxEntry {
    std::int64_t id{0};
    std::string category;
    std::string peer_ip;
  };

  explicit SecurityStore(std::shared_ptr<Impl> impl) noexcept;
  common::Result<void> InitializeSchema();
  common::Result<Transaction> BeginReadTransaction();
  common::Result<DeviceState> StateUnderConnectionLease() const;
  common::Result<AuthenticationContext> ReadAuthenticationContext(
      Transaction& transaction,
      std::string_view canonical_username,
      std::string_view normalized_peer_ip) const;
  common::Result<void> SetLoginFailureState(
      Transaction& transaction,
      std::int64_t user_id,
      std::int64_t failed_login_count,
      std::optional<std::int64_t> lock_until_seconds);
  common::Result<void> SetLoginSuccessState(Transaction& transaction,
                                            std::int64_t user_id,
                                            std::int64_t now_seconds);
  common::Result<void> InsertAuditEvent(
      Transaction& transaction,
      std::int64_t now_seconds,
      std::string_view event_type,
      std::string_view outcome,
      std::optional<std::int64_t> actor_user_id,
      std::string_view normalized_peer_ip,
      std::string_view detail_code);
  common::Result<void> CoalesceFirmwareLogOutbox(
      Transaction& transaction,
      std::int64_t now_seconds,
      std::string_view category,
      std::string_view normalized_peer_ip);
  common::Result<std::optional<FirmwareLogOutboxEntry>>
  ClaimFirmwareLogOutbox(std::span<const unsigned char> lease_owner,
                         std::span<const unsigned char> lease_token,
                         std::int64_t now_seconds,
                         std::int64_t lease_expires_at_seconds);
  common::Result<bool> HasClaimableFirmwareLogOutbox(
      std::int64_t now_seconds);
  common::Result<void> AcknowledgeFirmwareLogOutbox(
      std::int64_t outbox_id,
      std::span<const unsigned char> lease_owner,
      std::span<const unsigned char> lease_token);
  common::Result<void> ReleaseFirmwareLogOutbox(
      std::int64_t outbox_id,
      std::span<const unsigned char> lease_owner,
      std::span<const unsigned char> lease_token);
  common::Result<void> DeleteExpiredSessions(Transaction& transaction,
                                              std::int64_t now_seconds);
  common::Result<std::optional<StoredSession>> ReadAdministratorSession(
      Transaction& transaction) const;
  common::Result<std::optional<StoredSession>> ReadSessionByTokenHash(
      Transaction& transaction,
      std::span<const unsigned char> token_hash) const;
  common::Result<bool> SessionTokenHashExists(
      Transaction& transaction,
      std::span<const unsigned char> token_hash) const;
  common::Result<void> InsertSession(
      Transaction& transaction,
      std::span<const unsigned char> token_hash,
      std::int64_t user_id,
      std::string_view role,
      std::int64_t now_seconds,
      std::int64_t expires_at_seconds,
      std::string_view normalized_peer_ip);
  common::Result<void> RefreshSession(Transaction& transaction,
                                      std::int64_t session_id,
                                      std::int64_t now_seconds,
                                      std::int64_t expires_at_seconds);
  common::Result<void> DeleteSession(Transaction& transaction,
                                     std::int64_t session_id);
  common::Result<void> InstallBootstrapRtspCredential(
      const std::filesystem::path& configured_path,
      std::string_view username,
      std::string_view realm,
      std::span<const unsigned char> password) const;

  std::shared_ptr<Impl> impl_;
};

}  // namespace camera_firmware::security
