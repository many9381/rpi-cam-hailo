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
#include "camera_firmware/security/SecurityTypes.hpp"

namespace camera_firmware::security {

class BootstrapService;
class AuthService;
class AuditLogService;
class AuditLogServiceTestAccess;
class UserManagementService;

inline constexpr int kSecuritySchemaRevision = 5;

enum class DeviceState { kDefault, kOperational };

struct SecurityStoreConfig {
  std::filesystem::path state_directory;
  std::uint64_t max_audit_events{50000U};
  std::uint32_t audit_warning_percent{90U};
};

struct BootstrapRecord {
  std::string canonical_username;
  std::string display_username;
  PasswordRecord password;
  std::string normalized_peer_ip;
  std::int64_t completed_at_seconds{0};
  // Already normalized, already validated. InitializeDevice registers
  // `normalized_peer_ip` from its own field regardless of what this holds, so
  // an entry repeating the peer is redundant rather than harmful, and an empty
  // vector still leaves the device reachable.
  std::vector<std::string> additional_management_ips;
};

using CredentialInstaller = std::function<common::Result<void>()>;

struct StoredManagedUser {
  std::int64_t id{0};
  std::string canonical_username;
  std::string display_username;
  UserRole role{UserRole::kViewer};
  bool enabled{false};
  std::optional<std::int64_t> lock_until_seconds;
  std::int64_t created_at_seconds{0};
  std::int64_t password_changed_at_seconds{0};
  std::optional<std::int64_t> last_login_at_seconds;
};

struct StoredManagementIp {
  std::int64_t id{0};
  std::string normalized_ip;
  UserRole role{UserRole::kViewer};
  std::int64_t created_at_seconds{0};
};

struct PasswordMutationSnapshot {
  std::int64_t user_id{0};
  std::string canonical_username;
  PasswordRecord current;
  std::optional<PasswordRecord> previous;
  std::int64_t password_changed_at_seconds{0};
};

struct CommittedRevocation {
  std::vector<SessionIdentity> session_identities;
};

struct SecurityMutationContext {
  std::int64_t actor_user_id{0};
  std::string actor_username;
  UserRole actor_role{UserRole::kViewer};
  std::string normalized_peer_ip;
};

enum class PasswordMutationKind { kSelfChange, kAdministratorReset };

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
      BootstrapRecord record, const CredentialInstaller& install_credential);
  common::Result<DeviceState> State() const;
  common::Result<void> CheckHealth() const;
  common::Result<bool> IsManagementPeer(std::string_view normalized_peer_ip);
  [[nodiscard]] const std::filesystem::path& state_directory() const noexcept;
  [[nodiscard]] const std::filesystem::path& database_path() const noexcept;

 private:
  friend class BootstrapService;
  friend class AuthService;
  friend class AuditLogService;
  friend class AuditLogServiceTestAccess;
  friend class UserManagementService;

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
    std::int64_t management_expires_at_seconds{0};
  };

  struct FirmwareLogOutboxEntry {
    std::int64_t id{0};
    std::string category;
    std::string peer_ip;
  };

  struct AuditStatusSnapshot {
    std::uint64_t current_events{0U};
    std::uint64_t max_events{0U};
    std::uint32_t usage_percent{0U};
    bool warning{false};
    std::uint64_t rotated_event_count{0U};
    std::optional<std::int64_t> last_rotation_at_seconds;
    std::optional<std::int64_t> last_rotated_sequence;
  };

  enum class AuditEventSortField {
    kTimestamp,
    kEventType,
    kOutcome,
    kActor,
    kPeerIp,
    kSubject
  };

  enum class AuditEventSortDirection { kAscending, kDescending };

  struct AuditEventCursor {
    std::int64_t sequence{0};
    std::optional<std::int64_t> integer_key;
    std::optional<std::string> text_key;
  };

  struct AuditEventQuery {
    std::optional<std::int64_t> from_seconds;
    std::optional<std::int64_t> to_seconds;
    std::optional<std::string> event_type;
    std::optional<std::string> outcome;
    std::optional<std::string> actor_identity;
    std::optional<std::string> peer_ip;
    std::optional<std::string> subject_type;
    std::optional<std::string> subject_identity;
    AuditEventSortField sort_field{AuditEventSortField::kTimestamp};
    AuditEventSortDirection sort_direction{
        AuditEventSortDirection::kDescending};
    std::uint32_t limit{50U};
    std::optional<AuditEventCursor> cursor;
  };

  struct AuditEventRecord {
    std::int64_t sequence{0};
    std::int64_t server_timestamp_seconds{0};
    std::string event_type;
    std::string outcome;
    std::string actor_identity;
    std::string peer_ip;
    std::string detail_code;
    std::string subject_type;
    std::string subject_identity;
  };

  struct AuditEventQueryResult {
    std::vector<AuditEventRecord> events;
    bool has_more{false};
  };

  explicit SecurityStore(std::shared_ptr<Impl> impl) noexcept;
  common::Result<void> InitializeSchema();
  common::Result<void> MigrateToRevisionFive(int source_revision);
  common::Result<void> RollbackSchemaTransaction();
  common::Result<Transaction> BeginReadTransaction() const;
  common::Result<AuditStatusSnapshot> ReadAuditStatus() const;
  common::Result<AuditEventQueryResult> ReadAuditEvents(
      const AuditEventQuery& query) const;
  common::Result<DeviceState> StateUnderConnectionLease() const;
  common::Result<AuthenticationContext> ReadAuthenticationContext(
      Transaction& transaction, std::string_view canonical_username,
      std::string_view normalized_peer_ip) const;
  common::Result<void> SetLoginFailureState(
      Transaction& transaction, std::int64_t user_id,
      std::int64_t failed_login_count,
      std::optional<std::int64_t> lock_until_seconds);
  common::Result<void> SetLoginSuccessState(Transaction& transaction,
                                            std::int64_t user_id,
                                            std::int64_t now_seconds);
  common::Result<void> InsertAuditEvent(
      Transaction& transaction, std::int64_t now_seconds,
      std::string_view event_type, std::string_view outcome,
      std::optional<std::int64_t> actor_user_id,
      std::string_view normalized_peer_ip, std::string_view detail_code,
      std::string_view subject_type = {},
      std::string_view subject_identity = {});
  common::Result<void> CoalesceFirmwareLogOutbox(
      Transaction& transaction, std::int64_t now_seconds,
      std::string_view category, std::string_view normalized_peer_ip);
  common::Result<std::optional<FirmwareLogOutboxEntry>> ClaimFirmwareLogOutbox(
      std::span<const unsigned char> lease_owner,
      std::span<const unsigned char> lease_token, std::int64_t now_seconds,
      std::int64_t lease_expires_at_seconds);
  common::Result<bool> HasClaimableFirmwareLogOutbox(std::int64_t now_seconds);
  common::Result<void> AcknowledgeFirmwareLogOutbox(
      std::int64_t outbox_id, std::span<const unsigned char> lease_owner,
      std::span<const unsigned char> lease_token);
  common::Result<void> ReleaseFirmwareLogOutbox(
      std::int64_t outbox_id, std::span<const unsigned char> lease_owner,
      std::span<const unsigned char> lease_token);
  common::Result<std::vector<SessionIdentity>> DeleteExpiredSessions(
      Transaction& transaction, std::int64_t now_seconds);
  common::Result<std::optional<std::int64_t>> ReadNextSessionExpiry(
      Transaction& transaction) const;
  common::Result<std::optional<StoredSession>> ReadSessionByUserId(
      Transaction& transaction, std::int64_t user_id) const;
  common::Result<std::optional<StoredSession>> ReadSessionByTokenHash(
      Transaction& transaction, std::span<const unsigned char> token_hash,
      std::string_view normalized_peer_ip, std::int64_t now_seconds) const;
  common::Result<bool> SessionTokenHashExists(
      Transaction& transaction,
      std::span<const unsigned char> token_hash) const;
  common::Result<void> InsertSession(
      Transaction& transaction, std::span<const unsigned char> token_hash,
      std::int64_t user_id, std::string_view role, std::int64_t now_seconds,
      std::int64_t expires_at_seconds, std::string_view normalized_peer_ip,
      std::int64_t management_expires_at_seconds);
  common::Result<void> RefreshSession(Transaction& transaction,
                                      std::int64_t session_id,
                                      std::int64_t now_seconds,
                                      std::int64_t expires_at_seconds);
  common::Result<void> RefreshManagementDeadline(
      Transaction& transaction, std::int64_t session_id,
      std::int64_t management_expires_at_seconds);
  common::Result<std::optional<std::int64_t>> ReadNextManagementExpiry(
      Transaction& transaction) const;
  common::Result<std::size_t> ExpireLapsedManagementAuthority(
      Transaction& transaction, std::int64_t now_seconds);
  common::Result<void> DeleteSession(Transaction& transaction,
                                     std::int64_t session_id);
  common::Result<std::vector<StoredManagedUser>> ReadManagedUsers() const;
  common::Result<StoredManagedUser> InsertViewer(
      std::string canonical_username, std::string display_username,
      PasswordRecord password, std::int64_t now_seconds,
      const SecurityMutationContext& context);
  common::Result<CommittedRevocation> SetViewerEnabled(
      std::int64_t user_id, bool enabled, std::int64_t now_seconds,
      const SecurityMutationContext& context);
  common::Result<PasswordMutationSnapshot> ReadPasswordMutationSnapshot(
      std::int64_t user_id) const;
  common::Result<CommittedRevocation> ReplacePasswordIfCurrent(
      const PasswordMutationSnapshot& expected, PasswordRecord replacement,
      PasswordMutationKind kind, std::int64_t now_seconds,
      const SecurityMutationContext& context);
  common::Result<CommittedRevocation> DeleteViewer(
      std::int64_t user_id, std::int64_t now_seconds,
      const SecurityMutationContext& context);
  common::Result<std::vector<StoredManagementIp>> ReadManagementIps() const;
  common::Result<StoredManagementIp> InsertManagementIp(
      UserRole role, std::string normalized_ip, std::int64_t now_seconds,
      const SecurityMutationContext& context);
  common::Result<CommittedRevocation> UpdateManagementIp(
      std::int64_t management_ip_id, UserRole role,
      std::string normalized_replacement, std::int64_t now_seconds,
      const SecurityMutationContext& context);
  common::Result<CommittedRevocation> DeleteManagementIp(
      std::int64_t management_ip_id, UserRole role, std::int64_t now_seconds,
      const SecurityMutationContext& context);
  // Replaces the device's initial account in one transaction. Only valid while
  // the device is in `default` state, where the initial account is the only row
  // `users` can hold: every other account is created by an authenticated
  // administrator, which cannot exist until setup completes. The account is
  // stored with role 'viewer' so it never occupies the single-administrator
  // slot guarded by users_single_administrator_unique.
  common::Result<void> ReplaceInitialAccount(std::string canonical_username,
                                             std::string display_username,
                                             PasswordRecord password,
                                             std::int64_t now_seconds);
  common::Result<void> InstallBootstrapRtspCredential(
      const std::filesystem::path& configured_path, std::string_view username,
      std::string_view realm, std::span<const unsigned char> password) const;

  std::shared_ptr<Impl> impl_;
};

}  // namespace camera_firmware::security
