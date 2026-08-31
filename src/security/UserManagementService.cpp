#include "camera_firmware/security/UserManagementService.hpp"

#include <algorithm>
#include <chrono>
#include <string_view>
#include <utility>

#include <gio/gio.h>

#include "camera_firmware/security/PasswordPolicy.hpp"
#include "camera_firmware/security/SecurityStore.hpp"

namespace camera_firmware::security {
namespace {

template <typename T>
common::Result<T> Unavailable() {
  return common::Result<T>::Err(
      {"E_USER_MANAGEMENT_UNAVAILABLE", "user management is unavailable"});
}

common::Result<void> UnavailableVoid() {
  return common::Result<void>::Err(
      {"E_USER_MANAGEMENT_UNAVAILABLE", "user management is unavailable"});
}

std::int64_t DefaultNowSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string CanonicalUsername(std::string_view username) {
  std::string canonical(username);
  std::transform(canonical.begin(), canonical.end(), canonical.begin(),
                 [](unsigned char value) {
                   return static_cast<char>(value >= 'A' && value <= 'Z'
                                                ? value + ('a' - 'A')
                                                : value);
                 });
  return canonical;
}

std::string BoundedSubject(std::string_view subject) {
  constexpr std::size_t kMaximumAuditSubjectBytes = 64U;
  return std::string(subject.substr(0U, kMaximumAuditSubjectBytes));
}

SecurityMutationContext StoreContext(const UserMutationContext& context) {
  return {context.actor.user_id, context.actor.username, context.actor.role,
          context.normalized_peer_ip};
}

ManagedUser PublicUser(StoredManagedUser stored) {
  return {stored.id,
          std::move(stored.display_username),
          stored.role,
          stored.enabled,
          stored.lock_until_seconds,
          stored.created_at_seconds,
          stored.password_changed_at_seconds,
          stored.last_login_at_seconds};
}

ManagementIpEntry PublicManagementIp(StoredManagementIp stored) {
  return {stored.id, std::move(stored.normalized_ip), stored.role,
          stored.created_at_seconds};
}

struct InetAddressDeleter {
  void operator()(GInetAddress* address) const noexcept {
    if (address != nullptr) {
      g_object_unref(address);
    }
  }
};

struct GCharDeleter {
  void operator()(gchar* value) const noexcept { g_free(value); }
};

std::string ManagementIpAuditSubject(std::string_view input) {
  const auto nul = input.find('\0');
  return BoundedSubject(input.substr(0U, nul));
}

class SecretCleanup {
 public:
  explicit SecretCleanup(common::SecureBytes& bytes) noexcept
      : bytes_(&bytes) {}
  ~SecretCleanup() { Clear(); }

  SecretCleanup(const SecretCleanup&) = delete;
  SecretCleanup& operator=(const SecretCleanup&) = delete;

  void Clear() noexcept {
    if (bytes_ != nullptr) {
      bytes_->clear();
      bytes_ = nullptr;
    }
  }

 private:
  common::SecureBytes* bytes_;
};

void ClearPasswordRecord(PasswordRecord& record) noexcept {
  record.salt.clear();
  record.derived.clear();
}

void ClearSnapshot(PasswordMutationSnapshot& snapshot) noexcept {
  ClearPasswordRecord(snapshot.current);
  if (snapshot.previous.has_value()) {
    ClearPasswordRecord(*snapshot.previous);
  }
}

bool IsSemanticUserError(std::string_view code) {
  return code == "E_USER_DUPLICATE" || code == "E_VIEWER_LIMIT" ||
         code == "E_USER_NOT_FOUND" || code == "E_USER_PROTECTED" ||
         code == "E_USER_CONFLICT";
}

bool IsSemanticManagementIpError(std::string_view code) {
  return code == "E_MANAGEMENT_IP_FORBIDDEN" ||
         code == "E_MANAGEMENT_IP_DUPLICATE" ||
         code == "E_MANAGEMENT_IP_LIMIT" ||
         code == "E_MANAGEMENT_IP_NOT_FOUND" ||
         code == "E_MANAGEMENT_IP_ROLE_MISMATCH" ||
         code == "E_MANAGEMENT_IP_PROTECTED";
}

common::Result<bool> VerifyWithCallback(
    const AuthPasswordVerifyCallback& verify,
    const common::SecureBytes& password,
    const PasswordRecord& record) {
  try {
    return verify(password, record);
  } catch (...) {
    return common::Result<bool>::Err(
        {"E_PASSWORD_HASH", "password verification failed"});
  }
}

}  // namespace

// Deliberately not file-local: BootstrapService applies the same rule to the
// addresses submitted through the setup wizard. A management IP is a single
// host and nothing else — g_inet_address_new_from_string parses only a literal
// address, so CIDR, ranges, wildcards and hostnames all fail here, and the
// is_any check is what rejects 0.0.0.0 and ::, which parse but name every
// interface rather than one host.
common::Result<std::string> NormalizeManagementIp(std::string_view input) {
  if (input.empty() || input.find('\0') != std::string_view::npos) {
    return common::Result<std::string>::Err(
        {"E_MANAGEMENT_IP_INVALID", "management IP address is invalid"});
  }
  const std::string text(input);
  std::unique_ptr<GInetAddress, InetAddressDeleter> address(
      g_inet_address_new_from_string(text.c_str()));
  if (!address || g_inet_address_get_is_any(address.get())) {
    return common::Result<std::string>::Err(
        {"E_MANAGEMENT_IP_INVALID", "management IP address is invalid"});
  }
  std::unique_ptr<gchar, GCharDeleter> normalized(
      g_inet_address_to_string(address.get()));
  if (!normalized) {
    return common::Result<std::string>::Err(
        {"E_MANAGEMENT_IP_INVALID", "management IP address is invalid"});
  }
  return common::Result<std::string>::Ok(normalized.get());
}

UserManagementService::UserManagementService(
    SecurityStore& store,
    std::vector<std::string> reserved_identities,
    UserManagementDependencies dependencies)
    : store_(store),
      reserved_identities_(std::move(reserved_identities)),
      dependencies_(std::move(dependencies)) {
  if (!dependencies_.now_seconds) {
    dependencies_.now_seconds = DefaultNowSeconds;
  }
  if (!dependencies_.verify_password) {
    dependencies_.verify_password = VerifyPassword;
  }
}

common::Result<void> UserManagementService::RecordFailure(
    std::int64_t now_seconds,
    std::string_view event_type,
    std::string_view detail_code,
    std::string_view subject_identity,
    const UserMutationContext& context) const {
  auto started = store_.BeginTransaction();
  if (!started.ok()) {
    return UnavailableVoid();
  }
  auto transaction = std::move(started).value();
  try {
    const std::string bounded_subject = BoundedSubject(subject_identity);
    auto audited = store_.InsertAuditEvent(
        transaction, now_seconds, event_type, "failure", context.actor.user_id,
        context.normalized_peer_ip, detail_code, "user", bounded_subject);
    if (!audited.ok()) {
      if (transaction.active()) {
        (void)transaction.Rollback();
      }
      return UnavailableVoid();
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      if (transaction.active()) {
        (void)transaction.Rollback();
      }
      return UnavailableVoid();
    }
    return common::Result<void>::Ok();
  } catch (...) {
    if (transaction.active()) {
      (void)transaction.Rollback();
    }
    return UnavailableVoid();
  }
}

common::Result<void> UserManagementService::RecordManagementIpFailure(
    std::int64_t now_seconds,
    std::string_view event_type,
    std::string_view detail_code,
    std::string_view subject_identity,
    const UserMutationContext& context) const {
  auto started = store_.BeginTransaction();
  if (!started.ok()) {
    return UnavailableVoid();
  }
  auto transaction = std::move(started).value();
  try {
    const std::string bounded_subject = BoundedSubject(subject_identity);
    auto audited = store_.InsertAuditEvent(
        transaction, now_seconds, event_type, "failure", context.actor.user_id,
        context.normalized_peer_ip, detail_code, "management_ip",
        bounded_subject);
    if (!audited.ok()) {
      if (transaction.active()) {
        (void)transaction.Rollback();
      }
      return UnavailableVoid();
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      if (transaction.active()) {
        (void)transaction.Rollback();
      }
      return UnavailableVoid();
    }
    return common::Result<void>::Ok();
  } catch (...) {
    if (transaction.active()) {
      (void)transaction.Rollback();
    }
    return UnavailableVoid();
  }
}

common::Result<std::vector<ManagedUser>>
UserManagementService::ListUsers() const {
  auto stored = store_.ReadManagedUsers();
  if (!stored.ok()) {
    return Unavailable<std::vector<ManagedUser>>();
  }
  try {
    std::vector<ManagedUser> users;
    users.reserve(stored.value().size());
    for (auto& user : stored.value()) {
      users.emplace_back(PublicUser(std::move(user)));
    }
    return common::Result<std::vector<ManagedUser>>::Ok(std::move(users));
  } catch (...) {
    return Unavailable<std::vector<ManagedUser>>();
  }
}

common::Result<ManagedUser> UserManagementService::CreateViewer(
    std::string username,
    common::SecureBytes password,
    const UserMutationContext& context) {
  SecretCleanup password_cleanup(password);
  try {
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (now_seconds < 0) {
      return Unavailable<ManagedUser>();
    }
    const std::string canonical = CanonicalUsername(username);
    const std::string subject = BoundedSubject(canonical);
    if (context.actor.role != UserRole::kAdministrator) {
      if (!RecordFailure(now_seconds, "viewer_created", "role_forbidden",
                         subject, context)
               .ok()) {
        return Unavailable<ManagedUser>();
      }
      return common::Result<ManagedUser>::Err(
          {"E_USER_FORBIDDEN", "viewer creation is forbidden"});
    }

    std::vector<std::string_view> reserved;
    reserved.reserve(reserved_identities_.size());
    for (const auto& identity : reserved_identities_) {
      reserved.emplace_back(identity);
    }
    auto username_policy = ValidateInitialUsername(username, reserved);
    if (!username_policy.ok()) {
      if (!RecordFailure(now_seconds, "viewer_created", "username_policy",
                         subject, context)
               .ok()) {
        return Unavailable<ManagedUser>();
      }
      return common::Result<ManagedUser>::Err(username_policy.error());
    }
    auto password_policy = ValidatePassword(username, password);
    if (!password_policy.ok()) {
      if (!RecordFailure(now_seconds, "viewer_created", "password_policy",
                         subject, context)
               .ok()) {
        return Unavailable<ManagedUser>();
      }
      return common::Result<ManagedUser>::Err(password_policy.error());
    }
    auto derived = DerivePassword(
        password, PasswordHasherDependencies{dependencies_.random_bytes});
    if (!derived.ok()) {
      (void)RecordFailure(now_seconds, "viewer_created",
                          "cryptographic_failure", subject, context);
      return Unavailable<ManagedUser>();
    }
    password_cleanup.Clear();
    auto inserted = store_.InsertViewer(
        canonical, std::move(username), std::move(derived).value(), now_seconds,
        StoreContext(context));
    if (!inserted.ok()) {
      if (IsSemanticUserError(inserted.error().code)) {
        return common::Result<ManagedUser>::Err(inserted.error());
      }
      return Unavailable<ManagedUser>();
    }
    return common::Result<ManagedUser>::Ok(
        PublicUser(std::move(inserted).value()));
  } catch (...) {
    return Unavailable<ManagedUser>();
  }
}

common::Result<void> UserManagementService::SetViewerEnabled(
    std::int64_t user_id,
    bool enabled,
    const UserMutationContext& context) {
  try {
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (now_seconds < 0) {
      return UnavailableVoid();
    }
    const std::string subject = std::to_string(user_id);
    if (context.actor.role != UserRole::kAdministrator) {
      if (!RecordFailure(now_seconds,
                         enabled ? "viewer_enabled" : "viewer_disabled",
                         "role_forbidden", subject, context)
               .ok()) {
        return UnavailableVoid();
      }
      return common::Result<void>::Err(
          {"E_USER_FORBIDDEN", "viewer update is forbidden"});
    }
    auto updated = store_.SetViewerEnabled(user_id, enabled, now_seconds,
                                           StoreContext(context));
    if (!updated.ok()) {
      return IsSemanticUserError(updated.error().code)
                 ? common::Result<void>::Err(updated.error())
                 : UnavailableVoid();
    }
    auto identities = std::move(updated).value().session_identities;
    PublishSessionRevocations(identities, dependencies_.revoke_sessions,
                              dependencies_.revoke_all_streams);
    return common::Result<void>::Ok();
  } catch (...) {
    return UnavailableVoid();
  }
}

common::Result<void> UserManagementService::ResetViewerPassword(
    std::int64_t user_id,
    common::SecureBytes password,
    const UserMutationContext& context) {
  SecretCleanup password_cleanup(password);
  try {
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (now_seconds < 0) {
      return UnavailableVoid();
    }
    const std::string fallback_subject = std::to_string(user_id);
    if (context.actor.role != UserRole::kAdministrator) {
      if (!RecordFailure(now_seconds, "viewer_password_reset",
                         "role_forbidden", fallback_subject, context)
               .ok()) {
        return UnavailableVoid();
      }
      return common::Result<void>::Err(
          {"E_USER_FORBIDDEN", "password reset is forbidden"});
    }
    auto read = store_.ReadPasswordMutationSnapshot(user_id);
    if (!read.ok()) {
      if (read.error().code == "E_USER_NOT_FOUND") {
        if (!RecordFailure(now_seconds, "viewer_password_reset",
                           "user_not_found", fallback_subject, context)
                 .ok()) {
          return UnavailableVoid();
        }
        return common::Result<void>::Err(read.error());
      }
      return UnavailableVoid();
    }
    auto snapshot = std::move(read).value();
    const std::string subject = snapshot.canonical_username;
    const auto fail_after_snapshot = [&](std::string code,
                                         std::string detail) {
      ClearSnapshot(snapshot);
      if (!RecordFailure(now_seconds, "viewer_password_reset", detail,
                         subject, context)
               .ok()) {
        return UnavailableVoid();
      }
      return common::Result<void>::Err(
          {std::move(code), "password reset was rejected"});
    };
    auto policy = ValidatePassword(snapshot.canonical_username, password);
    if (!policy.ok()) {
      const auto error = policy.error();
      ClearSnapshot(snapshot);
      if (!RecordFailure(now_seconds, "viewer_password_reset",
                         "password_policy", subject, context)
               .ok()) {
        return UnavailableVoid();
      }
      return common::Result<void>::Err(error);
    }
    auto current_reuse = VerifyWithCallback(
        dependencies_.verify_password, password, snapshot.current);
    if (!current_reuse.ok()) {
      return fail_after_snapshot("E_USER_MANAGEMENT_UNAVAILABLE",
                                 "cryptographic_failure");
    }
    bool reused = current_reuse.value();
    if (snapshot.previous.has_value()) {
      auto previous_reuse = VerifyWithCallback(
          dependencies_.verify_password, password, *snapshot.previous);
      if (!previous_reuse.ok()) {
        return fail_after_snapshot("E_USER_MANAGEMENT_UNAVAILABLE",
                                   "cryptographic_failure");
      }
      reused = reused || previous_reuse.value();
    }
    if (reused) {
      return fail_after_snapshot("E_PASSWORD_REUSE", "password_reuse");
    }
    auto derived = DerivePassword(
        password, PasswordHasherDependencies{dependencies_.random_bytes});
    if (!derived.ok()) {
      return fail_after_snapshot("E_USER_MANAGEMENT_UNAVAILABLE",
                                 "cryptographic_failure");
    }
    password_cleanup.Clear();
    auto replaced = store_.ReplacePasswordIfCurrent(
        snapshot, std::move(derived).value(),
        PasswordMutationKind::kAdministratorReset, now_seconds,
        StoreContext(context));
    ClearSnapshot(snapshot);
    if (!replaced.ok()) {
      return IsSemanticUserError(replaced.error().code)
                 ? common::Result<void>::Err(replaced.error())
                 : UnavailableVoid();
    }
    auto identities = std::move(replaced).value().session_identities;
    PublishSessionRevocations(identities, dependencies_.revoke_sessions,
                              dependencies_.revoke_all_streams);
    return common::Result<void>::Ok();
  } catch (...) {
    return UnavailableVoid();
  }
}

common::Result<void> UserManagementService::DeleteViewer(
    std::int64_t user_id,
    const UserMutationContext& context) {
  try {
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (now_seconds < 0) {
      return UnavailableVoid();
    }
    const std::string subject = std::to_string(user_id);
    if (context.actor.role != UserRole::kAdministrator) {
      if (!RecordFailure(now_seconds, "viewer_deleted", "role_forbidden",
                         subject, context)
               .ok()) {
        return UnavailableVoid();
      }
      return common::Result<void>::Err(
          {"E_USER_FORBIDDEN", "viewer deletion is forbidden"});
    }
    auto deleted =
        store_.DeleteViewer(user_id, now_seconds, StoreContext(context));
    if (!deleted.ok()) {
      return IsSemanticUserError(deleted.error().code)
                 ? common::Result<void>::Err(deleted.error())
                 : UnavailableVoid();
    }
    auto identities = std::move(deleted).value().session_identities;
    PublishSessionRevocations(identities, dependencies_.revoke_sessions,
                              dependencies_.revoke_all_streams);
    return common::Result<void>::Ok();
  } catch (...) {
    return UnavailableVoid();
  }
}

common::Result<void> UserManagementService::ChangeOwnPassword(
    common::SecureBytes current_password,
    common::SecureBytes replacement_password,
    const UserMutationContext& context) {
  SecretCleanup current_cleanup(current_password);
  SecretCleanup replacement_cleanup(replacement_password);
  try {
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (now_seconds < 0) {
      return UnavailableVoid();
    }
    auto read =
        store_.ReadPasswordMutationSnapshot(context.actor.user_id);
    if (!read.ok()) {
      if (read.error().code == "E_USER_NOT_FOUND") {
        if (!RecordFailure(now_seconds, "password_changed", "user_not_found",
                           context.actor.username, context)
                 .ok()) {
          return UnavailableVoid();
        }
        return common::Result<void>::Err(read.error());
      }
      return UnavailableVoid();
    }
    auto snapshot = std::move(read).value();
    const std::string subject = snapshot.canonical_username;
    const auto fail_after_snapshot = [&](std::string code,
                                         std::string detail) {
      ClearSnapshot(snapshot);
      if (!RecordFailure(now_seconds, "password_changed", detail, subject,
                         context)
               .ok()) {
        return UnavailableVoid();
      }
      return common::Result<void>::Err(
          {std::move(code), "password change was rejected"});
    };
    auto current_matches = VerifyWithCallback(
        dependencies_.verify_password, current_password, snapshot.current);
    if (!current_matches.ok()) {
      return fail_after_snapshot("E_USER_MANAGEMENT_UNAVAILABLE",
                                 "cryptographic_failure");
    }
    if (!current_matches.value()) {
      return fail_after_snapshot("E_CURRENT_PASSWORD",
                                 "current_password_invalid");
    }
    auto policy =
        ValidatePassword(snapshot.canonical_username, replacement_password);
    if (!policy.ok()) {
      const auto error = policy.error();
      ClearSnapshot(snapshot);
      if (!RecordFailure(now_seconds, "password_changed", "password_policy",
                         subject, context)
               .ok()) {
        return UnavailableVoid();
      }
      return common::Result<void>::Err(error);
    }
    auto current_reuse = VerifyWithCallback(
        dependencies_.verify_password, replacement_password,
        snapshot.current);
    if (!current_reuse.ok()) {
      return fail_after_snapshot("E_USER_MANAGEMENT_UNAVAILABLE",
                                 "cryptographic_failure");
    }
    bool reused = current_reuse.value();
    if (snapshot.previous.has_value()) {
      auto previous_reuse = VerifyWithCallback(
          dependencies_.verify_password, replacement_password,
          *snapshot.previous);
      if (!previous_reuse.ok()) {
        return fail_after_snapshot("E_USER_MANAGEMENT_UNAVAILABLE",
                                   "cryptographic_failure");
      }
      reused = reused || previous_reuse.value();
    }
    if (reused) {
      return fail_after_snapshot("E_PASSWORD_REUSE", "password_reuse");
    }
    auto derived = DerivePassword(
        replacement_password,
        PasswordHasherDependencies{dependencies_.random_bytes});
    if (!derived.ok()) {
      return fail_after_snapshot("E_USER_MANAGEMENT_UNAVAILABLE",
                                 "cryptographic_failure");
    }
    current_cleanup.Clear();
    replacement_cleanup.Clear();
    auto replaced = store_.ReplacePasswordIfCurrent(
        snapshot, std::move(derived).value(),
        PasswordMutationKind::kSelfChange, now_seconds, StoreContext(context));
    ClearSnapshot(snapshot);
    if (!replaced.ok()) {
      return IsSemanticUserError(replaced.error().code)
                 ? common::Result<void>::Err(replaced.error())
                 : UnavailableVoid();
    }
    auto identities = std::move(replaced).value().session_identities;
    PublishSessionRevocations(identities, dependencies_.revoke_sessions,
                              dependencies_.revoke_all_streams);
    return common::Result<void>::Ok();
  } catch (...) {
    return UnavailableVoid();
  }
}

common::Result<std::vector<ManagementIpEntry>>
UserManagementService::ListManagementIps() const {
  auto stored = store_.ReadManagementIps();
  if (!stored.ok()) {
    return Unavailable<std::vector<ManagementIpEntry>>();
  }
  try {
    std::vector<ManagementIpEntry> entries;
    entries.reserve(stored.value().size());
    for (auto& entry : stored.value()) {
      entries.emplace_back(PublicManagementIp(std::move(entry)));
    }
    return common::Result<std::vector<ManagementIpEntry>>::Ok(
        std::move(entries));
  } catch (...) {
    return Unavailable<std::vector<ManagementIpEntry>>();
  }
}

common::Result<ManagementIpEntry> UserManagementService::AddManagementIp(
    UserRole role,
    std::string address,
    const UserMutationContext& context) {
  try {
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (now_seconds < 0) {
      return Unavailable<ManagementIpEntry>();
    }
    const std::string audit_subject = ManagementIpAuditSubject(address);
    if (context.actor.role != UserRole::kAdministrator) {
      if (!RecordManagementIpFailure(now_seconds, "management_ip_created",
                                     "role_forbidden", audit_subject, context)
               .ok()) {
        return Unavailable<ManagementIpEntry>();
      }
      return common::Result<ManagementIpEntry>::Err(
          {"E_MANAGEMENT_IP_FORBIDDEN", "management IP creation is forbidden"});
    }
    auto normalized = NormalizeManagementIp(address);
    address.clear();
    if (!normalized.ok()) {
      if (!RecordManagementIpFailure(now_seconds, "management_ip_created",
                                     "invalid_address", audit_subject, context)
               .ok()) {
        return Unavailable<ManagementIpEntry>();
      }
      return common::Result<ManagementIpEntry>::Err(normalized.error());
    }
    auto inserted = store_.InsertManagementIp(
        role, std::move(normalized).value(), now_seconds, StoreContext(context));
    if (!inserted.ok()) {
      return IsSemanticManagementIpError(inserted.error().code)
                 ? common::Result<ManagementIpEntry>::Err(inserted.error())
                 : Unavailable<ManagementIpEntry>();
    }
    return common::Result<ManagementIpEntry>::Ok(
        PublicManagementIp(std::move(inserted).value()));
  } catch (...) {
    return Unavailable<ManagementIpEntry>();
  }
}

common::Result<void> UserManagementService::UpdateManagementIp(
    std::int64_t management_ip_id,
    UserRole role,
    std::string replacement_address,
    const UserMutationContext& context) {
  try {
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (now_seconds < 0) {
      return UnavailableVoid();
    }
    const std::string audit_subject =
        ManagementIpAuditSubject(replacement_address);
    if (context.actor.role != UserRole::kAdministrator) {
      if (!RecordManagementIpFailure(now_seconds, "management_ip_updated",
                                     "role_forbidden", audit_subject, context)
               .ok()) {
        return UnavailableVoid();
      }
      return common::Result<void>::Err(
          {"E_MANAGEMENT_IP_FORBIDDEN", "management IP update is forbidden"});
    }
    auto normalized = NormalizeManagementIp(replacement_address);
    replacement_address.clear();
    if (!normalized.ok()) {
      if (!RecordManagementIpFailure(now_seconds, "management_ip_updated",
                                     "invalid_address", audit_subject, context)
               .ok()) {
        return UnavailableVoid();
      }
      return common::Result<void>::Err(normalized.error());
    }
    auto updated = store_.UpdateManagementIp(
        management_ip_id, role, std::move(normalized).value(), now_seconds,
        StoreContext(context));
    if (!updated.ok()) {
      return IsSemanticManagementIpError(updated.error().code)
                 ? common::Result<void>::Err(updated.error())
                 : UnavailableVoid();
    }
    auto identities = std::move(updated).value().session_identities;
    PublishSessionRevocations(identities, dependencies_.revoke_sessions,
                              dependencies_.revoke_all_streams);
    return common::Result<void>::Ok();
  } catch (...) {
    return UnavailableVoid();
  }
}

common::Result<void> UserManagementService::DeleteManagementIp(
    std::int64_t management_ip_id,
    UserRole role,
    const UserMutationContext& context) {
  try {
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (now_seconds < 0) {
      return UnavailableVoid();
    }
    auto deleted = store_.DeleteManagementIp(
        management_ip_id, role, now_seconds, StoreContext(context));
    if (!deleted.ok()) {
      return IsSemanticManagementIpError(deleted.error().code)
                 ? common::Result<void>::Err(deleted.error())
                 : UnavailableVoid();
    }
    auto identities = std::move(deleted).value().session_identities;
    PublishSessionRevocations(identities, dependencies_.revoke_sessions,
                              dependencies_.revoke_all_streams);
    return common::Result<void>::Ok();
  } catch (...) {
    return UnavailableVoid();
  }
}

}  // namespace camera_firmware::security
