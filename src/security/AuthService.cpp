#include "camera_firmware/security/AuthService.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <gio/gio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/security/SecurityStore.hpp"

namespace camera_firmware::security {
namespace {

constexpr std::size_t kSessionTokenBytes = 32U;
constexpr std::size_t kSessionTokenHashBytes = 32U;
constexpr std::int64_t kLockDurationSeconds = 5 * 60;
constexpr std::int64_t kIdleDurationSeconds = 10 * 60;
constexpr int kFailureLimit = 5;
constexpr int kTokenGenerationAttempts = 4;
constexpr std::string_view kAuthenticationFailureCode =
    "E_AUTHENTICATION_FAILED";
constexpr std::string_view kAuthenticationFailureMessage =
    "authentication failed";

template <typename T>
common::Result<T> AuthenticationFailure() {
  return common::Result<T>::Err(
      {std::string(kAuthenticationFailureCode),
       std::string(kAuthenticationFailureMessage)});
}

template <typename T>
common::Result<T> AuthenticationUnavailable() {
  return common::Result<T>::Err(
      {"E_AUTHENTICATION_UNAVAILABLE", "authentication service unavailable"});
}

class PasswordCleanupGuard {
 public:
  explicit PasswordCleanupGuard(common::SecureBytes& password) noexcept
      : password_(password) {}
  ~PasswordCleanupGuard() { password_.clear(); }

  PasswordCleanupGuard(const PasswordCleanupGuard&) = delete;
  PasswordCleanupGuard& operator=(const PasswordCleanupGuard&) = delete;

 private:
  common::SecureBytes& password_;
};

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

common::Result<std::string> NormalizePeerIp(std::string_view input) {
  if (input.empty() || input.find('\0') != std::string_view::npos) {
    return AuthenticationFailure<std::string>();
  }
  std::string text;
  try {
    text.assign(input);
  } catch (...) {
    return AuthenticationFailure<std::string>();
  }
  std::unique_ptr<GInetAddress, InetAddressDeleter> address(
      g_inet_address_new_from_string(text.c_str()));
  if (!address) {
    return AuthenticationFailure<std::string>();
  }
  std::unique_ptr<gchar, GCharDeleter> normalized(
      g_inet_address_to_string(address.get()));
  if (!normalized) {
    return AuthenticationFailure<std::string>();
  }
  return common::Result<std::string>::Ok(normalized.get());
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

std::int64_t DefaultNowSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

common::Result<common::SecureBytes> DefaultRandom(std::size_t output_size) {
  if (output_size > static_cast<std::size_t>(INT_MAX)) {
    return AuthenticationUnavailable<common::SecureBytes>();
  }
  common::SecureBytes output;
  try {
    output.resize(output_size);
  } catch (...) {
    return AuthenticationUnavailable<common::SecureBytes>();
  }
  if (::RAND_priv_bytes(output.data(), static_cast<int>(output.size())) != 1) {
    return AuthenticationUnavailable<common::SecureBytes>();
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

common::Result<common::SecureBytes> HashToken(
    std::span<const unsigned char> token) {
  common::SecureBytes digest;
  try {
    digest.resize(kSessionTokenHashBytes);
  } catch (...) {
    return AuthenticationUnavailable<common::SecureBytes>();
  }
  std::size_t digest_size = 0;
  if (::EVP_Q_digest(nullptr, "SHA256", nullptr, token.data(), token.size(),
                     digest.data(), &digest_size) != 1 ||
      digest_size != kSessionTokenHashBytes) {
    return AuthenticationUnavailable<common::SecureBytes>();
  }
  return common::Result<common::SecureBytes>::Ok(std::move(digest));
}

struct ProcessDummyPassword {
  ProcessDummyPassword() {
    record.salt.resize(kPasswordSaltBytes);
    record.derived.resize(kPasswordDerivedBytes);
    valid = ::RAND_priv_bytes(record.salt.data(),
                              static_cast<int>(record.salt.size())) == 1 &&
            ::RAND_priv_bytes(record.derived.data(),
                              static_cast<int>(record.derived.size())) == 1;
    if (!valid) {
      record.salt.clear();
      record.derived.clear();
    }
  }

  PasswordRecord record;
  bool valid{false};
};

const ProcessDummyPassword& DummyPassword() {
  static const ProcessDummyPassword dummy;
  return dummy;
}

bool HasSafeDeadline(std::int64_t now_seconds) {
  return now_seconds >= 0 &&
         now_seconds <=
             std::numeric_limits<std::int64_t>::max() - kIdleDurationSeconds;
}

bool PasswordRecordsEqual(const PasswordRecord& first,
                          const PasswordRecord& second) {
  if (first.algorithm != second.algorithm ||
      first.iterations != second.iterations ||
      first.salt.size() != second.salt.size() ||
      first.derived.size() != second.derived.size()) {
    return false;
  }
  const bool salt_equal =
      first.salt.size() == 0U ||
      ::CRYPTO_memcmp(first.salt.data(), second.salt.data(),
                      first.salt.size()) == 0;
  const bool derived_equal =
      first.derived.size() == 0U ||
      ::CRYPTO_memcmp(first.derived.data(), second.derived.data(),
                      first.derived.size()) == 0;
  return salt_equal && derived_equal;
}

std::optional<UserRole> ParseUserRole(std::string_view role) {
  if (role == "administrator") {
    return UserRole::kAdministrator;
  }
  if (role == "viewer") {
    return UserRole::kViewer;
  }
  return std::nullopt;
}

std::string_view UserRoleName(UserRole role) {
  switch (role) {
    case UserRole::kAdministrator:
      return "administrator";
    case UserRole::kViewer:
      return "viewer";
  }
  return {};
}

}  // namespace

class AuthService::FirmwareLogWorker {
 public:
  FirmwareLogWorker(SecurityStore& store,
                    AuthClockCallback now_seconds,
                    AuthRandomCallback random_bytes,
                    AuthHighSeverityLogCallback callback,
                    FirmwareLogBeforeAckCallback before_ack)
      : store_(store),
        now_seconds_(std::move(now_seconds)),
        random_bytes_(std::move(random_bytes)),
        callback_(std::move(callback)),
        before_ack_(std::move(before_ack)) {
    auto owner = random_bytes_(kLeaseOwnerBytes);
    if (owner.ok() && owner.value().size() == kLeaseOwnerBytes) {
      lease_owner_ = std::move(owner).value();
    }
    worker_ = std::thread([this] { Run(); });
  }

  ~FirmwareLogWorker() {
    {
      std::lock_guard lock(mutex_);
      stopping_ = true;
      condition_.notify_all();
    }
    if (worker_.joinable()) {
      worker_.join();
    }
  }

  FirmwareLogWorker(const FirmwareLogWorker&) = delete;
  FirmwareLogWorker& operator=(const FirmwareLogWorker&) = delete;

  void Wake() noexcept {
    std::lock_guard lock(mutex_);
    wake_requested_ = true;
    condition_.notify_one();
  }

 private:
  static constexpr std::size_t kLeaseOwnerBytes = 16U;
  static constexpr std::size_t kLeaseTokenBytes = 32U;
  static constexpr std::int64_t kLeaseDurationSeconds = 30;
  static constexpr auto kPollInterval = std::chrono::seconds(1);
  static constexpr auto kInitialRetry = std::chrono::milliseconds(25);
  static constexpr auto kMaximumRetry = std::chrono::milliseconds(1000);

  void Run() noexcept {
    if (lease_owner_.size() != kLeaseOwnerBytes) {
      return;
    }
    auto retry_delay = kInitialRetry;
    for (;;) {
      {
        std::unique_lock lock(mutex_);
        condition_.wait_for(lock, kPollInterval, [this] {
          return stopping_ || wake_requested_;
        });
        if (stopping_) {
          return;
        }
        wake_requested_ = false;
      }

      const std::int64_t now_seconds = now_seconds_();
      if (now_seconds < 0 ||
          now_seconds > std::numeric_limits<std::int64_t>::max() -
                            kLeaseDurationSeconds) {
        continue;
      }
      auto claimable = store_.HasClaimableFirmwareLogOutbox(now_seconds);
      if (!claimable.ok() || !claimable.value()) {
        continue;
      }
      auto token_result = random_bytes_(kLeaseTokenBytes);
      if (!token_result.ok() ||
          token_result.value().size() != kLeaseTokenBytes) {
        continue;
      }
      auto lease_token = std::move(token_result).value();
      auto claimed = store_.ClaimFirmwareLogOutbox(
          {lease_owner_.data(), lease_owner_.size()},
          {lease_token.data(), lease_token.size()}, now_seconds,
          now_seconds + kLeaseDurationSeconds);
      if (!claimed.ok() || !claimed.value().has_value()) {
        continue;
      }
      auto entry = std::move(*claimed.value());
      bool delivered = false;
      try {
        callback_(entry.category, entry.peer_ip);
        delivered = true;
      } catch (...) {
      }
      if (delivered && before_ack_) {
        try {
          before_ack_();
        } catch (...) {
          // Test-only crash-window injection deliberately leaves the live
          // lease for another process to recover after expiry.
          return;
        }
      }
      if (delivered) {
        (void)store_.AcknowledgeFirmwareLogOutbox(
            entry.id, {lease_owner_.data(), lease_owner_.size()},
            {lease_token.data(), lease_token.size()});
        retry_delay = kInitialRetry;
        Wake();
        continue;
      }

      (void)store_.ReleaseFirmwareLogOutbox(
          entry.id, {lease_owner_.data(), lease_owner_.size()},
          {lease_token.data(), lease_token.size()});
      std::unique_lock lock(mutex_);
      condition_.wait_for(lock, retry_delay,
                          [this] { return stopping_; });
      if (stopping_) {
        return;
      }
      retry_delay = std::min(retry_delay * 2, kMaximumRetry);
      wake_requested_ = true;
    }
  }

  SecurityStore& store_;
  AuthClockCallback now_seconds_;
  AuthRandomCallback random_bytes_;
  AuthHighSeverityLogCallback callback_;
  FirmwareLogBeforeAckCallback before_ack_;
  common::SecureBytes lease_owner_;
  std::mutex mutex_;
  std::condition_variable condition_;
  bool stopping_{false};
  bool wake_requested_{true};
  std::thread worker_;
};

AuthService::AuthService(SecurityStore& store)
    : AuthService(store, AuthServiceDependencies{}) {}

AuthService::AuthService(SecurityStore& store,
                         AuthServiceDependencies dependencies)
    : AuthService(store, std::move(dependencies), {}) {}

AuthService::AuthService(
    SecurityStore& store,
    AuthServiceDependencies dependencies,
    FirmwareLogBeforeAckCallback firmware_log_before_ack)
    : store_(store), dependencies_(std::move(dependencies)) {
  if (!dependencies_.now_seconds) {
    dependencies_.now_seconds = DefaultNowSeconds;
  }
  if (!dependencies_.random_bytes) {
    dependencies_.random_bytes = DefaultRandom;
  }
  if (!dependencies_.verify_password) {
    dependencies_.verify_password = VerifyPassword;
  }
  if (!dependencies_.high_severity_log) {
    dependencies_.high_severity_log =
        [](std::string_view category, std::string_view normalized_peer_ip) {
          std::array<char, 128> message{};
          const int length = std::snprintf(
              message.data(), message.size(), "%.*s|%.*s",
              static_cast<int>(category.size()), category.data(),
              static_cast<int>(normalized_peer_ip.size()),
              normalized_peer_ip.data());
          if (length > 0 &&
              static_cast<std::size_t>(length) < message.size()) {
            common::Logger::instance().log(common::Logger::Level::kError,
                                           message.data());
          }
        };
  }
  if (!dependencies_.firmware_log_random_bytes) {
    dependencies_.firmware_log_random_bytes = DefaultRandom;
  }
  firmware_log_worker_ = std::make_unique<FirmwareLogWorker>(
      store_, dependencies_.now_seconds,
      std::move(dependencies_.firmware_log_random_bytes),
      std::move(dependencies_.high_severity_log),
      std::move(firmware_log_before_ack));
}

AuthService::~AuthService() = default;

common::Result<LoginResult> AuthService::Login(LoginRequest request) {
  PasswordCleanupGuard password_cleanup(request.password);
  bool reached_limit = false;
  std::string normalized_peer;
  try {
    auto peer = NormalizePeerIp(request.peer_ip);
    if (!peer.ok()) {
      const auto& dummy = DummyPassword();
      if (dummy.valid) {
        (void)dependencies_.verify_password(request.password, dummy.record);
      }
      return AuthenticationFailure<LoginResult>();
    }
    normalized_peer = std::move(peer).value();
    const std::int64_t snapshot_now_seconds = dependencies_.now_seconds();
    if (!HasSafeDeadline(snapshot_now_seconds) || !DummyPassword().valid) {
      return AuthenticationUnavailable<LoginResult>();
    }

    const std::string canonical_username = CanonicalUsername(request.username);
    auto read_started = store_.BeginReadTransaction();
    if (!read_started.ok()) {
      return AuthenticationUnavailable<LoginResult>();
    }
    auto read_transaction = std::move(read_started).value();
    const auto rollback_read_unavailable = [&read_transaction]() {
      if (read_transaction.active()) {
        (void)read_transaction.Rollback();
      }
      return AuthenticationUnavailable<LoginResult>();
    };
    auto snapshot = store_.ReadAuthenticationContext(
        read_transaction, canonical_username, normalized_peer);
    if (!snapshot.ok()) {
      return rollback_read_unavailable();
    }
    auto read_committed = read_transaction.Commit();
    if (!read_committed.ok()) {
      return rollback_read_unavailable();
    }

    const PasswordRecord& password_record =
        snapshot.value().user.has_value()
            ? snapshot.value().user->password
            : DummyPassword().record;
    bool password_matches = false;
    try {
      auto verified =
          dependencies_.verify_password(request.password, password_record);
      password_matches = verified.ok() && verified.value();
    } catch (...) {
      password_matches = false;
    }

    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (!HasSafeDeadline(now_seconds) || now_seconds < snapshot_now_seconds) {
      return AuthenticationUnavailable<LoginResult>();
    }
    auto started = store_.BeginTransaction();
    if (!started.ok()) {
      return AuthenticationUnavailable<LoginResult>();
    }
    auto transaction = std::move(started).value();
    const auto rollback_unavailable = [&transaction]() {
      if (transaction.active()) {
        (void)transaction.Rollback();
      }
      return AuthenticationUnavailable<LoginResult>();
    };

    auto context = store_.ReadAuthenticationContext(
        transaction, canonical_username, normalized_peer);
    if (!context.ok()) {
      return rollback_unavailable();
    }

    const auto immutable_context_equal = [&snapshot, &context] {
      if (snapshot.value().state != context.value().state ||
          snapshot.value().peer_registered !=
              context.value().peer_registered ||
          snapshot.value().user.has_value() !=
              context.value().user.has_value()) {
        return false;
      }
      if (!snapshot.value().user.has_value()) {
        return true;
      }
      const auto& first = *snapshot.value().user;
      const auto& second = *context.value().user;
      return first.id == second.id &&
             first.display_username == second.display_username &&
             first.role == second.role && first.enabled == second.enabled &&
             first.created_at_seconds == second.created_at_seconds &&
             PasswordRecordsEqual(first.password, second.password);
    };
    const bool immutable_context_current = immutable_context_equal();
    const bool decision_state_current =
        immutable_context_current &&
        (!snapshot.value().user.has_value() ||
         (snapshot.value().user->failed_login_count ==
              context.value().user->failed_login_count &&
          snapshot.value().user->lock_until_seconds ==
              context.value().user->lock_until_seconds &&
          snapshot.value().user->last_login_at_seconds ==
              context.value().user->last_login_at_seconds));

    const bool has_user = context.value().user.has_value();
    const bool operational =
        context.value().state == DeviceState::kOperational;
    const bool peer_registered = context.value().peer_registered;
    const bool enabled = has_user && context.value().user->enabled;
    const std::optional<UserRole> user_role =
        has_user ? ParseUserRole(context.value().user->role) : std::nullopt;
    const bool lock_active =
        has_user && context.value().user->lock_until_seconds.has_value() &&
        now_seconds < *context.value().user->lock_until_seconds;
    const bool clock_valid =
        !has_user ||
        (now_seconds >= context.value().user->created_at_seconds &&
         (!context.value().user->last_login_at_seconds.has_value() ||
          now_seconds >= *context.value().user->last_login_at_seconds));
    if (immutable_context_current && !clock_valid) {
      return rollback_unavailable();
    }
    const bool accepted = operational && peer_registered && enabled &&
                          user_role.has_value() && !lock_active &&
                          password_matches && decision_state_current;

    const std::optional<std::int64_t> actor_user_id =
        has_user ? std::optional<std::int64_t>(context.value().user->id)
                 : std::nullopt;
    if (!accepted) {
      const bool counts_as_failure = operational && peer_registered && enabled &&
                                     user_role.has_value() && !lock_active &&
                                     !password_matches &&
                                     immutable_context_current;
      if (counts_as_failure) {
        const bool prior_lock_expired =
            context.value().user->lock_until_seconds.has_value() &&
            now_seconds >= *context.value().user->lock_until_seconds;
        const std::int64_t previous_failures =
            prior_lock_expired
                ? 0
                : std::clamp<std::int64_t>(
                      context.value().user->failed_login_count, 0, 5);
        const std::int64_t failures =
            std::min<std::int64_t>(previous_failures + 1, kFailureLimit);
        reached_limit = failures == kFailureLimit;
        const std::optional<std::int64_t> lock_until =
            reached_limit
                ? std::optional<std::int64_t>(now_seconds +
                                              kLockDurationSeconds)
                : std::nullopt;
        auto updated = store_.SetLoginFailureState(
            transaction, context.value().user->id, failures, lock_until);
        if (!updated.ok()) {
          return rollback_unavailable();
        }
      }

      auto failed_audit = store_.InsertAuditEvent(
          transaction, now_seconds, "authentication_failed", "failure",
          actor_user_id, normalized_peer, "authentication_failed");
      if (!failed_audit.ok()) {
        return rollback_unavailable();
      }
      if (reached_limit) {
        auto limit_audit = store_.InsertAuditEvent(
            transaction, now_seconds, "authentication_limit_reached",
            "failure", actor_user_id, normalized_peer,
            "consecutive_failure_limit");
        if (!limit_audit.ok()) {
          return rollback_unavailable();
        }
        auto outbox = store_.CoalesceFirmwareLogOutbox(
            transaction, now_seconds, "authentication_limit_reached",
            normalized_peer);
        if (!outbox.ok()) {
          return rollback_unavailable();
        }
      }
      auto response = AuthenticationFailure<LoginResult>();
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return rollback_unavailable();
      }
      if (reached_limit) {
        firmware_log_worker_->Wake();
      }
      return response;
    }

    auto expired = store_.DeleteExpiredSessions(transaction, now_seconds);
    if (!expired.ok()) {
      return rollback_unavailable();
    }
    common::Result<std::optional<SecurityStore::StoredSession>> active_session =
        common::Result<std::optional<SecurityStore::StoredSession>>::Ok(
            std::nullopt);
    if (*user_role == UserRole::kAdministrator) {
      active_session = store_.ReadAdministratorSession(transaction);
    }
    if (!active_session.ok()) {
      return rollback_unavailable();
    }
    if (active_session.value().has_value()) {
      auto duplicate_audit = store_.InsertAuditEvent(
          transaction, now_seconds, "authentication_failed", "failure",
          actor_user_id, normalized_peer, "active_administrator_session");
      if (!duplicate_audit.ok()) {
        return rollback_unavailable();
      }
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return rollback_unavailable();
      }
      return AuthenticationFailure<LoginResult>();
    }

    common::SecureBytes session_token;
    common::SecureBytes token_hash;
    bool token_ready = false;
    for (int attempt = 0; attempt < kTokenGenerationAttempts; ++attempt) {
      auto generated = dependencies_.random_bytes(kSessionTokenBytes);
      if (!generated.ok()) {
        return rollback_unavailable();
      }
      session_token = std::move(generated).value();
      if (session_token.size() != kSessionTokenBytes) {
        return rollback_unavailable();
      }
      auto hashed = HashToken(
          {session_token.data(), session_token.size()});
      if (!hashed.ok()) {
        return rollback_unavailable();
      }
      token_hash = std::move(hashed).value();
      auto exists = store_.SessionTokenHashExists(
          transaction, {token_hash.data(), token_hash.size()});
      if (!exists.ok()) {
        return rollback_unavailable();
      }
      if (!exists.value()) {
        token_ready = true;
        break;
      }
      session_token.clear();
      token_hash.clear();
    }
    if (!token_ready) {
      auto collision_audit = store_.InsertAuditEvent(
          transaction, now_seconds, "authentication_failed", "failure",
          actor_user_id, normalized_peer, "authentication_failed");
      if (!collision_audit.ok()) {
        return rollback_unavailable();
      }
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return rollback_unavailable();
      }
      return AuthenticationFailure<LoginResult>();
    }

    const std::int64_t expires_at_seconds =
        now_seconds + kIdleDurationSeconds;
    auto inserted = store_.InsertSession(
        transaction, {token_hash.data(), token_hash.size()},
        context.value().user->id, UserRoleName(*user_role), now_seconds,
        expires_at_seconds,
        normalized_peer);
    if (!inserted.ok()) {
      return rollback_unavailable();
    }
    auto reset = store_.SetLoginSuccessState(
        transaction, context.value().user->id, now_seconds);
    if (!reset.ok()) {
      return rollback_unavailable();
    }
    auto success_audit = store_.InsertAuditEvent(
        transaction, now_seconds, "authentication_succeeded", "success",
        actor_user_id, normalized_peer, "authenticated_login");
    if (!success_audit.ok()) {
      return rollback_unavailable();
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return rollback_unavailable();
    }
    token_hash.clear();
    return common::Result<LoginResult>::Ok(
        {std::move(session_token), *user_role, expires_at_seconds});
  } catch (...) {
    return AuthenticationUnavailable<LoginResult>();
  }
}

common::Result<Principal> AuthService::Verify(
    std::span<const unsigned char> token,
    std::string_view peer_ip) {
  try {
    auto token_hash = HashToken(token);
    if (!token_hash.ok() || !DummyPassword().valid) {
      return AuthenticationUnavailable<Principal>();
    }
    auto peer = NormalizePeerIp(peer_ip);
    if (!peer.ok()) {
      (void)::CRYPTO_memcmp(token_hash.value().data(),
                            DummyPassword().record.derived.data(),
                            kSessionTokenHashBytes);
      token_hash.value().clear();
      return AuthenticationFailure<Principal>();
    }
    const std::string normalized_peer = std::move(peer).value();
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (!HasSafeDeadline(now_seconds)) {
      token_hash.value().clear();
      return AuthenticationUnavailable<Principal>();
    }

    auto started = store_.BeginTransaction();
    if (!started.ok()) {
      token_hash.value().clear();
      return AuthenticationUnavailable<Principal>();
    }
    auto transaction = std::move(started).value();
    const auto rollback_unavailable = [&transaction, &token_hash]() {
      if (transaction.active()) {
        (void)transaction.Rollback();
      }
      token_hash.value().clear();
      return AuthenticationUnavailable<Principal>();
    };

    auto expired = store_.DeleteExpiredSessions(transaction, now_seconds);
    if (!expired.ok()) {
      return rollback_unavailable();
    }
    auto session = store_.ReadSessionByTokenHash(
        transaction, {token_hash.value().data(), token_hash.value().size()});
    if (!session.ok()) {
      return rollback_unavailable();
    }
    const unsigned char* expected_hash =
        DummyPassword().record.derived.data();
    if (session.value().has_value() &&
        session.value()->token_hash.size() == kSessionTokenHashBytes) {
      expected_hash = session.value()->token_hash.data();
    }
    const bool hash_matches =
        ::CRYPTO_memcmp(token_hash.value().data(), expected_hash,
                        kSessionTokenHashBytes) == 0;
    if (session.value().has_value() &&
        (now_seconds < session.value()->created_at_seconds ||
         now_seconds < session.value()->last_activity_at_seconds)) {
      return rollback_unavailable();
    }
    const std::optional<UserRole> role =
        session.value().has_value()
            ? ParseUserRole(session.value()->role)
            : std::nullopt;
    const bool valid = session.value().has_value() && hash_matches &&
                       session.value()->peer_ip == normalized_peer &&
                       role.has_value();
    if (valid) {
      auto refreshed = store_.RefreshSession(
          transaction, session.value()->id, now_seconds,
          now_seconds + kIdleDurationSeconds);
      if (!refreshed.ok()) {
        return rollback_unavailable();
      }
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return rollback_unavailable();
    }
    token_hash.value().clear();
    if (!valid) {
      return AuthenticationFailure<Principal>();
    }
    return common::Result<Principal>::Ok(
        {session.value()->user_id, std::move(session.value()->username),
         *role});
  } catch (...) {
    return AuthenticationUnavailable<Principal>();
  }
}

common::Result<void> AuthService::Logout(
    std::span<const unsigned char> token,
    std::string_view peer_ip) {
  try {
    auto token_hash = HashToken(token);
    if (!token_hash.ok() || !DummyPassword().valid) {
      return AuthenticationUnavailable<void>();
    }
    auto peer = NormalizePeerIp(peer_ip);
    if (!peer.ok()) {
      (void)::CRYPTO_memcmp(token_hash.value().data(),
                            DummyPassword().record.derived.data(),
                            kSessionTokenHashBytes);
      token_hash.value().clear();
      return AuthenticationFailure<void>();
    }
    const std::string normalized_peer = std::move(peer).value();
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (!HasSafeDeadline(now_seconds)) {
      token_hash.value().clear();
      return AuthenticationUnavailable<void>();
    }

    auto started = store_.BeginTransaction();
    if (!started.ok()) {
      token_hash.value().clear();
      return AuthenticationUnavailable<void>();
    }
    auto transaction = std::move(started).value();
    const auto rollback_unavailable = [&transaction, &token_hash]() {
      if (transaction.active()) {
        (void)transaction.Rollback();
      }
      token_hash.value().clear();
      return AuthenticationUnavailable<void>();
    };

    auto expired = store_.DeleteExpiredSessions(transaction, now_seconds);
    if (!expired.ok()) {
      return rollback_unavailable();
    }
    auto session = store_.ReadSessionByTokenHash(
        transaction, {token_hash.value().data(), token_hash.value().size()});
    if (!session.ok()) {
      return rollback_unavailable();
    }
    const unsigned char* expected_hash =
        DummyPassword().record.derived.data();
    if (session.value().has_value() &&
        session.value()->token_hash.size() == kSessionTokenHashBytes) {
      expected_hash = session.value()->token_hash.data();
    }
    const bool hash_matches =
        ::CRYPTO_memcmp(token_hash.value().data(), expected_hash,
                        kSessionTokenHashBytes) == 0;
    const bool valid =
        session.value().has_value() && hash_matches &&
        session.value()->peer_ip == normalized_peer &&
        ParseUserRole(session.value()->role).has_value();
    if (valid) {
      auto removed = store_.DeleteSession(transaction, session.value()->id);
      if (!removed.ok()) {
        return rollback_unavailable();
      }
      auto audit = store_.InsertAuditEvent(
          transaction, now_seconds, "session_logout", "success",
          session.value()->user_id, normalized_peer, "session_logout");
      if (!audit.ok()) {
        return rollback_unavailable();
      }
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return rollback_unavailable();
    }
    token_hash.value().clear();
    return valid ? common::Result<void>::Ok()
                 : AuthenticationFailure<void>();
  } catch (...) {
    return AuthenticationUnavailable<void>();
  }
}

}  // namespace camera_firmware::security
