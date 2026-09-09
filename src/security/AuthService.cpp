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
#include <vector>

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
constexpr std::int64_t kLockDurationSeconds = std::int64_t{5} * 60;
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

template <typename T>
common::Result<T> AuthenticationRequired() {
  return common::Result<T>::Err(
      {"E_AUTHENTICATION_REQUIRED", "authentication required"});
}

class SensitiveCleanupGuard {
 public:
  SensitiveCleanupGuard() = default;
  explicit SensitiveCleanupGuard(common::SecureBytes& bytes) noexcept
      : bytes_(&bytes) {}
  ~SensitiveCleanupGuard() { Clear(); }

  SensitiveCleanupGuard(const SensitiveCleanupGuard&) = delete;
  SensitiveCleanupGuard& operator=(const SensitiveCleanupGuard&) = delete;

  void Bind(common::SecureBytes& bytes) noexcept { bytes_ = &bytes; }

  void Clear() noexcept {
    if (bytes_ == nullptr) {
      return;
    }
    bytes_->clear();
    bytes_ = nullptr;
  }

 private:
  common::SecureBytes* bytes_{nullptr};
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

// Compares two canonical usernames without an early exit. The initial
// account's username is generated rather than chosen, so its length tells an
// attacker nothing, but a byte-at-a-time timing signal would let one recover
// it and spend all five lockout attempts on the right name.
bool CanonicalIdentityMatches(std::string_view canonical_username,
                              std::string_view expected) {
  if (canonical_username.empty() ||
      canonical_username.size() != expected.size()) {
    return false;
  }
  return ::CRYPTO_memcmp(canonical_username.data(), expected.data(),
                         canonical_username.size()) == 0;
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

// Draws from the provider's private DRBG (RandomBytesPrivate), not the
// public one (RandomBytes), matching DefaultRandom's use of RAND_priv_bytes
// below: session tokens and firmware-log nonces must not be downgraded to a
// randomness pool shared with everything else in the process.
AuthRandomCallback ProviderRandomCallback(crypto::CryptoProvider* provider) {
  return [provider](std::size_t output_size) {
    return provider->RandomBytesPrivate(output_size);
  };
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

bool HasSafeDeadline(std::int64_t now_seconds,
                     std::int64_t idle_timeout_seconds) {
  return now_seconds >= 0 && idle_timeout_seconds > 0 &&
         now_seconds <= std::numeric_limits<std::int64_t>::max() -
                            idle_timeout_seconds;
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
      try {
        if (!RunIteration(retry_delay)) {
          return;
        }
      } catch (...) {
        // swallowed: the outbox worker must outlive a throwing store call or
        // callback; a claimed lease expires on its own and the next poll
        // retries the entry.
      }
    }
  }

  // One poll of the outbox. Returns false when the worker must exit.
  bool RunIteration(std::chrono::milliseconds& retry_delay) {
    {
      std::unique_lock lock(mutex_);
      condition_.wait_for(lock, kPollInterval, [this] {
        return stopping_ || wake_requested_;
      });
      if (stopping_) {
        return false;
      }
      wake_requested_ = false;
    }

    const std::int64_t now_seconds = now_seconds_();
    if (now_seconds < 0 ||
        now_seconds > std::numeric_limits<std::int64_t>::max() -
                          kLeaseDurationSeconds) {
      return true;
    }
    auto claimable = store_.HasClaimableFirmwareLogOutbox(now_seconds);
    if (!claimable.ok() || !claimable.value()) {
      return true;
    }
    auto token_result = random_bytes_(kLeaseTokenBytes);
    if (!token_result.ok() ||
        token_result.value().size() != kLeaseTokenBytes) {
      return true;
    }
    auto lease_token = std::move(token_result).value();
    auto claimed = store_.ClaimFirmwareLogOutbox(
        {lease_owner_.data(), lease_owner_.size()},
        {lease_token.data(), lease_token.size()}, now_seconds,
        now_seconds + kLeaseDurationSeconds);
    if (!claimed.ok()) {
      return true;
    }
    auto& claimed_entry = claimed.value();
    if (!claimed_entry.has_value()) {
      return true;
    }
    auto entry = std::move(*claimed_entry);
    bool delivered = false;
    try {
      callback_(entry.category, entry.peer_ip);
      delivered = true;
    } catch (...) {
      // swallowed: the high-severity log callback is external code; a throw
      // counts as not delivered
    }
    if (delivered && before_ack_) {
      try {
        before_ack_();
      } catch (...) {
        // Test-only crash-window injection deliberately leaves the live
        // lease for another process to recover after expiry.
        return false;
      }
    }
    if (delivered) {
      (void)store_.AcknowledgeFirmwareLogOutbox(
          entry.id, {lease_owner_.data(), lease_owner_.size()},
          {lease_token.data(), lease_token.size()});
      retry_delay = kInitialRetry;
      Wake();
      return true;
    }

    (void)store_.ReleaseFirmwareLogOutbox(
        entry.id, {lease_owner_.data(), lease_owner_.size()},
        {lease_token.data(), lease_token.size()});
    std::unique_lock lock(mutex_);
    condition_.wait_for(lock, retry_delay,
                        [this] { return stopping_; });
    if (stopping_) {
      return false;
    }
    retry_delay = std::min(retry_delay * 2, kMaximumRetry);
    wake_requested_ = true;
    return true;
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

class AuthService::SessionExpiryWorker {
 public:
  SessionExpiryWorker(SecurityStore& store,
                      AuthClockCallback now_seconds,
                      AuthServiceRuntimeHooks hooks)
      : store_(store),
        now_seconds_(std::move(now_seconds)),
        hooks_(std::move(hooks)),
        worker_([this] { Run(); }) {}

  ~SessionExpiryWorker() {
    {
      std::lock_guard lock(mutex_);
      stopping_ = true;
      condition_.notify_all();
    }
    if (worker_.joinable()) {
      worker_.join();
    }
  }

  SessionExpiryWorker(const SessionExpiryWorker&) = delete;
  SessionExpiryWorker& operator=(const SessionExpiryWorker&) = delete;

  void Wake() noexcept {
    std::lock_guard lock(mutex_);
    wake_requested_ = true;
    condition_.notify_one();
  }

  // Blocks until the worker has finished all requested sweeps and parked.
  // Test-only: lets a fixture advance its fake clock without racing a sweep
  // that a previous operation's Wake() is still owed.
  void WaitForIdleForTesting() {
    std::unique_lock lock(mutex_);
    condition_.wait(lock, [this] {
      return stopping_ || (idle_ && !wake_requested_);
    });
  }

 private:
  struct SweepResult {
    bool ok{false};
    std::optional<std::int64_t> next_expiry;
  };

  SweepResult Sweep() noexcept {
    try {
      const std::int64_t now_seconds = now_seconds_();
      if (now_seconds < 0) {
        return {};
      }
      auto started = store_.BeginTransaction();
      if (!started.ok()) {
        return {};
      }
      auto transaction = std::move(started).value();
      auto expired = store_.DeleteExpiredSessions(transaction, now_seconds);
      if (!expired.ok()) {
        return {};
      }
      auto lapsed = store_.ExpireLapsedManagementAuthority(transaction,
                                                           now_seconds);
      if (!lapsed.ok()) {
        return {};
      }
      auto next = store_.ReadNextSessionExpiry(transaction);
      if (!next.ok()) {
        return {};
      }
      auto next_management = store_.ReadNextManagementExpiry(transaction);
      if (!next_management.ok()) {
        return {};
      }
      auto identities = std::move(expired).value();
      auto next_expiry = std::move(next).value();
      const auto next_management_expiry = std::move(next_management).value();
      if (next_management_expiry.has_value() &&
          (!next_expiry.has_value() ||
           *next_management_expiry < *next_expiry)) {
        next_expiry = next_management_expiry;
      }
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return {};
      }
      PublishSessionRevocations(identities, hooks_.revoke_sessions,
                                hooks_.revoke_all_streams);
      return {true, next_expiry};
    } catch (...) {
      return {};
    }
  }

  void Run() noexcept {
    std::unique_lock lock(mutex_);
    while (!stopping_) {
      wake_requested_ = false;
      lock.unlock();
      const auto sweep = Sweep();
      lock.lock();
      if (stopping_) {
        return;
      }
      if (!sweep.ok) {
        IdleScope idle(*this);
        condition_.wait_for(lock, std::chrono::seconds(1), [this] {
          return stopping_ || wake_requested_;
        });
        continue;
      }
      if (!sweep.next_expiry.has_value()) {
        IdleScope idle(*this);
        condition_.wait(lock,
                        [this] { return stopping_ || wake_requested_; });
        continue;
      }
      std::int64_t now_seconds = 0;
      try {
        now_seconds = now_seconds_();
      } catch (...) {
        IdleScope idle(*this);
        condition_.wait_for(lock, std::chrono::seconds(1), [this] {
          return stopping_ || wake_requested_;
        });
        continue;
      }
      if (now_seconds >= *sweep.next_expiry) {
        continue;
      }
      const auto delay_seconds =
          std::min<std::int64_t>(*sweep.next_expiry - now_seconds,
                                 std::int64_t{24} * 60 * 60);
      IdleScope idle(*this);
      condition_.wait_for(lock, std::chrono::seconds(delay_seconds), [this] {
        return stopping_ || wake_requested_;
      });
    }
  }

  SecurityStore& store_;
  AuthClockCallback now_seconds_;
  AuthServiceRuntimeHooks hooks_;
  // Marks the worker as parked for WaitForIdleForTesting while the
  // owning scope sits in a condition wait (mutex held on entry/exit).
  struct IdleScope {
    explicit IdleScope(SessionExpiryWorker& owner) : worker(owner) {
      worker.idle_ = true;
      worker.condition_.notify_all();
    }
    ~IdleScope() { worker.idle_ = false; }
    SessionExpiryWorker& worker;
  };

  std::mutex mutex_;
  std::condition_variable condition_;
  bool stopping_{false};
  bool wake_requested_{true};
  bool idle_{false};
  std::thread worker_;
};

AuthService::AuthService(SecurityStore& store,
                         AuthServiceRuntimeHooks hooks)
    : AuthService(store, AuthServiceDependencies{}, std::move(hooks), {}) {}

AuthService::AuthService(SecurityStore& store,
                         AuthServiceDependencies dependencies)
    : AuthService(store, std::move(dependencies), AuthServiceRuntimeHooks{},
                  {}) {}

AuthService::AuthService(
    SecurityStore& store,
    AuthServiceDependencies dependencies,
    FirmwareLogBeforeAckCallback firmware_log_before_ack)
    : AuthService(store, std::move(dependencies), AuthServiceRuntimeHooks{},
                  std::move(firmware_log_before_ack)) {}

AuthService::AuthService(SecurityStore& store,
                         AuthServiceDependencies dependencies,
                         AuthServiceRuntimeHooks hooks)
    : AuthService(store, std::move(dependencies), std::move(hooks), {}) {}

AuthService::AuthService(
    SecurityStore& store,
    AuthServiceDependencies dependencies,
    AuthServiceRuntimeHooks hooks,
    FirmwareLogBeforeAckCallback firmware_log_before_ack)
    : AuthService(store, std::move(dependencies), std::move(hooks),
                  std::move(firmware_log_before_ack), {}) {}

AuthService::AuthService(
    SecurityStore& store,
    AuthServiceDependencies dependencies,
    AuthServiceRuntimeHooks hooks,
    FirmwareLogBeforeAckCallback firmware_log_before_ack,
    LoginRoleValidatorCallback login_role_validator)
    : store_(store),
      dependencies_(std::move(dependencies)),
      hooks_(std::move(hooks)),
      login_role_validator_(std::move(login_role_validator)) {
  if (!dependencies_.now_seconds) {
    dependencies_.now_seconds = DefaultNowSeconds;
  }
  if (!dependencies_.random_bytes) {
    dependencies_.random_bytes =
        dependencies_.provider
            ? ProviderRandomCallback(dependencies_.provider)
            : AuthRandomCallback(DefaultRandom);
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
    dependencies_.firmware_log_random_bytes =
        dependencies_.provider
            ? ProviderRandomCallback(dependencies_.provider)
            : AuthRandomCallback(DefaultRandom);
  }
  if (!login_role_validator_) {
    login_role_validator_ = [](UserRole role) {
      return !UserRoleName(role).empty();
    };
  }
  // Canonicalized once here so Login() compares like against like: the
  // identity arrives in its display form, and the username a request submits
  // is canonicalized before the store lookup.
  if (dependencies_.initial_account_username.has_value()) {
    *dependencies_.initial_account_username =
        CanonicalUsername(*dependencies_.initial_account_username);
  }
  firmware_log_worker_ = std::make_unique<FirmwareLogWorker>(
      store_, dependencies_.now_seconds,
      std::move(dependencies_.firmware_log_random_bytes),
      std::move(dependencies_.high_severity_log),
      std::move(firmware_log_before_ack));
  session_expiry_worker_ = std::make_unique<SessionExpiryWorker>(
      store_, dependencies_.now_seconds, hooks_);
}

void AuthService::WaitForSessionExpiryIdleForTesting() {
  if (session_expiry_worker_) {
    session_expiry_worker_->WaitForIdleForTesting();
  }
}

AuthService::~AuthService() = default;

common::Result<LoginResult> AuthService::Login(LoginRequest request) {
  SensitiveCleanupGuard password_cleanup(request.password);
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
    if (!HasSafeDeadline(snapshot_now_seconds,
                         dependencies_.session_idle_timeout_seconds) ||
        !DummyPassword().valid) {
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
    const auto& snapshot_user_slot = snapshot.value().user;
    const auto* snapshot_user =
        snapshot_user_slot.has_value() ? &*snapshot_user_slot : nullptr;

    const PasswordRecord& password_record = snapshot_user != nullptr
                                                ? snapshot_user->password
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
    if (!HasSafeDeadline(now_seconds,
                         dependencies_.session_idle_timeout_seconds) ||
        now_seconds < snapshot_now_seconds) {
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
    const auto& context_user_slot = context.value().user;
    const auto* context_user =
        context_user_slot.has_value() ? &*context_user_slot : nullptr;

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
    // immutable_context_current implies both users are present or both are
    // absent; the explicit null checks keep that visible to the analyzer.
    const bool decision_state_current =
        immutable_context_current &&
        (snapshot_user == nullptr || context_user == nullptr ||
         (snapshot_user->failed_login_count ==
              context_user->failed_login_count &&
          snapshot_user->lock_until_seconds ==
              context_user->lock_until_seconds &&
          snapshot_user->last_login_at_seconds ==
              context_user->last_login_at_seconds));

    const bool has_user = context_user != nullptr;
    const bool operational =
        context.value().state == DeviceState::kOperational;
    const bool peer_registered = context.value().peer_registered;
    const bool enabled = has_user && context_user->enabled;
    const std::optional<UserRole> user_role =
        has_user ? ParseUserRole(context_user->role) : std::nullopt;
    const bool lock_active =
        has_user && context_user->lock_until_seconds.has_value() &&
        now_seconds < *context_user->lock_until_seconds;
    const bool clock_valid =
        !has_user ||
        (now_seconds >= context_user->created_at_seconds &&
         (!context_user->last_login_at_seconds.has_value() ||
          now_seconds >= *context_user->last_login_at_seconds));
    if (immutable_context_current && !clock_valid) {
      return rollback_unavailable();
    }
    // An uninitialized device has no registered management IP, by definition:
    // the first management_ips row is written by InitializeDevice. What takes
    // the place of that check is the pair below.
    //
    // `state` comes from the same transaction as the user row, and
    // InitializeDevice sets it to operational and deletes the initial account
    // in one transaction. So this arm closes at the instant setup commits,
    // and it closes because of the same write that removes the account it
    // admits — not because of a runtime flag that could go stale, and not on
    // a subsequent request that might race the transition.
    //
    // The identity is the account BootstrapService minted for this boot. It
    // makes the arm admit one named account rather than "whatever row `users`
    // happens to hold", and it is absent on a device that boots operational,
    // which closes the arm a second time and independently.
    const bool default_state = context.value().state == DeviceState::kDefault;
    const bool initial_account =
        default_state && has_user && user_role.has_value() &&
        *user_role == UserRole::kViewer &&
        dependencies_.initial_account_username.has_value() &&
        CanonicalIdentityMatches(canonical_username,
                                 *dependencies_.initial_account_username);
    // DeviceState has two values, so exactly one arm is live per attempt.
    // Everything downstream — lockout, failure counting, the
    // duplicate-session check, and every audit record — reads this one
    // predicate, so the initial account cannot silently acquire different
    // handling from an operational account.
    const bool peer_authorized =
        operational ? peer_registered : initial_account;
    const bool accepted = peer_authorized && enabled && user_role.has_value() &&
                          !lock_active && password_matches &&
                          decision_state_current;

    const std::optional<std::int64_t> actor_user_id =
        has_user ? std::optional<std::int64_t>(context_user->id)
                 : std::nullopt;
    const bool duplicate_check_allowed =
        peer_authorized && enabled && user_role.has_value() && !lock_active &&
        password_matches && immutable_context_current;
    std::vector<SessionIdentity> expired_identities;
    const auto publish_expired = [this, &expired_identities] {
      PublishSessionRevocations(expired_identities, hooks_.revoke_sessions,
                                hooks_.revoke_all_streams);
    };
    if (duplicate_check_allowed) {
      auto expired = store_.DeleteExpiredSessions(transaction, now_seconds);
      if (!expired.ok()) {
        return rollback_unavailable();
      }
      expired_identities = std::move(expired).value();
      auto active_session = store_.ReadSessionByUserId(
          transaction, context_user->id);
      if (!active_session.ok()) {
        return rollback_unavailable();
      }
      auto& active_session_record = active_session.value();
      if (active_session_record.has_value()) {
        active_session_record->token_hash.clear();
        const std::string_view duplicate_detail =
            *user_role == UserRole::kAdministrator
                ? "active_administrator_session"
                : "active_viewer_session";
        auto duplicate_audit = store_.InsertAuditEvent(
            transaction, now_seconds, "authentication_failed", "failure",
            actor_user_id, normalized_peer, duplicate_detail);
        if (!duplicate_audit.ok()) {
          return rollback_unavailable();
        }
        auto committed = transaction.Commit();
        if (!committed.ok()) {
          return rollback_unavailable();
        }
        session_expiry_worker_->Wake();
        publish_expired();
        return AuthenticationFailure<LoginResult>();
      }
    }
    if (!accepted) {
      // The initial account's credential is public on an uninitialized device
      // (setup/status serves it), so an account lock guards no secret -- it
      // would only let a reachable peer burn the five-attempt lock and deny
      // setup. Failures against it therefore never count toward a lock; the
      // operational path is unchanged. Default-state login flooding is bounded
      // by the request-rate limit instead of the lock.
      const bool counts_as_failure =
          peer_authorized && enabled && user_role.has_value() &&
          !lock_active && !password_matches && immutable_context_current &&
          !initial_account;
      if (counts_as_failure) {
        const bool prior_lock_expired =
            context_user->lock_until_seconds.has_value() &&
            now_seconds >= *context_user->lock_until_seconds;
        const std::int64_t previous_failures =
            prior_lock_expired
                ? 0
                : std::clamp<std::int64_t>(
                      context_user->failed_login_count, 0, 5);
        const std::int64_t failures =
            std::min<std::int64_t>(previous_failures + 1, kFailureLimit);
        reached_limit = failures == kFailureLimit;
        const std::optional<std::int64_t> lock_until =
            reached_limit
                ? std::optional<std::int64_t>(now_seconds +
                                              kLockDurationSeconds)
                : std::nullopt;
        auto updated = store_.SetLoginFailureState(
            transaction, context_user->id, failures, lock_until);
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
      session_expiry_worker_->Wake();
      if (reached_limit) {
        firmware_log_worker_->Wake();
      }
      publish_expired();
      return response;
    }

    bool login_role_valid = false;
    try {
      login_role_valid = login_role_validator_(*user_role);
    } catch (...) {
      return rollback_unavailable();
    }
    if (!login_role_valid) {
      return rollback_unavailable();
    }

    common::SecureBytes session_token;
    common::SecureBytes token_hash;
    SensitiveCleanupGuard token_hash_cleanup(token_hash);
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
      session_expiry_worker_->Wake();
      publish_expired();
      return AuthenticationFailure<LoginResult>();
    }

    const std::int64_t expires_at_seconds =
        now_seconds + dependencies_.session_idle_timeout_seconds;
    const std::int64_t management_expires_at_seconds = expires_at_seconds;
    auto inserted = store_.InsertSession(
        transaction, {token_hash.data(), token_hash.size()},
        context_user->id, UserRoleName(*user_role), now_seconds,
        expires_at_seconds, normalized_peer, management_expires_at_seconds);
    if (!inserted.ok()) {
      return rollback_unavailable();
    }
    auto reset = store_.SetLoginSuccessState(
        transaction, context_user->id, now_seconds);
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
    session_expiry_worker_->Wake();
    token_hash_cleanup.Clear();
    publish_expired();
    return common::Result<LoginResult>::Ok(
        {std::move(session_token), *user_role, expires_at_seconds});
  } catch (...) {
    return AuthenticationUnavailable<LoginResult>();
  }
}

common::Result<Principal> AuthService::Verify(
    std::span<const unsigned char> token,
    std::string_view peer_ip,
    ManagementActivity activity) {
  try {
    auto token_hash = HashToken(token);
    if (!token_hash.ok() || !DummyPassword().valid) {
      return AuthenticationUnavailable<Principal>();
    }
    SensitiveCleanupGuard token_hash_cleanup(token_hash.value());
    SensitiveCleanupGuard stored_hash_cleanup;
    auto peer = NormalizePeerIp(peer_ip);
    if (!peer.ok()) {
      (void)::CRYPTO_memcmp(token_hash.value().data(),
                            DummyPassword().record.derived.data(),
                            kSessionTokenHashBytes);
      return AuthenticationFailure<Principal>();
    }
    const std::string normalized_peer = std::move(peer).value();
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (!HasSafeDeadline(now_seconds,
                         dependencies_.session_idle_timeout_seconds)) {
      return AuthenticationUnavailable<Principal>();
    }

    auto started = store_.BeginTransaction();
    if (!started.ok()) {
      return AuthenticationUnavailable<Principal>();
    }
    auto transaction = std::move(started).value();
    const auto rollback_unavailable = [&transaction]() {
      if (transaction.active()) {
        (void)transaction.Rollback();
      }
      return AuthenticationUnavailable<Principal>();
    };

    auto expired = store_.DeleteExpiredSessions(transaction, now_seconds);
    if (!expired.ok()) {
      return rollback_unavailable();
    }
    auto expired_identities = std::move(expired).value();
    auto session = store_.ReadSessionByTokenHash(
        transaction, {token_hash.value().data(), token_hash.value().size()},
        normalized_peer, now_seconds);
    if (!session.ok()) {
      return rollback_unavailable();
    }
    auto& session_slot = session.value();
    auto* stored_session =
        session_slot.has_value() ? &*session_slot : nullptr;
    if (stored_session != nullptr) {
      stored_hash_cleanup.Bind(stored_session->token_hash);
    }
    const unsigned char* expected_hash =
        DummyPassword().record.derived.data();
    if (stored_session != nullptr &&
        stored_session->token_hash.size() == kSessionTokenHashBytes) {
      expected_hash = stored_session->token_hash.data();
    }
    const bool hash_matches =
        ::CRYPTO_memcmp(token_hash.value().data(), expected_hash,
                        kSessionTokenHashBytes) == 0;
    if (stored_session != nullptr &&
        (now_seconds < stored_session->created_at_seconds ||
         now_seconds < stored_session->last_activity_at_seconds)) {
      return rollback_unavailable();
    }
    const std::optional<UserRole> role =
        stored_session != nullptr
            ? ParseUserRole(stored_session->role)
            : std::nullopt;
    bool valid = stored_session != nullptr && hash_matches &&
                 stored_session->peer_ip == normalized_peer &&
                 role.has_value() &&
                 stored_session->token_hash.size() == kSessionIdentityBytes;

    const std::int64_t stored_management_deadline =
        stored_session != nullptr
            ? stored_session->management_expires_at_seconds
            : 0;
    const bool management_valid = stored_management_deadline > now_seconds;

    auto lapsed_management =
        store_.ExpireLapsedManagementAuthority(transaction, now_seconds);
    if (!lapsed_management.ok()) {
      return rollback_unavailable();
    }

    if (valid && activity == ManagementActivity::kManagement &&
        management_valid) {
      auto management_refreshed = store_.RefreshManagementDeadline(
          transaction, stored_session->id,
          now_seconds + dependencies_.session_idle_timeout_seconds);
      if (!management_refreshed.ok()) {
        return rollback_unavailable();
      }
    }

    SessionIdentity session_identity;
    if (valid) {
      std::copy_n(stored_session->token_hash.data(), kSessionIdentityBytes,
                  session_identity.bytes.begin());
    }
    if (valid) {
      auto refreshed = store_.RefreshSession(
          transaction, stored_session->id, now_seconds,
          now_seconds + dependencies_.session_idle_timeout_seconds);
      if (!refreshed.ok()) {
        return rollback_unavailable();
      }
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return rollback_unavailable();
    }
    session_expiry_worker_->Wake();
    stored_hash_cleanup.Clear();
    token_hash_cleanup.Clear();
    PublishSessionRevocations(expired_identities, hooks_.revoke_sessions,
                              hooks_.revoke_all_streams);
    if (!valid) {
      return AuthenticationFailure<Principal>();
    }
    return common::Result<Principal>::Ok(
        {stored_session->user_id, std::move(stored_session->username),
         *role, std::move(session_identity), management_valid});
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
    SensitiveCleanupGuard token_hash_cleanup(token_hash.value());
    SensitiveCleanupGuard stored_hash_cleanup;
    auto peer = NormalizePeerIp(peer_ip);
    if (!peer.ok()) {
      (void)::CRYPTO_memcmp(token_hash.value().data(),
                            DummyPassword().record.derived.data(),
                            kSessionTokenHashBytes);
      return AuthenticationFailure<void>();
    }
    const std::string normalized_peer = std::move(peer).value();
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (!HasSafeDeadline(now_seconds,
                         dependencies_.session_idle_timeout_seconds)) {
      return AuthenticationUnavailable<void>();
    }

    auto started = store_.BeginTransaction();
    if (!started.ok()) {
      return AuthenticationUnavailable<void>();
    }
    auto transaction = std::move(started).value();
    const auto rollback_unavailable = [&transaction]() {
      if (transaction.active()) {
        (void)transaction.Rollback();
      }
      return AuthenticationUnavailable<void>();
    };

    auto expired = store_.DeleteExpiredSessions(transaction, now_seconds);
    if (!expired.ok()) {
      return rollback_unavailable();
    }
    auto identities = std::move(expired).value();
    auto session = store_.ReadSessionByTokenHash(
        transaction, {token_hash.value().data(), token_hash.value().size()},
        normalized_peer, now_seconds);
    if (!session.ok()) {
      return rollback_unavailable();
    }
    auto& session_slot = session.value();
    auto* stored_session =
        session_slot.has_value() ? &*session_slot : nullptr;
    if (stored_session != nullptr) {
      stored_hash_cleanup.Bind(stored_session->token_hash);
    }
    const unsigned char* expected_hash =
        DummyPassword().record.derived.data();
    if (stored_session != nullptr &&
        stored_session->token_hash.size() == kSessionTokenHashBytes) {
      expected_hash = stored_session->token_hash.data();
    }
    const bool hash_matches =
        ::CRYPTO_memcmp(token_hash.value().data(), expected_hash,
                        kSessionTokenHashBytes) == 0;
    const bool valid =
        stored_session != nullptr && hash_matches &&
        stored_session->peer_ip == normalized_peer &&
        ParseUserRole(stored_session->role).has_value() &&
        stored_session->token_hash.size() == kSessionIdentityBytes;
    SessionIdentity session_identity;
    if (valid) {
      std::copy_n(stored_session->token_hash.data(), kSessionIdentityBytes,
                  session_identity.bytes.begin());
      identities.emplace_back(std::move(session_identity));
      auto removed = store_.DeleteSession(transaction, stored_session->id);
      if (!removed.ok()) {
        return rollback_unavailable();
      }
      auto audit = store_.InsertAuditEvent(
          transaction, now_seconds, "session_logout", "success",
          stored_session->user_id, normalized_peer, "session_logout");
      if (!audit.ok()) {
        return rollback_unavailable();
      }
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return rollback_unavailable();
    }
    session_expiry_worker_->Wake();
    stored_hash_cleanup.Clear();
    token_hash_cleanup.Clear();
    PublishSessionRevocations(identities, hooks_.revoke_sessions,
                              hooks_.revoke_all_streams);
    return valid ? common::Result<void>::Ok()
                 : AuthenticationFailure<void>();
  } catch (...) {
    return AuthenticationUnavailable<void>();
  }
}

common::Result<std::int64_t> AuthService::Reauthenticate(
    std::span<const unsigned char> token,
    std::string_view peer_ip,
    common::SecureBytes password) {
  try {
    SensitiveCleanupGuard password_cleanup(password);
    auto token_hash = HashToken(token);
    if (!token_hash.ok() || !DummyPassword().valid) {
      return AuthenticationUnavailable<std::int64_t>();
    }
    SensitiveCleanupGuard token_hash_cleanup(token_hash.value());
    SensitiveCleanupGuard stored_hash_cleanup;
    auto peer = NormalizePeerIp(peer_ip);
    if (!peer.ok()) {
      (void)::CRYPTO_memcmp(token_hash.value().data(),
                            DummyPassword().record.derived.data(),
                            kSessionTokenHashBytes);
      return AuthenticationRequired<std::int64_t>();
    }
    const std::string normalized_peer = std::move(peer).value();
    const std::int64_t now_seconds = dependencies_.now_seconds();
    if (!HasSafeDeadline(now_seconds,
                         dependencies_.session_idle_timeout_seconds)) {
      return AuthenticationUnavailable<std::int64_t>();
    }

    auto started = store_.BeginTransaction();
    if (!started.ok()) {
      return AuthenticationUnavailable<std::int64_t>();
    }
    auto transaction = std::move(started).value();
    const auto rollback_unavailable = [&transaction]() {
      if (transaction.active()) {
        (void)transaction.Rollback();
      }
      return AuthenticationUnavailable<std::int64_t>();
    };

    auto expired = store_.DeleteExpiredSessions(transaction, now_seconds);
    if (!expired.ok()) {
      return rollback_unavailable();
    }
    auto expired_identities = std::move(expired).value();
    auto session = store_.ReadSessionByTokenHash(
        transaction, {token_hash.value().data(), token_hash.value().size()},
        normalized_peer, now_seconds);
    if (!session.ok()) {
      return rollback_unavailable();
    }
    auto& session_slot = session.value();
    auto* stored_session =
        session_slot.has_value() ? &*session_slot : nullptr;
    if (stored_session != nullptr) {
      stored_hash_cleanup.Bind(stored_session->token_hash);
    }
    const unsigned char* expected_hash =
        DummyPassword().record.derived.data();
    if (stored_session != nullptr &&
        stored_session->token_hash.size() == kSessionTokenHashBytes) {
      expected_hash = stored_session->token_hash.data();
    }
    const bool hash_matches =
        ::CRYPTO_memcmp(token_hash.value().data(), expected_hash,
                        kSessionTokenHashBytes) == 0;
    const bool session_valid =
        stored_session != nullptr && hash_matches &&
        stored_session->peer_ip == normalized_peer &&
        ParseUserRole(stored_session->role).has_value();

    const std::string canonical_username =
        session_valid ? CanonicalUsername(stored_session->username)
                      : std::string();
    auto context = store_.ReadAuthenticationContext(
        transaction, canonical_username, normalized_peer);
    if (!context.ok()) {
      return rollback_unavailable();
    }
    const auto& context_user_slot = context.value().user;
    const auto* context_user =
        context_user_slot.has_value() ? &*context_user_slot : nullptr;
    const bool has_user =
        session_valid && context_user != nullptr;

    // Always run the KDF so a missing or mismatched session takes the same
    // time as a wrong password.
    const PasswordRecord& record =
        has_user ? context_user->password : DummyPassword().record;
    bool password_matches = false;
    try {
      auto verified = dependencies_.verify_password(password, record);
      password_matches = has_user && verified.ok() && verified.value();
    } catch (...) {
      password_matches = false;
    }
    password.clear();

    const bool lock_active =
        has_user && context_user->lock_until_seconds.has_value() &&
        now_seconds < *context_user->lock_until_seconds;
    const bool enabled = has_user && context_user->enabled;

    if (!session_valid) {
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return rollback_unavailable();
      }
      session_expiry_worker_->Wake();
      PublishSessionRevocations(expired_identities, hooks_.revoke_sessions,
                                hooks_.revoke_all_streams);
      return AuthenticationRequired<std::int64_t>();
    }

    const std::optional<std::int64_t> actor_user_id =
        has_user ? std::optional<std::int64_t>(context_user->id)
                 : std::nullopt;

    if (!password_matches || !enabled || lock_active) {
      if (has_user && enabled && !lock_active) {
        const bool prior_lock_expired =
            context_user->lock_until_seconds.has_value() &&
            now_seconds >= *context_user->lock_until_seconds;
        const std::int64_t previous_failures =
            prior_lock_expired
                ? 0
                : std::clamp<std::int64_t>(
                      context_user->failed_login_count, 0,
                      kFailureLimit);
        const std::int64_t failures =
            std::min<std::int64_t>(previous_failures + 1, kFailureLimit);
        const std::optional<std::int64_t> lock_until =
            failures == kFailureLimit
                ? std::optional<std::int64_t>(now_seconds +
                                              kLockDurationSeconds)
                : std::nullopt;
        auto updated = store_.SetLoginFailureState(
            transaction, context_user->id, failures, lock_until);
        if (!updated.ok()) {
          return rollback_unavailable();
        }
      }
      auto failed_audit = store_.InsertAuditEvent(
          transaction, now_seconds, "authentication_failed", "failure",
          actor_user_id, normalized_peer, "reauthentication_failed");
      if (!failed_audit.ok()) {
        return rollback_unavailable();
      }
      auto committed = transaction.Commit();
      if (!committed.ok()) {
        return rollback_unavailable();
      }
      session_expiry_worker_->Wake();
      PublishSessionRevocations(expired_identities, hooks_.revoke_sessions,
                                hooks_.revoke_all_streams);
      return AuthenticationFailure<std::int64_t>();
    }

    const std::int64_t management_expires_at_seconds =
        now_seconds + dependencies_.session_idle_timeout_seconds;
    auto refreshed = store_.RefreshManagementDeadline(
        transaction, stored_session->id, management_expires_at_seconds);
    if (!refreshed.ok()) {
      return rollback_unavailable();
    }
    auto cleared = store_.SetLoginFailureState(
        transaction, context_user->id, 0, std::nullopt);
    if (!cleared.ok()) {
      return rollback_unavailable();
    }
    auto success_audit = store_.InsertAuditEvent(
        transaction, now_seconds, "management_reauthenticated", "success",
        actor_user_id, normalized_peer, "management_reauthenticated");
    if (!success_audit.ok()) {
      return rollback_unavailable();
    }
    auto committed = transaction.Commit();
    if (!committed.ok()) {
      return rollback_unavailable();
    }
    session_expiry_worker_->Wake();
    stored_hash_cleanup.Clear();
    token_hash_cleanup.Clear();
    PublishSessionRevocations(expired_identities, hooks_.revoke_sessions,
                              hooks_.revoke_all_streams);
    return common::Result<std::int64_t>::Ok(management_expires_at_seconds);
  } catch (...) {
    return AuthenticationUnavailable<std::int64_t>();
  }
}

}  // namespace camera_firmware::security
