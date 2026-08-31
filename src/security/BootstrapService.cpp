#include "camera_firmware/security/BootstrapService.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <cstddef>
#include <memory>
#include <span>
#include <string_view>
#include <utility>

#include <gio/gio.h>
#include <openssl/rand.h>

#include "camera_firmware/security/PasswordHasher.hpp"
#include "camera_firmware/security/PasswordPolicy.hpp"
#include "camera_firmware/security/UserManagementService.hpp"

namespace camera_firmware::security {
namespace {

template <typename T>
common::Result<T> BootstrapError(std::string code, std::string message) {
  return common::Result<T>::Err({std::move(code), std::move(message)});
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
    return BootstrapError<std::string>("E_BOOTSTRAP_PEER",
                                       "peer address is invalid");
  }
  const std::string address_text(input);
  std::unique_ptr<GInetAddress, InetAddressDeleter> address(
      g_inet_address_new_from_string(address_text.c_str()));
  if (!address) {
    return BootstrapError<std::string>("E_BOOTSTRAP_PEER",
                                       "peer address is invalid");
  }
  std::unique_ptr<gchar, GCharDeleter> normalized(
      g_inet_address_to_string(address.get()));
  if (!normalized) {
    return BootstrapError<std::string>("E_BOOTSTRAP_PEER",
                                       "peer address is invalid");
  }
  return common::Result<std::string>::Ok(normalized.get());
}

// Mirrors src/security/AuthService.cpp's DefaultRandom: the initial account
// password is secret authenticator material, so it draws from OpenSSL's private
// DRBG rather than the public pool PasswordHasher uses for non-secret salts.
common::Result<common::SecureBytes> DefaultPrivateRandom(
    std::size_t output_size) {
  if (output_size > static_cast<std::size_t>(INT_MAX)) {
    return BootstrapError<common::SecureBytes>(
        "E_BOOTSTRAP_INITIAL_ACCOUNT", "initial account generation failed");
  }
  common::SecureBytes output;
  try {
    output.resize(output_size);
  } catch (...) {
    return BootstrapError<common::SecureBytes>(
        "E_BOOTSTRAP_INITIAL_ACCOUNT", "initial account generation failed");
  }
  if (::RAND_priv_bytes(output.data(), static_cast<int>(output.size())) != 1) {
    return BootstrapError<common::SecureBytes>(
        "E_BOOTSTRAP_INITIAL_ACCOUNT", "initial account generation failed");
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

// Generated credential shape. The username is deliberately delimiter-free so
// the only way it can collide with a reserved identity is by equalling one
// outright; ValidateInitialUsername still gets the final say below.
constexpr std::size_t kInitialUsernameLength = 12U;
constexpr std::size_t kInitialPasswordLength = 16U;
// Generation draws and validates rather than constructing to fit the policy, so
// a bound is needed. Each password attempt clears the policy with probability
// greater than 0.8, so 64 attempts fail only with negligible probability while
// still guaranteeing termination.
constexpr int kInitialGenerationAttempts = 64;

constexpr std::string_view kUsernameLeadAlphabet = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view kUsernameAlphabet =
    "abcdefghijklmnopqrstuvwxyz0123456789";

// Every printable, non-space ASCII byte, matching the range ValidatePassword
// accepts.
std::array<char, 94U> PasswordAlphabet() {
  std::array<char, 94U> alphabet{};
  for (std::size_t index = 0; index < alphabet.size(); ++index) {
    alphabet[index] = static_cast<char>(0x21U + index);
  }
  return alphabet;
}

// Uniform selection over `alphabet` by rejection sampling: bytes at or above
// the largest whole multiple of the alphabet size are discarded rather than
// folded, so no symbol is favoured.
template <typename Draw>
common::Result<common::SecureBytes> DrawFromAlphabet(
    const Draw& draw,
    std::span<const char> alphabet,
    std::size_t count) {
  constexpr int kMaximumDrawRounds = 32;
  const auto alphabet_size = static_cast<unsigned int>(alphabet.size());
  const unsigned int limit = 256U - (256U % alphabet_size);
  common::SecureBytes output;
  output.resize(count);
  std::size_t produced = 0U;
  for (int round = 0; round < kMaximumDrawRounds && produced < count; ++round) {
    auto entropy = draw((count - produced) * 2U + 8U);
    if (!entropy.ok()) {
      return common::Result<common::SecureBytes>::Err(entropy.error());
    }
    const common::SecureBytes& bytes = entropy.value();
    for (std::size_t index = 0; index < bytes.size() && produced < count;
         ++index) {
      const unsigned int value = bytes.data()[index];
      if (value >= limit) {
        continue;
      }
      output.data()[produced] =
          static_cast<unsigned char>(alphabet[value % alphabet_size]);
      ++produced;
    }
  }
  if (produced < count) {
    return BootstrapError<common::SecureBytes>(
        "E_BOOTSTRAP_INITIAL_ACCOUNT", "initial account generation failed");
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

template <typename Draw>
common::Result<std::string> GenerateInitialUsername(const Draw& draw) {
  auto lead = DrawFromAlphabet(draw, kUsernameLeadAlphabet, 1U);
  if (!lead.ok()) {
    return common::Result<std::string>::Err(lead.error());
  }
  auto tail =
      DrawFromAlphabet(draw, kUsernameAlphabet, kInitialUsernameLength - 1U);
  if (!tail.ok()) {
    return common::Result<std::string>::Err(tail.error());
  }
  std::string username;
  username.push_back(static_cast<char>(lead.value().data()[0]));
  username.append(reinterpret_cast<const char*>(tail.value().data()),
                  tail.value().size());
  return common::Result<std::string>::Ok(std::move(username));
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

}  // namespace

BootstrapService::BootstrapService(
    SecurityStore& store,
    config::AppConfig config,
    std::vector<std::string> reserved_identities,
    PasswordHasherDependencies hasher_dependencies)
    : store_(store),
      config_(std::move(config)),
      reserved_identities_(std::move(reserved_identities)),
      hasher_dependencies_(std::move(hasher_dependencies)) {}

// Draws from the provider's private DRBG (RandomBytesPrivate), not the public
// one (RandomBytes), matching DefaultPrivateRandom's use of RAND_priv_bytes
// above and AuthService's session tokens. The initial account password is a
// secret authenticator, not a salt: it must not be downgraded to a randomness
// pool shared with everything else in the process. DerivePassword keeps using
// the public seam below for the PBKDF2 salt, which is not secret.
common::Result<common::SecureBytes> BootstrapService::RandomBytes(
    std::size_t output_size) const {
  if (hasher_dependencies_.random_bytes) {
    return hasher_dependencies_.random_bytes(output_size);
  }
  if (hasher_dependencies_.provider != nullptr) {
    return hasher_dependencies_.provider->RandomBytesPrivate(output_size);
  }
  return DefaultPrivateRandom(output_size);
}

common::Result<InitialAccountCredential>
BootstrapService::EnsureInitialAccount() {
  try {
    // Global order: service initialization, store connection, credential I/O.
    // Sharing Initialize's mutex keeps account replacement and setup completion
    // from interleaving.
    std::lock_guard initialize_lock(initialize_mutex_);

    std::vector<std::string_view> reserved_views;
    reserved_views.reserve(reserved_identities_.size());
    for (const auto& identity : reserved_identities_) {
      reserved_views.emplace_back(identity);
    }

    const auto draw = [this](std::size_t output_size) {
      return RandomBytes(output_size);
    };

    // Generate and validate. The credential must clear the very policy a human
    // credential clears, so it can never drift from that policy by being built
    // to satisfy it.
    std::string username;
    for (int attempt = 0;
         attempt < kInitialGenerationAttempts && username.empty(); ++attempt) {
      auto generated = GenerateInitialUsername(draw);
      if (!generated.ok()) {
        return common::Result<InitialAccountCredential>::Err(
            generated.error());
      }
      if (ValidateInitialUsername(generated.value(), reserved_views).ok()) {
        username = std::move(generated).value();
      }
    }
    if (username.empty()) {
      return BootstrapError<InitialAccountCredential>(
          "E_BOOTSTRAP_INITIAL_ACCOUNT", "initial account generation failed");
    }

    const auto alphabet = PasswordAlphabet();
    common::SecureBytes password;
    for (int attempt = 0;
         attempt < kInitialGenerationAttempts && password.size() == 0U;
         ++attempt) {
      auto generated = DrawFromAlphabet(
          draw, std::span<const char>(alphabet), kInitialPasswordLength);
      if (!generated.ok()) {
        return common::Result<InitialAccountCredential>::Err(
            generated.error());
      }
      if (ValidatePassword(username, generated.value()).ok()) {
        password = std::move(generated).value();
      }
    }
    if (password.size() == 0U) {
      return BootstrapError<InitialAccountCredential>(
          "E_BOOTSTRAP_INITIAL_ACCOUNT", "initial account generation failed");
    }

    auto password_record = DerivePassword(password, hasher_dependencies_);
    if (!password_record.ok()) {
      password.clear();
      return BootstrapError<InitialAccountCredential>(
          "E_BOOTSTRAP_PASSWORD", "initial account setup failed");
    }

    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    auto stored = store_.ReplaceInitialAccount(
        CanonicalUsername(username), username,
        std::move(password_record).value(), now);
    if (!stored.ok()) {
      password.clear();
      return common::Result<InitialAccountCredential>::Err(stored.error());
    }

    InitialAccountCredential credential;
    credential.username = std::move(username);
    credential.password = std::move(password);
    return common::Result<InitialAccountCredential>::Ok(std::move(credential));
  } catch (...) {
    return BootstrapError<InitialAccountCredential>(
        "E_BOOTSTRAP_INITIAL_ACCOUNT", "initial account setup failed");
  }
}

common::Result<BootstrapResult> BootstrapService::Initialize(
    BootstrapRequest request) {
  PasswordCleanupGuard password_cleanup(request.password);
  try {
    // Global order: service initialization, store connection, credential I/O.
    std::lock_guard initialize_lock(initialize_mutex_);
    auto confirmed = NormalizePeerIp(request.confirmed_peer_ip);
    auto actual = NormalizePeerIp(request.actual_peer_ip);
    if (!confirmed.ok() || !actual.ok() ||
        confirmed.value() != actual.value()) {
      return BootstrapError<BootstrapResult>("E_BOOTSTRAP_PEER",
                                             "peer address confirmation failed");
    }

    // Validated in full before anything is written. The browser rejects
    // ranges, wildcards and CIDR with a visible reason, but that is a
    // convenience for the operator, not a control: this is the check that
    // decides. NormalizeManagementIp is the same one the administrator-only
    // management-IP routes run, so setup cannot admit an address those routes
    // would refuse.
    //
    // The confirming peer is not in this list and is not required to be. It is
    // registered from its own field by InitializeDevice; entries here only add
    // to it, and one repeating the peer collapses below.
    std::vector<std::string> additional_management_ips;
    additional_management_ips.reserve(request.management_ips.size());
    for (const auto& submitted : request.management_ips) {
      auto normalized = NormalizeManagementIp(submitted);
      if (!normalized.ok()) {
        return common::Result<BootstrapResult>::Err(normalized.error());
      }
      if (normalized.value() == confirmed.value() ||
          std::find(additional_management_ips.begin(),
                    additional_management_ips.end(),
                    normalized.value()) != additional_management_ips.end()) {
        continue;
      }
      additional_management_ips.push_back(std::move(normalized).value());
    }
    // The peer's own row counts against the store's per-role ceiling, so the
    // list may hold one fewer than that. Rejected here, before the device has
    // been touched, rather than discovered part way through the transaction.
    if (additional_management_ips.size() + 1U > kMaximumManagementIpsPerRole) {
      return BootstrapError<BootstrapResult>(
          "E_MANAGEMENT_IP_LIMIT", "too many management addresses");
    }

    std::vector<std::string_view> reserved_views;
    reserved_views.reserve(reserved_identities_.size());
    for (const auto& identity : reserved_identities_) {
      reserved_views.emplace_back(identity);
    }
    auto username_validation =
        ValidateInitialUsername(request.username, reserved_views);
    if (!username_validation.ok()) {
      return common::Result<BootstrapResult>::Err(
          username_validation.error());
    }
    auto password_validation = ValidatePassword(request.username,
                                                request.password);
    if (!password_validation.ok()) {
      return common::Result<BootstrapResult>::Err(
          password_validation.error());
    }

    auto password_record = DerivePassword(request.password);
    if (!password_record.ok()) {
      return BootstrapError<BootstrapResult>("E_BOOTSTRAP_PASSWORD",
                                             "password setup failed");
    }

    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    BootstrapRecord record{
        CanonicalUsername(request.username), request.username,
        std::move(password_record).value(), std::move(confirmed).value(), now,
        std::move(additional_management_ips)};
    auto initialized = store_.InitializeDevice(
        std::move(record), [this, &request] {
          return store_.InstallBootstrapRtspCredential(
              config_.secure_rtsp.client_auth.credential_file,
              request.username, config_.secure_rtsp.client_auth.realm,
              {request.password.data(), request.password.size()});
        });
    if (!initialized.ok()) {
      return common::Result<BootstrapResult>::Err(initialized.error());
    }
    return common::Result<BootstrapResult>::Ok(
        {DeviceState::kOperational});
  } catch (...) {
    return BootstrapError<BootstrapResult>("E_BOOTSTRAP_FAILED",
                                           "device setup failed");
  }
}

std::vector<std::string> BuildReservedIdentities(
    const config::AppConfig& config) {
  std::vector<std::string> identities = {
      "root", "admin", "administrator", "camera", "camera-firmware",
      "raspberry-pi", "hailo", "imx708"};
  if (!config.camera.id.empty()) {
    identities.push_back(config.camera.id);
  }
  return identities;
}

}  // namespace camera_firmware::security
