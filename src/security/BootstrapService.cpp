#include "camera_firmware/security/BootstrapService.hpp"

#include <algorithm>
#include <chrono>
#include <memory>
#include <string_view>
#include <utility>

#include <gio/gio.h>

#include "camera_firmware/security/PasswordHasher.hpp"
#include "camera_firmware/security/PasswordPolicy.hpp"

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
    std::vector<std::string> reserved_identities)
    : store_(store),
      config_(std::move(config)),
      reserved_identities_(std::move(reserved_identities)) {}

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
        std::move(password_record).value(), std::move(confirmed).value(), now};
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
