#pragma once

#include <cstddef>
#include <mutex>
#include <string>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/security/PasswordHasher.hpp"
#include "camera_firmware/security/SecurityStore.hpp"

namespace camera_firmware::security {

struct BootstrapRequest {
  std::string username;
  common::SecureBytes password;
  std::string confirmed_peer_ip;
  std::string actual_peer_ip;
  // Addresses the operator asked to admit in addition to the peer confirming
  // setup. `confirmed_peer_ip` is registered whatever this holds, including
  // when it is empty: see Initialize.
  std::vector<std::string> management_ips;
};

struct BootstrapResult {
  DeviceState state{DeviceState::kOperational};
};

// The per-device credential the operator uses to sign in before setup has run.
// The password is plaintext and lives in memory only: it is never written to
// the store, a log line, or an audit record.
struct InitialAccountCredential {
  std::string username;
  common::SecureBytes password;
};

class BootstrapService {
 public:
  BootstrapService(SecurityStore& store, config::AppConfig config,
                   std::vector<std::string> reserved_identities,
                   PasswordHasherDependencies hasher_dependencies = {});

  common::Result<BootstrapResult> Initialize(BootstrapRequest request);

  // Creates the initial account when the device holds no administrator,
  // replacing any previous initial account. Returns the plaintext credential
  // for display. The plaintext is not stored anywhere by this call.
  [[nodiscard]] common::Result<InitialAccountCredential> EnsureInitialAccount();

 private:
  [[nodiscard]] common::Result<common::SecureBytes> RandomBytes(
      std::size_t output_size) const;

  SecurityStore& store_;
  config::AppConfig config_;
  std::vector<std::string> reserved_identities_;
  PasswordHasherDependencies hasher_dependencies_;
  std::mutex initialize_mutex_;
};

std::vector<std::string> BuildReservedIdentities(
    const config::AppConfig& config);

}  // namespace camera_firmware::security
