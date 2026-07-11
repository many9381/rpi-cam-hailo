#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/security/SecurityStore.hpp"

namespace camera_firmware::security {

struct BootstrapRequest {
  std::string username;
  common::SecureBytes password;
  std::string confirmed_peer_ip;
  std::string actual_peer_ip;
};

struct BootstrapResult {
  DeviceState state{DeviceState::kOperational};
};

class BootstrapService {
 public:
  BootstrapService(SecurityStore& store,
                   config::AppConfig config,
                   std::vector<std::string> reserved_identities);

  common::Result<BootstrapResult> Initialize(BootstrapRequest request);

 private:
  SecurityStore& store_;
  config::AppConfig config_;
  std::vector<std::string> reserved_identities_;
  std::mutex initialize_mutex_;
};

std::vector<std::string> BuildReservedIdentities(
    const config::AppConfig& config);

}  // namespace camera_firmware::security
