#pragma once

#include <string>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::config {

struct SessionKeyConfig {
  std::string source{"file"};
  std::string path;
  std::string encoding{"hex"};
  bool zeroize_on_reload{true};
};

struct SecureRtspConfig {
  bool enabled{true};
  bool control_tls{true};
  bool media_srtp{true};
  std::string bind_ip{"0.0.0.0"};
  int port{8555};
  std::string mount{"/imx708/main"};
  SessionKeyConfig session_key;
};

struct AppConfig {
  SecureRtspConfig secure_rtsp;
};

common::Result<AppConfig> LoadConfigFile(const std::string& path);

}  // namespace camera_firmware::config
