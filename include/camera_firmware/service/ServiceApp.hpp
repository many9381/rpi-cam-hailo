#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <json/value.h>

#include "camera_firmware/config/AppConfig.hpp"

namespace camera_firmware::service {

struct CameraStatus {
  std::string id;
  std::string state{"unknown"};
  bool snapshot_available{false};
};

using CameraStatusProvider = std::function<std::vector<CameraStatus>()>;
using SnapshotCallback =
    std::function<std::optional<std::vector<std::uint8_t>>(const std::string&)>;

struct ServiceInitArgs {
  const config::AppConfig* app_config{nullptr};
  std::string bind_address{"0.0.0.0"};
  std::uint16_t port{8080};
  std::string document_root{"web"};
  std::string public_base_url{"http://127.0.0.1:8080"};
  std::string health_status{"ok"};
  bool ai_enabled{false};
  CameraStatusProvider camera_status_provider;
  SnapshotCallback snapshot_callback;
};

Json::Value BuildHealthJson(const std::string& status);
Json::Value BuildStreamJson(std::string_view public_base_url,
                            const config::SecureRtspConfig& secure_rtsp);

class ServiceApp {
 public:
  ServiceApp() = default;
  ~ServiceApp();

  ServiceApp(const ServiceApp&) = delete;
  ServiceApp& operator=(const ServiceApp&) = delete;
  ServiceApp(ServiceApp&&) = delete;
  ServiceApp& operator=(ServiceApp&&) = delete;

  void Init(const ServiceInitArgs& args);
  void Stop();

 private:
  bool initialized_{false};
  bool running_{false};
  std::thread server_thread_;
};

}  // namespace camera_firmware::service
