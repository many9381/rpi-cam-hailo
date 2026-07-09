#pragma once

#include <cstddef>
#include <chrono>
#include <cstdint>
#include <future>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <json/value.h>
#include <drogon/HttpResponse.h>

#include "camera_firmware/ai/DetectionBus.hpp"
#include "camera_firmware/ai/AiTypes.hpp"
#include "camera_firmware/common/Result.hpp"
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

struct AiRunnerServiceStatus {
  std::string camera_id;
  std::string model_id;
  std::string model_kind;
  std::uint64_t submitted_frames{0};
  std::uint64_t processed_frames{0};
  std::uint64_t dropped_frames{0};
  std::string last_error_code;
  std::string last_error_message;
};

struct AiServiceStatus {
  bool enabled{false};
  std::string backend{"disabled"};
  std::string state{"disabled"};
  std::size_t model_count{0};
  std::size_t runner_count{0};
  std::string reason{"disabled by config"};
  std::vector<AiRunnerServiceStatus> runners;
};

using AiStatusProvider = std::function<AiServiceStatus()>;
using AiControlCallback = std::function<common::Result<void>()>;

struct SecureStreamDiagnostics {
  std::uint64_t per_media_key_zeroize_count{0};
};

using SecureStreamDiagnosticsProvider =
    std::function<SecureStreamDiagnostics()>;

using DetectionSnapshotProvider =
    std::function<std::vector<ai::DetectionEvent>()>;
using DetectionEventSubscriber =
    std::function<ai::DetectionBus::Subscription(ai::DetectionBus::Handler)>;

struct ServiceListenerConfig {
  std::string bind_address{"0.0.0.0"};
  std::uint16_t port{8080};
  bool use_tls{false};
  std::string certificate_path;
  std::string private_key_path;
};

struct ServiceInitArgs {
  const config::AppConfig* app_config{nullptr};
  std::string bind_address{"0.0.0.0"};
  std::uint16_t port{8080};
  std::string document_root{"web"};
  std::string public_base_url{"http://127.0.0.1:8080"};
  std::string health_status{"ok"};
  bool ai_enabled{false};
  CameraStatusProvider camera_status_provider;
  AiStatusProvider ai_status_provider;
  AiControlCallback ai_restart_callback;
  SecureStreamDiagnosticsProvider secure_stream_diagnostics_provider;
  DetectionSnapshotProvider detection_snapshot_provider;
  DetectionEventSubscriber detection_event_subscriber;
  SnapshotCallback snapshot_callback;
};

Json::Value BuildHealthJson(const std::string& status);
Json::Value BuildAiStatusJson(const AiServiceStatus& status);
Json::Value BuildAiStatusJson(bool requested);
drogon::HttpResponsePtr BuildAiRestartResponse(
    const AiControlCallback& restart_callback,
    const AiStatusProvider& ai_status_provider = {});
Json::Value BuildDetectionEventJson(const ai::DetectionEvent& event);
Json::Value BuildDetectionSnapshotJson(
    const std::vector<ai::DetectionEvent>& events);
drogon::HttpResponsePtr BuildDetectionSnapshotResponse(
    const DetectionSnapshotProvider& detection_snapshot_provider);
std::vector<ai::DetectionEvent> MergeDetectionSnapshotWithEvent(
    std::vector<ai::DetectionEvent> events,
    const ai::DetectionEvent& event);
std::string BuildDetectionSseId(
    const std::vector<ai::DetectionEvent>& events);
std::string BuildDetectionSseEvent(
    const std::vector<ai::DetectionEvent>& events);
drogon::HttpResponsePtr BuildDetectionSseResponse(
    const std::vector<ai::DetectionEvent>& events);
Json::Value BuildStreamJson(
    std::string_view public_base_url,
    const config::SecureRtspConfig& secure_rtsp,
    const std::optional<SecureStreamDiagnostics>& diagnostics = std::nullopt);
ServiceListenerConfig BuildServiceListenerConfig(
    const config::HttpConfig& http_config);
common::Result<void> ValidateHttpTlsConfigFiles(
    const config::HttpConfig& http_config);
drogon::HttpResponsePtr BuildSnapshotResponse(
    const SnapshotCallback& snapshot_callback,
    const std::string& camera_id);

namespace internal {

common::Result<void> StopServiceThreadWithin(
    std::thread& service_thread,
    const std::shared_future<void>& service_thread_done,
    std::chrono::milliseconds timeout,
    const std::function<void()>& request_stop);

}  // namespace internal

class ServiceApp {
 public:
  ServiceApp() = default;
  ~ServiceApp();

  ServiceApp(const ServiceApp&) = delete;
  ServiceApp& operator=(const ServiceApp&) = delete;
  ServiceApp(ServiceApp&&) = delete;
  ServiceApp& operator=(ServiceApp&&) = delete;

  [[nodiscard]] common::Result<void> Init(const ServiceInitArgs& args);
  void Stop();

 private:
  bool initialized_{false};
  bool running_{false};
  std::thread server_thread_;
  std::shared_future<void> server_thread_done_;
};

}  // namespace camera_firmware::service
