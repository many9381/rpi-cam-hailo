#pragma once

#include <cstddef>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <functional>
#include <memory>
#include <mutex>
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
#include "camera_firmware/security/AuthService.hpp"
#include "camera_firmware/security/BootstrapService.hpp"
#include "camera_firmware/security/DeviceTlsManager.hpp"
#include "camera_firmware/security/SecurityStore.hpp"
#include "camera_firmware/service/BoundedWorker.hpp"

namespace trantor {
class EventLoop;
}

namespace camera_firmware::service {

struct CameraStatus {
  std::string id;
  std::string state{"unknown"};
  bool snapshot_available{false};
  unsigned int width{0U};
  unsigned int height{0U};
  unsigned int configured_fps{0U};
  double capture_fps{0.0};
  double encoded_fps{0.0};
  std::uint64_t captured_frames{0U};
  std::uint64_t encoded_frames{0U};
  std::uint64_t capture_error_count{0U};
  std::uint64_t encode_error_count{0U};
};

using CameraStatusProvider = std::function<std::vector<CameraStatus>()>;
using SnapshotCallback =
    std::function<std::optional<std::vector<std::uint8_t>>(const std::string&)>;
using LiveMp4StreamCallback = std::function<std::size_t(char*, std::size_t)>;
using LiveMp4OpenCallback = std::function<
    common::Result<LiveMp4StreamCallback>(const std::string&)>;

struct AiRunnerServiceStatus {
  std::string camera_id;
  std::string model_id;
  std::string model_kind;
  std::uint64_t submitted_frames{0};
  std::uint64_t processed_frames{0};
  std::uint64_t dropped_frames{0};
  double last_preprocess_ms{0.0};
  double last_inference_ms{0.0};
  std::uint64_t last_processed_sequence{0};
  std::string last_error_code;
  std::string last_error_message;
};

struct AiModelServiceStatus {
  std::string id;
  std::string kind;
  unsigned int input_width{0};
  unsigned int input_height{0};
  std::string input_format;
  bool letterbox{false};
  std::string output_name;
  float confidence_threshold{0.0F};
  std::string labels;
};

struct AiServiceStatus {
  bool enabled{false};
  std::string backend{"disabled"};
  std::string state{"disabled"};
  std::size_t model_count{0};
  std::size_t runner_count{0};
  std::string reason{"disabled by config"};
  std::vector<AiModelServiceStatus> models;
  std::vector<AiRunnerServiceStatus> runners;
};

using AiStatusProvider = std::function<AiServiceStatus()>;
using AiControlCallback = std::function<common::Result<void>()>;
using RuntimeStartCallback = std::function<common::Result<void>()>;

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
  std::optional<security::ResolvedTlsMaterial> tls_material;
};

struct ServiceInitArgs {
  const config::AppConfig* app_config{nullptr};
  std::string bind_address{"0.0.0.0"};
  std::uint16_t port{8080};
  std::string document_root{"web/dist"};
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
  LiveMp4OpenCallback live_stream_callback;
  RuntimeStartCallback runtime_start_callback;
  std::shared_ptr<security::SecurityStore> security_store;
  std::shared_ptr<security::BootstrapService> bootstrap_service;
  std::shared_ptr<security::AuthService> auth_service;
};

Json::Value BuildHealthJson(const std::string& status);
Json::Value BuildCameraStatusJson(const CameraStatus& camera);
Json::Value BuildAiStatusJson(const AiServiceStatus& status);
Json::Value BuildAiStatusJson(bool requested);
drogon::HttpResponsePtr BuildAiRestartResponse(
    const AiControlCallback& restart_callback,
    const AiStatusProvider& ai_status_provider = {});
drogon::HttpResponsePtr BuildRuntimeRestartResponse(
    const RuntimeStartCallback& restart_callback);
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
    const config::HttpConfig& http_config,
    const security::ResolvedTlsMaterial& tls_material);
common::Result<void> ValidateHttpTlsConfigFiles(
    const config::HttpConfig& http_config);
drogon::HttpResponsePtr BuildSnapshotResponse(
    const SnapshotCallback& snapshot_callback,
    const std::string& camera_id);
drogon::HttpResponsePtr BuildLiveMp4Response(
    const LiveMp4OpenCallback& live_stream_callback,
    const std::string& camera_id);

namespace internal {

std::thread StartServiceThreadWithTlsOwner(
    std::optional<security::ResolvedTlsMaterial> tls_material,
    std::function<void()> run);

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
  void BeginShutdown() noexcept;
  void Stop();

 private:
  void RunShutdownCoordinator() noexcept;
  void PerformShutdown(trantor::EventLoop* drain_loop) noexcept;
  void JoinShutdownCoordinator() noexcept;

  bool initialized_{false};
  bool running_{false};
  std::shared_ptr<BoundedWorker> security_worker_;
  std::optional<security::ResolvedTlsMaterial> tls_material_;
  std::thread server_thread_;
  std::shared_future<void> server_thread_done_;
  std::mutex shutdown_mutex_;
  std::condition_variable shutdown_condition_;
  std::thread shutdown_thread_;
  trantor::EventLoop* shutdown_drain_loop_{nullptr};
  bool shutdown_thread_started_{false};
  bool shutdown_requested_{false};
  bool shutdown_join_in_progress_{false};
  bool shutdown_thread_released_{false};
};

}  // namespace camera_firmware::service
