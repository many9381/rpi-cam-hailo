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

#include "camera_firmware/media/JpegEncoder.hpp"
#include <string_view>
#include <thread>
#include <vector>

#include <json/value.h>
#include <drogon/HttpResponse.h>

#include "camera_firmware/ai/DetectionBus.hpp"
#include "camera_firmware/ai/AiTypes.hpp"
#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/crypto/CryptoProvider.hpp"
#include "camera_firmware/security/AuthService.hpp"
#include "camera_firmware/security/BootstrapService.hpp"
#include "camera_firmware/security/DeviceTlsManager.hpp"
#include "camera_firmware/security/SecurityStore.hpp"
#include "camera_firmware/security/SystemProtectionService.hpp"
#include "camera_firmware/service/BoundedWorker.hpp"
#include "camera_firmware/service/RuntimeSettingsHttp.hpp"
#include "camera_firmware/service/SessionStreamRegistry.hpp"
#include "camera_firmware/settings/RuntimeSettingsService.hpp"

namespace trantor {
class EventLoop;
}

namespace camera_firmware::service {

// 0 = no per-response byte budget; the stream ends on EOF/cancel.
inline constexpr std::size_t kDefaultLiveMp4ResponseByteLimit = 0U;
inline constexpr std::size_t kMaximumServiceConnections = 32U;
inline constexpr std::size_t kMaximumServiceConnectionsPerIp =
    kMaximumServiceConnections;
static_assert(kMaximumServiceConnectionsPerIp <= kMaximumServiceConnections);

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
  double last_encode_ms{0.0};
};

using CameraStatusProvider = std::function<std::vector<CameraStatus>()>;
using SnapshotCallback =
    std::function<std::optional<media::JpegBytes>(const std::string&)>;
using LiveMp4StreamCallback = std::function<std::size_t(char*, std::size_t)>;
using LiveMp4CancelCallback = std::function<void()>;
struct LiveMp4StreamHandle {
  LiveMp4StreamCallback read;
  LiveMp4CancelCallback cancel;
};
using LiveMp4OpenCallback = std::function<
    common::Result<LiveMp4StreamCallback>(const std::string&)>;
using CancellableLiveMp4OpenCallback = std::function<
    common::Result<LiveMp4StreamHandle>(const std::string&)>;

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
using RuntimeSettingsSnapshotCallback =
    std::function<settings::RuntimeSettingsSnapshot()>;
using RuntimeSettingsSaveCallback = std::function<
    common::Result<settings::RuntimeSettingsSnapshot>(
        std::uint64_t, settings::RuntimeSettings)>;
using RuntimeSettingsApplyCallback =
    std::function<settings::SettingsApplyResult(std::uint64_t)>;
using RuntimeSettingsDiscardCallback = std::function<
    common::Result<settings::RuntimeSettingsSnapshot>(std::uint64_t)>;
using ProtectionSnapshotCallback =
    std::function<security::SystemProtectionSnapshot()>;
using ProtectionStartCheckCallback = std::function<
    common::Result<security::SystemProtectionSnapshot>(
        security::ProtectionSuite, security::ProtectionActor)>;
using ProtectionRuntimeAllowedCallback = std::function<bool()>;
using ProtectionRuntimeControlGate =
    std::function<bool(const std::function<void()>&)>;

struct SecureStreamDiagnostics {
  std::uint64_t per_media_key_zeroize_count{0};
};

using SecureStreamDiagnosticsProvider =
    std::function<SecureStreamDiagnostics()>;

using DetectionSnapshotProvider =
    std::function<std::vector<ai::DetectionEvent>()>;
using DetectionEventSubscriber =
    std::function<ai::DetectionBus::Subscription(ai::DetectionBus::Handler)>;
using AuthServiceDependenciesProvider =
    std::function<security::AuthServiceDependencies()>;

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
  // Owned by the caller (main.cpp constructs and self-tests exactly one,
  // before opening the security store, and it outlives this ServiceApp).
  // ServiceApp must never construct its own CryptoProvider: see
  // SelectServiceTlsMaterial, which fails closed rather than doing so.
  crypto::CryptoProvider* provider{nullptr};
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
  RuntimeSettingsSnapshotCallback runtime_settings_snapshot_callback;
  RuntimeSettingsSaveCallback runtime_settings_save_callback;
  RuntimeSettingsApplyCallback runtime_settings_apply_callback;
  RuntimeSettingsDiscardCallback runtime_settings_discard_callback;
  ProtectionSnapshotCallback protection_snapshot_callback;
  ProtectionStartCheckCallback protection_start_check_callback;
  ProtectionRuntimeAllowedCallback protection_runtime_allowed_callback;
  ProtectionRuntimeControlGate protection_runtime_control_gate;
  std::shared_ptr<security::SecurityStore> security_store;
  std::shared_ptr<security::BootstrapService> bootstrap_service;
  AuthServiceDependenciesProvider auth_service_dependencies_provider;
  std::shared_ptr<SessionStreamRegistry> stream_registry;
  CancellableLiveMp4OpenCallback cancellable_live_stream_callback;
  std::optional<security::ResolvedTlsMaterial> tls_material;
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
    const config::HttpConfig& http_config, crypto::CryptoProvider& provider);
drogon::HttpResponsePtr BuildSnapshotResponse(
    const SnapshotCallback& snapshot_callback,
    const std::string& camera_id);
drogon::HttpResponsePtr BuildCancellableLiveMp4Response(
    const CancellableLiveMp4OpenCallback& live_stream_callback,
    const std::string& camera_id,
    std::size_t maximum_response_bytes = kDefaultLiveMp4ResponseByteLimit,
    std::shared_ptr<SessionStreamLease> stream_lease = {});
drogon::HttpResponsePtr BuildLiveMp4Response(
    const LiveMp4OpenCallback& live_stream_callback,
    const std::string& camera_id,
    std::size_t maximum_response_bytes = kDefaultLiveMp4ResponseByteLimit,
    std::shared_ptr<SessionStreamLease> stream_lease = {});

namespace internal {

class LiveMp4PumpManager;
class RuntimeCallbackLifecycle;

drogon::HttpResponsePtr ExecuteProtectedRuntimeControlCommand(
    const ProtectionRuntimeAllowedCallback& protection_runtime_allowed,
    const std::function<drogon::HttpResponsePtr()>& command);
drogon::HttpResponsePtr ExecuteSequentialProtectedRuntimeControlCommand(
    const ProtectionRuntimeAllowedCallback& protection_runtime_allowed,
    const std::function<drogon::HttpResponsePtr()>& validate,
    const std::function<drogon::HttpResponsePtr()>& command);
drogon::HttpResponsePtr ExecuteAtomicallyProtectedRuntimeControlCommand(
    const ProtectionRuntimeControlGate& protection_runtime_control_gate,
    const std::function<drogon::HttpResponsePtr()>& command);
common::Result<void> DispatchAtomicallyProtectedRuntimeControlCommand(
    const std::shared_ptr<BoundedWorker>& worker,
    ProtectionRuntimeControlGate protection_runtime_control_gate,
    std::function<drogon::HttpResponsePtr()> command,
    std::function<void(drogon::HttpResponsePtr)> complete);
drogon::HttpResponsePtr ExecuteUnrestrictedRuntimeOperation(
    const std::function<drogon::HttpResponsePtr()>& operation);
common::Result<std::optional<security::ResolvedTlsMaterial>>
SelectServiceTlsMaterial(const ServiceInitArgs& args);
void InstallDefaultProtectionRuntimeAllowedCallback(
    ServiceInitArgs& args, bool security_enabled);

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
  // Callbacks supplied to Init may call Stop(), but ServiceApp must outlive
  // those callbacks and a subsequent non-callback Stop() join. Destroying the
  // object from one of its runtime or media callbacks terminates the process.
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
  std::shared_ptr<BoundedWorker> runtime_settings_worker_;
  std::shared_ptr<SessionStreamRegistry> stream_registry_;
  std::shared_ptr<internal::LiveMp4PumpManager> live_pump_manager_;
  std::shared_ptr<internal::RuntimeCallbackLifecycle> runtime_lifecycle_;
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
