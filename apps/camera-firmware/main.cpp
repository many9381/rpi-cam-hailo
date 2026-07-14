#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <drogon/HttpAppFramework.h>

#include "camera_firmware/ai/AiFrameTap.hpp"
#include "camera_firmware/ai/AiRuntime.hpp"
#include "camera_firmware/ai/DetectionBus.hpp"
#include "camera_firmware/boot/FirmwareBootCoordinator.hpp"
#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/CameraPipeline.hpp"
#include "camera_firmware/media/EncodedRing.hpp"
#include "camera_firmware/media/SnapshotTap.hpp"
#include "camera_firmware/rtsp/SecureRtspServer.hpp"
#include "camera_firmware/runtime/FirmwareRuntime.hpp"
#include "camera_firmware/security/SecurityStore.hpp"
#include "camera_firmware/service/ServiceApp.hpp"

namespace {

using camera_firmware::common::Error;
using camera_firmware::common::Logger;

std::atomic_bool g_stop_requested{false};

class LiveMp4ByteStream {
 public:
  LiveMp4ByteStream(
      camera_firmware::media::FragmentRing::Reader reader,
      std::chrono::milliseconds stale_timeout)
      : reader_(std::move(reader)), stale_timeout_(stale_timeout) {}

  std::size_t Read(char* output, std::size_t capacity) {
    if (output == nullptr) {
      Close();
      return 0U;
    }
    if (capacity == 0U || !reader_.valid()) {
      return 0U;
    }

    while (!current_bytes_ || current_offset_ >= current_bytes_->size()) {
      current_bytes_.reset();
      current_offset_ = 0U;
      auto next = reader_.WaitNext(stale_timeout_);
      if (!next.ok() || !next.value().has_value() ||
          !next.value()->bytes || next.value()->bytes->empty()) {
        Close();
        return 0U;
      }
      current_bytes_ = std::move(next).value()->bytes;
    }

    const auto count =
        std::min(capacity, current_bytes_->size() - current_offset_);
    std::copy_n(current_bytes_->data() + current_offset_, count, output);
    current_offset_ += count;
    return count;
  }

 private:
  void Close() noexcept {
    reader_ = {};
    current_bytes_.reset();
    current_offset_ = 0U;
  }

  camera_firmware::media::FragmentRing::Reader reader_;
  const std::chrono::milliseconds stale_timeout_;
  std::shared_ptr<const std::vector<std::uint8_t>> current_bytes_;
  std::size_t current_offset_{0U};
};

void RequestShutdown() {
  g_stop_requested.store(true);
}

void HandleSignal(int) { RequestShutdown(); }

int PrintError(const Error& error) {
  std::cerr << error.code << ": " << error.message << '\n';
  return EXIT_FAILURE;
}

void InstallSignalHandlers() {
  std::signal(SIGINT, HandleSignal);
  std::signal(SIGTERM, HandleSignal);
  drogon::app().setIntSignalHandler(RequestShutdown);
  drogon::app().setTermSignalHandler(RequestShutdown);
}

void WaitForShutdown() {
  while (!g_stop_requested.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

int ValidateConfig(const std::string& config_path) {
  auto cfg = camera_firmware::config::LoadConfigFile(config_path);
  if (!cfg.ok()) {
    return PrintError(cfg.error());
  }

  auto plugin = camera_firmware::rtsp::RegisterBuildTreeSecureSrtpPluginPath(
      CF_SECURE_SRTP_PLUGIN_DIR);
  if (!plugin.ok()) {
    return PrintError(plugin.error());
  }

  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(64);
  camera_firmware::media::CameraPipeline camera_pipeline(
      snapshot_tap, ai_frame_tap, encoded_ring);
  auto camera_validation = camera_pipeline.ValidateConfigOnly(cfg.value());
  if (!camera_validation.ok()) {
    return PrintError(camera_validation.error());
  }

  auto secure_files = camera_firmware::rtsp::ValidateSecureRtspConfigFiles(
      cfg.value().secure_rtsp);
  if (!secure_files.ok()) {
    return PrintError(secure_files.error());
  }
  auto http_tls = camera_firmware::service::ValidateHttpTlsConfigFiles(
      cfg.value().http);
  if (!http_tls.ok()) {
    return PrintError(http_tls.error());
  }

  if (cfg.value().secure_rtsp.media_srtp) {
    auto secure_media = camera_firmware::rtsp::VerifySecureMediaPath();
    if (!secure_media.ok()) {
      return PrintError(secure_media.error());
    }
  }

  camera_firmware::ai::DetectionBus detection_bus;
  camera_firmware::ai::AiRuntime ai_runtime(&detection_bus);
  auto ai_started = ai_runtime.Start(cfg.value());
  if (!ai_started.ok()) {
    return PrintError(ai_started.error());
  }
  const auto ai_status = ai_runtime.Status();
  ai_runtime.Stop();

  Logger::instance().log(Logger::Level::kInfo,
                         "config loaded: " + config_path);
  Logger::instance().log(
      Logger::Level::kInfo,
      "RTSP ready: " +
          camera_firmware::rtsp::BuildRtspUrl(cfg.value().secure_rtsp));
  const std::string http_scheme =
      cfg.value().http.tls.enabled ? "https" : "http";
  Logger::instance().log(
      Logger::Level::kInfo,
      "Drogon service config ready on " + http_scheme + "://" +
          cfg.value().http.bind_ip + ":" +
          std::to_string(cfg.value().http.port));
  Logger::instance().log(
      Logger::Level::kInfo,
      ai_status.enabled ? "AI backend " + ai_status.backend +
                              " configured; runtime skeleton state=" +
                              ai_status.state
                        : "AI disabled by config");
  return EXIT_SUCCESS;
}

std::vector<camera_firmware::service::CameraStatus> ToServiceStatus(
    const std::vector<camera_firmware::media::CameraPipelineStatus>& statuses) {
  std::vector<camera_firmware::service::CameraStatus> result;
  result.reserve(statuses.size());
  for (const auto& status : statuses) {
    camera_firmware::service::CameraStatus service_status;
    service_status.id = status.id;
    service_status.state = status.state;
    service_status.snapshot_available = status.snapshot_available;
    service_status.width = status.width;
    service_status.height = status.height;
    service_status.configured_fps = status.configured_fps;
    service_status.capture_fps = status.capture_fps;
    service_status.encoded_fps = status.encoded_fps;
    service_status.captured_frames = status.captured_frames;
    service_status.encoded_frames = status.encoded_frames;
    service_status.capture_error_count = status.capture_error_count;
    service_status.encode_error_count = status.encode_error_count;
    result.push_back(std::move(service_status));
  }
  return result;
}

camera_firmware::service::AiServiceStatus ToServiceAiStatus(
    const camera_firmware::ai::AiRuntimeStatus& status,
    const std::vector<camera_firmware::config::AiModelConfig>& models,
    const std::vector<camera_firmware::ai::AiModelRunnerStatus>& runners) {
  camera_firmware::service::AiServiceStatus service_status;
  service_status.enabled = status.enabled;
  service_status.backend = status.backend;
  service_status.state = status.state;
  service_status.model_count = status.model_count;
  service_status.runner_count = status.runner_count;
  service_status.models.reserve(models.size());
  for (const auto& model : models) {
    camera_firmware::service::AiModelServiceStatus model_status;
    model_status.id = model.id;
    model_status.kind = model.kind;
    model_status.input_width = model.input.width;
    model_status.input_height = model.input.height;
    model_status.input_format = model.input.format;
    model_status.letterbox = model.input.letterbox;
    model_status.output_name = model.output_name;
    model_status.confidence_threshold = model.confidence_threshold;
    model_status.labels = model.labels;
    service_status.models.push_back(std::move(model_status));
  }
  service_status.runners.reserve(runners.size());
  for (const auto& runner : runners) {
    camera_firmware::service::AiRunnerServiceStatus runner_status;
    runner_status.camera_id = runner.camera_id;
    runner_status.model_id = runner.model_id;
    runner_status.model_kind = runner.model_kind;
    runner_status.submitted_frames = runner.submitted_frames;
    runner_status.processed_frames = runner.processed_frames;
    runner_status.dropped_frames = runner.dropped_frames;
    runner_status.last_preprocess_ms = runner.last_preprocess_ms;
    runner_status.last_inference_ms = runner.last_inference_ms;
    runner_status.last_processed_sequence = runner.last_processed_sequence;
    runner_status.last_error_code = runner.last_error_code;
    runner_status.last_error_message = runner.last_error_message;
    service_status.runners.push_back(std::move(runner_status));
  }
  if (!status.last_error_message.empty()) {
    service_status.reason = status.last_error_message;
  } else if (!status.enabled) {
    service_status.reason = "disabled by config";
  } else {
    service_status.reason = "AI runtime ready";
  }
  return service_status;
}

int RunFirmware(const std::string& config_path) {
  auto cfg = camera_firmware::config::LoadConfigFile(config_path);
  if (!cfg.ok()) {
    return PrintError(cfg.error());
  }

  auto plugin = camera_firmware::rtsp::RegisterBuildTreeSecureSrtpPluginPath(
      CF_SECURE_SRTP_PLUGIN_DIR);
  if (!plugin.ok()) {
    return PrintError(plugin.error());
  }

  camera_firmware::runtime::FirmwareRuntime runtime(cfg.value());
  camera_firmware::service::ServiceApp service;

  camera_firmware::service::ServiceInitArgs service_args;
  service_args.app_config = &cfg.value();
  service_args.bind_address = cfg.value().http.bind_ip;
  service_args.port = cfg.value().http.port;
  service_args.document_root = cfg.value().http.web_root;
  service_args.public_base_url = cfg.value().http.public_base_url;
  service_args.camera_status_provider = [&runtime] {
    return ToServiceStatus(runtime.CameraStatuses());
  };
  service_args.ai_enabled = cfg.value().ai.enabled;
  service_args.ai_status_provider = [&runtime, &cfg] {
    return ToServiceAiStatus(runtime.AiStatus(),
                             cfg.value().ai.models,
                             runtime.AiRunnerStatuses());
  };
  service_args.ai_restart_callback = [&runtime] {
    return runtime.RestartAi();
  };
  service_args.secure_stream_diagnostics_provider = [&runtime] {
    camera_firmware::service::SecureStreamDiagnostics diagnostics;
    diagnostics.per_media_key_zeroize_count =
        runtime.PerMediaKeyZeroizeCount();
    return diagnostics;
  };
  service_args.detection_snapshot_provider = [&runtime] {
    return runtime.DetectionSnapshot();
  };
  service_args.detection_event_subscriber =
      [&runtime](camera_firmware::ai::DetectionBus::Handler handler) {
        return runtime.SubscribeDetections(std::move(handler));
      };
  service_args.snapshot_callback =
      [&runtime](const std::string& camera_id) {
        return runtime.Snapshot(camera_id);
      };
  service_args.live_stream_callback =
      [&runtime, stale_timeout = std::chrono::milliseconds(
                     cfg.value().http.live.stale_timeout_ms)](
          const std::string& camera_id)
          -> camera_firmware::common::Result<
              camera_firmware::service::LiveMp4StreamCallback> {
        auto opened = runtime.OpenLiveStream(camera_id);
        if (!opened.ok()) {
          return camera_firmware::common::Result<
              camera_firmware::service::LiveMp4StreamCallback>::Err(
              opened.error());
        }
        auto state = std::make_shared<LiveMp4ByteStream>(
            std::move(opened).value(), stale_timeout);
        camera_firmware::service::LiveMp4StreamCallback stream =
            [state = std::move(state)](char* output, std::size_t capacity) {
              return state->Read(output, capacity);
            };
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamCallback>::Ok(
            std::move(stream));
      };

  std::shared_ptr<camera_firmware::security::SecurityStore> security_store;
  if (cfg.value().security.enabled) {
    auto opened = camera_firmware::security::SecurityStore::Open(
        {cfg.value().security.state_directory});
    if (!opened.ok()) {
      return PrintError(opened.error());
    }
    security_store =
        std::shared_ptr<camera_firmware::security::SecurityStore>(
            std::move(opened).value());
    service_args.security_store = security_store;
  }

  camera_firmware::boot::FirmwareBootDependencies boot_dependencies;
  if (security_store) {
    boot_dependencies.read_device_state = [security_store] {
      return security_store->State();
    };
  }
  boot_dependencies.start_runtime = [&runtime] { return runtime.Start(); };
  boot_dependencies.stop_runtime = [&runtime] { runtime.Stop(); };
  boot_dependencies.start_service =
      [&service, &service_args](
          camera_firmware::boot::RuntimeStartCallback start_runtime) {
        service_args.runtime_start_callback = std::move(start_runtime);
        return service.Init(service_args);
      };
  boot_dependencies.quiesce_service = [&service] {
    service.BeginShutdown();
  };
  boot_dependencies.stop_service = [&service] { service.Stop(); };

  camera_firmware::boot::FirmwareBootCoordinator boot_coordinator(
      {cfg.value().security.enabled, cfg.value().http.enabled},
      std::move(boot_dependencies));
  auto boot_started = boot_coordinator.Start();
  if (!boot_started.ok()) {
    return PrintError(boot_started.error());
  }

  Logger::instance().log(Logger::Level::kInfo, "camera firmware running");
  WaitForShutdown();

  boot_coordinator.Stop();
  return EXIT_SUCCESS;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 3 && std::string(argv[1]) == "--validate-config") {
    return ValidateConfig(argv[2]);
  }
  if (argc == 2) {
    InstallSignalHandlers();
    return RunFirmware(argv[1]);
  }

  std::cerr << "usage: camera-firmware [--validate-config] <config.yaml>\n";
  return EXIT_FAILURE;
}
