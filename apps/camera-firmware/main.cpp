#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "camera_firmware/ai/AiFramePump.hpp"
#include "camera_firmware/ai/AiFrameTap.hpp"
#include "camera_firmware/ai/AiRuntime.hpp"
#include "camera_firmware/ai/DetectionBus.hpp"
#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/CameraPipeline.hpp"
#include "camera_firmware/media/EncodedRing.hpp"
#include "camera_firmware/media/SnapshotTap.hpp"
#include "camera_firmware/rtsp/SecureRtspServer.hpp"
#include "camera_firmware/service/ServiceApp.hpp"

namespace {

using camera_firmware::common::Error;
using camera_firmware::common::Logger;

std::atomic_bool g_stop_requested{false};

void HandleSignal(int) {
  g_stop_requested.store(true);
}

int PrintError(const Error& error) {
  std::cerr << error.code << ": " << error.message << '\n';
  return EXIT_FAILURE;
}

void InstallSignalHandlers() {
  std::signal(SIGINT, HandleSignal);
  std::signal(SIGTERM, HandleSignal);
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
    result.push_back({status.id, status.state, status.snapshot_available});
  }
  return result;
}

camera_firmware::service::AiServiceStatus ToServiceAiStatus(
    const camera_firmware::ai::AiRuntimeStatus& status) {
  camera_firmware::service::AiServiceStatus service_status;
  service_status.enabled = status.enabled;
  service_status.backend = status.backend;
  service_status.state = status.state;
  service_status.model_count = status.model_count;
  service_status.runner_count = status.runner_count;
  if (!status.last_error_message.empty()) {
    service_status.reason = status.last_error_message;
  } else if (!status.enabled) {
    service_status.reason = "disabled by config";
  } else {
    service_status.reason = "AI runtime skeleton ready";
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

  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::ai::DetectionBus detection_bus;
  camera_firmware::ai::AiRuntime ai_runtime(&detection_bus);
  camera_firmware::ai::AiFramePump ai_frame_pump(ai_frame_tap, ai_runtime);
  camera_firmware::media::EncodedRing encoded_ring(128);
  camera_firmware::media::CameraPipeline camera_pipeline(
      snapshot_tap, ai_frame_tap, encoded_ring);
  camera_firmware::rtsp::SecureRtspServer rtsp_server;
  camera_firmware::service::ServiceApp service;

  auto rtsp = rtsp_server.Start(cfg.value().secure_rtsp, encoded_ring);
  if (!rtsp.ok()) {
    return PrintError(rtsp.error());
  }

  auto ai_started = ai_runtime.Start(cfg.value());
  if (!ai_started.ok()) {
    rtsp_server.Stop();
    return PrintError(ai_started.error());
  }

  const bool should_pump_ai_frames =
      cfg.value().ai.enabled && cfg.value().camera.ai.enabled;
  if (should_pump_ai_frames) {
    auto pump_started = ai_frame_pump.Start();
    if (!pump_started.ok()) {
      ai_runtime.Stop();
      rtsp_server.Stop();
      return PrintError(pump_started.error());
    }
  }

  auto camera = camera_pipeline.Start(cfg.value());
  if (!camera.ok()) {
    ai_frame_pump.Stop();
    ai_runtime.Stop();
    rtsp_server.Stop();
    return PrintError(camera.error());
  }

  camera_firmware::service::ServiceInitArgs service_args;
  service_args.app_config = &cfg.value();
  service_args.bind_address = cfg.value().http.bind_ip;
  service_args.port = cfg.value().http.port;
  service_args.document_root = cfg.value().http.web_root;
  service_args.public_base_url = cfg.value().http.public_base_url;
  service_args.camera_status_provider = [&camera_pipeline] {
    return ToServiceStatus(camera_pipeline.Status());
  };
  service_args.ai_enabled = cfg.value().ai.enabled;
  service_args.ai_status_provider = [&ai_runtime] {
    return ToServiceAiStatus(ai_runtime.Status());
  };
  service_args.snapshot_callback =
      [&snapshot_tap,
       configured_camera_id = cfg.value().camera.id](const std::string& camera_id) {
        if (camera_id != configured_camera_id) {
          return std::optional<std::vector<std::uint8_t>>{};
        }
        return camera_firmware::media::BuildLatestSnapshotJpeg(snapshot_tap,
                                                              camera_id);
      };
  if (cfg.value().http.enabled) {
    auto service_started = service.Init(service_args);
    if (!service_started.ok()) {
      ai_frame_pump.Stop();
      ai_runtime.Stop();
      camera_pipeline.Stop();
      rtsp_server.Stop();
      return PrintError(service_started.error());
    }
  }

  Logger::instance().log(Logger::Level::kInfo, "camera firmware running");
  WaitForShutdown();

  if (cfg.value().http.enabled) {
    service.Stop();
  }
  ai_frame_pump.Stop();
  ai_runtime.Stop();
  camera_pipeline.Stop();
  rtsp_server.Stop();
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
