#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "camera_firmware/ai/AiFrameTap.hpp"
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
      cfg.value().ai.enabled
          ? "AI disabled: Hailo runtime not implemented"
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
  camera_firmware::media::EncodedRing encoded_ring(128);
  camera_firmware::media::CameraPipeline camera_pipeline(
      snapshot_tap, ai_frame_tap, encoded_ring);
  camera_firmware::rtsp::SecureRtspServer rtsp_server;
  camera_firmware::service::ServiceApp service;

  auto rtsp = rtsp_server.Start(cfg.value().secure_rtsp, encoded_ring);
  if (!rtsp.ok()) {
    return PrintError(rtsp.error());
  }

  auto camera = camera_pipeline.Start(cfg.value());
  if (!camera.ok()) {
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
