#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <vector>

#include "camera_firmware/ai/AiRuntime.hpp"
#include "camera_firmware/ai/DetectionBus.hpp"
#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/CameraPipeline.hpp"
#include "camera_firmware/media/FragmentedMp4Hub.hpp"
#include "camera_firmware/media/JpegEncoder.hpp"
#include "camera_firmware/media/SubStreamTap.hpp"

namespace camera_firmware::runtime {

class FirmwareRuntimeTestAccess;

enum class FirmwareRuntimeState {
  kStopped,
  kStarting,
  kRunning,
  kFailed,
  kStopping,
};

struct FirmwareRuntimeDependencies {
  std::function<common::Result<void>()> start_rtsp;
  std::function<common::Result<void>()> start_ai;
  std::function<common::Result<void>()> start_camera;
  std::function<common::Result<void>()> start_live;
  std::function<void()> stop_live;
  std::function<void()> stop_camera;
  std::function<void()> stop_ai;
  std::function<void()> stop_rtsp;

  std::function<std::vector<media::CameraPipelineStatus>()> camera_statuses;
  std::function<media::FragmentedMp4HubStatus()> live_status;
  std::function<ai::AiRuntimeStatus()> ai_status;
  std::function<std::vector<ai::AiModelRunnerStatus>()> ai_runner_statuses;
  std::function<common::Result<void>()> restart_ai;
  std::function<std::optional<media::JpegBytes>(std::string_view)> snapshot;
  std::function<common::Result<media::FragmentRing::Reader>(std::string_view)>
      open_live_stream;
  std::function<std::vector<ai::DetectionEvent>()> detection_snapshot;
  std::function<ai::DetectionBus::Subscription(ai::DetectionBus::Handler)>
      subscribe_detections;
  std::function<std::uint64_t()> per_media_key_zeroize_count;
};

class FirmwareRuntime {
 public:
  explicit FirmwareRuntime(const config::AppConfig& config);
  FirmwareRuntime(const config::AppConfig& config,
                  FirmwareRuntimeDependencies dependencies);
  ~FirmwareRuntime();

  FirmwareRuntime(const FirmwareRuntime&) = delete;
  FirmwareRuntime& operator=(const FirmwareRuntime&) = delete;
  FirmwareRuntime(FirmwareRuntime&&) = delete;
  FirmwareRuntime& operator=(FirmwareRuntime&&) = delete;

  [[nodiscard]] static common::Result<void> ValidateCandidateConfig(
      const config::AppConfig& config);
  [[nodiscard]] common::Result<void> Start();
  void Stop() noexcept;
  [[nodiscard]] FirmwareRuntimeState State() const noexcept;

  [[nodiscard]] std::vector<media::CameraPipelineStatus> CameraStatuses() const;
  [[nodiscard]] ai::AiRuntimeStatus AiStatus() const;
  [[nodiscard]] std::vector<ai::AiModelRunnerStatus> AiRunnerStatuses() const;
  [[nodiscard]] common::Result<void> RestartAi();
  [[nodiscard]] std::optional<media::JpegBytes> Snapshot(
      std::string_view camera_id) const;
  [[nodiscard]] media::FragmentedMp4HubStatus LiveStatus() const;
  [[nodiscard]] common::Result<media::FragmentRing::Reader> OpenLiveStream(
      std::string_view camera_id);
  [[nodiscard]] std::vector<ai::DetectionEvent> DetectionSnapshot() const;
  [[nodiscard]] ai::DetectionBus::Subscription SubscribeDetections(
      ai::DetectionBus::Handler handler);
  [[nodiscard]] std::uint64_t PerMediaKeyZeroizeCount() const noexcept;

 private:
  friend class FirmwareRuntimeTestAccess;

  [[nodiscard]] static FirmwareRuntimeDependencies BuildProductionDependencies(
      const config::AppConfig& config);

  // Test-only: exposes the persistent sub-stream tap and a live
  // encoded-frame counter alongside the normal production dependency
  // lambdas, so a test can drive a real frame through the sub-stream path
  // across a start_rtsp/stop_rtsp restart and confirm the SAME tap instance
  // -- which start_rtsp/stop_rtsp reuse across calls, see
  // ProductionRuntimeGraph in FirmwareRuntime.cpp -- still delivers frames
  // after being reopened. sub_stream_tap is a non-owning pointer kept alive
  // by dependencies' captured graph.
  struct ProductionSubStreamHandles {
    FirmwareRuntimeDependencies dependencies;
    media::SubStreamTap* sub_stream_tap{nullptr};
    std::function<std::uint64_t()> sub_encoded_frames;
  };
  [[nodiscard]] static ProductionSubStreamHandles
  BuildProductionDependenciesWithSubStreamHandles(
      const config::AppConfig& config);

  [[nodiscard]] static std::chrono::milliseconds SnapshotMaximumAge(
      const config::AppConfig& config) noexcept;
  [[nodiscard]] bool DependenciesComplete() const noexcept;
  [[nodiscard]] bool LifecycleDependenciesComplete() const noexcept;
  void UnwindStartedComponents() noexcept;
  [[nodiscard]] bool RunningLocked() const noexcept;

  config::AppConfig config_;
  FirmwareRuntimeDependencies dependencies_;
  mutable std::mutex mutex_;
  FirmwareRuntimeState state_{FirmwareRuntimeState::kStopped};
  bool rtsp_started_{false};
  bool ai_started_{false};
  bool camera_started_{false};
  bool live_started_{false};
};

}  // namespace camera_firmware::runtime
