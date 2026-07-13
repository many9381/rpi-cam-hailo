#include "camera_firmware/runtime/FirmwareRuntime.hpp"

#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <utility>

#include "camera_firmware/ai/AiFramePump.hpp"
#include "camera_firmware/ai/AiFrameTap.hpp"
#include "camera_firmware/ai/AiRuntimeController.hpp"
#include "camera_firmware/ai/DetectionEventStore.hpp"
#include "camera_firmware/media/EncodedRing.hpp"
#include "camera_firmware/media/MjpegFrameHub.hpp"
#include "camera_firmware/media/SnapshotTap.hpp"
#include "camera_firmware/rtsp/SecureRtspServer.hpp"

namespace camera_firmware::runtime {
namespace {

common::Result<void> MissingDependency(std::string_view name) {
  return common::Result<void>::Err(
      {"E_RUNTIME_DEPENDENCY", "missing runtime dependency: " + std::string(name)});
}

common::Result<void> RuntimeException() {
  return common::Result<void>::Err(
      {"E_RUNTIME_START", "firmware runtime component failed"});
}

common::Error PreviewUnavailable() {
  return {"E_PREVIEW_UNAVAILABLE", "MJPEG preview is unavailable"};
}

std::string CameraStateForRuntime(FirmwareRuntimeState state) {
  switch (state) {
    case FirmwareRuntimeState::kStopped:
      return "stopped";
    case FirmwareRuntimeState::kStarting:
      return "starting";
    case FirmwareRuntimeState::kRunning:
      return "running";
    case FirmwareRuntimeState::kFailed:
      return "error";
    case FirmwareRuntimeState::kStopping:
      return "stopping";
  }
  return "error";
}

struct ProductionRuntimeGraph {
  explicit ProductionRuntimeGraph(const config::AppConfig& configured)
      : config(configured),
        detection_event_store(detection_bus),
        ai_runtime(&detection_bus),
        ai_frame_pump(ai_frame_tap, ai_runtime),
        camera_pipeline(snapshot_tap, ai_frame_tap, encoded_ring),
        mjpeg_frame_hub(snapshot_tap, config.http.preview),
        ai_controller(config, ai_runtime, ai_frame_pump) {}

  config::AppConfig config;
  media::SnapshotTap snapshot_tap;
  ai::AiFrameTap ai_frame_tap;
  ai::DetectionBus detection_bus;
  ai::DetectionEventStore detection_event_store;
  ai::AiRuntime ai_runtime;
  ai::AiFramePump ai_frame_pump;
  media::EncodedRing encoded_ring{128U};
  media::CameraPipeline camera_pipeline;
  media::MjpegFrameHub mjpeg_frame_hub;
  ai::AiRuntimeController ai_controller;
  rtsp::SecureRtspServer rtsp_server;
};

}  // namespace

FirmwareRuntime::FirmwareRuntime(const config::AppConfig& config)
    : config_(config), dependencies_(BuildProductionDependencies(config_)) {}

FirmwareRuntime::FirmwareRuntime(const config::AppConfig& config,
                                 FirmwareRuntimeDependencies dependencies)
    : config_(config), dependencies_(std::move(dependencies)) {}

FirmwareRuntime::~FirmwareRuntime() {
  Stop();
}

common::Result<void> FirmwareRuntime::Start() {
  std::lock_guard lock(mutex_);
  if (state_ == FirmwareRuntimeState::kRunning) {
    return common::Result<void>::Ok();
  }
  state_ = FirmwareRuntimeState::kStarting;
  if (!LifecycleDependenciesComplete()) {
    state_ = FirmwareRuntimeState::kFailed;
    return MissingDependency("lifecycle callbacks");
  }

  try {
    auto rtsp = dependencies_.start_rtsp();
    if (!rtsp.ok()) {
      state_ = FirmwareRuntimeState::kFailed;
      return rtsp;
    }
    rtsp_started_ = true;

    auto ai = dependencies_.start_ai();
    if (!ai.ok()) {
      UnwindStartedComponents();
      state_ = FirmwareRuntimeState::kFailed;
      return ai;
    }
    ai_started_ = true;

    auto camera = dependencies_.start_camera();
    if (!camera.ok()) {
      UnwindStartedComponents();
      state_ = FirmwareRuntimeState::kFailed;
      return camera;
    }
    camera_started_ = true;

    auto preview = dependencies_.start_preview();
    if (!preview.ok()) {
      UnwindStartedComponents();
      state_ = FirmwareRuntimeState::kFailed;
      return preview;
    }
    preview_started_ = true;
    state_ = FirmwareRuntimeState::kRunning;
    return common::Result<void>::Ok();
  } catch (...) {
    UnwindStartedComponents();
    state_ = FirmwareRuntimeState::kFailed;
    return RuntimeException();
  }
}

void FirmwareRuntime::Stop() noexcept {
  std::lock_guard lock(mutex_);
  if (state_ == FirmwareRuntimeState::kStopped) {
    return;
  }
  state_ = FirmwareRuntimeState::kStopping;
  UnwindStartedComponents();
  state_ = FirmwareRuntimeState::kStopped;
}

FirmwareRuntimeState FirmwareRuntime::State() const noexcept {
  std::lock_guard lock(mutex_);
  return state_;
}

std::vector<media::CameraPipelineStatus> FirmwareRuntime::CameraStatuses() const {
  std::lock_guard lock(mutex_);
  const auto fallback_status = [this](std::string state) {
    media::CameraPipelineStatus status;
    status.id = config_.camera.id;
    status.state = std::move(state);
    status.width = config_.camera.video.width;
    status.height = config_.camera.video.height;
    status.configured_fps = config_.camera.video.fps;
    return std::vector<media::CameraPipelineStatus>{std::move(status)};
  };
  if (!RunningLocked()) {
    return fallback_status(CameraStateForRuntime(state_));
  }
  if (!dependencies_.camera_statuses) {
    return fallback_status("error");
  }
  try {
    return dependencies_.camera_statuses();
  } catch (...) {
    return fallback_status("error");
  }
}

ai::AiRuntimeStatus FirmwareRuntime::AiStatus() const {
  std::lock_guard lock(mutex_);
  if (!RunningLocked() || !dependencies_.ai_status) {
    ai::AiRuntimeStatus status;
    status.enabled = config_.ai.enabled;
    status.state = "stopped";
    return status;
  }
  try {
    return dependencies_.ai_status();
  } catch (...) {
    ai::AiRuntimeStatus status;
    status.enabled = config_.ai.enabled;
    status.state = "failed";
    return status;
  }
}

std::vector<ai::AiModelRunnerStatus> FirmwareRuntime::AiRunnerStatuses() const {
  std::lock_guard lock(mutex_);
  if (!RunningLocked() || !dependencies_.ai_runner_statuses) {
    return {};
  }
  try {
    return dependencies_.ai_runner_statuses();
  } catch (...) {
    return {};
  }
}

common::Result<void> FirmwareRuntime::RestartAi() {
  std::lock_guard lock(mutex_);
  if (!RunningLocked()) {
    return common::Result<void>::Err(
        {"E_RUNTIME_NOT_RUNNING", "firmware runtime is not running"});
  }
  if (!dependencies_.restart_ai) {
    return MissingDependency("restart_ai");
  }
  try {
    return dependencies_.restart_ai();
  } catch (...) {
    return common::Result<void>::Err(
        {"E_AI_RESTART", "AI runtime restart failed"});
  }
}

std::optional<std::vector<std::uint8_t>> FirmwareRuntime::Snapshot(
    std::string_view camera_id) const {
  std::lock_guard lock(mutex_);
  if (!RunningLocked() || !dependencies_.snapshot) {
    return std::nullopt;
  }
  try {
    return dependencies_.snapshot(camera_id);
  } catch (...) {
    return std::nullopt;
  }
}

common::Result<std::shared_ptr<media::MjpegStreamReader>>
FirmwareRuntime::OpenMjpegPreview(std::string_view camera_id) {
  std::lock_guard lock(mutex_);
  if (!RunningLocked() || !dependencies_.open_mjpeg_preview) {
    return common::Result<std::shared_ptr<media::MjpegStreamReader>>::Err(
        PreviewUnavailable());
  }
  try {
    return dependencies_.open_mjpeg_preview(camera_id);
  } catch (...) {
    return common::Result<std::shared_ptr<media::MjpegStreamReader>>::Err(
        PreviewUnavailable());
  }
}

std::vector<ai::DetectionEvent> FirmwareRuntime::DetectionSnapshot() const {
  std::lock_guard lock(mutex_);
  if (!RunningLocked() || !dependencies_.detection_snapshot) {
    return {};
  }
  try {
    return dependencies_.detection_snapshot();
  } catch (...) {
    return {};
  }
}

ai::DetectionBus::Subscription FirmwareRuntime::SubscribeDetections(
    ai::DetectionBus::Handler handler) {
  std::lock_guard lock(mutex_);
  if (!RunningLocked() || !dependencies_.subscribe_detections || !handler) {
    return {};
  }
  try {
    return dependencies_.subscribe_detections(std::move(handler));
  } catch (...) {
    return {};
  }
}

std::uint64_t FirmwareRuntime::PerMediaKeyZeroizeCount() const noexcept {
  std::lock_guard lock(mutex_);
  if (!RunningLocked() || !dependencies_.per_media_key_zeroize_count) {
    return 0U;
  }
  try {
    return dependencies_.per_media_key_zeroize_count();
  } catch (...) {
    return 0U;
  }
}

void FirmwareRuntime::UnwindStartedComponents() noexcept {
  if (preview_started_) {
    try {
      if (dependencies_.stop_preview) {
        dependencies_.stop_preview();
      }
    } catch (...) {
    }
    preview_started_ = false;
  }
  if (camera_started_) {
    try {
      if (dependencies_.stop_camera) {
        dependencies_.stop_camera();
      }
    } catch (...) {
    }
    camera_started_ = false;
  }
  if (ai_started_) {
    try {
      if (dependencies_.stop_ai) {
        dependencies_.stop_ai();
      }
    } catch (...) {
    }
    ai_started_ = false;
  }
  if (rtsp_started_) {
    try {
      if (dependencies_.stop_rtsp) {
        dependencies_.stop_rtsp();
      }
    } catch (...) {
    }
    rtsp_started_ = false;
  }
}

bool FirmwareRuntime::RunningLocked() const noexcept {
  return state_ == FirmwareRuntimeState::kRunning;
}

FirmwareRuntimeDependencies FirmwareRuntime::BuildProductionDependencies(
    const config::AppConfig& config) {
  auto graph = std::make_shared<ProductionRuntimeGraph>(config);
  FirmwareRuntimeDependencies dependencies;
  dependencies.start_rtsp = [graph] {
    return graph->rtsp_server.Start(graph->config.secure_rtsp,
                                    graph->encoded_ring);
  };
  dependencies.start_ai = [graph] { return graph->ai_controller.Restart(); };
  dependencies.start_camera = [graph] {
    return graph->camera_pipeline.Start(graph->config);
  };
  dependencies.start_preview = [graph] {
    return graph->mjpeg_frame_hub.Start();
  };
  dependencies.stop_preview = [graph] { graph->mjpeg_frame_hub.Stop(); };
  dependencies.stop_camera = [graph] { graph->camera_pipeline.Stop(); };
  dependencies.stop_ai = [graph] { graph->ai_controller.Stop(); };
  dependencies.stop_rtsp = [graph] { graph->rtsp_server.Stop(); };
  dependencies.camera_statuses = [graph] {
    return graph->camera_pipeline.Status(std::chrono::milliseconds(
        graph->config.http.preview.stale_timeout_ms));
  };
  dependencies.ai_status = [graph] { return graph->ai_runtime.Status(); };
  dependencies.ai_runner_statuses = [graph] {
    return graph->ai_runtime.RunnerStatuses();
  };
  dependencies.restart_ai = [graph] {
    return graph->ai_controller.Restart();
  };
  dependencies.snapshot = [graph](std::string_view camera_id) {
    if (camera_id != graph->config.camera.id) {
      return std::optional<std::vector<std::uint8_t>>{};
    }
    return media::BuildLatestSnapshotJpeg(
        graph->snapshot_tap, camera_id,
        std::chrono::milliseconds(
            graph->config.http.preview.stale_timeout_ms));
  };
  dependencies.open_mjpeg_preview = [graph](std::string_view camera_id) {
    return graph->mjpeg_frame_hub.Open(camera_id);
  };
  dependencies.detection_snapshot = [graph] {
    return graph->detection_event_store.Snapshot();
  };
  dependencies.subscribe_detections =
      [graph](ai::DetectionBus::Handler handler) {
        return graph->detection_bus.Subscribe(std::move(handler));
      };
  dependencies.per_media_key_zeroize_count = [graph] {
    return static_cast<std::uint64_t>(
        graph->rtsp_server.PerMediaKeyZeroizeCount());
  };
  return dependencies;
}

bool FirmwareRuntime::DependenciesComplete() const noexcept {
  return dependencies_.start_rtsp && dependencies_.start_ai &&
         dependencies_.start_camera && dependencies_.start_preview &&
         dependencies_.stop_preview && dependencies_.stop_camera &&
         dependencies_.stop_ai && dependencies_.stop_rtsp &&
         dependencies_.camera_statuses && dependencies_.ai_status &&
         dependencies_.ai_runner_statuses && dependencies_.restart_ai &&
         dependencies_.snapshot && dependencies_.open_mjpeg_preview &&
         dependencies_.detection_snapshot &&
         dependencies_.subscribe_detections &&
         dependencies_.per_media_key_zeroize_count;
}

bool FirmwareRuntime::LifecycleDependenciesComplete() const noexcept {
  return dependencies_.start_rtsp && dependencies_.start_ai &&
         dependencies_.start_camera && dependencies_.start_preview &&
         dependencies_.stop_preview && dependencies_.stop_camera &&
         dependencies_.stop_ai && dependencies_.stop_rtsp;
}

}  // namespace camera_firmware::runtime
