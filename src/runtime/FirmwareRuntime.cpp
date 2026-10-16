#include "camera_firmware/runtime/FirmwareRuntime.hpp"

#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "camera_firmware/ai/AiFramePump.hpp"
#include "camera_firmware/ai/AiFrameTap.hpp"
#include "camera_firmware/ai/AiRuntimeController.hpp"
#include "camera_firmware/ai/DetectionEventStore.hpp"
#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/media/EncodedRing.hpp"
#include "camera_firmware/media/FragmentedMp4Hub.hpp"
#include "camera_firmware/media/SnapshotTap.hpp"
#include "camera_firmware/media/SubStreamEncoder.hpp"
#include "camera_firmware/media/SubStreamTap.hpp"
#include "camera_firmware/rtsp/SecureRtspServer.hpp"

namespace camera_firmware::runtime {
namespace {

common::Result<void> MissingDependency(std::string_view name) {
  return common::Result<void>::Err(
      {"E_RUNTIME_DEPENDENCY",
       "missing runtime dependency: " + std::string(name)});
}

common::Result<void> RuntimeException() {
  return common::Result<void>::Err(
      {"E_RUNTIME_START", "firmware runtime component failed"});
}

// Shared with FirmwareRuntime::SnapshotMaximumAge (a private static member,
// unreachable from the free BuildDependenciesForGraph below) so both have a
// single source of truth for the freshness window.
std::chrono::milliseconds SnapshotMaximumAgeFor(
    const config::AppConfig& config) noexcept {
  return std::chrono::milliseconds(config.http.snapshot.stale_timeout_ms);
}

common::Error LiveUnavailable() {
  return {"E_LIVE_UNAVAILABLE", "live stream is unavailable"};
}

media::FragmentedMp4HubConfig BuildLiveHubConfig(
    const config::AppConfig& config) {
  media::FragmentedMp4HubConfig live;
  live.width = config.camera.video.width;
  live.height = config.camera.video.height;
  live.fps = config.camera.video.fps;
  live.fragment_duration_ms = config.http.live.fragment_duration_ms;
  live.stale_timeout_ms = config.http.live.stale_timeout_ms;
  live.ring_limits.max_fragments = config.http.live.ring_fragments;
  live.ring_limits.max_readers = config.http.live.max_clients;
  return live;
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
        ai_frame_pump(
            ai_frame_tap, ai_runtime,
            config.camera.ai.max_fps == 0U
                ? std::chrono::milliseconds{0}
                : std::chrono::milliseconds{1000U / config.camera.ai.max_fps}),
        camera_pipeline(
            snapshot_tap, ai_frame_tap, encoded_ring,
            configured.camera.sub_stream.enabled ? &sub_stream_tap : nullptr),
        fragmented_mp4_hub(encoded_ring),
        ai_controller(config, ai_runtime, ai_frame_pump) {}

  config::AppConfig config;
  media::SnapshotTap snapshot_tap;
  ai::AiFrameTap ai_frame_tap;
  ai::DetectionBus detection_bus;
  ai::DetectionEventStore detection_event_store;
  ai::AiRuntime ai_runtime;
  ai::AiFramePump ai_frame_pump;
  media::EncodedRing encoded_ring{128U};
  // Sub-stream members are declared (and thus constructed/destroyed) before
  // camera_pipeline and rtsp_server: camera_pipeline takes &sub_stream_tap at
  // construction, and rtsp_server's Stop() can synchronously invoke the sub
  // mount's on_deactivate callback (captures &sub_stream_tap) via its
  // post-join client teardown -- so the tap must still be alive whenever
  // rtsp_server is stopped or destroyed. Declaring these members earlier
  // means they are destroyed later (member destruction order is the reverse
  // of declaration order), i.e. strictly after rtsp_server.
  media::EncodedRing sub_encoded_ring{128U};
  media::SubStreamTap sub_stream_tap;
  media::SubMountDescriptor sub_mount_descriptor{};
  std::optional<media::SubStreamEncoder> sub_stream_encoder;
  media::CameraPipeline camera_pipeline;
  media::FragmentedMp4Hub fragmented_mp4_hub;
  ai::AiRuntimeController ai_controller;
  rtsp::SecureRtspServer rtsp_server;
};

// Shared by BuildProductionDependencies and the test-only
// BuildProductionDependenciesWithSubStreamHandles: both wire an identical set
// of dependency lambdas around one ProductionRuntimeGraph, so the wiring
// lives here once instead of being duplicated.
FirmwareRuntimeDependencies BuildDependenciesForGraph(
    std::shared_ptr<ProductionRuntimeGraph> graph) {
  using common::Logger;

  FirmwareRuntimeDependencies dependencies;
  // start_rtsp/stop_rtsp own the whole sub-stream lifecycle (encoder +
  // mount descriptor), not just the main mount. This file's overall
  // Start()/Stop() call sequence is fixed elsewhere (rtsp is the first
  // component started and the last one stopped) and several existing tests
  // pin that exact ordering, so it is not changed here. Folding the
  // sub-stream encoder into these two lambdas instead gets the two
  // properties that matter without touching that sequence:
  //   - start: the sub encoder is constructed and Start()ed, and the
  //     collision/format of sub.mount is validated, strictly before
  //     rtsp_server.Start() ever registers the sub mount -- so a client can
  //     never activate a mount with nothing consuming its tap.
  //   - stop: rtsp_server.Stop() runs first (so no new client can activate
  //     the sub mount, and any in-flight on_deactivate fires while the tap
  //     is still alive and the encoder is still around to be told), and
  //     only then is the sub encoder stopped.
  //
  // The sub stream is best-effort (see the design doc's error-handling
  // section): an invalid/colliding mount or a failed encoder Start() is
  // logged and disables the sub stream for this run, but must never fail
  // the main RTSP mount -- so both failure branches below fall through to
  // starting rtsp_server with no sub descriptor instead of returning early.
  dependencies.start_rtsp = [graph] {
    const auto& sub = graph->config.camera.sub_stream;
    if (!sub.enabled) {
      return graph->rtsp_server.Start(graph->config.secure_rtsp,
                                      graph->encoded_ring);
    }

    if (sub.mount.empty() || sub.mount.front() != '/' ||
        sub.mount == graph->config.secure_rtsp.mount) {
      Logger::instance().log(
          Logger::Level::kError,
          "sub_stream mount invalid or collides with main mount; disabling "
          "sub stream");
      return graph->rtsp_server.Start(graph->config.secure_rtsp,
                                      graph->encoded_ring);
    }

    media::SubStreamEncoderParams params;
    params.src_width = static_cast<int>(graph->config.camera.video.width);
    params.src_height = static_cast<int>(graph->config.camera.video.height);
    params.dst_width = static_cast<int>(sub.width);
    params.dst_height = static_cast<int>(sub.height);
    params.fps = sub.fps;
    params.bitrate_kbps = sub.bitrate_kbps;
    params.gop = sub.gop;
    params.preset = graph->config.camera.encoder.preset;

    graph->sub_stream_encoder.emplace(graph->sub_stream_tap,
                                      graph->sub_encoded_ring, params);
    auto encoder_started = graph->sub_stream_encoder->Start();
    if (!encoder_started.ok()) {
      Logger::instance().log(Logger::Level::kError,
                             "sub_stream encoder failed to start: " +
                                 encoder_started.error().message +
                                 "; disabling sub stream");
      graph->sub_stream_encoder.reset();
      return graph->rtsp_server.Start(graph->config.secure_rtsp,
                                      graph->encoded_ring);
    }

    graph->sub_mount_descriptor = media::SubMountDescriptor{
        sub.mount,
        &graph->sub_encoded_ring,
        [tap = &graph->sub_stream_tap] {
          tap->SetActive(true);
          tap->RequestNext();
        },
        [tap = &graph->sub_stream_tap] { tap->SetActive(false); },
    };

    auto rtsp_started =
        graph->rtsp_server.Start(graph->config.secure_rtsp, graph->encoded_ring,
                                 &graph->sub_mount_descriptor);
    if (!rtsp_started.ok()) {
      graph->sub_stream_encoder.reset();
      return rtsp_started;
    }
    return rtsp_started;
  };
  dependencies.start_ai = [graph] { return graph->ai_controller.Restart(); };
  dependencies.start_camera = [graph] {
    return graph->camera_pipeline.Start(graph->config);
  };
  dependencies.start_live = [graph] {
    if (!graph->config.http.live.enabled) {
      return common::Result<void>::Ok();
    }
    return graph->fragmented_mp4_hub.Start(BuildLiveHubConfig(graph->config));
  };
  dependencies.stop_live = [graph] { graph->fragmented_mp4_hub.Stop(); };
  dependencies.stop_camera = [graph] { graph->camera_pipeline.Stop(); };
  dependencies.stop_ai = [graph] { graph->ai_controller.Stop(); };
  dependencies.stop_rtsp = [graph] {
    graph->rtsp_server.Stop();
    if (graph->sub_stream_encoder) {
      graph->sub_stream_encoder->Stop();
      graph->sub_stream_encoder.reset();
    }
  };
  dependencies.camera_statuses = [graph] {
    return graph->camera_pipeline.Status(SnapshotMaximumAgeFor(graph->config));
  };
  dependencies.live_status = [graph] {
    return graph->fragmented_mp4_hub.Status();
  };
  dependencies.ai_status = [graph] { return graph->ai_runtime.Status(); };
  dependencies.ai_runner_statuses = [graph] {
    return graph->ai_runtime.RunnerStatuses();
  };
  dependencies.restart_ai = [graph] { return graph->ai_controller.Restart(); };
  dependencies.snapshot = [graph](std::string_view camera_id) {
    if (camera_id != graph->config.camera.id) {
      return std::optional<media::JpegBytes>{};
    }
    return media::BuildLatestSnapshotJpeg(graph->snapshot_tap, camera_id,
                                          SnapshotMaximumAgeFor(graph->config));
  };
  dependencies.open_live_stream = [graph](std::string_view camera_id) {
    if (camera_id != graph->config.camera.id) {
      return common::Result<media::FragmentRing::Reader>::Err(
          {"E_LIVE_NOT_FOUND", "camera not found"});
    }
    return graph->fragmented_mp4_hub.OpenReader();
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

}  // namespace

FirmwareRuntime::FirmwareRuntime(const config::AppConfig& config)
    : config_(config), dependencies_(BuildProductionDependencies(config_)) {}

FirmwareRuntime::FirmwareRuntime(const config::AppConfig& config,
                                 FirmwareRuntimeDependencies dependencies)
    : config_(config), dependencies_(std::move(dependencies)) {}

FirmwareRuntime::~FirmwareRuntime() {
  Stop();
}

common::Result<void> FirmwareRuntime::ValidateCandidateConfig(
    const config::AppConfig& config) {
  auto semantics = config::ValidateAppConfigSemantics(config);
  if (!semantics.ok()) {
    return semantics;
  }

  try {
    media::SnapshotTap snapshot_tap;
    ai::AiFrameTap ai_frame_tap;
    media::EncodedRing encoded_ring(64U);
    media::CameraPipeline camera_pipeline(snapshot_tap, ai_frame_tap,
                                          encoded_ring);
    auto camera_validation = camera_pipeline.ValidateConfigOnly(config);
    if (!camera_validation.ok()) {
      return camera_validation;
    }

    FirmwareRuntime candidate(config);
    return common::Result<void>::Ok();
  } catch (...) {
    return common::Result<void>::Err(
        {"E_PIPELINE_CANDIDATE", "runtime candidate validation failed"});
  }
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

    auto live = dependencies_.start_live();
    if (!live.ok()) {
      UnwindStartedComponents();
      state_ = FirmwareRuntimeState::kFailed;
      return live;
    }
    live_started_ = true;
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

std::vector<media::CameraPipelineStatus> FirmwareRuntime::CameraStatuses()
    const {
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

std::optional<media::JpegBytes> FirmwareRuntime::Snapshot(
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

media::FragmentedMp4HubStatus FirmwareRuntime::LiveStatus() const {
  std::lock_guard lock(mutex_);
  if (!RunningLocked() || !dependencies_.live_status) {
    return {};
  }
  try {
    return dependencies_.live_status();
  } catch (...) {
    media::FragmentedMp4HubStatus status;
    status.state = "error";
    status.last_error_code = "E_LIVE_UNAVAILABLE";
    status.last_error_message = "live stream is unavailable";
    return status;
  }
}

common::Result<media::FragmentRing::Reader> FirmwareRuntime::OpenLiveStream(
    std::string_view camera_id) {
  std::lock_guard lock(mutex_);
  if (!RunningLocked() || !dependencies_.open_live_stream) {
    return common::Result<media::FragmentRing::Reader>::Err(LiveUnavailable());
  }
  try {
    return dependencies_.open_live_stream(camera_id);
  } catch (...) {
    return common::Result<media::FragmentRing::Reader>::Err(LiveUnavailable());
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
  if (live_started_) {
    try {
      if (dependencies_.stop_live) {
        dependencies_.stop_live();
      }
    } catch (...) {
      // swallowed: a throwing stop hook must not skip the remaining stop hooks
    }
    live_started_ = false;
  }
  if (camera_started_) {
    try {
      if (dependencies_.stop_camera) {
        dependencies_.stop_camera();
      }
    } catch (...) {
      // swallowed: a throwing stop hook must not skip the remaining stop hooks
    }
    camera_started_ = false;
  }
  if (ai_started_) {
    try {
      if (dependencies_.stop_ai) {
        dependencies_.stop_ai();
      }
    } catch (...) {
      // swallowed: a throwing stop hook must not skip the remaining stop hooks
    }
    ai_started_ = false;
  }
  if (rtsp_started_) {
    try {
      if (dependencies_.stop_rtsp) {
        dependencies_.stop_rtsp();
      }
    } catch (...) {
      // swallowed: a throwing stop hook must not skip the remaining stop hooks
    }
    rtsp_started_ = false;
  }
}

bool FirmwareRuntime::RunningLocked() const noexcept {
  return state_ == FirmwareRuntimeState::kRunning;
}

std::chrono::milliseconds FirmwareRuntime::SnapshotMaximumAge(
    const config::AppConfig& config) noexcept {
  return SnapshotMaximumAgeFor(config);
}

FirmwareRuntimeDependencies FirmwareRuntime::BuildProductionDependencies(
    const config::AppConfig& config) {
  auto graph = std::make_shared<ProductionRuntimeGraph>(config);
  return BuildDependenciesForGraph(std::move(graph));
}

FirmwareRuntime::ProductionSubStreamHandles
FirmwareRuntime::BuildProductionDependenciesWithSubStreamHandles(
    const config::AppConfig& config) {
  auto graph = std::make_shared<ProductionRuntimeGraph>(config);
  ProductionSubStreamHandles handles;
  handles.sub_stream_tap = &graph->sub_stream_tap;
  handles.sub_encoded_frames = [graph] {
    return graph->sub_stream_encoder
               ? graph->sub_stream_encoder->encoded_frames()
               : std::uint64_t{0};
  };
  handles.dependencies = BuildDependenciesForGraph(graph);
  return handles;
}

bool FirmwareRuntime::DependenciesComplete() const noexcept {
  return dependencies_.start_rtsp && dependencies_.start_ai &&
         dependencies_.start_camera && dependencies_.start_live &&
         dependencies_.stop_live && dependencies_.stop_camera &&
         dependencies_.stop_ai && dependencies_.stop_rtsp &&
         dependencies_.camera_statuses && dependencies_.live_status &&
         dependencies_.ai_status && dependencies_.ai_runner_statuses &&
         dependencies_.restart_ai && dependencies_.snapshot &&
         dependencies_.open_live_stream && dependencies_.detection_snapshot &&
         dependencies_.subscribe_detections &&
         dependencies_.per_media_key_zeroize_count;
}

bool FirmwareRuntime::LifecycleDependenciesComplete() const noexcept {
  return dependencies_.start_rtsp && dependencies_.start_ai &&
         dependencies_.start_camera && dependencies_.start_live &&
         dependencies_.stop_live && dependencies_.stop_camera &&
         dependencies_.stop_ai && dependencies_.stop_rtsp;
}

}  // namespace camera_firmware::runtime
