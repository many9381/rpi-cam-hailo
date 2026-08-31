#include "camera_firmware/runtime/ManagedFirmwareRuntime.hpp"

#include <exception>
#include <string>
#include <type_traits>
#include <utility>

namespace camera_firmware::runtime {
namespace {

static_assert(std::is_nothrow_move_assignable_v<config::AppConfig>);

common::Error FactoryError(std::string message) {
  return {"E_RUNTIME_FACTORY", std::move(message)};
}

common::Error PromotionError(std::string message) {
  return {"E_RUNTIME_PROMOTION", std::move(message)};
}

common::Error RuntimeNotRunning() {
  return {"E_RUNTIME_NOT_RUNNING", "firmware runtime is not running"};
}

common::Error LiveUnavailable() {
  return {"E_LIVE_UNAVAILABLE", "live stream is unavailable"};
}

std::string CameraStateForManagedRuntime(ManagedRuntimeState state) {
  switch (state) {
    case ManagedRuntimeState::kStopped:
      return "stopped";
    case ManagedRuntimeState::kStarting:
      return "starting";
    case ManagedRuntimeState::kRunning:
      return "running";
    case ManagedRuntimeState::kApplying:
      return "stopped";
    case ManagedRuntimeState::kFailed:
      return "error";
    case ManagedRuntimeState::kStopping:
      return "stopping";
  }
  return "error";
}

}  // namespace

ManagedFirmwareRuntime::ManagedFirmwareRuntime(
    config::AppConfig initial_config,
    FirmwareRuntimeFactory factory)
    : active_config_(std::move(initial_config)), factory_(std::move(factory)) {}

ManagedFirmwareRuntime::~ManagedFirmwareRuntime() {
  try {
    Stop();
  } catch (...) {
  }
}

common::Result<void> ManagedFirmwareRuntime::Start() {
  std::lock_guard command_lock(command_mutex_);
  auto snapshot = ReadSnapshot();
  if (snapshot.state == ManagedRuntimeState::kRunning && snapshot.runtime) {
    return common::Result<void>::Ok();
  }

  SetState(ManagedRuntimeState::kStarting);
  bool newly_built = false;
  if (!snapshot.runtime) {
    auto built = BuildRuntime(snapshot.config);
    if (!built.ok()) {
      SetState(ManagedRuntimeState::kFailed);
      return common::Result<void>::Err(built.error());
    }
    snapshot.runtime = std::move(built).value();
    newly_built = true;
  }

  auto started = StartRuntime(snapshot.runtime);
  if (!started.ok()) {
    StopRuntime(snapshot.runtime);
    SetState(ManagedRuntimeState::kFailed);
    return started;
  }

  {
    std::lock_guard snapshot_lock(snapshot_mutex_);
    if (newly_built) {
      current_runtime_ = std::move(snapshot.runtime);
    }
    state_ = ManagedRuntimeState::kRunning;
  }
  return common::Result<void>::Ok();
}

void ManagedFirmwareRuntime::Stop() {
  std::lock_guard command_lock(command_mutex_);
  auto snapshot = ReadSnapshot();
  if (snapshot.state == ManagedRuntimeState::kStopped) {
    return;
  }

  SetState(ManagedRuntimeState::kStopping);
  StopRuntime(snapshot.runtime);
  SetState(ManagedRuntimeState::kStopped);
}

RuntimeReplacementResult ManagedFirmwareRuntime::Replace(
    const config::AppConfig& candidate_config,
    std::function<common::Result<void>()> durable_promote) {
  std::lock_guard command_lock(command_mutex_);
  const auto previous = ReadSnapshot();
  const bool running = previous.state == ManagedRuntimeState::kRunning &&
                       previous.runtime != nullptr;
  const bool recovering = previous.state == ManagedRuntimeState::kFailed;
  if (!running && !recovering) {
    return {RuntimeReplacementResult::Outcome::kCandidateFailed, false,
            RuntimeNotRunning()};
  }

  const auto validated = config::ValidateAppConfigSemantics(candidate_config);
  if (!validated.ok()) {
    return {RuntimeReplacementResult::Outcome::kCandidateFailed, false,
            validated.error()};
  }
  if (!durable_promote) {
    return {RuntimeReplacementResult::Outcome::kCommitFailed, false,
            PromotionError("runtime promotion callback is not configured")};
  }

  config::AppConfig published_config = candidate_config;
  SetState(ManagedRuntimeState::kApplying);
  StopRuntime(previous.runtime);

  auto built = BuildRuntime(candidate_config);
  if (!built.ok()) {
    const common::Error error = built.error();
    const bool restored = RestorePrevious(previous.runtime);
    return {RuntimeReplacementResult::Outcome::kCandidateFailed, restored,
            error};
  }
  auto candidate = std::move(built).value();
  if (candidate == previous.runtime) {
    const common::Error error =
        FactoryError("firmware runtime factory returned active runtime");
    const bool restored = RestorePrevious(previous.runtime);
    return {RuntimeReplacementResult::Outcome::kCandidateFailed, restored,
            error};
  }

  auto started = StartRuntime(candidate);
  if (!started.ok()) {
    const common::Error error = started.error();
    StopRuntime(candidate);
    const bool restored = RestorePrevious(previous.runtime);
    return {RuntimeReplacementResult::Outcome::kCandidateFailed, restored,
            error};
  }

  common::Result<void> promoted = common::Result<void>::Ok();
  try {
    promoted = durable_promote();
  } catch (...) {
    promoted = common::Result<void>::Err(
        PromotionError("runtime configuration promotion failed"));
  }
  if (!promoted.ok()) {
    const common::Error error = promoted.error();
    StopRuntime(candidate);
    const bool restored = RestorePrevious(previous.runtime);
    return {RuntimeReplacementResult::Outcome::kCommitFailed, restored,
            error};
  }

  {
    std::lock_guard snapshot_lock(snapshot_mutex_);
    current_runtime_ = std::move(candidate);
    active_config_ = std::move(published_config);
    state_ = ManagedRuntimeState::kRunning;
  }
  return {RuntimeReplacementResult::Outcome::kApplied, false, {}};
}

ManagedRuntimeState ManagedFirmwareRuntime::State() const {
  std::lock_guard snapshot_lock(snapshot_mutex_);
  return state_;
}

config::AppConfig ManagedFirmwareRuntime::ActiveConfig() const {
  std::lock_guard snapshot_lock(snapshot_mutex_);
  return active_config_;
}

std::vector<media::CameraPipelineStatus>
ManagedFirmwareRuntime::CameraStatuses() const {
  auto snapshot = ReadSnapshot();
  if (snapshot.runtime) {
    return snapshot.runtime->CameraStatuses();
  }

  media::CameraPipelineStatus status;
  status.id = snapshot.config.camera.id;
  status.state = CameraStateForManagedRuntime(snapshot.state);
  status.width = snapshot.config.camera.video.width;
  status.height = snapshot.config.camera.video.height;
  status.configured_fps = snapshot.config.camera.video.fps;
  return {std::move(status)};
}

ai::AiRuntimeStatus ManagedFirmwareRuntime::AiStatus() const {
  auto snapshot = ReadSnapshot();
  if (snapshot.runtime) {
    return snapshot.runtime->AiStatus();
  }

  ai::AiRuntimeStatus status;
  status.enabled = snapshot.config.ai.enabled;
  status.state = "stopped";
  return status;
}

std::vector<ai::AiModelRunnerStatus>
ManagedFirmwareRuntime::AiRunnerStatuses() const {
  auto runtime = ReadSnapshot().runtime;
  return runtime ? runtime->AiRunnerStatuses()
                 : std::vector<ai::AiModelRunnerStatus>{};
}

common::Result<void> ManagedFirmwareRuntime::RestartAi() {
  auto runtime = ReadSnapshot().runtime;
  if (!runtime) {
    return common::Result<void>::Err(RuntimeNotRunning());
  }
  return runtime->RestartAi();
}

std::optional<media::JpegBytes> ManagedFirmwareRuntime::Snapshot(
    std::string_view camera_id) const {
  auto runtime = ReadSnapshot().runtime;
  return runtime ? runtime->Snapshot(camera_id) : std::nullopt;
}

media::FragmentedMp4HubStatus ManagedFirmwareRuntime::LiveStatus() const {
  auto runtime = ReadSnapshot().runtime;
  return runtime ? runtime->LiveStatus() : media::FragmentedMp4HubStatus{};
}

common::Result<media::FragmentRing::Reader>
ManagedFirmwareRuntime::OpenLiveStream(std::string_view camera_id) {
  auto runtime = ReadSnapshot().runtime;
  if (!runtime) {
    return common::Result<media::FragmentRing::Reader>::Err(LiveUnavailable());
  }
  return runtime->OpenLiveStream(camera_id);
}

std::vector<ai::DetectionEvent>
ManagedFirmwareRuntime::DetectionSnapshot() const {
  auto runtime = ReadSnapshot().runtime;
  return runtime ? runtime->DetectionSnapshot()
                 : std::vector<ai::DetectionEvent>{};
}

ai::DetectionBus::Subscription ManagedFirmwareRuntime::SubscribeDetections(
    ai::DetectionBus::Handler handler) {
  auto runtime = ReadSnapshot().runtime;
  if (!runtime || !handler) {
    return {};
  }
  return runtime->SubscribeDetections(std::move(handler));
}

std::uint64_t ManagedFirmwareRuntime::PerMediaKeyZeroizeCount() const noexcept {
  try {
    auto runtime = ReadSnapshot().runtime;
    return runtime ? runtime->PerMediaKeyZeroizeCount() : 0U;
  } catch (...) {
    return 0U;
  }
}

ManagedFirmwareRuntime::RuntimeSnapshot
ManagedFirmwareRuntime::ReadSnapshot() const {
  std::lock_guard snapshot_lock(snapshot_mutex_);
  return {current_runtime_, active_config_, state_};
}

common::Result<std::shared_ptr<FirmwareRuntime>>
ManagedFirmwareRuntime::BuildRuntime(const config::AppConfig& config) {
  if (!factory_) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Err(
        FactoryError("firmware runtime factory is not configured"));
  }
  try {
    auto built = factory_(config);
    if (!built.ok()) {
      return common::Result<std::shared_ptr<FirmwareRuntime>>::Err(
          built.error());
    }
    if (!built.value()) {
      return common::Result<std::shared_ptr<FirmwareRuntime>>::Err(
          FactoryError("firmware runtime factory returned no runtime"));
    }
    return built;
  } catch (...) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Err(
        FactoryError("firmware runtime construction failed"));
  }
}

common::Result<void> ManagedFirmwareRuntime::StartRuntime(
    const std::shared_ptr<FirmwareRuntime>& runtime) {
  if (!runtime) {
    return common::Result<void>::Err(
        FactoryError("firmware runtime factory returned no runtime"));
  }
  try {
    return runtime->Start();
  } catch (...) {
    return common::Result<void>::Err(
        {"E_RUNTIME_START", "firmware runtime component failed"});
  }
}

void ManagedFirmwareRuntime::StopRuntime(
    const std::shared_ptr<FirmwareRuntime>& runtime) noexcept {
  if (!runtime) {
    return;
  }
  try {
    runtime->Stop();
  } catch (...) {
  }
}

bool ManagedFirmwareRuntime::RestorePrevious(
    const std::shared_ptr<FirmwareRuntime>& previous) {
  const bool restored = StartRuntime(previous).ok();
  SetState(restored ? ManagedRuntimeState::kRunning
                    : ManagedRuntimeState::kFailed);
  return restored;
}

void ManagedFirmwareRuntime::SetState(ManagedRuntimeState state) {
  std::lock_guard snapshot_lock(snapshot_mutex_);
  state_ = state;
}

}  // namespace camera_firmware::runtime
