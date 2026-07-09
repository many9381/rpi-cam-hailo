#include "camera_firmware/ai/AiRuntimeController.hpp"

namespace camera_firmware::ai {

AiRuntimeController::AiRuntimeController(const config::AppConfig& config,
                                         AiRuntime& runtime,
                                         AiFramePump& frame_pump)
    : config_(config),
      runtime_(runtime),
      frame_pump_(frame_pump) {}

common::Result<void> AiRuntimeController::Restart() {
  std::lock_guard lock(mutex_);
  if (shutting_down_) {
    return common::Result<void>::Err(
        {"E_AI_CONTROL_SHUTTING_DOWN",
         "AI runtime control is shutting down"});
  }
  return RestartLocked();
}

void AiRuntimeController::BeginShutdown() {
  std::lock_guard lock(mutex_);
  shutting_down_ = true;
}

void AiRuntimeController::Stop() {
  std::lock_guard lock(mutex_);
  frame_pump_.Stop();
  runtime_.Stop();
}

bool AiRuntimeController::ShouldPumpFrames() const {
  return config_.ai.enabled && config_.camera.ai.enabled;
}

common::Result<void> AiRuntimeController::RestartLocked() {
  frame_pump_.Stop();
  runtime_.Stop();

  auto runtime_started = runtime_.Start(config_);
  if (!runtime_started.ok()) {
    return runtime_started;
  }

  if (ShouldPumpFrames()) {
    auto pump_started = frame_pump_.Start();
    if (!pump_started.ok()) {
      runtime_.Stop();
      return pump_started;
    }
  }

  return common::Result<void>::Ok();
}

}  // namespace camera_firmware::ai
