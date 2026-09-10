#pragma once

#include <mutex>

#include "camera_firmware/ai/AiFramePump.hpp"
#include "camera_firmware/ai/AiRuntime.hpp"
#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"

namespace camera_firmware::ai {

class AiRuntimeController {
 public:
  AiRuntimeController(const config::AppConfig& config, AiRuntime& runtime,
                      AiFramePump& frame_pump);

  [[nodiscard]] common::Result<void> Restart();
  void BeginShutdown();
  void Stop();

 private:
  [[nodiscard]] bool ShouldPumpFrames() const;
  [[nodiscard]] common::Result<void> RestartLocked();

  const config::AppConfig& config_;
  AiRuntime& runtime_;
  AiFramePump& frame_pump_;
  std::mutex mutex_;
  bool shutting_down_{false};
};

}  // namespace camera_firmware::ai
