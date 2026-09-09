#pragma once

#include <chrono>
#include <memory>
#include <thread>

#include "camera_firmware/ai/AiFrameTap.hpp"
#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::ai {

class AiRuntime;

class AiFramePump {
 public:
  AiFramePump(AiFrameTap& frame_tap, AiRuntime& runtime,
              std::chrono::milliseconds minimum_interval = {});
  ~AiFramePump();

  AiFramePump(const AiFramePump&) = delete;
  AiFramePump& operator=(const AiFramePump&) = delete;
  AiFramePump(AiFramePump&&) = delete;
  AiFramePump& operator=(AiFramePump&&) = delete;

  [[nodiscard]] common::Result<void> Start();
  void Stop();

 private:
  struct SharedState;

  static void QueueFrame(const std::shared_ptr<SharedState>& state,
                         media::FrameLease frame);
  static void Run(const std::shared_ptr<SharedState>& state, AiRuntime& runtime,
                  std::chrono::milliseconds minimum_interval);

  AiFrameTap& frame_tap_;
  AiRuntime& runtime_;
  std::chrono::milliseconds minimum_interval_;
  std::shared_ptr<SharedState> state_;
  AiFrameTap::Subscription subscription_;
  std::thread worker_;
};

}  // namespace camera_firmware::ai
