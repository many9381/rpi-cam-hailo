#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <thread>

#include "camera_firmware/ai/AiBackend.hpp"
#include "camera_firmware/ai/AiModelProcessor.hpp"
#include "camera_firmware/ai/DetectionBus.hpp"
#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::ai {

struct AiModelRunnerStatus {
  std::string camera_id;
  std::string model_id;
  std::string model_kind;
  std::uint64_t submitted_frames{0};
  std::uint64_t dropped_frames{0};
  std::uint64_t processed_frames{0};
  std::string last_error_code;
  std::string last_error_message;
};

class AiModelRunner {
 public:
  AiModelRunner(std::string camera_id,
                config::AiModelConfig model,
                AiBackend* backend,
                ModelHandle model_handle,
                DetectionBus* detection_bus = nullptr);
  ~AiModelRunner();

  AiModelRunner(const AiModelRunner&) = delete;
  AiModelRunner& operator=(const AiModelRunner&) = delete;

  [[nodiscard]] common::Result<void> Submit(media::FrameLease frame);
  void Stop();
  [[nodiscard]] AiModelRunnerStatus Status() const;

 private:
  struct SharedState;

  void Run();
  void ProcessFrame(media::FrameLease frame);
  static void RecordDrop(const std::shared_ptr<SharedState>& state,
                         const common::Error& error);
  static void RecordProcessed(const std::shared_ptr<SharedState>& state);

  std::string camera_id_;
  config::AiModelConfig model_;
  AiBackend* backend_{nullptr};
  ModelHandle model_handle_{0};
  DetectionBus::Publisher detection_publisher_;
  std::shared_ptr<AiModelProcessor> processor_;
  std::shared_ptr<SharedState> state_;
  std::thread worker_;
};

}  // namespace camera_firmware::ai
