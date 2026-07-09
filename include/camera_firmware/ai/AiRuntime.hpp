#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "camera_firmware/ai/AiBackend.hpp"
#include "camera_firmware/ai/AiModelRunner.hpp"
#include "camera_firmware/ai/DetectionBus.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::ai {

struct AiRuntimeStatus {
  bool enabled{false};
  bool backend_available{false};
  std::string backend{"disabled"};
  std::string state{"disabled"};
  std::size_t model_count{0};
  std::size_t runner_count{0};
  std::string last_error_code;
  std::string last_error_message;
};

class AiRuntime {
 public:
  explicit AiRuntime(DetectionBus* detection_bus);
  AiRuntime(DetectionBus* detection_bus,
            std::shared_ptr<AiBackend> backend_override);
  ~AiRuntime();

  AiRuntime(const AiRuntime&) = delete;
  AiRuntime& operator=(const AiRuntime&) = delete;

  [[nodiscard]] common::Result<void> Start(const config::AppConfig& config);
  void Stop();
  [[nodiscard]] common::Result<void> SubmitFrame(media::FrameLease frame);
  [[nodiscard]] AiRuntimeStatus Status() const;
  [[nodiscard]] std::vector<AiModelRunnerStatus> RunnerStatuses() const;

 private:
  [[nodiscard]] std::shared_ptr<AiBackend> CreateBackend(
      const std::string& backend_name) const;
  struct RuntimeResources;

  [[nodiscard]] RuntimeResources ReleaseResourcesLocked();
  static void StopResources(RuntimeResources resources);
  void RecordError(const common::Error& error);

  DetectionBus* detection_bus_{nullptr};
  mutable std::mutex mutex_;
  std::shared_ptr<AiBackend> backend_override_;
  std::shared_ptr<AiBackend> backend_;
  std::unordered_map<std::string, ModelHandle> model_handles_;
  std::vector<std::shared_ptr<AiModelRunner>> runners_;
  std::vector<std::string> redacted_model_paths_;
  AiRuntimeStatus status_;
};

}  // namespace camera_firmware::ai
