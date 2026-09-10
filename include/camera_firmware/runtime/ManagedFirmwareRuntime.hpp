#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>

#include <vector>
#include "camera_firmware/media/JpegEncoder.hpp"

#include "camera_firmware/runtime/FirmwareRuntime.hpp"

namespace camera_firmware::runtime {

using FirmwareRuntimeFactory =
    std::function<common::Result<std::shared_ptr<FirmwareRuntime>>(
        const config::AppConfig&)>;

enum class ManagedRuntimeState {
  kStopped,
  kStarting,
  kRunning,
  kApplying,
  kFailed,
  kStopping,
};

struct RuntimeReplacementResult {
  enum class Outcome {
    kApplied,
    kCandidateFailed,
    kCommitFailed,
  };

  Outcome outcome{Outcome::kCandidateFailed};
  bool restored{false};
  common::Error error;
};

class ManagedFirmwareRuntime final {
 public:
  ManagedFirmwareRuntime(config::AppConfig initial_config,
                         FirmwareRuntimeFactory factory);
  ~ManagedFirmwareRuntime();

  ManagedFirmwareRuntime(const ManagedFirmwareRuntime&) = delete;
  ManagedFirmwareRuntime& operator=(const ManagedFirmwareRuntime&) = delete;
  ManagedFirmwareRuntime(ManagedFirmwareRuntime&&) = delete;
  ManagedFirmwareRuntime& operator=(ManagedFirmwareRuntime&&) = delete;

  [[nodiscard]] common::Result<void> Start();
  void Stop();
  [[nodiscard]] RuntimeReplacementResult Replace(
      const config::AppConfig& candidate_config,
      std::function<common::Result<void>()> durable_promote);

  [[nodiscard]] ManagedRuntimeState State() const;
  [[nodiscard]] config::AppConfig ActiveConfig() const;

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
  struct RuntimeSnapshot {
    std::shared_ptr<FirmwareRuntime> runtime;
    config::AppConfig config;
    ManagedRuntimeState state{ManagedRuntimeState::kStopped};
  };

  [[nodiscard]] RuntimeSnapshot ReadSnapshot() const;
  [[nodiscard]] common::Result<std::shared_ptr<FirmwareRuntime>> BuildRuntime(
      const config::AppConfig& config);
  [[nodiscard]] static common::Result<void> StartRuntime(
      const std::shared_ptr<FirmwareRuntime>& runtime);
  static void StopRuntime(
      const std::shared_ptr<FirmwareRuntime>& runtime) noexcept;
  [[nodiscard]] bool RestorePrevious(
      const std::shared_ptr<FirmwareRuntime>& previous);
  void SetState(ManagedRuntimeState state);

  mutable std::mutex command_mutex_;
  mutable std::mutex snapshot_mutex_;
  std::shared_ptr<FirmwareRuntime> current_runtime_;
  config::AppConfig active_config_;
  FirmwareRuntimeFactory factory_;
  ManagedRuntimeState state_{ManagedRuntimeState::kStopped};
};

}  // namespace camera_firmware::runtime
