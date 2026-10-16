#pragma once

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/security/SecurityStore.hpp"

namespace camera_firmware::boot {

enum class FirmwareBootState {
  kStopped,
  kStarting,
  kRunning,
  kStopping,
};

struct FirmwareBootConfig {
  bool security_enabled{false};
  bool service_enabled{false};
};

using RuntimeStartCallback = std::function<common::Result<void>()>;

struct FirmwareBootDependencies {
  std::function<common::Result<security::DeviceState>()> read_device_state;
  std::function<void()> run_startup_protection_checks;
  std::function<bool()> protection_allows_runtime;
  std::function<common::Result<void>()> start_runtime;
  std::function<void()> stop_runtime;
  std::function<common::Result<void>(RuntimeStartCallback)> start_service;
  std::function<void()> quiesce_service;
  std::function<void()> stop_service;
  // Optional: true when a previously started graph self-stopped after failure.
  std::function<bool()> runtime_needs_start;
};

class FirmwareBootCoordinator {
 public:
  FirmwareBootCoordinator(FirmwareBootConfig config,
                          FirmwareBootDependencies dependencies);
  ~FirmwareBootCoordinator();

  FirmwareBootCoordinator(const FirmwareBootCoordinator&) = delete;
  FirmwareBootCoordinator& operator=(const FirmwareBootCoordinator&) = delete;
  FirmwareBootCoordinator(FirmwareBootCoordinator&&) = delete;
  FirmwareBootCoordinator& operator=(FirmwareBootCoordinator&&) = delete;

  [[nodiscard]] common::Result<void> Start();
  void Stop() noexcept;
  [[nodiscard]] common::Result<void> StartRuntimeAfterBootstrap();
  void StopRuntimeForProtection() noexcept;
  [[nodiscard]] FirmwareBootState State() const noexcept;

 private:
  [[nodiscard]] common::Result<void> ValidateDependencies() const;
  [[nodiscard]] common::Result<void> StartRuntimeDependency();
  [[nodiscard]] bool ProtectionAllowsRuntime() const noexcept;
  void StopRuntimeDependency() noexcept;
  void QuiesceServiceDependency() noexcept;
  void StopServiceDependency() noexcept;
  void FinishFailedStart(bool unwind_runtime) noexcept;

  FirmwareBootConfig config_;
  FirmwareBootDependencies dependencies_;
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  FirmwareBootState state_{FirmwareBootState::kStopped};
  bool runtime_started_{false};
  bool service_started_{false};
  bool runtime_start_in_progress_{false};
  bool runtime_stop_in_progress_{false};
  bool accept_runtime_transition_{false};
  std::uint64_t runtime_transition_generation_{0U};
};

}  // namespace camera_firmware::boot
