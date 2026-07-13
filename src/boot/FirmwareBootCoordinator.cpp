#include "camera_firmware/boot/FirmwareBootCoordinator.hpp"

#include <string_view>
#include <utility>

namespace camera_firmware::boot {
namespace {

common::Result<void> BootError(std::string_view code,
                               std::string_view message) {
  return common::Result<void>::Err(
      {std::string(code), std::string(message)});
}

}  // namespace

FirmwareBootCoordinator::FirmwareBootCoordinator(
    FirmwareBootConfig config,
    FirmwareBootDependencies dependencies)
    : config_(config), dependencies_(std::move(dependencies)) {}

FirmwareBootCoordinator::~FirmwareBootCoordinator() {
  Stop();
}

common::Result<void> FirmwareBootCoordinator::Start() {
  auto dependencies_valid = ValidateDependencies();
  if (!dependencies_valid.ok()) {
    return dependencies_valid;
  }

  {
    std::unique_lock lock(mutex_);
    condition_.wait(lock, [this] {
      return state_ != FirmwareBootState::kStarting &&
             state_ != FirmwareBootState::kStopping;
    });
    if (state_ == FirmwareBootState::kRunning) {
      return common::Result<void>::Ok();
    }
    state_ = FirmwareBootState::kStarting;
  }

  bool should_start_runtime = !config_.security_enabled;
  if (config_.security_enabled) {
    common::Result<security::DeviceState> device_state = [&] {
      try {
        return dependencies_.read_device_state();
      } catch (...) {
        return common::Result<security::DeviceState>::Err(
            {"E_BOOT_STATE", "failed to read device state"});
      }
    }();
    if (!device_state.ok()) {
      FinishFailedStart(false);
      return common::Result<void>::Err(device_state.error());
    }
    should_start_runtime =
        device_state.value() == security::DeviceState::kOperational;
    if (!should_start_runtime && !config_.service_enabled) {
      FinishFailedStart(false);
      return BootError("E_BOOT_SERVICE_REQUIRED",
                       "default device state requires setup service");
    }
  }

  if (config_.service_enabled) {
    {
      std::scoped_lock lock(mutex_);
      accept_runtime_transition_ = true;
    }
    common::Result<void> service = [&] {
      try {
        return dependencies_.start_service(
            [this] { return StartRuntimeAfterBootstrap(); });
      } catch (...) {
        return BootError("E_BOOT_SERVICE_START",
                         "failed to start firmware service");
      }
    }();
    if (!service.ok()) {
      {
        std::scoped_lock lock(mutex_);
        accept_runtime_transition_ = false;
      }
      QuiesceServiceDependency();
      bool unwind_runtime = false;
      {
        std::unique_lock lock(mutex_);
        condition_.wait(lock,
                        [this] { return !runtime_start_in_progress_; });
        unwind_runtime = runtime_started_;
        runtime_started_ = false;
      }
      if (unwind_runtime) {
        StopRuntimeDependency();
      }
      StopServiceDependency();
      FinishFailedStart(false);
      return service;
    }
    std::scoped_lock lock(mutex_);
    service_started_ = true;
  }

  if (should_start_runtime) {
    if (config_.service_enabled) {
      (void)StartRuntimeAfterBootstrap();
    } else {
      auto runtime = StartRuntimeDependency();
      if (!runtime.ok()) {
        FinishFailedStart(false);
        return runtime;
      }
      std::scoped_lock lock(mutex_);
      runtime_started_ = true;
    }
  }

  {
    std::scoped_lock lock(mutex_);
    state_ = FirmwareBootState::kRunning;
  }
  condition_.notify_all();
  return common::Result<void>::Ok();
}

void FirmwareBootCoordinator::Stop() noexcept {
  bool stop_service = false;
  bool stop_runtime = false;
  {
    std::unique_lock lock(mutex_);
    condition_.wait(lock, [this] {
      return state_ != FirmwareBootState::kStarting;
    });
    if (state_ == FirmwareBootState::kStopping) {
      condition_.wait(lock, [this] {
        return state_ == FirmwareBootState::kStopped;
      });
      return;
    }
    if (state_ == FirmwareBootState::kStopped) {
      return;
    }
    state_ = FirmwareBootState::kStopping;
    accept_runtime_transition_ = false;
    stop_service = service_started_;
    condition_.wait(lock, [this] { return !runtime_start_in_progress_; });
    stop_runtime = runtime_started_;
    runtime_started_ = false;
  }

  if (stop_service) {
    QuiesceServiceDependency();
  }
  if (stop_runtime) {
    StopRuntimeDependency();
  }
  if (stop_service) {
    StopServiceDependency();
  }

  {
    std::scoped_lock lock(mutex_);
    service_started_ = false;
    state_ = FirmwareBootState::kStopped;
  }
  condition_.notify_all();
}

common::Result<void> FirmwareBootCoordinator::StartRuntimeAfterBootstrap() {
  {
    std::unique_lock lock(mutex_);
    condition_.wait(lock,
                    [this] { return !runtime_start_in_progress_; });
    if (!accept_runtime_transition_) {
      return BootError("E_BOOT_TRANSITION",
                       "runtime transition is not available");
    }
    if (runtime_started_) {
      return common::Result<void>::Ok();
    }
    runtime_start_in_progress_ = true;
  }

  auto runtime = StartRuntimeDependency();
  {
    std::scoped_lock lock(mutex_);
    runtime_start_in_progress_ = false;
    if (runtime.ok()) {
      runtime_started_ = true;
    }
  }
  condition_.notify_all();
  return runtime;
}

FirmwareBootState FirmwareBootCoordinator::State() const noexcept {
  std::scoped_lock lock(mutex_);
  return state_;
}

common::Result<void> FirmwareBootCoordinator::ValidateDependencies() const {
  if (!dependencies_.start_runtime || !dependencies_.stop_runtime) {
    return BootError("E_BOOT_DEPENDENCY",
                     "runtime lifecycle dependency is missing");
  }
  if (config_.security_enabled && !dependencies_.read_device_state) {
    return BootError("E_BOOT_DEPENDENCY",
                     "security state dependency is missing");
  }
  if (config_.service_enabled &&
      (!dependencies_.start_service || !dependencies_.quiesce_service ||
       !dependencies_.stop_service)) {
    return BootError("E_BOOT_DEPENDENCY",
                     "service lifecycle dependency is missing");
  }
  return common::Result<void>::Ok();
}

common::Result<void> FirmwareBootCoordinator::StartRuntimeDependency() {
  try {
    return dependencies_.start_runtime();
  } catch (...) {
    return BootError("E_BOOT_RUNTIME_START",
                     "failed to start firmware runtime");
  }
}

void FirmwareBootCoordinator::StopRuntimeDependency() noexcept {
  try {
    dependencies_.stop_runtime();
  } catch (...) {
  }
}

void FirmwareBootCoordinator::QuiesceServiceDependency() noexcept {
  try {
    dependencies_.quiesce_service();
  } catch (...) {
  }
}

void FirmwareBootCoordinator::StopServiceDependency() noexcept {
  try {
    dependencies_.stop_service();
  } catch (...) {
  }
}

void FirmwareBootCoordinator::FinishFailedStart(bool unwind_runtime) noexcept {
  if (unwind_runtime) {
    StopRuntimeDependency();
  }
  {
    std::scoped_lock lock(mutex_);
    runtime_started_ = false;
    service_started_ = false;
    accept_runtime_transition_ = false;
    runtime_start_in_progress_ = false;
    state_ = FirmwareBootState::kStopped;
  }
  condition_.notify_all();
}

}  // namespace camera_firmware::boot
