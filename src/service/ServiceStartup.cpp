#include "camera_firmware/service/ServiceStartup.hpp"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <utility>

namespace camera_firmware::service {
namespace {

common::Error StartupTimeoutError() {
  return {"E_SERVICE_START", "Drogon service startup timed out"};
}

}  // namespace

class ServiceStartupState {
 public:
  void Complete(std::optional<common::Error> error) {
    {
      std::scoped_lock lock(mutex_);
      if (completed_) {
        return;
      }
      error_ = std::move(error);
      completed_ = true;
    }
    cv_.notify_all();
  }

  common::Result<void> Wait(std::chrono::milliseconds timeout) {
    std::unique_lock lock(mutex_);
    if (!cv_.wait_for(lock, timeout, [this] { return completed_; })) {
      error_ = StartupTimeoutError();
      completed_ = true;
      lock.unlock();
      cv_.notify_all();
      return common::Result<void>::Err(*error_);
    }
    if (error_.has_value()) {
      return common::Result<void>::Err(*error_);
    }
    return common::Result<void>::Ok();
  }

 private:
  std::mutex mutex_;
  std::condition_variable cv_;
  bool completed_{false};
  std::optional<common::Error> error_;
};

ServiceStartupSignal::ServiceStartupSignal()
    : state_(std::make_shared<ServiceStartupState>()) {}

ServiceStartupSignal::~ServiceStartupSignal() = default;

void ServiceStartupSignal::ReportReady() {
  state_->Complete(std::nullopt);
}

void ServiceStartupSignal::ReportError(common::Error error) {
  state_->Complete(std::move(error));
}

common::Result<void> ServiceStartupSignal::Wait(
    std::chrono::milliseconds timeout) {
  return state_->Wait(timeout);
}

}  // namespace camera_firmware::service
