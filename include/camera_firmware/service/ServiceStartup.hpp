#pragma once

#include <chrono>
#include <memory>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::service {

class ServiceStartupState;

class ServiceStartupSignal {
 public:
  static constexpr std::chrono::milliseconds kDefaultServiceStartupTimeout{
      5000};

  ServiceStartupSignal();
  ~ServiceStartupSignal();

  ServiceStartupSignal(const ServiceStartupSignal&) = delete;
  ServiceStartupSignal& operator=(const ServiceStartupSignal&) = delete;
  ServiceStartupSignal(ServiceStartupSignal&&) = delete;
  ServiceStartupSignal& operator=(ServiceStartupSignal&&) = delete;

  void ReportReady();
  void ReportError(common::Error error);
  [[nodiscard]] common::Result<void> Wait(
      std::chrono::milliseconds timeout = kDefaultServiceStartupTimeout);

 private:
  std::shared_ptr<ServiceStartupState> state_;
};

}  // namespace camera_firmware::service
