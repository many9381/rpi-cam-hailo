#include "camera_firmware/boot/FirmwareBootCoordinator.hpp"

#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace camera_firmware::boot {
namespace {

struct Calls {
  void Record(std::string call) {
    std::lock_guard lock(mutex);
    ordered.push_back(std::move(call));
  }

  std::mutex mutex;
  std::vector<std::string> ordered;
  unsigned int state_reads{0U};
  unsigned int runtime_starts{0U};
  unsigned int runtime_stops{0U};
  unsigned int service_starts{0U};
  unsigned int service_stops{0U};
  RuntimeStartCallback runtime_start_callback;
};

FirmwareBootDependencies SuccessfulDependencies(
    Calls& calls,
    security::DeviceState state = security::DeviceState::kDefault) {
  FirmwareBootDependencies dependencies;
  dependencies.read_device_state = [&, state] {
    ++calls.state_reads;
    calls.Record("state");
    return common::Result<security::DeviceState>::Ok(state);
  };
  dependencies.start_runtime = [&] {
    ++calls.runtime_starts;
    calls.Record("runtime.start");
    return common::Result<void>::Ok();
  };
  dependencies.stop_runtime = [&] {
    ++calls.runtime_stops;
    calls.Record("runtime.stop");
  };
  dependencies.start_service = [&](RuntimeStartCallback start_runtime) {
    ++calls.service_starts;
    calls.Record("service.start");
    calls.runtime_start_callback = std::move(start_runtime);
    return common::Result<void>::Ok();
  };
  dependencies.stop_service = [&] {
    ++calls.service_stops;
    calls.Record("service.stop");
  };
  return dependencies;
}

TEST(FirmwareBootCoordinatorTest, DefaultStateStartsOnlyService) {
  Calls calls;
  FirmwareBootCoordinator coordinator(
      {true, true}, SuccessfulDependencies(calls));

  ASSERT_TRUE(coordinator.Start().ok());

  EXPECT_EQ(coordinator.State(), FirmwareBootState::kRunning);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"state", "service.start"}));
  EXPECT_EQ(calls.runtime_starts, 0U);
  ASSERT_TRUE(calls.runtime_start_callback);

  ASSERT_TRUE(calls.runtime_start_callback().ok());
  EXPECT_EQ(calls.runtime_starts, 1U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"state", "service.start",
                                      "runtime.start"}));
}

TEST(FirmwareBootCoordinatorTest, OperationalStateStartsRuntimeBeforeService) {
  Calls calls;
  FirmwareBootCoordinator coordinator(
      {true, true},
      SuccessfulDependencies(calls, security::DeviceState::kOperational));

  ASSERT_TRUE(coordinator.Start().ok());

  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"state", "runtime.start",
                                      "service.start"}));
  EXPECT_EQ(calls.runtime_starts, 1U);
  EXPECT_EQ(calls.service_starts, 1U);
}

TEST(FirmwareBootCoordinatorTest, SecurityDisabledSkipsStateRead) {
  Calls calls;
  FirmwareBootCoordinator coordinator(
      {false, true}, SuccessfulDependencies(calls));

  ASSERT_TRUE(coordinator.Start().ok());

  EXPECT_EQ(calls.state_reads, 0U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"runtime.start", "service.start"}));
}

TEST(FirmwareBootCoordinatorTest, StateReadFailurePreventsStartup) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.read_device_state = [&] {
    ++calls.state_reads;
    calls.Record("state");
    return common::Result<security::DeviceState>::Err(
        {"E_SECURITY_STATE", "injected state failure"});
  };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));

  auto started = coordinator.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_SECURITY_STATE");
  EXPECT_EQ(coordinator.State(), FirmwareBootState::kStopped);
  EXPECT_EQ(calls.ordered, (std::vector<std::string>{"state"}));
}

TEST(FirmwareBootCoordinatorTest, RuntimeFailurePreventsServiceStartup) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(
      calls, security::DeviceState::kOperational);
  dependencies.start_runtime = [&] {
    ++calls.runtime_starts;
    calls.Record("runtime.start");
    return common::Result<void>::Err(
        {"E_RUNTIME_START", "injected runtime failure"});
  };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));

  auto started = coordinator.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_RUNTIME_START");
  EXPECT_EQ(calls.service_starts, 0U);
  EXPECT_EQ(calls.runtime_stops, 0U);
}

TEST(FirmwareBootCoordinatorTest, ServiceFailureUnwindsStartedRuntime) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.start_service = [&](RuntimeStartCallback) {
    ++calls.service_starts;
    calls.Record("service.start");
    return common::Result<void>::Err(
        {"E_SERVICE_START", "injected service failure"});
  };
  FirmwareBootCoordinator coordinator({false, true}, std::move(dependencies));

  auto started = coordinator.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_SERVICE_START");
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"runtime.start", "service.start",
                                      "service.stop", "runtime.stop"}));
}

TEST(FirmwareBootCoordinatorTest, DefaultServiceFailureLeavesRuntimeUntouched) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.start_service = [&](RuntimeStartCallback) {
    ++calls.service_starts;
    calls.Record("service.start");
    return common::Result<void>::Err(
        {"E_SERVICE_START", "injected service failure"});
  };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));

  auto started = coordinator.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_SERVICE_START");
  EXPECT_EQ(calls.runtime_starts, 0U);
  EXPECT_EQ(calls.runtime_stops, 0U);
  EXPECT_EQ(calls.service_stops, 1U);
}

TEST(FirmwareBootCoordinatorTest,
     ServiceFailureStopsRuntimeCompletedWhileServiceDrains) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  std::promise<void> runtime_entered;
  std::promise<void> release_runtime;
  auto release_runtime_future = release_runtime.get_future().share();
  std::thread transition;
  bool transition_ok = false;
  dependencies.start_runtime = [&] {
    ++calls.runtime_starts;
    calls.Record("runtime.start");
    runtime_entered.set_value();
    release_runtime_future.wait();
    return common::Result<void>::Ok();
  };
  dependencies.start_service = [&](RuntimeStartCallback start_runtime) {
    ++calls.service_starts;
    calls.Record("service.start");
    transition = std::thread([&, start_runtime = std::move(start_runtime)] {
      transition_ok = start_runtime().ok();
    });
    runtime_entered.get_future().wait();
    return common::Result<void>::Err(
        {"E_SERVICE_START", "injected service failure"});
  };
  dependencies.stop_service = [&] {
    ++calls.service_stops;
    calls.Record("service.stop");
    release_runtime.set_value();
    transition.join();
  };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));

  auto started = coordinator.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_TRUE(transition_ok);
  EXPECT_EQ(calls.runtime_starts, 1U);
  EXPECT_EQ(calls.runtime_stops, 1U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"state", "service.start",
                                      "runtime.start", "service.stop",
                                      "runtime.stop"}));
}

TEST(FirmwareBootCoordinatorTest, FailedImmediateTransitionCanRetry) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.start_runtime = [&] {
    ++calls.runtime_starts;
    calls.Record("runtime.start");
    if (calls.runtime_starts == 1U) {
      return common::Result<void>::Err(
          {"E_RUNTIME_START", "injected runtime failure"});
    }
    return common::Result<void>::Ok();
  };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));
  ASSERT_TRUE(coordinator.Start().ok());
  ASSERT_TRUE(calls.runtime_start_callback);

  auto first = calls.runtime_start_callback();
  auto second = calls.runtime_start_callback();

  ASSERT_FALSE(first.ok());
  EXPECT_EQ(first.error().code, "E_RUNTIME_START");
  EXPECT_TRUE(second.ok());
  EXPECT_EQ(calls.runtime_starts, 2U);
  EXPECT_TRUE(calls.runtime_start_callback().ok());
  EXPECT_EQ(calls.runtime_starts, 2U);
}

TEST(FirmwareBootCoordinatorTest, StartAndStopAreIdempotentAndOrdered) {
  Calls calls;
  FirmwareBootCoordinator coordinator(
      {false, true}, SuccessfulDependencies(calls));

  ASSERT_TRUE(coordinator.Start().ok());
  ASSERT_TRUE(coordinator.Start().ok());
  coordinator.Stop();
  coordinator.Stop();

  EXPECT_EQ(coordinator.State(), FirmwareBootState::kStopped);
  EXPECT_EQ(calls.runtime_starts, 1U);
  EXPECT_EQ(calls.service_starts, 1U);
  EXPECT_EQ(calls.service_stops, 1U);
  EXPECT_EQ(calls.runtime_stops, 1U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"runtime.start", "service.start",
                                      "service.stop", "runtime.stop"}));
}

TEST(FirmwareBootCoordinatorTest, DefaultShutdownDoesNotStopRuntime) {
  Calls calls;
  FirmwareBootCoordinator coordinator(
      {true, true}, SuccessfulDependencies(calls));
  ASSERT_TRUE(coordinator.Start().ok());

  coordinator.Stop();

  EXPECT_EQ(calls.service_stops, 1U);
  EXPECT_EQ(calls.runtime_stops, 0U);
}

TEST(FirmwareBootCoordinatorTest, StopCleansRuntimeStartedWhileServiceDrains) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.stop_service = [&] {
    ++calls.service_stops;
    calls.Record("service.stop");
    ASSERT_TRUE(calls.runtime_start_callback);
    EXPECT_TRUE(calls.runtime_start_callback().ok());
  };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));
  ASSERT_TRUE(coordinator.Start().ok());

  coordinator.Stop();

  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"state", "service.start",
                                      "service.stop", "runtime.start",
                                      "runtime.stop"}));
}

}  // namespace
}  // namespace camera_firmware::boot
