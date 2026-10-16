#include "camera_firmware/boot/FirmwareBootCoordinator.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <mutex>
#include <stdexcept>
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
  unsigned int service_quiesces{0U};
  unsigned int service_stops{0U};
  unsigned int protection_checks{0U};
  unsigned int protection_allowed_reads{0U};
  bool protection_allows_runtime{true};
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
  dependencies.quiesce_service = [&] {
    ++calls.service_quiesces;
    calls.Record("service.quiesce");
  };
  dependencies.stop_service = [&] {
    ++calls.service_stops;
    calls.Record("service.stop");
  };
  dependencies.run_startup_protection_checks = [&] {
    ++calls.protection_checks;
    calls.Record("protection.check");
  };
  dependencies.protection_allows_runtime = [&] {
    ++calls.protection_allowed_reads;
    calls.Record("protection.allowed");
    return calls.protection_allows_runtime;
  };
  return dependencies;
}

TEST(FirmwareBootCoordinatorTest,
     SelfStoppedRuntimeCanBeRetriedButProtectionStillApplies) {
  Calls calls;
  bool needs_start = false;
  auto dependencies =
      SuccessfulDependencies(calls, security::DeviceState::kOperational);
  dependencies.runtime_needs_start = [&] { return needs_start; };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));
  ASSERT_TRUE(coordinator.Start().ok());
  ASSERT_TRUE(calls.runtime_start_callback().ok());
  EXPECT_EQ(calls.runtime_starts, 1U);
  needs_start = true;
  calls.protection_allows_runtime = false;
  EXPECT_FALSE(calls.runtime_start_callback().ok());
  EXPECT_EQ(calls.runtime_starts, 1U);
  calls.protection_allows_runtime = true;
  ASSERT_TRUE(calls.runtime_start_callback().ok());
  EXPECT_EQ(calls.runtime_starts, 2U);
}

TEST(FirmwareBootCoordinatorTest, DefaultStateStartsOnlyService) {
  Calls calls;
  FirmwareBootCoordinator coordinator({true, true},
                                      SuccessfulDependencies(calls));

  ASSERT_TRUE(coordinator.Start().ok());

  EXPECT_EQ(coordinator.State(), FirmwareBootState::kRunning);
  EXPECT_EQ(calls.ordered, (std::vector<std::string>{
                               "state", "protection.check", "service.start"}));
  EXPECT_EQ(calls.runtime_starts, 0U);
  ASSERT_TRUE(calls.runtime_start_callback);

  ASSERT_TRUE(calls.runtime_start_callback().ok());
  EXPECT_EQ(calls.runtime_starts, 1U);
  EXPECT_EQ(calls.ordered, (std::vector<std::string>{
                               "state", "protection.check", "service.start",
                               "protection.allowed", "runtime.start"}));
}

TEST(FirmwareBootCoordinatorTest, OperationalStateStartsServiceBeforeRuntime) {
  Calls calls;
  FirmwareBootCoordinator coordinator(
      {true, true},
      SuccessfulDependencies(calls, security::DeviceState::kOperational));

  ASSERT_TRUE(coordinator.Start().ok());

  EXPECT_EQ(calls.ordered, (std::vector<std::string>{
                               "state", "protection.check", "service.start",
                               "protection.allowed", "runtime.start"}));
  EXPECT_EQ(calls.runtime_starts, 1U);
  EXPECT_EQ(calls.service_starts, 1U);
}

TEST(FirmwareBootCoordinatorTest,
     RestrictedStartupStillStartsManagementServiceWithoutRuntime) {
  Calls calls;
  calls.protection_allows_runtime = false;
  FirmwareBootCoordinator coordinator(
      {true, true},
      SuccessfulDependencies(calls, security::DeviceState::kOperational));

  ASSERT_TRUE(coordinator.Start().ok());

  EXPECT_EQ(coordinator.State(), FirmwareBootState::kRunning);
  EXPECT_EQ(calls.protection_checks, 1U);
  EXPECT_EQ(calls.protection_allowed_reads, 1U);
  EXPECT_EQ(calls.service_starts, 1U);
  EXPECT_EQ(calls.runtime_starts, 0U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"state", "protection.check",
                                      "service.start", "protection.allowed"}));
}

TEST(FirmwareBootCoordinatorTest,
     RestrictedHeadlessStartupDoesNotStartRuntime) {
  Calls calls;
  calls.protection_allows_runtime = false;
  FirmwareBootCoordinator coordinator(
      {true, false},
      SuccessfulDependencies(calls, security::DeviceState::kOperational));

  ASSERT_TRUE(coordinator.Start().ok());

  EXPECT_EQ(calls.protection_checks, 1U);
  EXPECT_EQ(calls.protection_allowed_reads, 1U);
  EXPECT_EQ(calls.runtime_starts, 0U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"state", "protection.check",
                                      "protection.allowed"}));
}

TEST(FirmwareBootCoordinatorTest,
     ProtectionStopWaitsForInFlightRuntimeStartAndStopsOnce) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  std::promise<void> runtime_entered;
  const auto runtime_entered_future = runtime_entered.get_future().share();
  std::atomic_bool release_runtime{false};
  dependencies.start_runtime = [&] {
    ++calls.runtime_starts;
    calls.Record("runtime.start");
    runtime_entered.set_value();
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (!release_runtime.load() &&
           std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!release_runtime.load()) {
      return common::Result<void>::Err(
          {"E_TEST_TIMEOUT", "runtime start release timed out"});
    }
    return common::Result<void>::Ok();
  };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));
  ASSERT_TRUE(coordinator.Start().ok());
  ASSERT_TRUE(calls.runtime_start_callback);

  auto start = std::async(std::launch::async,
                          [&] { return calls.runtime_start_callback(); });
  ASSERT_EQ(runtime_entered_future.wait_for(std::chrono::milliseconds(250)),
            std::future_status::ready);
  auto stop = std::async(std::launch::async,
                         [&] { coordinator.StopRuntimeForProtection(); });

  EXPECT_EQ(stop.wait_for(std::chrono::milliseconds(250)),
            std::future_status::timeout);
  release_runtime.store(true);
  ASSERT_EQ(start.wait_for(std::chrono::milliseconds(500)),
            std::future_status::ready);
  ASSERT_TRUE(start.get().ok());
  ASSERT_EQ(stop.wait_for(std::chrono::milliseconds(500)),
            std::future_status::ready);
  stop.get();

  EXPECT_EQ(calls.runtime_starts, 1U);
  EXPECT_EQ(calls.runtime_stops, 1U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"state", "protection.check",
                                      "service.start", "protection.allowed",
                                      "runtime.start", "runtime.stop"}));
}

TEST(FirmwareBootCoordinatorTest,
     ProtectionStopInvalidatesAuthorizationReadBeforeStartAdmission) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  std::promise<void> authorization_read;
  const auto authorization_read_future =
      authorization_read.get_future().share();
  std::atomic_bool release_authorization{false};
  dependencies.protection_allows_runtime = [&] {
    ++calls.protection_allowed_reads;
    calls.Record("protection.allowed");
    const bool allowed = calls.protection_allows_runtime;
    authorization_read.set_value();
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (!release_authorization.load() &&
           std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return allowed;
  };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));
  ASSERT_TRUE(coordinator.Start().ok());
  ASSERT_TRUE(calls.runtime_start_callback);

  auto start = std::async(std::launch::async,
                          [&] { return calls.runtime_start_callback(); });
  ASSERT_EQ(authorization_read_future.wait_for(std::chrono::milliseconds(250)),
            std::future_status::ready);
  calls.protection_allows_runtime = false;
  auto protection_stop = std::async(
      std::launch::async, [&] { coordinator.StopRuntimeForProtection(); });
  const auto stop_status =
      protection_stop.wait_for(std::chrono::milliseconds(250));
  release_authorization.store(true);

  ASSERT_EQ(stop_status, std::future_status::ready);
  protection_stop.get();
  ASSERT_EQ(start.wait_for(std::chrono::milliseconds(500)),
            std::future_status::ready);
  const auto started = start.get();
  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_BOOT_PROTECTION_RESTRICTED");
  EXPECT_EQ(calls.runtime_starts, 0U);
  EXPECT_EQ(calls.runtime_stops, 0U);
}

TEST(FirmwareBootCoordinatorTest,
     ActiveProtectionStopBlocksNormalStopSecondStopAndStartAdmission) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  std::promise<void> runtime_stop_entered;
  const auto runtime_stop_entered_future =
      runtime_stop_entered.get_future().share();
  std::atomic_uint runtime_stop_calls{0U};
  std::atomic_bool release_runtime_stop{false};
  dependencies.stop_runtime = [&] {
    calls.Record("runtime.stop");
    if (runtime_stop_calls.fetch_add(1U) == 0U) {
      runtime_stop_entered.set_value();
    }
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(750);
    while (!release_runtime_stop.load() &&
           std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  };
  FirmwareBootCoordinator coordinator({false, true}, std::move(dependencies));
  ASSERT_TRUE(coordinator.Start().ok());
  ASSERT_TRUE(calls.runtime_start_callback);

  auto first_protection_stop = std::async(
      std::launch::async, [&] { coordinator.StopRuntimeForProtection(); });
  ASSERT_EQ(
      runtime_stop_entered_future.wait_for(std::chrono::milliseconds(250)),
      std::future_status::ready);
  auto normal_stop =
      std::async(std::launch::async, [&] { coordinator.Stop(); });
  auto second_protection_stop = std::async(
      std::launch::async, [&] { coordinator.StopRuntimeForProtection(); });
  auto start = std::async(std::launch::async,
                          [&] { return calls.runtime_start_callback(); });

  EXPECT_EQ(normal_stop.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  EXPECT_EQ(second_protection_stop.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  EXPECT_EQ(start.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  EXPECT_EQ(runtime_stop_calls.load(), 1U);
  release_runtime_stop.store(true);

  ASSERT_EQ(first_protection_stop.wait_for(std::chrono::milliseconds(500)),
            std::future_status::ready);
  first_protection_stop.get();
  ASSERT_EQ(second_protection_stop.wait_for(std::chrono::milliseconds(500)),
            std::future_status::ready);
  second_protection_stop.get();
  ASSERT_EQ(normal_stop.wait_for(std::chrono::milliseconds(500)),
            std::future_status::ready);
  normal_stop.get();
  ASSERT_EQ(start.wait_for(std::chrono::milliseconds(500)),
            std::future_status::ready);
  EXPECT_FALSE(start.get().ok());
  EXPECT_EQ(runtime_stop_calls.load(), 1U);
  EXPECT_EQ(calls.runtime_starts, 1U);
  EXPECT_EQ(coordinator.State(), FirmwareBootState::kStopped);
}

TEST(FirmwareBootCoordinatorTest,
     StartupProtectionExceptionStartsServiceWithoutRuntime) {
  Calls calls;
  auto dependencies =
      SuccessfulDependencies(calls, security::DeviceState::kOperational);
  dependencies.run_startup_protection_checks = [&] {
    ++calls.protection_checks;
    calls.Record("protection.check");
    throw std::runtime_error("injected startup protection failure");
  };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));

  ASSERT_TRUE(coordinator.Start().ok());

  EXPECT_EQ(coordinator.State(), FirmwareBootState::kRunning);
  EXPECT_EQ(calls.service_starts, 1U);
  EXPECT_EQ(calls.runtime_starts, 0U);
  EXPECT_EQ(calls.protection_allowed_reads, 0U);
  EXPECT_EQ(calls.ordered, (std::vector<std::string>{
                               "state", "protection.check", "service.start"}));
}

TEST(FirmwareBootCoordinatorTest, SecurityDisabledSkipsStateRead) {
  Calls calls;
  FirmwareBootCoordinator coordinator({false, true},
                                      SuccessfulDependencies(calls));

  ASSERT_TRUE(coordinator.Start().ok());

  EXPECT_EQ(calls.state_reads, 0U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"service.start", "runtime.start"}));
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

TEST(FirmwareBootCoordinatorTest,
     OperationalRuntimeFailureKeepsServiceRunningAndCanRetry) {
  Calls calls;
  auto dependencies =
      SuccessfulDependencies(calls, security::DeviceState::kOperational);
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

  auto started = coordinator.Start();

  ASSERT_TRUE(started.ok());
  EXPECT_EQ(coordinator.State(), FirmwareBootState::kRunning);
  EXPECT_EQ(calls.service_starts, 1U);
  EXPECT_EQ(calls.runtime_starts, 1U);
  EXPECT_EQ(calls.runtime_stops, 0U);
  ASSERT_TRUE(calls.runtime_start_callback);
  EXPECT_TRUE(calls.runtime_start_callback().ok());
  EXPECT_EQ(calls.runtime_starts, 2U);
}

TEST(FirmwareBootCoordinatorTest, HeadlessRuntimeFailureRemainsFatal) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.start_runtime = [&] {
    ++calls.runtime_starts;
    calls.Record("runtime.start");
    return common::Result<void>::Err(
        {"E_RUNTIME_START", "injected runtime failure"});
  };
  FirmwareBootCoordinator coordinator({false, false}, std::move(dependencies));

  auto started = coordinator.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_RUNTIME_START");
  EXPECT_EQ(coordinator.State(), FirmwareBootState::kStopped);
  EXPECT_EQ(calls.service_starts, 0U);
  EXPECT_EQ(calls.runtime_stops, 0U);
}

TEST(FirmwareBootCoordinatorTest, ServiceFailureDoesNotStartRuntime) {
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
            (std::vector<std::string>{"service.start", "service.quiesce",
                                      "service.stop"}));
  EXPECT_EQ(calls.runtime_starts, 0U);
  EXPECT_EQ(calls.runtime_stops, 0U);
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
  EXPECT_EQ(calls.service_quiesces, 1U);
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
  dependencies.quiesce_service = [&] {
    ++calls.service_quiesces;
    calls.Record("service.quiesce");
    release_runtime.set_value();
    transition.join();
  };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));

  auto started = coordinator.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_TRUE(transition_ok);
  EXPECT_EQ(calls.runtime_starts, 1U);
  EXPECT_EQ(calls.runtime_stops, 1U);
  EXPECT_EQ(
      calls.ordered,
      (std::vector<std::string>{
          "state", "protection.check", "service.start", "protection.allowed",
          "runtime.start", "service.quiesce", "runtime.stop", "service.stop"}));
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
  FirmwareBootCoordinator coordinator({false, true},
                                      SuccessfulDependencies(calls));

  ASSERT_TRUE(coordinator.Start().ok());
  ASSERT_TRUE(coordinator.Start().ok());
  coordinator.Stop();
  coordinator.Stop();

  EXPECT_EQ(coordinator.State(), FirmwareBootState::kStopped);
  EXPECT_EQ(calls.runtime_starts, 1U);
  EXPECT_EQ(calls.service_starts, 1U);
  EXPECT_EQ(calls.service_quiesces, 1U);
  EXPECT_EQ(calls.service_stops, 1U);
  EXPECT_EQ(calls.runtime_stops, 1U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"service.start", "runtime.start",
                                      "service.quiesce", "runtime.stop",
                                      "service.stop"}));
}

TEST(FirmwareBootCoordinatorTest, DefaultShutdownDoesNotStopRuntime) {
  Calls calls;
  FirmwareBootCoordinator coordinator({true, true},
                                      SuccessfulDependencies(calls));
  ASSERT_TRUE(coordinator.Start().ok());

  coordinator.Stop();

  EXPECT_EQ(calls.service_stops, 1U);
  EXPECT_EQ(calls.service_quiesces, 1U);
  EXPECT_EQ(calls.runtime_stops, 0U);
}

TEST(FirmwareBootCoordinatorTest, StopProhibitsRuntimeTransitionBeforeQuiesce) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.quiesce_service = [&] {
    ++calls.service_quiesces;
    calls.Record("service.quiesce");
    ASSERT_TRUE(calls.runtime_start_callback);
    const auto transition = calls.runtime_start_callback();
    EXPECT_FALSE(transition.ok());
    EXPECT_EQ(transition.error().code, "E_BOOT_TRANSITION");
  };
  FirmwareBootCoordinator coordinator({true, true}, std::move(dependencies));
  ASSERT_TRUE(coordinator.Start().ok());

  coordinator.Stop();

  EXPECT_EQ(calls.ordered, (std::vector<std::string>{
                               "state", "protection.check", "service.start",
                               "service.quiesce", "service.stop"}));
}

TEST(FirmwareBootCoordinatorTest,
     RuntimeStopWakesBlockedLiveStreamBeforeServiceJoin) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  std::promise<void> release_stream;
  auto stream_released = release_stream.get_future().share();
  dependencies.stop_runtime = [&] {
    ++calls.runtime_stops;
    calls.Record("runtime.stop");
    release_stream.set_value();
  };
  dependencies.stop_service = [&] {
    ++calls.service_stops;
    calls.Record("service.stop");
    stream_released.wait();
  };
  FirmwareBootCoordinator coordinator({false, true}, std::move(dependencies));
  ASSERT_TRUE(coordinator.Start().ok());

  auto stopped = std::async(std::launch::async, [&] { coordinator.Stop(); });
  const auto status = stopped.wait_for(std::chrono::milliseconds(250));
  if (status != std::future_status::ready) {
    try {
      release_stream.set_value();
    } catch (...) {
    }
  }
  EXPECT_EQ(status, std::future_status::ready);
  stopped.wait();

  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"service.start", "runtime.start",
                                      "service.quiesce", "runtime.stop",
                                      "service.stop"}));
}

TEST(FirmwareBootCoordinatorTest, StopContinuesWhenDependenciesThrow) {
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.quiesce_service = [&] {
    ++calls.service_quiesces;
    calls.Record("service.quiesce");
    throw std::runtime_error("injected quiesce failure");
  };
  dependencies.stop_runtime = [&] {
    ++calls.runtime_stops;
    calls.Record("runtime.stop");
    throw std::runtime_error("injected runtime stop failure");
  };
  FirmwareBootCoordinator coordinator({false, true}, std::move(dependencies));
  ASSERT_TRUE(coordinator.Start().ok());

  coordinator.Stop();
  coordinator.Stop();

  EXPECT_EQ(coordinator.State(), FirmwareBootState::kStopped);
  EXPECT_EQ(calls.service_quiesces, 1U);
  EXPECT_EQ(calls.runtime_stops, 1U);
  EXPECT_EQ(calls.service_stops, 1U);
}

}  // namespace
}  // namespace camera_firmware::boot
