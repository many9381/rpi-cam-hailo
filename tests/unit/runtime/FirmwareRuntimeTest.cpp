#include "camera_firmware/runtime/FirmwareRuntime.hpp"

#include <atomic>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace camera_firmware::runtime {

class FirmwareRuntimeTestAccess {
 public:
  static bool DependenciesComplete(const FirmwareRuntime& runtime) {
    return runtime.DependenciesComplete();
  }
};

namespace {

struct Calls {
  void Record(std::string call) {
    std::lock_guard lock(mutex);
    ordered.push_back(std::move(call));
  }

  mutable std::mutex mutex;
  std::vector<std::string> ordered;
  std::atomic<unsigned int> rtsp_starts{0U};
  std::atomic<unsigned int> ai_starts{0U};
  std::atomic<unsigned int> camera_starts{0U};
  std::atomic<unsigned int> rtsp_stops{0U};
  std::atomic<unsigned int> ai_stops{0U};
  std::atomic<unsigned int> camera_stops{0U};
  std::atomic<unsigned int> provider_calls{0U};
};

FirmwareRuntimeDependencies SuccessfulDependencies(Calls& calls) {
  FirmwareRuntimeDependencies dependencies;
  dependencies.start_rtsp = [&] {
    calls.rtsp_starts.fetch_add(1U);
    calls.Record("rtsp.start");
    return common::Result<void>::Ok();
  };
  dependencies.start_ai = [&] {
    calls.ai_starts.fetch_add(1U);
    calls.Record("ai.start");
    return common::Result<void>::Ok();
  };
  dependencies.start_camera = [&] {
    calls.camera_starts.fetch_add(1U);
    calls.Record("camera.start");
    return common::Result<void>::Ok();
  };
  dependencies.stop_camera = [&] {
    calls.camera_stops.fetch_add(1U);
    calls.Record("camera.stop");
  };
  dependencies.stop_ai = [&] {
    calls.ai_stops.fetch_add(1U);
    calls.Record("ai.stop");
  };
  dependencies.stop_rtsp = [&] {
    calls.rtsp_stops.fetch_add(1U);
    calls.Record("rtsp.stop");
  };
  return dependencies;
}

TEST(FirmwareRuntimeTest, StartsAndStopsEachComponentExactlyOnce) {
  config::AppConfig config;
  Calls calls;
  FirmwareRuntime runtime(config, SuccessfulDependencies(calls));

  ASSERT_TRUE(runtime.Start().ok());
  ASSERT_TRUE(runtime.Start().ok());
  EXPECT_EQ(runtime.State(), FirmwareRuntimeState::kRunning);
  EXPECT_EQ(calls.rtsp_starts.load(), 1U);
  EXPECT_EQ(calls.ai_starts.load(), 1U);
  EXPECT_EQ(calls.camera_starts.load(), 1U);

  runtime.Stop();
  runtime.Stop();

  EXPECT_EQ(runtime.State(), FirmwareRuntimeState::kStopped);
  EXPECT_EQ(calls.camera_stops.load(), 1U);
  EXPECT_EQ(calls.ai_stops.load(), 1U);
  EXPECT_EQ(calls.rtsp_stops.load(), 1U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"rtsp.start", "ai.start",
                                      "camera.start", "camera.stop",
                                      "ai.stop", "rtsp.stop"}));
}

TEST(FirmwareRuntimeTest, PartialFailureUnwindsStartedComponentsInReverseOrder) {
  config::AppConfig config;
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.start_camera = [&] {
    calls.camera_starts.fetch_add(1U);
    calls.Record("camera.start");
    return common::Result<void>::Err(
        {"E_CAMERA_START", "injected camera failure"});
  };
  FirmwareRuntime runtime(config, std::move(dependencies));

  auto started = runtime.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_CAMERA_START");
  EXPECT_EQ(runtime.State(), FirmwareRuntimeState::kFailed);
  EXPECT_EQ(calls.camera_stops.load(), 0U);
  EXPECT_EQ(calls.ai_stops.load(), 1U);
  EXPECT_EQ(calls.rtsp_stops.load(), 1U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"rtsp.start", "ai.start",
                                      "camera.start", "ai.stop",
                                      "rtsp.stop"}));
}

TEST(FirmwareRuntimeTest, StoppedProvidersReturnSafeValuesWithoutCallbacks) {
  config::AppConfig config;
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.camera_statuses = [&] {
    calls.provider_calls.fetch_add(1U);
    return std::vector<media::CameraPipelineStatus>{{"camera", "running", true}};
  };
  dependencies.restart_ai = [&] {
    calls.provider_calls.fetch_add(1U);
    return common::Result<void>::Ok();
  };
  dependencies.snapshot = [&](std::string_view) {
    calls.provider_calls.fetch_add(1U);
    return std::optional<std::vector<std::uint8_t>>{{1U, 2U, 3U}};
  };
  FirmwareRuntime runtime(config, std::move(dependencies));

  EXPECT_TRUE(runtime.CameraStatuses().empty());
  EXPECT_EQ(runtime.AiStatus().state, "stopped");
  EXPECT_TRUE(runtime.AiRunnerStatuses().empty());
  EXPECT_FALSE(runtime.RestartAi().ok());
  EXPECT_FALSE(runtime.Snapshot("camera").has_value());
  EXPECT_TRUE(runtime.DetectionSnapshot().empty());
  EXPECT_FALSE(runtime.SubscribeDetections([](const ai::DetectionEvent&) {}).valid());
  EXPECT_EQ(runtime.PerMediaKeyZeroizeCount(), 0U);
  EXPECT_EQ(calls.provider_calls.load(), 0U);
}

TEST(FirmwareRuntimeTest, RunningProvidersDelegateToOwnedDependencies) {
  config::AppConfig config;
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.camera_statuses = [&] {
    calls.provider_calls.fetch_add(1U);
    return std::vector<media::CameraPipelineStatus>{{"camera", "running", true}};
  };
  dependencies.ai_status = [&] {
    calls.provider_calls.fetch_add(1U);
    ai::AiRuntimeStatus status;
    status.enabled = true;
    status.state = "running";
    return status;
  };
  dependencies.restart_ai = [&] {
    calls.provider_calls.fetch_add(1U);
    return common::Result<void>::Ok();
  };
  dependencies.snapshot = [&](std::string_view camera_id) {
    calls.provider_calls.fetch_add(1U);
    if (camera_id == "camera") {
      return std::optional<std::vector<std::uint8_t>>{{1U, 2U, 3U}};
    }
    return std::optional<std::vector<std::uint8_t>>{};
  };
  dependencies.per_media_key_zeroize_count = [&] {
    calls.provider_calls.fetch_add(1U);
    return 7U;
  };
  FirmwareRuntime runtime(config, std::move(dependencies));
  ASSERT_TRUE(runtime.Start().ok());

  ASSERT_EQ(runtime.CameraStatuses().size(), 1U);
  EXPECT_EQ(runtime.AiStatus().state, "running");
  EXPECT_TRUE(runtime.RestartAi().ok());
  EXPECT_EQ(runtime.Snapshot("camera"),
            (std::optional<std::vector<std::uint8_t>>{{1U, 2U, 3U}}));
  EXPECT_EQ(runtime.PerMediaKeyZeroizeCount(), 7U);
  EXPECT_EQ(calls.provider_calls.load(), 5U);
}

TEST(FirmwareRuntimeTest, ConcurrentStartsAreSerializedAndIdempotent) {
  config::AppConfig config;
  Calls calls;
  FirmwareRuntime runtime(config, SuccessfulDependencies(calls));
  std::atomic<unsigned int> failures{0U};
  std::vector<std::thread> starters;
  for (int index = 0; index < 8; ++index) {
    starters.emplace_back([&] {
      if (!runtime.Start().ok()) {
        failures.fetch_add(1U);
      }
    });
  }
  for (auto& starter : starters) {
    starter.join();
  }

  EXPECT_EQ(failures.load(), 0U);
  EXPECT_EQ(calls.rtsp_starts.load(), 1U);
  EXPECT_EQ(calls.ai_starts.load(), 1U);
  EXPECT_EQ(calls.camera_starts.load(), 1U);
  runtime.Stop();
}

TEST(FirmwareRuntimeTest, CanStartAgainAfterStop) {
  config::AppConfig config;
  Calls calls;
  FirmwareRuntime runtime(config, SuccessfulDependencies(calls));

  ASSERT_TRUE(runtime.Start().ok());
  runtime.Stop();
  ASSERT_TRUE(runtime.Start().ok());
  runtime.Stop();

  EXPECT_EQ(runtime.State(), FirmwareRuntimeState::kStopped);
  EXPECT_EQ(calls.rtsp_starts.load(), 2U);
  EXPECT_EQ(calls.ai_starts.load(), 2U);
  EXPECT_EQ(calls.camera_starts.load(), 2U);
  EXPECT_EQ(calls.camera_stops.load(), 2U);
  EXPECT_EQ(calls.ai_stops.load(), 2U);
  EXPECT_EQ(calls.rtsp_stops.load(), 2U);
}

TEST(FirmwareRuntimeTest, StopContinuesUnwindWhenCallbacksThrow) {
  config::AppConfig config;
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.stop_camera = [&] {
    calls.camera_stops.fetch_add(1U);
    calls.Record("camera.stop");
    throw std::runtime_error("injected camera stop failure");
  };
  dependencies.stop_ai = [&] {
    calls.ai_stops.fetch_add(1U);
    calls.Record("ai.stop");
    throw std::runtime_error("injected AI stop failure");
  };
  FirmwareRuntime runtime(config, std::move(dependencies));
  ASSERT_TRUE(runtime.Start().ok());

  runtime.Stop();

  EXPECT_EQ(runtime.State(), FirmwareRuntimeState::kStopped);
  EXPECT_EQ(calls.camera_stops.load(), 1U);
  EXPECT_EQ(calls.ai_stops.load(), 1U);
  EXPECT_EQ(calls.rtsp_stops.load(), 1U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"rtsp.start", "ai.start",
                                      "camera.start", "camera.stop",
                                      "ai.stop", "rtsp.stop"}));
}

TEST(FirmwareRuntimeTest, ProductionConstructorOwnsCompleteComponentGraph) {
  config::AppConfig config;

  FirmwareRuntime runtime(config);

  EXPECT_TRUE(FirmwareRuntimeTestAccess::DependenciesComplete(runtime));
  EXPECT_EQ(runtime.State(), FirmwareRuntimeState::kStopped);
}

TEST(FirmwareRuntimeTest, MissingStopDependencyFailsBeforeStartingComponents) {
  config::AppConfig config;
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.stop_rtsp = {};
  FirmwareRuntime runtime(config, std::move(dependencies));

  auto started = runtime.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_RUNTIME_DEPENDENCY");
  EXPECT_EQ(runtime.State(), FirmwareRuntimeState::kFailed);
  EXPECT_EQ(calls.rtsp_starts.load(), 0U);
  EXPECT_EQ(calls.ai_starts.load(), 0U);
  EXPECT_EQ(calls.camera_starts.load(), 0U);
}

}  // namespace
}  // namespace camera_firmware::runtime
