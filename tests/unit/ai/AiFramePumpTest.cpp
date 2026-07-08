#include "camera_firmware/ai/AiFramePump.hpp"

#include <chrono>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

#include "camera_firmware/ai/AiFrameTap.hpp"
#include "camera_firmware/ai/AiRuntime.hpp"
#include "camera_firmware/ai/DetectionBus.hpp"

namespace {

camera_firmware::config::AppConfig PumpRuntimeConfig() {
  camera_firmware::config::AppConfig config;
  config.ai.enabled = true;
  config.ai.backend = "hailo";

  camera_firmware::config::AiModelConfig model;
  model.id = "objects";
  model.kind = "object_detection";
  model.hef_path = "/opt/cf/models/objects.hef";
  model.input.width = 640;
  model.input.height = 640;
  model.input.format = "rgb8";
  config.ai.models.push_back(model);

  config.camera.ai.enabled = true;
  config.camera.ai.model_ids = {"objects"};
  return config;
}

std::shared_ptr<camera_firmware::ai::AiBackend> PumpUnavailableBackend() {
  return std::make_shared<camera_firmware::ai::UnavailableAiBackend>();
}

bool WaitForRunnerSubmitCount(camera_firmware::ai::AiRuntime& runtime,
                              std::uint64_t expected_submits) {
  for (int attempt = 0; attempt < 100; ++attempt) {
    const auto runners = runtime.RunnerStatuses();
    if (runners.size() == 1U &&
        runners[0].submitted_frames >= expected_submits) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return false;
}

bool WaitForRunnerSubmit(camera_firmware::ai::AiRuntime& runtime) {
  return WaitForRunnerSubmitCount(runtime, 1);
}

}  // namespace

TEST(AiFramePumpTest, ForwardsPublishedTapFrameToRuntimeRunner) {
  camera_firmware::ai::AiFrameTap tap;
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(&bus, PumpUnavailableBackend());
  ASSERT_TRUE(runtime.Start(PumpRuntimeConfig()).ok());

  camera_firmware::ai::AiFramePump pump(tap, runtime);
  ASSERT_TRUE(pump.Start().ok());

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 640;
  handle.height = 480;
  handle.sequence = 44;
  tap.PublishLatest(camera_firmware::media::FrameLease(handle, [] {}));

  EXPECT_TRUE(WaitForRunnerSubmit(runtime));
  pump.Stop();
  runtime.Stop();
}

TEST(AiFramePumpTest, StopPreventsFutureRuntimeSubmits) {
  camera_firmware::ai::AiFrameTap tap;
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(&bus, PumpUnavailableBackend());
  ASSERT_TRUE(runtime.Start(PumpRuntimeConfig()).ok());

  camera_firmware::ai::AiFramePump pump(tap, runtime);
  ASSERT_TRUE(pump.Start().ok());

  camera_firmware::media::FrameHandle first;
  first.camera_id = "imx708-main";
  first.format = "NV12";
  first.width = 640;
  first.height = 480;
  first.sequence = 45;
  tap.PublishLatest(camera_firmware::media::FrameLease(first, [] {}));
  ASSERT_TRUE(WaitForRunnerSubmitCount(runtime, 1));

  pump.Stop();

  camera_firmware::media::FrameHandle second = first;
  second.sequence = 46;
  tap.PublishLatest(camera_firmware::media::FrameLease(second, [] {}));
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  const auto runners = runtime.RunnerStatuses();
  ASSERT_EQ(runners.size(), 1U);
  EXPECT_EQ(runners[0].submitted_frames, 1U);
  runtime.Stop();
}

TEST(AiFramePumpTest, CanRestartAfterStop) {
  camera_firmware::ai::AiFrameTap tap;
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(&bus, PumpUnavailableBackend());
  ASSERT_TRUE(runtime.Start(PumpRuntimeConfig()).ok());

  camera_firmware::ai::AiFramePump pump(tap, runtime);
  ASSERT_TRUE(pump.Start().ok());
  EXPECT_FALSE(pump.Start().ok());
  pump.Stop();
  ASSERT_TRUE(pump.Start().ok());

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 640;
  handle.height = 480;
  handle.sequence = 47;
  tap.PublishLatest(camera_firmware::media::FrameLease(handle, [] {}));

  EXPECT_TRUE(WaitForRunnerSubmitCount(runtime, 1));
  pump.Stop();
  runtime.Stop();
}

TEST(AiFramePumpTest, KeepsFrameLeaseUntilTapDropsLatestFrame) {
  int releases = 0;
  {
    camera_firmware::ai::AiFrameTap tap;
    camera_firmware::ai::DetectionBus bus;
    camera_firmware::ai::AiRuntime runtime(&bus, PumpUnavailableBackend());
    ASSERT_TRUE(runtime.Start(PumpRuntimeConfig()).ok());

    camera_firmware::ai::AiFramePump pump(tap, runtime);
    ASSERT_TRUE(pump.Start().ok());

    camera_firmware::media::FrameHandle handle;
    handle.camera_id = "imx708-main";
    handle.format = "NV12";
    handle.width = 640;
    handle.height = 480;
    handle.sequence = 48;
    tap.PublishLatest(
        camera_firmware::media::FrameLease(handle, [&releases] {
          ++releases;
        }));
    ASSERT_TRUE(WaitForRunnerSubmitCount(runtime, 1));

    pump.Stop();
    runtime.Stop();
    EXPECT_EQ(releases, 0);
  }

  EXPECT_EQ(releases, 1);
}
