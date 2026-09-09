#include "camera_firmware/ai/AiFramePump.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

#include <unistd.h>

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

// A backend that always succeeds synchronously with an empty detection
// output. Paired with a valid (fd-backed) NV12 frame lease, this lets
// AiModelRunner run the full preprocess/submit/postprocess path so that
// AiModelRunnerStatus::last_processed_sequence reflects which frame the
// pump actually handed to the runtime -- unlike UnavailableAiBackend,
// where every submission is dropped before a sequence is ever recorded.
class SucceedingAiBackend final : public camera_firmware::ai::AiBackend {
 public:
  [[nodiscard]] std::string_view name() const noexcept override {
    return "hailo";
  }

  [[nodiscard]] bool available() const noexcept override { return true; }

  [[nodiscard]] camera_firmware::common::Result<void> Init() override {
    return camera_firmware::common::Result<void>::Ok();
  }

  void Shutdown() override {}

  [[nodiscard]] camera_firmware::common::Result<
      camera_firmware::ai::ModelHandle>
  LoadModel(const camera_firmware::config::AiModelConfig&) override {
    return camera_firmware::common::Result<
        camera_firmware::ai::ModelHandle>::Ok(1);
  }

  void Unload(camera_firmware::ai::ModelHandle) override {}

  [[nodiscard]] camera_firmware::common::Result<void> Submit(
      camera_firmware::ai::ModelHandle, camera_firmware::ai::InputView,
      camera_firmware::ai::InferCallback callback) override {
    if (callback) {
      callback(
          camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
              {}));
    }
    return camera_firmware::common::Result<void>::Ok();
  }
};

int CreateGatingAnonymousFile(const std::vector<std::uint8_t>& bytes) {
  std::array<char, 32> path{"/tmp/cf-ai-pump-XXXXXX"};
  int fd = ::mkstemp(path.data());
  if (fd < 0) {
    return -1;
  }
  (void)::unlink(path.data());
  if (::ftruncate(fd, static_cast<off_t>(bytes.size())) != 0) {
    (void)::close(fd);
    return -1;
  }
  if (::write(fd, bytes.data(), bytes.size()) !=
      static_cast<ssize_t>(bytes.size())) {
    (void)::close(fd);
    return -1;
  }
  return fd;
}

// A minimal but real (fd-backed) 8x4 NV12 frame, so AiModelRunner's
// preprocess step actually succeeds instead of dropping the frame before
// a sequence number is ever recorded.
camera_firmware::media::FrameLease GatingNv12Lease(std::uint64_t sequence) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(8U * 4U + 8U * 2U);
  bytes.insert(bytes.end(), 8U * 4U, 16U);
  bytes.insert(bytes.end(), 8U * 2U, 128U);
  const int fd = CreateGatingAnonymousFile(bytes);

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 8;
  handle.height = 4;
  handle.sequence = sequence;
  handle.plane_count = 2;
  handle.planes[0].dmabuf_fd = fd;
  handle.planes[0].stride = 8;
  handle.planes[0].length = 32;
  handle.planes[0].offset = 0;
  handle.planes[1].dmabuf_fd = fd;
  handle.planes[1].stride = 8;
  handle.planes[1].length = 16;
  handle.planes[1].offset = handle.planes[0].length;

  return camera_firmware::media::FrameLease(std::move(handle), [fd] {
    if (fd >= 0) {
      (void)::close(fd);
    }
  });
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

TEST(AiFramePumpTest, ForwardedFrameLeaseIsReleasedNotRetained) {
  // Pull-on-ready: the tap retains nothing with the pump subscribed, and
  // the pump forwards without holding the lease in a rate gate, so a
  // published frame's lease is released once the runner is done with it --
  // no lease pins a buffer across the idle gap.
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
    tap.PublishLatest(camera_firmware::media::FrameLease(
        handle, [&releases] { ++releases; }));
    ASSERT_TRUE(WaitForRunnerSubmitCount(runtime, 1));

    pump.Stop();
    runtime.Stop();
  }
  EXPECT_EQ(releases, 1);  // released exactly once, no leak, no double
}

TEST(AiFramePumpTest, ReArmsTapDemandEvenWhenFrameIsDropped) {
  // A frame dropped before submission (unavailable backend) must still
  // re-arm the pull demand, or AI would stall after one frame.
  camera_firmware::ai::AiFrameTap tap;
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(&bus, PumpUnavailableBackend());
  ASSERT_TRUE(runtime.Start(PumpRuntimeConfig()).ok());

  camera_firmware::ai::AiFramePump pump(tap, runtime);
  ASSERT_TRUE(pump.Start().ok());

  EXPECT_TRUE(tap.ConsumeDemand());  // drain initial arm
  EXPECT_FALSE(tap.ConsumeDemand());

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 640;
  handle.height = 480;
  handle.sequence = 71;
  tap.PublishLatest(camera_firmware::media::FrameLease(handle, [] {}));

  bool re_armed = false;
  for (int attempt = 0; attempt < 200; ++attempt) {
    if (tap.ConsumeDemand()) {
      re_armed = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  EXPECT_TRUE(re_armed);

  pump.Stop();
  runtime.Stop();
}

TEST(AiFramePumpTest, ReArmsTapDemandAfterInferenceCompletes) {
  // The pump wires the runtime's ready callback so that finishing an
  // inference re-arms the tap's pull demand for the next frame.
  camera_firmware::ai::AiFrameTap tap;
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(
      &bus, std::make_shared<SucceedingAiBackend>());
  ASSERT_TRUE(runtime.Start(PumpRuntimeConfig()).ok());

  camera_firmware::ai::AiFramePump pump(tap, runtime);
  ASSERT_TRUE(pump.Start().ok());

  // Drain the initial armed demand so we observe the RE-arm, not the
  // starting state.
  EXPECT_TRUE(tap.ConsumeDemand());
  EXPECT_FALSE(tap.ConsumeDemand());

  tap.PublishLatest(GatingNv12Lease(600));

  // After the succeeding backend completes the inference, the pump's ready
  // callback must have re-armed the demand.
  bool re_armed = false;
  for (int attempt = 0; attempt < 200; ++attempt) {
    if (tap.ConsumeDemand()) {
      re_armed = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  EXPECT_TRUE(re_armed);

  pump.Stop();
  runtime.Stop();
}
