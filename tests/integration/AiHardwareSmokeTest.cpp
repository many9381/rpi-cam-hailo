#include "camera_firmware/ai/AiRuntime.hpp"
#include "camera_firmware/ai/DetectionBus.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/FrameLease.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

bool HailoHardwareSmokeEnabled() {
  const char* value = std::getenv("CF_RUN_HAILO_HARDWARE_SMOKE");
  return value != nullptr && std::string(value) == "1";
}

int CreateAnonymousFrameFile(const std::vector<std::uint8_t>& bytes) {
  std::array<char, 32> path{"/tmp/cf-ai-hw-XXXXXX"};
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

camera_firmware::media::FrameLease SyntheticNv12Frame(
    std::uint64_t sequence) {
  constexpr std::uint32_t kWidth = 8;
  constexpr std::uint32_t kHeight = 4;
  constexpr std::size_t kYSize = kWidth * kHeight;
  constexpr std::size_t kUvSize = kWidth * (kHeight / 2U);

  std::vector<std::uint8_t> bytes;
  bytes.reserve(kYSize + kUvSize);
  bytes.insert(bytes.end(), kYSize, 16U);
  bytes.insert(bytes.end(), kUvSize, 128U);

  const int fd = CreateAnonymousFrameFile(bytes);
  if (fd < 0) {
    return {};
  }

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = kWidth;
  handle.height = kHeight;
  handle.sequence = sequence;
  handle.timestamp = std::chrono::nanoseconds(sequence);
  handle.plane_count = 2;
  handle.planes[0].dmabuf_fd = fd;
  handle.planes[0].offset = 0;
  handle.planes[0].length = kYSize;
  handle.planes[0].stride = kWidth;
  handle.planes[1].dmabuf_fd = fd;
  handle.planes[1].offset = kYSize;
  handle.planes[1].length = kUvSize;
  handle.planes[1].stride = kWidth;

  return camera_firmware::media::FrameLease(std::move(handle), [fd] {
    (void)::close(fd);
  });
}

bool WaitForProcessedOrDropped(camera_firmware::ai::AiRuntime& runtime) {
  for (int attempt = 0; attempt < 500; ++attempt) {
    const auto runners = runtime.RunnerStatuses();
    if (runners.size() == 1U &&
        (runners[0].processed_frames >= 1U ||
         runners[0].dropped_frames >= 1U)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return false;
}

std::string RunnerStatusMessage(
    const std::vector<camera_firmware::ai::AiModelRunnerStatus>& runners) {
  std::ostringstream stream;
  stream << "runner_count=" << runners.size();
  for (const auto& runner : runners) {
    stream << " [" << runner.camera_id << "/" << runner.model_id
           << " submitted=" << runner.submitted_frames
           << " processed=" << runner.processed_frames
           << " dropped=" << runner.dropped_frames
           << " last_error=" << runner.last_error_code << ": "
           << runner.last_error_message << "]";
  }
  return stream.str();
}

}  // namespace

TEST(AiHardwareSmokeTest, StartsConfiguredHailoRuntimeWhenEnabled) {
  if (!HailoHardwareSmokeEnabled()) {
    GTEST_SKIP()
        << "set CF_RUN_HAILO_HARDWARE_SMOKE=1 to require Hailo hardware";
  }

#if !defined(CF_HAVE_HAILORT)
  FAIL() << "CF_RUN_HAILO_HARDWARE_SMOKE=1 requires a build with HailoRT";
#else
  auto config =
      camera_firmware::config::LoadConfigFile("config/app-rpi5-ai-dev.yaml");
  ASSERT_TRUE(config.ok()) << config.error().message;
  ASSERT_TRUE(config.value().ai.enabled);
  ASSERT_EQ(config.value().ai.backend, "hailo");
  ASSERT_EQ(config.value().ai.models.size(), 1u);
  ASSERT_EQ(config.value().camera.ai.model_ids.size(), 1u);
  ASSERT_EQ(config.value().camera.ai.model_ids[0],
            config.value().ai.models[0].id);

  const std::filesystem::path hef_path{config.value().ai.models[0].hef_path};
  ASSERT_TRUE(std::filesystem::exists(hef_path))
      << "missing Hailo model: " << hef_path;

  camera_firmware::ai::DetectionBus detection_bus;
  camera_firmware::ai::AiRuntime runtime(&detection_bus);

  auto started = runtime.Start(config.value());
  ASSERT_TRUE(started.ok()) << started.error().message;

  const auto status = runtime.Status();
  EXPECT_TRUE(status.enabled);
  EXPECT_EQ(status.backend, "hailo");
  EXPECT_TRUE(status.backend_available)
      << status.last_error_code << ": " << status.last_error_message;
  ASSERT_EQ(status.state, "ready")
      << status.last_error_code << ": " << status.last_error_message;
  EXPECT_EQ(status.model_count, 1u);
  EXPECT_EQ(status.runner_count, 1u);
  EXPECT_TRUE(status.last_error_code.empty()) << status.last_error_message;

  const auto runners = runtime.RunnerStatuses();
  ASSERT_EQ(runners.size(), 1u);
  EXPECT_EQ(runners[0].camera_id, "imx708-main");
  EXPECT_EQ(runners[0].model_id, "objects");
  EXPECT_EQ(runners[0].model_kind, "object_detection");

  runtime.Stop();
#endif
}

TEST(AiHardwareSmokeTest, SubmitsSyntheticNv12FrameWhenEnabled) {
  if (!HailoHardwareSmokeEnabled()) {
    GTEST_SKIP()
        << "set CF_RUN_HAILO_HARDWARE_SMOKE=1 to require Hailo hardware";
  }

#if !defined(CF_HAVE_HAILORT)
  FAIL() << "CF_RUN_HAILO_HARDWARE_SMOKE=1 requires a build with HailoRT";
#else
  auto config =
      camera_firmware::config::LoadConfigFile("config/app-rpi5-ai-dev.yaml");
  ASSERT_TRUE(config.ok()) << config.error().message;
  ASSERT_EQ(config.value().ai.models.size(), 1u);
  ASSERT_TRUE(
      std::filesystem::exists(config.value().ai.models[0].hef_path))
      << "missing Hailo model: " << config.value().ai.models[0].hef_path;

  camera_firmware::ai::DetectionBus detection_bus;
  auto runtime =
      std::make_unique<camera_firmware::ai::AiRuntime>(&detection_bus);
  auto started = runtime->Start(config.value());
  ASSERT_TRUE(started.ok()) << started.error().message;

  const auto started_status = runtime->Status();
  ASSERT_EQ(started_status.state, "ready")
      << started_status.last_error_code << ": "
      << started_status.last_error_message;
  ASSERT_EQ(started_status.runner_count, 1u);

  auto submitted = runtime->SubmitFrame(SyntheticNv12Frame(1));
  ASSERT_TRUE(submitted.ok()) << submitted.error().message;
  if (!WaitForProcessedOrDropped(*runtime)) {
    ADD_FAILURE() << "timed out waiting for Hailo inference callback; "
                  << RunnerStatusMessage(runtime->RunnerStatuses());
    (void)runtime.release();
    return;
  }

  const auto runners = runtime->RunnerStatuses();
  ASSERT_EQ(runners.size(), 1u);
  EXPECT_EQ(runners[0].submitted_frames, 1u);
  EXPECT_EQ(runners[0].processed_frames, 1u)
      << runners[0].last_error_code << ": "
      << runners[0].last_error_message;
  EXPECT_EQ(runners[0].dropped_frames, 0u)
      << runners[0].last_error_code << ": "
      << runners[0].last_error_message;

  runtime->Stop();
#endif
}
