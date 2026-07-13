#include "camera_firmware/media/CameraPipeline.hpp"

#include "camera_firmware/ai/AiFrameTap.hpp"

#include <chrono>
#include <cstdlib>
#include <sstream>
#include <string>
#include <thread>

#include <gtest/gtest.h>

namespace {

bool CameraHardwareSmokeEnabled() {
  const char* value = std::getenv("CF_RUN_CAMERA_HARDWARE_SMOKE");
  return value != nullptr && std::string(value) == "1";
}

bool Meets1080p50Acceptance(
    const camera_firmware::media::CameraPipelineStatus& status) {
  return status.state == "running" && status.width == 1920U &&
         status.height == 1080U && status.configured_fps == 50U &&
         status.captured_frames >= 100U && status.encoded_frames >= 95U &&
         status.capture_fps >= 45.0 && status.encoded_fps >= 45.0;
}

std::string StatusMessage(
    const camera_firmware::media::CameraPipelineStatus& status) {
  std::ostringstream stream;
  stream << status.width << "x" << status.height
         << " configured_fps=" << status.configured_fps
         << " capture_fps=" << status.capture_fps
         << " encoded_fps=" << status.encoded_fps
         << " captured=" << status.captured_frames
         << " encoded=" << status.encoded_frames
         << " capture_errors=" << status.capture_error_count
         << " encode_errors=" << status.encode_error_count;
  return stream.str();
}

}  // namespace

TEST(CameraPipelineHardwareSmokeTest, Sustains1080p50CaptureAndEncoding) {
  if (!CameraHardwareSmokeEnabled()) {
    GTEST_SKIP()
        << "set CF_RUN_CAMERA_HARDWARE_SMOKE=1 to require camera hardware";
  }

  camera_firmware::config::AppConfig config;
  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(128U);
  camera_firmware::media::CameraPipeline pipeline(snapshot_tap, ai_frame_tap,
                                                  encoded_ring);

  const auto started = pipeline.Start(config);
  ASSERT_TRUE(started.ok()) << started.error().code << ": "
                            << started.error().message;

  camera_firmware::media::CameraPipelineStatus status;
  bool accepted = false;
  for (int attempt = 0; attempt < 100; ++attempt) {
    const auto statuses = pipeline.Status();
    ASSERT_EQ(statuses.size(), 1U);
    status = statuses.front();
    if (Meets1080p50Acceptance(status)) {
      accepted = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  pipeline.Stop();

  EXPECT_TRUE(accepted) << StatusMessage(status);
  EXPECT_EQ(status.capture_error_count, 0U) << StatusMessage(status);
  EXPECT_EQ(status.encode_error_count, 0U) << StatusMessage(status);
}
