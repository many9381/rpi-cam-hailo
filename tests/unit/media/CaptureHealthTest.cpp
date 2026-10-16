#include "camera_firmware/media/CaptureHealth.hpp"

#include <gtest/gtest.h>

namespace camera_firmware::media {
namespace {
using namespace std::chrono_literals;
const CaptureHealth::TimePoint epoch{};

TEST(CaptureHealthTest, NoFirstFrameIsNotRunningAndTimesOutAtDeadline) {
  CaptureHealth health;
  health.Start(epoch);
  EXPECT_EQ(health.State(epoch + 9999ms), "starting");
  EXPECT_EQ(health.ErrorCode(epoch + 9999ms), "");
  EXPECT_EQ(health.State(epoch + 10s), "error");
  EXPECT_EQ(health.ErrorCode(epoch + 10s), "E_CAMERA_NO_FRAMES");
}

TEST(CaptureHealthTest, RealFramesRefreshDeadlineAndDistinguishLaterStall) {
  CaptureHealth health;
  health.Start(epoch);
  health.Frame(epoch + 1s);
  EXPECT_EQ(health.State(epoch + 5999ms), "running");
  EXPECT_EQ(health.ErrorCode(epoch + 6s), "E_CAMERA_CAPTURE_STALLED");
  health.Frame(epoch + 6s);
  EXPECT_EQ(health.State(epoch + 10s), "running");
  EXPECT_EQ(health.State(epoch + 11s), "error");
}

TEST(CaptureHealthTest, NewRunDoesNotReusePreviousFrameOrTimeout) {
  CaptureHealth health;
  health.Start(epoch);
  health.Frame(epoch + 1s);
  health.Start(epoch + 30s);
  EXPECT_EQ(health.State(epoch + 31s), "starting");
  EXPECT_EQ(health.ErrorCode(epoch + 40s), "E_CAMERA_NO_FRAMES");
}
}  // namespace
}  // namespace camera_firmware::media
