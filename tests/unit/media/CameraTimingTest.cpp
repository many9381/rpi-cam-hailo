#include "camera_firmware/media/CameraTiming.hpp"

#include <array>
#include <chrono>
#include <cstdint>

#include <gtest/gtest.h>

TEST(CameraTimingTest, BuildsFixedFrameDurationLimits) {
  const auto fifty_fps = camera_firmware::media::FixedFrameDurationLimits(50U);
  ASSERT_TRUE(fifty_fps.ok()) << fifty_fps.error().message;
  EXPECT_EQ(fifty_fps.value(), (std::array<std::int64_t, 2>{20000, 20000}));

  const auto thirty_fps = camera_firmware::media::FixedFrameDurationLimits(30U);
  ASSERT_TRUE(thirty_fps.ok()) << thirty_fps.error().message;
  EXPECT_EQ(thirty_fps.value(), (std::array<std::int64_t, 2>{33333, 33333}));
}

TEST(CameraTimingTest, RejectsUnrepresentableFrameRates) {
  const auto zero = camera_firmware::media::FixedFrameDurationLimits(0U);
  ASSERT_FALSE(zero.ok());
  EXPECT_EQ(zero.error().code, "E_CAMERA_FRAME_RATE");

  const auto too_fast =
      camera_firmware::media::FixedFrameDurationLimits(2000001U);
  ASSERT_FALSE(too_fast.ok());
  EXPECT_EQ(too_fast.error().code, "E_CAMERA_FRAME_RATE");
}

TEST(CameraTimingTest, ResolvesConfiguredX264PresetWithAutomaticThreads) {
  camera_firmware::config::CameraEncoderConfig config;
  config.preset = "medium";

  const auto policy = camera_firmware::media::ResolveX264RuntimePolicy(config);

  EXPECT_EQ(policy.preset, "medium");
  EXPECT_EQ(policy.threads, 0);
}

TEST(CameraTimingTest, ResolvesX264VBVBufferSizeFromBitrate) {
  camera_firmware::config::CameraEncoderConfig config;
  config.preset = "medium";
  config.bitrate_kbps = 6000U;

  const auto policy = camera_firmware::media::ResolveX264RuntimePolicy(config);

  EXPECT_EQ(policy.vbv_max_bitrate_kbps, 6000);
  EXPECT_EQ(policy.vbv_buffer_size_kbits, 3000);
}

TEST(CameraTimingTest, EstimatesFrameRateFromBoundedTimestampWindow) {
  using namespace std::chrono_literals;
  camera_firmware::media::FrameRateEstimator estimator(3U);

  estimator.Record(0ns);
  estimator.Record(20ms);
  estimator.Record(40ms);
  estimator.Record(60ms);

  EXPECT_EQ(estimator.sample_count(), 3U);
  EXPECT_DOUBLE_EQ(estimator.FramesPerSecond(), 50.0);
}

TEST(CameraTimingTest, ResetsFrameRateWindowForNonMonotonicTimestamp) {
  using namespace std::chrono_literals;
  camera_firmware::media::FrameRateEstimator estimator;
  estimator.Record(10ms);
  estimator.Record(30ms);
  ASSERT_DOUBLE_EQ(estimator.FramesPerSecond(), 50.0);

  estimator.Record(20ms);

  EXPECT_EQ(estimator.sample_count(), 1U);
  EXPECT_DOUBLE_EQ(estimator.FramesPerSecond(), 0.0);
}
