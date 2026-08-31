#include "camera_firmware/media/CameraPipeline.hpp"

#include "camera_firmware/ai/AiFrameTap.hpp"

#include <gtest/gtest.h>

TEST(CameraPipelineConfigTest, RejectsEmptyX264Preset) {
  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(8U);
  camera_firmware::media::CameraPipeline pipeline(snapshot_tap, ai_frame_tap,
                                                  encoded_ring);
  camera_firmware::config::AppConfig config;
  config.camera.encoder.preset.clear();

  const auto result = pipeline.ValidateConfigOnly(config);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_CAMERA_CONFIG");
}

TEST(CameraPipelineConfigTest, RejectsBitrateBelowTheFloor) {
  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(8U);
  camera_firmware::media::CameraPipeline pipeline(snapshot_tap, ai_frame_tap,
                                                  encoded_ring);
  camera_firmware::config::AppConfig config;
  config.camera.encoder.bitrate_kbps =
      camera_firmware::config::kMinEncoderBitrateKbps - 1U;

  const auto result = pipeline.ValidateConfigOnly(config);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_CAMERA_CONFIG");
}

TEST(CameraPipelineConfigTest, RejectsBitrateAboveTheCeiling) {
  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(8U);
  camera_firmware::media::CameraPipeline pipeline(snapshot_tap, ai_frame_tap,
                                                  encoded_ring);
  camera_firmware::config::AppConfig config;
  config.camera.encoder.bitrate_kbps =
      camera_firmware::config::kMaxEncoderBitrateKbps + 1U;

  const auto result = pipeline.ValidateConfigOnly(config);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_CAMERA_CONFIG");
}

TEST(CameraPipelineConfigTest, AcceptsBitrateAtTheFloor) {
  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(8U);
  camera_firmware::media::CameraPipeline pipeline(snapshot_tap, ai_frame_tap,
                                                  encoded_ring);
  camera_firmware::config::AppConfig config;
  config.camera.encoder.bitrate_kbps =
      camera_firmware::config::kMinEncoderBitrateKbps;

  const auto result = pipeline.ValidateConfigOnly(config);

  ASSERT_TRUE(result.ok()) << result.error().message;
}

TEST(CameraPipelineConfigTest, ReportsConfiguredOutputBeforeCaptureStarts) {
  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(8U);
  camera_firmware::media::CameraPipeline pipeline(snapshot_tap, ai_frame_tap,
                                                  encoded_ring);

  const auto statuses = pipeline.Status();

  ASSERT_EQ(statuses.size(), 1U);
  EXPECT_EQ(statuses.front().width, 1920U);
  EXPECT_EQ(statuses.front().height, 1080U);
  EXPECT_EQ(statuses.front().configured_fps, 50U);
  EXPECT_DOUBLE_EQ(statuses.front().capture_fps, 0.0);
  EXPECT_DOUBLE_EQ(statuses.front().encoded_fps, 0.0);
}

TEST(CameraPipelineConfigTest, ReportsMainFallbackAiSourceBeforeCaptureStarts) {
  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(8U);
  camera_firmware::media::CameraPipeline pipeline(snapshot_tap, ai_frame_tap,
                                                  encoded_ring);

  const auto statuses = pipeline.Status();

  ASSERT_EQ(statuses.size(), 1U);
  EXPECT_EQ(statuses.front().ai_source, "main-fallback");
}
