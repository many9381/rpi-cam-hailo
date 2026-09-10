#include "camera_firmware/media/CameraPipeline.hpp"
#include "camera_firmware/media/FragmentedMp4Hub.hpp"

#include "camera_firmware/ai/AiFrameTap.hpp"

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace {

bool CameraHardwareSmokeEnabled() {
  const char* value = std::getenv("CF_RUN_CAMERA_HARDWARE_SMOKE");
  return value != nullptr && std::string(value) == "1";
}

struct CameraHardwareProfile {
  const char* id;
  unsigned int width;
  unsigned int height;
  unsigned int fps;
};

constexpr CameraHardwareProfile k1080p50{"imx708-1080p50", 1920U, 1080U, 50U};
constexpr CameraHardwareProfile k1080p30{"imx708-1080p30", 1920U, 1080U, 30U};
constexpr CameraHardwareProfile k720p50{"imx708-720p50", 1280U, 720U, 50U};

void ApplyProfile(camera_firmware::config::AppConfig& config,
                  const CameraHardwareProfile& profile) {
  config.camera.video.width = profile.width;
  config.camera.video.height = profile.height;
  config.camera.video.fps = profile.fps;
}

bool MeetsAcceptance(const camera_firmware::media::CameraPipelineStatus& status,
                     const CameraHardwareProfile& profile) {
  const auto minimum_captured = static_cast<std::uint64_t>(profile.fps) * 2U;
  const auto minimum_encoded =
      static_cast<std::uint64_t>(profile.fps) * 19U / 10U;
  const auto minimum_rate = static_cast<double>(profile.fps) * 0.9;
  return status.state == "running" && status.width == profile.width &&
         status.height == profile.height &&
         status.configured_fps == profile.fps &&
         status.captured_frames >= minimum_captured &&
         status.encoded_frames >= minimum_encoded &&
         status.capture_fps >= minimum_rate &&
         status.encoded_fps >= minimum_rate;
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

void RunCaptureAndEncodingSmoke(const CameraHardwareProfile& profile) {
  if (!CameraHardwareSmokeEnabled()) {
    GTEST_SKIP()
        << "set CF_RUN_CAMERA_HARDWARE_SMOKE=1 to require camera hardware";
  }

  camera_firmware::config::AppConfig config;
  ApplyProfile(config, profile);
  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(128U);
  camera_firmware::media::CameraPipeline pipeline(snapshot_tap, ai_frame_tap,
                                                  encoded_ring);

  const auto started = pipeline.Start(config);
  ASSERT_TRUE(started.ok())
      << started.error().code << ": " << started.error().message;

  camera_firmware::media::CameraPipelineStatus status;
  bool accepted = false;
  for (int attempt = 0; attempt < 100; ++attempt) {
    const auto statuses = pipeline.Status();
    ASSERT_EQ(statuses.size(), 1U);
    status = statuses.front();
    if (MeetsAcceptance(status, profile)) {
      accepted = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  pipeline.Stop();

  EXPECT_TRUE(accepted) << profile.id << ": " << StatusMessage(status);
  EXPECT_EQ(status.capture_error_count, 0U)
      << profile.id << ": " << StatusMessage(status);
  EXPECT_EQ(status.encode_error_count, 0U)
      << profile.id << ": " << StatusMessage(status);
}

void RunFragmentedMp4Smoke(const CameraHardwareProfile& profile) {
  if (!CameraHardwareSmokeEnabled()) {
    GTEST_SKIP()
        << "set CF_RUN_CAMERA_HARDWARE_SMOKE=1 to require camera hardware";
  }

  camera_firmware::config::AppConfig config;
  ApplyProfile(config, profile);
  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(256U);
  camera_firmware::media::CameraPipeline pipeline(snapshot_tap, ai_frame_tap,
                                                  encoded_ring);
  camera_firmware::media::FragmentedMp4Hub hub(encoded_ring);

  const auto camera_started = pipeline.Start(config);
  ASSERT_TRUE(camera_started.ok())
      << camera_started.error().code << ": " << camera_started.error().message;
  camera_firmware::media::FragmentedMp4HubConfig live_config;
  live_config.width = config.camera.video.width;
  live_config.height = config.camera.video.height;
  live_config.fps = config.camera.video.fps;
  live_config.fragment_duration_ms = 500U;
  live_config.ring_limits = {
      .max_fragments = 8U, .max_bytes = 32U * 1024U * 1024U, .max_readers = 1U};
  const auto hub_started = hub.Start(live_config);
  ASSERT_TRUE(hub_started.ok())
      << hub_started.error().code << ": " << hub_started.error().message;

  std::optional<camera_firmware::media::FragmentRing::Reader> reader;
  for (int attempt = 0; attempt < 100 && !reader.has_value(); ++attempt) {
    auto opened = hub.OpenReader();
    if (opened.ok()) {
      reader.emplace(std::move(opened).value());
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  ASSERT_TRUE(reader.has_value()) << hub.Status().last_error_code << ": "
                                  << hub.Status().last_error_message;

  std::vector<std::uint8_t> stream_bytes;
  unsigned int media_fragments = 0U;
  for (int attempt = 0; attempt < 20 && media_fragments < 4U; ++attempt) {
    const auto chunk = reader->WaitNext(std::chrono::milliseconds(750));
    ASSERT_TRUE(chunk.ok()) << chunk.error().message;
    if (!chunk.value().has_value()) {
      continue;
    }
    ASSERT_TRUE(chunk.value()->bytes);
    stream_bytes.insert(stream_bytes.end(), chunk.value()->bytes->begin(),
                        chunk.value()->bytes->end());
    if (chunk.value()->kind ==
        camera_firmware::media::FragmentedMp4ChunkKind::kMediaFragment) {
      ++media_fragments;
    }
  }

  const auto hub_status = hub.Status();
  const auto camera_status = pipeline.Status().front();
  hub.Stop();
  pipeline.Stop();

  ASSERT_EQ(media_fragments, 4U)
      << hub_status.last_error_code << ": " << hub_status.last_error_message;
  EXPECT_TRUE(hub_status.last_error_code.empty())
      << hub_status.last_error_message;
  const auto minimum_rate = static_cast<double>(profile.fps) * 0.9;
  EXPECT_GE(camera_status.capture_fps, minimum_rate)
      << profile.id << ": " << StatusMessage(camera_status);
  EXPECT_GE(camera_status.encoded_fps, minimum_rate)
      << profile.id << ": " << StatusMessage(camera_status);

  const char* output_path = std::getenv("CF_FMP4_SMOKE_OUTPUT");
  if (output_path != nullptr && output_path[0] != '\0') {
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(output) << "failed to open fMP4 smoke output";
    output.write(reinterpret_cast<const char*>(stream_bytes.data()),
                 static_cast<std::streamsize>(stream_bytes.size()));
    ASSERT_TRUE(output) << "failed to write fMP4 smoke output";
  }
}

void RunAiLoresRoutingSmoke(const CameraHardwareProfile& profile) {
  if (!CameraHardwareSmokeEnabled()) {
    GTEST_SKIP()
        << "set CF_RUN_CAMERA_HARDWARE_SMOKE=1 to require camera hardware";
  }

  camera_firmware::config::AppConfig config;
  ApplyProfile(config, profile);
  config.camera.ai.enabled = true;
  config.camera.ai.model_ids = {"objects"};
  camera_firmware::config::AiModelConfig model;
  model.id = "objects";
  model.input.width = 640U;
  model.input.height = 640U;
  config.ai.models.push_back(model);

  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(128U);
  camera_firmware::media::CameraPipeline pipeline(snapshot_tap, ai_frame_tap,
                                                  encoded_ring);

  const auto started = pipeline.Start(config);
  ASSERT_TRUE(started.ok())
      << started.error().code << ": " << started.error().message;

  camera_firmware::media::CameraPipelineStatus status;
  bool reached_running = false;
  for (int attempt = 0; attempt < 100; ++attempt) {
    const auto statuses = pipeline.Status();
    ASSERT_EQ(statuses.size(), 1U);
    status = statuses.front();
    if (status.state == "running") {
      reached_running = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  ASSERT_TRUE(reached_running) << profile.id << ": " << StatusMessage(status);

  // Capture the AI tap's latest lease before Stop() so this mirrors the
  // existing tests' Stop-then-EXPECT ordering below: Stop() does not clear
  // AiFrameTap (it only tears down the camera/encoder/requeue state), but
  // capturing first keeps the running-pipeline observation and the Stop()
  // call unambiguously ordered.
  std::optional<camera_firmware::media::FrameLease> ai_frame =
      ai_frame_tap.Latest();
  for (int attempt = 0; attempt < 100 && !ai_frame.has_value(); ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ai_frame = ai_frame_tap.Latest();
  }

  pipeline.Stop();

  EXPECT_EQ(status.ai_source, "lores-rgb")
      << profile.id << ": " << StatusMessage(status);
  EXPECT_EQ(status.width, 1920U) << profile.id << ": " << StatusMessage(status);
  EXPECT_EQ(status.height, 1080U)
      << profile.id << ": " << StatusMessage(status);
  ASSERT_TRUE(ai_frame.has_value())
      << profile.id << ": no AI lores frame observed on the tap";
  EXPECT_EQ(ai_frame->handle().width, 640U) << profile.id;
  EXPECT_EQ(ai_frame->handle().height, 360U) << profile.id;
}

}  // namespace

TEST(CameraPipelineHardwareSmokeTest, Sustains1080p50CaptureAndEncoding) {
  RunCaptureAndEncodingSmoke(k1080p50);
}

TEST(CameraPipelineHardwareSmokeTest, Packages1080p50AsFragmentedMp4) {
  RunFragmentedMp4Smoke(k1080p50);
}

TEST(CameraPipelineHardwareSmokeTest, Sustains1080p30CaptureAndEncoding) {
  RunCaptureAndEncodingSmoke(k1080p30);
}

TEST(CameraPipelineHardwareSmokeTest, Packages1080p30AsFragmentedMp4) {
  RunFragmentedMp4Smoke(k1080p30);
}

TEST(CameraPipelineHardwareSmokeTest, Sustains720p50CaptureAndEncoding) {
  RunCaptureAndEncodingSmoke(k720p50);
}

TEST(CameraPipelineHardwareSmokeTest, Packages720p50AsFragmentedMp4) {
  RunFragmentedMp4Smoke(k720p50);
}

TEST(CameraPipelineHardwareSmokeTest, RoutesAiInferenceToHardwareLoresStream) {
  RunAiLoresRoutingSmoke(k1080p50);
}
