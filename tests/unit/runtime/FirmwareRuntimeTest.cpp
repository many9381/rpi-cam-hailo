#include "camera_firmware/runtime/FirmwareRuntime.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "camera_firmware/ai/AiFrameTap.hpp"
#include "camera_firmware/media/EncodedRing.hpp"

namespace camera_firmware::runtime {

class FirmwareRuntimeTestAccess {
 public:
  static bool DependenciesComplete(const FirmwareRuntime& runtime) {
    return runtime.DependenciesComplete();
  }

  static FirmwareRuntimeDependencies ProductionDependencies(
      const config::AppConfig& config) {
    return FirmwareRuntime::BuildProductionDependencies(config);
  }

  static std::chrono::milliseconds SnapshotMaximumAge(
      const config::AppConfig& config) {
    return FirmwareRuntime::SnapshotMaximumAge(config);
  }

  static FirmwareRuntime::ProductionSubStreamHandles
  ProductionDependenciesWithSubStreamHandles(const config::AppConfig& config) {
    return FirmwareRuntime::BuildProductionDependenciesWithSubStreamHandles(
        config);
  }
};

namespace {

int CreateNv12Memfd() {
  int fd = memfd_create("cf-runtime-freshness", MFD_CLOEXEC);
  if (fd < 0) {
    return fd;
  }
  const std::vector<std::uint8_t> nv12{
      0x40, 0x80, 0x80, 0xc0, 0x80, 0x80,
  };
  if (ftruncate(fd, static_cast<off_t>(nv12.size())) != 0 ||
      write(fd, nv12.data(), nv12.size()) !=
          static_cast<ssize_t>(nv12.size())) {
    close(fd);
    return -1;
  }
  return fd;
}

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
  std::atomic<unsigned int> live_starts{0U};
  std::atomic<unsigned int> rtsp_stops{0U};
  std::atomic<unsigned int> ai_stops{0U};
  std::atomic<unsigned int> camera_stops{0U};
  std::atomic<unsigned int> live_stops{0U};
  std::atomic<unsigned int> live_opens{0U};
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
  dependencies.start_live = [&] {
    calls.live_starts.fetch_add(1U);
    calls.Record("live.start");
    return common::Result<void>::Ok();
  };
  dependencies.stop_live = [&] {
    calls.live_stops.fetch_add(1U);
    calls.Record("live.stop");
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
  dependencies.open_live_stream = [&](std::string_view) {
    calls.live_opens.fetch_add(1U);
    return common::Result<media::FragmentRing::Reader>::Err(
        {"E_LIVE_UNAVAILABLE", "live stream is unavailable"});
  };
  dependencies.live_status = [] {
    media::FragmentedMp4HubStatus status;
    status.state = "running";
    return status;
  };
  return dependencies;
}

config::AppConfig CandidateConfig() {
  config::AppConfig config;
  config.secure_rtsp.enabled = false;
  config.security.enabled = false;
  config.http.tls.enabled = false;
  config.ai.enabled = false;
  config.camera.ai.enabled = false;
  return config;
}

TEST(FirmwareRuntimeTest,
     CandidateValidationRejectsUnsupportedCameraBeforeRuntimeStart) {
  auto config = CandidateConfig();
  config.camera.source.backend = "unsupported";
  ASSERT_TRUE(config::ValidateAppConfigSemantics(config).ok());

  const auto validated = FirmwareRuntime::ValidateCandidateConfig(config);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_CAMERA_CONFIG");
}

TEST(FirmwareRuntimeTest,
     CandidateValidationAcceptsSupportedConfigWithoutStartingHardware) {
  const auto validated =
      FirmwareRuntime::ValidateCandidateConfig(CandidateConfig());

  EXPECT_TRUE(validated.ok()) << validated.error().message;
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
  EXPECT_EQ(calls.live_starts.load(), 1U);

  runtime.Stop();
  runtime.Stop();

  EXPECT_EQ(runtime.State(), FirmwareRuntimeState::kStopped);
  EXPECT_EQ(calls.camera_stops.load(), 1U);
  EXPECT_EQ(calls.live_stops.load(), 1U);
  EXPECT_EQ(calls.ai_stops.load(), 1U);
  EXPECT_EQ(calls.rtsp_stops.load(), 1U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"rtsp.start", "ai.start", "camera.start",
                                      "live.start", "live.stop", "camera.stop",
                                      "ai.stop", "rtsp.stop"}));
}

TEST(FirmwareRuntimeTest, LiveStartFailureUnwindsCameraAndEarlierComponents) {
  config::AppConfig config;
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.start_live = [&] {
    calls.live_starts.fetch_add(1U);
    calls.Record("live.start");
    return common::Result<void>::Err(
        {"E_LIVE_UNAVAILABLE", "live stream is unavailable"});
  };
  FirmwareRuntime runtime(config, std::move(dependencies));

  const auto started = runtime.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_LIVE_UNAVAILABLE");
  EXPECT_EQ(calls.live_stops.load(), 0U);
  EXPECT_EQ(calls.camera_stops.load(), 1U);
  EXPECT_EQ(calls.ordered,
            (std::vector<std::string>{"rtsp.start", "ai.start", "camera.start",
                                      "live.start", "camera.stop", "ai.stop",
                                      "rtsp.stop"}));
}

TEST(FirmwareRuntimeTest,
     PartialFailureUnwindsStartedComponentsInReverseOrder) {
  config::AppConfig config;
  config.camera.id = "configured-camera";
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
            (std::vector<std::string>{"rtsp.start", "ai.start", "camera.start",
                                      "ai.stop", "rtsp.stop"}));
  const auto statuses = runtime.CameraStatuses();
  ASSERT_EQ(statuses.size(), 1U);
  EXPECT_EQ(statuses.front().id, "configured-camera");
  EXPECT_EQ(statuses.front().state, "error");
  EXPECT_FALSE(statuses.front().snapshot_available);
}

TEST(FirmwareRuntimeTest, StoppedRuntimeReturnsSafeProviderValues) {
  config::AppConfig config;
  config.camera.id = "configured-camera";
  config.camera.video.width = 1280U;
  config.camera.video.height = 720U;
  config.camera.video.fps = 50U;
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.camera_statuses = [&] {
    calls.provider_calls.fetch_add(1U);
    return std::vector<media::CameraPipelineStatus>{
        {"camera", "running", true}};
  };
  dependencies.restart_ai = [&] {
    calls.provider_calls.fetch_add(1U);
    return common::Result<void>::Ok();
  };
  dependencies.snapshot = [&](std::string_view) {
    calls.provider_calls.fetch_add(1U);
    return std::optional<camera_firmware::media::JpegBytes>{
        std::string("\x01\x02\x03", 3U)};
  };
  FirmwareRuntime runtime(config, std::move(dependencies));

  const auto statuses = runtime.CameraStatuses();
  ASSERT_EQ(statuses.size(), 1U);
  EXPECT_EQ(statuses.front().id, "configured-camera");
  EXPECT_EQ(statuses.front().state, "stopped");
  EXPECT_FALSE(statuses.front().snapshot_available);
  EXPECT_EQ(statuses.front().width, 1280U);
  EXPECT_EQ(statuses.front().height, 720U);
  EXPECT_EQ(statuses.front().configured_fps, 50U);
  EXPECT_DOUBLE_EQ(statuses.front().capture_fps, 0.0);
  EXPECT_DOUBLE_EQ(statuses.front().encoded_fps, 0.0);
  EXPECT_EQ(statuses.front().captured_frames, 0U);
  EXPECT_EQ(statuses.front().encoded_frames, 0U);
  EXPECT_EQ(statuses.front().capture_error_count, 0U);
  EXPECT_EQ(statuses.front().encode_error_count, 0U);
  EXPECT_EQ(runtime.AiStatus().state, "stopped");
  EXPECT_TRUE(runtime.AiRunnerStatuses().empty());
  EXPECT_FALSE(runtime.RestartAi().ok());
  EXPECT_FALSE(runtime.Snapshot("camera").has_value());
  const auto live = runtime.OpenLiveStream("camera");
  ASSERT_FALSE(live.ok());
  EXPECT_EQ(live.error().code, "E_LIVE_UNAVAILABLE");
  EXPECT_TRUE(runtime.DetectionSnapshot().empty());
  EXPECT_FALSE(
      runtime.SubscribeDetections([](const ai::DetectionEvent&) {}).valid());
  EXPECT_EQ(runtime.PerMediaKeyZeroizeCount(), 0U);
  EXPECT_EQ(calls.provider_calls.load(), 0U);
  EXPECT_EQ(calls.live_opens.load(), 0U);
}

TEST(FirmwareRuntimeTest, RunningLiveProvidersDelegateToOwnedDependencies) {
  config::AppConfig config;
  Calls calls;
  FirmwareRuntime runtime(config, SuccessfulDependencies(calls));
  ASSERT_TRUE(runtime.Start().ok());

  const auto status = runtime.LiveStatus();
  const auto opened = runtime.OpenLiveStream("imx708-main");

  EXPECT_EQ(status.state, "running");
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_LIVE_UNAVAILABLE");
  EXPECT_EQ(calls.live_opens.load(), 1U);
}

TEST(FirmwareRuntimeTest, RunningProvidersDelegateToOwnedDependencies) {
  config::AppConfig config;
  Calls calls;
  auto dependencies = SuccessfulDependencies(calls);
  dependencies.camera_statuses = [&] {
    calls.provider_calls.fetch_add(1U);
    return std::vector<media::CameraPipelineStatus>{
        {"camera", "running", true}};
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
      return std::optional<camera_firmware::media::JpegBytes>{
          std::string("\x01\x02\x03", 3U)};
    }
    return std::optional<camera_firmware::media::JpegBytes>{};
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
            (std::optional<camera_firmware::media::JpegBytes>{
                std::string("\x01\x02\x03", 3U)}));
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
  EXPECT_EQ(calls.live_starts.load(), 1U);
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
  EXPECT_EQ(calls.live_starts.load(), 2U);
  EXPECT_EQ(calls.live_stops.load(), 2U);
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
            (std::vector<std::string>{"rtsp.start", "ai.start", "camera.start",
                                      "live.start", "live.stop", "camera.stop",
                                      "ai.stop", "rtsp.stop"}));
}

TEST(FirmwareRuntimeTest, ProductionConstructorOwnsCompleteComponentGraph) {
  config::AppConfig config;

  FirmwareRuntime runtime(config);

  EXPECT_TRUE(FirmwareRuntimeTestAccess::DependenciesComplete(runtime));
  EXPECT_EQ(runtime.State(), FirmwareRuntimeState::kStopped);
}

TEST(FirmwareRuntimeTest,
     CameraStatusAndSnapshotShareConfiguredSnapshotFreshnessLimit) {
  config::AppConfig config;
  config.http.snapshot.stale_timeout_ms = 1375U;
  const auto maximum_age =
      FirmwareRuntimeTestAccess::SnapshotMaximumAge(config);
  EXPECT_EQ(maximum_age, std::chrono::milliseconds(1375));

  auto now = std::chrono::steady_clock::time_point{};
  media::SnapshotTap snapshot_tap([&now] { return now; });
  ai::AiFrameTap ai_frame_tap;
  media::EncodedRing encoded_ring(1U);
  media::CameraPipeline pipeline(snapshot_tap, ai_frame_tap, encoded_ring);
  int fd = CreateNv12Memfd();
  ASSERT_GE(fd, 0);
  media::FrameHandle handle;
  handle.camera_id = config.camera.id;
  handle.format = "NV12";
  handle.width = 2U;
  handle.height = 2U;
  handle.plane_count = 2U;
  handle.planes[0] = {
      .dmabuf_fd = fd, .offset = 0U, .length = 4U, .stride = 2U};
  handle.planes[1] = {
      .dmabuf_fd = fd, .offset = 4U, .length = 2U, .stride = 2U};
  snapshot_tap.Publish(
      media::FrameLease(std::move(handle), [fd] { (void)close(fd); }));

  ASSERT_EQ(pipeline.Status(maximum_age).size(), 1U);
  EXPECT_TRUE(pipeline.Status(maximum_age).front().snapshot_available);
  EXPECT_TRUE(media::BuildLatestSnapshotJpeg(snapshot_tap, config.camera.id,
                                             maximum_age)
                  .has_value());

  now += maximum_age;

  ASSERT_EQ(pipeline.Status(maximum_age).size(), 1U);
  EXPECT_TRUE(pipeline.Status(maximum_age).front().snapshot_available);
  EXPECT_TRUE(media::BuildLatestSnapshotJpeg(snapshot_tap, config.camera.id,
                                             maximum_age)
                  .has_value());

  now += std::chrono::milliseconds(1);

  ASSERT_EQ(pipeline.Status(maximum_age).size(), 1U);
  EXPECT_FALSE(pipeline.Status(maximum_age).front().snapshot_available);
  EXPECT_FALSE(media::BuildLatestSnapshotJpeg(snapshot_tap, config.camera.id,
                                              maximum_age)
                   .has_value());
}

// The sub stream is best-effort (design doc error-handling section): a
// colliding/invalid sub mount must be logged and disable the sub stream, but
// must NOT prevent the main RTSP mount from starting. Before this fix,
// start_rtsp() treated this as a hard gate and failed the whole runtime.
TEST(FirmwareRuntimeTest,
     ProductionSubStreamMountCollisionDisablesSubButStartsMainMount) {
  auto config = CandidateConfig();
  config.camera.sub_stream.enabled = true;
  config.camera.sub_stream.mount = config.secure_rtsp.mount;

  auto dependencies = FirmwareRuntimeTestAccess::ProductionDependencies(config);
  const auto started = dependencies.start_rtsp();

  // The main mount starts normally; the sub is disabled, not fatal.
  ASSERT_TRUE(started.ok()) << started.error().message;

  // The invalid-mount branch returns before ever constructing/starting the
  // sub encoder (see start_rtsp's mount-validity check), so stop_rtsp must
  // still be safe even though there is no sub encoder instance to stop.
  dependencies.stop_rtsp();
}

TEST(FirmwareRuntimeTest,
     ProductionSubStreamEncoderStartsAndStopsWhenMountIsDistinct) {
  auto config = CandidateConfig();
  config.camera.sub_stream.enabled = true;
  ASSERT_NE(config.camera.sub_stream.mount, config.secure_rtsp.mount);

  auto dependencies = FirmwareRuntimeTestAccess::ProductionDependencies(config);
  const auto started = dependencies.start_rtsp();

  ASSERT_TRUE(started.ok()) << started.error().message;

  // rtsp is disabled in CandidateConfig(), so this exercises the sub
  // encoder's own Start()/Stop() (software x264 + swscale, no hardware)
  // without needing a real RTSP/TLS stack.
  dependencies.stop_rtsp();
}

// A tightly-packed solid NV12 frame at the given dimensions -- mirrors
// SubStreamEncoderTest.cpp's frame builders. Named for the caller's use
// (feeding one frame through the sub-stream path), not for a small buffer:
// the caller passes the real configured camera.video geometry (see the
// comment at its call site for why a tiny test-only size isn't safe here).
media::FrameLease MakeSmallNv12SubFrame(std::uint32_t width,
                                        std::uint32_t height) {
  const std::size_t y_size = static_cast<std::size_t>(width) * height;
  const std::size_t uv_size = static_cast<std::size_t>(width) * (height / 2U);
  std::vector<std::uint8_t> combined(y_size + uv_size, 128U);

  const int fd = memfd_create("cf-runtime-substream-nv12", MFD_CLOEXEC);
  EXPECT_GE(fd, 0);
  if (fd >= 0) {
    EXPECT_EQ(ftruncate(fd, static_cast<off_t>(combined.size())), 0);
    EXPECT_EQ(write(fd, combined.data(), combined.size()),
              static_cast<ssize_t>(combined.size()));
  }

  media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = width;
  handle.height = height;
  handle.plane_count = 2;
  handle.planes[0] = {
      .dmabuf_fd = fd, .offset = 0, .length = y_size, .stride = width};
  handle.planes[1] = {
      .dmabuf_fd = fd, .offset = y_size, .length = uv_size, .stride = width};

  return media::FrameLease(std::move(handle), [fd] {
    if (fd >= 0) {
      close(fd);
    }
  });
}

// Regression test for the sub-stream tap being reused (not recreated) across
// a runtime restart: SubStreamTap is a persistent member of the runtime
// graph, but SubStreamEncoder::Stop() (invoked from stop_rtsp) closes it.
// Without SubStreamEncoder::Impl::Start() reopening it, a SECOND
// start_rtsp()/stop_rtsp() cycle would silently produce zero sub frames
// forever, even though start_rtsp() itself still reports success.
TEST(FirmwareRuntimeTest,
     ProductionSubStreamSurvivesRestartAndProducesFramesOnSecondRun) {
  // Same src/dst geometry as SubStreamEncoderTest.cpp's frame-feeding tests
  // (1920x1080 -> 640x360): libswscale needs realistic plane geometry to
  // scale safely, so this deliberately does not shrink camera.video/
  // sub_stream dimensions down to a tiny test-only size.
  auto config = CandidateConfig();
  config.camera.sub_stream.enabled = true;
  ASSERT_NE(config.camera.sub_stream.mount, config.secure_rtsp.mount);
  const std::uint32_t kWidth = config.camera.video.width;
  const std::uint32_t kHeight = config.camera.video.height;

  auto handles =
      FirmwareRuntimeTestAccess::ProductionDependenciesWithSubStreamHandles(
          config);
  ASSERT_NE(handles.sub_stream_tap, nullptr);

  const auto feed_one_frame_and_wait_encoded = [&] {
    handles.sub_stream_tap->SetActive(true);
    handles.sub_stream_tap->PublishLatest(
        MakeSmallNv12SubFrame(kWidth, kHeight));
    for (int i = 0; i < 50 && handles.sub_encoded_frames() == 0U; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return handles.sub_encoded_frames();
  };

  // First run: the sub encoder wraps a freshly-constructed (never-closed)
  // tap and must produce a frame.
  ASSERT_TRUE(handles.dependencies.start_rtsp().ok());
  EXPECT_GT(feed_one_frame_and_wait_encoded(), 0U);
  handles.dependencies.stop_rtsp();

  // Second run: a NEW SubStreamEncoder wraps the SAME tap, which stop_rtsp
  // just Close()d. Without SubStreamTap::Reopen() being called from
  // SubStreamEncoder::Impl::Start(), the tap stays permanently closed and
  // every published frame is dropped instead of reaching the encoder.
  ASSERT_TRUE(handles.dependencies.start_rtsp().ok());
  EXPECT_GT(feed_one_frame_and_wait_encoded(), 0U);
  handles.dependencies.stop_rtsp();
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
