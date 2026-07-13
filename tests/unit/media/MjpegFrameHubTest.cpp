#include "camera_firmware/media/MjpegFrameHub.hpp"

#include <array>
#include <atomic>
#include <barrier>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace camera_firmware::media {

class MjpegFrameHubTestAccess {
 public:
  static common::Result<void> StartWithoutWorker(MjpegFrameHub& hub) {
    return hub.StartWithoutWorkerForTest();
  }

  static void SetBeforeWorkerStart(MjpegFrameHub& hub,
                                   std::function<void()> callback) {
    hub.SetBeforeWorkerStartForTest(std::move(callback));
  }

  static bool WaitForBlockedReader(MjpegFrameHub& hub,
                                   std::chrono::milliseconds timeout) {
    return hub.WaitForBlockedReaderForTest(timeout);
  }

  static void PublishLatestFrame(MjpegFrameHub& hub) {
    hub.PublishLatestFrame();
  }
};

}  // namespace camera_firmware::media

namespace {

using namespace std::chrono_literals;
using camera_firmware::common::Result;
using camera_firmware::config::HttpPreviewConfig;
using camera_firmware::media::FrameHandle;
using camera_firmware::media::FrameLease;
using camera_firmware::media::JpegImage;
using camera_firmware::media::MjpegFrameHub;
using camera_firmware::media::MjpegFrameHubDependencies;
using camera_firmware::media::MjpegFrameHubTestAccess;
using camera_firmware::media::MjpegStreamReader;
using camera_firmware::media::SnapshotTap;

constexpr std::string_view kCameraId = "imx708-main";

FrameLease TestFrame(
    std::uint64_t sequence,
    FrameLease::ReleaseCallback release = [] {},
    std::string camera_id = std::string(kCameraId)) {
  FrameHandle handle;
  handle.camera_id = std::move(camera_id);
  handle.format = "NV12";
  handle.width = 640U;
  handle.height = 480U;
  handle.sequence = sequence;
  return FrameLease(std::move(handle), std::move(release));
}

std::string ExpectedPart(const std::vector<std::uint8_t>& jpeg) {
  std::string expected = "--cf-frame\r\nContent-Type: image/jpeg\r\n";
  expected +=
      "Content-Length: " + std::to_string(jpeg.size()) + "\r\n\r\n";
  expected.append(reinterpret_cast<const char*>(jpeg.data()), jpeg.size());
  expected += "\r\n";
  return expected;
}

std::string ReadBytes(MjpegStreamReader& reader, std::size_t byte_count,
                      std::size_t chunk_size) {
  std::string bytes;
  std::vector<char> buffer(chunk_size);
  while (bytes.size() < byte_count) {
    const std::size_t copied = reader.Read(buffer.data(), buffer.size());
    if (copied == 0U) {
      break;
    }
    bytes.append(buffer.data(), copied);
  }
  return bytes;
}

class MjpegFrameHubTest : public ::testing::Test {
 protected:
  MjpegFrameHubTest()
      : tap_([this] { return now_; }),
        hub_(tap_, config_,
             MjpegFrameHubDependencies{
                 .now = [this] { return now_; },
                 .encode = [this](const FrameLease& frame,
                                  unsigned int maximum_width,
                                  unsigned int quality) {
                   ++encode_count_;
                   encoded_sequences_.push_back(frame.handle().sequence);
                   observed_widths_.push_back(maximum_width);
                   observed_qualities_.push_back(quality);
                   if (on_encode_) {
                     on_encode_();
                   }
                   if (fail_encode_) {
                     return Result<JpegImage>::Err(
                         {"E_TEST_ENCODE", "injected encode failure"});
                   }
                   JpegImage image;
                   image.width = 3U;
                   image.height = 2U;
                   image.bytes = jpeg_bytes_;
                   return Result<JpegImage>::Ok(std::move(image));
                 },
             }) {}

  void Start() {
    ASSERT_TRUE(MjpegFrameHubTestAccess::StartWithoutWorker(hub_).ok());
  }

  void Publish(std::uint64_t sequence,
               std::string camera_id = std::string(kCameraId)) {
    tap_.Publish(TestFrame(sequence, [] {}, std::move(camera_id)));
    MjpegFrameHubTestAccess::PublishLatestFrame(hub_);
  }

  MjpegFrameHubDependencies::Clock::time_point now_{};
  SnapshotTap tap_;
  HttpPreviewConfig config_;
  bool fail_encode_{false};
  std::function<void()> on_encode_;
  int encode_count_{0};
  std::vector<std::uint64_t> encoded_sequences_;
  std::vector<unsigned int> observed_widths_;
  std::vector<unsigned int> observed_qualities_;
  const std::vector<std::uint8_t> jpeg_bytes_{0xffU, 0xd8U, 0x00U, 0xffU,
                                               0xd9U};
  MjpegFrameHub hub_;
};

TEST_F(MjpegFrameHubTest, OpenIsUnavailableBeforeStartAndAfterStop) {
  auto before_start = hub_.Open(kCameraId);
  ASSERT_FALSE(before_start.ok());
  EXPECT_EQ(before_start.error().code, "E_PREVIEW_UNAVAILABLE");

  Start();
  hub_.Stop();

  auto after_stop = hub_.Open(kCameraId);
  ASSERT_FALSE(after_stop.ok());
  EXPECT_EQ(after_stop.error().code, "E_PREVIEW_UNAVAILABLE");
}

TEST_F(MjpegFrameHubTest, AdmissionRejectsWhenNoJpegHasBeenEncoded) {
  Start();

  const auto opened = hub_.Open(kCameraId);

  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_PREVIEW_UNAVAILABLE");
}

TEST_F(MjpegFrameHubTest, AdmissionRejectsFreshSourceAfterJpegEncodeFailure) {
  Start();
  fail_encode_ = true;
  Publish(10U);
  ASSERT_EQ(encode_count_, 1);

  const auto opened = hub_.Open(kCameraId);

  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_PREVIEW_UNAVAILABLE");
}

TEST_F(MjpegFrameHubTest,
       AdmissionRejectsWrongCameraWithoutConsumingCapacity) {
  Start();
  Publish(11U);

  const auto wrong_camera = hub_.Open("other-camera");
  ASSERT_FALSE(wrong_camera.ok());
  EXPECT_EQ(wrong_camera.error().code, "E_PREVIEW_UNAVAILABLE");

  const auto first = hub_.Open(kCameraId);
  const auto second = hub_.Open(kCameraId);
  ASSERT_TRUE(first.ok());
  ASSERT_TRUE(second.ok());
  const auto at_capacity = hub_.Open(kCameraId);
  ASSERT_FALSE(at_capacity.ok());
  EXPECT_EQ(at_capacity.error().code, "E_PREVIEW_CAPACITY");
}

TEST_F(MjpegFrameHubTest, AdmissionRejectsStaleEncodedFrame) {
  Start();
  Publish(12U);
  now_ += std::chrono::milliseconds(config_.stale_timeout_ms + 1U);

  const auto opened = hub_.Open(kCameraId);

  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_PREVIEW_UNAVAILABLE");
}

TEST_F(MjpegFrameHubTest, AdmissionAcceptsFreshMatchingEncodedFrame) {
  Start();
  Publish(13U);

  const auto opened = hub_.Open(kCameraId);

  EXPECT_TRUE(opened.ok());
}

TEST_F(MjpegFrameHubTest, DelayedEncodeCannotRefreshExpiredSourceFrame) {
  Start();
  on_encode_ = [this] {
    now_ += std::chrono::milliseconds(config_.stale_timeout_ms + 1U);
  };

  Publish(35U);
  const auto opened = hub_.Open(kCameraId);

  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_PREVIEW_UNAVAILABLE");
}

TEST_F(MjpegFrameHubTest, EncodeFromInvalidatedSourceRunIsNotPublished) {
  const auto source_run = tap_.BeginSourceRun();
  Start();
  on_encode_ = [this, source_run] {
    tap_.EndSourceRun(source_run);
    (void)tap_.BeginSourceRun();
  };

  Publish(36U);
  const auto opened = hub_.Open(kCameraId);

  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_PREVIEW_UNAVAILABLE");
}

TEST_F(MjpegFrameHubTest, NewerFrameInSameSourceRunDoesNotRejectEncode) {
  const auto source_run = tap_.BeginSourceRun();
  Start();
  on_encode_ = [this, source_run] {
    tap_.Publish(TestFrame(38U), source_run);
  };

  Publish(37U);

  EXPECT_TRUE(hub_.Open(kCameraId).ok());
  EXPECT_EQ(encoded_sequences_, (std::vector<std::uint64_t>{37U}));
}

TEST_F(MjpegFrameHubTest, RestartCannotPublishAnEndedSourceRun) {
  const auto source_run = tap_.BeginSourceRun();
  Start();
  Publish(39U);
  ASSERT_TRUE(hub_.Open(kCameraId).ok());

  hub_.Stop();
  tap_.EndSourceRun(source_run);
  Start();
  MjpegFrameHubTestAccess::PublishLatestFrame(hub_);

  const auto opened = hub_.Open(kCameraId);
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_PREVIEW_UNAVAILABLE");
}

TEST_F(MjpegFrameHubTest,
       ReaderSurvivingHubDestructionReturnsZeroWithoutCallingClock) {
  std::atomic<int> clock_calls{0};
  std::shared_ptr<MjpegStreamReader> reader;
  {
    SnapshotTap tap;
    HttpPreviewConfig config;
    MjpegFrameHub hub(
        tap, config,
        MjpegFrameHubDependencies{
            .now = [&] {
              ++clock_calls;
              return MjpegFrameHubDependencies::Clock::time_point{};
            },
            .encode = [](const FrameLease&, unsigned int, unsigned int) {
              JpegImage image;
              image.width = 2U;
              image.height = 2U;
              image.bytes = {0xffU, 0xd8U, 0xffU, 0xd9U};
              return Result<JpegImage>::Ok(std::move(image));
            },
        });
    ASSERT_TRUE(MjpegFrameHubTestAccess::StartWithoutWorker(hub).ok());
    tap.Publish(TestFrame(14U));
    MjpegFrameHubTestAccess::PublishLatestFrame(hub);
    auto opened = hub.Open(kCameraId);
    ASSERT_TRUE(opened.ok());
    reader = std::move(opened).value();
  }

  const int calls_before_read = clock_calls.load();
  std::array<char, 16U> output{};
  EXPECT_EQ(reader->Read(output.data(), output.size()), 0U);
  EXPECT_EQ(clock_calls.load(), calls_before_read);
}

TEST_F(MjpegFrameHubTest, ManualStartPublishesWithoutCadenceWorker) {
  ASSERT_TRUE(MjpegFrameHubTestAccess::StartWithoutWorker(hub_).ok());
  Publish(16U);
  auto opened = hub_.Open(kCameraId);
  ASSERT_TRUE(opened.ok());

  const std::string expected = ExpectedPart(jpeg_bytes_);
  EXPECT_EQ(ReadBytes(*opened.value(), expected.size(), expected.size()),
            expected);
  EXPECT_EQ(encode_count_, 1);
}

TEST_F(MjpegFrameHubTest, InjectedWorkerStartFailureRollsBackRunningState) {
  MjpegFrameHubTestAccess::SetBeforeWorkerStart(
      hub_, [] { throw std::runtime_error("injected worker start failure"); });

  auto started = hub_.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_PREVIEW_UNAVAILABLE");
  auto opened = hub_.Open(kCameraId);
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_PREVIEW_UNAVAILABLE");
}

TEST_F(MjpegFrameHubTest, StartStopAreIdempotentAndSupportRestart) {
  SnapshotTap tap;
  HttpPreviewConfig config;
  std::atomic<int> worker_starts{0};
  MjpegFrameHub hub(
      tap, config,
      MjpegFrameHubDependencies{
          .now = [] { return MjpegFrameHubDependencies::Clock::now(); },
          .encode = [](const FrameLease&, unsigned int, unsigned int) {
            JpegImage image;
            image.width = 2U;
            image.height = 2U;
            image.bytes = {0xffU, 0xd8U, 0xffU, 0xd9U};
            return Result<JpegImage>::Ok(std::move(image));
          },
      });
  MjpegFrameHubTestAccess::SetBeforeWorkerStart(
      hub, [&] { ++worker_starts; });

  EXPECT_TRUE(hub.Start().ok());
  EXPECT_TRUE(hub.Start().ok());
  EXPECT_EQ(worker_starts.load(), 1);
  tap.Publish(TestFrame(15U));
  MjpegFrameHubTestAccess::PublishLatestFrame(hub);
  auto first_reader = hub.Open(kCameraId);
  ASSERT_TRUE(first_reader.ok());
  first_reader.value().reset();

  hub.Stop();
  hub.Stop();

  EXPECT_TRUE(hub.Start().ok());
  EXPECT_EQ(worker_starts.load(), 2);
  tap.Publish(TestFrame(16U));
  MjpegFrameHubTestAccess::PublishLatestFrame(hub);
  auto restarted_reader = hub.Open(kCameraId);
  EXPECT_TRUE(restarted_reader.ok());
  hub.Stop();
}

TEST_F(MjpegFrameHubTest,
       RetainedReaderCannotAttachToRestartedHubAndKeepsCapacity) {
  Start();
  Publish(33U);
  auto opened = hub_.Open(kCameraId);
  ASSERT_TRUE(opened.ok());
  auto retained = std::move(opened).value();

  hub_.Stop();
  Start();
  Publish(34U);

  std::array<char, 64U> output{};
  EXPECT_EQ(retained->Read(output.data(), output.size()), 0U);
  auto current = hub_.Open(kCameraId);
  ASSERT_TRUE(current.ok());
  auto at_capacity = hub_.Open(kCameraId);
  ASSERT_FALSE(at_capacity.ok());
  EXPECT_EQ(at_capacity.error().code, "E_PREVIEW_CAPACITY");

  retained.reset();
  auto after_release = hub_.Open(kCameraId);
  EXPECT_TRUE(after_release.ok());
}

TEST_F(MjpegFrameHubTest, WorkerStartRollbackKeepsRetainedReaderTerminated) {
  Start();
  Publish(15U);
  auto opened = hub_.Open(kCameraId);
  ASSERT_TRUE(opened.ok());
  auto reader = std::move(opened).value();
  hub_.Stop();

  std::mutex hook_mutex;
  std::condition_variable hook_changed;
  bool hook_entered = false;
  bool allow_failure = false;
  MjpegFrameHubTestAccess::SetBeforeWorkerStart(hub_, [&] {
    std::unique_lock lock(hook_mutex);
    hook_entered = true;
    hook_changed.notify_all();
    hook_changed.wait(lock, [&] { return allow_failure; });
    throw std::runtime_error("injected worker start failure");
  });
  auto start = std::async(std::launch::async, [&] { return hub_.Start(); });
  {
    std::unique_lock lock(hook_mutex);
    ASSERT_TRUE(hook_changed.wait_for(lock, 1s,
                                      [&] { return hook_entered; }));
  }

  auto read = std::async(std::launch::async, [reader] {
    std::array<char, 16U> output{};
    return reader->Read(output.data(), output.size());
  });
  ASSERT_EQ(read.wait_for(1s), std::future_status::ready);
  EXPECT_EQ(read.get(), 0U);
  {
    std::lock_guard lock(hook_mutex);
    allow_failure = true;
  }
  hook_changed.notify_all();

  ASSERT_EQ(start.wait_for(1s), std::future_status::ready);
  auto started = start.get();
  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_PREVIEW_UNAVAILABLE");
}

TEST_F(MjpegFrameHubTest, OneSourceSequenceBuildsOneExactPartForTwoReaders) {
  Start();
  Publish(17U);
  auto first = hub_.Open(kCameraId);
  auto second = hub_.Open(kCameraId);
  ASSERT_TRUE(first.ok());
  ASSERT_TRUE(second.ok());

  const std::string expected = ExpectedPart(jpeg_bytes_);
  EXPECT_EQ(ReadBytes(*first.value(), expected.size(), expected.size()),
            expected);
  EXPECT_EQ(ReadBytes(*second.value(), expected.size(), expected.size()),
            expected);
  EXPECT_EQ(encode_count_, 1);
  EXPECT_EQ(encoded_sequences_, std::vector<std::uint64_t>{17U});
  EXPECT_EQ(observed_widths_, std::vector<unsigned int>{config_.width});
  EXPECT_EQ(observed_qualities_,
            std::vector<unsigned int>{config_.jpeg_quality});
}

TEST_F(MjpegFrameHubTest, SmallBuffersResumeAcrossEveryMultipartSegment) {
  Start();
  Publish(18U);
  auto opened = hub_.Open(kCameraId);
  ASSERT_TRUE(opened.ok());

  const std::string expected = ExpectedPart(jpeg_bytes_);
  const std::string actual = ReadBytes(*opened.value(), expected.size(), 3U);

  EXPECT_EQ(actual, expected);
  EXPECT_EQ(encode_count_, 1);
}

TEST_F(MjpegFrameHubTest, StalenessAfterPartStartsCannotTruncateMultipartTail) {
  Start();
  Publish(40U);
  auto opened = hub_.Open(kCameraId);
  ASSERT_TRUE(opened.ok());
  const std::string expected = ExpectedPart(jpeg_bytes_);
  std::array<char, 7U> output{};

  const std::size_t first =
      opened.value()->Read(output.data(), output.size());
  ASSERT_EQ(first, output.size());
  std::string actual(output.data(), first);
  now_ += std::chrono::milliseconds(config_.stale_timeout_ms + 1U);
  while (actual.size() < expected.size()) {
    const std::size_t copied =
        opened.value()->Read(output.data(), output.size());
    if (copied == 0U) {
      break;
    }
    actual.append(output.data(), copied);
  }

  EXPECT_EQ(actual, expected);
  EXPECT_EQ(opened.value()->Read(output.data(), output.size()), 0U);
}

TEST_F(MjpegFrameHubTest, DuplicateSourceSequencesAreNotEncodedAgain) {
  Start();
  Publish(23U);
  tap_.Publish(TestFrame(23U));
  MjpegFrameHubTestAccess::PublishLatestFrame(hub_);
  tap_.Publish(TestFrame(24U));
  MjpegFrameHubTestAccess::PublishLatestFrame(hub_);

  EXPECT_EQ(encode_count_, 2);
  EXPECT_EQ(encoded_sequences_, (std::vector<std::uint64_t>{23U, 24U}));
}

TEST_F(MjpegFrameHubTest, EncodeFailureIsAttemptedOncePerClaimedSequence) {
  fail_encode_ = true;
  Start();
  tap_.Publish(TestFrame(25U));
  MjpegFrameHubTestAccess::PublishLatestFrame(hub_);
  tap_.Publish(TestFrame(25U));
  MjpegFrameHubTestAccess::PublishLatestFrame(hub_);
  tap_.Publish(TestFrame(26U));
  MjpegFrameHubTestAccess::PublishLatestFrame(hub_);

  EXPECT_EQ(encode_count_, 2);
  EXPECT_EQ(encoded_sequences_, (std::vector<std::uint64_t>{25U, 26U}));
}

TEST_F(MjpegFrameHubTest, ReaderSlotIsReleasedOnlyAfterLastOwnerDrops) {
  Start();
  Publish(27U);
  auto first = hub_.Open(kCameraId);
  auto second = hub_.Open(kCameraId);
  ASSERT_TRUE(first.ok());
  ASSERT_TRUE(second.ok());
  std::shared_ptr<MjpegStreamReader> first_alias = first.value();

  first.value().reset();
  auto at_capacity = hub_.Open(kCameraId);
  ASSERT_FALSE(at_capacity.ok());
  EXPECT_EQ(at_capacity.error().code, "E_PREVIEW_CAPACITY");

  first_alias.reset();
  auto reopened = hub_.Open(kCameraId);
  EXPECT_TRUE(reopened.ok());
}

TEST_F(MjpegFrameHubTest, ConcurrentOpenNeverExceedsConfiguredCapacity) {
  Start();
  Publish(28U);
  constexpr std::size_t kAttempts = 12U;
  std::barrier gate(static_cast<std::ptrdiff_t>(kAttempts + 1U));
  std::mutex readers_mutex;
  std::vector<std::shared_ptr<MjpegStreamReader>> readers;
  std::vector<std::thread> threads;
  threads.reserve(kAttempts);

  for (std::size_t index = 0U; index < kAttempts; ++index) {
    threads.emplace_back([&] {
      gate.arrive_and_wait();
      auto opened = hub_.Open(kCameraId);
      if (opened.ok()) {
        std::lock_guard lock(readers_mutex);
        readers.push_back(std::move(opened).value());
      } else {
        EXPECT_EQ(opened.error().code, "E_PREVIEW_CAPACITY");
      }
    });
  }
  gate.arrive_and_wait();
  for (auto& thread : threads) {
    thread.join();
  }

  EXPECT_EQ(readers.size(), config_.max_clients);
}

TEST_F(MjpegFrameHubTest, StaleUnreadFrameEndsReader) {
  Start();
  Publish(31U);
  auto opened = hub_.Open(kCameraId);
  ASSERT_TRUE(opened.ok());
  now_ += std::chrono::milliseconds(config_.stale_timeout_ms + 1U);

  std::array<char, 64U> output{};
  EXPECT_EQ(opened.value()->Read(output.data(), output.size()), 0U);
}

TEST_F(MjpegFrameHubTest, StopWakesBlockedReaderAndReadReturnsZero) {
  Start();
  Publish(32U);
  auto opened = hub_.Open(kCameraId);
  ASSERT_TRUE(opened.ok());
  auto reader = opened.value();
  const std::string initial_part = ExpectedPart(jpeg_bytes_);
  ASSERT_EQ(ReadBytes(*reader, initial_part.size(), initial_part.size()),
            initial_part);
  auto blocked_read = std::async(std::launch::async, [reader] {
    std::array<char, 64U> output{};
    return reader->Read(output.data(), output.size());
  });
  ASSERT_TRUE(MjpegFrameHubTestAccess::WaitForBlockedReader(hub_, 1s));

  hub_.Stop();

  ASSERT_EQ(blocked_read.wait_for(1s), std::future_status::ready);
  EXPECT_EQ(blocked_read.get(), 0U);
  std::array<char, 8U> output{};
  EXPECT_EQ(reader->Read(output.data(), output.size()), 0U);
}

TEST_F(MjpegFrameHubTest,
       StopJoinsEncodingWithoutHoldingStateLockAndReleasesFrameLease) {
  HttpPreviewConfig config;
  config.fps = 15U;
  SnapshotTap tap;
  std::mutex encoder_mutex;
  std::condition_variable encoder_changed;
  bool encoder_entered = false;
  bool allow_encoder_return = false;
  std::atomic<int> releases{0};
  const std::vector<std::uint8_t> jpeg{0xffU, 0xd8U, 0xffU, 0xd9U};

  MjpegFrameHub hub(
      tap, config,
      MjpegFrameHubDependencies{
          .now = [] { return MjpegFrameHubDependencies::Clock::now(); },
          .encode = [&](const FrameLease& frame, unsigned int, unsigned int) {
            if (frame.handle().sequence == 42U) {
              std::unique_lock lock(encoder_mutex);
              encoder_entered = true;
              encoder_changed.notify_all();
              encoder_changed.wait(lock,
                                   [&] { return allow_encoder_return; });
            }
            JpegImage image;
            image.width = 2U;
            image.height = 2U;
            image.bytes = jpeg;
            return Result<JpegImage>::Ok(std::move(image));
          },
      });
  tap.Publish(TestFrame(41U));
  ASSERT_TRUE(hub.Start().ok());
  MjpegFrameHubTestAccess::PublishLatestFrame(hub);
  auto opened = hub.Open(kCameraId);
  ASSERT_TRUE(opened.ok());
  auto reader = std::move(opened).value();
  const auto initial_part = ExpectedPart(jpeg);
  ASSERT_EQ(ReadBytes(*reader, initial_part.size(), initial_part.size()),
            initial_part);

  tap.Publish(TestFrame(42U, [&] { ++releases; }));
  {
    std::unique_lock lock(encoder_mutex);
    ASSERT_TRUE(encoder_changed.wait_for(lock, 2s,
                                         [&] { return encoder_entered; }));
  }

  auto open_during_encode = std::async(
      std::launch::async, [&] { return hub.Open(kCameraId); });
  const auto open_status = open_during_encode.wait_for(1s);
  if (open_status != std::future_status::ready) {
    {
      std::lock_guard lock(encoder_mutex);
      allow_encoder_return = true;
    }
    encoder_changed.notify_all();
    ASSERT_EQ(open_during_encode.wait_for(2s), std::future_status::ready);
    hub.Stop();
  }
  ASSERT_EQ(open_status, std::future_status::ready);
  auto opened_during_encode = open_during_encode.get();
  ASSERT_TRUE(opened_during_encode.ok());
  opened_during_encode.value().reset();
  auto blocked_read = std::async(std::launch::async, [reader] {
    std::array<char, 16U> output{};
    return reader->Read(output.data(), output.size());
  });
  ASSERT_TRUE(MjpegFrameHubTestAccess::WaitForBlockedReader(hub, 1s));

  tap.Publish(FrameLease{});
  auto stop = std::async(std::launch::async, [&] { hub.Stop(); });
  ASSERT_EQ(blocked_read.wait_for(1s), std::future_status::ready);
  EXPECT_EQ(blocked_read.get(), 0U);
  EXPECT_EQ(stop.wait_for(0ms), std::future_status::timeout);

  {
    std::lock_guard lock(encoder_mutex);
    allow_encoder_return = true;
  }
  encoder_changed.notify_all();

  ASSERT_EQ(stop.wait_for(2s), std::future_status::ready);
  stop.get();
  EXPECT_EQ(releases.load(), 1);
}

TEST_F(MjpegFrameHubTest, DisabledPreviewCannotBeOpened) {
  SnapshotTap tap;
  HttpPreviewConfig config;
  config.enabled = false;
  MjpegFrameHub hub(tap, config);

  EXPECT_TRUE(hub.Start().ok());
  auto opened = hub.Open(kCameraId);
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_PREVIEW_UNAVAILABLE");
}

}  // namespace
