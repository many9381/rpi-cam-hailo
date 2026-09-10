#include "camera_firmware/media/SnapshotTap.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace {

int CreateNv12Memfd() {
  int fd = memfd_create("cf-nv12-snapshot", MFD_CLOEXEC);
  if (fd < 0) {
    return fd;
  }
  const std::vector<std::uint8_t> nv12{
      0x40, 0x80, 0x80, 0xc0, 0x80, 0x80,
  };
  if (ftruncate(fd, static_cast<off_t>(nv12.size())) != 0) {
    close(fd);
    return -1;
  }
  if (write(fd, nv12.data(), nv12.size()) !=
      static_cast<ssize_t>(nv12.size())) {
    close(fd);
    return -1;
  }
  return fd;
}

}  // namespace

TEST(SnapshotTapTest, BuildsJpegForLatestMatchingCameraFrame) {
  int fd = CreateNv12Memfd();
  ASSERT_GE(fd, 0);

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 2;
  handle.height = 2;
  handle.plane_count = 2;
  handle.planes[0] = {.dmabuf_fd = fd, .offset = 0, .length = 4, .stride = 2};
  handle.planes[1] = {.dmabuf_fd = fd, .offset = 4, .length = 2, .stride = 2};

  camera_firmware::media::SnapshotTap tap;
  tap.Publish(camera_firmware::media::FrameLease(std::move(handle),
                                                 [fd] { close(fd); }));

  auto jpeg =
      camera_firmware::media::BuildLatestSnapshotJpeg(tap, "imx708-main");

  ASSERT_TRUE(jpeg.has_value());
  ASSERT_GE(jpeg->size(), 4u);
  EXPECT_EQ((*jpeg)[0], 0xff);
  EXPECT_EQ((*jpeg)[1], 0xd8);
  EXPECT_EQ((*jpeg)[jpeg->size() - 2], 0xff);
  EXPECT_EQ((*jpeg)[jpeg->size() - 1], 0xd9);
}

TEST(SnapshotTapTest, RejectsSnapshotForMismatchedCameraId) {
  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 2;
  handle.height = 2;

  camera_firmware::media::SnapshotTap tap;
  tap.Publish(camera_firmware::media::FrameLease(std::move(handle), [] {}));

  auto jpeg = camera_firmware::media::BuildLatestSnapshotJpeg(tap, "other");

  EXPECT_FALSE(jpeg.has_value());
}

TEST(SnapshotTapTest, FreshFrameExpiresFromBoundedSnapshotAccess) {
  using namespace std::chrono_literals;

  auto now = std::chrono::steady_clock::time_point{};
  camera_firmware::media::SnapshotTap tap([&now] { return now; });
  int fd = CreateNv12Memfd();
  ASSERT_GE(fd, 0);

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 2;
  handle.height = 2;
  handle.plane_count = 2;
  handle.planes[0] = {.dmabuf_fd = fd, .offset = 0, .length = 4, .stride = 2};
  handle.planes[1] = {.dmabuf_fd = fd, .offset = 4, .length = 2, .stride = 2};
  tap.Publish(camera_firmware::media::FrameLease(std::move(handle),
                                                 [fd] { (void)close(fd); }));

  EXPECT_TRUE(tap.HasFreshFrame(2000ms));
  EXPECT_TRUE(tap.Latest(2000ms).has_value());
  EXPECT_TRUE(camera_firmware::media::BuildLatestSnapshotJpeg(
                  tap, "imx708-main", 2000ms)
                  .has_value());

  now += 2001ms;

  EXPECT_FALSE(tap.HasFreshFrame(2000ms));
  EXPECT_FALSE(tap.Latest(2000ms).has_value());
  EXPECT_FALSE(camera_firmware::media::BuildLatestSnapshotJpeg(
                   tap, "imx708-main", 2000ms)
                   .has_value());
  EXPECT_TRUE(tap.Latest().has_value());
}

TEST(SnapshotTapTest, HasFreshFrameRejectsInvalidLease) {
  using namespace std::chrono_literals;

  camera_firmware::media::SnapshotTap tap;
  tap.Publish(camera_firmware::media::FrameLease{});

  EXPECT_FALSE(tap.HasFreshFrame(2000ms));
}

TEST(SnapshotTapTest, PublicationClockRunsUnlockedAndLateCallCannotOverwrite) {
  using namespace std::chrono_literals;

  std::mutex callback_mutex;
  std::condition_variable callback_changed;
  int callback_count = 0;
  bool release_first_callback = false;
  camera_firmware::media::SnapshotTap tap([&] {
    std::unique_lock lock(callback_mutex);
    const int call = callback_count++;
    callback_changed.notify_all();
    if (call == 0) {
      callback_changed.wait(lock, [&] { return release_first_callback; });
    }
    return std::chrono::steady_clock::time_point{} +
           std::chrono::milliseconds(call);
  });

  camera_firmware::media::FrameHandle first_handle;
  first_handle.sequence = 1U;
  std::thread first([&] {
    tap.Publish(
        camera_firmware::media::FrameLease(std::move(first_handle), [] {}));
  });

  {
    std::unique_lock lock(callback_mutex);
    callback_changed.wait(lock, [&] { return callback_count >= 1; });
  }

  camera_firmware::media::FrameHandle second_handle;
  second_handle.sequence = 2U;
  std::thread second([&] {
    tap.Publish(
        camera_firmware::media::FrameLease(std::move(second_handle), [] {}));
  });

  bool second_clock_call_ran_before_release = false;
  {
    std::unique_lock lock(callback_mutex);
    second_clock_call_ran_before_release = callback_changed.wait_for(
        lock, 100ms, [&] { return callback_count >= 2; });
    release_first_callback = true;
  }
  callback_changed.notify_all();
  first.join();
  second.join();

  EXPECT_TRUE(second_clock_call_ran_before_release);
  const auto latest = tap.Latest();
  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(latest->handle().sequence, 2U);
}

TEST(SnapshotTapTest, SourceRunMetadataInvalidatesPriorCameraFrames) {
  using namespace std::chrono_literals;

  auto now = std::chrono::steady_clock::time_point{} + 10ms;
  camera_firmware::media::SnapshotTap tap([&now] { return now; });
  const auto first_run = tap.BeginSourceRun();
  camera_firmware::media::FrameHandle first_handle;
  first_handle.camera_id = "imx708-main";
  first_handle.sequence = 41U;
  tap.Publish(
      camera_firmware::media::FrameLease(std::move(first_handle), [] {}),
      first_run);

  auto first = tap.LatestPublication(100ms);
  ASSERT_TRUE(first.has_value());
  EXPECT_EQ(first->frame.handle().sequence, 41U);
  EXPECT_EQ(first->published_at, now);
  EXPECT_EQ(first->source_epoch, first_run);
  EXPECT_TRUE(tap.IsSourceRunCurrent(first_run));

  tap.EndSourceRun(first_run);
  EXPECT_FALSE(tap.Latest().has_value());
  EXPECT_FALSE(tap.IsSourceRunCurrent(first_run));

  const auto second_run = tap.BeginSourceRun();
  EXPECT_NE(second_run, first_run);
  camera_firmware::media::FrameHandle late_first_handle;
  late_first_handle.camera_id = "imx708-main";
  late_first_handle.sequence = 42U;
  tap.Publish(
      camera_firmware::media::FrameLease(std::move(late_first_handle), [] {}),
      first_run);
  EXPECT_FALSE(tap.Latest().has_value());

  camera_firmware::media::FrameHandle second_handle;
  second_handle.camera_id = "imx708-main";
  second_handle.sequence = 43U;
  tap.Publish(
      camera_firmware::media::FrameLease(std::move(second_handle), [] {}),
      second_run);
  auto second = tap.LatestPublication(100ms);
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(second->frame.handle().sequence, 43U);
  EXPECT_EQ(second->source_epoch, second_run);
}
