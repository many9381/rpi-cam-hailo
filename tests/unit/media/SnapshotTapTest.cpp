#include "camera_firmware/media/SnapshotTap.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

namespace {

int CreateNv12Memfd() {
  int fd = memfd_create("cf-nv12-snapshot", MFD_CLOEXEC);
  if (fd < 0) {
    return fd;
  }
  const std::vector<std::uint8_t> nv12{
      0x40, 0x80, 0x80, 0xc0,
      0x80, 0x80,
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
  tap.Publish(camera_firmware::media::FrameLease(std::move(handle), [fd] {
    close(fd);
  }));

  auto jpeg = camera_firmware::media::BuildLatestSnapshotJpeg(
      tap, "imx708-main");

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
