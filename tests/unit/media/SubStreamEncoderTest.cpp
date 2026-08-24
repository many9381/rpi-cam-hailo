#include "camera_firmware/media/SubStreamEncoder.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "camera_firmware/media/EncodedRing.hpp"
#include "camera_firmware/media/FrameLease.hpp"
#include "camera_firmware/media/SubStreamTap.hpp"

namespace {

using camera_firmware::media::EncodedRing;
using camera_firmware::media::FrameHandle;
using camera_firmware::media::FrameLease;
using camera_firmware::media::SubStreamEncoder;
using camera_firmware::media::SubStreamEncoderParams;
using camera_firmware::media::SubStreamTap;

int CreateMemfd(std::string_view name, const std::vector<std::uint8_t>& bytes) {
  const int fd = memfd_create(name.data(), MFD_CLOEXEC);
  if (fd < 0) {
    return fd;
  }
  if (ftruncate(fd, static_cast<off_t>(bytes.size())) != 0 ||
      write(fd, bytes.data(), bytes.size()) !=
          static_cast<ssize_t>(bytes.size())) {
    (void)close(fd);
    return -1;
  }
  return fd;
}

// A solid-grey 1920x1080 NV12 frame with a PADDED stride (stride != width),
// exactly like a real dmabuf capture buffer: this exercises the same
// stride-from-handle path production frames take, instead of the
// tightly-packed (stride == width) shape used by Nv12DownscalerTest.
FrameLease MakeSolidNv12Lease(std::uint64_t sequence) {
  constexpr std::uint32_t kWidth = 1920;
  constexpr std::uint32_t kHeight = 1080;
  constexpr std::uint32_t kStride = kWidth + 128;  // padded, != width

  std::vector<std::uint8_t> combined(
      static_cast<std::size_t>(kStride) * kHeight +
          static_cast<std::size_t>(kStride) * (kHeight / 2U),
      128U);

  const std::size_t y_size = static_cast<std::size_t>(kStride) * kHeight;
  const std::size_t uv_size =
      static_cast<std::size_t>(kStride) * (kHeight / 2U);

  const int fd = CreateMemfd("cf-substream-nv12", combined);
  EXPECT_GE(fd, 0);

  FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = kWidth;
  handle.height = kHeight;
  handle.sequence = sequence;
  handle.timestamp = std::chrono::nanoseconds(sequence * 1000000);
  handle.plane_count = 2;
  handle.planes[0] = {
      .dmabuf_fd = fd, .offset = 0, .length = y_size, .stride = kStride};
  handle.planes[1] = {.dmabuf_fd = fd,
                      .offset = y_size,
                      .length = uv_size,
                      .stride = kStride};

  return FrameLease(std::move(handle), [fd] {
    if (fd >= 0) {
      (void)close(fd);
    }
  });
}

TEST(SubStreamEncoderTest, EncodesFedFramesToSubRingAtTargetSize) {
  SubStreamTap tap;
  EncodedRing ring(8);
  SubStreamEncoderParams p{1920, 1080, 640, 360, 15, 1000, 30, "ultrafast"};
  SubStreamEncoder enc(tap, ring, p);
  ASSERT_TRUE(enc.Start().ok());
  tap.SetActive(true);
  auto reader = ring.NewReader();

  // Feed ~5 frames; each ConsumeDemand cycle the encoder RequestNexts.
  for (int i = 0; i < 5; ++i) {
    tap.PublishLatest(MakeSolidNv12Lease(static_cast<std::uint64_t>(i) + 1));
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
  }

  bool got = false;
  for (int i = 0; i < 20 && !got; ++i) {
    auto au = reader.WaitNext(std::chrono::milliseconds(50));
    got = au.has_value() && au->bytes && !au->bytes->empty();
  }
  enc.Stop();

  EXPECT_TRUE(got);
  EXPECT_GT(enc.encoded_frames(), 0u);
}

TEST(SubStreamEncoderTest, IdleWhenNoFramesFed) {
  SubStreamTap tap;
  EncodedRing ring(8);
  SubStreamEncoderParams p{1920, 1080, 640, 360, 15, 1000, 30, "ultrafast"};
  SubStreamEncoder enc(tap, ring, p);
  ASSERT_TRUE(enc.Start().ok());
  std::this_thread::sleep_for(std::chrono::milliseconds(60));
  enc.Stop();
  EXPECT_EQ(enc.encoded_frames(), 0u);
}

}  // namespace
