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

// A solid-grey NV12 frame with a PADDED stride (stride != width), exactly
// like a real dmabuf capture buffer: this exercises the same
// stride-from-handle path production frames take, instead of the
// tightly-packed (stride == width) shape used by Nv12DownscalerTest.
FrameLease MakeSolidNv12LeaseWithGeometry(std::uint64_t sequence,
                                          std::uint32_t width,
                                          std::uint32_t height) {
  const std::uint32_t stride = width + 128;  // padded, != width

  const std::size_t y_size = static_cast<std::size_t>(stride) * height;
  const std::size_t uv_size = static_cast<std::size_t>(stride) * (height / 2U);
  std::vector<std::uint8_t> combined(y_size + uv_size, 128U);

  const int fd = CreateMemfd("cf-substream-nv12", combined);
  EXPECT_GE(fd, 0);

  FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = width;
  handle.height = height;
  handle.sequence = sequence;
  handle.timestamp = std::chrono::nanoseconds(sequence * 1000000);
  handle.plane_count = 2;
  handle.planes[0] = {
      .dmabuf_fd = fd, .offset = 0, .length = y_size, .stride = stride};
  handle.planes[1] = {.dmabuf_fd = fd,
                      .offset = y_size,
                      .length = uv_size,
                      .stride = stride};

  return FrameLease(std::move(handle), [fd] {
    if (fd >= 0) {
      (void)close(fd);
    }
  });
}

FrameLease MakeSolidNv12Lease(std::uint64_t sequence) {
  return MakeSolidNv12LeaseWithGeometry(sequence, 1920, 1080);
}

// The handle's own width/height/plane_count are self-consistent and match
// the encoder's configured src geometry (1920x1080), but the Y plane's
// declared `length` only covers half the rows its own stride*height (as
// implied by that geometry) requires. MapPlaneReadOnly sizes its mmap from
// plane.offset+plane.length, so a caller that trusted the declared length
// but then read params.src_height rows anyway would walk straight past the
// real mapping (a genuine SIGBUS risk, not just a logic bug) if the
// plane.length-vs-stride*rows guard were missing or wrong.
FrameLease MakeUndersizedYPlaneLease() {
  constexpr std::uint32_t kWidth = 1920;
  constexpr std::uint32_t kHeight = 1080;
  constexpr std::uint32_t kStride = kWidth + 128;

  const std::size_t short_y_rows = kHeight / 2U;
  const std::size_t short_y_size =
      static_cast<std::size_t>(kStride) * short_y_rows;
  const std::size_t uv_size = static_cast<std::size_t>(kStride) * (kHeight / 2U);

  std::vector<std::uint8_t> y_bytes(short_y_size, 128U);
  std::vector<std::uint8_t> uv_bytes(uv_size, 128U);

  const int y_fd = CreateMemfd("cf-substream-y-short", y_bytes);
  const int uv_fd = CreateMemfd("cf-substream-uv", uv_bytes);
  EXPECT_GE(y_fd, 0);
  EXPECT_GE(uv_fd, 0);

  FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = kWidth;
  handle.height = kHeight;  // matches params -- the geometry check alone
                            // can't catch this; the plane-length check must.
  handle.sequence = 1;
  handle.timestamp = std::chrono::nanoseconds(0);
  handle.plane_count = 2;
  handle.planes[0] = {.dmabuf_fd = y_fd,
                      .offset = 0,
                      .length = short_y_size,
                      .stride = kStride};
  handle.planes[1] = {
      .dmabuf_fd = uv_fd, .offset = 0, .length = uv_size, .stride = kStride};

  return FrameLease(std::move(handle), [y_fd, uv_fd] {
    if (y_fd >= 0) {
      (void)close(y_fd);
    }
    if (uv_fd >= 0) {
      (void)close(uv_fd);
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

// A lease whose handle reports 1280x720 fed to an encoder configured for
// 1920x1080 must be rejected (counted, not crashed on) instead of being
// scaled with the wrong source geometry.
TEST(SubStreamEncoderTest, SkipsFrameWithMismatchedGeometry) {
  SubStreamTap tap;
  EncodedRing ring(8);
  SubStreamEncoderParams p{1920, 1080, 640, 360, 15, 1000, 30, "ultrafast"};
  SubStreamEncoder enc(tap, ring, p);
  ASSERT_TRUE(enc.Start().ok());
  tap.SetActive(true);
  auto reader = ring.NewReader();

  tap.PublishLatest(MakeSolidNv12LeaseWithGeometry(1, 1280, 720));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  enc.Stop();

  EXPECT_GT(enc.error_count(), 0u);
  EXPECT_EQ(enc.encoded_frames(), 0u);
  EXPECT_FALSE(reader.WaitNext(std::chrono::milliseconds(10)).has_value());
}

// A lease whose width/height matches the configured src geometry, but whose
// Y plane's declared length can't actually cover src_height rows at its own
// stride, must also be rejected rather than mapped/scaled (see
// MakeUndersizedYPlaneLease for why this is a real out-of-bounds-read risk,
// not just a logic-level mismatch).
TEST(SubStreamEncoderTest, SkipsFrameWithUndersizedPlaneLength) {
  SubStreamTap tap;
  EncodedRing ring(8);
  SubStreamEncoderParams p{1920, 1080, 640, 360, 15, 1000, 30, "ultrafast"};
  SubStreamEncoder enc(tap, ring, p);
  ASSERT_TRUE(enc.Start().ok());
  tap.SetActive(true);
  auto reader = ring.NewReader();

  tap.PublishLatest(MakeUndersizedYPlaneLease());
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  enc.Stop();

  EXPECT_GT(enc.error_count(), 0u);
  EXPECT_EQ(enc.encoded_frames(), 0u);
  EXPECT_FALSE(reader.WaitNext(std::chrono::milliseconds(10)).has_value());
}

}  // namespace
