#include "camera_firmware/media/JpegEncoder.hpp"

#include <fcntl.h>
#include <linux/dma-buf.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include <jpeglib.h>

namespace {

using camera_firmware::media::FrameHandle;
using camera_firmware::media::FrameLease;

struct SyncCall {
  int fd;
  std::uint64_t flags;
};

enum class SyncMode {
  kCallReal,
  kSucceed,
  kFailAtCall,
};

struct SyncControl {
  std::mutex mutex;
  SyncMode mode{SyncMode::kCallReal};
  std::size_t failure_call{0U};
  int failure_errno{EIO};
  std::vector<SyncCall> calls;
};

SyncControl& DmaBufSyncControl() {
  static SyncControl control;
  return control;
}

void ResetDmaBufSync() {
  auto& control = DmaBufSyncControl();
  std::lock_guard lock(control.mutex);
  control.mode = SyncMode::kCallReal;
  control.failure_call = 0U;
  control.failure_errno = EIO;
  control.calls.clear();
}

void SucceedDmaBufSync() {
  auto& control = DmaBufSyncControl();
  std::lock_guard lock(control.mutex);
  control.mode = SyncMode::kSucceed;
}

void FailDmaBufSyncAt(std::size_t call, int error) {
  auto& control = DmaBufSyncControl();
  std::lock_guard lock(control.mutex);
  control.mode = SyncMode::kFailAtCall;
  control.failure_call = call;
  control.failure_errno = error;
}

std::vector<SyncCall> DmaBufSyncCalls() {
  auto& control = DmaBufSyncControl();
  std::lock_guard lock(control.mutex);
  return control.calls;
}

}  // namespace

extern "C" int __real_ioctl(int fd, unsigned long request, ...);

extern "C" int __wrap_ioctl(int fd, unsigned long request, ...) {
  va_list arguments;
  va_start(arguments, request);
  void* argument = va_arg(arguments, void*);
  va_end(arguments);

  if (request != DMA_BUF_IOCTL_SYNC) {
    return __real_ioctl(fd, request, argument);
  }

  const auto* sync = static_cast<const dma_buf_sync*>(argument);
  auto& control = DmaBufSyncControl();
  SyncMode mode = SyncMode::kCallReal;
  std::size_t call_index = 0U;
  std::size_t failure_call = 0U;
  int failure_errno = EIO;
  {
    std::lock_guard lock(control.mutex);
    call_index = control.calls.size();
    control.calls.push_back(SyncCall{fd, sync->flags});
    mode = control.mode;
    failure_call = control.failure_call;
    failure_errno = control.failure_errno;
  }

  if (mode == SyncMode::kSucceed) {
    return 0;
  }
  if (mode == SyncMode::kFailAtCall && call_index == failure_call) {
    errno = failure_errno;
    return -1;
  }
  if (mode == SyncMode::kFailAtCall) {
    return 0;
  }
  return __real_ioctl(fd, request, argument);
}

namespace {

struct JpegDimensions {
  unsigned int width;
  unsigned int height;
};

struct RgbPixel {
  unsigned int red;
  unsigned int green;
  unsigned int blue;
};

struct DistinctNv12Frame {
  FrameLease lease;
  int y_fd;
  int uv_fd;
};

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

int CreateNv12Memfd() {
  const std::vector<std::uint8_t> nv12{
      0x20, 0x40, 0x80, 0xc0, 0x30, 0x50, 0x90, 0xd0, 0x80, 0x80, 0x80, 0x80,
  };
  return CreateMemfd("cf-nv12-encoder", nv12);
}

FrameLease Nv12Lease() {
  const int fd = CreateNv12Memfd();
  EXPECT_GE(fd, 0);

  FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 4;
  handle.height = 2;
  handle.plane_count = 2;
  handle.planes[0] = {.dmabuf_fd = fd, .offset = 0, .length = 8, .stride = 4};
  handle.planes[1] = {.dmabuf_fd = fd, .offset = 8, .length = 4, .stride = 4};
  return FrameLease(std::move(handle), [fd] {
    if (fd >= 0) {
      (void)close(fd);
    }
  });
}

DistinctNv12Frame OffsetPaddedColorLease() {
  constexpr std::size_t kYPlaneOffset = 3U;
  constexpr std::size_t kYStride = 11U;
  constexpr std::size_t kYPlaneLength = 7U * kYStride + 8U;
  std::vector<std::uint8_t> y_bytes(kYPlaneOffset + kYPlaneLength, 0U);
  for (std::size_t row = 0U; row < 8U; ++row) {
    for (std::size_t column = 0U; column < 8U; ++column) {
      y_bytes[kYPlaneOffset + row * kYStride + column] = 128U;
    }
  }

  constexpr std::size_t kUvPlaneOffset = 5U;
  constexpr std::size_t kUvStride = 12U;
  constexpr std::size_t kUvPlaneLength = 3U * kUvStride + 8U;
  std::vector<std::uint8_t> uv_bytes(kUvPlaneOffset + kUvPlaneLength, 0U);
  for (std::size_t row = 0U; row < 4U; ++row) {
    const std::uint8_t u = row < 2U ? 255U : 0U;
    const std::uint8_t v = row < 2U ? 0U : 255U;
    for (std::size_t pair = 0U; pair < 4U; ++pair) {
      const std::size_t offset = kUvPlaneOffset + row * kUvStride + pair * 2U;
      uv_bytes[offset] = u;
      uv_bytes[offset + 1U] = v;
    }
  }

  const int y_fd = CreateMemfd("cf-nv12-y", y_bytes);
  const int uv_fd = CreateMemfd("cf-nv12-uv", uv_bytes);
  EXPECT_GE(y_fd, 0);
  EXPECT_GE(uv_fd, 0);

  FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 8U;
  handle.height = 8U;
  handle.plane_count = 2U;
  handle.planes[0] = {.dmabuf_fd = y_fd,
                      .offset = kYPlaneOffset,
                      .length = kYPlaneLength,
                      .stride = kYStride};
  handle.planes[1] = {.dmabuf_fd = uv_fd,
                      .offset = kUvPlaneOffset,
                      .length = kUvPlaneLength,
                      .stride = kUvStride};
  return {FrameLease(std::move(handle),
                     [y_fd, uv_fd] {
                       if (y_fd >= 0) {
                         (void)close(y_fd);
                       }
                       if (uv_fd >= 0) {
                         (void)close(uv_fd);
                       }
                     }),
          y_fd, uv_fd};
}

bool IsStartOfFrame(std::uint8_t marker) {
  return (marker >= 0xc0U && marker <= 0xc3U) ||
         (marker >= 0xc5U && marker <= 0xc7U) ||
         (marker >= 0xc9U && marker <= 0xcbU) ||
         (marker >= 0xcdU && marker <= 0xcfU);
}

std::optional<JpegDimensions> ReadJpegDimensions(
    const camera_firmware::media::JpegBytes& jpeg_bytes) {
  const auto* bytes_data =
      reinterpret_cast<const std::uint8_t*>(jpeg_bytes.data());
  const std::vector<std::uint8_t> bytes(bytes_data,
                                        bytes_data + jpeg_bytes.size());
  if (bytes.size() < 4U || bytes[0] != 0xffU || bytes[1] != 0xd8U ||
      bytes[bytes.size() - 2U] != 0xffU || bytes.back() != 0xd9U) {
    return std::nullopt;
  }

  std::size_t cursor = 2U;
  while (cursor < bytes.size()) {
    while (cursor < bytes.size() && bytes[cursor] == 0xffU) {
      ++cursor;
    }
    if (cursor >= bytes.size()) {
      return std::nullopt;
    }
    const std::uint8_t marker = bytes[cursor++];
    if (marker == 0x00U || marker == 0x01U ||
        (marker >= 0xd0U && marker <= 0xd9U)) {
      continue;
    }
    if (cursor + 2U > bytes.size()) {
      return std::nullopt;
    }
    const std::size_t segment_length =
        (static_cast<std::size_t>(bytes[cursor]) << 8U) | bytes[cursor + 1U];
    if (segment_length < 2U || segment_length > bytes.size() - cursor) {
      return std::nullopt;
    }
    if (IsStartOfFrame(marker)) {
      if (segment_length < 7U) {
        return std::nullopt;
      }
      const unsigned int height =
          (static_cast<unsigned int>(bytes[cursor + 3U]) << 8U) |
          bytes[cursor + 4U];
      const unsigned int width =
          (static_cast<unsigned int>(bytes[cursor + 5U]) << 8U) |
          bytes[cursor + 6U];
      return JpegDimensions{width, height};
    }
    cursor += segment_length;
  }
  return std::nullopt;
}

struct JpegDecompressError {
  jpeg_error_mgr pub;
  jmp_buf jump;
};

struct JpegDecompressState {
  jpeg_decompress_struct decompressor{};
  JpegDecompressError error{};
  bool creation_attempted{false};
};

void JpegDecompressErrorExit(j_common_ptr cinfo) {
  auto* error = reinterpret_cast<JpegDecompressError*>(cinfo->err);
  longjmp(error->jump, 1);
}

void SuppressJpegMessage(j_common_ptr) {}

std::optional<std::vector<std::uint8_t>> DecodeJpegRgb(
    const camera_firmware::media::JpegBytes& jpeg, unsigned int expected_width,
    unsigned int expected_height) {
  std::vector<std::uint8_t> rgb(static_cast<std::size_t>(expected_width) *
                                expected_height * 3U);
  auto state = std::make_unique<JpegDecompressState>();
  state->decompressor.err = jpeg_std_error(&state->error.pub);
  state->error.pub.error_exit = JpegDecompressErrorExit;
  state->error.pub.output_message = SuppressJpegMessage;
  if (setjmp(state->error.jump) != 0) {
    if (state->creation_attempted) {
      jpeg_destroy_decompress(&state->decompressor);
    }
    return std::nullopt;
  }

  state->creation_attempted = true;
  jpeg_create_decompress(&state->decompressor);
  jpeg_mem_src(&state->decompressor,
               reinterpret_cast<const unsigned char*>(jpeg.data()),
               jpeg.size());
  if (jpeg_read_header(&state->decompressor, TRUE) != JPEG_HEADER_OK) {
    jpeg_destroy_decompress(&state->decompressor);
    return std::nullopt;
  }
  state->decompressor.out_color_space = JCS_RGB;
  (void)jpeg_start_decompress(&state->decompressor);
  if (state->decompressor.output_width != expected_width ||
      state->decompressor.output_height != expected_height ||
      state->decompressor.output_components != 3U) {
    jpeg_destroy_decompress(&state->decompressor);
    return std::nullopt;
  }

  const std::size_t row_bytes = static_cast<std::size_t>(expected_width) * 3U;
  while (state->decompressor.output_scanline < expected_height) {
    JSAMPROW row = rgb.data() + static_cast<std::size_t>(
                                    state->decompressor.output_scanline) *
                                    row_bytes;
    if (jpeg_read_scanlines(&state->decompressor, &row, 1U) != 1U) {
      jpeg_destroy_decompress(&state->decompressor);
      return std::nullopt;
    }
  }
  (void)jpeg_finish_decompress(&state->decompressor);
  jpeg_destroy_decompress(&state->decompressor);
  state->creation_attempted = false;
  return rgb;
}

RgbPixel PixelAt(const std::vector<std::uint8_t>& rgb, unsigned int width,
                 unsigned int column, unsigned int row) {
  const std::size_t index =
      (static_cast<std::size_t>(row) * width + column) * 3U;
  return {rgb[index], rgb[index + 1U], rgb[index + 2U]};
}

void ExpectSyncCall(const std::vector<SyncCall>& calls, std::size_t index,
                    int fd, std::uint64_t flags) {
  ASSERT_LT(index, calls.size());
  EXPECT_EQ(calls[index].fd, fd);
  EXPECT_EQ(calls[index].flags, flags);
}

class JpegEncoderTest : public ::testing::Test {
 protected:
  void SetUp() override { ResetDmaBufSync(); }
  void TearDown() override { ResetDmaBufSync(); }
};

TEST_F(JpegEncoderTest, EncodesNv12AtSourceWidthAsValidJpeg) {
  auto lease = Nv12Lease();

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(lease, 4U, 85U);

  ASSERT_TRUE(encoded.ok()) << encoded.error().message;
  const auto dimensions = ReadJpegDimensions(encoded.value().bytes);
  ASSERT_TRUE(dimensions.has_value());
  EXPECT_EQ(encoded.value().width, 4U);
  EXPECT_EQ(encoded.value().height, 2U);
  EXPECT_EQ(dimensions->width, 4U);
  EXPECT_EQ(dimensions->height, 2U);
}

TEST_F(JpegEncoderTest, ScalesWithoutEnlargingAndKeepsHeightEven) {
  auto lease = Nv12Lease();

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(lease, 2U, 85U);

  ASSERT_TRUE(encoded.ok()) << encoded.error().message;
  const auto dimensions = ReadJpegDimensions(encoded.value().bytes);
  ASSERT_TRUE(dimensions.has_value());
  EXPECT_EQ(encoded.value().width, 2U);
  EXPECT_EQ(encoded.value().height, 2U);
  EXPECT_LE(encoded.value().width, lease->width);
  EXPECT_LE(encoded.value().height, lease->height);
  EXPECT_EQ(encoded.value().height % 2U, 0U);
  EXPECT_EQ(dimensions->width, encoded.value().width);
  EXPECT_EQ(dimensions->height, encoded.value().height);
}

TEST_F(JpegEncoderTest, DoesNotUpscaleBeyondSourceWidth) {
  auto lease = Nv12Lease();

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(lease, 8U, 85U);

  ASSERT_TRUE(encoded.ok()) << encoded.error().message;
  EXPECT_EQ(encoded.value().width, 4U);
  EXPECT_EQ(encoded.value().height, 2U);
}

TEST_F(JpegEncoderTest, RejectsShortNv12PlaneLengths) {
  auto source = Nv12Lease();
  FrameHandle handle = source.handle();
  handle.planes[0].length = 7U;
  FrameLease short_frame(std::move(handle), [] {});

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(
      short_frame, short_frame->width, 85U);

  ASSERT_FALSE(encoded.ok());
  EXPECT_EQ(encoded.error().code, "E_JPEG_ENCODE");
}

TEST_F(JpegEncoderTest, RejectsPlaneOffsetLengthOverflow) {
  auto source = Nv12Lease();
  FrameHandle handle = source.handle();
  handle.planes[0].offset = std::numeric_limits<std::size_t>::max();
  handle.planes[0].length = 1U;
  FrameLease overflowing_frame(std::move(handle), [] {});

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(
      overflowing_frame, overflowing_frame->width, 85U);

  ASSERT_FALSE(encoded.ok());
  EXPECT_EQ(encoded.error().code, "E_JPEG_ENCODE");
}

TEST_F(JpegEncoderTest, EndsAllStartedFdsWhenPlaneMappingFails) {
  SucceedDmaBufSync();
  auto source = Nv12Lease();
  const int fd = source->planes[0].dmabuf_fd;
  FrameHandle handle = source.handle();
  handle.planes[1].offset = 12U;
  FrameLease out_of_range_frame(std::move(handle), [] {});

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(
      out_of_range_frame, out_of_range_frame->width, 85U);

  ASSERT_FALSE(encoded.ok());
  EXPECT_EQ(encoded.error().code, "E_JPEG_ENCODE");
  const auto calls = DmaBufSyncCalls();
  ASSERT_EQ(calls.size(), 2U);
  ExpectSyncCall(calls, 0U, fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ);
  ExpectSyncCall(calls, 1U, fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ);
}

TEST_F(JpegEncoderTest, RejectsZeroQuality) {
  auto lease = Nv12Lease();

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(lease, 4U, 0U);

  ASSERT_FALSE(encoded.ok());
  EXPECT_EQ(encoded.error().code, "E_JPEG_ENCODE");
}

TEST_F(JpegEncoderTest, RejectsQualityAboveHundred) {
  auto lease = Nv12Lease();

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(lease, 4U, 101U);

  ASSERT_FALSE(encoded.ok());
  EXPECT_EQ(encoded.error().code, "E_JPEG_ENCODE");
}

TEST_F(JpegEncoderTest, AllowsMemfdEnottyAndSyncsSharedFdOnce) {
  auto lease = Nv12Lease();
  const int fd = lease->planes[0].dmabuf_fd;

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(lease, 4U, 85U);

  ASSERT_TRUE(encoded.ok()) << encoded.error().message;
  const auto calls = DmaBufSyncCalls();
  ASSERT_EQ(calls.size(), 2U);
  ExpectSyncCall(calls, 0U, fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ);
  ExpectSyncCall(calls, 1U, fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ);
}

TEST_F(JpegEncoderTest, RetriesInterruptedSyncStart) {
  FailDmaBufSyncAt(0U, EINTR);
  auto lease = Nv12Lease();
  const int fd = lease->planes[0].dmabuf_fd;

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(lease, 4U, 85U);

  ASSERT_TRUE(encoded.ok()) << encoded.error().message;
  const auto calls = DmaBufSyncCalls();
  ASSERT_EQ(calls.size(), 3U);
  ExpectSyncCall(calls, 0U, fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ);
  ExpectSyncCall(calls, 1U, fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ);
  ExpectSyncCall(calls, 2U, fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ);
}

TEST_F(JpegEncoderTest, RetriesInterruptedSyncEndBeforeRetiringFd) {
  FailDmaBufSyncAt(1U, EINTR);
  auto lease = Nv12Lease();
  const int fd = lease->planes[0].dmabuf_fd;

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(lease, 4U, 85U);

  ASSERT_TRUE(encoded.ok()) << encoded.error().message;
  const auto calls = DmaBufSyncCalls();
  ASSERT_EQ(calls.size(), 3U);
  ExpectSyncCall(calls, 0U, fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ);
  ExpectSyncCall(calls, 1U, fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ);
  ExpectSyncCall(calls, 2U, fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ);
}

TEST_F(JpegEncoderTest, EndsFirstFdWhenSecondSyncStartFails) {
  FailDmaBufSyncAt(1U, EIO);
  auto frame = OffsetPaddedColorLease();

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(
      frame.lease, frame.lease->width, 100U);

  ASSERT_FALSE(encoded.ok());
  EXPECT_EQ(encoded.error().code, "E_JPEG_ENCODE");
  const auto calls = DmaBufSyncCalls();
  ASSERT_EQ(calls.size(), 3U);
  ExpectSyncCall(calls, 0U, frame.y_fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ);
  ExpectSyncCall(calls, 1U, frame.uv_fd,
                 DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ);
  ExpectSyncCall(calls, 2U, frame.y_fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ);
}

TEST_F(JpegEncoderTest, FailsClosedWhenSyncEndFails) {
  FailDmaBufSyncAt(1U, EIO);
  auto lease = Nv12Lease();

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(lease, 4U, 85U);

  ASSERT_FALSE(encoded.ok());
  EXPECT_EQ(encoded.error().code, "E_JPEG_ENCODE");
  EXPECT_EQ(DmaBufSyncCalls().size(), 2U);
}

TEST_F(JpegEncoderTest, ReadsOffsetPaddedDistinctPlanesWithCorrectNv12Color) {
  SucceedDmaBufSync();
  auto frame = OffsetPaddedColorLease();

  auto encoded = camera_firmware::media::EncodeNv12Jpeg(
      frame.lease, frame.lease->width, 100U);

  ASSERT_TRUE(encoded.ok()) << encoded.error().message;
  auto rgb = DecodeJpegRgb(encoded.value().bytes, 8U, 8U);
  ASSERT_TRUE(rgb.has_value());
  const RgbPixel top = PixelAt(*rgb, 8U, 3U, 1U);
  const RgbPixel bottom = PixelAt(*rgb, 8U, 3U, 6U);
  EXPECT_LT(top.red, 70U);
  EXPECT_GT(top.green, 140U);
  EXPECT_GT(top.blue, 210U);
  EXPECT_GT(bottom.red, 210U);
  EXPECT_LT(bottom.green, 130U);
  EXPECT_LT(bottom.blue, 70U);

  const auto calls = DmaBufSyncCalls();
  ASSERT_EQ(calls.size(), 4U);
  ExpectSyncCall(calls, 0U, frame.y_fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ);
  ExpectSyncCall(calls, 1U, frame.uv_fd,
                 DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ);
  ExpectSyncCall(calls, 2U, frame.uv_fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ);
  ExpectSyncCall(calls, 3U, frame.y_fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ);
}

}  // namespace
