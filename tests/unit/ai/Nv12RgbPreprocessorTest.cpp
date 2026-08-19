#include "camera_firmware/ai/Nv12RgbPreprocessor.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

#include <gtest/gtest.h>

namespace {

using camera_firmware::ai::Nv12RgbPreprocessor;
using camera_firmware::media::FrameHandle;
using camera_firmware::media::FrameLease;

int CreateAnonymousFile(const std::vector<std::uint8_t>& bytes) {
  std::array<char, 32> path{"/tmp/cf-nv12-rgb-XXXXXX"};
  const int fd = ::mkstemp(path.data());
  if (fd < 0) {
    return -1;
  }
  (void)::unlink(path.data());
  if (::ftruncate(fd, static_cast<off_t>(bytes.size())) != 0 ||
      ::write(fd, bytes.data(), bytes.size()) !=
          static_cast<ssize_t>(bytes.size())) {
    (void)::close(fd);
    return -1;
  }
  return fd;
}

FrameLease MakeNv12Lease(std::uint32_t width,
                         std::uint32_t height,
                         std::uint32_t y_stride,
                         std::uint32_t uv_stride,
                         std::size_t y_offset,
                         std::size_t uv_offset,
                         std::vector<std::uint8_t> bytes) {
  FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = width;
  handle.height = height;
  handle.plane_count = 2;
  handle.planes[0] = {0, y_offset, static_cast<std::size_t>(y_stride) * height,
                      y_stride};
  handle.planes[1] = {0,
                      uv_offset,
                      static_cast<std::size_t>(uv_stride) * ((height + 1U) / 2U),
                      uv_stride};
  const int fd = CreateAnonymousFile(bytes);
  handle.planes[0].dmabuf_fd = fd;
  handle.planes[1].dmabuf_fd = fd;
  return FrameLease(handle, [fd] {
    if (fd >= 0) {
      (void)::close(fd);
    }
  });
}

FrameLease GrayNv12Lease(std::uint32_t width,
                         std::uint32_t height,
                         std::uint8_t luma = 128U) {
  constexpr std::size_t kYOffset = 41U;
  constexpr std::size_t kUvOffset = 109U;
  const std::size_t y_plane_size = static_cast<std::size_t>(width) * height;
  const std::size_t uv_plane_size =
      static_cast<std::size_t>(width) * ((height + 1U) / 2U);
  const std::size_t total_size =
      std::max(kYOffset + y_plane_size, kUvOffset + uv_plane_size);
  std::vector<std::uint8_t> bytes(total_size, 0U);
  std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(kYOffset),
            bytes.begin() + static_cast<std::ptrdiff_t>(kYOffset + y_plane_size),
            luma);
  std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(kUvOffset),
            bytes.begin() + static_cast<std::ptrdiff_t>(kUvOffset + uv_plane_size),
            128U);
  return MakeNv12Lease(width, height, width, width, kYOffset, kUvOffset,
                       std::move(bytes));
}

// Converts a uniform, non-letterboxed `target`x`target` gray frame at the
// given luma and returns pixel 0's mapped RGB byte -- a ground-truth
// reference value for a given luma, independent of the NV12->RGB601
// conversion formula's exact constants.
std::uint8_t UniformConvertedPixel(std::uint32_t target, std::uint8_t luma) {
  Nv12RgbPreprocessor probe(target, target, false, 114U);
  auto converted = probe.Convert(GrayNv12Lease(target, target, luma));
  EXPECT_TRUE(converted.ok()) << converted.error().message;
  return converted.ok() ? converted.value()[0] : 0U;
}

FrameLease StridedBlackWhiteNv12Lease() {
  constexpr std::size_t kYOffset = 33U;
  constexpr std::size_t kUvOffset = 89U;
  std::vector<std::uint8_t> bytes(kUvOffset + 4U, 0U);
  bytes[kYOffset] = 16U;
  bytes[kYOffset + 1U] = 235U;
  bytes[kYOffset + 4U] = 16U;
  bytes[kYOffset + 5U] = 235U;
  bytes[kUvOffset] = 128U;
  bytes[kUvOffset + 1U] = 128U;
  return MakeNv12Lease(2U, 2U, 4U, 4U, kYOffset, kUvOffset,
                       std::move(bytes));
}

FrameLease InvalidFdNv12Lease() {
  FrameHandle handle;
  handle.format = "NV12";
  handle.width = 2U;
  handle.height = 2U;
  handle.plane_count = 2U;
  handle.planes[0] = {-1, 0U, 4U, 2U};
  handle.planes[1] = {-1, 4U, 2U, 2U};
  return FrameLease(handle, [] {});
}

bool RowEquals(const std::vector<std::uint8_t>& rgb,
               int row,
               int width,
               std::uint8_t value) {
  const std::size_t first = static_cast<std::size_t>(row) * width * 3U;
  const std::size_t last = first + static_cast<std::size_t>(width) * 3U;
  return std::all_of(rgb.begin() + static_cast<std::ptrdiff_t>(first),
                     rgb.begin() + static_cast<std::ptrdiff_t>(last),
                     [value](std::uint8_t pixel) { return pixel == value; });
}

// Overload for byte-offset based checking
bool RowEquals(const std::vector<std::uint8_t>& rgb,
               std::size_t first_byte,
               std::size_t last_byte,
               std::uint8_t value) {
  return std::all_of(rgb.begin() + static_cast<std::ptrdiff_t>(first_byte),
                     rgb.begin() + static_cast<std::ptrdiff_t>(last_byte),
                     [value](std::uint8_t pixel) { return pixel == value; });
}

}  // namespace

TEST(Nv12RgbPreprocessorTest, LetterboxesWithBilinearRgbAnd114Padding) {
  Nv12RgbPreprocessor preprocessor(4, 4, true, 114U);
  auto converted = preprocessor.Convert(GrayNv12Lease(8, 4));
  ASSERT_TRUE(converted.ok()) << converted.error().message;
  ASSERT_EQ(converted.value().size(), 4U * 4U * 3U);
  EXPECT_TRUE(RowEquals(converted.value(), 0, 4, 114U));
  EXPECT_TRUE(RowEquals(converted.value(), 3, 4, 114U));
}

TEST(Nv12RgbPreprocessorTest, AcceptsPaddedSourceStrides) {
  Nv12RgbPreprocessor preprocessor(2, 2, false, 114U);
  auto converted = preprocessor.Convert(StridedBlackWhiteNv12Lease());
  ASSERT_TRUE(converted.ok()) << converted.error().message;
  EXPECT_NEAR(converted.value()[0], 0, 2);
  EXPECT_NEAR(converted.value()[3], 255, 2);
}

TEST(Nv12RgbPreprocessorTest, RejectsInvalidDmabufWithoutMapping) {
  Nv12RgbPreprocessor preprocessor(2, 2, false, 114U);
  auto converted = preprocessor.Convert(InvalidFdNv12Lease());
  ASSERT_FALSE(converted.ok());
  EXPECT_EQ(converted.error().code, "E_AI_PREPROCESS");
}

TEST(Nv12RgbPreprocessorTest, RepeatedConvertCallsProduceIdenticalOutput) {
  // General determinism guard: converting the same source geometry twice on
  // the same preprocessor instance, from the same still-open lease, must
  // produce byte-for-byte identical output both times. This also exercises
  // the dmabuf mmap cache's hit path against a stable, unchanged fd (the
  // lease is not destroyed between calls) -- a cache hit must return the
  // same correct data as the first mapping did.
  Nv12RgbPreprocessor preprocessor(4, 4, true, 114U);
  const auto lease = GrayNv12Lease(8, 4);

  auto first = preprocessor.Convert(lease);
  ASSERT_TRUE(first.ok()) << first.error().message;
  auto second = preprocessor.Convert(lease);
  ASSERT_TRUE(second.ok()) << second.error().message;

  EXPECT_EQ(first.value(), second.value());
  EXPECT_TRUE(RowEquals(second.value(), 0, 4, 114U));
  EXPECT_TRUE(RowEquals(second.value(), 3, 4, 114U));
}

TEST(Nv12RgbPreprocessorTest, GeometryChangeRepadsPreviouslyContentColumns) {
  // First call letterboxes an 8x4 (2:1) DARK source into a 4x4 target:
  // content occupies rows 1-2 (full width), rows 0 and 3 are top/bottom
  // padding. Second call, on the SAME preprocessor instance, letterboxes a
  // 4x8 (1:2) BRIGHT source into the same 4x4 target: content occupies
  // columns 1-2 for every row, columns 0 and 3 are left/right padding --
  // including in rows 1-2, which held real (non-114) pixel data after the
  // first call.
  //
  // The two fixtures deliberately use different luma values (not the same
  // implicit 128 both times): the first call's lease is destroyed before
  // the second call's lease is created, and both leases share identical
  // (width, height) -> identical dmabuf plane offsets/lengths, which is
  // exactly the shape of dmabuf fd recycling this preprocessor's mmap
  // cache must not be fooled by (see CacheDoesNotServeStaleDataAfterFdRecycling
  // for a more direct test of that). If the geometry-change pad logic or a
  // stale cached mapping ever let the first call's data leak through, the
  // pad bytes would stay 114 (this part alone wouldn't show it) but the
  // *content* columns below would come back dark instead of bright.
  constexpr std::uint8_t kDarkLuma = 40U;
  constexpr std::uint8_t kBrightLuma = 200U;
  const std::uint8_t bright_pixel = UniformConvertedPixel(4U, kBrightLuma);
  const std::uint8_t dark_pixel = UniformConvertedPixel(4U, kDarkLuma);
  ASSERT_GT(static_cast<int>(bright_pixel) - static_cast<int>(dark_pixel), 40)
      << "test fixture setup: dark/bright luma values did not map to "
         "distinguishable RGB pixels (bright=" << static_cast<int>(bright_pixel)
      << " dark=" << static_cast<int>(dark_pixel) << ")";

  Nv12RgbPreprocessor preprocessor(4, 4, true, 114U);

  auto landscape = preprocessor.Convert(GrayNv12Lease(8, 4, kDarkLuma));
  ASSERT_TRUE(landscape.ok()) << landscape.error().message;
  EXPECT_TRUE(RowEquals(landscape.value(), 0, 4, 114U));
  EXPECT_TRUE(RowEquals(landscape.value(), 3, 4, 114U));

  auto portrait = preprocessor.Convert(GrayNv12Lease(4, 8, kBrightLuma));
  ASSERT_TRUE(portrait.ok()) << portrait.error().message;
  ASSERT_EQ(portrait.value().size(), 4U * 4U * 3U);

  constexpr std::size_t kBytesPerPixel = 3U;
  constexpr std::size_t kRowBytes = 4U * kBytesPerPixel;
  for (int row = 0; row < 4; ++row) {
    const std::size_t row_start = static_cast<std::size_t>(row) * kRowBytes;
    // Column 0 (left pad) and column 3 (right pad) must be 114 in every row,
    // including rows 1 and 2 which were letterbox *content* rows for the
    // previous (landscape) geometry.
    EXPECT_TRUE(RowEquals(portrait.value(), row_start, row_start + kBytesPerPixel,
                          114U))
        << "row " << row << " left pad";
    EXPECT_TRUE(RowEquals(portrait.value(), row_start + 3U * kBytesPerPixel,
                          row_start + kRowBytes, 114U))
        << "row " << row << " right pad";

    // Content columns (1-2) must reflect the SECOND (bright) lease, not the
    // first (dark) one.
    const std::size_t content_start = row_start + kBytesPerPixel;
    const std::size_t content_end = content_start + 2U * kBytesPerPixel;
    for (std::size_t byte = content_start; byte < content_end; ++byte) {
      EXPECT_NEAR(portrait.value()[byte], bright_pixel, 3)
          << "row " << row << " content byte " << byte
          << " (dark reference was " << static_cast<int>(dark_pixel) << ")";
    }
  }
}

TEST(Nv12RgbPreprocessorTest, CacheDoesNotServeStaleDataAfterFdRecycling) {
  // Direct regression test for the dmabuf mmap cache silently serving a
  // stale mapping after its backing fd is closed and the OS recycles that
  // exact fd number for a later, unrelated buffer (reviewer repro: "dark
  // frame decoded as bright"). Lease A and lease B share identical
  // dimensions and plane offsets/lengths, so once lease A's fd is closed
  // and recycled for lease B they collide on the SAME (fd, mapping_offset,
  // mapping_size) cache key -- only an identity check (fstat st_dev/st_ino)
  // can tell the two apart.
  Nv12RgbPreprocessor preprocessor(2, 2, false, 114U);

  constexpr std::uint8_t kLumaA = 40U;
  constexpr std::uint8_t kLumaB = 200U;

  int fd_a = -1;
  {
    auto lease_a = GrayNv12Lease(2, 2, kLumaA);
    fd_a = lease_a.handle().planes[0].dmabuf_fd;
    auto converted_a = preprocessor.Convert(lease_a);
    ASSERT_TRUE(converted_a.ok()) << converted_a.error().message;
  }  // lease_a destroyed here: its release callback closes fd_a.

  auto lease_b = GrayNv12Lease(2, 2, kLumaB);
  const int fd_b = lease_b.handle().planes[0].dmabuf_fd;
  ASSERT_EQ(fd_a, fd_b)
      << "test precondition not met: expected the OS to recycle the "
         "just-closed fd number for lease B's mkstemp() call";

  auto converted_b = preprocessor.Convert(lease_b);
  ASSERT_TRUE(converted_b.ok()) << converted_b.error().message;

  // A stale (pre-fix) cache hit would read back lease A's (dark) data
  // instead of lease B's (bright) data.
  EXPECT_GT(converted_b.value()[0], 150U)
      << "content pixel reflects lease A's (stale) luma instead of lease "
         "B's -- the mmap cache served a dead mapping after fd recycling";
}

TEST(Nv12RgbPreprocessorTest, LoresSourceHasSameLetterboxGeometryAsFullSource) {
  // A 640x640 letterbox model input. A 16:9 source letterboxes to a 640x360
  // content band centred vertically: rows 0..139 and 500..639 are 114 padding,
  // rows 140..499 are content. This must hold identically whether the source
  // is the 1920x1080 main frame (today) or the 640x360 lores frame (this
  // feature), proving the detector sees the same geometry.
  constexpr std::size_t kBytesPerRow = 640U * 3U;
  const auto pad_top_end = 140U * kBytesPerRow;
  const auto pad_bottom_begin = 500U * kBytesPerRow;
  const auto output_bytes = 640U * 640U * 3U;

  for (const auto& source : {std::pair<std::uint32_t, std::uint32_t>{1920U, 1080U},
                             std::pair<std::uint32_t, std::uint32_t>{640U, 360U}}) {
    Nv12RgbPreprocessor preprocessor(640, 640, true, 114U);
    auto converted = preprocessor.Convert(GrayNv12Lease(source.first, source.second));
    ASSERT_TRUE(converted.ok()) << converted.error().message
                                << " for " << source.first << "x" << source.second;
    ASSERT_EQ(converted.value().size(), output_bytes);
    // Top and bottom padding bands are exactly 114.
    EXPECT_TRUE(RowEquals(converted.value(), 0U, pad_top_end, 114U))
        << source.first << "x" << source.second;
    EXPECT_TRUE(RowEquals(converted.value(), pad_bottom_begin, output_bytes, 114U))
        << source.first << "x" << source.second;
    // The first content row (140) is not padding — content is present there.
    EXPECT_FALSE(RowEquals(converted.value(), pad_top_end,
                           pad_top_end + kBytesPerRow, 114U))
        << source.first << "x" << source.second;
  }
}
