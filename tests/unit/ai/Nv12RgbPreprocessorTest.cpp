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

FrameLease GrayNv12Lease(std::uint32_t width, std::uint32_t height) {
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
            128U);
  std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(kUvOffset),
            bytes.begin() + static_cast<std::ptrdiff_t>(kUvOffset + uv_plane_size),
            128U);
  return MakeNv12Lease(width, height, width, width, kYOffset, kUvOffset,
                       std::move(bytes));
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
