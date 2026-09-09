#include <gtest/gtest.h>
#include <vector>
#include "camera_firmware/media/Nv12Downscaler.hpp"
namespace {
using camera_firmware::media::Nv12Downscaler;
using camera_firmware::media::Nv12Plane;

// Build a solid-grey NV12 source (Y=128, UV=128) of the given size.
std::vector<std::uint8_t> SolidNv12(int w, int h, std::uint8_t y,
                                    std::uint8_t uv) {
  std::vector<std::uint8_t> buf(static_cast<std::size_t>(w) * h * 3 / 2);
  std::fill(buf.begin(), buf.begin() + w * h, y);
  std::fill(buf.begin() + w * h, buf.end(), uv);
  return buf;
}

TEST(Nv12DownscalerTest, ScalesToTargetDimensionsAndSize) {
  Nv12Downscaler d(1920, 1080, 640, 360);
  ASSERT_TRUE(d.valid());
  auto src = SolidNv12(1920, 1080, 128, 128);
  Nv12Plane view{src.data(), src.data() + 1920 * 1080, 1920, 1920, 1920, 1080};
  std::vector<std::uint8_t> dst;
  ASSERT_TRUE(d.Scale(view, dst));
  EXPECT_EQ(dst.size(), static_cast<std::size_t>(640) * 360 * 3 / 2);
}

TEST(Nv12DownscalerTest, PreservesASolidColour) {
  Nv12Downscaler d(1920, 1080, 640, 360);
  auto src = SolidNv12(1920, 1080, 200, 100);
  Nv12Plane view{src.data(), src.data() + 1920 * 1080, 1920, 1920, 1920, 1080};
  std::vector<std::uint8_t> dst;
  ASSERT_TRUE(d.Scale(view, dst));
  // Interior Y pixel stays ~200, interior UV ~100 (bilinear on a flat field).
  EXPECT_NEAR(dst[640 * 180 + 320], 200, 2);             // centre Y
  EXPECT_NEAR(dst[640 * 360 + 640 * 90 + 320], 100, 2);  // centre UV
}

TEST(Nv12DownscalerTest, RejectsMismatchedSourceGeometry) {
  Nv12Downscaler d(1920, 1080, 640, 360);
  auto src = SolidNv12(1280, 720, 128, 128);
  Nv12Plane view{src.data(), src.data() + 1280 * 720, 1280, 1280, 1280, 720};
  std::vector<std::uint8_t> dst;
  EXPECT_FALSE(d.Scale(view, dst));  // width/height != constructor src
}
}  // namespace
