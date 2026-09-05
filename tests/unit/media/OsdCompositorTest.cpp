#include "camera_firmware/media/OsdCompositor.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/TextRasterizer.hpp"

namespace {

using camera_firmware::config::CameraOsdConfig;
using camera_firmware::config::CameraOsdItem;
using camera_firmware::media::Nv12MutableView;
using camera_firmware::media::OsdCompositor;
using camera_firmware::media::OsdLayoutMetrics;
using camera_firmware::media::TextRasterizer;

constexpr std::size_t kGuard = 64U;
constexpr std::uint8_t kGuardByte = 0xA5U;

// A solid NV12 frame (Y = 128, UV = 128) with guard bytes around each plane
// so an out-of-bounds write is caught by a byte comparison.
struct Frame {
  int width;
  int height;
  int y_stride;   // luma row stride; may exceed width when the caller pads rows
  int uv_stride;  // NV12 chroma rows hold 2 * ceil(width / 2) bytes
  std::vector<std::uint8_t> y_storage;
  std::vector<std::uint8_t> uv_storage;

  Frame(int w, int h, int y_stride)
      : width(w), height(h), y_stride(y_stride), uv_stride(w + (w % 2)),
        y_storage(kGuard + static_cast<std::size_t>(y_stride) * h + kGuard, 128U),
        uv_storage(kGuard + static_cast<std::size_t>(uv_stride) * ((h + 1) / 2) + kGuard, 128U) {
    std::fill_n(y_storage.begin(), kGuard, kGuardByte);
    std::fill_n(y_storage.end() - static_cast<std::ptrdiff_t>(kGuard), kGuard, kGuardByte);
    std::fill_n(uv_storage.begin(), kGuard, kGuardByte);
    std::fill_n(uv_storage.end() - static_cast<std::ptrdiff_t>(kGuard), kGuard, kGuardByte);
  }
  Frame(int w, int h) : Frame(w, h, w) {}
  Nv12MutableView view() {
    return {y_storage.data() + kGuard, uv_storage.data() + kGuard, y_stride, uv_stride, width, height};
  }
  std::uint8_t Y(int x, int y) const {
    return y_storage[kGuard + static_cast<std::size_t>(y) * y_stride + x];
  }
  std::uint8_t U(int x, int y) const {  // chroma sample for luma (x, y)
    return uv_storage[kGuard + static_cast<std::size_t>(y / 2) * uv_stride + (x / 2) * 2];
  }
  bool GuardsIntact() const {
    auto ok = [](const std::vector<std::uint8_t>& s) {
      return std::all_of(s.begin(), s.begin() + kGuard, [](auto b) { return b == kGuardByte; }) &&
             std::all_of(s.end() - static_cast<std::ptrdiff_t>(kGuard), s.end(), [](auto b) { return b == kGuardByte; });
    };
    return ok(y_storage) && ok(uv_storage);
  }
  bool Untouched() const {
    return std::all_of(y_storage.begin() + kGuard, y_storage.end() - static_cast<std::ptrdiff_t>(kGuard), [](auto b) { return b == 128U; }) &&
           std::all_of(uv_storage.begin() + kGuard, uv_storage.end() - static_cast<std::ptrdiff_t>(kGuard), [](auto b) { return b == 128U; });
  }
};

CameraOsdConfig Config(std::vector<CameraOsdItem> items, bool enabled = true) {
  CameraOsdConfig config;
  config.enabled = enabled;
  config.items = std::move(items);
  return config;
}

TextRasterizer Font() {
  auto font = TextRasterizer::LoadEmbedded();
  EXPECT_TRUE(font.ok());
  return std::move(font).value();
}

OsdCompositor Make(const CameraOsdConfig& config, TextRasterizer& font, int w = 1920, int h = 1080) {
  auto compositor = OsdCompositor::Create(config, "imx708-main", w, h, font);
  EXPECT_TRUE(compositor.ok()) << compositor.error().message;
  return std::move(compositor).value();
}

std::time_t At(int hour, int minute, int second) {
  std::tm tm{};
  tm.tm_year = 2026 - 1900;
  tm.tm_mon = 8;
  tm.tm_mday = 5;
  tm.tm_hour = hour;
  tm.tm_min = minute;
  tm.tm_sec = second;
  tm.tm_isdst = -1;
  return std::mktime(&tm);
}

TEST(OsdCompositorTest, LeavesTheFrameUntouchedWhileDisabled) {
  auto font = Font();
  auto compositor = Make(Config({{"custom_text", "Front door", "top_left"}}, false), font);
  Frame frame(1920, 1080);
  compositor.Stamp(frame.view(), At(14, 30, 7));
  EXPECT_TRUE(frame.Untouched());
  EXPECT_TRUE(compositor.SpriteRects().empty());
}

TEST(OsdCompositorTest, DarkensTheBoxAndBrightensTheTextAtTheTopLeftInset) {
  auto font = Font();
  auto compositor = Make(Config({{"custom_text", "Front door", "top_left"}}), font);
  Frame frame(1920, 1080);
  compositor.Stamp(frame.view(), At(14, 30, 7));

  const auto rects = compositor.SpriteRects();
  ASSERT_EQ(rects.size(), 1U);
  const auto m = OsdLayoutMetrics::For(1920, 1080);
  EXPECT_EQ(rects[0].x, m.inset_px);
  EXPECT_EQ(rects[0].y, m.inset_px);
  EXPECT_EQ(rects[0].height, m.box_height());
  EXPECT_GT(rects[0].width, 2 * m.pad_x);
  // Box corner pixel: 45% toward Y=16, rounded -> (128*55 + 16*45 + 50)/100 = 78.
  EXPECT_EQ(frame.Y(rects[0].x, rects[0].y), 78);
  EXPECT_EQ(frame.U(rects[0].x, rects[0].y), 128);
  // Just outside the box nothing changed.
  EXPECT_EQ(frame.Y(rects[0].x - 1, rects[0].y), 128);
  EXPECT_EQ(frame.Y(rects[0].x, rects[0].y - 1), 128);
  // Some pixel inside the box is bright text.
  int bright = 0;
  for (int y = rects[0].y; y < rects[0].y + rects[0].height; ++y) {
    for (int x = rects[0].x; x < rects[0].x + rects[0].width; ++x) {
      bright += frame.Y(x, y) > 200 ? 1 : 0;
    }
  }
  EXPECT_GT(bright, 50);
  EXPECT_TRUE(frame.GuardsIntact());
}

TEST(OsdCompositorTest, RightAlignsRightCornersAndStacksBottomCornersUpward) {
  auto font = Font();
  auto compositor = Make(Config({
      {"custom_text", "one", "top_right"},
      {"custom_text", "first", "bottom_left"},
      {"custom_text", "second", "bottom_left"},
  }), font);
  Frame frame(1920, 1080);
  compositor.Stamp(frame.view(), At(14, 30, 7));
  const auto rects = compositor.SpriteRects();
  ASSERT_EQ(rects.size(), 3U);
  const auto m = OsdLayoutMetrics::For(1920, 1080);
  EXPECT_EQ(rects[0].x + rects[0].width, 1920 - m.inset_px);
  EXPECT_EQ(rects[0].y, m.inset_px);
  // The last bottom-left item sits nearest the bottom edge.
  EXPECT_EQ(rects[2].y + rects[2].height, 1080 - m.inset_px);
  EXPECT_EQ(rects[1].y + rects[1].height + m.gap_px, rects[2].y);
  EXPECT_EQ(rects[1].x, m.inset_px);
  EXPECT_TRUE(frame.GuardsIntact());
}

TEST(OsdCompositorTest, RendersTheCameraIdForCameraNameItems) {
  auto font = Font();
  auto short_id = OsdCompositor::Create(Config({{"camera_name", "", "top_left"}}), "ab", 1920, 1080, font);
  auto long_id = OsdCompositor::Create(Config({{"camera_name", "", "top_left"}}), "imx708-main-long-name", 1920, 1080, font);
  ASSERT_TRUE(short_id.ok());
  ASSERT_TRUE(long_id.ok());
  EXPECT_LT(short_id.value().SpriteRects()[0].width, long_id.value().SpriteRects()[0].width);
}

TEST(OsdCompositorTest, RebuildsTimestampSpritesOnlyWhenTheSecondChanges) {
  auto font = Font();
  auto compositor = Make(Config({{"timestamp", "", "top_left"}}), font);
  Frame a(1920, 1080);
  Frame b(1920, 1080);
  Frame c(1920, 1080);
  compositor.Stamp(a.view(), At(14, 30, 7));
  compositor.Stamp(b.view(), At(14, 30, 7));
  compositor.Stamp(c.view(), At(14, 30, 8));
  EXPECT_EQ(a.y_storage, b.y_storage);
  EXPECT_NE(a.y_storage, c.y_storage);
}

TEST(OsdCompositorTest, ClipsLongTextToTheColumnWidth) {
  auto font = Font();
  const std::string sixty_four(64, 'W');
  auto compositor = Make(Config({{"custom_text", sixty_four, "top_left"}}), font);
  const auto m = OsdLayoutMetrics::For(1920, 1080);
  EXPECT_EQ(compositor.SpriteRects()[0].width, m.column_px);
  Frame frame(1920, 1080);
  compositor.Stamp(frame.view(), At(14, 30, 7));
  EXPECT_TRUE(frame.GuardsIntact());
}

TEST(OsdCompositorTest, StaysInBoundsWithEightItemsOnATinyFrame) {
  auto font = Font();
  std::vector<CameraOsdItem> items;
  const char* positions[] = {"top_left", "top_right", "bottom_left", "bottom_right"};
  for (int i = 0; i < 8; ++i) {
    items.push_back({"custom_text", "\xea\xb0\x80\xeb\x82\x98\xeb\x8b\xa4 WWWWWWWW", positions[i % 4]});
  }
  auto compositor = Make(Config(items), font, 320, 180);
  Frame frame(320, 180);
  compositor.Stamp(frame.view(), At(14, 30, 7));
  EXPECT_TRUE(frame.GuardsIntact());
  EXPECT_FALSE(frame.Untouched());
}

TEST(OsdCompositorTest, HandlesOddFrameGeometryWithoutTouchingGuards) {
  auto font = Font();
  auto compositor = Make(Config({{"custom_text", "odd", "bottom_right"}}), font, 321, 181);
  Frame frame(321, 181);
  compositor.Stamp(frame.view(), At(14, 30, 7));
  EXPECT_TRUE(frame.GuardsIntact());
}

TEST(OsdCompositorTest, HonoursALumaStrideWiderThanTheFrame) {
  auto font = Font();
  auto compositor = Make(Config({{"custom_text", "Front door", "top_left"},
                                 {"custom_text", "Back door", "bottom_right"}}), font);
  Frame frame(1920, 1080, 2048);
  compositor.Stamp(frame.view(), At(14, 30, 7));
  const auto rects = compositor.SpriteRects();
  ASSERT_EQ(rects.size(), 2U);
  EXPECT_EQ(frame.Y(rects[0].x, rects[0].y), 78);
  EXPECT_EQ(frame.Y(rects[1].x + rects[1].width - 1, rects[1].y + rects[1].height - 1), 78);
  EXPECT_EQ(frame.Y(rects[0].x + rects[0].width, rects[0].y), 128);
  EXPECT_TRUE(frame.GuardsIntact());
}

}  // namespace
