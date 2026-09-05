#include "camera_firmware/media/OsdCompositor.hpp"

#include <gtest/gtest.h>

namespace {

using camera_firmware::media::OsdLayoutMetrics;

// These numbers are the shared contract with web/src/features/settings/
// osdLayout.ts (OSD_FONT_RATIO 0.035, OSD_INSET_RATIO 0.02) and the CSS
// overlay (padding 0.15em/0.4em, line-height 1.2, gap 0.25em).
TEST(OsdLayoutMetricsTest, Derives1080pMetricsFromTheSharedRatios) {
  const auto m = OsdLayoutMetrics::For(1920, 1080);
  EXPECT_EQ(m.font_px, 38);
  EXPECT_EQ(m.inset_px, 22);
  EXPECT_EQ(m.pad_x, 15);
  EXPECT_EQ(m.pad_y, 6);
  EXPECT_EQ(m.line_px, 46);
  EXPECT_EQ(m.gap_px, 10);
  EXPECT_EQ(m.column_px, 928);
  EXPECT_EQ(m.box_height(), 58);
}

TEST(OsdLayoutMetricsTest, Derives360pMetricsFromTheSharedRatios) {
  const auto m = OsdLayoutMetrics::For(640, 360);
  EXPECT_EQ(m.font_px, 13);
  EXPECT_EQ(m.inset_px, 7);
  EXPECT_EQ(m.pad_x, 5);
  EXPECT_EQ(m.pad_y, 2);
  EXPECT_EQ(m.line_px, 16);
  EXPECT_EQ(m.gap_px, 3);
  EXPECT_EQ(m.column_px, 310);
}

}  // namespace
