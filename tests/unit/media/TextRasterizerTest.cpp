#include "camera_firmware/media/TextRasterizer.hpp"

#include <array>
#include <cstdint>
#include <string>

#include <gtest/gtest.h>

#include "camera_firmware/media/OsdFontData.hpp"

namespace {

using camera_firmware::media::EmbeddedOsdFont;
using camera_firmware::media::TextRasterizer;

TextRasterizer LoadFont() {
  auto font = TextRasterizer::LoadEmbedded();
  EXPECT_TRUE(font.ok()) << font.error().message;
  return std::move(font).value();
}

TEST(TextRasterizerTest, EmbedsTheWholeNanumGothicBoldFile) {
  EXPECT_EQ(EmbeddedOsdFont().size(), 4642244U);
  EXPECT_TRUE(TextRasterizer::LoadEmbedded().ok());
}

TEST(TextRasterizerTest, RejectsBytesThatAreNotAFont) {
  const std::array<std::uint8_t, 8> junk{1, 2, 3, 4, 5, 6, 7, 8};
  EXPECT_FALSE(TextRasterizer::Load(junk).ok());
}

TEST(TextRasterizerTest, CoversLatinAndHangulButNotUnassignedCodepoints) {
  auto font = LoadFont();
  EXPECT_TRUE(font.HasGlyph(U'A'));
  EXPECT_TRUE(font.HasGlyph(U'가'));  // 가
  EXPECT_TRUE(font.HasGlyph(U'힣'));  // 힣 (last modern syllable)
  EXPECT_FALSE(font.HasGlyph(U'͸'));  // unassigned
  EXPECT_GT(font.GetGlyph(U'͸', 38).width, 0);
}

TEST(TextRasterizerTest, ShapesLatinAndHangulLeftToRight) {
  auto font = LoadFont();
  const auto run = font.Shape("A\xea\xb0\x80", 38);  // "A가"
  ASSERT_EQ(run.glyphs.size(), 2U);
  EXPECT_GT(run.width, 0);
  EXPECT_GT(run.glyphs[1].pen_x, run.glyphs[0].pen_x);
  for (const auto& placed : run.glyphs) {
    EXPECT_GT(placed.glyph->width, 0);
    EXPECT_GT(placed.glyph->height, 0);
    EXPECT_LE(placed.glyph->height, 48);
    EXPECT_EQ(placed.glyph->alpha.size(),
              static_cast<std::size_t>(placed.glyph->width) * placed.glyph->height);
  }
  EXPECT_GT(run.ascent, 0);
  EXPECT_GT(run.descent, 0);
  EXPECT_LE(run.ascent + run.descent, 60);
}

TEST(TextRasterizerTest, CachesGlyphsPerCodepointAndSize) {
  auto font = LoadFont();
  const auto* first = &font.GetGlyph(U'A', 38);
  EXPECT_EQ(first, &font.GetGlyph(U'A', 38));
  EXPECT_NE(first, &font.GetGlyph(U'A', 39));
}

TEST(TextRasterizerTest, DecodesInvalidUtf8AsReplacementCharacter) {
  auto font = LoadFont();
  const auto run = font.Shape("\xff", 38);
  ASSERT_EQ(run.glyphs.size(), 1U);
  EXPECT_EQ(run.glyphs[0].glyph, &font.GetGlyph(U'�', 38));
}

}  // namespace
