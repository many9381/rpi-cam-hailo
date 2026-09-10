#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::media {

struct GlyphBitmap {
  int glyph_index{0};  // stb glyph index; 0 is the font's .notdef glyph
  int width{0};
  int height{0};
  int bearing_x{0};  // left edge of the bitmap relative to the pen position
  int bearing_y{
      0};  // top edge of the bitmap relative to the baseline (negative = above)
  int advance{0};                   // horizontal pen advance in pixels
  std::vector<std::uint8_t> alpha;  // width * height coverage values, row-major
};

struct PlacedGlyph {
  const GlyphBitmap* glyph{nullptr};
  int pen_x{0};  // pen position; the bitmap's left edge is pen_x + bearing_x
};

struct TextRun {
  int width{0};    // total advance including the last glyph's ink
  int ascent{0};   // pixels above the baseline
  int descent{0};  // pixels below the baseline
  std::vector<PlacedGlyph> glyphs;
};

// Glyph rasterizer over one TrueType font (stb_truetype). Not thread-safe;
// the capture callback owns the instance the compositor uses.
class TextRasterizer {
 public:
  // `ttf` must outlive the rasterizer (the embedded font has static lifetime).
  [[nodiscard]] static common::Result<TextRasterizer> Load(
      std::span<const std::uint8_t> ttf);
  [[nodiscard]] static common::Result<TextRasterizer> LoadEmbedded();
  ~TextRasterizer();
  TextRasterizer(TextRasterizer&&) noexcept;
  TextRasterizer& operator=(TextRasterizer&&) noexcept;
  TextRasterizer(const TextRasterizer&) = delete;
  TextRasterizer& operator=(const TextRasterizer&) = delete;

  [[nodiscard]] bool HasGlyph(char32_t codepoint) const;
  // Cached per (codepoint, pixel_height); the reference stays valid for the
  // rasterizer's lifetime. Unknown codepoints render the .notdef glyph.
  [[nodiscard]] const GlyphBitmap& GetGlyph(char32_t codepoint,
                                            int pixel_height);
  // Lays out UTF-8 text left to right with kerning. Malformed UTF-8 bytes
  // decode to U+FFFD.
  [[nodiscard]] TextRun Shape(std::string_view utf8, int pixel_height);
  [[nodiscard]] int Ascent(int pixel_height) const;
  [[nodiscard]] int Descent(int pixel_height) const;

 private:
  struct Impl;
  explicit TextRasterizer(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

// Decodes UTF-8 into code points. Every byte that cannot start or continue a
// valid sequence becomes one U+FFFD, so a partially valid multi-byte sequence
// may produce several.
[[nodiscard]] std::u32string DecodeUtf8(std::string_view utf8);

}  // namespace camera_firmware::media
