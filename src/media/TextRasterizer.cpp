#include "camera_firmware/media/TextRasterizer.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <string>
#include <unordered_map>
#include <utility>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wcast-qual"
#define STB_TRUETYPE_IMPLEMENTATION
#define STBTT_STATIC
#include "stb_truetype.h"
#pragma GCC diagnostic pop

#include "camera_firmware/media/OsdFontData.hpp"

namespace camera_firmware::media {

namespace {

constexpr char32_t kReplacementCharacter = U'�';

int RoundToInt(float value) {
  return static_cast<int>(std::lround(value));
}

std::uint64_t CacheKey(char32_t codepoint, int pixel_height) {
  return (static_cast<std::uint64_t>(static_cast<std::uint32_t>(pixel_height))
          << 32U) |
         static_cast<std::uint64_t>(codepoint);
}

}  // namespace

std::u32string DecodeUtf8(std::string_view utf8) {
  std::u32string out;
  out.reserve(utf8.size());
  std::size_t i = 0;
  while (i < utf8.size()) {
    const auto lead = static_cast<unsigned char>(utf8[i]);
    int extra = 0;
    char32_t code = 0;
    if (lead < 0x80U) {
      out.push_back(lead);
      ++i;
      continue;
    } else if ((lead & 0xE0U) == 0xC0U) {
      extra = 1;
      code = lead & 0x1FU;
    } else if ((lead & 0xF0U) == 0xE0U) {
      extra = 2;
      code = lead & 0x0FU;
    } else if ((lead & 0xF8U) == 0xF0U) {
      extra = 3;
      code = lead & 0x07U;
    } else {
      out.push_back(kReplacementCharacter);
      ++i;
      continue;
    }
    if (i + static_cast<std::size_t>(extra) >= utf8.size()) {
      // Truncated sequence: one replacement, advance one byte.
      out.push_back(kReplacementCharacter);
      ++i;
      continue;
    }
    bool valid = true;
    for (int k = 1; k <= extra; ++k) {
      const auto byte = static_cast<unsigned char>(utf8[i + static_cast<std::size_t>(k)]);
      if ((byte & 0xC0U) != 0x80U) {
        valid = false;
        break;
      }
      code = (code << 6U) | (byte & 0x3FU);
    }
    const bool overlong = (extra == 1 && code < 0x80U) ||
                          (extra == 2 && code < 0x800U) ||
                          (extra == 3 && code < 0x10000U);
    const bool surrogate = code >= 0xD800U && code <= 0xDFFFU;
    if (!valid || overlong || surrogate || code > 0x10FFFFU) {
      out.push_back(kReplacementCharacter);
      ++i;
      continue;
    }
    out.push_back(code);
    i += static_cast<std::size_t>(extra) + 1U;
  }
  return out;
}

struct TextRasterizer::Impl {
  stbtt_fontinfo info{};
  std::unordered_map<std::uint64_t, std::unique_ptr<GlyphBitmap>> cache;

  // font_px is the em size, exactly like the CSS font-size the web overlay uses.
  [[nodiscard]] float Scale(int pixel_height) const {
    return stbtt_ScaleForMappingEmToPixels(&info, static_cast<float>(pixel_height));
  }
};

TextRasterizer::TextRasterizer(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
TextRasterizer::~TextRasterizer() = default;
TextRasterizer::TextRasterizer(TextRasterizer&&) noexcept = default;
TextRasterizer& TextRasterizer::operator=(TextRasterizer&&) noexcept = default;

common::Result<TextRasterizer> TextRasterizer::Load(std::span<const std::uint8_t> ttf) {
  auto impl = std::make_unique<Impl>();
  if (ttf.empty()) {
    return common::Result<TextRasterizer>::Err({"E_OSD_FONT", "OSD font is empty"});
  }
  const int offset = stbtt_GetFontOffsetForIndex(ttf.data(), 0);
  if (offset < 0 || stbtt_InitFont(&impl->info, ttf.data(), offset) == 0) {
    return common::Result<TextRasterizer>::Err(
        {"E_OSD_FONT", "OSD font could not be parsed"});
  }
  return common::Result<TextRasterizer>::Ok(TextRasterizer(std::move(impl)));
}

common::Result<TextRasterizer> TextRasterizer::LoadEmbedded() {
  return Load(EmbeddedOsdFont());
}

bool TextRasterizer::HasGlyph(char32_t codepoint) const {
  return stbtt_FindGlyphIndex(&impl_->info, static_cast<int>(codepoint)) != 0;
}

const GlyphBitmap& TextRasterizer::GetGlyph(char32_t codepoint, int pixel_height) {
  const auto key = CacheKey(codepoint, pixel_height);
  if (const auto found = impl_->cache.find(key); found != impl_->cache.end()) {
    return *found->second;
  }
  auto glyph = std::make_unique<GlyphBitmap>();
  const float scale = impl_->Scale(pixel_height);
  glyph->glyph_index = stbtt_FindGlyphIndex(&impl_->info, static_cast<int>(codepoint));
  int advance = 0;
  int left_side_bearing = 0;
  stbtt_GetGlyphHMetrics(&impl_->info, glyph->glyph_index, &advance, &left_side_bearing);
  glyph->advance = RoundToInt(static_cast<float>(advance) * scale);
  int x0 = 0;
  int y0 = 0;
  int x1 = 0;
  int y1 = 0;
  stbtt_GetGlyphBitmapBox(&impl_->info, glyph->glyph_index, scale, scale, &x0, &y0, &x1, &y1);
  glyph->width = x1 - x0;
  glyph->height = y1 - y0;
  glyph->bearing_x = x0;
  glyph->bearing_y = y0;
  if (glyph->width > 0 && glyph->height > 0) {
    glyph->alpha.assign(static_cast<std::size_t>(glyph->width) * glyph->height, 0U);
    stbtt_MakeGlyphBitmap(&impl_->info, glyph->alpha.data(), glyph->width,
                          glyph->height, glyph->width, scale, scale,
                          glyph->glyph_index);
  } else {
    glyph->width = 0;
    glyph->height = 0;
  }
  const auto [inserted, _] = impl_->cache.emplace(key, std::move(glyph));
  return *inserted->second;
}

TextRun TextRasterizer::Shape(std::string_view utf8, int pixel_height) {
  TextRun run;
  run.ascent = Ascent(pixel_height);
  run.descent = Descent(pixel_height);
  const float scale = impl_->Scale(pixel_height);
  int pen = 0;
  const GlyphBitmap* previous = nullptr;
  for (const char32_t codepoint : DecodeUtf8(utf8)) {
    const GlyphBitmap& glyph = GetGlyph(codepoint, pixel_height);
    if (previous != nullptr) {
      pen += RoundToInt(static_cast<float>(stbtt_GetGlyphKernAdvance(
                            &impl_->info, previous->glyph_index, glyph.glyph_index)) *
                        scale);
    }
    run.glyphs.push_back({&glyph, pen});
    run.width = std::max(run.width, pen + glyph.bearing_x + glyph.width);
    pen += glyph.advance;
    run.width = std::max(run.width, pen);
    previous = &glyph;
  }
  return run;
}

int TextRasterizer::Ascent(int pixel_height) const {
  int ascent = 0;
  int descent = 0;
  int line_gap = 0;
  stbtt_GetFontVMetrics(&impl_->info, &ascent, &descent, &line_gap);
  return RoundToInt(static_cast<float>(ascent) * impl_->Scale(pixel_height));
}

int TextRasterizer::Descent(int pixel_height) const {
  int ascent = 0;
  int descent = 0;
  int line_gap = 0;
  stbtt_GetFontVMetrics(&impl_->info, &ascent, &descent, &line_gap);
  return RoundToInt(static_cast<float>(-descent) * impl_->Scale(pixel_height));
}

}  // namespace camera_firmware::media
