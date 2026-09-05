#include "camera_firmware/media/OsdCompositor.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <ctime>
#include <string_view>
#include <utility>

namespace camera_firmware::media {

namespace {

int Round(double value) {
  return static_cast<int>(std::lround(value));
}

constexpr int kBoxLuma = 16;
constexpr int kNeutralChroma = 128;
constexpr int kTextLuma = 235;
constexpr int kBoxOpacityPercent = 45;

std::uint8_t Darken(std::uint8_t sample, int target) {
  return static_cast<std::uint8_t>(
      (sample * (100 - kBoxOpacityPercent) + target * kBoxOpacityPercent + 50) / 100);
}

std::uint8_t Toward(std::uint8_t sample, int target, int coverage) {
  return static_cast<std::uint8_t>(sample + ((target - sample) * coverage + 127) / 255);
}

}  // namespace

std::string FormatOsdTimestamp(std::time_t now) {
  std::tm local{};
  localtime_r(&now, &local);
  char buffer[32];
  const auto written = std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local);
  return std::string(buffer, written);
}

OsdLayoutMetrics OsdLayoutMetrics::For(int width, int height) {
  OsdLayoutMetrics m;
  m.font_px = Round(height * 0.035);
  m.inset_px = Round(height * 0.02);
  m.pad_x = Round(0.40 * m.font_px);
  m.pad_y = Round(0.15 * m.font_px);
  m.line_px = Round(1.2 * m.font_px);
  m.gap_px = Round(0.25 * m.font_px);
  m.column_px = width / 2 - m.inset_px - m.gap_px;
  return m;
}

common::Result<OsdCompositor> OsdCompositor::Create(
    const config::CameraOsdConfig& config, std::string camera_id, int width,
    int height, TextRasterizer& rasterizer) {
  if (width <= 0 || height <= 0) {
    return common::Result<OsdCompositor>::Err(
        {"E_OSD_GEOMETRY", "OSD frame geometry must be positive"});
  }
  const auto semantics = config::ValidateCameraOsdSemantics(config);
  if (!semantics.ok()) {
    return common::Result<OsdCompositor>::Err(semantics.error());
  }
  OsdCompositor compositor(config, std::move(camera_id), width, height, rasterizer);
  compositor.BuildSprites(std::time(nullptr));
  return common::Result<OsdCompositor>::Ok(std::move(compositor));
}

OsdCompositor::OsdCompositor(config::CameraOsdConfig config, std::string camera_id,
                             int width, int height, TextRasterizer& rasterizer)
    : config_(std::move(config)), camera_id_(std::move(camera_id)),
      width_(width), height_(height), rasterizer_(&rasterizer),
      metrics_(OsdLayoutMetrics::For(width, height)) {}

std::string OsdCompositor::TextFor(const config::CameraOsdItem& item,
                                   std::time_t now) const {
  if (item.type == "timestamp") {
    return FormatOsdTimestamp(now);
  }
  if (item.type == "camera_name") {
    return camera_id_;
  }
  return item.text;
}

void OsdCompositor::RasterizeText(Sprite& sprite, const std::string& text) {
  const auto run = rasterizer_->Shape(text, metrics_.font_px);
  sprite.width = std::clamp(2 * metrics_.pad_x + run.width, 2 * metrics_.pad_x,
                            std::max(metrics_.column_px, 2 * metrics_.pad_x));
  sprite.height = metrics_.box_height();
  sprite.coverage.assign(static_cast<std::size_t>(sprite.width) * sprite.height, 0U);
  const int baseline = metrics_.pad_y +
      Round((metrics_.line_px - (run.ascent + run.descent)) / 2.0) + run.ascent;
  for (const auto& placed : run.glyphs) {
    const GlyphBitmap& glyph = *placed.glyph;
    const int left = metrics_.pad_x + placed.pen_x + glyph.bearing_x;
    const int top = baseline + glyph.bearing_y;
    for (int gy = 0; gy < glyph.height; ++gy) {
      const int y = top + gy;
      if (y < 0 || y >= sprite.height) {
        continue;
      }
      for (int gx = 0; gx < glyph.width; ++gx) {
        const int x = left + gx;
        if (x < 0 || x >= sprite.width) {
          continue;
        }
        auto& cell = sprite.coverage[static_cast<std::size_t>(y) * sprite.width + x];
        cell = std::max(cell, glyph.alpha[static_cast<std::size_t>(gy) * glyph.width + gx]);
      }
    }
  }
}

void OsdCompositor::PlaceHorizontally(Sprite& sprite) const {
  const bool right = sprite.item.position == "top_right" ||
                     sprite.item.position == "bottom_right";
  sprite.x = right ? width_ - metrics_.inset_px - sprite.width : metrics_.inset_px;
}

void OsdCompositor::BuildSprites(std::time_t now) {
  sprites_.clear();
  has_timestamp_ = false;
  if (!config_.enabled) {
    return;
  }
  for (const auto& item : config_.items) {
    Sprite sprite;
    sprite.item = item;
    has_timestamp_ = has_timestamp_ || item.type == "timestamp";
    RasterizeText(sprite, TextFor(item, now));
    PlaceHorizontally(sprite);
    sprites_.push_back(std::move(sprite));
  }
  // Vertical stacking per corner: top corners grow downward from the inset,
  // bottom corners are a block whose last item touches the bottom inset.
  for (const char* position : {"top_left", "top_right", "bottom_left", "bottom_right"}) {
    std::vector<Sprite*> group;
    for (auto& sprite : sprites_) {
      if (sprite.item.position == position) {
        group.push_back(&sprite);
      }
    }
    if (group.empty()) {
      continue;
    }
    const bool bottom = std::string_view(position).starts_with("bottom");
    const int block = static_cast<int>(group.size()) * metrics_.box_height() +
                      (static_cast<int>(group.size()) - 1) * metrics_.gap_px;
    int y = bottom ? height_ - metrics_.inset_px - block : metrics_.inset_px;
    for (auto* sprite : group) {
      sprite->y = y;
      y += metrics_.box_height() + metrics_.gap_px;
    }
  }
  last_second_ = now;
}

void OsdCompositor::Stamp(const Nv12MutableView& frame, std::time_t now) {
  if (sprites_.empty()) {
    return;
  }
  if (has_timestamp_ && now != last_second_) {
    for (auto& sprite : sprites_) {
      if (sprite.item.type == "timestamp") {
        RasterizeText(sprite, FormatOsdTimestamp(now));
        PlaceHorizontally(sprite);
      }
    }
    last_second_ = now;
  }
  for (const auto& sprite : sprites_) {
    BlendSprite(frame, sprite);
  }
}

void OsdCompositor::BlendSprite(const Nv12MutableView& frame, const Sprite& sprite) const {
  if (frame.y == nullptr || frame.uv == nullptr || frame.width <= 0 || frame.height <= 0 ||
      frame.y_stride < frame.width || frame.uv_stride < 2 * ((frame.width + 1) / 2)) {
    return;  // a view whose strides cannot hold a full row is never written
  }
  const int x0 = std::max(0, sprite.x);
  const int y0 = std::max(0, sprite.y);
  const int x1 = std::min(frame.width, sprite.x + sprite.width);
  const int y1 = std::min(frame.height, sprite.y + sprite.height);
  if (x0 >= x1 || y0 >= y1) {
    return;
  }
  // Luma: darken the box, then lift text pixels toward white.
  for (int y = y0; y < y1; ++y) {
    std::uint8_t* row = frame.y + static_cast<std::ptrdiff_t>(y) * frame.y_stride;
    const std::uint8_t* cover =
        sprite.coverage.data() + static_cast<std::size_t>(y - sprite.y) * sprite.width;
    for (int x = x0; x < x1; ++x) {
      std::uint8_t sample = Darken(row[x], kBoxLuma);
      const int coverage = cover[x - sprite.x];
      if (coverage > 0) {
        sample = Toward(sample, kTextLuma, coverage);
      }
      row[x] = sample;
    }
  }
  // Chroma: one sample per 2x2 luma block; text coverage is the block mean.
  const int chroma_rows = (frame.height + 1) / 2;
  const int chroma_cols = (frame.width + 1) / 2;
  for (int cy = y0 / 2; cy < std::min(chroma_rows, (y1 + 1) / 2); ++cy) {
    std::uint8_t* row = frame.uv + static_cast<std::ptrdiff_t>(cy) * frame.uv_stride;
    for (int cx = x0 / 2; cx < std::min(chroma_cols, (x1 + 1) / 2); ++cx) {
      int sum = 0;
      int count = 0;
      for (int dy = 0; dy < 2; ++dy) {
        for (int dx = 0; dx < 2; ++dx) {
          const int lx = cx * 2 + dx;
          const int ly = cy * 2 + dy;
          if (lx < x0 || lx >= x1 || ly < y0 || ly >= y1) {
            continue;
          }
          sum += sprite.coverage[static_cast<std::size_t>(ly - sprite.y) * sprite.width +
                                 (lx - sprite.x)];
          ++count;
        }
      }
      if (count == 0) {
        continue;
      }
      const int coverage = sum / count;
      for (int component = 0; component < 2; ++component) {
        std::uint8_t sample = Darken(row[cx * 2 + component], kNeutralChroma);
        if (coverage > 0) {
          sample = Toward(sample, kNeutralChroma, coverage);
        }
        row[cx * 2 + component] = sample;
      }
    }
  }
}

std::vector<OsdCompositor::SpriteRect> OsdCompositor::SpriteRects() const {
  std::vector<SpriteRect> rects;
  rects.reserve(sprites_.size());
  for (const auto& sprite : sprites_) {
    rects.push_back({sprite.x, sprite.y, sprite.width, sprite.height,
                     sprite.item.position, sprite.item.type});
  }
  return rects;
}

}  // namespace camera_firmware::media
