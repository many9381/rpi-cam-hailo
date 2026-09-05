#pragma once

#include <array>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/TextRasterizer.hpp"

namespace camera_firmware::media {

// Mutable twin of Nv12Plane: Y plane then interleaved CbCr at half height.
struct Nv12MutableView {
  std::uint8_t* y{nullptr};
  std::uint8_t* uv{nullptr};
  int y_stride{0};
  int uv_stride{0};
  int width{0};
  int height{0};
};

// Frame-height-relative layout, shared with the web overlay
// (web/src/features/settings/osdLayout.ts): text height 3.5% of the frame
// height, corner inset 2%, box padding 0.15em/0.4em, line height 1.2em,
// stack gap 0.25em, one column per half frame.
struct OsdLayoutMetrics {
  int font_px{0};
  int inset_px{0};
  int pad_x{0};
  int pad_y{0};
  int line_px{0};
  int gap_px{0};
  int column_px{0};

  [[nodiscard]] static OsdLayoutMetrics For(int width, int height);
  [[nodiscard]] int box_height() const { return line_px + 2 * pad_y; }
};

// Draws the configured OSD items into NV12 frames in place. One sprite
// (box + text coverage) per item is rasterized up front; Stamp() blends them
// and re-rasterizes timestamp items when the wall-clock second changes.
// Owned and driven by the capture callback; not thread-safe.
class OsdCompositor {
 public:
  struct SpriteRect {
    int x{0};
    int y{0};
    int width{0};
    int height{0};
    std::string position;
    std::string type;
  };

  [[nodiscard]] static common::Result<OsdCompositor> Create(
      const config::CameraOsdConfig& config, std::string camera_id,
      int width, int height, TextRasterizer& rasterizer);

  void Stamp(const Nv12MutableView& frame, std::time_t now);
  [[nodiscard]] std::vector<SpriteRect> SpriteRects() const;

 private:
  struct Sprite {
    config::CameraOsdItem item;
    int x{0};
    int y{0};
    int width{0};
    int height{0};
    std::vector<std::uint8_t> coverage;  // width * height text alpha
  };

  OsdCompositor(config::CameraOsdConfig config, std::string camera_id,
                int width, int height, TextRasterizer& rasterizer);
  void BuildSprites(std::time_t now);
  void RasterizeText(Sprite& sprite, const std::string& text);
  void PlaceHorizontally(Sprite& sprite) const;
  [[nodiscard]] std::string TextFor(const config::CameraOsdItem& item,
                                    std::time_t now) const;
  void BlendSprite(const Nv12MutableView& frame, const Sprite& sprite) const;

  config::CameraOsdConfig config_;
  std::string camera_id_;
  int width_{0};
  int height_{0};
  TextRasterizer* rasterizer_{nullptr};
  OsdLayoutMetrics metrics_;
  std::vector<Sprite> sprites_;
  // One cached row of scratch: the capture buffers are mapped non-cacheable,
  // so rows are copied in with memcpy, blended here, and copied back.
  mutable std::vector<std::uint8_t> row_scratch_;
  bool has_timestamp_{false};
  std::time_t last_second_{-1};
};

// %Y-%m-%d %H:%M:%S in device local time.
[[nodiscard]] std::string FormatOsdTimestamp(std::time_t now);

}  // namespace camera_firmware::media
