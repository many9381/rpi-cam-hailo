#include "camera_firmware/media/OsdFontData.hpp"

#include <cstddef>

extern "C" const std::uint8_t camera_firmware_osd_font_start[];
extern "C" const std::uint8_t camera_firmware_osd_font_end[];

namespace camera_firmware::media {

std::span<const std::uint8_t> EmbeddedOsdFont() noexcept {
  return {camera_firmware_osd_font_start,
          static_cast<std::size_t>(camera_firmware_osd_font_end -
                                   camera_firmware_osd_font_start)};
}

}  // namespace camera_firmware::media
