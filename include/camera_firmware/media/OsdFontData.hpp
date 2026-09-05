#pragma once

#include <cstdint>
#include <span>

namespace camera_firmware::media {

// NanumGothicBold.ttf (OFL-1.1, see vendor/fonts/README.md) embedded via
// OsdFontData.S; the bytes live in the firmware binary's .rodata.
[[nodiscard]] std::span<const std::uint8_t> EmbeddedOsdFont() noexcept;

}  // namespace camera_firmware::media
