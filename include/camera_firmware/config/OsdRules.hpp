#pragma once

#include <cstddef>
#include <string_view>

namespace camera_firmware::config {

// The OSD item contract shared by the YAML/effective config validator, the
// runtime-settings validator, and the compositor. The web client mirrors
// these bounds (web/src/features/settings/contracts.ts); change both.
inline constexpr std::size_t kMaxOsdItems = 8U;
inline constexpr std::size_t kMaxOsdTextBytes = 64U;

[[nodiscard]] bool IsAllowedOsdType(std::string_view type);
[[nodiscard]] bool IsAllowedOsdPosition(std::string_view position);
// At most kMaxOsdTextBytes UTF-8 bytes, none below 0x20 and no 0x7f (DEL).
[[nodiscard]] bool IsPrintableOsdText(std::string_view text);
// Every rule one item must satisfy: allowed type and position, printable text
// within the byte bound, and non-empty text when the type is custom_text.
[[nodiscard]] bool IsValidOsdItem(std::string_view type, std::string_view text,
                                  std::string_view position);

}  // namespace camera_firmware::config
