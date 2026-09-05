#include "camera_firmware/config/OsdRules.hpp"

namespace camera_firmware::config {

bool IsAllowedOsdType(std::string_view type) {
  return type == "timestamp" || type == "camera_name" || type == "custom_text";
}

bool IsAllowedOsdPosition(std::string_view position) {
  return position == "top_left" || position == "top_right" ||
         position == "bottom_left" || position == "bottom_right";
}

bool IsPrintableOsdText(std::string_view text) {
  if (text.size() > kMaxOsdTextBytes) {
    return false;
  }
  for (const unsigned char c : text) {
    if (c < 0x20U || c == 0x7fU) {
      return false;
    }
  }
  return true;
}

bool IsValidOsdItem(std::string_view type, std::string_view text,
                    std::string_view position) {
  return IsAllowedOsdType(type) && IsAllowedOsdPosition(position) &&
         IsPrintableOsdText(text) && !(type == "custom_text" && text.empty());
}

}  // namespace camera_firmware::config
