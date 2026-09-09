#pragma once

#include <span>
#include <string_view>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"

namespace camera_firmware::security {

[[nodiscard]] common::Result<void> ValidateInitialUsername(
    std::string_view username,
    std::span<const std::string_view> reserved_identities);

[[nodiscard]] common::Result<void> ValidatePassword(
    std::string_view username, const common::SecureBytes& password);

}  // namespace camera_firmware::security
