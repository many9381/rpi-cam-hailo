#pragma once

#include <string_view>

namespace camera_firmware::integrity::testing {

[[nodiscard]] bool RestrictedYamlPreflightAcceptsForTest(std::string_view yaml);

}  // namespace camera_firmware::integrity::testing
