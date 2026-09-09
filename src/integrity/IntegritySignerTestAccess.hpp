#pragma once

#include <filesystem>
#include <functional>
#include <span>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::integrity::testing {

[[nodiscard]] common::Result<void>
WriteIntegrityArtifactAtomicallyWithPrePublishHook(
    const std::filesystem::path& output, std::span<const unsigned char> bytes,
    std::function<void()> before_publish);

}  // namespace camera_firmware::integrity::testing
