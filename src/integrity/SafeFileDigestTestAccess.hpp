#pragma once

#include <filesystem>
#include <functional>

#include "camera_firmware/integrity/SafeFileDigest.hpp"

namespace camera_firmware::integrity::testing {

using DigestReadHook = std::function<void()>;

[[nodiscard]] common::Result<Sha256Digest> DigestRegularFileWithReadHook(
    const std::filesystem::path& path, const DigestReadHook& hook);

}  // namespace camera_firmware::integrity::testing
