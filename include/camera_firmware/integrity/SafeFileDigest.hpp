#pragma once

#include <array>
#include <filesystem>
#include <string>
#include <string_view>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::integrity {

using Sha256Digest = std::array<unsigned char, 32U>;

[[nodiscard]] common::Result<Sha256Digest> DigestRegularFile(
    const std::filesystem::path& path);
[[nodiscard]] std::string HexSha256(const Sha256Digest& digest);
[[nodiscard]] common::Result<Sha256Digest> ParseSha256(std::string_view value);

}  // namespace camera_firmware::integrity
