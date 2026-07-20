#pragma once

#include <array>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/integrity/IntegrityManifest.hpp"

namespace camera_firmware::integrity {

[[nodiscard]] common::Result<std::string> SerializeIntegrityManifest(
    const IntegrityManifest& manifest);
[[nodiscard]] common::Result<std::vector<unsigned char>>
ReadIntegrityManifestForSigning(const std::filesystem::path& path);
[[nodiscard]] common::Result<std::array<unsigned char, 64U>> SignIntegrityManifest(
    std::span<const unsigned char> bytes,
    const std::filesystem::path& private_key_path);
[[nodiscard]] common::Result<void> WriteIntegrityArtifactAtomically(
    const std::filesystem::path& output, std::span<const unsigned char> bytes);

}  // namespace camera_firmware::integrity
