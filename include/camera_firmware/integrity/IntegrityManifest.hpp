#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/integrity/SafeFileDigest.hpp"

namespace camera_firmware::integrity {

inline constexpr std::size_t kMaximumIntegrityManifestEntries = 4096U;
inline constexpr std::size_t kMaximumIntegrityIdBytes = 64U;

enum class IntegrityCategory {
  kFirmware,
  kLibrary,
  kConfiguration,
  kWebAsset,
  kKernel,
  kKernelModule,
};

struct IntegrityEntry {
  std::string id;
  IntegrityCategory category;
  std::filesystem::path path;
  Sha256Digest expected_sha256;
};

struct IntegrityManifest {
  std::uint32_t schema_version{1U};
  std::string product;
  std::string created_at;
  std::vector<IntegrityEntry> files;
};

[[nodiscard]] std::string_view IntegrityCategoryName(
    IntegrityCategory category) noexcept;
[[nodiscard]] common::Result<IntegrityCategory> ParseIntegrityCategory(
    std::string_view value);
[[nodiscard]] common::Result<IntegrityManifest> ParseIntegrityManifest(
    std::string_view yaml);

}  // namespace camera_firmware::integrity
