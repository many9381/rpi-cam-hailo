#pragma once

#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/crypto/CryptoProvider.hpp"
#include "camera_firmware/integrity/IntegrityManifest.hpp"

namespace camera_firmware::integrity {

struct IntegrityItemResult {
  std::string id;
  IntegrityCategory category;
  bool passed{false};
  std::string code;
};

struct IntegrityVerificationReport {
  bool passed{false};
  std::vector<IntegrityItemResult> items;
};

[[nodiscard]] common::Result<void> VerifyEd25519Signature(
    std::span<const unsigned char> manifest,
    std::span<const unsigned char> signature, std::string_view public_key_pem,
    crypto::CryptoProvider& provider);
[[nodiscard]] common::Result<IntegrityVerificationReport>
VerifyIntegrityManifest(const std::filesystem::path& manifest_path,
                        const std::filesystem::path& signature_path,
                        std::string_view public_key_pem,
                        const std::filesystem::path& active_executable,
                        const std::filesystem::path& active_config,
                        crypto::CryptoProvider& provider);

}  // namespace camera_firmware::integrity
