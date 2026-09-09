#pragma once

#include <cstddef>
#include <filesystem>
#include <functional>
#include <string_view>

#include <sys/types.h>

#include "camera_firmware/integrity/IntegrityVerifier.hpp"

namespace camera_firmware::integrity::testing {

using ArtifactReadHook = std::function<void()>;
using ArtifactReadFunction = std::function<ssize_t(int, void*, std::size_t)>;

enum class VerifierFaultPoint {
  kReportReserve,
  kReportItemCopy,
  kReportItemAppend,
};

struct IntegrityVerifierTestHooks {
  ArtifactReadHook before_artifact_read;
  ArtifactReadFunction read;
  std::function<void(VerifierFaultPoint)> inject_fault;
};

[[nodiscard]] common::Result<IntegrityVerificationReport>
VerifyIntegrityManifestWithArtifactReadHook(
    const std::filesystem::path& manifest_path,
    const std::filesystem::path& signature_path,
    std::string_view public_key_pem,
    const std::filesystem::path& active_executable,
    const std::filesystem::path& active_config,
    crypto::CryptoProvider& provider, ArtifactReadHook hook);

[[nodiscard]] common::Result<IntegrityVerificationReport>
VerifyIntegrityManifestWithTestHooks(
    const std::filesystem::path& manifest_path,
    const std::filesystem::path& signature_path,
    std::string_view public_key_pem,
    const std::filesystem::path& active_executable,
    const std::filesystem::path& active_config,
    crypto::CryptoProvider& provider, IntegrityVerifierTestHooks hooks);

}  // namespace camera_firmware::integrity::testing
