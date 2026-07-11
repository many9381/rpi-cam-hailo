#pragma once

#include <filesystem>
#include <memory>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"

namespace camera_firmware::security {

class ResolvedTlsMaterial;

namespace detail {
struct ResolvedTlsHandles;
}

class ResolvedTlsMaterial {
 public:
  ResolvedTlsMaterial(const ResolvedTlsMaterial&) = default;
  ResolvedTlsMaterial& operator=(const ResolvedTlsMaterial&) = default;
  ResolvedTlsMaterial(ResolvedTlsMaterial&&) noexcept = default;
  ResolvedTlsMaterial& operator=(ResolvedTlsMaterial&&) noexcept = default;

  std::filesystem::path certificate_path;
  std::filesystem::path private_key_path;
  bool generated_for_development{false};

 private:
  friend common::Result<ResolvedTlsMaterial> ResolveTlsMaterial(
      const config::HttpTlsConfig&,
      const std::filesystem::path&);
  ResolvedTlsMaterial(
      std::filesystem::path certificate,
      std::filesystem::path private_key,
      bool generated,
      std::shared_ptr<detail::ResolvedTlsHandles> handles) noexcept;

  std::shared_ptr<detail::ResolvedTlsHandles> handles_;
};

common::Result<ResolvedTlsMaterial> ResolveTlsMaterial(
    const config::HttpTlsConfig& tls,
    const std::filesystem::path& protected_state_directory);

}  // namespace camera_firmware::security
