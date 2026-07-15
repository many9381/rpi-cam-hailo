#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/settings/RuntimeSettings.hpp"

namespace camera_firmware::settings {

enum class ApplyStatus { kNever, kSuccess, kFailed };

struct LastApplyResult {
  ApplyStatus status{ApplyStatus::kNever};
  std::string code;
  bool restored{false};
};

struct RuntimeSettingsDocument {
  std::uint64_t revision{0};
  RuntimeSettings active;
  std::optional<RuntimeSettings> pending;
  LastApplyResult last_apply;
  bool recovery_required{false};
  std::string recovery_code;
};

class RuntimeSettingsStore final {
 public:
  static common::Result<std::unique_ptr<RuntimeSettingsStore>> Open(
      const std::filesystem::path& state_directory,
      RuntimeSettings base_active,
      const config::AppConfig& base_config,
      const CameraProfileCatalog& profiles);

  ~RuntimeSettingsStore();

  RuntimeSettingsStore(const RuntimeSettingsStore&) = delete;
  RuntimeSettingsStore& operator=(const RuntimeSettingsStore&) = delete;

  RuntimeSettingsDocument Snapshot() const;
  common::Result<RuntimeSettingsDocument> SavePending(
      std::uint64_t expected_revision,
      RuntimeSettings pending);
  common::Result<RuntimeSettingsDocument> DiscardPending(
      std::uint64_t expected_revision);
  common::Result<RuntimeSettingsDocument> PromotePending(
      std::uint64_t expected_revision);
  common::Result<RuntimeSettingsDocument> RecordApplyFailure(
      std::uint64_t expected_revision,
      std::string code,
      bool restored);

 private:
  struct Impl;

  explicit RuntimeSettingsStore(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::settings
