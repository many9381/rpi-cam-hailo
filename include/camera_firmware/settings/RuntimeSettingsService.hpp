#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/runtime/ManagedFirmwareRuntime.hpp"
#include "camera_firmware/settings/RuntimeSettings.hpp"
#include "camera_firmware/settings/RuntimeSettingsStore.hpp"

namespace camera_firmware::settings {

enum class RuntimeSettingsState {
  kClean,
  kPending,
  kApplying,
  kFailed,
  kRecoveryRequired,
};

struct ModelCapability {
  std::string id;
  std::string kind;
  unsigned int input_width;
  unsigned int input_height;
  std::string input_format;
  bool letterbox;
  std::string labels;
};

struct RuntimeSettingsSnapshot {
  std::uint64_t revision;
  RuntimeSettingsState state;
  RuntimeSettings active;
  std::optional<RuntimeSettings> pending;
  LastApplyResult last_apply;
  std::vector<CameraProfile> camera_profiles;
  std::vector<ModelCapability> model_capabilities;
};

using CandidateValidator =
    std::function<common::Result<void>(const config::AppConfig&)>;
using RuntimeReplacer = std::function<runtime::RuntimeReplacementResult(
    const config::AppConfig&, std::function<common::Result<void>()>)>;

struct SettingsApplyResult {
  RuntimeSettingsSnapshot snapshot;
  bool applied;
  bool restored;
  common::Error error;
};

class RuntimeSettingsService final {
 public:
  RuntimeSettingsService(config::AppConfig base_config,
                         CameraProfileCatalog profiles,
                         RuntimeSettingsStore& store,
                         runtime::ManagedFirmwareRuntime& runtime,
                         CandidateValidator candidate_validator,
                         RuntimeReplacer runtime_replacer = {});

  RuntimeSettingsService(const RuntimeSettingsService&) = delete;
  RuntimeSettingsService& operator=(const RuntimeSettingsService&) = delete;

  [[nodiscard]] RuntimeSettingsSnapshot Snapshot() const;
  [[nodiscard]] common::Result<RuntimeSettingsSnapshot> Save(
      std::uint64_t expected_revision, RuntimeSettings settings);
  [[nodiscard]] common::Result<RuntimeSettingsSnapshot> Discard(
      std::uint64_t expected_revision);
  [[nodiscard]] SettingsApplyResult Apply(
      std::uint64_t expected_revision);

 private:
  class ApplyingGuard {
   public:
    explicit ApplyingGuard(RuntimeSettingsService& owner) noexcept;
    ~ApplyingGuard() noexcept;
    void Dismiss() noexcept;

   private:
    RuntimeSettingsService& owner_;
    bool active_{true};
  };

  [[nodiscard]] RuntimeSettingsSnapshot SnapshotLocked(
      runtime::ManagedRuntimeState runtime_state) const;
  [[nodiscard]] RuntimeSettingsState StateLocked(
      runtime::ManagedRuntimeState runtime_state) const;
  void Publish(RuntimeSettingsDocument document);
  void BeginApplying();
  void PublishApplyCompletion(
      std::optional<RuntimeSettingsDocument> document);
  [[nodiscard]] SettingsApplyResult RejectApply(common::Error error) const;
  [[nodiscard]] SettingsApplyResult FinishFailedApply(
      std::uint64_t expected_revision, common::Error primary_error,
      bool restored);

  config::AppConfig base_config_;
  CameraProfileCatalog profiles_;
  RuntimeSettingsStore& store_;
  runtime::ManagedFirmwareRuntime& runtime_;
  CandidateValidator candidate_validator_;
  RuntimeReplacer runtime_replacer_;
  std::vector<CameraProfile> camera_profiles_;
  std::vector<ModelCapability> model_capabilities_;

  mutable std::mutex command_mutex_;
  mutable std::mutex snapshot_mutex_;
  RuntimeSettingsDocument document_;
  bool applying_{false};
  std::uint64_t snapshot_generation_{0U};
};

}  // namespace camera_firmware::settings
