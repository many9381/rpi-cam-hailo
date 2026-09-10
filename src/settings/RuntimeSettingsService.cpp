#include "camera_firmware/settings/RuntimeSettingsService.hpp"

#include <string_view>
#include <utility>

namespace camera_firmware::settings {
namespace {

constexpr std::size_t kMaximumPublicApplyCodeBytes = 64U;

common::Error BusyError() {
  return {"E_RUNTIME_SETTINGS_BUSY",
          "another runtime settings command is in progress"};
}

common::Error RevisionError() {
  return {"E_RUNTIME_SETTINGS_REVISION", "runtime settings revision is stale"};
}

common::Error NoPendingError() {
  return {"E_RUNTIME_SETTINGS_NO_PENDING",
          "runtime settings have no pending state"};
}

common::Error RecoveryRequiredError() {
  return {"E_RUNTIME_SETTINGS_RECOVERY_REQUIRED",
          "runtime settings recovery requires an explicit save"};
}

bool IsPublicApplyCode(std::string_view code) {
  if (code.empty() || code.size() > kMaximumPublicApplyCodeBytes) {
    return false;
  }
  for (const unsigned char character : code) {
    if ((character < 'A' || character > 'Z') &&
        (character < '0' || character > '9') && character != '_') {
      return false;
    }
  }
  return true;
}

common::Error PublicApplyError(common::Error error) {
  if (IsPublicApplyCode(error.code)) {
    return error;
  }
  return {"E_RUNTIME_SETTINGS_APPLY", "runtime settings apply failed"};
}

}  // namespace

RuntimeSettingsService::RuntimeSettingsService(
    config::AppConfig base_config, CameraProfileCatalog profiles,
    RuntimeSettingsStore& store, runtime::ManagedFirmwareRuntime& runtime,
    CandidateValidator candidate_validator, RuntimeReplacer runtime_replacer)
    : base_config_(std::move(base_config)),
      profiles_(std::move(profiles)),
      store_(store),
      runtime_(runtime),
      candidate_validator_(std::move(candidate_validator)),
      runtime_replacer_(std::move(runtime_replacer)),
      document_(store_.Snapshot()) {
  if (!runtime_replacer_) {
    runtime_replacer_ =
        [&runtime](const config::AppConfig& candidate,
                   const std::function<common::Result<void>()>& promote) {
          return runtime.Replace(candidate, promote);
        };
  }
  const auto profile_span = profiles_.Profiles();
  camera_profiles_.assign(profile_span.begin(), profile_span.end());

  model_capabilities_.reserve(base_config_.ai.models.size());
  for (const auto& model : base_config_.ai.models) {
    model_capabilities_.push_back({
        .id = model.id,
        .kind = model.kind,
        .input_width = model.input.width,
        .input_height = model.input.height,
        .input_format = model.input.format,
        .letterbox = model.input.letterbox,
        .labels = model.labels,
    });
  }
}

RuntimeSettingsService::ApplyingGuard::ApplyingGuard(
    RuntimeSettingsService& owner) noexcept
    : owner_(owner) {}

RuntimeSettingsService::ApplyingGuard::~ApplyingGuard() noexcept {
  if (active_) {
    try {
      owner_.PublishApplyCompletion(std::nullopt);
    } catch (...) {
      // swallowed: destructors must not throw; the completion is published best
      // effort
    }
  }
}

void RuntimeSettingsService::ApplyingGuard::Dismiss() noexcept {
  active_ = false;
}

RuntimeSettingsSnapshot RuntimeSettingsService::Snapshot() const {
  for (;;) {
    std::uint64_t generation = 0U;
    {
      std::lock_guard lock(snapshot_mutex_);
      if (applying_) {
        return SnapshotLocked(runtime::ManagedRuntimeState::kApplying);
      }
      generation = snapshot_generation_;
    }

    const auto runtime_state = runtime_.State();

    std::lock_guard lock(snapshot_mutex_);
    if (applying_ || snapshot_generation_ != generation) {
      continue;
    }
    return SnapshotLocked(runtime_state);
  }
}

common::Result<RuntimeSettingsSnapshot> RuntimeSettingsService::Save(
    std::uint64_t expected_revision, RuntimeSettings settings) {
  std::unique_lock command_lock(command_mutex_, std::try_to_lock);
  if (!command_lock.owns_lock()) {
    return common::Result<RuntimeSettingsSnapshot>::Err(BusyError());
  }

  {
    std::lock_guard snapshot_lock(snapshot_mutex_);
    if (expected_revision != document_.revision) {
      return common::Result<RuntimeSettingsSnapshot>::Err(RevisionError());
    }
  }

  const auto validated =
      ValidateRuntimeSettings(settings, base_config_, profiles_);
  if (!validated.ok()) {
    return common::Result<RuntimeSettingsSnapshot>::Err(validated.error());
  }

  auto saved = store_.SavePending(expected_revision, std::move(settings));
  if (!saved.ok()) {
    Publish(store_.Snapshot());
    return common::Result<RuntimeSettingsSnapshot>::Err(saved.error());
  }
  Publish(std::move(saved).value());
  return common::Result<RuntimeSettingsSnapshot>::Ok(Snapshot());
}

common::Result<RuntimeSettingsSnapshot> RuntimeSettingsService::Discard(
    std::uint64_t expected_revision) {
  std::unique_lock command_lock(command_mutex_, std::try_to_lock);
  if (!command_lock.owns_lock()) {
    return common::Result<RuntimeSettingsSnapshot>::Err(BusyError());
  }

  auto discarded = store_.DiscardPending(expected_revision);
  if (!discarded.ok()) {
    Publish(store_.Snapshot());
    return common::Result<RuntimeSettingsSnapshot>::Err(discarded.error());
  }
  Publish(std::move(discarded).value());
  return common::Result<RuntimeSettingsSnapshot>::Ok(Snapshot());
}

SettingsApplyResult RuntimeSettingsService::Apply(
    std::uint64_t expected_revision) {
  std::unique_lock command_lock(command_mutex_, std::try_to_lock);
  if (!command_lock.owns_lock()) {
    return RejectApply(BusyError());
  }

  RuntimeSettingsDocument current;
  {
    std::lock_guard snapshot_lock(snapshot_mutex_);
    current = document_;
  }
  if (expected_revision != current.revision) {
    return RejectApply(RevisionError());
  }
  if (current.recovery_required) {
    return RejectApply(RecoveryRequiredError());
  }
  if (!current.pending.has_value()) {
    return RejectApply(NoPendingError());
  }

  auto candidate =
      BuildEffectiveConfig(base_config_, *current.pending, profiles_);
  if (!candidate.ok()) {
    return RejectApply(candidate.error());
  }

  if (!candidate_validator_) {
    return RejectApply({"E_RUNTIME_SETTINGS_APPLY",
                        "runtime settings candidate validator is unavailable"});
  }
  common::Result<void> candidate_validated = common::Result<void>::Ok();
  try {
    candidate_validated = candidate_validator_(candidate.value());
  } catch (...) {
    candidate_validated = common::Result<void>::Err(
        {"E_RUNTIME_SETTINGS_APPLY",
         "runtime settings candidate validation failed"});
  }
  if (!candidate_validated.ok()) {
    return RejectApply(candidate_validated.error());
  }

  std::optional<RuntimeSettingsDocument> promoted_document;
  BeginApplying();
  ApplyingGuard applying_guard(*this);
  runtime::RuntimeReplacementResult replacement;
  try {
    replacement =
        runtime_replacer_(candidate.value(), [&]() -> common::Result<void> {
          auto promoted = store_.PromotePending(expected_revision);
          if (!promoted.ok()) {
            return common::Result<void>::Err(promoted.error());
          }
          promoted_document = std::move(promoted).value();
          return common::Result<void>::Ok();
        });
  } catch (...) {
    auto failed = FinishFailedApply(
        expected_revision,
        {"E_RUNTIME_SETTINGS_APPLY", "runtime settings replacement failed"},
        false);
    applying_guard.Dismiss();
    return failed;
  }

  if (replacement.outcome ==
      runtime::RuntimeReplacementResult::Outcome::kApplied) {
    if (!promoted_document.has_value()) {
      auto failed = FinishFailedApply(
          expected_revision,
          {"E_RUNTIME_SETTINGS_APPLY",
           "runtime replacement skipped durable settings promotion"},
          false);
      applying_guard.Dismiss();
      return failed;
    }
    PublishApplyCompletion(std::move(promoted_document));
    applying_guard.Dismiss();
    return {Snapshot(), true, false, {}};
  }

  auto failed = FinishFailedApply(expected_revision, replacement.error,
                                  replacement.restored);
  applying_guard.Dismiss();
  return failed;
}

RuntimeSettingsSnapshot RuntimeSettingsService::SnapshotLocked(
    runtime::ManagedRuntimeState runtime_state) const {
  return {
      .revision = document_.revision,
      .state = StateLocked(runtime_state),
      .active = document_.active,
      .pending = document_.pending,
      .last_apply = document_.last_apply,
      .camera_profiles = camera_profiles_,
      .model_capabilities = model_capabilities_,
  };
}

RuntimeSettingsState RuntimeSettingsService::StateLocked(
    runtime::ManagedRuntimeState runtime_state) const {
  if (applying_) {
    return RuntimeSettingsState::kApplying;
  }
  if (document_.recovery_required) {
    return RuntimeSettingsState::kRecoveryRequired;
  }
  if (runtime_state == runtime::ManagedRuntimeState::kFailed) {
    return RuntimeSettingsState::kFailed;
  }
  return document_.pending.has_value() ? RuntimeSettingsState::kPending
                                       : RuntimeSettingsState::kClean;
}

void RuntimeSettingsService::Publish(RuntimeSettingsDocument document) {
  std::lock_guard lock(snapshot_mutex_);
  document_ = std::move(document);
  ++snapshot_generation_;
}

void RuntimeSettingsService::BeginApplying() {
  std::lock_guard lock(snapshot_mutex_);
  applying_ = true;
  ++snapshot_generation_;
}

void RuntimeSettingsService::PublishApplyCompletion(
    std::optional<RuntimeSettingsDocument> document) {
  std::lock_guard lock(snapshot_mutex_);
  if (document.has_value()) {
    document_ = std::move(*document);
  }
  applying_ = false;
  ++snapshot_generation_;
}

SettingsApplyResult RuntimeSettingsService::RejectApply(
    common::Error error) const {
  return {Snapshot(), false, false, std::move(error)};
}

SettingsApplyResult RuntimeSettingsService::FinishFailedApply(
    std::uint64_t expected_revision, common::Error primary_error,
    bool restored) {
  primary_error = PublicApplyError(std::move(primary_error));
  auto recorded = store_.RecordApplyFailure(expected_revision,
                                            primary_error.code, restored);
  common::Error result_error = primary_error;
  std::optional<RuntimeSettingsDocument> recorded_document;
  if (recorded.ok()) {
    recorded_document = std::move(recorded).value();
  } else {
    result_error = recorded.error();
    recorded_document = store_.Snapshot();
  }
  PublishApplyCompletion(std::move(recorded_document));
  return {Snapshot(), false, restored, std::move(result_error)};
}

}  // namespace camera_firmware::settings
