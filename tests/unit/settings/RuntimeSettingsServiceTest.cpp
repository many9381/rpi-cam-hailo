#include "camera_firmware/settings/RuntimeSettingsService.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

extern "C" int __real_camera_firmware_settings_renameat(
    int old_directory, const char* old_name, int new_directory,
    const char* new_name);
extern "C" int __real_camera_firmware_settings_fsync(int descriptor);
extern "C" camera_firmware::runtime::ManagedRuntimeState
__real_camera_firmware_managed_runtime_state(
    const camera_firmware::runtime::ManagedFirmwareRuntime* runtime)
    asm("__real__ZNK15camera_firmware7runtime22ManagedFirmwareRuntime5StateEv");

namespace {

using namespace std::chrono_literals;
using camera_firmware::common::Error;
using camera_firmware::common::Result;
using camera_firmware::config::AiModelConfig;
using camera_firmware::config::AppConfig;
using camera_firmware::runtime::FirmwareRuntime;
using camera_firmware::runtime::FirmwareRuntimeDependencies;
using camera_firmware::runtime::ManagedFirmwareRuntime;
using camera_firmware::runtime::ManagedRuntimeState;
using camera_firmware::settings::ApplyStatus;
using camera_firmware::settings::CameraProfileCatalog;
using camera_firmware::settings::CandidateValidator;
using camera_firmware::settings::ModelCapability;
using camera_firmware::settings::RuntimeSettings;
using camera_firmware::settings::RuntimeSettingsDocument;
using camera_firmware::settings::RuntimeSettingsService;
using camera_firmware::settings::RuntimeSettingsSnapshot;
using camera_firmware::settings::RuntimeSettingsState;
using camera_firmware::settings::RuntimeSettingsStore;
using camera_firmware::settings::SettingsApplyResult;

std::atomic<bool> fail_store_rename{false};
std::atomic<int> fail_store_rename_on_call{0};
std::atomic<int> fail_store_fsync_on_call{0};
std::atomic<int> store_rename_calls{0};
std::atomic<int> store_fsync_calls{0};

class ManagedStateReadGate {
 public:
  void Arm(const ManagedFirmwareRuntime& runtime,
           ManagedRuntimeState expected_state) {
    std::lock_guard lock(mutex_);
    runtime_ = &runtime;
    expected_state_ = expected_state;
    entered_ = false;
    released_ = false;
  }

  void BlockAfterRead(const ManagedFirmwareRuntime* runtime,
                      ManagedRuntimeState state) {
    std::unique_lock lock(mutex_);
    if (runtime != runtime_ || state != expected_state_ || entered_) {
      return;
    }
    entered_ = true;
    condition_.notify_all();
    condition_.wait(lock, [this] { return released_; });
    runtime_ = nullptr;
  }

  [[nodiscard]] bool WaitUntilEntered() {
    std::unique_lock lock(mutex_);
    return condition_.wait_for(lock, 2s, [this] { return entered_; });
  }

  void Release() {
    std::lock_guard lock(mutex_);
    released_ = true;
    condition_.notify_all();
  }

 private:
  std::mutex mutex_;
  std::condition_variable condition_;
  const ManagedFirmwareRuntime* runtime_{nullptr};
  ManagedRuntimeState expected_state_{ManagedRuntimeState::kStopped};
  bool entered_{false};
  bool released_{false};
};

ManagedStateReadGate managed_state_read_gate;

class StoreHookScope {
 public:
  StoreHookScope() { Reset(); }
  ~StoreHookScope() { Reset(); }

 private:
  static void Reset() {
    fail_store_rename.store(false);
    fail_store_rename_on_call.store(0);
    fail_store_fsync_on_call.store(0);
    store_rename_calls.store(0);
    store_fsync_calls.store(0);
  }
};

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::filesystem::create_directories(CF_TEST_BINARY_DIR);
    std::string pattern =
        std::string(CF_TEST_BINARY_DIR) + "/runtime-settings-service-XXXXXX";
    char* created = ::mkdtemp(pattern.data());
    if (created == nullptr) {
      throw std::runtime_error("failed to create service test directory");
    }
    path_ = created;
  }

  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept {
    return path_;
  }

 private:
  std::filesystem::path path_;
};

AiModelConfig MakeModel(std::string id, std::string labels,
                        unsigned int width, unsigned int height,
                        std::string format, bool letterbox, float threshold) {
  AiModelConfig model;
  model.id = std::move(id);
  model.kind = "object_detection";
  model.hef_path = "/private/models/" + model.id + ".hef";
  model.output_name = model.id + "/private-output";
  model.input.width = width;
  model.input.height = height;
  model.input.format = std::move(format);
  model.input.letterbox = letterbox;
  model.confidence_threshold = threshold;
  model.labels = std::move(labels);
  return model;
}

AppConfig MakeBaseConfig() {
  AppConfig base;
  base.secure_rtsp.enabled = false;
  base.security.enabled = false;
  base.ai.enabled = true;
  base.ai.backend = "hailo";
  base.ai.models = {
      MakeModel("objects", "coco80", 640U, 640U, "rgb8", true, 0.40F),
      MakeModel("pose", "pose17", 320U, 256U, "rgb8", false, 0.35F),
  };
  base.camera.ai.enabled = true;
  base.camera.ai.model_ids = {"objects", "pose"};
  return base;
}

RuntimeSettings MakeBaseActive() {
  return {
      .camera = {"imx708-1080p50", 6000U, 25U},
      // Non-zero geometry even while disabled: value-initializing an omitted
      // .sub_stream would zero it, which validation now rejects (the settings-UI
      // DoS invariant). Use the shipped default geometry.
      .sub_stream = {false, 640U, 360U, 15U, 1000U},
      .models = {{"objects", true, 0.40F}, {"pose", true, 0.35F}},
  };
}

RuntimeSettings MakePending() {
  return {
      .camera = {"imx708-1080p30", 8000U, 30U},
      .sub_stream = {false, 640U, 360U, 15U, 1000U},
      .models = {{"objects", true, 0.55F}, {"pose", false, 0.25F}},
  };
}

void ExpectSettingsEqual(const RuntimeSettings& actual,
                         const RuntimeSettings& expected) {
  EXPECT_EQ(actual.camera.profile_id, expected.camera.profile_id);
  EXPECT_EQ(actual.camera.bitrate_kbps, expected.camera.bitrate_kbps);
  EXPECT_EQ(actual.camera.gop, expected.camera.gop);
  ASSERT_EQ(actual.models.size(), expected.models.size());
  for (std::size_t index = 0U; index < expected.models.size(); ++index) {
    EXPECT_EQ(actual.models[index].id, expected.models[index].id);
    EXPECT_EQ(actual.models[index].enabled, expected.models[index].enabled);
    EXPECT_FLOAT_EQ(actual.models[index].confidence_threshold,
                    expected.models[index].confidence_threshold);
  }
}

void ExpectDocumentEqual(const RuntimeSettingsDocument& actual,
                         const RuntimeSettingsDocument& expected) {
  EXPECT_EQ(actual.revision, expected.revision);
  ExpectSettingsEqual(actual.active, expected.active);
  EXPECT_EQ(actual.pending.has_value(), expected.pending.has_value());
  if (actual.pending.has_value() && expected.pending.has_value()) {
    ExpectSettingsEqual(*actual.pending, *expected.pending);
  }
  EXPECT_EQ(actual.last_apply.status, expected.last_apply.status);
  EXPECT_EQ(actual.last_apply.code, expected.last_apply.code);
  EXPECT_EQ(actual.last_apply.restored, expected.last_apply.restored);
  EXPECT_EQ(actual.recovery_required, expected.recovery_required);
  EXPECT_EQ(actual.recovery_code, expected.recovery_code);
}

struct RuntimeProbe {
  std::atomic<unsigned int> starts{0U};
  std::atomic<unsigned int> stops{0U};
  unsigned int fail_start_attempt{0U};
  std::string failure_code{"E_CANDIDATE_START"};
  std::function<void(unsigned int)> before_start;
};

FirmwareRuntimeDependencies DependenciesFor(
    const std::shared_ptr<RuntimeProbe>& probe) {
  FirmwareRuntimeDependencies dependencies;
  dependencies.start_rtsp = [probe] {
    const unsigned int attempt = probe->starts.fetch_add(1U) + 1U;
    if (probe->before_start) {
      probe->before_start(attempt);
    }
    if (attempt == probe->fail_start_attempt) {
      return Result<void>::Err(
          {probe->failure_code, "injected runtime start failure"});
    }
    return Result<void>::Ok();
  };
  dependencies.start_ai = [] { return Result<void>::Ok(); };
  dependencies.start_camera = [] { return Result<void>::Ok(); };
  dependencies.start_live = [] { return Result<void>::Ok(); };
  dependencies.stop_live = [] {};
  dependencies.stop_camera = [] {};
  dependencies.stop_ai = [] {};
  dependencies.stop_rtsp = [probe] { probe->stops.fetch_add(1U); };
  return dependencies;
}

class RuntimeFactorySequence {
 public:
  using Action = std::function<Result<std::shared_ptr<FirmwareRuntime>>(
      const AppConfig&)>;

  void Push(Action action) {
    std::lock_guard lock(mutex_);
    actions_.push_back(std::move(action));
  }

  Result<std::shared_ptr<FirmwareRuntime>> Next(const AppConfig& config) {
    calls.fetch_add(1U);
    Action action;
    {
      std::lock_guard lock(mutex_);
      if (actions_.empty()) {
        return Result<std::shared_ptr<FirmwareRuntime>>::Err(
            {"E_TEST_FACTORY_EMPTY", "no queued runtime"});
      }
      action = std::move(actions_.front());
      actions_.pop_front();
    }
    return action(config);
  }

  std::atomic<unsigned int> calls{0U};

 private:
  std::mutex mutex_;
  std::deque<Action> actions_;
};

CandidateValidator AcceptCandidate() {
  return [](const AppConfig&) { return Result<void>::Ok(); };
}

class ServiceContext {
 public:
  explicit ServiceContext(CandidateValidator validator = AcceptCandidate(),
                          AppConfig base = MakeBaseConfig(),
                          bool invalid_document = false,
                          std::optional<AppConfig> initial_config = std::nullopt,
                          camera_firmware::settings::RuntimeReplacer replacer = {})
      : base_(std::move(base)),
        profiles_(CameraProfileCatalog::Rpi5Imx708()),
        factory_(std::make_shared<RuntimeFactorySequence>()),
        old_probe_(std::make_shared<RuntimeProbe>()) {
    if (invalid_document) {
      const auto document = directory_.path() / "runtime-settings.json";
      std::ofstream output(document);
      output << "not-json";
      output.close();
      if (::chmod(document.c_str(), 0600) != 0) {
        throw std::runtime_error("failed to protect invalid test document");
      }
    }

    auto opened = RuntimeSettingsStore::Open(
        directory_.path(), MakeBaseActive(), base_, profiles_);
    if (!opened.ok()) {
      throw std::runtime_error(opened.error().code + ": " +
                               opened.error().message);
    }
    store_ = std::move(opened).value();

    const auto effective = camera_firmware::settings::BuildEffectiveConfig(
        base_, store_->Snapshot().active, profiles_);
    if (!effective.ok() && !invalid_document && !initial_config.has_value()) {
      throw std::runtime_error(effective.error().code + ": " +
                               effective.error().message);
    }
    const AppConfig runtime_config = initial_config.has_value()
                                         ? std::move(*initial_config)
                                         : (effective.ok() ? effective.value()
                                                           : base_);
    factory_->Push([probe = old_probe_](const AppConfig& config) {
      return Result<std::shared_ptr<FirmwareRuntime>>::Ok(
          std::make_shared<FirmwareRuntime>(config, DependenciesFor(probe)));
    });
    runtime_ = std::make_unique<ManagedFirmwareRuntime>(
        runtime_config,
        [factory = factory_](const AppConfig& config) {
          return factory->Next(config);
        });
    const auto started = runtime_->Start();
    if (!started.ok()) {
      throw std::runtime_error(started.error().code + ": " +
                               started.error().message);
    }
    service_ = std::make_unique<RuntimeSettingsService>(
        base_, profiles_, *store_, *runtime_, std::move(validator),
        std::move(replacer));
  }

  std::shared_ptr<RuntimeProbe> QueueCandidate(
      std::function<void(const AppConfig&)> inspect = {}) {
    auto probe = std::make_shared<RuntimeProbe>();
    factory_->Push([probe, inspect = std::move(inspect)](
                       const AppConfig& config) {
      if (inspect) {
        inspect(config);
      }
      return Result<std::shared_ptr<FirmwareRuntime>>::Ok(
          std::make_shared<FirmwareRuntime>(config, DependenciesFor(probe)));
    });
    return probe;
  }

  void QueueFactoryFailure(Error error) {
    factory_->Push([error = std::move(error)](const AppConfig&) {
      return Result<std::shared_ptr<FirmwareRuntime>>::Err(error);
    });
  }

  std::unique_ptr<RuntimeSettingsStore> ReopenStore() const {
    auto opened = RuntimeSettingsStore::Open(
        directory_.path(), MakeBaseActive(), base_, profiles_);
    if (!opened.ok()) {
      throw std::runtime_error(opened.error().code + ": " +
                               opened.error().message);
    }
    return std::move(opened).value();
  }

  RuntimeSettingsService& service() { return *service_; }
  RuntimeSettingsStore& store() { return *store_; }
  ManagedFirmwareRuntime& runtime() { return *runtime_; }
  RuntimeFactorySequence& factory() { return *factory_; }
  RuntimeProbe& old_probe() { return *old_probe_; }

 private:
  TemporaryDirectory directory_;
  AppConfig base_;
  CameraProfileCatalog profiles_;
  std::shared_ptr<RuntimeFactorySequence> factory_;
  std::shared_ptr<RuntimeProbe> old_probe_;
  std::unique_ptr<RuntimeSettingsStore> store_;
  std::unique_ptr<ManagedFirmwareRuntime> runtime_;
  std::unique_ptr<RuntimeSettingsService> service_;
};

template <typename T>
concept HasHefPath = requires(T value) { value.hef_path; };

template <typename T>
concept HasOutputName = requires(T value) { value.output_name; };

static_assert(!HasHefPath<ModelCapability>);
static_assert(!HasOutputName<ModelCapability>);

TEST(RuntimeSettingsServiceTest,
     SnapshotExposesCleanPendingAndSafeOrderedCapabilities) {
  ServiceContext context;

  const auto clean = context.service().Snapshot();

  EXPECT_EQ(clean.revision, 0U);
  EXPECT_EQ(clean.state, RuntimeSettingsState::kClean);
  EXPECT_FALSE(clean.pending.has_value());
  ASSERT_EQ(clean.camera_profiles.size(), 3U);
  EXPECT_EQ(clean.camera_profiles[0].id, "imx708-1080p50");
  ASSERT_EQ(clean.model_capabilities.size(), 2U);
  EXPECT_EQ(clean.model_capabilities[0].id, "objects");
  EXPECT_EQ(clean.model_capabilities[0].kind, "object_detection");
  EXPECT_EQ(clean.model_capabilities[0].input_width, 640U);
  EXPECT_EQ(clean.model_capabilities[0].input_height, 640U);
  EXPECT_EQ(clean.model_capabilities[0].input_format, "rgb8");
  EXPECT_TRUE(clean.model_capabilities[0].letterbox);
  EXPECT_EQ(clean.model_capabilities[0].labels, "coco80");
  EXPECT_EQ(clean.model_capabilities[1].id, "pose");
  EXPECT_EQ(clean.model_capabilities[1].labels, "pose17");

  const auto saved = context.service().Save(0U, MakePending());

  ASSERT_TRUE(saved.ok()) << saved.error().message;
  EXPECT_EQ(saved.value().revision, 1U);
  EXPECT_EQ(saved.value().state, RuntimeSettingsState::kPending);
  ASSERT_TRUE(saved.value().pending.has_value());
  ExpectSettingsEqual(*saved.value().pending, MakePending());
}

TEST(RuntimeSettingsServiceTest,
     SaveAndDiscardEnforceOptimisticRevisionAndFullModelSnapshot) {
  ServiceContext context;
  auto invalid = MakePending();
  std::swap(invalid.models[0], invalid.models[1]);

  const auto invalid_save = context.service().Save(0U, invalid);
  ASSERT_FALSE(invalid_save.ok());
  EXPECT_EQ(invalid_save.error().code, "E_RUNTIME_SETTINGS_MODEL_ORDER");
  EXPECT_EQ(context.service().Snapshot().revision, 0U);

  const auto saved = context.service().Save(0U, MakePending());
  ASSERT_TRUE(saved.ok()) << saved.error().message;
  const auto stale_save = context.service().Save(0U, MakePending());
  ASSERT_FALSE(stale_save.ok());
  EXPECT_EQ(stale_save.error().code, "E_RUNTIME_SETTINGS_REVISION");
  const auto stale_discard = context.service().Discard(0U);
  ASSERT_FALSE(stale_discard.ok());
  EXPECT_EQ(stale_discard.error().code, "E_RUNTIME_SETTINGS_REVISION");

  const auto discarded = context.service().Discard(1U);
  ASSERT_TRUE(discarded.ok()) << discarded.error().message;
  EXPECT_EQ(discarded.value().revision, 2U);
  EXPECT_EQ(discarded.value().state, RuntimeSettingsState::kClean);
  EXPECT_FALSE(discarded.value().pending.has_value());

  const auto no_pending_discard = context.service().Discard(2U);
  ASSERT_FALSE(no_pending_discard.ok());
  EXPECT_EQ(no_pending_discard.error().code,
            "E_RUNTIME_SETTINGS_NO_PENDING");
}

TEST(RuntimeSettingsServiceTest, ApplyRejectsStaleRevisionAndMissingPending) {
  ServiceContext context;

  const auto missing = context.service().Apply(0U);
  EXPECT_FALSE(missing.applied);
  EXPECT_EQ(missing.error.code, "E_RUNTIME_SETTINGS_NO_PENDING");

  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  const auto stale = context.service().Apply(0U);
  EXPECT_FALSE(stale.applied);
  EXPECT_EQ(stale.error.code, "E_RUNTIME_SETTINGS_REVISION");
  EXPECT_EQ(context.old_probe().stops.load(), 0U);
}

TEST(RuntimeSettingsServiceTest,
     SemanticValidationRejectsCandidateBeforeValidatorAndOldStop) {
  auto base = MakeBaseConfig();
  base.http.live.fragment_duration_ms = 1000U;
  base.http.live.stale_timeout_ms = 1500U;
  std::atomic<unsigned int> validator_calls{0U};
  ServiceContext context(
      [&validator_calls](const AppConfig&) {
        validator_calls.fetch_add(1U);
        return Result<void>::Ok();
      },
      base, false, MakeBaseConfig());
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  const auto before = context.ReopenStore()->Snapshot();

  const auto applied = context.service().Apply(1U);

  EXPECT_FALSE(applied.applied);
  EXPECT_EQ(applied.error.code, "E_CONFIG_HTTP_LIVE");
  EXPECT_EQ(validator_calls.load(), 0U);
  EXPECT_EQ(context.old_probe().stops.load(), 0U);
  EXPECT_EQ(context.factory().calls.load(), 1U);
  EXPECT_EQ(applied.snapshot.revision, before.revision);
  EXPECT_EQ(applied.snapshot.last_apply.status, before.last_apply.status);
  ExpectDocumentEqual(context.store().Snapshot(), before);
  ExpectDocumentEqual(context.ReopenStore()->Snapshot(), before);
}

TEST(RuntimeSettingsServiceTest,
     CandidateValidatorRejectsBeforeOldRuntimeIsStopped) {
  std::atomic<unsigned int> validator_calls{0U};
  ServiceContext context([&validator_calls](const AppConfig&) {
    validator_calls.fetch_add(1U);
    return Result<void>::Err(
        {"E_PIPELINE_CANDIDATE", "candidate pipeline is unsupported"});
  });
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  const auto before = context.ReopenStore()->Snapshot();

  const auto applied = context.service().Apply(1U);

  EXPECT_FALSE(applied.applied);
  EXPECT_EQ(applied.error.code, "E_PIPELINE_CANDIDATE");
  EXPECT_EQ(validator_calls.load(), 1U);
  EXPECT_EQ(context.old_probe().stops.load(), 0U);
  EXPECT_EQ(context.factory().calls.load(), 1U);
  EXPECT_EQ(applied.snapshot.revision, before.revision);
  EXPECT_EQ(applied.snapshot.last_apply.status, before.last_apply.status);
  ExpectDocumentEqual(context.store().Snapshot(), before);
  ExpectDocumentEqual(context.ReopenStore()->Snapshot(), before);
}

TEST(RuntimeSettingsServiceTest,
     RuntimeReplacementExceptionClearsApplyingState) {
  camera_firmware::settings::RuntimeReplacer throwing_replacer =
      [](const AppConfig&, std::function<Result<void>()>)
          -> camera_firmware::runtime::RuntimeReplacementResult {
        throw std::runtime_error("injected replacement exception");
      };
  ServiceContext context(AcceptCandidate(), MakeBaseConfig(), false,
                         std::nullopt, std::move(throwing_replacer));
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());

  const auto applied = context.service().Apply(1U);

  EXPECT_FALSE(applied.applied);
  EXPECT_EQ(applied.error.code, "E_RUNTIME_SETTINGS_APPLY");
  EXPECT_EQ(context.service().Snapshot().state,
            RuntimeSettingsState::kPending);
}

TEST(RuntimeSettingsServiceTest,
     ReplacementSuccessWithoutDurablePromotionIsRejected) {
  camera_firmware::settings::RuntimeReplacer incomplete_replacer =
      [](const AppConfig&, std::function<Result<void>()>) {
        return camera_firmware::runtime::RuntimeReplacementResult{
            .outcome = camera_firmware::runtime::RuntimeReplacementResult::
                Outcome::kApplied,
        };
      };
  ServiceContext context(AcceptCandidate(), MakeBaseConfig(), false,
                         std::nullopt, std::move(incomplete_replacer));
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());

  const auto applied = context.service().Apply(1U);

  EXPECT_FALSE(applied.applied);
  EXPECT_EQ(applied.error.code, "E_RUNTIME_SETTINGS_APPLY");
  EXPECT_EQ(context.service().Snapshot().state,
            RuntimeSettingsState::kPending);
}

TEST(RuntimeSettingsServiceConcurrencyTest,
     ValidatorPreflightRemainsPendingUntilRuntimeReplacementStarts) {
  std::promise<void> validator_entered;
  std::promise<void> release_validator;
  const auto release = release_validator.get_future().share();
  ServiceContext context([&](const AppConfig&) {
    validator_entered.set_value();
    release.wait();
    return Result<void>::Ok();
  });
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  context.QueueCandidate();

  std::optional<SettingsApplyResult> apply_result;
  std::thread applying(
      [&] { apply_result = context.service().Apply(1U); });
  const auto entered_status = validator_entered.get_future().wait_for(2s);
  std::optional<RuntimeSettingsSnapshot> during_validation;
  if (entered_status == std::future_status::ready) {
    during_validation = context.service().Snapshot();
  }

  release_validator.set_value();
  applying.join();

  ASSERT_EQ(entered_status, std::future_status::ready);
  ASSERT_TRUE(during_validation.has_value());
  EXPECT_EQ(during_validation->state, RuntimeSettingsState::kPending);
  EXPECT_EQ(during_validation->revision, 1U);
  EXPECT_EQ(context.old_probe().stops.load(), 1U);
  ASSERT_TRUE(apply_result.has_value());
  EXPECT_TRUE(apply_result->applied);
}

TEST(RuntimeSettingsServiceTest,
     SuccessfulApplyPromotesExactRevisionAndPublishesCandidate) {
  ServiceContext context;
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  std::optional<AppConfig> candidate_config;
  context.QueueCandidate(
      [&candidate_config](const AppConfig& config) { candidate_config = config; });

  const SettingsApplyResult applied = context.service().Apply(1U);

  EXPECT_TRUE(applied.applied);
  EXPECT_FALSE(applied.restored);
  EXPECT_TRUE(applied.error.code.empty());
  EXPECT_EQ(applied.snapshot.revision, 2U);
  EXPECT_EQ(applied.snapshot.state, RuntimeSettingsState::kClean);
  EXPECT_FALSE(applied.snapshot.pending.has_value());
  ExpectSettingsEqual(applied.snapshot.active, MakePending());
  EXPECT_EQ(applied.snapshot.last_apply.status, ApplyStatus::kSuccess);
  ASSERT_TRUE(candidate_config.has_value());
  EXPECT_EQ(candidate_config->camera.video.fps, 30U);
  EXPECT_EQ(context.runtime().ActiveConfig().camera.video.fps, 30U);
}

TEST(RuntimeSettingsServiceTest,
     CandidateFailureRestoresOldRuntimeAndDurablyRecordsFailure) {
  ServiceContext context;
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  context.QueueFactoryFailure(
      {"E_CANDIDATE_FACTORY", "injected candidate factory failure"});

  const auto applied = context.service().Apply(1U);

  EXPECT_FALSE(applied.applied);
  EXPECT_TRUE(applied.restored);
  EXPECT_EQ(applied.error.code, "E_CANDIDATE_FACTORY");
  EXPECT_EQ(applied.snapshot.revision, 2U);
  EXPECT_EQ(applied.snapshot.state, RuntimeSettingsState::kPending);
  ASSERT_TRUE(applied.snapshot.pending.has_value());
  EXPECT_EQ(applied.snapshot.last_apply.status, ApplyStatus::kFailed);
  EXPECT_EQ(applied.snapshot.last_apply.code, "E_CANDIDATE_FACTORY");
  EXPECT_TRUE(applied.snapshot.last_apply.restored);
  EXPECT_EQ(context.old_probe().starts.load(), 2U);

  const auto reopened = context.ReopenStore()->Snapshot();
  EXPECT_EQ(reopened.revision, 2U);
  EXPECT_EQ(reopened.last_apply.status, ApplyStatus::kFailed);
  EXPECT_EQ(reopened.last_apply.code, "E_CANDIDATE_FACTORY");
  EXPECT_TRUE(reopened.last_apply.restored);
  EXPECT_TRUE(reopened.pending.has_value());
}

TEST(RuntimeSettingsServiceTest,
     FailedCandidateAndFailedRestoreReportFailedState) {
  ServiceContext context;
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  context.old_probe().fail_start_attempt = 2U;
  context.QueueFactoryFailure(
      {"E_CANDIDATE_FACTORY", "injected candidate factory failure"});

  const auto applied = context.service().Apply(1U);

  EXPECT_FALSE(applied.applied);
  EXPECT_FALSE(applied.restored);
  EXPECT_EQ(applied.error.code, "E_CANDIDATE_FACTORY");
  EXPECT_EQ(applied.snapshot.state, RuntimeSettingsState::kFailed);
  EXPECT_EQ(applied.snapshot.last_apply.status, ApplyStatus::kFailed);
  EXPECT_FALSE(applied.snapshot.last_apply.restored);
  EXPECT_TRUE(applied.snapshot.pending.has_value());
}

TEST(RuntimeSettingsServiceTest,
     FailedRestoreCanSaveAndApplyCorrectedPendingSettings) {
  ServiceContext context;
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  context.old_probe().fail_start_attempt = 2U;
  context.QueueFactoryFailure(
      {"E_CANDIDATE_FACTORY", "injected candidate factory failure"});
  const auto failed = context.service().Apply(1U);
  ASSERT_FALSE(failed.applied);
  ASSERT_FALSE(failed.restored);
  ASSERT_EQ(failed.snapshot.revision, 2U);
  ASSERT_EQ(failed.snapshot.state, RuntimeSettingsState::kFailed);

  auto corrected = MakePending();
  corrected.camera.profile_id = "imx708-720p50";
  corrected.camera.bitrate_kbps = 7000U;
  corrected.camera.gop = 50U;
  const auto saved = context.service().Save(2U, corrected);
  ASSERT_TRUE(saved.ok()) << saved.error().message;
  EXPECT_EQ(saved.value().revision, 3U);
  EXPECT_EQ(saved.value().state, RuntimeSettingsState::kFailed);
  ASSERT_TRUE(saved.value().pending.has_value());
  ExpectSettingsEqual(*saved.value().pending, corrected);
  context.QueueCandidate();

  const auto recovered = context.service().Apply(3U);

  ASSERT_TRUE(recovered.applied) << recovered.error.message;
  EXPECT_FALSE(recovered.restored);
  EXPECT_EQ(recovered.snapshot.revision, 4U);
  EXPECT_EQ(recovered.snapshot.state, RuntimeSettingsState::kClean);
  EXPECT_FALSE(recovered.snapshot.pending.has_value());
  EXPECT_EQ(recovered.snapshot.last_apply.status, ApplyStatus::kSuccess);
  ExpectSettingsEqual(recovered.snapshot.active, corrected);
  EXPECT_EQ(context.runtime().ActiveConfig().camera.video.width, 1280U);
  EXPECT_EQ(context.runtime().ActiveConfig().camera.video.height, 720U);
  EXPECT_EQ(context.runtime().ActiveConfig().camera.video.fps, 50U);

  const auto reopened = context.ReopenStore()->Snapshot();
  EXPECT_EQ(reopened.revision, 4U);
  EXPECT_FALSE(reopened.pending.has_value());
  EXPECT_EQ(reopened.last_apply.status, ApplyStatus::kSuccess);
  ExpectSettingsEqual(reopened.active, corrected);
}

TEST(RuntimeSettingsServiceConcurrencyTest,
     SnapshotKeepsRuntimeStateCoherentAcrossFailureAndRecoveryPublication) {
  ServiceContext context;
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  context.old_probe().fail_start_attempt = 2U;
  context.QueueFactoryFailure(
      {"E_CANDIDATE_FACTORY", "injected candidate factory failure"});

  managed_state_read_gate.Arm(context.runtime(), ManagedRuntimeState::kRunning);
  std::optional<RuntimeSettingsSnapshot> failure_snapshot;
  std::thread failure_reader(
      [&] { failure_snapshot = context.service().Snapshot(); });
  const bool failure_reader_entered =
      managed_state_read_gate.WaitUntilEntered();
  std::optional<SettingsApplyResult> failed;
  if (failure_reader_entered) {
    failed = context.service().Apply(1U);
  }
  managed_state_read_gate.Release();
  failure_reader.join();

  ASSERT_TRUE(failure_reader_entered);
  ASSERT_TRUE(failed.has_value());
  ASSERT_FALSE(failed->applied);
  ASSERT_FALSE(failed->restored);
  ASSERT_TRUE(failure_snapshot.has_value());
  EXPECT_EQ(failure_snapshot->revision, 2U);
  EXPECT_EQ(failure_snapshot->state, RuntimeSettingsState::kFailed);
  EXPECT_TRUE(failure_snapshot->pending.has_value());

  auto corrected = MakePending();
  corrected.camera.profile_id = "imx708-720p50";
  corrected.camera.bitrate_kbps = 7000U;
  corrected.camera.gop = 50U;
  const auto saved = context.service().Save(2U, corrected);
  ASSERT_TRUE(saved.ok()) << saved.error().message;
  ASSERT_EQ(saved.value().revision, 3U);
  context.QueueCandidate();

  managed_state_read_gate.Arm(context.runtime(), ManagedRuntimeState::kFailed);
  std::optional<RuntimeSettingsSnapshot> recovery_snapshot;
  std::thread recovery_reader(
      [&] { recovery_snapshot = context.service().Snapshot(); });
  const bool recovery_reader_entered =
      managed_state_read_gate.WaitUntilEntered();
  std::optional<SettingsApplyResult> recovered;
  if (recovery_reader_entered) {
    recovered = context.service().Apply(3U);
  }
  managed_state_read_gate.Release();
  recovery_reader.join();

  ASSERT_TRUE(recovery_reader_entered);
  ASSERT_TRUE(recovered.has_value());
  ASSERT_TRUE(recovered->applied) << recovered->error.message;
  ASSERT_TRUE(recovery_snapshot.has_value());
  EXPECT_EQ(recovery_snapshot->revision, 4U);
  EXPECT_EQ(recovery_snapshot->state, RuntimeSettingsState::kClean);
  EXPECT_FALSE(recovery_snapshot->pending.has_value());
}

TEST(RuntimeSettingsServiceTest,
     InvalidCandidateErrorCodeIsReplacedByBoundedPublicCode) {
  ServiceContext context;
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  context.QueueFactoryFailure(
      {std::string(80U, 'x'), "/private/models/secret.hef failed"});

  const auto applied = context.service().Apply(1U);

  EXPECT_FALSE(applied.applied);
  EXPECT_EQ(applied.error.code, "E_RUNTIME_SETTINGS_APPLY");
  EXPECT_EQ(applied.snapshot.last_apply.code, "E_RUNTIME_SETTINGS_APPLY");
  EXPECT_EQ(applied.snapshot.last_apply.code.find("private"), std::string::npos);
}

TEST(RuntimeSettingsServiceTest,
     PromotionFailureRestoresOldRuntimeAndPreservesDurableRevision) {
  StoreHookScope hooks;
  ServiceContext context;
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  context.QueueCandidate();
  fail_store_rename.store(true);

  const auto applied = context.service().Apply(1U);

  EXPECT_FALSE(applied.applied);
  EXPECT_TRUE(applied.restored);
  EXPECT_EQ(applied.error.code, "E_RUNTIME_SETTINGS_STORE");
  EXPECT_EQ(applied.snapshot.revision, 1U);
  EXPECT_EQ(applied.snapshot.state,
            RuntimeSettingsState::kRecoveryRequired);
  EXPECT_EQ(applied.snapshot.last_apply.status, ApplyStatus::kNever);
  EXPECT_TRUE(applied.snapshot.pending.has_value());
  EXPECT_EQ(context.runtime().ActiveConfig().camera.video.fps, 50U);

  fail_store_rename.store(false);
  const auto reopened = context.ReopenStore()->Snapshot();
  EXPECT_EQ(reopened.revision, 1U);
  EXPECT_TRUE(reopened.recovery_required);
  EXPECT_EQ(reopened.last_apply.status, ApplyStatus::kNever);
  EXPECT_TRUE(reopened.pending.has_value());
}

TEST(RuntimeSettingsServiceTest,
     IndeterminateSaveFailurePublishesRecoveryStateAndBlocksRetry) {
  StoreHookScope hooks;
  ServiceContext context;
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  store_fsync_calls.store(0);
  store_rename_calls.store(0);
  fail_store_fsync_on_call.store(2);
  fail_store_rename_on_call.store(2);

  const auto saved = context.service().Save(1U, MakeBaseActive());

  ASSERT_FALSE(saved.ok());
  EXPECT_EQ(saved.error().code, "E_RUNTIME_SETTINGS_STORE");
  const auto recovery = context.service().Snapshot();
  EXPECT_EQ(recovery.state, RuntimeSettingsState::kRecoveryRequired);
  const auto retried = context.service().Save(recovery.revision, MakePending());
  ASSERT_FALSE(retried.ok());
  EXPECT_EQ(retried.error().code, "E_RUNTIME_SETTINGS_STORE");
}

TEST(RuntimeSettingsServiceTest,
     FailureRecordingFailureReturnsStoreErrorAndUnchangedDurableSnapshot) {
  StoreHookScope hooks;
  ServiceContext context;
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  const auto before = context.ReopenStore()->Snapshot();
  context.QueueFactoryFailure(
      {"E_CANDIDATE_FACTORY", "injected candidate factory failure"});
  fail_store_rename.store(true);

  const auto applied = context.service().Apply(1U);

  EXPECT_FALSE(applied.applied);
  EXPECT_TRUE(applied.restored);
  EXPECT_EQ(applied.error.code, "E_RUNTIME_SETTINGS_STORE");
  EXPECT_EQ(applied.snapshot.revision, 1U);
  EXPECT_EQ(applied.snapshot.last_apply.status, ApplyStatus::kNever);
  EXPECT_TRUE(applied.snapshot.pending.has_value());
  ExpectDocumentEqual(context.store().Snapshot(), before);

  fail_store_rename.store(false);
  ExpectDocumentEqual(context.ReopenStore()->Snapshot(), before);
}

TEST(RuntimeSettingsServiceTest,
     RecoverySaveIsOnlyCommandThatReplacesInvalidStorage) {
  ServiceContext context(AcceptCandidate(), MakeBaseConfig(), true);

  const auto recovery = context.service().Snapshot();
  EXPECT_EQ(recovery.revision, 0U);
  EXPECT_EQ(recovery.state, RuntimeSettingsState::kRecoveryRequired);
  const auto discarded = context.service().Discard(0U);
  ASSERT_FALSE(discarded.ok());
  EXPECT_EQ(discarded.error().code,
            "E_RUNTIME_SETTINGS_RECOVERY_REQUIRED");
  const auto applied = context.service().Apply(0U);
  EXPECT_FALSE(applied.applied);

  const auto saved = context.service().Save(0U, MakePending());

  ASSERT_TRUE(saved.ok()) << saved.error().message;
  EXPECT_EQ(saved.value().revision, 1U);
  EXPECT_EQ(saved.value().state, RuntimeSettingsState::kPending);
  EXPECT_TRUE(saved.value().pending.has_value());
  EXPECT_FALSE(context.store().Snapshot().recovery_required);
}

TEST(RuntimeSettingsServiceTest,
     AllModelsDisabledKeepsBaseAiAndVideoButDisablesCameraInference) {
  ServiceContext context;
  auto pending = MakePending();
  for (auto& model : pending.models) {
    model.enabled = false;
  }
  ASSERT_TRUE(context.service().Save(0U, pending).ok());
  std::optional<AppConfig> candidate_config;
  context.QueueCandidate(
      [&candidate_config](const AppConfig& config) { candidate_config = config; });

  const auto applied = context.service().Apply(1U);

  ASSERT_TRUE(applied.applied) << applied.error.message;
  ASSERT_TRUE(candidate_config.has_value());
  EXPECT_TRUE(candidate_config->ai.enabled);
  EXPECT_TRUE(candidate_config->http.live.enabled);
  EXPECT_FALSE(candidate_config->camera.ai.enabled);
  EXPECT_TRUE(candidate_config->camera.ai.model_ids.empty());
  EXPECT_EQ(context.runtime().ActiveConfig().camera.video.fps, 30U);
}

TEST(RuntimeSettingsServiceConcurrencyTest,
     OverlappingCommandsReturnBusyWhileSnapshotsRemainRaceFree) {
  ServiceContext context;
  ASSERT_TRUE(context.service().Save(0U, MakePending()).ok());
  std::promise<void> candidate_entered;
  std::promise<void> release_candidate;
  const auto release = release_candidate.get_future().share();
  auto candidate = context.QueueCandidate();
  candidate->before_start = [&](unsigned int) {
    candidate_entered.set_value();
    release.wait();
  };

  std::optional<SettingsApplyResult> primary_apply;
  std::thread applying(
      [&] { primary_apply = context.service().Apply(1U); });
  const auto candidate_status = candidate_entered.get_future().wait_for(2s);
  std::optional<RuntimeSettingsSnapshot> applying_snapshot;
  if (candidate_status == std::future_status::ready) {
    applying_snapshot = context.service().Snapshot();
  }

  std::atomic<bool> stop_reader{false};
  std::atomic<bool> invalid_snapshot{false};
  std::thread reader([&] {
    while (!stop_reader.load()) {
      const auto snapshot = context.service().Snapshot();
      if (snapshot.camera_profiles.size() != 3U ||
          snapshot.model_capabilities.size() != 2U ||
          snapshot.active.models.size() != 2U ||
          snapshot.revision > 2U) {
        invalid_snapshot.store(true);
      }
    }
  });

  auto save = std::async(std::launch::async, [&] {
    return context.service().Save(1U, MakePending());
  });
  auto discard = std::async(std::launch::async,
                            [&] { return context.service().Discard(1U); });
  auto second_apply = std::async(
      std::launch::async, [&] { return context.service().Apply(1U); });

  const auto save_status = save.wait_for(250ms);
  const auto discard_status = discard.wait_for(250ms);
  const auto second_apply_status = second_apply.wait_for(250ms);

  release_candidate.set_value();
  stop_reader.store(true);
  reader.join();
  applying.join();

  const auto save_result = save.get();
  const auto discard_result = discard.get();
  const auto apply_result = second_apply.get();

  ASSERT_EQ(candidate_status, std::future_status::ready);
  ASSERT_TRUE(applying_snapshot.has_value());
  EXPECT_EQ(applying_snapshot->state, RuntimeSettingsState::kApplying);
  ASSERT_EQ(save_status, std::future_status::ready);
  ASSERT_EQ(discard_status, std::future_status::ready);
  ASSERT_EQ(second_apply_status, std::future_status::ready);
  ASSERT_FALSE(save_result.ok());
  ASSERT_FALSE(discard_result.ok());
  EXPECT_EQ(save_result.error().code, "E_RUNTIME_SETTINGS_BUSY");
  EXPECT_EQ(discard_result.error().code, "E_RUNTIME_SETTINGS_BUSY");
  EXPECT_FALSE(apply_result.applied);
  EXPECT_EQ(apply_result.error.code, "E_RUNTIME_SETTINGS_BUSY");
  ASSERT_TRUE(primary_apply.has_value());
  EXPECT_TRUE(primary_apply->applied);
  EXPECT_FALSE(invalid_snapshot.load());
  EXPECT_EQ(context.service().Snapshot().state, RuntimeSettingsState::kClean);
}

}  // namespace

extern "C" int __wrap_camera_firmware_settings_renameat(
    int old_directory, const char* old_name, int new_directory,
    const char* new_name) {
  const int call = store_rename_calls.fetch_add(1) + 1;
  if (fail_store_rename.load() ||
      call == fail_store_rename_on_call.load()) {
    errno = EIO;
    return -1;
  }
  return __real_camera_firmware_settings_renameat(
      old_directory, old_name, new_directory, new_name);
}

extern "C" int __wrap_camera_firmware_settings_fsync(int descriptor) {
  const int call = store_fsync_calls.fetch_add(1) + 1;
  if (call == fail_store_fsync_on_call.load()) {
    errno = EIO;
    return -1;
  }
  return __real_camera_firmware_settings_fsync(descriptor);
}

extern "C" camera_firmware::runtime::ManagedRuntimeState
__wrap_camera_firmware_managed_runtime_state(
    const camera_firmware::runtime::ManagedFirmwareRuntime* runtime)
    asm("__wrap__ZNK15camera_firmware7runtime22ManagedFirmwareRuntime5StateEv");

extern "C" camera_firmware::runtime::ManagedRuntimeState
__wrap_camera_firmware_managed_runtime_state(
    const camera_firmware::runtime::ManagedFirmwareRuntime* runtime) {
  const auto state = __real_camera_firmware_managed_runtime_state(runtime);
  managed_state_read_gate.BlockAfterRead(runtime, state);
  return state;
}
