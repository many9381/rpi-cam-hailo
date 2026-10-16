#include "camera_firmware/runtime/ManagedFirmwareRuntime.hpp"

#include <atomic>
#include <chrono>
#include <deque>
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

#include <gtest/gtest.h>

namespace camera_firmware::runtime {
namespace {

using namespace std::chrono_literals;

class EventLog {
 public:
  void Record(std::string event) {
    std::lock_guard lock(mutex_);
    events_.push_back(std::move(event));
  }

  [[nodiscard]] std::vector<std::string> Snapshot() const {
    std::lock_guard lock(mutex_);
    return events_;
  }

 private:
  mutable std::mutex mutex_;
  std::vector<std::string> events_;
};

enum class StartFailure {
  kNone,
  kRtsp,
  kAi,
  kCamera,
  kLive,
};

struct RuntimeProbe {
  RuntimeProbe(std::string runtime_name, std::shared_ptr<EventLog> event_log)
      : name(std::move(runtime_name)), events(std::move(event_log)) {}

  std::string name;
  std::shared_ptr<EventLog> events;
  StartFailure failure{StartFailure::kNone};
  unsigned int failure_attempt{1U};
  std::atomic<unsigned int> rtsp_starts{0U};
  std::atomic<unsigned int> ai_starts{0U};
  std::atomic<unsigned int> camera_starts{0U};
  std::atomic<unsigned int> live_starts{0U};
  std::atomic<unsigned int> rtsp_stops{0U};
  std::atomic<unsigned int> ai_stops{0U};
  std::atomic<unsigned int> camera_stops{0U};
  std::atomic<unsigned int> live_stops{0U};
  std::atomic<unsigned int> provider_calls{0U};
};

common::Result<void> StartComponent(const std::shared_ptr<RuntimeProbe>& probe,
                                    std::string_view component,
                                    StartFailure component_failure,
                                    std::atomic<unsigned int>& attempts) {
  const unsigned int attempt = attempts.fetch_add(1U) + 1U;
  probe->events->Record(probe->name + "." + std::string(component) + ".start");
  if (probe->failure == component_failure &&
      attempt == probe->failure_attempt) {
    return common::Result<void>::Err(
        {"E_" + probe->name + "_" + std::string(component),
         "injected " + std::string(component) + " start failure"});
  }
  return common::Result<void>::Ok();
}

FirmwareRuntimeDependencies DependenciesFor(
    const std::shared_ptr<RuntimeProbe>& probe) {
  FirmwareRuntimeDependencies dependencies;
  dependencies.start_rtsp = [probe] {
    return StartComponent(probe, "rtsp", StartFailure::kRtsp,
                          probe->rtsp_starts);
  };
  dependencies.start_ai = [probe] {
    return StartComponent(probe, "ai", StartFailure::kAi, probe->ai_starts);
  };
  dependencies.start_camera = [probe] {
    return StartComponent(probe, "camera", StartFailure::kCamera,
                          probe->camera_starts);
  };
  dependencies.start_live = [probe] {
    return StartComponent(probe, "live", StartFailure::kLive,
                          probe->live_starts);
  };
  dependencies.stop_live = [probe] {
    probe->live_stops.fetch_add(1U);
    probe->events->Record(probe->name + ".live.stop");
  };
  dependencies.stop_camera = [probe] {
    probe->camera_stops.fetch_add(1U);
    probe->events->Record(probe->name + ".camera.stop");
  };
  dependencies.stop_ai = [probe] {
    probe->ai_stops.fetch_add(1U);
    probe->events->Record(probe->name + ".ai.stop");
  };
  dependencies.stop_rtsp = [probe] {
    probe->rtsp_stops.fetch_add(1U);
    probe->events->Record(probe->name + ".rtsp.stop");
  };
  dependencies.camera_statuses = [probe] {
    probe->provider_calls.fetch_add(1U);
    return std::vector<media::CameraPipelineStatus>{
        {probe->name, "running", true}};
  };
  dependencies.ai_status = [probe] {
    probe->provider_calls.fetch_add(1U);
    ai::AiRuntimeStatus status;
    status.enabled = true;
    status.state = probe->name;
    return status;
  };
  dependencies.ai_runner_statuses = [probe] {
    probe->provider_calls.fetch_add(1U);
    ai::AiModelRunnerStatus status;
    status.model_id = probe->name;
    return std::vector<ai::AiModelRunnerStatus>{std::move(status)};
  };
  dependencies.restart_ai = [probe] {
    probe->provider_calls.fetch_add(1U);
    return common::Result<void>::Ok();
  };
  dependencies.snapshot = [probe](std::string_view) {
    probe->provider_calls.fetch_add(1U);
    return std::optional<camera_firmware::media::JpegBytes>{
        std::string(1U, static_cast<char>(probe->name.size()))};
  };
  dependencies.live_status = [probe] {
    probe->provider_calls.fetch_add(1U);
    media::FragmentedMp4HubStatus status;
    status.state = probe->name;
    return status;
  };
  dependencies.open_live_stream = [probe](std::string_view) {
    probe->provider_calls.fetch_add(1U);
    return common::Result<media::FragmentRing::Reader>::Err(
        {"E_" + probe->name + "_LIVE", "forwarded live result"});
  };
  dependencies.detection_snapshot = [probe] {
    probe->provider_calls.fetch_add(1U);
    ai::DetectionEvent event;
    event.camera_id = probe->name;
    return std::vector<ai::DetectionEvent>{std::move(event)};
  };
  auto detection_bus = std::make_shared<ai::DetectionBus>();
  dependencies.subscribe_detections =
      [probe, detection_bus](ai::DetectionBus::Handler handler) {
        probe->provider_calls.fetch_add(1U);
        return detection_bus->Subscribe(std::move(handler));
      };
  dependencies.per_media_key_zeroize_count = [probe] {
    probe->provider_calls.fetch_add(1U);
    return static_cast<std::uint64_t>(probe->name.size());
  };
  return dependencies;
}

std::shared_ptr<FirmwareRuntime> MakeRuntime(
    const config::AppConfig& config,
    const std::shared_ptr<RuntimeProbe>& probe) {
  return std::make_shared<FirmwareRuntime>(config, DependenciesFor(probe));
}

// Use real lifecycle orchestration, replacing only the camera/device
// dependencies.
TEST(ManagedCameraRecoveryTest,
     StopsStalledGraphRetriesThreeTimesThenAllowsManualStart) {
  auto events = std::make_shared<EventLog>();
  auto probe = std::make_shared<RuntimeProbe>("camera", events);
  auto now = std::chrono::steady_clock::time_point{};
  auto dependencies = DependenciesFor(probe);
  dependencies.camera_statuses = [] {
    media::CameraPipelineStatus status;
    status.state = "error";
    status.capture_error = "E_CAMERA_NO_FRAMES";
    return std::vector{status};
  };
  config::AppConfig config;
  ManagedFirmwareRuntime managed(
      config,
      [dependencies](const auto& cfg) {
        return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
            std::make_shared<FirmwareRuntime>(cfg, dependencies));
      },
      [&] { return now; });
  ASSERT_TRUE(managed.Start().ok());
  // Reading status before the supervisor runs must not claim retries exhausted.
  EXPECT_EQ(managed.CameraStatuses()[0].state, "recovering");
  for (unsigned attempt = 0; attempt != 3; ++attempt) {
    managed.PollCameraHealth();
    EXPECT_EQ(managed.State(), ManagedRuntimeState::kFailed);
    EXPECT_EQ(managed.CameraStatuses()[0].state, "recovering");
    now += 4999ms;
    managed.PollCameraHealth();
    EXPECT_EQ(probe->camera_starts, attempt + 1);
    now += 1ms;
    managed.PollCameraHealth();
    EXPECT_EQ(probe->camera_starts, attempt + 2);
    EXPECT_EQ(managed.CameraStatuses()[0].state, "recovering");
  }
  managed.PollCameraHealth();
  now += 1h;
  managed.PollCameraHealth();
  EXPECT_EQ(probe->camera_starts, 4U);
  const auto status = managed.CameraStatuses()[0];
  EXPECT_EQ(status.state, "error");
  EXPECT_EQ(status.capture_error, "E_CAMERA_NO_FRAMES");
  EXPECT_EQ(status.recovery_attempts, 3U);
  EXPECT_FALSE(status.snapshot_available);
  ASSERT_TRUE(managed.Start().ok());
  EXPECT_EQ(probe->camera_starts, 5U);
  EXPECT_EQ(managed.CameraStatuses()[0].recovery_attempts, 0U);
}

TEST(ManagedCameraRecoveryTest, ExplicitStopCancelsPendingRetry) {
  auto probe =
      std::make_shared<RuntimeProbe>("camera", std::make_shared<EventLog>());
  auto now = std::chrono::steady_clock::time_point{};
  auto dependencies = DependenciesFor(probe);
  dependencies.camera_statuses = [] {
    media::CameraPipelineStatus status;
    status.state = "error";
    status.capture_error = "E_CAMERA_CAPTURE_STALLED";
    return std::vector{status};
  };
  ManagedFirmwareRuntime managed(
      {},
      [dependencies](const auto& cfg) {
        return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
            std::make_shared<FirmwareRuntime>(cfg, dependencies));
      },
      [&] { return now; });
  ASSERT_TRUE(managed.Start().ok());
  managed.PollCameraHealth();
  managed.Stop();
  now += 1h;
  managed.PollCameraHealth();
  EXPECT_EQ(probe->camera_starts, 1U);
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kStopped);
  EXPECT_EQ(managed.CameraStatuses()[0].state, "stopped");
}

TEST(ManagedCameraRecoveryTest,
     FailedRestartConsumesBudgetAndHealthyCaptureRearmsIt) {
  auto probe =
      std::make_shared<RuntimeProbe>("camera", std::make_shared<EventLog>());
  auto now = std::chrono::steady_clock::time_point{};
  bool stalled = true;
  auto dependencies = DependenciesFor(probe);
  dependencies.camera_statuses = [&] {
    media::CameraPipelineStatus status;
    status.state = stalled ? "error" : "running";
    status.capture_error = stalled ? "E_CAMERA_CAPTURE_STALLED" : "";
    return std::vector{status};
  };
  ManagedFirmwareRuntime managed(
      {},
      [dependencies](const auto& cfg) {
        return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
            std::make_shared<FirmwareRuntime>(cfg, dependencies));
      },
      [&] { return now; });
  ASSERT_TRUE(managed.Start().ok());
  probe->failure = StartFailure::kCamera;
  probe->failure_attempt = 2;
  managed.PollCameraHealth();
  now += 5s;
  managed.PollCameraHealth();
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kFailed);
  EXPECT_EQ(managed.CameraStatuses()[0].recovery_attempts, 1U);
  now += 5s;
  managed.PollCameraHealth();
  stalled = false;
  managed.PollCameraHealth();
  now += 59s;
  managed.PollCameraHealth();
  EXPECT_EQ(managed.CameraStatuses()[0].recovery_attempts, 2U);
  now += 1s;
  managed.PollCameraHealth();
  EXPECT_EQ(managed.CameraStatuses()[0].recovery_attempts, 0U);
  stalled = true;
  managed.PollCameraHealth();
  now += 5s;
  managed.PollCameraHealth();
  EXPECT_EQ(probe->camera_starts, 4U);
  EXPECT_EQ(managed.CameraStatuses()[0].recovery_attempts, 1U);
}

TEST(ManagedCameraRecoveryTest,
     ApplyingConfigurationCancelsOldRetryAndKeepsCandidate) {
  auto old_probe =
      std::make_shared<RuntimeProbe>("old", std::make_shared<EventLog>());
  auto new_probe =
      std::make_shared<RuntimeProbe>("new", std::make_shared<EventLog>());
  auto now = std::chrono::steady_clock::time_point{};
  auto old_dependencies = DependenciesFor(old_probe);
  old_dependencies.camera_statuses = [] {
    media::CameraPipelineStatus status;
    status.state = "error";
    status.capture_error = "E_CAMERA_NO_FRAMES";
    return std::vector{status};
  };
  unsigned created = 0;
  ManagedFirmwareRuntime managed(
      {},
      [&](const auto& cfg) {
        return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
            std::make_shared<FirmwareRuntime>(
                cfg, ++created == 1 ? old_dependencies
                                    : DependenciesFor(new_probe)));
      },
      [&] { return now; });
  ASSERT_TRUE(managed.Start().ok());
  managed.PollCameraHealth();
  config::AppConfig candidate;
  candidate.secure_rtsp.enabled = false;
  candidate.security.enabled = false;
  const auto replacement =
      managed.Replace(candidate, [] { return common::Result<void>::Ok(); });
  ASSERT_EQ(replacement.outcome, RuntimeReplacementResult::Outcome::kApplied);
  now += 1h;
  managed.PollCameraHealth();
  EXPECT_EQ(old_probe->camera_starts, 1U);
  EXPECT_EQ(new_probe->camera_starts, 1U);
  EXPECT_EQ(managed.CameraStatuses()[0].id, "new");
  EXPECT_EQ(managed.CameraStatuses()[0].recovery_attempts, 0U);
}

class FactorySequence {
 public:
  using Action = std::function<common::Result<std::shared_ptr<FirmwareRuntime>>(
      const config::AppConfig&)>;

  void Push(Action action) { actions_.push_back(std::move(action)); }

  common::Result<std::shared_ptr<FirmwareRuntime>> Next(
      const config::AppConfig& config) {
    calls.fetch_add(1U);
    if (actions_.empty()) {
      return common::Result<std::shared_ptr<FirmwareRuntime>>::Err(
          {"E_TEST_FACTORY_EMPTY", "no queued runtime"});
    }
    auto action = std::move(actions_.front());
    actions_.pop_front();
    return action(config);
  }

  std::atomic<unsigned int> calls{0U};

 private:
  std::deque<Action> actions_;
};

FirmwareRuntimeFactory FactoryFrom(
    const std::shared_ptr<FactorySequence>& sequence) {
  return [sequence](const config::AppConfig& config) {
    return sequence->Next(config);
  };
}

config::AppConfig ConfigNamed(std::string name) {
  config::AppConfig config;
  config.camera.id = std::move(name);
  config.secure_rtsp.enabled = false;
  config.security.enabled = false;
  return config;
}

template <typename Predicate>
bool WaitUntil(Predicate predicate) {
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::sleep_for(1ms);
  }
  return predicate();
}

TEST(ManagedFirmwareRuntimeTest, InitialStartAndStopAreIdempotentAndReusable) {
  const auto config = ConfigNamed("old");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto old_runtime = MakeRuntime(config, old_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  ManagedFirmwareRuntime managed(config, FactoryFrom(sequence));

  ASSERT_TRUE(managed.Start().ok());
  ASSERT_TRUE(managed.Start().ok());
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kRunning);
  EXPECT_EQ(sequence->calls.load(), 1U);
  EXPECT_EQ(old_probe->rtsp_starts.load(), 1U);

  managed.Stop();
  managed.Stop();
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kStopped);
  EXPECT_EQ(old_probe->rtsp_stops.load(), 1U);

  ASSERT_TRUE(managed.Start().ok());
  EXPECT_EQ(sequence->calls.load(), 1U);
  EXPECT_EQ(old_probe->rtsp_starts.load(), 2U);
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest, InitialStartSafelyRetriesFactoryFailures) {
  const auto config = ConfigNamed("old");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto old_runtime = MakeRuntime(config, old_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([](const config::AppConfig&)
                     -> common::Result<std::shared_ptr<FirmwareRuntime>> {
    throw std::runtime_error("injected factory exception");
  });
  sequence->Push([](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Err(
        {"E_FACTORY_INJECTED", "injected factory error"});
  });
  sequence->Push([](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(nullptr);
  });
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  ManagedFirmwareRuntime managed(config, FactoryFrom(sequence));

  auto started = managed.Start();
  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_RUNTIME_FACTORY");
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kFailed);

  started = managed.Start();
  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_FACTORY_INJECTED");

  started = managed.Start();
  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_RUNTIME_FACTORY");

  ASSERT_TRUE(managed.Start().ok());
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kRunning);
  EXPECT_EQ(sequence->calls.load(), 4U);
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest, RejectsMissingFactoryWithoutThrowing) {
  ManagedFirmwareRuntime managed(ConfigNamed("old"), {});

  const auto started = managed.Start();

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_RUNTIME_FACTORY");
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kFailed);
  managed.Stop();
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kStopped);
}

TEST(ManagedFirmwareRuntimeTest,
     ReplaceRejectsNeverStartedAndStoppedStatesWithoutSideEffects) {
  const auto config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto old_runtime = MakeRuntime(config, old_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  ManagedFirmwareRuntime managed(config, FactoryFrom(sequence));
  std::atomic<unsigned int> promotions{0U};
  const auto promote = [&] {
    promotions.fetch_add(1U);
    return common::Result<void>::Ok();
  };

  const auto never_started = managed.Replace(candidate_config, promote);

  EXPECT_EQ(never_started.outcome,
            RuntimeReplacementResult::Outcome::kCandidateFailed);
  EXPECT_FALSE(never_started.restored);
  EXPECT_EQ(never_started.error.code, "E_RUNTIME_NOT_RUNNING");
  EXPECT_EQ(sequence->calls.load(), 0U);
  EXPECT_EQ(promotions.load(), 0U);

  ASSERT_TRUE(managed.Start().ok());
  managed.Stop();
  const auto stopped = managed.Replace(candidate_config, promote);

  EXPECT_EQ(stopped.outcome,
            RuntimeReplacementResult::Outcome::kCandidateFailed);
  EXPECT_FALSE(stopped.restored);
  EXPECT_EQ(stopped.error.code, "E_RUNTIME_NOT_RUNNING");
  EXPECT_EQ(sequence->calls.load(), 1U);
  EXPECT_EQ(promotions.load(), 0U);
}

TEST(ManagedFirmwareRuntimeTest,
     RejectsSemanticallyInvalidCandidateBeforeDisruptingRunningRuntime) {
  const auto old_config = ConfigNamed("old");
  auto invalid_config = ConfigNamed("candidate");
  invalid_config.http.live.fragment_duration_ms = 1000U;
  invalid_config.http.live.stale_timeout_ms = 1500U;
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto old_runtime = MakeRuntime(old_config, old_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());
  std::atomic<unsigned int> promotions{0U};

  const auto replaced = managed.Replace(invalid_config, [&] {
    promotions.fetch_add(1U);
    return common::Result<void>::Ok();
  });

  EXPECT_EQ(replaced.outcome,
            RuntimeReplacementResult::Outcome::kCandidateFailed);
  EXPECT_FALSE(replaced.restored);
  EXPECT_EQ(replaced.error.code, "E_CONFIG_HTTP_LIVE");
  EXPECT_EQ(sequence->calls.load(), 1U);
  EXPECT_EQ(promotions.load(), 0U);
  EXPECT_EQ(old_probe->rtsp_starts.load(), 1U);
  EXPECT_EQ(old_probe->rtsp_stops.load(), 0U);
  EXPECT_EQ(old_runtime->State(), FirmwareRuntimeState::kRunning);
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kRunning);
  EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
  EXPECT_EQ(managed.CameraStatuses().front().id, "old");
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest,
     RejectsMissingDurablePromotionBeforeDisruptingRunningRuntime) {
  const auto old_config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto old_runtime = MakeRuntime(old_config, old_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());

  const auto replaced = managed.Replace(candidate_config, {});

  EXPECT_EQ(replaced.outcome, RuntimeReplacementResult::Outcome::kCommitFailed);
  EXPECT_FALSE(replaced.restored);
  EXPECT_EQ(replaced.error.code, "E_RUNTIME_PROMOTION");
  EXPECT_EQ(sequence->calls.load(), 1U);
  EXPECT_EQ(old_probe->rtsp_starts.load(), 1U);
  EXPECT_EQ(old_probe->rtsp_stops.load(), 0U);
  EXPECT_EQ(old_runtime->State(), FirmwareRuntimeState::kRunning);
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kRunning);
  EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
  EXPECT_EQ(managed.CameraStatuses().front().id, "old");
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest,
     RejectsFactoryAliasWithoutPromotingMismatchedConfiguration) {
  const auto old_config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto old_runtime = MakeRuntime(old_config, old_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());
  std::atomic<unsigned int> promotions{0U};

  const auto replaced = managed.Replace(candidate_config, [&] {
    promotions.fetch_add(1U);
    return common::Result<void>::Ok();
  });

  EXPECT_EQ(replaced.outcome,
            RuntimeReplacementResult::Outcome::kCandidateFailed);
  EXPECT_TRUE(replaced.restored);
  EXPECT_EQ(replaced.error.code, "E_RUNTIME_FACTORY");
  EXPECT_EQ(sequence->calls.load(), 2U);
  EXPECT_EQ(promotions.load(), 0U);
  EXPECT_EQ(old_probe->rtsp_starts.load(), 2U);
  EXPECT_EQ(old_probe->rtsp_stops.load(), 1U);
  EXPECT_EQ(old_runtime->State(), FirmwareRuntimeState::kRunning);
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kRunning);
  EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
  EXPECT_EQ(managed.CameraStatuses().front().id, "old");
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest,
     SuccessfulReplacePromotesBeforePublishingCandidate) {
  const auto old_config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto candidate_probe =
      std::make_shared<RuntimeProbe>("candidate", events);
  const auto old_runtime = MakeRuntime(old_config, old_probe);
  const auto candidate_runtime = MakeRuntime(candidate_config, candidate_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime, events](const config::AppConfig&) {
    events->Record("old.factory");
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  sequence->Push([candidate_runtime, events](const config::AppConfig&) {
    events->Record("candidate.factory");
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        candidate_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());

  const auto replaced = managed.Replace(candidate_config, [&] {
    EXPECT_EQ(managed.State(), ManagedRuntimeState::kApplying);
    EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
    const auto statuses = managed.CameraStatuses();
    EXPECT_EQ(statuses.front().id, "old");
    EXPECT_EQ(statuses.front().state, "stopped");
    EXPECT_EQ(candidate_probe->provider_calls.load(), 0U);
    events->Record("durable.promote");
    return common::Result<void>::Ok();
  });

  EXPECT_EQ(replaced.outcome, RuntimeReplacementResult::Outcome::kApplied);
  EXPECT_FALSE(replaced.restored);
  EXPECT_TRUE(replaced.error.code.empty());
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kRunning);
  EXPECT_EQ(managed.ActiveConfig().camera.id, "candidate");
  EXPECT_EQ(managed.CameraStatuses().front().id, "candidate");
  EXPECT_EQ(old_runtime->State(), FirmwareRuntimeState::kStopped);
  EXPECT_EQ(candidate_runtime->State(), FirmwareRuntimeState::kRunning);
  EXPECT_EQ(
      events->Snapshot(),
      (std::vector<std::string>{
          "old.factory", "old.rtsp.start", "old.ai.start", "old.camera.start",
          "old.live.start", "old.live.stop", "old.camera.stop", "old.ai.stop",
          "old.rtsp.stop", "candidate.factory", "candidate.rtsp.start",
          "candidate.ai.start", "candidate.camera.start",
          "candidate.live.start", "durable.promote"}));
  managed.Stop();
}

struct CandidateFailureCase {
  const char* name;
  std::optional<StartFailure> failure;
};

class ManagedFirmwareRuntimeCandidateFailureTest
    : public ::testing::TestWithParam<CandidateFailureCase> {};

TEST_P(ManagedFirmwareRuntimeCandidateFailureTest,
       RestartsPreviousRuntimeAndDoesNotPromote) {
  const auto test_case = GetParam();
  const auto old_config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto old_runtime = MakeRuntime(old_config, old_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });

  std::shared_ptr<RuntimeProbe> candidate_probe;
  std::shared_ptr<FirmwareRuntime> candidate_runtime;
  if (!test_case.failure.has_value()) {
    sequence->Push([](const config::AppConfig&) {
      return common::Result<std::shared_ptr<FirmwareRuntime>>::Err(
          {"E_CANDIDATE_CONSTRUCTION", "injected construction failure"});
    });
  } else {
    candidate_probe = std::make_shared<RuntimeProbe>("candidate", events);
    candidate_probe->failure = *test_case.failure;
    candidate_runtime = MakeRuntime(candidate_config, candidate_probe);
    sequence->Push([candidate_runtime](const config::AppConfig&) {
      return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
          candidate_runtime);
    });
  }
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());
  std::atomic<unsigned int> promotions{0U};

  const auto replaced = managed.Replace(candidate_config, [&] {
    promotions.fetch_add(1U);
    return common::Result<void>::Ok();
  });

  EXPECT_EQ(replaced.outcome,
            RuntimeReplacementResult::Outcome::kCandidateFailed);
  EXPECT_TRUE(replaced.restored);
  EXPECT_EQ(promotions.load(), 0U);
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kRunning);
  EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
  EXPECT_EQ(managed.CameraStatuses().front().id, "old");
  EXPECT_EQ(old_probe->rtsp_starts.load(), 2U);
  if (candidate_runtime) {
    EXPECT_EQ(candidate_runtime->State(), FirmwareRuntimeState::kStopped);
  }
  managed.Stop();
}

INSTANTIATE_TEST_SUITE_P(
    FailurePoints, ManagedFirmwareRuntimeCandidateFailureTest,
    ::testing::Values(CandidateFailureCase{"Construction", std::nullopt},
                      CandidateFailureCase{"Rtsp", StartFailure::kRtsp},
                      CandidateFailureCase{"Ai", StartFailure::kAi},
                      CandidateFailureCase{"Camera", StartFailure::kCamera},
                      CandidateFailureCase{"FragmentedMp4",
                                           StartFailure::kLive}),
    [](const ::testing::TestParamInfo<CandidateFailureCase>& info) {
      return info.param.name;
    });

class ManagedFirmwareRuntimeErrorSnapshotTest
    : public ::testing::TestWithParam<bool> {};

TEST_P(ManagedFirmwareRuntimeErrorSnapshotTest,
       PreservesFailureWhenRecoveryChangesStaticError) {
  const bool fail_during_start = GetParam();
  // Static lifetime does not imply an immutable diagnostic. Recovery may use
  // the same callback-owned error storage as the failed operation.
  static common::Error shared_error;
  shared_error = {"E_ORIGINAL", "original operation failure"};
  const auto old_config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  auto old_dependencies = DependenciesFor(old_probe);
  old_dependencies.start_rtsp = [old_probe] {
    auto result = StartComponent(old_probe, "rtsp", StartFailure::kRtsp,
                                 old_probe->rtsp_starts);
    if (old_probe->rtsp_starts.load() > 1U) {
      shared_error = {"E_RECOVERY", "diagnostic replaced during recovery"};
    }
    return result;
  };
  const auto old_runtime = std::make_shared<FirmwareRuntime>(
      old_config, std::move(old_dependencies));
  const auto candidate_probe =
      std::make_shared<RuntimeProbe>("candidate", events);
  auto candidate_dependencies = DependenciesFor(candidate_probe);
  if (fail_during_start) {
    candidate_dependencies.start_rtsp = [] {
      return common::Result<void>::ErrFromStaticLifetime(shared_error);
    };
  }
  const auto candidate_runtime = std::make_shared<FirmwareRuntime>(
      candidate_config, std::move(candidate_dependencies));
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  sequence->Push([candidate_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        candidate_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());

  const auto replaced = managed.Replace(candidate_config, [] {
    return common::Result<void>::ErrFromStaticLifetime(shared_error);
  });

  EXPECT_EQ(replaced.outcome,
            fail_during_start
                ? RuntimeReplacementResult::Outcome::kCandidateFailed
                : RuntimeReplacementResult::Outcome::kCommitFailed);
  EXPECT_TRUE(replaced.restored);
  EXPECT_EQ(replaced.error.code, "E_ORIGINAL");
  EXPECT_EQ(replaced.error.message, "original operation failure");
  EXPECT_EQ(old_probe->rtsp_starts.load(), 2U);
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kRunning);
  EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
  EXPECT_EQ(candidate_runtime->State(), FirmwareRuntimeState::kStopped);
  managed.Stop();
}

INSTANTIATE_TEST_SUITE_P(FailurePoints, ManagedFirmwareRuntimeErrorSnapshotTest,
                         ::testing::Values(true, false),
                         [](const ::testing::TestParamInfo<bool>& info) {
                           return info.param ? "CandidateStart" : "Promotion";
                         });

TEST(ManagedFirmwareRuntimeTest,
     PromotionFailureStopsCandidateAndRestartsPreviousRuntime) {
  const auto old_config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto candidate_probe =
      std::make_shared<RuntimeProbe>("candidate", events);
  const auto old_runtime = MakeRuntime(old_config, old_probe);
  const auto candidate_runtime = MakeRuntime(candidate_config, candidate_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  sequence->Push([candidate_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        candidate_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());

  const auto replaced = managed.Replace(candidate_config, [] {
    return common::Result<void>::Err(
        {"E_PROMOTE_INJECTED", "injected durable promotion failure"});
  });

  EXPECT_EQ(replaced.outcome, RuntimeReplacementResult::Outcome::kCommitFailed);
  EXPECT_TRUE(replaced.restored);
  EXPECT_EQ(replaced.error.code, "E_PROMOTE_INJECTED");
  EXPECT_EQ(candidate_runtime->State(), FirmwareRuntimeState::kStopped);
  EXPECT_EQ(old_runtime->State(), FirmwareRuntimeState::kRunning);
  EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
  EXPECT_EQ(candidate_probe->rtsp_stops.load(), 1U);
  EXPECT_EQ(old_probe->rtsp_starts.load(), 2U);
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest,
     PromotionExceptionIsCaughtAndPreviousRuntimeIsRestored) {
  const auto old_config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto candidate_probe =
      std::make_shared<RuntimeProbe>("candidate", events);
  const auto old_runtime = MakeRuntime(old_config, old_probe);
  const auto candidate_runtime = MakeRuntime(candidate_config, candidate_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  sequence->Push([candidate_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        candidate_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());

  const auto replaced =
      managed.Replace(candidate_config, []() -> common::Result<void> {
        throw std::runtime_error("injected promotion exception");
      });

  EXPECT_EQ(replaced.outcome, RuntimeReplacementResult::Outcome::kCommitFailed);
  EXPECT_TRUE(replaced.restored);
  EXPECT_EQ(replaced.error.code, "E_RUNTIME_PROMOTION");
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kRunning);
  EXPECT_EQ(candidate_runtime->State(), FirmwareRuntimeState::kStopped);
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest, ReportsFailedPreviousRuntimeRestoration) {
  const auto old_config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  old_probe->failure = StartFailure::kRtsp;
  old_probe->failure_attempt = 2U;
  const auto candidate_probe =
      std::make_shared<RuntimeProbe>("candidate", events);
  const auto old_runtime = MakeRuntime(old_config, old_probe);
  const auto candidate_runtime = MakeRuntime(candidate_config, candidate_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  sequence->Push([candidate_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        candidate_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());

  const auto replaced = managed.Replace(candidate_config, [] {
    return common::Result<void>::Err(
        {"E_PROMOTE_INJECTED", "injected durable promotion failure"});
  });

  EXPECT_EQ(replaced.outcome, RuntimeReplacementResult::Outcome::kCommitFailed);
  EXPECT_FALSE(replaced.restored);
  EXPECT_EQ(replaced.error.code, "E_PROMOTE_INJECTED");
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kFailed);
  EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
  EXPECT_EQ(old_runtime->State(), FirmwareRuntimeState::kFailed);
  EXPECT_EQ(candidate_runtime->State(), FirmwareRuntimeState::kStopped);
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest,
     ReplaceRecoversFailedRetainedRuntimeWithoutPublishingBeforePromotion) {
  const auto old_config = ConfigNamed("old");
  const auto failed_candidate_config = ConfigNamed("failed-candidate");
  const auto recovery_config = ConfigNamed("recovery");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  old_probe->failure = StartFailure::kRtsp;
  old_probe->failure_attempt = 2U;
  const auto failed_candidate_probe =
      std::make_shared<RuntimeProbe>("failed-candidate", events);
  const auto recovery_probe =
      std::make_shared<RuntimeProbe>("recovery", events);
  const auto old_runtime = MakeRuntime(old_config, old_probe);
  const auto failed_candidate_runtime =
      MakeRuntime(failed_candidate_config, failed_candidate_probe);
  const auto recovery_runtime = MakeRuntime(recovery_config, recovery_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  sequence->Push([failed_candidate_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        failed_candidate_runtime);
  });
  sequence->Push([recovery_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        recovery_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());
  const auto failed = managed.Replace(failed_candidate_config, [] {
    return common::Result<void>::Err(
        {"E_PROMOTE_INJECTED", "injected durable promotion failure"});
  });
  ASSERT_EQ(failed.outcome, RuntimeReplacementResult::Outcome::kCommitFailed);
  ASSERT_FALSE(failed.restored);
  ASSERT_EQ(managed.State(), ManagedRuntimeState::kFailed);

  std::atomic<unsigned int> promotions{0U};
  const auto recovered = managed.Replace(recovery_config, [&] {
    promotions.fetch_add(1U);
    EXPECT_EQ(managed.State(), ManagedRuntimeState::kApplying);
    EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
    EXPECT_EQ(managed.CameraStatuses().front().id, "old");
    EXPECT_EQ(recovery_probe->provider_calls.load(), 0U);
    return common::Result<void>::Ok();
  });

  EXPECT_EQ(recovered.outcome, RuntimeReplacementResult::Outcome::kApplied);
  EXPECT_FALSE(recovered.restored);
  EXPECT_TRUE(recovered.error.code.empty());
  EXPECT_EQ(promotions.load(), 1U);
  EXPECT_EQ(sequence->calls.load(), 3U);
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kRunning);
  EXPECT_EQ(managed.ActiveConfig().camera.id, "recovery");
  EXPECT_EQ(managed.CameraStatuses().front().id, "recovery");
  EXPECT_EQ(recovery_runtime->State(), FirmwareRuntimeState::kRunning);
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest,
     ReplaceRecoversFailedInitialStartWithoutPublishedRuntime) {
  const auto old_config = ConfigNamed("old");
  const auto recovery_config = ConfigNamed("recovery");
  const auto events = std::make_shared<EventLog>();
  const auto recovery_probe =
      std::make_shared<RuntimeProbe>("recovery", events);
  const auto recovery_runtime = MakeRuntime(recovery_config, recovery_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Err(
        {"E_INITIAL_FACTORY", "injected initial factory failure"});
  });
  sequence->Push([recovery_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        recovery_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_FALSE(managed.Start().ok());
  ASSERT_EQ(managed.State(), ManagedRuntimeState::kFailed);

  std::atomic<unsigned int> promotions{0U};
  const auto recovered = managed.Replace(recovery_config, [&] {
    promotions.fetch_add(1U);
    EXPECT_EQ(managed.State(), ManagedRuntimeState::kApplying);
    EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
    const auto before_publish = managed.CameraStatuses();
    EXPECT_EQ(before_publish.front().id, "old");
    EXPECT_EQ(before_publish.front().state, "stopped");
    EXPECT_EQ(recovery_probe->provider_calls.load(), 0U);
    return common::Result<void>::Ok();
  });

  EXPECT_EQ(recovered.outcome, RuntimeReplacementResult::Outcome::kApplied);
  EXPECT_FALSE(recovered.restored);
  EXPECT_EQ(promotions.load(), 1U);
  EXPECT_EQ(sequence->calls.load(), 2U);
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kRunning);
  EXPECT_EQ(managed.ActiveConfig().camera.id, "recovery");
  EXPECT_EQ(managed.CameraStatuses().front().id, "recovery");
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest,
     FailedRecoveryWithoutPreviousRuntimeRemainsFailedAndDoesNotPromote) {
  const auto old_config = ConfigNamed("old");
  const auto recovery_config = ConfigNamed("recovery");
  const auto events = std::make_shared<EventLog>();
  const auto recovery_probe =
      std::make_shared<RuntimeProbe>("recovery", events);
  recovery_probe->failure = StartFailure::kRtsp;
  const auto recovery_runtime = MakeRuntime(recovery_config, recovery_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Err(
        {"E_INITIAL_FACTORY", "injected initial factory failure"});
  });
  sequence->Push([recovery_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        recovery_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_FALSE(managed.Start().ok());

  std::atomic<unsigned int> promotions{0U};
  const auto recovered = managed.Replace(recovery_config, [&] {
    promotions.fetch_add(1U);
    return common::Result<void>::Ok();
  });

  EXPECT_EQ(recovered.outcome,
            RuntimeReplacementResult::Outcome::kCandidateFailed);
  EXPECT_FALSE(recovered.restored);
  EXPECT_EQ(recovered.error.code, "E_recovery_rtsp");
  EXPECT_EQ(promotions.load(), 0U);
  EXPECT_EQ(sequence->calls.load(), 2U);
  EXPECT_EQ(managed.State(), ManagedRuntimeState::kFailed);
  EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
  EXPECT_EQ(recovery_runtime->State(), FirmwareRuntimeState::kStopped);
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest, AbsentRuntimeProvidersUseSafeFallbacks) {
  auto config = ConfigNamed("configured-camera");
  config.camera.video.width = 1280U;
  config.camera.video.height = 720U;
  config.camera.video.fps = 50U;
  config.ai.enabled = true;
  ManagedFirmwareRuntime managed(config, {});
  ASSERT_FALSE(managed.Start().ok());

  const auto cameras = managed.CameraStatuses();
  ASSERT_EQ(cameras.size(), 1U);
  EXPECT_EQ(cameras.front().id, "configured-camera");
  EXPECT_EQ(cameras.front().state, "error");
  EXPECT_EQ(cameras.front().width, 1280U);
  EXPECT_EQ(cameras.front().height, 720U);
  EXPECT_EQ(cameras.front().configured_fps, 50U);
  EXPECT_TRUE(managed.AiStatus().enabled);
  EXPECT_EQ(managed.AiStatus().state, "stopped");
  EXPECT_TRUE(managed.AiRunnerStatuses().empty());
  const auto restarted = managed.RestartAi();
  ASSERT_FALSE(restarted.ok());
  EXPECT_EQ(restarted.error().code, "E_RUNTIME_NOT_RUNNING");
  EXPECT_FALSE(managed.Snapshot("configured-camera").has_value());
  EXPECT_EQ(managed.LiveStatus().state, "stopped");
  const auto opened = managed.OpenLiveStream("configured-camera");
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_LIVE_UNAVAILABLE");
  EXPECT_TRUE(managed.DetectionSnapshot().empty());
  EXPECT_FALSE(
      managed.SubscribeDetections([](const ai::DetectionEvent&) {}).valid());
  EXPECT_EQ(managed.PerMediaKeyZeroizeCount(), 0U);
}

TEST(ManagedFirmwareRuntimeTest, RunningProvidersForwardToPublishedRuntime) {
  const auto config = ConfigNamed("forwarded");
  const auto events = std::make_shared<EventLog>();
  const auto probe = std::make_shared<RuntimeProbe>("forwarded", events);
  const auto runtime = MakeRuntime(config, probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(runtime);
  });
  ManagedFirmwareRuntime managed(config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());

  EXPECT_EQ(managed.CameraStatuses().front().id, "forwarded");
  EXPECT_EQ(managed.AiStatus().state, "forwarded");
  EXPECT_EQ(managed.AiRunnerStatuses().front().model_id, "forwarded");
  EXPECT_TRUE(managed.RestartAi().ok());
  EXPECT_EQ(static_cast<unsigned>(managed.Snapshot("forwarded")->front()), 9U);
  EXPECT_EQ(managed.LiveStatus().state, "forwarded");
  const auto opened = managed.OpenLiveStream("forwarded");
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_forwarded_LIVE");
  EXPECT_EQ(managed.DetectionSnapshot().front().camera_id, "forwarded");
  EXPECT_TRUE(
      managed.SubscribeDetections([](const ai::DetectionEvent&) {}).valid());
  EXPECT_EQ(managed.PerMediaKeyZeroizeCount(), 9U);
  EXPECT_EQ(probe->provider_calls.load(), 10U);
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest,
     ReadersCannotObserveCandidateBeforeDurablePromotionCompletes) {
  const auto old_config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto candidate_probe =
      std::make_shared<RuntimeProbe>("candidate", events);
  const auto old_runtime = MakeRuntime(old_config, old_probe);
  const auto candidate_runtime = MakeRuntime(candidate_config, candidate_probe);
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  sequence->Push([candidate_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        candidate_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());
  std::promise<void> promotion_entered;
  std::promise<void> release_promotion;
  const auto release = release_promotion.get_future().share();
  std::optional<RuntimeReplacementResult> replacement;
  std::thread replacing([&] {
    replacement = managed.Replace(candidate_config, [&] {
      promotion_entered.set_value();
      release.wait();
      return common::Result<void>::Ok();
    });
  });
  const auto promotion_status = promotion_entered.get_future().wait_for(2s);
  EXPECT_EQ(promotion_status, std::future_status::ready);
  if (promotion_status == std::future_status::ready) {
    EXPECT_EQ(managed.State(), ManagedRuntimeState::kApplying);
    EXPECT_EQ(managed.ActiveConfig().camera.id, "old");
    const auto during_apply = managed.CameraStatuses();
    EXPECT_EQ(during_apply.size(), 1U);
    if (!during_apply.empty()) {
      EXPECT_EQ(during_apply.front().id, "old");
      EXPECT_EQ(during_apply.front().state, "stopped");
    }
    EXPECT_EQ(candidate_probe->provider_calls.load(), 0U);
  }

  release_promotion.set_value();
  replacing.join();
  ASSERT_EQ(promotion_status, std::future_status::ready);
  ASSERT_TRUE(replacement.has_value());
  EXPECT_EQ(replacement->outcome, RuntimeReplacementResult::Outcome::kApplied);
  EXPECT_EQ(managed.CameraStatuses().front().id, "candidate");
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest,
     ConcurrentReaderRetainsPublishedRuntimeUntilForwardingCompletes) {
  const auto old_config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  auto old_dependencies = DependenciesFor(old_probe);
  std::promise<void> provider_entered;
  std::promise<void> release_provider;
  const auto release = release_provider.get_future().share();
  old_dependencies.camera_statuses = [&] {
    provider_entered.set_value();
    release.wait();
    return std::vector<media::CameraPipelineStatus>{{"old", "running", true}};
  };
  auto old_runtime = std::make_shared<FirmwareRuntime>(
      old_config, std::move(old_dependencies));
  const auto candidate_probe =
      std::make_shared<RuntimeProbe>("candidate", events);
  auto candidate_runtime = MakeRuntime(candidate_config, candidate_probe);
  const std::weak_ptr<FirmwareRuntime> old_weak = old_runtime;
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  sequence->Push([candidate_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        candidate_runtime);
  });
  ManagedFirmwareRuntime managed(old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed.Start().ok());
  old_runtime.reset();

  std::vector<media::CameraPipelineStatus> reader_result;
  std::thread reader([&] { reader_result = managed.CameraStatuses(); });
  const auto provider_status = provider_entered.get_future().wait_for(2s);
  EXPECT_EQ(provider_status, std::future_status::ready);
  std::optional<RuntimeReplacementResult> replacement;
  std::thread replacing([&] {
    replacement = managed.Replace(candidate_config,
                                  [] { return common::Result<void>::Ok(); });
  });
  const bool applying = WaitUntil(
      [&] { return managed.State() == ManagedRuntimeState::kApplying; });
  EXPECT_TRUE(applying);
  if (applying) {
    EXPECT_FALSE(old_weak.expired());
    EXPECT_EQ(sequence->calls.load(), 1U);
  }

  release_provider.set_value();
  reader.join();
  replacing.join();

  ASSERT_EQ(provider_status, std::future_status::ready);
  ASSERT_TRUE(applying);
  ASSERT_EQ(reader_result.size(), 1U);
  EXPECT_EQ(reader_result.front().id, "old");
  ASSERT_TRUE(replacement.has_value());
  EXPECT_EQ(replacement->outcome, RuntimeReplacementResult::Outcome::kApplied);
  EXPECT_TRUE(old_weak.expired());
  managed.Stop();
}

TEST(ManagedFirmwareRuntimeTest,
     StopWaitsForReplacementThenStopsPublishedCandidateBeforeDestruction) {
  const auto old_config = ConfigNamed("old");
  const auto candidate_config = ConfigNamed("candidate");
  const auto events = std::make_shared<EventLog>();
  const auto old_probe = std::make_shared<RuntimeProbe>("old", events);
  const auto candidate_probe =
      std::make_shared<RuntimeProbe>("candidate", events);
  const auto old_runtime = MakeRuntime(old_config, old_probe);
  auto candidate_runtime = MakeRuntime(candidate_config, candidate_probe);
  const std::weak_ptr<FirmwareRuntime> candidate_weak = candidate_runtime;
  const auto sequence = std::make_shared<FactorySequence>();
  sequence->Push([old_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(old_runtime);
  });
  sequence->Push([candidate_runtime](const config::AppConfig&) {
    return common::Result<std::shared_ptr<FirmwareRuntime>>::Ok(
        candidate_runtime);
  });
  auto managed = std::make_unique<ManagedFirmwareRuntime>(
      old_config, FactoryFrom(sequence));
  ASSERT_TRUE(managed->Start().ok());
  candidate_runtime.reset();
  std::promise<void> promotion_entered;
  std::promise<void> release_promotion;
  const auto release = release_promotion.get_future().share();
  std::optional<RuntimeReplacementResult> replacement;
  std::thread replacing([&] {
    replacement = managed->Replace(candidate_config, [&] {
      promotion_entered.set_value();
      release.wait();
      return common::Result<void>::Ok();
    });
  });
  const auto promotion_status = promotion_entered.get_future().wait_for(2s);
  EXPECT_EQ(promotion_status, std::future_status::ready);
  std::promise<void> stop_returned;
  auto stopped = stop_returned.get_future();
  std::thread stopping([&] {
    managed->Stop();
    stop_returned.set_value();
  });

  EXPECT_EQ(stopped.wait_for(50ms), std::future_status::timeout);
  EXPECT_FALSE(candidate_weak.expired());
  release_promotion.set_value();
  replacing.join();
  const auto stop_status = stopped.wait_for(2s);
  EXPECT_EQ(stop_status, std::future_status::ready);
  stopping.join();

  ASSERT_EQ(promotion_status, std::future_status::ready);
  ASSERT_TRUE(replacement.has_value());
  EXPECT_EQ(replacement->outcome, RuntimeReplacementResult::Outcome::kApplied);
  ASSERT_EQ(stop_status, std::future_status::ready);
  EXPECT_EQ(managed->State(), ManagedRuntimeState::kStopped);
  EXPECT_EQ(candidate_probe->rtsp_stops.load(), 1U);
  EXPECT_FALSE(candidate_weak.expired());
  managed.reset();
  EXPECT_TRUE(candidate_weak.expired());
}

}  // namespace
}  // namespace camera_firmware::runtime
