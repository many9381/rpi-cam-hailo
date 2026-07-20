#include "camera_firmware/security/SystemProtectionService.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace camera_firmware::security {
namespace {

constexpr auto kDefaultAutomaticInterval = std::chrono::hours{24};
constexpr std::string_view kAuditSuccess = "success";
constexpr std::string_view kAuditFailure = "failure";
constexpr std::string_view kAuditOk = "OK";
constexpr std::string_view kAuditError = "E_PROTECTION_AUDIT";
constexpr std::string_view kDeviceStateError = "E_PROTECTION_DEVICE_STATE";
constexpr std::string_view kRuntimeStartError = "E_PROTECTION_RUNTIME_START";
constexpr std::string_view kRuntimeStopError = "E_PROTECTION_RUNTIME_STOP";
constexpr std::size_t kMaximumAuditSubjectBytes = 64U;

std::int64_t EpochSeconds(std::chrono::system_clock::time_point value) {
  return std::chrono::duration_cast<std::chrono::seconds>(
             value.time_since_epoch())
      .count();
}

}  // namespace

class SystemProtectionService::Impl {
 public:
  explicit Impl(SystemProtectionDependencies dependencies)
      : dependencies_(std::move(dependencies)) {
    if (dependencies_.automatic_interval <=
        std::chrono::steady_clock::duration::zero()) {
      dependencies_.automatic_interval = kDefaultAutomaticInterval;
    }
    const auto interval_seconds = std::chrono::duration_cast<std::chrono::seconds>(
                                      dependencies_.automatic_interval)
                                      .count();
    snapshot_.next_periodic_at_seconds = WallNowSeconds() + interval_seconds;
    next_periodic_deadline_ =
        SteadyNow() + dependencies_.automatic_interval;
    worker_ = std::thread([this] { WorkerLoop(); });
    worker_thread_id_ = worker_.get_id();
    try {
      scheduler_ = std::thread([this] { SchedulerLoop(); });
      scheduler_thread_id_ = scheduler_.get_id();
    } catch (...) {
      {
        std::lock_guard lock(mutex_);
        stopping_ = true;
      }
      worker_condition_.notify_all();
      worker_.join();
      throw;
    }
  }

  ~Impl() { Stop(); }

  SystemProtectionSnapshot RunStartupChecks() noexcept {
    bool startup_registered = false;
    try {
      {
        std::lock_guard transition_lock(runtime_transition_mutex_);
        {
          std::lock_guard lock(mutex_);
          if (stopping_ || snapshot_.check_running) {
            return snapshot_;
          }
          startup_active_ = true;
          startup_thread_id_ = std::this_thread::get_id();
          startup_registered = true;
          snapshot_.state = ProtectionState::kChecking;
          snapshot_.check_running = true;
          snapshot_.transition_code.reset();
          runtime_authorized_ = false;
        }
      }
      const ProtectionActor system_actor;
      RunSuite(ProtectionSuite::kSelfTest, ProtectionTrigger::kStartup,
               system_actor);
      bool run_integrity = false;
      {
        std::lock_guard lock(mutex_);
        run_integrity = !stopping_;
      }
      if (run_integrity) {
        RunSuite(ProtectionSuite::kIntegrity, ProtectionTrigger::kStartup,
                 system_actor);
      }

      SystemProtectionSnapshot completed;
      {
        std::lock_guard lock(mutex_);
        snapshot_.check_running = false;
        if (stopping_) {
          snapshot_.state = ProtectionState::kStopping;
          runtime_authorized_ = false;
        }
        startup_active_ = false;
        startup_thread_id_ = {};
        startup_registered = false;
        completed = snapshot_;
        startup_condition_.notify_all();
      }
      return completed;
    } catch (...) {
      SystemProtectionSnapshot failed;
      {
        std::lock_guard lock(mutex_);
        snapshot_.state = stopping_ ? ProtectionState::kStopping
                                    : ProtectionState::kRestricted;
        snapshot_.check_running = false;
        runtime_authorized_ = false;
        if (!stopping_) {
          snapshot_.transition_code = "E_PROTECTION_INTERNAL";
        }
        if (startup_registered) {
          startup_active_ = false;
          startup_thread_id_ = {};
        }
        failed = snapshot_;
        startup_condition_.notify_all();
      }
      return failed;
    }
  }

  SystemProtectionSnapshot Snapshot() const {
    std::lock_guard lock(mutex_);
    return snapshot_;
  }

  bool RuntimeAllowed() const {
    std::lock_guard lock(mutex_);
    return runtime_authorized_;
  }

  bool RunRuntimeControlIfAllowed(const std::function<void()>& command) {
    if (!command) {
      return false;
    }
    std::lock_guard transition_lock(runtime_transition_mutex_);
    {
      std::lock_guard lock(mutex_);
      if (stopping_ || !runtime_authorized_) {
        return false;
      }
    }
    command();
    return true;
  }

  common::Result<SystemProtectionSnapshot> StartManualCheck(
      ProtectionSuite suite, ProtectionActor actor) {
    SystemProtectionSnapshot accepted;
    {
      std::unique_lock transition_lock(runtime_transition_mutex_,
                                       std::try_to_lock);
      if (!transition_lock.owns_lock()) {
        return common::Result<SystemProtectionSnapshot>::Err(
            {"E_PROTECTION_TRANSITION_BUSY", "runtime transition is busy"});
      }
      {
        std::lock_guard lock(mutex_);
        if (stopping_) {
          return common::Result<SystemProtectionSnapshot>::Err(
              {"E_PROTECTION_STOPPING", "protection service is stopping"});
        }
        if (snapshot_.check_running || pending_work_.has_value()) {
          return common::Result<SystemProtectionSnapshot>::Err(
              {"E_PROTECTION_CHECK_RUNNING", "protection check is running"});
        }
        pending_work_ = WorkItem{suite, ProtectionTrigger::kManual,
                                 std::move(actor), false};
        snapshot_.state = ProtectionState::kChecking;
        snapshot_.check_running = true;
        snapshot_.transition_code.reset();
        runtime_authorized_ = false;
        accepted = snapshot_;
      }
    }
    worker_condition_.notify_one();
    return common::Result<SystemProtectionSnapshot>::Ok(std::move(accepted));
  }

  void SetRuntimeCallbacks(ProtectionRuntimeCallbacks callbacks) {
    std::lock_guard lock(mutex_);
    runtime_callbacks_ = std::move(callbacks);
  }

  void Stop() noexcept {
    bool called_from_startup = false;
    bool called_from_owned_thread = false;
    {
      std::lock_guard transition_lock(runtime_transition_mutex_);
      {
        std::lock_guard lock(mutex_);
        const auto caller = std::this_thread::get_id();
        called_from_startup = startup_active_ &&
                              startup_thread_id_ == caller;
        called_from_owned_thread =
            (!worker_exited_ && worker_thread_id_ == caller) ||
            (!scheduler_exited_ && scheduler_thread_id_ == caller);
        stopping_ = true;
        pending_work_.reset();
        snapshot_.state = ProtectionState::kStopping;
        runtime_authorized_ = false;
        if (!worker_active_ && !startup_active_) {
          snapshot_.check_running = false;
        }
      }
    }
    worker_condition_.notify_all();
    scheduler_condition_.notify_all();

    if (called_from_owned_thread) {
      return;
    }
    if (!called_from_startup) {
      std::unique_lock lock(mutex_);
      startup_condition_.wait(lock, [this] { return !startup_active_; });
    }
    try {
      std::lock_guard join_lock(join_mutex_);
      if (scheduler_.joinable()) {
        scheduler_.join();
      }
      if (worker_.joinable()) {
        worker_.join();
      }
    } catch (...) {
    }
  }

 private:
  struct WorkItem {
    ProtectionSuite suite;
    ProtectionTrigger trigger;
    ProtectionActor actor;
    bool run_both_suites{false};
  };

  static std::string_view StartedEvent(ProtectionSuite suite) noexcept {
    return suite == ProtectionSuite::kSelfTest ? "self_test.started"
                                               : "integrity_check.started";
  }

  static std::string_view FinishedEvent(ProtectionSuite suite,
                                        bool passed) noexcept {
    if (suite == ProtectionSuite::kSelfTest) {
      return passed ? "self_test.succeeded" : "self_test.failed";
    }
    return passed ? "integrity_check.succeeded" : "integrity_check.failed";
  }

  static std::string_view SuiteFailureCode(ProtectionSuite suite) noexcept {
    return suite == ProtectionSuite::kSelfTest
               ? "E_PROTECTION_SELF_TEST"
               : "E_PROTECTION_INTEGRITY";
  }

  bool AppendAudit(const ProtectionActor& actor,
                   ProtectionTrigger trigger,
                   std::string_view event_type,
                   std::string_view outcome,
                   std::string_view detail_code,
                   std::int64_t duration_milliseconds = 0,
                   const std::vector<std::string>& failed_check_ids = {},
                   std::size_t failed_check_count = 0U)
      noexcept {
    try {
      const ProtectionAuditRecord record{
          std::string{event_type}, std::string{outcome},
          std::string{detail_code}, trigger, duration_milliseconds,
          failed_check_ids, failed_check_count};
      if (trigger == ProtectionTrigger::kManual) {
        if (dependencies_.append_administrator_audit_record) {
          return dependencies_.append_administrator_audit_record(actor, record)
              .ok();
        }
        return dependencies_.append_administrator_audit &&
               dependencies_.append_administrator_audit(
                   actor, event_type, outcome, detail_code)
                   .ok();
      }
      if (dependencies_.append_system_audit_record) {
        return dependencies_.append_system_audit_record(record).ok();
      }
      return dependencies_.append_system_audit &&
             dependencies_.append_system_audit(event_type, outcome, detail_code)
                 .ok();
    } catch (...) {
      return false;
    }
  }

  ProtectionSuiteSnapshot ExecuteSuite(ProtectionSuite suite,
                                        ProtectionTrigger trigger) noexcept {
    const auto started_steady = SteadyNow();
    ProtectionSuiteSnapshot result{
        .suite = suite,
        .trigger = trigger,
        .started_at_seconds = WallNowSeconds(),
    };
    try {
      if (suite == ProtectionSuite::kSelfTest &&
          dependencies_.run_self_tests) {
        auto report = dependencies_.run_self_tests();
        if (report.ok()) {
          result.passed = report.value().passed;
          result.self_test_items = std::move(report).value().items;
        }
      } else if (suite == ProtectionSuite::kIntegrity &&
                 dependencies_.run_integrity) {
        auto report = dependencies_.run_integrity();
        if (report.ok()) {
          result.passed = report.value().passed;
          result.integrity_items = std::move(report).value().items;
        }
      }
    } catch (...) {
      result.passed = false;
    }
    result.finished_at_seconds = WallNowSeconds();
    const auto finished_steady = SteadyNow();
    if (finished_steady >= started_steady) {
      result.duration_milliseconds =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              finished_steady - started_steady)
              .count();
    }
    return result;
  }

  static std::vector<std::string> FailedCheckIds(
      const ProtectionSuiteSnapshot& result) {
    std::vector<std::string> failed_ids;
    if (result.suite == ProtectionSuite::kSelfTest) {
      for (const auto& item : result.self_test_items) {
        if (!item.passed) {
          failed_ids.push_back(item.id);
        }
      }
    } else {
      for (const auto& item : result.integrity_items) {
        if (!item.passed) {
          failed_ids.push_back(item.id);
        }
      }
    }
    return failed_ids;
  }

  static std::size_t FailedCheckCount(
      const ProtectionSuiteSnapshot& result) noexcept {
    std::size_t failed_count = 0U;
    if (result.suite == ProtectionSuite::kSelfTest) {
      for (const auto& item : result.self_test_items) {
        failed_count += item.passed ? 0U : 1U;
      }
    } else {
      for (const auto& item : result.integrity_items) {
        failed_count += item.passed ? 0U : 1U;
      }
    }
    return failed_count;
  }

  void RunSuite(ProtectionSuite suite,
                ProtectionTrigger trigger,
                const ProtectionActor& actor) noexcept {
    bool audit_ok = AppendAudit(actor, trigger, StartedEvent(suite),
                                kAuditSuccess, kAuditOk);
    auto result = ExecuteSuite(suite, trigger);
    const auto duration_milliseconds = result.duration_milliseconds;
    const auto failed_check_count = FailedCheckCount(result);
    std::vector<std::string> failed_check_ids;
    bool failure_details_available = true;
    try {
      failed_check_ids = FailedCheckIds(result);
    } catch (...) {
      failure_details_available = false;
    }
    const bool finished_audit_ok = AppendAudit(
        actor, trigger, FinishedEvent(suite, result.passed),
        result.passed ? kAuditSuccess : kAuditFailure,
        result.passed ? kAuditOk : SuiteFailureCode(suite),
        duration_milliseconds, failed_check_ids, failed_check_count);
    audit_ok = failure_details_available && finished_audit_ok && audit_ok;

    bool stop_runtime = false;
    bool append_restricted = false;
    bool append_recovered = false;
    bool stopping = false;
    ProtectionRuntimeCallbacks runtime_callbacks;
    std::unique_lock transition_lock(runtime_transition_mutex_);
    {
      std::lock_guard lock(mutex_);
      if (suite == ProtectionSuite::kSelfTest) {
        snapshot_.self_test = std::move(result);
        self_test_audit_ok_ = audit_ok;
      } else {
        snapshot_.integrity = std::move(result);
        integrity_audit_ok_ = audit_ok;
      }

      if (stopping_) {
        snapshot_.state = ProtectionState::kStopping;
        runtime_authorized_ = false;
        stopping = true;
      } else {
        const bool self_test_passed =
            snapshot_.self_test.has_value() && snapshot_.self_test->passed;
        const bool integrity_passed =
            snapshot_.integrity.has_value() && snapshot_.integrity->passed;
        const bool both_passed = self_test_passed && integrity_passed;
        const bool audits_passed = self_test_audit_ok_ && integrity_audit_ok_;

        if (!audit_ok ||
            (suite == ProtectionSuite::kSelfTest && !self_test_passed) ||
            (suite == ProtectionSuite::kIntegrity && !integrity_passed)) {
          if (!audit_ok) {
            restriction_error_code_ = std::string{kAuditError};
          } else if (!restriction_error_code_.has_value()) {
            restriction_error_code_ = std::string{SuiteFailureCode(suite)};
          }
          snapshot_.state = ProtectionState::kRestricted;
          snapshot_.transition_code = restriction_error_code_;
          runtime_authorized_ = false;
          if (!restriction_latched_) {
            restriction_latched_ = true;
            stop_runtime = true;
            append_restricted = true;
            runtime_callbacks = runtime_callbacks_;
          }
        } else if (both_passed && audits_passed && !restriction_latched_) {
          snapshot_.state = ProtectionState::kOperational;
          snapshot_.transition_code.reset();
          runtime_authorized_ = true;
        } else if (both_passed && audits_passed) {
          snapshot_.state = ProtectionState::kOperational;
          snapshot_.transition_code.reset();
          runtime_authorized_ = false;
          append_recovered = true;
          runtime_callbacks = runtime_callbacks_;
        } else if (restriction_latched_) {
          snapshot_.state = ProtectionState::kRestricted;
          runtime_authorized_ = false;
          if (restriction_error_code_.has_value()) {
            snapshot_.transition_code = restriction_error_code_;
          } else {
            snapshot_.transition_code =
                self_test_passed
                    ? std::optional<std::string>{"E_PROTECTION_INTEGRITY"}
                    : std::optional<std::string>{"E_PROTECTION_SELF_TEST"};
          }
        } else {
          snapshot_.state = ProtectionState::kChecking;
          runtime_authorized_ = false;
        }
      }
    }

    if (stopping) {
      return;
    }

    bool runtime_stop_ok = true;
    if (stop_runtime && runtime_callbacks.stop) {
      try {
        runtime_callbacks.stop();
      } catch (...) {
        runtime_stop_ok = false;
      }
    }
    transition_lock.unlock();
    const bool restricted_audit_ok =
        !append_restricted ||
        AppendAudit(actor, trigger, "protection.restricted", kAuditFailure,
                    audit_ok ? SuiteFailureCode(suite) : kAuditError,
                    duration_milliseconds, failed_check_ids,
                    failed_check_count);
    if (!runtime_stop_ok || !restricted_audit_ok) {
      std::lock_guard lock(mutex_);
      if (!stopping_) {
        restriction_error_code_ =
            !restricted_audit_ok ? std::string{kAuditError}
                                 : std::string{kRuntimeStopError};
        snapshot_.transition_code = restriction_error_code_;
      }
    }

    if (!append_recovered) {
      return;
    }
    if (!AppendAudit(actor, trigger, "protection.recovered", kAuditSuccess,
                     kAuditOk, duration_milliseconds, failed_check_ids,
                     failed_check_count)) {
      std::lock_guard lock(mutex_);
      if (stopping_) {
        snapshot_.state = ProtectionState::kStopping;
        runtime_authorized_ = false;
      } else {
        snapshot_.state = ProtectionState::kRestricted;
        runtime_authorized_ = false;
        restriction_error_code_ = std::string{kAuditError};
        snapshot_.transition_code = restriction_error_code_;
      }
      return;
    }

    {
      std::lock_guard transition_lock(runtime_transition_mutex_);
      {
        std::lock_guard lock(mutex_);
        if (stopping_) {
          snapshot_.state = ProtectionState::kStopping;
          runtime_authorized_ = false;
          return;
        }
        restriction_latched_ = false;
        restriction_error_code_.reset();
        runtime_authorized_ = true;
      }

      bool device_operational = false;
      bool device_read_ok = false;
      try {
        if (dependencies_.read_device_state) {
          const auto device_state = dependencies_.read_device_state();
          device_read_ok = device_state.ok();
          device_operational =
              device_read_ok &&
              device_state.value() == DeviceState::kOperational;
        }
      } catch (...) {
        device_read_ok = false;
      }
      if (!device_read_ok) {
        std::lock_guard lock(mutex_);
        if (!stopping_) {
          snapshot_.transition_code = std::string{kDeviceStateError};
        }
        return;
      }
      if (!device_operational || !runtime_callbacks.start) {
        return;
      }

      {
        std::lock_guard lock(mutex_);
        if (stopping_) {
          return;
        }
      }
      bool runtime_start_ok = false;
      try {
        const auto started = runtime_callbacks.start();
        runtime_start_ok = started.ok();
      } catch (...) {
        runtime_start_ok = false;
      }
      if (!runtime_start_ok) {
        std::lock_guard lock(mutex_);
        snapshot_.transition_code = std::string{kRuntimeStartError};
      }
    }
  }

  void WorkerLoop() noexcept {
    for (;;) {
      std::optional<WorkItem> work;
      {
        std::unique_lock lock(mutex_);
        worker_condition_.wait(
            lock, [this] { return stopping_ || pending_work_.has_value(); });
        if (stopping_) {
          if (!startup_active_) {
            snapshot_.check_running = false;
          }
          worker_exited_ = true;
          return;
        }
        work = std::move(pending_work_);
        pending_work_.reset();
        worker_active_ = true;
      }

      RunSuite(work->suite, work->trigger, work->actor);
      bool run_second_suite = work->run_both_suites;
      if (run_second_suite) {
        std::lock_guard lock(mutex_);
        run_second_suite = !stopping_;
      }
      if (run_second_suite) {
        RunSuite(ProtectionSuite::kIntegrity, work->trigger, work->actor);
      }

      {
        std::lock_guard lock(mutex_);
        worker_active_ = false;
        snapshot_.check_running = false;
        if (stopping_) {
          snapshot_.state = ProtectionState::kStopping;
        }
      }
    }
  }

  void SchedulerLoop() noexcept {
    for (;;) {
      const auto now = SteadyNow();
      std::chrono::steady_clock::duration wait_duration{};
      std::chrono::steady_clock::time_point display_deadline;
      bool queue_periodic = false;
      bool periodic_due = false;
      {
        std::lock_guard lock(mutex_);
        if (stopping_) {
          scheduler_exited_ = true;
          return;
        }
        if (now >= next_periodic_deadline_) {
          const auto elapsed = now - next_periodic_deadline_;
          const auto skipped = elapsed / dependencies_.automatic_interval + 1;
          next_periodic_deadline_ +=
              dependencies_.automatic_interval * skipped;
          periodic_due = true;
        }
        wait_duration = next_periodic_deadline_ - now;
        display_deadline = next_periodic_deadline_;
      }

      if (periodic_due) {
        std::lock_guard transition_lock(runtime_transition_mutex_);
        std::lock_guard lock(mutex_);
        if (!stopping_ && !snapshot_.check_running &&
            !pending_work_.has_value() && !worker_active_) {
          pending_work_ =
              WorkItem{ProtectionSuite::kSelfTest,
                       ProtectionTrigger::kPeriodic, ProtectionActor{}, true};
          snapshot_.state = ProtectionState::kChecking;
          snapshot_.check_running = true;
          snapshot_.transition_code.reset();
          runtime_authorized_ = false;
          queue_periodic = true;
        }
      }

      UpdateNextPeriodicDisplay(display_deadline);
      if (queue_periodic) {
        worker_condition_.notify_one();
      }

      std::unique_lock lock(mutex_);
      scheduler_condition_.wait_for(
          lock, wait_duration, [this] { return stopping_; });
      if (stopping_) {
        scheduler_exited_ = true;
        return;
      }
    }
  }

  void UpdateNextPeriodicDisplay(
      std::chrono::steady_clock::time_point deadline) noexcept {
    const auto steady_now = SteadyNow();
    const auto remaining = deadline > steady_now
                               ? deadline - steady_now
                               : std::chrono::steady_clock::duration::zero();
    const auto display =
        WallNowSeconds() +
        std::chrono::duration_cast<std::chrono::seconds>(remaining).count();
    std::lock_guard lock(mutex_);
    if (!stopping_ && deadline == next_periodic_deadline_) {
      snapshot_.next_periodic_at_seconds = display;
    }
  }

  std::int64_t WallNowSeconds() const noexcept {
    try {
      if (dependencies_.wall_now) {
        return EpochSeconds(dependencies_.wall_now());
      }
    } catch (...) {
    }
    return EpochSeconds(std::chrono::system_clock::now());
  }

  std::chrono::steady_clock::time_point SteadyNow() const noexcept {
    try {
      if (dependencies_.steady_now) {
        return dependencies_.steady_now();
      }
    } catch (...) {
    }
    return std::chrono::steady_clock::now();
  }

  SystemProtectionDependencies dependencies_;
  mutable std::mutex mutex_;
  std::mutex join_mutex_;
  std::recursive_mutex runtime_transition_mutex_;
  std::condition_variable worker_condition_;
  std::condition_variable scheduler_condition_;
  std::condition_variable startup_condition_;
  SystemProtectionSnapshot snapshot_;
  ProtectionRuntimeCallbacks runtime_callbacks_;
  std::optional<WorkItem> pending_work_;
  std::thread worker_;
  std::thread scheduler_;
  std::thread::id worker_thread_id_;
  std::thread::id scheduler_thread_id_;
  std::thread::id startup_thread_id_;
  std::chrono::steady_clock::time_point next_periodic_deadline_;
  bool self_test_audit_ok_{false};
  bool integrity_audit_ok_{false};
  bool restriction_latched_{false};
  std::optional<std::string> restriction_error_code_;
  bool worker_active_{false};
  bool startup_active_{false};
  bool worker_exited_{false};
  bool scheduler_exited_{false};
  bool stopping_{false};
  bool runtime_authorized_{false};
};

SystemProtectionService::SystemProtectionService(
    SystemProtectionDependencies dependencies)
    : impl_(std::make_unique<Impl>(std::move(dependencies))) {}

std::string ProtectionAuditSubjectType(
    const ProtectionAuditRecord& record) {
  switch (record.trigger) {
    case ProtectionTrigger::kStartup:
      return "startup";
    case ProtectionTrigger::kManual:
      return "manual";
    case ProtectionTrigger::kPeriodic:
      return "periodic";
  }
  return "unknown";
}

std::string ProtectionAuditSubjectIdentity(
    const ProtectionAuditRecord& record) {
  const auto duration = std::max<std::int64_t>(
      0, record.duration_milliseconds);
  const auto failed_count =
      std::max(record.failed_check_count, record.failed_check_ids.size());
  std::string subject = "d_ms=" + std::to_string(duration) +
                        ";n=" +
                        std::to_string(failed_count) +
                        ";ids=";
  if (failed_count == 0U) {
    subject.push_back('-');
    return subject;
  }

  std::size_t included = 0U;
  bool omitted_suffix_written = false;
  for (std::size_t index = 0U; index < record.failed_check_ids.size();
       ++index) {
    const auto remaining = failed_count - included - 1U;
    const std::string separator = included == 0U ? "" : ",";
    const std::string suffix =
        remaining == 0U ? "" : ";more=" + std::to_string(remaining);
    if (subject.size() + separator.size() +
            record.failed_check_ids[index].size() + suffix.size() >
        kMaximumAuditSubjectBytes) {
      subject += ";more=" +
                 std::to_string(failed_count - included);
      omitted_suffix_written = true;
      break;
    }
    subject += separator;
    subject += record.failed_check_ids[index];
    ++included;
  }
  if (included < failed_count && !omitted_suffix_written) {
    subject += ";more=" + std::to_string(failed_count - included);
  }
  return subject;
}

SystemProtectionService::~SystemProtectionService() = default;

SystemProtectionSnapshot SystemProtectionService::RunStartupChecks() noexcept {
  return impl_->RunStartupChecks();
}

SystemProtectionSnapshot SystemProtectionService::Snapshot() const {
  return impl_->Snapshot();
}

bool SystemProtectionService::RuntimeAllowed() const {
  return impl_->RuntimeAllowed();
}

bool SystemProtectionService::RunRuntimeControlIfAllowed(
    const std::function<void()>& command) {
  return impl_->RunRuntimeControlIfAllowed(command);
}

common::Result<SystemProtectionSnapshot>
SystemProtectionService::StartManualCheck(ProtectionSuite suite,
                                          ProtectionActor actor) {
  return impl_->StartManualCheck(suite, std::move(actor));
}

void SystemProtectionService::SetRuntimeCallbacks(
    ProtectionRuntimeCallbacks callbacks) {
  impl_->SetRuntimeCallbacks(std::move(callbacks));
}

void SystemProtectionService::Stop() noexcept {
  impl_->Stop();
}

}  // namespace camera_firmware::security
