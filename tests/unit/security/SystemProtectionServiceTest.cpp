#include "camera_firmware/security/SystemProtectionService.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <functional>
#include <future>
#include <latch>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

thread_local bool fail_next_sized_allocation = false;
thread_local std::size_t failing_allocation_size = 0U;

void* AllocateForProtectionTest(std::size_t size) {
  if (fail_next_sized_allocation && size == failing_allocation_size) {
    fail_next_sized_allocation = false;
    throw std::bad_alloc{};
  }
  if (void* allocation = std::malloc(size == 0U ? 1U : size)) {
    return allocation;
  }
  throw std::bad_alloc{};
}

void FailNextAllocationOfSize(std::size_t size) noexcept {
  failing_allocation_size = size;
  fail_next_sized_allocation = true;
}

}  // namespace

void* operator new(std::size_t size) {
  return AllocateForProtectionTest(size);
}
void* operator new[](std::size_t size) {
  return AllocateForProtectionTest(size);
}
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
  try {
    return AllocateForProtectionTest(size);
  } catch (...) {
    return nullptr;
  }
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
  try {
    return AllocateForProtectionTest(size);
  } catch (...) {
    return nullptr;
  }
}
void operator delete(void* allocation) noexcept {
  std::free(allocation);
}
void operator delete[](void* allocation) noexcept {
  std::free(allocation);
}
void operator delete(void* allocation, const std::nothrow_t&) noexcept {
  std::free(allocation);
}
void operator delete[](void* allocation, const std::nothrow_t&) noexcept {
  std::free(allocation);
}
void operator delete(void* allocation, std::size_t) noexcept {
  std::free(allocation);
}
void operator delete[](void* allocation, std::size_t) noexcept {
  std::free(allocation);
}

namespace camera_firmware::security {
namespace {

using namespace std::chrono_literals;

common::Result<SelfTestReport> PassingSelfTestReport() {
  return common::Result<SelfTestReport>::Ok(
      {true, {{"crypto.sha256", true, "OK"}}});
}

common::Result<integrity::IntegrityVerificationReport>
PassingIntegrityReport() {
  return common::Result<integrity::IntegrityVerificationReport>::Ok(
      {true,
       {{"camera-firmware", integrity::IntegrityCategory::kFirmware, true,
         "OK"}}});
}

common::Result<void> AuditOk() {
  return common::Result<void>::Ok();
}

bool WaitForIdle(SystemProtectionService& service,
                 std::chrono::milliseconds timeout = 2s) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (service.Snapshot().check_running &&
         std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(1ms);
  }
  return !service.Snapshot().check_running;
}

TEST(SystemProtectionServiceTest,
     RuntimeControlAndProtectionAdmissionAreAtomicallyOrdered) {
  std::atomic<unsigned int> self_test_calls{0U};
  std::latch manual_entered{1};
  std::latch release_manual{1};
  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = [&] {
    if (++self_test_calls > 1U) {
      manual_entered.count_down();
      release_manual.wait();
    }
    return PassingSelfTestReport();
  };
  dependencies.run_integrity = PassingIntegrityReport;
  dependencies.append_system_audit = [](auto, auto, auto) { return AuditOk(); };
  dependencies.append_administrator_audit = [](auto const&, auto, auto, auto) {
    return AuditOk();
  };
  dependencies.read_device_state = [] {
    return common::Result<DeviceState>::Ok(DeviceState::kOperational);
  };
  SystemProtectionService service(std::move(dependencies));
  ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kOperational);

  std::latch command_entered{1};
  std::latch release_command{1};
  bool command_executed = false;
  std::thread command([&] {
    command_executed = service.RunRuntimeControlIfAllowed([&] {
      command_entered.count_down();
      release_command.wait();
    });
  });
  command_entered.wait();

  auto manual = std::async(std::launch::async, [&] {
    return service.StartManualCheck(ProtectionSuite::kSelfTest,
                                    ProtectionActor{1, "admin", "127.0.0.1"});
  });
  const auto admission_status = manual.wait_for(100ms);
  EXPECT_EQ(admission_status, std::future_status::ready);
  release_command.count_down();
  command.join();
  ASSERT_TRUE(command_executed);
  ASSERT_EQ(manual.wait_for(2s), std::future_status::ready);
  const auto busy = manual.get();
  if (busy.ok()) {
    manual_entered.wait();
    release_manual.count_down();
    EXPECT_TRUE(WaitForIdle(service));
    ADD_FAILURE() << "manual admission waited for the runtime command";
    return;
  }
  EXPECT_EQ(busy.error().code, "E_PROTECTION_TRANSITION_BUSY");

  const auto accepted = service.StartManualCheck(
      ProtectionSuite::kSelfTest, ProtectionActor{1, "admin", "127.0.0.1"});
  ASSERT_TRUE(accepted.ok()) << accepted.error().message;
  manual_entered.wait();

  unsigned int rejected_command_calls = 0U;
  EXPECT_FALSE(
      service.RunRuntimeControlIfAllowed([&] { ++rejected_command_calls; }));
  EXPECT_EQ(rejected_command_calls, 0U);

  release_manual.count_down();
  EXPECT_TRUE(WaitForIdle(service));
}

enum class BoundedSubprocessOutcome {
  kExited,
  kTimedOutBeforeBoundary,
  kTimedOutAfterBoundary,
};

struct BoundedSubprocessResult {
  BoundedSubprocessOutcome outcome{BoundedSubprocessOutcome::kExited};
  int status{0};
  bool boundary_observed{false};
};

void MarkSubprocessBoundary(int descriptor) {
  constexpr char kMarker = 'R';
  ssize_t written;
  do {
    written = ::write(descriptor, &kMarker, sizeof(kMarker));
  } while (written < 0 && errno == EINTR);
  EXPECT_EQ(written, 1);
}

BoundedSubprocessResult RunInBoundedSubprocessAtBoundary(
    const std::function<void(int)>& scenario,
    std::chrono::milliseconds setup_timeout = 2s,
    std::chrono::milliseconds completion_timeout = 2s) {
  int boundary_pipe[2] = {-1, -1};
  if (::pipe(boundary_pipe) != 0) {
    throw std::system_error(errno, std::generic_category(), "pipe");
  }

  const pid_t child = ::fork();
  if (child < 0) {
    const int error = errno;
    (void)::close(boundary_pipe[0]);
    (void)::close(boundary_pipe[1]);
    throw std::system_error(error, std::generic_category(), "fork");
  }
  if (child == 0) {
    (void)::close(boundary_pipe[0]);
    try {
      scenario(boundary_pipe[1]);
    } catch (...) {
      (void)::close(boundary_pipe[1]);
      ::_exit(2);
    }
    (void)::close(boundary_pipe[1]);
    ::_exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  (void)::close(boundary_pipe[1]);
  bool boundary_observed = false;
  auto deadline = std::chrono::steady_clock::now() + setup_timeout;
  for (;;) {
    int status = 0;
    const pid_t waited = ::waitpid(child, &status, WNOHANG);
    if (waited == child) {
      if (!boundary_observed) {
        char marker = 0;
        ssize_t bytes_read;
        do {
          bytes_read = ::read(boundary_pipe[0], &marker, sizeof(marker));
        } while (bytes_read < 0 && errno == EINTR);
        boundary_observed = bytes_read == 1;
      }
      (void)::close(boundary_pipe[0]);
      return {BoundedSubprocessOutcome::kExited, status, boundary_observed};
    }
    if (waited < 0 && errno != EINTR) {
      const int error = errno;
      (void)::close(boundary_pipe[0]);
      throw std::system_error(error, std::generic_category(), "waitpid");
    }

    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      (void)::kill(child, SIGKILL);
      while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
      }
      (void)::close(boundary_pipe[0]);
      return {boundary_observed
                  ? BoundedSubprocessOutcome::kTimedOutAfterBoundary
                  : BoundedSubprocessOutcome::kTimedOutBeforeBoundary,
              status, boundary_observed};
    }

    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    const int poll_timeout = static_cast<int>(
        std::clamp(remaining.count(), std::int64_t{1}, std::int64_t{10}));
    pollfd descriptor{boundary_pipe[0], POLLIN, 0};
    const int polled = ::poll(&descriptor, 1, poll_timeout);
    if (polled < 0 && errno != EINTR) {
      const int error = errno;
      (void)::kill(child, SIGKILL);
      while (::waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
      }
      (void)::close(boundary_pipe[0]);
      throw std::system_error(error, std::generic_category(), "poll");
    }
    if (!boundary_observed && polled > 0 &&
        (descriptor.revents & POLLIN) != 0) {
      char marker = 0;
      ssize_t bytes_read;
      do {
        bytes_read = ::read(boundary_pipe[0], &marker, sizeof(marker));
      } while (bytes_read < 0 && errno == EINTR);
      if (bytes_read == 1) {
        boundary_observed = true;
        deadline = std::chrono::steady_clock::now() + completion_timeout;
      }
    }
  }
}

::testing::AssertionResult BoundedSubprocessPassed(
    const BoundedSubprocessResult& result) {
  if (result.outcome != BoundedSubprocessOutcome::kExited) {
    return ::testing::AssertionFailure()
           << "subprocess timed out "
           << (result.boundary_observed ? "after" : "before")
           << " the diagnostic boundary";
  }
  if (!WIFEXITED(result.status)) {
    return ::testing::AssertionFailure()
           << "subprocess did not exit normally, status=" << result.status;
  }
  if (WEXITSTATUS(result.status) != 0) {
    return ::testing::AssertionFailure()
           << "subprocess exit code=" << WEXITSTATUS(result.status);
  }
  return ::testing::AssertionSuccess();
}

struct RuntimeStopCopyBoundaryState {
  std::atomic<bool> block_next_copy{false};
  std::latch copy_entered{1};
  std::latch release_copy{1};
  std::atomic<std::size_t> stop_calls{0U};
};

class RuntimeStopAtCopyBoundary {
 public:
  explicit RuntimeStopAtCopyBoundary(
      std::shared_ptr<RuntimeStopCopyBoundaryState> state)
      : state_(std::move(state)) {}

  RuntimeStopAtCopyBoundary(const RuntimeStopAtCopyBoundary& other)
      : state_(other.state_) {
    if (state_->block_next_copy.exchange(false)) {
      state_->copy_entered.count_down();
      state_->release_copy.wait();
    }
  }

  RuntimeStopAtCopyBoundary(RuntimeStopAtCopyBoundary&&) noexcept = default;
  RuntimeStopAtCopyBoundary& operator=(const RuntimeStopAtCopyBoundary&) =
      default;
  RuntimeStopAtCopyBoundary& operator=(RuntimeStopAtCopyBoundary&&) noexcept =
      default;

  void operator()() const { ++state_->stop_calls; }

 private:
  std::shared_ptr<RuntimeStopCopyBoundaryState> state_;
};

TEST(SystemProtectionServiceTest,
     StartupPassesInDeterministicOrderAndPublishesExactNextRun) {
  std::vector<std::string> calls;
  const auto wall_now =
      std::chrono::system_clock::time_point{std::chrono::seconds{1'000}};
  const auto steady_now = std::chrono::steady_clock::now();

  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = [&] {
    calls.emplace_back("self_test");
    return PassingSelfTestReport();
  };
  dependencies.run_integrity = [&] {
    calls.emplace_back("integrity");
    return PassingIntegrityReport();
  };
  dependencies.append_system_audit = [](std::string_view, std::string_view,
                                        std::string_view) { return AuditOk(); };
  dependencies.append_administrator_audit =
      [](const ProtectionActor&, std::string_view, std::string_view,
         std::string_view) { return AuditOk(); };
  dependencies.read_device_state = [] {
    return common::Result<DeviceState>::Ok(DeviceState::kOperational);
  };
  dependencies.wall_now = [wall_now] { return wall_now; };
  dependencies.steady_now = [steady_now] { return steady_now; };
  dependencies.automatic_interval = 24h;

  SystemProtectionService service(std::move(dependencies));

  const auto initial = service.Snapshot();
  EXPECT_EQ(initial.state, ProtectionState::kChecking);
  EXPECT_FALSE(initial.check_running);
  EXPECT_FALSE(service.RuntimeAllowed());
  EXPECT_EQ(initial.next_periodic_at_seconds, 87'400);

  const auto result = service.RunStartupChecks();

  EXPECT_EQ(calls, (std::vector<std::string>{"self_test", "integrity"}));
  EXPECT_EQ(result.state, ProtectionState::kOperational);
  EXPECT_FALSE(result.check_running);
  ASSERT_TRUE(result.self_test.has_value());
  EXPECT_TRUE(result.self_test->passed);
  EXPECT_EQ(result.self_test->trigger, ProtectionTrigger::kStartup);
  ASSERT_TRUE(result.integrity.has_value());
  EXPECT_TRUE(result.integrity->passed);
  EXPECT_EQ(result.integrity->trigger, ProtectionTrigger::kStartup);
  EXPECT_TRUE(service.RuntimeAllowed());
}

TEST(SystemProtectionServiceTest,
     AuditRecordsIncludeTriggerDurationAndAllFailedCheckIds) {
  std::atomic<std::int64_t> steady_milliseconds{0};
  std::vector<ProtectionAuditRecord> records;
  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = [&] {
    steady_milliseconds.fetch_add(37);
    return common::Result<SelfTestReport>::Ok(
        {false,
         {{"crypto.sha256", false, "E_SELF_TEST_SHA256"},
          {"security.database", true, "OK"},
          {"security.tls_identity", false, "E_SELF_TEST_TLS"}}});
  };
  dependencies.run_integrity = [&] {
    steady_milliseconds.fetch_add(13);
    return PassingIntegrityReport();
  };
  dependencies.append_system_audit_record =
      [&](const ProtectionAuditRecord& record) {
        records.push_back(record);
        return AuditOk();
      };
  dependencies.read_device_state = [] {
    return common::Result<DeviceState>::Ok(DeviceState::kOperational);
  };
  dependencies.steady_now = [&] {
    return std::chrono::steady_clock::time_point{
        std::chrono::milliseconds{steady_milliseconds.load()}};
  };

  SystemProtectionService service(std::move(dependencies));
  EXPECT_EQ(service.RunStartupChecks().state, ProtectionState::kRestricted);

  const auto self_test_started = std::ranges::find(
      records, "self_test.started", &ProtectionAuditRecord::event_type);
  ASSERT_NE(self_test_started, records.end());
  EXPECT_EQ(self_test_started->trigger, ProtectionTrigger::kStartup);
  EXPECT_EQ(self_test_started->detail_code, "OK");
  EXPECT_EQ(self_test_started->duration_milliseconds, 0);
  EXPECT_TRUE(self_test_started->failed_check_ids.empty());

  const auto self_test_failed = std::ranges::find(
      records, "self_test.failed", &ProtectionAuditRecord::event_type);
  ASSERT_NE(self_test_failed, records.end());
  EXPECT_EQ(self_test_failed->trigger, ProtectionTrigger::kStartup);
  EXPECT_EQ(self_test_failed->detail_code, "E_PROTECTION_SELF_TEST");
  EXPECT_EQ(self_test_failed->duration_milliseconds, 37);
  EXPECT_EQ(
      self_test_failed->failed_check_ids,
      (std::vector<std::string>{"crypto.sha256", "security.tls_identity"}));
  EXPECT_EQ(ProtectionAuditSubjectType(*self_test_failed), "startup");
  EXPECT_EQ(ProtectionAuditSubjectIdentity(*self_test_failed),
            "d_ms=37;n=2;ids=crypto.sha256,security.tls_identity");

  const auto integrity_succeeded = std::ranges::find(
      records, "integrity_check.succeeded", &ProtectionAuditRecord::event_type);
  ASSERT_NE(integrity_succeeded, records.end());
  EXPECT_EQ(integrity_succeeded->duration_milliseconds, 13);
  EXPECT_TRUE(integrity_succeeded->failed_check_ids.empty());
  EXPECT_EQ(ProtectionAuditSubjectIdentity(*integrity_succeeded),
            "d_ms=13;n=0;ids=-");

  ProtectionAuditRecord oversized = *self_test_failed;
  oversized.failed_check_ids = {std::string(64U, 'a'), std::string(64U, 'b')};
  const auto bounded_subject = ProtectionAuditSubjectIdentity(oversized);
  EXPECT_LE(bounded_subject.size(), 64U);
  EXPECT_EQ(bounded_subject, "d_ms=37;n=2;ids=;more=2");

  oversized.failed_check_ids.clear();
  oversized.failed_check_count = 2U;
  EXPECT_EQ(ProtectionAuditSubjectIdentity(oversized),
            "d_ms=37;n=2;ids=;more=2");
}

TEST(SystemProtectionServiceTest,
     AuditIdAllocationFailureRestrictsWithoutTerminatingFirmware) {
  const auto bounded = RunInBoundedSubprocessAtBoundary([](int descriptor) {
    std::vector<std::string> events;
    events.reserve(8U);
    SystemProtectionDependencies dependencies;
    dependencies.run_self_tests = [] {
      return common::Result<SelfTestReport>::Ok(
          {false, {{"crypto.sha256", false, "E_SELF_TEST_SHA256"}}});
    };
    dependencies.run_integrity = PassingIntegrityReport;
    dependencies.append_system_audit = [&](std::string_view event_type, auto,
                                           auto) {
      events.emplace_back(event_type);
      return AuditOk();
    };
    dependencies.append_administrator_audit = [](auto const&, auto, auto,
                                                 auto) { return AuditOk(); };
    dependencies.read_device_state = [] {
      return common::Result<DeviceState>::Ok(DeviceState::kOperational);
    };
    SystemProtectionService service(std::move(dependencies));

    FailNextAllocationOfSize(sizeof(std::string));
    MarkSubprocessBoundary(descriptor);
    const auto snapshot = service.RunStartupChecks();

    EXPECT_FALSE(fail_next_sized_allocation);
    EXPECT_EQ(snapshot.state, ProtectionState::kRestricted);
    ASSERT_TRUE(snapshot.transition_code.has_value());
    EXPECT_EQ(*snapshot.transition_code, "E_PROTECTION_AUDIT");
    ASSERT_TRUE(snapshot.self_test.has_value());
    EXPECT_FALSE(snapshot.self_test->passed);
    ASSERT_EQ(snapshot.self_test->self_test_items.size(), 1U);
    EXPECT_EQ(snapshot.self_test->self_test_items.front().id, "crypto.sha256");
    EXPECT_EQ(events, (std::vector<std::string>{
                          "self_test.started", "self_test.failed",
                          "protection.restricted", "integrity_check.started",
                          "integrity_check.succeeded"}));
  });

  EXPECT_TRUE(BoundedSubprocessPassed(bounded));
}

TEST(SystemProtectionServiceTest,
     EitherStartupSuiteFailureRestrictsWithOrderedSystemAudits) {
  for (const auto failed_suite :
       {ProtectionSuite::kSelfTest, ProtectionSuite::kIntegrity}) {
    std::vector<std::string> events;
    SystemProtectionService* service_ptr = nullptr;
    ProtectionState state_seen_by_stop = ProtectionState::kChecking;
    std::size_t stop_calls = 0U;
    std::size_t start_calls = 0U;

    SystemProtectionDependencies dependencies;
    dependencies.run_self_tests = [failed_suite] {
      auto report = PassingSelfTestReport();
      if (failed_suite == ProtectionSuite::kSelfTest) {
        report.value().passed = false;
        report.value().items.front().passed = false;
        report.value().items.front().code = "E_SELF_TEST_SHA256";
      }
      return report;
    };
    dependencies.run_integrity = [failed_suite] {
      auto report = PassingIntegrityReport();
      if (failed_suite == ProtectionSuite::kIntegrity) {
        report.value().passed = false;
        report.value().items.front().passed = false;
        report.value().items.front().code = "E_INTEGRITY_MISMATCH";
      }
      return report;
    };
    dependencies.append_system_audit = [&](std::string_view event_type,
                                           std::string_view, std::string_view) {
      events.emplace_back("audit:" + std::string(event_type));
      if (event_type == "protection.restricted") {
        EXPECT_EQ(stop_calls, 1U);
      }
      return AuditOk();
    };
    dependencies.append_administrator_audit =
        [](const ProtectionActor&, std::string_view, std::string_view,
           std::string_view) {
          ADD_FAILURE() << "startup audit used administrator path";
          return AuditOk();
        };
    dependencies.read_device_state = [] {
      return common::Result<DeviceState>::Ok(DeviceState::kOperational);
    };
    dependencies.wall_now = [] {
      return std::chrono::system_clock::time_point{std::chrono::seconds{1'000}};
    };
    dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

    SystemProtectionService service(std::move(dependencies));
    service_ptr = &service;
    service.SetRuntimeCallbacks({.start =
                                     [&] {
                                       ++start_calls;
                                       return AuditOk();
                                     },
                                 .stop =
                                     [&] {
                                       state_seen_by_stop =
                                           service_ptr->Snapshot().state;
                                       ++stop_calls;
                                       events.emplace_back("runtime:stop");
                                     }});

    const auto result = service.RunStartupChecks();

    EXPECT_EQ(result.state, ProtectionState::kRestricted);
    EXPECT_FALSE(service.RuntimeAllowed());
    EXPECT_EQ(stop_calls, 1U);
    EXPECT_EQ(start_calls, 0U);
    EXPECT_EQ(state_seen_by_stop, ProtectionState::kRestricted);
    if (failed_suite == ProtectionSuite::kSelfTest) {
      EXPECT_EQ(events, (std::vector<std::string>{
                            "audit:self_test.started", "audit:self_test.failed",
                            "runtime:stop", "audit:protection.restricted",
                            "audit:integrity_check.started",
                            "audit:integrity_check.succeeded"}));
    } else {
      EXPECT_EQ(
          events,
          (std::vector<std::string>{
              "audit:self_test.started", "audit:self_test.succeeded",
              "audit:integrity_check.started", "audit:integrity_check.failed",
              "runtime:stop", "audit:protection.restricted"}));
    }
  }
}

TEST(SystemProtectionServiceTest,
     ManualCheckIsAsynchronousSingleFlightAndUsesAdministratorActor) {
  const auto bounded = RunInBoundedSubprocessAtBoundary([](int boundary) {
    std::atomic<int> self_test_calls{0};
    std::latch manual_entered{1};
    std::latch release_manual{1};
    std::thread::id manual_thread;
    std::mutex audit_mutex;
    std::vector<std::string> administrator_events;
    std::vector<std::string> administrator_outcomes;
    std::vector<std::string> administrator_details;
    std::vector<ProtectionActor> administrator_actors;
    std::size_t runtime_start_calls = 0U;

    SystemProtectionDependencies dependencies;
    dependencies.run_self_tests = [&] {
      if (self_test_calls.fetch_add(1) == 1) {
        manual_thread = std::this_thread::get_id();
        manual_entered.count_down();
        release_manual.wait();
      }
      return PassingSelfTestReport();
    };
    dependencies.run_integrity = PassingIntegrityReport;
    dependencies.append_system_audit = [](std::string_view, std::string_view,
                                          std::string_view) {
      return AuditOk();
    };
    dependencies.append_administrator_audit =
        [&](const ProtectionActor& actor, std::string_view event_type,
            std::string_view outcome, std::string_view detail_code) {
          std::lock_guard lock(audit_mutex);
          administrator_events.emplace_back(event_type);
          administrator_outcomes.emplace_back(outcome);
          administrator_details.emplace_back(detail_code);
          administrator_actors.push_back(actor);
          return AuditOk();
        };
    dependencies.read_device_state = [] {
      return common::Result<DeviceState>::Ok(DeviceState::kOperational);
    };
    dependencies.wall_now = [] {
      return std::chrono::system_clock::time_point{std::chrono::seconds{2'000}};
    };
    dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

    SystemProtectionService service(std::move(dependencies));
    service.SetRuntimeCallbacks({.start =
                                     [&] {
                                       ++runtime_start_calls;
                                       return AuditOk();
                                     },
                                 .stop = [] {}});
    ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kOperational);

    const ProtectionActor actor{42, "admin.one", "192.0.2.44"};
    const auto requester_thread = std::this_thread::get_id();
    MarkSubprocessBoundary(boundary);
    const auto request_started = std::chrono::steady_clock::now();
    const auto accepted =
        service.StartManualCheck(ProtectionSuite::kSelfTest, actor);
    const auto request_elapsed =
        std::chrono::steady_clock::now() - request_started;
    ASSERT_TRUE(accepted.ok()) << accepted.error().message;
    EXPECT_LT(request_elapsed, 250ms);
    EXPECT_EQ(accepted.value().state, ProtectionState::kChecking);
    EXPECT_TRUE(accepted.value().check_running);

    manual_entered.wait();
    EXPECT_NE(manual_thread, requester_thread);

    const auto conflict =
        service.StartManualCheck(ProtectionSuite::kIntegrity, actor);
    ASSERT_FALSE(conflict.ok());
    EXPECT_EQ(conflict.error().code, "E_PROTECTION_CHECK_RUNNING");

    release_manual.count_down();
    EXPECT_TRUE(WaitForIdle(service));
    const auto completed = service.Snapshot();
    EXPECT_FALSE(completed.check_running);
    EXPECT_EQ(completed.state, ProtectionState::kOperational);
    ASSERT_TRUE(completed.self_test.has_value());
    EXPECT_EQ(completed.self_test->trigger, ProtectionTrigger::kManual);
    EXPECT_EQ(runtime_start_calls, 0U);
    {
      std::lock_guard lock(audit_mutex);
      EXPECT_EQ(administrator_events,
                (std::vector<std::string>{"self_test.started",
                                          "self_test.succeeded"}));
      EXPECT_EQ(administrator_outcomes,
                (std::vector<std::string>{"success", "success"}));
      EXPECT_EQ(administrator_details, (std::vector<std::string>{"OK", "OK"}));
      ASSERT_EQ(administrator_actors.size(), 2U);
      for (const auto& observed_actor : administrator_actors) {
        EXPECT_EQ(observed_actor.user_id, actor.user_id);
        EXPECT_EQ(observed_actor.username, actor.username);
        EXPECT_EQ(observed_actor.peer_ip, actor.peer_ip);
      }
    }
  });

  EXPECT_TRUE(BoundedSubprocessPassed(bounded));
}

TEST(SystemProtectionServiceTest,
     RecoveryNeedsBothLatestPassesAndOrdersAuditBeforeRuntimeStart) {
  std::atomic<bool> self_test_passes{false};
  std::atomic<bool> integrity_passes{false};
  std::mutex event_mutex;
  std::vector<std::string> events;
  std::atomic<std::size_t> stop_calls{0U};
  std::atomic<std::size_t> start_calls{0U};
  SystemProtectionService* service_ptr = nullptr;

  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = [&] {
    auto report = PassingSelfTestReport();
    report.value().passed = self_test_passes.load();
    report.value().items.front().passed = report.value().passed;
    return report;
  };
  dependencies.run_integrity = [&] {
    auto report = PassingIntegrityReport();
    report.value().passed = integrity_passes.load();
    report.value().items.front().passed = report.value().passed;
    return report;
  };
  dependencies.append_system_audit = [](std::string_view, std::string_view,
                                        std::string_view) { return AuditOk(); };
  dependencies.append_administrator_audit = [&](const ProtectionActor&,
                                                std::string_view event_type,
                                                std::string_view,
                                                std::string_view) {
    std::lock_guard lock(event_mutex);
    events.emplace_back("audit:" + std::string(event_type));
    if (event_type == "protection.recovered") {
      EXPECT_EQ(service_ptr->Snapshot().state, ProtectionState::kOperational);
      EXPECT_EQ(start_calls.load(), 0U);
    }
    return AuditOk();
  };
  dependencies.read_device_state = [&] {
    EXPECT_EQ(service_ptr->Snapshot().state, ProtectionState::kOperational);
    return common::Result<DeviceState>::Ok(DeviceState::kOperational);
  };
  dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
  dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

  SystemProtectionService service(std::move(dependencies));
  service_ptr = &service;
  service.SetRuntimeCallbacks({.start =
                                   [&] {
                                     EXPECT_EQ(service.Snapshot().state,
                                               ProtectionState::kOperational);
                                     ++start_calls;
                                     std::lock_guard lock(event_mutex);
                                     events.emplace_back("runtime:start");
                                     return AuditOk();
                                   },
                               .stop = [&] { ++stop_calls; }});
  ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kRestricted);
  EXPECT_EQ(stop_calls.load(), 1U);

  const ProtectionActor actor{7, "recovery.admin", "198.51.100.7"};
  self_test_passes = true;
  ASSERT_TRUE(service.StartManualCheck(ProtectionSuite::kSelfTest, actor).ok());
  ASSERT_TRUE(WaitForIdle(service));
  EXPECT_EQ(service.Snapshot().state, ProtectionState::kRestricted);
  EXPECT_EQ(start_calls.load(), 0U);

  integrity_passes = true;
  ASSERT_TRUE(
      service.StartManualCheck(ProtectionSuite::kIntegrity, actor).ok());
  ASSERT_TRUE(WaitForIdle(service));
  EXPECT_EQ(service.Snapshot().state, ProtectionState::kOperational);
  EXPECT_TRUE(service.RuntimeAllowed());
  EXPECT_EQ(start_calls.load(), 1U);
  EXPECT_EQ(stop_calls.load(), 1U);
  {
    std::lock_guard lock(event_mutex);
    EXPECT_EQ(
        events,
        (std::vector<std::string>{
            "audit:self_test.started", "audit:self_test.succeeded",
            "audit:integrity_check.started", "audit:integrity_check.succeeded",
            "audit:protection.recovered", "runtime:start"}));
  }

  integrity_passes = false;
  ASSERT_TRUE(
      service.StartManualCheck(ProtectionSuite::kIntegrity, actor).ok());
  ASSERT_TRUE(WaitForIdle(service));
  EXPECT_EQ(service.Snapshot().state, ProtectionState::kRestricted);
  EXPECT_EQ(stop_calls.load(), 2U);

  ASSERT_TRUE(
      service.StartManualCheck(ProtectionSuite::kIntegrity, actor).ok());
  ASSERT_TRUE(WaitForIdle(service));
  EXPECT_EQ(service.Snapshot().state, ProtectionState::kRestricted);
  EXPECT_EQ(stop_calls.load(), 2U);
}

TEST(SystemProtectionServiceTest, RecoveryOnDefaultDeviceDoesNotStartRuntime) {
  std::atomic<bool> integrity_passes{false};
  std::atomic<std::size_t> start_calls{0U};
  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = PassingSelfTestReport;
  dependencies.run_integrity = [&] {
    auto report = PassingIntegrityReport();
    report.value().passed = integrity_passes.load();
    report.value().items.front().passed = report.value().passed;
    return report;
  };
  dependencies.append_system_audit = [](std::string_view, std::string_view,
                                        std::string_view) { return AuditOk(); };
  dependencies.append_administrator_audit =
      [](const ProtectionActor&, std::string_view, std::string_view,
         std::string_view) { return AuditOk(); };
  dependencies.read_device_state = [] {
    return common::Result<DeviceState>::Ok(DeviceState::kDefault);
  };
  dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
  dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

  SystemProtectionService service(std::move(dependencies));
  service.SetRuntimeCallbacks({.start =
                                   [&] {
                                     ++start_calls;
                                     return AuditOk();
                                   },
                               .stop = [] {}});
  ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kRestricted);

  integrity_passes = true;
  ASSERT_TRUE(service
                  .StartManualCheck(ProtectionSuite::kIntegrity,
                                    {9, "default.admin", "203.0.113.9"})
                  .ok());
  ASSERT_TRUE(WaitForIdle(service));

  EXPECT_EQ(service.Snapshot().state, ProtectionState::kOperational);
  EXPECT_TRUE(service.RuntimeAllowed());
  EXPECT_EQ(start_calls.load(), 0U);
}

TEST(SystemProtectionServiceTest,
     PeriodicSchedulerUsesSteadyTimeAndRunsSuitesWithoutOverlap) {
  std::atomic<int> self_test_calls{0};
  std::atomic<int> integrity_calls{0};
  std::atomic<int> active_callbacks{0};
  std::atomic<int> maximum_active_callbacks{0};
  std::atomic<std::int64_t> wall_seconds{5'000};

  const auto run_serialized = [&](std::atomic<int>& calls) {
    ++calls;
    const int active = ++active_callbacks;
    int observed = maximum_active_callbacks.load();
    while (active > observed &&
           !maximum_active_callbacks.compare_exchange_weak(observed, active)) {
    }
    std::this_thread::sleep_for(2ms);
    --active_callbacks;
  };

  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = [&] {
    run_serialized(self_test_calls);
    return PassingSelfTestReport();
  };
  dependencies.run_integrity = [&] {
    run_serialized(integrity_calls);
    return PassingIntegrityReport();
  };
  dependencies.append_system_audit = [](std::string_view, std::string_view,
                                        std::string_view) { return AuditOk(); };
  dependencies.append_administrator_audit =
      [](const ProtectionActor&, std::string_view, std::string_view,
         std::string_view) { return AuditOk(); };
  dependencies.read_device_state = [] {
    return common::Result<DeviceState>::Ok(DeviceState::kOperational);
  };
  dependencies.wall_now = [&] {
    return std::chrono::system_clock::time_point{
        std::chrono::seconds{wall_seconds.load()}};
  };
  dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };
  dependencies.automatic_interval = 40ms;

  SystemProtectionService service(std::move(dependencies));
  ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kOperational);
  wall_seconds = -50'000;

  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while ((self_test_calls.load() < 2 || integrity_calls.load() < 2) &&
         std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(1ms);
  }
  service.Stop();

  EXPECT_GE(self_test_calls.load(), 2);
  EXPECT_GE(integrity_calls.load(), 2);
  EXPECT_EQ(maximum_active_callbacks.load(), 1);
  const auto snapshot = service.Snapshot();
  ASSERT_TRUE(snapshot.self_test.has_value());
  EXPECT_EQ(snapshot.self_test->trigger, ProtectionTrigger::kPeriodic);
  ASSERT_TRUE(snapshot.integrity.has_value());
  EXPECT_EQ(snapshot.integrity->trigger, ProtectionTrigger::kPeriodic);
}

TEST(SystemProtectionServiceTest,
     SchedulerCollisionRejectsManualAndDoesNotBuildPeriodicBacklog) {
  std::atomic<int> self_test_calls{0};
  std::atomic<int> integrity_calls{0};
  std::promise<void> periodic_entered_promise;
  auto periodic_entered = periodic_entered_promise.get_future();
  std::promise<void> release_periodic_promise;
  const auto release_periodic = release_periodic_promise.get_future().share();
  std::promise<void> periodic_finished_promise;
  auto periodic_finished = periodic_finished_promise.get_future();

  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = [&] {
    if (++self_test_calls == 2) {
      periodic_entered_promise.set_value();
      release_periodic.wait();
    }
    return PassingSelfTestReport();
  };
  dependencies.run_integrity = [&] {
    if (++integrity_calls == 2) {
      periodic_finished_promise.set_value();
    }
    return PassingIntegrityReport();
  };
  dependencies.append_system_audit = [](std::string_view, std::string_view,
                                        std::string_view) { return AuditOk(); };
  dependencies.append_administrator_audit =
      [](const ProtectionActor&, std::string_view, std::string_view,
         std::string_view) { return AuditOk(); };
  dependencies.read_device_state = [] {
    return common::Result<DeviceState>::Ok(DeviceState::kOperational);
  };
  dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
  dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };
  dependencies.automatic_interval = 20ms;

  SystemProtectionService service(std::move(dependencies));
  ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kOperational);

  const auto entered_status = periodic_entered.wait_for(2s);
  if (entered_status != std::future_status::ready) {
    release_periodic_promise.set_value();
  }
  ASSERT_EQ(entered_status, std::future_status::ready);
  const auto conflict = service.StartManualCheck(
      ProtectionSuite::kSelfTest, {3, "collision.admin", "192.0.2.3"});
  ASSERT_FALSE(conflict.ok());
  EXPECT_EQ(conflict.error().code, "E_PROTECTION_CHECK_RUNNING");

  std::this_thread::sleep_for(100ms);
  release_periodic_promise.set_value();
  ASSERT_EQ(periodic_finished.wait_for(2s), std::future_status::ready);
  service.Stop();

  EXPECT_EQ(self_test_calls.load(), 2);
  EXPECT_EQ(integrity_calls.load(), 2);
}

TEST(SystemProtectionServiceTest,
     StopWaitsForActiveIntegrityAndSuppressesQueuedWorkAndRecovery) {
  const auto bounded = RunInBoundedSubprocessAtBoundary([](int boundary) {
    std::atomic<int> self_test_calls{0};
    std::atomic<int> integrity_calls{0};
    std::atomic<bool> recovery_integrity_passes{false};
    std::atomic<std::size_t> recovered_audits{0U};
    std::atomic<std::size_t> runtime_start_calls{0U};
    std::atomic<int> stop_returns{0};
    std::latch integrity_entered{1};
    std::latch release_integrity{1};

    SystemProtectionDependencies dependencies;
    dependencies.run_self_tests = [&] {
      ++self_test_calls;
      return PassingSelfTestReport();
    };
    dependencies.run_integrity = [&] {
      const int call = ++integrity_calls;
      auto report = PassingIntegrityReport();
      if (call == 1) {
        report.value().passed = false;
        report.value().items.front().passed = false;
      } else {
        integrity_entered.count_down();
        release_integrity.wait();
        report.value().passed = recovery_integrity_passes.load();
        report.value().items.front().passed = report.value().passed;
      }
      return report;
    };
    dependencies.append_system_audit = [](std::string_view, std::string_view,
                                          std::string_view) {
      return AuditOk();
    };
    dependencies.append_administrator_audit =
        [&](const ProtectionActor&, std::string_view event_type,
            std::string_view, std::string_view) {
          if (event_type == "protection.recovered") {
            ++recovered_audits;
          }
          return AuditOk();
        };
    dependencies.read_device_state = [] {
      return common::Result<DeviceState>::Ok(DeviceState::kOperational);
    };
    dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
    dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };
    dependencies.automatic_interval = 20ms;

    SystemProtectionService service(std::move(dependencies));
    service.SetRuntimeCallbacks({.start =
                                     [&] {
                                       ++runtime_start_calls;
                                       return AuditOk();
                                     },
                                 .stop = [] {}});
    ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kRestricted);

    recovery_integrity_passes = true;
    ASSERT_TRUE(service
                    .StartManualCheck(ProtectionSuite::kIntegrity,
                                      {11, "shutdown.admin", "192.0.2.11"})
                    .ok());
    integrity_entered.wait();
    MarkSubprocessBoundary(boundary);

    std::thread first_stopper([&] {
      service.Stop();
      ++stop_returns;
    });
    std::thread second_stopper([&] {
      service.Stop();
      ++stop_returns;
    });
    const auto stopping_deadline = std::chrono::steady_clock::now() + 500ms;
    while (service.Snapshot().state != ProtectionState::kStopping &&
           std::chrono::steady_clock::now() < stopping_deadline) {
      std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(service.Snapshot().state, ProtectionState::kStopping);
    EXPECT_FALSE(service.RuntimeAllowed());
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(stop_returns.load(), 0);
    const auto rejected = service.StartManualCheck(
        ProtectionSuite::kSelfTest, {11, "shutdown.admin", "192.0.2.11"});
    EXPECT_FALSE(rejected.ok());
    if (!rejected.ok()) {
      EXPECT_EQ(rejected.error().code, "E_PROTECTION_STOPPING");
    }

    release_integrity.count_down();
    first_stopper.join();
    second_stopper.join();
    EXPECT_EQ(stop_returns.load(), 2);
    service.Stop();

    const auto snapshot = service.Snapshot();
    EXPECT_EQ(snapshot.state, ProtectionState::kStopping);
    EXPECT_FALSE(snapshot.check_running);
    ASSERT_TRUE(snapshot.integrity.has_value());
    EXPECT_TRUE(snapshot.integrity->passed);
    EXPECT_EQ(recovered_audits.load(), 0U);
    EXPECT_EQ(runtime_start_calls.load(), 0U);
    EXPECT_EQ(self_test_calls.load(), 1);
    EXPECT_EQ(integrity_calls.load(), 2);
  });

  EXPECT_TRUE(BoundedSubprocessPassed(bounded));
}

TEST(SystemProtectionServiceTest,
     ExternalStopWaitsForBlockingStartupIntegrityCallback) {
  const auto bounded = RunInBoundedSubprocessAtBoundary([](int boundary) {
    std::latch integrity_entered{1};
    std::latch release_integrity{1};
    std::atomic<bool> integrity_completed{false};
    std::atomic<bool> startup_returned{false};
    std::atomic<bool> stop_returned{false};

    SystemProtectionDependencies dependencies;
    dependencies.run_self_tests = PassingSelfTestReport;
    dependencies.run_integrity = [&] {
      integrity_entered.count_down();
      release_integrity.wait();
      integrity_completed = true;
      return PassingIntegrityReport();
    };
    dependencies.append_system_audit = [](std::string_view, std::string_view,
                                          std::string_view) {
      return AuditOk();
    };
    dependencies.append_administrator_audit =
        [](const ProtectionActor&, std::string_view, std::string_view,
           std::string_view) { return AuditOk(); };
    dependencies.read_device_state = [] {
      return common::Result<DeviceState>::Ok(DeviceState::kOperational);
    };
    dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
    dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

    SystemProtectionService service(std::move(dependencies));
    std::thread startup([&] {
      (void)service.RunStartupChecks();
      startup_returned = true;
    });
    integrity_entered.wait();
    EXPECT_EQ(service.Snapshot().state, ProtectionState::kChecking);
    EXPECT_TRUE(service.Snapshot().check_running);
    EXPECT_FALSE(service.RuntimeAllowed());
    MarkSubprocessBoundary(boundary);

    std::thread stopper([&] {
      service.Stop();
      stop_returned = true;
    });
    const auto stopping_deadline = std::chrono::steady_clock::now() + 500ms;
    while (service.Snapshot().state != ProtectionState::kStopping &&
           std::chrono::steady_clock::now() < stopping_deadline) {
      std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(service.Snapshot().state, ProtectionState::kStopping);
    EXPECT_FALSE(service.RuntimeAllowed());
    std::this_thread::sleep_for(50ms);
    EXPECT_FALSE(integrity_completed.load());
    EXPECT_FALSE(startup_returned.load());
    EXPECT_FALSE(stop_returned.load());

    release_integrity.count_down();
    startup.join();
    stopper.join();

    EXPECT_TRUE(integrity_completed.load());
    EXPECT_TRUE(startup_returned.load());
    EXPECT_TRUE(stop_returned.load());
    const auto snapshot = service.Snapshot();
    EXPECT_EQ(snapshot.state, ProtectionState::kStopping);
    EXPECT_FALSE(snapshot.check_running);
    EXPECT_FALSE(service.RuntimeAllowed());
  });

  EXPECT_TRUE(BoundedSubprocessPassed(bounded));
}

TEST(SystemProtectionServiceTest,
     StartupCallbackStopReturnsWithoutPublishingIdleUntilStartupExits) {
  const auto bounded = RunInBoundedSubprocessAtBoundary([](int boundary) {
    std::atomic<bool> callback_stop_returned{false};
    std::atomic<int> integrity_calls{0};
    SystemProtectionService* service_ptr = nullptr;

    SystemProtectionDependencies dependencies;
    dependencies.run_self_tests = [&] {
      service_ptr->Stop();
      callback_stop_returned = true;
      const auto stopping = service_ptr->Snapshot();
      EXPECT_EQ(stopping.state, ProtectionState::kStopping);
      EXPECT_TRUE(stopping.check_running);
      EXPECT_FALSE(service_ptr->RuntimeAllowed());
      return PassingSelfTestReport();
    };
    dependencies.run_integrity = [&] {
      ++integrity_calls;
      return PassingIntegrityReport();
    };
    dependencies.append_system_audit = [](std::string_view, std::string_view,
                                          std::string_view) {
      return AuditOk();
    };
    dependencies.append_administrator_audit =
        [](const ProtectionActor&, std::string_view, std::string_view,
           std::string_view) { return AuditOk(); };
    dependencies.read_device_state = [] {
      return common::Result<DeviceState>::Ok(DeviceState::kOperational);
    };
    dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
    dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

    SystemProtectionService service(std::move(dependencies));
    service_ptr = &service;
    MarkSubprocessBoundary(boundary);
    const auto stopped = service.RunStartupChecks();

    EXPECT_TRUE(callback_stop_returned.load());
    EXPECT_EQ(integrity_calls.load(), 0);
    EXPECT_EQ(stopped.state, ProtectionState::kStopping);
    EXPECT_FALSE(stopped.check_running);
    EXPECT_FALSE(service.RuntimeAllowed());
    service.Stop();
  });

  EXPECT_TRUE(BoundedSubprocessPassed(bounded));
}

TEST(SystemProtectionServiceTest,
     PublishedRestrictionStopsRuntimeBeforeConcurrentStopReturns) {
  const auto bounded = RunInBoundedSubprocessAtBoundary([](int boundary) {
    const auto copy_boundary = std::make_shared<RuntimeStopCopyBoundaryState>();
    std::atomic<bool> startup_returned{false};
    std::atomic<bool> stop_returned{false};
    std::atomic<bool> stop_observed_before_return{false};

    SystemProtectionDependencies dependencies;
    dependencies.run_self_tests = [] {
      auto report = PassingSelfTestReport();
      report.value().passed = false;
      report.value().items.front().passed = false;
      return report;
    };
    dependencies.run_integrity = PassingIntegrityReport;
    dependencies.append_system_audit = [](std::string_view, std::string_view,
                                          std::string_view) {
      return AuditOk();
    };
    dependencies.append_administrator_audit =
        [](const ProtectionActor&, std::string_view, std::string_view,
           std::string_view) { return AuditOk(); };
    dependencies.read_device_state = [] {
      return common::Result<DeviceState>::Ok(DeviceState::kOperational);
    };
    dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
    dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

    SystemProtectionService service(std::move(dependencies));
    service.SetRuntimeCallbacks(
        {.start = AuditOk, .stop = RuntimeStopAtCopyBoundary{copy_boundary}});
    copy_boundary->block_next_copy = true;

    std::thread startup([&] {
      (void)service.RunStartupChecks();
      startup_returned = true;
    });
    copy_boundary->copy_entered.wait();
    MarkSubprocessBoundary(boundary);

    std::latch stop_call_started{1};
    std::thread stopper([&] {
      stop_call_started.count_down();
      service.Stop();
      stop_observed_before_return = copy_boundary->stop_calls.load() == 1U;
      stop_returned = true;
    });
    stop_call_started.wait();
    std::this_thread::sleep_for(50ms);
    copy_boundary->release_copy.count_down();

    startup.join();
    stopper.join();
    EXPECT_TRUE(startup_returned.load());
    EXPECT_TRUE(stop_returned.load());
    EXPECT_EQ(copy_boundary->stop_calls.load(), 1U);
    EXPECT_TRUE(stop_observed_before_return.load());
    EXPECT_EQ(service.Snapshot().state, ProtectionState::kStopping);
    EXPECT_FALSE(service.RuntimeAllowed());
  });

  EXPECT_TRUE(BoundedSubprocessPassed(bounded));
}

TEST(SystemProtectionServiceTest,
     AuditErrorOrExceptionPreservesPassingSuitesAndStablePublicCode) {
  for (const bool throw_from_audit : {false, true}) {
    std::atomic<bool> failed_once{false};
    SystemProtectionDependencies dependencies;
    dependencies.run_self_tests = PassingSelfTestReport;
    dependencies.run_integrity = PassingIntegrityReport;
    dependencies.append_system_audit =
        [&](std::string_view event_type, std::string_view,
            std::string_view) -> common::Result<void> {
      if (event_type == "self_test.succeeded" && !failed_once.exchange(true)) {
        if (throw_from_audit) {
          throw std::runtime_error("/secret/audit/database.db");
        }
        return common::Result<void>::Err(
            {"E_PRIVATE", "/secret/audit/database.db"});
      }
      return AuditOk();
    };
    dependencies.append_administrator_audit =
        [](const ProtectionActor&, std::string_view, std::string_view,
           std::string_view) { return AuditOk(); };
    dependencies.read_device_state = [] {
      return common::Result<DeviceState>::Ok(DeviceState::kOperational);
    };
    dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
    dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

    SystemProtectionService service(std::move(dependencies));
    const auto snapshot = service.RunStartupChecks();

    EXPECT_EQ(snapshot.state, ProtectionState::kRestricted);
    ASSERT_TRUE(snapshot.self_test.has_value());
    EXPECT_TRUE(snapshot.self_test->passed);
    ASSERT_TRUE(snapshot.integrity.has_value());
    EXPECT_TRUE(snapshot.integrity->passed);
    ASSERT_TRUE(snapshot.transition_code.has_value());
    EXPECT_EQ(*snapshot.transition_code, "E_PROTECTION_AUDIT");
    EXPECT_EQ(snapshot.transition_code->find("secret"), std::string::npos);
  }
}

TEST(SystemProtectionServiceTest,
     RecoveryAuditFailureKeepsRuntimeUnauthorizedWhileAuditIsBlocked) {
  for (const bool throw_from_audit : {false, true}) {
    const auto bounded = RunInBoundedSubprocessAtBoundary([throw_from_audit](
                                                              int boundary) {
      std::atomic<bool> integrity_passes{false};
      std::atomic<std::size_t> runtime_start_calls{0U};
      std::latch recovery_audit_entered{1};
      std::latch release_recovery_audit{1};
      std::vector<std::string> administrator_events;
      std::mutex event_mutex;
      SystemProtectionDependencies dependencies;
      dependencies.run_self_tests = PassingSelfTestReport;
      dependencies.run_integrity = [&] {
        auto report = PassingIntegrityReport();
        report.value().passed = integrity_passes.load();
        report.value().items.front().passed = report.value().passed;
        return report;
      };
      dependencies.append_system_audit = [](std::string_view, std::string_view,
                                            std::string_view) {
        return AuditOk();
      };
      dependencies.append_administrator_audit =
          [&](const ProtectionActor&, std::string_view event_type,
              std::string_view, std::string_view) {
            {
              std::lock_guard lock(event_mutex);
              administrator_events.emplace_back(event_type);
            }
            if (event_type == "protection.recovered") {
              recovery_audit_entered.count_down();
              release_recovery_audit.wait();
              if (throw_from_audit) {
                throw std::runtime_error("/secret/audit/recovery.log");
              }
              return common::Result<void>::Err(
                  {"E_PRIVATE", "/secret/audit/recovery.log"});
            }
            return AuditOk();
          };
      dependencies.read_device_state = [] {
        return common::Result<DeviceState>::Ok(DeviceState::kOperational);
      };
      dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
      dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

      SystemProtectionService service(std::move(dependencies));
      service.SetRuntimeCallbacks({.start =
                                       [&] {
                                         ++runtime_start_calls;
                                         return AuditOk();
                                       },
                                   .stop = [] {}});
      ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kRestricted);
      EXPECT_FALSE(service.RuntimeAllowed());

      integrity_passes = true;
      ASSERT_TRUE(service
                      .StartManualCheck(ProtectionSuite::kIntegrity,
                                        {19, "audit.admin", "192.0.2.19"})
                      .ok());
      MarkSubprocessBoundary(boundary);
      recovery_audit_entered.wait();

      EXPECT_EQ(service.Snapshot().state, ProtectionState::kOperational);
      EXPECT_FALSE(service.RuntimeAllowed());
      EXPECT_EQ(runtime_start_calls.load(), 0U);

      release_recovery_audit.count_down();
      ASSERT_TRUE(WaitForIdle(service));

      const auto snapshot = service.Snapshot();
      EXPECT_EQ(snapshot.state, ProtectionState::kRestricted);
      EXPECT_FALSE(service.RuntimeAllowed());
      ASSERT_TRUE(snapshot.integrity.has_value());
      EXPECT_TRUE(snapshot.integrity->passed);
      ASSERT_TRUE(snapshot.transition_code.has_value());
      EXPECT_EQ(*snapshot.transition_code, "E_PROTECTION_AUDIT");
      EXPECT_EQ(runtime_start_calls.load(), 0U);
      std::lock_guard lock(event_mutex);
      EXPECT_EQ(administrator_events,
                (std::vector<std::string>{"integrity_check.started",
                                          "integrity_check.succeeded",
                                          "protection.recovered"}));
    });

    EXPECT_TRUE(BoundedSubprocessPassed(bounded))
        << "throw_from_audit=" << throw_from_audit;
  }
}

TEST(SystemProtectionServiceTest,
     SuiteErrorsAndExceptionsBecomeSecretFreeFailedSnapshots) {
  for (const bool throw_from_suite : {false, true}) {
    SystemProtectionDependencies dependencies;
    dependencies.run_self_tests =
        [throw_from_suite]() -> common::Result<SelfTestReport> {
      if (throw_from_suite) {
        throw std::runtime_error("/secret/self-test/key.pem");
      }
      return common::Result<SelfTestReport>::Err(
          {"E_PRIVATE", "/secret/self-test/key.pem"});
    };
    dependencies.run_integrity = PassingIntegrityReport;
    dependencies.append_system_audit = [](std::string_view, std::string_view,
                                          std::string_view) {
      return AuditOk();
    };
    dependencies.append_administrator_audit =
        [](const ProtectionActor&, std::string_view, std::string_view,
           std::string_view) { return AuditOk(); };
    dependencies.read_device_state = [] {
      return common::Result<DeviceState>::Ok(DeviceState::kOperational);
    };
    dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
    dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

    SystemProtectionService service(std::move(dependencies));
    SystemProtectionSnapshot snapshot;
    EXPECT_NO_THROW(snapshot = service.RunStartupChecks());
    EXPECT_EQ(snapshot.state, ProtectionState::kRestricted);
    ASSERT_TRUE(snapshot.self_test.has_value());
    EXPECT_FALSE(snapshot.self_test->passed);
    EXPECT_TRUE(snapshot.self_test->self_test_items.empty());
    ASSERT_TRUE(snapshot.transition_code.has_value());
    EXPECT_EQ(*snapshot.transition_code, "E_PROTECTION_SELF_TEST");
    EXPECT_EQ(snapshot.transition_code->find("secret"), std::string::npos);
  }
}

TEST(SystemProtectionServiceTest,
     DeviceAndRuntimeStartFailuresDoNotFalsifyRecoveredSuites) {
  enum class FailureMode {
    kDeviceError,
    kDeviceThrow,
    kStartError,
    kStartThrow
  };
  for (const auto mode : {FailureMode::kDeviceError, FailureMode::kDeviceThrow,
                          FailureMode::kStartError, FailureMode::kStartThrow}) {
    std::atomic<bool> integrity_passes{false};
    std::atomic<std::size_t> start_calls{0U};
    SystemProtectionDependencies dependencies;
    dependencies.run_self_tests = PassingSelfTestReport;
    dependencies.run_integrity = [&] {
      auto report = PassingIntegrityReport();
      report.value().passed = integrity_passes.load();
      report.value().items.front().passed = report.value().passed;
      return report;
    };
    dependencies.append_system_audit = [](std::string_view, std::string_view,
                                          std::string_view) {
      return AuditOk();
    };
    dependencies.append_administrator_audit =
        [](const ProtectionActor&, std::string_view, std::string_view,
           std::string_view) { return AuditOk(); };
    dependencies.read_device_state = [mode] {
      if (mode == FailureMode::kDeviceThrow) {
        throw std::runtime_error("/secret/device/state.db");
      }
      if (mode == FailureMode::kDeviceError) {
        return common::Result<DeviceState>::Err(
            {"E_PRIVATE", "/secret/device/state.db"});
      }
      return common::Result<DeviceState>::Ok(DeviceState::kOperational);
    };
    dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
    dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

    SystemProtectionService service(std::move(dependencies));
    service.SetRuntimeCallbacks({.start = [&, mode]() -> common::Result<void> {
                                   ++start_calls;
                                   if (mode == FailureMode::kStartThrow) {
                                     throw std::runtime_error(
                                         "/secret/runtime/socket");
                                   }
                                   return common::Result<void>::Err(
                                       {"E_PRIVATE", "/secret/runtime/socket"});
                                 },
                                 .stop = [] {}});
    ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kRestricted);
    integrity_passes = true;
    ASSERT_TRUE(service
                    .StartManualCheck(ProtectionSuite::kIntegrity,
                                      {13, "failure.admin", "192.0.2.13"})
                    .ok());
    ASSERT_TRUE(WaitForIdle(service));

    const auto snapshot = service.Snapshot();
    EXPECT_EQ(snapshot.state, ProtectionState::kOperational);
    EXPECT_TRUE(service.RuntimeAllowed());
    ASSERT_TRUE(snapshot.integrity.has_value());
    EXPECT_TRUE(snapshot.integrity->passed);
    ASSERT_TRUE(snapshot.transition_code.has_value());
    const bool device_failure =
        mode == FailureMode::kDeviceError || mode == FailureMode::kDeviceThrow;
    EXPECT_EQ(*snapshot.transition_code, device_failure
                                             ? "E_PROTECTION_DEVICE_STATE"
                                             : "E_PROTECTION_RUNTIME_START");
    EXPECT_EQ(start_calls.load(), device_failure ? 0U : 1U);
    EXPECT_EQ(snapshot.transition_code->find("secret"), std::string::npos);
  }
}

TEST(SystemProtectionServiceTest,
     RuntimeStopExceptionIsContainedAndRemainsObservable) {
  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = [] {
    auto report = PassingSelfTestReport();
    report.value().passed = false;
    report.value().items.front().passed = false;
    return report;
  };
  dependencies.run_integrity = PassingIntegrityReport;
  dependencies.append_system_audit = [](std::string_view, std::string_view,
                                        std::string_view) { return AuditOk(); };
  dependencies.append_administrator_audit =
      [](const ProtectionActor&, std::string_view, std::string_view,
         std::string_view) { return AuditOk(); };
  dependencies.read_device_state = [] {
    return common::Result<DeviceState>::Ok(DeviceState::kOperational);
  };
  dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
  dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

  SystemProtectionService service(std::move(dependencies));
  service.SetRuntimeCallbacks(
      {.start = AuditOk,
       .stop = [] { throw std::runtime_error("/secret/runtime/stop"); }});

  SystemProtectionSnapshot snapshot;
  EXPECT_NO_THROW(snapshot = service.RunStartupChecks());
  EXPECT_EQ(snapshot.state, ProtectionState::kRestricted);
  ASSERT_TRUE(snapshot.transition_code.has_value());
  EXPECT_EQ(*snapshot.transition_code, "E_PROTECTION_RUNTIME_STOP");
}

TEST(SystemProtectionServiceTest,
     ConcurrentReadersObserveOnlyCoherentSnapshots) {
  std::atomic<bool> self_test_passes{true};
  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = [&] {
    auto report = PassingSelfTestReport();
    report.value().passed = self_test_passes.load();
    report.value().items.front().passed = report.value().passed;
    return report;
  };
  dependencies.run_integrity = PassingIntegrityReport;
  dependencies.append_system_audit = [](std::string_view, std::string_view,
                                        std::string_view) { return AuditOk(); };
  dependencies.append_administrator_audit =
      [](const ProtectionActor&, std::string_view, std::string_view,
         std::string_view) { return AuditOk(); };
  dependencies.read_device_state = [] {
    return common::Result<DeviceState>::Ok(DeviceState::kDefault);
  };
  dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
  dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

  SystemProtectionService service(std::move(dependencies));
  ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kOperational);

  std::atomic<bool> readers_running{true};
  std::atomic<std::size_t> violations{0U};
  std::atomic<std::size_t> runtime_allowed_observations{0U};
  std::latch readers_ready{4};
  std::latch release_readers{1};
  std::vector<std::thread> readers;
  for (int index = 0; index < 4; ++index) {
    readers.emplace_back([&] {
      readers_ready.count_down();
      release_readers.wait();
      while (readers_running.load()) {
        const auto snapshot = service.Snapshot();
        if (snapshot.state == ProtectionState::kOperational &&
            (!snapshot.self_test.has_value() ||
             !snapshot.integrity.has_value() || !snapshot.self_test->passed ||
             !snapshot.integrity->passed)) {
          ++violations;
        }
        if (service.RuntimeAllowed()) {
          ++runtime_allowed_observations;
        }
      }
    });
  }

  readers_ready.wait();
  release_readers.count_down();
  const auto observation_deadline = std::chrono::steady_clock::now() + 500ms;
  while (runtime_allowed_observations.load() < 4U &&
         std::chrono::steady_clock::now() < observation_deadline) {
    std::this_thread::sleep_for(1ms);
  }
  EXPECT_GE(runtime_allowed_observations.load(), 4U);

  const ProtectionActor actor{15, "reader.admin", "198.51.100.15"};
  for (int iteration = 0; iteration < 20; ++iteration) {
    self_test_passes = (iteration % 2) != 0;
    if (!service.StartManualCheck(ProtectionSuite::kSelfTest, actor).ok() ||
        !WaitForIdle(service)) {
      ++violations;
      break;
    }
  }
  readers_running = false;
  for (auto& reader : readers) {
    reader.join();
  }

  EXPECT_EQ(violations.load(), 0U);
  EXPECT_GT(runtime_allowed_observations.load(), 0U);
}

TEST(SystemProtectionServiceTest,
     NonPositiveIntervalNormalizesWithoutBusyLoop) {
  std::atomic<int> self_test_calls{0};
  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = [&] {
    ++self_test_calls;
    return PassingSelfTestReport();
  };
  dependencies.run_integrity = PassingIntegrityReport;
  dependencies.append_system_audit = [](std::string_view, std::string_view,
                                        std::string_view) { return AuditOk(); };
  dependencies.append_administrator_audit =
      [](const ProtectionActor&, std::string_view, std::string_view,
         std::string_view) { return AuditOk(); };
  dependencies.read_device_state = [] {
    return common::Result<DeviceState>::Ok(DeviceState::kOperational);
  };
  dependencies.wall_now = [] {
    return std::chrono::system_clock::time_point{std::chrono::seconds{100}};
  };
  const auto steady_now = std::chrono::steady_clock::now();
  dependencies.steady_now = [steady_now] { return steady_now; };
  dependencies.automatic_interval = 0ms;

  SystemProtectionService service(std::move(dependencies));
  EXPECT_EQ(service.Snapshot().next_periodic_at_seconds, 86'500);
  ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kOperational);
  std::this_thread::sleep_for(20ms);
  service.Stop();
  EXPECT_EQ(self_test_calls.load(), 1);
}

TEST(SystemProtectionServiceTest,
     WorkerThreadStopSelfCallDoesNotSelfJoinOrDetach) {
  std::atomic<int> self_test_calls{0};
  SystemProtectionService* service_ptr = nullptr;
  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = [&] {
    if (++self_test_calls == 2) {
      service_ptr->Stop();
    }
    return PassingSelfTestReport();
  };
  dependencies.run_integrity = PassingIntegrityReport;
  dependencies.append_system_audit = [](std::string_view, std::string_view,
                                        std::string_view) { return AuditOk(); };
  dependencies.append_administrator_audit =
      [](const ProtectionActor&, std::string_view, std::string_view,
         std::string_view) { return AuditOk(); };
  dependencies.read_device_state = [] {
    return common::Result<DeviceState>::Ok(DeviceState::kOperational);
  };
  dependencies.wall_now = [] { return std::chrono::system_clock::now(); };
  dependencies.steady_now = [] { return std::chrono::steady_clock::now(); };

  SystemProtectionService service(std::move(dependencies));
  service_ptr = &service;
  ASSERT_EQ(service.RunStartupChecks().state, ProtectionState::kOperational);
  ASSERT_TRUE(service
                  .StartManualCheck(ProtectionSuite::kSelfTest,
                                    {17, "self-stop.admin", "203.0.113.17"})
                  .ok());

  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (service.Snapshot().state != ProtectionState::kStopping &&
         std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(1ms);
  }
  EXPECT_EQ(service.Snapshot().state, ProtectionState::kStopping);
  service.Stop();
  EXPECT_EQ(self_test_calls.load(), 2);
}

}  // namespace
}  // namespace camera_firmware::security
