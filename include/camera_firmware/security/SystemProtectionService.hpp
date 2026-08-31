#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/integrity/IntegrityVerifier.hpp"
#include "camera_firmware/security/SecuritySelfTest.hpp"
#include "camera_firmware/security/SecurityStore.hpp"

namespace camera_firmware::security {

enum class ProtectionState { kChecking, kOperational, kRestricted, kStopping };
enum class ProtectionTrigger { kStartup, kManual, kPeriodic };
enum class ProtectionSuite { kSelfTest, kIntegrity };

struct ProtectionActor {
  std::optional<std::int64_t> user_id;
  std::string username{"system"};
  std::string peer_ip{"127.0.0.1"};
};

struct ProtectionSuiteSnapshot {
  ProtectionSuite suite;
  ProtectionTrigger trigger;
  bool passed{false};
  std::int64_t started_at_seconds{0};
  std::int64_t finished_at_seconds{0};
  std::int64_t duration_milliseconds{0};
  std::vector<SelfTestItemResult> self_test_items;
  std::vector<integrity::IntegrityItemResult> integrity_items;
};

struct SystemProtectionSnapshot {
  ProtectionState state{ProtectionState::kChecking};
  bool check_running{false};
  std::int64_t next_periodic_at_seconds{0};
  std::optional<ProtectionSuiteSnapshot> self_test;
  std::optional<ProtectionSuiteSnapshot> integrity;
  std::optional<std::string> transition_code;
};

struct ProtectionRuntimeCallbacks {
  std::function<common::Result<void>()> start;
  std::function<void()> stop;
};

struct ProtectionAuditRecord {
  std::string event_type;
  std::string outcome;
  std::string detail_code;
  ProtectionTrigger trigger{ProtectionTrigger::kStartup};
  std::int64_t duration_milliseconds{0};
  std::vector<std::string> failed_check_ids;
  std::size_t failed_check_count{0U};
};

std::string ProtectionAuditSubjectType(const ProtectionAuditRecord& record);
std::string ProtectionAuditSubjectIdentity(
    const ProtectionAuditRecord& record);

using ProtectionSystemAuditCallback =
    std::function<common::Result<void>(std::string_view event_type,
                                       std::string_view outcome,
                                       std::string_view detail_code)>;
using ProtectionAdministratorAuditCallback =
    std::function<common::Result<void>(const ProtectionActor& actor,
                                       std::string_view event_type,
                                       std::string_view outcome,
                                       std::string_view detail_code)>;
using ProtectionSystemAuditRecordCallback =
    std::function<common::Result<void>(const ProtectionAuditRecord& record)>;
using ProtectionAdministratorAuditRecordCallback =
    std::function<common::Result<void>(const ProtectionActor& actor,
                                       const ProtectionAuditRecord& record)>;

struct SystemProtectionDependencies {
  std::function<common::Result<SelfTestReport>()> run_self_tests;
  std::function<common::Result<integrity::IntegrityVerificationReport>()>
      run_integrity;
  ProtectionSystemAuditCallback append_system_audit;
  ProtectionAdministratorAuditCallback append_administrator_audit;
  ProtectionSystemAuditRecordCallback append_system_audit_record;
  ProtectionAdministratorAuditRecordCallback
      append_administrator_audit_record;
  std::function<common::Result<DeviceState>()> read_device_state;
  std::function<std::chrono::system_clock::time_point()> wall_now;
  std::function<std::chrono::steady_clock::time_point()> steady_now;
  std::chrono::steady_clock::duration automatic_interval{
      std::chrono::hours{24}};
};

class SystemProtectionService {
 public:
  explicit SystemProtectionService(SystemProtectionDependencies dependencies);
  ~SystemProtectionService();

  SystemProtectionService(const SystemProtectionService&) = delete;
  SystemProtectionService& operator=(const SystemProtectionService&) = delete;

  SystemProtectionSnapshot RunStartupChecks() noexcept;
  common::Result<SystemProtectionSnapshot> StartManualCheck(
      ProtectionSuite suite, ProtectionActor actor);
  SystemProtectionSnapshot Snapshot() const;
  bool RuntimeAllowed() const;
  bool RunRuntimeControlIfAllowed(const std::function<void()>& command);
  void SetRuntimeCallbacks(ProtectionRuntimeCallbacks callbacks);
  void Stop() noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::security
