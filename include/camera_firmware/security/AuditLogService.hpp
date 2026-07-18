#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::security {

class SecurityStore;
struct Principal;

enum class AuditSortField {
  kTimestamp,
  kEventType,
  kOutcome,
  kActor,
  kPeerIp,
  kSubject
};

enum class AuditSortDirection { kAscending, kDescending };

struct AuditQueryParameters {
  std::optional<std::string> from_seconds;
  std::optional<std::string> to_seconds;
  std::optional<std::string> event_type;
  std::optional<std::string> outcome;
  std::optional<std::string> actor_identity;
  std::optional<std::string> peer_ip;
  std::optional<std::string> subject_type;
  std::optional<std::string> subject_identity;
  std::optional<std::string> sort_by;
  std::optional<std::string> sort_direction;
  std::optional<std::string> limit;
  std::optional<std::string> cursor;
};

struct AuditEvent {
  std::int64_t sequence{0};
  std::int64_t server_timestamp_seconds{0};
  std::string event_type;
  std::string outcome;
  std::string actor_identity;
  std::string peer_ip;
  std::string detail_code;
  std::string subject_type;
  std::string subject_identity;
};

struct AuditEventPage {
  std::vector<AuditEvent> events;
  std::optional<std::string> next_cursor;
};

struct AuditStatus {
  std::uint64_t current_events{0U};
  std::uint64_t max_events{0U};
  std::uint32_t usage_percent{0U};
  bool warning{false};
  std::uint64_t rotated_event_count{0U};
  std::optional<std::int64_t> last_rotation_at_seconds;
  std::optional<std::int64_t> last_rotated_sequence;
};

class AuditLogService {
 public:
  explicit AuditLogService(SecurityStore& store);

  common::Result<AuditStatus> ReadStatus(const Principal& actor) const;
  common::Result<AuditEventPage> ListEvents(
      const AuditQueryParameters& parameters,
      const Principal& actor) const;

 private:
  SecurityStore& store_;
};

}  // namespace camera_firmware::security
