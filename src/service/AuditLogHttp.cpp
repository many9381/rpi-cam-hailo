#include "camera_firmware/service/AuditLogHttp.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <string>
#include <utility>

#include <drogon/HttpTypes.h>

namespace camera_firmware::service {
namespace {

using QueryMember =
    std::optional<std::string> security::AuditQueryParameters::*;

constexpr std::array<std::pair<std::string_view, QueryMember>, 12>
    kAuditQueryMembers = {{
        {"from_seconds", &security::AuditQueryParameters::from_seconds},
        {"to_seconds", &security::AuditQueryParameters::to_seconds},
        {"event_type", &security::AuditQueryParameters::event_type},
        {"outcome", &security::AuditQueryParameters::outcome},
        {"actor_identity", &security::AuditQueryParameters::actor_identity},
        {"peer_ip", &security::AuditQueryParameters::peer_ip},
        {"subject_type", &security::AuditQueryParameters::subject_type},
        {"subject_identity", &security::AuditQueryParameters::subject_identity},
        {"sort_by", &security::AuditQueryParameters::sort_by},
        {"sort_direction", &security::AuditQueryParameters::sort_direction},
        {"limit", &security::AuditQueryParameters::limit},
        {"cursor", &security::AuditQueryParameters::cursor},
    }};

template <typename T>
common::Result<T> InvalidAuditQuery() {
  return common::Result<T>::Err(
      {"E_AUDIT_QUERY_INVALID", "Audit query is invalid."});
}

int HexDigit(char value) noexcept {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }
  return -1;
}

std::optional<std::string> PercentDecode(std::string_view encoded) {
  std::string decoded;
  decoded.reserve(encoded.size());
  for (std::size_t index = 0U; index < encoded.size(); ++index) {
    const char value = encoded[index];
    if (value == '+') {
      decoded.push_back(' ');
      continue;
    }
    if (value != '%') {
      decoded.push_back(value);
      continue;
    }
    if (encoded.size() - index < 3U) {
      return std::nullopt;
    }
    const int high = HexDigit(encoded[index + 1U]);
    const int low = HexDigit(encoded[index + 2U]);
    if (high < 0 || low < 0) {
      return std::nullopt;
    }
    decoded.push_back(static_cast<char>((high << 4) | low));
    index += 2U;
  }
  return decoded;
}

struct PublicAuditError {
  drogon::HttpStatusCode status;
  std::string_view code;
  std::string_view message;
};

PublicAuditError MapAuditError(std::string_view code) noexcept {
  if (code == "E_AUDIT_QUERY_INVALID") {
    return {drogon::k400BadRequest, "E_AUDIT_QUERY_INVALID",
            "Audit query is invalid."};
  }
  if (code == "E_AUDIT_FORBIDDEN" || code == "E_AUTHORIZATION_REQUIRED") {
    return {drogon::k403Forbidden, "E_AUTHORIZATION_REQUIRED",
            "Authorization is required."};
  }
  return {drogon::k503ServiceUnavailable, "E_AUDIT_UNAVAILABLE",
          "Audit records are temporarily unavailable."};
}

}  // namespace

common::Result<security::AuditQueryParameters> ParseAuditEventQuery(
    std::string_view raw_query) {
  if (raw_query.size() > kMaximumAuditRawQueryBytes) {
    return InvalidAuditQuery<security::AuditQueryParameters>();
  }
  security::AuditQueryParameters parameters;
  if (raw_query.empty()) {
    return common::Result<security::AuditQueryParameters>::Ok(
        std::move(parameters));
  }

  std::size_t segment_begin = 0U;
  while (segment_begin < raw_query.size()) {
    const std::size_t ampersand = raw_query.find('&', segment_begin);
    const std::size_t segment_end =
        ampersand == std::string_view::npos ? raw_query.size() : ampersand;
    const std::string_view segment =
        raw_query.substr(segment_begin, segment_end - segment_begin);
    if (segment.empty()) {
      return InvalidAuditQuery<security::AuditQueryParameters>();
    }
    const std::size_t equals = segment.find('=');
    if (equals == std::string_view::npos) {
      return InvalidAuditQuery<security::AuditQueryParameters>();
    }
    auto key = PercentDecode(segment.substr(0U, equals));
    auto value = PercentDecode(segment.substr(equals + 1U));
    if (!key.has_value() || !value.has_value()) {
      return InvalidAuditQuery<security::AuditQueryParameters>();
    }

    const auto member =
        std::find_if(kAuditQueryMembers.begin(), kAuditQueryMembers.end(),
                     [&key](const auto& entry) { return entry.first == *key; });
    if (member == kAuditQueryMembers.end() ||
        (parameters.*(member->second)).has_value()) {
      return InvalidAuditQuery<security::AuditQueryParameters>();
    }
    parameters.*(member->second) = std::move(*value);

    if (ampersand == std::string_view::npos) {
      break;
    }
    segment_begin = ampersand + 1U;
    if (segment_begin == raw_query.size()) {
      return InvalidAuditQuery<security::AuditQueryParameters>();
    }
  }
  return common::Result<security::AuditQueryParameters>::Ok(
      std::move(parameters));
}

common::Result<void> ValidateEmptyAuditStatusQuery(std::string_view raw_query) {
  if (!raw_query.empty() || raw_query.size() > kMaximumAuditRawQueryBytes) {
    return InvalidAuditQuery<void>();
  }
  return common::Result<void>::Ok();
}

Json::Value BuildAuditStatusJson(const security::AuditStatus& status) {
  Json::Value json(Json::objectValue);
  json["current_events"] = Json::UInt64(status.current_events);
  json["max_events"] = Json::UInt64(status.max_events);
  json["usage_percent"] = Json::UInt(status.usage_percent);
  json["warning"] = status.warning;
  json["rotated_event_count"] = Json::UInt64(status.rotated_event_count);
  json["last_rotation_at_seconds"] =
      status.last_rotation_at_seconds.has_value()
          ? Json::Value(Json::Int64(*status.last_rotation_at_seconds))
          : Json::Value(Json::nullValue);
  json["last_rotated_sequence"] =
      status.last_rotated_sequence.has_value()
          ? Json::Value(Json::Int64(*status.last_rotated_sequence))
          : Json::Value(Json::nullValue);
  return json;
}

Json::Value BuildAuditEventPageJson(const security::AuditEventPage& page) {
  Json::Value events(Json::arrayValue);
  for (const auto& event : page.events) {
    Json::Value json(Json::objectValue);
    json["sequence"] = Json::Int64(event.sequence);
    json["server_timestamp_seconds"] =
        Json::Int64(event.server_timestamp_seconds);
    json["event_type"] = event.event_type;
    json["outcome"] = event.outcome;
    json["actor_identity"] = event.actor_identity;
    json["peer_ip"] = event.peer_ip;
    json["detail_code"] = event.detail_code;
    json["subject_type"] = event.subject_type;
    json["subject_identity"] = event.subject_identity;
    events.append(std::move(json));
  }
  Json::Value json(Json::objectValue);
  json["events"] = std::move(events);
  json["next_cursor"] = page.next_cursor.has_value()
                            ? Json::Value(*page.next_cursor)
                            : Json::Value(Json::nullValue);
  return json;
}

drogon::HttpResponsePtr BuildAuditLogErrorResponse(const common::Error& error) {
  const auto mapped = MapAuditError(error.code);
  Json::Value json(Json::objectValue);
  json["code"] = std::string(mapped.code);
  json["message"] = std::string(mapped.message);
  auto response = drogon::HttpResponse::newHttpJsonResponse(std::move(json));
  response->setStatusCode(mapped.status);
  return response;
}

}  // namespace camera_firmware::service
