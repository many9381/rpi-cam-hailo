#include "camera_firmware/security/AuditLogService.hpp"

#include <charconv>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <gio/gio.h>
#include <openssl/evp.h>

#include "camera_firmware/security/AuthService.hpp"
#include "camera_firmware/security/SecurityStore.hpp"

namespace camera_firmware::security {
namespace {

constexpr std::size_t kMaximumQueryTextBytes = 64U;
constexpr std::size_t kMaximumPeerIpBytes = 45U;
constexpr std::size_t kMaximumCursorBytes = 512U;
constexpr std::size_t kMaximumEpochSecondsDigits = 19U;
constexpr std::size_t kMaximumLimitDigits = 3U;
constexpr unsigned char kCursorVersion = 1U;
constexpr unsigned char kIntegerCursorKey = 0U;
constexpr unsigned char kTextCursorKey = 1U;
constexpr std::size_t kCursorHeaderBytes = 14U;

static_assert(static_cast<unsigned char>(AuditSortField::kTimestamp) == 0U);
static_assert(static_cast<unsigned char>(AuditSortField::kSubject) == 5U);
static_assert(
    static_cast<unsigned char>(AuditSortDirection::kAscending) == 0U);
static_assert(
    static_cast<unsigned char>(AuditSortDirection::kDescending) == 1U);

struct InetAddressDeleter {
  void operator()(GInetAddress* address) const noexcept {
    if (address != nullptr) {
      g_object_unref(address);
    }
  }
};

struct GCharDeleter {
  void operator()(gchar* value) const noexcept { g_free(value); }
};

struct DecodedAuditCursor {
  std::int64_t sequence{0};
  std::optional<std::int64_t> integer_key;
  std::optional<std::string> text_key;
};

struct ValidatedAuditQuery {
  std::optional<std::int64_t> from_seconds;
  std::optional<std::int64_t> to_seconds;
  std::optional<std::string> event_type;
  std::optional<std::string> outcome;
  std::optional<std::string> actor_identity;
  std::optional<std::string> peer_ip;
  std::optional<std::string> subject_type;
  std::optional<std::string> subject_identity;
  AuditSortField sort_field{AuditSortField::kTimestamp};
  AuditSortDirection sort_direction{AuditSortDirection::kDescending};
  std::uint32_t limit{50U};
  std::optional<DecodedAuditCursor> cursor;
};

bool IsValidText(std::string_view value,
                 std::size_t minimum_bytes,
                 std::size_t maximum_bytes) {
  return value.size() >= minimum_bytes && value.size() <= maximum_bytes &&
         value.find('\0') == std::string_view::npos &&
         g_utf8_validate(value.data(), static_cast<gssize>(value.size()),
                         nullptr);
}

bool ValidateOptionalText(const std::optional<std::string>& input,
                          std::size_t minimum_bytes,
                          std::size_t maximum_bytes,
                          std::optional<std::string>& output) {
  if (!input.has_value()) {
    return true;
  }
  if (!IsValidText(*input, minimum_bytes, maximum_bytes)) {
    return false;
  }
  output = *input;
  return true;
}

bool ParseNonnegativeInteger(const std::optional<std::string>& input,
                             std::size_t maximum_digits,
                             std::optional<std::int64_t>& output) {
  if (!input.has_value()) {
    return true;
  }
  if (input->empty() || input->size() > maximum_digits) {
    return false;
  }
  for (const char character : *input) {
    if (character < '0' || character > '9') {
      return false;
    }
  }
  std::int64_t parsed = 0;
  const char* const end = input->data() + input->size();
  const auto result = std::from_chars(input->data(), end, parsed);
  if (result.ec != std::errc{} || result.ptr != end || parsed < 0) {
    return false;
  }
  output = parsed;
  return true;
}

std::optional<std::string> NormalizePeerIp(const std::string& input) {
  if (!IsValidText(input, 1U, kMaximumPeerIpBytes)) {
    return std::nullopt;
  }
  std::unique_ptr<GInetAddress, InetAddressDeleter> address(
      g_inet_address_new_from_string(input.c_str()));
  if (!address) {
    return std::nullopt;
  }
  std::unique_ptr<gchar, GCharDeleter> normalized(
      g_inet_address_to_string(address.get()));
  if (!normalized) {
    return std::nullopt;
  }
  std::string value(normalized.get());
  if (!IsValidText(value, 2U, kMaximumPeerIpBytes)) {
    return std::nullopt;
  }
  return value;
}

std::optional<AuditSortField> ParseSortField(
    const std::optional<std::string>& input) {
  if (!input.has_value() || *input == "timestamp") {
    return AuditSortField::kTimestamp;
  }
  if (*input == "event_type") {
    return AuditSortField::kEventType;
  }
  if (*input == "outcome") {
    return AuditSortField::kOutcome;
  }
  if (*input == "actor") {
    return AuditSortField::kActor;
  }
  if (*input == "peer_ip") {
    return AuditSortField::kPeerIp;
  }
  if (*input == "subject") {
    return AuditSortField::kSubject;
  }
  return std::nullopt;
}

std::optional<AuditSortDirection> ParseSortDirection(
    const std::optional<std::string>& input) {
  if (!input.has_value() || *input == "desc") {
    return AuditSortDirection::kDescending;
  }
  if (*input == "asc") {
    return AuditSortDirection::kAscending;
  }
  return std::nullopt;
}

void AppendUint64(std::vector<unsigned char>& output, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    output.push_back(static_cast<unsigned char>((value >> shift) & 0xffU));
  }
}

std::uint64_t ReadUint64(const std::vector<unsigned char>& input,
                         std::size_t offset) {
  std::uint64_t value = 0U;
  for (std::size_t index = 0; index < 8U; ++index) {
    value = (value << 8U) | input[offset + index];
  }
  return value;
}

std::optional<std::string> EncodeBase64Url(
    const std::vector<unsigned char>& input) {
  if (input.empty() ||
      input.size() > static_cast<std::size_t>(
                         std::numeric_limits<int>::max())) {
    return std::nullopt;
  }
  const std::size_t encoded_size = 4U * ((input.size() + 2U) / 3U);
  std::vector<unsigned char> buffer(encoded_size + 1U, 0U);
  const int written = EVP_EncodeBlock(
      buffer.data(), input.data(), static_cast<int>(input.size()));
  if (written < 0 || static_cast<std::size_t>(written) != encoded_size) {
    return std::nullopt;
  }
  std::string encoded(reinterpret_cast<const char*>(buffer.data()),
                      encoded_size);
  for (char& character : encoded) {
    if (character == '+') {
      character = '-';
    } else if (character == '/') {
      character = '_';
    }
  }
  while (!encoded.empty() && encoded.back() == '=') {
    encoded.pop_back();
  }
  return encoded;
}

bool IsBase64UrlCharacter(char character) {
  return (character >= 'A' && character <= 'Z') ||
         (character >= 'a' && character <= 'z') ||
         (character >= '0' && character <= '9') || character == '-' ||
         character == '_';
}

std::optional<std::vector<unsigned char>> DecodeBase64Url(
    std::string_view encoded) {
  if (encoded.empty() || encoded.size() > kMaximumCursorBytes ||
      encoded.size() % 4U == 1U) {
    return std::nullopt;
  }
  std::string standard;
  standard.reserve(encoded.size() + 3U);
  for (const char character : encoded) {
    if (!IsBase64UrlCharacter(character)) {
      return std::nullopt;
    }
    standard.push_back(character == '-'   ? '+'
                       : character == '_' ? '/'
                                          : character);
  }
  const std::size_t padding = (4U - standard.size() % 4U) % 4U;
  standard.append(padding, '=');
  std::vector<unsigned char> decoded(3U * (standard.size() / 4U));
  const int decoded_size = EVP_DecodeBlock(
      decoded.data(), reinterpret_cast<const unsigned char*>(standard.data()),
      static_cast<int>(standard.size()));
  if (decoded_size < 0 ||
      static_cast<std::size_t>(decoded_size) < padding) {
    return std::nullopt;
  }
  decoded.resize(static_cast<std::size_t>(decoded_size) - padding);
  const auto canonical = EncodeBase64Url(decoded);
  if (!canonical.has_value() || *canonical != encoded) {
    return std::nullopt;
  }
  return decoded;
}

bool IsValidCursorText(AuditSortField field, const std::string& value) {
  const std::size_t minimum =
      field == AuditSortField::kSubject ? 0U : 1U;
  if (!IsValidText(value, minimum, kMaximumQueryTextBytes)) {
    return false;
  }
  if (field == AuditSortField::kOutcome) {
    return value == "success" || value == "failure";
  }
  if (field == AuditSortField::kPeerIp) {
    const auto normalized = NormalizePeerIp(value);
    return normalized.has_value() && *normalized == value;
  }
  return true;
}

std::optional<DecodedAuditCursor> DecodeCursor(
    std::string_view encoded,
    AuditSortField requested_field,
    AuditSortDirection requested_direction) {
  const auto decoded = DecodeBase64Url(encoded);
  if (!decoded.has_value() || decoded->size() < kCursorHeaderBytes) {
    return std::nullopt;
  }
  const auto& bytes = *decoded;
  if (bytes[0] != kCursorVersion || bytes[1] > 5U || bytes[2] > 1U ||
      bytes[3] > 1U) {
    return std::nullopt;
  }
  const auto field = static_cast<AuditSortField>(bytes[1]);
  const auto direction = static_cast<AuditSortDirection>(bytes[2]);
  if (field != requested_field || direction != requested_direction) {
    return std::nullopt;
  }
  const bool expects_integer = field == AuditSortField::kTimestamp;
  if (bytes[3] !=
      (expects_integer ? kIntegerCursorKey : kTextCursorKey)) {
    return std::nullopt;
  }
  const std::uint64_t sequence = ReadUint64(bytes, 4U);
  if (sequence == 0U ||
      sequence >
          static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
    return std::nullopt;
  }
  const std::size_t key_length =
      static_cast<std::size_t>(bytes[12]) << 8U | bytes[13];
  if (key_length > kMaximumQueryTextBytes ||
      bytes.size() != kCursorHeaderBytes + key_length) {
    return std::nullopt;
  }

  DecodedAuditCursor cursor;
  cursor.sequence = static_cast<std::int64_t>(sequence);
  if (expects_integer) {
    if (key_length != 8U) {
      return std::nullopt;
    }
    const std::uint64_t key = ReadUint64(bytes, kCursorHeaderBytes);
    if (key > static_cast<std::uint64_t>(
                  std::numeric_limits<std::int64_t>::max())) {
      return std::nullopt;
    }
    cursor.integer_key = static_cast<std::int64_t>(key);
  } else {
    std::string key(bytes.begin() + kCursorHeaderBytes, bytes.end());
    if (!IsValidCursorText(field, key)) {
      return std::nullopt;
    }
    cursor.text_key = std::move(key);
  }
  return cursor;
}

std::optional<std::string> EncodeCursor(const AuditEvent& event,
                                        AuditSortField field,
                                        AuditSortDirection direction) {
  if (event.sequence <= 0) {
    return std::nullopt;
  }
  std::vector<unsigned char> key;
  unsigned char key_kind = kTextCursorKey;
  if (field == AuditSortField::kTimestamp) {
    if (event.server_timestamp_seconds < 0) {
      return std::nullopt;
    }
    key_kind = kIntegerCursorKey;
    AppendUint64(key,
                 static_cast<std::uint64_t>(event.server_timestamp_seconds));
  } else {
    const std::string* text = nullptr;
    switch (field) {
      case AuditSortField::kEventType:
        text = &event.event_type;
        break;
      case AuditSortField::kOutcome:
        text = &event.outcome;
        break;
      case AuditSortField::kActor:
        text = &event.actor_identity;
        break;
      case AuditSortField::kPeerIp:
        text = &event.peer_ip;
        break;
      case AuditSortField::kSubject:
        text = &event.subject_identity;
        break;
      case AuditSortField::kTimestamp:
        return std::nullopt;
    }
    if (text == nullptr || !IsValidCursorText(field, *text)) {
      return std::nullopt;
    }
    key.assign(text->begin(), text->end());
  }
  if (key.size() > kMaximumQueryTextBytes) {
    return std::nullopt;
  }

  std::vector<unsigned char> payload;
  payload.reserve(kCursorHeaderBytes + key.size());
  payload.push_back(kCursorVersion);
  payload.push_back(static_cast<unsigned char>(field));
  payload.push_back(static_cast<unsigned char>(direction));
  payload.push_back(key_kind);
  AppendUint64(payload, static_cast<std::uint64_t>(event.sequence));
  payload.push_back(static_cast<unsigned char>((key.size() >> 8U) & 0xffU));
  payload.push_back(static_cast<unsigned char>(key.size() & 0xffU));
  payload.insert(payload.end(), key.begin(), key.end());
  return EncodeBase64Url(payload);
}

std::optional<ValidatedAuditQuery> ValidateAuditQuery(
    const AuditQueryParameters& parameters) {
  ValidatedAuditQuery query;
  if (!ParseNonnegativeInteger(parameters.from_seconds,
                               kMaximumEpochSecondsDigits,
                               query.from_seconds) ||
      !ParseNonnegativeInteger(parameters.to_seconds,
                               kMaximumEpochSecondsDigits,
                               query.to_seconds) ||
      (query.from_seconds.has_value() && query.to_seconds.has_value() &&
       *query.from_seconds > *query.to_seconds) ||
      !ValidateOptionalText(parameters.event_type, 1U,
                            kMaximumQueryTextBytes, query.event_type) ||
      !ValidateOptionalText(parameters.outcome, 1U, 7U, query.outcome) ||
      !ValidateOptionalText(parameters.actor_identity, 1U,
                            kMaximumQueryTextBytes, query.actor_identity) ||
      !ValidateOptionalText(parameters.subject_type, 1U,
                            kMaximumQueryTextBytes, query.subject_type) ||
      !ValidateOptionalText(parameters.subject_identity, 1U,
                            kMaximumQueryTextBytes,
                            query.subject_identity)) {
    return std::nullopt;
  }
  if (query.outcome.has_value() && *query.outcome != "success" &&
      *query.outcome != "failure") {
    return std::nullopt;
  }
  if (parameters.peer_ip.has_value()) {
    query.peer_ip = NormalizePeerIp(*parameters.peer_ip);
    if (!query.peer_ip.has_value()) {
      return std::nullopt;
    }
  }

  const auto sort_field = ParseSortField(parameters.sort_by);
  const auto sort_direction = ParseSortDirection(parameters.sort_direction);
  if (!sort_field.has_value() || !sort_direction.has_value()) {
    return std::nullopt;
  }
  query.sort_field = *sort_field;
  query.sort_direction = *sort_direction;

  if (parameters.limit.has_value()) {
    std::optional<std::int64_t> parsed_limit;
    if (!ParseNonnegativeInteger(parameters.limit, kMaximumLimitDigits,
                                 parsed_limit) ||
        !parsed_limit.has_value() || *parsed_limit < 1 || *parsed_limit > 100) {
      return std::nullopt;
    }
    query.limit = static_cast<std::uint32_t>(*parsed_limit);
  }
  if (parameters.cursor.has_value()) {
    query.cursor = DecodeCursor(*parameters.cursor, query.sort_field,
                                query.sort_direction);
    if (!query.cursor.has_value()) {
      return std::nullopt;
    }
  }
  return query;
}

common::Result<AuditEventPage> InvalidAuditQuery() {
  return common::Result<AuditEventPage>::Err(
      {"E_AUDIT_QUERY_INVALID", "audit query is invalid"});
}

common::Result<AuditEventPage> UnavailableAuditEvents() {
  return common::Result<AuditEventPage>::Err(
      {"E_AUDIT_UNAVAILABLE", "audit events are unavailable"});
}

}  // namespace

AuditLogService::AuditLogService(SecurityStore& store) : store_(store) {}

common::Result<AuditStatus> AuditLogService::ReadStatus(
    const Principal& actor) const {
  if (actor.role != UserRole::kAdministrator) {
    return common::Result<AuditStatus>::Err(
        {"E_AUDIT_FORBIDDEN", "audit status access is forbidden"});
  }

  auto stored = store_.ReadAuditStatus();
  if (!stored.ok()) {
    return common::Result<AuditStatus>::Err(
        {"E_AUDIT_UNAVAILABLE", "audit status is unavailable"});
  }
  const auto& snapshot = stored.value();
  return common::Result<AuditStatus>::Ok(
      {snapshot.current_events,
       snapshot.max_events,
       snapshot.usage_percent,
       snapshot.warning,
       snapshot.rotated_event_count,
       snapshot.last_rotation_at_seconds,
       snapshot.last_rotated_sequence});
}

common::Result<AuditEventPage> AuditLogService::ListEvents(
    const AuditQueryParameters& parameters,
    const Principal& actor) const {
  if (actor.role != UserRole::kAdministrator) {
    return common::Result<AuditEventPage>::Err(
        {"E_AUDIT_FORBIDDEN", "audit event access is forbidden"});
  }
  const auto validated = ValidateAuditQuery(parameters);
  if (!validated.has_value()) {
    return InvalidAuditQuery();
  }

  SecurityStore::AuditEventQuery query;
  query.from_seconds = validated->from_seconds;
  query.to_seconds = validated->to_seconds;
  query.event_type = validated->event_type;
  query.outcome = validated->outcome;
  query.actor_identity = validated->actor_identity;
  query.peer_ip = validated->peer_ip;
  query.subject_type = validated->subject_type;
  query.subject_identity = validated->subject_identity;
  switch (validated->sort_field) {
    case AuditSortField::kTimestamp:
      query.sort_field = SecurityStore::AuditEventSortField::kTimestamp;
      break;
    case AuditSortField::kEventType:
      query.sort_field = SecurityStore::AuditEventSortField::kEventType;
      break;
    case AuditSortField::kOutcome:
      query.sort_field = SecurityStore::AuditEventSortField::kOutcome;
      break;
    case AuditSortField::kActor:
      query.sort_field = SecurityStore::AuditEventSortField::kActor;
      break;
    case AuditSortField::kPeerIp:
      query.sort_field = SecurityStore::AuditEventSortField::kPeerIp;
      break;
    case AuditSortField::kSubject:
      query.sort_field = SecurityStore::AuditEventSortField::kSubject;
      break;
  }
  query.sort_direction =
      validated->sort_direction == AuditSortDirection::kAscending
          ? SecurityStore::AuditEventSortDirection::kAscending
          : SecurityStore::AuditEventSortDirection::kDescending;
  query.limit = validated->limit;
  if (validated->cursor.has_value()) {
    query.cursor = SecurityStore::AuditEventCursor{
        validated->cursor->sequence, validated->cursor->integer_key,
        validated->cursor->text_key};
  }

  auto stored = store_.ReadAuditEvents(query);
  if (!stored.ok()) {
    return UnavailableAuditEvents();
  }
  auto result = std::move(stored).value();
  AuditEventPage page;
  page.events.reserve(result.events.size());
  for (auto& event : result.events) {
    page.events.push_back(
        {event.sequence,
         event.server_timestamp_seconds,
         std::move(event.event_type),
         std::move(event.outcome),
         std::move(event.actor_identity),
         std::move(event.peer_ip),
         std::move(event.detail_code),
         std::move(event.subject_type),
         std::move(event.subject_identity)});
  }
  if (result.has_more) {
    if (page.events.empty()) {
      return UnavailableAuditEvents();
    }
    page.next_cursor = EncodeCursor(page.events.back(), validated->sort_field,
                                    validated->sort_direction);
    if (!page.next_cursor.has_value()) {
      return UnavailableAuditEvents();
    }
  }
  return common::Result<AuditEventPage>::Ok(std::move(page));
}

}  // namespace camera_firmware::security
