#include "camera_firmware/service/UserManagementHttp.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>

#include <glib.h>

#include "camera_firmware/service/SecurityRequestGate.hpp"

namespace camera_firmware::service {
namespace {

constexpr std::size_t kMaximumUsernameBytes = 32U;
constexpr std::size_t kMaximumPasswordBytes = 128U;

#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
using SecretCleanupObserverForTesting = void (*)(
    std::string_view,
    common::ZeroizeAudit,
    common::ZeroizeAudit) noexcept;

std::atomic<SecretCleanupObserverForTesting>&
SecretCleanupObserverStorageForTesting() {
  static std::atomic<SecretCleanupObserverForTesting> observer{nullptr};
  return observer;
}
#endif

void NotifySecretCleanup(std::string_view label,
                         common::ZeroizeAudit before,
                         common::ZeroizeAudit after) noexcept {
#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
  const auto observer = SecretCleanupObserverStorageForTesting().load(
      std::memory_order_acquire);
  if (observer != nullptr) {
    try {
      observer(label, before, after);
    } catch (...) {
      // swallowed: test observer errors must not escape this noexcept notifier
    }
  }
#else
  (void)label;
  (void)before;
  (void)after;
#endif
}

class SecretCleanupGuard {
 public:
  SecretCleanupGuard(common::SecureBytes& secret,
                     std::string_view label) noexcept
      : secret_(&secret), label_(label) {}

  ~SecretCleanupGuard() {
    if (secret_ == nullptr) {
      return;
    }
    const auto before = secret_->zeroize_audit();
    secret_->clear();
    const auto after = secret_->zeroize_audit();
    NotifySecretCleanup(label_, before, after);
  }

  SecretCleanupGuard(const SecretCleanupGuard&) = delete;
  SecretCleanupGuard& operator=(const SecretCleanupGuard&) = delete;

  void Release() noexcept { secret_ = nullptr; }

 private:
  common::SecureBytes* secret_;
  std::string_view label_;
};

template <typename T>
common::Result<T> InvalidRequest(std::string code = "E_INVALID_REQUEST") {
  return common::Result<T>::Err(
      {std::move(code), "user management request is invalid"});
}

bool IsJsonContentType(std::string_view content_type) {
  std::string normalized(content_type);
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](unsigned char value) {
                   return static_cast<char>(std::tolower(value));
                 });
  return normalized == "application/json" ||
         normalized == "application/json; charset=utf-8";
}

int JsonHexValue(unsigned char value) {
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

struct DecodedJsonString {
  std::size_t offset{0U};
  std::size_t size{0U};
};

class StrictInSituJsonObjectParser {
 public:
  explicit StrictInSituJsonObjectParser(common::SecureBytes& body)
      : body_(body) {}

  bool Begin() {
    SkipWhitespace();
    if (!Consume('{')) {
      return false;
    }
    SkipWhitespace();
    return !Peek('}');
  }

  bool NextKey(DecodedJsonString& key, bool& was_escaped) {
    was_escaped = false;
    if (!ParseString(key, &was_escaped)) {
      return false;
    }
    SkipWhitespace();
    if (!Consume(':')) {
      return false;
    }
    SkipWhitespace();
    return true;
  }

  bool NextField(bool& complete) {
    SkipWhitespace();
    if (Consume('}')) {
      SkipWhitespace();
      complete = position_ == body_.size();
      return complete;
    }
    if (!Consume(',')) {
      return false;
    }
    SkipWhitespace();
    complete = false;
    return true;
  }

  bool ParseString(DecodedJsonString& decoded, bool* was_escaped = nullptr) {
    if (!Consume('"')) {
      return false;
    }
    const std::size_t output_start = position_;
    std::size_t output = output_start;
    while (position_ < body_.size()) {
      const unsigned char value = body_.data()[position_++];
      if (value == '"') {
        decoded = {output_start, output - output_start};
        return std::find(body_.data() + decoded.offset,
                         body_.data() + decoded.offset + decoded.size,
                         static_cast<unsigned char>(0U)) ==
                   body_.data() + decoded.offset + decoded.size &&
               g_utf8_validate(
                   reinterpret_cast<const char*>(body_.data() + decoded.offset),
                   static_cast<gssize>(decoded.size), nullptr);
      }
      if (value < 0x20U) {
        return false;
      }
      if (value != '\\') {
        body_.data()[output++] = value;
        continue;
      }
      if (was_escaped != nullptr) {
        *was_escaped = true;
      }
      if (position_ >= body_.size()) {
        return false;
      }
      const unsigned char escaped = body_.data()[position_++];
      switch (escaped) {
        case '"':
        case '\\':
        case '/':
          body_.data()[output++] = escaped;
          break;
        case 'b':
          body_.data()[output++] = '\b';
          break;
        case 'f':
          body_.data()[output++] = '\f';
          break;
        case 'n':
          body_.data()[output++] = '\n';
          break;
        case 'r':
          body_.data()[output++] = '\r';
          break;
        case 't':
          body_.data()[output++] = '\t';
          break;
        case 'u': {
          std::uint32_t code_point = 0U;
          if (!ParseHexCodeUnit(code_point)) {
            return false;
          }
          if (code_point >= 0xd800U && code_point <= 0xdbffU) {
            if (position_ + 2U > body_.size() ||
                body_.data()[position_] != '\\' ||
                body_.data()[position_ + 1U] != 'u') {
              return false;
            }
            position_ += 2U;
            std::uint32_t low = 0U;
            if (!ParseHexCodeUnit(low) || low < 0xdc00U || low > 0xdfffU) {
              return false;
            }
            code_point = 0x10000U + ((code_point - 0xd800U) << 10U) +
                         (low - 0xdc00U);
          } else if (code_point >= 0xdc00U && code_point <= 0xdfffU) {
            return false;
          }
          EncodeUtf8(code_point, output);
          break;
        }
        default:
          return false;
      }
    }
    return false;
  }

  bool ParseBool(bool& value) {
    constexpr std::string_view kTrue = "true";
    constexpr std::string_view kFalse = "false";
    if (Matches(kTrue)) {
      position_ += kTrue.size();
      value = true;
      return true;
    }
    if (Matches(kFalse)) {
      position_ += kFalse.size();
      value = false;
      return true;
    }
    return false;
  }

  bool KeyEquals(const DecodedJsonString& key, std::string_view expected) const {
    return key.size == expected.size() &&
           std::equal(expected.begin(), expected.end(),
                      body_.data() + key.offset);
  }

  void CopyString(const DecodedJsonString& source, std::string& destination) {
    destination.assign(
        reinterpret_cast<const char*>(body_.data() + source.offset),
        source.size);
  }

  void CopySecret(const DecodedJsonString& source,
                  common::SecureBytes& destination) {
    destination.assign(body_.data() + source.offset, source.size);
  }

 private:
  bool ParseHexCodeUnit(std::uint32_t& code_unit) {
    if (position_ + 4U > body_.size()) {
      return false;
    }
    code_unit = 0U;
    for (std::size_t count = 0U; count < 4U; ++count) {
      const int digit = JsonHexValue(body_.data()[position_++]);
      if (digit < 0) {
        return false;
      }
      code_unit = (code_unit << 4U) | static_cast<std::uint32_t>(digit);
    }
    return true;
  }

  void EncodeUtf8(std::uint32_t code_point, std::size_t& output) {
    if (code_point <= 0x7fU) {
      body_.data()[output++] = static_cast<unsigned char>(code_point);
    } else if (code_point <= 0x7ffU) {
      body_.data()[output++] =
          static_cast<unsigned char>(0xc0U | (code_point >> 6U));
      body_.data()[output++] =
          static_cast<unsigned char>(0x80U | (code_point & 0x3fU));
    } else if (code_point <= 0xffffU) {
      body_.data()[output++] =
          static_cast<unsigned char>(0xe0U | (code_point >> 12U));
      body_.data()[output++] = static_cast<unsigned char>(
          0x80U | ((code_point >> 6U) & 0x3fU));
      body_.data()[output++] =
          static_cast<unsigned char>(0x80U | (code_point & 0x3fU));
    } else {
      body_.data()[output++] =
          static_cast<unsigned char>(0xf0U | (code_point >> 18U));
      body_.data()[output++] = static_cast<unsigned char>(
          0x80U | ((code_point >> 12U) & 0x3fU));
      body_.data()[output++] = static_cast<unsigned char>(
          0x80U | ((code_point >> 6U) & 0x3fU));
      body_.data()[output++] =
          static_cast<unsigned char>(0x80U | (code_point & 0x3fU));
    }
  }

  bool Consume(unsigned char expected) {
    if (position_ >= body_.size() || body_.data()[position_] != expected) {
      return false;
    }
    ++position_;
    return true;
  }

  bool Peek(unsigned char expected) const {
    return position_ < body_.size() && body_.data()[position_] == expected;
  }

  bool Matches(std::string_view value) const {
    return position_ + value.size() <= body_.size() &&
           std::equal(value.begin(), value.end(), body_.data() + position_);
  }

  void SkipWhitespace() {
    while (position_ < body_.size()) {
      const unsigned char value = body_.data()[position_];
      if (value != ' ' && value != '\t' && value != '\r' && value != '\n') {
        return;
      }
      ++position_;
    }
  }

  common::SecureBytes& body_;
  std::size_t position_{0U};
};

common::Result<void> ValidateJsonBody(common::SecureBytes& body,
                                      std::string_view content_type) {
  if (body.size() > kMaximumSecurityBodyBytes) {
    return InvalidRequest<void>("E_REQUEST_TOO_LARGE");
  }
  if (body.size() == 0U || !IsJsonContentType(content_type) ||
      std::find(body.data(), body.data() + body.size(),
                static_cast<unsigned char>(0U)) != body.data() + body.size() ||
      !g_utf8_validate(reinterpret_cast<const char*>(body.data()),
                       static_cast<gssize>(body.size()), nullptr)) {
    return InvalidRequest<void>();
  }
  return common::Result<void>::Ok();
}

common::Result<common::SecureBytes> SecureJsonBody(std::string_view body) {
  if (body.size() > kMaximumSecurityBodyBytes) {
    return InvalidRequest<common::SecureBytes>("E_REQUEST_TOO_LARGE");
  }
  common::SecureBytes secure_body;
  secure_body.assign(reinterpret_cast<const unsigned char*>(body.data()),
                     body.size());
  return common::Result<common::SecureBytes>::Ok(std::move(secure_body));
}

bool IsValidPasswordSize(const common::SecureBytes& password) {
  return password.size() >= 1U && password.size() <= kMaximumPasswordBytes;
}

bool IsValidUsernameSize(std::string_view username) {
  return !username.empty() && username.size() <= kMaximumUsernameBytes;
}

std::string_view RoleName(security::UserRole role) {
  return role == security::UserRole::kAdministrator ? "administrator" : "viewer";
}

struct PublicError {
  drogon::HttpStatusCode status;
  std::string_view code;
  std::string_view message;
};

template <std::size_t Size>
bool ContainsCode(const std::array<std::string_view, Size>& codes,
                  std::string_view code) {
  return std::find(codes.begin(), codes.end(), code) != codes.end();
}

bool IsConflictCode(std::string_view code) {
  constexpr std::array<std::string_view, 9> kCodes = {
      "E_USER_DUPLICATE", "E_VIEWER_LIMIT", "E_USER_PROTECTED",
      "E_USER_CONFLICT", "E_PASSWORD_REUSE", "E_MANAGEMENT_IP_DUPLICATE",
      "E_MANAGEMENT_IP_LIMIT", "E_MANAGEMENT_IP_ROLE_MISMATCH",
      "E_MANAGEMENT_IP_PROTECTED"};
  return ContainsCode(kCodes, code);
}

bool IsPolicyCode(std::string_view code) {
  constexpr std::array<std::string_view, 8> kCodes = {
      "E_USERNAME_RESERVED", "E_USERNAME_FORMAT", "E_PASSWORD_LENGTH",
      "E_PASSWORD_ASCII", "E_PASSWORD_USERNAME", "E_PASSWORD_CLASS",
      "E_PASSWORD_REPEAT", "E_PASSWORD_SEQUENCE"};
  return ContainsCode(kCodes, code);
}

PublicError MapPublicError(std::string_view code) {
  if (code == "E_REQUEST_TOO_LARGE") {
    return {drogon::k413RequestEntityTooLarge, "E_REQUEST_TOO_LARGE",
            "request could not be processed"};
  }
  if (code == "E_USER_FORBIDDEN" ||
      code == "E_MANAGEMENT_IP_FORBIDDEN" ||
      code == "E_AUTHORIZATION_REQUIRED") {
    return {drogon::k403Forbidden, "E_AUTHORIZATION_REQUIRED",
            "authorization required"};
  }
  if (code == "E_INVALID_REQUEST") {
    return {drogon::k400BadRequest, "E_INVALID_REQUEST",
            "request could not be processed"};
  }
  if (code == "E_CURRENT_PASSWORD" || code == "E_MANAGEMENT_IP_INVALID" ||
      IsPolicyCode(code)) {
    return {drogon::k400BadRequest, code,
            "user management request is invalid"};
  }
  if (code == "E_USER_NOT_FOUND" || code == "E_MANAGEMENT_IP_NOT_FOUND") {
    return {drogon::k404NotFound, code,
            "user management resource was not found"};
  }
  if (IsConflictCode(code)) {
    return {drogon::k409Conflict, code,
            "user management request conflicts with current state"};
  }
  return {drogon::k503ServiceUnavailable, "E_USER_MANAGEMENT_UNAVAILABLE",
          "user management is unavailable"};
}

}  // namespace

#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
namespace internal {

using UserManagementSecretCleanupObserverForTesting = void (*)(
    std::string_view,
    common::ZeroizeAudit,
    common::ZeroizeAudit) noexcept;

void SetUserManagementSecretCleanupObserverForTesting(
    UserManagementSecretCleanupObserverForTesting observer) noexcept {
  SecretCleanupObserverStorageForTesting().store(observer,
                                                  std::memory_order_release);
}

void ResetUserManagementSecretCleanupObserverForTesting() noexcept {
  SecretCleanupObserverStorageForTesting().store(nullptr,
                                                  std::memory_order_release);
}

}  // namespace internal
#endif

common::Result<ParsedCreateViewerRequest> ParseCreateViewerJson(
    common::SecureBytes body,
    std::string_view content_type) {
  SecretCleanupGuard body_cleanup(body, "create.request_body");
  const auto valid = ValidateJsonBody(body, content_type);
  if (!valid.ok()) {
    return common::Result<ParsedCreateViewerRequest>::Err(valid.error());
  }

  ParsedCreateViewerRequest parsed;
  SecretCleanupGuard password_cleanup(parsed.password, "create.password");
  StrictInSituJsonObjectParser parser(body);
  if (!parser.Begin()) {
    return InvalidRequest<ParsedCreateViewerRequest>();
  }
  bool username = false;
  bool password = false;
  for (;;) {
    DecodedJsonString key;
    bool escaped = false;
    DecodedJsonString value;
    if (!parser.NextKey(key, escaped) || escaped || !parser.ParseString(value)) {
      return InvalidRequest<ParsedCreateViewerRequest>();
    }
    if (parser.KeyEquals(key, "username") && !username) {
      parser.CopyString(value, parsed.username);
      username = true;
    } else if (parser.KeyEquals(key, "password") && !password) {
      parser.CopySecret(value, parsed.password);
      password = true;
    } else {
      return InvalidRequest<ParsedCreateViewerRequest>();
    }
    bool complete = false;
    if (!parser.NextField(complete)) {
      return InvalidRequest<ParsedCreateViewerRequest>();
    }
    if (complete) {
      break;
    }
  }
  if (!username || !password || !IsValidUsernameSize(parsed.username) ||
      !IsValidPasswordSize(parsed.password)) {
    return InvalidRequest<ParsedCreateViewerRequest>();
  }
  auto result =
      common::Result<ParsedCreateViewerRequest>::Ok(std::move(parsed));
  password_cleanup.Release();
  return result;
}

common::Result<ParsedSetViewerEnabledRequest> ParseSetViewerEnabledJson(
    std::string_view body,
    std::string_view content_type) {
  auto secure_body = SecureJsonBody(body);
  if (!secure_body.ok()) {
    return common::Result<ParsedSetViewerEnabledRequest>::Err(
        secure_body.error());
  }
  auto valid = ValidateJsonBody(secure_body.value(), content_type);
  if (!valid.ok()) {
    return common::Result<ParsedSetViewerEnabledRequest>::Err(valid.error());
  }

  ParsedSetViewerEnabledRequest parsed;
  StrictInSituJsonObjectParser parser(secure_body.value());
  if (!parser.Begin()) {
    return InvalidRequest<ParsedSetViewerEnabledRequest>();
  }
  DecodedJsonString key;
  bool escaped = false;
  bool complete = false;
  if (!parser.NextKey(key, escaped) || escaped ||
      !parser.KeyEquals(key, "enabled") || !parser.ParseBool(parsed.enabled) ||
      !parser.NextField(complete) || !complete) {
    return InvalidRequest<ParsedSetViewerEnabledRequest>();
  }
  return common::Result<ParsedSetViewerEnabledRequest>::Ok(parsed);
}

common::Result<ParsedPasswordResetRequest> ParsePasswordResetJson(
    common::SecureBytes body,
    std::string_view content_type) {
  SecretCleanupGuard body_cleanup(body, "reset.request_body");
  const auto valid = ValidateJsonBody(body, content_type);
  if (!valid.ok()) {
    return common::Result<ParsedPasswordResetRequest>::Err(valid.error());
  }

  ParsedPasswordResetRequest parsed;
  SecretCleanupGuard password_cleanup(parsed.password, "reset.password");
  StrictInSituJsonObjectParser parser(body);
  DecodedJsonString key;
  DecodedJsonString value;
  bool escaped = false;
  bool complete = false;
  if (!parser.Begin() || !parser.NextKey(key, escaped) || escaped ||
      !parser.KeyEquals(key, "password") || !parser.ParseString(value) ||
      !parser.NextField(complete) || !complete) {
    return InvalidRequest<ParsedPasswordResetRequest>();
  }
  parser.CopySecret(value, parsed.password);
  if (!IsValidPasswordSize(parsed.password)) {
    return InvalidRequest<ParsedPasswordResetRequest>();
  }
  auto result =
      common::Result<ParsedPasswordResetRequest>::Ok(std::move(parsed));
  password_cleanup.Release();
  return result;
}

common::Result<ParsedOwnPasswordRequest> ParseOwnPasswordJson(
    common::SecureBytes body,
    std::string_view content_type) {
  SecretCleanupGuard body_cleanup(body, "own.request_body");
  const auto valid = ValidateJsonBody(body, content_type);
  if (!valid.ok()) {
    return common::Result<ParsedOwnPasswordRequest>::Err(valid.error());
  }

  ParsedOwnPasswordRequest parsed;
  SecretCleanupGuard current_cleanup(parsed.current_password,
                                     "own.current_password");
  SecretCleanupGuard replacement_cleanup(parsed.replacement_password,
                                         "own.replacement_password");
  StrictInSituJsonObjectParser parser(body);
  if (!parser.Begin()) {
    return InvalidRequest<ParsedOwnPasswordRequest>();
  }
  bool current = false;
  bool replacement = false;
  for (;;) {
    DecodedJsonString key;
    DecodedJsonString value;
    bool escaped = false;
    if (!parser.NextKey(key, escaped) || escaped || !parser.ParseString(value)) {
      return InvalidRequest<ParsedOwnPasswordRequest>();
    }
    if (parser.KeyEquals(key, "current_password") && !current) {
      parser.CopySecret(value, parsed.current_password);
      current = true;
    } else if (parser.KeyEquals(key, "replacement_password") &&
               !replacement) {
      parser.CopySecret(value, parsed.replacement_password);
      replacement = true;
    } else {
      return InvalidRequest<ParsedOwnPasswordRequest>();
    }
    bool complete = false;
    if (!parser.NextField(complete)) {
      return InvalidRequest<ParsedOwnPasswordRequest>();
    }
    if (complete) {
      break;
    }
  }
  if (!current || !replacement || !IsValidPasswordSize(parsed.current_password) ||
      !IsValidPasswordSize(parsed.replacement_password)) {
    return InvalidRequest<ParsedOwnPasswordRequest>();
  }
  auto result = common::Result<ParsedOwnPasswordRequest>::Ok(
      std::move(parsed));
  current_cleanup.Release();
  replacement_cleanup.Release();
  return result;
}

common::Result<ParsedManagementIpRequest> ParseManagementIpJson(
    std::string_view body,
    std::string_view content_type) {
  auto secure_body = SecureJsonBody(body);
  if (!secure_body.ok()) {
    return common::Result<ParsedManagementIpRequest>::Err(secure_body.error());
  }
  const auto valid = ValidateJsonBody(secure_body.value(), content_type);
  if (!valid.ok()) {
    return common::Result<ParsedManagementIpRequest>::Err(valid.error());
  }

  ParsedManagementIpRequest parsed;
  StrictInSituJsonObjectParser parser(secure_body.value());
  DecodedJsonString key;
  DecodedJsonString value;
  bool escaped = false;
  bool complete = false;
  if (!parser.Begin() || !parser.NextKey(key, escaped) || escaped ||
      !parser.KeyEquals(key, "address") || !parser.ParseString(value) ||
      !parser.NextField(complete) || !complete) {
    return InvalidRequest<ParsedManagementIpRequest>();
  }
  parser.CopyString(value, parsed.address);
  if (parsed.address.empty()) {
    return InvalidRequest<ParsedManagementIpRequest>();
  }
  return common::Result<ParsedManagementIpRequest>::Ok(std::move(parsed));
}

common::Result<void> ValidateEmptyRequestBody(std::string_view body) {
  return body.empty() ? common::Result<void>::Ok() : InvalidRequest<void>();
}

common::Result<std::int64_t> ParseManagedResourceId(std::string_view value) {
  if (value.empty() || value.front() == '0' ||
      !std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return character >= '0' && character <= '9';
      })) {
    return InvalidRequest<std::int64_t>();
  }
  std::int64_t parsed = 0;
  const auto [end, error] =
      std::from_chars(value.data(), value.data() + value.size(), parsed);
  if (error != std::errc() || end != value.data() + value.size() || parsed <= 0) {
    return InvalidRequest<std::int64_t>();
  }
  return common::Result<std::int64_t>::Ok(parsed);
}

common::Result<security::UserRole> ParseManagedRole(std::string_view value) {
  if (value == "administrator") {
    return common::Result<security::UserRole>::Ok(
        security::UserRole::kAdministrator);
  }
  if (value == "viewer") {
    return common::Result<security::UserRole>::Ok(security::UserRole::kViewer);
  }
  return InvalidRequest<security::UserRole>();
}

Json::Value BuildManagedUserJson(const security::ManagedUser& user) {
  Json::Value json(Json::objectValue);
  json["id"] = Json::Int64(user.id);
  json["username"] = user.username;
  json["role"] = std::string(RoleName(user.role));
  json["enabled"] = user.enabled;
  json["lock_until_seconds"] = user.lock_until_seconds.has_value()
                                   ? Json::Value(Json::Int64(*user.lock_until_seconds))
                                   : Json::Value(Json::nullValue);
  json["created_at_seconds"] = Json::Int64(user.created_at_seconds);
  json["password_changed_at_seconds"] = Json::Int64(user.password_changed_at_seconds);
  json["last_login_at_seconds"] = user.last_login_at_seconds.has_value()
                                      ? Json::Value(Json::Int64(*user.last_login_at_seconds))
                                      : Json::Value(Json::nullValue);
  return json;
}

Json::Value BuildManagementIpJson(const security::ManagementIpEntry& entry) {
  Json::Value json(Json::objectValue);
  json["id"] = Json::Int64(entry.id);
  json["address"] = entry.normalized_ip;
  json["role"] = std::string(RoleName(entry.role));
  json["created_at_seconds"] = Json::Int64(entry.created_at_seconds);
  return json;
}

Json::Value BuildManagementIpListJson(
    const std::vector<security::ManagementIpEntry>& entries,
    std::string_view current_peer_ip) {
  Json::Value serialized(Json::arrayValue);
  for (const auto& entry : entries) {
    serialized.append(BuildManagementIpJson(entry));
  }
  Json::Value body(Json::objectValue);
  body["management_ips"] = std::move(serialized);
  body["current_peer_ip"] = std::string(current_peer_ip);
  return body;
}

drogon::HttpResponsePtr BuildUserManagementErrorResponse(
    const common::Error& error) {
  const auto mapped = MapPublicError(error.code);
  Json::Value json(Json::objectValue);
  json["code"] = std::string(mapped.code);
  json["message"] = std::string(mapped.message);
  auto response = drogon::HttpResponse::newHttpJsonResponse(std::move(json));
  response->setStatusCode(mapped.status);
  return response;
}

drogon::HttpStatusCode UserManagementErrorStatus(std::string_view code) {
  return MapPublicError(code).status;
}

}  // namespace camera_firmware::service
