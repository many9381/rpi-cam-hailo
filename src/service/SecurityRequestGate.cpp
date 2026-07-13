#include "camera_firmware/service/SecurityRequestGate.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <gio/gio.h>

namespace camera_firmware::service {
namespace {

constexpr std::size_t kMaximumUsernameBytes = 32U;
constexpr std::size_t kMaximumPasswordBytes = 128U;
constexpr std::size_t kMaximumPeerIpBytes = 45U;
constexpr std::size_t kSessionTokenBytes = 32U;

template <typename T>
common::Result<T> InvalidRequest(std::string code = "E_INVALID_REQUEST") {
  return common::Result<T>::Err(
      {std::move(code), "request could not be processed"});
}

common::Result<void> GateError(std::string code, std::string message) {
  return common::Result<void>::Err({std::move(code), std::move(message)});
}

struct GObjectDeleter {
  void operator()(gpointer value) const noexcept {
    if (value != nullptr) {
      g_object_unref(value);
    }
  }
};

struct GUriDeleter {
  void operator()(GUri* uri) const noexcept {
    if (uri != nullptr) {
      g_uri_unref(uri);
    }
  }
};

struct GCharDeleter {
  void operator()(gchar* value) const noexcept { g_free(value); }
};

std::string UpperMethod(std::string_view method) {
  std::string normalized;
  normalized.reserve(method.size());
  for (const unsigned char value : method) {
    if (value < 'A' || (value > 'Z' && value < 'a') || value > 'z') {
      return {};
    }
    normalized.push_back(static_cast<char>(std::toupper(value)));
  }
  return normalized;
}

bool IsStaticAsset(std::string_view path, std::string_view method) {
  return method == "GET" &&
         (path == "/" || path == "/index.html" || path == "/app.js" ||
          path == "/styles.css");
}

bool IsStateChanging(std::string_view method) { return method == "POST"; }

bool IsKnownProtectedRoute(std::string_view path, std::string_view method) {
  if (method == "GET") {
    if (path == "/api/v1/health" || path == "/api/v1/cameras" ||
        path == "/api/v1/ai/detections" ||
        path == "/api/v1/ai/detections/stream" ||
        path == "/api/v1/stream" || path == "/api/v1/auth/me") {
      return true;
    }
    constexpr std::string_view prefix = "/api/v1/cameras/";
    constexpr std::array<std::string_view, 2> suffixes = {
        "/snapshot.jpg", "/preview.mjpeg"};
    for (const auto suffix : suffixes) {
      if (path.starts_with(prefix) && path.ends_with(suffix) &&
          path.size() > prefix.size() + suffix.size()) {
        const auto camera_id = path.substr(
            prefix.size(), path.size() - prefix.size() - suffix.size());
        if (camera_id.find('/') == std::string_view::npos) {
          return true;
        }
      }
    }
  }
  return method == "POST" &&
         (path == "/api/v1/ai/restart" ||
          path == "/api/v1/auth/logout");
}

common::Result<std::string> CanonicalOrigin(std::string_view origin,
                                            bool allow_path) {
  if (origin.empty() || origin.find('\0') != std::string_view::npos) {
    return InvalidRequest<std::string>();
  }
  const std::string origin_text(origin);
  GError* parse_error = nullptr;
  std::unique_ptr<GUri, GUriDeleter> uri(
      g_uri_parse(origin_text.c_str(), G_URI_FLAGS_NONE, &parse_error));
  if (parse_error != nullptr) {
    g_error_free(parse_error);
  }
  if (!uri) {
    return InvalidRequest<std::string>();
  }
  const gchar* scheme = g_uri_get_scheme(uri.get());
  const gchar* host = g_uri_get_host(uri.get());
  const gchar* path = g_uri_get_path(uri.get());
  if (scheme == nullptr || host == nullptr || *host == '\0' ||
      g_uri_get_userinfo(uri.get()) != nullptr ||
      g_uri_get_query(uri.get()) != nullptr ||
      g_uri_get_fragment(uri.get()) != nullptr ||
      (!allow_path && path != nullptr && *path != '\0')) {
    return InvalidRequest<std::string>();
  }
  std::string normalized_scheme(scheme);
  std::transform(normalized_scheme.begin(), normalized_scheme.end(),
                 normalized_scheme.begin(), [](unsigned char value) {
                   return static_cast<char>(std::tolower(value));
                 });
  if (normalized_scheme != "https") {
    return InvalidRequest<std::string>();
  }

  std::string normalized_host(host);
  if (auto address = NormalizePeerIp(normalized_host); address.ok()) {
    normalized_host = std::move(address).value();
  } else {
    std::transform(normalized_host.begin(), normalized_host.end(),
                   normalized_host.begin(), [](unsigned char value) {
                     return static_cast<char>(std::tolower(value));
                   });
  }
  gint port = g_uri_get_port(uri.get());
  if (port < 0) {
    port = 443;
  }
  if (port <= 0 || port > 65535) {
    return InvalidRequest<std::string>();
  }
  return common::Result<std::string>::Ok(normalized_scheme + "://" +
                                          normalized_host + ":" +
                                          std::to_string(port));
}

bool SameOrigin(std::string_view actual, std::string_view expected) {
  auto actual_origin = CanonicalOrigin(actual, false);
  auto expected_origin = CanonicalOrigin(expected, true);
  return actual_origin.ok() && expected_origin.ok() &&
         actual_origin.value() == expected_origin.value();
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

int HexValue(char value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  return -1;
}

int JsonHexValue(char value) {
  const int lowercase = HexValue(value);
  if (lowercase >= 0) {
    return lowercase;
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

class InSituCredentialParser {
 public:
  explicit InSituCredentialParser(common::SecureBytes& body) : body_(body) {}

  bool Parse(bool require_peer,
             std::string& username,
             common::SecureBytes& password,
             std::string& peer_ip) {
    if (body_.size() == 0U ||
        !g_utf8_validate(reinterpret_cast<const char*>(body_.data()),
                         static_cast<gssize>(body_.size()), nullptr)) {
      return false;
    }
    SkipWhitespace();
    if (!Consume('{')) {
      return false;
    }
    SkipWhitespace();
    if (Peek('}')) {
      return false;
    }

    bool have_username = false;
    bool have_password = false;
    bool have_peer = false;
    for (;;) {
      DecodedJsonString key_slice;
      if (!ParseString(key_slice)) {
        return false;
      }
      const std::string key = OrdinaryString(key_slice);
      SkipWhitespace();
      if (!Consume(':')) {
        return false;
      }
      SkipWhitespace();

      DecodedJsonString value;
      if (!ParseString(value)) {
        return false;
      }
      if (key == "username" && !have_username) {
        username = OrdinaryString(value);
        have_username = true;
      } else if (key == "password" && !have_password) {
        password.assign(body_.data() + value.offset, value.size);
        have_password = true;
      } else if (require_peer && key == "peer_ip" && !have_peer) {
        peer_ip = OrdinaryString(value);
        have_peer = true;
      } else {
        return false;
      }

      SkipWhitespace();
      if (Consume('}')) {
        break;
      }
      if (!Consume(',')) {
        return false;
      }
      SkipWhitespace();
    }
    SkipWhitespace();
    return position_ == body_.size() && have_username && have_password &&
           have_peer == require_peer;
  }

 private:
  bool ParseString(DecodedJsonString& decoded) {
    if (!Consume('"')) {
      return false;
    }
    const std::size_t output_start = position_;
    std::size_t output = output_start;
    while (position_ < body_.size()) {
      const unsigned char value = body_.data()[position_++];
      if (value == '"') {
        decoded = {output_start, output - output_start};
        return g_utf8_validate(
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

  bool ParseHexCodeUnit(std::uint32_t& code_unit) {
    if (position_ + 4U > body_.size()) {
      return false;
    }
    code_unit = 0U;
    for (std::size_t count = 0U; count < 4U; ++count) {
      const int digit =
          JsonHexValue(static_cast<char>(body_.data()[position_++]));
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

  std::string OrdinaryString(const DecodedJsonString& decoded) const {
    return {reinterpret_cast<const char*>(body_.data() + decoded.offset),
            decoded.size};
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

common::Result<common::SecureBytes> SecureRequestBody(std::string_view body) {
  if (body.size() > kMaximumSecurityBodyBytes) {
    return InvalidRequest<common::SecureBytes>("E_REQUEST_TOO_LARGE");
  }
  common::SecureBytes secure_body;
  secure_body.assign(reinterpret_cast<const unsigned char*>(body.data()),
                     body.size());
  return common::Result<common::SecureBytes>::Ok(std::move(secure_body));
}

}  // namespace

common::Result<void> AuthorizeSecurityRequest(
    const SecurityRequestContext& context) {
  const std::string method = UpperMethod(context.method);
  if (method.empty()) {
    return GateError("E_ACCESS_DENIED", "request denied");
  }
  if (IsStaticAsset(context.path, method)) {
    return common::Result<void>::Ok();
  }
  if (context.path == "/api/v1/setup/status" && method == "GET") {
    return common::Result<void>::Ok();
  }

  if (context.state == security::DeviceState::kDefault) {
    const bool setup_command =
        context.path == "/api/v1/setup/initialize" ||
        context.path == "/api/v1/setup/runtime";
    if (!setup_command || method != "POST") {
      return GateError("E_ACCESS_DENIED", "request denied");
    }
    if (!SameOrigin(context.origin, context.expected_origin)) {
      return GateError("E_REQUEST_ORIGIN", "request denied");
    }
    if (!context.has_management_header) {
      return GateError("E_REQUEST_HEADER", "request denied");
    }
    return common::Result<void>::Ok();
  }

  if (context.path == "/api/v1/setup/initialize" ||
      context.path == "/api/v1/setup/runtime") {
    return GateError("E_ACCESS_DENIED", "request denied");
  }
  const bool login =
      context.path == "/api/v1/auth/login" && method == "POST";
  if (!login && !IsKnownProtectedRoute(context.path, method)) {
    return GateError("E_ACCESS_DENIED", "request denied");
  }
  if (!context.peer_is_management) {
    return GateError("E_ACCESS_DENIED", "request denied");
  }
  if (!login && !context.principal.has_value()) {
    return GateError("E_AUTHENTICATION_REQUIRED", "authentication required");
  }
  if (IsStateChanging(method)) {
    if (!SameOrigin(context.origin, context.expected_origin)) {
      return GateError("E_REQUEST_ORIGIN", "request denied");
    }
    if (!context.has_management_header) {
      return GateError("E_REQUEST_HEADER", "request denied");
    }
  }
  if (!login && context.principal->role != security::UserRole::kAdministrator) {
    return GateError("E_AUTHORIZATION_REQUIRED", "authorization required");
  }
  return common::Result<void>::Ok();
}

common::Result<std::string> NormalizePeerIp(std::string_view peer_ip) {
  if (peer_ip.empty() || peer_ip.size() > kMaximumPeerIpBytes ||
      peer_ip.find('\0') != std::string_view::npos) {
    return InvalidRequest<std::string>();
  }
  const std::string input(peer_ip);
  std::unique_ptr<GInetAddress, GObjectDeleter> address(
      g_inet_address_new_from_string(input.c_str()));
  if (!address) {
    return InvalidRequest<std::string>();
  }
  std::unique_ptr<gchar, GCharDeleter> normalized(
      g_inet_address_to_string(address.get()));
  if (!normalized) {
    return InvalidRequest<std::string>();
  }
  return common::Result<std::string>::Ok(normalized.get());
}

common::Result<common::SecureBytes> ParseSessionCookie(
    std::string_view cookie_header) {
  const std::size_t equals = cookie_header.find('=');
  if (cookie_header.empty() ||
      cookie_header.find(';') != std::string_view::npos ||
      equals == std::string_view::npos || equals == 0U ||
      cookie_header.find('=', equals + 1U) != std::string_view::npos ||
      cookie_header.find_first_of("\t\r\n ") != std::string_view::npos ||
      cookie_header.substr(0, equals) != kSessionCookieName) {
    return InvalidRequest<common::SecureBytes>("E_AUTHENTICATION_REQUIRED");
  }
  const std::string_view token = cookie_header.substr(equals + 1U);
  if (token.size() != kSessionTokenBytes * 2U) {
    return InvalidRequest<common::SecureBytes>("E_AUTHENTICATION_REQUIRED");
  }
  common::SecureBytes decoded;
  decoded.resize(kSessionTokenBytes);
  for (std::size_t index = 0; index < kSessionTokenBytes; ++index) {
    const int high = HexValue(token[index * 2U]);
    const int low = HexValue(token[index * 2U + 1U]);
    if (high < 0 || low < 0) {
      decoded.clear();
      return InvalidRequest<common::SecureBytes>("E_AUTHENTICATION_REQUIRED");
    }
    decoded.data()[index] = static_cast<unsigned char>((high << 4) | low);
  }
  return common::Result<common::SecureBytes>::Ok(std::move(decoded));
}

common::Result<common::SecureBytes> ParseSessionCookieHeaders(
    std::span<const std::string> cookie_headers) {
  if (cookie_headers.size() != 1U) {
    return InvalidRequest<common::SecureBytes>("E_AUTHENTICATION_REQUIRED");
  }
  return ParseSessionCookie(cookie_headers.front());
}

common::Result<ParsedLoginRequest> ParseLoginJson(
    std::string_view body,
    std::string_view content_type) {
  auto secure_body = SecureRequestBody(body);
  if (!secure_body.ok()) {
    return common::Result<ParsedLoginRequest>::Err(secure_body.error());
  }
  return ParseLoginJson(std::move(secure_body).value(), content_type);
}

common::Result<ParsedLoginRequest> ParseLoginJson(
    common::SecureBytes body,
    std::string_view content_type) {
  if (body.size() > kMaximumSecurityBodyBytes) {
    return InvalidRequest<ParsedLoginRequest>("E_REQUEST_TOO_LARGE");
  }
  if (!IsJsonContentType(content_type)) {
    return InvalidRequest<ParsedLoginRequest>();
  }
  ParsedLoginRequest parsed;
  std::string ignored_peer;
  InSituCredentialParser parser(body);
  if (!parser.Parse(false, parsed.username, parsed.password, ignored_peer) ||
      parsed.username.empty() ||
      parsed.username.size() > kMaximumUsernameBytes ||
      parsed.password.size() == 0U ||
      parsed.password.size() > kMaximumPasswordBytes) {
    return InvalidRequest<ParsedLoginRequest>();
  }
  return common::Result<ParsedLoginRequest>::Ok(std::move(parsed));
}

common::Result<ParsedSetupRequest> ParseSetupJson(
    std::string_view body,
    std::string_view content_type) {
  auto secure_body = SecureRequestBody(body);
  if (!secure_body.ok()) {
    return common::Result<ParsedSetupRequest>::Err(secure_body.error());
  }
  return ParseSetupJson(std::move(secure_body).value(), content_type);
}

common::Result<ParsedSetupRequest> ParseSetupJson(
    common::SecureBytes body,
    std::string_view content_type) {
  if (body.size() > kMaximumSecurityBodyBytes) {
    return InvalidRequest<ParsedSetupRequest>("E_REQUEST_TOO_LARGE");
  }
  if (!IsJsonContentType(content_type)) {
    return InvalidRequest<ParsedSetupRequest>();
  }
  ParsedSetupRequest parsed;
  InSituCredentialParser parser(body);
  if (!parser.Parse(true, parsed.username, parsed.password,
                    parsed.confirmed_peer_ip) ||
      parsed.username.empty() ||
      parsed.username.size() > kMaximumUsernameBytes ||
      parsed.password.size() == 0U ||
      parsed.password.size() > kMaximumPasswordBytes ||
      parsed.confirmed_peer_ip.empty() ||
      parsed.confirmed_peer_ip.size() > kMaximumPeerIpBytes) {
    return InvalidRequest<ParsedSetupRequest>();
  }
  return common::Result<ParsedSetupRequest>::Ok(std::move(parsed));
}

common::Result<void> ValidateEmptyJsonObject(
    std::string_view body,
    std::string_view content_type) {
  if (body.size() > kMaximumSecurityBodyBytes) {
    return InvalidRequest<void>("E_REQUEST_TOO_LARGE");
  }
  if (!IsJsonContentType(content_type)) {
    return InvalidRequest<void>();
  }
  std::string compact;
  compact.reserve(body.size());
  for (const unsigned char byte : body) {
    const bool json_whitespace = byte == ' ' || byte == '\t' ||
                                 byte == '\r' || byte == '\n';
    if (!json_whitespace) {
      compact.push_back(static_cast<char>(byte));
    }
  }
  if (compact != "{}") {
    return InvalidRequest<void>();
  }
  return common::Result<void>::Ok();
}

}  // namespace camera_firmware::service
