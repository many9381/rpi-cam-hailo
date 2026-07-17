#include "camera_firmware/service/UserManagementHttp.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <initializer_list>
#include <sstream>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

namespace camera_firmware::service::internal {

using UserManagementSecretCleanupObserverForTesting = void (*)(
    std::string_view label,
    common::ZeroizeAudit before,
    common::ZeroizeAudit after) noexcept;

void SetUserManagementSecretCleanupObserverForTesting(
    UserManagementSecretCleanupObserverForTesting observer) noexcept;
void ResetUserManagementSecretCleanupObserverForTesting() noexcept;

}  // namespace camera_firmware::service::internal

namespace {

using camera_firmware::common::SecureBytes;
using camera_firmware::security::ManagedUser;
using camera_firmware::security::ManagementIpEntry;
using camera_firmware::security::UserRole;
using camera_firmware::service::BuildManagedUserJson;
using camera_firmware::service::BuildManagementIpJson;
using camera_firmware::service::BuildUserManagementErrorResponse;
using camera_firmware::service::ParseCreateViewerJson;
using camera_firmware::service::ParseManagedResourceId;
using camera_firmware::service::ParseManagedRole;
using camera_firmware::service::ParseManagementIpJson;
using camera_firmware::service::ParseOwnPasswordJson;
using camera_firmware::service::ParsePasswordResetJson;
using camera_firmware::service::ParseSetViewerEnabledJson;
using camera_firmware::service::UserManagementErrorStatus;
using camera_firmware::service::ValidateEmptyRequestBody;

struct CleanupEvent {
  std::string_view label;
  camera_firmware::common::ZeroizeAudit before;
  camera_firmware::common::ZeroizeAudit after;
};

struct CleanupEvents {
  std::array<CleanupEvent, 16U> entries{};
  std::size_t size{0U};
};

thread_local CleanupEvents* active_cleanup_events = nullptr;

void RecordCleanupEvent(
    std::string_view label,
    camera_firmware::common::ZeroizeAudit before,
    camera_firmware::common::ZeroizeAudit after) noexcept {
  if (active_cleanup_events == nullptr ||
      active_cleanup_events->size >= active_cleanup_events->entries.size()) {
    return;
  }
  active_cleanup_events->entries[active_cleanup_events->size++] =
      {label, before, after};
}

class CleanupObserverScope {
 public:
  explicit CleanupObserverScope(CleanupEvents& events) noexcept {
    camera_firmware::service::internal::
        ResetUserManagementSecretCleanupObserverForTesting();
    active_cleanup_events = &events;
    camera_firmware::service::internal::
        SetUserManagementSecretCleanupObserverForTesting(RecordCleanupEvent);
  }

  ~CleanupObserverScope() {
    camera_firmware::service::internal::
        ResetUserManagementSecretCleanupObserverForTesting();
    active_cleanup_events = nullptr;
  }

  CleanupObserverScope(const CleanupObserverScope&) = delete;
  CleanupObserverScope& operator=(const CleanupObserverScope&) = delete;
};

class StreamBufferScope {
 public:
  StreamBufferScope(std::ostream& stream, std::streambuf* replacement)
      : stream_(stream), previous_(stream.rdbuf(replacement)) {}

  ~StreamBufferScope() { stream_.rdbuf(previous_); }

  StreamBufferScope(const StreamBufferScope&) = delete;
  StreamBufferScope& operator=(const StreamBufferScope&) = delete;

 private:
  std::ostream& stream_;
  std::streambuf* previous_;
};

std::size_t CleanupEventCount(const CleanupEvents& events,
                              std::string_view label) {
  return std::count_if(
      events.entries.begin(), events.entries.begin() + events.size,
      [label](const CleanupEvent& event) { return event.label == label; });
}

void ExpectObservedCleanupAudits(const CleanupEvents& events) {
  ASSERT_GT(events.size, 0U);
  for (std::size_t index = 0U; index < events.size; ++index) {
    const auto& event = events.entries[index];
    SCOPED_TRACE(event.label);
    EXPECT_GT(event.after.count, 0U);
    EXPECT_GT(event.after.count, event.before.count);
    EXPECT_TRUE(event.after.last_verified);
  }
}

SecureBytes SecureBody(std::string_view text) {
  SecureBytes body;
  body.assign(reinterpret_cast<const unsigned char*>(text.data()), text.size());
  return body;
}

SecureBytes RepeatedSecretBody(std::string_view prefix,
                               std::size_t secret_length,
                               std::string_view suffix,
                               unsigned char value = 'P') {
  SecureBytes body;
  body.resize(prefix.size() + secret_length + suffix.size());
  auto* output = body.data();
  output = std::copy(prefix.begin(), prefix.end(), output);
  output = std::fill_n(output, secret_length, value);
  (void)std::copy(suffix.begin(), suffix.end(), output);
  return body;
}

SecureBytes PasswordResetBody(std::size_t password_length) {
  return RepeatedSecretBody(R"({"password":")", password_length, R"("})");
}

SecureBytes OwnPasswordBody(std::size_t current_length,
                            std::size_t replacement_length) {
  constexpr std::string_view kPrefix = R"({"current_password":")";
  constexpr std::string_view kMiddle = R"(","replacement_password":")";
  constexpr std::string_view kSuffix = R"("})";
  SecureBytes body;
  body.resize(kPrefix.size() + current_length + kMiddle.size() +
              replacement_length + kSuffix.size());
  auto* output = body.data();
  output = std::copy(kPrefix.begin(), kPrefix.end(), output);
  output = std::fill_n(output, current_length, 'C');
  output = std::copy(kMiddle.begin(), kMiddle.end(), output);
  output = std::fill_n(output, replacement_length, 'R');
  (void)std::copy(kSuffix.begin(), kSuffix.end(), output);
  return body;
}

void ExpectSecureOwnerClears(SecureBytes& secret) {
  ASSERT_GT(secret.size(), 0U);
  const auto before = secret.zeroize_audit().count;
  secret.clear();
  EXPECT_EQ(secret.size(), 0U);
  EXPECT_GT(secret.zeroize_audit().count, before);
  EXPECT_TRUE(secret.zeroize_audit().last_verified);
}

void ExpectExactKeys(const Json::Value& value,
                     std::initializer_list<std::string_view> keys) {
  ASSERT_TRUE(value.isObject());
  EXPECT_EQ(value.size(), keys.size());
  for (const auto key : keys) {
    EXPECT_TRUE(value.isMember(std::string(key))) << key;
  }
}

TEST(UserManagementHttpTest, PasswordRequestParsersKeepSecretsInSecureBytes) {
  auto create = ParseCreateViewerJson(
      SecureBody(R"({"username":"viewer","password":"P"})"),
      "application/json");
  ASSERT_TRUE(create.ok()) << "create parser rejected valid fixture";
  EXPECT_EQ(create.value().username, "viewer");
  EXPECT_EQ(create.value().password.size(), 1U);

  auto reset =
      ParsePasswordResetJson(PasswordResetBody(128U), "application/json");
  ASSERT_TRUE(reset.ok()) << "reset parser rejected valid fixture";
  EXPECT_EQ(reset.value().password.size(), 128U);

  auto own =
      ParseOwnPasswordJson(OwnPasswordBody(1U, 128U), "application/json");
  ASSERT_TRUE(own.ok()) << "own-password parser rejected valid fixture";
  EXPECT_EQ(own.value().current_password.size(), 1U);
  EXPECT_EQ(own.value().replacement_password.size(), 128U);

  ExpectSecureOwnerClears(create.value().password);
  ExpectSecureOwnerClears(reset.value().password);
  ExpectSecureOwnerClears(own.value().current_password);
  ExpectSecureOwnerClears(own.value().replacement_password);
}

TEST(UserManagementHttpTest,
     SuccessfulSecretParsersObserveBodyCleanupAndMovedOwnerCleanup) {
  CleanupEvents events;
  CleanupObserverScope observer(events);

  auto create = ParseCreateViewerJson(
      SecureBody(R"({"username":"viewer","password":"P"})"),
      "application/json");
  ASSERT_TRUE(create.ok()) << "create parser rejected valid fixture";
  auto create_owner = std::move(create).value();
  SecureBytes create_password = std::move(create_owner.password);

  auto reset =
      ParsePasswordResetJson(PasswordResetBody(1U), "application/json");
  ASSERT_TRUE(reset.ok()) << "reset parser rejected valid fixture";
  auto reset_owner = std::move(reset).value();
  SecureBytes reset_password = std::move(reset_owner.password);

  auto own =
      ParseOwnPasswordJson(OwnPasswordBody(1U, 1U), "application/json");
  ASSERT_TRUE(own.ok()) << "own-password parser rejected valid fixture";
  auto own_owner = std::move(own).value();
  SecureBytes current_password = std::move(own_owner.current_password);
  SecureBytes replacement_password =
      std::move(own_owner.replacement_password);

  EXPECT_EQ(CleanupEventCount(events, "create.request_body"), 1U);
  EXPECT_EQ(CleanupEventCount(events, "reset.request_body"), 1U);
  EXPECT_EQ(CleanupEventCount(events, "own.request_body"), 1U);
  EXPECT_EQ(CleanupEventCount(events, "create.password"), 0U);
  EXPECT_EQ(CleanupEventCount(events, "reset.password"), 0U);
  EXPECT_EQ(CleanupEventCount(events, "own.current_password"), 0U);
  EXPECT_EQ(CleanupEventCount(events, "own.replacement_password"), 0U);
  ExpectObservedCleanupAudits(events);

  ExpectSecureOwnerClears(create_password);
  ExpectSecureOwnerClears(reset_password);
  ExpectSecureOwnerClears(current_password);
  ExpectSecureOwnerClears(replacement_password);
}

TEST(UserManagementHttpTest,
     MalformedSecretParsersObserveBodyAndPartialOwnerCleanup) {
  CleanupEvents events;
  CleanupObserverScope observer(events);

  auto create = ParseCreateViewerJson(
      SecureBody(R"({"password":"P","extra":"x"})"),
      "application/json");
  EXPECT_FALSE(create.ok());

  auto own = ParseOwnPasswordJson(
      SecureBody(
          R"({"current_password":"C","replacement_password":"R","extra":"x"})"),
      "application/json");
  EXPECT_FALSE(own.ok());

  EXPECT_EQ(CleanupEventCount(events, "create.request_body"), 1U);
  EXPECT_EQ(CleanupEventCount(events, "create.password"), 1U);
  EXPECT_EQ(CleanupEventCount(events, "own.request_body"), 1U);
  EXPECT_EQ(CleanupEventCount(events, "own.current_password"), 1U);
  EXPECT_EQ(CleanupEventCount(events, "own.replacement_password"), 1U);
  ExpectObservedCleanupAudits(events);
}

TEST(UserManagementHttpTest, SecretJsonParsersRejectMalformedBodies) {
  struct NamedBody {
    std::string_view name;
    std::string_view body;
  };
  constexpr std::array<NamedBody, 6> kInvalidCreateBodies = {{
      {"missing-password", R"({"username":"viewer"})"},
      {"unknown-field",
       R"({"username":"viewer","password":"P","extra":"x"})"},
      {"duplicate-username",
       R"({"username":"viewer","username":"other","password":"P"})"},
      {"escaped-username-key",
       R"({"user\u006eame":"viewer","password":"P"})"},
      {"escaped-password-key",
       R"({"username":"viewer","pass\u0077ord":"P"})"},
      {"trailing-input",
       R"({"username":"viewer","password":"P"} trailing)"},
  }};
  for (const auto& test_case : kInvalidCreateBodies) {
    SCOPED_TRACE(test_case.name);
    EXPECT_FALSE(ParseCreateViewerJson(SecureBody(test_case.body),
                                       "application/json")
                     .ok());
  }

  constexpr std::array<NamedBody, 7> kInvalidResetBodies = {{
      {"duplicate-password", R"({"password":"P","password":"Q"})"},
      {"high-surrogate-without-low", R"({"password":"\uD83D"})"},
      {"isolated-low-surrogate", R"({"password":"\uDE00"})"},
      {"non-low-surrogate-pair", R"({"password":"\uD83D\u0041"})"},
      {"short-unicode-escape", R"({"password":"\u12"})"},
      {"invalid-unicode-escape", R"({"password":"\uZZZZ"})"},
      {"unknown-escape", R"({"password":"\x"})"},
  }};
  for (const auto& test_case : kInvalidResetBodies) {
    SCOPED_TRACE(test_case.name);
    EXPECT_FALSE(ParsePasswordResetJson(SecureBody(test_case.body),
                                        "application/json")
                     .ok());
  }
}

TEST(UserManagementHttpTest, PasswordLengthBoundariesAreExact) {
  for (const std::size_t invalid_length : {0U, 129U}) {
    SCOPED_TRACE(invalid_length);
    EXPECT_FALSE(ParsePasswordResetJson(PasswordResetBody(invalid_length),
                                        "application/json")
                     .ok());
  }
  for (const std::size_t valid_length : {1U, 128U}) {
    SCOPED_TRACE(valid_length);
    auto parsed = ParsePasswordResetJson(PasswordResetBody(valid_length),
                                         "application/json");
    ASSERT_TRUE(parsed.ok()) << "valid password boundary was rejected";
    EXPECT_EQ(parsed.value().password.size(), valid_length);
    ExpectSecureOwnerClears(parsed.value().password);
  }
}

TEST(UserManagementHttpTest, EscapedValuesAndSurrogatePairsAreAccepted) {
  auto parsed = ParseCreateViewerJson(
      SecureBody(
          R"({"username":"view\u0065r","password":"\uD83D\uDE00"})"),
      "application/json");
  ASSERT_TRUE(parsed.ok()) << "valid escaped values were rejected";
  EXPECT_EQ(parsed.value().username, "viewer");
  EXPECT_EQ(parsed.value().password.size(), 4U);
  EXPECT_EQ(parsed.value().password.data()[0], 0xf0U);
  EXPECT_EQ(parsed.value().password.data()[1], 0x9fU);
  EXPECT_EQ(parsed.value().password.data()[2], 0x98U);
  EXPECT_EQ(parsed.value().password.data()[3], 0x80U);
  ExpectSecureOwnerClears(parsed.value().password);
}

TEST(UserManagementHttpTest, OwnPasswordParserRejectsMalformedPaths) {
  struct NamedBody {
    std::string_view name;
    std::string_view body;
  };
  constexpr std::array<NamedBody, 9> kCases = {{
      {"missing-current", R"({"replacement_password":"R"})"},
      {"missing-replacement", R"({"current_password":"C"})"},
      {"duplicate-current",
       R"({"current_password":"C","current_password":"D","replacement_password":"R"})"},
      {"duplicate-replacement",
       R"({"current_password":"C","replacement_password":"R","replacement_password":"S"})"},
      {"unknown-field",
       R"({"current_password":"C","replacement_password":"R","extra":"x"})"},
      {"escaped-key",
       R"({"current_password":"C","replacement\u005fpassword":"R"})"},
      {"wrong-current-type",
       R"({"current_password":7,"replacement_password":"R"})"},
      {"trailing-input",
       R"({"current_password":"C","replacement_password":"R"} trailing)"},
      {"malformed-replacement-escape",
       R"({"current_password":"C","replacement_password":"\uD83D"})"},
  }};
  for (const auto& test_case : kCases) {
    SCOPED_TRACE(test_case.name);
    EXPECT_FALSE(ParseOwnPasswordJson(SecureBody(test_case.body),
                                      "application/json")
                     .ok());
  }
}

TEST(UserManagementHttpTest, PublicJsonParsersRejectMalformedBodies) {
  for (const auto& body : {R"({"enabled":true,"enabled":false})",
                           R"({"en\u0061bled":true})",
                           R"({"enabled":1})",
                           R"({"enabled":true} trailing)"}) {
    EXPECT_FALSE(ParseSetViewerEnabledJson(body, "application/json").ok())
        << body;
  }
  for (const auto& body : {R"({"address":"192.0.2.10","extra":"x"})",
                           R"({"addr\u0065ss":"192.0.2.10"})",
                           R"({"address":7})"}) {
    EXPECT_FALSE(ParseManagementIpJson(body, "application/json").ok())
        << body;
  }
}

TEST(UserManagementHttpTest, JsonParsersEnforceEncodingNulAndBodyLimits) {
  EXPECT_FALSE(ParseCreateViewerJson(SecureBody(""), "application/json").ok());
  EXPECT_FALSE(ParsePasswordResetJson(SecureBody(""), "application/json").ok());
  EXPECT_FALSE(ParseOwnPasswordJson(SecureBody(""), "application/json").ok());
  EXPECT_FALSE(ParseSetViewerEnabledJson("", "application/json").ok());
  EXPECT_FALSE(ParseManagementIpJson("", "application/json").ok());

  std::string invalid_utf8 = R"({"username":"viewer","password":")";
  invalid_utf8.push_back(static_cast<char>(0xff));
  invalid_utf8 += R"("})";
  EXPECT_FALSE(ParseCreateViewerJson(SecureBody(invalid_utf8),
                                     "application/json")
                   .ok());

  std::string nul_body = R"({"enabled":true})";
  nul_body.insert(2U, 1U, '\0');
  EXPECT_FALSE(ParseSetViewerEnabledJson(nul_body, "application/json").ok());

  std::string exact_limit = R"({"address":")";
  exact_limit.append(4082U, 'a');
  exact_limit += R"("})";
  ASSERT_EQ(exact_limit.size(), 4096U);
  auto exact = ParseManagementIpJson(exact_limit, "application/json");
  ASSERT_TRUE(exact.ok()) << "exact body-size limit was rejected";
  EXPECT_EQ(exact.value().address.size(), 4082U);

  const auto oversized_public =
      ParseManagementIpJson(std::string(4097U, ' '), "application/json");
  ASSERT_FALSE(oversized_public.ok());
  EXPECT_EQ(oversized_public.error().code, "E_REQUEST_TOO_LARGE");

  const auto oversized_secret = ParsePasswordResetJson(
      SecureBody(std::string(4097U, ' ')), "application/json");
  ASSERT_FALSE(oversized_secret.ok());
  EXPECT_EQ(oversized_secret.error().code, "E_REQUEST_TOO_LARGE");
}

TEST(UserManagementHttpTest, PublicJsonParsersRequireExactTypesAndContentType) {
  auto enabled = ParseSetViewerEnabledJson(R"({"enabled":false})",
                                           "application/json; charset=utf-8");
  ASSERT_TRUE(enabled.ok()) << enabled.error().message;
  EXPECT_FALSE(enabled.value().enabled);

  auto address = ParseManagementIpJson(R"({"address":"2001:db8::1"})",
                                       "application/json");
  ASSERT_TRUE(address.ok()) << address.error().message;
  EXPECT_EQ(address.value().address, "2001:db8::1");

  EXPECT_FALSE(ParseSetViewerEnabledJson(R"({"enabled":true})", "text/plain")
                   .ok());
  EXPECT_TRUE(ValidateEmptyRequestBody("").ok());
  EXPECT_FALSE(ValidateEmptyRequestBody("{}").ok());
}

TEST(UserManagementHttpTest, ResourceIdsAndRolesAreExact) {
  EXPECT_EQ(ParseManagedResourceId("1").value(), 1);
  EXPECT_EQ(ParseManagedResourceId("9223372036854775807").value(),
            INT64_MAX);
  for (const auto value : {"", "0", "01", "+1", "-1", " 1", "1 ",
                           "1x", "9223372036854775808"}) {
    EXPECT_FALSE(ParseManagedResourceId(value).ok()) << value;
  }

  EXPECT_EQ(ParseManagedRole("administrator").value(),
            UserRole::kAdministrator);
  EXPECT_EQ(ParseManagedRole("viewer").value(), UserRole::kViewer);
  for (const auto value : {"Administrator", "admin", "viewer ", " viewer"}) {
    EXPECT_FALSE(ParseManagedRole(value).ok()) << value;
  }
}

TEST(UserManagementHttpTest, PublicSerializersExposeExactManagedFields) {
  ManagedUser user;
  user.id = 7;
  user.username = "viewer";
  user.role = UserRole::kViewer;
  user.enabled = true;
  user.created_at_seconds = 11;
  user.password_changed_at_seconds = 12;
  const auto user_json = BuildManagedUserJson(user);
  ExpectExactKeys(user_json, {"id", "username", "role", "enabled",
                              "lock_until_seconds", "created_at_seconds",
                              "password_changed_at_seconds",
                              "last_login_at_seconds"});
  EXPECT_TRUE(user_json["lock_until_seconds"].isNull());
  EXPECT_TRUE(user_json["last_login_at_seconds"].isNull());
  EXPECT_EQ(user_json["role"].asString(), "viewer");

  user.lock_until_seconds = 13;
  user.last_login_at_seconds = 14;
  const auto nullable_json = BuildManagedUserJson(user);
  EXPECT_EQ(nullable_json["lock_until_seconds"].asInt64(), 13);
  EXPECT_EQ(nullable_json["last_login_at_seconds"].asInt64(), 14);

  ManagementIpEntry entry;
  entry.id = 8;
  entry.normalized_ip = "192.0.2.10";
  entry.role = UserRole::kAdministrator;
  entry.created_at_seconds = 15;
  const auto ip_json = BuildManagementIpJson(entry);
  ExpectExactKeys(ip_json, {"id", "address", "role", "created_at_seconds"});
  EXPECT_EQ(ip_json["address"].asString(), "192.0.2.10");
  EXPECT_EQ(ip_json["role"].asString(), "administrator");
}

TEST(UserManagementHttpTest, SemanticErrorsMapToPublicStatusClasses) {
  struct Mapping {
    std::string_view code;
    drogon::HttpStatusCode status;
  };
  for (const auto& mapping : std::array<Mapping, 21>{
           {{"E_INVALID_REQUEST", drogon::k400BadRequest},
            {"E_REQUEST_TOO_LARGE", drogon::k413RequestEntityTooLarge},
            {"E_USER_FORBIDDEN", drogon::k403Forbidden},
            {"E_MANAGEMENT_IP_FORBIDDEN", drogon::k403Forbidden},
            {"E_USERNAME_RESERVED", drogon::k400BadRequest},
            {"E_PASSWORD_LENGTH", drogon::k400BadRequest},
            {"E_CURRENT_PASSWORD", drogon::k400BadRequest},
            {"E_PASSWORD_HASH", drogon::k503ServiceUnavailable},
            {"E_USER_NOT_FOUND", drogon::k404NotFound},
            {"E_MANAGEMENT_IP_NOT_FOUND", drogon::k404NotFound},
            {"E_USER_DUPLICATE", drogon::k409Conflict},
            {"E_VIEWER_LIMIT", drogon::k409Conflict},
            {"E_USER_PROTECTED", drogon::k409Conflict},
            {"E_PASSWORD_REUSE", drogon::k409Conflict},
            {"E_USER_CONFLICT", drogon::k409Conflict},
            {"E_MANAGEMENT_IP_DUPLICATE", drogon::k409Conflict},
            {"E_MANAGEMENT_IP_LIMIT", drogon::k409Conflict},
            {"E_MANAGEMENT_IP_ROLE_MISMATCH", drogon::k409Conflict},
            {"E_MANAGEMENT_IP_PROTECTED", drogon::k409Conflict},
            {"E_USER_MANAGEMENT_UNAVAILABLE", drogon::k503ServiceUnavailable},
            {"E_PRIVATE_BACKEND_FAILURE", drogon::k503ServiceUnavailable}}}) {
    EXPECT_EQ(UserManagementErrorStatus(mapping.code), mapping.status)
        << mapping.code;
  }
}

TEST(UserManagementHttpTest, ErrorResponsesUseSanitizedPublicAllowlist) {
  struct ResponseCase {
    std::string_view internal_code;
    drogon::HttpStatusCode status;
    std::string_view public_code;
    std::string_view public_message;
  };
  constexpr std::array<ResponseCase, 10> kCases = {{
      {"E_INVALID_REQUEST", drogon::k400BadRequest, "E_INVALID_REQUEST",
       "request could not be processed"},
      {"E_USER_FORBIDDEN", drogon::k403Forbidden,
       "E_AUTHORIZATION_REQUIRED", "authorization required"},
      {"E_MANAGEMENT_IP_FORBIDDEN", drogon::k403Forbidden,
       "E_AUTHORIZATION_REQUIRED", "authorization required"},
      {"E_USER_NOT_FOUND", drogon::k404NotFound, "E_USER_NOT_FOUND",
       "user management resource was not found"},
      {"E_MANAGEMENT_IP_ROLE_MISMATCH", drogon::k409Conflict,
       "E_MANAGEMENT_IP_ROLE_MISMATCH",
       "user management request conflicts with current state"},
      {"E_USER_MANAGEMENT_UNAVAILABLE", drogon::k503ServiceUnavailable,
       "E_USER_MANAGEMENT_UNAVAILABLE", "user management is unavailable"},
      {"E_PRIVATE_BACKEND_FAILURE", drogon::k503ServiceUnavailable,
       "E_USER_MANAGEMENT_UNAVAILABLE", "user management is unavailable"},
      {"E_PASSWORD_LENGTH", drogon::k400BadRequest, "E_PASSWORD_LENGTH",
       "user management request is invalid"},
      {"E_CURRENT_PASSWORD", drogon::k400BadRequest, "E_CURRENT_PASSWORD",
       "user management request is invalid"},
      {"E_PASSWORD_HASH", drogon::k503ServiceUnavailable,
       "E_USER_MANAGEMENT_UNAVAILABLE", "user management is unavailable"},
  }};

  const std::string submitted_secret = "ReviewPassword9!";
  std::ostringstream captured_log;
  StreamBufferScope capture(std::clog, captured_log.rdbuf());
  for (const auto& test_case : kCases) {
    SCOPED_TRACE(test_case.internal_code);
    const auto response = BuildUserManagementErrorResponse(
        {std::string(test_case.internal_code),
         "private detail contains " + submitted_secret});
    ASSERT_NE(response, nullptr);
    EXPECT_EQ(response->statusCode(), test_case.status);
    const auto json = response->getJsonObject();
    ASSERT_NE(json, nullptr);
    ExpectExactKeys(*json, {"code", "message"});
    EXPECT_EQ((*json)["code"].asString(), test_case.public_code);
    EXPECT_EQ((*json)["message"].asString(), test_case.public_message);
    EXPECT_EQ(response->body().find(submitted_secret), std::string::npos);
    EXPECT_EQ(response->body().find("private detail"), std::string::npos);
  }
  EXPECT_EQ(captured_log.str().find(submitted_secret), std::string::npos);
  EXPECT_EQ(captured_log.str().find("private detail"), std::string::npos);
}

}  // namespace
