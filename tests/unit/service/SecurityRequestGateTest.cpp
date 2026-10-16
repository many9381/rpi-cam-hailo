#include "camera_firmware/service/BoundedWorker.hpp"
#include "camera_firmware/service/SecurityRequestGate.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <future>
#include <string>
#include <thread>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

using camera_firmware::common::Result;
using camera_firmware::common::SecureBytes;
using camera_firmware::security::DeviceState;
using camera_firmware::security::Principal;
using camera_firmware::security::UserRole;
using camera_firmware::service::AuthorizeSecurityRequest;
using camera_firmware::service::BoundedWorker;
using camera_firmware::service::ParseLoginJson;
using camera_firmware::service::ParseReauthenticateJson;
using camera_firmware::service::ParseSessionCookie;
using camera_firmware::service::ParseSessionCookieHeaders;
using camera_firmware::service::ParseSetupJson;
using camera_firmware::service::RouteRefreshesManagementDeadline;
using camera_firmware::service::SecurityRequestContext;
using camera_firmware::service::ValidateEmptyJsonObject;

constexpr std::string_view kOrigin = "https://camera.example";

SecureBytes SecureBody(std::string_view text) {
  SecureBytes body;
  body.assign(reinterpret_cast<const unsigned char*>(text.data()), text.size());
  return body;
}

Principal Administrator() {
  Principal principal{1, "operator", UserRole::kAdministrator};
  principal.management_authority_valid = true;
  return principal;
}

Principal Viewer() {
  return {2, "viewer", UserRole::kViewer};
}

SecurityRequestContext Request(std::string path, std::string method = "GET") {
  SecurityRequestContext context;
  context.state = DeviceState::kDefault;
  context.path = std::move(path);
  context.method = std::move(method);
  context.normalized_peer_ip = "192.0.2.10";
  context.expected_origin = std::string(kOrigin);
  return context;
}

SecurityRequestContext Operational(std::string path,
                                   std::string method = "GET") {
  auto context = Request(std::move(path), std::move(method));
  context.state = DeviceState::kOperational;
  context.peer_is_management = true;
  return context;
}

SecurityRequestContext ValidManagementPost(std::string path) {
  auto context = Operational(std::move(path), "POST");
  context.origin = "https://CAMERA.example:443";
  context.has_management_header = true;
  context.principal = Administrator();
  return context;
}

SecurityRequestContext ValidManagementRequest(std::string path,
                                              std::string method) {
  auto context = Operational(std::move(path), std::move(method));
  context.origin = "https://CAMERA.example:443";
  context.has_management_header = true;
  context.principal = Administrator();
  return context;
}

TEST(SecurityRequestGateTest, DefaultStateAllowsOnlyExactSetupSurface) {
  EXPECT_TRUE(AuthorizeSecurityRequest(Request("/api/v1/setup/status")).ok());

  auto initialize = Request("/api/v1/setup/initialize", "post");
  initialize.origin = std::string(kOrigin);
  initialize.has_management_header = true;
  EXPECT_TRUE(AuthorizeSecurityRequest(initialize).ok());

  auto runtime = Request("/api/v1/setup/runtime", "post");
  runtime.origin = std::string(kOrigin);
  runtime.has_management_header = true;
  EXPECT_TRUE(AuthorizeSecurityRequest(runtime).ok());

  EXPECT_TRUE(AuthorizeSecurityRequest(Request("/")).ok());
  EXPECT_TRUE(AuthorizeSecurityRequest(Request("/index.html")).ok());
  EXPECT_TRUE(AuthorizeSecurityRequest(Request("/app.js")).ok());
  EXPECT_TRUE(AuthorizeSecurityRequest(Request("/styles.css")).ok());

  for (const std::string path :
       {"/api/v1/health", "/api/v1/stream", "/api/v1/setup/status/extra",
        "/index.html/", "/app.js.map", "/assets/app.js", "/dashboard",
        "/%2e%2e/etc/passwd"}) {
    auto result = AuthorizeSecurityRequest(Request(path));
    ASSERT_FALSE(result.ok()) << path;
    EXPECT_EQ(result.error().code, "E_ACCESS_DENIED") << path;
  }
}

TEST(SecurityRequestGateTest, DefaultStateAdmitsOnlyTheSetupSurface) {
  // Reuses the existing Request() helper (state = kDefault, normalized_peer_ip
  // and expected_origin pre-filled) rather than building a second raw
  // SecurityRequestContext literal.
  const auto context = [](std::string path, std::string method) {
    auto value = Request(std::move(path), std::move(method));
    value.origin = std::string(kOrigin);
    value.has_management_header = true;
    return value;
  };

  const std::vector<std::pair<std::string, std::string>> allowed = {
      {"/api/v1/setup/status", "GET"},      {"/api/v1/auth/login", "POST"},
      {"/api/v1/auth/me", "GET"},           {"/api/v1/auth/logout", "POST"},
      {"/api/v1/setup/initialize", "POST"}, {"/api/v1/setup/runtime", "POST"}};
  for (const auto& [path, method] : allowed) {
    EXPECT_TRUE(AuthorizeSecurityRequest(context(path, method)).ok())
        << path << " " << method;
  }

  const std::vector<std::pair<std::string, std::string>> denied = {
      {"/api/v1/security/users", "GET"}, {"/api/v1/settings/runtime", "GET"},
      {"/api/v1/audit/events", "GET"},   {"/api/v1/monitoring/cameras", "GET"},
      {"/api/v1/cameras", "GET"},        {"/api/v1/system/protection", "GET"},
      {"/api/v1/auth/password", "PUT"},  {"/api/v1/setup/status", "POST"}};
  for (const auto& [path, method] : denied) {
    const auto result = AuthorizeSecurityRequest(context(path, method));
    ASSERT_FALSE(result.ok()) << path << " " << method;
    EXPECT_EQ(result.error().code, "E_ACCESS_DENIED") << path << " " << method;
  }
}

TEST(SecurityRequestGateTest,
     DefaultStateGateDeniesFullRouteMethodMatrixExceptTheSix) {
  // The fixed-list check above only proves the paths someone thought to
  // write down. This crosses every route path known to the operational
  // branch (administrator and viewer routes, audit, settings, camera,
  // security-management, monitoring, ai) plus near-miss variants of the six
  // admitted paths (trailing slash, suffix, prefix, parent) against every
  // HTTP method, and asserts denial for every pair that is not exactly one
  // of the six. Static-asset paths ("/", "/index.html", ...) are excluded:
  // they bypass the device-state gate entirely, before and independent of
  // this task, and are covered by DefaultStateAllowsOnlyExactSetupSurface.
  const auto context = [](std::string path, std::string method) {
    auto value = Request(std::move(path), std::move(method));
    value.origin = std::string(kOrigin);
    value.has_management_header = true;
    return value;
  };

  const std::vector<std::pair<std::string, std::string>> allowed = {
      {"/api/v1/setup/status", "GET"},      {"/api/v1/auth/login", "POST"},
      {"/api/v1/auth/me", "GET"},           {"/api/v1/auth/logout", "POST"},
      {"/api/v1/setup/initialize", "POST"}, {"/api/v1/setup/runtime", "POST"}};

  const std::vector<std::string> paths = {
      // The six admitted paths themselves (every method but the admitted
      // one for each must still be denied).
      "/api/v1/setup/status",
      "/api/v1/auth/login",
      "/api/v1/auth/me",
      "/api/v1/auth/logout",
      "/api/v1/setup/initialize",
      "/api/v1/setup/runtime",
      // Every other known route surface, operational or not.
      "/api/v1/auth/password",
      "/api/v1/auth/reauthenticate",
      "/api/v1/security/users",
      "/api/v1/security/users/7",
      "/api/v1/security/users/7/enabled",
      "/api/v1/security/users/7/password",
      "/api/v1/security/management-ips",
      "/api/v1/security/management-ips/viewer",
      "/api/v1/security/management-ips/viewer/7",
      "/api/v1/audit/status",
      "/api/v1/audit/events",
      "/api/v1/system/protection",
      "/api/v1/system/self-tests",
      "/api/v1/system/integrity-checks",
      "/api/v1/health",
      "/api/v1/cameras",
      "/api/v1/cameras/main/snapshot.jpg",
      "/api/v1/cameras/main/live.mp4",
      "/api/v1/stream",
      "/api/v1/settings/runtime",
      "/api/v1/settings/runtime/apply",
      "/api/v1/settings/runtime/discard",
      "/api/v1/monitoring/cameras",
      "/api/v1/ai/detections",
      "/api/v1/ai/detections/stream",
      "/api/v1/ai/restart",
      "/api/v1/runtime/restart",
      // Near-miss variants of the six admitted paths: a route table keyed
      // on prefix or substring matching would wrongly admit these.
      "/api/v1/setup/status/",
      "/api/v1/setup/status/extra",
      "/api/v1/setup/statusx",
      "/api/v1/auth/login/",
      "/api/v1/auth/loginx",
      "/api/v1/auth/me/",
      "/api/v1/auth/mex",
      "/api/v1/auth/logout/",
      "/api/v1/auth/logoutx",
      "/api/v1/setup/initialize/",
      "/api/v1/setup/initializex",
      "/api/v1/setup/runtime/",
      "/api/v1/setup/runtimex",
      "/api/v1/setup",
      "/api/v1/setup/",
      "/api/v1/auth",
  };

  constexpr std::array<const char*, 5> methods = {"GET", "POST", "PUT", "PATCH",
                                                  "DELETE"};

  std::size_t checked = 0U;
  for (const auto& path : paths) {
    for (const auto* method : methods) {
      const bool is_allowed = std::find(allowed.begin(), allowed.end(),
                                        std::pair<std::string, std::string>{
                                            path, method}) != allowed.end();
      if (is_allowed) {
        continue;
      }
      ++checked;
      const auto result = AuthorizeSecurityRequest(context(path, method));
      ASSERT_FALSE(result.ok()) << path << " " << method;
      EXPECT_EQ(result.error().code, "E_ACCESS_DENIED")
          << path << " " << method;
    }
  }
  // Sanity check that the matrix actually exercised a large number of
  // pairs and did not silently collapse to a near-empty loop.
  EXPECT_GT(checked, 200U);
}

TEST(SecurityRequestGateTest, DefaultGateChecksAllowlistBeforeCsrf) {
  auto denied = Request("/api/v1/ai/restart", "POST");
  auto result = AuthorizeSecurityRequest(denied);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_ACCESS_DENIED");
}

TEST(SecurityRequestGateTest, SetupInitializationRequiresOriginThenHeader) {
  auto context = Request("/api/v1/setup/initialize", "POST");
  auto missing_origin = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(missing_origin.ok());
  EXPECT_EQ(missing_origin.error().code, "E_REQUEST_ORIGIN");

  context.origin = std::string(kOrigin);
  auto missing_header = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(missing_header.ok());
  EXPECT_EQ(missing_header.error().code, "E_REQUEST_HEADER");

  context.has_management_header = true;
  EXPECT_TRUE(AuthorizeSecurityRequest(context).ok());
}

TEST(SecurityRequestGateTest, OperationalSetupIsLockedBeforeOtherChecks) {
  for (const std::string path :
       {"/api/v1/setup/initialize", "/api/v1/setup/runtime"}) {
    auto context = Operational(path, "POST");
    auto result = AuthorizeSecurityRequest(context);
    ASSERT_FALSE(result.ok()) << path;
    EXPECT_EQ(result.error().code, "E_ACCESS_DENIED") << path;
  }
}

TEST(SecurityRequestGateTest, OperationalStatusAndStaticAssetsRemainPublic) {
  EXPECT_TRUE(
      AuthorizeSecurityRequest(Operational("/api/v1/setup/status")).ok());
  EXPECT_TRUE(AuthorizeSecurityRequest(Operational("/app.js")).ok());
}

TEST(SecurityRequestGateTest, OperationalLoginRequiresManagementIpAndCsrf) {
  auto context = Operational("/api/v1/auth/login", "POST");
  context.peer_is_management = false;
  auto wrong_ip = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(wrong_ip.ok());
  EXPECT_EQ(wrong_ip.error().code, "E_ACCESS_DENIED");

  context.peer_is_management = true;
  auto missing_origin = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(missing_origin.ok());
  EXPECT_EQ(missing_origin.error().code, "E_REQUEST_ORIGIN");

  context.origin = std::string(kOrigin);
  auto missing_header = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(missing_header.ok());
  EXPECT_EQ(missing_header.error().code, "E_REQUEST_HEADER");

  context.has_management_header = true;
  EXPECT_TRUE(AuthorizeSecurityRequest(context).ok());
}

TEST(SecurityRequestGateTest, ProtectedRequestOrderingIsIpSessionCsrfRole) {
  auto context = Operational("/api/v1/ai/restart", "POST");
  context.peer_is_management = false;
  auto wrong_ip = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(wrong_ip.ok());
  EXPECT_EQ(wrong_ip.error().code, "E_ACCESS_DENIED");

  context.peer_is_management = true;
  auto missing_session = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(missing_session.ok());
  EXPECT_EQ(missing_session.error().code, "E_AUTHENTICATION_REQUIRED");

  context.principal = Administrator();
  context.origin = "https://attacker.example";
  auto cross_origin = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(cross_origin.ok());
  EXPECT_EQ(cross_origin.error().code, "E_REQUEST_ORIGIN");

  context.origin = std::string(kOrigin);
  auto missing_header = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(missing_header.ok());
  EXPECT_EQ(missing_header.error().code, "E_REQUEST_HEADER");

  context.has_management_header = true;
  context.principal->role = UserRole::kViewer;
  auto wrong_role = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(wrong_role.ok());
  EXPECT_EQ(wrong_role.error().code, "E_AUTHORIZATION_REQUIRED");

  context.principal->role = UserRole::kAdministrator;
  EXPECT_TRUE(AuthorizeSecurityRequest(context).ok());
}

TEST(SecurityRequestGateTest, RuntimeRestartUsesOperationalAdminCsrfPolicy) {
  auto context = ValidManagementPost("/api/v1/runtime/restart");
  EXPECT_TRUE(AuthorizeSecurityRequest(context).ok());

  context.has_management_header = false;
  auto missing_header = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(missing_header.ok());
  EXPECT_EQ(missing_header.error().code, "E_REQUEST_HEADER");

  context.has_management_header = true;
  context.principal->role = UserRole::kViewer;
  auto wrong_role = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(wrong_role.ok());
  EXPECT_EQ(wrong_role.error().code, "E_AUTHORIZATION_REQUIRED");
}

TEST(SecurityRequestGateTest, RuntimeSettingsGetRequiresManagementAdminOnly) {
  auto context = Operational("/api/v1/settings/runtime", "GET");

  auto missing_session = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(missing_session.ok());
  EXPECT_EQ(missing_session.error().code, "E_AUTHENTICATION_REQUIRED");

  context.principal = Administrator();
  EXPECT_TRUE(AuthorizeSecurityRequest(context).ok());

  context.principal->role = UserRole::kViewer;
  auto viewer = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(viewer.ok());
  EXPECT_EQ(viewer.error().code, "E_AUTHORIZATION_REQUIRED");
}

TEST(SecurityRequestGateTest, RuntimeSettingsMutationsRequireCsrfAndAdmin) {
  for (const auto& [path, method] :
       std::vector<std::pair<std::string, std::string>>{
           {"/api/v1/settings/runtime", "PUT"},
           {"/api/v1/settings/runtime/apply", "POST"},
           {"/api/v1/settings/runtime/discard", "POST"},
       }) {
    auto context = Operational(path, method);
    context.principal = Administrator();

    auto missing_origin = AuthorizeSecurityRequest(context);
    ASSERT_FALSE(missing_origin.ok()) << path;
    EXPECT_EQ(missing_origin.error().code, "E_REQUEST_ORIGIN") << path;

    context.origin = std::string(kOrigin);
    auto missing_header = AuthorizeSecurityRequest(context);
    ASSERT_FALSE(missing_header.ok()) << path;
    EXPECT_EQ(missing_header.error().code, "E_REQUEST_HEADER") << path;

    context.has_management_header = true;
    EXPECT_TRUE(AuthorizeSecurityRequest(context).ok()) << path;
  }
}

TEST(SecurityRequestGateTest, RuntimeSettingsRouteMethodsAreExact) {
  for (const auto& [path, method] :
       std::vector<std::pair<std::string, std::string>>{
           {"/api/v1/settings/runtime", "POST"},
           {"/api/v1/settings/runtime", "PATCH"},
           {"/api/v1/settings/runtime", "DELETE"},
           {"/api/v1/settings/runtime/apply", "GET"},
           {"/api/v1/settings/runtime/apply", "PUT"},
           {"/api/v1/settings/runtime/discard", "GET"},
           {"/api/v1/settings/runtime/extra", "GET"},
       }) {
    const auto result =
        AuthorizeSecurityRequest(ValidManagementRequest(path, method));
    ASSERT_FALSE(result.ok()) << path << ' ' << method;
    EXPECT_EQ(result.error().code, "E_ACCESS_DENIED") << path << ' ' << method;
  }
}

TEST(SecurityRequestGateTest,
     ProtectionStatusRequiresManagementAdministratorWithoutCsrf) {
  auto wrong_ip = Operational("/api/v1/system/protection");
  wrong_ip.peer_is_management = false;
  auto denied_ip = AuthorizeSecurityRequest(wrong_ip);
  ASSERT_FALSE(denied_ip.ok());
  EXPECT_EQ(denied_ip.error().code, "E_ACCESS_DENIED");

  auto unauthenticated = Operational("/api/v1/system/protection");
  auto missing = AuthorizeSecurityRequest(unauthenticated);
  ASSERT_FALSE(missing.ok());
  EXPECT_EQ(missing.error().code, "E_AUTHENTICATION_REQUIRED");

  auto viewer = Operational("/api/v1/system/protection");
  viewer.principal = Viewer();
  auto wrong_role = AuthorizeSecurityRequest(viewer);
  ASSERT_FALSE(wrong_role.ok());
  EXPECT_EQ(wrong_role.error().code, "E_AUTHORIZATION_REQUIRED");

  auto administrator = Operational("/api/v1/system/protection");
  administrator.principal = Administrator();
  EXPECT_TRUE(AuthorizeSecurityRequest(administrator).ok());
}

TEST(SecurityRequestGateTest,
     ProtectionStartsRequireAdministratorOriginAndManagementHeader) {
  for (const std::string path :
       {"/api/v1/system/self-tests", "/api/v1/system/integrity-checks"}) {
    auto context = Operational(path, "POST");
    context.principal = Administrator();

    auto missing_origin = AuthorizeSecurityRequest(context);
    ASSERT_FALSE(missing_origin.ok()) << path;
    EXPECT_EQ(missing_origin.error().code, "E_REQUEST_ORIGIN") << path;

    context.origin = std::string(kOrigin);
    auto missing_header = AuthorizeSecurityRequest(context);
    ASSERT_FALSE(missing_header.ok()) << path;
    EXPECT_EQ(missing_header.error().code, "E_REQUEST_HEADER") << path;

    context.has_management_header = true;
    EXPECT_TRUE(AuthorizeSecurityRequest(context).ok()) << path;

    context.principal = Viewer();
    auto viewer = AuthorizeSecurityRequest(context);
    ASSERT_FALSE(viewer.ok()) << path;
    EXPECT_EQ(viewer.error().code, "E_AUTHORIZATION_REQUIRED") << path;
  }
}

TEST(SecurityRequestGateTest,
     ProtectionRoutesRejectWrongMethodsAndUnknownPaths) {
  for (const auto& [path, method] :
       std::vector<std::pair<std::string, std::string>>{
           {"/api/v1/system/protection", "POST"},
           {"/api/v1/system/protection", "PUT"},
           {"/api/v1/system/self-tests", "GET"},
           {"/api/v1/system/self-tests", "PUT"},
           {"/api/v1/system/integrity-checks", "GET"},
           {"/api/v1/system/integrity-checks", "DELETE"},
           {"/api/v1/system/protection/", "GET"},
           {"/api/v1/system/self-tests/extra", "POST"},
           {"/api/v1/system/integrity-check", "POST"},
       }) {
    const auto denied =
        AuthorizeSecurityRequest(ValidManagementRequest(path, method));
    ASSERT_FALSE(denied.ok()) << method << ' ' << path;
    EXPECT_EQ(denied.error().code, "E_ACCESS_DENIED") << method << ' ' << path;
  }
}

TEST(SecurityRequestGateTest,
     ProtectionStartsRequireExactBoundedObjectAndSingleCookie) {
  EXPECT_TRUE(ValidateEmptyJsonObject("{}", "application/json").ok());
  for (const std::string body : {"", "null", "[]", "{\"extra\":true}"}) {
    auto parsed = ValidateEmptyJsonObject(body, "application/json");
    ASSERT_FALSE(parsed.ok()) << body;
    EXPECT_EQ(parsed.error().code, "E_INVALID_REQUEST") << body;
  }
  auto oversized = ValidateEmptyJsonObject(
      std::string(camera_firmware::service::kMaximumSecurityBodyBytes + 1U,
                  ' '),
      "application/json");
  ASSERT_FALSE(oversized.ok());
  EXPECT_EQ(oversized.error().code, "E_REQUEST_TOO_LARGE");

  const std::array<std::string, 2U> duplicate_cookies = {
      "camera_session=" + std::string(64U, 'a'),
      "camera_session=" + std::string(64U, 'b'),
  };
  auto cookie = ParseSessionCookieHeaders(duplicate_cookies);
  ASSERT_FALSE(cookie.ok());
  EXPECT_EQ(cookie.error().code, "E_AUTHENTICATION_REQUIRED");
}

TEST(SecurityRequestGateTest, AuditReadsRequireAdministratorWithoutCsrf) {
  for (const std::string path :
       {"/api/v1/audit/status", "/api/v1/audit/events"}) {
    auto unauthenticated = Operational(path);
    const auto missing = AuthorizeSecurityRequest(unauthenticated);
    ASSERT_FALSE(missing.ok()) << path;
    EXPECT_EQ(missing.error().code, "E_AUTHENTICATION_REQUIRED") << path;

    auto administrator = Operational(path);
    administrator.principal = Administrator();
    EXPECT_TRUE(AuthorizeSecurityRequest(administrator).ok()) << path;

    auto viewer = Operational(path);
    viewer.principal = Viewer();
    const auto denied = AuthorizeSecurityRequest(viewer);
    ASSERT_FALSE(denied.ok()) << path;
    EXPECT_EQ(denied.error().code, "E_AUTHORIZATION_REQUIRED") << path;
  }
}

TEST(SecurityRequestGateTest, AuditRoutesRecognizeOnlyExactGetPaths) {
  struct Route {
    const char* method;
    const char* path;
  };
  constexpr std::array<Route, 8> kUnknownRoutes = {{
      {"POST", "/api/v1/audit/status"},
      {"PUT", "/api/v1/audit/status"},
      {"DELETE", "/api/v1/audit/events"},
      {"PATCH", "/api/v1/audit/events"},
      {"GET", "/api/v1/audit/status/"},
      {"GET", "/api/v1/audit/status/extra"},
      {"GET", "/api/v1/audit/events/"},
      {"GET", "/api/v1/audit/events/extra"},
  }};

  for (const auto& route : kUnknownRoutes) {
    const auto denied = AuthorizeSecurityRequest(
        ValidManagementRequest(route.path, route.method));
    ASSERT_FALSE(denied.ok()) << route.method << ' ' << route.path;
    EXPECT_EQ(denied.error().code, "E_ACCESS_DENIED")
        << route.method << ' ' << route.path;
  }
}

TEST(SecurityRequestGateTest, DefaultStateCannotAccessAuditReads) {
  for (const std::string path :
       {"/api/v1/audit/status", "/api/v1/audit/events"}) {
    const auto denied = AuthorizeSecurityRequest(Request(path));
    ASSERT_FALSE(denied.ok()) << path;
    EXPECT_EQ(denied.error().code, "E_ACCESS_DENIED") << path;
  }
}

TEST(SecurityRequestGateTest, DefaultStateCannotAccessRuntimeSettings) {
  for (const auto& [path, method] :
       std::vector<std::pair<std::string, std::string>>{
           {"/api/v1/settings/runtime", "GET"},
           {"/api/v1/settings/runtime", "PUT"},
           {"/api/v1/settings/runtime/apply", "POST"},
           {"/api/v1/settings/runtime/discard", "POST"},
       }) {
    const auto result = AuthorizeSecurityRequest(Request(path, method));
    ASSERT_FALSE(result.ok()) << path;
    EXPECT_EQ(result.error().code, "E_ACCESS_DENIED") << path;
  }
}

TEST(SecurityRequestGateTest, GetMeNeedsSessionButNotCsrf) {
  auto context = Operational("/api/v1/auth/me");
  auto missing = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(missing.ok());
  EXPECT_EQ(missing.error().code, "E_AUTHENTICATION_REQUIRED");

  context.principal = Administrator();
  EXPECT_TRUE(AuthorizeSecurityRequest(context).ok());
}

TEST(SecurityRequestGateTest,
     UserManagementRoutesRecognizeExactMethodsAndShapes) {
  struct Route {
    const char* method;
    const char* path;
  };
  const std::array<Route, 9> routes = {{
      {"GET", "/api/v1/security/users"},
      {"POST", "/api/v1/security/users"},
      {"PUT", "/api/v1/security/users/7/enabled"},
      {"PUT", "/api/v1/security/users/7/password"},
      {"DELETE", "/api/v1/security/users/7"},
      {"GET", "/api/v1/security/management-ips"},
      {"POST", "/api/v1/security/management-ips/viewer"},
      {"PUT", "/api/v1/security/management-ips/viewer/7"},
      {"DELETE", "/api/v1/security/management-ips/viewer/7"},
  }};

  for (const auto& route : routes) {
    auto context = ValidManagementRequest(route.path, route.method);
    EXPECT_TRUE(AuthorizeSecurityRequest(context).ok())
        << route.method << " " << route.path;
  }

  auto own_password = ValidManagementRequest("/api/v1/auth/password", "PUT");
  EXPECT_TRUE(AuthorizeSecurityRequest(own_password).ok());

  for (const auto& route : std::array<Route, 3>{{
           {"POST", "/api/v1/security/users/"},
           {"PUT", "/api/v1/security/management-ips/viewer/7/extra"},
           {"POST", "/api/v1/auth/password"},
       }}) {
    const auto result = AuthorizeSecurityRequest(
        ValidManagementRequest(route.path, route.method));
    EXPECT_FALSE(result.ok()) << route.method << " " << route.path;
    if (!result.ok()) {
      EXPECT_EQ(result.error().code, "E_ACCESS_DENIED")
          << route.method << " " << route.path;
    }
  }
}

TEST(SecurityRequestGateTest,
     ManagementIpMalformedRoleAndIdsRemainAdministratorProtectedForHandlers) {
  struct Route {
    const char* method;
    const char* path;
  };

  for (const auto& route : std::array<Route, 6>{{
           {"POST", "/api/v1/security/management-ips/operator"},
           {"PUT", "/api/v1/security/management-ips/viewer/0"},
           {"PUT", "/api/v1/security/management-ips/viewer/+7"},
           {"DELETE", "/api/v1/security/management-ips/viewer/07"},
           {"DELETE",
            "/api/v1/security/management-ips/viewer/9223372036854775808"},
           {"DELETE", "/api/v1/security/management-ips/viewer/7x"},
       }}) {
    const auto result = AuthorizeSecurityRequest(
        ValidManagementRequest(route.path, route.method));
    EXPECT_TRUE(result.ok()) << route.method << " " << route.path;

    auto viewer_request = ValidManagementRequest(route.path, route.method);
    viewer_request.principal = Viewer();
    const auto viewer_result = AuthorizeSecurityRequest(viewer_request);
    ASSERT_FALSE(viewer_result.ok()) << route.method << " " << route.path;
    EXPECT_EQ(viewer_result.error().code, "E_AUTHORIZATION_REQUIRED")
        << route.method << " " << route.path;
  }
}

TEST(SecurityRequestGateTest,
     UserManagementMalformedIdsRemainAdministratorProtectedForHandlers) {
  struct Route {
    const char* method;
    const char* path;
  };

  for (const auto& route : std::array<Route, 5>{{
           {"PUT", "/api/v1/security/users/0/enabled"},
           {"PUT", "/api/v1/security/users/+7/password"},
           {"DELETE", "/api/v1/security/users/07"},
           {"DELETE", "/api/v1/security/users/9223372036854775808"},
           {"DELETE", "/api/v1/security/users/7x"},
       }}) {
    const auto result = AuthorizeSecurityRequest(
        ValidManagementRequest(route.path, route.method));
    EXPECT_TRUE(result.ok()) << route.method << " " << route.path;
  }

  for (const auto& route : std::array<Route, 3>{{
           {"PUT", "/api/v1/security/users/7/enabled/extra"},
           {"PUT", "/api/v1/security/users/7/unknown"},
           {"POST", "/api/v1/security/users/7/password"},
       }}) {
    const auto result = AuthorizeSecurityRequest(
        ValidManagementRequest(route.path, route.method));
    ASSERT_FALSE(result.ok()) << route.method << " " << route.path;
    EXPECT_EQ(result.error().code, "E_ACCESS_DENIED")
        << route.method << " " << route.path;
  }
}

TEST(SecurityRequestGateTest, ViewerCanReadOnlyMonitoringMediaAndOwnAuth) {
  for (const std::string path : {
           "/api/v1/auth/me",
           "/api/v1/monitoring/cameras",
           "/api/v1/cameras/main/snapshot.jpg",
           "/api/v1/cameras/main/live.mp4",
           "/api/v1/ai/detections",
           "/api/v1/ai/detections/stream",
       }) {
    auto context = Operational(path);
    context.principal = Viewer();
    EXPECT_TRUE(AuthorizeSecurityRequest(context).ok()) << path;
  }

  auto password = Operational("/api/v1/auth/password", "PUT");
  password.principal = Viewer();
  password.origin = std::string(kOrigin);
  password.has_management_header = true;
  EXPECT_TRUE(AuthorizeSecurityRequest(password).ok());

  auto logout = Operational("/api/v1/auth/logout", "POST");
  logout.principal = Viewer();
  logout.origin = std::string(kOrigin);
  logout.has_management_header = true;
  EXPECT_TRUE(AuthorizeSecurityRequest(logout).ok());

  for (const std::string path : {
           "/api/v1/health",
           "/api/v1/cameras",
           "/api/v1/stream",
           "/api/v1/settings/runtime",
           "/api/v1/security/users",
           "/api/v1/security/management-ips",
       }) {
    auto context = Operational(path);
    context.principal = Viewer();
    const auto result = AuthorizeSecurityRequest(context);
    ASSERT_FALSE(result.ok()) << path;
    EXPECT_EQ(result.error().code, "E_AUTHORIZATION_REQUIRED") << path;
  }

  auto management_mutation = Operational("/api/v1/security/users", "POST");
  management_mutation.principal = Viewer();
  management_mutation.origin = std::string(kOrigin);
  management_mutation.has_management_header = true;
  const auto denied_mutation = AuthorizeSecurityRequest(management_mutation);
  ASSERT_FALSE(denied_mutation.ok());
  EXPECT_EQ(denied_mutation.error().code, "E_AUTHORIZATION_REQUIRED");
}

TEST(SecurityRequestGateTest, RetiredMjpegPreviewIsNotAnOperationalApi) {
  auto context = Operational("/api/v1/cameras/imx708-main/preview.mjpeg");
  context.principal = Administrator();

  const auto result = AuthorizeSecurityRequest(context);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_ACCESS_DENIED");
}

TEST(SecurityRequestGateTest, LiveGetRequiresOneWellFormedCameraPathSegment) {
  auto live = Operational("/api/v1/cameras/imx708-main/live.mp4");
  live.principal = Administrator();
  EXPECT_TRUE(AuthorizeSecurityRequest(live).ok());

  for (const std::string path : {
           "/api/v1/cameras/imx708-main/preview.jpg",
           "/api/v1/cameras//live.mp4",
           "/api/v1/cameras/imx708-main/extra/live.mp4",
           "/api/v1/cameras/imx708-main/live.mp4/extra",
       }) {
    auto malformed = Operational(path);
    malformed.principal = Administrator();
    const auto result = AuthorizeSecurityRequest(malformed);
    ASSERT_FALSE(result.ok()) << path;
    EXPECT_EQ(result.error().code, "E_ACCESS_DENIED") << path;
  }

  auto wrong_live_method =
      Operational("/api/v1/cameras/imx708-main/live.mp4", "POST");
  wrong_live_method.principal = Administrator();
  const auto live_result = AuthorizeSecurityRequest(wrong_live_method);
  ASSERT_FALSE(live_result.ok());
  EXPECT_EQ(live_result.error().code, "E_ACCESS_DENIED");
}

TEST(SecurityRequestGateTest, CanonicalOriginIncludesEffectivePort) {
  auto context = ValidManagementPost("/api/v1/auth/logout");
  EXPECT_TRUE(AuthorizeSecurityRequest(context).ok());

  context.origin = "http://camera.example:443";
  auto wrong_scheme = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(wrong_scheme.ok());
  EXPECT_EQ(wrong_scheme.error().code, "E_REQUEST_ORIGIN");

  context.origin = "https://camera.example:444";
  auto wrong_port = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(wrong_port.ok());
  EXPECT_EQ(wrong_port.error().code, "E_REQUEST_ORIGIN");

  context.origin = "https://camera.example/path";
  auto path = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(path.ok());
  EXPECT_EQ(path.error().code, "E_REQUEST_ORIGIN");
}

TEST(SecurityRequestGateTest, ExpectedPublicUrlPathDoesNotChangeOriginTuple) {
  auto context = ValidManagementPost("/api/v1/auth/logout");
  context.expected_origin = "https://camera.example/management/ui";

  EXPECT_TRUE(AuthorizeSecurityRequest(context).ok());
}

TEST(SecurityRequestGateTest, RejectsUnknownMethodsAndRouteMethodMismatch) {
  auto status_post = Request("/api/v1/setup/status", "POST");
  auto status_result = AuthorizeSecurityRequest(status_post);
  ASSERT_FALSE(status_result.ok());
  EXPECT_EQ(status_result.error().code, "E_ACCESS_DENIED");

  auto malformed = Request("/api/v1/setup/status", "G ET");
  auto malformed_result = AuthorizeSecurityRequest(malformed);
  ASSERT_FALSE(malformed_result.ok());
  EXPECT_EQ(malformed_result.error().code, "E_ACCESS_DENIED");
}

TEST(SecurityRequestGateTest,
     SocketAddressAllowsDhcpOriginsBeforeAndAfterSetup) {
  for (const auto state : {DeviceState::kDefault, DeviceState::kOperational}) {
    for (const std::string address :
         {"198.51.100.60", "198.51.100.81", "2001:db8::60"}) {
      auto context = Operational("/api/v1/auth/login", "POST");
      context.state = state;
      context.expected_origin = "https://198.51.100.61:8443";
      context.local_ip = address;
      context.local_port = 8443;
      context.local_tls = true;
      context.origin =
          "https://" +
          (address.find(':') == std::string::npos ? address
                                                  : "[" + address + "]") +
          ":8443";
      context.has_management_header = true;
      EXPECT_TRUE(AuthorizeSecurityRequest(context).ok()) << address;
      context.has_management_header = false;
      auto denied = AuthorizeSecurityRequest(context);
      ASSERT_FALSE(denied.ok());
      EXPECT_EQ(denied.error().code, "E_REQUEST_HEADER");
    }
  }
}

TEST(SecurityRequestGateTest,
     SocketOriginStillRejectsOtherSitesAndInvalidEndpoints) {
  auto context = Operational("/api/v1/auth/login", "POST");
  context.expected_origin.clear();
  context.local_ip = "198.51.100.60";
  context.local_port = 8443;
  context.local_tls = true;
  context.has_management_header = true;
  for (const std::string origin :
       {"https://attacker.example:8443", "https://198.51.100.61:8443",
        "http://198.51.100.60:8443", "https://198.51.100.60:443",
        "https://198.51.100.60:8443/path", "null", ""}) {
    context.origin = origin;
    auto denied = AuthorizeSecurityRequest(context);
    ASSERT_FALSE(denied.ok()) << origin;
    EXPECT_EQ(denied.error().code, "E_REQUEST_ORIGIN") << origin;
  }
  context.origin = "https://198.51.100.60:8443";
  context.local_tls = false;
  EXPECT_FALSE(AuthorizeSecurityRequest(context).ok());
  context.local_tls = true;
  context.local_port = 0;
  EXPECT_FALSE(AuthorizeSecurityRequest(context).ok());
  context.local_port = 8443;
  for (const std::string address : {"0.0.0.0", "::", "attacker.example", ""}) {
    context.local_ip = address;
    EXPECT_FALSE(AuthorizeSecurityRequest(context).ok());
  }
}

TEST(SecurityRequestGateTest,
     ManagementIpPolicyRequiresAdministratorAndFreshAuthority) {
  auto context =
      ValidManagementRequest("/api/v1/security/management-ip-policy", "PUT");
  EXPECT_TRUE(AuthorizeSecurityRequest(context).ok());
  EXPECT_TRUE(RouteRefreshesManagementDeadline(context.path, context.method));
  context.principal = Viewer();
  auto denied = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(denied.ok());
  EXPECT_EQ(denied.error().code, "E_AUTHORIZATION_REQUIRED");
  context.principal = Administrator();
  context.principal->management_authority_valid = false;
  denied = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(denied.ok());
  EXPECT_EQ(denied.error().code, "E_MANAGEMENT_REAUTHENTICATION_REQUIRED");
  context.method = "GET";
  context.principal = Administrator();
  EXPECT_TRUE(AuthorizeSecurityRequest(context).ok());
  context.state = DeviceState::kDefault;
  EXPECT_FALSE(AuthorizeSecurityRequest(context).ok());
}

TEST(SecurityRequestGateTest,
     SetupAcceptsExplicitIpPolicyAndDefaultsLegacyRequestsToRestricted) {
  const std::string prefix =
      R"({"username":"operator","password":"T4m#pR9vLw","peer_ip":"192.0.2.10")";
  auto legacy = ParseSetupJson(prefix + "}", "application/json");
  ASSERT_TRUE(legacy.ok());
  EXPECT_TRUE(legacy.value().management_ip_restriction_enabled);
  for (const bool enabled : {false, true}) {
    auto parsed =
        ParseSetupJson(prefix + ",\"management_ip_restriction_enabled\":" +
                           (enabled ? "true}" : "false}"),
                       "application/json");
    ASSERT_TRUE(parsed.ok());
    EXPECT_EQ(parsed.value().management_ip_restriction_enabled, enabled);
  }
  for (const std::string suffix :
       {"0}", "\"false\"}", "null}", "falsejunk}",
        "false,\"management_ip_restriction_enabled\":true}"}) {
    EXPECT_FALSE(
        ParseSetupJson(
            prefix + ",\"management_ip_restriction_enabled\":" + suffix,
            "application/json")
            .ok());
  }
}

TEST(SecurityRequestGateTest, SessionCookieIsStrictAndRejectsDuplicates) {
  const std::string token(64U, 'a');
  auto parsed = ParseSessionCookie("camera_session=" + token);
  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  EXPECT_EQ(parsed.value().size(), 32U);

  const std::vector<std::string> invalid = {
      "",
      "camera_session=",
      "camera_session=" + std::string(63U, 'a'),
      "camera_session=" + std::string(64U, 'A'),
      // Two camera_session pairs are ambiguous: the token that reaches
      // Verify would depend on selection order, so both identical and
      // differing duplicates fail closed.
      "camera_session=" + token + "; camera_session=" + token,
      "camera_session=" + token + "; camera_session=" + std::string(64U, 'b'),
      // Space before '=' makes the name "camera_session ", which is not our
      // cookie: RFC 6265 permits no whitespace around '=' in a cookie-pair.
      "camera_session =" + token,
      // A lone foreign pair carries no session at all.
      "theme=dark",
      // Cookie names are case-sensitive: an attacker-planted upper-case
      // variant must not be readable as ours.
      "CAMERA_SESSION=" + token,
      // The ambiguity rule counts every camera_session pair, not only ones
      // whose value could be a token.
      "camera_session=" + token + "; camera_session=short",
      // Only ';' separates pairs. ',' is storable inside a browser cookie
      // value, so a parser that also split on ',' would let a foreign
      // cookie smuggle a camera_session pair into the line.
      "theme=a,camera_session=" + token,
  };
  for (const auto& cookie : invalid) {
    auto result = ParseSessionCookie(cookie);
    ASSERT_FALSE(result.ok()) << cookie;
    EXPECT_EQ(result.error().code, "E_AUTHENTICATION_REQUIRED") << cookie;
  }
}

TEST(SecurityRequestGateTest, SessionCookieSelectsOwnPairAmongForeignCookies) {
  // Browsers scope cookies per host and ignore the port, so any cookie ever
  // set by another service on this address rides every request in the same
  // Cookie line. The parser must select camera_session out of that line
  // (RFC 6265 section 5.4 sends all pairs joined by "; "); rejecting the line
  // outright locks the operator out of every authenticated route.
  const std::string token(64U, 'a');
  const std::string foreign_token(64U, 'b');
  const std::vector<std::string> coexisting = {
      "theme=dark; camera_session=" + token,
      "camera_session=" + token + "; theme=dark",
      "a=1; b=2; camera_session=" + token + "; c=3",
      // A foreign value may itself contain '=' (e.g. a JWT or base64 pad).
      "jwt=h.p=s; camera_session=" + token,
      // No space after the separator.
      "theme=dark;camera_session=" + token,
      // Foreign junk that is not even a pair, and a trailing separator.
      "camera_session=" + token + "; broken",
      "camera_session=" + token + ";",
      // A foreign pair whose value is itself a plausible 64-hex token must
      // not be mistaken for ours.
      "impostor_session=" + foreign_token + "; camera_session=" + token,
      // A case-variant name is a foreign pair, not a duplicate of ours.
      "CAMERA_SESSION=" + foreign_token + "; camera_session=" + token,
      // Whitespace around a segment is trimmed from both edges.
      "camera_session=" + token + " ; theme=dark",
  };
  for (const auto& cookie : coexisting) {
    auto result = ParseSessionCookie(cookie);
    ASSERT_TRUE(result.ok()) << cookie << " -> " << result.error().message;
    ASSERT_EQ(result.value().size(), 32U) << cookie;
    for (std::size_t index = 0; index < result.value().size(); ++index) {
      // 'a' repeated decodes to 0xaa bytes; a wrong selection (the foreign
      // 'b' token decodes to 0xbb) fails here.
      ASSERT_EQ(result.value().data()[index], 0xaaU) << cookie;
    }
  }
}

TEST(SecurityRequestGateTest, RawSessionCookieHeadersRequireExactlyOneField) {
  const std::string token(64U, 'a');
  const std::vector<std::string> one = {"camera_session=" + token};
  auto parsed = ParseSessionCookieHeaders(one);
  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  EXPECT_EQ(parsed.value().size(), 32U);

  const std::vector<std::string> duplicate = {"camera_session=" + token,
                                              "camera_session=" + token};
  EXPECT_FALSE(ParseSessionCookieHeaders(duplicate).ok());
  EXPECT_FALSE(ParseSessionCookieHeaders({}).ok());
}

TEST(SecurityRequestGateTest, CredentialsParseInSituFromSecureBytes) {
  auto login = ParseLoginJson(
      SecureBody(R"({"username":"operator","password":"ValidPass1!"})"),
      "application/json");
  ASSERT_TRUE(login.ok()) << login.error().message;
  EXPECT_EQ(login.value().username, "operator");
  EXPECT_EQ(login.value().password.size(), 11U);

  auto setup = ParseSetupJson(
      SecureBody(
          R"({"username":"operator","password":"ValidPass1!","peer_ip":"192.0.2.10"})"),
      "application/json");
  ASSERT_TRUE(setup.ok()) << setup.error().message;
  EXPECT_EQ(setup.value().confirmed_peer_ip, "192.0.2.10");

  auto escaped = ParseLoginJson(
      SecureBody(R"({"username":"oper\u004Ator","password":"ValidPass1!"})"),
      "application/json");
  ASSERT_TRUE(escaped.ok()) << escaped.error().message;
  EXPECT_EQ(escaped.value().username, "operJtor");
}

TEST(SecurityRequestGateTest, LoginJsonRequiresStrictBoundedObject) {
  auto parsed =
      ParseLoginJson(R"({"username":"operator","password":"ValidPass1!"})",
                     "application/json; charset=utf-8");
  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  EXPECT_EQ(parsed.value().username, "operator");
  EXPECT_EQ(parsed.value().password.size(), 11U);

  const std::vector<std::string> invalid = {
      R"([])",
      R"({"username":"operator"})",
      R"({"password":"ValidPass1!"})",
      R"({"username":"operator","password":"ValidPass1!","extra":1})",
      R"({"username":"operator","username":"other","password":"ValidPass1!"})",
      R"({"username":7,"password":"ValidPass1!"})",
      R"({"username":"operator","password":"ValidPass1!"} trailing)",
  };
  for (const auto& body : invalid) {
    auto result = ParseLoginJson(body, "application/json");
    ASSERT_FALSE(result.ok()) << body;
    EXPECT_EQ(result.error().code, "E_INVALID_REQUEST") << body;
  }
}

TEST(SecurityRequestGateTest, JsonParserEnforcesContentTypeAndAllBounds) {
  auto wrong_type = ParseLoginJson("{}", "text/plain");
  ASSERT_FALSE(wrong_type.ok());
  EXPECT_EQ(wrong_type.error().code, "E_INVALID_REQUEST");

  auto oversized = ParseLoginJson(std::string(4097U, 'x'), "application/json");
  ASSERT_FALSE(oversized.ok());
  EXPECT_EQ(oversized.error().code, "E_REQUEST_TOO_LARGE");

  auto username = ParseLoginJson("{\"username\":\"" + std::string(33U, 'a') +
                                     "\",\"password\":\"ValidPass1!\"}",
                                 "application/json");
  ASSERT_FALSE(username.ok());
  EXPECT_EQ(username.error().code, "E_INVALID_REQUEST");

  auto password = ParseLoginJson("{\"username\":\"operator\",\"password\":\"" +
                                     std::string(129U, 'p') + "\"}",
                                 "application/json");
  ASSERT_FALSE(password.ok());
  EXPECT_EQ(password.error().code, "E_INVALID_REQUEST");

  std::string invalid_utf8 =
      R"({"username":"operator","password":"ValidPass1!)";
  invalid_utf8.push_back(static_cast<char>(0xff));
  invalid_utf8 += R"("})";
  auto encoding = ParseLoginJson(invalid_utf8, "application/json");
  ASSERT_FALSE(encoding.ok());
  EXPECT_EQ(encoding.error().code, "E_INVALID_REQUEST");
}

TEST(SecurityRequestGateTest, SetupJsonRequiresExactPeerFieldAndBounds) {
  auto parsed = ParseSetupJson(
      R"({"username":"operator","password":"ValidPass1!","peer_ip":"2001:db8::1"})",
      "application/json");
  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  EXPECT_EQ(parsed.value().confirmed_peer_ip, "2001:db8::1");

  auto missing =
      ParseSetupJson(R"({"username":"operator","password":"ValidPass1!"})",
                     "application/json");
  ASSERT_FALSE(missing.ok());
  EXPECT_EQ(missing.error().code, "E_INVALID_REQUEST");

  auto oversized_ip = ParseSetupJson(
      "{\"username\":\"operator\",\"password\":\"ValidPass1!\","
      "\"peer_ip\":\"" +
          std::string(46U, '1') + "\"}",
      "application/json");
  ASSERT_FALSE(oversized_ip.ok());
  EXPECT_EQ(oversized_ip.error().code, "E_INVALID_REQUEST");
}

TEST(SecurityRequestGateTest, SetupJsonAcceptsAnOptionalManagementIpArray) {
  // Omitted entirely: the wizard's step 2 may add nothing at all, and every
  // body written before this field existed must keep parsing.
  auto absent = ParseSetupJson(
      R"({"username":"operator","password":"ValidPass1!","peer_ip":"192.0.2.10"})",
      "application/json");
  ASSERT_TRUE(absent.ok()) << absent.error().message;
  EXPECT_TRUE(absent.value().management_ips.empty());

  auto empty = ParseSetupJson(
      R"({"username":"operator","password":"ValidPass1!","peer_ip":"192.0.2.10",)"
      R"("management_ips":[]})",
      "application/json");
  ASSERT_TRUE(empty.ok()) << empty.error().message;
  EXPECT_TRUE(empty.value().management_ips.empty());

  // Key order is not fixed by the parser, so the array is exercised first as
  // well as last.
  auto listed = ParseSetupJson(
      SecureBody(R"({"management_ips":["198.51.100.7","2001:db8::2"],)"
                 R"("username":"operator","password":"ValidPass1!",)"
                 R"("peer_ip":"192.0.2.10"})"),
      "application/json");
  ASSERT_TRUE(listed.ok()) << listed.error().message;
  EXPECT_EQ(listed.value().confirmed_peer_ip, "192.0.2.10");
  EXPECT_EQ(listed.value().management_ips,
            (std::vector<std::string>{"198.51.100.7", "2001:db8::2"}));

  // Elements decode in situ, into the same buffer the elements after them
  // have not been read out of yet. That aliasing exists nowhere else in this
  // parser: every other string it decodes is the last thing it decodes from
  // its own region. So the escapes here are deliberately in the elements that
  // are NOT last — a decoded element has to still be intact after its
  // successors have been decoded over the bytes that followed it. A single
  // element, or escapes only in the final one, cannot show that at all.
  auto escaped = ParseSetupJson(
      SecureBody(R"({"username":"operator","password":"ValidPass1!",)"
                 R"("peer_ip":"192.0.2.10","management_ips":[)"
                 R"("198.51.100.\u0037","2001:db8:\u003a2","203.0.113.94"]})"),
      "application/json");
  ASSERT_TRUE(escaped.ok()) << escaped.error().message;
  EXPECT_EQ(escaped.value().management_ips,
            (std::vector<std::string>{"198.51.100.7", "2001:db8::2",
                                      "203.0.113.94"}));

  // Duplicates survive the parser: deduplication is a setup-time decision, not
  // a wire-shape one, and rejecting them here would abort setup over something
  // harmless.
  auto duplicated = ParseSetupJson(
      R"({"username":"operator","password":"ValidPass1!","peer_ip":"192.0.2.10",)"
      R"("management_ips":["192.0.2.10","192.0.2.10"]})",
      "application/json");
  ASSERT_TRUE(duplicated.ok()) << duplicated.error().message;
  EXPECT_EQ(duplicated.value().management_ips,
            (std::vector<std::string>{"192.0.2.10", "192.0.2.10"}));
}

TEST(SecurityRequestGateTest, SetupJsonRejectsMalformedOrUnboundedIpArrays) {
  const std::string prefix =
      R"({"username":"operator","password":"ValidPass1!",)"
      R"("peer_ip":"192.0.2.10","management_ips":)";
  const std::vector<std::string> invalid = {
      prefix + R"("198.51.100.7"})",
      prefix + R"(7})",
      prefix + R"(null})",
      prefix + R"([7]})",
      prefix + R"([""]})",
      prefix + R"([["198.51.100.7"]]})",
      prefix + R"({"0":"198.51.100.7"}})",
      prefix + R"(["198.51.100.7",]})",
      prefix + R"([,"198.51.100.7"]})",
      prefix + R"(["198.51.100.7"})",
      prefix + R"(["198.51.100.7"]} trailing)",
      R"({"username":"operator","password":"ValidPass1!","peer_ip":"192.0.2.10",)"
      R"("management_ips":["198.51.100.7"],"management_ips":["198.51.100.8"]})",
  };
  for (const auto& body : invalid) {
    auto result = ParseSetupJson(body, "application/json");
    ASSERT_FALSE(result.ok()) << body;
    EXPECT_EQ(result.error().code, "E_INVALID_REQUEST") << body;
  }

  auto oversized_entry = ParseSetupJson(
      R"({"username":"operator","password":"ValidPass1!","peer_ip":"192.0.2.10",)"
      "\"management_ips\":[\"" +
          std::string(46U, '1') + "\"]}",
      "application/json");
  ASSERT_FALSE(oversized_entry.ok());
  EXPECT_EQ(oversized_entry.error().code, "E_INVALID_REQUEST");

  // 32 is the store's per-role ceiling on management_ips rows; a body naming
  // more addresses than the device could ever hold is refused before any of it
  // is trusted.
  const auto body_with = [](std::size_t count) {
    std::string body = R"({"username":"operator","password":"ValidPass1!",)"
                       R"("peer_ip":"192.0.2.10","management_ips":[)";
    for (std::size_t index = 0U; index < count; ++index) {
      body += (index == 0U ? "\"198.51.100." : ",\"198.51.100.") +
              std::to_string(index + 1U) + "\"";
    }
    body += "]}";
    return body;
  };
  auto at_limit = ParseSetupJson(body_with(32U), "application/json");
  ASSERT_TRUE(at_limit.ok()) << at_limit.error().message;
  EXPECT_EQ(at_limit.value().management_ips.size(), 32U);

  auto over_limit = ParseSetupJson(body_with(33U), "application/json");
  ASSERT_FALSE(over_limit.ok());
  EXPECT_EQ(over_limit.error().code, "E_INVALID_REQUEST");

  // The list belongs to setup only. Login has no use for it and must keep
  // rejecting every key it does not name.
  auto login_with_list =
      ParseLoginJson(R"({"username":"operator","password":"ValidPass1!",)"
                     R"("management_ips":["198.51.100.7"]})",
                     "application/json");
  ASSERT_FALSE(login_with_list.ok());
  EXPECT_EQ(login_with_list.error().code, "E_INVALID_REQUEST");
}

TEST(SecurityRequestGateTest, ReauthenticateJsonRequiresStrictBoundedObject) {
  auto parsed =
      ParseReauthenticateJson(SecureBody(R"({"password":"ValidPass1!"})"),
                              "application/json; charset=utf-8");
  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  EXPECT_EQ(parsed.value().size(), 11U);

  const std::vector<std::string> invalid = {
      R"([])",
      R"({})",
      R"({"username":"operator"})",
      R"({"password":"ValidPass1!","role":"administrator"})",
      R"({"password":"ValidPass1!","password":"OtherPass1!"})",
      R"({"password":7})",
      R"({"password":"ValidPass1!"} trailing)",
  };
  for (const auto& body : invalid) {
    auto result = ParseReauthenticateJson(SecureBody(body), "application/json");
    ASSERT_FALSE(result.ok()) << body;
    EXPECT_EQ(result.error().code, "E_INVALID_REQUEST") << body;
  }

  auto wrong_type = ParseReauthenticateJson(
      SecureBody(R"({"password":"ValidPass1!"})"), "text/plain");
  ASSERT_FALSE(wrong_type.ok());
  EXPECT_EQ(wrong_type.error().code, "E_INVALID_REQUEST");

  auto absent_type =
      ParseReauthenticateJson(SecureBody(R"({"password":"ValidPass1!"})"), "");
  ASSERT_FALSE(absent_type.ok());
  EXPECT_EQ(absent_type.error().code, "E_INVALID_REQUEST");

  auto oversized_body = ParseReauthenticateJson(
      SecureBody(std::string(4097U, 'x')), "application/json");
  ASSERT_FALSE(oversized_body.ok());
  EXPECT_EQ(oversized_body.error().code, "E_REQUEST_TOO_LARGE");

  auto oversized_password = ParseReauthenticateJson(
      SecureBody("{\"password\":\"" + std::string(129U, 'p') + "\"}"),
      "application/json");
  ASSERT_FALSE(oversized_password.ok());
  EXPECT_EQ(oversized_password.error().code, "E_INVALID_REQUEST");
}

TEST(SecurityRequestGateTest, RuntimeRetryRequiresAnExactEmptyJsonObject) {
  EXPECT_TRUE(ValidateEmptyJsonObject(" { \n } ", "application/json").ok());

  for (const std::string body : {"", "null", "[]", "{\"peer_ip\":\"x\"}"}) {
    auto parsed = ValidateEmptyJsonObject(body, "application/json");
    ASSERT_FALSE(parsed.ok()) << body;
    EXPECT_EQ(parsed.error().code, "E_INVALID_REQUEST") << body;
  }
  auto wrong_type = ValidateEmptyJsonObject("{}", "text/plain");
  ASSERT_FALSE(wrong_type.ok());
  EXPECT_EQ(wrong_type.error().code, "E_INVALID_REQUEST");
  auto oversized =
      ValidateEmptyJsonObject(std::string(4097U, ' '), "application/json");
  ASSERT_FALSE(oversized.ok());
  EXPECT_EQ(oversized.error().code, "E_REQUEST_TOO_LARGE");
  for (const std::string body : {"{\v}", "{\f}"}) {
    auto non_json_whitespace =
        ValidateEmptyJsonObject(body, "application/json");
    ASSERT_FALSE(non_json_whitespace.ok()) << body;
    EXPECT_EQ(non_json_whitespace.error().code, "E_INVALID_REQUEST") << body;
  }
}

TEST(SecurityRequestGateTest, ManagementDeadlineRefreshClassification) {
  const std::vector<std::pair<std::string, std::string>> refreshing = {
      {"/api/v1/security/users", "GET"},
      {"/api/v1/security/users", "POST"},
      {"/api/v1/security/users/7", "DELETE"},
      {"/api/v1/security/users/7/enabled", "PUT"},
      {"/api/v1/security/users/7/password", "PUT"},
      {"/api/v1/security/management-ips", "GET"},
      {"/api/v1/security/management-ips/administrator", "POST"},
      {"/api/v1/security/management-ips/administrator/3", "PUT"},
      {"/api/v1/security/management-ips/administrator/3", "DELETE"},
      {"/api/v1/audit/events", "GET"},
      {"/api/v1/settings/runtime", "GET"},
      {"/api/v1/settings/runtime", "PUT"},
      {"/api/v1/settings/runtime/apply", "POST"},
      {"/api/v1/settings/runtime/discard", "POST"},
      {"/api/v1/system/self-tests", "POST"},
      {"/api/v1/system/integrity-checks", "POST"},
      {"/api/v1/runtime/restart", "POST"},
      {"/api/v1/ai/restart", "POST"}};
  for (const auto& [path, method] : refreshing) {
    EXPECT_TRUE(RouteRefreshesManagementDeadline(path, method))
        << path << " " << method;
  }

  const std::vector<std::pair<std::string, std::string>> non_refreshing = {
      {"/api/v1/health", "GET"},
      {"/api/v1/setup/status", "GET"},
      {"/api/v1/auth/me", "GET"},
      {"/api/v1/auth/login", "POST"},
      {"/api/v1/auth/logout", "POST"},
      {"/api/v1/auth/password", "PUT"},
      {"/api/v1/auth/reauthenticate", "POST"},
      {"/api/v1/monitoring/cameras", "GET"},
      {"/api/v1/cameras", "GET"},
      {"/api/v1/cameras/imx708-main/snapshot.jpg", "GET"},
      {"/api/v1/cameras/imx708-main/live.mp4", "GET"},
      {"/api/v1/stream", "GET"},
      {"/api/v1/ai/detections", "GET"},
      {"/api/v1/ai/detections/stream", "GET"},
      {"/api/v1/audit/status", "GET"},
      {"/api/v1/system/protection", "GET"},
      {"/api/v1/unknown/route", "GET"}};
  for (const auto& [path, method] : non_refreshing) {
    EXPECT_FALSE(RouteRefreshesManagementDeadline(path, method))
        << path << " " << method;
  }
}

TEST(SecurityRequestGateTest,
     LapsedManagementAuthorityIsRefusedOnlyOnRefreshingRoutes) {
  const auto context = [](std::string path, std::string method,
                          bool management_valid) {
    SecurityRequestContext value;
    value.state = DeviceState::kOperational;
    value.path = std::move(path);
    value.method = std::move(method);
    value.normalized_peer_ip = "192.0.2.10";
    value.peer_is_management = true;
    value.origin = "https://camera.example";
    value.expected_origin = "https://camera.example";
    value.has_management_header = true;
    Principal principal;
    principal.user_id = 1;
    principal.username = "Operator.One";
    principal.role = UserRole::kAdministrator;
    principal.management_authority_valid = management_valid;
    value.principal = std::move(principal);
    return value;
  };

  const auto refused =
      AuthorizeSecurityRequest(context("/api/v1/security/users", "GET", false));
  ASSERT_FALSE(refused.ok());
  EXPECT_EQ(refused.error().code, "E_MANAGEMENT_REAUTHENTICATION_REQUIRED");
  EXPECT_EQ(refused.error().message, "management reauthentication required");

  EXPECT_TRUE(
      AuthorizeSecurityRequest(context("/api/v1/security/users", "GET", true))
          .ok());
  EXPECT_TRUE(AuthorizeSecurityRequest(
                  context("/api/v1/monitoring/cameras", "GET", false))
                  .ok());
  EXPECT_TRUE(
      AuthorizeSecurityRequest(context("/api/v1/audit/status", "GET", false))
          .ok());
}

TEST(BoundedWorkerTest, SubmitDoesNotBlockCallingThread) {
  BoundedWorker worker(2U);
  std::promise<void> started;
  std::promise<void> release;
  auto release_future = release.get_future().share();
  ASSERT_TRUE(worker
                  .Submit([&] {
                    started.set_value();
                    release_future.wait();
                  })
                  .ok());
  started.get_future().wait();

  const auto before = std::chrono::steady_clock::now();
  auto submitted = worker.Submit([] {});
  const auto elapsed = std::chrono::steady_clock::now() - before;

  EXPECT_TRUE(submitted.ok());
  EXPECT_LT(elapsed, std::chrono::milliseconds(100));
  release.set_value();
  worker.Stop();
}

TEST(BoundedWorkerTest, QueueOverflowFailsClosed) {
  BoundedWorker worker(2U);
  std::promise<void> started;
  std::promise<void> release;
  auto release_future = release.get_future().share();
  ASSERT_TRUE(worker
                  .Submit([&] {
                    started.set_value();
                    release_future.wait();
                  })
                  .ok());
  started.get_future().wait();

  EXPECT_TRUE(worker.Submit([] {}).ok());
  EXPECT_TRUE(worker.Submit([] {}).ok());
  auto overflow = worker.Submit([] {});
  ASSERT_FALSE(overflow.ok());
  EXPECT_EQ(overflow.error().code, "E_SECURITY_UNAVAILABLE");

  release.set_value();
  worker.Stop();
}

TEST(BoundedWorkerTest, ThrownTaskDoesNotStopLaterTasks) {
  BoundedWorker worker(2U);
  std::promise<void> completed;
  ASSERT_TRUE(worker.Submit([] { throw std::runtime_error("test"); }).ok());
  ASSERT_TRUE(worker.Submit([&] { completed.set_value(); }).ok());
  EXPECT_EQ(completed.get_future().wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  worker.Stop();
}

TEST(BoundedWorkerTest, StopDrainsAcceptedTasksAndIsTerminal) {
  BoundedWorker worker(4U);
  std::atomic<int> calls{0};
  for (int i = 0; i < 4; ++i) {
    ASSERT_TRUE(worker.Submit([&] { calls.fetch_add(1); }).ok());
  }
  worker.Stop();
  worker.Stop();

  EXPECT_EQ(calls.load(), 4);
  auto after_stop = worker.Submit([&] { calls.fetch_add(1); });
  ASSERT_FALSE(after_stop.ok());
  EXPECT_EQ(after_stop.error().code, "E_SECURITY_UNAVAILABLE");
  EXPECT_EQ(calls.load(), 4);
}

TEST(BoundedWorkerTest, StopRequestedByWorkerTaskIsTerminal) {
  BoundedWorker worker(2U);
  std::promise<void> returned_from_stop;
  ASSERT_TRUE(worker
                  .Submit([&] {
                    worker.Stop();
                    returned_from_stop.set_value();
                  })
                  .ok());

  EXPECT_EQ(returned_from_stop.get_future().wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  worker.Stop();
  EXPECT_FALSE(worker.Submit([] {}).ok());
}

TEST(BoundedWorkerTest, ExternalAndWorkerStopRaceDoesNotDeadlock) {
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(2U);
    BoundedWorker worker(2U);
    std::promise<void> task_started;
    std::promise<void> release_task;
    auto release_future = release_task.get_future().share();
    if (!worker
             .Submit([&] {
               task_started.set_value();
               release_future.wait();
               worker.Stop();
             })
             .ok()) {
      _exit(2);
    }
    task_started.get_future().wait();
    std::thread external_stop([&] { worker.Stop(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    release_task.set_value();
    external_stop.join();
    _exit(0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(BoundedWorkerTest, ConcurrentStopCallersWaitForWorkerDrain) {
  BoundedWorker worker(2U);
  std::promise<void> task_started;
  std::promise<void> release_task;
  auto release_future = release_task.get_future().share();
  std::atomic<int> completed{0};
  ASSERT_TRUE(worker
                  .Submit([&] {
                    task_started.set_value();
                    release_future.wait();
                    worker.Stop();
                    completed.fetch_add(1);
                  })
                  .ok());
  ASSERT_TRUE(worker.Submit([&] { completed.fetch_add(1); }).ok());
  task_started.get_future().wait();

  std::array<std::future<void>, 4U> stoppers;
  for (auto& stopper : stoppers) {
    stopper = std::async(std::launch::async, [&] { worker.Stop(); });
  }
  for (auto& stopper : stoppers) {
    EXPECT_EQ(stopper.wait_for(std::chrono::milliseconds(20)),
              std::future_status::timeout);
  }

  release_task.set_value();
  for (auto& stopper : stoppers) {
    EXPECT_EQ(stopper.wait_for(std::chrono::seconds(1)),
              std::future_status::ready);
  }
  EXPECT_EQ(completed.load(), 2);
}

TEST(BoundedWorkerTest, LastOwnerMayBeReleasedByWorkerTask) {
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(2U);
    std::promise<void> task_ran;
    auto worker = std::make_shared<BoundedWorker>(2U);
    if (!worker->Submit([owner = worker, &task_ran] { task_ran.set_value(); })
             .ok()) {
      _exit(2);
    }
    worker.reset();
    if (task_ran.get_future().wait_for(std::chrono::seconds(1)) !=
        std::future_status::ready) {
      _exit(3);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    _exit(0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(BoundedWorkerTest, SubmitStopRaceExecutesEachAcceptedTaskExactlyOnce) {
  BoundedWorker worker(16U);
  std::atomic<int> accepted{0};
  std::atomic<int> executed{0};
  std::atomic<int> duplicate{0};
  std::vector<std::atomic<int>> per_task(128);
  for (auto& count : per_task) {
    count.store(0);
  }

  std::vector<std::thread> submitters;
  for (int thread_index = 0; thread_index < 4; ++thread_index) {
    submitters.emplace_back([&, thread_index] {
      for (int index = thread_index; index < 128; index += 4) {
        auto result = worker.Submit([&, index] {
          if (per_task[static_cast<std::size_t>(index)].fetch_add(1) != 0) {
            duplicate.fetch_add(1);
          }
          executed.fetch_add(1);
        });
        if (result.ok()) {
          accepted.fetch_add(1);
        }
      }
    });
  }
  std::thread stopper([&] { worker.Stop(); });
  for (auto& submitter : submitters) {
    submitter.join();
  }
  stopper.join();

  EXPECT_EQ(executed.load(), accepted.load());
  EXPECT_EQ(duplicate.load(), 0);
}

}  // namespace
