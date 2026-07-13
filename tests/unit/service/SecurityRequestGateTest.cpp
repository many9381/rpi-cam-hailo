#include "camera_firmware/service/BoundedWorker.hpp"
#include "camera_firmware/service/SecurityRequestGate.hpp"

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
using camera_firmware::service::ParseSessionCookie;
using camera_firmware::service::ParseSessionCookieHeaders;
using camera_firmware::service::ParseSetupJson;
using camera_firmware::service::SecurityRequestContext;
using camera_firmware::service::ValidateEmptyJsonObject;

constexpr std::string_view kOrigin = "https://camera.example";

SecureBytes SecureBody(std::string_view text) {
  SecureBytes body;
  body.assign(reinterpret_cast<const unsigned char*>(text.data()), text.size());
  return body;
}

Principal Administrator() {
  return {1, "operator", UserRole::kAdministrator};
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

  for (const std::string path : {
           "/api/v1/health", "/api/v1/stream",
           "/api/v1/setup/status/extra", "/index.html/", "/app.js.map",
           "/assets/app.js", "/dashboard", "/%2e%2e/etc/passwd"}) {
    auto result = AuthorizeSecurityRequest(Request(path));
    ASSERT_FALSE(result.ok()) << path;
    EXPECT_EQ(result.error().code, "E_ACCESS_DENIED") << path;
  }
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
  for (const std::string path : {"/api/v1/setup/initialize",
                                 "/api/v1/setup/runtime"}) {
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

TEST(SecurityRequestGateTest, GetMeNeedsSessionButNotCsrf) {
  auto context = Operational("/api/v1/auth/me");
  auto missing = AuthorizeSecurityRequest(context);
  ASSERT_FALSE(missing.ok());
  EXPECT_EQ(missing.error().code, "E_AUTHENTICATION_REQUIRED");

  context.principal = Administrator();
  EXPECT_TRUE(AuthorizeSecurityRequest(context).ok());
}

TEST(SecurityRequestGateTest, PreviewGetRequiresOneWellFormedCameraPathSegment) {
  auto valid = Operational("/api/v1/cameras/imx708-main/preview.mjpeg");
  valid.principal = Administrator();
  EXPECT_TRUE(AuthorizeSecurityRequest(valid).ok());

  for (const std::string path : {
           "/api/v1/cameras//preview.mjpeg",
           "/api/v1/cameras/imx708-main/extra/preview.mjpeg",
           "/api/v1/cameras/imx708-main/preview.mjpeg/extra",
           "/api/v1/cameras/imx708-main/preview.jpg",
       }) {
    auto malformed = Operational(path);
    malformed.principal = Administrator();
    const auto result = AuthorizeSecurityRequest(malformed);
    ASSERT_FALSE(result.ok()) << path;
    EXPECT_EQ(result.error().code, "E_ACCESS_DENIED") << path;
  }

  auto wrong_method = Operational(
      "/api/v1/cameras/imx708-main/preview.mjpeg", "POST");
  wrong_method.principal = Administrator();
  const auto result = AuthorizeSecurityRequest(wrong_method);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_ACCESS_DENIED");
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

TEST(SecurityRequestGateTest, SessionCookieIsStrictAndRejectsDuplicates) {
  const std::string token(64U, 'a');
  auto parsed = ParseSessionCookie("camera_session=" + token);
  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  EXPECT_EQ(parsed.value().size(), 32U);

  std::vector<std::string> invalid = {
      "", "camera_session=", "camera_session=" + std::string(63U, 'a'),
      "camera_session=" + std::string(64U, 'A'),
      "camera_session=" + token + "; camera_session=" + token,
      "camera_session=" + token + "; broken", "camera_session =" + token};
  invalid.push_back("camera_session=" + token + ";");
  invalid.push_back("theme=dark; camera_session=" + token);
  for (const auto& cookie : invalid) {
    auto result = ParseSessionCookie(cookie);
    ASSERT_FALSE(result.ok()) << cookie;
    EXPECT_EQ(result.error().code, "E_AUTHENTICATION_REQUIRED") << cookie;
  }
}

TEST(SecurityRequestGateTest, RawSessionCookieHeadersRequireExactlyOneField) {
  const std::string token(64U, 'a');
  const std::vector<std::string> one = {"camera_session=" + token};
  auto parsed = ParseSessionCookieHeaders(one);
  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  EXPECT_EQ(parsed.value().size(), 32U);

  const std::vector<std::string> duplicate = {
      "camera_session=" + token, "camera_session=" + token};
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
  auto parsed = ParseLoginJson(
      R"({"username":"operator","password":"ValidPass1!"})",
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

  auto username = ParseLoginJson(
      "{\"username\":\"" + std::string(33U, 'a') +
          "\",\"password\":\"ValidPass1!\"}",
      "application/json");
  ASSERT_FALSE(username.ok());
  EXPECT_EQ(username.error().code, "E_INVALID_REQUEST");

  auto password = ParseLoginJson(
      "{\"username\":\"operator\",\"password\":\"" +
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

  auto missing = ParseSetupJson(
      R"({"username":"operator","password":"ValidPass1!"})",
      "application/json");
  ASSERT_FALSE(missing.ok());
  EXPECT_EQ(missing.error().code, "E_INVALID_REQUEST");

  auto oversized_ip = ParseSetupJson(
      "{\"username\":\"operator\",\"password\":\"ValidPass1!\","
      "\"peer_ip\":\"" + std::string(46U, '1') + "\"}",
      "application/json");
  ASSERT_FALSE(oversized_ip.ok());
  EXPECT_EQ(oversized_ip.error().code, "E_INVALID_REQUEST");
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
  auto oversized = ValidateEmptyJsonObject(std::string(4097U, ' '),
                                           "application/json");
  ASSERT_FALSE(oversized.ok());
  EXPECT_EQ(oversized.error().code, "E_REQUEST_TOO_LARGE");
  for (const std::string body : {"{\v}", "{\f}"}) {
    auto non_json_whitespace = ValidateEmptyJsonObject(body, "application/json");
    ASSERT_FALSE(non_json_whitespace.ok()) << body;
    EXPECT_EQ(non_json_whitespace.error().code, "E_INVALID_REQUEST") << body;
  }
}

TEST(BoundedWorkerTest, SubmitDoesNotBlockCallingThread) {
  BoundedWorker worker(2U);
  std::promise<void> started;
  std::promise<void> release;
  auto release_future = release.get_future().share();
  ASSERT_TRUE(worker.Submit([&] {
    started.set_value();
    release_future.wait();
  }).ok());
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
  ASSERT_TRUE(worker.Submit([&] {
    started.set_value();
    release_future.wait();
  }).ok());
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
  ASSERT_TRUE(worker.Submit([&] {
    worker.Stop();
    returned_from_stop.set_value();
  }).ok());

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
    if (!worker.Submit([&] {
          task_started.set_value();
          release_future.wait();
          worker.Stop();
        }).ok()) {
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
  ASSERT_TRUE(worker.Submit([&] {
    task_started.set_value();
    release_future.wait();
    worker.Stop();
    completed.fetch_add(1);
  }).ok());
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
