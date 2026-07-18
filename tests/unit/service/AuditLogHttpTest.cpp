#include "camera_firmware/service/AuditLogHttp.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <gtest/gtest.h>
#include <trantor/net/EventLoopThread.h>

#include "camera_firmware/security/AuthService.hpp"
#include "camera_firmware/security/AuditLogService.hpp"
#include "camera_firmware/security/SecurityStore.hpp"
#include "camera_firmware/service/BoundedWorker.hpp"
#include "camera_firmware/service/ServiceApp.hpp"

namespace camera_firmware::service::internal {

using AuditHandlerCallbackForTesting =
    std::function<void(const drogon::HttpResponsePtr&)>;

void HandleAuthorizedAuditStatusForTesting(
    security::Principal principal,
    std::shared_ptr<security::AuditLogService> service,
    std::shared_ptr<BoundedWorker> worker,
    bool shutting_down,
    trantor::EventLoop* event_loop,
    AuditHandlerCallbackForTesting callback);
void HandleAuthorizedAuditEventsForTesting(
    security::Principal principal,
    security::AuditQueryParameters parameters,
    std::shared_ptr<security::AuditLogService> service,
    std::shared_ptr<BoundedWorker> worker,
    bool shutting_down,
    trantor::EventLoop* event_loop,
    AuditHandlerCallbackForTesting callback);
void InstallAuditDependenciesForShutdownTesting(
    std::shared_ptr<security::AuditLogService> service,
    std::shared_ptr<BoundedWorker> worker) noexcept;
bool AuditShutdownStartedForTesting() noexcept;
void FailNextTerminalResponseQueueForTesting() noexcept;
void ResetTerminalResponseQueueFailureForTesting() noexcept;

}  // namespace camera_firmware::service::internal

namespace {

using namespace std::chrono_literals;

using camera_firmware::security::AuditEvent;
using camera_firmware::security::AuditEventPage;
using camera_firmware::security::AuditLogService;
using camera_firmware::security::AuditQueryParameters;
using camera_firmware::security::AuditStatus;
using camera_firmware::security::Principal;
using camera_firmware::security::SecurityStore;
using camera_firmware::security::UserRole;
using camera_firmware::service::BoundedWorker;
using camera_firmware::service::BuildAuditEventPageJson;
using camera_firmware::service::BuildAuditLogErrorResponse;
using camera_firmware::service::BuildAuditStatusJson;
using camera_firmware::service::ParseAuditEventQuery;
using camera_firmware::service::ValidateEmptyAuditStatusQuery;

void ExpectExactKeys(const Json::Value& value,
                     std::initializer_list<std::string_view> expected) {
  ASSERT_TRUE(value.isObject());
  std::set<std::string> actual_keys;
  for (const auto& key : value.getMemberNames()) {
    actual_keys.insert(key);
  }
  std::set<std::string> expected_keys;
  for (const auto key : expected) {
    expected_keys.emplace(key);
  }
  EXPECT_EQ(actual_keys, expected_keys);
}

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 48> pattern{"/tmp/cf-audit-http-async-XXXXXX"};
    char* created = ::mkdtemp(pattern.data());
    if (created == nullptr) {
      throw std::system_error(errno, std::generic_category(), "mkdtemp");
    }
    path_ = created;
  }

  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept {
    return path_;
  }

 private:
  std::filesystem::path path_;
};

class RunningEventLoop {
 public:
  RunningEventLoop() { thread_.run(); }

  ~RunningEventLoop() {
    if (thread_.getLoop() != nullptr) {
      thread_.getLoop()->quit();
    }
    thread_.wait();
  }

  RunningEventLoop(const RunningEventLoop&) = delete;
  RunningEventLoop& operator=(const RunningEventLoop&) = delete;

  [[nodiscard]] trantor::EventLoop* get() const noexcept {
    return thread_.getLoop();
  }

  [[nodiscard]] bool Drain() const {
    std::promise<void> drained;
    auto future = drained.get_future();
    get()->queueInLoop([&drained] { drained.set_value(); });
    return future.wait_for(2s) == std::future_status::ready;
  }

 private:
  trantor::EventLoopThread thread_{"AuditLogHttpTest"};
};

class ResponseRecorder {
 public:
  void Record(const drogon::HttpResponsePtr& response) {
    {
      std::lock_guard lock(mutex_);
      responses_.push_back(response);
    }
    changed_.notify_all();
  }

  [[nodiscard]] bool WaitForCount(std::size_t count) {
    std::unique_lock lock(mutex_);
    return changed_.wait_for(lock, 2s,
                             [&] { return responses_.size() >= count; });
  }

  [[nodiscard]] std::size_t count() const {
    std::lock_guard lock(mutex_);
    return responses_.size();
  }

  [[nodiscard]] drogon::HttpResponsePtr first() const {
    std::lock_guard lock(mutex_);
    return responses_.empty() ? nullptr : responses_.front();
  }

 private:
  mutable std::mutex mutex_;
  std::condition_variable changed_;
  std::vector<drogon::HttpResponsePtr> responses_;
};

class PromiseReleaseGuard {
 public:
  explicit PromiseReleaseGuard(std::promise<void>& release)
      : release_(release) {}

  ~PromiseReleaseGuard() { Release(); }

  void Release() noexcept {
    if (released_.exchange(true)) {
      return;
    }
    try {
      release_.set_value();
    } catch (...) {
    }
  }

 private:
  std::promise<void>& release_;
  std::atomic<bool> released_{false};
};

enum class AuditRoute { kStatus, kEvents };

Principal Administrator() {
  return {1, "owner1", UserRole::kAdministrator, {}};
}

std::unique_ptr<SecurityStore> OpenStore(
    const std::filesystem::path& state_directory) {
  auto opened = SecurityStore::Open({state_directory, 50U, 80U});
  if (!opened.ok()) {
    throw std::runtime_error(opened.error().message);
  }
  return std::move(opened).value();
}

void InvokeAuthorizedAuditHandler(
    AuditRoute route,
    const std::shared_ptr<AuditLogService>& service,
    const std::shared_ptr<BoundedWorker>& worker,
    bool shutting_down,
    trantor::EventLoop* event_loop,
    camera_firmware::service::internal::AuditHandlerCallbackForTesting
        callback) {
  if (route == AuditRoute::kStatus) {
    camera_firmware::service::internal::HandleAuthorizedAuditStatusForTesting(
        Administrator(), service, worker, shutting_down, event_loop,
        std::move(callback));
    return;
  }
  camera_firmware::service::internal::HandleAuthorizedAuditEventsForTesting(
      Administrator(), AuditQueryParameters{}, service, worker, shutting_down,
      event_loop, std::move(callback));
}

void ExpectSanitizedUnavailable(const ResponseRecorder& recorder) {
  ASSERT_EQ(recorder.count(), 1U);
  const auto response = recorder.first();
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
  const auto json = response->getJsonObject();
  ASSERT_NE(json, nullptr);
  ExpectExactKeys(*json, {"code", "message"});
  EXPECT_EQ((*json)["code"].asString(), "E_AUDIT_UNAVAILABLE");
  EXPECT_EQ((*json)["message"].asString(),
            "Audit records are temporarily unavailable.");
}

bool WaitForAuditShutdownStart() {
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (std::chrono::steady_clock::now() < deadline) {
    if (camera_firmware::service::internal::
            AuditShutdownStartedForTesting()) {
      return true;
    }
    std::this_thread::yield();
  }
  return false;
}

TEST(AuditLogHttpTest, EmptyEventQueryPreservesServiceDefaults) {
  const auto parsed = ParseAuditEventQuery("");

  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  const auto& query = parsed.value();
  EXPECT_FALSE(query.from_seconds.has_value());
  EXPECT_FALSE(query.to_seconds.has_value());
  EXPECT_FALSE(query.event_type.has_value());
  EXPECT_FALSE(query.outcome.has_value());
  EXPECT_FALSE(query.actor_identity.has_value());
  EXPECT_FALSE(query.peer_ip.has_value());
  EXPECT_FALSE(query.subject_type.has_value());
  EXPECT_FALSE(query.subject_identity.has_value());
  EXPECT_FALSE(query.sort_by.has_value());
  EXPECT_FALSE(query.sort_direction.has_value());
  EXPECT_FALSE(query.limit.has_value());
  EXPECT_FALSE(query.cursor.has_value());
}

TEST(AuditLogHttpTest, EventQueryStrictlyDecodesEveryKnownParameter) {
  const auto parsed = ParseAuditEventQuery(
      "from_seconds=10&to_seconds=20&event%5Ftype=user%5Fcreated&"
      "outcome=success&actor_identity=camera+owner&"
      "peer_ip=2001%3Adb8%3A%3A1&subject_type=user&"
      "subject_identity=viewer%2B1&sort_by=event_type&"
      "sort_direction=asc&limit=25&cursor=AQID");

  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  const auto& query = parsed.value();
  EXPECT_EQ(query.from_seconds, "10");
  EXPECT_EQ(query.to_seconds, "20");
  EXPECT_EQ(query.event_type, "user_created");
  EXPECT_EQ(query.outcome, "success");
  EXPECT_EQ(query.actor_identity, "camera owner");
  EXPECT_EQ(query.peer_ip, "2001:db8::1");
  EXPECT_EQ(query.subject_type, "user");
  EXPECT_EQ(query.subject_identity, "viewer+1");
  EXPECT_EQ(query.sort_by, "event_type");
  EXPECT_EQ(query.sort_direction, "asc");
  EXPECT_EQ(query.limit, "25");
  EXPECT_EQ(query.cursor, "AQID");
}

TEST(AuditLogHttpTest, EventQueryPreservesEmptyValuesForSemanticValidation) {
  const auto parsed = ParseAuditEventQuery("event_type=&limit=&cursor=");

  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  EXPECT_EQ(parsed.value().event_type, "");
  EXPECT_EQ(parsed.value().limit, "");
  EXPECT_EQ(parsed.value().cursor, "");
}

TEST(AuditLogHttpTest, EventQueryRejectsMalformedStructureAndEncoding) {
  constexpr std::array<std::string_view, 11> kInvalidQueries = {
      "event_type=one&event_type=two",
      "event_type=one&event%5Ftype=two",
      "unknown=value",
      "limit",
      "%=value",
      "limit=%",
      "limit=%0",
      "limit=%GG",
      "&limit=1",
      "limit=1&",
      "limit=1&&outcome=success",
  };

  for (const auto query : kInvalidQueries) {
    SCOPED_TRACE(query);
    const auto parsed = ParseAuditEventQuery(query);
    ASSERT_FALSE(parsed.ok());
    EXPECT_EQ(parsed.error().code, "E_AUDIT_QUERY_INVALID");
  }
}

TEST(AuditLogHttpTest, EventQueryAppliesRaw4096ByteLimitBeforeDecoding) {
  const std::string boundary = "event_type=" + std::string(4085U, 'a');
  ASSERT_EQ(boundary.size(), 4096U);
  EXPECT_TRUE(ParseAuditEventQuery(boundary).ok());

  const auto oversized = ParseAuditEventQuery(boundary + "a");
  ASSERT_FALSE(oversized.ok());
  EXPECT_EQ(oversized.error().code, "E_AUDIT_QUERY_INVALID");
}

TEST(AuditLogHttpTest, StatusAcceptsOnlyAnEmptyBoundedRawQuery) {
  EXPECT_TRUE(ValidateEmptyAuditStatusQuery("").ok());

  for (const std::string& query :
       std::array<std::string, 2>{"limit=1", std::string(4097U, 'a')}) {
    const auto validated = ValidateEmptyAuditStatusQuery(query);
    ASSERT_FALSE(validated.ok());
    EXPECT_EQ(validated.error().code, "E_AUDIT_QUERY_INVALID");
  }
}

TEST(AuditLogHttpTest, StatusJsonUsesExactKeysAndPairedNulls) {
  const AuditStatus status{45U, 50U, 90U, true, 7U, std::nullopt,
                           std::nullopt};

  const auto json = BuildAuditStatusJson(status);

  ExpectExactKeys(json, {"current_events", "max_events", "usage_percent",
                         "warning", "rotated_event_count",
                         "last_rotation_at_seconds",
                         "last_rotated_sequence"});
  EXPECT_EQ(json["current_events"].asUInt64(), 45U);
  EXPECT_EQ(json["max_events"].asUInt64(), 50U);
  EXPECT_EQ(json["usage_percent"].asUInt(), 90U);
  EXPECT_TRUE(json["warning"].asBool());
  EXPECT_EQ(json["rotated_event_count"].asUInt64(), 7U);
  EXPECT_TRUE(json["last_rotation_at_seconds"].isNull());
  EXPECT_TRUE(json["last_rotated_sequence"].isNull());
  EXPECT_FALSE(json.isMember("database_path"));
}

TEST(AuditLogHttpTest, StatusJsonSerializesRotationValuesAsIntegers) {
  const AuditStatus status{5U, 5U, 100U, true, 12U, 1234, 91};

  const auto json = BuildAuditStatusJson(status);

  EXPECT_EQ(json["last_rotation_at_seconds"].asInt64(), 1234);
  EXPECT_EQ(json["last_rotated_sequence"].asInt64(), 91);
}

TEST(AuditLogHttpTest, EventPageJsonUsesExactPublicKeysAndNullCursor) {
  AuditEventPage page;
  page.events.push_back(AuditEvent{381,
                                   1784300000,
                                   "viewer_disabled",
                                   "success",
                                   "cameraowner",
                                   "198.51.100.61",
                                   "",
                                   "user",
                                   "viewer01"});

  const auto json = BuildAuditEventPageJson(page);

  ExpectExactKeys(json, {"events", "next_cursor"});
  ASSERT_TRUE(json["events"].isArray());
  ASSERT_EQ(json["events"].size(), 1U);
  const auto& event = json["events"][0U];
  ExpectExactKeys(event, {"sequence", "server_timestamp_seconds",
                          "event_type", "outcome", "actor_identity",
                          "peer_ip", "detail_code", "subject_type",
                          "subject_identity"});
  EXPECT_EQ(event["sequence"].asInt64(), 381);
  EXPECT_EQ(event["server_timestamp_seconds"].asInt64(), 1784300000);
  EXPECT_EQ(event["event_type"].asString(), "viewer_disabled");
  EXPECT_EQ(event["outcome"].asString(), "success");
  EXPECT_EQ(event["actor_identity"].asString(), "cameraowner");
  EXPECT_EQ(event["peer_ip"].asString(), "198.51.100.61");
  EXPECT_EQ(event["detail_code"].asString(), "");
  EXPECT_EQ(event["subject_type"].asString(), "user");
  EXPECT_EQ(event["subject_identity"].asString(), "viewer01");
  EXPECT_FALSE(event.isMember("actor_user_id"));
  EXPECT_TRUE(json["next_cursor"].isNull());
}

TEST(AuditLogHttpTest, EventPageJsonSerializesOpaqueCursor) {
  AuditEventPage page;
  page.next_cursor = "AQID";

  const auto json = BuildAuditEventPageJson(page);

  EXPECT_TRUE(json["events"].isArray());
  EXPECT_TRUE(json["events"].empty());
  EXPECT_EQ(json["next_cursor"].asString(), "AQID");
}

TEST(AuditLogHttpTest, ErrorResponsesExposeOnlySanitizedPublicClasses) {
  struct ErrorCase {
    std::string_view internal_code;
    drogon::HttpStatusCode status;
    std::string_view public_code;
    std::string_view public_message;
  };
  constexpr std::array<ErrorCase, 3> kCases = {{
      {"E_AUDIT_QUERY_INVALID", drogon::k400BadRequest,
       "E_AUDIT_QUERY_INVALID", "Audit query is invalid."},
      {"E_AUDIT_FORBIDDEN", drogon::k403Forbidden,
       "E_AUTHORIZATION_REQUIRED", "Authorization is required."},
      {"E_PRIVATE_SQLITE_PATH", drogon::k503ServiceUnavailable,
       "E_AUDIT_UNAVAILABLE",
       "Audit records are temporarily unavailable."},
  }};

  for (const auto& test_case : kCases) {
    SCOPED_TRACE(test_case.internal_code);
    const auto response = BuildAuditLogErrorResponse(
        {std::string(test_case.internal_code),
         "private SQL /var/lib/camera-firmware/security.sqlite"});
    ASSERT_NE(response, nullptr);
    EXPECT_EQ(response->statusCode(), test_case.status);
    const auto json = response->getJsonObject();
    ASSERT_NE(json, nullptr);
    ExpectExactKeys(*json, {"code", "message"});
    EXPECT_EQ((*json)["code"].asString(), test_case.public_code);
    EXPECT_EQ((*json)["message"].asString(), test_case.public_message);
    EXPECT_EQ(response->body().find("private SQL"), std::string::npos);
    EXPECT_EQ(response->body().find("/var/lib"), std::string::npos);
  }
}

TEST(AuditLogHttpTest,
     AsyncHandlersSanitizeUnavailableDependenciesAndRejectedSubmissionsOnce) {
  TemporaryDirectory directory;
  auto store = OpenStore(directory.path());
  auto audit_log_service = std::make_shared<AuditLogService>(*store);
  RunningEventLoop event_loop;

  const auto verify = [&](AuditRoute route,
                          const std::shared_ptr<AuditLogService>& service,
                          const std::shared_ptr<BoundedWorker>& worker,
                          bool shutting_down) {
    ResponseRecorder recorder;
    InvokeAuthorizedAuditHandler(
        route, service, worker, shutting_down, event_loop.get(),
        [&recorder](const drogon::HttpResponsePtr& response) {
          recorder.Record(response);
        });
    EXPECT_TRUE(recorder.WaitForCount(1U));
    EXPECT_TRUE(event_loop.Drain());
    ExpectSanitizedUnavailable(recorder);
  };

  for (const auto route : {AuditRoute::kStatus, AuditRoute::kEvents}) {
    SCOPED_TRACE(route == AuditRoute::kStatus ? "status" : "events");
    verify(route, nullptr, std::make_shared<BoundedWorker>(2U), false);
    verify(route, audit_log_service, nullptr, false);
    verify(route, audit_log_service, std::make_shared<BoundedWorker>(2U),
           true);

    auto stopped_worker = std::make_shared<BoundedWorker>(2U);
    stopped_worker->Stop();
    verify(route, audit_log_service, stopped_worker, false);
  }

  auto saturated_worker = std::make_shared<BoundedWorker>(1U);
  std::promise<void> blocker_started;
  std::promise<void> release_blocker;
  PromiseReleaseGuard release_guard(release_blocker);
  auto release_future = release_blocker.get_future().share();
  ASSERT_TRUE(saturated_worker
                  ->Submit([&blocker_started, release_future] {
                    blocker_started.set_value();
                    release_future.wait();
                  })
                  .ok());
  ASSERT_EQ(blocker_started.get_future().wait_for(2s),
            std::future_status::ready);
  ASSERT_TRUE(saturated_worker->Submit([] {}).ok());

  for (const auto route : {AuditRoute::kStatus, AuditRoute::kEvents}) {
    SCOPED_TRACE(route == AuditRoute::kStatus ? "saturated status"
                                              : "saturated events");
    verify(route, audit_log_service, saturated_worker, false);
  }
  release_guard.Release();
  saturated_worker->Stop();
}

TEST(AuditLogHttpTest,
     ShutdownDrainsAdmittedAuditWorkAndTerminalFallbackRespondsOnce) {
  TemporaryDirectory directory;
  auto store = OpenStore(directory.path());
  auto audit_log_service = std::make_shared<AuditLogService>(*store);
  RunningEventLoop event_loop;

  const auto run_scenario = [&](bool fail_initial_terminal_queue) {
    auto worker = std::make_shared<BoundedWorker>(2U);
    std::promise<void> blocker_started;
    std::promise<void> release_blocker;
    PromiseReleaseGuard release_guard(release_blocker);
    auto release_future = release_blocker.get_future().share();
    ASSERT_TRUE(worker
                    ->Submit([&blocker_started, release_future] {
                      blocker_started.set_value();
                      release_future.wait();
                    })
                    .ok());
    ASSERT_EQ(blocker_started.get_future().wait_for(2s),
              std::future_status::ready);

    camera_firmware::service::internal::
        InstallAuditDependenciesForShutdownTesting(audit_log_service, worker);
    camera_firmware::service::ServiceApp service_app;
    ResponseRecorder recorder;
    if (fail_initial_terminal_queue) {
      camera_firmware::service::internal::
          FailNextTerminalResponseQueueForTesting();
    }
    InvokeAuthorizedAuditHandler(
        AuditRoute::kStatus, audit_log_service, worker, false,
        event_loop.get(),
        [&recorder](const drogon::HttpResponsePtr& response) {
          recorder.Record(response);
        });
    EXPECT_EQ(recorder.count(), 0U);

    auto stopping =
        std::async(std::launch::async, [&] { service_app.BeginShutdown(); });
    const bool shutdown_started = WaitForAuditShutdownStart();
    const bool shutdown_waited_for_admitted_work =
        stopping.wait_for(0s) == std::future_status::timeout;
    release_guard.Release();
    const bool shutdown_completed =
        stopping.wait_for(2s) == std::future_status::ready;
    if (shutdown_completed) {
      stopping.get();
    }
    const bool callback_completed = recorder.WaitForCount(1U);
    const bool event_loop_drained = event_loop.Drain();

    camera_firmware::service::internal::
        ResetTerminalResponseQueueFailureForTesting();
    service_app.Stop();

    EXPECT_TRUE(shutdown_started);
    EXPECT_TRUE(shutdown_waited_for_admitted_work);
    EXPECT_TRUE(shutdown_completed);
    EXPECT_TRUE(callback_completed);
    EXPECT_TRUE(event_loop_drained);
    ASSERT_EQ(recorder.count(), 1U);
    const auto response = recorder.first();
    ASSERT_NE(response, nullptr);
    if (fail_initial_terminal_queue) {
      ExpectSanitizedUnavailable(recorder);
    } else {
      EXPECT_EQ(response->statusCode(), drogon::k200OK);
    }
  };

  run_scenario(false);
  run_scenario(true);
}

}  // namespace
