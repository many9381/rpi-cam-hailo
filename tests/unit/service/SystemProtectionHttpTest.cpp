#include "camera_firmware/service/SystemProtectionHttp.hpp"

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <drogon/HttpResponse.h>
#include <gtest/gtest.h>
#include <json/value.h>

#include "camera_firmware/integrity/IntegrityManifest.hpp"
#include "camera_firmware/security/SystemProtectionService.hpp"

namespace {

using camera_firmware::common::Result;
using camera_firmware::integrity::IntegrityCategory;
using camera_firmware::integrity::IntegrityItemResult;
using camera_firmware::security::ProtectionState;
using camera_firmware::security::ProtectionSuite;
using camera_firmware::security::ProtectionSuiteSnapshot;
using camera_firmware::security::ProtectionTrigger;
using camera_firmware::security::SelfTestItemResult;
using camera_firmware::security::SystemProtectionSnapshot;
using camera_firmware::service::BuildSystemProtectionJson;
using camera_firmware::service::BuildSystemProtectionStartResponse;
using camera_firmware::service::BuildSystemProtectionStatusResponse;

void ExpectExactKeys(const Json::Value& value,
                     std::initializer_list<std::string_view> expected) {
  ASSERT_TRUE(value.isObject());
  auto actual = value.getMemberNames();
  std::sort(actual.begin(), actual.end());
  std::vector<std::string> expected_keys;
  expected_keys.reserve(expected.size());
  for (const auto key : expected) {
    expected_keys.emplace_back(key);
  }
  std::sort(expected_keys.begin(), expected_keys.end());
  EXPECT_EQ(actual, expected_keys);
}

SystemProtectionSnapshot CompleteSnapshot() {
  SystemProtectionSnapshot snapshot;
  snapshot.state = ProtectionState::kOperational;
  snapshot.check_running = false;
  snapshot.next_periodic_at_seconds = 1'721'444'800;
  snapshot.transition_code = "/private/manifest expected-hash actual-hash";
  snapshot.self_test = ProtectionSuiteSnapshot{
      .suite = ProtectionSuite::kSelfTest,
      .trigger = ProtectionTrigger::kStartup,
      .passed = true,
      .started_at_seconds = 1'721'358'300,
      .finished_at_seconds = 1'721'358'301,
      .self_test_items = {{"crypto.sha256", true, "OK"}},
  };
  snapshot.integrity = ProtectionSuiteSnapshot{
      .suite = ProtectionSuite::kIntegrity,
      .trigger = ProtectionTrigger::kPeriodic,
      .passed = false,
      .started_at_seconds = 1'721'358'400,
      .finished_at_seconds = 1'721'358'402,
      .integrity_items =
          {
              {"firmware", IntegrityCategory::kFirmware, true, "OK"},
              {"library", IntegrityCategory::kLibrary, true, "OK"},
              {"configuration", IntegrityCategory::kConfiguration, true, "OK"},
              {"web", IntegrityCategory::kWebAsset, true, "OK"},
              {"kernel", IntegrityCategory::kKernel, false,
               "E_INTEGRITY_MISMATCH"},
              {"module", IntegrityCategory::kKernelModule, true, "OK"},
          },
  };
  return snapshot;
}

void ExpectPublicError(const drogon::HttpResponsePtr& response,
                       drogon::HttpStatusCode status, std::string_view code,
                       std::string_view message) {
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), status);
  const auto* json = response->getJsonObject().get();
  ASSERT_NE(json, nullptr);
  ExpectExactKeys(*json, {"code", "message"});
  EXPECT_EQ((*json)["code"].asString(), code);
  EXPECT_EQ((*json)["message"].asString(), message);
}

TEST(SystemProtectionHttpTest,
     SerializesExactSnapshotSuiteAndItemContractsWithoutPrivateDetails) {
  auto serialized = BuildSystemProtectionJson(CompleteSnapshot());
  ASSERT_TRUE(serialized.ok()) << serialized.error().code;
  const auto& json = serialized.value();
  ExpectExactKeys(json, {"state", "check_running", "next_periodic_at_seconds",
                         "self_test", "integrity"});
  EXPECT_EQ(json["state"].asString(), "operational");
  EXPECT_FALSE(json["check_running"].asBool());
  EXPECT_EQ(json["next_periodic_at_seconds"].asInt64(), 1'721'444'800);

  const auto& self_test = json["self_test"];
  ExpectExactKeys(self_test,
                  {"suite", "trigger", "passed", "started_at_seconds",
                   "finished_at_seconds", "items"});
  EXPECT_EQ(self_test["suite"].asString(), "self_test");
  EXPECT_EQ(self_test["trigger"].asString(), "startup");
  ASSERT_EQ(self_test["items"].size(), 1U);
  ExpectExactKeys(self_test["items"][0U], {"id", "category", "passed", "code"});
  EXPECT_TRUE(self_test["items"][0U]["category"].isNull());

  const auto& integrity = json["integrity"];
  EXPECT_EQ(integrity["suite"].asString(), "integrity");
  EXPECT_EQ(integrity["trigger"].asString(), "periodic");
  const std::vector<std::string> expected_categories = {
      "firmware",  "library", "configuration",
      "web_asset", "kernel",  "kernel_module"};
  ASSERT_EQ(integrity["items"].size(), expected_categories.size());
  for (Json::ArrayIndex index = 0U; index < integrity["items"].size();
       ++index) {
    ExpectExactKeys(integrity["items"][index],
                    {"id", "category", "passed", "code"});
    EXPECT_EQ(integrity["items"][index]["category"].asString(),
              expected_categories[index]);
  }

  const std::string text = json.toStyledString();
  EXPECT_EQ(text.find("transition_code"), std::string::npos);
  EXPECT_EQ(text.find("/private/"), std::string::npos);
  EXPECT_EQ(text.find("expected-hash"), std::string::npos);
  EXPECT_EQ(text.find("actual-hash"), std::string::npos);
  EXPECT_EQ(text.find("message"), std::string::npos);
}

TEST(SystemProtectionHttpTest,
     SerializesCheckingRestrictedManualAndNullSuites) {
  SystemProtectionSnapshot snapshot;
  snapshot.state = ProtectionState::kChecking;
  snapshot.check_running = true;
  snapshot.next_periodic_at_seconds = 0;
  auto checking = BuildSystemProtectionJson(snapshot);
  ASSERT_TRUE(checking.ok());
  EXPECT_EQ(checking.value()["state"].asString(), "checking");
  EXPECT_TRUE(checking.value()["self_test"].isNull());
  EXPECT_TRUE(checking.value()["integrity"].isNull());

  snapshot.state = ProtectionState::kRestricted;
  snapshot.self_test = ProtectionSuiteSnapshot{
      .suite = ProtectionSuite::kSelfTest,
      .trigger = ProtectionTrigger::kManual,
      .passed = false,
  };
  auto restricted = BuildSystemProtectionJson(snapshot);
  ASSERT_TRUE(restricted.ok());
  EXPECT_EQ(restricted.value()["state"].asString(), "restricted");
  EXPECT_EQ(restricted.value()["self_test"]["trigger"].asString(), "manual");
}

TEST(SystemProtectionHttpTest, RejectsOversizedResultArraysWithoutPartialJson) {
  auto snapshot = CompleteSnapshot();
  snapshot.self_test->self_test_items.assign(
      camera_firmware::service::kMaximumProtectionResultItems + 1U,
      SelfTestItemResult{"id", true, "OK"});
  auto serialized = BuildSystemProtectionJson(snapshot);
  ASSERT_FALSE(serialized.ok());
  EXPECT_EQ(serialized.error().code, "E_PROTECTION_RESULT_INVALID");

  snapshot = CompleteSnapshot();
  snapshot.integrity->integrity_items.assign(
      camera_firmware::service::kMaximumProtectionResultItems + 1U,
      IntegrityItemResult{"id", IntegrityCategory::kFirmware, true, "OK"});
  serialized = BuildSystemProtectionJson(snapshot);
  ASSERT_FALSE(serialized.ok());
  EXPECT_EQ(serialized.error().code, "E_PROTECTION_RESULT_INVALID");
}

TEST(SystemProtectionHttpTest, RejectsOversizedIdsAndCodes) {
  auto snapshot = CompleteSnapshot();
  snapshot.self_test->self_test_items[0U].id.assign(
      camera_firmware::service::kMaximumProtectionResultTextBytes + 1U, 'i');
  auto serialized = BuildSystemProtectionJson(snapshot);
  ASSERT_FALSE(serialized.ok());
  EXPECT_EQ(serialized.error().code, "E_PROTECTION_RESULT_INVALID");

  snapshot = CompleteSnapshot();
  snapshot.integrity->integrity_items[0U].code.assign(
      camera_firmware::service::kMaximumProtectionResultTextBytes + 1U, 'c');
  serialized = BuildSystemProtectionJson(snapshot);
  ASSERT_FALSE(serialized.ok());
  EXPECT_EQ(serialized.error().code, "E_PROTECTION_RESULT_INVALID");
}

TEST(SystemProtectionHttpTest,
     StatusResponseConvertsInvalidAndExceptionalData) {
  auto invalid = CompleteSnapshot();
  invalid.integrity->integrity_items[0U].id.assign(65U, 'x');
  ExpectPublicError(
      BuildSystemProtectionStatusResponse([invalid] { return invalid; }),
      drogon::k503ServiceUnavailable, "E_PROTECTION_RESULT_INVALID",
      "system protection result is invalid");
  ExpectPublicError(
      BuildSystemProtectionStatusResponse([]() -> SystemProtectionSnapshot {
        throw std::runtime_error("/private/hash-message");
      }),
      drogon::k503ServiceUnavailable, "E_PROTECTION_UNAVAILABLE",
      "system protection is unavailable");
  ExpectPublicError(BuildSystemProtectionStatusResponse({}),
                    drogon::k503ServiceUnavailable, "E_PROTECTION_UNAVAILABLE",
                    "system protection is unavailable");
}

TEST(SystemProtectionHttpTest, StartResponseReturns202Snapshot) {
  auto response = BuildSystemProtectionStartResponse(
      [] { return Result<SystemProtectionSnapshot>::Ok(CompleteSnapshot()); });
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k202Accepted);
  const auto* json = response->getJsonObject().get();
  ASSERT_NE(json, nullptr);
  ExpectExactKeys(*json, {"state", "check_running", "next_periodic_at_seconds",
                          "self_test", "integrity"});
}

TEST(SystemProtectionHttpTest, StartResponseMapsConflictAndUnavailable) {
  ExpectPublicError(BuildSystemProtectionStartResponse([] {
                      return Result<SystemProtectionSnapshot>::Err(
                          {"E_PROTECTION_CHECK_RUNNING", "/private/running"});
                    }),
                    drogon::k409Conflict, "E_PROTECTION_CHECK_RUNNING",
                    "protection check is already running");
  ExpectPublicError(
      BuildSystemProtectionStartResponse([] {
        return Result<SystemProtectionSnapshot>::Err(
            {"E_PROTECTION_TRANSITION_BUSY", "/private/runtime-command"});
      }),
      drogon::k409Conflict, "E_PROTECTION_TRANSITION_BUSY",
      "runtime transition is busy");
  ExpectPublicError(BuildSystemProtectionStartResponse([] {
                      return Result<SystemProtectionSnapshot>::Err(
                          {"E_PROTECTION_STOPPING", "/private/stopping"});
                    }),
                    drogon::k503ServiceUnavailable, "E_PROTECTION_UNAVAILABLE",
                    "system protection is unavailable");
  ExpectPublicError(BuildSystemProtectionStartResponse(
                        []() -> Result<SystemProtectionSnapshot> {
                          throw std::runtime_error("/private/exception");
                        }),
                    drogon::k503ServiceUnavailable, "E_PROTECTION_UNAVAILABLE",
                    "system protection is unavailable");
}

}  // namespace
