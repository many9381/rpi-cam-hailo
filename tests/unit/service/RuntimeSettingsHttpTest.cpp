#include "camera_firmware/service/RuntimeSettingsHttp.hpp"

#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <drogon/HttpResponse.h>
#include <gtest/gtest.h>

namespace {

using camera_firmware::common::Error;
using camera_firmware::common::Result;
using camera_firmware::service::BuildRuntimeSettingsApplyResponse;
using camera_firmware::service::BuildRuntimeSettingsErrorResponse;
using camera_firmware::service::BuildRuntimeSettingsSnapshotJson;
using camera_firmware::service::BuildRuntimeSettingsSnapshotResponse;
using camera_firmware::service::ParseRuntimeSettingsCommandJson;
using camera_firmware::service::ParseRuntimeSettingsUpdateJson;
using camera_firmware::settings::ApplyStatus;
using camera_firmware::settings::RuntimeSettingsSnapshot;
using camera_firmware::settings::RuntimeSettingsState;
using camera_firmware::settings::SettingsApplyResult;

constexpr std::string_view kUpdateJson = R"({
  "expected_revision": 7,
  "settings": {
    "camera": {
      "profile_id": "imx708-1080p30",
      "bitrate_kbps": 8000,
      "gop": 30
    },
    "models": [
      {"id":"objects","enabled":true,"confidence_threshold":0.55},
      {"id":"pose","enabled":false,"confidence_threshold":0.25}
    ]
  }
})";

RuntimeSettingsSnapshot MakeSnapshot() {
  RuntimeSettingsSnapshot snapshot;
  snapshot.revision = 7U;
  snapshot.state = RuntimeSettingsState::kPending;
  snapshot.active.camera = {"imx708-1080p50", 6000U, 25U};
  snapshot.active.models = {{"objects", true, 0.40F},
                            {"pose", true, 0.35F}};
  snapshot.pending = snapshot.active;
  snapshot.pending->camera = {"imx708-1080p30", 8000U, 30U};
  snapshot.pending->models = {{"objects", true, 0.55F},
                              {"pose", false, 0.25F}};
  snapshot.last_apply = {ApplyStatus::kFailed,
                         "E_PRIVATE_BACKEND_/opt/models/model.hef", true};
  snapshot.camera_profiles = {
      {"imx708-1080p50", "1080p 50 fps", 1920U, 1080U, 50U},
      {"imx708-1080p30", "1080p 30 fps", 1920U, 1080U, 30U},
  };
  snapshot.model_capabilities = {
      {"objects", "object_detection", 640U, 640U, "rgb8", true,
       "coco80"},
      {"pose", "pose_estimation", 640U, 640U, "rgb8", false,
       "pose17"},
  };
  return snapshot;
}

void ExpectPublicError(const drogon::HttpResponsePtr& response,
                       drogon::HttpStatusCode status,
                       std::string_view code,
                       std::string_view message) {
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), status);
  const auto json = response->getJsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), code);
  EXPECT_EQ((*json)["message"].asString(), message);
  EXPECT_EQ(response->body().find("private"), std::string::npos);
  EXPECT_EQ(response->body().find("/opt/"), std::string::npos);
}

TEST(RuntimeSettingsHttpTest, ParsesExactCompleteUpdateAndPreservesModelOrder) {
  const auto parsed =
      ParseRuntimeSettingsUpdateJson(kUpdateJson, "application/json");

  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  EXPECT_EQ(parsed.value().expected_revision, 7U);
  EXPECT_EQ(parsed.value().settings.camera.profile_id, "imx708-1080p30");
  EXPECT_EQ(parsed.value().settings.camera.bitrate_kbps, 8000U);
  EXPECT_EQ(parsed.value().settings.camera.gop, 30U);
  ASSERT_EQ(parsed.value().settings.models.size(), 2U);
  EXPECT_EQ(parsed.value().settings.models[0].id, "objects");
  EXPECT_EQ(parsed.value().settings.models[1].id, "pose");
  EXPECT_FLOAT_EQ(parsed.value().settings.models[0].confidence_threshold,
                  0.55F);
}

TEST(RuntimeSettingsHttpTest, ParsesExactExpectedRevisionCommand) {
  const auto parsed = ParseRuntimeSettingsCommandJson(
      R"({"expected_revision":18446744073709551615})", "application/json");

  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  EXPECT_EQ(parsed.value().expected_revision,
            std::numeric_limits<std::uint64_t>::max());
}

TEST(RuntimeSettingsHttpTest, RejectsNonJsonContentTypeAndBodiesOver16KiB) {
  auto wrong_type =
      ParseRuntimeSettingsUpdateJson(kUpdateJson, "text/json");
  ASSERT_FALSE(wrong_type.ok());
  EXPECT_EQ(wrong_type.error().code, "E_SETTINGS_REQUEST_INVALID");

  std::string oversized(16U * 1024U + 1U, ' ');
  auto too_large =
      ParseRuntimeSettingsCommandJson(oversized, "application/json");
  ASSERT_FALSE(too_large.ok());
  EXPECT_EQ(too_large.error().code, "E_SETTINGS_REQUEST_INVALID");
}

TEST(RuntimeSettingsHttpTest, StrictJsonRejectsAmbiguousOrMalformedInput) {
  std::vector<std::string> invalid = {
      R"({"expected_revision":1,"expected_revision":2})",
      R"({"expected_revision":1} trailing)",
      R"({"expected_revision":1 /* comment */})",
      R"({"expected_revision":NaN})",
      R"({"expected_revision":-1})",
      R"({"expected_revision":1.0})",
      R"({"expected_revision":"1"})",
      R"({"expected_revision":1,"extra":true})",
      R"({})",
  };
  std::string invalid_utf8 = R"({"expected_revision":1,"x":")";
  invalid_utf8.push_back(static_cast<char>(0xc0));
  invalid_utf8.push_back(static_cast<char>(0xaf));
  invalid_utf8 += R"("})";
  invalid.push_back(std::move(invalid_utf8));

  for (const auto& body : invalid) {
    const auto parsed =
        ParseRuntimeSettingsCommandJson(body, "application/json");
    ASSERT_FALSE(parsed.ok()) << body;
    EXPECT_EQ(parsed.error().code, "E_SETTINGS_REQUEST_INVALID") << body;
  }
}

TEST(RuntimeSettingsHttpTest, UpdateRequiresExactKeysAndIntegerCameraFields) {
  const std::vector<std::string> invalid = {
      R"({"expected_revision":7})",
      R"({"expected_revision":7,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30,"extra":1},"models":[]}})",
      R"({"expected_revision":7,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000.0,"gop":30},"models":[]}})",
      R"({"expected_revision":7,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30},"models":[{"id":"objects","enabled":1,"confidence_threshold":0.5}]}})",
      R"({"expected_revision":7,"settings":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30},"models":[{"id":"objects","enabled":true,"confidence_threshold":"0.5"}]}})",
  };

  for (const auto& body : invalid) {
    const auto parsed =
        ParseRuntimeSettingsUpdateJson(body, "application/json");
    ASSERT_FALSE(parsed.ok()) << body;
    EXPECT_EQ(parsed.error().code, "E_SETTINGS_REQUEST_INVALID") << body;
  }
}

TEST(RuntimeSettingsHttpTest, SnapshotJsonContainsOnlySafeOrderedCapabilities) {
  const auto json = BuildRuntimeSettingsSnapshotJson(MakeSnapshot());

  EXPECT_EQ(json["schema_version"].asUInt(), 1U);
  EXPECT_EQ(json["revision"].asUInt64(), 7U);
  EXPECT_EQ(json["state"].asString(), "pending");
  EXPECT_EQ(json["capabilities"]["bitrate_kbps"]["minimum"].asUInt(),
            500U);
  EXPECT_EQ(json["capabilities"]["bitrate_kbps"]["maximum"].asUInt(),
            20000U);
  EXPECT_FALSE(json["capabilities"]["bitrate_kbps"].isMember("min"));
  EXPECT_FALSE(json["capabilities"]["bitrate_kbps"].isMember("max"));
  EXPECT_EQ(json["capabilities"]["gop"]["minimum"].asUInt(), 1U);
  EXPECT_EQ(json["capabilities"]["gop"]["maximum"].asUInt(), 300U);
  EXPECT_FALSE(json["capabilities"]["gop"].isMember("min"));
  EXPECT_FALSE(json["capabilities"]["gop"].isMember("max"));
  ASSERT_EQ(json["capabilities"]["models"].size(), 2U);
  EXPECT_EQ(json["capabilities"]["models"][0U]["id"].asString(),
            "objects");
  EXPECT_TRUE(json["capabilities"]["models"][0U]["labels"].isString());
  EXPECT_EQ(json["capabilities"]["models"][0U]["labels"].asString(),
            "coco80");
  EXPECT_FALSE(json["capabilities"]["models"][0U].isMember("hef_path"));
  EXPECT_FALSE(json["capabilities"]["models"][0U].isMember("output_name"));
  EXPECT_EQ(json["active"]["models"][0U]["id"].asString(), "objects");
  EXPECT_EQ(json["pending"]["models"][1U]["id"].asString(), "pose");
  EXPECT_EQ(json["last_apply"]["code"].asString(),
            "E_SETTINGS_APPLY_FAILED");
}

TEST(RuntimeSettingsHttpTest, SnapshotResponseUsesJsonContract) {
  const auto response = BuildRuntimeSettingsSnapshotResponse(MakeSnapshot());

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  const auto json = response->getJsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["schema_version"].asUInt(), 1U);
}

TEST(RuntimeSettingsHttpTest, InternalErrorsMapToBoundedPublicContract) {
  struct Case {
    std::string internal_code;
    drogon::HttpStatusCode status;
    std::string public_code;
    std::string message;
  };
  const std::vector<Case> cases = {
      {"E_SETTINGS_REQUEST_INVALID", drogon::k400BadRequest,
       "E_SETTINGS_REQUEST_INVALID", "runtime settings request is invalid"},
      {"E_RUNTIME_SETTINGS_REVISION", drogon::k409Conflict,
       "E_SETTINGS_REVISION_CONFLICT", "runtime settings revision conflict"},
      {"E_RUNTIME_SETTINGS_NO_PENDING", drogon::k409Conflict,
       "E_SETTINGS_NO_PENDING", "no pending runtime settings"},
      {"E_RUNTIME_SETTINGS_BUSY", drogon::k409Conflict, "E_SETTINGS_BUSY",
       "runtime settings are busy"},
      {"E_RUNTIME_SETTINGS_MODEL_ORDER", drogon::k422UnprocessableEntity,
       "E_SETTINGS_UNSUPPORTED", "runtime settings are unsupported"},
      {"E_CONFIG_HTTP_LIVE", drogon::k422UnprocessableEntity,
       "E_SETTINGS_UNSUPPORTED", "runtime settings are unsupported"},
      {"E_PIPELINE_CANDIDATE", drogon::k422UnprocessableEntity,
       "E_SETTINGS_UNSUPPORTED", "runtime settings are unsupported"},
      {"E_RUNTIME_SETTINGS_STORE", drogon::k500InternalServerError,
       "E_SETTINGS_STORE", "runtime settings store failed"},
      {"E_RUNTIME_FACTORY", drogon::k503ServiceUnavailable,
       "E_SETTINGS_APPLY_FAILED", "runtime settings apply failed"},
      {"E_RUNTIME_START", drogon::k503ServiceUnavailable,
       "E_SETTINGS_APPLY_FAILED", "runtime settings apply failed"},
      {"E_PRIVATE_BACKEND_FAILURE", drogon::k503ServiceUnavailable,
       "E_SETTINGS_APPLY_FAILED", "runtime settings apply failed"},
      {"E_SETTINGS_UNAVAILABLE", drogon::k503ServiceUnavailable,
       "E_SETTINGS_UNAVAILABLE", "runtime settings are unavailable"},
  };

  for (const auto& test : cases) {
    ExpectPublicError(
        BuildRuntimeSettingsErrorResponse(
            {test.internal_code, "private /opt/backend/model.hef detail"}),
        test.status, test.public_code, test.message);
  }
}

TEST(RuntimeSettingsHttpTest, ApplyFailureReportsTruthfulRestorationSafely) {
  SettingsApplyResult result{MakeSnapshot(), false, true,
                             {"E_PRIVATE_BACKEND_FAILURE",
                              "private /opt/backend/model.hef detail"}};

  const auto response = BuildRuntimeSettingsApplyResponse(result);

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
  const auto json = response->getJsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_FALSE((*json)["applied"].asBool());
  EXPECT_TRUE((*json)["restored"].asBool());
  EXPECT_EQ((*json)["code"].asString(), "E_SETTINGS_APPLY_FAILED");
  EXPECT_EQ(response->body().find("private"), std::string::npos);
  EXPECT_EQ(response->body().find("/opt/"), std::string::npos);
}

TEST(RuntimeSettingsHttpTest, ApplySuccessReturnsSnapshotAndOutcome) {
  SettingsApplyResult result{MakeSnapshot(), true, false, {}};

  const auto response = BuildRuntimeSettingsApplyResponse(result);

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  const auto json = response->getJsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_TRUE((*json)["applied"].asBool());
  EXPECT_FALSE((*json)["restored"].asBool());
  EXPECT_EQ((*json)["revision"].asUInt64(), 7U);
  EXPECT_FALSE(json->isMember("code"));
}

}  // namespace
