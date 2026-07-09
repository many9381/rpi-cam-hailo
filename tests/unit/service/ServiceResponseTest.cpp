#include "camera_firmware/service/ServiceApp.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "camera_firmware/ai/AiTypes.hpp"

TEST(ServiceResponseTest, HealthJsonContainsStatus) {
  auto json = camera_firmware::service::BuildHealthJson("ok");
  ASSERT_TRUE(json.isMember("status"));
  EXPECT_EQ(json["status"].asString(), "ok");
}

TEST(ServiceResponseTest, StreamJsonUsesConfiguredPublicHost) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = true;
  secure_rtsp.media_srtp = false;
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  auto json = camera_firmware::service::BuildStreamJson(
      "https://camera.example:9443/service", secure_rtsp);

  EXPECT_EQ(json["url"].asString(), "rtsps://camera.example:8555/imx708/main");
}

TEST(ServiceResponseTest,
     StreamJsonKeepsRtspSchemeWhenOnlyMediaSrtpEnabled) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = false;
  secure_rtsp.media_srtp = true;
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  auto json = camera_firmware::service::BuildStreamJson(
      "http://stream.example:8080/ui", secure_rtsp);

  EXPECT_EQ(json["url"].asString(), "rtsp://stream.example:8555/imx708/main");
  ASSERT_TRUE(json.isMember("media_srtp"));
  EXPECT_TRUE(json["media_srtp"].asBool());
}

TEST(ServiceResponseTest, StreamJsonIncludesSrtpSecureMediaDiagnostics) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = true;
  secure_rtsp.media_srtp = true;
  secure_rtsp.keying = "sdes-over-rtsps";
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  const auto json = camera_firmware::service::BuildStreamJson(
      "https://camera.example:9443/service", secure_rtsp);

  EXPECT_EQ(json["url"].asString(), "rtsps://camera.example:8555/imx708/main");
  EXPECT_TRUE(json["control_tls"].asBool());
  EXPECT_TRUE(json["media_srtp"].asBool());
  ASSERT_TRUE(json.isMember("secure_media"));
  EXPECT_EQ(json["secure_media"]["control_scheme"].asString(), "rtsps");
  EXPECT_EQ(json["secure_media"]["media_profile"].asString(), "RTP/SAVPF");
  EXPECT_EQ(json["secure_media"]["keying"].asString(), "SDES-over-RTSPS");
  EXPECT_TRUE(
      json["secure_media"]["requires_tls_control_channel"].asBool());
}

TEST(ServiceResponseTest,
     StreamJsonIncludesRuntimeSrtpZeroizeDiagnosticsWhenAvailable) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = true;
  secure_rtsp.media_srtp = true;
  secure_rtsp.keying = "sdes-over-rtsps";
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  camera_firmware::service::SecureStreamDiagnostics diagnostics;
  diagnostics.per_media_key_zeroize_count = 7U;

  const auto json = camera_firmware::service::BuildStreamJson(
      "https://camera.example:9443/service", secure_rtsp, diagnostics);

  ASSERT_TRUE(json.isMember("secure_media"));
  ASSERT_TRUE(
      json["secure_media"].isMember("per_media_key_zeroize_count"));
  EXPECT_EQ(
      json["secure_media"]["per_media_key_zeroize_count"].asUInt64(), 7U);
}

TEST(ServiceResponseTest,
     StreamJsonOmitsRuntimeSrtpZeroizeDiagnosticsWithoutProvider) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = true;
  secure_rtsp.media_srtp = true;
  secure_rtsp.keying = "sdes-over-rtsps";
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  const auto json = camera_firmware::service::BuildStreamJson(
      "https://camera.example:9443/service", secure_rtsp);

  ASSERT_TRUE(json.isMember("secure_media"));
  EXPECT_FALSE(
      json["secure_media"].isMember("per_media_key_zeroize_count"));
}

TEST(ServiceResponseTest, StreamJsonIncludesPlainMediaDiagnostics) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = false;
  secure_rtsp.media_srtp = false;
  secure_rtsp.keying = "";
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  const auto json = camera_firmware::service::BuildStreamJson(
      "http://camera.example:8080/service", secure_rtsp);

  EXPECT_EQ(json["url"].asString(), "rtsp://camera.example:8555/imx708/main");
  EXPECT_FALSE(json["control_tls"].asBool());
  EXPECT_FALSE(json["media_srtp"].asBool());
  ASSERT_TRUE(json.isMember("secure_media"));
  EXPECT_EQ(json["secure_media"]["control_scheme"].asString(), "rtsp");
  EXPECT_EQ(json["secure_media"]["media_profile"].asString(), "RTP/AVP");
  EXPECT_EQ(json["secure_media"]["keying"].asString(), "none");
  EXPECT_FALSE(
      json["secure_media"]["requires_tls_control_channel"].asBool());
  EXPECT_FALSE(
      json["secure_media"].isMember("per_media_key_zeroize_count"));
}

TEST(ServiceResponseTest, AiStatusReportsRuntimeSkeletonWhenRequested) {
  auto json = camera_firmware::service::BuildAiStatusJson(true);

  EXPECT_TRUE(json["enabled"].asBool());
  EXPECT_EQ(json["backend"].asString(), "hailo");
  EXPECT_EQ(json["state"].asString(), "backend_unavailable");
  EXPECT_EQ(json["model_count"].asUInt64(), 0u);
  EXPECT_EQ(json["runner_count"].asUInt64(), 0u);
  EXPECT_EQ(json["reason"].asString(),
            "Hailo backend is not implemented in this build");
  ASSERT_TRUE(json["runners"].isArray());
  EXPECT_TRUE(json["runners"].empty());
}

TEST(ServiceResponseTest, AiStatusReportsEmptyRunnersWhenDisabled) {
  auto json = camera_firmware::service::BuildAiStatusJson(false);

  EXPECT_FALSE(json["enabled"].asBool());
  EXPECT_EQ(json["backend"].asString(), "disabled");
  EXPECT_EQ(json["state"].asString(), "disabled");
  EXPECT_EQ(json["runner_count"].asUInt64(), 0u);
  ASSERT_TRUE(json["runners"].isArray());
  EXPECT_TRUE(json["runners"].empty());
}

TEST(ServiceResponseTest, AiStatusReportsRuntimeSkeletonState) {
  camera_firmware::service::AiServiceStatus status;
  status.enabled = true;
  status.backend = "hailo";
  status.state = "backend_unavailable";
  status.model_count = 2;
  status.runner_count = 2;
  status.reason = "Hailo backend is not implemented in this build";

  auto json = camera_firmware::service::BuildAiStatusJson(status);

  EXPECT_TRUE(json["enabled"].asBool());
  EXPECT_EQ(json["backend"].asString(), "hailo");
  EXPECT_EQ(json["state"].asString(), "backend_unavailable");
  EXPECT_EQ(json["model_count"].asUInt64(), 2u);
  EXPECT_EQ(json["runner_count"].asUInt64(), 2u);
  EXPECT_EQ(json["reason"].asString(),
            "Hailo backend is not implemented in this build");
  ASSERT_TRUE(json["runners"].isArray());
  EXPECT_TRUE(json["runners"].empty());
}

TEST(ServiceResponseTest, AiStatusSerializesRunnerStatuses) {
  camera_firmware::service::AiServiceStatus status;
  status.enabled = true;
  status.backend = "hailo";
  status.state = "ready";
  status.model_count = 2;
  status.runner_count = 2;
  status.reason = "AI runtime ready";

  camera_firmware::service::AiRunnerServiceStatus objects;
  objects.camera_id = "imx708-main";
  objects.model_id = "objects";
  objects.model_kind = "object_detection";
  objects.submitted_frames = 11;
  objects.processed_frames = 10;
  objects.dropped_frames = 1;
  objects.last_error_code = "E_AI_POSTPROCESS";
  objects.last_error_message = "malformed output";
  status.runners.push_back(objects);

  camera_firmware::service::AiRunnerServiceStatus pose;
  pose.camera_id = "imx708-main";
  pose.model_id = "pose";
  pose.model_kind = "pose";
  pose.submitted_frames = 7;
  pose.processed_frames = 7;
  status.runners.push_back(pose);

  const auto json = camera_firmware::service::BuildAiStatusJson(status);

  ASSERT_TRUE(json["runners"].isArray());
  ASSERT_EQ(json["runners"].size(), 2U);
  const auto& first = json["runners"][0];
  EXPECT_EQ(first["camera_id"].asString(), "imx708-main");
  EXPECT_EQ(first["model_id"].asString(), "objects");
  EXPECT_EQ(first["model_kind"].asString(), "object_detection");
  EXPECT_EQ(first["submitted_frames"].asUInt64(), 11U);
  EXPECT_EQ(first["processed_frames"].asUInt64(), 10U);
  EXPECT_EQ(first["dropped_frames"].asUInt64(), 1U);
  EXPECT_EQ(first["last_error_code"].asString(), "E_AI_POSTPROCESS");
  EXPECT_EQ(first["last_error_message"].asString(), "malformed output");

  const auto& second = json["runners"][1];
  EXPECT_EQ(second["model_id"].asString(), "pose");
  EXPECT_EQ(second["model_kind"].asString(), "pose");
  EXPECT_EQ(second["submitted_frames"].asUInt64(), 7U);
  EXPECT_EQ(second["processed_frames"].asUInt64(), 7U);
  EXPECT_EQ(second["dropped_frames"].asUInt64(), 0U);
  EXPECT_EQ(second["last_error_code"].asString(), "");
  EXPECT_EQ(second["last_error_message"].asString(), "");
}

TEST(ServiceResponseTest, AiRestartResponseInvokesCallback) {
  bool restarted = false;

  auto response = camera_firmware::service::BuildAiRestartResponse(
      [&restarted] {
        restarted = true;
        return camera_firmware::common::Result<void>::Ok();
      });

  ASSERT_TRUE(restarted);
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["status"].asString(), "restarted");
}

TEST(ServiceResponseTest, AiRestartResponseIncludesRuntimeStatus) {
  bool restarted = false;

  camera_firmware::service::AiServiceStatus status;
  status.enabled = true;
  status.backend = "hailo";
  status.state = "ready";
  status.model_count = 1;
  status.runner_count = 1;
  status.reason = "AI runtime ready";

  auto response = camera_firmware::service::BuildAiRestartResponse(
      [&restarted] {
        restarted = true;
        return camera_firmware::common::Result<void>::Ok();
      },
      [&status] { return status; });

  ASSERT_TRUE(restarted);
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["status"].asString(), "restarted");
  ASSERT_TRUE((*json).isMember("ai"));
  EXPECT_TRUE((*json)["ai"]["enabled"].asBool());
  EXPECT_EQ((*json)["ai"]["backend"].asString(), "hailo");
  EXPECT_EQ((*json)["ai"]["state"].asString(), "ready");
  EXPECT_EQ((*json)["ai"]["model_count"].asUInt64(), 1U);
  EXPECT_EQ((*json)["ai"]["runner_count"].asUInt64(), 1U);
  EXPECT_EQ((*json)["ai"]["reason"].asString(), "AI runtime ready");
}

TEST(ServiceResponseTest, AiRestartResponseReportsMissingCallback) {
  auto response = camera_firmware::service::BuildAiRestartResponse({});

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), "E_AI_CONTROL_UNAVAILABLE");
}

TEST(ServiceResponseTest, AiRestartResponseReportsCallbackError) {
  auto response = camera_firmware::service::BuildAiRestartResponse([] {
    return camera_firmware::common::Result<void>::Err(
        {"E_AI_RESTART", "restart failed"});
  });

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k500InternalServerError);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), "E_AI_RESTART");
  EXPECT_EQ((*json)["message"].asString(), "restart failed");
}

TEST(ServiceResponseTest, AiRestartResponseDoesNotReadStatusAfterCallbackError) {
  bool status_provider_called = false;

  auto response = camera_firmware::service::BuildAiRestartResponse(
      [] {
        return camera_firmware::common::Result<void>::Err(
            {"E_AI_RESTART", "restart failed"});
      },
      [&status_provider_called] {
        status_provider_called = true;
        return camera_firmware::service::AiServiceStatus{};
      });

  ASSERT_FALSE(status_provider_called);
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k500InternalServerError);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), "E_AI_RESTART");
  EXPECT_FALSE((*json).isMember("ai"));
}

TEST(ServiceResponseTest, DetectionSnapshotJsonReturnsEmptyEventsArray) {
  const auto json =
      camera_firmware::service::BuildDetectionSnapshotJson({});

  ASSERT_TRUE(json.isMember("events"));
  ASSERT_TRUE(json["events"].isArray());
  EXPECT_TRUE(json["events"].empty());
}

TEST(ServiceResponseTest, DetectionSnapshotJsonSerializesDetectionEvent) {
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.model_id = "objects";
  event.model_kind = "object_detection";
  event.result_state = "decoded";
  event.frame_sequence = 101;

  camera_firmware::ai::Detection detection;
  detection.label = "car";
  detection.confidence = 0.88F;
  detection.box.x = 0.15F;
  detection.box.y = 0.20F;
  detection.box.width = 0.50F;
  detection.box.height = 0.40F;
  event.detections.push_back(detection);

  const auto json =
      camera_firmware::service::BuildDetectionSnapshotJson({event});

  ASSERT_TRUE(json.isMember("events"));
  ASSERT_EQ(json["events"].size(), 1U);
  const auto& serialized_event = json["events"][0];
  EXPECT_EQ(serialized_event["camera_id"].asString(), "imx708-main");
  EXPECT_EQ(serialized_event["model_id"].asString(), "objects");
  EXPECT_EQ(serialized_event["model_kind"].asString(), "object_detection");
  EXPECT_EQ(serialized_event["result_state"].asString(), "decoded");
  EXPECT_EQ(serialized_event["frame_sequence"].asUInt64(), 101U);
  ASSERT_EQ(serialized_event["detections"].size(), 1U);
  const auto& serialized_detection = serialized_event["detections"][0];
  EXPECT_EQ(serialized_detection["label"].asString(), "car");
  EXPECT_FLOAT_EQ(serialized_detection["confidence"].asFloat(), 0.88F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["x"].asFloat(), 0.15F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["y"].asFloat(), 0.20F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["width"].asFloat(), 0.50F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["height"].asFloat(), 0.40F);
}

TEST(ServiceResponseTest, DetectionSnapshotResponseReturnsEmptyWithoutProvider) {
  const auto response =
      camera_firmware::service::BuildDetectionSnapshotResponse({});

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  ASSERT_TRUE(json->isMember("events"));
  EXPECT_TRUE((*json)["events"].empty());
}

TEST(ServiceResponseTest, DetectionSnapshotResponseUsesProvider) {
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.model_id = "objects";
  event.model_kind = "object_detection";
  event.result_state = "decoded";
  event.frame_sequence = 77;

  const auto response =
      camera_firmware::service::BuildDetectionSnapshotResponse(
          [&event] {
            return std::vector<camera_firmware::ai::DetectionEvent>{event};
          });

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  ASSERT_EQ((*json)["events"].size(), 1U);
  EXPECT_EQ((*json)["events"][0]["camera_id"].asString(), "imx708-main");
  EXPECT_EQ((*json)["events"][0]["model_id"].asString(), "objects");
  EXPECT_EQ((*json)["events"][0]["frame_sequence"].asUInt64(), 77U);
}

TEST(ServiceResponseTest, DetectionSseEventSerializesSnapshot) {
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.model_id = "objects";
  event.model_kind = "object_detection";
  event.result_state = "decoded";
  event.frame_sequence = 88;

  const auto payload =
      camera_firmware::service::BuildDetectionSseEvent({event});

  EXPECT_NE(payload.find("event: detections\n"), std::string::npos);
  EXPECT_NE(payload.find("id: imx708-main/objects/88/decoded\n"),
            std::string::npos);
  EXPECT_NE(payload.find("\"camera_id\":\"imx708-main\""), std::string::npos);
  EXPECT_NE(payload.find("\"frame_sequence\":88"), std::string::npos);
  EXPECT_TRUE(payload.ends_with("\n\n"));
}

TEST(ServiceResponseTest, DetectionSseIdChangesWithSnapshotContent) {
  camera_firmware::ai::DetectionEvent first;
  first.camera_id = "imx708-main";
  first.model_id = "objects";
  first.result_state = "decoded";
  first.frame_sequence = 88;

  camera_firmware::ai::DetectionEvent second = first;
  second.frame_sequence = 89;

  EXPECT_NE(camera_firmware::service::BuildDetectionSseId({first}),
            camera_firmware::service::BuildDetectionSseId({second}));
  EXPECT_EQ(camera_firmware::service::BuildDetectionSseId({}), "empty");
}

TEST(ServiceResponseTest, DetectionSseResponseUsesEventStreamBody) {
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.model_id = "objects";
  event.model_kind = "object_detection";
  event.result_state = "decoded";
  event.frame_sequence = 89;

  const auto response =
      camera_firmware::service::BuildDetectionSseResponse({event});

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  EXPECT_EQ(response->contentTypeString(), "text/event-stream");
  EXPECT_EQ(response->getHeader("Cache-Control"), "no-cache");
  EXPECT_NE(response->body().find("\"frame_sequence\":89"), std::string::npos);
}

TEST(ServiceResponseTest, DetectionSseMergeAddsLiveEventToStaleSnapshot) {
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.model_id = "objects";
  event.model_kind = "object_detection";
  event.result_state = "decoded";
  event.frame_sequence = 90;

  const auto merged =
      camera_firmware::service::MergeDetectionSnapshotWithEvent({}, event);

  ASSERT_EQ(merged.size(), 1U);
  EXPECT_EQ(merged[0].frame_sequence, 90U);
}

TEST(ServiceResponseTest, DetectionSseMergeReplacesMatchingCameraModel) {
  camera_firmware::ai::DetectionEvent stored;
  stored.camera_id = "imx708-main";
  stored.model_id = "objects";
  stored.model_kind = "object_detection";
  stored.result_state = "decoded";
  stored.frame_sequence = 91;

  camera_firmware::ai::DetectionEvent live = stored;
  live.frame_sequence = 92;

  const auto merged =
      camera_firmware::service::MergeDetectionSnapshotWithEvent({stored}, live);

  ASSERT_EQ(merged.size(), 1U);
  EXPECT_EQ(merged[0].frame_sequence, 92U);
}

TEST(ServiceResponseTest, ListenerConfigEnablesHttpsFromHttpConfig) {
  camera_firmware::config::AppConfig config;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = 9443;
  config.http.tls.enabled = true;
  config.http.tls.certificate_path = "/tmp/http.crt";
  config.http.tls.private_key_path = "/tmp/http.key";

  const auto listener =
      camera_firmware::service::BuildServiceListenerConfig(config.http);

  EXPECT_EQ(listener.bind_address, "127.0.0.1");
  EXPECT_EQ(listener.port, 9443u);
  EXPECT_TRUE(listener.use_tls);
  EXPECT_EQ(listener.certificate_path, "/tmp/http.crt");
  EXPECT_EQ(listener.private_key_path, "/tmp/http.key");
}

TEST(ServiceResponseTest, HttpTlsValidationRejectsUnreadableOrInvalidFiles) {
  const auto cert_path =
      std::filesystem::temp_directory_path() / "cf-invalid-http.crt";
  const auto key_path =
      std::filesystem::temp_directory_path() / "cf-invalid-http.key";
  {
    std::ofstream cert(cert_path);
    cert << "not a certificate";
    std::ofstream key(key_path);
    key << "not a key";
  }

  camera_firmware::config::HttpConfig http;
  http.enabled = true;
  http.tls.enabled = true;
  http.tls.certificate_path = cert_path.string();
  http.tls.private_key_path = key_path.string();

  auto validated = camera_firmware::service::ValidateHttpTlsConfigFiles(http);

  std::filesystem::remove(cert_path);
  std::filesystem::remove(key_path);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_HTTP_TLS_CERT");
}

TEST(ServiceResponseTest, InitReturnsErrorWhenConfigIsMissing) {
  camera_firmware::service::ServiceApp service;
  camera_firmware::service::ServiceInitArgs args;

  auto initialized = service.Init(args);

  ASSERT_FALSE(initialized.ok());
  EXPECT_EQ(initialized.error().code, "E_SERVICE_CONFIG");
}

TEST(ServiceResponseTest, SnapshotResponseReturnsJpegBytesFromCallback) {
  const std::vector<std::uint8_t> jpeg{0xff, 0xd8, 0xff, 0xd9};

  auto response = camera_firmware::service::BuildSnapshotResponse(
      [&](const std::string& camera_id)
          -> std::optional<std::vector<std::uint8_t>> {
        if (camera_id != "imx708-main") {
          return std::nullopt;
        }
        return jpeg;
      },
      "imx708-main");

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  EXPECT_EQ(response->body(), std::string("\xff\xd8\xff\xd9", 4));
}

TEST(ServiceResponseTest, SnapshotResponseReturnsUnavailableForUnknownCamera) {
  auto response = camera_firmware::service::BuildSnapshotResponse(
      [](const std::string&) -> std::optional<std::vector<std::uint8_t>> {
        return std::nullopt;
      },
      "unknown");

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
}
