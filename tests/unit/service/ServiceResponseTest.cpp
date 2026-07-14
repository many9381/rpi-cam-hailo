#include "camera_firmware/service/ServiceApp.hpp"

#include <algorithm>
#include <chrono>
#include <array>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <future>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "camera_firmware/ai/AiTypes.hpp"

namespace {

class TemporaryTlsDirectory {
 public:
  TemporaryTlsDirectory() {
    std::array<char, 40> pattern{"/tmp/cf-service-tls-XXXXXX"};
    char* created = ::mkdtemp(pattern.data());
    if (created == nullptr) {
      throw std::system_error(errno, std::generic_category(), "mkdtemp");
    }
    path_ = created;
  }

  ~TemporaryTlsDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  [[nodiscard]] const std::filesystem::path& path() const noexcept {
    return path_;
  }

 private:
  std::filesystem::path path_;
};

void WriteExclusiveTlsFile(const std::filesystem::path& directory,
                           std::string_view name,
                           mode_t mode,
                           std::string_view contents) {
  const int directory_fd =
      ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory_fd < 0) {
    throw std::system_error(errno, std::generic_category(), "open directory");
  }
  const int file_fd =
      ::openat(directory_fd, name.data(),
               O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
  if (file_fd < 0 || ::fchmod(file_fd, mode) != 0 ||
      ::write(file_fd, contents.data(), contents.size()) !=
          static_cast<ssize_t>(contents.size())) {
    const int error = errno;
    if (file_fd >= 0) {
      (void)::close(file_fd);
    }
    (void)::close(directory_fd);
    throw std::system_error(error, std::generic_category(), "write TLS file");
  }
  const int file_close = ::close(file_fd);
  const int directory_close = ::close(directory_fd);
  if (file_close != 0 || directory_close != 0) {
    throw std::system_error(errno, std::generic_category(), "close TLS file");
  }
}

}  // namespace

TEST(ServiceResponseTest, HealthJsonContainsStatus) {
  auto json = camera_firmware::service::BuildHealthJson("ok");
  ASSERT_TRUE(json.isMember("status"));
  EXPECT_EQ(json["status"].asString(), "ok");
}

TEST(ServiceResponseTest, CameraStatusJsonIncludesCaptureDiagnostics) {
  camera_firmware::service::CameraStatus status;
  status.id = "imx708-main";
  status.state = "running";
  status.snapshot_available = true;
  status.width = 1920U;
  status.height = 1080U;
  status.configured_fps = 50U;
  status.capture_fps = 49.8;
  status.encoded_fps = 49.7;
  status.captured_frames = 1000U;
  status.encoded_frames = 998U;
  status.capture_error_count = 2U;
  status.encode_error_count = 1U;

  const auto json =
      camera_firmware::service::BuildCameraStatusJson(status);

  EXPECT_EQ(json["id"].asString(), "imx708-main");
  EXPECT_EQ(json["state"].asString(), "running");
  EXPECT_TRUE(json["snapshot_available"].asBool());
  EXPECT_EQ(json["width"].asUInt(), 1920U);
  EXPECT_EQ(json["height"].asUInt(), 1080U);
  EXPECT_EQ(json["configured_fps"].asUInt(), 50U);
  EXPECT_DOUBLE_EQ(json["capture_fps"].asDouble(), 49.8);
  EXPECT_DOUBLE_EQ(json["encoded_fps"].asDouble(), 49.7);
  EXPECT_EQ(json["captured_frames"].asUInt64(), 1000U);
  EXPECT_EQ(json["encoded_frames"].asUInt64(), 998U);
  EXPECT_EQ(json["capture_error_count"].asUInt64(), 2U);
  EXPECT_EQ(json["encode_error_count"].asUInt64(), 1U);
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

TEST(ServiceResponseTest, AiStatusSerializesConfiguredModelInventory) {
  camera_firmware::service::AiServiceStatus status;
  status.enabled = true;
  status.backend = "hailo";
  status.state = "ready";
  status.model_count = 2;
  status.runner_count = 2;
  status.reason = "AI runtime ready";

  camera_firmware::service::AiModelServiceStatus objects;
  objects.id = "objects";
  objects.kind = "object_detection";
  objects.input_width = 640;
  objects.input_height = 640;
  objects.input_format = "rgb8";
  objects.letterbox = true;
  objects.output_name = "yolov8_nms_postprocess";
  objects.confidence_threshold = 0.40F;
  objects.labels = "coco80";
  status.models.push_back(objects);

  camera_firmware::service::AiModelServiceStatus pose;
  pose.id = "pose";
  pose.kind = "pose";
  pose.input_width = 256;
  pose.input_height = 256;
  pose.input_format = "rgb8";
  pose.letterbox = false;
  pose.output_name = "yolov8_pose_postprocess";
  pose.confidence_threshold = 0.30F;
  pose.labels = "pose17";
  status.models.push_back(pose);

  const auto json = camera_firmware::service::BuildAiStatusJson(status);

  ASSERT_TRUE(json["models"].isArray());
  ASSERT_EQ(json["models"].size(), 2U);
  const auto& first = json["models"][0];
  EXPECT_EQ(first["id"].asString(), "objects");
  EXPECT_EQ(first["kind"].asString(), "object_detection");
  EXPECT_EQ(first["input_width"].asUInt(), 640U);
  EXPECT_EQ(first["input_height"].asUInt(), 640U);
  EXPECT_EQ(first["input_format"].asString(), "rgb8");
  EXPECT_TRUE(first["letterbox"].asBool());
  EXPECT_EQ(first["output_name"].asString(), "yolov8_nms_postprocess");
  EXPECT_FLOAT_EQ(first["confidence_threshold"].asFloat(), 0.40F);
  EXPECT_EQ(first["labels"].asString(), "coco80");
  EXPECT_FALSE(first.isMember("hef_path"));

  const auto& second = json["models"][1];
  EXPECT_EQ(second["id"].asString(), "pose");
  EXPECT_EQ(second["kind"].asString(), "pose");
  EXPECT_EQ(second["input_width"].asUInt(), 256U);
  EXPECT_EQ(second["input_height"].asUInt(), 256U);
  EXPECT_EQ(second["input_format"].asString(), "rgb8");
  EXPECT_FALSE(second["letterbox"].asBool());
  EXPECT_EQ(second["output_name"].asString(), "yolov8_pose_postprocess");
  EXPECT_FLOAT_EQ(second["confidence_threshold"].asFloat(), 0.30F);
  EXPECT_EQ(second["labels"].asString(), "pose17");
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
  objects.last_preprocess_ms = 1.2;
  objects.last_inference_ms = 3.4;
  objects.last_processed_sequence = 11;
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
  EXPECT_DOUBLE_EQ(first["last_preprocess_ms"].asDouble(), 1.2);
  EXPECT_DOUBLE_EQ(first["last_inference_ms"].asDouble(), 3.4);
  EXPECT_EQ(first["last_processed_sequence"].asUInt64(), 11U);
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

TEST(ServiceResponseTest, AiStatusClampsInvalidRunnerTimingValues) {
  camera_firmware::service::AiServiceStatus status;
  camera_firmware::service::AiRunnerServiceStatus runner;
  runner.last_preprocess_ms = -1.0;
  runner.last_inference_ms = std::numeric_limits<double>::quiet_NaN();
  status.runners.push_back(runner);

  auto json = camera_firmware::service::BuildAiStatusJson(status);

  ASSERT_EQ(json["runners"].size(), 1U);
  EXPECT_DOUBLE_EQ(json["runners"][0]["last_preprocess_ms"].asDouble(), 0.0);
  EXPECT_DOUBLE_EQ(json["runners"][0]["last_inference_ms"].asDouble(), 0.0);

  status.runners[0].last_preprocess_ms =
      std::numeric_limits<double>::infinity();
  status.runners[0].last_inference_ms =
      -std::numeric_limits<double>::infinity();
  json = camera_firmware::service::BuildAiStatusJson(status);

  EXPECT_DOUBLE_EQ(json["runners"][0]["last_preprocess_ms"].asDouble(), 0.0);
  EXPECT_DOUBLE_EQ(json["runners"][0]["last_inference_ms"].asDouble(), 0.0);
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
  event.frame_timestamp = std::chrono::nanoseconds{123456789};

  camera_firmware::ai::Detection detection;
  detection.class_id = 2;
  detection.label = "car";
  detection.confidence = 0.88F;
  detection.box.x = 0.15F;
  detection.box.y = 0.20F;
  detection.box.width = 0.50F;
  detection.box.height = 0.40F;
  camera_firmware::ai::Keypoint left_shoulder;
  left_shoulder.name = "left_shoulder";
  left_shoulder.x = 0.34F;
  left_shoulder.y = 0.28F;
  left_shoulder.confidence = 0.81F;
  camera_firmware::ai::Keypoint right_shoulder;
  right_shoulder.name = "right_shoulder";
  right_shoulder.x = 0.52F;
  right_shoulder.y = 0.29F;
  right_shoulder.confidence = 0.79F;
  detection.keypoints = {left_shoulder, right_shoulder};
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
  EXPECT_EQ(serialized_event["frame_timestamp_ns"].asInt64(), 123456789);
  ASSERT_EQ(serialized_event["detections"].size(), 1U);
  const auto& serialized_detection = serialized_event["detections"][0];
  EXPECT_EQ(serialized_detection["class_id"].asInt(), 2);
  EXPECT_EQ(serialized_detection["label"].asString(), "car");
  EXPECT_FLOAT_EQ(serialized_detection["confidence"].asFloat(), 0.88F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["x"].asFloat(), 0.15F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["y"].asFloat(), 0.20F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["width"].asFloat(), 0.50F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["height"].asFloat(), 0.40F);
  ASSERT_TRUE(serialized_detection["keypoints"].isArray());
  ASSERT_EQ(serialized_detection["keypoints"].size(), 2U);
  EXPECT_EQ(serialized_detection["keypoints"][0]["name"].asString(),
            "left_shoulder");
  EXPECT_FLOAT_EQ(serialized_detection["keypoints"][0]["x"].asFloat(), 0.34F);
  EXPECT_FLOAT_EQ(serialized_detection["keypoints"][0]["y"].asFloat(), 0.28F);
  EXPECT_FLOAT_EQ(
      serialized_detection["keypoints"][0]["confidence"].asFloat(), 0.81F);
  EXPECT_EQ(serialized_detection["keypoints"][1]["name"].asString(),
            "right_shoulder");
  EXPECT_FLOAT_EQ(serialized_detection["keypoints"][1]["x"].asFloat(), 0.52F);
  EXPECT_FLOAT_EQ(serialized_detection["keypoints"][1]["y"].asFloat(), 0.29F);
  EXPECT_FLOAT_EQ(
      serialized_detection["keypoints"][1]["confidence"].asFloat(), 0.79F);
}

TEST(ServiceResponseTest, DetectionSnapshotJsonFiltersInvalidClassIds) {
  camera_firmware::ai::DetectionEvent event;
  camera_firmware::ai::Detection invalid;
  invalid.label = "invalid";
  camera_firmware::ai::Detection valid;
  valid.class_id = 0;
  valid.label = "person";
  event.detections = {invalid, valid};

  const auto json =
      camera_firmware::service::BuildDetectionSnapshotJson({event});

  ASSERT_EQ(json["events"].size(), 1U);
  ASSERT_EQ(json["events"][0]["detections"].size(), 1U);
  EXPECT_EQ(json["events"][0]["detections"][0]["class_id"].asInt(), 0);
  EXPECT_EQ(json["events"][0]["detections"][0]["label"].asString(),
            "person");
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
  event.frame_timestamp = std::chrono::nanoseconds{987654321};
  camera_firmware::ai::Detection detection;
  detection.class_id = 0;
  detection.label = "person";
  detection.confidence = 0.91F;
  camera_firmware::ai::Keypoint keypoint;
  keypoint.name = "nose";
  keypoint.x = 0.45F;
  keypoint.y = 0.18F;
  keypoint.confidence = 0.93F;
  detection.keypoints.push_back(keypoint);
  event.detections.push_back(detection);

  const auto payload =
      camera_firmware::service::BuildDetectionSseEvent({event});

  EXPECT_NE(payload.find("event: detections\n"), std::string::npos);
  EXPECT_NE(payload.find("id: imx708-main/objects/88/decoded\n"),
            std::string::npos);
  EXPECT_NE(payload.find("\"camera_id\":\"imx708-main\""), std::string::npos);
  EXPECT_NE(payload.find("\"frame_sequence\":88"), std::string::npos);
  EXPECT_NE(payload.find("\"frame_timestamp_ns\":987654321"),
            std::string::npos);
  EXPECT_NE(payload.find("\"class_id\":0"), std::string::npos);
  EXPECT_NE(payload.find("\"keypoints\""), std::string::npos);
  EXPECT_NE(payload.find("\"name\":\"nose\""), std::string::npos);
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

TEST(ServiceResponseTest, TlsListenerConfigUsesResolvedMaterial) {
  TemporaryTlsDirectory state;
  camera_firmware::config::AppConfig config;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = 9443;
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  camera_firmware::service::ServiceListenerConfig listener;
  struct stat validated_certificate {};
  {
    auto resolved = camera_firmware::security::ResolveTlsMaterial(
        config.http.tls, state.path());
    ASSERT_TRUE(resolved.ok()) << resolved.error().message;
    listener = camera_firmware::service::BuildServiceListenerConfig(
        config.http, resolved.value());
    ASSERT_EQ(::stat(listener.certificate_path.c_str(),
                     &validated_certificate),
              0);
  }
  std::filesystem::rename(state.path() / "device-tls",
                          state.path() / "validated-device-tls");
  ASSERT_TRUE(std::filesystem::create_directory(state.path() / "device-tls"));
  ASSERT_EQ(::chmod((state.path() / "device-tls").c_str(), 0700), 0);
  WriteExclusiveTlsFile(state.path() / "device-tls", "certificate.pem", 0644,
                        "replacement certificate\n");
  WriteExclusiveTlsFile(state.path() / "device-tls", "private-key.pem", 0600,
                        "replacement key\n");

  EXPECT_EQ(listener.bind_address, "127.0.0.1");
  EXPECT_EQ(listener.port, 9443u);
  EXPECT_TRUE(listener.use_tls);
  EXPECT_TRUE(listener.certificate_path.starts_with("/proc/self/fd/"));
  EXPECT_TRUE(listener.private_key_path.starts_with("/proc/self/fd/"));
  EXPECT_TRUE(std::filesystem::exists(listener.certificate_path));
  EXPECT_TRUE(std::filesystem::exists(listener.private_key_path));
  struct stat listener_certificate {};
  ASSERT_EQ(::stat(listener.certificate_path.c_str(), &listener_certificate), 0);
  EXPECT_EQ(listener_certificate.st_dev, validated_certificate.st_dev);
  EXPECT_EQ(listener_certificate.st_ino, validated_certificate.st_ino);
}

TEST(ServiceResponseTest, HttpTlsValidationPermitsMissingExplicitDevelopmentPair) {
  camera_firmware::config::HttpConfig http;
  http.enabled = true;
  http.tls.enabled = true;
  http.tls.allow_development_self_signed_tls = true;

  const auto validated =
      camera_firmware::service::ValidateHttpTlsConfigFiles(http);

  ASSERT_TRUE(validated.ok()) << validated.error().message;
}

TEST(ServiceResponseTest, HttpTlsValidationRejectsMissingProductionPair) {
  camera_firmware::config::HttpConfig http;
  http.enabled = true;
  http.tls.enabled = true;

  const auto validated =
      camera_firmware::service::ValidateHttpTlsConfigFiles(http);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_HTTP_TLS_REQUIRED");
}

TEST(ServiceResponseTest, HttpTlsValidationRejectsIncompleteDevelopmentPair) {
  camera_firmware::config::HttpConfig http;
  http.enabled = true;
  http.tls.enabled = true;
  http.tls.allow_development_self_signed_tls = true;
  http.tls.certificate_path = "/configured/http.crt";

  const auto validated =
      camera_firmware::service::ValidateHttpTlsConfigFiles(http);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_HTTP_TLS_REQUIRED");
}

TEST(ServiceResponseTest, TlsInitRejectsSecurityWithoutTlsInsteadOfDowngrade) {
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.http.enabled = true;
  config.http.tls.enabled = false;
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  camera_firmware::service::ServiceApp service;

  const auto initialized = service.Init(args);

  ASSERT_FALSE(initialized.ok());
  EXPECT_EQ(initialized.error().code, "E_HTTP_TLS_REQUIRED");
}

TEST(ServiceResponseTest,
     InitRejectsDefaultSecurityStateWithoutRuntimeStartCallback) {
  TemporaryTlsDirectory state;
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = state.path().string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = 0;
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  camera_firmware::service::ServiceApp service;

  const auto initialized = service.Init(args);

  ASSERT_FALSE(initialized.ok());
  EXPECT_EQ(initialized.error().code, "E_SERVICE_CONFIG");
}

TEST(ServiceResponseTest, TlsDescriptorOwnerSurvivesTimeoutUntilSafeJoin) {
  TemporaryTlsDirectory state;
  camera_firmware::config::HttpTlsConfig tls;
  tls.enabled = true;
  tls.allow_development_self_signed_tls = true;
  auto resolved = camera_firmware::security::ResolveTlsMaterial(tls, state.path());
  ASSERT_TRUE(resolved.ok()) << resolved.error().message;
  const auto certificate_path = resolved.value().certificate_path;
  const auto private_key_path = resolved.value().private_key_path;

  auto release = std::make_shared<std::promise<void>>();
  auto release_future = release->get_future().share();
  auto completion = std::make_shared<std::promise<void>>();
  auto completion_future = completion->get_future().share();
  auto service_thread =
      camera_firmware::service::internal::StartServiceThreadWithTlsOwner(
          std::optional<camera_firmware::security::ResolvedTlsMaterial>{
              std::move(resolved).value()},
          [release_future, completion] {
            release_future.wait();
            completion->set_value();
          });

  auto stopped = camera_firmware::service::internal::StopServiceThreadWithin(
      service_thread, completion_future, std::chrono::milliseconds(10), [] {});

  ASSERT_FALSE(stopped.ok());
  EXPECT_EQ(stopped.error().code, "E_SERVICE_THREAD_STOP_TIMEOUT");
  EXPECT_TRUE(service_thread.joinable());
  EXPECT_EQ(::access(certificate_path.c_str(), R_OK), 0);
  EXPECT_EQ(::access(private_key_path.c_str(), R_OK), 0);

  release->set_value();
  ASSERT_EQ(completion_future.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  if (service_thread.joinable()) {
    service_thread.join();
  }
  for (int attempt = 0; attempt < 1000; ++attempt) {
    if (::access(certificate_path.c_str(), F_OK) != 0 &&
        ::access(private_key_path.c_str(), F_OK) != 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  EXPECT_NE(::access(certificate_path.c_str(), F_OK), 0);
  EXPECT_NE(::access(private_key_path.c_str(), F_OK), 0);
}

TEST(ServiceResponseTest, HttpTlsValidationRejectsUnreadableOrInvalidFiles) {
  TemporaryTlsDirectory state;
  WriteExclusiveTlsFile(state.path(), "invalid-http.crt", 0644,
                        "not a certificate\n");
  WriteExclusiveTlsFile(state.path(), "invalid-http.key", 0600,
                        "not a private key\n");
  const auto cert_path = state.path() / "invalid-http.crt";
  const auto key_path = state.path() / "invalid-http.key";

  camera_firmware::config::HttpConfig http;
  http.enabled = true;
  http.tls.enabled = true;
  http.tls.certificate_path = cert_path.string();
  http.tls.private_key_path = key_path.string();

  auto validated = camera_firmware::service::ValidateHttpTlsConfigFiles(http);

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

TEST(ServiceResponseTest, LiveUnavailableUsesOnlyPublicErrorContract) {
  auto response = camera_firmware::service::BuildLiveMp4Response(
      [](const std::string&) {
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamCallback>::Err(
            {"E_LIVE_STALE", "private fragment timing detail"});
      },
      "imx708-main");

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), "E_LIVE_UNAVAILABLE");
  EXPECT_EQ((*json)["message"].asString(), "live preview is unavailable");
}

TEST(ServiceResponseTest, LiveCapacityUsesOnlyPublicErrorContract) {
  auto response = camera_firmware::service::BuildLiveMp4Response(
      [](const std::string&) {
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamCallback>::Err(
            {"E_LIVE_CAPACITY", "private reader detail"});
      },
      "imx708-main");

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), "E_LIVE_CAPACITY");
  EXPECT_EQ((*json)["message"].asString(),
            "live preview reader capacity is full");
}

TEST(ServiceResponseTest, LiveMp4ResponseWritesBytesAndSignalsRelease) {
  struct StreamState {
    std::string bytes{"fragmented-mp4-bytes"};
    bool released{false};
  };
  auto state = std::make_shared<StreamState>();

  auto response = camera_firmware::service::BuildLiveMp4Response(
      [state](const std::string& camera_id) {
        if (camera_id != "imx708-main") {
          return camera_firmware::common::Result<
              camera_firmware::service::LiveMp4StreamCallback>::Err(
              {"E_LIVE_NOT_FOUND", "camera not found"});
        }
        camera_firmware::service::LiveMp4StreamCallback stream =
            [state](char* output, std::size_t capacity) {
              if (output == nullptr) {
                state->released = true;
                return std::size_t{0};
              }
              const auto count = std::min(capacity, state->bytes.size());
              std::copy_n(state->bytes.data(), count, output);
              return count;
            };
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamCallback>::Ok(
            std::move(stream));
      },
      "imx708-main");

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  EXPECT_EQ(response->contentTypeString(), "video/mp4");
  EXPECT_EQ(response->getHeader("Content-Encoding"), "identity");
  ASSERT_TRUE(response->streamCallback());

  std::array<char, 32> output{};
  const auto written =
      response->streamCallback()(output.data(), output.size());
  EXPECT_EQ(std::string_view(output.data(), written), "fragmented-mp4-bytes");
  EXPECT_FALSE(state->released);

  EXPECT_EQ(response->streamCallback()(nullptr, 0U), 0U);
  EXPECT_TRUE(state->released);
}
