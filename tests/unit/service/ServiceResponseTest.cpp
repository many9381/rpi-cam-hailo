#include "camera_firmware/service/ServiceApp.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

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

TEST(ServiceResponseTest, AiStatusReportsRuntimeSkeletonWhenRequested) {
  auto json = camera_firmware::service::BuildAiStatusJson(true);

  EXPECT_TRUE(json["enabled"].asBool());
  EXPECT_EQ(json["backend"].asString(), "hailo");
  EXPECT_EQ(json["state"].asString(), "backend_unavailable");
  EXPECT_EQ(json["model_count"].asUInt64(), 0u);
  EXPECT_EQ(json["runner_count"].asUInt64(), 0u);
  EXPECT_EQ(json["reason"].asString(),
            "Hailo backend is not implemented in this build");
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
