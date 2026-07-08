#include "camera_firmware/service/ServiceApp.hpp"

#include <string_view>

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
