#include "camera_firmware/config/AppConfig.hpp"

#include <fstream>

#include <gtest/gtest.h>

TEST(AppConfigTest, LoadsSecureRtspSessionKeyConfig) {
  auto cfg = camera_firmware::config::LoadConfigFile("config/app-rpi5-dev.yaml");
  ASSERT_TRUE(cfg.ok()) << cfg.error().message;
  EXPECT_TRUE(cfg.value().secure_rtsp.enabled);
  EXPECT_TRUE(cfg.value().secure_rtsp.media_srtp);
  EXPECT_EQ(cfg.value().secure_rtsp.session_key.encoding, "hex");
}

TEST(AppConfigTest, RejectsMissingSessionKeyWhenSrtpEnabled) {
  const char* yaml = "/tmp/cf-missing-key.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n  enabled: true\n  media_srtp: true\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);
  ASSERT_FALSE(cfg.ok());
  EXPECT_EQ(cfg.error().code, "E_CONFIG_SESSION_KEY");
}
