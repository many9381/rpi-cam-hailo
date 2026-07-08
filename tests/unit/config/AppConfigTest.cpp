#include "camera_firmware/config/AppConfig.hpp"

#include <fstream>

#include <gtest/gtest.h>

TEST(AppConfigTest, LoadsSecureRtspSessionKeyConfig) {
  auto cfg = camera_firmware::config::LoadConfigFile("config/app-rpi5-dev.yaml");
  ASSERT_TRUE(cfg.ok()) << cfg.error().message;
  EXPECT_TRUE(cfg.value().secure_rtsp.enabled);
  EXPECT_TRUE(cfg.value().secure_rtsp.media_srtp);
  EXPECT_EQ(cfg.value().secure_rtsp.session_key.encoding, "hex");
  EXPECT_TRUE(cfg.value().secure_rtsp.allow_development_self_signed_tls);
  EXPECT_EQ(cfg.value().secure_rtsp.keying, "sdes-over-rtsps");
  EXPECT_EQ(cfg.value().platform.target, "rpi5");
  EXPECT_EQ(cfg.value().camera.id, "imx708-main");
  EXPECT_EQ(cfg.value().camera.source.backend, "libcamera");
  EXPECT_EQ(cfg.value().camera.video.width, 1536u);
  EXPECT_EQ(cfg.value().camera.video.height, 864u);
  EXPECT_EQ(cfg.value().camera.video.fps, 30u);
  EXPECT_EQ(cfg.value().camera.video.format, "nv12");
  EXPECT_EQ(cfg.value().camera.encoder.backend, "x264");
  EXPECT_EQ(cfg.value().camera.encoder.bitrate_kbps, 3000u);
  EXPECT_EQ(cfg.value().camera.encoder.gop, 30u);
  EXPECT_TRUE(cfg.value().http.enabled);
  EXPECT_FALSE(cfg.value().http.tls.enabled);
  EXPECT_EQ(cfg.value().http.port, 8443u);
  EXPECT_EQ(cfg.value().http.public_base_url, "http://127.0.0.1:8443");
  EXPECT_EQ(cfg.value().http.web_root, "web");
  EXPECT_FALSE(cfg.value().ai.enabled);
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

TEST(AppConfigTest, RejectsMissingTlsCertificateConfigWhenControlTlsEnabled) {
  const char* yaml = "/tmp/cf-missing-tls.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: true\n"
         "  control_tls: true\n"
         "  media_srtp: false\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_FALSE(cfg.ok());
  EXPECT_EQ(cfg.error().code, "E_CONFIG_TLS_CERT");
}

TEST(AppConfigTest, LoadsConfiguredTlsCertificateAndKeyPaths) {
  const char* yaml = "/tmp/cf-tls-paths.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: true\n"
         "  control_tls: true\n"
         "  media_srtp: false\n"
         "  tls_certificate_path: /etc/camera-firmware/tls.crt\n"
         "  tls_private_key_path: /etc/camera-firmware/tls.key\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_TRUE(cfg.ok()) << cfg.error().message;
  EXPECT_EQ(cfg.value().secure_rtsp.tls_certificate_path,
            "/etc/camera-firmware/tls.crt");
  EXPECT_EQ(cfg.value().secure_rtsp.tls_private_key_path,
            "/etc/camera-firmware/tls.key");
  EXPECT_FALSE(cfg.value().secure_rtsp.allow_development_self_signed_tls);
}

TEST(AppConfigTest, RejectsSdesKeyingWithoutRtspsControlChannel) {
  const char* yaml = "/tmp/cf-sdes-without-rtsps.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: true\n"
         "  control_tls: false\n"
         "  media_srtp: true\n"
         "  keying: sdes-over-rtsps\n"
         "  session_key:\n"
         "    path: /tmp/key.hex\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_FALSE(cfg.ok());
  EXPECT_EQ(cfg.error().code, "E_CONFIG_SRTP_KEYING");
}

TEST(AppConfigTest, SharedSecureRtspSemanticsRejectSdesWithoutRtsps) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.enabled = true;
  secure_rtsp.control_tls = false;
  secure_rtsp.media_srtp = true;
  secure_rtsp.keying = "sdes-over-rtsps";
  secure_rtsp.session_key.path = "/tmp/key.hex";

  auto validated =
      camera_firmware::config::ValidateSecureRtspSemantics(secure_rtsp);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_CONFIG_SRTP_KEYING");
}

TEST(AppConfigTest, RejectsHttpTlsWithoutCertificatePair) {
  const char* yaml = "/tmp/cf-http-tls-missing-pair.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: false\n"
         "http:\n"
         "  enabled: true\n"
         "  tls:\n"
         "    enabled: true\n"
         "    certificate_path: /tmp/http.crt\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_FALSE(cfg.ok());
  EXPECT_EQ(cfg.error().code, "E_CONFIG_HTTP_TLS");
}
