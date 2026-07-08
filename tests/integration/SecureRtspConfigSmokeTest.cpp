#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/EncodedRing.hpp"
#include "camera_firmware/rtsp/SecureRtspServer.hpp"

#include <arpa/inet.h>
#include <filesystem>
#include <fstream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

int FindFreeLoopbackPort() {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return 18555;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    close(fd);
    return 18555;
  }
  socklen_t length = sizeof(address);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    close(fd);
    return 18555;
  }
  const int port = ntohs(address.sin_port);
  close(fd);
  return port;
}

}  // namespace

TEST(SecureRtspConfigSmokeTest, AppConfigCanBuildRtspUrl) {
  auto cfg =
      camera_firmware::config::LoadConfigFile("config/app-rpi5-dev.yaml");
  ASSERT_TRUE(cfg.ok()) << cfg.error().message;

  auto url = camera_firmware::rtsp::BuildRtspUrl(cfg.value().secure_rtsp);

  EXPECT_EQ(url, "rtsps://0.0.0.0:8555/imx708/main");
}

TEST(SecureRtspConfigSmokeTest, SecureServerStartsAndStopsWithoutCamera) {
  const auto key_path =
      std::filesystem::temp_directory_path() / "camera-firmware-test-srtp.hex";
  {
    std::ofstream out(key_path);
    out << std::string(60, '1');
  }

  camera_firmware::config::SecureRtspConfig config;
  config.bind_ip = "127.0.0.1";
  config.port = FindFreeLoopbackPort();
  config.mount = "/test/main";
  config.control_tls = true;
  config.allow_development_self_signed_tls = true;
  config.media_srtp = true;
  config.keying = "sdes-over-rtsps";
  config.session_key.path = key_path.string();

  camera_firmware::media::EncodedRing ring(4);
  camera_firmware::rtsp::SecureRtspServer server;
  auto started = server.Start(config, ring);

  std::filesystem::remove(key_path);
  ASSERT_TRUE(started.ok()) << started.error().code << ": "
                            << started.error().message;
  server.Stop();
}

TEST(SecureRtspConfigSmokeTest, SecureEncoderHooksReturnProjectElement) {
  auto hook_probe = camera_firmware::rtsp::VerifySecureEncoderHooks();

  ASSERT_TRUE(hook_probe.ok()) << hook_probe.error().code << ": "
                               << hook_probe.error().message;
  EXPECT_EQ(hook_probe.value().rtp_element_factory_name, "cfsecuresrtpenc");
  EXPECT_EQ(hook_probe.value().rtcp_element_factory_name, "cfsecuresrtpenc");
  EXPECT_GE(hook_probe.value().per_media_key_zeroize_count, 1u);
}

TEST(SecureRtspConfigSmokeTest, SecureServerStartStopKeepsOnlyActiveKeyOwner) {
  const auto key_path =
      std::filesystem::temp_directory_path() /
      "camera-firmware-test-cleanup-srtp.hex";
  {
    std::ofstream out(key_path);
    out << std::string(60, '2');
  }

  camera_firmware::config::SecureRtspConfig config;
  config.bind_ip = "127.0.0.1";
  config.port = FindFreeLoopbackPort();
  config.mount = "/test/cleanup";
  config.control_tls = true;
  config.allow_development_self_signed_tls = true;
  config.media_srtp = true;
  config.keying = "sdes-over-rtsps";
  config.session_key.path = key_path.string();

  camera_firmware::media::EncodedRing ring(4);
  camera_firmware::rtsp::SecureRtspServer server;
  auto started = server.Start(config, ring);
  std::filesystem::remove(key_path);
  ASSERT_TRUE(started.ok()) << started.error().code << ": "
                            << started.error().message;
  server.Stop();
}

TEST(SecureRtspConfigSmokeTest, SecureMediaSemanticsUseSdesOverRtsps) {
  camera_firmware::config::SecureRtspConfig config;
  config.control_tls = true;
  config.media_srtp = true;
  config.keying = "sdes-over-rtsps";

  auto description = camera_firmware::rtsp::DescribeSecureMedia(config);

  EXPECT_EQ(description.control_scheme, "rtsps");
  EXPECT_EQ(description.media_profile, "RTP/SAVPF");
  EXPECT_EQ(description.keying, "SDES-over-RTSPS");
  EXPECT_TRUE(description.requires_tls_control_channel);
}

TEST(SecureRtspConfigSmokeTest, SecureFileValidationRejectsMalformedSrtpKey) {
  const auto key_path =
      std::filesystem::temp_directory_path() / "cf-invalid-srtp-key.hex";
  {
    std::ofstream out(key_path);
    out << "0011";
  }

  camera_firmware::config::SecureRtspConfig config;
  config.control_tls = true;
  config.media_srtp = true;
  config.session_key.path = key_path.string();

  auto validated = camera_firmware::rtsp::ValidateSecureRtspConfigFiles(config);

  std::filesystem::remove(key_path);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_SRTP_KEY_LENGTH");
}

TEST(SecureRtspConfigSmokeTest,
     SecureFileValidationRejectsSdesOverRtspBeforeReadingKey) {
  const auto key_path =
      std::filesystem::temp_directory_path() / "cf-valid-srtp-no-rtsps.hex";
  {
    std::ofstream out(key_path);
    out << std::string(60, '3');
  }

  camera_firmware::config::SecureRtspConfig config;
  config.control_tls = false;
  config.media_srtp = true;
  config.keying = "sdes-over-rtsps";
  config.session_key.path = key_path.string();

  auto validated = camera_firmware::rtsp::ValidateSecureRtspConfigFiles(config);

  std::filesystem::remove(key_path);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_CONFIG_SRTP_KEYING");
}

TEST(SecureRtspConfigSmokeTest, ServerStartRejectsSdesOverRtsp) {
  const auto key_path =
      std::filesystem::temp_directory_path() / "cf-start-srtp-no-rtsps.hex";
  {
    std::ofstream out(key_path);
    out << std::string(60, '4');
  }

  camera_firmware::config::SecureRtspConfig config;
  config.bind_ip = "127.0.0.1";
  config.port = FindFreeLoopbackPort();
  config.mount = "/test/no-rtsps";
  config.control_tls = false;
  config.media_srtp = true;
  config.keying = "sdes-over-rtsps";
  config.session_key.path = key_path.string();

  camera_firmware::media::EncodedRing ring(4);
  camera_firmware::rtsp::SecureRtspServer server;
  auto started = server.Start(config, ring);

  std::filesystem::remove(key_path);
  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_CONFIG_SRTP_KEYING");
}

TEST(SecureRtspConfigSmokeTest, SecureFileValidationRejectsInvalidRtspTlsPair) {
  const auto cert_path =
      std::filesystem::temp_directory_path() / "cf-invalid-rtsp.crt";
  const auto key_path =
      std::filesystem::temp_directory_path() / "cf-invalid-rtsp.key";
  {
    std::ofstream cert(cert_path);
    cert << "not a certificate";
    std::ofstream key(key_path);
    key << "not a key";
  }

  camera_firmware::config::SecureRtspConfig config;
  config.control_tls = true;
  config.allow_development_self_signed_tls = false;
  config.media_srtp = false;
  config.tls_certificate_path = cert_path.string();
  config.tls_private_key_path = key_path.string();

  auto validated = camera_firmware::rtsp::ValidateSecureRtspConfigFiles(config);

  std::filesystem::remove(cert_path);
  std::filesystem::remove(key_path);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RTSP_TLS_CERT");
}
