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

bool CanBindLoopbackPort(int port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return false;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(static_cast<std::uint16_t>(port));
  const bool bound =
      bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
  close(fd);
  return bound;
}

camera_firmware::config::SecureRtspConfig ClientAuthConfig(
    int port, const std::filesystem::path& credential_file) {
  camera_firmware::config::SecureRtspConfig config;
  config.bind_ip = "127.0.0.1";
  config.port = port;
  config.mount = "/test/auth";
  config.control_tls = true;
  config.allow_development_self_signed_tls = true;
  config.media_srtp = false;
  config.client_auth.enabled = true;
  config.client_auth.realm = "rpi-camera";
  config.client_auth.credential_file = credential_file.string();
  config.client_auth.algorithms = {"sha-256"};
  config.client_auth.nonce_ttl_seconds = 30U;
  return config;
}

void WriteValidClientCredentials(const std::filesystem::path& path,
                                 char digest_digit) {
  {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << "CFDIGEST1\noperator:rpi-camera:sha-256:"
        << std::string(64U, digest_digit) << "\n";
  }
  std::filesystem::permissions(
      path,
      std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace);
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
  EXPECT_EQ(server.PerMediaKeyZeroizeCount(), 0u);
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

TEST(SecureRtspConfigSmokeTest,
     ClientAuthMissingCredentialsFailsBeforeListenerAttach) {
  const auto missing = std::filesystem::temp_directory_path() /
                       "cf-missing-rtsp-client-auth.credentials";
  std::filesystem::remove(missing);
  const int port = FindFreeLoopbackPort();
  auto config = ClientAuthConfig(port, missing);
  camera_firmware::media::EncodedRing ring(4);
  camera_firmware::rtsp::SecureRtspServer server;

  auto started = server.Start(config, ring);

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_RTSP_AUTH_CREDENTIALS");
  EXPECT_TRUE(CanBindLoopbackPort(port));
}

TEST(SecureRtspConfigSmokeTest,
     ClientAuthMalformedCredentialsFailsBeforeListenerAttach) {
  const auto credentials = std::filesystem::temp_directory_path() /
                           "cf-malformed-rtsp-client-auth.credentials";
  {
    std::ofstream out(credentials);
    out << "not-a-credential-file\n";
  }
  std::filesystem::permissions(
      credentials, std::filesystem::perms::owner_read |
                       std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace);
  const int port = FindFreeLoopbackPort();
  auto config = ClientAuthConfig(port, credentials);
  camera_firmware::media::EncodedRing ring(4);
  camera_firmware::rtsp::SecureRtspServer server;

  auto started = server.Start(config, ring);

  std::filesystem::remove(credentials);
  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_RTSP_AUTH_CREDENTIALS");
  EXPECT_TRUE(CanBindLoopbackPort(port));
}

TEST(SecureRtspConfigSmokeTest,
     ClientAuthInsecureCredentialsFailsBeforeListenerAttach) {
  const auto credentials = std::filesystem::temp_directory_path() /
                           "cf-insecure-rtsp-client-auth.credentials";
  WriteValidClientCredentials(credentials, '0');
  std::filesystem::permissions(
      credentials,
      std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_write |
          std::filesystem::perms::group_read,
      std::filesystem::perm_options::replace);
  const int port = FindFreeLoopbackPort();
  auto config = ClientAuthConfig(port, credentials);
  camera_firmware::media::EncodedRing ring(4);
  camera_firmware::rtsp::SecureRtspServer server;

  auto started = server.Start(config, ring);

  std::filesystem::remove(credentials);
  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_RTSP_AUTH_CREDENTIALS");
  EXPECT_TRUE(CanBindLoopbackPort(port));
}

TEST(SecureRtspConfigSmokeTest,
     ClientAuthEnabledStartsAndReloadsCredentials) {
  const auto credentials = std::filesystem::temp_directory_path() /
                           "cf-valid-rtsp-client-auth.credentials";
  WriteValidClientCredentials(credentials, '0');
  const int port = FindFreeLoopbackPort();
  auto config = ClientAuthConfig(port, credentials);
  camera_firmware::media::EncodedRing ring(4);
  camera_firmware::rtsp::SecureRtspServer server;

  auto started = server.Start(config, ring);
  ASSERT_TRUE(started.ok()) << started.error().code << ": "
                            << started.error().message;
  WriteValidClientCredentials(credentials, '1');
  auto reloaded = server.ReloadClientCredentials();

  EXPECT_TRUE(reloaded.ok())
      << (reloaded.ok() ? std::string{} : reloaded.error().message);
  server.Stop();
  std::filesystem::remove(credentials);
  EXPECT_TRUE(CanBindLoopbackPort(port));
}

TEST(SecureRtspConfigSmokeTest, ClientAuthDisabledPreservesStartupBehavior) {
  const int port = FindFreeLoopbackPort();
  auto config = ClientAuthConfig(
      port, std::filesystem::temp_directory_path() /
                "cf-unused-disabled-client-auth.credentials");
  config.client_auth.enabled = false;
  camera_firmware::media::EncodedRing ring(4);
  camera_firmware::rtsp::SecureRtspServer server;

  auto started = server.Start(config, ring);

  ASSERT_TRUE(started.ok()) << started.error().code << ": "
                            << started.error().message;
  auto reload = server.ReloadClientCredentials();
  EXPECT_FALSE(reload.ok());
  server.Stop();
}
