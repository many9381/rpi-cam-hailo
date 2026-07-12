#include "camera_firmware/config/AppConfig.hpp"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

namespace {

camera_firmware::config::AiConfig MakeValidAiConfig() {
  camera_firmware::config::AiConfig ai;
  ai.enabled = true;
  ai.backend = "hailo";

  camera_firmware::config::AiModelConfig model;
  model.id = "objects";
  model.kind = "object_detection";
  model.hef_path = "/opt/cf/models/yolov8n.hef";
  model.input.width = 640;
  model.input.height = 640;
  model.input.format = "rgb8";
  model.confidence_threshold = 0.40F;
  ai.models.push_back(model);

  return ai;
}

camera_firmware::common::Result<camera_firmware::config::AppConfig>
LoadInlineConfig(std::string_view yaml) {
  static std::atomic<unsigned int> next_file{0U};
  const auto path = std::filesystem::temp_directory_path() /
                    ("cf-app-config-" +
                     std::to_string(next_file.fetch_add(1U)) + ".yaml");
  {
    std::ofstream out(path);
    out << yaml;
  }
  auto config = camera_firmware::config::LoadConfigFile(path.string());
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
  return config;
}

std::string SecurityConfigWithTls(bool tls_enabled) {
  return std::string(R"(
http:
  enabled: true
  public_base_url: https://camera.local:8443
  tls:
    enabled: )") +
         (tls_enabled ? "true" : "false") + R"(
    certificate_path: /tmp/camera.crt
    private_key_path: /tmp/camera.key
security:
  enabled: true
  state_directory: /var/lib/camera-firmware/security
secure_rtsp:
  enabled: true
  control_tls: true
  media_srtp: false
  allow_development_self_signed_tls: true
  client_auth:
    enabled: true
    realm: rpi-camera
    credential_file: /var/lib/camera-firmware/security/rtsp.credentials
    algorithms: [sha-256]
)";
}

std::string SecurityConfigWithRtspAuth(bool auth_enabled) {
  std::string yaml = SecurityConfigWithTls(true);
  const auto marker = std::string("    enabled: true\n    realm: rpi-camera");
  const auto position = yaml.rfind(marker);
  EXPECT_NE(position, std::string::npos);
  yaml.replace(position, marker.size(),
               auth_enabled ? marker : "    enabled: false\n    realm: rpi-camera");
  return yaml;
}

std::string SecurityConfigWithPublicUrl(std::string_view public_url) {
  std::string yaml = SecurityConfigWithTls(true);
  constexpr std::string_view kDefaultUrl = "https://camera.local:8443";
  const auto position = yaml.find(kDefaultUrl);
  EXPECT_NE(position, std::string::npos);
  yaml.replace(position, kDefaultUrl.size(), public_url);
  return yaml;
}

std::string SecurityConfigWithAlgorithms(std::string_view algorithms) {
  std::string yaml = SecurityConfigWithTls(true);
  constexpr std::string_view kDefaultAlgorithms = "[sha-256]";
  const auto position = yaml.find(kDefaultAlgorithms);
  EXPECT_NE(position, std::string::npos);
  yaml.replace(position, kDefaultAlgorithms.size(), algorithms);
  return yaml;
}

std::string SecurityConfigWithCredentialFile(std::string_view credential_file) {
  std::string yaml = SecurityConfigWithTls(true);
  constexpr std::string_view kDefaultCredential =
      "/var/lib/camera-firmware/security/rtsp.credentials";
  const auto position = yaml.find(kDefaultCredential);
  EXPECT_NE(position, std::string::npos);
  yaml.replace(position, kDefaultCredential.size(), credential_file);
  return yaml;
}

void ExpectConfigError(std::string_view yaml, std::string_view code) {
  const auto config = LoadInlineConfig(yaml);
  ASSERT_FALSE(config.ok());
  EXPECT_EQ(config.error().code, code);
}

}  // namespace

TEST(AppConfigTest, LoadsEnabledBootstrapSecurityConfig) {
  const auto config = LoadInlineConfig(R"(
http:
  enabled: true
  public_base_url: https://camera.local:8443
  tls:
    enabled: true
    certificate_path: /tmp/camera.crt
    private_key_path: /tmp/camera.key
security:
  enabled: true
  state_directory: /var/lib/camera-firmware/security
secure_rtsp:
  enabled: true
  control_tls: true
  media_srtp: false
  allow_development_self_signed_tls: true
  client_auth:
    enabled: true
    realm: rpi-camera
    credential_file: /var/lib/camera-firmware/security/rtsp.credentials
    algorithms: [sha-256]
)");
  ASSERT_TRUE(config.ok()) << config.error().message;
  EXPECT_TRUE(config.value().security.enabled);
  EXPECT_EQ(config.value().security.state_directory,
            "/var/lib/camera-firmware/security");
}

TEST(AppConfigTest, DefaultsOmittedWebRootToProductionArtifacts) {
  const auto config = LoadInlineConfig(R"(
http:
  enabled: true
security:
  enabled: false
secure_rtsp:
  enabled: false
)");

  ASSERT_TRUE(config.ok()) << config.error().message;
  EXPECT_EQ(config.value().http.web_root, "web/dist");
}

TEST(AppConfigTest, RejectsSecurityWithoutHttpsOrSha256RtspAuth) {
  ExpectConfigError(SecurityConfigWithTls(false), "E_SECURITY_TLS");
  ExpectConfigError(SecurityConfigWithRtspAuth(false), "E_SECURITY_RTSP_AUTH");
  ExpectConfigError(SecurityConfigWithPublicUrl("http://camera.local"),
                    "E_SECURITY_PUBLIC_URL");
  ExpectConfigError(SecurityConfigWithAlgorithms("[sha-256, md5]"),
                    "E_SECURITY_RTSP_AUTH");
  ExpectConfigError(
      SecurityConfigWithCredentialFile(
          "/var/lib/camera-firmware/security/../rtsp.credentials"),
      "E_SECURITY_CREDENTIAL_PATH");
}

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
  EXPECT_EQ(cfg.value().http.web_root, "web/dist");
  EXPECT_FALSE(cfg.value().security.enabled);
  EXPECT_FALSE(cfg.value().ai.enabled);
  EXPECT_TRUE(cfg.value().ai.models.empty());
  EXPECT_FALSE(cfg.value().camera.ai.enabled);
  EXPECT_TRUE(cfg.value().camera.ai.model_ids.empty());
}

TEST(AppConfigTest, RtspClientAuthDefaultsToDisabledSha256Policy) {
  camera_firmware::config::SecureRtspConfig config;

  EXPECT_FALSE(config.client_auth.enabled);
  EXPECT_TRUE(config.client_auth.realm.empty());
  EXPECT_TRUE(config.client_auth.credential_file.empty());
  EXPECT_EQ(config.client_auth.algorithms,
            std::vector<std::string>({"sha-256"}));
  EXPECT_EQ(config.client_auth.nonce_ttl_seconds, 300U);
}

TEST(AppConfigTest, LoadsEnabledRtspClientAuthConfig) {
  const char* yaml = "/tmp/cf-rtsp-client-auth.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: true\n"
         "  control_tls: true\n"
         "  media_srtp: false\n"
         "  tls_certificate_path: /etc/camera-firmware/tls.crt\n"
         "  tls_private_key_path: /etc/camera-firmware/tls.key\n"
         "  client_auth:\n"
         "    enabled: true\n"
         "    realm: rpi-camera\n"
         "    credential_file: /etc/camera-firmware/rtsp.credentials\n"
         "    algorithms: [sha-256, md5]\n"
         "    nonce_ttl_seconds: 600\n"
         "security:\n"
         "  enabled: false\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_TRUE(cfg.ok()) << cfg.error().message;
  EXPECT_TRUE(cfg.value().secure_rtsp.client_auth.enabled);
  EXPECT_EQ(cfg.value().secure_rtsp.client_auth.realm, "rpi-camera");
  EXPECT_EQ(cfg.value().secure_rtsp.client_auth.credential_file,
            "/etc/camera-firmware/rtsp.credentials");
  EXPECT_EQ(cfg.value().secure_rtsp.client_auth.algorithms,
            std::vector<std::string>({"sha-256", "md5"}));
  EXPECT_EQ(cfg.value().secure_rtsp.client_auth.nonce_ttl_seconds, 600U);
}

TEST(AppConfigTest, LoadsEnabledRtspClientAuthWithDefaultAlgorithms) {
  const char* yaml = "/tmp/cf-rtsp-client-auth-default-algorithms.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: true\n"
         "  control_tls: true\n"
         "  media_srtp: false\n"
         "  tls_certificate_path: /etc/camera-firmware/tls.crt\n"
         "  tls_private_key_path: /etc/camera-firmware/tls.key\n"
         "  client_auth:\n"
         "    enabled: true\n"
         "    realm: rpi-camera\n"
         "    credential_file: /etc/camera-firmware/rtsp.credentials\n"
         "security:\n"
         "  enabled: false\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_TRUE(cfg.ok()) << cfg.error().message;
  EXPECT_EQ(cfg.value().secure_rtsp.client_auth.algorithms,
            std::vector<std::string>({"sha-256"}));
}

TEST(AppConfigTest, RejectsExplicitlyEmptyRtspClientAuthAlgorithms) {
  const char* yaml = "/tmp/cf-rtsp-client-auth-empty-algorithms.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: true\n"
         "  control_tls: true\n"
         "  media_srtp: false\n"
         "  tls_certificate_path: /etc/camera-firmware/tls.crt\n"
         "  tls_private_key_path: /etc/camera-firmware/tls.key\n"
         "  client_auth:\n"
         "    enabled: true\n"
         "    realm: rpi-camera\n"
         "    credential_file: /etc/camera-firmware/rtsp.credentials\n"
         "    algorithms: []\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_FALSE(cfg.ok());
  EXPECT_EQ(cfg.error().code, "E_CONFIG_RTSP_AUTH_ALGORITHM");
  EXPECT_EQ(cfg.error().message,
            "secure_rtsp.client_auth.algorithms is invalid");
}

TEST(AppConfigTest, RejectsScalarRtspClientAuthAlgorithms) {
  const char* yaml = "/tmp/cf-rtsp-client-auth-scalar-algorithms.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: true\n"
         "  control_tls: true\n"
         "  media_srtp: false\n"
         "  tls_certificate_path: /etc/camera-firmware/tls.crt\n"
         "  tls_private_key_path: /etc/camera-firmware/tls.key\n"
         "  client_auth:\n"
         "    enabled: true\n"
         "    realm: rpi-camera\n"
         "    credential_file: /etc/camera-firmware/rtsp.credentials\n"
         "    algorithms: sha-256\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_FALSE(cfg.ok());
  EXPECT_EQ(cfg.error().code, "E_CONFIG_RTSP_AUTH_ALGORITHM");
  EXPECT_EQ(cfg.error().message,
            "secure_rtsp.client_auth.algorithms is invalid");
}

TEST(AppConfigTest, AcceptsEnabledRtspClientAuthWithSha256) {
  camera_firmware::config::SecureRtspConfig config;
  config.enabled = true;
  config.control_tls = true;
  config.media_srtp = false;
  config.client_auth.enabled = true;
  config.client_auth.realm = "rpi-camera";
  config.client_auth.credential_file = "/tmp/test.credentials";

  auto result = camera_firmware::config::ValidateSecureRtspSemantics(config);

  EXPECT_TRUE(result.ok()) << result.error().message;
}

TEST(AppConfigTest, RejectsEnabledRtspClientAuthWithoutTls) {
  camera_firmware::config::SecureRtspConfig config;
  config.enabled = true;
  config.control_tls = false;
  config.media_srtp = false;
  config.client_auth.enabled = true;
  config.client_auth.realm = "rpi-camera";
  config.client_auth.credential_file = "/tmp/test.credentials";

  auto result = camera_firmware::config::ValidateSecureRtspSemantics(config);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_CONFIG_RTSP_AUTH_TLS");
}

TEST(AppConfigTest, RejectsMd5OnlyRtspClientAuth) {
  camera_firmware::config::SecureRtspConfig config;
  config.enabled = true;
  config.control_tls = true;
  config.media_srtp = false;
  config.client_auth.enabled = true;
  config.client_auth.realm = "rpi-camera";
  config.client_auth.credential_file = "/tmp/test.credentials";
  config.client_auth.algorithms = {"md5"};

  auto result = camera_firmware::config::ValidateSecureRtspSemantics(config);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_CONFIG_RTSP_AUTH_ALGORITHM");
}

TEST(AppConfigTest, RejectsRtspClientAuthWithMissingRealm) {
  camera_firmware::config::SecureRtspConfig config;
  config.enabled = true;
  config.control_tls = true;
  config.media_srtp = false;
  config.client_auth.enabled = true;
  config.client_auth.credential_file = "/tmp/test.credentials";

  auto result = camera_firmware::config::ValidateSecureRtspSemantics(config);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_CONFIG_RTSP_AUTH_REALM");
}

TEST(AppConfigTest, RejectsRtspClientAuthWithMissingCredentialFile) {
  camera_firmware::config::SecureRtspConfig config;
  config.enabled = true;
  config.control_tls = true;
  config.media_srtp = false;
  config.client_auth.enabled = true;
  config.client_auth.realm = "rpi-camera";

  auto result = camera_firmware::config::ValidateSecureRtspSemantics(config);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_CONFIG_RTSP_AUTH");
  EXPECT_EQ(result.error().message,
            "secure_rtsp.client_auth.credential_file is required");
}

TEST(AppConfigTest, RejectsDuplicateRtspClientAuthAlgorithms) {
  camera_firmware::config::SecureRtspConfig config;
  config.enabled = true;
  config.control_tls = true;
  config.media_srtp = false;
  config.client_auth.enabled = true;
  config.client_auth.realm = "rpi-camera";
  config.client_auth.credential_file = "/tmp/test.credentials";
  config.client_auth.algorithms = {"sha-256", "sha-256"};

  auto result = camera_firmware::config::ValidateSecureRtspSemantics(config);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_CONFIG_RTSP_AUTH_ALGORITHM");
}

TEST(AppConfigTest, RejectsRtspClientAuthRealmWithForbiddenBytes) {
  camera_firmware::config::SecureRtspConfig config;
  config.enabled = true;
  config.control_tls = true;
  config.media_srtp = false;
  config.client_auth.enabled = true;
  config.client_auth.realm = "rpi:camera";
  config.client_auth.credential_file = "/tmp/test.credentials";

  auto result = camera_firmware::config::ValidateSecureRtspSemantics(config);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_CONFIG_RTSP_AUTH_REALM");
}

TEST(AppConfigTest, RejectsRtspClientAuthNonceTtlBelowMinimum) {
  camera_firmware::config::SecureRtspConfig config;
  config.enabled = true;
  config.control_tls = true;
  config.media_srtp = false;
  config.client_auth.enabled = true;
  config.client_auth.realm = "rpi-camera";
  config.client_auth.credential_file = "/tmp/test.credentials";
  config.client_auth.nonce_ttl_seconds = 29;

  auto result = camera_firmware::config::ValidateSecureRtspSemantics(config);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_CONFIG_RTSP_AUTH");
  EXPECT_EQ(result.error().message,
            "secure_rtsp.client_auth.nonce_ttl_seconds is invalid");
}

TEST(AppConfigTest, RejectsRtspClientAuthNonceTtlAboveMaximum) {
  camera_firmware::config::SecureRtspConfig config;
  config.enabled = true;
  config.control_tls = true;
  config.media_srtp = false;
  config.client_auth.enabled = true;
  config.client_auth.realm = "rpi-camera";
  config.client_auth.credential_file = "/tmp/test.credentials";
  config.client_auth.nonce_ttl_seconds = 3601;

  auto result = camera_firmware::config::ValidateSecureRtspSemantics(config);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_CONFIG_RTSP_AUTH");
  EXPECT_EQ(result.error().message,
            "secure_rtsp.client_auth.nonce_ttl_seconds is invalid");
}

TEST(AppConfigTest, LoadsRpi5AiDevConfig) {
  auto cfg =
      camera_firmware::config::LoadConfigFile("config/app-rpi5-ai-dev.yaml");

  ASSERT_TRUE(cfg.ok()) << cfg.error().message;
  EXPECT_EQ(cfg.value().platform.target, "rpi5");
  EXPECT_EQ(cfg.value().camera.id, "imx708-main");
  EXPECT_TRUE(cfg.value().camera.ai.enabled);
  ASSERT_EQ(cfg.value().camera.ai.model_ids.size(), 1u);
  EXPECT_EQ(cfg.value().camera.ai.model_ids[0], "objects");

  EXPECT_TRUE(cfg.value().ai.enabled);
  EXPECT_EQ(cfg.value().ai.backend, "hailo");
  ASSERT_EQ(cfg.value().ai.models.size(), 1u);
  const auto& model = cfg.value().ai.models[0];
  EXPECT_EQ(model.id, "objects");
  EXPECT_EQ(model.kind, "object_detection");
  EXPECT_EQ(model.hef_path, "vendor/models/yolo_model.hef");
  EXPECT_EQ(model.input.width, 640u);
  EXPECT_EQ(model.input.height, 640u);
  EXPECT_EQ(model.input.format, "rgb8");
  EXPECT_TRUE(model.input.letterbox);
  EXPECT_FLOAT_EQ(model.confidence_threshold, 0.40F);
  EXPECT_EQ(model.labels, "coco80");
  EXPECT_TRUE(model.output_name.empty());

  EXPECT_TRUE(cfg.value().secure_rtsp.enabled);
  EXPECT_TRUE(cfg.value().secure_rtsp.media_srtp);
  EXPECT_EQ(cfg.value().secure_rtsp.session_key.path,
            "config/dev-srtp-session.hex");
  EXPECT_TRUE(cfg.value().secure_rtsp.session_key.zeroize_on_reload);
  EXPECT_FALSE(cfg.value().security.enabled);
}

TEST(AppConfigTest, LoadsRpi5AiMultiModelDevConfig) {
  auto cfg = camera_firmware::config::LoadConfigFile(
      "config/app-rpi5-ai-multimodel-dev.yaml");

  ASSERT_TRUE(cfg.ok()) << cfg.error().message;
  EXPECT_EQ(cfg.value().platform.target, "rpi5");
  EXPECT_EQ(cfg.value().camera.id, "imx708-main");
  EXPECT_TRUE(cfg.value().camera.ai.enabled);
  ASSERT_EQ(cfg.value().camera.ai.model_ids.size(), 2u);
  EXPECT_EQ(cfg.value().camera.ai.model_ids[0], "objects");
  EXPECT_EQ(cfg.value().camera.ai.model_ids[1], "pose");

  EXPECT_TRUE(cfg.value().ai.enabled);
  EXPECT_EQ(cfg.value().ai.backend, "hailo");
  ASSERT_EQ(cfg.value().ai.models.size(), 2u);

  const auto& objects = cfg.value().ai.models[0];
  EXPECT_EQ(objects.id, "objects");
  EXPECT_EQ(objects.kind, "object_detection");
  EXPECT_EQ(objects.hef_path, "vendor/models/yolo_model.hef");
  EXPECT_TRUE(objects.output_name.empty());
  EXPECT_EQ(objects.input.width, 640u);
  EXPECT_EQ(objects.input.height, 640u);
  EXPECT_EQ(objects.input.format, "rgb8");
  EXPECT_TRUE(objects.input.letterbox);
  EXPECT_FLOAT_EQ(objects.confidence_threshold, 0.40F);
  EXPECT_EQ(objects.labels, "coco80");

  const auto& pose = cfg.value().ai.models[1];
  EXPECT_EQ(pose.id, "pose");
  EXPECT_EQ(pose.kind, "pose");
  EXPECT_EQ(pose.hef_path, "vendor/models/yolov8n-pose.hef");
  EXPECT_EQ(pose.output_name, "yolov8_pose_postprocess");
  EXPECT_EQ(pose.input.width, 640u);
  EXPECT_EQ(pose.input.height, 640u);
  EXPECT_EQ(pose.input.format, "rgb8");
  EXPECT_TRUE(pose.input.letterbox);
  EXPECT_FLOAT_EQ(pose.confidence_threshold, 0.35F);
  EXPECT_EQ(pose.labels, "pose17");

  EXPECT_TRUE(cfg.value().secure_rtsp.enabled);
  EXPECT_TRUE(cfg.value().secure_rtsp.media_srtp);
  EXPECT_TRUE(cfg.value().secure_rtsp.session_key.zeroize_on_reload);
  EXPECT_FALSE(cfg.value().security.enabled);
}

TEST(AppConfigTest, LoadsMultiModelAiConfig) {
  const char* yaml = "/tmp/cf-ai-multi-model.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: false\n"
         "security:\n"
         "  enabled: false\n"
         "ai:\n"
         "  enabled: true\n"
         "  backend: hailo\n"
         "  models:\n"
         "    - id: objects\n"
         "      kind: object_detection\n"
         "      hef_path: /opt/cf/models/yolov8n.hef\n"
         "      output_name: yolov8_nms_postprocess\n"
         "      input:\n"
         "        width: 640\n"
         "        height: 640\n"
         "        format: rgb8\n"
         "        letterbox: true\n"
         "      confidence_threshold: 0.40\n"
         "      labels: coco80\n"
         "    - id: pose\n"
         "      kind: pose\n"
         "      hef_path: /opt/cf/models/yolov8n-pose.hef\n"
         "      output_name: yolov8_pose_postprocess\n"
         "      input:\n"
         "        width: 640\n"
         "        height: 640\n"
         "        format: rgb8\n"
         "        letterbox: true\n"
         "      confidence_threshold: 0.35\n"
         "camera:\n"
         "  ai:\n"
         "    enabled: true\n"
         "    model_ids: [objects, pose]\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_TRUE(cfg.ok()) << cfg.error().message;
  EXPECT_TRUE(cfg.value().ai.enabled);
  EXPECT_EQ(cfg.value().ai.backend, "hailo");
  ASSERT_EQ(cfg.value().ai.models.size(), 2u);
  EXPECT_EQ(cfg.value().ai.models[0].id, "objects");
  EXPECT_EQ(cfg.value().ai.models[0].kind, "object_detection");
  EXPECT_EQ(cfg.value().ai.models[0].hef_path,
            "/opt/cf/models/yolov8n.hef");
  EXPECT_EQ(cfg.value().ai.models[0].output_name,
            "yolov8_nms_postprocess");
  EXPECT_EQ(cfg.value().ai.models[0].input.width, 640u);
  EXPECT_EQ(cfg.value().ai.models[0].input.height, 640u);
  EXPECT_EQ(cfg.value().ai.models[0].input.format, "rgb8");
  EXPECT_TRUE(cfg.value().ai.models[0].input.letterbox);
  EXPECT_FLOAT_EQ(cfg.value().ai.models[0].confidence_threshold, 0.40F);
  EXPECT_EQ(cfg.value().ai.models[0].labels, "coco80");
  EXPECT_EQ(cfg.value().ai.models[1].output_name,
            "yolov8_pose_postprocess");
  EXPECT_TRUE(cfg.value().camera.ai.enabled);
  ASSERT_EQ(cfg.value().camera.ai.model_ids.size(), 2u);
  EXPECT_EQ(cfg.value().camera.ai.model_ids[0], "objects");
  EXPECT_EQ(cfg.value().camera.ai.model_ids[1], "pose");
}

TEST(AppConfigTest, RejectsEnabledAiWithUnsupportedBackend) {
  auto ai = MakeValidAiConfig();
  ai.backend = "onnx";
  camera_firmware::config::CameraConfig camera;

  auto validated =
      camera_firmware::config::ValidateAiConfigSemantics(ai, camera);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_CONFIG_AI_BACKEND");
}

TEST(AppConfigTest, RejectsEnabledCameraAiWithEmptyModelIds) {
  auto ai = MakeValidAiConfig();
  camera_firmware::config::CameraConfig camera;
  camera.ai.enabled = true;

  auto validated =
      camera_firmware::config::ValidateAiConfigSemantics(ai, camera);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_CONFIG_AI_CAMERA_MODEL");
}

TEST(AppConfigTest, RejectsAiModelWithEmptyHefPath) {
  auto ai = MakeValidAiConfig();
  ai.models[0].hef_path.clear();
  camera_firmware::config::CameraConfig camera;

  auto validated =
      camera_firmware::config::ValidateAiConfigSemantics(ai, camera);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_CONFIG_AI_MODEL");
}

TEST(AppConfigTest, RejectsAiModelWithZeroInputDimensions) {
  auto ai = MakeValidAiConfig();
  ai.models[0].input.width = 0;
  camera_firmware::config::CameraConfig camera;

  auto validated =
      camera_firmware::config::ValidateAiConfigSemantics(ai, camera);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_CONFIG_AI_MODEL");
}

TEST(AppConfigTest, RejectsAiModelWithNonRgb8InputFormat) {
  auto ai = MakeValidAiConfig();
  ai.models[0].input.format = "nv12";
  camera_firmware::config::CameraConfig camera;

  auto validated =
      camera_firmware::config::ValidateAiConfigSemantics(ai, camera);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_CONFIG_AI_MODEL");
}

TEST(AppConfigTest, RejectsAiModelWithOutOfRangeConfidenceThreshold) {
  auto ai = MakeValidAiConfig();
  ai.models[0].confidence_threshold = 1.5F;
  camera_firmware::config::CameraConfig camera;

  auto validated =
      camera_firmware::config::ValidateAiConfigSemantics(ai, camera);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_CONFIG_AI_MODEL");
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
         "  tls_private_key_path: /etc/camera-firmware/tls.key\n"
         "security:\n"
         "  enabled: false\n";
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

TEST(AppConfigTest, LoadsExplicitDevelopmentHttpTlsWithoutCertificatePair) {
  const auto config = LoadInlineConfig(R"(
http:
  enabled: true
  public_base_url: https://camera.local:8443
  tls:
    enabled: true
    allow_development_self_signed_tls: true
security:
  enabled: false
secure_rtsp:
  enabled: false
)");

  ASSERT_TRUE(config.ok()) << config.error().message;
  EXPECT_TRUE(config.value().http.tls.enabled);
  EXPECT_TRUE(config.value().http.tls.allow_development_self_signed_tls);
  EXPECT_TRUE(config.value().http.tls.certificate_path.empty());
  EXPECT_TRUE(config.value().http.tls.private_key_path.empty());
}

TEST(AppConfigTest, RejectsCameraAiWhenGlobalAiDisabled) {
  const char* yaml = "/tmp/cf-camera-ai-without-global.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: false\n"
         "ai:\n"
         "  enabled: false\n"
         "camera:\n"
         "  ai:\n"
         "    enabled: true\n"
         "    model_ids: [objects]\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_FALSE(cfg.ok());
  EXPECT_EQ(cfg.error().code, "E_CONFIG_AI_BACKEND");
}

TEST(AppConfigTest, RejectsDuplicateAiModelIds) {
  const char* yaml = "/tmp/cf-ai-duplicate-model.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: false\n"
         "ai:\n"
         "  enabled: true\n"
         "  backend: hailo\n"
         "  models:\n"
         "    - id: objects\n"
         "      kind: object_detection\n"
         "      hef_path: /opt/cf/models/a.hef\n"
         "    - id: objects\n"
         "      kind: pose\n"
         "      hef_path: /opt/cf/models/b.hef\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_FALSE(cfg.ok());
  EXPECT_EQ(cfg.error().code, "E_CONFIG_AI_MODEL_DUPLICATE");
}

TEST(AppConfigTest, RejectsUnsupportedAiModelKind) {
  const char* yaml = "/tmp/cf-ai-unsupported-kind.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: false\n"
         "ai:\n"
         "  enabled: true\n"
         "  backend: hailo\n"
         "  models:\n"
         "    - id: segment\n"
         "      kind: segmentation\n"
         "      hef_path: /opt/cf/models/seg.hef\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_FALSE(cfg.ok());
  EXPECT_EQ(cfg.error().code, "E_CONFIG_AI_MODEL");
}

TEST(AppConfigTest, RejectsUnknownCameraAiModel) {
  const char* yaml = "/tmp/cf-ai-unknown-camera-model.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: false\n"
         "ai:\n"
         "  enabled: true\n"
         "  backend: hailo\n"
         "  models:\n"
         "    - id: objects\n"
         "      kind: object_detection\n"
         "      hef_path: /opt/cf/models/yolov8n.hef\n"
         "camera:\n"
         "  ai:\n"
         "    enabled: true\n"
         "    model_ids: [pose]\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_FALSE(cfg.ok());
  EXPECT_EQ(cfg.error().code, "E_CONFIG_AI_CAMERA_MODEL");
}

TEST(AppConfigTest, RejectsDuplicateCameraAiModelIds) {
  const char* yaml = "/tmp/cf-ai-duplicate-camera-model.yaml";
  std::ofstream out(yaml);
  out << "secure_rtsp:\n"
         "  enabled: false\n"
         "ai:\n"
         "  enabled: true\n"
         "  backend: hailo\n"
         "  models:\n"
         "    - id: objects\n"
         "      kind: object_detection\n"
         "      hef_path: /opt/cf/models/yolov8n.hef\n"
         "camera:\n"
         "  ai:\n"
         "    enabled: true\n"
         "    model_ids: [objects, objects]\n";
  out.close();

  auto cfg = camera_firmware::config::LoadConfigFile(yaml);

  ASSERT_FALSE(cfg.ok());
  EXPECT_EQ(cfg.error().code, "E_CONFIG_AI_CAMERA_MODEL");
}
