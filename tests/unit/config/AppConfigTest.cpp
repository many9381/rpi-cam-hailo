#include "camera_firmware/config/AppConfig.hpp"

#include <fstream>

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

}  // namespace

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
  EXPECT_TRUE(cfg.value().ai.models.empty());
  EXPECT_FALSE(cfg.value().camera.ai.enabled);
  EXPECT_TRUE(cfg.value().camera.ai.model_ids.empty());
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

  EXPECT_TRUE(cfg.value().secure_rtsp.enabled);
  EXPECT_TRUE(cfg.value().secure_rtsp.media_srtp);
  EXPECT_EQ(cfg.value().secure_rtsp.session_key.path,
            "config/dev-srtp-session.hex");
  EXPECT_TRUE(cfg.value().secure_rtsp.session_key.zeroize_on_reload);
}

TEST(AppConfigTest, LoadsMultiModelAiConfig) {
  const char* yaml = "/tmp/cf-ai-multi-model.yaml";
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
  EXPECT_EQ(cfg.value().ai.models[0].input.width, 640u);
  EXPECT_EQ(cfg.value().ai.models[0].input.height, 640u);
  EXPECT_EQ(cfg.value().ai.models[0].input.format, "rgb8");
  EXPECT_TRUE(cfg.value().ai.models[0].input.letterbox);
  EXPECT_FLOAT_EQ(cfg.value().ai.models[0].confidence_threshold, 0.40F);
  EXPECT_EQ(cfg.value().ai.models[0].labels, "coco80");
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
