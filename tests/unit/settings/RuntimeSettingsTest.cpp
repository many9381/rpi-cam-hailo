#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/settings/RuntimeSettings.hpp"

#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace {

using camera_firmware::config::AiModelConfig;
using camera_firmware::config::AppConfig;
using camera_firmware::settings::CameraProfileCatalog;
using camera_firmware::settings::ModelRuntimeSettings;
using camera_firmware::settings::OsdItemRuntimeSettings;
using camera_firmware::settings::RuntimeSettings;

AiModelConfig MakeModel(std::string id, float confidence_threshold) {
  AiModelConfig model;
  model.id = std::move(id);
  model.kind = "object_detection";
  model.hef_path = "/opt/camera-firmware/models/model.hef";
  model.confidence_threshold = confidence_threshold;
  return model;
}

AppConfig MakeBaseConfig() {
  AppConfig base;
  base.secure_rtsp.enabled = false;
  base.security.enabled = false;
  base.ai.enabled = true;
  base.ai.backend = "hailo";
  base.ai.models = {MakeModel("objects", 0.40F), MakeModel("pose", 0.35F)};
  base.camera.ai.enabled = true;
  base.camera.ai.model_ids = {"objects", "pose"};
  return base;
}

RuntimeSettings MakeRuntimeSettings() {
  RuntimeSettings settings;
  settings.camera.profile_id = "imx708-1080p30";
  settings.camera.bitrate_kbps = 8000U;
  settings.camera.gop = 30U;
  settings.sub_stream = {false, 640U, 360U, 15U, 1000U};
  settings.models = {{"objects", true, 0.55F}, {"pose", false, 0.25F}};
  return settings;
}

}  // namespace

TEST(RuntimeSettingsTest, DeriveCopiesSubStreamFromBaseConfig) {
  auto base = MakeBaseConfig();
  base.camera.sub_stream.enabled = true;
  base.camera.sub_stream.width = 640U;
  base.camera.sub_stream.height = 360U;
  base.camera.sub_stream.fps = 15U;
  base.camera.sub_stream.bitrate_kbps = 1000U;
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();

  const auto settings =
      camera_firmware::settings::DeriveRuntimeSettings(base, catalog);

  ASSERT_TRUE(settings.ok()) << settings.error().message;
  EXPECT_TRUE(settings.value().sub_stream.enabled);
  EXPECT_EQ(settings.value().sub_stream.width, 640U);
  EXPECT_EQ(settings.value().sub_stream.height, 360U);
  EXPECT_EQ(settings.value().sub_stream.fps, 15U);
  EXPECT_EQ(settings.value().sub_stream.bitrate_kbps, 1000U);
}

TEST(RuntimeSettingsTest, BuildEffectiveConfigMapsSubStream) {
  auto base = MakeBaseConfig();
  base.camera.sub_stream.gop = 30U;
  base.camera.sub_stream.mount = "/imx708/sub";
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.sub_stream = {true, 854U, 480U, 25U, 2000U};

  const auto effective =
      camera_firmware::settings::BuildEffectiveConfig(base, settings, catalog);

  ASSERT_TRUE(effective.ok()) << effective.error().message;
  const auto& sub = effective.value().camera.sub_stream;
  EXPECT_TRUE(sub.enabled);
  EXPECT_EQ(sub.width, 854U);
  EXPECT_EQ(sub.height, 480U);
  EXPECT_EQ(sub.fps, 25U);
  EXPECT_EQ(sub.bitrate_kbps, 2000U);
  EXPECT_EQ(sub.gop, 30U);
  EXPECT_EQ(sub.mount, "/imx708/sub");
}

TEST(RuntimeSettingsTest, ValidateRejectsBadSubStreamWhenEnabled) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();

  auto ok = MakeRuntimeSettings();
  ok.sub_stream = {true, 640U, 360U, 15U, 1000U};
  EXPECT_TRUE(
      camera_firmware::settings::ValidateRuntimeSettings(ok, base, catalog)
          .ok());

  auto bad_resolution = ok;
  bad_resolution.sub_stream.width = 999U;
  bad_resolution.sub_stream.height = 561U;
  auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      bad_resolution, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_SUB_RESOLUTION");

  auto bad_fps = ok;
  bad_fps.sub_stream.fps = 60U;
  validated =
      camera_firmware::settings::ValidateRuntimeSettings(bad_fps, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_SUB_FPS");

  auto bad_bitrate = ok;
  bad_bitrate.sub_stream.bitrate_kbps = 100U;
  validated = camera_firmware::settings::ValidateRuntimeSettings(
      bad_bitrate, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_SUB_BITRATE");

  auto disabled = ok;
  disabled.sub_stream = {false, 1U, 1U, 1U, 1U};
  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  disabled, base, catalog)
                  .ok());
}

TEST(RuntimeSettingsTest, ValidateRejectsZeroSubStreamGeometryRegardlessOfEnabled) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();

  // A DISABLED sub-stream with any zero geometry field must be rejected: the web
  // client rejects zero geometry unconditionally, so a persisted zero would brick
  // the settings UI. This must hold with enabled=false (the DoS vector).
  for (const auto zeroed : std::vector<camera_firmware::settings::SubStreamRuntimeSettings>{
           {false, 0U, 360U, 15U, 1000U},
           {false, 640U, 0U, 15U, 1000U},
           {false, 640U, 360U, 0U, 1000U},
           {false, 640U, 360U, 15U, 0U}}) {
    auto settings = MakeRuntimeSettings();
    settings.sub_stream = zeroed;
    const auto validated =
        camera_firmware::settings::ValidateRuntimeSettings(settings, base, catalog);
    ASSERT_FALSE(validated.ok())
        << "zero field: " << zeroed.width << "x" << zeroed.height << "@"
        << zeroed.fps << " " << zeroed.bitrate_kbps;
    EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_SUB_GEOMETRY");
  }

  // Enabled + zero must also be rejected as geometry (before the allowlist check).
  auto enabled_zero = MakeRuntimeSettings();
  enabled_zero.sub_stream = {true, 0U, 0U, 0U, 0U};
  const auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      enabled_zero, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_SUB_GEOMETRY");
}

TEST(RuntimeSettingsTest, ValidateBypassesAllowlistForDisabledNonZeroSubStream) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();

  // Disabled + non-zero but off-allowlist geometry still passes: the allowlist /
  // fps-range / bitrate-range checks remain enabled-only. Only the non-zero
  // invariant is enforced regardless of `enabled`.
  settings.sub_stream = {false, 800U, 600U, 20U, 1200U};
  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  settings, base, catalog)
                  .ok());
}

TEST(RuntimeSettingsTest, ValidateAcceptsSubStreamFpsInclusiveBoundaries) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.sub_stream = {true, 640U, 360U, 5U, 1000U};

  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  settings, base, catalog)
                  .ok());

  settings.sub_stream.fps = 30U;
  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  settings, base, catalog)
                  .ok());
}

TEST(RuntimeSettingsTest, ValidateRejectsSubStreamFpsJustOutsideBoundaries) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.sub_stream = {true, 640U, 360U, 4U, 1000U};

  auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_SUB_FPS");

  settings.sub_stream.fps = 31U;
  validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_SUB_FPS");
}

TEST(RuntimeSettingsTest, ValidateAcceptsSubStreamBitrateInclusiveBoundaries) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.sub_stream = {true, 640U, 360U, 15U, 500U};

  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  settings, base, catalog)
                  .ok());

  settings.sub_stream.bitrate_kbps = 20000U;
  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  settings, base, catalog)
                  .ok());
}

TEST(RuntimeSettingsTest,
     ValidateRejectsSubStreamBitrateJustOutsideBoundaries) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.sub_stream = {true, 640U, 360U, 15U, 499U};

  auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_SUB_BITRATE");

  settings.sub_stream.bitrate_kbps = 20001U;
  validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_SUB_BITRATE");
}

TEST(RuntimeSettingsTest, ValidateAcceptsAllAllowlistedSubStreamResolutions) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();

  settings.sub_stream = {true, 640U, 360U, 15U, 1000U};
  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  settings, base, catalog)
                  .ok());

  settings.sub_stream = {true, 854U, 480U, 15U, 1000U};
  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  settings, base, catalog)
                  .ok());

  settings.sub_stream = {true, 1280U, 720U, 15U, 1000U};
  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  settings, base, catalog)
                  .ok());
}

TEST(RuntimeSettingsTest, ValidateRejectsNearMissSubStreamResolutions) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();

  settings.sub_stream = {true, 640U, 361U, 15U, 1000U};
  auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_SUB_RESOLUTION");

  settings.sub_stream = {true, 641U, 360U, 15U, 1000U};
  validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_SUB_RESOLUTION");
}

TEST(RuntimeSettingsTest, ValidateAcceptsDefaultEmptyOsd) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  const auto settings = MakeRuntimeSettings();

  // MakeRuntimeSettings() never touches `.osd`, so it is left at the struct
  // default (disabled, no items). That default must validate.
  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  settings, base, catalog)
                  .ok());
}

TEST(RuntimeSettingsTest, ValidateAcceptsEightOsdItemsRejectsNine) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.osd.enabled = true;

  settings.osd.items = std::vector<OsdItemRuntimeSettings>(
      8U, OsdItemRuntimeSettings{"timestamp", "", "top_left"});
  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  settings, base, catalog)
                  .ok());

  settings.osd.items.push_back({"timestamp", "", "top_left"});
  ASSERT_EQ(settings.osd.items.size(), 9U);
  const auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_SETTINGS_OSD");
}

TEST(RuntimeSettingsTest, ValidateRejectsCustomTextOsdItemWithEmptyText) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.osd.enabled = true;
  settings.osd.items = {{"custom_text", "", "top_left"}};

  const auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_SETTINGS_OSD");
}

TEST(RuntimeSettingsTest, ValidateRejectsUnknownOsdItemType) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.osd.enabled = true;
  settings.osd.items = {{"bogus_type", "", "top_left"}};

  const auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_SETTINGS_OSD");
}

TEST(RuntimeSettingsTest, ValidateRejectsUnknownOsdItemPosition) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.osd.enabled = true;
  settings.osd.items = {{"timestamp", "", "middle_center"}};

  const auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_SETTINGS_OSD");
}

TEST(RuntimeSettingsTest, ValidateAcceptsOsdTextAtByteLimitRejectsOverLimit) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.osd.enabled = true;
  settings.osd.items = {{"custom_text", std::string(64U, 'a'), "top_left"}};

  EXPECT_TRUE(camera_firmware::settings::ValidateRuntimeSettings(
                  settings, base, catalog)
                  .ok());

  settings.osd.items[0].text = std::string(65U, 'a');
  const auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_SETTINGS_OSD");
}

TEST(RuntimeSettingsTest, ValidateRejectsOsdTextWithControlCharacter) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.osd.enabled = true;
  settings.osd.items = {{"timestamp", "\x01", "top_left"}};

  const auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_SETTINGS_OSD");
}

TEST(RuntimeSettingsTest, ValidateRejectsInvalidOsdItemsEvenWhenDisabled) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();

  // osd.enabled == false must NOT bypass item validation: an invalid item
  // persisted while disabled would otherwise brick the settings UI the moment
  // OSD is later turned on (the same unconditional-validation seam sub_stream
  // already closed for zero geometry).
  settings.osd.enabled = false;
  settings.osd.items = {{"custom_text", "", "top_left"}};

  const auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_SETTINGS_OSD");
}

TEST(RuntimeSettingsTest, CatalogExposesApprovedRpi5Imx708Profiles) {
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  const auto profiles = catalog.Profiles();

  ASSERT_EQ(profiles.size(), 3U);
  EXPECT_EQ(profiles[0].id, "imx708-1080p50");
  EXPECT_EQ(profiles[0].width, 1920U);
  EXPECT_EQ(profiles[0].height, 1080U);
  EXPECT_EQ(profiles[0].fps, 50U);
  EXPECT_EQ(profiles[1].id, "imx708-1080p30");
  EXPECT_EQ(profiles[1].width, 1920U);
  EXPECT_EQ(profiles[1].height, 1080U);
  EXPECT_EQ(profiles[1].fps, 30U);
  EXPECT_EQ(profiles[2].id, "imx708-720p50");
  EXPECT_EQ(profiles[2].width, 1280U);
  EXPECT_EQ(profiles[2].height, 720U);
  EXPECT_EQ(profiles[2].fps, 50U);
}

TEST(RuntimeSettingsTest, DerivesManagedSettingsFromMatchingBaseConfig) {
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  const auto settings =
      camera_firmware::settings::DeriveRuntimeSettings(MakeBaseConfig(), catalog);

  ASSERT_TRUE(settings.ok()) << settings.error().message;
  EXPECT_EQ(settings.value().camera.profile_id, "imx708-1080p50");
  EXPECT_EQ(settings.value().camera.bitrate_kbps, 6000U);
  EXPECT_EQ(settings.value().camera.gop, 25U);
  ASSERT_EQ(settings.value().models.size(), 2U);
  EXPECT_EQ(settings.value().models[0].id, "objects");
  EXPECT_TRUE(settings.value().models[0].enabled);
  EXPECT_FLOAT_EQ(settings.value().models[0].confidence_threshold, 0.40F);
  EXPECT_EQ(settings.value().models[1].id, "pose");
  EXPECT_TRUE(settings.value().models[1].enabled);
  EXPECT_FLOAT_EQ(settings.value().models[1].confidence_threshold, 0.35F);
}

TEST(RuntimeSettingsTest, RejectsUnsupportedBaseCaptureMode) {
  auto base = MakeBaseConfig();
  base.camera.video.fps = 60U;
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();

  const auto settings =
      camera_firmware::settings::DeriveRuntimeSettings(base, catalog);

  ASSERT_FALSE(settings.ok());
  EXPECT_EQ(settings.error().code, "E_RUNTIME_SETTINGS_CAPTURE_MODE");
}

TEST(RuntimeSettingsTest, RejectsCameraValuesOutsideApprovedRanges) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();

  settings.camera.bitrate_kbps = 499U;
  auto validated =
      camera_firmware::settings::ValidateRuntimeSettings(settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_BITRATE");

  settings.camera.bitrate_kbps = 20001U;
  validated =
      camera_firmware::settings::ValidateRuntimeSettings(settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_BITRATE");

  settings.camera.bitrate_kbps = 8000U;
  settings.camera.gop = 0U;
  validated =
      camera_firmware::settings::ValidateRuntimeSettings(settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_GOP");

  settings.camera.gop = 301U;
  validated =
      camera_firmware::settings::ValidateRuntimeSettings(settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_GOP");
}

TEST(RuntimeSettingsTest, RejectsDuplicateMissingAndUnknownModelIds) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();

  settings.models[1].id = "objects";
  auto validated =
      camera_firmware::settings::ValidateRuntimeSettings(settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_MODEL_DUPLICATE");

  settings = MakeRuntimeSettings();
  settings.models.pop_back();
  validated =
      camera_firmware::settings::ValidateRuntimeSettings(settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_MODEL_MISSING");

  settings = MakeRuntimeSettings();
  settings.models[1].id = "unknown";
  validated =
      camera_firmware::settings::ValidateRuntimeSettings(settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_MODEL_UNKNOWN");
}

TEST(RuntimeSettingsTest, RejectsModelsOutsideBaseYamlOrder) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();

  std::swap(settings.models[0], settings.models[1]);
  const auto validated =
      camera_firmware::settings::ValidateRuntimeSettings(settings, base, catalog);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_MODEL_ORDER");
}

TEST(RuntimeSettingsTest, RejectsEnabledModelWhenBaseGlobalAiIsDisabled) {
  auto base = MakeBaseConfig();
  base.ai.enabled = false;
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();

  const auto validated = camera_firmware::settings::ValidateRuntimeSettings(
      MakeRuntimeSettings(), base, catalog);

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_AI_DISABLED");
}

TEST(RuntimeSettingsTest, RejectsNonFiniteAndOutOfRangeConfidenceThresholds) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();

  settings.models[0].confidence_threshold =
      std::numeric_limits<float>::quiet_NaN();
  auto validated =
      camera_firmware::settings::ValidateRuntimeSettings(settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_MODEL_THRESHOLD");

  settings.models[0].confidence_threshold = 1.01F;
  validated =
      camera_firmware::settings::ValidateRuntimeSettings(settings, base, catalog);
  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_RUNTIME_SETTINGS_MODEL_THRESHOLD");
}

TEST(RuntimeSettingsTest, DisablingEveryModelDisablesCameraInference) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.models[0].enabled = false;

  const auto effective =
      camera_firmware::settings::BuildEffectiveConfig(base, settings, catalog);

  ASSERT_TRUE(effective.ok()) << effective.error().message;
  EXPECT_EQ(effective.value().ai.enabled, base.ai.enabled);
  EXPECT_FALSE(effective.value().camera.ai.enabled);
  EXPECT_TRUE(effective.value().camera.ai.model_ids.empty());
}

TEST(RuntimeSettingsTest, BuildsEffectiveConfigWithoutChangingUnmanagedFields) {
  auto base = MakeBaseConfig();
  base.platform.target = "test-platform";
  base.camera.id = "test-camera";
  base.camera.source.backend = "test-source";
  base.camera.source.camera_index = 3U;
  base.camera.video.format = "test-format";
  base.camera.encoder.backend = "test-encoder";
  base.camera.encoder.preset = "test-preset";
  base.http.bind_ip = "127.0.0.2";
  base.secure_rtsp.mount = "/test-mount";
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();

  const auto effective = camera_firmware::settings::BuildEffectiveConfig(
      base, MakeRuntimeSettings(), catalog);

  ASSERT_TRUE(effective.ok()) << effective.error().message;
  EXPECT_EQ(effective.value().camera.video.width, 1920U);
  EXPECT_EQ(effective.value().camera.video.height, 1080U);
  EXPECT_EQ(effective.value().camera.video.fps, 30U);
  EXPECT_EQ(effective.value().camera.encoder.bitrate_kbps, 8000U);
  EXPECT_EQ(effective.value().camera.encoder.gop, 30U);
  EXPECT_TRUE(effective.value().ai.enabled);
  EXPECT_TRUE(effective.value().camera.ai.enabled);
  EXPECT_EQ(effective.value().camera.ai.model_ids,
            std::vector<std::string>({"objects"}));
  EXPECT_FLOAT_EQ(effective.value().ai.models[0].confidence_threshold, 0.55F);
  EXPECT_FLOAT_EQ(effective.value().ai.models[1].confidence_threshold, 0.25F);
  EXPECT_EQ(effective.value().platform.target, base.platform.target);
  EXPECT_EQ(effective.value().camera.id, base.camera.id);
  EXPECT_EQ(effective.value().camera.source.backend, base.camera.source.backend);
  EXPECT_EQ(effective.value().camera.source.camera_index,
            base.camera.source.camera_index);
  EXPECT_EQ(effective.value().camera.video.format, base.camera.video.format);
  EXPECT_EQ(effective.value().camera.encoder.backend,
            base.camera.encoder.backend);
  EXPECT_EQ(effective.value().camera.encoder.preset, base.camera.encoder.preset);
  EXPECT_EQ(effective.value().http.bind_ip, base.http.bind_ip);
  EXPECT_EQ(effective.value().secure_rtsp.mount, base.secure_rtsp.mount);
  EXPECT_EQ(effective.value().ai.models[0].hef_path, base.ai.models[0].hef_path);
  EXPECT_EQ(effective.value().ai.models[1].kind, base.ai.models[1].kind);
}

TEST(RuntimeSettingsTest, BuildEffectiveConfigMapsOsd) {
  const auto base = MakeBaseConfig();
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  auto settings = MakeRuntimeSettings();
  settings.osd.enabled = true;
  settings.osd.items = {
      OsdItemRuntimeSettings{"timestamp", "", "top_left"},
      OsdItemRuntimeSettings{"camera_name", "", "top_right"},
      OsdItemRuntimeSettings{"custom_text", "Front door", "bottom_right"},
  };
  const auto effective =
      camera_firmware::settings::BuildEffectiveConfig(base, settings, catalog);
  ASSERT_TRUE(effective.ok()) << effective.error().message;
  const auto& osd = effective.value().camera.osd;
  EXPECT_TRUE(osd.enabled);
  ASSERT_EQ(osd.items.size(), 3U);
  EXPECT_EQ(osd.items[0].type, "timestamp");
  EXPECT_EQ(osd.items[0].position, "top_left");
  EXPECT_EQ(osd.items[1].type, "camera_name");
  EXPECT_EQ(osd.items[1].position, "top_right");
  EXPECT_EQ(osd.items[2].type, "custom_text");
  EXPECT_EQ(osd.items[2].text, "Front door");
  EXPECT_EQ(osd.items[2].position, "bottom_right");
}

TEST(RuntimeSettingsTest, BuildEffectiveConfigClearsStaleBaseOsdItems) {
  auto base = MakeBaseConfig();
  base.camera.osd.enabled = true;
  base.camera.osd.items = {{"custom_text", "stale", "top_left"}};
  const auto catalog = CameraProfileCatalog::Rpi5Imx708();
  const auto settings = MakeRuntimeSettings();  // osd default: disabled, empty
  const auto effective =
      camera_firmware::settings::BuildEffectiveConfig(base, settings, catalog);
  ASSERT_TRUE(effective.ok()) << effective.error().message;
  EXPECT_FALSE(effective.value().camera.osd.enabled);
  EXPECT_TRUE(effective.value().camera.osd.items.empty());
}
