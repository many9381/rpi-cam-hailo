#include "camera_firmware/media/LoresGeometry.hpp"

#include <gtest/gtest.h>

#include "camera_firmware/config/AppConfig.hpp"

namespace {

using camera_firmware::media::ComputeLoresSize;
using camera_firmware::media::ResolveAiLoresWidth;

TEST(LoresGeometryTest, ScalesModelWidthToSensorAspect) {
  const auto lores = ComputeLoresSize(1920U, 1080U, 640U);
  EXPECT_EQ(lores.width, 640U);
  EXPECT_EQ(lores.height, 360U);
}

TEST(LoresGeometryTest, PreservesFourThreeAspect) {
  const auto lores = ComputeLoresSize(1280U, 960U, 640U);
  EXPECT_EQ(lores.width, 640U);
  EXPECT_EQ(lores.height, 480U);
}

TEST(LoresGeometryTest, FloorsBothDimensionsToEven) {
  // 641 -> 640; height 640*1083/1920 = 361 -> 360.
  const auto lores = ComputeLoresSize(1920U, 1083U, 641U);
  EXPECT_EQ(lores.width % 2U, 0U);
  EXPECT_EQ(lores.height % 2U, 0U);
  EXPECT_EQ(lores.width, 640U);
  EXPECT_EQ(lores.height, 360U);
}

TEST(LoresGeometryTest, ReturnsZeroForZeroInput) {
  EXPECT_EQ(ComputeLoresSize(0U, 1080U, 640U).width, 0U);
  EXPECT_EQ(ComputeLoresSize(0U, 1080U, 640U).height, 0U);
  EXPECT_EQ(ComputeLoresSize(1920U, 1080U, 0U).width, 0U);
  EXPECT_EQ(ComputeLoresSize(1920U, 1080U, 0U).height, 0U);
  EXPECT_EQ(ComputeLoresSize(1920U, 0U, 640U).width, 0U);
  EXPECT_EQ(ComputeLoresSize(1920U, 0U, 640U).height, 0U);
}

TEST(LoresGeometryTest, ResolvesLargestActiveModelWidth) {
  camera_firmware::config::AppConfig config;
  config.camera.ai.enabled = true;
  config.camera.ai.model_ids = {"faces", "objects"};
  camera_firmware::config::AiModelConfig faces;
  faces.id = "faces";
  faces.input.width = 416U;
  camera_firmware::config::AiModelConfig objects;
  objects.id = "objects";
  objects.input.width = 640U;
  config.ai.models = {faces, objects};

  EXPECT_EQ(ResolveAiLoresWidth(config), 640U);
}

TEST(LoresGeometryTest, ReturnsZeroWhenCameraAiDisabled) {
  camera_firmware::config::AppConfig config;
  config.camera.ai.enabled = false;
  config.camera.ai.model_ids = {"objects"};
  camera_firmware::config::AiModelConfig objects;
  objects.id = "objects";
  objects.input.width = 640U;
  config.ai.models = {objects};

  EXPECT_EQ(ResolveAiLoresWidth(config), 0U);
}

TEST(LoresGeometryTest, ReturnsZeroWhenNoModelMatchesId) {
  camera_firmware::config::AppConfig config;
  config.camera.ai.enabled = true;
  config.camera.ai.model_ids = {"missing"};
  camera_firmware::config::AiModelConfig objects;
  objects.id = "objects";
  objects.input.width = 640U;
  config.ai.models = {objects};

  EXPECT_EQ(ResolveAiLoresWidth(config), 0U);
}

TEST(LoresGeometryTest, ClampsWidthToSensorWidth) {
  // Model input width (640) exceeds sensor width (320), so width clamps to 320.
  const auto lores = ComputeLoresSize(320U, 240U, 640U);
  EXPECT_EQ(lores.width, 320U);
  EXPECT_EQ(lores.height, 240U);
}

}  // namespace
