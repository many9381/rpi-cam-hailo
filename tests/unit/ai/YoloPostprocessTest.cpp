#include "camera_firmware/ai/YoloPostprocess.hpp"

#include <limits>
#include <vector>

#include <gtest/gtest.h>

TEST(YoloPostprocessTest, ParsesHailoNmsByClassDetections) {
  std::vector<float> buffer;
  buffer.push_back(1.0F);
  buffer.insert(buffer.end(), {0.10F, 0.20F, 0.50F, 0.60F, 0.90F});
  buffer.insert(buffer.end(), 5, 0.0F);
  buffer.push_back(0.0F);
  buffer.insert(buffer.end(), 10, 0.0F);
  buffer.push_back(2.0F);
  buffer.insert(buffer.end(), {0.30F, 0.40F, 0.70F, 0.80F, 0.85F});
  buffer.insert(buffer.end(), {0.10F, 0.10F, 0.20F, 0.20F, 0.30F});

  const auto detections =
      camera_firmware::ai::ParseYoloHailoNms(buffer.data(),
                                             buffer.size(),
                                             3,
                                             2,
                                             0.50F);

  ASSERT_EQ(detections.size(), 2U);
  EXPECT_EQ(detections[0].label, "person");
  EXPECT_NEAR(detections[0].confidence, 0.90F, 1e-6F);
  EXPECT_NEAR(detections[0].box.x, 0.20F, 1e-6F);
  EXPECT_NEAR(detections[0].box.y, 0.10F, 1e-6F);
  EXPECT_NEAR(detections[0].box.width, 0.40F, 1e-6F);
  EXPECT_NEAR(detections[0].box.height, 0.40F, 1e-6F);
  EXPECT_EQ(detections[1].label, "car");
  EXPECT_NEAR(detections[1].confidence, 0.85F, 1e-6F);
}

TEST(YoloPostprocessTest, ReturnsEmptyForNullOrTruncatedBuffers) {
  EXPECT_TRUE(camera_firmware::ai::ParseYoloHailoNms(nullptr, 0, 80, 100, 0.4F)
                  .empty());

  const std::vector<float> truncated = {1.0F, 0.1F, 0.2F};
  EXPECT_TRUE(camera_firmware::ai::ParseYoloHailoNms(truncated.data(),
                                                    truncated.size(),
                                                    1,
                                                    1,
                                                    0.4F)
                  .empty());
}

TEST(YoloPostprocessTest, SkipsNonFiniteOrInvertedBoxes) {
  std::vector<float> buffer;
  buffer.push_back(3.0F);
  buffer.insert(buffer.end(),
                {std::numeric_limits<float>::quiet_NaN(),
                 0.20F,
                 0.50F,
                 0.60F,
                 0.90F});
  buffer.insert(buffer.end(), {0.30F, 0.80F, 0.70F, 0.40F, 0.85F});
  buffer.insert(buffer.end(), {0.30F, 0.40F, 0.30F, 0.80F, 0.95F});

  EXPECT_TRUE(camera_firmware::ai::ParseYoloHailoNms(buffer.data(),
                                                    buffer.size(),
                                                    1,
                                                    3,
                                                    0.50F)
                  .empty());
}

TEST(YoloPostprocessTest, ClampsLargeFiniteCountsBeforeIntConversion) {
  std::vector<float> buffer;
  buffer.push_back(std::numeric_limits<float>::max());
  buffer.insert(buffer.end(), {0.10F, 0.20F, 0.50F, 0.60F, 0.90F});
  buffer.insert(buffer.end(), {0.20F, 0.30F, 0.60F, 0.70F, 0.80F});

  const auto detections =
      camera_firmware::ai::ParseYoloHailoNms(buffer.data(),
                                             buffer.size(),
                                             1,
                                             2,
                                             0.50F);

  ASSERT_EQ(detections.size(), 2U);
  EXPECT_EQ(detections[0].label, "person");
  EXPECT_EQ(detections[1].label, "person");
}

TEST(YoloPostprocessTest, ParsesYoloPoseRowsWithCoco17Keypoints) {
  constexpr std::size_t kPoseRowFloats = 5U + (17U * 3U);
  std::vector<float> row(kPoseRowFloats, 0.0F);
  row[0] = 0.10F;
  row[1] = 0.20F;
  row[2] = 0.70F;
  row[3] = 0.80F;
  row[4] = 0.92F;
  row[5] = 0.45F;
  row[6] = 0.25F;
  row[7] = 0.95F;
  const std::size_t left_shoulder = 5U + (5U * 3U);
  row[left_shoulder] = 0.34F;
  row[left_shoulder + 1U] = 0.52F;
  row[left_shoulder + 2U] = 0.81F;
  const std::size_t right_shoulder = 5U + (6U * 3U);
  row[right_shoulder] = 0.66F;
  row[right_shoulder + 1U] = 0.53F;
  row[right_shoulder + 2U] = 0.20F;

  const auto detections =
      camera_firmware::ai::ParseYoloPoseRows(row.data(),
                                             row.size(),
                                             0.50F,
                                             0.50F);

  ASSERT_EQ(detections.size(), 1U);
  EXPECT_EQ(detections[0].label, "person");
  EXPECT_FLOAT_EQ(detections[0].confidence, 0.92F);
  EXPECT_FLOAT_EQ(detections[0].box.x, 0.10F);
  EXPECT_FLOAT_EQ(detections[0].box.y, 0.20F);
  EXPECT_FLOAT_EQ(detections[0].box.width, 0.60F);
  EXPECT_FLOAT_EQ(detections[0].box.height, 0.60F);
  ASSERT_EQ(detections[0].keypoints.size(), 2U);
  EXPECT_EQ(detections[0].keypoints[0].name, "nose");
  EXPECT_FLOAT_EQ(detections[0].keypoints[0].x, 0.45F);
  EXPECT_FLOAT_EQ(detections[0].keypoints[0].y, 0.25F);
  EXPECT_FLOAT_EQ(detections[0].keypoints[0].confidence, 0.95F);
  EXPECT_EQ(detections[0].keypoints[1].name, "left_shoulder");
  EXPECT_FLOAT_EQ(detections[0].keypoints[1].x, 0.34F);
  EXPECT_FLOAT_EQ(detections[0].keypoints[1].y, 0.52F);
  EXPECT_FLOAT_EQ(detections[0].keypoints[1].confidence, 0.81F);
}

TEST(YoloPostprocessTest, RejectsMalformedYoloPoseRows) {
  const std::vector<float> truncated = {0.1F, 0.2F, 0.3F};
  EXPECT_TRUE(camera_firmware::ai::ParseYoloPoseRows(truncated.data(),
                                                    truncated.size(),
                                                    0.50F,
                                                    0.50F)
                  .empty());

  constexpr std::size_t kPoseRowFloats = 5U + (17U * 3U);
  std::vector<float> inverted(kPoseRowFloats, 0.0F);
  inverted[0] = 0.70F;
  inverted[1] = 0.20F;
  inverted[2] = 0.10F;
  inverted[3] = 0.80F;
  inverted[4] = 0.92F;
  EXPECT_TRUE(camera_firmware::ai::ParseYoloPoseRows(inverted.data(),
                                                    inverted.size(),
                                                    0.50F,
                                                    0.50F)
                  .empty());
}
