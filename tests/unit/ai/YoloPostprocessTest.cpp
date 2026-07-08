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
