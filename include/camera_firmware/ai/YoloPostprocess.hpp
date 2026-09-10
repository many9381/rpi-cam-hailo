#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "camera_firmware/ai/AiTypes.hpp"

namespace camera_firmware::ai {

inline constexpr std::size_t kCoco17PoseKeypointCount = 17U;
inline constexpr std::size_t kYoloPoseBoxScoreFloatCount = 5U;
inline constexpr std::size_t kYoloPoseFloatsPerKeypoint = 3U;
inline constexpr std::size_t kYoloPoseRowFloatCount =
    kYoloPoseBoxScoreFloatCount +
    (kCoco17PoseKeypointCount * kYoloPoseFloatsPerKeypoint);

[[nodiscard]] const std::vector<std::string>& Coco80Labels();

[[nodiscard]] const std::vector<std::string>& Coco17PoseKeypointNames();

[[nodiscard]] std::vector<Detection> ParseYoloHailoNms(
    const float* tensor, std::size_t total_floats, int num_classes,
    int max_bboxes_per_class, float confidence_threshold);

[[nodiscard]] std::vector<Detection> ParseYoloPoseRows(
    const float* tensor, std::size_t total_floats, float confidence_threshold,
    float keypoint_confidence_threshold);

}  // namespace camera_firmware::ai
