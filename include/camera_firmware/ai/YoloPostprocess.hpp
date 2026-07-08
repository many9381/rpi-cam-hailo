#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "camera_firmware/ai/AiTypes.hpp"

namespace camera_firmware::ai {

[[nodiscard]] const std::vector<std::string>& Coco80Labels();

[[nodiscard]] std::vector<Detection> ParseYoloHailoNms(
    const float* tensor,
    std::size_t total_floats,
    int num_classes,
    int max_bboxes_per_class,
    float confidence_threshold);

}  // namespace camera_firmware::ai
