#include "camera_firmware/ai/YoloPostprocess.hpp"

#include <cmath>
#include <string>
#include <utility>
#include <vector>

namespace camera_firmware::ai {

const std::vector<std::string>& Coco80Labels() {
  static const std::vector<std::string> kLabels = {
      "person",      "bicycle",      "car",           "motorcycle",
      "airplane",    "bus",          "train",         "truck",
      "boat",        "traffic light", "fire hydrant",  "stop sign",
      "parking meter", "bench",       "bird",          "cat",
      "dog",         "horse",        "sheep",         "cow",
      "elephant",    "bear",         "zebra",         "giraffe",
      "backpack",    "umbrella",     "handbag",       "tie",
      "suitcase",    "frisbee",      "skis",          "snowboard",
      "sports ball", "kite",         "baseball bat",  "baseball glove",
      "skateboard",  "surfboard",    "tennis racket", "bottle",
      "wine glass",  "cup",          "fork",          "knife",
      "spoon",       "bowl",         "banana",        "apple",
      "sandwich",    "orange",       "broccoli",      "carrot",
      "hot dog",     "pizza",        "donut",         "cake",
      "chair",       "couch",        "potted plant",  "bed",
      "dining table", "toilet",      "tv",            "laptop",
      "mouse",       "remote",       "keyboard",      "cell phone",
      "microwave",   "oven",         "toaster",       "sink",
      "refrigerator", "book",        "clock",         "vase",
      "scissors",    "teddy bear",   "hair drier",    "toothbrush"};
  return kLabels;
}

std::vector<Detection> ParseYoloHailoNms(const float* tensor,
                                         std::size_t total_floats,
                                         int num_classes,
                                         int max_bboxes_per_class,
                                         float confidence_threshold) {
  std::vector<Detection> detections;
  if (tensor == nullptr || total_floats == 0U || num_classes <= 0 ||
      max_bboxes_per_class <= 0) {
    return detections;
  }

  const auto& labels = Coco80Labels();
  std::size_t offset = 0;
  for (int class_index = 0; class_index < num_classes; ++class_index) {
    if (offset >= total_floats) {
      return {};
    }

    float raw_count = tensor[offset++];
    if (!std::isfinite(raw_count)) {
      return {};
    }
    int count = 0;
    if (raw_count > 0.0F) {
      count = raw_count >= static_cast<float>(max_bboxes_per_class)
                  ? max_bboxes_per_class
                  : static_cast<int>(raw_count);
    }

    for (int box_index = 0; box_index < max_bboxes_per_class; ++box_index) {
      if (offset + 5U > total_floats) {
        return {};
      }

      const float y_min = tensor[offset];
      const float x_min = tensor[offset + 1U];
      const float y_max = tensor[offset + 2U];
      const float x_max = tensor[offset + 3U];
      const float score = tensor[offset + 4U];
      offset += 5U;

      if (box_index >= count || !std::isfinite(y_min) ||
          !std::isfinite(x_min) || !std::isfinite(y_max) ||
          !std::isfinite(x_max) || !std::isfinite(score) ||
          score < confidence_threshold || x_max <= x_min || y_max <= y_min) {
        continue;
      }

      Detection detection;
      detection.label = class_index < static_cast<int>(labels.size())
                            ? labels[static_cast<std::size_t>(class_index)]
                            : "unknown";
      detection.confidence = score;
      detection.box.x = x_min;
      detection.box.y = y_min;
      detection.box.width = x_max - x_min;
      detection.box.height = y_max - y_min;
      detections.push_back(std::move(detection));
    }
  }

  return detections;
}

}  // namespace camera_firmware::ai
