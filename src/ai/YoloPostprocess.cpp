#include "camera_firmware/ai/YoloPostprocess.hpp"

#include <cmath>
#include <string>
#include <utility>
#include <vector>

namespace camera_firmware::ai {
namespace {

bool IsFiniteBox(float x_min, float y_min, float x_max, float y_max,
                 float score) {
  return std::isfinite(x_min) && std::isfinite(y_min) && std::isfinite(x_max) &&
         std::isfinite(y_max) && std::isfinite(score);
}

bool IsNormalizedBox(float x_min, float y_min, float x_max, float y_max) {
  return x_min >= 0.0F && y_min >= 0.0F && x_max <= 1.0F && y_max <= 1.0F &&
         x_max > x_min && y_max > y_min;
}

}  // namespace

const std::vector<std::string>& Coco80Labels() {
  static const std::vector<std::string> kLabels = {
      "person",        "bicycle",      "car",
      "motorcycle",    "airplane",     "bus",
      "train",         "truck",        "boat",
      "traffic light", "fire hydrant", "stop sign",
      "parking meter", "bench",        "bird",
      "cat",           "dog",          "horse",
      "sheep",         "cow",          "elephant",
      "bear",          "zebra",        "giraffe",
      "backpack",      "umbrella",     "handbag",
      "tie",           "suitcase",     "frisbee",
      "skis",          "snowboard",    "sports ball",
      "kite",          "baseball bat", "baseball glove",
      "skateboard",    "surfboard",    "tennis racket",
      "bottle",        "wine glass",   "cup",
      "fork",          "knife",        "spoon",
      "bowl",          "banana",       "apple",
      "sandwich",      "orange",       "broccoli",
      "carrot",        "hot dog",      "pizza",
      "donut",         "cake",         "chair",
      "couch",         "potted plant", "bed",
      "dining table",  "toilet",       "tv",
      "laptop",        "mouse",        "remote",
      "keyboard",      "cell phone",   "microwave",
      "oven",          "toaster",      "sink",
      "refrigerator",  "book",         "clock",
      "vase",          "scissors",     "teddy bear",
      "hair drier",    "toothbrush"};
  return kLabels;
}

const std::vector<std::string>& Coco17PoseKeypointNames() {
  static const std::vector<std::string> kNames = {
      "nose",        "left_eye",      "right_eye",      "left_ear",
      "right_ear",   "left_shoulder", "right_shoulder", "left_elbow",
      "right_elbow", "left_wrist",    "right_wrist",    "left_hip",
      "right_hip",   "left_knee",     "right_knee",     "left_ankle",
      "right_ankle"};
  return kNames;
}

std::vector<Detection> ParseYoloHailoNms(const float* tensor,
                                         std::size_t total_floats,
                                         int num_classes,
                                         int max_bboxes_per_class,
                                         float confidence_threshold) {
  std::vector<Detection> detections;
  if (tensor == nullptr || total_floats == 0U || num_classes <= 0 ||
      max_bboxes_per_class <= 0 || !std::isfinite(confidence_threshold)) {
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
    if (raw_count < 0.0F ||
        raw_count > static_cast<float>(max_bboxes_per_class) ||
        std::floor(raw_count) != raw_count) {
      return {};
    }
    const int count = static_cast<int>(raw_count);

    const auto box_count = static_cast<std::size_t>(count);
    constexpr std::size_t kFloatsPerBox = 5U;
    if (box_count > (total_floats - offset) / kFloatsPerBox) {
      return {};
    }

    for (std::size_t box_index = 0; box_index < box_count; ++box_index) {
      const float y_min = tensor[offset];
      const float x_min = tensor[offset + 1U];
      const float y_max = tensor[offset + 2U];
      const float x_max = tensor[offset + 3U];
      const float score = tensor[offset + 4U];
      offset += kFloatsPerBox;

      if (!IsFiniteBox(x_min, y_min, x_max, y_max, score) ||
          !IsNormalizedBox(x_min, y_min, x_max, y_max) ||
          score < confidence_threshold || score > 1.0F) {
        continue;
      }

      Detection detection;
      detection.class_id = class_index;
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

std::vector<Detection> ParseYoloPoseRows(const float* tensor,
                                         std::size_t total_floats,
                                         float confidence_threshold,
                                         float keypoint_confidence_threshold) {
  std::vector<Detection> detections;
  if (tensor == nullptr || total_floats == 0U ||
      (total_floats % kYoloPoseRowFloatCount) != 0U) {
    return detections;
  }

  const auto& keypoint_names = Coco17PoseKeypointNames();
  const std::size_t row_count = total_floats / kYoloPoseRowFloatCount;
  detections.reserve(row_count);
  for (std::size_t row = 0; row < row_count; ++row) {
    const std::size_t offset = row * kYoloPoseRowFloatCount;
    const float x_min = tensor[offset];
    const float y_min = tensor[offset + 1U];
    const float x_max = tensor[offset + 2U];
    const float y_max = tensor[offset + 3U];
    const float score = tensor[offset + 4U];
    if (!IsFiniteBox(x_min, y_min, x_max, y_max, score) ||
        score < confidence_threshold || x_max <= x_min || y_max <= y_min) {
      continue;
    }

    Detection detection;
    detection.class_id = 0;
    detection.label = "person";
    detection.confidence = score;
    detection.box.x = x_min;
    detection.box.y = y_min;
    detection.box.width = x_max - x_min;
    detection.box.height = y_max - y_min;

    for (std::size_t index = 0; index < keypoint_names.size(); ++index) {
      const std::size_t keypoint_offset = offset + kYoloPoseBoxScoreFloatCount +
                                          (index * kYoloPoseFloatsPerKeypoint);
      const float x = tensor[keypoint_offset];
      const float y = tensor[keypoint_offset + 1U];
      const float confidence = tensor[keypoint_offset + 2U];
      if (!std::isfinite(x) || !std::isfinite(y) ||
          !std::isfinite(confidence) ||
          confidence < keypoint_confidence_threshold) {
        continue;
      }

      Keypoint keypoint;
      keypoint.name = keypoint_names[index];
      keypoint.x = x;
      keypoint.y = y;
      keypoint.confidence = confidence;
      detection.keypoints.push_back(std::move(keypoint));
    }
    detections.push_back(std::move(detection));
  }

  return detections;
}

}  // namespace camera_firmware::ai
