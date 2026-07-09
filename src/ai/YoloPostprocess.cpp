#include "camera_firmware/ai/YoloPostprocess.hpp"

#include <cmath>
#include <string>
#include <utility>
#include <vector>

namespace camera_firmware::ai {
namespace {

bool IsFiniteBox(float x_min,
                 float y_min,
                 float x_max,
                 float y_max,
                 float score) {
  return std::isfinite(x_min) && std::isfinite(y_min) &&
         std::isfinite(x_max) && std::isfinite(y_max) &&
         std::isfinite(score);
}

}  // namespace

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

const std::vector<std::string>& Coco17PoseKeypointNames() {
  static const std::vector<std::string> kNames = {
      "nose",
      "left_eye",
      "right_eye",
      "left_ear",
      "right_ear",
      "left_shoulder",
      "right_shoulder",
      "left_elbow",
      "right_elbow",
      "left_wrist",
      "right_wrist",
      "left_hip",
      "right_hip",
      "left_knee",
      "right_knee",
      "left_ankle",
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

std::vector<Detection> ParseYoloPoseRows(
    const float* tensor,
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
    detection.label = "person";
    detection.confidence = score;
    detection.box.x = x_min;
    detection.box.y = y_min;
    detection.box.width = x_max - x_min;
    detection.box.height = y_max - y_min;

    for (std::size_t index = 0; index < keypoint_names.size(); ++index) {
      const std::size_t keypoint_offset =
          offset + kYoloPoseBoxScoreFloatCount +
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
