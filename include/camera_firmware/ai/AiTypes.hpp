#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace camera_firmware::ai {

struct DetectionBox {
  float x{0.0F};
  float y{0.0F};
  float width{0.0F};
  float height{0.0F};
};

struct Detection {
  std::string label;
  float confidence{0.0F};
  DetectionBox box;
};

struct DetectionEvent {
  std::string camera_id;
  std::string model_id;
  std::string model_kind;
  std::string result_state{"decoded"};
  std::uint64_t frame_sequence{0};
  std::chrono::nanoseconds frame_timestamp{0};
  std::vector<Detection> detections;
};

}  // namespace camera_firmware::ai
