#pragma once

#include <algorithm>

#include "camera_firmware/config/AppConfig.hpp"

namespace camera_firmware::media {

struct LoresSize {
  unsigned int width{0U};
  unsigned int height{0U};
};

// The AI lores stream: the model input width at the sensor's aspect ratio,
// each dimension floored to even (NV12 planes require even dimensions). This
// is the smallest ISP output that lets the existing letterbox preprocessor
// reach the model input with no downscale — only vertical padding.
inline LoresSize ComputeLoresSize(unsigned int sensor_width,
                                  unsigned int sensor_height,
                                  unsigned int model_input_width) {
  if (sensor_width == 0U || sensor_height == 0U || model_input_width == 0U) {
    return {0U, 0U};
  }
  const unsigned int width = std::min(model_input_width, sensor_width) & ~1U;
  if (width == 0U) {
    return {0U, 0U};
  }
  const auto height =
      static_cast<unsigned int>(static_cast<unsigned long>(width) *
                                sensor_height / sensor_width) &
      ~1U;
  return {width, height == 0U ? 2U : height};
}

// Largest input width among the models this camera actually runs AI on, or 0
// when the camera has no active AI (then no lores stream is requested and the
// pipeline stays single-stream).
inline unsigned int ResolveAiLoresWidth(const config::AppConfig& config) {
  if (!config.camera.ai.enabled) {
    return 0U;
  }
  unsigned int best = 0U;
  for (const auto& id : config.camera.ai.model_ids) {
    for (const auto& model : config.ai.models) {
      if (model.id == id && model.input.width > best) {
        best = model.input.width;
      }
    }
  }
  return best;
}

}  // namespace camera_firmware::media
