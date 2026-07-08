#pragma once

#include <optional>
#include <string_view>

#include "camera_firmware/ai/AiTypes.hpp"
#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::ai {

class AiBackend {
 public:
  virtual ~AiBackend() = default;

  [[nodiscard]] virtual std::string_view name() const noexcept = 0;
  [[nodiscard]] virtual std::optional<DetectionEvent> ProcessFrame(
      const media::FrameLease& frame) = 0;
};

}  // namespace camera_firmware::ai
