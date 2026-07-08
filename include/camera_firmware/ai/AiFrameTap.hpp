#pragma once

#include <mutex>
#include <optional>

#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::ai {

class AiFrameTap {
 public:
  void PublishLatest(media::FrameLease frame);
  [[nodiscard]] std::optional<media::FrameLease> Latest() const;

 private:
  mutable std::mutex mutex_;
  std::optional<media::FrameLease> latest_;
};

}  // namespace camera_firmware::ai
