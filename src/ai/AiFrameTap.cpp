#include "camera_firmware/ai/AiFrameTap.hpp"

#include <mutex>
#include <utility>

namespace camera_firmware::ai {

void AiFrameTap::PublishLatest(media::FrameLease frame) {
  std::lock_guard lock(mutex_);
  latest_ = std::move(frame);
}

std::optional<media::FrameLease> AiFrameTap::Latest() const {
  std::lock_guard lock(mutex_);
  if (!latest_.has_value()) {
    return std::nullopt;
  }
  return latest_->CloneRef();
}

}  // namespace camera_firmware::ai
