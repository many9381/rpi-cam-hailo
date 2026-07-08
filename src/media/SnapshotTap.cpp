#include "camera_firmware/media/SnapshotTap.hpp"

#include <mutex>
#include <utility>

namespace camera_firmware::media {

void SnapshotTap::Publish(FrameLease frame) {
  std::lock_guard lock(mutex_);
  latest_ = std::move(frame);
}

std::optional<FrameLease> SnapshotTap::Latest() const {
  std::lock_guard lock(mutex_);
  if (!latest_.has_value()) {
    return std::nullopt;
  }
  return latest_->CloneRef();
}

}  // namespace camera_firmware::media
