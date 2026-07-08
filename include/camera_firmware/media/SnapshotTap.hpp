#pragma once

#include <mutex>
#include <optional>

#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::media {

class SnapshotTap {
 public:
  void Publish(FrameLease frame);
  [[nodiscard]] std::optional<FrameLease> Latest() const;

 private:
  mutable std::mutex mutex_;
  std::optional<FrameLease> latest_;
};

}  // namespace camera_firmware::media
