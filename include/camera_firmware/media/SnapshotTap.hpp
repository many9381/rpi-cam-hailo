#pragma once

#include <mutex>
#include <optional>
#include <cstdint>
#include <string_view>
#include <vector>

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

[[nodiscard]] std::optional<std::vector<std::uint8_t>> BuildLatestSnapshotJpeg(
    const SnapshotTap& tap,
    std::string_view camera_id);

}  // namespace camera_firmware::media
