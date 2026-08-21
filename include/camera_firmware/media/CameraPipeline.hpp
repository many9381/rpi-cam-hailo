#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/EncodedRing.hpp"
#include "camera_firmware/media/SnapshotTap.hpp"

namespace camera_firmware::ai {
class AiFrameTap;
}  // namespace camera_firmware::ai

namespace camera_firmware::media {

struct CameraPipelineStatus {
  std::string id{"imx708-main"};
  std::string state{"stopped"};
  bool snapshot_available{false};
  unsigned int width{0U};
  unsigned int height{0U};
  unsigned int configured_fps{0U};
  double capture_fps{0.0};
  double encoded_fps{0.0};
  std::uint64_t captured_frames{0U};
  std::uint64_t encoded_frames{0U};
  std::uint64_t capture_error_count{0U};
  std::uint64_t encode_error_count{0U};
  // Wall-clock cost of the most recent x264 encode call and the number of
  // encoded access units dropped from the ring before any reader saw them.
  double last_encode_ms{0.0};
  std::uint64_t encoded_ring_overruns{0U};
  std::string ai_source{"main-fallback"};
};

class CameraPipeline {
 public:
  CameraPipeline(SnapshotTap& snapshot_tap,
                 ai::AiFrameTap& ai_frame_tap,
                 EncodedRing& encoded_ring);
  ~CameraPipeline();

  CameraPipeline(const CameraPipeline&) = delete;
  CameraPipeline& operator=(const CameraPipeline&) = delete;
  CameraPipeline(CameraPipeline&&) = delete;
  CameraPipeline& operator=(CameraPipeline&&) = delete;

  [[nodiscard]] common::Result<void> ValidateConfigOnly(
      const config::AppConfig& config);
  [[nodiscard]] common::Result<void> Start(const config::AppConfig& config);
  void Stop();

  [[nodiscard]] std::vector<CameraPipelineStatus> Status() const;
  [[nodiscard]] std::vector<CameraPipelineStatus> Status(
      std::chrono::milliseconds maximum_snapshot_age) const;

 private:
  struct Impl;

  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::media
