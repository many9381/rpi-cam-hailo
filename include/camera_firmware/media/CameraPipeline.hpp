#pragma once

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

 private:
  struct Impl;

  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::media
