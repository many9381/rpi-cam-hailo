#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "camera_firmware/ai/AiBackend.hpp"
#include "camera_firmware/ai/DetectionBus.hpp"
#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::ai {

struct ModelInputBuffer {
  std::vector<std::uint8_t> bytes;

  [[nodiscard]] InputView view() const noexcept {
    return {bytes.data(), bytes.size()};
  }
};

class AiModelProcessor {
 public:
  virtual ~AiModelProcessor() = default;

  [[nodiscard]] virtual std::string_view model_id() const noexcept = 0;
  [[nodiscard]] virtual std::string_view model_kind() const noexcept = 0;
  [[nodiscard]] virtual common::Result<ModelInputBuffer> Preprocess(
      const media::FrameLease& frame) = 0;
  virtual void Postprocess(common::Result<OutputView> output,
                           const media::FrameHandle& source_frame,
                           const DetectionBus::Publisher& publisher) = 0;
};

[[nodiscard]] common::Result<std::shared_ptr<AiModelProcessor>>
CreateAiModelProcessor(const config::AiModelConfig& model);

}  // namespace camera_firmware::ai
