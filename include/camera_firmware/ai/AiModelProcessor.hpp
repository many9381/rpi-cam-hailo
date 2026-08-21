#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "camera_firmware/ai/AiBackend.hpp"
#include "camera_firmware/ai/DetectionBus.hpp"
#include "camera_firmware/ai/ModelInputBuffer.hpp"
#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::ai {

class AiModelProcessor {
 public:
  virtual ~AiModelProcessor() = default;

  [[nodiscard]] virtual std::string_view model_id() const noexcept = 0;
  [[nodiscard]] virtual std::string_view model_kind() const noexcept = 0;
  // Writes the model input into `canvas`, reusing its storage and letterbox
  // padding when the geometry tag matches (see ModelInputBuffer).
  [[nodiscard]] virtual common::Result<void> Preprocess(
      const media::FrameLease& frame, ModelInputBuffer& canvas) = 0;
  virtual void Postprocess(common::Result<OutputView> output,
                           const media::FrameHandle& source_frame,
                           const DetectionBus::Publisher& publisher) = 0;
};

[[nodiscard]] common::Result<std::shared_ptr<AiModelProcessor>>
CreateAiModelProcessor(const config::AiModelConfig& model);

}  // namespace camera_firmware::ai
