#pragma once

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "camera_firmware/ai/AiBackend.hpp"

namespace hailort {
class ConfiguredInferModel;
class InferModel;
class VDevice;
}  // namespace hailort

namespace camera_firmware::ai {

class HailoBackend final : public AiBackend {
 public:
  HailoBackend();
  ~HailoBackend() override;

  [[nodiscard]] std::string_view name() const noexcept override;
  [[nodiscard]] bool available() const noexcept override;
  [[nodiscard]] common::Result<void> Init() override;
  void Shutdown() override;
  [[nodiscard]] common::Result<ModelHandle> LoadModel(
      const config::AiModelConfig& model) override;
  void Unload(ModelHandle handle) override;
  [[nodiscard]] common::Result<void> Submit(ModelHandle handle, InputView input,
                                            InferCallback callback) override;

 private:
  struct LoadedModel;

  void FinishInference() noexcept;

  mutable std::mutex mutex_;
  std::condition_variable idle_;
  std::unique_ptr<hailort::VDevice> vdevice_;
  std::vector<std::shared_ptr<LoadedModel>> models_;
  std::uint64_t in_flight_{0};
  bool shutting_down_{false};
};

}  // namespace camera_firmware::ai
