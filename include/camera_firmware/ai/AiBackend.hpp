#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string_view>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"

namespace camera_firmware::ai {

using ModelHandle = std::uint64_t;

struct InputView {
  const std::uint8_t* data{nullptr};
  std::size_t size{0};
};

struct OutputView {
  const std::uint8_t* data{nullptr};
  std::size_t size{0};
};

using InferCallback = std::function<void(common::Result<OutputView>)>;

class AiBackend {
 public:
  virtual ~AiBackend() = default;

  [[nodiscard]] virtual std::string_view name() const noexcept = 0;
  [[nodiscard]] virtual bool available() const noexcept = 0;
  [[nodiscard]] virtual common::Result<void> Init() = 0;
  virtual void Shutdown() = 0;
  [[nodiscard]] virtual common::Result<ModelHandle> LoadModel(
      const config::AiModelConfig& model) = 0;
  virtual void Unload(ModelHandle handle) = 0;
  [[nodiscard]] virtual common::Result<void> Submit(ModelHandle handle,
                                                    InputView input,
                                                    InferCallback callback) = 0;
};

class UnavailableAiBackend final : public AiBackend {
 public:
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
  ModelHandle next_handle_{1};
};

}  // namespace camera_firmware::ai
