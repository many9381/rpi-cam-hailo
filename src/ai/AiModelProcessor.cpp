#include "camera_firmware/ai/AiModelProcessor.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "camera_firmware/ai/Nv12RgbPreprocessor.hpp"
#include "camera_firmware/ai/YoloPostprocess.hpp"

namespace camera_firmware::ai {
namespace {

constexpr int kYoloClassCount = 80;
constexpr int kYoloMaxBoxesPerClass = 100;
constexpr std::size_t kYoloValuesPerBox = 5U;
constexpr std::size_t kYoloNmsFloatCount =
    static_cast<std::size_t>(kYoloClassCount) *
    (1U + (static_cast<std::size_t>(kYoloMaxBoxesPerClass) *
           kYoloValuesPerBox));

struct ModelInputGeometry {
  std::uint32_t scaled_width{0};
  std::uint32_t scaled_height{0};
  std::uint32_t x_offset{0};
  std::uint32_t y_offset{0};
};

ModelInputGeometry BuildModelInputGeometry(
    const media::FrameHandle& source,
    const config::AiModelInputConfig& target) {
  ModelInputGeometry geometry;
  geometry.scaled_width = target.width;
  geometry.scaled_height = target.height;

  if (!target.letterbox || source.width == 0U || source.height == 0U ||
      target.width == 0U || target.height == 0U) {
    return geometry;
  }

  const double scale = std::min(
      static_cast<double>(target.width) / source.width,
      static_cast<double>(target.height) / source.height);
  geometry.scaled_width = std::min(
      target.width,
      std::max(1U, static_cast<std::uint32_t>(
                       static_cast<double>(source.width) * scale)));
  geometry.scaled_height = std::min(
      target.height,
      std::max(1U, static_cast<std::uint32_t>(
                       static_cast<double>(source.height) * scale)));
  geometry.x_offset = (target.width - geometry.scaled_width) / 2U;
  geometry.y_offset = (target.height - geometry.scaled_height) / 2U;
  return geometry;
}

float ClampUnit(double value) {
  return static_cast<float>(std::clamp(value, 0.0, 1.0));
}

void MapBoxFromLetterboxedModel(const config::AiModelInputConfig& input,
                                const media::FrameHandle& source,
                                DetectionBox& box) {
  if (!input.letterbox || input.width == 0U || input.height == 0U ||
      source.width == 0U || source.height == 0U) {
    return;
  }

  const auto geometry = BuildModelInputGeometry(source, input);
  const double model_width = static_cast<double>(input.width);
  const double model_height = static_cast<double>(input.height);
  const double active_width = static_cast<double>(geometry.scaled_width);
  const double active_height = static_cast<double>(geometry.scaled_height);
  if (active_width <= 0.0 || active_height <= 0.0) {
    return;
  }

  const double x_offset = static_cast<double>(geometry.x_offset);
  const double y_offset = static_cast<double>(geometry.y_offset);
  const auto map_x = [&](double normalized_x) {
    return ((normalized_x * model_width) - x_offset) / active_width;
  };
  const auto map_y = [&](double normalized_y) {
    return ((normalized_y * model_height) - y_offset) / active_height;
  };

  const float left = ClampUnit(map_x(box.x));
  const float top = ClampUnit(map_y(box.y));
  const float right = ClampUnit(map_x(box.x + box.width));
  const float bottom = ClampUnit(map_y(box.y + box.height));
  box.x = left;
  box.y = top;
  box.width = std::max(0.0F, right - left);
  box.height = std::max(0.0F, bottom - top);
}

void MapKeypointFromLetterboxedModel(const config::AiModelInputConfig& input,
                                     const media::FrameHandle& source,
                                     Keypoint& keypoint) {
  if (!input.letterbox || input.width == 0U || input.height == 0U ||
      source.width == 0U || source.height == 0U) {
    return;
  }

  const auto geometry = BuildModelInputGeometry(source, input);
  const double model_width = static_cast<double>(input.width);
  const double model_height = static_cast<double>(input.height);
  const double active_width = static_cast<double>(geometry.scaled_width);
  const double active_height = static_cast<double>(geometry.scaled_height);
  if (active_width <= 0.0 || active_height <= 0.0) {
    return;
  }

  keypoint.x = ClampUnit(((static_cast<double>(keypoint.x) * model_width) -
                          static_cast<double>(geometry.x_offset)) /
                         active_width);
  keypoint.y = ClampUnit(((static_cast<double>(keypoint.y) * model_height) -
                          static_cast<double>(geometry.y_offset)) /
                         active_height);
}

class DefaultModelProcessor final : public AiModelProcessor {
 public:
  explicit DefaultModelProcessor(config::AiModelConfig model)
      : model_(std::move(model)),
        preprocessor_(model_.input.width,
                      model_.input.height,
                      model_.input.letterbox,
                      114U) {}

  [[nodiscard]] std::string_view model_id() const noexcept override {
    return model_.id;
  }

  [[nodiscard]] std::string_view model_kind() const noexcept override {
    return model_.kind;
  }

  [[nodiscard]] common::Result<void> Preprocess(
      const media::FrameLease& frame, ModelInputBuffer& canvas) override {
    if (model_.input.format != "rgb8" || model_.input.width == 0U ||
        model_.input.height == 0U) {
      return common::Result<void>::Err(
          {"E_AI_PREPROCESS", "AI model input must be non-empty rgb8"});
    }
    return preprocessor_.ConvertInto(frame, canvas);
  }

  void Postprocess(common::Result<OutputView> output,
                   const media::FrameHandle& source_frame,
                   const DetectionBus::Publisher& publisher) override {
    if (!output.ok() || !publisher.valid()) {
      return;
    }

    DetectionEvent event;
    event.camera_id = source_frame.camera_id;
    event.model_id = model_.id;
    event.model_kind = model_.kind;
    event.frame_sequence = source_frame.sequence;
    event.frame_timestamp = source_frame.timestamp;

    if (model_.kind != "object_detection" && model_.kind != "pose") {
      return;
    }

    const auto output_view = output.value();
    if (output_view.size == 0U) {
      event.result_state = "skeleton_no_decoder";
      publisher.Publish(event);
      return;
    }

    if (model_.kind == "pose") {
      if (output_view.data == nullptr) {
        throw std::runtime_error("AI pose output data is null");
      }
      if ((output_view.size % sizeof(float)) != 0U) {
        throw std::runtime_error("AI pose output size " +
                                 std::to_string(output_view.size) +
                                 " bytes is not float aligned");
      }

      std::vector<float> tensor(output_view.size / sizeof(float));
      if ((tensor.size() % kYoloPoseRowFloatCount) != 0U) {
        throw std::runtime_error(
            "AI pose output size " + std::to_string(tensor.size()) +
            " floats does not match " +
            std::to_string(kYoloPoseRowFloatCount) +
            "-float YOLO pose row shape");
      }
      std::memcpy(tensor.data(), output_view.data, output_view.size);
      event.result_state = "decoded";
      event.detections =
          ParseYoloPoseRows(tensor.data(),
                            tensor.size(),
                            model_.confidence_threshold,
                            model_.confidence_threshold);
      for (auto& detection : event.detections) {
        MapBoxFromLetterboxedModel(model_.input, source_frame, detection.box);
        for (auto& keypoint : detection.keypoints) {
          MapKeypointFromLetterboxedModel(model_.input,
                                          source_frame,
                                          keypoint);
        }
      }
      publisher.Publish(event);
      return;
    }

    if (output_view.data == nullptr) {
      throw std::runtime_error("AI object detection output data is null");
    }
    if ((output_view.size % sizeof(float)) != 0U) {
      throw std::runtime_error(
          "AI object detection output size is not float aligned");
    }
    if ((output_view.size / sizeof(float)) != kYoloNmsFloatCount) {
      throw std::runtime_error(
          "AI object detection output size does not match YOLO NMS shape");
    }

    std::vector<float> tensor(output_view.size / sizeof(float));
    std::memcpy(tensor.data(), output_view.data, output_view.size);
    event.result_state = "decoded";
    event.detections =
        ParseYoloHailoNms(tensor.data(),
                          tensor.size(),
                          kYoloClassCount,
                          kYoloMaxBoxesPerClass,
                          model_.confidence_threshold);
    for (auto& detection : event.detections) {
      MapBoxFromLetterboxedModel(model_.input, source_frame, detection.box);
    }
    publisher.Publish(event);
  }

 private:
  config::AiModelConfig model_;
  Nv12RgbPreprocessor preprocessor_;
};

}  // namespace

common::Result<std::shared_ptr<AiModelProcessor>> CreateAiModelProcessor(
    const config::AiModelConfig& model) {
  if (model.kind == "object_detection" || model.kind == "pose") {
    return common::Result<std::shared_ptr<AiModelProcessor>>::Ok(
        std::make_shared<DefaultModelProcessor>(model));
  }

  return common::Result<std::shared_ptr<AiModelProcessor>>::Err(
      {"E_AI_MODEL_KIND", "Unsupported AI model kind: " + model.kind});
}

}  // namespace camera_firmware::ai
