#include "camera_firmware/ai/AiModelProcessor.hpp"

#include <sys/mman.h>
#include <sys/stat.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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

struct MappedReadPlane {
  const std::uint8_t* data{nullptr};
  std::size_t size{0};
  void* mapping{nullptr};
  std::size_t mapping_size{0};

  MappedReadPlane() = default;
  MappedReadPlane(const std::uint8_t* plane_data,
                  std::size_t plane_size,
                  void* mapped_address,
                  std::size_t mapped_size)
      : data(plane_data),
        size(plane_size),
        mapping(mapped_address),
        mapping_size(mapped_size) {}

  MappedReadPlane(const MappedReadPlane&) = delete;
  MappedReadPlane& operator=(const MappedReadPlane&) = delete;

  MappedReadPlane(MappedReadPlane&& other) noexcept
      : data(other.data),
        size(other.size),
        mapping(other.mapping),
        mapping_size(other.mapping_size) {
    other.data = nullptr;
    other.size = 0;
    other.mapping = nullptr;
    other.mapping_size = 0;
  }

  MappedReadPlane& operator=(MappedReadPlane&& other) noexcept {
    if (this == &other) {
      return *this;
    }
    Reset();
    data = other.data;
    size = other.size;
    mapping = other.mapping;
    mapping_size = other.mapping_size;
    other.data = nullptr;
    other.size = 0;
    other.mapping = nullptr;
    other.mapping_size = 0;
    return *this;
  }

  ~MappedReadPlane() { Reset(); }

 private:
  void Reset() noexcept {
    if (mapping != nullptr && mapping != MAP_FAILED) {
      (void)::munmap(mapping, mapping_size);
    }
    data = nullptr;
    size = 0;
    mapping = nullptr;
    mapping_size = 0;
  }
};

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

std::optional<MappedReadPlane> MapPlaneReadOnly(
    const media::FramePlane& plane) {
  if (plane.dmabuf_fd < 0 || plane.length == 0U) {
    return std::nullopt;
  }
  if (plane.offset > std::numeric_limits<std::size_t>::max() - plane.length) {
    return std::nullopt;
  }

  const std::size_t mapping_size = plane.offset + plane.length;
  struct stat backing {};
  if (::fstat(plane.dmabuf_fd, &backing) != 0 || backing.st_size < 0 ||
      static_cast<std::uint64_t>(mapping_size) >
          static_cast<std::uint64_t>(backing.st_size)) {
    return std::nullopt;
  }
  void* mapping =
      ::mmap(nullptr, mapping_size, PROT_READ, MAP_SHARED, plane.dmabuf_fd, 0);
  if (mapping == MAP_FAILED) {
    return std::nullopt;
  }

  const auto* bytes = static_cast<const std::uint8_t*>(mapping);
  return MappedReadPlane{bytes + plane.offset, plane.length, mapping,
                         mapping_size};
}

std::optional<std::size_t> Rgb8ByteCount(std::uint32_t width,
                                         std::uint32_t height) {
  constexpr std::size_t kChannels = 3U;
  const std::size_t width_size = width;
  const std::size_t height_size = height;
  if (height_size > std::numeric_limits<std::size_t>::max() / kChannels) {
    return std::nullopt;
  }
  const std::size_t row_channel_count = height_size * kChannels;
  if (width_size >
      std::numeric_limits<std::size_t>::max() / row_channel_count) {
    return std::nullopt;
  }
  return width_size * row_channel_count;
}

std::uint8_t ClampToByte(int value) {
  return static_cast<std::uint8_t>(std::clamp(value, 0, 255));
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

void WriteNv12PixelRgb(const media::FrameHandle& source,
                       const std::uint8_t* y_plane,
                       const std::uint8_t* uv_plane,
                       std::uint32_t x,
                       std::uint32_t y,
                       std::uint8_t* output) {
  const int y_value =
      y_plane[static_cast<std::size_t>(y) * source.planes[0].stride + x];
  const std::uint32_t uv_x = (x / 2U) * 2U;
  const std::uint32_t uv_y = y / 2U;
  const std::size_t uv_index =
      static_cast<std::size_t>(uv_y) * source.planes[1].stride + uv_x;
  const int u_value = uv_plane[uv_index] - 128;
  const int v_value = uv_plane[uv_index + 1U] - 128;
  const int c = y_value - 16;

  output[0] = ClampToByte((298 * c + 409 * v_value + 128) >> 8);
  output[1] =
      ClampToByte((298 * c - 100 * u_value - 208 * v_value + 128) >> 8);
  output[2] = ClampToByte((298 * c + 516 * u_value + 128) >> 8);
}

ModelInputBuffer ConvertNv12ToRgb8(const media::FrameHandle& source,
                                   const std::uint8_t* y_plane,
                                   const std::uint8_t* uv_plane,
                                   const config::AiModelInputConfig& target) {
  ModelInputBuffer input;
  input.bytes.assign(Rgb8ByteCount(target.width, target.height).value(),
                     target.letterbox ? 114U : 0U);

  const auto geometry = BuildModelInputGeometry(source, target);

  for (std::uint32_t dst_y = 0; dst_y < geometry.scaled_height; ++dst_y) {
    const std::uint32_t src_y = std::min<std::uint32_t>(
        source.height - 1U,
        static_cast<std::uint64_t>(dst_y) * source.height /
            geometry.scaled_height);
    for (std::uint32_t dst_x = 0; dst_x < geometry.scaled_width; ++dst_x) {
      const std::uint32_t src_x = std::min<std::uint32_t>(
          source.width - 1U,
          static_cast<std::uint64_t>(dst_x) * source.width /
              geometry.scaled_width);
      const std::size_t output_index =
          (static_cast<std::size_t>(dst_y + geometry.y_offset) * target.width +
           (dst_x + geometry.x_offset)) *
          3U;
      WriteNv12PixelRgb(source,
                        y_plane,
                        uv_plane,
                        src_x,
                        src_y,
                        input.bytes.data() + output_index);
    }
  }

  return input;
}

class DefaultModelProcessor final : public AiModelProcessor {
 public:
  explicit DefaultModelProcessor(config::AiModelConfig model)
      : model_(std::move(model)) {}

  [[nodiscard]] std::string_view model_id() const noexcept override {
    return model_.id;
  }

  [[nodiscard]] std::string_view model_kind() const noexcept override {
    return model_.kind;
  }

  [[nodiscard]] common::Result<ModelInputBuffer> Preprocess(
      const media::FrameLease& frame) override {
    if (!frame.valid()) {
      return common::Result<ModelInputBuffer>::Err(
          {"E_AI_PREPROCESS", "AI frame lease is invalid"});
    }

    const auto& handle = frame.handle();
    if (handle.format != "NV12" || handle.width == 0U ||
        handle.height == 0U || handle.plane_count < 2U) {
      return common::Result<ModelInputBuffer>::Err(
          {"E_AI_PREPROCESS", "AI processor expected an NV12 camera frame"});
    }
    if ((handle.width % 2U) != 0U) {
      return common::Result<ModelInputBuffer>::Err(
          {"E_AI_PREPROCESS", "AI processor expected even-width NV12 frame"});
    }
    const std::size_t y_required =
        static_cast<std::size_t>(handle.planes[0].stride) * handle.height;
    const std::size_t uv_required =
        static_cast<std::size_t>(handle.planes[1].stride) *
        ((handle.height + 1U) / 2U);
    if (handle.planes[0].stride < handle.width ||
        handle.planes[1].stride < handle.width ||
        handle.planes[0].length < y_required ||
        handle.planes[1].length < uv_required) {
      return common::Result<ModelInputBuffer>::Err(
          {"E_AI_PREPROCESS", "AI processor received inconsistent NV12 planes"});
    }
    if (model_.input.format != "rgb8" || model_.input.width == 0U ||
        model_.input.height == 0U) {
      return common::Result<ModelInputBuffer>::Err(
          {"E_AI_PREPROCESS", "AI model input must be non-empty rgb8"});
    }
    if (!Rgb8ByteCount(model_.input.width, model_.input.height).has_value()) {
      return common::Result<ModelInputBuffer>::Err(
          {"E_AI_PREPROCESS", "AI model input dimensions are too large"});
    }

    auto y_plane = MapPlaneReadOnly(handle.planes[0]);
    auto uv_plane = MapPlaneReadOnly(handle.planes[1]);
    if (!y_plane.has_value() || !uv_plane.has_value()) {
      return common::Result<ModelInputBuffer>::Err(
          {"E_AI_PREPROCESS", "AI processor failed to map NV12 planes"});
    }

    return common::Result<ModelInputBuffer>::Ok(
        ConvertNv12ToRgb8(handle, y_plane->data, uv_plane->data, model_.input));
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
