#include "camera_firmware/ai/Nv12RgbPreprocessor.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include <libavutil/pixfmt.h>
#include <libswscale/swscale.h>
}

#include "camera_firmware/config/AppConfig.hpp"

namespace camera_firmware::ai {
namespace {

constexpr std::size_t kRgbChannels = 3U;

common::Error PreprocessError(std::string message) {
  return {"E_AI_PREPROCESS", std::move(message)};
}

struct MappedReadPlane {
  const std::uint8_t* data{nullptr};
  void* mapping{nullptr};
  std::size_t mapping_size{0};

  MappedReadPlane() = default;
  MappedReadPlane(const std::uint8_t* plane_data,
                  void* mapped_address,
                  std::size_t mapped_size)
      : data(plane_data), mapping(mapped_address), mapping_size(mapped_size) {}

  MappedReadPlane(const MappedReadPlane&) = delete;
  MappedReadPlane& operator=(const MappedReadPlane&) = delete;

  MappedReadPlane(MappedReadPlane&& other) noexcept
      : data(other.data), mapping(other.mapping), mapping_size(other.mapping_size) {
    other.data = nullptr;
    other.mapping = nullptr;
    other.mapping_size = 0;
  }

  MappedReadPlane& operator=(MappedReadPlane&& other) noexcept {
    if (this != &other) {
      Reset();
      data = other.data;
      mapping = other.mapping;
      mapping_size = other.mapping_size;
      other.data = nullptr;
      other.mapping = nullptr;
      other.mapping_size = 0;
    }
    return *this;
  }

  ~MappedReadPlane() { Reset(); }

 private:
  void Reset() noexcept {
    if (mapping != nullptr && mapping != MAP_FAILED) {
      (void)::munmap(mapping, mapping_size);
    }
    data = nullptr;
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

bool MultiplicationOverflows(std::size_t left, std::size_t right) {
  return left != 0U && right > std::numeric_limits<std::size_t>::max() / left;
}

common::Result<std::size_t> Rgb8ByteCount(std::uint32_t width,
                                           std::uint32_t height) {
  if (width == 0U || height == 0U ||
      MultiplicationOverflows(width, height) ||
      MultiplicationOverflows(static_cast<std::size_t>(width) * height,
                              kRgbChannels)) {
    return common::Result<std::size_t>::Err(
        PreprocessError("AI model input dimensions are invalid"));
  }
  const auto bytes = static_cast<std::size_t>(width) * height * kRgbChannels;
  if (bytes > config::kMaximumAiModelInputBytes) {
    return common::Result<std::size_t>::Err(
        PreprocessError("AI model input exceeds the RGB8 memory limit"));
  }
  return common::Result<std::size_t>::Ok(bytes);
}

common::Result<std::size_t> RequiredPlaneBytes(std::uint32_t stride,
                                                std::uint32_t rows) {
  if (stride == 0U || rows == 0U || MultiplicationOverflows(stride, rows)) {
    return common::Result<std::size_t>::Err(
        PreprocessError("NV12 plane dimensions are invalid"));
  }
  return common::Result<std::size_t>::Ok(
      static_cast<std::size_t>(stride) * rows);
}

common::Result<MappedReadPlane> MapPlaneReadOnly(
    const media::FramePlane& plane) {
  if (plane.dmabuf_fd < 0 || plane.length == 0U ||
      plane.offset > std::numeric_limits<std::size_t>::max() - plane.length) {
    return common::Result<MappedReadPlane>::Err(
        PreprocessError("NV12 plane descriptor is invalid"));
  }
  if (::fcntl(plane.dmabuf_fd, F_GETFD) == -1) {
    return common::Result<MappedReadPlane>::Err(
        PreprocessError("NV12 plane descriptor cannot be used"));
  }

  const long page_size_long = ::sysconf(_SC_PAGESIZE);
  if (page_size_long <= 0) {
    return common::Result<MappedReadPlane>::Err(
        PreprocessError("cannot determine system page size"));
  }
  const auto page_size = static_cast<std::size_t>(page_size_long);
  const std::size_t mapping_offset = plane.offset - (plane.offset % page_size);
  const std::size_t data_offset = plane.offset - mapping_offset;
  if (data_offset > std::numeric_limits<std::size_t>::max() - plane.length ||
      mapping_offset >
          static_cast<std::size_t>(std::numeric_limits<off_t>::max())) {
    return common::Result<MappedReadPlane>::Err(
        PreprocessError("NV12 plane mapping range is invalid"));
  }
  const std::size_t mapping_size = data_offset + plane.length;

  struct stat backing {};
  if (::fstat(plane.dmabuf_fd, &backing) == 0 && S_ISREG(backing.st_mode) &&
      static_cast<std::uintmax_t>(plane.offset) + plane.length >
          static_cast<std::uintmax_t>(backing.st_size)) {
    return common::Result<MappedReadPlane>::Err(
        PreprocessError("NV12 plane range exceeds its backing file"));
  }

  void* mapping = ::mmap(nullptr,
                         mapping_size,
                         PROT_READ,
                         MAP_SHARED,
                         plane.dmabuf_fd,
                         static_cast<off_t>(mapping_offset));
  if (mapping == MAP_FAILED) {
    return common::Result<MappedReadPlane>::Err(
        PreprocessError("failed to map NV12 plane"));
  }
  const auto* bytes = static_cast<const std::uint8_t*>(mapping);
  return common::Result<MappedReadPlane>::Ok(
      MappedReadPlane(bytes + data_offset, mapping, mapping_size));
}

common::Result<ModelInputGeometry> BuildModelInputGeometry(
    std::uint32_t source_width,
    std::uint32_t source_height,
    std::uint32_t target_width,
    std::uint32_t target_height,
    bool letterbox) {
  if (source_width == 0U || source_height == 0U || target_width == 0U ||
      target_height == 0U) {
    return common::Result<ModelInputGeometry>::Err(
        PreprocessError("NV12 source or model input dimensions are invalid"));
  }

  ModelInputGeometry geometry{target_width, target_height, 0U, 0U};
  if (!letterbox) {
    return common::Result<ModelInputGeometry>::Ok(geometry);
  }

  const double scale = std::min(
      static_cast<double>(target_width) / source_width,
      static_cast<double>(target_height) / source_height);
  geometry.scaled_width = std::min(
      target_width,
      std::max(1U, static_cast<std::uint32_t>(source_width * scale)));
  geometry.scaled_height = std::min(
      target_height,
      std::max(1U, static_cast<std::uint32_t>(source_height * scale)));
  geometry.x_offset = (target_width - geometry.scaled_width) / 2U;
  geometry.y_offset = (target_height - geometry.scaled_height) / 2U;
  return common::Result<ModelInputGeometry>::Ok(geometry);
}

}  // namespace

struct Nv12RgbPreprocessor::Impl {
  Impl(std::uint32_t width,
       std::uint32_t height,
       bool use_letterbox,
       std::uint8_t fill)
      : target_width(width),
        target_height(height),
        letterbox(use_letterbox),
        padding(fill) {}

  ~Impl() { sws_freeContext(sws); }

  std::uint32_t target_width;
  std::uint32_t target_height;
  bool letterbox;
  std::uint8_t padding;
  SwsContext* sws{nullptr};
};

Nv12RgbPreprocessor::Nv12RgbPreprocessor(std::uint32_t target_width,
                                         std::uint32_t target_height,
                                         bool letterbox,
                                         std::uint8_t padding)
    : impl_(std::make_unique<Impl>(target_width,
                                   target_height,
                                   letterbox,
                                   padding)) {}

Nv12RgbPreprocessor::~Nv12RgbPreprocessor() = default;

common::Result<std::vector<std::uint8_t>> Nv12RgbPreprocessor::Convert(
    const media::FrameLease& frame) {
  if (!frame.valid()) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("AI frame lease is invalid"));
  }

  const auto& source = frame.handle();
  if (source.format != "NV12" || source.width == 0U || source.height == 0U ||
      source.plane_count < 2U || (source.width % 2U) != 0U ||
      (source.height % 2U) != 0U) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("AI processor expected an even-dimension NV12 frame"));
  }
  if (source.planes[0].stride < source.width ||
      source.planes[1].stride < source.width) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("NV12 plane stride is smaller than the source width"));
  }

  const auto y_required = RequiredPlaneBytes(source.planes[0].stride,
                                             source.height);
  const auto uv_required = RequiredPlaneBytes(source.planes[1].stride,
                                              source.height / 2U);
  if (!y_required.ok() || !uv_required.ok() ||
      source.planes[0].length < y_required.value() ||
      source.planes[1].length < uv_required.value()) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("AI processor received inconsistent NV12 planes"));
  }

  const auto geometry = BuildModelInputGeometry(source.width,
                                                source.height,
                                                impl_->target_width,
                                                impl_->target_height,
                                                impl_->letterbox);
  const auto target_bytes = Rgb8ByteCount(impl_->target_width,
                                          impl_->target_height);
  if (!geometry.ok()) {
    return common::Result<std::vector<std::uint8_t>>::Err(geometry.error());
  }
  if (!target_bytes.ok()) {
    return common::Result<std::vector<std::uint8_t>>::Err(target_bytes.error());
  }
  if (source.width > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      source.height > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      source.planes[0].stride >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      source.planes[1].stride >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      geometry.value().scaled_width >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      geometry.value().scaled_height >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      impl_->target_width >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max() / 3)) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("NV12 dimensions exceed libswscale limits"));
  }

  auto mapped_y = MapPlaneReadOnly(source.planes[0]);
  if (!mapped_y.ok()) {
    return common::Result<std::vector<std::uint8_t>>::Err(mapped_y.error());
  }
  auto mapped_uv = MapPlaneReadOnly(source.planes[1]);
  if (!mapped_uv.ok()) {
    return common::Result<std::vector<std::uint8_t>>::Err(mapped_uv.error());
  }

  impl_->sws = sws_getCachedContext(
      impl_->sws,
      static_cast<int>(source.width),
      static_cast<int>(source.height),
      AV_PIX_FMT_NV12,
      static_cast<int>(geometry.value().scaled_width),
      static_cast<int>(geometry.value().scaled_height),
      AV_PIX_FMT_RGB24,
      SWS_BILINEAR,
      nullptr,
      nullptr,
      nullptr);
  if (impl_->sws == nullptr) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("failed to create NV12 conversion context"));
  }

  std::vector<std::uint8_t> rgb;
  try {
    rgb.assign(target_bytes.value(), impl_->padding);
  } catch (const std::bad_alloc&) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("failed to allocate AI model input buffer"));
  } catch (const std::length_error&) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("AI model input buffer size is invalid"));
  }
  const std::uint8_t* source_planes[2] = {mapped_y.value().data,
                                          mapped_uv.value().data};
  int source_strides[2] = {static_cast<int>(source.planes[0].stride),
                           static_cast<int>(source.planes[1].stride)};
  std::uint8_t* target_planes[1] = {
      rgb.data() + ((static_cast<std::size_t>(geometry.value().y_offset) *
                         impl_->target_width +
                     geometry.value().x_offset) *
                    kRgbChannels)};
  int target_strides[1] = {static_cast<int>(impl_->target_width * kRgbChannels)};

  const int scaled_rows = sws_scale(impl_->sws,
                                    source_planes,
                                    source_strides,
                                    0,
                                    static_cast<int>(source.height),
                                    target_planes,
                                    target_strides);
  if (scaled_rows != static_cast<int>(geometry.value().scaled_height)) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("failed to scale NV12 frame to model input"));
  }
  return common::Result<std::vector<std::uint8_t>>::Ok(std::move(rgb));
}

}  // namespace camera_firmware::ai
