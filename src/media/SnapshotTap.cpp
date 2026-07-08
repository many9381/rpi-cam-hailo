#include "camera_firmware/media/SnapshotTap.hpp"

#include <jpeglib.h>
#include <setjmp.h>
#include <sys/mman.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace camera_firmware::media {

void SnapshotTap::Publish(FrameLease frame) {
  std::lock_guard lock(mutex_);
  latest_ = std::move(frame);
}

std::optional<FrameLease> SnapshotTap::Latest() const {
  std::lock_guard lock(mutex_);
  if (!latest_.has_value()) {
    return std::nullopt;
  }
  return latest_->CloneRef();
}

namespace {

struct JpegErrorManager {
  jpeg_error_mgr pub;
  jmp_buf jump;
};

void JpegErrorExit(j_common_ptr cinfo) {
  auto* manager = reinterpret_cast<JpegErrorManager*>(cinfo->err);
  longjmp(manager->jump, 1);
}

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
    if (mapping != nullptr && mapping != MAP_FAILED) {
      (void)munmap(mapping, mapping_size);
    }
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

  ~MappedReadPlane() {
    if (mapping != nullptr && mapping != MAP_FAILED) {
      (void)munmap(mapping, mapping_size);
    }
  }
};

std::optional<MappedReadPlane> MapPlaneReadOnly(const FramePlane& plane) {
  if (plane.dmabuf_fd < 0 || plane.length == 0U) {
    return std::nullopt;
  }
  const std::size_t mapping_size = plane.offset + plane.length;
  void* mapping =
      mmap(nullptr, mapping_size, PROT_READ, MAP_SHARED, plane.dmabuf_fd, 0);
  if (mapping == MAP_FAILED) {
    return std::nullopt;
  }
  auto* bytes = static_cast<const std::uint8_t*>(mapping);
  return MappedReadPlane{bytes + plane.offset, plane.length, mapping,
                         mapping_size};
}

std::uint8_t ClampToByte(int value) {
  return static_cast<std::uint8_t>(std::clamp(value, 0, 255));
}

std::vector<std::uint8_t> Nv12ToRgb(const FrameHandle& handle,
                                    const std::uint8_t* y_plane,
                                    const std::uint8_t* uv_plane) {
  std::vector<std::uint8_t> rgb(
      static_cast<std::size_t>(handle.width) * handle.height * 3U);
  const std::uint32_t y_stride = handle.planes[0].stride;
  const std::uint32_t uv_stride = handle.planes[1].stride;

  for (std::uint32_t row = 0; row < handle.height; ++row) {
    for (std::uint32_t column = 0; column < handle.width; ++column) {
      const int y_value =
          y_plane[static_cast<std::size_t>(row) * y_stride + column];
      const std::uint32_t uv_column = (column / 2U) * 2U;
      const std::uint32_t uv_row = row / 2U;
      const std::size_t uv_index =
          static_cast<std::size_t>(uv_row) * uv_stride + uv_column;
      const int u_value = uv_plane[uv_index] - 128;
      const int v_value = uv_plane[uv_index + 1U] - 128;
      const int c = y_value - 16;
      const int d = u_value;
      const int e = v_value;

      const std::size_t output =
          (static_cast<std::size_t>(row) * handle.width + column) * 3U;
      rgb[output] = ClampToByte((298 * c + 409 * e + 128) >> 8);
      rgb[output + 1U] =
          ClampToByte((298 * c - 100 * d - 208 * e + 128) >> 8);
      rgb[output + 2U] = ClampToByte((298 * c + 516 * d + 128) >> 8);
    }
  }
  return rgb;
}

std::optional<std::vector<std::uint8_t>> EncodeRgbJpeg(
    const FrameHandle& handle,
    const std::vector<std::uint8_t>& rgb) {
  jpeg_compress_struct cinfo{};
  JpegErrorManager error{};
  cinfo.err = jpeg_std_error(&error.pub);
  error.pub.error_exit = JpegErrorExit;
  if (setjmp(error.jump) != 0) {
    jpeg_destroy_compress(&cinfo);
    return std::nullopt;
  }

  jpeg_create_compress(&cinfo);
  unsigned char* output = nullptr;
  unsigned long output_size = 0;
  jpeg_mem_dest(&cinfo, &output, &output_size);
  cinfo.image_width = handle.width;
  cinfo.image_height = handle.height;
  cinfo.input_components = 3;
  cinfo.in_color_space = JCS_RGB;
  jpeg_set_defaults(&cinfo);
  jpeg_set_quality(&cinfo, 85, TRUE);
  jpeg_start_compress(&cinfo, TRUE);

  while (cinfo.next_scanline < cinfo.image_height) {
    JSAMPROW row = const_cast<JSAMPROW>(
        rgb.data() + static_cast<std::size_t>(cinfo.next_scanline) *
                         handle.width * 3U);
    jpeg_write_scanlines(&cinfo, &row, 1);
  }
  jpeg_finish_compress(&cinfo);

  std::vector<std::uint8_t> jpeg(output, output + output_size);
  std::free(output);
  jpeg_destroy_compress(&cinfo);
  return jpeg;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> BuildLatestSnapshotJpeg(
    const SnapshotTap& tap,
    std::string_view camera_id) {
  auto latest = tap.Latest();
  if (!latest.has_value() || !latest->valid()) {
    return std::nullopt;
  }
  const FrameHandle& handle = latest->handle();
  if (handle.camera_id != camera_id || handle.format != "NV12" ||
      handle.width == 0U || handle.height == 0U || handle.plane_count < 2U) {
    return std::nullopt;
  }

  auto y_plane = MapPlaneReadOnly(handle.planes[0]);
  auto uv_plane = MapPlaneReadOnly(handle.planes[1]);
  if (!y_plane.has_value() || !uv_plane.has_value()) {
    return std::nullopt;
  }
  const std::size_t y_required =
      static_cast<std::size_t>(handle.planes[0].stride) * handle.height;
  const std::size_t uv_required =
      static_cast<std::size_t>(handle.planes[1].stride) *
      ((handle.height + 1U) / 2U);
  if (y_plane->size < y_required || uv_plane->size < uv_required) {
    return std::nullopt;
  }

  auto rgb = Nv12ToRgb(handle, y_plane->data, uv_plane->data);
  return EncodeRgbJpeg(handle, rgb);
}

}  // namespace camera_firmware::media
