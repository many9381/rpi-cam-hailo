#include "camera_firmware/media/JpegEncoder.hpp"

#include <fcntl.h>
#include <linux/dma-buf.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <jpeglib.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace camera_firmware::media {
namespace {

common::Result<JpegImage> EncodeError(const char* message) {
  return common::Result<JpegImage>::Err({"E_JPEG_ENCODE", message});
}

bool CheckedAdd(std::size_t left,
                std::size_t right,
                std::size_t& result) {
  if (left > std::numeric_limits<std::size_t>::max() - right) {
    return false;
  }
  result = left + right;
  return true;
}

bool CheckedMultiply(std::size_t left,
                     std::size_t right,
                     std::size_t& result) {
  if (left != 0U && right > std::numeric_limits<std::size_t>::max() / left) {
    return false;
  }
  result = left * right;
  return true;
}

bool IsMemfdTestBackend(int fd) {
  // Unit tests use memfds; real DMA-BUF fds do not support file seals.
  struct stat status {};
  return ::fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
         ::fcntl(fd, F_GET_SEALS) >= 0;
}

bool SyncDmaBuf(int fd, std::uint64_t flags) {
  dma_buf_sync sync{.flags = flags};
  int status = 0;
  do {
    status = ::ioctl(fd, DMA_BUF_IOCTL_SYNC, &sync);
  } while (status != 0 && errno == EINTR);
  if (status == 0) {
    return true;
  }
  const int sync_error = errno;
  return sync_error == ENOTTY && IsMemfdTestBackend(fd);
}

class DmaBufReadSession {
 public:
  DmaBufReadSession() = default;
  DmaBufReadSession(const DmaBufReadSession&) = delete;
  DmaBufReadSession& operator=(const DmaBufReadSession&) = delete;

  ~DmaBufReadSession() { (void)End(); }

  bool Start(int fd) {
    for (std::size_t index = 0U; index < active_count_; ++index) {
      if (active_fds_[index] == fd) {
        return true;
      }
    }
    if (active_count_ >= active_fds_.size() ||
        !SyncDmaBuf(fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ)) {
      return false;
    }
    active_fds_[active_count_++] = fd;
    return true;
  }

  bool End() {
    bool success = true;
    while (active_count_ > 0U) {
      const int fd = active_fds_[active_count_ - 1U];
      const bool ended =
          SyncDmaBuf(fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ);
      --active_count_;
      if (!ended) {
        success = false;
      }
    }
    return success;
  }

 private:
  std::array<int, 2U> active_fds_{};
  std::size_t active_count_{0U};
};

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
      : data(std::exchange(other.data, nullptr)),
        size(std::exchange(other.size, 0U)),
        mapping(std::exchange(other.mapping, nullptr)),
        mapping_size(std::exchange(other.mapping_size, 0U)) {}
  MappedReadPlane& operator=(MappedReadPlane&&) = delete;

  ~MappedReadPlane() {
    if (mapping != nullptr && mapping != MAP_FAILED) {
      (void)::munmap(mapping, mapping_size);
    }
  }
};

std::optional<MappedReadPlane> MapPlaneReadOnly(const FramePlane& plane) {
  if (plane.dmabuf_fd < 0 || plane.length == 0U) {
    return std::nullopt;
  }

  std::size_t mapping_size = 0U;
  if (!CheckedAdd(plane.offset, plane.length, mapping_size) ||
      mapping_size == 0U) {
    return std::nullopt;
  }

  struct stat backing {};
  if (::fstat(plane.dmabuf_fd, &backing) != 0 || backing.st_size < 0 ||
      static_cast<std::uintmax_t>(mapping_size) >
          static_cast<std::uintmax_t>(backing.st_size)) {
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

bool PlaneContainsRows(const FramePlane& plane,
                       std::size_t row_bytes,
                       std::size_t rows) {
  if (rows == 0U || row_bytes == 0U || plane.stride < row_bytes) {
    return false;
  }

  std::size_t preceding_rows = 0U;
  std::size_t required = 0U;
  return CheckedMultiply(rows - 1U, plane.stride, preceding_rows) &&
         CheckedAdd(preceding_rows, row_bytes, required) &&
         required <= plane.length;
}

std::optional<unsigned int> ScaledEvenHeight(const FrameHandle& source,
                                              unsigned int output_width) {
  const std::uint64_t source_height = source.height;
  const std::uint64_t scaled_product =
      source_height * static_cast<std::uint64_t>(output_width);
  std::uint64_t output_height = scaled_product / source.width;
  output_height = std::max<std::uint64_t>(output_height, 1U);

  if ((output_height & 1U) != 0U) {
    if (output_height < source.height) {
      ++output_height;
    } else {
      --output_height;
    }
  }

  if (output_height == 0U || output_height > source.height ||
      output_height > std::numeric_limits<unsigned int>::max()) {
    return std::nullopt;
  }
  return static_cast<unsigned int>(output_height);
}

std::optional<std::size_t> RgbByteCount(unsigned int width,
                                        unsigned int height) {
  std::size_t row_bytes = 0U;
  std::size_t byte_count = 0U;
  if (!CheckedMultiply(width, 3U, row_bytes) ||
      !CheckedMultiply(row_bytes, height, byte_count)) {
    return std::nullopt;
  }
  return byte_count;
}

std::uint8_t ClampToByte(int value) {
  return static_cast<std::uint8_t>(std::clamp(value, 0, 255));
}

void ConvertScaledNv12ToRgb(const FrameHandle& source,
                            const MappedReadPlane& y_plane,
                            const MappedReadPlane& uv_plane,
                            unsigned int output_width,
                            unsigned int output_height,
                            std::vector<std::uint8_t>& rgb) {
  for (unsigned int row = 0U; row < output_height; ++row) {
    const std::size_t source_row =
        static_cast<std::uint64_t>(row) * source.height / output_height;
    for (unsigned int column = 0U; column < output_width; ++column) {
      const std::size_t source_column =
          static_cast<std::uint64_t>(column) * source.width / output_width;
      const std::size_t y_index =
          source_row * source.planes[0].stride + source_column;
      const std::size_t uv_index =
          (source_row / 2U) * source.planes[1].stride +
          (source_column / 2U) * 2U;
      const int y = y_plane.data[y_index];
      const int u = uv_plane.data[uv_index] - 128;
      const int v = uv_plane.data[uv_index + 1U] - 128;
      const int adjusted_y = y - 16;

      const std::size_t output_index =
          (static_cast<std::size_t>(row) * output_width + column) * 3U;
      rgb[output_index] =
          ClampToByte((298 * adjusted_y + 409 * v + 128) >> 8);
      rgb[output_index + 1U] = ClampToByte(
          (298 * adjusted_y - 100 * u - 208 * v + 128) >> 8);
      rgb[output_index + 2U] =
          ClampToByte((298 * adjusted_y + 516 * u + 128) >> 8);
    }
  }
}

struct JpegErrorManager {
  jpeg_error_mgr pub;
  jmp_buf jump;
};

struct JpegCompressionState {
  jpeg_compress_struct compressor{};
  JpegErrorManager error{};
  unsigned char* output{nullptr};
  unsigned long output_size{0U};
  bool creation_attempted{false};
};

void JpegErrorExit(j_common_ptr cinfo) {
  auto* manager = reinterpret_cast<JpegErrorManager*>(cinfo->err);
  longjmp(manager->jump, 1);
}

void SuppressJpegMessage(j_common_ptr) {}

common::Result<JpegImage> EncodeRgbJpeg(unsigned int width,
                                       unsigned int height,
                                       unsigned int quality,
                                       const std::vector<std::uint8_t>& rgb) {
  std::unique_ptr<JpegCompressionState> state;
  try {
    state = std::make_unique<JpegCompressionState>();
  } catch (const std::bad_alloc&) {
    return EncodeError("JPEG compressor allocation failed");
  }
  state->compressor.err = jpeg_std_error(&state->error.pub);
  state->error.pub.error_exit = JpegErrorExit;
  state->error.pub.output_message = SuppressJpegMessage;

  if (setjmp(state->error.jump) != 0) {
    if (state->creation_attempted) {
      jpeg_destroy_compress(&state->compressor);
    }
    std::free(state->output);
    return EncodeError("libjpeg failed to encode the frame");
  }

  state->creation_attempted = true;
  jpeg_create_compress(&state->compressor);
  jpeg_mem_dest(&state->compressor, &state->output, &state->output_size);
  state->compressor.image_width = width;
  state->compressor.image_height = height;
  state->compressor.input_components = 3;
  state->compressor.in_color_space = JCS_RGB;
  jpeg_set_defaults(&state->compressor);
  jpeg_set_quality(&state->compressor, static_cast<int>(quality), TRUE);
  jpeg_start_compress(&state->compressor, TRUE);

  const std::size_t row_bytes = static_cast<std::size_t>(width) * 3U;
  while (state->compressor.next_scanline < state->compressor.image_height) {
    JSAMPROW row = const_cast<JSAMPROW>(
        rgb.data() + state->compressor.next_scanline * row_bytes);
    (void)jpeg_write_scanlines(&state->compressor, &row, 1U);
  }
  jpeg_finish_compress(&state->compressor);
  jpeg_destroy_compress(&state->compressor);
  state->creation_attempted = false;

  if (state->output == nullptr ||
      state->output_size > std::numeric_limits<std::size_t>::max() ||
      state->output_size > JpegImage{}.bytes.max_size()) {
    std::free(state->output);
    return EncodeError("libjpeg returned an invalid output buffer");
  }

  JpegImage image;
  image.width = width;
  image.height = height;
  try {
    image.bytes.assign(state->output, state->output + state->output_size);
  } catch (const std::bad_alloc&) {
    std::free(state->output);
    return EncodeError("JPEG output allocation failed");
  }
  std::free(state->output);
  return common::Result<JpegImage>::Ok(std::move(image));
}

}  // namespace

common::Result<JpegImage> EncodeNv12Jpeg(const FrameLease& frame,
                                         unsigned int maximum_width,
                                         unsigned int quality) {
  if (!frame.valid() || maximum_width == 0U || quality == 0U ||
      quality > 100U) {
    return EncodeError("invalid JPEG encoding parameters");
  }

  const FrameHandle& source = frame.handle();
  if (source.format != "NV12" || source.width == 0U || source.height < 2U ||
      source.plane_count < 2U) {
    return EncodeError("frame is not a supported NV12 image");
  }

  const unsigned int output_width = std::min(maximum_width, source.width);
  const auto output_height = ScaledEvenHeight(source, output_width);
  if (!output_height.has_value()) {
    return EncodeError("scaled JPEG dimensions are invalid");
  }

  const std::size_t chroma_columns =
      static_cast<std::size_t>(source.width) / 2U + source.width % 2U;
  std::size_t chroma_row_bytes = 0U;
  if (!CheckedMultiply(chroma_columns, 2U, chroma_row_bytes)) {
    return EncodeError("NV12 chroma dimensions overflow");
  }
  const std::size_t chroma_rows =
      static_cast<std::size_t>(source.height) / 2U + source.height % 2U;
  if (!PlaneContainsRows(source.planes[0], source.width, source.height) ||
      !PlaneContainsRows(source.planes[1], chroma_row_bytes, chroma_rows)) {
    return EncodeError("NV12 plane lengths or strides are invalid");
  }

  DmaBufReadSession read_session;
  if (!read_session.Start(source.planes[0].dmabuf_fd) ||
      !read_session.Start(source.planes[1].dmabuf_fd)) {
    return EncodeError("DMA-BUF read synchronization failed");
  }

  auto y_plane = MapPlaneReadOnly(source.planes[0]);
  auto uv_plane = MapPlaneReadOnly(source.planes[1]);
  if (!y_plane.has_value() || !uv_plane.has_value()) {
    return EncodeError("NV12 planes could not be mapped safely");
  }

  const auto rgb_byte_count = RgbByteCount(output_width, *output_height);
  if (!rgb_byte_count.has_value()) {
    return EncodeError("RGB output dimensions overflow");
  }

  std::vector<std::uint8_t> rgb;
  if (*rgb_byte_count > rgb.max_size()) {
    return EncodeError("RGB output dimensions exceed allocation limits");
  }
  try {
    rgb.resize(*rgb_byte_count);
  } catch (const std::length_error&) {
    return EncodeError("RGB output dimensions exceed allocation limits");
  } catch (const std::bad_alloc&) {
    return EncodeError("RGB output allocation failed");
  }
  ConvertScaledNv12ToRgb(source, *y_plane, *uv_plane, output_width,
                         *output_height, rgb);
  if (!read_session.End()) {
    return EncodeError("DMA-BUF read synchronization failed");
  }
  return EncodeRgbJpeg(output_width, *output_height, quality, rgb);
}

}  // namespace camera_firmware::media
