#include "camera_firmware/media/Nv12Downscaler.hpp"

#include <cstddef>

extern "C" {
#include <libavutil/pixfmt.h>
#include <libswscale/swscale.h>
}

namespace camera_firmware::media {

Nv12Downscaler::Nv12Downscaler(int src_width, int src_height, int dst_width,
                               int dst_height)
    : src_width_(src_width),
      src_height_(src_height),
      dst_width_(dst_width),
      dst_height_(dst_height) {
  sws_ = sws_getContext(src_width_, src_height_, AV_PIX_FMT_NV12, dst_width_,
                        dst_height_, AV_PIX_FMT_NV12, SWS_BILINEAR, nullptr,
                        nullptr, nullptr);
}

Nv12Downscaler::~Nv12Downscaler() {
  sws_freeContext(sws_);
}

bool Nv12Downscaler::valid() const noexcept {
  return sws_ != nullptr;
}

int Nv12Downscaler::dst_width() const noexcept {
  return dst_width_;
}

int Nv12Downscaler::dst_height() const noexcept {
  return dst_height_;
}

bool Nv12Downscaler::Scale(const Nv12Plane& src,
                           std::vector<std::uint8_t>& dst_out) {
  if (sws_ == nullptr) {
    return false;
  }
  if (src.width != src_width_ || src.height != src_height_) {
    return false;
  }

  const std::size_t dst_bytes =
      static_cast<std::size_t>(dst_width_) * dst_height_ * 3 / 2;
  dst_out.resize(dst_bytes);

  const std::uint8_t* src_slice[2] = {src.y, src.uv};
  int src_stride[2] = {src.y_stride, src.uv_stride};
  std::uint8_t* dst_slice[2] = {
      dst_out.data(),
      dst_out.data() + static_cast<std::size_t>(dst_width_) * dst_height_};
  int dst_stride[2] = {dst_width_, dst_width_};

  const int scaled_rows = sws_scale(sws_, src_slice, src_stride, 0, src_height_,
                                    dst_slice, dst_stride);
  return scaled_rows == dst_height_;
}

}  // namespace camera_firmware::media
