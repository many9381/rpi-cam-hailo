#pragma once

#include <cstdint>
#include <vector>

struct SwsContext;

namespace camera_firmware::media {

// A view of NV12 pixels the caller owns. Plane 0 is Y (`width` bytes per
// row), plane 1 is interleaved CbCr at half height (`width` bytes per row).
struct Nv12Plane {
  const std::uint8_t* y{nullptr};   // Y plane
  const std::uint8_t* uv{nullptr};  // interleaved CbCr plane
  int y_stride{0};
  int uv_stride{0};
  int width{0};
  int height{0};
};

// Downscales a fixed-geometry NV12 frame to a smaller fixed-geometry NV12
// frame via libswscale, reusing a single SwsContext across calls. Intended
// for producing an RTSP sub-stream's input from the main capture frame.
class Nv12Downscaler {
 public:
  Nv12Downscaler(int src_width, int src_height, int dst_width, int dst_height);
  ~Nv12Downscaler();

  Nv12Downscaler(const Nv12Downscaler&) = delete;
  Nv12Downscaler& operator=(const Nv12Downscaler&) = delete;

  [[nodiscard]] bool valid() const noexcept;  // sws context created
  [[nodiscard]] int dst_width() const noexcept;
  [[nodiscard]] int dst_height() const noexcept;

  // Scales src into a tightly-packed dst NV12 buffer: Y then interleaved UV.
  // dst_out is resized to dst_width*dst_height*3/2. Returns false on geometry
  // mismatch or an inactive sws context.
  [[nodiscard]] bool Scale(const Nv12Plane& src, std::vector<std::uint8_t>& dst_out);

 private:
  int src_width_{0};
  int src_height_{0};
  int dst_width_{0};
  int dst_height_{0};
  SwsContext* sws_{nullptr};
};

}  // namespace camera_firmware::media
