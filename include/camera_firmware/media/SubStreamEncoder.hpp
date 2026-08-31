#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/media/EncodedRing.hpp"
#include "camera_firmware/media/SubStreamTap.hpp"

namespace camera_firmware::media {

struct SubStreamEncoderParams {
  int src_width{0};
  int src_height{0};   // main stream geometry (e.g. 1920x1080)
  int dst_width{0};
  int dst_height{0};   // sub geometry (e.g. 640x360)
  unsigned int fps{0};
  unsigned int bitrate_kbps{0};
  unsigned int gop{0};
  std::string preset;  // reuse main preset ("ultrafast")
};

// Dedicated worker thread for the RTSP sub-stream: pulls the latest main
// NV12 frame from a SubStreamTap, downscales it with Nv12Downscaler to the
// sub-stream geometry, encodes it with a second (independent) x264 instance,
// and publishes the resulting access unit to a sub EncodedRing.
//
// Mirrors CameraPipeline's own encoder thread (see ConfigureEncoder /
// EncodeBuffer / RunEncoderLoop in CameraPipeline.cpp) but at the
// sub-stream's resolution/fps/bitrate/gop, and it reads pixels from a
// downscaled, tightly-packed NV12 buffer instead of the raw capture dmabuf.
class SubStreamEncoder {
 public:
  SubStreamEncoder(SubStreamTap& tap, EncodedRing& out_ring,
                    SubStreamEncoderParams params);
  ~SubStreamEncoder();  // Stop() if running

  SubStreamEncoder(const SubStreamEncoder&) = delete;
  SubStreamEncoder& operator=(const SubStreamEncoder&) = delete;

  // Opens the sub x264 encoder and spawns the worker thread.
  [[nodiscard]] common::Result<void> Start();

  // Closes the tap (wakes the worker thread), joins it, then closes x264.
  // Safe to call multiple times and safe to call even if Start() was never
  // called or failed.
  void Stop();

  [[nodiscard]] std::uint64_t encoded_frames() const noexcept;
  [[nodiscard]] std::uint64_t error_count() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::media
