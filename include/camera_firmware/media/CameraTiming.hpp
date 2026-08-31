#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"

namespace camera_firmware::media {

[[nodiscard]] common::Result<std::array<std::int64_t, 2>>
FixedFrameDurationLimits(unsigned int fps);

struct X264RuntimePolicy {
  std::string preset;
  int threads{0};
  int vbv_max_bitrate_kbps{0};
  int vbv_buffer_size_kbits{0};
};

[[nodiscard]] X264RuntimePolicy ResolveX264RuntimePolicy(
    const config::CameraEncoderConfig& config);

class FrameRateEstimator {
 public:
  explicit FrameRateEstimator(std::size_t maximum_samples = 101U);

  void Record(std::chrono::nanoseconds timestamp);
  void Reset();
  [[nodiscard]] double FramesPerSecond() const;
  [[nodiscard]] std::size_t sample_count() const noexcept;

 private:
  std::size_t maximum_samples_;
  std::deque<std::chrono::nanoseconds> samples_;
};

}  // namespace camera_firmware::media
