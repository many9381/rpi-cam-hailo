#include "camera_firmware/media/CameraTiming.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace camera_firmware::media {

common::Result<std::array<std::int64_t, 2>> FixedFrameDurationLimits(
    unsigned int fps) {
  constexpr std::uint64_t kMicrosecondsPerSecond = 1000000U;
  constexpr unsigned int kMaximumRepresentableFps = 2000000U;
  if (fps == 0U || fps > kMaximumRepresentableFps) {
    return common::Result<std::array<std::int64_t, 2>>::Err(
        {"E_CAMERA_FRAME_RATE",
         "camera fps cannot be represented as a libcamera frame duration"});
  }

  const auto duration =
      static_cast<std::int64_t>((kMicrosecondsPerSecond + (fps / 2U)) / fps);
  return common::Result<std::array<std::int64_t, 2>>::Ok({duration, duration});
}

X264RuntimePolicy ResolveX264RuntimePolicy(
    const config::CameraEncoderConfig& config) {
  return {.preset = config.preset,
          .threads = 0,
          .vbv_max_bitrate_kbps = static_cast<int>(config.bitrate_kbps),
          .vbv_buffer_size_kbits = static_cast<int>(config.bitrate_kbps / 2U)};
}

FrameRateEstimator::FrameRateEstimator(std::size_t maximum_samples)
    : maximum_samples_(maximum_samples < 2U ? 2U : maximum_samples) {}

void FrameRateEstimator::Record(std::chrono::nanoseconds timestamp) {
  if (!samples_.empty() && timestamp <= samples_.back()) {
    samples_.clear();
  }
  samples_.push_back(timestamp);
  while (samples_.size() > maximum_samples_) {
    samples_.pop_front();
  }
}

void FrameRateEstimator::Reset() {
  samples_.clear();
}

double FrameRateEstimator::FramesPerSecond() const {
  if (samples_.size() < 2U) {
    return 0.0;
  }
  const auto elapsed = samples_.back() - samples_.front();
  if (elapsed.count() <= 0) {
    return 0.0;
  }
  constexpr double kNanosecondsPerSecond = 1000000000.0;
  return static_cast<double>(samples_.size() - 1U) * kNanosecondsPerSecond /
         static_cast<double>(elapsed.count());
}

std::size_t FrameRateEstimator::sample_count() const noexcept {
  return samples_.size();
}

}  // namespace camera_firmware::media
