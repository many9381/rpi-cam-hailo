#pragma once

#include <cstdint>
#include <vector>

#include "camera_firmware/ai/AiBackend.hpp"

namespace camera_firmware::ai {

// Reusable model-input canvas. The preprocessor writes the frame's content
// region on every conversion, but the letterbox padding bands only change
// when the source/target geometry changes -- the `padded_*` tag records what
// the padding currently laid out in `bytes` was written for, so a recycled
// buffer skips the full-canvas fill. Nothing downstream may write into the
// buffer (the Hailo backend only reads it during async inference), which is
// what keeps the padding trustworthy across reuses.
struct ModelInputBuffer {
  std::vector<std::uint8_t> bytes;
  std::uint32_t padded_source_width{0};
  std::uint32_t padded_source_height{0};
  bool padded{false};

  [[nodiscard]] InputView view() const noexcept {
    return {bytes.data(), bytes.size()};
  }
};

}  // namespace camera_firmware::ai
