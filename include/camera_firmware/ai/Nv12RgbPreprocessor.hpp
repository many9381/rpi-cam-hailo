#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "camera_firmware/ai/ModelInputBuffer.hpp"
#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::ai {

class Nv12RgbPreprocessor {
 public:
  Nv12RgbPreprocessor(std::uint32_t target_width, std::uint32_t target_height,
                      bool letterbox, std::uint8_t padding = 114U);
  ~Nv12RgbPreprocessor();

  Nv12RgbPreprocessor(const Nv12RgbPreprocessor&) = delete;
  Nv12RgbPreprocessor& operator=(const Nv12RgbPreprocessor&) = delete;

  // Convenience wrapper: converts into a fresh buffer and moves it out.
  [[nodiscard]] common::Result<std::vector<std::uint8_t>> Convert(
      const media::FrameLease& frame);

  // Converts into `canvas`, reusing its storage; the full letterbox pad
  // fill runs only when the canvas geometry tag does not match this frame.
  [[nodiscard]] common::Result<void> ConvertInto(const media::FrameLease& frame,
                                                 ModelInputBuffer& canvas);

 private:
  [[nodiscard]] common::Result<void> ConvertBgr888(
      const media::FrameHandle& source, ModelInputBuffer& canvas);

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::ai
