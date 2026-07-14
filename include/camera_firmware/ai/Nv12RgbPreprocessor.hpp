#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::ai {

class Nv12RgbPreprocessor {
 public:
  Nv12RgbPreprocessor(std::uint32_t target_width,
                      std::uint32_t target_height,
                      bool letterbox,
                      std::uint8_t padding = 114U);
  ~Nv12RgbPreprocessor();

  Nv12RgbPreprocessor(const Nv12RgbPreprocessor&) = delete;
  Nv12RgbPreprocessor& operator=(const Nv12RgbPreprocessor&) = delete;

  [[nodiscard]] common::Result<std::vector<std::uint8_t>> Convert(
      const media::FrameLease& frame);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::ai
