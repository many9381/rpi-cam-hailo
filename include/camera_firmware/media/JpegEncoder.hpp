#pragma once

#include <cstdint>
#include <vector>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::media {

struct JpegImage {
  unsigned int width{0};
  unsigned int height{0};
  std::vector<std::uint8_t> bytes;
};

[[nodiscard]] common::Result<JpegImage> EncodeNv12Jpeg(
    const FrameLease& frame,
    unsigned int maximum_width,
    unsigned int quality);

}  // namespace camera_firmware::media
