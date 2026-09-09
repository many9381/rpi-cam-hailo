#pragma once

#include <cstdint>
#include <vector>

#include <string>
#include "camera_firmware/common/Result.hpp"

#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::media {

// JPEG payload container: std::string so the bytes can be moved
// straight into an HTTP response body without a copy.
using JpegBytes = std::string;

struct JpegImage {
  unsigned int width{0};
  unsigned int height{0};
  JpegBytes bytes;
};

[[nodiscard]] common::Result<JpegImage> EncodeNv12Jpeg(
    const FrameLease& frame, unsigned int maximum_width, unsigned int quality);

}  // namespace camera_firmware::media
