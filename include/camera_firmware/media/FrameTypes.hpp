#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace camera_firmware::media {

struct FramePlane {
  int dmabuf_fd{-1};
  std::size_t offset{0};
  std::size_t length{0};
  std::uint32_t stride{0};
};

struct FrameHandle {
  std::string camera_id;
  std::string format;
  std::uint32_t width{0};
  std::uint32_t height{0};
  std::uint64_t sequence{0};
  std::chrono::nanoseconds timestamp{0};
  std::array<FramePlane, 3> planes{};
  std::size_t plane_count{0};
};

struct EncodedAccessUnit {
  std::uint64_t sequence{0};
  std::chrono::nanoseconds timestamp{0};
  bool is_key_frame{false};
  // Immutable, refcounted payload: every ring reader and every downstream
  // consumer (fMP4 mux, RTSP feed) shares one allocation per access unit.
  std::shared_ptr<const std::vector<std::uint8_t>> bytes;
};

}  // namespace camera_firmware::media
