#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

#include "camera_firmware/media/FrameTypes.hpp"

namespace camera_firmware::media {

class EncodedRing {
 public:
  class Reader {
   public:
    Reader() = default;

    [[nodiscard]] std::optional<EncodedAccessUnit> WaitNext(
        std::chrono::milliseconds timeout);
    [[nodiscard]] bool valid() const noexcept;

   private:
    struct CursorState;

    explicit Reader(std::shared_ptr<CursorState> cursor_state);

    std::shared_ptr<CursorState> cursor_state_;

    friend class EncodedRing;
  };

  explicit EncodedRing(std::size_t capacity);

  void Publish(EncodedAccessUnit access_unit);
  [[nodiscard]] Reader NewReader() const;
  [[nodiscard]] std::uint64_t overrun_total() const;

 private:
  struct SharedState;

  std::shared_ptr<SharedState> shared_state_;
};

}  // namespace camera_firmware::media
