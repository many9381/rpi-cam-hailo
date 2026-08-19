#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "camera_firmware/media/FragmentRing.hpp"

class LiveMp4ByteStream {
 public:
  LiveMp4ByteStream(
      camera_firmware::media::FragmentRing::Reader reader,
      std::chrono::milliseconds stale_timeout,
      std::chrono::milliseconds maximum_idle)
      : reader_(std::move(reader)),
        stale_timeout_(stale_timeout),
        maximum_idle_(maximum_idle) {}

  std::size_t Read(char* output, std::size_t capacity) {
    if (capacity == 0U || !reader_.valid()) {
      return 0U;
    }

    const auto idle_started = std::chrono::steady_clock::now();
    while (!current_bytes_ || current_offset_ >= current_bytes_->size()) {
      current_bytes_.reset();
      current_offset_ = 0U;
      auto next = reader_.WaitNext(stale_timeout_);
      if (!next.ok()) {
        return 0U;  // terminal: cancelled / generation replaced
      }
      if (!next.value().has_value()) {
        // Plain timeout tick -- not EOF. Keep waiting until a fragment
        // arrives or the stream has been silent for maximum_idle_.
        if (std::chrono::steady_clock::now() - idle_started >=
            maximum_idle_) {
          return 0U;
        }
        continue;
      }
      if (!next.value()->bytes || next.value()->bytes->empty()) {
        return 0U;
      }
      current_bytes_ = std::move(next).value()->bytes;
    }

    const auto count =
        std::min(capacity, current_bytes_->size() - current_offset_);
    std::copy_n(current_bytes_->data() + current_offset_, count, output);
    current_offset_ += count;
    return count;
  }

  void Cancel() noexcept {
    reader_.Cancel();
  }

 private:
  camera_firmware::media::FragmentRing::Reader reader_;
  const std::chrono::milliseconds stale_timeout_;
  const std::chrono::milliseconds maximum_idle_;
  std::shared_ptr<const std::vector<std::uint8_t>> current_bytes_;
  std::size_t current_offset_{0U};
};
