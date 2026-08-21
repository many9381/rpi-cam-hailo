#pragma once

#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "camera_firmware/ai/ModelInputBuffer.hpp"

namespace camera_firmware::ai {

// Small free-list of ModelInputBuffers so the AI path stops paying a
// ~1.2MB allocation + full pad fill per frame. Acquire() hands out a
// shared_ptr whose deleter returns the buffer to the pool; when the pool
// itself is gone (runner torn down while an async inference still holds a
// buffer), the deleter simply frees it. Thread-safe: buffers are acquired
// on the runner worker thread and released from the Hailo completion
// callback thread.
class ModelInputBufferPool
    : public std::enable_shared_from_this<ModelInputBufferPool> {
 public:
  explicit ModelInputBufferPool(std::size_t maximum_retained)
      : maximum_retained_(maximum_retained) {}

  [[nodiscard]] std::shared_ptr<ModelInputBuffer> Acquire() {
    std::unique_ptr<ModelInputBuffer> buffer;
    {
      std::lock_guard lock(mutex_);
      if (!free_.empty()) {
        buffer = std::move(free_.back());
        free_.pop_back();
      }
    }
    if (buffer == nullptr) {
      buffer = std::make_unique<ModelInputBuffer>();
    }
    std::weak_ptr<ModelInputBufferPool> weak_pool = weak_from_this();
    return std::shared_ptr<ModelInputBuffer>(
        buffer.release(), [weak_pool](ModelInputBuffer* released) {
          if (released == nullptr) {
            return;
          }
          if (const auto pool = weak_pool.lock()) {
            pool->Release(std::unique_ptr<ModelInputBuffer>(released));
            return;
          }
          delete released;
        });
  }

 private:
  void Release(std::unique_ptr<ModelInputBuffer> buffer) {
    std::lock_guard lock(mutex_);
    if (free_.size() < maximum_retained_) {
      free_.push_back(std::move(buffer));
    }
    // Beyond capacity the unique_ptr frees the buffer on scope exit.
  }

  const std::size_t maximum_retained_;
  std::mutex mutex_;
  std::vector<std::unique_ptr<ModelInputBuffer>> free_;
};

}  // namespace camera_firmware::ai
