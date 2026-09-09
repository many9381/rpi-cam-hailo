#pragma once

#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <unistd.h>

namespace camera_firmware::ai {

// Page-aligned byte buffer for DMA-facing I/O (hailort output bindings).
// `size` is the requested payload size; `allocated_size` is the page-rounded
// capacity actually backing `data`.
struct PageAlignedBuffer {
  std::size_t size{0};
  std::size_t allocated_size{0};
  std::uint8_t* data{nullptr};

  PageAlignedBuffer() = default;
  PageAlignedBuffer(const PageAlignedBuffer&) = delete;
  PageAlignedBuffer& operator=(const PageAlignedBuffer&) = delete;
  ~PageAlignedBuffer() { std::free(data); }
};

// Free-list of page-aligned buffers so per-frame DMA output allocations
// become steady-state reuses. Acquire() hands out a shared_ptr whose
// deleter returns the buffer to the pool; once the pool itself is gone the
// deleter plainly frees the buffer. Thread-safe: inference submissions
// acquire on the runner thread while completions release from the hailort
// callback thread. Reused buffers are NOT zeroed -- same contract as the
// fresh posix_memalign allocations they replace.
class AlignedBufferPool
    : public std::enable_shared_from_this<AlignedBufferPool> {
 public:
  explicit AlignedBufferPool(std::size_t maximum_retained)
      : maximum_retained_(maximum_retained) {}

  [[nodiscard]] std::shared_ptr<PageAlignedBuffer> Acquire(std::size_t size) {
    if (size == 0U) {
      return nullptr;
    }

    std::unique_ptr<PageAlignedBuffer> buffer;
    {
      std::lock_guard lock(mutex_);
      for (auto it = free_.begin(); it != free_.end(); ++it) {
        if ((*it)->allocated_size >= size) {
          buffer = std::move(*it);
          free_.erase(it);
          break;
        }
      }
    }
    if (buffer == nullptr) {
      buffer = AllocatePageAligned(size);
      if (buffer == nullptr) {
        return nullptr;
      }
    }
    buffer->size = size;

    std::weak_ptr<AlignedBufferPool> weak_pool = weak_from_this();
    return std::shared_ptr<PageAlignedBuffer>(
        buffer.release(), [weak_pool](PageAlignedBuffer* released) {
          if (released == nullptr) {
            return;
          }
          if (const auto pool = weak_pool.lock()) {
            pool->Release(std::unique_ptr<PageAlignedBuffer>(released));
            return;
          }
          delete released;
        });
  }

 private:
  static std::unique_ptr<PageAlignedBuffer> AllocatePageAligned(
      std::size_t size) {
    long page_size = ::sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
      page_size = 4096;
    }
    const auto page = static_cast<std::size_t>(page_size);
    if (size > std::numeric_limits<std::size_t>::max() - page + 1U) {
      return nullptr;
    }
    const std::size_t allocated = ((size + page - 1U) / page) * page;

    void* data = nullptr;
    if (posix_memalign(&data, page, allocated) != 0) {
      return nullptr;
    }
    auto buffer = std::make_unique<PageAlignedBuffer>();
    buffer->size = size;
    buffer->allocated_size = allocated;
    buffer->data = static_cast<std::uint8_t*>(data);
    return buffer;
  }

  void Release(std::unique_ptr<PageAlignedBuffer> buffer) {
    std::lock_guard lock(mutex_);
    if (free_.size() < maximum_retained_) {
      free_.push_back(std::move(buffer));
    }
    // Beyond capacity the unique_ptr frees the buffer on scope exit.
  }

  const std::size_t maximum_retained_;
  std::mutex mutex_;
  std::vector<std::unique_ptr<PageAlignedBuffer>> free_;
};

}  // namespace camera_firmware::ai
