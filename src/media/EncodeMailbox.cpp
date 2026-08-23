#include "camera_firmware/media/EncodeMailbox.hpp"

#include <utility>

namespace camera_firmware::media {

void EncodeMailbox::Publish(EncodeJob job) {
  std::optional<EncodeJob> superseded;
  {
    std::scoped_lock lock(mutex_);
    if (closed_) {
      // Drop outside the lock below; the lease release must not run here.
      superseded = std::move(job);
    } else {
      superseded = std::move(pending_);
      pending_ = std::move(job);
    }
  }
  cv_.notify_one();
  // superseded's lease releases here, off the lock, requeuing its buffer.
}

std::optional<EncodeJob> EncodeMailbox::Take() {
  std::optional<EncodeJob> job;
  {
    std::unique_lock lock(mutex_);
    cv_.wait(lock, [this] { return pending_.has_value() || closed_; });
    if (closed_) {
      return std::nullopt;
    }
    job = std::move(pending_);
    pending_.reset();
  }
  return job;
}

void EncodeMailbox::Close() {
  std::optional<EncodeJob> dropped;
  {
    std::scoped_lock lock(mutex_);
    closed_ = true;
    dropped = std::move(pending_);
    pending_.reset();
  }
  cv_.notify_all();
  // dropped's lease releases here, off the lock, requeuing its buffer.
}

void EncodeMailbox::Reopen() {
  std::optional<EncodeJob> dropped;
  {
    std::scoped_lock lock(mutex_);
    closed_ = false;
    dropped = std::move(pending_);
    pending_.reset();
  }
  // dropped's lease releases here, off the lock.
}

}  // namespace camera_firmware::media
