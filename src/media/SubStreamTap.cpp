#include "camera_firmware/media/SubStreamTap.hpp"

#include <utility>

namespace camera_firmware::media {

bool SubStreamTap::ConsumeDemand() noexcept {
  std::lock_guard lock(mutex_);
  if (!active_ || closed_) {
    return false;
  }
  const bool demanded = wants_frame_;
  wants_frame_ = false;
  return demanded;
}

void SubStreamTap::PublishLatest(FrameLease frame) {
  std::optional<FrameLease> superseded;
  {
    std::lock_guard lock(mutex_);
    superseded = std::move(pending_);
    pending_ = std::move(frame);
  }
  cv_.notify_one();
  // superseded's lease releases here, off the lock, requeuing its buffer.
}

std::optional<FrameLease> SubStreamTap::WaitNext(std::chrono::milliseconds timeout) {
  std::unique_lock lock(mutex_);
  cv_.wait_for(lock, timeout,
               [this] { return pending_.has_value() || !active_ || closed_; });
  if (active_ && !closed_ && pending_.has_value()) {
    std::optional<FrameLease> frame = std::move(pending_);
    pending_.reset();
    return frame;
  }
  return std::nullopt;
}

void SubStreamTap::RequestNext() noexcept {
  std::lock_guard lock(mutex_);
  wants_frame_ = true;
}

void SubStreamTap::SetActive(bool active) noexcept {
  std::optional<FrameLease> dropped;
  {
    std::lock_guard lock(mutex_);
    active_ = active;
    if (!active_) {
      dropped = std::move(pending_);
      pending_.reset();
      wants_frame_ = false;
    }
  }
  cv_.notify_all();
  // dropped's lease releases here, off the lock, requeuing its buffer.
}

bool SubStreamTap::active() const noexcept {
  std::lock_guard lock(mutex_);
  return active_;
}

void SubStreamTap::Close() noexcept {
  std::optional<FrameLease> dropped;
  {
    std::lock_guard lock(mutex_);
    closed_ = true;
    dropped = std::move(pending_);
    pending_.reset();
    wants_frame_ = false;
  }
  cv_.notify_all();
  // dropped's lease releases here, off the lock, requeuing its buffer.
}

}  // namespace camera_firmware::media
