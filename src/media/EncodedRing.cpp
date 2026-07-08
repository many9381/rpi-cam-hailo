#include "camera_firmware/media/EncodedRing.hpp"

#include <cassert>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace camera_firmware::media {

struct EncodedRing::SharedState {
  struct Entry {
    std::uint64_t publish_index{0};
    EncodedAccessUnit access_unit;
  };

  explicit SharedState(std::size_t ring_capacity) : capacity(ring_capacity) {}

  const std::size_t capacity;
  mutable std::mutex mutex;
  std::condition_variable published_cv;
  std::deque<Entry> entries;
  std::uint64_t next_publish_index{0};
  std::uint64_t overrun_total{0};
};

struct EncodedRing::Reader::CursorState {
  std::shared_ptr<SharedState> shared_state;
  std::uint64_t next_publish_index{0};
};

EncodedRing::Reader::Reader(std::shared_ptr<CursorState> cursor_state)
    : cursor_state_(std::move(cursor_state)) {}

std::optional<EncodedAccessUnit> EncodedRing::Reader::WaitNext(
    std::chrono::milliseconds timeout) {
  if (!cursor_state_) {
    return std::nullopt;
  }

  auto state = cursor_state_->shared_state;
  std::unique_lock lock(state->mutex);
  state->published_cv.wait_for(lock, timeout, [&] {
    return state->next_publish_index > cursor_state_->next_publish_index;
  });

  if (state->next_publish_index <= cursor_state_->next_publish_index ||
      state->entries.empty()) {
    return std::nullopt;
  }

  const auto earliest_available = state->entries.front().publish_index;
  const auto latest_available = state->entries.back().publish_index;
  if (cursor_state_->next_publish_index < earliest_available) {
    cursor_state_->next_publish_index = earliest_available;
  }
  if (cursor_state_->next_publish_index > latest_available) {
    return std::nullopt;
  }

  const auto offset = static_cast<std::size_t>(
      cursor_state_->next_publish_index - earliest_available);
  assert(offset < state->entries.size());

  const auto& entry = state->entries[offset];
  cursor_state_->next_publish_index = entry.publish_index + 1;
  return entry.access_unit;
}

bool EncodedRing::Reader::valid() const noexcept {
  return static_cast<bool>(cursor_state_);
}

EncodedRing::EncodedRing(std::size_t capacity)
    : shared_state_(std::make_shared<SharedState>(capacity)) {
  if (capacity == 0) {
    throw std::invalid_argument("EncodedRing capacity must be positive");
  }
}

void EncodedRing::Publish(EncodedAccessUnit access_unit) {
  std::lock_guard lock(shared_state_->mutex);

  if (shared_state_->entries.size() == shared_state_->capacity) {
    shared_state_->entries.pop_front();
    ++shared_state_->overrun_total;
  }

  shared_state_->entries.push_back(SharedState::Entry{
      .publish_index = shared_state_->next_publish_index++,
      .access_unit = std::move(access_unit),
  });
  shared_state_->published_cv.notify_all();
}

EncodedRing::Reader EncodedRing::NewReader() const {
  std::lock_guard lock(shared_state_->mutex);
  auto cursor_state = std::make_shared<Reader::CursorState>();
  cursor_state->shared_state = shared_state_;
  cursor_state->next_publish_index = shared_state_->next_publish_index;
  return Reader(std::move(cursor_state));
}

std::uint64_t EncodedRing::overrun_total() const {
  std::lock_guard lock(shared_state_->mutex);
  return shared_state_->overrun_total;
}

}  // namespace camera_firmware::media
