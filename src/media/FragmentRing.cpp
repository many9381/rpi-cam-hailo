#include "camera_firmware/media/FragmentRing.hpp"

#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace camera_firmware::media {

struct FragmentRing::SharedState {
  struct Entry {
    std::uint64_t sequence{0U};
    bool random_access{false};
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;
  };

  SharedState(FragmentRingLimits configured_limits, NowCallback configured_now)
      : limits(configured_limits), now(std::move(configured_now)) {}

  const FragmentRingLimits limits;
  const NowCallback now;
  mutable std::mutex mutex;
  std::condition_variable changed;
  std::shared_ptr<const std::vector<std::uint8_t>> initialization_segment;
  std::deque<Entry> fragments;
  std::uint64_t generation{0U};
  std::uint64_t next_fragment_sequence{1U};
  std::uint64_t overrun_total{0U};
  std::size_t retained_bytes{0U};
  std::size_t active_readers{0U};
  std::size_t waiting_readers{0U};
  std::optional<Clock::time_point> last_publication_at;
  bool available{false};
};

struct FragmentRing::Reader::CursorState {
  ~CursorState() {
    if (!state) {
      return;
    }
    std::lock_guard lock(state->mutex);
    if (!reader_slot_released) {
      assert(state->active_readers > 0U);
      --state->active_readers;
      reader_slot_released = true;
    }
    state->changed.notify_all();
  }

  std::shared_ptr<SharedState> state;
  std::uint64_t generation{0U};
  std::uint64_t next_fragment_sequence{1U};
  bool initialization_pending{true};
  bool cancelled{false};
  bool reader_slot_released{false};
};

FragmentRing::Reader::Reader(std::shared_ptr<CursorState> cursor)
    : cursor_(std::move(cursor)) {}

common::Result<std::optional<FragmentedMp4Chunk>>
FragmentRing::Reader::WaitNext(std::chrono::milliseconds timeout) {
  using Result = common::Result<std::optional<FragmentedMp4Chunk>>;
  if (!cursor_ || !cursor_->state) {
    return Result::Err({"E_LIVE_READER", "live stream reader is not active"});
  }

  const auto state = cursor_->state;
  std::unique_lock lock(state->mutex);
  const auto generation_valid = [&] {
    return state->available && state->generation == cursor_->generation;
  };
  if (cursor_->cancelled) {
    return Result::Err(
        {"E_LIVE_CANCELLED", "live stream reader was cancelled"});
  }
  if (!generation_valid()) {
    return Result::Err(
        {"E_LIVE_GENERATION", "live stream generation is no longer active"});
  }

  if (cursor_->initialization_pending) {
    cursor_->initialization_pending = false;
    return Result::Ok(FragmentedMp4Chunk{
        .kind = FragmentedMp4ChunkKind::kInitialization,
        .generation = cursor_->generation,
        .sequence = 0U,
        .random_access = true,
        .bytes = state->initialization_segment,
    });
  }

  ++state->waiting_readers;
  try {
    state->changed.wait_for(lock, timeout, [&] {
      return cursor_->cancelled || !generation_valid() ||
             state->next_fragment_sequence > cursor_->next_fragment_sequence;
    });
  } catch (...) {
    assert(state->waiting_readers > 0U);
    --state->waiting_readers;
    throw;
  }
  assert(state->waiting_readers > 0U);
  --state->waiting_readers;
  if (cursor_->cancelled) {
    return Result::Err(
        {"E_LIVE_CANCELLED", "live stream reader was cancelled"});
  }
  if (!generation_valid()) {
    return Result::Err(
        {"E_LIVE_GENERATION", "live stream generation is no longer active"});
  }
  if (state->fragments.empty() ||
      state->next_fragment_sequence <= cursor_->next_fragment_sequence) {
    return Result::Ok(std::nullopt);
  }

  const auto earliest = state->fragments.front().sequence;
  const auto latest = state->fragments.back().sequence;
  if (cursor_->next_fragment_sequence < earliest) {
    const auto latest_random_access =
        std::find_if(state->fragments.rbegin(), state->fragments.rend(),
                     [](const auto& entry) { return entry.random_access; });
    if (latest_random_access == state->fragments.rend()) {
      cursor_->next_fragment_sequence = state->next_fragment_sequence;
      return Result::Ok(std::nullopt);
    }
    cursor_->next_fragment_sequence = latest_random_access->sequence;
  }
  if (cursor_->next_fragment_sequence > latest) {
    return Result::Ok(std::nullopt);
  }

  const auto offset = static_cast<std::size_t>(
      cursor_->next_fragment_sequence - earliest);
  assert(offset < state->fragments.size());
  const auto& entry = state->fragments[offset];
  cursor_->next_fragment_sequence = entry.sequence + 1U;
  return Result::Ok(FragmentedMp4Chunk{
      .kind = FragmentedMp4ChunkKind::kMediaFragment,
      .generation = cursor_->generation,
      .sequence = entry.sequence,
      .random_access = entry.random_access,
      .bytes = entry.bytes,
  });
}

void FragmentRing::Reader::Cancel() noexcept {
  const auto cursor = cursor_;
  if (!cursor || !cursor->state) {
    return;
  }
  const auto state = cursor->state;
  std::lock_guard lock(state->mutex);
  cursor->cancelled = true;
  if (!cursor->reader_slot_released) {
    assert(state->active_readers > 0U);
    --state->active_readers;
    cursor->reader_slot_released = true;
  }
  state->changed.notify_all();
}

bool FragmentRing::Reader::valid() const noexcept {
  const auto cursor = cursor_;
  if (!cursor || !cursor->state) {
    return false;
  }
  std::lock_guard lock(cursor->state->mutex);
  return !cursor->cancelled;
}

FragmentRing::FragmentRing(FragmentRingLimits limits)
    : FragmentRing(limits, [] { return Clock::now(); }) {}

FragmentRing::FragmentRing(FragmentRingLimits limits, NowCallback now)
    : state_(std::make_shared<SharedState>(limits, std::move(now))) {
  if (limits.max_fragments == 0U || limits.max_bytes == 0U ||
      limits.max_readers == 0U || !state_->now) {
    throw std::invalid_argument("fragment ring limits must be positive");
  }
}

common::Result<std::uint64_t> FragmentRing::BeginGeneration(
    std::vector<std::uint8_t> initialization_segment) {
  std::lock_guard lock(state_->mutex);
  ++state_->generation;
  state_->available = false;
  state_->initialization_segment.reset();
  state_->fragments.clear();
  state_->retained_bytes = 0U;
  state_->next_fragment_sequence = 1U;
  state_->last_publication_at.reset();

  if (initialization_segment.empty() ||
      initialization_segment.size() > state_->limits.max_bytes) {
    state_->changed.notify_all();
    return common::Result<std::uint64_t>::Err(
        {"E_LIVE_LIMIT", "live initialization segment exceeds ring limit"});
  }

  state_->retained_bytes = initialization_segment.size();
  state_->initialization_segment =
      std::make_shared<const std::vector<std::uint8_t>>(
          std::move(initialization_segment));
  state_->last_publication_at = state_->now();
  state_->available = true;
  state_->changed.notify_all();
  return common::Result<std::uint64_t>::Ok(state_->generation);
}

common::Result<void> FragmentRing::Publish(
    std::vector<std::uint8_t> media_fragment,
    bool random_access) {
  std::lock_guard lock(state_->mutex);
  const auto invalidate = [this] {
    ++state_->generation;
    state_->available = false;
    state_->initialization_segment.reset();
    state_->fragments.clear();
    state_->retained_bytes = 0U;
    state_->next_fragment_sequence = 1U;
    state_->last_publication_at.reset();
    state_->changed.notify_all();
  };

  if (!state_->available || !state_->initialization_segment) {
    return common::Result<void>::Err(
        {"E_LIVE_UNAVAILABLE", "live stream generation is unavailable"});
  }
  const auto initialization_size = state_->initialization_segment->size();
  if (media_fragment.empty() ||
      initialization_size > state_->limits.max_bytes ||
      media_fragment.size() > state_->limits.max_bytes - initialization_size) {
    invalidate();
    return common::Result<void>::Err(
        {"E_LIVE_LIMIT", "live media fragment exceeds ring limit"});
  }

  while (!state_->fragments.empty() &&
         (state_->fragments.size() >= state_->limits.max_fragments ||
          media_fragment.size() >
              state_->limits.max_bytes - state_->retained_bytes)) {
    state_->retained_bytes -= state_->fragments.front().bytes->size();
    state_->fragments.pop_front();
    ++state_->overrun_total;
  }
  if (media_fragment.size() >
      state_->limits.max_bytes - state_->retained_bytes) {
    invalidate();
    return common::Result<void>::Err(
        {"E_LIVE_LIMIT", "live media fragment exceeds ring limit"});
  }

  const auto bytes = std::make_shared<const std::vector<std::uint8_t>>(
      std::move(media_fragment));
  state_->retained_bytes += bytes->size();
  state_->fragments.push_back(SharedState::Entry{
      .sequence = state_->next_fragment_sequence++,
      .random_access = random_access,
      .bytes = bytes,
  });
  state_->last_publication_at = state_->now();
  state_->changed.notify_all();
  return common::Result<void>::Ok();
}

void FragmentRing::Invalidate() noexcept {
  std::lock_guard lock(state_->mutex);
  ++state_->generation;
  state_->available = false;
  state_->initialization_segment.reset();
  state_->fragments.clear();
  state_->retained_bytes = 0U;
  state_->next_fragment_sequence = 1U;
  state_->last_publication_at.reset();
  state_->changed.notify_all();
}

common::Result<FragmentRing::Reader> FragmentRing::OpenReader() {
  return OpenReaderInternal(std::nullopt);
}

common::Result<FragmentRing::Reader> FragmentRing::OpenReader(
    std::chrono::milliseconds maximum_age) {
  return OpenReaderInternal(maximum_age);
}

common::Result<FragmentRing::Reader> FragmentRing::OpenReaderInternal(
    std::optional<std::chrono::milliseconds> maximum_age) {
  std::lock_guard lock(state_->mutex);
  if (!state_->available || !state_->initialization_segment) {
    return common::Result<Reader>::Err(
        {"E_LIVE_UNAVAILABLE", "live stream is unavailable"});
  }
  if (maximum_age.has_value()) {
    const auto current_time = state_->now();
    const auto& last_publication_at = state_->last_publication_at;
    if (*maximum_age <= std::chrono::milliseconds::zero() ||
        !last_publication_at.has_value() ||
        current_time < *last_publication_at ||
        current_time - *last_publication_at > *maximum_age) {
      return common::Result<Reader>::Err(
          {"E_LIVE_STALE", "live stream has stopped producing fragments"});
    }
  }
  if (state_->active_readers >= state_->limits.max_readers) {
    return common::Result<Reader>::Err(
        {"E_LIVE_CAPACITY", "live stream reader capacity is full"});
  }

  auto cursor = std::make_shared<Reader::CursorState>();
  cursor->state = state_;
  cursor->generation = state_->generation;
  const auto latest_random_access =
      std::find_if(state_->fragments.rbegin(), state_->fragments.rend(),
                   [](const auto& entry) { return entry.random_access; });
  cursor->next_fragment_sequence =
      latest_random_access == state_->fragments.rend()
          ? state_->next_fragment_sequence
          : latest_random_access->sequence;
  ++state_->active_readers;
  return common::Result<Reader>::Ok(Reader(std::move(cursor)));
}

std::uint64_t FragmentRing::generation() const noexcept {
  std::lock_guard lock(state_->mutex);
  return state_->generation;
}

std::uint64_t FragmentRing::overrun_total() const noexcept {
  std::lock_guard lock(state_->mutex);
  return state_->overrun_total;
}

std::size_t FragmentRing::retained_bytes() const noexcept {
  std::lock_guard lock(state_->mutex);
  return state_->retained_bytes;
}

std::size_t FragmentRing::active_readers() const noexcept {
  std::lock_guard lock(state_->mutex);
  return state_->active_readers;
}

std::size_t FragmentRing::waiting_readers() const noexcept {
  std::lock_guard lock(state_->mutex);
  return state_->waiting_readers;
}

}  // namespace camera_firmware::media
