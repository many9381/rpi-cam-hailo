#include "camera_firmware/media/MjpegFrameHub.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace camera_firmware::media {
namespace {

constexpr std::string_view kMultipartBoundary = "--cf-frame\r\n";
constexpr std::string_view kContentType = "Content-Type: image/jpeg\r\n";
constexpr std::string_view kPartSuffix = "\r\n";

MjpegFrameHubDependencies::Clock::time_point SteadyNow() {
  return MjpegFrameHubDependencies::Clock::now();
}

common::Result<JpegImage> EncodeDefault(const FrameLease& frame,
                                        unsigned int maximum_width,
                                        unsigned int quality) {
  return EncodeNv12Jpeg(frame, maximum_width, quality);
}

common::Error PreviewUnavailable() {
  return {"E_PREVIEW_UNAVAILABLE", "MJPEG preview is unavailable"};
}

common::Error PreviewCapacity() {
  return {"E_PREVIEW_CAPACITY", "MJPEG preview reader capacity is full"};
}

bool IsStale(MjpegFrameHubDependencies::Clock::time_point now,
             MjpegFrameHubDependencies::Clock::time_point published_at,
             std::chrono::milliseconds maximum_age) {
  return now > published_at && now - published_at > maximum_age;
}

}  // namespace

struct MjpegFrameHubSharedState {
  explicit MjpegFrameHubSharedState(MjpegFrameHubDependencies::NowCallback now,
                                    unsigned int stale_timeout_ms)
      : now(std::move(now)), stale_timeout(stale_timeout_ms) {}

  MjpegFrameHubDependencies::NowCallback now;
  const std::chrono::milliseconds stale_timeout;
  std::mutex mutex;
  std::condition_variable changed;
  std::condition_variable blocked_reader_changed;
  bool running{false};
  bool stop_requested{true};
  std::uint64_t run_epoch{0U};
  std::size_t active_readers{0U};
  std::size_t blocked_readers{0U};
  std::optional<std::uint64_t> last_source_sequence;
  std::shared_ptr<const std::vector<std::uint8_t>> latest_jpeg;
  std::shared_ptr<const SnapshotTap::SourceRunToken> latest_source_run;
  std::string latest_camera_id;
  std::uint64_t latest_sequence{0U};
  MjpegFrameHubDependencies::Clock::time_point latest_published_at{};
};

struct MjpegStreamReader::Impl {
  enum class Segment { kPrefix, kPayload, kSuffix };

  Impl(std::shared_ptr<MjpegFrameHubSharedState> shared_state,
       std::string requested_camera_id,
       std::uint64_t reader_run_epoch)
      : state(std::move(shared_state)),
        camera_id(std::move(requested_camera_id)),
        run_epoch(reader_run_epoch) {}

  void ResetPart() {
    prefix.clear();
    jpeg.reset();
    segment = Segment::kPrefix;
    segment_offset = 0U;
  }

  void BeginPart(std::shared_ptr<const std::vector<std::uint8_t>> next_jpeg,
                 std::uint64_t sequence,
                 MjpegFrameHubDependencies::Clock::time_point published_at) {
    prefix = std::string(kMultipartBoundary) + std::string(kContentType) +
             "Content-Length: " + std::to_string(next_jpeg->size()) +
             "\r\n\r\n";
    jpeg = std::move(next_jpeg);
    current_published_at = published_at;
    last_sequence = sequence;
    has_sequence = true;
    segment = Segment::kPrefix;
    segment_offset = 0U;
  }

  std::size_t CopyPart(char* output, std::size_t capacity) {
    std::size_t copied = 0U;
    while (copied < capacity && jpeg) {
      const char* source = nullptr;
      std::size_t source_size = 0U;
      if (segment == Segment::kPrefix) {
        source = prefix.data();
        source_size = prefix.size();
      } else if (segment == Segment::kPayload) {
        source = reinterpret_cast<const char*>(jpeg->data());
        source_size = jpeg->size();
      } else {
        source = kPartSuffix.data();
        source_size = kPartSuffix.size();
      }

      const std::size_t available = source_size - segment_offset;
      const std::size_t to_copy = std::min(available, capacity - copied);
      if (to_copy > 0U) {
        std::memcpy(output + copied, source + segment_offset, to_copy);
        copied += to_copy;
        segment_offset += to_copy;
      }
      if (segment_offset != source_size) {
        continue;
      }
      segment_offset = 0U;
      if (segment == Segment::kPrefix) {
        segment = Segment::kPayload;
      } else if (segment == Segment::kPayload) {
        segment = Segment::kSuffix;
      } else {
        ResetPart();
      }
    }
    return copied;
  }

  std::shared_ptr<MjpegFrameHubSharedState> state;
  const std::string camera_id;
  const std::uint64_t run_epoch;
  std::mutex mutex;
  std::shared_ptr<const std::vector<std::uint8_t>> jpeg;
  std::string prefix;
  Segment segment{Segment::kPrefix};
  std::size_t segment_offset{0U};
  bool has_sequence{false};
  std::uint64_t last_sequence{0U};
  MjpegFrameHubDependencies::Clock::time_point current_published_at{};
};

MjpegStreamReader::MjpegStreamReader(
    std::shared_ptr<MjpegFrameHubSharedState> state,
    std::string camera_id,
    std::uint64_t run_epoch)
    : impl_(std::make_unique<Impl>(std::move(state), std::move(camera_id),
                                   run_epoch)) {}

MjpegStreamReader::~MjpegStreamReader() {
  if (!impl_) {
    return;
  }
  auto state = impl_->state;
  impl_.reset();
  std::lock_guard lock(state->mutex);
  assert(state->active_readers > 0U);
  --state->active_readers;
}

std::size_t MjpegStreamReader::Read(char* output, std::size_t capacity) {
  if (output == nullptr || capacity == 0U || !impl_) {
    return 0U;
  }

  std::unique_lock reader_lock(impl_->mutex);
  try {
    while (true) {
      bool stopped = false;
      {
        std::lock_guard state_lock(impl_->state->mutex);
        stopped = impl_->state->stop_requested ||
                  impl_->state->run_epoch != impl_->run_epoch;
      }
      if (stopped) {
        impl_->ResetPart();
        return 0U;
      }
      if (impl_->jpeg) {
        bool stopped = false;
        {
          std::lock_guard state_lock(impl_->state->mutex);
          stopped = impl_->state->stop_requested ||
                    impl_->state->run_epoch != impl_->run_epoch;
        }
        if (stopped) {
          impl_->ResetPart();
          return 0U;
        }
        return impl_->CopyPart(output, capacity);
      }

      const auto now = impl_->state->now();

      std::shared_ptr<const std::vector<std::uint8_t>> next_jpeg;
      std::uint64_t next_sequence = 0U;
      MjpegFrameHubDependencies::Clock::time_point next_published_at{};
      std::unique_lock state_lock(impl_->state->mutex);
      if (impl_->state->stop_requested ||
          impl_->state->run_epoch != impl_->run_epoch) {
        return 0U;
      }

      const bool camera_matches =
          impl_->state->latest_jpeg &&
          impl_->state->latest_source_run &&
          impl_->state->latest_source_run->valid() &&
          impl_->state->latest_camera_id == impl_->camera_id;
      if (impl_->state->latest_jpeg &&
          (!impl_->state->latest_source_run ||
           !impl_->state->latest_source_run->valid())) {
        return 0U;
      }
      const bool is_new =
          camera_matches &&
          (!impl_->has_sequence ||
           impl_->state->latest_sequence != impl_->last_sequence);
      if (is_new) {
        if (IsStale(now, impl_->state->latest_published_at,
                    impl_->state->stale_timeout)) {
          return 0U;
        }
        next_jpeg = impl_->state->latest_jpeg;
        next_sequence = impl_->state->latest_sequence;
        next_published_at = impl_->state->latest_published_at;
        state_lock.unlock();
        impl_->BeginPart(std::move(next_jpeg), next_sequence,
                         next_published_at);
        return impl_->CopyPart(output, capacity);
      }

      if (camera_matches &&
          IsStale(now, impl_->state->latest_published_at,
                  impl_->state->stale_timeout)) {
        return 0U;
      }

      const auto changed = [this] {
        return impl_->state->stop_requested ||
               impl_->state->run_epoch != impl_->run_epoch ||
               (impl_->state->latest_jpeg &&
                impl_->state->latest_camera_id == impl_->camera_id &&
                (!impl_->has_sequence ||
                 impl_->state->latest_sequence != impl_->last_sequence));
      };
      const auto wait_for_change = [&](std::optional<std::chrono::milliseconds>
                                           timeout) {
        ++impl_->state->blocked_readers;
        impl_->state->blocked_reader_changed.notify_all();
        try {
          if (timeout.has_value()) {
            impl_->state->changed.wait_for(state_lock, *timeout, changed);
          } else {
            impl_->state->changed.wait(state_lock, changed);
          }
        } catch (...) {
          --impl_->state->blocked_readers;
          throw;
        }
        --impl_->state->blocked_readers;
      };
      if (!camera_matches) {
        wait_for_change(std::nullopt);
        continue;
      }

      auto remaining = impl_->state->stale_timeout;
      if (now > impl_->state->latest_published_at) {
        const auto age = now - impl_->state->latest_published_at;
        if (age < remaining) {
          remaining -=
              std::chrono::duration_cast<std::chrono::milliseconds>(age);
        } else {
          remaining = std::chrono::milliseconds{1};
        }
      }
      wait_for_change(remaining);
    }
  } catch (...) {
    impl_->ResetPart();
    return 0U;
  }
}

struct MjpegFrameHub::Impl {
  Impl(SnapshotTap& source_tap,
       const config::HttpPreviewConfig& preview_config,
       MjpegFrameHubDependencies supplied_dependencies)
      : tap(source_tap),
        config(preview_config),
        dependencies(std::move(supplied_dependencies)) {
    if (!dependencies.now) {
      dependencies.now = SteadyNow;
    }
    if (!dependencies.encode) {
      dependencies.encode = EncodeDefault;
    }
    state = std::make_shared<MjpegFrameHubSharedState>(
        dependencies.now, config.stale_timeout_ms);
  }

  SnapshotTap& tap;
  const config::HttpPreviewConfig config;
  MjpegFrameHubDependencies dependencies;
  std::shared_ptr<MjpegFrameHubSharedState> state;
  std::mutex lifecycle_mutex;
  std::function<void()> before_worker_start_for_test;
  std::thread worker;
};

MjpegFrameHub::MjpegFrameHub(
    SnapshotTap& tap,
    const config::HttpPreviewConfig& config,
    MjpegFrameHubDependencies dependencies)
    : impl_(std::make_unique<Impl>(tap, config, std::move(dependencies))) {}

MjpegFrameHub::~MjpegFrameHub() { Stop(); }

common::Result<void> MjpegFrameHub::Start() {
  std::lock_guard lifecycle_lock(impl_->lifecycle_mutex);
  if (!impl_->config.enabled) {
    return common::Result<void>::Ok();
  }

  std::shared_ptr<const std::vector<std::uint8_t>> old_jpeg;
  std::string old_camera_id;
  {
    std::lock_guard state_lock(impl_->state->mutex);
    if (impl_->state->running) {
      return common::Result<void>::Ok();
    }
    old_jpeg = std::move(impl_->state->latest_jpeg);
    impl_->state->latest_source_run.reset();
    old_camera_id = std::move(impl_->state->latest_camera_id);
    impl_->state->last_source_sequence.reset();
    ++impl_->state->run_epoch;
    impl_->state->stop_requested = false;
    impl_->state->running = true;
  }

  try {
    if (impl_->before_worker_start_for_test) {
      impl_->before_worker_start_for_test();
    }
    impl_->worker = std::thread([this] { WorkerLoop(); });
  } catch (...) {
    {
      std::lock_guard state_lock(impl_->state->mutex);
      impl_->state->stop_requested = true;
      impl_->state->running = false;
    }
    impl_->state->changed.notify_all();
    return common::Result<void>::Err(PreviewUnavailable());
  }
  return common::Result<void>::Ok();
}

common::Result<void> MjpegFrameHub::StartWithoutWorkerForTest() {
  std::lock_guard lifecycle_lock(impl_->lifecycle_mutex);
  if (!impl_->config.enabled) {
    return common::Result<void>::Ok();
  }

  std::shared_ptr<const std::vector<std::uint8_t>> old_jpeg;
  std::string old_camera_id;
  {
    std::lock_guard state_lock(impl_->state->mutex);
    if (impl_->state->running) {
      return common::Result<void>::Ok();
    }
    old_jpeg = std::move(impl_->state->latest_jpeg);
    impl_->state->latest_source_run.reset();
    old_camera_id = std::move(impl_->state->latest_camera_id);
    impl_->state->last_source_sequence.reset();
    ++impl_->state->run_epoch;
    impl_->state->stop_requested = false;
    impl_->state->running = true;
  }
  return common::Result<void>::Ok();
}

void MjpegFrameHub::SetBeforeWorkerStartForTest(
    std::function<void()> callback) {
  std::lock_guard lifecycle_lock(impl_->lifecycle_mutex);
  impl_->before_worker_start_for_test = std::move(callback);
}

bool MjpegFrameHub::WaitForBlockedReaderForTest(
    std::chrono::milliseconds timeout) {
  std::unique_lock state_lock(impl_->state->mutex);
  return impl_->state->blocked_reader_changed.wait_for(
      state_lock, timeout,
      [this] { return impl_->state->blocked_readers > 0U; });
}

void MjpegFrameHub::Stop() noexcept {
  if (!impl_) {
    return;
  }
  std::lock_guard lifecycle_lock(impl_->lifecycle_mutex);
  std::shared_ptr<const std::vector<std::uint8_t>> old_jpeg;
  std::string old_camera_id;
  {
    std::lock_guard state_lock(impl_->state->mutex);
    impl_->state->stop_requested = true;
    impl_->state->running = false;
    old_jpeg = std::move(impl_->state->latest_jpeg);
    impl_->state->latest_source_run.reset();
    old_camera_id = std::move(impl_->state->latest_camera_id);
  }
  impl_->state->changed.notify_all();
  if (impl_->worker.joinable()) {
    impl_->worker.join();
  }
}

common::Result<std::shared_ptr<MjpegStreamReader>> MjpegFrameHub::Open(
    std::string_view camera_id) {
  std::uint64_t run_epoch = 0U;
  {
    std::lock_guard state_lock(impl_->state->mutex);
    if (!impl_->config.enabled || !impl_->state->running ||
        impl_->state->stop_requested) {
      return common::Result<std::shared_ptr<MjpegStreamReader>>::Err(
          PreviewUnavailable());
    }
  }

  MjpegFrameHubDependencies::Clock::time_point now;
  try {
    now = impl_->dependencies.now();
  } catch (...) {
    return common::Result<std::shared_ptr<MjpegStreamReader>>::Err(
        PreviewUnavailable());
  }

  {
    std::lock_guard state_lock(impl_->state->mutex);
    if (!impl_->config.enabled || !impl_->state->running ||
        impl_->state->stop_requested || !impl_->state->latest_jpeg ||
        !impl_->state->latest_source_run ||
        !impl_->state->latest_source_run->valid() ||
        impl_->state->latest_camera_id != camera_id ||
        IsStale(now, impl_->state->latest_published_at,
                impl_->state->stale_timeout)) {
      return common::Result<std::shared_ptr<MjpegStreamReader>>::Err(
          PreviewUnavailable());
    }
    if (impl_->state->active_readers >= impl_->config.max_clients) {
      return common::Result<std::shared_ptr<MjpegStreamReader>>::Err(
          PreviewCapacity());
    }
    ++impl_->state->active_readers;
    run_epoch = impl_->state->run_epoch;
  }

  MjpegStreamReader* reader = nullptr;
  try {
    reader = new MjpegStreamReader(impl_->state, std::string(camera_id),
                                   run_epoch);
  } catch (...) {
    std::lock_guard state_lock(impl_->state->mutex);
    --impl_->state->active_readers;
    return common::Result<std::shared_ptr<MjpegStreamReader>>::Err(
        PreviewUnavailable());
  }

  try {
    return common::Result<std::shared_ptr<MjpegStreamReader>>::Ok(
        std::shared_ptr<MjpegStreamReader>(reader));
  } catch (...) {
    return common::Result<std::shared_ptr<MjpegStreamReader>>::Err(
        PreviewUnavailable());
  }
}

void MjpegFrameHub::PublishLatestFrame() {
  try {
    auto publication =
        impl_->tap.LatestPublication(impl_->state->stale_timeout);
    if (!publication.has_value() || !publication->frame.valid()) {
      return;
    }

    const std::uint64_t sequence = publication->frame.handle().sequence;
    std::string camera_id = publication->frame.handle().camera_id;
    {
      std::lock_guard state_lock(impl_->state->mutex);
      if (impl_->state->stop_requested || !impl_->state->running ||
          impl_->state->last_source_sequence == sequence) {
        return;
      }
      impl_->state->last_source_sequence = sequence;
    }

    auto encoded = impl_->dependencies.encode(
        publication->frame, impl_->config.width, impl_->config.jpeg_quality);
    if (!encoded.ok()) {
      return;
    }
    JpegImage image = std::move(encoded).value();
    std::shared_ptr<const std::vector<std::uint8_t>> jpeg =
        std::make_shared<std::vector<std::uint8_t>>(std::move(image.bytes));
    const auto now = impl_->dependencies.now();
    if (IsStale(now, publication->published_at,
                impl_->state->stale_timeout) ||
        !publication->source_run || !publication->source_run->valid()) {
      return;
    }

    std::shared_ptr<const std::vector<std::uint8_t>> old_jpeg;
    std::string old_camera_id;
    {
      std::lock_guard state_lock(impl_->state->mutex);
      if (impl_->state->stop_requested || !impl_->state->running ||
          impl_->state->last_source_sequence != sequence) {
        return;
      }
      old_jpeg = std::move(impl_->state->latest_jpeg);
      old_camera_id = std::move(impl_->state->latest_camera_id);
      impl_->state->latest_jpeg = std::move(jpeg);
      impl_->state->latest_source_run = publication->source_run;
      impl_->state->latest_camera_id = std::move(camera_id);
      impl_->state->latest_sequence = sequence;
      impl_->state->latest_published_at = publication->published_at;
    }
    impl_->state->changed.notify_all();
  } catch (...) {
  }
}

void MjpegFrameHub::WorkerLoop() noexcept {
  const auto interval =
      std::chrono::milliseconds(1000U / impl_->config.fps);
  while (true) {
    std::unique_lock state_lock(impl_->state->mutex);
    if (impl_->state->changed.wait_for(
            state_lock, interval,
            [this] { return impl_->state->stop_requested; })) {
      return;
    }
    state_lock.unlock();
    PublishLatestFrame();
  }
}

}  // namespace camera_firmware::media
