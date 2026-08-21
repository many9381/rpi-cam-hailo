#include "camera_firmware/media/SnapshotTap.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

#include "camera_firmware/media/JpegEncoder.hpp"

namespace camera_firmware::media {
namespace {

SnapshotTap::Clock::time_point SteadyNow() {
  return SnapshotTap::Clock::now();
}

std::optional<JpegBytes> EncodeSnapshot(
    std::optional<FrameLease> latest,
    std::string_view camera_id) {
  if (!latest.has_value() || !latest->valid()) {
    return std::nullopt;
  }

  const FrameHandle& handle = latest->handle();
  if (handle.camera_id != camera_id) {
    return std::nullopt;
  }

  auto encoded = EncodeNv12Jpeg(*latest, handle.width, 85U);
  if (!encoded.ok()) {
    return std::nullopt;
  }
  JpegImage image = std::move(encoded).value();
  return std::move(image.bytes);
}

}  // namespace

SnapshotTap::SnapshotTap() : SnapshotTap(SteadyNow) {}

SnapshotTap::SnapshotTap(NowCallback now)
    : now_(now ? std::move(now) : NowCallback(SteadyNow)),
      source_run_(std::make_shared<SourceRunToken>()) {}

SnapshotTap::SourceEpoch SnapshotTap::BeginSourceRun() {
  auto next_source_run = std::make_shared<SourceRunToken>();
  std::optional<PublishedFrame> old;
  SourceEpoch source_epoch = 0U;
  {
    std::lock_guard lock(mutex_);
    ++source_epoch_;
    if (source_epoch_ == 0U) {
      ++source_epoch_;
    }
    source_run_->valid_.store(false, std::memory_order_release);
    source_active_ = true;
    source_run_ = std::move(next_source_run);
    old.swap(latest_);
    source_epoch = source_epoch_;
  }
  return source_epoch;
}

void SnapshotTap::EndSourceRun(SourceEpoch source_epoch) noexcept {
  std::optional<PublishedFrame> old;
  {
    std::lock_guard lock(mutex_);
    if (!source_active_ || source_epoch_ != source_epoch) {
      return;
    }
    source_run_->valid_.store(false, std::memory_order_release);
    source_active_ = false;
    old.swap(latest_);
  }
}

void SnapshotTap::Publish(FrameLease frame) {
  SourceEpoch source_epoch = 0U;
  {
    std::lock_guard lock(mutex_);
    source_epoch = source_epoch_;
  }
  Publish(std::move(frame), source_epoch);
}

void SnapshotTap::Publish(FrameLease frame, SourceEpoch source_epoch) {
  const std::uint64_t publication_id =
      next_publication_id_.fetch_add(1U, std::memory_order_relaxed) + 1U;
  const Clock::time_point published_at = now_();
  std::optional<PublishedFrame> old;
  {
    std::lock_guard lock(mutex_);
    if (!source_active_ || source_epoch_ != source_epoch ||
        (latest_.has_value() &&
         latest_->publication_id > publication_id)) {
      return;
    }
    old.swap(latest_);
    latest_ = PublishedFrame{std::move(frame), published_at, source_epoch,
                             publication_id, source_run_};
  }
}

std::optional<SnapshotTap::Publication> SnapshotTap::LatestPublication() const {
  std::lock_guard lock(mutex_);
  if (!source_active_ || !latest_.has_value()) {
    return std::nullopt;
  }
  return Publication{latest_->frame.CloneRef(), latest_->published_at,
                     latest_->source_epoch, latest_->source_run};
}

std::optional<SnapshotTap::Publication> SnapshotTap::LatestPublication(
    std::chrono::milliseconds maximum_age) const {
  if (maximum_age < std::chrono::milliseconds::zero()) {
    return std::nullopt;
  }

  const Clock::time_point now = now_();
  std::lock_guard lock(mutex_);
  if (!source_active_ || !latest_.has_value() ||
      (now > latest_->published_at &&
       now - latest_->published_at > maximum_age)) {
    return std::nullopt;
  }
  return Publication{latest_->frame.CloneRef(), latest_->published_at,
                     latest_->source_epoch, latest_->source_run};
}

bool SnapshotTap::IsSourceRunCurrent(SourceEpoch source_epoch) const noexcept {
  std::lock_guard lock(mutex_);
  return source_active_ && source_epoch_ == source_epoch &&
         source_run_->valid();
}

std::optional<FrameLease> SnapshotTap::Latest() const {
  auto publication = LatestPublication();
  if (!publication.has_value()) {
    return std::nullopt;
  }
  return std::move(publication->frame);
}

std::optional<FrameLease> SnapshotTap::Latest(
    std::chrono::milliseconds maximum_age) const {
  auto publication = LatestPublication(maximum_age);
  if (!publication.has_value()) {
    return std::nullopt;
  }
  return std::move(publication->frame);
}

bool SnapshotTap::HasFreshFrame(
    std::chrono::milliseconds maximum_age) const {
  auto latest = Latest(maximum_age);
  return latest.has_value() && latest->valid();
}

std::optional<JpegBytes> BuildLatestSnapshotJpeg(
    const SnapshotTap& tap,
    std::string_view camera_id) {
  return EncodeSnapshot(tap.Latest(), camera_id);
}

std::optional<JpegBytes> BuildLatestSnapshotJpeg(
    const SnapshotTap& tap,
    std::string_view camera_id,
    std::chrono::milliseconds maximum_age) {
  return EncodeSnapshot(tap.Latest(maximum_age), camera_id);
}

}  // namespace camera_firmware::media
