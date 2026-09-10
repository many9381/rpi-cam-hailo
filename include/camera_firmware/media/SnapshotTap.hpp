#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <vector>

#include "camera_firmware/media/FrameLease.hpp"
#include "camera_firmware/media/JpegEncoder.hpp"

namespace camera_firmware::media {

class SnapshotTap {
 public:
  using Clock = std::chrono::steady_clock;
  using NowCallback = std::function<Clock::time_point()>;
  using SourceEpoch = std::uint64_t;

  class SourceRunToken {
   public:
    [[nodiscard]] bool valid() const noexcept {
      return valid_.load(std::memory_order_acquire);
    }

   private:
    friend class SnapshotTap;
    std::atomic<bool> valid_{true};
  };

  struct Publication {
    FrameLease frame;
    Clock::time_point published_at;
    SourceEpoch source_epoch{0U};
    std::shared_ptr<const SourceRunToken> source_run;
  };

  SnapshotTap();
  explicit SnapshotTap(NowCallback now);

  [[nodiscard]] SourceEpoch BeginSourceRun();
  void EndSourceRun(SourceEpoch source_epoch) noexcept;
  void Publish(FrameLease frame);
  void Publish(FrameLease frame, SourceEpoch source_epoch);
  [[nodiscard]] std::optional<Publication> LatestPublication() const;
  [[nodiscard]] std::optional<Publication> LatestPublication(
      std::chrono::milliseconds maximum_age) const;
  [[nodiscard]] bool IsSourceRunCurrent(
      SourceEpoch source_epoch) const noexcept;
  [[nodiscard]] std::optional<FrameLease> Latest() const;
  [[nodiscard]] std::optional<FrameLease> Latest(
      std::chrono::milliseconds maximum_age) const;
  [[nodiscard]] bool HasFreshFrame(std::chrono::milliseconds maximum_age) const;

 private:
  struct PublishedFrame {
    FrameLease frame;
    Clock::time_point published_at;
    SourceEpoch source_epoch{0U};
    std::uint64_t publication_id{0U};
    std::shared_ptr<const SourceRunToken> source_run;
  };

  NowCallback now_;
  std::atomic<std::uint64_t> next_publication_id_{0U};
  mutable std::mutex mutex_;
  std::optional<PublishedFrame> latest_;
  SourceEpoch source_epoch_{1U};
  bool source_active_{true};
  std::shared_ptr<SourceRunToken> source_run_;
};

[[nodiscard]] std::optional<JpegBytes> BuildLatestSnapshotJpeg(
    const SnapshotTap& tap, std::string_view camera_id);
[[nodiscard]] std::optional<JpegBytes> BuildLatestSnapshotJpeg(
    const SnapshotTap& tap, std::string_view camera_id,
    std::chrono::milliseconds maximum_age);

}  // namespace camera_firmware::media
