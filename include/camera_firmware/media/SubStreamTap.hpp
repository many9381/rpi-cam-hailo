#pragma once

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>

#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::media {

// Single-producer (capture thread), single-consumer (sub encoder thread)
// pull-on-ready tap for the main-stream sub-encode path, gated by an RTSP
// "active" flag.
//
// The capture thread calls ConsumeDemand() before building a sub-stream frame
// and only does the work when it returns true, then PublishLatest()s the
// resulting lease; the sub encoder thread calls RequestNext() to arm one-shot
// demand and blocks in WaitNext() for the next lease. The RTSP server toggles
// SetActive() as sub clients connect/leave: while inactive, ConsumeDemand()
// always reports false (so capture never builds a sub frame nobody wants) and
// a blocked WaitNext() wakes with nullopt. Close() is a permanent shutdown
// with the same wake-with-nullopt behavior.
//
// Mirrors the latest-wins mailbox pattern in EncodeMailbox: PublishLatest()
// drops any undelivered lease, and SetActive(false)/Close() drop any pending
// lease too. In every case the drop happens outside the tap mutex -- the
// lease is moved to a local, the lock released, and only then does the local
// destruct and run its release callback, so a libcamera buffer requeue never
// runs while holding this mutex.
class SubStreamTap {
 public:
  SubStreamTap() = default;
  SubStreamTap(const SubStreamTap&) = delete;
  SubStreamTap& operator=(const SubStreamTap&) = delete;

  // Producer (CameraPipeline) side.

  // True only if the tap is active and the consumer has an outstanding,
  // one-shot request for the next frame. The request is consumed (cleared)
  // only on that active/open path; while inactive or closed it is left
  // untouched, so it is still pending once the tap becomes active again.
  [[nodiscard]] bool ConsumeDemand() noexcept;

  // Hand the latest lease to the waiting consumer, superseding (and
  // releasing) any lease the consumer has not yet taken.
  void PublishLatest(FrameLease frame);

  // Consumer (SubStreamEncoder) side.

  // Blocks up to timeout for a frame. Returns nullopt on timeout, on
  // SetActive(false), or on Close().
  [[nodiscard]] std::optional<FrameLease> WaitNext(std::chrono::milliseconds timeout);

  // Arm one-shot demand for the next frame.
  void RequestNext() noexcept;

  // RTSP gate.

  // false -> ConsumeDemand() always returns false and a blocked WaitNext()
  // wakes with nullopt; any pending lease and outstanding demand are cleared.
  void SetActive(bool active) noexcept;
  [[nodiscard]] bool active() const noexcept;

  // Permanent shutdown: wakes a blocked WaitNext() with nullopt now and
  // forever after.
  void Close() noexcept;

  // Return a closed tap to service for a fresh sub-encoder run (the runtime
  // graph reuses one tap instance across restarts, mirroring
  // EncodeMailbox::Reopen()). Clears closed_ and any outstanding one-shot
  // demand, and drops any leftover pending lease before reopening.
  void Reopen() noexcept;

 private:
  mutable std::mutex mutex_;
  std::condition_variable cv_;
  std::optional<FrameLease> pending_;
  bool wants_frame_{false};  // starts disarmed; RequestNext arms
  bool active_{false};
  bool closed_{false};
};

}  // namespace camera_firmware::media
