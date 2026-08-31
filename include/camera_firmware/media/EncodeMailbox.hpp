#pragma once

#include <condition_variable>
#include <mutex>
#include <optional>

#include "camera_firmware/media/FrameLease.hpp"

namespace libcamera {
class FrameBuffer;
}

namespace camera_firmware::media {

// One captured main-stream frame handed to the encoder thread. The lease keeps
// the capture buffer alive (and requeues it when dropped); the buffer pointer
// is the map key the encoder uses to reach the frame's pixels.
struct EncodeJob {
  const libcamera::FrameBuffer* buffer{nullptr};
  FrameLease lease;
};

// Single-consumer, latest-wins mailbox between the capture callback (producer)
// and a dedicated encoder thread (consumer). Publish() replaces any job the
// encoder has not yet taken, dropping the stale job's lease so its capture
// buffer requeues immediately rather than pinning the pool while the encoder
// falls behind. Take() blocks until a job is available or the mailbox closes.
//
// Decoupling encode from the capture callback this way keeps capture (and the
// AI pull) running at the sensor rate even when per-frame encode time spikes;
// only the encoded output rate drops, and only for as long as the spike lasts.
class EncodeMailbox {
 public:
  EncodeMailbox() = default;
  EncodeMailbox(const EncodeMailbox&) = delete;
  EncodeMailbox& operator=(const EncodeMailbox&) = delete;

  // Hand a frame to the encoder, superseding any undelivered frame. After
  // Close() the job is dropped at once (its lease releases here).
  void Publish(EncodeJob job);

  // Block until a job is available, returning it; returns nullopt once the
  // mailbox is closed (any undelivered job is discarded on close).
  [[nodiscard]] std::optional<EncodeJob> Take();

  // Wake a blocked Take() and make every later Take() return nullopt. Releases
  // any undelivered job so its buffer requeues on shutdown.
  void Close();

  // Return a closed mailbox to service for a fresh capture run (the pipeline
  // reuses one instance across profile-change restarts). Drops any leftover
  // job before reopening.
  void Reopen();

 private:
  std::mutex mutex_;
  std::condition_variable cv_;
  std::optional<EncodeJob> pending_;
  bool closed_{false};
};

}  // namespace camera_firmware::media
