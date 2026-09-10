#include "camera_firmware/ai/AiFramePump.hpp"

#include <condition_variable>
#include <mutex>
#include <optional>
#include <utility>

#include "camera_firmware/ai/AiRuntime.hpp"
#include "camera_firmware/common/ThreadTuning.hpp"

namespace camera_firmware::ai {

struct AiFramePump::SharedState {
  std::mutex mutex;
  std::condition_variable changed;
  std::optional<media::FrameLease> pending_frame;
  bool running{false};
  bool stopping{false};
};

AiFramePump::AiFramePump(AiFrameTap& frame_tap, AiRuntime& runtime,
                         std::chrono::milliseconds minimum_interval)
    : frame_tap_(frame_tap),
      runtime_(runtime),
      minimum_interval_(minimum_interval),
      state_(std::make_shared<SharedState>()) {}

AiFramePump::~AiFramePump() {
  Stop();
}

common::Result<void> AiFramePump::Start() {
  {
    std::lock_guard lock(state_->mutex);
    if (state_->running || worker_.joinable()) {
      return common::Result<void>::Err(
          {"E_AI_FRAME_PUMP_RUNNING", "AI frame pump is already running"});
    }
    state_->pending_frame.reset();
    state_->stopping = false;
    state_->running = true;
  }

  worker_ = std::thread(
      [state = state_, &runtime = runtime_, interval = minimum_interval_] {
        common::NameCurrentThread("ai-pump");
        common::DeprioritizeCurrentThread(10);
        Run(state, runtime, interval);
      });

  // Pull-on-ready: re-arm the tap's demand each time the runtime finishes
  // an inference, so the capture side leases a lores buffer only when the
  // runner is actually ready for the next frame.
  runtime_.SetReadyCallback(
      [&frame_tap = frame_tap_] { frame_tap.RequestNext(); });

  std::weak_ptr<SharedState> weak_state = state_;
  subscription_ = frame_tap_.Subscribe([weak_state](media::FrameLease frame) {
    if (auto state = weak_state.lock()) {
      QueueFrame(state, std::move(frame));
    }
  });

  return common::Result<void>::Ok();
}

void AiFramePump::Stop() {
  AiFrameTap::Subscription subscription;
  {
    std::lock_guard lock(state_->mutex);
    if (!state_->running && !worker_.joinable()) {
      return;
    }
    state_->running = false;
    state_->stopping = true;
    state_->pending_frame.reset();
    subscription = std::move(subscription_);
  }

  state_->changed.notify_all();

  if (worker_.joinable()) {
    worker_.join();
  }
}

void AiFramePump::QueueFrame(const std::shared_ptr<SharedState>& state,
                             media::FrameLease frame) {
  {
    std::lock_guard lock(state->mutex);
    if (!state->running || state->stopping) {
      return;
    }
    state->pending_frame = std::move(frame);
  }
  state->changed.notify_one();
}

void AiFramePump::Run(const std::shared_ptr<SharedState>& state,
                      AiRuntime& runtime,
                      std::chrono::milliseconds /*minimum_interval*/) {
  // Pull-on-ready: the capture side only publishes a lores frame while the
  // tap's demand is armed (re-armed on inference completion), and paces the
  // AI rate itself, so the pump simply forwards each delivered frame to the
  // runtime without holding it in a rate gate. Holding a frame here would
  // pin its libcamera request and starve the capture buffer pool.
  while (true) {
    std::optional<media::FrameLease> frame;
    {
      std::unique_lock lock(state->mutex);
      state->changed.wait(lock, [&state] {
        return state->stopping || state->pending_frame.has_value();
      });
      if (state->stopping) {
        return;
      }
      frame = std::move(state->pending_frame);
      state->pending_frame.reset();
    }

    if (!frame.has_value()) {
      continue;
    }

    (void)runtime.SubmitFrame(std::move(*frame));
  }
}

}  // namespace camera_firmware::ai
