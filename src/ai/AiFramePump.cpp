#include "camera_firmware/ai/AiFramePump.hpp"

#include <condition_variable>
#include <mutex>
#include <optional>
#include <utility>

#include "camera_firmware/ai/AiRuntime.hpp"

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

AiFramePump::~AiFramePump() { Stop(); }

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
        Run(state, runtime, interval);
      });

  std::weak_ptr<SharedState> weak_state = state_;
  subscription_ = frame_tap_.Subscribe(
      [weak_state](media::FrameLease frame) {
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
                      std::chrono::milliseconds minimum_interval) {
  auto next_allowed = std::chrono::steady_clock::now();
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

    if (minimum_interval.count() > 0) {
      std::unique_lock lock(state->mutex);
      state->changed.wait_until(lock, next_allowed,
                                [&state] { return state->stopping; });
      if (state->stopping) {
        return;
      }
      // A newer frame may have arrived while gated -- take it
      // (latest-wins).
      if (state->pending_frame.has_value()) {
        frame = std::move(state->pending_frame);
        state->pending_frame.reset();
      }
    }

    (void)runtime.SubmitFrame(std::move(*frame));
    next_allowed = std::chrono::steady_clock::now() + minimum_interval;
  }
}

}  // namespace camera_firmware::ai
