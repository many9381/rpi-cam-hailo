#include "camera_firmware/ai/AiModelRunner.hpp"

#include <condition_variable>
#include <mutex>
#include <optional>
#include <utility>

namespace camera_firmware::ai {

struct AiModelRunner::SharedState {
  mutable std::mutex mutex;
  std::condition_variable changed;
  std::optional<media::FrameLease> pending_frame;
  AiModelRunnerStatus status;
  std::uint64_t in_flight_callbacks{0};
  bool stopping{false};
};

std::string_view UnavailableAiBackend::name() const noexcept { return "hailo"; }

bool UnavailableAiBackend::available() const noexcept { return false; }

common::Result<void> UnavailableAiBackend::Init() {
  next_handle_ = 1;
  return common::Result<void>::Ok();
}

void UnavailableAiBackend::Shutdown() {}

common::Result<ModelHandle> UnavailableAiBackend::LoadModel(
    const config::AiModelConfig&) {
  return common::Result<ModelHandle>::Ok(next_handle_++);
}

void UnavailableAiBackend::Unload(ModelHandle) {}

common::Result<void> UnavailableAiBackend::Submit(
    ModelHandle,
    InputView,
    InferCallback) {
  return common::Result<void>::Err(
      {"E_AI_BACKEND_UNAVAILABLE",
       "Hailo backend is not implemented in this build"});
}

AiModelRunner::AiModelRunner(std::string camera_id,
                             config::AiModelConfig model,
                             AiBackend* backend,
                             ModelHandle model_handle)
    : camera_id_(std::move(camera_id)),
      model_(std::move(model)),
      backend_(backend),
      model_handle_(model_handle),
      state_(std::make_shared<SharedState>()) {
  state_->status.camera_id = camera_id_;
  state_->status.model_id = model_.id;
  state_->status.model_kind = model_.kind;
  worker_ = std::thread([this] { Run(); });
}

AiModelRunner::~AiModelRunner() { Stop(); }

common::Result<void> AiModelRunner::Submit(media::FrameLease frame) {
  {
    std::lock_guard lock(state_->mutex);
    if (state_->stopping) {
      return common::Result<void>::Ok();
    }
    ++state_->status.submitted_frames;
    if (state_->pending_frame.has_value()) {
      ++state_->status.dropped_frames;
      state_->status.last_error_code = "E_AI_FRAME_REPLACED";
      state_->status.last_error_message =
          "AI runner replaced queued frame with a newer frame";
    }
    state_->pending_frame = std::move(frame);
  }
  state_->changed.notify_one();

  return common::Result<void>::Ok();
}

void AiModelRunner::Stop() {
  {
    std::lock_guard lock(state_->mutex);
    state_->stopping = true;
    state_->pending_frame.reset();
  }
  state_->changed.notify_all();
  if (worker_.joinable()) {
    worker_.join();
  }
  std::unique_lock lock(state_->mutex);
  state_->changed.wait(lock, [this] {
    return state_->in_flight_callbacks == 0U;
  });
}

AiModelRunnerStatus AiModelRunner::Status() const {
  std::lock_guard lock(state_->mutex);
  return state_->status;
}

void AiModelRunner::Run() {
  while (true) {
    std::optional<media::FrameLease> frame;
    {
      std::unique_lock lock(state_->mutex);
      state_->changed.wait(lock, [this] {
        return state_->stopping ||
               (state_->pending_frame.has_value() &&
                state_->in_flight_callbacks == 0U);
      });
      if (state_->stopping ||
          (state_->pending_frame.has_value() &&
           state_->in_flight_callbacks > 0U)) {
        return;
      }
      frame = std::move(state_->pending_frame);
      state_->pending_frame.reset();
    }

    if (frame.has_value()) {
      ProcessFrame(std::move(*frame));
    }
  }
}

void AiModelRunner::ProcessFrame(media::FrameLease frame) {
  (void)frame;
  if (backend_ == nullptr) {
    RecordDrop(state_,
               {"E_AI_BACKEND_UNAVAILABLE", "AI backend is unavailable"});
    return;
  }

  std::weak_ptr<SharedState> weak_state = state_;
  {
    std::lock_guard lock(state_->mutex);
    ++state_->in_flight_callbacks;
  }
  auto submitted = backend_->Submit(
      model_handle_, InputView{},
      [weak_state](common::Result<OutputView> output) {
        auto state = weak_state.lock();
        if (state == nullptr) {
          return;
        }

        if (output.ok()) {
          RecordProcessed(state);
        } else {
          RecordDrop(state, output.error());
        }

        {
          std::lock_guard lock(state->mutex);
          if (state->in_flight_callbacks > 0U) {
            --state->in_flight_callbacks;
          }
        }
        state->changed.notify_all();
      });
  if (!submitted.ok()) {
    {
      std::lock_guard lock(state_->mutex);
      if (state_->in_flight_callbacks > 0U) {
        --state_->in_flight_callbacks;
      }
    }
    state_->changed.notify_all();
    RecordDrop(state_, submitted.error());
  }
}

void AiModelRunner::RecordDrop(const std::shared_ptr<SharedState>& state,
                               const common::Error& error) {
  std::lock_guard lock(state->mutex);
  ++state->status.dropped_frames;
  state->status.last_error_code = error.code;
  state->status.last_error_message = error.message;
}

void AiModelRunner::RecordProcessed(const std::shared_ptr<SharedState>& state) {
  std::lock_guard lock(state->mutex);
  ++state->status.processed_frames;
}

}  // namespace camera_firmware::ai
