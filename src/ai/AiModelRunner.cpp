#include "camera_firmware/ai/AiModelRunner.hpp"

#include <condition_variable>
#include <exception>
#include <mutex>
#include <optional>
#include <string>
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
                             ModelHandle model_handle,
                             DetectionBus* detection_bus)
    : camera_id_(std::move(camera_id)),
      model_(std::move(model)),
      backend_(backend),
      model_handle_(model_handle),
      detection_publisher_(detection_bus != nullptr
                               ? detection_bus->PublisherHandle()
                               : DetectionBus::Publisher{}),
      state_(std::make_shared<SharedState>()) {
  state_->status.camera_id = camera_id_;
  state_->status.model_id = model_.id;
  state_->status.model_kind = model_.kind;
  auto processor = CreateAiModelProcessor(model_);
  if (processor.ok()) {
    processor_ = processor.value();
  } else {
    state_->status.last_error_code = processor.error().code;
    state_->status.last_error_message = processor.error().message;
  }
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
  if (backend_ == nullptr) {
    RecordDrop(state_,
               {"E_AI_BACKEND_UNAVAILABLE", "AI backend is unavailable"});
    return;
  }
  if (processor_ == nullptr) {
    RecordDrop(state_,
               {"E_AI_PROCESSOR_UNAVAILABLE",
                "AI model processor is unavailable"});
    return;
  }
  if (!frame.valid()) {
    RecordDrop(state_, {"E_AI_PREPROCESS", "AI frame lease is invalid"});
    return;
  }

  const media::FrameHandle source_frame = frame.handle();
  auto input = processor_->Preprocess(frame);
  if (!input.ok()) {
    RecordDrop(state_, input.error());
    return;
  }

  auto input_buffer =
      std::make_shared<ModelInputBuffer>(std::move(input).value());
  auto processor = processor_;

  std::weak_ptr<SharedState> weak_state = state_;
  {
    std::lock_guard lock(state_->mutex);
    ++state_->in_flight_callbacks;
  }
  auto submitted = backend_->Submit(
      model_handle_, input_buffer->view(),
      [weak_state,
       input_buffer,
       processor,
       source_frame,
       detection_publisher = detection_publisher_](
          common::Result<OutputView> output) mutable {
        (void)input_buffer;
        auto state = weak_state.lock();
        if (state == nullptr) {
          return;
        }

        struct CompletionGuard {
          explicit CompletionGuard(std::shared_ptr<SharedState> shared_state)
              : state(std::move(shared_state)) {}

          CompletionGuard(const CompletionGuard&) = delete;
          CompletionGuard& operator=(const CompletionGuard&) = delete;

          ~CompletionGuard() {
            {
              std::lock_guard lock(state->mutex);
              if (state->in_flight_callbacks > 0U) {
                --state->in_flight_callbacks;
              }
            }
            state->changed.notify_all();
          }

          std::shared_ptr<SharedState> state;
        } completion(state);

        if (output.ok()) {
          try {
            processor->Postprocess(std::move(output),
                                   source_frame,
                                   detection_publisher);
            RecordProcessed(state);
          } catch (const std::exception& ex) {
            RecordDrop(state, {"E_AI_POSTPROCESS", ex.what()});
          } catch (...) {
            RecordDrop(state,
                       {"E_AI_POSTPROCESS",
                        "AI postprocess failed with an unknown exception"});
          }
        } else {
          RecordDrop(state, output.error());
        }
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
