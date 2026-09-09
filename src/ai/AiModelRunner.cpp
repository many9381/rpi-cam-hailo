#include "camera_firmware/ai/AiModelRunner.hpp"

#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "camera_firmware/common/ThreadTuning.hpp"

namespace camera_firmware::ai {

struct AiModelRunner::SharedState {
  mutable std::mutex mutex;
  std::condition_variable changed;
  std::optional<media::FrameLease> pending_frame;
  AiModelRunnerStatus status;
  std::uint64_t in_flight_callbacks{0};
  bool stopping{false};
  std::function<void()> on_idle;
};

namespace {

struct DeferredCompletion {
  std::chrono::steady_clock::time_point arrived_at;
  std::optional<common::Error> error;
  std::vector<std::uint8_t> output_bytes;
};

struct SubmissionState {
  std::mutex mutex;
  bool callback_claimed{false};
  bool submit_resolved{false};
  bool submit_accepted{false};
  bool finalized{false};
  std::optional<std::chrono::steady_clock::time_point> handoff_at;
  std::optional<DeferredCompletion> deferred_completion;
};

DeferredCompletion CopyDeferredCompletion(
    common::Result<OutputView> output,
    std::chrono::steady_clock::time_point arrived_at) {
  DeferredCompletion deferred{.arrived_at = arrived_at};
  try {
    if (!output.ok()) {
      deferred.error = output.error();
      return deferred;
    }

    const auto output_view = output.value();
    if (output_view.size > 0U && output_view.data == nullptr) {
      deferred.error = {"E_AI_POSTPROCESS",
                        "AI backend callback provided null output data"};
      return deferred;
    }
    if (output_view.size > 0U) {
      deferred.output_bytes.assign(output_view.data,
                                   output_view.data + output_view.size);
    }
  } catch (const std::exception& ex) {
    deferred.error = {"E_AI_POSTPROCESS", ex.what()};
  } catch (...) {
    deferred.error = {
        "E_AI_POSTPROCESS",
        "AI callback output copy failed with an unknown exception"};
  }
  return deferred;
}

double MillisecondsSince(std::chrono::steady_clock::time_point start,
                         std::chrono::steady_clock::time_point end) {
  if (end <= start) {
    return 0.0;
  }
  return std::chrono::duration<double, std::milli>(end - start).count();
}

}  // namespace

std::string_view UnavailableAiBackend::name() const noexcept {
  return "hailo";
}

bool UnavailableAiBackend::available() const noexcept {
  return false;
}

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

common::Result<void> UnavailableAiBackend::Submit(ModelHandle, InputView,
                                                  InferCallback) {
  return common::Result<void>::Err(
      {"E_AI_BACKEND_UNAVAILABLE",
       "Hailo backend is not implemented in this build"});
}

AiModelRunner::AiModelRunner(
    std::string camera_id, config::AiModelConfig model, AiBackend* backend,
    ModelHandle model_handle, DetectionBus* detection_bus,
    SubmissionResolvedObserver submission_resolved_observer)
    : camera_id_(std::move(camera_id)),
      model_(std::move(model)),
      backend_(backend),
      model_handle_(model_handle),
      detection_publisher_(detection_bus != nullptr
                               ? detection_bus->PublisherHandle()
                               : DetectionBus::Publisher{}),
      submission_resolved_observer_(std::move(submission_resolved_observer)),
      // One in flight + one being prepared + one spare; recycling avoids the
      // ~1.2MB allocation and full letterbox pad fill per frame.
      canvas_pool_(std::make_shared<ModelInputBufferPool>(3U)),
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
  worker_ = std::thread([this] {
    common::NameCurrentThread("ai-runner");
    common::DeprioritizeCurrentThread(10);
    Run();
  });
}

AiModelRunner::~AiModelRunner() {
  Stop();
}

common::Result<void> AiModelRunner::Submit(media::FrameLease frame) {
  {
    std::lock_guard lock(state_->mutex);
    if (state_->stopping) {
      return common::Result<void>::Ok();
    }
    ++state_->status.submitted_frames;
    if (state_->pending_frame.has_value()) {
      ++state_->status.dropped_frames;
    }
    state_->pending_frame = std::move(frame);
  }
  state_->changed.notify_one();

  return common::Result<void>::Ok();
}

void AiModelRunner::SetReadyCallback(std::function<void()> on_ready) {
  std::lock_guard lock(state_->mutex);
  state_->on_idle = std::move(on_ready);
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
  state_->changed.wait(lock,
                       [this] { return state_->in_flight_callbacks == 0U; });
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
        return state_->stopping || (state_->pending_frame.has_value() &&
                                    state_->in_flight_callbacks == 0U);
      });
      if (state_->stopping || (state_->pending_frame.has_value() &&
                               state_->in_flight_callbacks > 0U)) {
        return;
      }
      frame = std::move(state_->pending_frame);
      state_->pending_frame.reset();
    }

    if (frame.has_value()) {
      ProcessFrame(std::move(*frame));
      // If ProcessFrame dropped the frame without submitting (backend
      // unavailable, invalid frame, preprocess failure), no async
      // completion will fire, so re-arm the pull demand here. When it did
      // submit, in_flight_callbacks is non-zero and finish_submission
      // re-arms on completion instead. A harmless double re-arm is possible
      // if the async callback already completed -- RequestNext is idempotent.
      std::function<void()> on_idle;
      {
        std::lock_guard lock(state_->mutex);
        if (state_->in_flight_callbacks == 0U && state_->on_idle) {
          on_idle = state_->on_idle;
        }
      }
      if (on_idle) {
        on_idle();
      }
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
    RecordDrop(state_, {"E_AI_PROCESSOR_UNAVAILABLE",
                        "AI model processor is unavailable"});
    return;
  }
  if (!frame.valid()) {
    RecordDrop(state_, {"E_AI_PREPROCESS", "AI frame lease is invalid"});
    return;
  }

  const media::FrameHandle source_frame = frame.handle();
  // Recycled canvas: released back to the pool by its deleter once the last
  // holder (normally the Hailo completion callback) drops it.
  auto input_buffer = canvas_pool_->Acquire();
  const auto preprocess_started = std::chrono::steady_clock::now();
  auto input = processor_->Preprocess(frame, *input_buffer);
  const auto preprocess_finished = std::chrono::steady_clock::now();
  if (!input.ok()) {
    RecordDrop(state_, input.error());
    return;
  }
  const double preprocess_ms = std::chrono::duration<double, std::milli>(
                                   preprocess_finished - preprocess_started)
                                   .count();

  auto processor = processor_;
  auto submission = std::make_shared<SubmissionState>();

  std::weak_ptr<SharedState> weak_state = state_;
  auto finish_submission =
      [](const std::shared_ptr<SharedState>& state,
         const std::shared_ptr<SubmissionState>& submission_state) {
        {
          std::lock_guard lock(submission_state->mutex);
          if (submission_state->finalized) {
            return;
          }
          submission_state->finalized = true;
        }
        std::function<void()> on_idle;
        {
          std::lock_guard lock(state->mutex);
          if (state->in_flight_callbacks > 0U) {
            --state->in_flight_callbacks;
          }
          // Inference finished and nothing else is in flight: the runner is
          // ready to pull the next frame (pull-on-ready).
          if (state->in_flight_callbacks == 0U && state->on_idle) {
            on_idle = state->on_idle;
          }
        }
        state->changed.notify_all();
        if (on_idle) {
          on_idle();
        }
      };
  auto complete_output = [weak_state, processor, source_frame, preprocess_ms,
                          detection_publisher = detection_publisher_,
                          submission,
                          finish_submission](common::Result<OutputView> output,
                                             double inference_ms) mutable {
    auto state = weak_state.lock();
    if (state == nullptr) {
      return;
    }

    if (!output.ok()) {
      RecordDrop(state, output.error());
      finish_submission(state, submission);
      return;
    }

    try {
      processor->Postprocess(std::move(output), source_frame,
                             detection_publisher);
      RecordProcessed(state, preprocess_ms, inference_ms,
                      source_frame.sequence);
    } catch (const std::exception& ex) {
      RecordDrop(state, {"E_AI_POSTPROCESS", ex.what()});
    } catch (...) {
      RecordDrop(state, {"E_AI_POSTPROCESS",
                         "AI postprocess failed with an unknown exception"});
    }
    finish_submission(state, submission);
  };
  auto complete_deferred = [complete_output](DeferredCompletion completion,
                                             double inference_ms) mutable {
    if (completion.error.has_value()) {
      complete_output(
          common::Result<OutputView>::Err(std::move(*completion.error)),
          inference_ms);
      return;
    }
    const OutputView output{completion.output_bytes.empty()
                                ? nullptr
                                : completion.output_bytes.data(),
                            completion.output_bytes.size()};
    complete_output(common::Result<OutputView>::Ok(output), inference_ms);
  };
  {
    std::lock_guard lock(state_->mutex);
    ++state_->in_flight_callbacks;
  }
  auto submitted = backend_->Submit(
      model_handle_, input_buffer->view(),
      [input_buffer, submission,
       complete_output](common::Result<OutputView> output) mutable {
        (void)input_buffer;
        const auto arrived_at = std::chrono::steady_clock::now();
        std::optional<double> inference_ms;
        {
          std::lock_guard lock(submission->mutex);
          if (submission->callback_claimed) {
            return;
          }
          submission->callback_claimed = true;
          if (!submission->submit_resolved) {
            submission->deferred_completion =
                CopyDeferredCompletion(std::move(output), arrived_at);
            return;
          }
          if (!submission->submit_accepted ||
              !submission->handoff_at.has_value()) {
            return;
          }
          inference_ms = MillisecondsSince(*submission->handoff_at, arrived_at);
        }
        complete_output(std::move(output), *inference_ms);
      });
  const auto handoff_at = std::chrono::steady_clock::now();
  std::optional<DeferredCompletion> deferred_completion;
  {
    std::lock_guard lock(submission->mutex);
    submission->submit_resolved = true;
    submission->submit_accepted = submitted.ok();
    if (submitted.ok()) {
      submission->handoff_at = handoff_at;
      deferred_completion = std::move(submission->deferred_completion);
    }
  }
  if (!submitted.ok()) {
    finish_submission(state_, submission);
    RecordDrop(state_, submitted.error());
    NotifySubmissionResolved(false);
    return;
  }
  NotifySubmissionResolved(true);
  if (deferred_completion.has_value()) {
    const double inference_ms =
        MillisecondsSince(handoff_at, deferred_completion->arrived_at);
    complete_deferred(std::move(*deferred_completion), inference_ms);
  }
}

void AiModelRunner::NotifySubmissionResolved(bool accepted) const noexcept {
  if (!submission_resolved_observer_) {
    return;
  }
  try {
    submission_resolved_observer_(accepted);
  } catch (...) {
    // swallowed: observer errors must not escape this noexcept notifier
  }
}

void AiModelRunner::RecordDrop(const std::shared_ptr<SharedState>& state,
                               const common::Error& error) {
  std::lock_guard lock(state->mutex);
  ++state->status.dropped_frames;
  state->status.last_error_code = error.code;
  state->status.last_error_message = error.message;
}

void AiModelRunner::RecordProcessed(const std::shared_ptr<SharedState>& state,
                                    double preprocess_ms, double inference_ms,
                                    std::uint64_t sequence) {
  std::lock_guard lock(state->mutex);
  ++state->status.processed_frames;
  state->status.last_preprocess_ms = preprocess_ms;
  state->status.last_inference_ms = inference_ms;
  state->status.last_processed_sequence = sequence;
}

}  // namespace camera_firmware::ai
