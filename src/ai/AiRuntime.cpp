#include "camera_firmware/ai/AiRuntime.hpp"

#if defined(CF_HAVE_HAILORT)
#include "camera_firmware/ai/HailoBackend.hpp"
#endif

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace camera_firmware::ai {
namespace {

constexpr const char* kRedactedModelPath = "[redacted model path]";

const config::AiModelConfig* FindModelById(const config::AppConfig& config,
                                           const std::string& model_id) {
  for (const auto& model : config.ai.models) {
    if (model.id == model_id) {
      return &model;
    }
  }

  return nullptr;
}

void ReplaceAll(std::string& value, const std::string& needle,
                const std::string& replacement) {
  if (needle.empty()) {
    return;
  }

  std::size_t pos = 0;
  while ((pos = value.find(needle, pos)) != std::string::npos) {
    value.replace(pos, needle.size(), replacement);
    pos += replacement.size();
  }
}

std::vector<std::string> BuildModelPathRedactions(
    const config::AppConfig& config) {
  std::vector<std::string> paths;
  for (const auto& model : config.ai.models) {
    if (!model.hef_path.empty()) {
      paths.push_back(model.hef_path);
    }
  }

  std::sort(paths.begin(), paths.end(), [](const auto& lhs, const auto& rhs) {
    if (lhs.size() != rhs.size()) {
      return lhs.size() > rhs.size();
    }
    return lhs < rhs;
  });
  paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
  return paths;
}

void RedactConfiguredModelPaths(std::string& message,
                                const std::vector<std::string>& paths) {
  for (const auto& path : paths) {
    ReplaceAll(message, path, kRedactedModelPath);
  }
}

}  // namespace

struct AiRuntime::RuntimeResources {
  std::shared_ptr<AiBackend> backend;
  std::unordered_map<std::string, ModelHandle> model_handles;
  std::vector<std::shared_ptr<AiModelRunner>> runners;
};

AiRuntime::AiRuntime(DetectionBus* detection_bus)
    : detection_bus_(detection_bus) {}

AiRuntime::AiRuntime(DetectionBus* detection_bus,
                     std::shared_ptr<AiBackend> backend_override)
    : detection_bus_(detection_bus),
      backend_override_(std::move(backend_override)) {}

AiRuntime::~AiRuntime() {
  Stop();
}

common::Result<void> AiRuntime::Start(const config::AppConfig& config) {
  Stop();

  std::lock_guard lock(mutex_);

  status_ = AiRuntimeStatus{};
  status_.enabled = config.ai.enabled;
  status_.backend = config.ai.enabled ? config.ai.backend : "disabled";
  status_.model_count = config.ai.models.size();
  redacted_model_paths_ = BuildModelPathRedactions(config);

  if (!status_.enabled) {
    status_.state = "disabled";
    return common::Result<void>::Ok();
  }

  backend_ = backend_override_ != nullptr ? backend_override_
                                          : CreateBackend(config.ai.backend);
  if (backend_ == nullptr) {
    status_.state = "backend_unavailable";
    RecordError({"E_AI_BACKEND_UNAVAILABLE",
                 "AI backend is unavailable: " + config.ai.backend});
    return common::Result<void>::Ok();
  }

  status_.backend = std::string(backend_->name());

  auto initialized = backend_->Init();
  if (!initialized.ok()) {
    status_.backend_available = backend_->available();
    status_.state = "backend_unavailable";
    RecordError(initialized.error());
    return common::Result<void>::Ok();
  }

  status_.backend_available = backend_->available();
  if (!status_.backend_available) {
    status_.state = "backend_unavailable";
    RecordError({"E_AI_BACKEND_UNAVAILABLE",
                 "Hailo backend is not implemented in this build"});
  } else {
    status_.state = "ready";
  }

  for (const auto& model : config.ai.models) {
    auto loaded = backend_->LoadModel(model);
    if (!loaded.ok()) {
      if (status_.state == "ready") {
        status_.state = "error";
      }
      RecordError(loaded.error());
      continue;
    }

    model_handles_[model.id] = loaded.value();
  }

  if (config.camera.ai.enabled) {
    for (const auto& model_id : config.camera.ai.model_ids) {
      const auto* model = FindModelById(config, model_id);
      if (model == nullptr) {
        if (status_.state == "ready") {
          status_.state = "error";
        }
        RecordError({"E_AI_MODEL_NOT_FOUND",
                     "Camera AI model binding is missing model: " + model_id});
        continue;
      }

      auto handle_it = model_handles_.find(model_id);
      if (handle_it == model_handles_.end()) {
        if (status_.state == "ready") {
          status_.state = "error";
        }
        RecordError(
            {"E_AI_MODEL_NOT_LOADED", "Failed to load AI model: " + model_id});
        continue;
      }

      auto runner = std::make_shared<AiModelRunner>(
          config.camera.id, *model, backend_.get(), handle_it->second,
          detection_bus_);
      if (ready_callback_) {
        runner->SetReadyCallback(ready_callback_);
      }
      runners_.push_back(std::move(runner));
    }
  }

  status_.runner_count = runners_.size();
  (void)detection_bus_;
  return common::Result<void>::Ok();
}

void AiRuntime::Stop() {
  RuntimeResources resources;
  {
    std::lock_guard lock(mutex_);
    resources = ReleaseResourcesLocked();
  }
  StopResources(std::move(resources));
}

void AiRuntime::SetReadyCallback(std::function<void()> on_ready) {
  std::vector<std::shared_ptr<AiModelRunner>> runners;
  {
    std::lock_guard lock(mutex_);
    ready_callback_ = std::move(on_ready);
    runners = runners_;
  }
  for (const auto& runner : runners) {
    runner->SetReadyCallback(ready_callback_);
  }
}

AiRuntime::RuntimeResources AiRuntime::ReleaseResourcesLocked() {
  RuntimeResources resources;
  resources.runners = std::move(runners_);
  resources.model_handles = std::move(model_handles_);
  resources.backend = std::move(backend_);
  status_ = AiRuntimeStatus{};
  redacted_model_paths_.clear();
  return resources;
}

void AiRuntime::StopResources(RuntimeResources resources) {
  for (auto& runner : resources.runners) {
    runner->Stop();
  }
  resources.runners.clear();

  if (resources.backend != nullptr) {
    for (const auto& [model_id, handle] : resources.model_handles) {
      (void)model_id;
      resources.backend->Unload(handle);
    }
    resources.backend->Shutdown();
  }
}

common::Result<void> AiRuntime::SubmitFrame(media::FrameLease frame) {
  std::vector<std::shared_ptr<AiModelRunner>> runners;
  {
    std::lock_guard lock(mutex_);
    runners = runners_;
  }

  common::Result<void> first_error = common::Result<void>::Ok();

  const auto record_error =
      [&first_error](const common::Result<void>& submitted) {
        if (!submitted.ok() && first_error.ok()) {
          first_error = common::Result<void>::Err(submitted.error());
        }
      };
  // Every runner but the last gets a shared reference; the last one takes
  // ownership of the frame.
  for (std::size_t index = 0; index + 1U < runners.size(); ++index) {
    record_error(runners[index]->Submit(frame.CloneRef()));
  }
  if (!runners.empty()) {
    record_error(runners.back()->Submit(std::move(frame)));
  }

  if (!first_error.ok()) {
    std::lock_guard lock(mutex_);
    if (status_.state == "ready") {
      status_.state = "error";
    }
    RecordError(first_error.error());
  }

  return first_error;
}

AiRuntimeStatus AiRuntime::Status() const {
  std::lock_guard lock(mutex_);
  return status_;
}

std::vector<AiModelRunnerStatus> AiRuntime::RunnerStatuses() const {
  std::lock_guard lock(mutex_);
  std::vector<AiModelRunnerStatus> statuses;
  statuses.reserve(runners_.size());
  for (const auto& runner : runners_) {
    statuses.push_back(runner->Status());
  }
  return statuses;
}

std::shared_ptr<AiBackend> AiRuntime::CreateBackend(
    const std::string& backend_name) const {
  if (backend_name == "hailo") {
#if defined(CF_HAVE_HAILORT)
    return std::make_shared<HailoBackend>();
#else
    return std::make_shared<UnavailableAiBackend>();
#endif
  }

  return nullptr;
}

void AiRuntime::RecordError(const common::Error& error) {
  status_.last_error_code = error.code;
  status_.last_error_message = error.message;
  RedactConfiguredModelPaths(status_.last_error_message, redacted_model_paths_);
}

}  // namespace camera_firmware::ai
