#include "camera_firmware/ai/AiRuntime.hpp"

#include <utility>

namespace camera_firmware::ai {
namespace {

const config::AiModelConfig* FindModelById(const config::AppConfig& config,
                                           const std::string& model_id) {
  for (const auto& model : config.ai.models) {
    if (model.id == model_id) {
      return &model;
    }
  }

  return nullptr;
}

}  // namespace

struct AiRuntime::RuntimeResources {
  std::shared_ptr<AiBackend> backend;
  std::unordered_map<std::string, ModelHandle> model_handles;
  std::vector<std::shared_ptr<AiModelRunner>> runners;
};

AiRuntime::AiRuntime(DetectionBus* detection_bus)
    : detection_bus_(detection_bus) {}

AiRuntime::~AiRuntime() { Stop(); }

common::Result<void> AiRuntime::Start(const config::AppConfig& config) {
  Stop();

  std::lock_guard lock(mutex_);

  status_ = AiRuntimeStatus{};
  status_.enabled = config.ai.enabled;
  status_.backend = config.ai.enabled ? config.ai.backend : "disabled";
  status_.model_count = config.ai.models.size();

  if (!status_.enabled) {
    status_.state = "disabled";
    return common::Result<void>::Ok();
  }

  backend_ = CreateBackend(config.ai.backend);
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

      runners_.push_back(std::make_shared<AiModelRunner>(
          config.camera.id, *model, backend_.get(), handle_it->second));
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

AiRuntime::RuntimeResources AiRuntime::ReleaseResourcesLocked() {
  RuntimeResources resources;
  resources.runners = std::move(runners_);
  resources.model_handles = std::move(model_handles_);
  resources.backend = std::move(backend_);
  status_ = AiRuntimeStatus{};
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

  for (std::size_t index = 0; index < runners.size(); ++index) {
    auto submitted =
        index + 1U < runners.size() ? runners[index]->Submit(frame.CloneRef())
                                    : runners[index]->Submit(std::move(frame));
    if (!submitted.ok() && first_error.ok()) {
      first_error = common::Result<void>::Err(submitted.error());
    }
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
    return std::make_shared<UnavailableAiBackend>();
  }

  return nullptr;
}

void AiRuntime::RecordError(const common::Error& error) {
  status_.last_error_code = error.code;
  status_.last_error_message = error.message;
}

}  // namespace camera_firmware::ai
