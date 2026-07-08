#include "camera_firmware/ai/HailoBackend.hpp"

#include <hailo/hailort.h>
#include <hailo/infer_model.hpp>
#include <hailo/vdevice.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <limits>
#include <string>
#include <utility>

#include <unistd.h>

namespace camera_firmware::ai {
namespace {

constexpr auto kAsyncReadyTimeout = std::chrono::milliseconds(50);

std::string StatusMessage(std::string prefix, hailo_status status) {
  return std::move(prefix) + " (hailo_status=" + std::to_string(status) + ")";
}

struct PageAlignedBuffer {
  std::size_t size{0};
  std::size_t allocated_size{0};
  std::uint8_t* data{nullptr};

  PageAlignedBuffer(const PageAlignedBuffer&) = delete;
  PageAlignedBuffer& operator=(const PageAlignedBuffer&) = delete;

  PageAlignedBuffer() = default;
  ~PageAlignedBuffer() { std::free(data); }
};

std::shared_ptr<PageAlignedBuffer> AllocatePageAligned(std::size_t size) {
  if (size == 0U) {
    return nullptr;
  }

  long page_size = ::sysconf(_SC_PAGESIZE);
  if (page_size <= 0) {
    page_size = 4096;
  }
  const auto page = static_cast<std::size_t>(page_size);
  if (size > std::numeric_limits<std::size_t>::max() - page + 1U) {
    return nullptr;
  }
  const std::size_t allocated = ((size + page - 1U) / page) * page;

  void* data = nullptr;
  if (posix_memalign(&data, page, allocated) != 0) {
    return nullptr;
  }

  auto buffer = std::make_shared<PageAlignedBuffer>();
  buffer->size = size;
  buffer->allocated_size = allocated;
  buffer->data = static_cast<std::uint8_t*>(data);
  return buffer;
}

}  // namespace

struct HailoBackend::LoadedModel {
  std::string id;
  std::shared_ptr<hailort::InferModel> infer_model;
  std::unique_ptr<hailort::ConfiguredInferModel> configured;
  std::string input_name;
  std::string output_name;
  std::size_t output_size{0};
};

HailoBackend::HailoBackend() = default;

HailoBackend::~HailoBackend() { Shutdown(); }

std::string_view HailoBackend::name() const noexcept { return "hailo"; }

bool HailoBackend::available() const noexcept {
  std::lock_guard lock(mutex_);
  return vdevice_ != nullptr && !shutting_down_;
}

common::Result<void> HailoBackend::Init() {
  std::unique_lock lock(mutex_);
  shutting_down_ = true;
  idle_.wait(lock, [this] { return in_flight_ == 0U; });
  models_.clear();
  vdevice_.reset();
  shutting_down_ = false;

  hailo_vdevice_params_t params{};
  const hailo_status param_status = hailo_init_vdevice_params(&params);
  if (param_status != HAILO_SUCCESS) {
    return common::Result<void>::Err(
        {"E_HAILO_PARAMS",
         StatusMessage("hailo_init_vdevice_params failed", param_status)});
  }

  params.scheduling_algorithm = HAILO_SCHEDULING_ALGORITHM_ROUND_ROBIN;
  params.multi_process_service = false;

  auto created = hailort::VDevice::create(params);
  if (!created) {
    return common::Result<void>::Err(
        {"E_HAILO_VDEVICE",
         StatusMessage("failed to create Hailo VDevice", created.status())});
  }

  vdevice_ = std::move(created.value());
  return common::Result<void>::Ok();
}

void HailoBackend::Shutdown() {
  std::unique_lock lock(mutex_);
  shutting_down_ = true;
  idle_.wait(lock, [this] { return in_flight_ == 0U; });
  models_.clear();
  vdevice_.reset();
}

common::Result<ModelHandle> HailoBackend::LoadModel(
    const config::AiModelConfig& model) {
  std::shared_ptr<hailort::InferModel> infer_model;
  {
    std::lock_guard lock(mutex_);
    if (vdevice_ == nullptr) {
      return common::Result<ModelHandle>::Err(
          {"E_HAILO_NOT_INITIALIZED", "Hailo backend is not initialized"});
    }

    auto created_model = vdevice_->create_infer_model(model.hef_path);
    if (!created_model) {
      return common::Result<ModelHandle>::Err(
          {"E_HAILO_HEF",
           StatusMessage("failed to create Hailo infer model from " +
                             model.hef_path,
                         created_model.status())});
    }
    infer_model = std::move(created_model.value());
  }

  auto input = infer_model->input();
  if (!input) {
    return common::Result<ModelHandle>::Err(
        {"E_HAILO_INPUT", StatusMessage("HEF must expose one input",
                                        input.status())});
  }
  input.value().set_format_type(HAILO_FORMAT_TYPE_UINT8);
  input.value().set_format_order(HAILO_FORMAT_ORDER_NHWC);

  auto output = infer_model->output();
  if (!output) {
    return common::Result<ModelHandle>::Err(
        {"E_HAILO_OUTPUT", StatusMessage("HEF must expose one output",
                                         output.status())});
  }

  auto configured = infer_model->configure();
  if (!configured) {
    return common::Result<ModelHandle>::Err(
        {"E_HAILO_CONFIGURE",
         StatusMessage("failed to configure Hailo infer model",
                       configured.status())});
  }

  auto loaded = std::make_shared<LoadedModel>();
  loaded->id = model.id;
  loaded->infer_model = std::move(infer_model);
  loaded->configured =
      std::make_unique<hailort::ConfiguredInferModel>(
          std::move(configured.value()));
  loaded->input_name = input.value().name();
  loaded->output_name = output.value().name();
  loaded->output_size = output.value().get_frame_size();
  if (loaded->output_size == 0U) {
    return common::Result<ModelHandle>::Err(
        {"E_HAILO_OUTPUT_SIZE", "HEF output frame size is zero"});
  }

  std::lock_guard lock(mutex_);
  models_.push_back(std::move(loaded));
  return common::Result<ModelHandle>::Ok(models_.size() - 1U);
}

void HailoBackend::Unload(ModelHandle handle) {
  std::lock_guard lock(mutex_);
  if (handle < models_.size()) {
    models_[handle].reset();
  }
}

void HailoBackend::FinishInference() noexcept {
  {
    std::lock_guard lock(mutex_);
    if (in_flight_ > 0U) {
      --in_flight_;
    }
  }
  idle_.notify_all();
}

common::Result<void> HailoBackend::Submit(ModelHandle handle,
                                          InputView input,
                                          InferCallback callback) {
  if (input.data == nullptr || input.size == 0U) {
    return common::Result<void>::Err(
        {"E_HAILO_INPUT", "Hailo input buffer is empty"});
  }

  std::shared_ptr<LoadedModel> model;
  {
    std::lock_guard lock(mutex_);
    if (shutting_down_) {
      return common::Result<void>::Err(
          {"E_HAILO_SHUTDOWN", "Hailo backend is shutting down"});
    }
    if (handle >= models_.size() || models_[handle] == nullptr) {
      return common::Result<void>::Err(
          {"E_HAILO_BAD_HANDLE", "Unknown Hailo model handle"});
    }
    model = models_[handle];
    ++in_flight_;
  }

  struct InFlightGuard {
    explicit InFlightGuard(HailoBackend* owner) : backend(owner) {}
    InFlightGuard(const InFlightGuard&) = delete;
    InFlightGuard& operator=(const InFlightGuard&) = delete;
    ~InFlightGuard() {
      if (active && backend != nullptr) {
        backend->FinishInference();
      }
    }
    void Dismiss() noexcept { active = false; }

    HailoBackend* backend{nullptr};
    bool active{true};
  } in_flight(this);

  auto output_buffer = AllocatePageAligned(model->output_size);
  if (output_buffer == nullptr) {
    return common::Result<void>::Err(
        {"E_HAILO_ALLOC", "failed to allocate page-aligned output buffer"});
  }

  auto bindings = model->configured->create_bindings();
  if (!bindings) {
    return common::Result<void>::Err(
        {"E_HAILO_BINDINGS",
         StatusMessage("failed to create Hailo bindings", bindings.status())});
  }
  auto binding_state =
      std::make_shared<hailort::ConfiguredInferModel::Bindings>(
          std::move(bindings.value()));

  auto input_stream = binding_state->input(model->input_name);
  if (!input_stream) {
    return common::Result<void>::Err(
        {"E_HAILO_INPUT",
         StatusMessage("failed to bind Hailo input", input_stream.status())});
  }
  const hailo_status input_status = input_stream.value().set_buffer(
      hailort::MemoryView(const_cast<std::uint8_t*>(input.data), input.size));
  if (input_status != HAILO_SUCCESS) {
    return common::Result<void>::Err(
        {"E_HAILO_INPUT", StatusMessage("failed to set Hailo input buffer",
                                        input_status)});
  }

  auto output_stream = binding_state->output(model->output_name);
  if (!output_stream) {
    return common::Result<void>::Err(
        {"E_HAILO_OUTPUT",
         StatusMessage("failed to bind Hailo output", output_stream.status())});
  }
  const hailo_status output_status = output_stream.value().set_buffer(
      hailort::MemoryView(output_buffer->data, output_buffer->size));
  if (output_status != HAILO_SUCCESS) {
    return common::Result<void>::Err(
        {"E_HAILO_OUTPUT", StatusMessage("failed to set Hailo output buffer",
                                         output_status)});
  }

  const hailo_status ready_status =
      model->configured->wait_for_async_ready(kAsyncReadyTimeout);
  if (ready_status != HAILO_SUCCESS) {
    return common::Result<void>::Err(
        {"E_HAILO_WAIT",
         StatusMessage("Hailo async pipeline was not ready", ready_status)});
  }

  auto job = model->configured->run_async(
      *binding_state,
      [this,
       callback = std::move(callback),
       binding_state,
       output_buffer,
       model](
          const hailort::AsyncInferCompletionInfo& info) mutable {
        struct CompletionGuard {
          explicit CompletionGuard(HailoBackend* owner) : backend(owner) {}
          CompletionGuard(const CompletionGuard&) = delete;
          CompletionGuard& operator=(const CompletionGuard&) = delete;
          ~CompletionGuard() {
            if (backend != nullptr) {
              backend->FinishInference();
            }
          }

          HailoBackend* backend{nullptr};
        } completion(this);

        (void)binding_state;
        (void)model;
        if (!callback) {
          return;
        }
        if (info.status != HAILO_SUCCESS) {
          callback(common::Result<OutputView>::Err(
              {"E_HAILO_INFER",
               StatusMessage("Hailo inference failed", info.status)}));
          return;
        }
        callback(common::Result<OutputView>::Ok(
            OutputView{output_buffer->data, output_buffer->size}));
      });
  if (!job) {
    return common::Result<void>::Err(
        {"E_HAILO_SUBMIT",
         StatusMessage("failed to submit Hailo async inference",
                       job.status())});
  }

  job.value().detach();
  in_flight.Dismiss();
  return common::Result<void>::Ok();
}

}  // namespace camera_firmware::ai
