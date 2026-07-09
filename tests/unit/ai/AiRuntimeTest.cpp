#include "camera_firmware/ai/AiRuntime.hpp"
#include "camera_firmware/ai/AiFramePump.hpp"
#include "camera_firmware/ai/AiFrameTap.hpp"
#include "camera_firmware/ai/AiRuntimeController.hpp"

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

camera_firmware::config::AiModelConfig Model(std::string id,
                                             std::string kind) {
  camera_firmware::config::AiModelConfig model;
  model.id = std::move(id);
  model.kind = std::move(kind);
  model.hef_path = "/opt/cf/models/" + model.id + ".hef";
  model.input.width = 640;
  model.input.height = 640;
  model.input.format = "rgb8";
  return model;
}

camera_firmware::config::AppConfig RuntimeConfig() {
  camera_firmware::config::AppConfig config;
  config.ai.enabled = true;
  config.ai.backend = "hailo";
  config.ai.models.push_back(Model("objects", "object_detection"));
  config.ai.models.push_back(Model("pose", "pose"));
  config.camera.ai.enabled = true;
  config.camera.ai.model_ids = {"objects", "pose"};
  return config;
}

std::shared_ptr<camera_firmware::ai::AiBackend> UnavailableBackend() {
  return std::make_shared<camera_firmware::ai::UnavailableAiBackend>();
}

class GateBackend final : public camera_firmware::ai::AiBackend {
 public:
  [[nodiscard]] std::string_view name() const noexcept override {
    return "gate";
  }

  [[nodiscard]] bool available() const noexcept override { return true; }

  [[nodiscard]] camera_firmware::common::Result<void> Init() override {
    return camera_firmware::common::Result<void>::Ok();
  }

  void Shutdown() override {}

  [[nodiscard]] camera_firmware::common::Result<camera_firmware::ai::ModelHandle>
  LoadModel(const camera_firmware::config::AiModelConfig&) override {
    return camera_firmware::common::Result<camera_firmware::ai::ModelHandle>::Ok(
        1);
  }

  void Unload(camera_firmware::ai::ModelHandle) override {}

  [[nodiscard]] camera_firmware::common::Result<void> Submit(
      camera_firmware::ai::ModelHandle,
      camera_firmware::ai::InputView,
      camera_firmware::ai::InferCallback callback) override {
    {
      std::unique_lock lock(mutex_);
      ++submit_count_;
      changed_.notify_all();
      changed_.wait(lock, [this] { return allowed_submits_ > 0; });
      --allowed_submits_;
    }

    if (callback) {
      callback(camera_firmware::common::Result<camera_firmware::ai::OutputView>::
                   Ok(camera_firmware::ai::OutputView{}));
    }
    return camera_firmware::common::Result<void>::Ok();
  }

  bool WaitForSubmitCount(int expected) {
    std::unique_lock lock(mutex_);
    return changed_.wait_for(lock, std::chrono::seconds(1), [this, expected] {
      return submit_count_ >= expected;
    });
  }

  void AllowOne() {
    {
      std::lock_guard lock(mutex_);
      ++allowed_submits_;
    }
    changed_.notify_all();
  }

  [[nodiscard]] int submit_count() const {
    std::lock_guard lock(mutex_);
    return submit_count_;
  }

 private:
  mutable std::mutex mutex_;
  std::condition_variable changed_;
  int submit_count_{0};
  int allowed_submits_{0};
};

class AsyncCallbackBackend final : public camera_firmware::ai::AiBackend {
 public:
  [[nodiscard]] std::string_view name() const noexcept override {
    return "async";
  }

  [[nodiscard]] bool available() const noexcept override { return true; }

  [[nodiscard]] camera_firmware::common::Result<void> Init() override {
    return camera_firmware::common::Result<void>::Ok();
  }

  void Shutdown() override {}

  [[nodiscard]] camera_firmware::common::Result<camera_firmware::ai::ModelHandle>
  LoadModel(const camera_firmware::config::AiModelConfig&) override {
    return camera_firmware::common::Result<camera_firmware::ai::ModelHandle>::Ok(
        1);
  }

  void Unload(camera_firmware::ai::ModelHandle) override {}

  [[nodiscard]] camera_firmware::common::Result<void> Submit(
      camera_firmware::ai::ModelHandle,
      camera_firmware::ai::InputView,
      camera_firmware::ai::InferCallback callback) override {
    {
      std::lock_guard lock(mutex_);
      callbacks_.push_back(std::move(callback));
      ++submit_count_;
    }
    changed_.notify_all();
    return camera_firmware::common::Result<void>::Ok();
  }

  bool WaitForSubmit() {
    return WaitForSubmitCount(1);
  }

  bool WaitForSubmitCount(int expected) {
    std::unique_lock lock(mutex_);
    return changed_.wait_for(lock, std::chrono::seconds(1), [this, expected] {
      return submit_count_ >= expected;
    });
  }

  void Complete() {
    camera_firmware::ai::InferCallback callback;
    {
      std::lock_guard lock(mutex_);
      if (callbacks_.empty()) {
        return;
      }
      callback = std::move(callbacks_.front());
      callbacks_.erase(callbacks_.begin());
    }
    if (callback) {
      callback(camera_firmware::common::Result<camera_firmware::ai::OutputView>::
                   Ok(camera_firmware::ai::OutputView{}));
    }
  }

 private:
  mutable std::mutex mutex_;
  std::condition_variable changed_;
  std::vector<camera_firmware::ai::InferCallback> callbacks_;
  int submit_count_{0};
};

class CapturingSuccessBackend final : public camera_firmware::ai::AiBackend {
 public:
  explicit CapturingSuccessBackend(std::vector<std::uint8_t> output = {})
      : output_(std::move(output)) {}

  [[nodiscard]] std::string_view name() const noexcept override {
    return "capture";
  }

  [[nodiscard]] bool available() const noexcept override { return true; }

  [[nodiscard]] camera_firmware::common::Result<void> Init() override {
    return camera_firmware::common::Result<void>::Ok();
  }

  void Shutdown() override {}

  [[nodiscard]] camera_firmware::common::Result<camera_firmware::ai::ModelHandle>
  LoadModel(const camera_firmware::config::AiModelConfig&) override {
    return camera_firmware::common::Result<camera_firmware::ai::ModelHandle>::Ok(
        1);
  }

  void Unload(camera_firmware::ai::ModelHandle) override {}

  [[nodiscard]] camera_firmware::common::Result<void> Submit(
      camera_firmware::ai::ModelHandle,
      camera_firmware::ai::InputView input,
      camera_firmware::ai::InferCallback callback) override {
    {
      std::lock_guard lock(mutex_);
      ++submit_count_;
      last_input_size_ = input.size;
      last_input_was_null_ = input.data == nullptr;
    }
    changed_.notify_all();
    if (callback) {
      camera_firmware::ai::OutputView output;
      if (!output_.empty()) {
        output.data = output_.data();
        output.size = output_.size();
      }
      callback(camera_firmware::common::Result<camera_firmware::ai::OutputView>::
                   Ok(output));
    }
    return camera_firmware::common::Result<void>::Ok();
  }

  bool WaitForSubmit() {
    std::unique_lock lock(mutex_);
    return changed_.wait_for(lock, std::chrono::seconds(1), [this] {
      return submit_count_ >= 1;
    });
  }

  [[nodiscard]] std::size_t last_input_size() const {
    std::lock_guard lock(mutex_);
    return last_input_size_;
  }

  [[nodiscard]] bool last_input_was_null() const {
    std::lock_guard lock(mutex_);
    return last_input_was_null_;
  }

 private:
  mutable std::mutex mutex_;
  std::condition_variable changed_;
  int submit_count_{0};
  std::size_t last_input_size_{0};
  bool last_input_was_null_{true};
  std::vector<std::uint8_t> output_;
};

class BlockingInitBackend final : public camera_firmware::ai::AiBackend {
 public:
  [[nodiscard]] std::string_view name() const noexcept override {
    return "blocking-init";
  }

  [[nodiscard]] bool available() const noexcept override { return true; }

  [[nodiscard]] camera_firmware::common::Result<void> Init() override {
    std::unique_lock lock(mutex_);
    init_started_ = true;
    changed_.notify_all();
    changed_.wait(lock, [this] { return init_released_; });
    return camera_firmware::common::Result<void>::Ok();
  }

  void Shutdown() override {}

  [[nodiscard]] camera_firmware::common::Result<camera_firmware::ai::ModelHandle>
  LoadModel(const camera_firmware::config::AiModelConfig&) override {
    return camera_firmware::common::Result<camera_firmware::ai::ModelHandle>::Ok(
        1);
  }

  void Unload(camera_firmware::ai::ModelHandle) override {}

  [[nodiscard]] camera_firmware::common::Result<void> Submit(
      camera_firmware::ai::ModelHandle,
      camera_firmware::ai::InputView,
      camera_firmware::ai::InferCallback callback) override {
    if (callback) {
      callback(camera_firmware::common::Result<camera_firmware::ai::OutputView>::
                   Ok(camera_firmware::ai::OutputView{}));
    }
    return camera_firmware::common::Result<void>::Ok();
  }

  bool WaitForInit() {
    std::unique_lock lock(mutex_);
    return changed_.wait_for(lock, std::chrono::seconds(1), [this] {
      return init_started_;
    });
  }

  void ReleaseInit() {
    {
      std::lock_guard lock(mutex_);
      init_released_ = true;
    }
    changed_.notify_all();
  }

 private:
  mutable std::mutex mutex_;
  std::condition_variable changed_;
  bool init_started_{false};
  bool init_released_{false};
};

class ModelPathErrorBackend final : public camera_firmware::ai::AiBackend {
 public:
  [[nodiscard]] std::string_view name() const noexcept override {
    return "model-path-error";
  }

  [[nodiscard]] bool available() const noexcept override { return true; }

  [[nodiscard]] camera_firmware::common::Result<void> Init() override {
    return camera_firmware::common::Result<void>::Ok();
  }

  void Shutdown() override {}

  [[nodiscard]] camera_firmware::common::Result<camera_firmware::ai::ModelHandle>
  LoadModel(const camera_firmware::config::AiModelConfig& model) override {
    return camera_firmware::common::Result<camera_firmware::ai::ModelHandle>::Err(
        {"E_HAILO_HEF",
         "failed to load model " + model.id + " from " + model.hef_path});
  }

  void Unload(camera_firmware::ai::ModelHandle) override {}

  [[nodiscard]] camera_firmware::common::Result<void> Submit(
      camera_firmware::ai::ModelHandle,
      camera_firmware::ai::InputView,
      camera_firmware::ai::InferCallback) override {
    return camera_firmware::common::Result<void>::Ok();
  }
};

bool WaitUntilRunnerDropped(camera_firmware::ai::AiRuntime& runtime,
                            std::size_t runner_count) {
  for (int attempt = 0; attempt < 100; ++attempt) {
    const auto runners = runtime.RunnerStatuses();
    if (runners.size() == runner_count) {
      bool all_dropped = true;
      for (const auto& runner : runners) {
        all_dropped = all_dropped && runner.dropped_frames == 1U;
      }
      if (all_dropped) {
        return true;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return false;
}

int CreateRuntimeAnonymousFile(const std::vector<std::uint8_t>& bytes) {
  std::array<char, 32> path{"/tmp/cf-ai-run-XXXXXX"};
  int fd = ::mkstemp(path.data());
  if (fd < 0) {
    return -1;
  }
  (void)::unlink(path.data());
  if (::ftruncate(fd, static_cast<off_t>(bytes.size())) != 0) {
    (void)::close(fd);
    return -1;
  }
  if (::write(fd, bytes.data(), bytes.size()) !=
      static_cast<ssize_t>(bytes.size())) {
    (void)::close(fd);
    return -1;
  }
  return fd;
}

camera_firmware::media::FrameHandle Nv12RuntimeHandle(
    std::uint64_t sequence,
    int fd) {
  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 8;
  handle.height = 4;
  handle.sequence = sequence;
  handle.plane_count = 2;
  handle.planes[0].dmabuf_fd = fd;
  handle.planes[0].stride = 8;
  handle.planes[0].length = 32;
  handle.planes[0].offset = 0;
  handle.planes[1].dmabuf_fd = fd;
  handle.planes[1].stride = 8;
  handle.planes[1].length = 16;
  handle.planes[1].offset = handle.planes[0].length;
  return handle;
}

camera_firmware::media::FrameLease Nv12RuntimeLease(
    std::uint64_t sequence,
    camera_firmware::media::FrameLease::ReleaseCallback release_callback =
        [] {}) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(8U * 4U + 8U * 2U);
  bytes.insert(bytes.end(), 8U * 4U, 16U);
  bytes.insert(bytes.end(), 8U * 2U, 128U);
  const int fd = CreateRuntimeAnonymousFile(bytes);
  auto handle = Nv12RuntimeHandle(sequence, fd);
  return camera_firmware::media::FrameLease(std::move(handle),
                                            [fd,
                                             release_callback =
                                                 std::move(release_callback)] {
                                              if (fd >= 0) {
                                                (void)::close(fd);
                                              }
                                              release_callback();
                                            });
}

std::vector<std::uint8_t> RuntimeYoloNmsOutputBytes(float confidence) {
  constexpr int kClassCount = 80;
  constexpr int kMaxBoxesPerClass = 100;
  constexpr int kValuesPerClass = 1 + (kMaxBoxesPerClass * 5);

  std::vector<float> tensor(kClassCount * kValuesPerClass, 0.0F);
  const std::size_t class_offset = 2U * kValuesPerClass;
  tensor[class_offset] = 1.0F;
  tensor[class_offset + 1U] = 0.20F;
  tensor[class_offset + 2U] = 0.15F;
  tensor[class_offset + 3U] = 0.70F;
  tensor[class_offset + 4U] = 0.65F;
  tensor[class_offset + 5U] = confidence;

  std::vector<std::uint8_t> bytes(tensor.size() * sizeof(float));
  std::memcpy(bytes.data(), tensor.data(), bytes.size());
  return bytes;
}

std::vector<std::uint8_t> RuntimeYoloPoseOutputBytes(float confidence) {
  constexpr std::size_t kPoseRowFloats = 5U + (17U * 3U);

  std::vector<float> tensor(kPoseRowFloats, 0.0F);
  tensor[0] = 0.15F;
  tensor[1] = 0.20F;
  tensor[2] = 0.65F;
  tensor[3] = 0.70F;
  tensor[4] = confidence;
  tensor[5] = 0.45F;
  tensor[6] = 0.25F;
  tensor[7] = 0.93F;
  const std::size_t left_shoulder = 5U + (5U * 3U);
  tensor[left_shoulder] = 0.35F;
  tensor[left_shoulder + 1U] = 0.50F;
  tensor[left_shoulder + 2U] = 0.86F;

  std::vector<std::uint8_t> bytes(tensor.size() * sizeof(float));
  std::memcpy(bytes.data(), tensor.data(), bytes.size());
  return bytes;
}

}  // namespace

TEST(AiRuntimeTest, DisabledRuntimeStartsAndStopsCleanly) {
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(&bus);
  camera_firmware::config::AppConfig config;

  auto started = runtime.Start(config);

  ASSERT_TRUE(started.ok()) << started.error().message;
  auto status = runtime.Status();
  EXPECT_FALSE(status.enabled);
  EXPECT_EQ(status.state, "disabled");
  EXPECT_EQ(status.model_count, 0u);
  EXPECT_EQ(status.runner_count, 0u);
  runtime.Stop();
}

TEST(AiRuntimeTest, BuildsRunnerPerConfiguredCameraModel) {
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(&bus, UnavailableBackend());

  auto started = runtime.Start(RuntimeConfig());

  ASSERT_TRUE(started.ok()) << started.error().message;
  auto status = runtime.Status();
  EXPECT_TRUE(status.enabled);
  EXPECT_EQ(status.backend, "hailo");
  EXPECT_EQ(status.state, "backend_unavailable");
  EXPECT_FALSE(status.backend_available);
  EXPECT_EQ(status.model_count, 2u);
  EXPECT_EQ(status.runner_count, 2u);
  EXPECT_EQ(status.last_error_code, "E_AI_BACKEND_UNAVAILABLE");

  auto runners = runtime.RunnerStatuses();
  ASSERT_EQ(runners.size(), 2u);
  EXPECT_EQ(runners[0].camera_id, "imx708-main");
  EXPECT_EQ(runners[0].model_id, "objects");
  EXPECT_EQ(runners[1].model_id, "pose");
}

TEST(AiRuntimeTest, GlobalAiEnabledWithoutCameraBindingIsConfigured) {
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(&bus, UnavailableBackend());
  auto config = RuntimeConfig();
  config.camera.ai.enabled = false;
  config.camera.ai.model_ids.clear();

  auto started = runtime.Start(config);

  ASSERT_TRUE(started.ok()) << started.error().message;
  auto status = runtime.Status();
  EXPECT_TRUE(status.enabled);
  EXPECT_EQ(status.backend, "hailo");
  EXPECT_EQ(status.state, "backend_unavailable");
  EXPECT_FALSE(status.backend_available);
  EXPECT_EQ(status.model_count, 2u);
  EXPECT_EQ(status.runner_count, 0u);
  EXPECT_EQ(status.last_error_code, "E_AI_BACKEND_UNAVAILABLE");
  EXPECT_TRUE(runtime.RunnerStatuses().empty());
}

TEST(AiRuntimeTest, ControllerRestartsRuntimeAndStartsPumpWhenCameraAiEnabled) {
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiFrameTap tap;
  camera_firmware::ai::AiRuntime runtime(&bus, UnavailableBackend());
  camera_firmware::ai::AiFramePump pump(tap, runtime);
  const auto config = RuntimeConfig();
  camera_firmware::ai::AiRuntimeController controller(config, runtime, pump);

  auto restarted = controller.Restart();

  ASSERT_TRUE(restarted.ok()) << restarted.error().message;
  tap.PublishLatest(Nv12RuntimeLease(31));
  EXPECT_TRUE(WaitUntilRunnerDropped(runtime, 2u));
  controller.BeginShutdown();
  controller.Stop();
}

TEST(AiRuntimeTest, ControllerRejectsRestartsAfterShutdownBegins) {
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiFrameTap tap;
  camera_firmware::ai::AiRuntime runtime(&bus, UnavailableBackend());
  camera_firmware::ai::AiFramePump pump(tap, runtime);
  const auto config = RuntimeConfig();
  camera_firmware::ai::AiRuntimeController controller(config, runtime, pump);
  ASSERT_TRUE(controller.Restart().ok());

  controller.BeginShutdown();
  auto restarted = controller.Restart();

  ASSERT_FALSE(restarted.ok());
  EXPECT_EQ(restarted.error().code, "E_AI_CONTROL_SHUTTING_DOWN");
  controller.Stop();
  EXPECT_FALSE(runtime.Status().enabled);
}

TEST(AiRuntimeTest, ControllerShutdownWaitsForActiveRestart) {
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiFrameTap tap;
  auto backend = std::make_shared<BlockingInitBackend>();
  camera_firmware::ai::AiRuntime runtime(&bus, backend);
  camera_firmware::ai::AiFramePump pump(tap, runtime);
  const auto config = RuntimeConfig();
  camera_firmware::ai::AiRuntimeController controller(config, runtime, pump);

  auto restart = std::async(std::launch::async, [&controller] {
    return controller.Restart();
  });
  ASSERT_TRUE(backend->WaitForInit());

  auto shutdown = std::async(std::launch::async, [&controller] {
    controller.BeginShutdown();
  });
  EXPECT_EQ(shutdown.wait_for(std::chrono::milliseconds(50)),
            std::future_status::timeout);

  backend->ReleaseInit();
  ASSERT_EQ(restart.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  ASSERT_TRUE(restart.get().ok());
  ASSERT_EQ(shutdown.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);

  auto second_restart = controller.Restart();
  ASSERT_FALSE(second_restart.ok());
  EXPECT_EQ(second_restart.error().code, "E_AI_CONTROL_SHUTTING_DOWN");
  controller.Stop();
}

TEST(AiRuntimeTest, BuildDetectsHailortWhenInstalled) {
#if defined(CF_TEST_EXPECT_HAILORT)
#if !defined(CF_HAVE_HAILORT)
  FAIL() << "HailoRT headers/library were detected by CMake, but "
            "CF_HAVE_HAILORT was not defined for the AI target";
#endif
#else
  GTEST_SKIP() << "HailoRT is not installed on this build host";
#endif
}

TEST(AiRuntimeTest, HailortBackendReportsDeviceInitFailureWithoutFallback) {
#if defined(CF_HAVE_HAILORT)
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(&bus);

  auto started = runtime.Start(RuntimeConfig());

  ASSERT_TRUE(started.ok()) << started.error().message;
  const auto status = runtime.Status();
  if (status.backend_available) {
    GTEST_SKIP() << "Hailo device is available on this host";
  }
  EXPECT_EQ(status.backend, "hailo");
  EXPECT_EQ(status.state, "backend_unavailable");
  EXPECT_EQ(status.runner_count, 0u);
  EXPECT_TRUE(status.last_error_code.starts_with("E_HAILO_"))
      << status.last_error_code;
#else
  GTEST_SKIP() << "HailoRT is not enabled in this build";
#endif
}

TEST(AiRuntimeTest, RedactsConfiguredModelPathsFromLoadErrors) {
  camera_firmware::config::AppConfig config;
  config.ai.enabled = true;
  config.ai.backend = "hailo";
  auto model = Model("objects", "object_detection");
  model.hef_path = "/opt/cf/models/private/objects.hef";
  config.ai.models.push_back(model);
  config.camera.ai.enabled = false;
  config.camera.ai.model_ids = {};

  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(
      &bus,
      std::make_shared<ModelPathErrorBackend>());

  auto started = runtime.Start(config);

  ASSERT_TRUE(started.ok()) << started.error().message;
  const auto status = runtime.Status();
  EXPECT_EQ(status.state, "error");
  EXPECT_EQ(status.last_error_code, "E_HAILO_HEF");
  EXPECT_EQ(status.last_error_message,
            "failed to load model objects from [redacted model path]");
  EXPECT_EQ(status.last_error_message.find(model.hef_path), std::string::npos);
}

TEST(AiRuntimeTest, RedactsConfiguredModelPathsAtStatusWriteBoundary) {
  camera_firmware::config::AppConfig config;
  config.ai.enabled = true;
  auto parent_path = Model("parent", "object_detection");
  parent_path.hef_path = "/opt/cf/models/private";
  auto model = Model("objects", "object_detection");
  model.hef_path = "/opt/cf/models/private/objects.hef";
  config.ai.models.push_back(parent_path);
  config.ai.models.push_back(model);
  config.ai.backend = model.hef_path;

  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(&bus);

  auto started = runtime.Start(config);

  ASSERT_TRUE(started.ok()) << started.error().message;
  const auto status = runtime.Status();
  EXPECT_EQ(status.state, "backend_unavailable");
  EXPECT_EQ(status.last_error_code, "E_AI_BACKEND_UNAVAILABLE");
  EXPECT_EQ(status.last_error_message,
            "AI backend is unavailable: [redacted model path]");
  EXPECT_EQ(status.last_error_message.find(model.hef_path), std::string::npos);
  EXPECT_EQ(status.last_error_message.find("objects.hef"), std::string::npos);
}

TEST(AiRuntimeTest, BackendUnavailableSubmitDropsWithoutPublishing) {
  camera_firmware::ai::DetectionBus bus;
  int published = 0;
  auto subscription = bus.Subscribe(
      [&published](const camera_firmware::ai::DetectionEvent&) { ++published; });
  camera_firmware::ai::AiRuntime runtime(&bus, UnavailableBackend());
  ASSERT_TRUE(runtime.Start(RuntimeConfig()).ok());

  auto submitted = runtime.SubmitFrame(Nv12RuntimeLease(9));

  ASSERT_TRUE(submitted.ok()) << submitted.error().message;
  ASSERT_TRUE(WaitUntilRunnerDropped(runtime, 2u));
  EXPECT_EQ(published, 0);
  auto runners = runtime.RunnerStatuses();
  ASSERT_EQ(runners.size(), 2u);
  EXPECT_EQ(runners[0].submitted_frames, 1u);
  EXPECT_EQ(runners[0].dropped_frames, 1u);
  EXPECT_EQ(runners[0].last_error_code, "E_AI_BACKEND_UNAVAILABLE");
  EXPECT_EQ(runners[1].submitted_frames, 1u);
  EXPECT_EQ(runners[1].dropped_frames, 1u);
  EXPECT_TRUE(subscription.valid());
}

TEST(AiRuntimeTest, MultiRunnerSubmitReleasesFrameLeaseOnce) {
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::AiRuntime runtime(&bus, UnavailableBackend());
  ASSERT_TRUE(runtime.Start(RuntimeConfig()).ok());

  int releases = 0;
  {
    auto lease = Nv12RuntimeLease(10, [&] { ++releases; });
    ASSERT_TRUE(runtime.SubmitFrame(std::move(lease)).ok());
  }

  runtime.Stop();
  EXPECT_EQ(releases, 1);
}

TEST(AiRuntimeTest, ModelRunnerSubmitUsesLatestWinsQueue) {
  GateBackend backend;
  auto model = Model("objects", "object_detection");
  camera_firmware::ai::AiModelRunner runner(
      "imx708-main", model, &backend, 1);

  int releases = 0;
  auto make_lease = [&releases](std::uint64_t sequence) {
    return Nv12RuntimeLease(sequence, [&releases] { ++releases; });
  };

  auto first_submit = std::async(
      std::launch::async,
      [&runner, lease = make_lease(1)]() mutable {
        return runner.Submit(std::move(lease));
      });

  if (first_submit.wait_for(std::chrono::milliseconds(100)) !=
      std::future_status::ready) {
    backend.AllowOne();
    ASSERT_EQ(first_submit.wait_for(std::chrono::seconds(1)),
              std::future_status::ready);
    FAIL() << "AiModelRunner::Submit blocked on backend submission";
  }
  ASSERT_TRUE(first_submit.get().ok());
  ASSERT_TRUE(backend.WaitForSubmitCount(1));

  ASSERT_TRUE(runner.Submit(make_lease(2)).ok());
  ASSERT_TRUE(runner.Submit(make_lease(3)).ok());

  backend.AllowOne();
  ASSERT_TRUE(backend.WaitForSubmitCount(2));
  backend.AllowOne();
  runner.Stop();

  EXPECT_EQ(backend.submit_count(), 2);
  auto status = runner.Status();
  EXPECT_EQ(status.submitted_frames, 3u);
  EXPECT_EQ(status.processed_frames, 2u);
  EXPECT_EQ(releases, 3);
}

TEST(AiRuntimeTest, ModelRunnerStopWaitsForAsyncBackendCallback) {
  AsyncCallbackBackend backend;
  auto model = Model("objects", "object_detection");
  camera_firmware::ai::AiModelRunner runner(
      "imx708-main", model, &backend, 1);

  ASSERT_TRUE(runner.Submit(Nv12RuntimeLease(4)).ok());
  ASSERT_TRUE(backend.WaitForSubmit());

  auto stop = std::async(std::launch::async, [&runner] { runner.Stop(); });

  ASSERT_EQ(stop.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);
  backend.Complete();
  ASSERT_EQ(stop.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);

  auto status = runner.Status();
  EXPECT_EQ(status.submitted_frames, 1u);
  EXPECT_EQ(status.processed_frames, 1u);
}

TEST(AiRuntimeTest, ModelRunnerKeepsOneAsyncInferenceInFlight) {
  AsyncCallbackBackend backend;
  auto model = Model("objects", "object_detection");
  camera_firmware::ai::AiModelRunner runner(
      "imx708-main", model, &backend, 1);

  auto make_lease = [](std::uint64_t sequence) {
    return Nv12RuntimeLease(sequence);
  };

  ASSERT_TRUE(runner.Submit(make_lease(1)).ok());
  ASSERT_TRUE(backend.WaitForSubmitCount(1));
  ASSERT_TRUE(runner.Submit(make_lease(2)).ok());
  ASSERT_TRUE(runner.Submit(make_lease(3)).ok());

  EXPECT_FALSE(backend.WaitForSubmitCount(2));

  backend.Complete();
  ASSERT_TRUE(backend.WaitForSubmitCount(2));
  backend.Complete();
  runner.Stop();

  auto status = runner.Status();
  EXPECT_EQ(status.submitted_frames, 3u);
  EXPECT_EQ(status.processed_frames, 2u);
  EXPECT_EQ(status.dropped_frames, 1u);
}

TEST(AiRuntimeTest, ModelRunnerPreprocessesAndPublishesDetectionEvent) {
  CapturingSuccessBackend backend;
  camera_firmware::ai::DetectionBus bus;
  auto model = Model("objects", "object_detection");
  model.input.width = 4;
  model.input.height = 2;

  std::mutex event_mutex;
  std::condition_variable event_changed;
  std::vector<camera_firmware::ai::DetectionEvent> events;
  auto subscription = bus.Subscribe(
      [&](const camera_firmware::ai::DetectionEvent& event) {
        {
          std::lock_guard lock(event_mutex);
          events.push_back(event);
        }
        event_changed.notify_all();
      });

  camera_firmware::ai::AiModelRunner runner(
      "imx708-main", model, &backend, 1, &bus);

  ASSERT_TRUE(runner.Submit(Nv12RuntimeLease(99)).ok());
  ASSERT_TRUE(backend.WaitForSubmit());

  {
    std::unique_lock lock(event_mutex);
    ASSERT_TRUE(event_changed.wait_for(lock, std::chrono::seconds(1), [&] {
      return !events.empty();
    }));
    ASSERT_EQ(events.size(), 1U);
    EXPECT_EQ(events[0].camera_id, "imx708-main");
    EXPECT_EQ(events[0].model_id, "objects");
    EXPECT_EQ(events[0].model_kind, "object_detection");
    EXPECT_EQ(events[0].result_state, "skeleton_no_decoder");
    EXPECT_EQ(events[0].frame_sequence, 99U);
    EXPECT_TRUE(events[0].detections.empty());
  }

  EXPECT_FALSE(backend.last_input_was_null());
  EXPECT_EQ(backend.last_input_size(), 4U * 2U * 3U);
  runner.Stop();
  EXPECT_TRUE(subscription.valid());
}

TEST(AiRuntimeTest, ModelRunnerPublishesDecodedYoloDetectionEvent) {
  CapturingSuccessBackend backend(RuntimeYoloNmsOutputBytes(0.88F));
  camera_firmware::ai::DetectionBus bus;
  auto model = Model("objects", "object_detection");
  model.input.width = 4;
  model.input.height = 2;
  model.confidence_threshold = 0.50F;

  std::mutex event_mutex;
  std::condition_variable event_changed;
  std::vector<camera_firmware::ai::DetectionEvent> events;
  auto subscription = bus.Subscribe(
      [&](const camera_firmware::ai::DetectionEvent& event) {
        {
          std::lock_guard lock(event_mutex);
          events.push_back(event);
        }
        event_changed.notify_all();
      });

  camera_firmware::ai::AiModelRunner runner(
      "imx708-main", model, &backend, 1, &bus);

  ASSERT_TRUE(runner.Submit(Nv12RuntimeLease(101)).ok());
  ASSERT_TRUE(backend.WaitForSubmit());

  {
    std::unique_lock lock(event_mutex);
    ASSERT_TRUE(event_changed.wait_for(lock, std::chrono::seconds(1), [&] {
      return !events.empty();
    }));
    ASSERT_EQ(events.size(), 1U);
    EXPECT_EQ(events[0].camera_id, "imx708-main");
    EXPECT_EQ(events[0].model_id, "objects");
    EXPECT_EQ(events[0].model_kind, "object_detection");
    EXPECT_EQ(events[0].result_state, "decoded");
    EXPECT_EQ(events[0].frame_sequence, 101U);
    ASSERT_EQ(events[0].detections.size(), 1U);
    EXPECT_EQ(events[0].detections[0].label, "car");
    EXPECT_FLOAT_EQ(events[0].detections[0].confidence, 0.88F);
    EXPECT_FLOAT_EQ(events[0].detections[0].box.x, 0.15F);
    EXPECT_FLOAT_EQ(events[0].detections[0].box.y, 0.20F);
    EXPECT_FLOAT_EQ(events[0].detections[0].box.width, 0.50F);
    EXPECT_FLOAT_EQ(events[0].detections[0].box.height, 0.50F);
  }

  runner.Stop();
  EXPECT_TRUE(subscription.valid());
}

TEST(AiRuntimeTest, ModelRunnerPublishesDecodedPoseKeypointEvent) {
  CapturingSuccessBackend backend(RuntimeYoloPoseOutputBytes(0.90F));
  camera_firmware::ai::DetectionBus bus;
  auto model = Model("pose", "pose");
  model.input.width = 4;
  model.input.height = 2;
  model.confidence_threshold = 0.50F;

  std::mutex event_mutex;
  std::condition_variable event_changed;
  std::vector<camera_firmware::ai::DetectionEvent> events;
  auto subscription = bus.Subscribe(
      [&](const camera_firmware::ai::DetectionEvent& event) {
        {
          std::lock_guard lock(event_mutex);
          events.push_back(event);
        }
        event_changed.notify_all();
      });

  camera_firmware::ai::AiModelRunner runner(
      "imx708-main", model, &backend, 1, &bus);

  ASSERT_TRUE(runner.Submit(Nv12RuntimeLease(103)).ok());
  ASSERT_TRUE(backend.WaitForSubmit());

  {
    std::unique_lock lock(event_mutex);
    ASSERT_TRUE(event_changed.wait_for(lock, std::chrono::seconds(1), [&] {
      return !events.empty();
    }));
    ASSERT_EQ(events.size(), 1U);
    EXPECT_EQ(events[0].camera_id, "imx708-main");
    EXPECT_EQ(events[0].model_id, "pose");
    EXPECT_EQ(events[0].model_kind, "pose");
    EXPECT_EQ(events[0].result_state, "decoded");
    EXPECT_EQ(events[0].frame_sequence, 103U);
    ASSERT_EQ(events[0].detections.size(), 1U);
    EXPECT_EQ(events[0].detections[0].label, "person");
    EXPECT_FLOAT_EQ(events[0].detections[0].confidence, 0.90F);
    ASSERT_EQ(events[0].detections[0].keypoints.size(), 2U);
    EXPECT_EQ(events[0].detections[0].keypoints[0].name, "nose");
    EXPECT_FLOAT_EQ(events[0].detections[0].keypoints[0].x, 0.45F);
    EXPECT_FLOAT_EQ(events[0].detections[0].keypoints[0].y, 0.25F);
    EXPECT_EQ(events[0].detections[0].keypoints[1].name, "left_shoulder");
  }

  runner.Stop();
  EXPECT_TRUE(subscription.valid());
}

TEST(AiRuntimeTest, ModelRunnerDropsMalformedYoloOutputShape) {
  std::vector<std::uint8_t> truncated(sizeof(float) * 3U, 0U);
  CapturingSuccessBackend backend(std::move(truncated));
  camera_firmware::ai::DetectionBus bus;
  auto model = Model("objects", "object_detection");
  model.input.width = 4;
  model.input.height = 2;

  int published = 0;
  auto subscription = bus.Subscribe(
      [&published](const camera_firmware::ai::DetectionEvent&) { ++published; });

  camera_firmware::ai::AiModelRunner runner(
      "imx708-main", model, &backend, 1, &bus);

  ASSERT_TRUE(runner.Submit(Nv12RuntimeLease(102)).ok());
  ASSERT_TRUE(backend.WaitForSubmit());
  runner.Stop();

  const auto status = runner.Status();
  EXPECT_EQ(status.processed_frames, 0U);
  EXPECT_EQ(status.dropped_frames, 1U);
  EXPECT_EQ(status.last_error_code, "E_AI_POSTPROCESS");
  EXPECT_EQ(published, 0);
  EXPECT_TRUE(subscription.valid());
}

TEST(AiRuntimeTest, ModelRunnerDropsMalformedPoseOutputShape) {
  std::vector<std::uint8_t> truncated(sizeof(float) * 3U, 0U);
  CapturingSuccessBackend backend(std::move(truncated));
  camera_firmware::ai::DetectionBus bus;
  auto model = Model("pose", "pose");
  model.input.width = 4;
  model.input.height = 2;

  int published = 0;
  auto subscription = bus.Subscribe(
      [&published](const camera_firmware::ai::DetectionEvent&) { ++published; });

  camera_firmware::ai::AiModelRunner runner(
      "imx708-main", model, &backend, 1, &bus);

  ASSERT_TRUE(runner.Submit(Nv12RuntimeLease(104)).ok());
  ASSERT_TRUE(backend.WaitForSubmit());
  runner.Stop();

  const auto status = runner.Status();
  EXPECT_EQ(status.processed_frames, 0U);
  EXPECT_EQ(status.dropped_frames, 1U);
  EXPECT_EQ(status.last_error_code, "E_AI_POSTPROCESS");
  EXPECT_NE(status.last_error_message.find("3 floats"), std::string::npos)
      << status.last_error_message;
  EXPECT_NE(status.last_error_message.find("56-float"), std::string::npos)
      << status.last_error_message;
  EXPECT_EQ(published, 0);
  EXPECT_TRUE(subscription.valid());
}

TEST(AiRuntimeTest, ModelRunnerStopCompletesWhenDetectionSubscriberThrows) {
  AsyncCallbackBackend backend;
  camera_firmware::ai::DetectionBus bus;
  auto model = Model("objects", "object_detection");
  camera_firmware::ai::AiModelRunner runner(
      "imx708-main", model, &backend, 1, &bus);
  auto subscription = bus.Subscribe(
      [](const camera_firmware::ai::DetectionEvent&) {
        throw std::runtime_error("subscriber failed");
      });

  ASSERT_TRUE(runner.Submit(Nv12RuntimeLease(100)).ok());
  ASSERT_TRUE(backend.WaitForSubmit());

  EXPECT_NO_THROW(backend.Complete());

  auto stop = std::async(std::launch::async, [&runner] { runner.Stop(); });
  ASSERT_EQ(stop.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  auto status = runner.Status();
  EXPECT_EQ(status.dropped_frames, 1u);
  EXPECT_EQ(status.last_error_code, "E_AI_POSTPROCESS");
  EXPECT_TRUE(subscription.valid());
}
