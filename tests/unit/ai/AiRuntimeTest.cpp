#include "camera_firmware/ai/AiRuntime.hpp"

#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

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
  camera_firmware::ai::AiRuntime runtime(&bus);

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
  camera_firmware::ai::AiRuntime runtime(&bus);
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

TEST(AiRuntimeTest, BackendUnavailableSubmitDropsWithoutPublishing) {
  camera_firmware::ai::DetectionBus bus;
  int published = 0;
  auto subscription = bus.Subscribe(
      [&published](const camera_firmware::ai::DetectionEvent&) { ++published; });
  camera_firmware::ai::AiRuntime runtime(&bus);
  ASSERT_TRUE(runtime.Start(RuntimeConfig()).ok());

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.sequence = 9;
  camera_firmware::media::FrameLease lease(handle, [] {});

  auto submitted = runtime.SubmitFrame(std::move(lease));

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
  camera_firmware::ai::AiRuntime runtime(&bus);
  ASSERT_TRUE(runtime.Start(RuntimeConfig()).ok());

  int releases = 0;
  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.sequence = 10;

  {
    camera_firmware::media::FrameLease lease(handle, [&] { ++releases; });
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
    camera_firmware::media::FrameHandle handle;
    handle.camera_id = "imx708-main";
    handle.sequence = sequence;
    return camera_firmware::media::FrameLease(handle, [&releases] {
      ++releases;
    });
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

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.sequence = 4;
  ASSERT_TRUE(runner.Submit(camera_firmware::media::FrameLease(handle, [] {}))
                  .ok());
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
    camera_firmware::media::FrameHandle handle;
    handle.camera_id = "imx708-main";
    handle.sequence = sequence;
    return camera_firmware::media::FrameLease(handle, [] {});
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
