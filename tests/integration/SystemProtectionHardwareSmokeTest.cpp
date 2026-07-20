#include <chrono>
#include <cstdlib>
#include <string>
#include <thread>

#include <gtest/gtest.h>

#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/integrity/IntegrityVerifier.hpp"
#include "camera_firmware/runtime/FirmwareRuntime.hpp"
#include "camera_firmware/security/SystemProtectionService.hpp"

namespace {

using camera_firmware::common::Result;
using camera_firmware::integrity::IntegrityCategory;
using camera_firmware::integrity::IntegrityVerificationReport;
using camera_firmware::runtime::FirmwareRuntime;
using camera_firmware::runtime::FirmwareRuntimeState;
using camera_firmware::security::DeviceState;
using camera_firmware::security::ProtectionState;
using camera_firmware::security::SelfTestReport;
using camera_firmware::security::SystemProtectionDependencies;
using camera_firmware::security::SystemProtectionService;

bool HardwareSmokeEnabled() {
  const char* camera = std::getenv("CF_RUN_CAMERA_HARDWARE_SMOKE");
  const char* hailo = std::getenv("CF_RUN_HAILO_HARDWARE_SMOKE");
  return camera != nullptr && std::string(camera) == "1" &&
         hailo != nullptr && std::string(hailo) == "1";
}

Result<SelfTestReport> PassingSelfTestReport() {
  return Result<SelfTestReport>::Ok(
      {true, {{"hardware-smoke-self-test", true, "OK"}}});
}

Result<IntegrityVerificationReport> FailingIntegrityReport() {
  return Result<IntegrityVerificationReport>::Ok(
      {false,
       {{"hardware-smoke-corruption", IntegrityCategory::kFirmware, false,
         "E_INTEGRITY_DIGEST_MISMATCH"}}});
}

bool RuntimeResourcesAllocated(FirmwareRuntime& runtime) {
  const auto cameras = runtime.CameraStatuses();
  const auto ai = runtime.AiStatus();
  return runtime.State() == FirmwareRuntimeState::kRunning &&
         cameras.size() == 1U && cameras.front().state == "running" &&
         cameras.front().captured_frames > 0U &&
         cameras.front().encoded_frames > 0U && ai.state == "ready" &&
         ai.runner_count == 1U && runtime.AiRunnerStatuses().size() == 1U;
}

}  // namespace

TEST(SystemProtectionHardwareSmokeTest,
     RestrictionStopsCameraAndHailoRuntimeAndReleasesResources) {
  if (!HardwareSmokeEnabled()) {
    GTEST_SKIP() << "set CF_RUN_CAMERA_HARDWARE_SMOKE=1 and "
                    "CF_RUN_HAILO_HARDWARE_SMOKE=1 to require hardware";
  }

#if !defined(CF_HAVE_HAILORT)
  FAIL() << "hardware smoke requires a build with HailoRT";
#else
  auto config =
      camera_firmware::config::LoadConfigFile("config/app-rpi5-ai-dev.yaml");
  ASSERT_TRUE(config.ok()) << config.error().code << ": "
                           << config.error().message;

  FirmwareRuntime runtime(config.value());
  const auto started = runtime.Start();
  ASSERT_TRUE(started.ok()) << started.error().code << ": "
                            << started.error().message;

  bool resources_allocated = false;
  for (int attempt = 0; attempt < 100; ++attempt) {
    if (RuntimeResourcesAllocated(runtime)) {
      resources_allocated = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  ASSERT_TRUE(resources_allocated);

  SystemProtectionDependencies dependencies;
  dependencies.run_self_tests = PassingSelfTestReport;
  dependencies.run_integrity = FailingIntegrityReport;
  dependencies.append_system_audit =
      [](std::string_view, std::string_view, std::string_view) {
        return Result<void>::Ok();
      };
  dependencies.read_device_state = [] {
    return Result<DeviceState>::Ok(DeviceState::kOperational);
  };
  SystemProtectionService protection(std::move(dependencies));
  protection.SetRuntimeCallbacks(
      {.start = [&runtime] { return runtime.Start(); },
       .stop = [&runtime] { runtime.Stop(); }});

  const auto restricted = protection.RunStartupChecks();

  EXPECT_EQ(restricted.state, ProtectionState::kRestricted);
  ASSERT_TRUE(restricted.self_test.has_value());
  EXPECT_TRUE(restricted.self_test->passed);
  ASSERT_TRUE(restricted.integrity.has_value());
  EXPECT_FALSE(restricted.integrity->passed);
  EXPECT_FALSE(protection.RuntimeAllowed());
  EXPECT_EQ(runtime.State(), FirmwareRuntimeState::kStopped);

  const auto released_cameras = runtime.CameraStatuses();
  ASSERT_EQ(released_cameras.size(), 1U);
  EXPECT_EQ(released_cameras.front().state, "stopped");
  EXPECT_EQ(released_cameras.front().captured_frames, 0U);
  EXPECT_EQ(released_cameras.front().encoded_frames, 0U);

  const auto released_ai = runtime.AiStatus();
  EXPECT_EQ(released_ai.state, "stopped");
  EXPECT_EQ(released_ai.model_count, 0U);
  EXPECT_EQ(released_ai.runner_count, 0U);
  EXPECT_TRUE(runtime.AiRunnerStatuses().empty());
#endif
}
