#include "camera_firmware/service/ServiceApp.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <concepts>
#include <cstdint>
#include <filesystem>
#include <future>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
#include <vector>

#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "camera_firmware/ai/AiTypes.hpp"
#include "camera_firmware/crypto/OpenSslCryptoProvider.hpp"
#include "camera_firmware/service/SessionStreamRegistry.hpp"

namespace camera_firmware::service::internal {
void FailNextLiveMp4PumpAllocationForTesting() noexcept;
std::optional<std::string_view> SerializeUserRoleForTesting(
    security::UserRole role) noexcept;
drogon::HttpResponsePtr ExecuteProtectedRuntimeControlCommand(
    const ProtectionRuntimeAllowedCallback& protection_runtime_allowed,
    const std::function<drogon::HttpResponsePtr()>& command);
drogon::HttpResponsePtr ExecuteSequentialProtectedRuntimeControlCommand(
    const ProtectionRuntimeAllowedCallback& protection_runtime_allowed,
    const std::function<drogon::HttpResponsePtr()>& validate,
    const std::function<drogon::HttpResponsePtr()>& command);
drogon::HttpResponsePtr ExecuteAtomicallyProtectedRuntimeControlCommand(
    const ProtectionRuntimeControlGate& protection_runtime_control_gate,
    const std::function<drogon::HttpResponsePtr()>& command);
common::Result<void> DispatchAtomicallyProtectedRuntimeControlCommand(
    const std::shared_ptr<BoundedWorker>& worker,
    ProtectionRuntimeControlGate protection_runtime_control_gate,
    std::function<drogon::HttpResponsePtr()> command,
    std::function<void(drogon::HttpResponsePtr)> complete);
drogon::HttpResponsePtr ExecuteUnrestrictedRuntimeOperation(
    const std::function<drogon::HttpResponsePtr()>& operation);
common::Result<std::optional<security::ResolvedTlsMaterial>>
SelectServiceTlsMaterial(const ServiceInitArgs& args);
void InstallDefaultProtectionRuntimeAllowedCallback(
    ServiceInitArgs& args, bool security_enabled);
}

namespace {

// A single self-tested provider shared by every test in this file that
// resolves TLS material directly (rather than through ServiceApp's own
// internal provider construction).
camera_firmware::crypto::CryptoProvider& TestCryptoProvider() {
  static camera_firmware::crypto::OpenSslCryptoProvider provider;
  static const bool initialized = [] {
    const auto self_test = provider.SelfTest();
    if (!self_test.ok() || !self_test.value().passed) {
      throw std::runtime_error("crypto provider self-test failed");
    }
    return true;
  }();
  (void)initialized;
  return provider;
}

template <typename T>
concept HasCompletedAuthServiceInjection = requires(T value) {
  value.auth_service;
};

template <typename T>
concept HasAuthServiceFactoryInjection = requires(T value) {
  value.auth_service_factory;
};

template <typename T>
concept HasUserManagementServiceInjection = requires(T value) {
  value.user_management_service;
};

template <typename T>
concept HasCancellableLiveStreamCallback = requires(T value) {
  value.cancellable_live_stream_callback;
};

template <typename T>
concept HasExactLegacyLiveStreamCallback =
    std::same_as<std::remove_cvref_t<decltype(
                     std::declval<T&>().live_stream_callback)>,
                 camera_firmware::service::LiveMp4OpenCallback>;

static_assert(!HasCompletedAuthServiceInjection<
              camera_firmware::service::ServiceInitArgs>);
static_assert(!HasAuthServiceFactoryInjection<
              camera_firmware::service::ServiceInitArgs>);
static_assert(!HasUserManagementServiceInjection<
              camera_firmware::service::ServiceInitArgs>);
static_assert(HasExactLegacyLiveStreamCallback<
              camera_firmware::service::ServiceInitArgs>);
static_assert(HasCancellableLiveStreamCallback<
              camera_firmware::service::ServiceInitArgs>);

class TemporaryTlsDirectory {
 public:
  TemporaryTlsDirectory() {
    std::array<char, 40> pattern{"/tmp/cf-service-tls-XXXXXX"};
    char* created = ::mkdtemp(pattern.data());
    if (created == nullptr) {
      throw std::system_error(errno, std::generic_category(), "mkdtemp");
    }
    path_ = created;
  }

  ~TemporaryTlsDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  [[nodiscard]] const std::filesystem::path& path() const noexcept {
    return path_;
  }

 private:
  std::filesystem::path path_;
};

void WriteExclusiveTlsFile(const std::filesystem::path& directory,
                           std::string_view name,
                           mode_t mode,
                           std::string_view contents) {
  const int directory_fd =
      ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory_fd < 0) {
    throw std::system_error(errno, std::generic_category(), "open directory");
  }
  const int file_fd =
      ::openat(directory_fd, name.data(),
               O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
  if (file_fd < 0 || ::fchmod(file_fd, mode) != 0 ||
      ::write(file_fd, contents.data(), contents.size()) !=
          static_cast<ssize_t>(contents.size())) {
    const int error = errno;
    if (file_fd >= 0) {
      (void)::close(file_fd);
    }
    (void)::close(directory_fd);
    throw std::system_error(error, std::generic_category(), "write TLS file");
  }
  const int file_close = ::close(file_fd);
  const int directory_close = ::close(directory_fd);
  if (file_close != 0 || directory_close != 0) {
    throw std::system_error(errno, std::generic_category(), "close TLS file");
  }
}

}  // namespace

TEST(ServiceResponseTest, HealthJsonContainsStatus) {
  auto json = camera_firmware::service::BuildHealthJson("ok");
  ASSERT_TRUE(json.isMember("status"));
  EXPECT_EQ(json["status"].asString(), "ok");
}

TEST(ServiceResponseTest, CameraStatusJsonIncludesCaptureDiagnostics) {
  camera_firmware::service::CameraStatus status;
  status.id = "imx708-main";
  status.state = "running";
  status.snapshot_available = true;
  status.width = 1920U;
  status.height = 1080U;
  status.configured_fps = 50U;
  status.capture_fps = 49.8;
  status.encoded_fps = 49.7;
  status.captured_frames = 1000U;
  status.encoded_frames = 998U;
  status.capture_error_count = 2U;
  status.encode_error_count = 1U;

  const auto json =
      camera_firmware::service::BuildCameraStatusJson(status);

  EXPECT_EQ(json["id"].asString(), "imx708-main");
  EXPECT_EQ(json["state"].asString(), "running");
  EXPECT_TRUE(json["snapshot_available"].asBool());
  EXPECT_EQ(json["width"].asUInt(), 1920U);
  EXPECT_EQ(json["height"].asUInt(), 1080U);
  EXPECT_EQ(json["configured_fps"].asUInt(), 50U);
  EXPECT_DOUBLE_EQ(json["capture_fps"].asDouble(), 49.8);
  EXPECT_DOUBLE_EQ(json["encoded_fps"].asDouble(), 49.7);
  EXPECT_EQ(json["captured_frames"].asUInt64(), 1000U);
  EXPECT_EQ(json["encoded_frames"].asUInt64(), 998U);
  EXPECT_EQ(json["capture_error_count"].asUInt64(), 2U);
  EXPECT_EQ(json["encode_error_count"].asUInt64(), 1U);
}

TEST(ServiceResponseTest, StreamJsonUsesConfiguredPublicHost) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = true;
  secure_rtsp.media_srtp = false;
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  auto json = camera_firmware::service::BuildStreamJson(
      "https://camera.example:9443/service", secure_rtsp);

  EXPECT_EQ(json["url"].asString(), "rtsps://camera.example:8555/imx708/main");
}

TEST(ServiceResponseTest,
     StreamJsonKeepsRtspSchemeWhenOnlyMediaSrtpEnabled) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = false;
  secure_rtsp.media_srtp = true;
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  auto json = camera_firmware::service::BuildStreamJson(
      "http://stream.example:8080/ui", secure_rtsp);

  EXPECT_EQ(json["url"].asString(), "rtsp://stream.example:8555/imx708/main");
  ASSERT_TRUE(json.isMember("media_srtp"));
  EXPECT_TRUE(json["media_srtp"].asBool());
}

TEST(ServiceResponseTest, StreamJsonIncludesSrtpSecureMediaDiagnostics) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = true;
  secure_rtsp.media_srtp = true;
  secure_rtsp.keying = "sdes-over-rtsps";
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  const auto json = camera_firmware::service::BuildStreamJson(
      "https://camera.example:9443/service", secure_rtsp);

  EXPECT_EQ(json["url"].asString(), "rtsps://camera.example:8555/imx708/main");
  EXPECT_TRUE(json["control_tls"].asBool());
  EXPECT_TRUE(json["media_srtp"].asBool());
  ASSERT_TRUE(json.isMember("secure_media"));
  EXPECT_EQ(json["secure_media"]["control_scheme"].asString(), "rtsps");
  EXPECT_EQ(json["secure_media"]["media_profile"].asString(), "RTP/SAVPF");
  EXPECT_EQ(json["secure_media"]["keying"].asString(), "SDES-over-RTSPS");
  EXPECT_TRUE(
      json["secure_media"]["requires_tls_control_channel"].asBool());
}

TEST(ServiceResponseTest,
     StreamJsonIncludesRuntimeSrtpZeroizeDiagnosticsWhenAvailable) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = true;
  secure_rtsp.media_srtp = true;
  secure_rtsp.keying = "sdes-over-rtsps";
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  camera_firmware::service::SecureStreamDiagnostics diagnostics;
  diagnostics.per_media_key_zeroize_count = 7U;

  const auto json = camera_firmware::service::BuildStreamJson(
      "https://camera.example:9443/service", secure_rtsp, diagnostics);

  ASSERT_TRUE(json.isMember("secure_media"));
  ASSERT_TRUE(
      json["secure_media"].isMember("per_media_key_zeroize_count"));
  EXPECT_EQ(
      json["secure_media"]["per_media_key_zeroize_count"].asUInt64(), 7U);
}

TEST(ServiceResponseTest,
     StreamJsonOmitsRuntimeSrtpZeroizeDiagnosticsWithoutProvider) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = true;
  secure_rtsp.media_srtp = true;
  secure_rtsp.keying = "sdes-over-rtsps";
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  const auto json = camera_firmware::service::BuildStreamJson(
      "https://camera.example:9443/service", secure_rtsp);

  ASSERT_TRUE(json.isMember("secure_media"));
  EXPECT_FALSE(
      json["secure_media"].isMember("per_media_key_zeroize_count"));
}

TEST(ServiceResponseTest, StreamJsonIncludesPlainMediaDiagnostics) {
  camera_firmware::config::SecureRtspConfig secure_rtsp;
  secure_rtsp.control_tls = false;
  secure_rtsp.media_srtp = false;
  secure_rtsp.keying = "";
  secure_rtsp.port = 8555;
  secure_rtsp.mount = "/imx708/main";

  const auto json = camera_firmware::service::BuildStreamJson(
      "http://camera.example:8080/service", secure_rtsp);

  EXPECT_EQ(json["url"].asString(), "rtsp://camera.example:8555/imx708/main");
  EXPECT_FALSE(json["control_tls"].asBool());
  EXPECT_FALSE(json["media_srtp"].asBool());
  ASSERT_TRUE(json.isMember("secure_media"));
  EXPECT_EQ(json["secure_media"]["control_scheme"].asString(), "rtsp");
  EXPECT_EQ(json["secure_media"]["media_profile"].asString(), "RTP/AVP");
  EXPECT_EQ(json["secure_media"]["keying"].asString(), "none");
  EXPECT_FALSE(
      json["secure_media"]["requires_tls_control_channel"].asBool());
  EXPECT_FALSE(
      json["secure_media"].isMember("per_media_key_zeroize_count"));
}

TEST(ServiceResponseTest, AiStatusReportsRuntimeSkeletonWhenRequested) {
  auto json = camera_firmware::service::BuildAiStatusJson(true);

  EXPECT_TRUE(json["enabled"].asBool());
  EXPECT_EQ(json["backend"].asString(), "hailo");
  EXPECT_EQ(json["state"].asString(), "backend_unavailable");
  EXPECT_EQ(json["model_count"].asUInt64(), 0u);
  EXPECT_EQ(json["runner_count"].asUInt64(), 0u);
  EXPECT_EQ(json["reason"].asString(),
            "Hailo backend is not implemented in this build");
  ASSERT_TRUE(json["runners"].isArray());
  EXPECT_TRUE(json["runners"].empty());
}

TEST(ServiceResponseTest, AiStatusReportsEmptyRunnersWhenDisabled) {
  auto json = camera_firmware::service::BuildAiStatusJson(false);

  EXPECT_FALSE(json["enabled"].asBool());
  EXPECT_EQ(json["backend"].asString(), "disabled");
  EXPECT_EQ(json["state"].asString(), "disabled");
  EXPECT_EQ(json["runner_count"].asUInt64(), 0u);
  ASSERT_TRUE(json["runners"].isArray());
  EXPECT_TRUE(json["runners"].empty());
}

TEST(ServiceResponseTest, AiStatusReportsRuntimeSkeletonState) {
  camera_firmware::service::AiServiceStatus status;
  status.enabled = true;
  status.backend = "hailo";
  status.state = "backend_unavailable";
  status.model_count = 2;
  status.runner_count = 2;
  status.reason = "Hailo backend is not implemented in this build";

  auto json = camera_firmware::service::BuildAiStatusJson(status);

  EXPECT_TRUE(json["enabled"].asBool());
  EXPECT_EQ(json["backend"].asString(), "hailo");
  EXPECT_EQ(json["state"].asString(), "backend_unavailable");
  EXPECT_EQ(json["model_count"].asUInt64(), 2u);
  EXPECT_EQ(json["runner_count"].asUInt64(), 2u);
  EXPECT_EQ(json["reason"].asString(),
            "Hailo backend is not implemented in this build");
  ASSERT_TRUE(json["runners"].isArray());
  EXPECT_TRUE(json["runners"].empty());
}

TEST(ServiceResponseTest, AiStatusSerializesConfiguredModelInventory) {
  camera_firmware::service::AiServiceStatus status;
  status.enabled = true;
  status.backend = "hailo";
  status.state = "ready";
  status.model_count = 2;
  status.runner_count = 2;
  status.reason = "AI runtime ready";

  camera_firmware::service::AiModelServiceStatus objects;
  objects.id = "objects";
  objects.kind = "object_detection";
  objects.input_width = 640;
  objects.input_height = 640;
  objects.input_format = "rgb8";
  objects.letterbox = true;
  objects.output_name = "yolov8_nms_postprocess";
  objects.confidence_threshold = 0.40F;
  objects.labels = "coco80";
  status.models.push_back(objects);

  camera_firmware::service::AiModelServiceStatus pose;
  pose.id = "pose";
  pose.kind = "pose";
  pose.input_width = 256;
  pose.input_height = 256;
  pose.input_format = "rgb8";
  pose.letterbox = false;
  pose.output_name = "yolov8_pose_postprocess";
  pose.confidence_threshold = 0.30F;
  pose.labels = "pose17";
  status.models.push_back(pose);

  const auto json = camera_firmware::service::BuildAiStatusJson(status);

  ASSERT_TRUE(json["models"].isArray());
  ASSERT_EQ(json["models"].size(), 2U);
  const auto& first = json["models"][0];
  EXPECT_EQ(first["id"].asString(), "objects");
  EXPECT_EQ(first["kind"].asString(), "object_detection");
  EXPECT_EQ(first["input_width"].asUInt(), 640U);
  EXPECT_EQ(first["input_height"].asUInt(), 640U);
  EXPECT_EQ(first["input_format"].asString(), "rgb8");
  EXPECT_TRUE(first["letterbox"].asBool());
  EXPECT_EQ(first["output_name"].asString(), "yolov8_nms_postprocess");
  EXPECT_FLOAT_EQ(first["confidence_threshold"].asFloat(), 0.40F);
  EXPECT_EQ(first["labels"].asString(), "coco80");
  EXPECT_FALSE(first.isMember("hef_path"));

  const auto& second = json["models"][1];
  EXPECT_EQ(second["id"].asString(), "pose");
  EXPECT_EQ(second["kind"].asString(), "pose");
  EXPECT_EQ(second["input_width"].asUInt(), 256U);
  EXPECT_EQ(second["input_height"].asUInt(), 256U);
  EXPECT_EQ(second["input_format"].asString(), "rgb8");
  EXPECT_FALSE(second["letterbox"].asBool());
  EXPECT_EQ(second["output_name"].asString(), "yolov8_pose_postprocess");
  EXPECT_FLOAT_EQ(second["confidence_threshold"].asFloat(), 0.30F);
  EXPECT_EQ(second["labels"].asString(), "pose17");
}

TEST(ServiceResponseTest, AiStatusSerializesRunnerStatuses) {
  camera_firmware::service::AiServiceStatus status;
  status.enabled = true;
  status.backend = "hailo";
  status.state = "ready";
  status.model_count = 2;
  status.runner_count = 2;
  status.reason = "AI runtime ready";

  camera_firmware::service::AiRunnerServiceStatus objects;
  objects.camera_id = "imx708-main";
  objects.model_id = "objects";
  objects.model_kind = "object_detection";
  objects.submitted_frames = 11;
  objects.processed_frames = 10;
  objects.dropped_frames = 1;
  objects.last_preprocess_ms = 1.2;
  objects.last_inference_ms = 3.4;
  objects.last_processed_sequence = 11;
  objects.last_error_code = "E_AI_POSTPROCESS";
  objects.last_error_message = "malformed output";
  status.runners.push_back(objects);

  camera_firmware::service::AiRunnerServiceStatus pose;
  pose.camera_id = "imx708-main";
  pose.model_id = "pose";
  pose.model_kind = "pose";
  pose.submitted_frames = 7;
  pose.processed_frames = 7;
  status.runners.push_back(pose);

  const auto json = camera_firmware::service::BuildAiStatusJson(status);

  ASSERT_TRUE(json["runners"].isArray());
  ASSERT_EQ(json["runners"].size(), 2U);
  const auto& first = json["runners"][0];
  EXPECT_EQ(first["camera_id"].asString(), "imx708-main");
  EXPECT_EQ(first["model_id"].asString(), "objects");
  EXPECT_EQ(first["model_kind"].asString(), "object_detection");
  EXPECT_EQ(first["submitted_frames"].asUInt64(), 11U);
  EXPECT_EQ(first["processed_frames"].asUInt64(), 10U);
  EXPECT_EQ(first["dropped_frames"].asUInt64(), 1U);
  EXPECT_DOUBLE_EQ(first["last_preprocess_ms"].asDouble(), 1.2);
  EXPECT_DOUBLE_EQ(first["last_inference_ms"].asDouble(), 3.4);
  EXPECT_EQ(first["last_processed_sequence"].asUInt64(), 11U);
  EXPECT_EQ(first["last_error_code"].asString(), "E_AI_POSTPROCESS");
  EXPECT_EQ(first["last_error_message"].asString(), "malformed output");

  const auto& second = json["runners"][1];
  EXPECT_EQ(second["model_id"].asString(), "pose");
  EXPECT_EQ(second["model_kind"].asString(), "pose");
  EXPECT_EQ(second["submitted_frames"].asUInt64(), 7U);
  EXPECT_EQ(second["processed_frames"].asUInt64(), 7U);
  EXPECT_EQ(second["dropped_frames"].asUInt64(), 0U);
  EXPECT_EQ(second["last_error_code"].asString(), "");
  EXPECT_EQ(second["last_error_message"].asString(), "");
}

TEST(ServiceResponseTest, AiStatusClampsInvalidRunnerTimingValues) {
  camera_firmware::service::AiServiceStatus status;
  camera_firmware::service::AiRunnerServiceStatus runner;
  runner.last_preprocess_ms = -1.0;
  runner.last_inference_ms = std::numeric_limits<double>::quiet_NaN();
  status.runners.push_back(runner);

  auto json = camera_firmware::service::BuildAiStatusJson(status);

  ASSERT_EQ(json["runners"].size(), 1U);
  EXPECT_DOUBLE_EQ(json["runners"][0]["last_preprocess_ms"].asDouble(), 0.0);
  EXPECT_DOUBLE_EQ(json["runners"][0]["last_inference_ms"].asDouble(), 0.0);

  status.runners[0].last_preprocess_ms =
      std::numeric_limits<double>::infinity();
  status.runners[0].last_inference_ms =
      -std::numeric_limits<double>::infinity();
  json = camera_firmware::service::BuildAiStatusJson(status);

  EXPECT_DOUBLE_EQ(json["runners"][0]["last_preprocess_ms"].asDouble(), 0.0);
  EXPECT_DOUBLE_EQ(json["runners"][0]["last_inference_ms"].asDouble(), 0.0);
}

TEST(ServiceResponseTest, AiRestartResponseInvokesCallback) {
  bool restarted = false;

  auto response = camera_firmware::service::BuildAiRestartResponse(
      [&restarted] {
        restarted = true;
        return camera_firmware::common::Result<void>::Ok();
      });

  ASSERT_TRUE(restarted);
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["status"].asString(), "restarted");
}

TEST(ServiceResponseTest, ProtectionRestrictionResponseIsLocked) {
  const auto response =
      camera_firmware::service::BuildProtectionRestrictedResponse();

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k423Locked);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), "E_PROTECTION_RESTRICTED");
  EXPECT_EQ((*json)["message"].asString(), "runtime control is restricted");
  EXPECT_EQ(response->body().find("/"), std::string::npos);
}

TEST(ServiceResponseTest,
     ProtectedRuntimeControlRejectsRestrictedMissingAndThrowingPredicates) {
  const std::vector<camera_firmware::service::ProtectionRuntimeAllowedCallback>
      predicates = {
          [] { return false; },
          {},
          []() -> bool {
            throw std::runtime_error("injected protection predicate failure");
          },
      };

  for (const auto& predicate : predicates) {
    unsigned int command_calls = 0U;
    const auto response = camera_firmware::service::internal::
        ExecuteProtectedRuntimeControlCommand(predicate, [&] {
          ++command_calls;
          return camera_firmware::service::BuildRuntimeRestartResponse([] {
            return camera_firmware::common::Result<void>::Ok();
          });
        });

    ASSERT_NE(response, nullptr);
    EXPECT_EQ(response->statusCode(), drogon::k423Locked);
    EXPECT_EQ(command_calls, 0U);
  }
}

TEST(ServiceResponseTest, ProtectedRuntimeControlInvokesAllowedCommandOnce) {
  unsigned int predicate_calls = 0U;
  unsigned int command_calls = 0U;

  const auto response = camera_firmware::service::internal::
      ExecuteProtectedRuntimeControlCommand(
          [&] {
            ++predicate_calls;
            return true;
          },
          [&] {
            ++command_calls;
            return camera_firmware::service::BuildRuntimeRestartResponse([] {
              return camera_firmware::common::Result<void>::Ok();
            });
          });

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  EXPECT_EQ(predicate_calls, 1U);
  EXPECT_EQ(command_calls, 1U);
}

TEST(ServiceResponseTest,
     AtomicRuntimeControlGateRechecksAtExecutionAndRunsCommandOnce) {
  unsigned int rejected_calls = 0U;
  const camera_firmware::service::ProtectionRuntimeControlGate restricted =
      [](const std::function<void()>&) { return false; };
  const auto rejected = camera_firmware::service::internal::
      ExecuteAtomicallyProtectedRuntimeControlCommand(restricted, [&] {
        ++rejected_calls;
        return drogon::HttpResponse::newHttpResponse();
      });

  ASSERT_NE(rejected, nullptr);
  EXPECT_EQ(rejected->statusCode(), drogon::k423Locked);
  EXPECT_EQ(rejected_calls, 0U);

  unsigned int allowed_calls = 0U;
  const camera_firmware::service::ProtectionRuntimeControlGate operational =
      [](const std::function<void()>& command) {
        command();
        return true;
      };
  const auto allowed = camera_firmware::service::internal::
      ExecuteAtomicallyProtectedRuntimeControlCommand(operational, [&] {
        ++allowed_calls;
        auto response = drogon::HttpResponse::newHttpResponse();
        response->setStatusCode(drogon::k200OK);
        return response;
      });

  ASSERT_NE(allowed, nullptr);
  EXPECT_EQ(allowed->statusCode(), drogon::k200OK);
  EXPECT_EQ(allowed_calls, 1U);
}

TEST(ServiceResponseTest,
     AtomicRuntimeControlDispatchDoesNotRunCommandOnCallingThread) {
  auto worker = std::make_shared<camera_firmware::service::BoundedWorker>(2U);
  std::promise<void> command_entered;
  std::promise<void> release_command;
  auto release_future = release_command.get_future().share();
  std::promise<drogon::HttpResponsePtr> completed;
  auto completion = completed.get_future();
  const auto calling_thread = std::this_thread::get_id();
  std::thread::id command_thread;

  const auto dispatched = camera_firmware::service::internal::
      DispatchAtomicallyProtectedRuntimeControlCommand(
          worker,
          [](const std::function<void()>& command) {
            command();
            return true;
          },
          [&] {
            command_thread = std::this_thread::get_id();
            command_entered.set_value();
            release_future.wait();
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setStatusCode(drogon::k200OK);
            return response;
          },
          [&](drogon::HttpResponsePtr response) {
            completed.set_value(std::move(response));
          });

  ASSERT_TRUE(dispatched.ok()) << dispatched.error().message;
  ASSERT_EQ(command_entered.get_future().wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  EXPECT_NE(command_thread, calling_thread);
  EXPECT_EQ(completion.wait_for(std::chrono::milliseconds(20)),
            std::future_status::timeout);
  release_command.set_value();
  ASSERT_EQ(completion.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  ASSERT_NE(completion.get(), nullptr);
  worker->Stop();
}

TEST(ServiceResponseTest,
     SequentialRuntimeControlReturnsRestrictionBeforeBodyValidation) {
  unsigned int validation_calls = 0U;
  unsigned int command_calls = 0U;

  const auto response = camera_firmware::service::internal::
      ExecuteSequentialProtectedRuntimeControlCommand(
          [] { return false; },
          [&] {
            ++validation_calls;
            return camera_firmware::service::BuildRuntimeRestartResponse({});
          },
          [&] {
            ++command_calls;
            return drogon::HttpResponse::newHttpResponse();
          });

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k423Locked);
  EXPECT_EQ(validation_calls, 0U);
  EXPECT_EQ(command_calls, 0U);
}

TEST(ServiceResponseTest,
     SequentialRuntimeControlRechecksProtectionAfterValidation) {
  bool allowed = true;
  unsigned int predicate_calls = 0U;
  unsigned int command_calls = 0U;

  const auto response = camera_firmware::service::internal::
      ExecuteSequentialProtectedRuntimeControlCommand(
          [&] {
            ++predicate_calls;
            return allowed;
          },
          [&] {
            allowed = false;
            return drogon::HttpResponsePtr{};
          },
          [&] {
            ++command_calls;
            return drogon::HttpResponse::newHttpResponse();
          });

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k423Locked);
  EXPECT_EQ(predicate_calls, 2U);
  EXPECT_EQ(command_calls, 0U);
}

TEST(ServiceResponseTest, ReadSaveAndDiscardOperationsRemainUnrestricted) {
  unsigned int operation_calls = 0U;

  for (unsigned int operation = 0U; operation < 3U; ++operation) {
    const auto response = camera_firmware::service::internal::
        ExecuteUnrestrictedRuntimeOperation([&] {
          ++operation_calls;
          auto allowed = drogon::HttpResponse::newHttpResponse();
          allowed->setStatusCode(drogon::k200OK);
          return allowed;
        });
    ASSERT_NE(response, nullptr);
    EXPECT_EQ(response->statusCode(), drogon::k200OK);
  }

  EXPECT_EQ(operation_calls, 3U);
}

TEST(ServiceResponseTest,
     ServiceInitProtectionDefaultFailsClosedOnlyWhenSecurityIsEnabled) {
  camera_firmware::service::ServiceInitArgs secured;
  camera_firmware::service::internal::
      InstallDefaultProtectionRuntimeAllowedCallback(secured, true);
  ASSERT_TRUE(secured.protection_runtime_allowed_callback);
  EXPECT_FALSE(secured.protection_runtime_allowed_callback());
  EXPECT_FALSE(secured.protection_runtime_control_gate);

  camera_firmware::service::ServiceInitArgs unsecured;
  camera_firmware::service::internal::
      InstallDefaultProtectionRuntimeAllowedCallback(unsecured, false);
  ASSERT_TRUE(unsecured.protection_runtime_allowed_callback);
  EXPECT_TRUE(unsecured.protection_runtime_allowed_callback());
  ASSERT_TRUE(unsecured.protection_runtime_control_gate);
  unsigned int unsecured_command_calls = 0U;
  EXPECT_TRUE(unsecured.protection_runtime_control_gate(
      [&] { ++unsecured_command_calls; }));
  EXPECT_EQ(unsecured_command_calls, 1U);

  camera_firmware::service::ServiceInitArgs configured;
  configured.protection_runtime_allowed_callback = []() -> bool {
    throw std::runtime_error("injected configured predicate");
  };
  camera_firmware::service::internal::
      InstallDefaultProtectionRuntimeAllowedCallback(configured, true);
  EXPECT_THROW(configured.protection_runtime_allowed_callback(),
               std::runtime_error);
}

TEST(ServiceResponseTest, AiRestartResponseIncludesRuntimeStatus) {
  bool restarted = false;

  camera_firmware::service::AiServiceStatus status;
  status.enabled = true;
  status.backend = "hailo";
  status.state = "ready";
  status.model_count = 1;
  status.runner_count = 1;
  status.reason = "AI runtime ready";

  auto response = camera_firmware::service::BuildAiRestartResponse(
      [&restarted] {
        restarted = true;
        return camera_firmware::common::Result<void>::Ok();
      },
      [&status] { return status; });

  ASSERT_TRUE(restarted);
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["status"].asString(), "restarted");
  ASSERT_TRUE((*json).isMember("ai"));
  EXPECT_TRUE((*json)["ai"]["enabled"].asBool());
  EXPECT_EQ((*json)["ai"]["backend"].asString(), "hailo");
  EXPECT_EQ((*json)["ai"]["state"].asString(), "ready");
  EXPECT_EQ((*json)["ai"]["model_count"].asUInt64(), 1U);
  EXPECT_EQ((*json)["ai"]["runner_count"].asUInt64(), 1U);
  EXPECT_EQ((*json)["ai"]["reason"].asString(), "AI runtime ready");
}

TEST(ServiceResponseTest, AiRestartResponseReportsMissingCallback) {
  auto response = camera_firmware::service::BuildAiRestartResponse({});

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), "E_AI_CONTROL_UNAVAILABLE");
}

TEST(ServiceResponseTest, AiRestartResponseReportsCallbackError) {
  auto response = camera_firmware::service::BuildAiRestartResponse([] {
    return camera_firmware::common::Result<void>::Err(
        {"E_AI_RESTART", "restart failed"});
  });

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k500InternalServerError);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), "E_AI_RESTART");
  EXPECT_EQ((*json)["message"].asString(), "restart failed");
}

TEST(ServiceResponseTest, AiRestartResponseDoesNotReadStatusAfterCallbackError) {
  bool status_provider_called = false;

  auto response = camera_firmware::service::BuildAiRestartResponse(
      [] {
        return camera_firmware::common::Result<void>::Err(
            {"E_AI_RESTART", "restart failed"});
      },
      [&status_provider_called] {
        status_provider_called = true;
        return camera_firmware::service::AiServiceStatus{};
      });

  ASSERT_FALSE(status_provider_called);
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k500InternalServerError);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), "E_AI_RESTART");
  EXPECT_FALSE((*json).isMember("ai"));
}

TEST(ServiceResponseTest, DetectionSnapshotJsonReturnsEmptyEventsArray) {
  const auto json =
      camera_firmware::service::BuildDetectionSnapshotJson({});

  ASSERT_TRUE(json.isMember("events"));
  ASSERT_TRUE(json["events"].isArray());
  EXPECT_TRUE(json["events"].empty());
}

TEST(ServiceResponseTest, DetectionSnapshotJsonSerializesDetectionEvent) {
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.model_id = "objects";
  event.model_kind = "object_detection";
  event.result_state = "decoded";
  event.frame_sequence = 101;
  event.frame_timestamp = std::chrono::nanoseconds{123456789};

  camera_firmware::ai::Detection detection;
  detection.class_id = 2;
  detection.label = "car";
  detection.confidence = 0.88F;
  detection.box.x = 0.15F;
  detection.box.y = 0.20F;
  detection.box.width = 0.50F;
  detection.box.height = 0.40F;
  camera_firmware::ai::Keypoint left_shoulder;
  left_shoulder.name = "left_shoulder";
  left_shoulder.x = 0.34F;
  left_shoulder.y = 0.28F;
  left_shoulder.confidence = 0.81F;
  camera_firmware::ai::Keypoint right_shoulder;
  right_shoulder.name = "right_shoulder";
  right_shoulder.x = 0.52F;
  right_shoulder.y = 0.29F;
  right_shoulder.confidence = 0.79F;
  detection.keypoints = {left_shoulder, right_shoulder};
  event.detections.push_back(detection);

  const auto json =
      camera_firmware::service::BuildDetectionSnapshotJson({event});

  ASSERT_TRUE(json.isMember("events"));
  ASSERT_EQ(json["events"].size(), 1U);
  const auto& serialized_event = json["events"][0];
  EXPECT_EQ(serialized_event["camera_id"].asString(), "imx708-main");
  EXPECT_EQ(serialized_event["model_id"].asString(), "objects");
  EXPECT_EQ(serialized_event["model_kind"].asString(), "object_detection");
  EXPECT_EQ(serialized_event["result_state"].asString(), "decoded");
  EXPECT_EQ(serialized_event["frame_sequence"].asUInt64(), 101U);
  EXPECT_EQ(serialized_event["frame_timestamp_ns"].asInt64(), 123456789);
  ASSERT_EQ(serialized_event["detections"].size(), 1U);
  const auto& serialized_detection = serialized_event["detections"][0];
  EXPECT_EQ(serialized_detection["class_id"].asInt(), 2);
  EXPECT_EQ(serialized_detection["label"].asString(), "car");
  EXPECT_FLOAT_EQ(serialized_detection["confidence"].asFloat(), 0.88F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["x"].asFloat(), 0.15F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["y"].asFloat(), 0.20F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["width"].asFloat(), 0.50F);
  EXPECT_FLOAT_EQ(serialized_detection["box"]["height"].asFloat(), 0.40F);
  ASSERT_TRUE(serialized_detection["keypoints"].isArray());
  ASSERT_EQ(serialized_detection["keypoints"].size(), 2U);
  EXPECT_EQ(serialized_detection["keypoints"][0]["name"].asString(),
            "left_shoulder");
  EXPECT_FLOAT_EQ(serialized_detection["keypoints"][0]["x"].asFloat(), 0.34F);
  EXPECT_FLOAT_EQ(serialized_detection["keypoints"][0]["y"].asFloat(), 0.28F);
  EXPECT_FLOAT_EQ(
      serialized_detection["keypoints"][0]["confidence"].asFloat(), 0.81F);
  EXPECT_EQ(serialized_detection["keypoints"][1]["name"].asString(),
            "right_shoulder");
  EXPECT_FLOAT_EQ(serialized_detection["keypoints"][1]["x"].asFloat(), 0.52F);
  EXPECT_FLOAT_EQ(serialized_detection["keypoints"][1]["y"].asFloat(), 0.29F);
  EXPECT_FLOAT_EQ(
      serialized_detection["keypoints"][1]["confidence"].asFloat(), 0.79F);
}

TEST(ServiceResponseTest, DetectionSnapshotJsonFiltersInvalidClassIds) {
  camera_firmware::ai::DetectionEvent event;
  camera_firmware::ai::Detection invalid;
  invalid.label = "invalid";
  camera_firmware::ai::Detection valid;
  valid.class_id = 0;
  valid.label = "person";
  event.detections = {invalid, valid};

  const auto json =
      camera_firmware::service::BuildDetectionSnapshotJson({event});

  ASSERT_EQ(json["events"].size(), 1U);
  ASSERT_EQ(json["events"][0]["detections"].size(), 1U);
  EXPECT_EQ(json["events"][0]["detections"][0]["class_id"].asInt(), 0);
  EXPECT_EQ(json["events"][0]["detections"][0]["label"].asString(),
            "person");
}

TEST(ServiceResponseTest, DetectionSnapshotResponseReturnsEmptyWithoutProvider) {
  const auto response =
      camera_firmware::service::BuildDetectionSnapshotResponse({});

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  ASSERT_TRUE(json->isMember("events"));
  EXPECT_TRUE((*json)["events"].empty());
}

TEST(ServiceResponseTest, DetectionSnapshotResponseUsesProvider) {
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.model_id = "objects";
  event.model_kind = "object_detection";
  event.result_state = "decoded";
  event.frame_sequence = 77;

  const auto response =
      camera_firmware::service::BuildDetectionSnapshotResponse(
          [&event] {
            return std::vector<camera_firmware::ai::DetectionEvent>{event};
          });

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  ASSERT_EQ((*json)["events"].size(), 1U);
  EXPECT_EQ((*json)["events"][0]["camera_id"].asString(), "imx708-main");
  EXPECT_EQ((*json)["events"][0]["model_id"].asString(), "objects");
  EXPECT_EQ((*json)["events"][0]["frame_sequence"].asUInt64(), 77U);
}

TEST(ServiceResponseTest, DetectionSseEventSerializesSnapshot) {
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.model_id = "objects";
  event.model_kind = "object_detection";
  event.result_state = "decoded";
  event.frame_sequence = 88;
  event.frame_timestamp = std::chrono::nanoseconds{987654321};
  camera_firmware::ai::Detection detection;
  detection.class_id = 0;
  detection.label = "person";
  detection.confidence = 0.91F;
  camera_firmware::ai::Keypoint keypoint;
  keypoint.name = "nose";
  keypoint.x = 0.45F;
  keypoint.y = 0.18F;
  keypoint.confidence = 0.93F;
  detection.keypoints.push_back(keypoint);
  event.detections.push_back(detection);

  const auto payload =
      camera_firmware::service::BuildDetectionSseEvent({event});

  EXPECT_NE(payload.find("event: detections\n"), std::string::npos);
  // The browser's EventSource waits this many ms before reconnecting after
  // each one-shot long-poll response, so it caps the bbox overlay refresh
  // rate. 200 gives ~5 Hz; a change here is a visible-cadence change.
  EXPECT_NE(payload.find("\nretry: 200\n"), std::string::npos);
  EXPECT_NE(payload.find("id: imx708-main/objects/88/decoded\n"),
            std::string::npos);
  EXPECT_NE(payload.find("\"camera_id\":\"imx708-main\""), std::string::npos);
  EXPECT_NE(payload.find("\"frame_sequence\":88"), std::string::npos);
  EXPECT_NE(payload.find("\"frame_timestamp_ns\":987654321"),
            std::string::npos);
  EXPECT_NE(payload.find("\"class_id\":0"), std::string::npos);
  EXPECT_NE(payload.find("\"keypoints\""), std::string::npos);
  EXPECT_NE(payload.find("\"name\":\"nose\""), std::string::npos);
  EXPECT_TRUE(payload.ends_with("\n\n"));
}

TEST(ServiceResponseTest, DetectionSseIdChangesWithSnapshotContent) {
  camera_firmware::ai::DetectionEvent first;
  first.camera_id = "imx708-main";
  first.model_id = "objects";
  first.result_state = "decoded";
  first.frame_sequence = 88;

  camera_firmware::ai::DetectionEvent second = first;
  second.frame_sequence = 89;

  EXPECT_NE(camera_firmware::service::BuildDetectionSseId({first}),
            camera_firmware::service::BuildDetectionSseId({second}));
  EXPECT_EQ(camera_firmware::service::BuildDetectionSseId({}), "empty");
}

TEST(ServiceResponseTest, DetectionSseResponseUsesEventStreamBody) {
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.model_id = "objects";
  event.model_kind = "object_detection";
  event.result_state = "decoded";
  event.frame_sequence = 89;

  const auto response =
      camera_firmware::service::BuildDetectionSseResponse({event});

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  EXPECT_EQ(response->contentTypeString(), "text/event-stream");
  EXPECT_EQ(response->getHeader("Cache-Control"), "no-cache");
  EXPECT_NE(response->body().find("\"frame_sequence\":89"), std::string::npos);
}

TEST(ServiceResponseTest, DetectionSseMergeAddsLiveEventToStaleSnapshot) {
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.model_id = "objects";
  event.model_kind = "object_detection";
  event.result_state = "decoded";
  event.frame_sequence = 90;

  const auto merged =
      camera_firmware::service::MergeDetectionSnapshotWithEvent({}, event);

  ASSERT_EQ(merged.size(), 1U);
  EXPECT_EQ(merged[0].frame_sequence, 90U);
}

TEST(ServiceResponseTest, DetectionSseMergeReplacesMatchingCameraModel) {
  camera_firmware::ai::DetectionEvent stored;
  stored.camera_id = "imx708-main";
  stored.model_id = "objects";
  stored.model_kind = "object_detection";
  stored.result_state = "decoded";
  stored.frame_sequence = 91;

  camera_firmware::ai::DetectionEvent live = stored;
  live.frame_sequence = 92;

  const auto merged =
      camera_firmware::service::MergeDetectionSnapshotWithEvent({stored}, live);

  ASSERT_EQ(merged.size(), 1U);
  EXPECT_EQ(merged[0].frame_sequence, 92U);
}

TEST(ServiceResponseTest, TlsListenerConfigUsesResolvedMaterial) {
  TemporaryTlsDirectory state;
  camera_firmware::config::AppConfig config;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = 9443;
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  camera_firmware::service::ServiceListenerConfig listener;
  struct stat validated_certificate {};
  {
    auto resolved = camera_firmware::security::ResolveTlsMaterial(
        config.http.tls, state.path(), TestCryptoProvider());
    ASSERT_TRUE(resolved.ok()) << resolved.error().message;
    listener = camera_firmware::service::BuildServiceListenerConfig(
        config.http, resolved.value());
    ASSERT_EQ(::stat(listener.certificate_path.c_str(),
                     &validated_certificate),
              0);
  }
  std::filesystem::rename(state.path() / "device-tls",
                          state.path() / "validated-device-tls");
  ASSERT_TRUE(std::filesystem::create_directory(state.path() / "device-tls"));
  ASSERT_EQ(::chmod((state.path() / "device-tls").c_str(), 0700), 0);
  WriteExclusiveTlsFile(state.path() / "device-tls", "certificate.pem", 0644,
                        "replacement certificate\n");
  WriteExclusiveTlsFile(state.path() / "device-tls", "private-key.pem", 0600,
                        "replacement key\n");

  EXPECT_EQ(listener.bind_address, "127.0.0.1");
  EXPECT_EQ(listener.port, 9443u);
  EXPECT_TRUE(listener.use_tls);
  EXPECT_TRUE(listener.certificate_path.starts_with("/proc/self/fd/"));
  EXPECT_TRUE(listener.private_key_path.starts_with("/proc/self/fd/"));
  EXPECT_TRUE(std::filesystem::exists(listener.certificate_path));
  EXPECT_TRUE(std::filesystem::exists(listener.private_key_path));
  struct stat listener_certificate {};
  ASSERT_EQ(::stat(listener.certificate_path.c_str(), &listener_certificate), 0);
  EXPECT_EQ(listener_certificate.st_dev, validated_certificate.st_dev);
  EXPECT_EQ(listener_certificate.st_ino, validated_certificate.st_ino);
}

TEST(ServiceResponseTest,
     InjectedTlsOwnerSurvivesConfiguredPathRemovalBeforeServiceInit) {
  TemporaryTlsDirectory state;
  camera_firmware::config::HttpTlsConfig development_tls;
  development_tls.enabled = true;
  development_tls.allow_development_self_signed_tls = true;
  auto generated = camera_firmware::security::ResolveTlsMaterial(
      development_tls, state.path(), TestCryptoProvider());
  ASSERT_TRUE(generated.ok()) << generated.error().message;

  camera_firmware::config::AppConfig config;
  config.http.enabled = true;
  config.http.tls.enabled = true;
  config.http.tls.certificate_path =
      (state.path() / "device-tls" / "certificate.pem").string();
  config.http.tls.private_key_path =
      (state.path() / "device-tls" / "private-key.pem").string();
  auto pinned = camera_firmware::security::ResolveTlsMaterial(
      config.http.tls, state.path(), TestCryptoProvider());
  ASSERT_TRUE(pinned.ok()) << pinned.error().message;
  struct stat pinned_certificate {};
  ASSERT_EQ(::stat(pinned.value().certificate_path.c_str(),
                   &pinned_certificate),
            0);

  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.tls_material = pinned.value();
  ASSERT_TRUE(std::filesystem::remove_all(state.path() / "device-tls"));

  auto selected =
      camera_firmware::service::internal::SelectServiceTlsMaterial(args);

  ASSERT_TRUE(selected.ok()) << selected.error().message;
  ASSERT_TRUE(selected.value().has_value());
  struct stat selected_certificate {};
  ASSERT_EQ(::stat(selected.value()->certificate_path.c_str(),
                   &selected_certificate),
            0);
  EXPECT_EQ(selected_certificate.st_dev, pinned_certificate.st_dev);
  EXPECT_EQ(selected_certificate.st_ino, pinned_certificate.st_ino);
  EXPECT_TRUE(std::filesystem::exists(selected.value()->private_key_path));
}

// SelectServiceTlsMaterial must never construct its own CryptoProvider (see
// its comment): if args.provider is unset, it must fail closed rather than
// silently self-provisioning one.
TEST(ServiceResponseTest, SelectServiceTlsMaterialFailsClosedWithoutInjectedProvider) {
  camera_firmware::config::AppConfig config;
  config.http.enabled = true;
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;  // provider deliberately left unset

  const auto selected =
      camera_firmware::service::internal::SelectServiceTlsMaterial(args);

  ASSERT_FALSE(selected.ok());
  EXPECT_EQ(selected.error().code, "E_CRYPTO_UNAVAILABLE");
}

TEST(ServiceResponseTest, HttpTlsValidationPermitsMissingExplicitDevelopmentPair) {
  camera_firmware::config::HttpConfig http;
  http.enabled = true;
  http.tls.enabled = true;
  http.tls.allow_development_self_signed_tls = true;

  const auto validated =
      camera_firmware::service::ValidateHttpTlsConfigFiles(http, TestCryptoProvider());

  ASSERT_TRUE(validated.ok()) << validated.error().message;
}

TEST(ServiceResponseTest, HttpTlsValidationRejectsMissingProductionPair) {
  camera_firmware::config::HttpConfig http;
  http.enabled = true;
  http.tls.enabled = true;

  const auto validated =
      camera_firmware::service::ValidateHttpTlsConfigFiles(http, TestCryptoProvider());

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_HTTP_TLS_REQUIRED");
}

TEST(ServiceResponseTest, HttpTlsValidationRejectsIncompleteDevelopmentPair) {
  camera_firmware::config::HttpConfig http;
  http.enabled = true;
  http.tls.enabled = true;
  http.tls.allow_development_self_signed_tls = true;
  http.tls.certificate_path = "/configured/http.crt";

  const auto validated =
      camera_firmware::service::ValidateHttpTlsConfigFiles(http, TestCryptoProvider());

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_HTTP_TLS_REQUIRED");
}

TEST(ServiceResponseTest, TlsInitRejectsSecurityWithoutTlsInsteadOfDowngrade) {
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.http.enabled = true;
  config.http.tls.enabled = false;
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  camera_firmware::service::ServiceApp service;

  const auto initialized = service.Init(args);

  ASSERT_FALSE(initialized.ok());
  EXPECT_EQ(initialized.error().code, "E_HTTP_TLS_REQUIRED");
}

TEST(ServiceResponseTest,
     InitRejectsConfiguredSelfProtectionWithoutAtomicRuntimeControlGate) {
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.self_protection.manifest_path = "/opt/camera/integrity.yaml";
  config.self_protection.signature_path = "/opt/camera/integrity.sig";
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  camera_firmware::service::ServiceApp service;

  const auto initialized = service.Init(args);

  ASSERT_FALSE(initialized.ok());
  EXPECT_EQ(initialized.error().code, "E_SERVICE_CONFIG");
  EXPECT_NE(initialized.error().message.find("atomic runtime control gate"),
            std::string::npos);
}

TEST(ServiceResponseTest,
     InitRejectsDefaultSecurityStateWithoutRuntimeStartCallback) {
  TemporaryTlsDirectory state;
  camera_firmware::config::AppConfig config;
  config.security.enabled = true;
  config.security.state_directory = state.path().string();
  config.http.enabled = true;
  config.http.bind_ip = "127.0.0.1";
  config.http.port = 0;
  config.http.tls.enabled = true;
  config.http.tls.allow_development_self_signed_tls = true;
  camera_firmware::service::ServiceInitArgs args;
  args.app_config = &config;
  args.provider = &TestCryptoProvider();
  camera_firmware::service::ServiceApp service;

  const auto initialized = service.Init(args);

  ASSERT_FALSE(initialized.ok());
  EXPECT_EQ(initialized.error().code, "E_SERVICE_CONFIG");
}

TEST(ServiceResponseTest, TlsDescriptorOwnerSurvivesTimeoutUntilSafeJoin) {
  TemporaryTlsDirectory state;
  camera_firmware::config::HttpTlsConfig tls;
  tls.enabled = true;
  tls.allow_development_self_signed_tls = true;
  auto resolved = camera_firmware::security::ResolveTlsMaterial(tls, state.path(), TestCryptoProvider());
  ASSERT_TRUE(resolved.ok()) << resolved.error().message;
  const auto certificate_path = resolved.value().certificate_path;
  const auto private_key_path = resolved.value().private_key_path;

  auto release = std::make_shared<std::promise<void>>();
  auto release_future = release->get_future().share();
  auto completion = std::make_shared<std::promise<void>>();
  auto completion_future = completion->get_future().share();
  auto service_thread =
      camera_firmware::service::internal::StartServiceThreadWithTlsOwner(
          std::optional<camera_firmware::security::ResolvedTlsMaterial>{
              std::move(resolved).value()},
          [release_future, completion] {
            release_future.wait();
            completion->set_value();
          });

  auto stopped = camera_firmware::service::internal::StopServiceThreadWithin(
      service_thread, completion_future, std::chrono::milliseconds(10), [] {});

  ASSERT_FALSE(stopped.ok());
  EXPECT_EQ(stopped.error().code, "E_SERVICE_THREAD_STOP_TIMEOUT");
  EXPECT_TRUE(service_thread.joinable());
  EXPECT_EQ(::access(certificate_path.c_str(), R_OK), 0);
  EXPECT_EQ(::access(private_key_path.c_str(), R_OK), 0);

  release->set_value();
  ASSERT_EQ(completion_future.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  if (service_thread.joinable()) {
    service_thread.join();
  }
  for (int attempt = 0; attempt < 1000; ++attempt) {
    if (::access(certificate_path.c_str(), F_OK) != 0 &&
        ::access(private_key_path.c_str(), F_OK) != 0) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  EXPECT_NE(::access(certificate_path.c_str(), F_OK), 0);
  EXPECT_NE(::access(private_key_path.c_str(), F_OK), 0);
}

TEST(ServiceResponseTest, HttpTlsValidationRejectsUnreadableOrInvalidFiles) {
  TemporaryTlsDirectory state;
  WriteExclusiveTlsFile(state.path(), "invalid-http.crt", 0644,
                        "not a certificate\n");
  WriteExclusiveTlsFile(state.path(), "invalid-http.key", 0600,
                        "not a private key\n");
  const auto cert_path = state.path() / "invalid-http.crt";
  const auto key_path = state.path() / "invalid-http.key";

  camera_firmware::config::HttpConfig http;
  http.enabled = true;
  http.tls.enabled = true;
  http.tls.certificate_path = cert_path.string();
  http.tls.private_key_path = key_path.string();

  auto validated = camera_firmware::service::ValidateHttpTlsConfigFiles(http, TestCryptoProvider());

  ASSERT_FALSE(validated.ok());
  EXPECT_EQ(validated.error().code, "E_HTTP_TLS_CERT");
}

TEST(ServiceResponseTest, InitReturnsErrorWhenConfigIsMissing) {
  camera_firmware::service::ServiceApp service;
  camera_firmware::service::ServiceInitArgs args;

  auto initialized = service.Init(args);

  ASSERT_FALSE(initialized.ok());
  EXPECT_EQ(initialized.error().code, "E_SERVICE_CONFIG");
}

TEST(ServiceResponseTest, ServiceInitArgsAcceptsInjectableStreamRegistry) {
  camera_firmware::service::ServiceInitArgs args;
  auto registry =
      std::make_shared<camera_firmware::service::SessionStreamRegistry>();

  args.stream_registry = registry;

  EXPECT_EQ(args.stream_registry, registry);
}

TEST(ServiceResponseTest, ServiceInitArgsAcceptsAuthServiceDependenciesOnly) {
  camera_firmware::service::ServiceInitArgs args;
  bool provider_called = false;
  args.auth_service_dependencies_provider = [&] {
    provider_called = true;
    return camera_firmware::security::AuthServiceDependencies{};
  };

  const auto dependencies = args.auth_service_dependencies_provider();

  EXPECT_TRUE(provider_called);
  EXPECT_FALSE(dependencies.now_seconds);
}

TEST(ServiceResponseTest,
     ServiceInitArgsDoesNotExposeUserManagementServiceConstruction) {
  EXPECT_FALSE(HasUserManagementServiceInjection<
               camera_firmware::service::ServiceInitArgs>);
}

TEST(ServiceResponseTest, SerializesAdministratorRole) {
  const auto role = camera_firmware::service::internal::
      SerializeUserRoleForTesting(
          camera_firmware::security::UserRole::kAdministrator);

  ASSERT_TRUE(role.has_value());
  EXPECT_EQ(*role, "administrator");
}

TEST(ServiceResponseTest, SerializesViewerRole) {
  const auto role = camera_firmware::service::internal::
      SerializeUserRoleForTesting(camera_firmware::security::UserRole::kViewer);

  ASSERT_TRUE(role.has_value());
  EXPECT_EQ(*role, "viewer");
}

TEST(ServiceResponseTest, RejectsUnknownRoleSerialization) {
  using Role = camera_firmware::security::UserRole;
  using Underlying = std::underlying_type_t<Role>;
  const auto role = camera_firmware::service::internal::
      SerializeUserRoleForTesting(
          static_cast<Role>(std::numeric_limits<Underlying>::max()));

  EXPECT_FALSE(role.has_value());
}

TEST(ServiceResponseTest, ServiceInitArgsRetainsTypedLegacyLiveCallback) {
  EXPECT_TRUE(HasExactLegacyLiveStreamCallback<
              camera_firmware::service::ServiceInitArgs>);
  EXPECT_TRUE(HasCancellableLiveStreamCallback<
              camera_firmware::service::ServiceInitArgs>);
  camera_firmware::service::LiveMp4OpenCallback typed_legacy =
      [](const std::string&) {
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamCallback>::Err(
            {"E_LIVE_UNAVAILABLE", "unavailable"});
      };
  camera_firmware::service::ServiceInitArgs args;
  args.live_stream_callback = typed_legacy;
  EXPECT_TRUE(static_cast<bool>(args.live_stream_callback));
}

TEST(ServiceResponseTest, LegacyEmptyLiveCallbackRemainsSourceCompatible) {
  auto response = camera_firmware::service::BuildLiveMp4Response(
      {}, "imx708-main");

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
}

TEST(ServiceResponseTest, SnapshotResponseReturnsJpegBytesFromCallback) {
  const std::vector<std::uint8_t> jpeg{0xff, 0xd8, 0xff, 0xd9};

  auto response = camera_firmware::service::BuildSnapshotResponse(
      [&](const std::string& camera_id)
          -> std::optional<std::vector<std::uint8_t>> {
        if (camera_id != "imx708-main") {
          return std::nullopt;
        }
        return jpeg;
      },
      "imx708-main");

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  EXPECT_EQ(response->body(), std::string("\xff\xd8\xff\xd9", 4));
}

TEST(ServiceResponseTest, SnapshotResponseReturnsUnavailableForUnknownCamera) {
  auto response = camera_firmware::service::BuildSnapshotResponse(
      [](const std::string&) -> std::optional<std::vector<std::uint8_t>> {
        return std::nullopt;
      },
      "unknown");

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
}

TEST(ServiceResponseTest, LiveUnavailableUsesOnlyPublicErrorContract) {
  auto response = camera_firmware::service::BuildLiveMp4Response(
      [](const std::string&) {
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamCallback>::Err(
            {"E_LIVE_STALE", "private fragment timing detail"});
      },
      "imx708-main");

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), "E_LIVE_UNAVAILABLE");
  EXPECT_EQ((*json)["message"].asString(), "live preview is unavailable");
}

TEST(ServiceResponseTest,
     LiveMp4PumpAllocationFailureCancelsOpenedMediaExactlyOnce) {
  std::atomic_size_t cancel_calls{0U};
  camera_firmware::service::internal::
      FailNextLiveMp4PumpAllocationForTesting();

  drogon::HttpResponsePtr response;
  EXPECT_NO_THROW(
      response = camera_firmware::service::BuildCancellableLiveMp4Response(
                      [&](const std::string&) {
                        return camera_firmware::common::Result<
                            camera_firmware::service::LiveMp4StreamHandle>::Ok(
                            {
                                .read = [](char*, std::size_t) {
                                  return std::size_t{0U};
                                },
                                .cancel = [&] {
                                  cancel_calls.fetch_add(
                                      1U, std::memory_order_relaxed);
                                },
                            });
                      },
                      "imx708-main"));
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
  EXPECT_EQ(cancel_calls.load(std::memory_order_relaxed), 1U);
}

TEST(ServiceResponseTest,
     LiveMp4TypedLegacyCallbackUsesOneStatefulFunctorForReadAndCancel) {
  struct InvocationState {
    std::mutex mutex;
    std::condition_variable changed;
    std::atomic<unsigned int> next_id{0U};
    std::atomic<unsigned int> read_id{0U};
    std::atomic<unsigned int> cancel_id{0U};
  };
  class StatefulStream {
   public:
    explicit StatefulStream(std::shared_ptr<InvocationState> state)
        : state_(std::move(state)), id_(++state_->next_id) {}
    StatefulStream(const StatefulStream& other)
        : state_(other.state_), id_(++state_->next_id) {}
    StatefulStream(StatefulStream&&) noexcept = default;

    std::size_t operator()(char* output, std::size_t capacity) {
      if (output == nullptr) {
        state_->cancel_id.store(id_);
        state_->changed.notify_all();
        return 0U;
      }
      state_->read_id.store(id_);
      if (sent_ || capacity == 0U) {
        return 0U;
      }
      sent_ = true;
      output[0] = 'x';
      return 1U;
    }

   private:
    std::shared_ptr<InvocationState> state_;
    unsigned int id_{0U};
    bool sent_{false};
  };
  struct OutputState {
    std::mutex mutex;
    std::condition_variable changed;
    bool closed{false};
  };
  class ClosingStream final : public trantor::AsyncStream {
   public:
    explicit ClosingStream(std::shared_ptr<OutputState> state)
        : state_(std::move(state)) {}
    bool send(const char*, std::size_t) override { return true; }
    void close() override {
      std::lock_guard lock(state_->mutex);
      state_->closed = true;
      state_->changed.notify_all();
    }

   private:
    std::shared_ptr<OutputState> state_;
  };

  auto invocation = std::make_shared<InvocationState>();
  camera_firmware::service::LiveMp4OpenCallback callback =
      [invocation](const std::string&) {
        camera_firmware::service::LiveMp4StreamCallback stream =
            StatefulStream(invocation);
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamCallback>::Ok(
            std::move(stream));
      };
  auto response = camera_firmware::service::BuildLiveMp4Response(
      callback, "imx708-main");
  auto output = std::make_shared<OutputState>();
  ASSERT_TRUE(response->asyncStreamCallback());

  response->asyncStreamCallback()(std::make_unique<ClosingStream>(output));

  std::unique_lock lock(output->mutex);
  ASSERT_TRUE(output->changed.wait_for(
      lock, std::chrono::seconds(1), [&] { return output->closed; }));
  lock.unlock();
  std::unique_lock invocation_lock(invocation->mutex);
  ASSERT_TRUE(invocation->changed.wait_for(
      invocation_lock, std::chrono::seconds(1),
      [&] { return invocation->cancel_id.load() != 0U; }));
  ASSERT_NE(invocation->read_id.load(), 0U);
  EXPECT_EQ(invocation->cancel_id.load(), invocation->read_id.load());
}

TEST(ServiceResponseTest, LiveCapacityUsesOnlyPublicErrorContract) {
  auto response = camera_firmware::service::BuildLiveMp4Response(
      [](const std::string&) {
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamCallback>::Err(
            {"E_LIVE_CAPACITY", "private reader detail"});
      },
      "imx708-main");

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k503ServiceUnavailable);
  const auto json = response->jsonObject();
  ASSERT_NE(json, nullptr);
  EXPECT_EQ((*json)["code"].asString(), "E_LIVE_CAPACITY");
  EXPECT_EQ((*json)["message"].asString(),
            "live preview reader capacity is full");
}

TEST(ServiceResponseTest, LiveMp4ResponseWritesBytesAndSignalsRelease) {
  struct StreamState {
    std::string bytes{"fragmented-mp4-bytes"};
    bool sent{false};
    std::atomic_bool released{false};
  };
  struct OutputState {
    std::mutex mutex;
    std::condition_variable changed;
    std::string bytes;
    bool closed{false};
  };
  class RecordingAsyncStream final : public trantor::AsyncStream {
   public:
    explicit RecordingAsyncStream(std::shared_ptr<OutputState> state)
        : state_(std::move(state)) {}

    bool send(const char* data, std::size_t size) override {
      std::lock_guard lock(state_->mutex);
      state_->bytes.append(data, size);
      return true;
    }

    void close() override {
      std::lock_guard lock(state_->mutex);
      state_->closed = true;
      state_->changed.notify_all();
    }

   private:
    std::shared_ptr<OutputState> state_;
  };
  auto state = std::make_shared<StreamState>();
  auto output_state = std::make_shared<OutputState>();

  auto response = camera_firmware::service::BuildLiveMp4Response(
      [state](const std::string& camera_id) {
        if (camera_id != "imx708-main") {
          return camera_firmware::common::Result<
              camera_firmware::service::LiveMp4StreamCallback>::Err(
              {"E_LIVE_NOT_FOUND", "camera not found"});
        }
        camera_firmware::service::LiveMp4StreamCallback stream =
            [state](char* output, std::size_t capacity) {
              if (output == nullptr) {
                state->released.store(true);
                return std::size_t{0};
              }
              if (state->sent) {
                return std::size_t{0};
              }
              state->sent = true;
              const auto count = std::min(capacity, state->bytes.size());
              std::copy_n(state->bytes.data(), count, output);
              return count;
            };
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamCallback>::Ok(
            std::move(stream));
      },
      "imx708-main");

  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->statusCode(), drogon::k200OK);
  EXPECT_EQ(response->contentTypeString(), "video/mp4");
  EXPECT_EQ(response->getHeader("Content-Encoding"), "identity");
  EXPECT_FALSE(response->streamCallback());
  ASSERT_TRUE(response->asyncStreamCallback());

  response->asyncStreamCallback()(
      std::make_unique<RecordingAsyncStream>(output_state));
  std::unique_lock lock(output_state->mutex);
  ASSERT_TRUE(output_state->changed.wait_for(
      lock, std::chrono::seconds(1), [&] { return output_state->closed; }));
  EXPECT_EQ(output_state->bytes, "fragmented-mp4-bytes");
  lock.unlock();

  EXPECT_TRUE(state->released.load());
}

TEST(ServiceResponseTest, LiveMp4ResponseBoundsQueuedBytesPerConnection) {
  constexpr std::size_t kResponseLimit = 32U * 1024U + 123U;
  struct StreamState {
    std::atomic_bool released{false};
  };
  struct OutputState {
    std::mutex mutex;
    std::condition_variable changed;
    std::size_t bytes{0U};
    bool closed{false};
  };
  class CountingAsyncStream final : public trantor::AsyncStream {
   public:
    explicit CountingAsyncStream(std::shared_ptr<OutputState> state)
        : state_(std::move(state)) {}

    bool send(const char*, std::size_t size) override {
      std::lock_guard lock(state_->mutex);
      state_->bytes += size;
      return true;
    }

    void close() override {
      std::lock_guard lock(state_->mutex);
      state_->closed = true;
      state_->changed.notify_all();
    }

   private:
    std::shared_ptr<OutputState> state_;
  };
  auto stream_state = std::make_shared<StreamState>();
  auto output_state = std::make_shared<OutputState>();

  auto response = camera_firmware::service::BuildLiveMp4Response(
      [stream_state](const std::string&) {
        camera_firmware::service::LiveMp4StreamCallback stream =
            [stream_state](char* output, std::size_t capacity) {
              if (output == nullptr) {
                stream_state->released.store(true);
                return std::size_t{0};
              }
              std::fill_n(output, capacity, 'x');
              return capacity;
            };
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamCallback>::Ok(
            std::move(stream));
      },
      "imx708-main", kResponseLimit);

  ASSERT_NE(response, nullptr);
  ASSERT_TRUE(response->asyncStreamCallback());
  response->asyncStreamCallback()(
      std::make_unique<CountingAsyncStream>(output_state));
  std::unique_lock lock(output_state->mutex);
  ASSERT_TRUE(output_state->changed.wait_for(
      lock, std::chrono::seconds(1), [&] { return output_state->closed; }));
  EXPECT_EQ(output_state->bytes, kResponseLimit);
  lock.unlock();
  const auto release_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (!stream_state->released.load() &&
         std::chrono::steady_clock::now() < release_deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  EXPECT_TRUE(stream_state->released.load());
}

TEST(ServiceResponseTest, LiveMp4ZeroBudgetStreamsPastFormerDefaultLimit) {
  // A zero response-byte budget must mean "no budget": the pump should keep
  // streaming well past the old 16MiB hard cutoff instead of force-cutting
  // the viewer mid-fragment. It only stops when the source read() reports
  // EOF (returns 0), which this fixture triggers once it has served more
  // than the former default limit.
  constexpr std::size_t kFormerDefaultLimit = 16U * 1024U * 1024U;
  struct StreamState {
    std::atomic<std::size_t> served{0U};
  };
  struct OutputState {
    std::mutex mutex;
    std::condition_variable changed;
    std::size_t bytes{0U};
    bool closed{false};
  };
  class CountingAsyncStream final : public trantor::AsyncStream {
   public:
    explicit CountingAsyncStream(std::shared_ptr<OutputState> state)
        : state_(std::move(state)) {}

    bool send(const char*, std::size_t size) override {
      std::lock_guard lock(state_->mutex);
      state_->bytes += size;
      return true;
    }

    void close() override {
      std::lock_guard lock(state_->mutex);
      state_->closed = true;
      state_->changed.notify_all();
    }

   private:
    std::shared_ptr<OutputState> state_;
  };

  auto stream_state = std::make_shared<StreamState>();
  auto output_state = std::make_shared<OutputState>();

  auto response = camera_firmware::service::BuildLiveMp4Response(
      [stream_state](const std::string&) {
        camera_firmware::service::LiveMp4StreamCallback stream =
            [stream_state](char* output, std::size_t capacity) {
              if (output == nullptr) {
                return std::size_t{0};
              }
              if (stream_state->served.load() >
                  kFormerDefaultLimit + (256U * 1024U)) {
                return std::size_t{0};
              }
              std::fill_n(output, capacity, 'x');
              stream_state->served += capacity;
              return capacity;
            };
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamCallback>::Ok(
            std::move(stream));
      },
      "imx708-main", /*maximum_response_bytes=*/0U);

  ASSERT_NE(response, nullptr);
  ASSERT_TRUE(response->asyncStreamCallback());
  response->asyncStreamCallback()(
      std::make_unique<CountingAsyncStream>(output_state));

  std::unique_lock lock(output_state->mutex);
  ASSERT_TRUE(output_state->changed.wait_for(
      lock, std::chrono::seconds(5), [&] { return output_state->closed; }));
  EXPECT_GT(output_state->bytes, kFormerDefaultLimit);
}

TEST(ServiceResponseTest,
     LiveMp4RevocationClosesBlockedOutputWithoutSendingReturnedBytes) {
  struct StreamState {
    std::mutex mutex;
    std::condition_variable changed;
    bool read_started{false};
    bool cancelled{false};
    bool read_finished{false};
    std::size_t cancel_calls{0U};
  };
  struct OutputState {
    std::mutex mutex;
    std::condition_variable changed;
    std::string bytes;
    std::size_t close_calls{0U};
  };
  class RecordingAsyncStream final : public trantor::AsyncStream {
   public:
    explicit RecordingAsyncStream(std::shared_ptr<OutputState> state)
        : state_(std::move(state)) {}

    bool send(const char* data, std::size_t size) override {
      std::lock_guard lock(state_->mutex);
      state_->bytes.append(data, size);
      return true;
    }

    void close() override {
      std::lock_guard lock(state_->mutex);
      ++state_->close_calls;
      state_->changed.notify_all();
    }

   private:
    std::shared_ptr<OutputState> state_;
  };

  camera_firmware::service::SessionStreamRegistry registry;
  camera_firmware::security::SessionIdentity identity;
  identity.bytes.fill(34U);
  auto lease = registry.Acquire(identity);
  auto stream_state = std::make_shared<StreamState>();
  auto output_state = std::make_shared<OutputState>();
  auto response = camera_firmware::service::BuildCancellableLiveMp4Response(
      [stream_state](const std::string&) {
        camera_firmware::service::LiveMp4StreamHandle stream{
            .read = [stream_state](char* output, std::size_t capacity) {
              std::unique_lock lock(stream_state->mutex);
              stream_state->read_started = true;
              stream_state->changed.notify_all();
              stream_state->changed.wait(
                  lock, [&] { return stream_state->cancelled; });
              stream_state->read_finished = true;
              stream_state->changed.notify_all();
              const auto count = std::min(capacity, std::size_t{4U});
              std::fill_n(output, count, 'x');
              return count;
            },
            .cancel = [stream_state] {
              std::lock_guard lock(stream_state->mutex);
              ++stream_state->cancel_calls;
              stream_state->cancelled = true;
              stream_state->changed.notify_all();
            },
        };
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamHandle>::Ok(
            std::move(stream));
      },
      "imx708-main",
      camera_firmware::service::kDefaultLiveMp4ResponseByteLimit, lease);
  ASSERT_NE(response, nullptr);
  ASSERT_TRUE(response->asyncStreamCallback());
  response->asyncStreamCallback()(
      std::make_unique<RecordingAsyncStream>(output_state));
  {
    std::unique_lock lock(stream_state->mutex);
    ASSERT_TRUE(stream_state->changed.wait_for(
        lock, std::chrono::seconds(1),
        [&] { return stream_state->read_started; }));
  }

  const std::array revoked{identity};
  const auto revoke_started = std::chrono::steady_clock::now();
  const auto revoke_deadline = revoke_started + std::chrono::seconds(1);
  registry.Revoke(revoked);

  bool closed_promptly = false;
  {
    std::unique_lock lock(output_state->mutex);
    closed_promptly = output_state->changed.wait_until(
        lock, revoke_deadline,
        [&] { return output_state->close_calls != 0U; });
  }
  {
    std::unique_lock lock(stream_state->mutex);
    EXPECT_TRUE(stream_state->changed.wait_until(
        lock, revoke_deadline,
        [&] { return stream_state->read_finished; }));
    EXPECT_EQ(stream_state->cancel_calls, 1U);
  }

  EXPECT_TRUE(closed_promptly);
  EXPECT_LT(std::chrono::steady_clock::now() - revoke_started,
            std::chrono::seconds(1));
  std::lock_guard output_lock(output_state->mutex);
  EXPECT_TRUE(output_state->bytes.empty());
  EXPECT_EQ(output_state->close_calls, 1U);
}

TEST(ServiceResponseTest, LiveMp4DuplicateStartUsesOnePumpThread) {
  struct StreamState {
    std::mutex mutex;
    std::condition_variable changed;
    std::size_t read_calls{0U};
    std::size_t cancel_calls{0U};
    bool cancelled{false};
  };
  struct OutputState {
    std::mutex mutex;
    std::condition_variable changed;
    std::size_t close_calls{0U};
  };
  class CloseCountingStream final : public trantor::AsyncStream {
   public:
    explicit CloseCountingStream(std::shared_ptr<OutputState> state)
        : state_(std::move(state)) {}

    bool send(const char*, std::size_t) override { return true; }

    void close() override {
      std::lock_guard lock(state_->mutex);
      ++state_->close_calls;
      state_->changed.notify_all();
    }

   private:
    std::shared_ptr<OutputState> state_;
  };

  camera_firmware::service::SessionStreamRegistry registry;
  camera_firmware::security::SessionIdentity identity;
  identity.bytes.fill(36U);
  auto lease = registry.Acquire(identity);
  auto stream_state = std::make_shared<StreamState>();
  auto first_output = std::make_shared<OutputState>();
  auto duplicate_output = std::make_shared<OutputState>();
  auto response = camera_firmware::service::BuildCancellableLiveMp4Response(
      [stream_state](const std::string&) {
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamHandle>::Ok({
            .read = [stream_state](char*, std::size_t) {
              std::unique_lock lock(stream_state->mutex);
              ++stream_state->read_calls;
              stream_state->changed.notify_all();
              stream_state->changed.wait(
                  lock, [&] { return stream_state->cancelled; });
              return std::size_t{0U};
            },
            .cancel = [stream_state] {
              std::lock_guard lock(stream_state->mutex);
              ++stream_state->cancel_calls;
              stream_state->cancelled = true;
              stream_state->changed.notify_all();
            },
        });
      },
      "imx708-main",
      camera_firmware::service::kDefaultLiveMp4ResponseByteLimit, lease);
  ASSERT_TRUE(response->asyncStreamCallback());

  response->asyncStreamCallback()(
      std::make_unique<CloseCountingStream>(first_output));
  {
    std::unique_lock lock(stream_state->mutex);
    ASSERT_TRUE(stream_state->changed.wait_for(
        lock, std::chrono::seconds(1),
        [&] { return stream_state->read_calls != 0U; }));
  }
  response->asyncStreamCallback()(
      std::make_unique<CloseCountingStream>(duplicate_output));
  {
    std::unique_lock lock(duplicate_output->mutex);
    EXPECT_TRUE(duplicate_output->changed.wait_for(
        lock, std::chrono::seconds(1),
        [&] { return duplicate_output->close_calls != 0U; }));
  }
  {
    std::lock_guard lock(first_output->mutex);
    EXPECT_EQ(first_output->close_calls, 0U);
  }
  {
    std::lock_guard lock(stream_state->mutex);
    EXPECT_EQ(stream_state->cancel_calls, 0U);
  }

  const std::array revoked{identity};
  registry.Revoke(revoked);

  {
    std::unique_lock lock(first_output->mutex);
    EXPECT_TRUE(first_output->changed.wait_for(
        lock, std::chrono::seconds(1),
        [&] { return first_output->close_calls != 0U; }));
    EXPECT_EQ(first_output->close_calls, 1U);
  }
  {
    std::lock_guard lock(duplicate_output->mutex);
    EXPECT_EQ(duplicate_output->close_calls, 1U);
  }
  std::lock_guard lock(stream_state->mutex);
  EXPECT_EQ(stream_state->read_calls, 1U);
  EXPECT_EQ(stream_state->cancel_calls, 1U);
}

TEST(ServiceResponseTest, LiveMp4ReadExceptionCancelsAndClosesExactlyOnce) {
  struct State {
    std::mutex mutex;
    std::condition_variable changed;
    std::size_t read_calls{0U};
    std::size_t cancel_calls{0U};
    std::size_t close_calls{0U};
  };
  class ClosingStream final : public trantor::AsyncStream {
   public:
    explicit ClosingStream(std::shared_ptr<State> state)
        : state_(std::move(state)) {}
    bool send(const char*, std::size_t) override { return true; }
    void close() override {
      std::lock_guard lock(state_->mutex);
      ++state_->close_calls;
      state_->changed.notify_all();
    }

   private:
    std::shared_ptr<State> state_;
  };
  auto state = std::make_shared<State>();
  auto response = camera_firmware::service::BuildCancellableLiveMp4Response(
      [state](const std::string&) {
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamHandle>::Ok({
            .read = [state](char*, std::size_t) -> std::size_t {
              std::lock_guard lock(state->mutex);
              ++state->read_calls;
              throw std::runtime_error("read failed");
            },
            .cancel = [state] {
              std::lock_guard lock(state->mutex);
              ++state->cancel_calls;
              state->changed.notify_all();
            },
        });
      },
      "imx708-main");
  response->asyncStreamCallback()(std::make_unique<ClosingStream>(state));

  std::unique_lock lock(state->mutex);
  ASSERT_TRUE(state->changed.wait_for(
      lock, std::chrono::seconds(1),
      [&] { return state->cancel_calls == 1U && state->close_calls == 1U; }));
  EXPECT_EQ(state->read_calls, 1U);
}

TEST(ServiceResponseTest,
     LiveMp4SendFailureCompletesWhenCancelAndCloseThrow) {
  struct State {
    std::mutex mutex;
    std::condition_variable changed;
    std::size_t read_calls{0U};
    std::size_t send_calls{0U};
    std::size_t cancel_calls{0U};
    std::size_t close_calls{0U};
  };
  class FailingStream final : public trantor::AsyncStream {
   public:
    explicit FailingStream(std::shared_ptr<State> state)
        : state_(std::move(state)) {}
    bool send(const char*, std::size_t) override {
      std::lock_guard lock(state_->mutex);
      ++state_->send_calls;
      return false;
    }
    void close() override {
      std::lock_guard lock(state_->mutex);
      ++state_->close_calls;
      state_->changed.notify_all();
      throw std::runtime_error("close failed");
    }

   private:
    std::shared_ptr<State> state_;
  };
  auto state = std::make_shared<State>();
  auto response = camera_firmware::service::BuildCancellableLiveMp4Response(
      [state](const std::string&) {
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamHandle>::Ok({
            .read = [state](char* output, std::size_t capacity) {
              std::lock_guard lock(state->mutex);
              ++state->read_calls;
              const auto count = std::min(capacity, std::size_t{1U});
              std::fill_n(output, count, 'x');
              return count;
            },
            .cancel = [state] {
              std::lock_guard lock(state->mutex);
              ++state->cancel_calls;
              state->changed.notify_all();
              throw std::runtime_error("cancel failed");
            },
        });
      },
      "imx708-main");
  response->asyncStreamCallback()(std::make_unique<FailingStream>(state));

  std::unique_lock lock(state->mutex);
  ASSERT_TRUE(state->changed.wait_for(
      lock, std::chrono::seconds(1),
      [&] { return state->cancel_calls == 1U && state->close_calls == 1U; }));
  EXPECT_EQ(state->read_calls, 1U);
  EXPECT_EQ(state->send_calls, 1U);
}

TEST(ServiceResponseTest, LiveMp4RevokeSerializesWithInProgressSend) {
  struct State {
    std::mutex mutex;
    std::condition_variable changed;
    bool send_started{false};
    bool release_send{false};
    std::size_t send_calls{0U};
    std::size_t cancel_calls{0U};
    std::size_t close_calls{0U};
  };
  class BlockingSendStream final : public trantor::AsyncStream {
   public:
    explicit BlockingSendStream(std::shared_ptr<State> state)
        : state_(std::move(state)) {}
    bool send(const char*, std::size_t) override {
      std::unique_lock lock(state_->mutex);
      ++state_->send_calls;
      state_->send_started = true;
      state_->changed.notify_all();
      state_->changed.wait(lock, [&] { return state_->release_send; });
      return true;
    }
    void close() override {
      std::lock_guard lock(state_->mutex);
      ++state_->close_calls;
      state_->changed.notify_all();
    }

   private:
    std::shared_ptr<State> state_;
  };

  camera_firmware::service::SessionStreamRegistry registry;
  camera_firmware::security::SessionIdentity identity;
  identity.bytes.fill(37U);
  auto lease = registry.Acquire(identity);
  auto state = std::make_shared<State>();
  auto response = camera_firmware::service::BuildCancellableLiveMp4Response(
      [state](const std::string&) {
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamHandle>::Ok({
            .read = [](char* output, std::size_t capacity) {
              const auto count = std::min(capacity, std::size_t{1U});
              std::fill_n(output, count, 'x');
              return count;
            },
            .cancel = [state] {
              std::lock_guard lock(state->mutex);
              ++state->cancel_calls;
              state->changed.notify_all();
            },
        });
      },
      "imx708-main",
      camera_firmware::service::kDefaultLiveMp4ResponseByteLimit, lease);
  response->asyncStreamCallback()(
      std::make_unique<BlockingSendStream>(state));
  {
    std::unique_lock lock(state->mutex);
    ASSERT_TRUE(state->changed.wait_for(
        lock, std::chrono::seconds(1), [&] { return state->send_started; }));
  }

  const std::array revoked{identity};
  auto revoking = std::async(std::launch::async,
                             [&] { registry.Revoke(revoked); });
  EXPECT_EQ(revoking.wait_for(std::chrono::milliseconds(30)),
            std::future_status::timeout);
  {
    std::lock_guard lock(state->mutex);
    state->release_send = true;
    state->changed.notify_all();
  }
  ASSERT_EQ(revoking.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  revoking.get();

  std::unique_lock lock(state->mutex);
  ASSERT_TRUE(state->changed.wait_for(
      lock, std::chrono::seconds(1),
      [&] { return state->cancel_calls == 1U && state->close_calls == 1U; }));
  EXPECT_EQ(state->send_calls, 1U);
}

TEST(ServiceResponseTest, LiveMp4SendMayRevokeItsOwnLeaseWithoutDeadlock) {
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(5U);
    struct State {
      std::mutex mutex;
      std::condition_variable changed;
      std::size_t send_calls{0U};
      std::size_t cancel_calls{0U};
      std::size_t close_calls{0U};
      bool revoke_returned{false};
    };
    class ReentrantStream final : public trantor::AsyncStream {
     public:
      ReentrantStream(
          std::shared_ptr<State> state,
          camera_firmware::service::SessionStreamRegistry& registry,
          camera_firmware::security::SessionIdentity identity)
          : state_(std::move(state)),
            registry_(registry),
            identity_(identity) {}

      bool send(const char*, std::size_t) override {
        {
          std::lock_guard lock(state_->mutex);
          ++state_->send_calls;
        }
        const std::array revoked{identity_};
        registry_.Revoke(revoked);
        {
          std::lock_guard lock(state_->mutex);
          state_->revoke_returned = true;
          state_->changed.notify_all();
        }
        return true;
      }

      void close() override {
        std::lock_guard lock(state_->mutex);
        ++state_->close_calls;
        state_->changed.notify_all();
      }

     private:
      std::shared_ptr<State> state_;
      camera_firmware::service::SessionStreamRegistry& registry_;
      camera_firmware::security::SessionIdentity identity_;
    };

    camera_firmware::service::SessionStreamRegistry registry;
    camera_firmware::security::SessionIdentity identity;
    identity.bytes.fill(38U);
    auto lease = registry.Acquire(identity);
    auto state = std::make_shared<State>();
    auto response =
        camera_firmware::service::BuildCancellableLiveMp4Response(
        [state](const std::string&) {
          return camera_firmware::common::Result<
              camera_firmware::service::LiveMp4StreamHandle>::Ok({
              .read = [](char* output, std::size_t capacity) {
                const auto count = std::min(capacity, std::size_t{1U});
                std::fill_n(output, count, 'x');
                return count;
              },
              .cancel = [state] {
                std::lock_guard lock(state->mutex);
                ++state->cancel_calls;
                state->changed.notify_all();
              },
          });
        },
        "imx708-main",
        camera_firmware::service::kDefaultLiveMp4ResponseByteLimit, lease);
    response->asyncStreamCallback()(
        std::make_unique<ReentrantStream>(state, registry, identity));

    {
      std::unique_lock lock(state->mutex);
      EXPECT_TRUE(state->changed.wait_for(
          lock, std::chrono::seconds(2), [&] {
            return state->revoke_returned && state->cancel_calls == 1U &&
                   state->close_calls == 1U;
          }));
      EXPECT_EQ(state->send_calls, 1U);
    }
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(ServiceResponseTest,
     LiveMp4ConcurrentSendsMayRevokePeerLeasesWithoutDeadlock) {
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    (void)::alarm(5U);
    struct State {
      std::mutex mutex;
      std::condition_variable changed;
      std::size_t sends_entered{0U};
      std::size_t revokes_returned{0U};
      std::size_t cancel_calls{0U};
      std::size_t close_calls{0U};
    };
    class CrossRevokingStream final : public trantor::AsyncStream {
     public:
      CrossRevokingStream(
          std::shared_ptr<State> state,
          camera_firmware::service::SessionStreamRegistry& registry,
          camera_firmware::security::SessionIdentity peer_identity)
          : state_(std::move(state)),
            registry_(registry),
            peer_identity_(peer_identity) {}

      bool send(const char*, std::size_t) override {
        if (!first_send_) {
          return false;
        }
        first_send_ = false;
        {
          std::unique_lock lock(state_->mutex);
          ++state_->sends_entered;
          state_->changed.notify_all();
          state_->changed.wait(
              lock, [&] { return state_->sends_entered == 2U; });
        }
        const std::array revoked{peer_identity_};
        registry_.Revoke(revoked);
        {
          std::lock_guard lock(state_->mutex);
          ++state_->revokes_returned;
          state_->changed.notify_all();
        }
        return true;
      }

      void close() override {
        std::lock_guard lock(state_->mutex);
        ++state_->close_calls;
        state_->changed.notify_all();
      }

     private:
      std::shared_ptr<State> state_;
      camera_firmware::service::SessionStreamRegistry& registry_;
      camera_firmware::security::SessionIdentity peer_identity_;
      bool first_send_{true};
    };

    camera_firmware::service::SessionStreamRegistry registry;
    camera_firmware::security::SessionIdentity first_identity;
    camera_firmware::security::SessionIdentity second_identity;
    first_identity.bytes.fill(39U);
    second_identity.bytes.fill(40U);
    auto first_lease = registry.Acquire(first_identity);
    auto second_lease = registry.Acquire(second_identity);
    auto state = std::make_shared<State>();
    const auto build_response = [&](
                                    const auto& lease) {
      return camera_firmware::service::BuildCancellableLiveMp4Response(
          [state](const std::string&) {
            return camera_firmware::common::Result<
                camera_firmware::service::LiveMp4StreamHandle>::Ok({
                .read = [](char* output, std::size_t capacity) {
                  const auto count = std::min(capacity, std::size_t{1U});
                  std::fill_n(output, count, 'x');
                  return count;
                },
                .cancel = [state] {
                  std::lock_guard lock(state->mutex);
                  ++state->cancel_calls;
                  state->changed.notify_all();
                },
            });
          },
          "imx708-main",
          camera_firmware::service::kDefaultLiveMp4ResponseByteLimit,
          lease);
    };
    auto first_response = build_response(first_lease);
    auto second_response = build_response(second_lease);
    first_response->asyncStreamCallback()(std::make_unique<CrossRevokingStream>(
        state, registry, second_identity));
    second_response->asyncStreamCallback()(
        std::make_unique<CrossRevokingStream>(state, registry,
                                             first_identity));

    {
      std::unique_lock lock(state->mutex);
      const bool completed = state->changed.wait_for(
          lock, std::chrono::seconds(2), [&] {
            return state->revokes_returned == 2U &&
                   state->cancel_calls == 2U && state->close_calls == 2U;
          });
      EXPECT_TRUE(completed)
          << "sends_entered=" << state->sends_entered
          << " revokes_returned=" << state->revokes_returned
          << " cancel_calls=" << state->cancel_calls
          << " close_calls=" << state->close_calls;
    }
    _exit(::testing::Test::HasFailure() ? 1 : 0);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}
