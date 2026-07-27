#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if defined(CAMERA_FIRMWARE_TEST_PROTECTION_RUNTIME_PROBE)
#include <cerrno>
#include <climits>
#include <unistd.h>
#endif

#include <drogon/HttpAppFramework.h>

#include "camera_firmware/ai/AiFrameTap.hpp"
#include "camera_firmware/ai/AiRuntime.hpp"
#include "camera_firmware/ai/DetectionBus.hpp"
#include "camera_firmware/boot/FirmwareBootCoordinator.hpp"
#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/crypto/OpenSslCryptoProvider.hpp"
#include "camera_firmware/media/CameraPipeline.hpp"
#include "camera_firmware/media/EncodedRing.hpp"
#include "camera_firmware/media/SnapshotTap.hpp"
#include "camera_firmware/rtsp/SecureRtspServer.hpp"
#include "camera_firmware/runtime/FirmwareRuntime.hpp"
#include "camera_firmware/runtime/ManagedFirmwareRuntime.hpp"
#include "camera_firmware/integrity/IntegrityTrustAnchor.hpp"
#include "camera_firmware/integrity/IntegrityVerifier.hpp"
#include "camera_firmware/security/AuditLogService.hpp"
#include "camera_firmware/security/DeviceTlsManager.hpp"
#include "camera_firmware/security/SecuritySelfTest.hpp"
#include "camera_firmware/security/SecurityStore.hpp"
#include "camera_firmware/security/SystemProtectionService.hpp"
#include "camera_firmware/service/ServiceApp.hpp"
#include "camera_firmware/settings/RuntimeSettings.hpp"
#include "camera_firmware/settings/RuntimeSettingsService.hpp"
#include "camera_firmware/settings/RuntimeSettingsStore.hpp"

namespace {

using camera_firmware::common::Error;
using camera_firmware::common::Logger;

std::atomic_bool g_stop_requested{false};

class LiveMp4ByteStream {
 public:
  LiveMp4ByteStream(
      camera_firmware::media::FragmentRing::Reader reader,
      std::chrono::milliseconds stale_timeout)
      : reader_(std::move(reader)), stale_timeout_(stale_timeout) {}

  std::size_t Read(char* output, std::size_t capacity) {
    if (capacity == 0U || !reader_.valid()) {
      return 0U;
    }

    while (!current_bytes_ || current_offset_ >= current_bytes_->size()) {
      current_bytes_.reset();
      current_offset_ = 0U;
      auto next = reader_.WaitNext(stale_timeout_);
      if (!next.ok() || !next.value().has_value() ||
          !next.value()->bytes || next.value()->bytes->empty()) {
        return 0U;
      }
      current_bytes_ = std::move(next).value()->bytes;
    }

    const auto count =
        std::min(capacity, current_bytes_->size() - current_offset_);
    std::copy_n(current_bytes_->data() + current_offset_, count, output);
    current_offset_ += count;
    return count;
  }

  void Cancel() noexcept {
    reader_.Cancel();
  }

 private:
  camera_firmware::media::FragmentRing::Reader reader_;
  const std::chrono::milliseconds stale_timeout_;
  std::shared_ptr<const std::vector<std::uint8_t>> current_bytes_;
  std::size_t current_offset_{0U};
};

void RequestShutdown() {
  g_stop_requested.store(true);
}

void HandleSignal(int) { RequestShutdown(); }

int PrintError(const Error& error) {
  std::cerr << error.code << ": " << error.message << '\n';
  return EXIT_FAILURE;
}

std::string IntegrityPublicKeyPem() {
#if defined(CAMERA_FIRMWARE_TEST_INTEGRITY_TRUST_ANCHOR)
  if (const char* test_public_key =
          std::getenv("CF_TEST_INTEGRITY_PUBLIC_KEY_PEM");
      test_public_key != nullptr) {
    return test_public_key;
  }
#endif
  return std::string(
      camera_firmware::integrity::EmbeddedIntegrityPublicKeyPem());
}

#if defined(CAMERA_FIRMWARE_TEST_PROTECTION_RUNTIME_PROBE)
void SignalProtectionRuntimeStartForTesting() noexcept {
  const char* descriptor_text =
      std::getenv("CF_TEST_PROTECTION_RUNTIME_START_FD");
  if (descriptor_text == nullptr || *descriptor_text == '\0') {
    return;
  }

  errno = 0;
  char* end = nullptr;
  const long descriptor = std::strtol(descriptor_text, &end, 10);
  if (errno != 0 || end == descriptor_text || *end != '\0' ||
      descriptor < 0 || descriptor > INT_MAX) {
    return;
  }

  constexpr char kRuntimeStartSignal = 'R';
  ssize_t written = 0;
  do {
    written = ::write(static_cast<int>(descriptor), &kRuntimeStartSignal, 1U);
  } while (written < 0 && errno == EINTR);
}
#endif

#if defined(CAMERA_FIRMWARE_TEST_CRYPTO_SELF_TEST_HOOK)
bool ForceCryptoSelfTestFailureForTesting() noexcept {
  const char* forced =
      std::getenv("CAMERA_FIRMWARE_FORCE_CRYPTO_SELF_TEST_FAILURE");
  return forced != nullptr && *forced != '\0';
}
#endif

void InstallSignalHandlers() {
  std::signal(SIGINT, HandleSignal);
  std::signal(SIGTERM, HandleSignal);
  drogon::app().setIntSignalHandler(RequestShutdown);
  drogon::app().setTermSignalHandler(RequestShutdown);
}

void WaitForShutdown() {
  while (!g_stop_requested.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

int ValidateConfig(const std::string& config_path) {
  auto cfg = camera_firmware::config::LoadConfigFile(config_path);
  if (!cfg.ok()) {
    return PrintError(cfg.error());
  }

  // Mirrors RunFirmware's gate: no cryptographic operation (including the
  // HTTP TLS material validation below) may run before the provider has
  // proved itself, even on the --validate-config path.
  camera_firmware::crypto::OpenSslCryptoProvider crypto_provider;
  auto crypto_self_test = crypto_provider.SelfTest();
  if (!crypto_self_test.ok() || !crypto_self_test.value().passed) {
    return PrintError({"E_CRYPTO_UNAVAILABLE",
                       "cryptographic provider self-test failed"});
  }

  auto plugin = camera_firmware::rtsp::RegisterBuildTreeSecureSrtpPluginPath(
      CF_SECURE_SRTP_PLUGIN_DIR);
  if (!plugin.ok()) {
    return PrintError(plugin.error());
  }

  camera_firmware::media::SnapshotTap snapshot_tap;
  camera_firmware::ai::AiFrameTap ai_frame_tap;
  camera_firmware::media::EncodedRing encoded_ring(64);
  camera_firmware::media::CameraPipeline camera_pipeline(
      snapshot_tap, ai_frame_tap, encoded_ring);
  auto camera_validation = camera_pipeline.ValidateConfigOnly(cfg.value());
  if (!camera_validation.ok()) {
    return PrintError(camera_validation.error());
  }

  auto secure_files = camera_firmware::rtsp::ValidateSecureRtspConfigFiles(
      cfg.value().secure_rtsp);
  if (!secure_files.ok()) {
    return PrintError(secure_files.error());
  }
  auto http_tls = camera_firmware::service::ValidateHttpTlsConfigFiles(
      cfg.value().http, crypto_provider);
  if (!http_tls.ok()) {
    return PrintError(http_tls.error());
  }

  if (cfg.value().secure_rtsp.media_srtp) {
    auto secure_media = camera_firmware::rtsp::VerifySecureMediaPath();
    if (!secure_media.ok()) {
      return PrintError(secure_media.error());
    }
  }

  camera_firmware::ai::DetectionBus detection_bus;
  camera_firmware::ai::AiRuntime ai_runtime(&detection_bus);
  auto ai_started = ai_runtime.Start(cfg.value());
  if (!ai_started.ok()) {
    return PrintError(ai_started.error());
  }
  const auto ai_status = ai_runtime.Status();
  ai_runtime.Stop();

  Logger::instance().log(Logger::Level::kInfo,
                         "config loaded: " + config_path);
  Logger::instance().log(
      Logger::Level::kInfo,
      "RTSP ready: " +
          camera_firmware::rtsp::BuildRtspUrl(cfg.value().secure_rtsp));
  const std::string http_scheme =
      cfg.value().http.tls.enabled ? "https" : "http";
  Logger::instance().log(
      Logger::Level::kInfo,
      "Drogon service config ready on " + http_scheme + "://" +
          cfg.value().http.bind_ip + ":" +
          std::to_string(cfg.value().http.port));
  Logger::instance().log(
      Logger::Level::kInfo,
      ai_status.enabled ? "AI backend " + ai_status.backend +
                              " configured; runtime skeleton state=" +
                              ai_status.state
                        : "AI disabled by config");
  return EXIT_SUCCESS;
}

std::vector<camera_firmware::service::CameraStatus> ToServiceStatus(
    const std::vector<camera_firmware::media::CameraPipelineStatus>& statuses) {
  std::vector<camera_firmware::service::CameraStatus> result;
  result.reserve(statuses.size());
  for (const auto& status : statuses) {
    camera_firmware::service::CameraStatus service_status;
    service_status.id = status.id;
    service_status.state = status.state;
    service_status.snapshot_available = status.snapshot_available;
    service_status.width = status.width;
    service_status.height = status.height;
    service_status.configured_fps = status.configured_fps;
    service_status.capture_fps = status.capture_fps;
    service_status.encoded_fps = status.encoded_fps;
    service_status.captured_frames = status.captured_frames;
    service_status.encoded_frames = status.encoded_frames;
    service_status.capture_error_count = status.capture_error_count;
    service_status.encode_error_count = status.encode_error_count;
    result.push_back(std::move(service_status));
  }
  return result;
}

camera_firmware::service::AiServiceStatus ToServiceAiStatus(
    const camera_firmware::ai::AiRuntimeStatus& status,
    const std::vector<camera_firmware::config::AiModelConfig>& models,
    const std::vector<camera_firmware::ai::AiModelRunnerStatus>& runners) {
  camera_firmware::service::AiServiceStatus service_status;
  service_status.enabled = status.enabled;
  service_status.backend = status.backend;
  service_status.state = status.state;
  service_status.model_count = status.model_count;
  service_status.runner_count = status.runner_count;
  service_status.models.reserve(models.size());
  for (const auto& model : models) {
    camera_firmware::service::AiModelServiceStatus model_status;
    model_status.id = model.id;
    model_status.kind = model.kind;
    model_status.input_width = model.input.width;
    model_status.input_height = model.input.height;
    model_status.input_format = model.input.format;
    model_status.letterbox = model.input.letterbox;
    model_status.output_name = model.output_name;
    model_status.confidence_threshold = model.confidence_threshold;
    model_status.labels = model.labels;
    service_status.models.push_back(std::move(model_status));
  }
  service_status.runners.reserve(runners.size());
  for (const auto& runner : runners) {
    camera_firmware::service::AiRunnerServiceStatus runner_status;
    runner_status.camera_id = runner.camera_id;
    runner_status.model_id = runner.model_id;
    runner_status.model_kind = runner.model_kind;
    runner_status.submitted_frames = runner.submitted_frames;
    runner_status.processed_frames = runner.processed_frames;
    runner_status.dropped_frames = runner.dropped_frames;
    runner_status.last_preprocess_ms = runner.last_preprocess_ms;
    runner_status.last_inference_ms = runner.last_inference_ms;
    runner_status.last_processed_sequence = runner.last_processed_sequence;
    runner_status.last_error_code = runner.last_error_code;
    runner_status.last_error_message = runner.last_error_message;
    service_status.runners.push_back(std::move(runner_status));
  }
  if (!status.last_error_message.empty()) {
    service_status.reason = status.last_error_message;
  } else if (!status.enabled) {
    service_status.reason = "disabled by config";
  } else {
    service_status.reason = "AI runtime ready";
  }
  return service_status;
}

camera_firmware::common::Result<
    std::shared_ptr<camera_firmware::runtime::FirmwareRuntime>>
CreateProductionRuntime(const camera_firmware::config::AppConfig& config) {
  try {
    return camera_firmware::common::Result<
        std::shared_ptr<camera_firmware::runtime::FirmwareRuntime>>::Ok(
        std::make_shared<camera_firmware::runtime::FirmwareRuntime>(config));
  } catch (...) {
    return camera_firmware::common::Result<
        std::shared_ptr<camera_firmware::runtime::FirmwareRuntime>>::Err(
        {"E_RUNTIME_FACTORY", "firmware runtime graph construction failed"});
  }
}

camera_firmware::common::Result<void> ValidateRuntimeCandidate(
    const camera_firmware::config::AppConfig& config) {
  return camera_firmware::runtime::FirmwareRuntime::ValidateCandidateConfig(
      config);
}

int RunFirmware(const std::string& config_path) {
  auto cfg = camera_firmware::config::LoadConfigFile(config_path);
  if (!cfg.ok()) {
    return PrintError(cfg.error());
  }

  // The crypto provider must be constructed and proven (via SelfTest) before
  // any subsystem that could perform a cryptographic operation is created —
  // in particular before the security store is opened and before integrity
  // verification (the boot trust root) runs. No cryptographic operation may
  // execute against an unproven provider.
  camera_firmware::crypto::OpenSslCryptoProvider crypto_provider;
  auto crypto_self_test = crypto_provider.SelfTest();
  bool crypto_self_test_failed =
      !crypto_self_test.ok() || !crypto_self_test.value().passed;
#if defined(CAMERA_FIRMWARE_TEST_CRYPTO_SELF_TEST_HOOK)
  if (ForceCryptoSelfTestFailureForTesting()) {
    crypto_self_test_failed = true;
  }
#endif
  if (crypto_self_test_failed) {
    return PrintError({"E_CRYPTO_UNAVAILABLE",
                       "cryptographic provider self-test failed"});
  }

  auto plugin = camera_firmware::rtsp::RegisterBuildTreeSecureSrtpPluginPath(
      CF_SECURE_SRTP_PLUGIN_DIR);
  if (!plugin.ok()) {
    return PrintError(plugin.error());
  }

  const auto& base_config = cfg.value();
  camera_firmware::config::AppConfig initial_config = base_config;

  std::shared_ptr<camera_firmware::security::SecurityStore> security_store;
  std::unique_ptr<camera_firmware::security::AuditLogService>
      audit_log_service;
  std::optional<camera_firmware::security::ResolvedTlsMaterial> tls_material;
  std::unique_ptr<camera_firmware::security::SystemProtectionService>
      system_protection;
  std::unique_ptr<camera_firmware::settings::RuntimeSettingsStore>
      runtime_settings_store;
  std::optional<camera_firmware::settings::CameraProfileCatalog>
      runtime_profiles;
  if (base_config.security.enabled) {
    auto opened = camera_firmware::security::SecurityStore::Open(
        {base_config.security.state_directory,
         base_config.security.audit.max_events,
         base_config.security.audit.warning_percent});
    if (!opened.ok()) {
      return PrintError(opened.error());
    }
    security_store =
        std::shared_ptr<camera_firmware::security::SecurityStore>(
            std::move(opened).value());

    audit_log_service =
        std::make_unique<camera_firmware::security::AuditLogService>(
            *security_store);
    if (base_config.http.tls.enabled) {
      auto resolved = camera_firmware::security::ResolveTlsMaterial(
          base_config.http.tls, base_config.security.state_directory,
          crypto_provider);
      if (!resolved.ok()) {
        return PrintError(resolved.error());
      }
      tls_material = std::move(resolved).value();
    }

    camera_firmware::security::SecuritySelfTestDependencies self_test;
    self_test.provider = &crypto_provider;
    self_test.database_check = [security_store] {
      return security_store->CheckHealth();
    };
    self_test.tls_identity_check = [tls_material] {
      if (!tls_material) {
        return camera_firmware::common::Result<void>::Err(
            {"E_PROTECTION_TLS", "TLS identity is unavailable"});
      }
      return camera_firmware::security::CheckTlsMaterialHealth(
          *tls_material, std::chrono::system_clock::now());
    };
    self_test.audit_append_check =
        [audit_log_service = audit_log_service.get()] {
          return audit_log_service->AppendSystemEvent(
              "self_test.audit_append", "success", "PROTECTION_STARTUP");
        };
    std::error_code path_error;
    const auto active_executable =
        std::filesystem::canonical("/proc/self/exe", path_error);
    if (path_error) {
      return PrintError({"E_PROTECTION_INTEGRITY",
                         "integrity process identity is unavailable"});
    }
    const auto active_config =
        std::filesystem::absolute(config_path, path_error).lexically_normal();
    if (path_error) {
      return PrintError({"E_PROTECTION_INTEGRITY",
                         "integrity configuration identity is unavailable"});
    }
    camera_firmware::security::SystemProtectionDependencies
        protection_dependencies;
    protection_dependencies.run_self_tests = [self_test] {
      return camera_firmware::security::RunSecuritySelfTests(self_test);
    };
    protection_dependencies.run_integrity =
        [manifest_path = base_config.self_protection.manifest_path,
         signature_path = base_config.self_protection.signature_path,
         active_executable, active_config,
         public_key_pem = IntegrityPublicKeyPem(), &crypto_provider] {
      return camera_firmware::integrity::VerifyIntegrityManifest(
          manifest_path, signature_path, public_key_pem,
          active_executable, active_config, crypto_provider);
    };
    protection_dependencies.append_system_audit_record =
        [audit_log_service = audit_log_service.get()](
            const camera_firmware::security::ProtectionAuditRecord& record) {
          return audit_log_service->AppendSystemEvent(
              record.event_type, record.outcome, record.detail_code,
              camera_firmware::security::ProtectionAuditSubjectType(record),
              camera_firmware::security::ProtectionAuditSubjectIdentity(
                  record));
        };
    protection_dependencies.append_administrator_audit_record =
        [audit_log_service = audit_log_service.get()](
            const camera_firmware::security::ProtectionActor& actor,
            const camera_firmware::security::ProtectionAuditRecord& record) {
          camera_firmware::security::Principal principal;
          principal.user_id = actor.user_id.value_or(0);
          principal.username = actor.username;
          principal.role =
              camera_firmware::security::UserRole::kAdministrator;
          return audit_log_service->AppendAdministratorEvent(
              principal, actor.peer_ip, record.event_type, record.outcome,
              record.detail_code,
              camera_firmware::security::ProtectionAuditSubjectType(record),
              camera_firmware::security::ProtectionAuditSubjectIdentity(
                  record));
        };
    protection_dependencies.read_device_state = [security_store] {
      return security_store->State();
    };
    protection_dependencies.automatic_interval =
        std::chrono::hours(base_config.self_protection.interval_hours);
    system_protection =
        std::make_unique<camera_firmware::security::SystemProtectionService>(
            std::move(protection_dependencies));

    runtime_profiles.emplace(
        camera_firmware::settings::CameraProfileCatalog::Rpi5Imx708());
    auto base_active = camera_firmware::settings::DeriveRuntimeSettings(
        base_config, *runtime_profiles);
    if (!base_active.ok()) {
      return PrintError(base_active.error());
    }
    auto settings_opened =
        camera_firmware::settings::RuntimeSettingsStore::Open(
            base_config.security.state_directory,
            std::move(base_active).value(), base_config, *runtime_profiles);
    if (!settings_opened.ok()) {
      return PrintError(settings_opened.error());
    }
    runtime_settings_store = std::move(settings_opened).value();

    auto effective = camera_firmware::settings::BuildEffectiveConfig(
        base_config, runtime_settings_store->Snapshot().active,
        *runtime_profiles);
    if (!effective.ok()) {
      return PrintError(effective.error());
    }
    initial_config = std::move(effective).value();
  }

  auto runtime =
      std::make_unique<camera_firmware::runtime::ManagedFirmwareRuntime>(
          initial_config, CreateProductionRuntime);
  std::unique_ptr<camera_firmware::settings::RuntimeSettingsService>
      runtime_settings;
  if (runtime_settings_store) {
    runtime_settings =
        std::make_unique<camera_firmware::settings::RuntimeSettingsService>(
            base_config, std::move(*runtime_profiles),
            *runtime_settings_store, *runtime, ValidateRuntimeCandidate);
  }

  camera_firmware::service::ServiceApp service;

  camera_firmware::service::ServiceInitArgs service_args;
  service_args.app_config = &base_config;
  // Threaded unconditionally (not only inside `if (security_store)` below):
  // ServiceApp can need to resolve TLS material (SelectServiceTlsMaterial)
  // whenever HTTP TLS is enabled, regardless of whether security/the
  // security store is enabled, and it must always be the one provider
  // main.cpp constructed and self-tested above, never one of its own.
  service_args.provider = &crypto_provider;
  service_args.bind_address = base_config.http.bind_ip;
  service_args.port = base_config.http.port;
  service_args.document_root = base_config.http.web_root;
  service_args.public_base_url = base_config.http.public_base_url;
  service_args.camera_status_provider = [&runtime] {
    return ToServiceStatus(runtime->CameraStatuses());
  };
  service_args.ai_enabled = initial_config.ai.enabled;
  service_args.ai_status_provider = [&runtime] {
    return ToServiceAiStatus(runtime->AiStatus(),
                             runtime->ActiveConfig().ai.models,
                             runtime->AiRunnerStatuses());
  };
  service_args.ai_restart_callback = [&runtime] {
    return runtime->RestartAi();
  };
  service_args.secure_stream_diagnostics_provider = [&runtime] {
    camera_firmware::service::SecureStreamDiagnostics diagnostics;
    diagnostics.per_media_key_zeroize_count =
        runtime->PerMediaKeyZeroizeCount();
    return diagnostics;
  };
  service_args.detection_snapshot_provider = [&runtime] {
    return runtime->DetectionSnapshot();
  };
  service_args.detection_event_subscriber =
      [&runtime](camera_firmware::ai::DetectionBus::Handler handler) {
        return runtime->SubscribeDetections(std::move(handler));
      };
  service_args.snapshot_callback =
      [&runtime](const std::string& camera_id) {
        return runtime->Snapshot(camera_id);
      };
  service_args.cancellable_live_stream_callback =
      [&runtime](
          const std::string& camera_id)
          -> camera_firmware::common::Result<
              camera_firmware::service::LiveMp4StreamHandle> {
        auto opened = runtime->OpenLiveStream(camera_id);
        if (!opened.ok()) {
          return camera_firmware::common::Result<
              camera_firmware::service::LiveMp4StreamHandle>::Err(
              opened.error());
        }
        const auto stale_timeout = std::chrono::milliseconds(
            runtime->ActiveConfig().http.live.stale_timeout_ms);
        auto state = std::make_shared<LiveMp4ByteStream>(
            std::move(opened).value(), stale_timeout);
        camera_firmware::service::LiveMp4StreamHandle stream{
            .read = [state](char* output, std::size_t capacity) {
              return state->Read(output, capacity);
            },
            .cancel = [state] { state->Cancel(); },
        };
        return camera_firmware::common::Result<
            camera_firmware::service::LiveMp4StreamHandle>::Ok(
            std::move(stream));
      };

  if (security_store) {
    service_args.security_store = security_store;
    service_args.tls_material = tls_material;
    service_args.auth_service_dependencies_provider = [&crypto_provider] {
      camera_firmware::security::AuthServiceDependencies auth_dependencies;
      auth_dependencies.provider = &crypto_provider;
      return auth_dependencies;
    };
    service_args.protection_snapshot_callback = [system_protection_ptr =
                                                     system_protection.get()] {
      return system_protection_ptr->Snapshot();
    };
    service_args.protection_start_check_callback =
        [system_protection_ptr = system_protection.get()](
            camera_firmware::security::ProtectionSuite suite,
            camera_firmware::security::ProtectionActor actor) {
          return system_protection_ptr->StartManualCheck(suite,
                                                         std::move(actor));
        };
    service_args.protection_runtime_allowed_callback =
        [system_protection_ptr = system_protection.get()] {
          return system_protection_ptr->RuntimeAllowed();
        };
    service_args.protection_runtime_control_gate =
        [system_protection_ptr = system_protection.get()](
            const std::function<void()>& command) {
          return system_protection_ptr->RunRuntimeControlIfAllowed(command);
        };
  }
  if (runtime_settings) {
    service_args.runtime_settings_snapshot_callback = [&runtime_settings] {
      return runtime_settings->Snapshot();
    };
    service_args.runtime_settings_save_callback =
        [&runtime_settings](
            std::uint64_t expected_revision,
            camera_firmware::settings::RuntimeSettings settings) {
          return runtime_settings->Save(expected_revision,
                                        std::move(settings));
        };
    service_args.runtime_settings_apply_callback =
        [&runtime_settings](std::uint64_t expected_revision) {
          return runtime_settings->Apply(expected_revision);
        };
    service_args.runtime_settings_discard_callback =
        [&runtime_settings](std::uint64_t expected_revision) {
          return runtime_settings->Discard(expected_revision);
        };
  }

  camera_firmware::boot::FirmwareBootDependencies boot_dependencies;
  if (security_store) {
    boot_dependencies.read_device_state = [security_store] {
      return security_store->State();
    };
    boot_dependencies.run_startup_protection_checks =
        [system_protection_ptr = system_protection.get()] {
          (void)system_protection_ptr->RunStartupChecks();
        };
    boot_dependencies.protection_allows_runtime =
        [system_protection_ptr = system_protection.get()] {
          return system_protection_ptr->RuntimeAllowed();
        };
  }
  boot_dependencies.start_runtime = [&runtime] { return runtime->Start(); };
  boot_dependencies.stop_runtime = [&runtime] { runtime->Stop(); };
  boot_dependencies.start_service =
      [&service, &service_args](
          camera_firmware::boot::RuntimeStartCallback start_runtime) {
        service_args.runtime_start_callback = std::move(start_runtime);
        return service.Init(service_args);
      };
  boot_dependencies.quiesce_service = [&service] {
    service.BeginShutdown();
  };
  boot_dependencies.stop_service = [&service] { service.Stop(); };

  camera_firmware::boot::FirmwareBootCoordinator boot_coordinator(
      {base_config.security.enabled, base_config.http.enabled},
      std::move(boot_dependencies));
  if (system_protection) {
    system_protection->SetRuntimeCallbacks(
        {.start = [&boot_coordinator] {
#if defined(CAMERA_FIRMWARE_TEST_PROTECTION_RUNTIME_PROBE)
           SignalProtectionRuntimeStartForTesting();
#endif
           return boot_coordinator.StartRuntimeAfterBootstrap();
         },
         .stop = [&boot_coordinator] {
           boot_coordinator.StopRuntimeForProtection();
         }});
  }
  auto boot_started = boot_coordinator.Start();
  if (!boot_started.ok()) {
    if (system_protection) {
      system_protection->Stop();
    }
    boot_coordinator.Stop();
    return PrintError(boot_started.error());
  }

  Logger::instance().log(Logger::Level::kInfo, "camera firmware running");
  WaitForShutdown();

  if (system_protection) {
    system_protection->Stop();
  }
  boot_coordinator.Stop();
  return EXIT_SUCCESS;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 3 && std::string(argv[1]) == "--validate-config") {
    return ValidateConfig(argv[2]);
  }
  if (argc == 2) {
    InstallSignalHandlers();
    return RunFirmware(argv[1]);
  }

  std::cerr << "usage: camera-firmware [--validate-config] <config.yaml>\n";
  return EXIT_FAILURE;
}
