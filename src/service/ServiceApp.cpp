#include "camera_firmware/service/ServiceApp.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <gio/gio.h>
#include <json/writer.h>

#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/service/ServiceStartup.hpp"

namespace camera_firmware::service {
namespace {

struct ServiceState {
  ServiceInitArgs args;
};

constexpr std::chrono::milliseconds kServiceThreadStopTimeout{2000};
constexpr std::chrono::seconds kDetectionSsePendingTimeout{15};
constexpr std::uint32_t kDetectionSseReconnectMs{1000};

ServiceState& GlobalState() {
  static ServiceState state;
  return state;
}

std::mutex& StateMutex() {
  static std::mutex mutex;
  return mutex;
}

std::string ExtractPublicHost(std::string_view public_base_url) {
  std::string_view authority = public_base_url;
  if (const std::size_t scheme_pos = authority.find("://");
      scheme_pos != std::string_view::npos) {
    authority.remove_prefix(scheme_pos + 3);
  }

  const std::size_t path_pos = authority.find_first_of("/?#");
  if (path_pos != std::string_view::npos) {
    authority = authority.substr(0, path_pos);
  }

  if (authority.empty()) {
    return "127.0.0.1";
  }

  if (const std::size_t at_pos = authority.rfind('@');
      at_pos != std::string_view::npos) {
    authority.remove_prefix(at_pos + 1);
  }

  if (authority.front() == '[') {
    const std::size_t bracket_pos = authority.find(']');
    if (bracket_pos != std::string_view::npos) {
      return std::string(authority.substr(0, bracket_pos + 1));
    }
    return std::string(authority);
  }

  const std::size_t port_pos = authority.find(':');
  if (port_pos != std::string_view::npos) {
    authority = authority.substr(0, port_pos);
  }

  if (authority.empty()) {
    return "127.0.0.1";
  }
  return std::string(authority);
}

std::string BuildRtspUrl(std::string_view public_base_url,
                         const config::SecureRtspConfig& secure_rtsp) {
  const std::string scheme = secure_rtsp.control_tls ? "rtsps" : "rtsp";
  return scheme + "://" + ExtractPublicHost(public_base_url) + ":" +
         std::to_string(secure_rtsp.port) + secure_rtsp.mount;
}

Json::Value BuildCameraJson(const CameraStatus& camera) {
  Json::Value json(Json::objectValue);
  json["id"] = camera.id;
  json["state"] = camera.state;
  json["snapshot_available"] = camera.snapshot_available;
  return json;
}

Json::Value BuildSnapshotUnavailableJson() {
  Json::Value json(Json::objectValue);
  json["code"] = "E_NO_SNAPSHOT";
  json["message"] = "snapshot unavailable";
  return json;
}

Json::Value BuildSecureMediaJson(
    const config::SecureRtspConfig& secure_rtsp) {
  Json::Value json(Json::objectValue);
  json["control_scheme"] = secure_rtsp.control_tls ? "rtsps" : "rtsp";
  json["media_profile"] = secure_rtsp.media_srtp ? "RTP/SAVPF" : "RTP/AVP";
  json["keying"] =
      secure_rtsp.media_srtp && secure_rtsp.keying == "sdes-over-rtsps"
          ? "SDES-over-RTSPS"
          : "none";
  json["requires_tls_control_channel"] =
      secure_rtsp.media_srtp && secure_rtsp.keying == "sdes-over-rtsps";
  return json;
}

drogon::HttpResponsePtr JsonResponse(Json::Value json,
                                     drogon::HttpStatusCode status =
                                         drogon::k200OK) {
  auto response = drogon::HttpResponse::newHttpJsonResponse(std::move(json));
  response->setStatusCode(status);
  return response;
}

std::string CompactJson(Json::Value json) {
  Json::StreamWriterBuilder writer;
  writer["indentation"] = "";
  return Json::writeString(writer, json);
}

class DetectionSsePendingResponse {
 public:
  using ResponseCallback =
      std::function<void(const drogon::HttpResponsePtr&)>;

  DetectionSsePendingResponse(
      DetectionSnapshotProvider detection_snapshot_provider,
      ResponseCallback response_callback)
      : detection_snapshot_provider_(
            std::move(detection_snapshot_provider)),
        response_callback_(std::move(response_callback)) {}

  DetectionSsePendingResponse(const DetectionSsePendingResponse&) = delete;
  DetectionSsePendingResponse& operator=(
      const DetectionSsePendingResponse&) = delete;

  void SetSubscription(ai::DetectionBus::Subscription subscription) {
    std::lock_guard lock(mutex_);
    if (!completed_) {
      subscription_ = std::move(subscription);
    }
  }

  void CompleteWithEvent(const ai::DetectionEvent& event) {
    Complete(MergeDetectionSnapshotWithEvent(Snapshot(), event));
  }

  void CompleteWithSnapshot() {
    Complete(Snapshot());
  }

 private:
  std::vector<ai::DetectionEvent> Snapshot() const {
    if (detection_snapshot_provider_) {
      return detection_snapshot_provider_();
    }
    return {};
  }

  void Complete(std::vector<ai::DetectionEvent> events) {
    ResponseCallback callback;
    ai::DetectionBus::Subscription subscription;
    {
      std::lock_guard lock(mutex_);
      if (completed_) {
        return;
      }
      completed_ = true;
      callback = std::move(response_callback_);
      subscription = std::move(subscription_);
    }
    if (callback) {
      auto response = BuildDetectionSseResponse(events);
      drogon::app().getLoop()->queueInLoop(
          [callback = std::move(callback),
           response = std::move(response)]() mutable {
            callback(response);
          });
    }
  }

  DetectionSnapshotProvider detection_snapshot_provider_;
  mutable std::mutex mutex_;
  ResponseCallback response_callback_;
  ai::DetectionBus::Subscription subscription_;
  bool completed_{false};
};

class ThreadCompletionReporter {
 public:
  explicit ThreadCompletionReporter(
      std::shared_ptr<std::promise<void>> completion)
      : completion_(std::move(completion)) {}

  ~ThreadCompletionReporter() noexcept {
    if (!completion_) {
      return;
    }
    try {
      completion_->set_value();
    } catch (...) {
    }
  }

 private:
  std::shared_ptr<std::promise<void>> completion_;
};

void RegisterHandlers() {
  using namespace drogon;

  app().registerHandler(
      "/api/v1/health",
      [](const HttpRequestPtr&,
         std::function<void(const HttpResponsePtr&)>&& callback) {
        std::string status;
        {
          std::scoped_lock lock(StateMutex());
          status = GlobalState().args.health_status;
        }
        callback(JsonResponse(BuildHealthJson(status)));
      },
      {Get});

  app().registerHandler(
      "/api/v1/cameras",
      [](const HttpRequestPtr&,
         std::function<void(const HttpResponsePtr&)>&& callback) {
        Json::Value body(Json::objectValue);
        Json::Value cameras(Json::arrayValue);
        CameraStatusProvider provider;
        AiStatusProvider ai_status_provider;
        bool ai_enabled = false;

        {
          std::scoped_lock lock(StateMutex());
          provider = GlobalState().args.camera_status_provider;
          ai_status_provider = GlobalState().args.ai_status_provider;
          ai_enabled = GlobalState().args.ai_enabled;
        }

        if (provider) {
          for (const auto& camera : provider()) {
            cameras.append(BuildCameraJson(camera));
          }
        }
        body["cameras"] = std::move(cameras);
        body["ai"] = ai_status_provider
                         ? BuildAiStatusJson(ai_status_provider())
                         : BuildAiStatusJson(ai_enabled);
        callback(JsonResponse(std::move(body)));
      },
      {Get});

  app().registerHandler(
      "/api/v1/cameras/{1}/snapshot.jpg",
      [](const HttpRequestPtr&,
         std::function<void(const HttpResponsePtr&)>&& callback,
         const std::string& camera_id) {
        SnapshotCallback snapshot_callback;
        {
          std::scoped_lock lock(StateMutex());
          snapshot_callback = GlobalState().args.snapshot_callback;
        }
        if (!snapshot_callback) {
          callback(JsonResponse(BuildSnapshotUnavailableJson(),
                                drogon::k503ServiceUnavailable));
          return;
        }

        callback(BuildSnapshotResponse(snapshot_callback, camera_id));
      },
      {Get});

  app().registerHandler(
      "/api/v1/ai/detections",
      [](const HttpRequestPtr&,
         std::function<void(const HttpResponsePtr&)>&& callback) {
        DetectionSnapshotProvider detection_snapshot_provider;
        {
          std::scoped_lock lock(StateMutex());
          detection_snapshot_provider =
              GlobalState().args.detection_snapshot_provider;
        }
        callback(BuildDetectionSnapshotResponse(detection_snapshot_provider));
      },
      {Get});

  app().registerHandler(
      "/api/v1/ai/restart",
      [](const HttpRequestPtr&,
         std::function<void(const HttpResponsePtr&)>&& callback) {
        AiControlCallback restart_callback;
        AiStatusProvider ai_status_provider;
        {
          std::scoped_lock lock(StateMutex());
          restart_callback = GlobalState().args.ai_restart_callback;
          ai_status_provider = GlobalState().args.ai_status_provider;
        }
        callback(BuildAiRestartResponse(restart_callback, ai_status_provider));
      },
      {Post});

  app().registerHandler(
      "/api/v1/ai/detections/stream",
      [](const HttpRequestPtr& request,
         std::function<void(const HttpResponsePtr&)>&& callback) {
        DetectionSnapshotProvider detection_snapshot_provider;
        DetectionEventSubscriber detection_event_subscriber;
        {
          std::scoped_lock lock(StateMutex());
          detection_snapshot_provider =
              GlobalState().args.detection_snapshot_provider;
          detection_event_subscriber =
              GlobalState().args.detection_event_subscriber;
        }
        const std::string last_event_id =
            request ? request->getHeader("Last-Event-ID") : "";
        DetectionSnapshotProvider snapshot_provider_for_check =
            detection_snapshot_provider;
        auto pending = std::make_shared<DetectionSsePendingResponse>(
            std::move(detection_snapshot_provider),
            std::move(callback));
        if (!detection_event_subscriber) {
          pending->CompleteWithSnapshot();
          return;
        }

        pending->SetSubscription(detection_event_subscriber(
            [pending](const ai::DetectionEvent& event) {
              pending->CompleteWithEvent(event);
            }));
        if (snapshot_provider_for_check) {
          const auto snapshot = snapshot_provider_for_check();
          const auto snapshot_id = BuildDetectionSseId(snapshot);
          if (last_event_id.empty() || last_event_id != snapshot_id) {
            pending->CompleteWithSnapshot();
            return;
          }
        }
        app().getLoop()->runAfter(kDetectionSsePendingTimeout, [pending] {
          pending->CompleteWithSnapshot();
        });
      },
      {Get});

  app().registerHandler(
      "/api/v1/stream",
      [](const HttpRequestPtr&,
         std::function<void(const HttpResponsePtr&)>&& callback) {
        const config::AppConfig* config = nullptr;
        std::string public_base_url;
        SecureStreamDiagnosticsProvider secure_stream_diagnostics_provider;
        {
          std::scoped_lock lock(StateMutex());
          config = GlobalState().args.app_config;
          public_base_url = GlobalState().args.public_base_url;
          secure_stream_diagnostics_provider =
              GlobalState().args.secure_stream_diagnostics_provider;
        }
        if (config == nullptr) {
          Json::Value body(Json::objectValue);
          body["code"] = "E_CONFIG";
          body["message"] = "service config unavailable";
          callback(JsonResponse(std::move(body), drogon::k500InternalServerError));
          return;
        }

        std::optional<SecureStreamDiagnostics> diagnostics;
        if (secure_stream_diagnostics_provider) {
          diagnostics = secure_stream_diagnostics_provider();
        }
        callback(JsonResponse(
            BuildStreamJson(public_base_url, config->secure_rtsp, diagnostics)));
      },
      {Get});
}

}  // namespace

namespace internal {

common::Result<void> StopServiceThreadWithin(
    std::thread& service_thread,
    const std::shared_future<void>& service_thread_done,
    std::chrono::milliseconds timeout,
    const std::function<void()>& request_stop) {
  if (request_stop) {
    request_stop();
  }
  if (!service_thread.joinable()) {
    return common::Result<void>::Ok();
  }
  if (service_thread_done.valid() &&
      service_thread_done.wait_for(timeout) == std::future_status::ready) {
    service_thread.join();
    return common::Result<void>::Ok();
  }

  service_thread.detach();
  return common::Result<void>::Err(
      {"E_SERVICE_THREAD_STOP_TIMEOUT",
       "service thread stop timed out; detached Drogon service thread"});
}

}  // namespace internal

Json::Value BuildHealthJson(const std::string& status) {
  Json::Value json(Json::objectValue);
  json["status"] = status;
  return json;
}

Json::Value BuildAiStatusJson(const AiServiceStatus& status) {
  Json::Value json(Json::objectValue);
  json["enabled"] = status.enabled;
  json["backend"] = status.backend;
  json["state"] = status.state;
  json["model_count"] = static_cast<Json::UInt64>(status.model_count);
  json["runner_count"] = static_cast<Json::UInt64>(status.runner_count);
  json["reason"] = status.reason;

  Json::Value runners(Json::arrayValue);
  for (const auto& runner : status.runners) {
    Json::Value runner_json(Json::objectValue);
    runner_json["camera_id"] = runner.camera_id;
    runner_json["model_id"] = runner.model_id;
    runner_json["model_kind"] = runner.model_kind;
    runner_json["submitted_frames"] =
        static_cast<Json::UInt64>(runner.submitted_frames);
    runner_json["processed_frames"] =
        static_cast<Json::UInt64>(runner.processed_frames);
    runner_json["dropped_frames"] =
        static_cast<Json::UInt64>(runner.dropped_frames);
    runner_json["last_error_code"] = runner.last_error_code;
    runner_json["last_error_message"] = runner.last_error_message;
    runners.append(std::move(runner_json));
  }
  json["runners"] = std::move(runners);
  return json;
}

Json::Value BuildAiStatusJson(bool requested) {
  AiServiceStatus status;
  if (requested) {
    status.enabled = true;
    status.backend = "hailo";
    status.state = "backend_unavailable";
    status.reason = "Hailo backend is not implemented in this build";
  }
  return BuildAiStatusJson(status);
}

drogon::HttpResponsePtr BuildAiRestartResponse(
    const AiControlCallback& restart_callback,
    const AiStatusProvider& ai_status_provider) {
  if (!restart_callback) {
    Json::Value body(Json::objectValue);
    body["code"] = "E_AI_CONTROL_UNAVAILABLE";
    body["message"] = "AI restart control is unavailable";
    return JsonResponse(std::move(body), drogon::k503ServiceUnavailable);
  }

  auto restarted = restart_callback();
  if (!restarted.ok()) {
    Json::Value body(Json::objectValue);
    body["code"] = restarted.error().code;
    body["message"] = restarted.error().message;
    return JsonResponse(std::move(body), drogon::k500InternalServerError);
  }

  Json::Value body(Json::objectValue);
  body["status"] = "restarted";
  if (ai_status_provider) {
    body["ai"] = BuildAiStatusJson(ai_status_provider());
  }
  return JsonResponse(std::move(body));
}

Json::Value BuildDetectionEventJson(const ai::DetectionEvent& event) {
  Json::Value json(Json::objectValue);
  json["camera_id"] = event.camera_id;
  json["model_id"] = event.model_id;
  json["model_kind"] = event.model_kind;
  json["result_state"] = event.result_state;
  json["frame_sequence"] =
      static_cast<Json::UInt64>(event.frame_sequence);

  Json::Value detections(Json::arrayValue);
  for (const auto& detection : event.detections) {
    Json::Value detection_json(Json::objectValue);
    detection_json["label"] = detection.label;
    detection_json["confidence"] = detection.confidence;

    Json::Value box(Json::objectValue);
    box["x"] = detection.box.x;
    box["y"] = detection.box.y;
    box["width"] = detection.box.width;
    box["height"] = detection.box.height;
    detection_json["box"] = std::move(box);

    detections.append(std::move(detection_json));
  }
  json["detections"] = std::move(detections);
  return json;
}

Json::Value BuildDetectionSnapshotJson(
    const std::vector<ai::DetectionEvent>& events) {
  Json::Value json(Json::objectValue);
  Json::Value event_array(Json::arrayValue);
  for (const auto& event : events) {
    event_array.append(BuildDetectionEventJson(event));
  }
  json["events"] = std::move(event_array);
  return json;
}

drogon::HttpResponsePtr BuildDetectionSnapshotResponse(
    const DetectionSnapshotProvider& detection_snapshot_provider) {
  std::vector<ai::DetectionEvent> events;
  if (detection_snapshot_provider) {
    events = detection_snapshot_provider();
  }
  return JsonResponse(BuildDetectionSnapshotJson(events));
}

std::string BuildDetectionSseEvent(
    const std::vector<ai::DetectionEvent>& events) {
  return "id: " + BuildDetectionSseId(events) +
         "\nretry: " + std::to_string(kDetectionSseReconnectMs) +
         "\nevent: detections\ndata: " +
         CompactJson(BuildDetectionSnapshotJson(events)) + "\n\n";
}

std::string BuildDetectionSseId(
    const std::vector<ai::DetectionEvent>& events) {
  if (events.empty()) {
    return "empty";
  }

  std::vector<std::string> parts;
  parts.reserve(events.size());
  for (const auto& event : events) {
    parts.push_back(event.camera_id + "/" + event.model_id + "/" +
                    std::to_string(event.frame_sequence) + "/" +
                    event.result_state);
  }
  std::sort(parts.begin(), parts.end());

  std::string id;
  for (const auto& part : parts) {
    if (!id.empty()) {
      id += "|";
    }
    id += part;
  }
  return id;
}

std::vector<ai::DetectionEvent> MergeDetectionSnapshotWithEvent(
    std::vector<ai::DetectionEvent> events,
    const ai::DetectionEvent& event) {
  const auto same_binding = [&event](const ai::DetectionEvent& stored) {
    return stored.camera_id == event.camera_id &&
           stored.model_id == event.model_id;
  };
  const auto existing =
      std::find_if(events.begin(), events.end(), same_binding);
  if (existing != events.end()) {
    *existing = event;
  } else {
    events.push_back(event);
  }
  return events;
}

drogon::HttpResponsePtr BuildDetectionSseResponse(
    const std::vector<ai::DetectionEvent>& events) {
  auto response = drogon::HttpResponse::newHttpResponse();
  response->setStatusCode(drogon::k200OK);
  response->setContentTypeCodeAndCustomString(drogon::CT_CUSTOM,
                                              "text/event-stream");
  response->addHeader("Cache-Control", "no-cache");
  response->addHeader("X-Accel-Buffering", "no");
  response->setBody(BuildDetectionSseEvent(events));
  return response;
}

Json::Value BuildStreamJson(
    std::string_view public_base_url,
    const config::SecureRtspConfig& secure_rtsp,
    const std::optional<SecureStreamDiagnostics>& diagnostics) {
  Json::Value json(Json::objectValue);
  json["url"] = BuildRtspUrl(public_base_url, secure_rtsp);
  json["control_tls"] = secure_rtsp.control_tls;
  json["media_srtp"] = secure_rtsp.media_srtp;
  Json::Value secure_media = BuildSecureMediaJson(secure_rtsp);
  if (diagnostics.has_value()) {
    secure_media["per_media_key_zeroize_count"] =
        Json::UInt64(diagnostics->per_media_key_zeroize_count);
  }
  json["secure_media"] = std::move(secure_media);
  return json;
}

ServiceListenerConfig BuildServiceListenerConfig(
    const config::HttpConfig& http_config) {
  ServiceListenerConfig listener;
  listener.bind_address = http_config.bind_ip;
  listener.port = http_config.port;
  listener.use_tls = http_config.tls.enabled;
  listener.certificate_path = http_config.tls.certificate_path;
  listener.private_key_path = http_config.tls.private_key_path;
  return listener;
}

common::Result<void> ValidateHttpTlsConfigFiles(
    const config::HttpConfig& http_config) {
  if (!http_config.enabled || !http_config.tls.enabled) {
    return common::Result<void>::Ok();
  }

  GError* error = nullptr;
  GTlsCertificate* certificate = g_tls_certificate_new_from_files(
      http_config.tls.certificate_path.c_str(),
      http_config.tls.private_key_path.c_str(),
      &error);
  if (certificate == nullptr) {
    std::string message =
        "failed to load HTTP TLS certificate/key files from configured paths";
    if (error != nullptr) {
      message += ": ";
      message += error->message;
      g_error_free(error);
    }
    return common::Result<void>::Err({"E_HTTP_TLS_CERT", message});
  }

  g_object_unref(certificate);
  return common::Result<void>::Ok();
}

drogon::HttpResponsePtr BuildSnapshotResponse(
    const SnapshotCallback& snapshot_callback,
    const std::string& camera_id) {
  if (!snapshot_callback) {
    return JsonResponse(BuildSnapshotUnavailableJson(),
                        drogon::k503ServiceUnavailable);
  }

  const auto snapshot = snapshot_callback(camera_id);
  if (!snapshot.has_value() || snapshot->empty()) {
    return JsonResponse(BuildSnapshotUnavailableJson(),
                        drogon::k503ServiceUnavailable);
  }

  auto response = drogon::HttpResponse::newHttpResponse();
  response->setStatusCode(drogon::k200OK);
  response->setContentTypeCode(drogon::CT_IMAGE_JPG);
  response->setBody(std::string(snapshot->begin(), snapshot->end()));
  return response;
}

ServiceApp::~ServiceApp() {
  Stop();
}

common::Result<void> ServiceApp::Init(const ServiceInitArgs& args) {
  if (args.app_config == nullptr) {
    return common::Result<void>::Err(
        {"E_SERVICE_CONFIG", "ServiceApp::Init requires app_config"});
  }
  auto tls_validation = ValidateHttpTlsConfigFiles(args.app_config->http);
  if (!tls_validation.ok()) {
    return tls_validation;
  }

  try {
    std::shared_ptr<ServiceStartupSignal> startup_signal;
    {
      std::scoped_lock lock(StateMutex());
      GlobalState().args = args;
      if (!initialized_) {
        const auto web_root = std::filesystem::absolute(args.document_root);
        const auto listener = BuildServiceListenerConfig(args.app_config->http);
        drogon::app().setThreadNum(1);
        drogon::app().disableSession();
        drogon::app().setDocumentRoot(web_root.string());
        drogon::app().addListener(listener.bind_address,
                                  listener.port,
                                  listener.use_tls,
                                  listener.certificate_path,
                                  listener.private_key_path);
        RegisterHandlers();
        initialized_ = true;
      }
      if (!drogon::app().isRunning()) {
        startup_signal = std::make_shared<ServiceStartupSignal>();
        auto thread_completion = std::make_shared<std::promise<void>>();
        server_thread_done_ = thread_completion->get_future().share();
        drogon::app().registerBeginningAdvice(
            [startup_signal] { startup_signal->ReportReady(); });
        server_thread_ = std::thread([startup_signal, thread_completion] {
          ThreadCompletionReporter completion_reporter(thread_completion);
          try {
            drogon::app().run();
            startup_signal->ReportError(
                {"E_SERVICE_START",
                 "Drogon service stopped before reporting startup readiness"});
          } catch (const std::exception& ex) {
            startup_signal->ReportError(
                {"E_SERVICE_START",
                 std::string("failed to start service: ") + ex.what()});
          } catch (...) {
            startup_signal->ReportError(
                {"E_SERVICE_START",
                 "failed to start service: unknown Drogon exception"});
          }
        });
        running_ = true;
      }
    }

    if (startup_signal) {
      auto startup = startup_signal->Wait();
      if (!startup.ok()) {
        auto stopped = internal::StopServiceThreadWithin(
            server_thread_,
            server_thread_done_,
            kServiceThreadStopTimeout,
            [] { drogon::app().quit(); });
        running_ = false;
        if (!stopped.ok()) {
          return common::Result<void>::Err(
              {"E_SERVICE_START",
               startup.error().message + "; " + stopped.error().message});
        }
        return startup;
      }
    }
  } catch (const std::exception& ex) {
    Stop();
    return common::Result<void>::Err(
        {"E_SERVICE_START", std::string("failed to start service: ") + ex.what()});
  }

  return common::Result<void>::Ok();
}

void ServiceApp::Stop() {
  if (running_ || server_thread_.joinable()) {
    auto stopped = internal::StopServiceThreadWithin(
        server_thread_,
        server_thread_done_,
        kServiceThreadStopTimeout,
        [] { drogon::app().quit(); });
    if (!stopped.ok()) {
      common::Logger::instance().log(common::Logger::Level::kWarn,
                                     stopped.error().message);
    }
    running_ = false;
  }
}

}  // namespace camera_firmware::service
