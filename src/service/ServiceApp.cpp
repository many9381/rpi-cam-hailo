#include "camera_firmware/service/ServiceApp.hpp"

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

#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/service/ServiceStartup.hpp"

namespace camera_firmware::service {
namespace {

struct ServiceState {
  ServiceInitArgs args;
};

constexpr std::chrono::milliseconds kServiceThreadStopTimeout{2000};

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

drogon::HttpResponsePtr JsonResponse(Json::Value json,
                                     drogon::HttpStatusCode status =
                                         drogon::k200OK) {
  auto response = drogon::HttpResponse::newHttpJsonResponse(std::move(json));
  response->setStatusCode(status);
  return response;
}

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
      "/api/v1/stream",
      [](const HttpRequestPtr&,
         std::function<void(const HttpResponsePtr&)>&& callback) {
        const config::AppConfig* config = nullptr;
        std::string public_base_url;
        {
          std::scoped_lock lock(StateMutex());
          config = GlobalState().args.app_config;
          public_base_url = GlobalState().args.public_base_url;
        }
        if (config == nullptr) {
          Json::Value body(Json::objectValue);
          body["code"] = "E_CONFIG";
          body["message"] = "service config unavailable";
          callback(JsonResponse(std::move(body), drogon::k500InternalServerError));
          return;
        }

        callback(JsonResponse(
            BuildStreamJson(public_base_url, config->secure_rtsp)));
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

Json::Value BuildStreamJson(std::string_view public_base_url,
                            const config::SecureRtspConfig& secure_rtsp) {
  Json::Value json(Json::objectValue);
  json["url"] = BuildRtspUrl(public_base_url, secure_rtsp);
  json["control_tls"] = secure_rtsp.control_tls;
  json["media_srtp"] = secure_rtsp.media_srtp;
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
