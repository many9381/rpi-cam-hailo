#include "camera_firmware/service/ServiceApp.hpp"

#include <filesystem>
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

namespace camera_firmware::service {
namespace {

struct ServiceState {
  ServiceInitArgs args;
};

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

Json::Value BuildAiJson(bool enabled) {
  Json::Value json(Json::objectValue);
  json["enabled"] = enabled;
  json["backend"] = enabled ? "configured" : "disabled";
  return json;
}

drogon::HttpResponsePtr JsonResponse(Json::Value json,
                                     drogon::HttpStatusCode status =
                                         drogon::k200OK) {
  auto response = drogon::HttpResponse::newHttpJsonResponse(std::move(json));
  response->setStatusCode(status);
  return response;
}

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
        bool ai_enabled = false;

        {
          std::scoped_lock lock(StateMutex());
          provider = GlobalState().args.camera_status_provider;
          ai_enabled = GlobalState().args.ai_enabled;
        }

        if (provider) {
          for (const auto& camera : provider()) {
            cameras.append(BuildCameraJson(camera));
          }
        }
        body["cameras"] = std::move(cameras);
        body["ai"] = BuildAiJson(ai_enabled);
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

        const auto snapshot = snapshot_callback(camera_id);
        if (!snapshot.has_value() || snapshot->empty()) {
          callback(JsonResponse(BuildSnapshotUnavailableJson(),
                                drogon::k503ServiceUnavailable));
          return;
        }

        auto response = drogon::HttpResponse::newHttpResponse();
        response->setStatusCode(drogon::k200OK);
        response->setContentTypeCode(drogon::CT_IMAGE_JPG);
        response->setBody(std::string(snapshot->begin(), snapshot->end()));
        callback(response);
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

Json::Value BuildHealthJson(const std::string& status) {
  Json::Value json(Json::objectValue);
  json["status"] = status;
  return json;
}

Json::Value BuildStreamJson(std::string_view public_base_url,
                            const config::SecureRtspConfig& secure_rtsp) {
  Json::Value json(Json::objectValue);
  json["url"] = BuildRtspUrl(public_base_url, secure_rtsp);
  json["control_tls"] = secure_rtsp.control_tls;
  json["media_srtp"] = secure_rtsp.media_srtp;
  return json;
}

ServiceApp::~ServiceApp() {
  Stop();
}

void ServiceApp::Init(const ServiceInitArgs& args) {
  if (args.app_config == nullptr) {
    throw std::invalid_argument("ServiceApp::Init requires app_config");
  }

  std::scoped_lock lock(StateMutex());
  GlobalState().args = args;
  if (!initialized_) {
    const auto web_root = std::filesystem::absolute(args.document_root);
    drogon::app().setThreadNum(1);
    drogon::app().disableSession();
    drogon::app().setDocumentRoot(web_root.string());
    drogon::app().addListener(args.bind_address, args.port);
    RegisterHandlers();
    initialized_ = true;
  }
  if (!drogon::app().isRunning()) {
    server_thread_ = std::thread([] { drogon::app().run(); });
    running_ = true;
  }
}

void ServiceApp::Stop() {
  if (running_) {
    drogon::app().quit();
    if (server_thread_.joinable()) {
      server_thread_.join();
    }
    running_ = false;
  }
}

}  // namespace camera_firmware::service
