#include "camera_firmware/service/ServiceApp.hpp"

#include <algorithm>
#include <array>
#include <atomic>
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
#include <json/writer.h>
#include <trantor/net/EventLoop.h>

#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/service/SecurityRequestGate.hpp"
#include "camera_firmware/service/ServiceStartup.hpp"

namespace camera_firmware::service {
namespace {

struct ServiceState {
  ServiceInitArgs args;
  std::shared_ptr<BoundedWorker> security_worker;
  security::DeviceState device_state{security::DeviceState::kDefault};
  std::optional<std::string> runtime_pending_peer;
  bool shutting_down{false};
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

bool IsRegisteredApiRoute(std::string_view path, drogon::HttpMethod method) {
  if (method == drogon::Get) {
    if (path == "/api/v1/setup/status" || path == "/api/v1/auth/me" ||
        path == "/api/v1/health" || path == "/api/v1/cameras" ||
        path == "/api/v1/ai/detections" ||
        path == "/api/v1/ai/detections/stream" ||
        path == "/api/v1/stream") {
      return true;
    }
    constexpr std::string_view prefix = "/api/v1/cameras/";
    constexpr std::array<std::string_view, 3> suffixes = {
        "/snapshot.jpg", "/preview.mjpeg", "/live.mp4"};
    for (const auto suffix : suffixes) {
      if (path.starts_with(prefix) && path.ends_with(suffix) &&
          path.size() > prefix.size() + suffix.size()) {
        const auto camera_id = path.substr(
            prefix.size(), path.size() - prefix.size() - suffix.size());
        if (camera_id.find('/') == std::string_view::npos) {
          return true;
        }
      }
    }
    return false;
  }
  return method == drogon::Post &&
         (path == "/api/v1/setup/initialize" ||
          path == "/api/v1/setup/runtime" ||
          path == "/api/v1/auth/login" ||
          path == "/api/v1/auth/logout" ||
          path == "/api/v1/runtime/restart" ||
          path == "/api/v1/ai/restart");
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

Json::Value BuildCameraStatusJsonValue(const CameraStatus& camera) {
  Json::Value json(Json::objectValue);
  json["id"] = camera.id;
  json["state"] = camera.state;
  json["snapshot_available"] = camera.snapshot_available;
  json["width"] = camera.width;
  json["height"] = camera.height;
  json["configured_fps"] = camera.configured_fps;
  json["capture_fps"] = camera.capture_fps;
  json["encoded_fps"] = camera.encoded_fps;
  json["captured_frames"] = Json::UInt64(camera.captured_frames);
  json["encoded_frames"] = Json::UInt64(camera.encoded_frames);
  json["capture_error_count"] = Json::UInt64(camera.capture_error_count);
  json["encode_error_count"] = Json::UInt64(camera.encode_error_count);
  return json;
}

Json::Value BuildSnapshotUnavailableJson() {
  Json::Value json(Json::objectValue);
  json["code"] = "E_NO_SNAPSHOT";
  json["message"] = "snapshot unavailable";
  return json;
}

Json::Value BuildPreviewErrorJson(std::string_view code) {
  Json::Value json(Json::objectValue);
  if (code == "E_PREVIEW_CAPACITY") {
    json["code"] = "E_PREVIEW_CAPACITY";
    json["message"] = "MJPEG preview reader capacity is full";
  } else {
    json["code"] = "E_PREVIEW_UNAVAILABLE";
    json["message"] = "MJPEG preview is unavailable";
  }
  return json;
}

Json::Value BuildLiveErrorJson(std::string_view code) {
  Json::Value json(Json::objectValue);
  if (code == "E_LIVE_CAPACITY") {
    json["code"] = "E_LIVE_CAPACITY";
    json["message"] = "live preview reader capacity is full";
  } else {
    json["code"] = "E_LIVE_UNAVAILABLE";
    json["message"] = "live preview is unavailable";
  }
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

using DrogonCallback =
    std::function<void(const drogon::HttpResponsePtr&)>;

class TerminalResponse {
 public:
  TerminalResponse(trantor::EventLoop* event_loop, DrogonCallback callback)
      : event_loop_(event_loop), callback_(std::move(callback)) {}

  void Respond(drogon::HttpResponsePtr response) {
    if (completed_.exchange(true)) {
      return;
    }
    callback_(response);
  }

  void Queue(drogon::HttpResponsePtr response) {
    if (completed_.exchange(true)) {
      return;
    }
    event_loop_->queueInLoop(
        [callback = std::move(callback_),
         response = std::move(response)]() mutable { callback(response); });
  }

 private:
  trantor::EventLoop* event_loop_;
  DrogonCallback callback_;
  std::atomic<bool> completed_{false};
};

class HttpCallback {
 public:
  HttpCallback() = default;
  explicit HttpCallback(std::shared_ptr<TerminalResponse> terminal)
      : terminal_(std::move(terminal)) {}

  void operator()(drogon::HttpResponsePtr response) const {
    terminal_->Respond(std::move(response));
  }

  void Queue(drogon::HttpResponsePtr response) const {
    terminal_->Queue(std::move(response));
  }

  explicit operator bool() const noexcept {
    return static_cast<bool>(terminal_);
  }

 private:
  std::shared_ptr<TerminalResponse> terminal_;
};

using AuthorizedContinuation =
    std::function<void(std::optional<security::Principal>, HttpCallback)>;

drogon::HttpResponsePtr SecurityErrorResponse(const common::Error& error) {
  Json::Value body(Json::objectValue);
  body["code"] = error.code;
  drogon::HttpStatusCode status = drogon::k403Forbidden;
  std::string message = "request denied";
  if (error.code == "E_AUTHENTICATION_REQUIRED" ||
      error.code == "E_AUTHENTICATION_FAILED") {
    status = drogon::k401Unauthorized;
    message = "authentication required";
  } else if (error.code == "E_SECURITY_UNAVAILABLE" ||
             error.code == "E_AUTHENTICATION_UNAVAILABLE" ||
             error.code == "E_AUTHENTICATION_STORE") {
    status = drogon::k503ServiceUnavailable;
    body["code"] = "E_SECURITY_UNAVAILABLE";
    message = "security service unavailable";
  } else if (error.code == "E_REQUEST_TOO_LARGE") {
    status = drogon::k413RequestEntityTooLarge;
    message = "request could not be processed";
  } else if (error.code == "E_INVALID_REQUEST") {
    status = drogon::k400BadRequest;
    message = "request could not be processed";
  }
  body["message"] = message;
  return JsonResponse(std::move(body), status);
}

drogon::HttpResponsePtr SecurityUnavailableResponse() {
  return SecurityErrorResponse(
      {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
}

drogon::HttpResponsePtr BootstrapErrorResponse(const common::Error& error) {
  const bool validation =
      error.code == "E_BOOTSTRAP_PEER" ||
      error.code.starts_with("E_USERNAME_") ||
      error.code.starts_with("E_PASSWORD_");
  if (!validation && error.code != "E_BOOTSTRAP_UNAVAILABLE") {
    return SecurityUnavailableResponse();
  }
  Json::Value body(Json::objectValue);
  body["code"] = error.code;
  body["message"] = validation ? "device setup request is invalid"
                                : "device setup is already complete";
  return JsonResponse(std::move(body),
                      validation ? drogon::k400BadRequest
                                 : drogon::k409Conflict);
}

class AsyncAuthorization final
    : public std::enable_shared_from_this<AsyncAuthorization> {
 public:
  AsyncAuthorization(trantor::EventLoop* event_loop,
                     DrogonCallback callback,
                     AuthorizedContinuation continuation)
      : event_loop_(event_loop),
        terminal_(HttpCallback(std::make_shared<TerminalResponse>(
            event_loop, std::move(callback)))),
        continuation_(std::move(continuation)) {}

  void Deny(common::Error error) {
    auto response = SecurityErrorResponse(error);
    Dispatch([response = std::move(response)](HttpCallback terminal,
                                               AuthorizedContinuation) {
      terminal(response);
    });
  }

  void Allow(std::optional<security::Principal> principal) {
    Dispatch([principal = std::move(principal)](
                 HttpCallback terminal,
                 AuthorizedContinuation continuation) mutable {
      try {
        continuation(std::move(principal), terminal);
      } catch (...) {
        terminal(SecurityUnavailableResponse());
      }
    });
  }

 private:
  using DispatchAction =
      std::function<void(HttpCallback, AuthorizedContinuation)>;

  void Dispatch(DispatchAction action) {
    if (completed_.exchange(true)) {
      return;
    }
    auto terminal = terminal_;
    auto continuation = std::move(continuation_);
    event_loop_->queueInLoop(
        [action = std::move(action), terminal = std::move(terminal),
         continuation = std::move(continuation)]() mutable {
          action(std::move(terminal), std::move(continuation));
        });
  }

  trantor::EventLoop* event_loop_;
  HttpCallback terminal_;
  AuthorizedContinuation continuation_;
  std::atomic<bool> completed_{false};
};

struct SecurityDependencies {
  bool enabled{false};
  bool shutting_down{false};
  std::string expected_origin;
  std::shared_ptr<security::SecurityStore> store;
  std::shared_ptr<security::AuthService> auth_service;
  std::shared_ptr<BoundedWorker> worker;
};

SecurityDependencies CopySecurityDependencies() {
  std::scoped_lock lock(StateMutex());
  const auto& state = GlobalState();
  return {state.args.app_config != nullptr &&
              state.args.app_config->security.enabled,
          state.shutting_down,
          state.args.public_base_url,
          state.args.security_store,
          state.args.auth_service,
          state.security_worker};
}

void AuthorizeRequest(const drogon::HttpRequestPtr& request,
                      DrogonCallback callback,
                      AuthorizedContinuation continuation) {
  auto completion = std::make_shared<AsyncAuthorization>(
      drogon::app().getLoop(), std::move(callback), std::move(continuation));
  const auto dependencies = CopySecurityDependencies();
  if (!dependencies.enabled) {
    completion->Allow(std::nullopt);
    return;
  }
  if (dependencies.shutting_down) {
    completion->Deny(
        {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
    return;
  }
  if (!request || !dependencies.store || !dependencies.auth_service ||
      !dependencies.worker) {
    completion->Deny(
        {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
    return;
  }

  auto normalized_peer = NormalizePeerIp(request->peerAddr().toIp());
  if (!normalized_peer.ok()) {
    completion->Deny({"E_ACCESS_DENIED", "request denied"});
    return;
  }
  SecurityRequestContext context;
  context.path = request->path();
  context.method = request->methodString();
  context.normalized_peer_ip = std::move(normalized_peer).value();
  context.origin = request->getHeader("origin");
  context.expected_origin = dependencies.expected_origin;
  context.has_management_header =
      request->getHeader("x-camera-request") == "management";
  std::shared_ptr<common::SecureBytes> session_token;
  auto parsed_token =
      ParseSessionCookieHeaders(request->getRawCookieHeaders());
  if (parsed_token.ok()) {
    session_token = std::make_shared<common::SecureBytes>(
        std::move(parsed_token).value());
  }

  auto submitted = dependencies.worker->Submit(
      [context = std::move(context), session_token,
       dependencies, completion]() mutable {
        try {
          auto state = dependencies.store->State();
          if (!state.ok()) {
            completion->Deny(
                {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
            return;
          }
          std::optional<std::string> runtime_pending_peer;
          security::DeviceState process_state;
          {
            std::scoped_lock lock(StateMutex());
            runtime_pending_peer = GlobalState().runtime_pending_peer;
            process_state = GlobalState().device_state;
          }
          context.state = runtime_pending_peer.has_value()
                              ? security::DeviceState::kDefault
                              : process_state;
          const bool setup_initialize =
              context.path == "/api/v1/setup/initialize";
          const bool setup_runtime =
              context.path == "/api/v1/setup/runtime";
          if ((setup_initialize || setup_runtime) &&
              runtime_pending_peer.has_value() &&
              context.normalized_peer_ip != *runtime_pending_peer) {
            completion->Deny({"E_ACCESS_DENIED", "request denied"});
            return;
          }
          const bool login = context.path == "/api/v1/auth/login" &&
                             context.method == "POST";
          if (context.state == security::DeviceState::kOperational &&
              !setup_initialize) {
            auto management = dependencies.store->IsManagementPeer(
                context.normalized_peer_ip);
            if (!management.ok()) {
              completion->Deny({"E_SECURITY_UNAVAILABLE",
                                "security service unavailable"});
              return;
            }
            context.peer_is_management = management.value();
            if (!login && context.peer_is_management && session_token) {
              if (session_token->size() != 0U) {
                auto principal = dependencies.auth_service->Verify(
                    {session_token->data(), session_token->size()},
                    context.normalized_peer_ip);
                if (principal.ok()) {
                  context.principal = std::move(principal).value();
                } else if (principal.error().code ==
                           "E_AUTHENTICATION_UNAVAILABLE") {
                  completion->Deny({"E_SECURITY_UNAVAILABLE",
                                    "security service unavailable"});
                  return;
                }
              }
            }
          }
          auto authorized = AuthorizeSecurityRequest(context);
          if (!authorized.ok()) {
            completion->Deny(authorized.error());
            return;
          }
          completion->Allow(std::move(context.principal));
        } catch (...) {
          completion->Deny(
              {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
        }
      });
  if (!submitted.ok()) {
    completion->Deny(submitted.error());
  }
}

void QueueResponse(trantor::EventLoop* event_loop,
                   HttpCallback callback,
                   drogon::HttpResponsePtr response) {
  (void)event_loop;
  callback.Queue(std::move(response));
}

std::string EncodeSessionToken(common::SecureBytes& token) {
  static constexpr std::array<char, 16> kHex = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string encoded(token.size() * 2U, '0');
  for (std::size_t index = 0; index < token.size(); ++index) {
    encoded[index * 2U] = kHex[token.data()[index] >> 4U];
    encoded[index * 2U + 1U] = kHex[token.data()[index] & 0x0fU];
  }
  token.clear();
  return encoded;
}

drogon::Cookie SessionCookie(std::string value, int max_age = -1) {
  drogon::Cookie cookie(std::string(kSessionCookieName), std::move(value));
  cookie.setSecure(true);
  cookie.setHttpOnly(true);
  cookie.setSameSite(drogon::Cookie::SameSite::kStrict);
  cookie.setPath("/");
  if (max_age >= 0) {
    cookie.setMaxAge(max_age);
  }
  return cookie;
}

std::string CompactJson(Json::Value json) {
  Json::StreamWriterBuilder writer;
  writer["indentation"] = "";
  return Json::writeString(writer, json);
}

class DetectionSsePendingResponse {
 public:
  using ResponseCallback = HttpCallback;

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
      callback.Queue(std::move(response));
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

  app().registerPreSendingAdvice(
      [](const HttpRequestPtr&, const HttpResponsePtr& response) {
        response->addHeader("Cache-Control", "no-store");
        response->addHeader("Strict-Transport-Security", "max-age=31536000");
        response->addHeader("X-Content-Type-Options", "nosniff");
        response->addHeader("Referrer-Policy", "no-referrer");
        response->addHeader("X-Frame-Options", "DENY");
        response->addHeader(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' blob:; object-src 'none'; "
            "media-src 'self' blob:; "
            "base-uri 'none'; "
            "frame-ancestors 'none'");
      });

  app().registerPreRoutingAdvice(
      [](const HttpRequestPtr& request, AdviceCallback&& callback,
         AdviceChainCallback&& chain) {
        const std::string_view path = request->path();
        const bool api = IsRegisteredApiRoute(path, request->method());
        const bool static_asset =
            request->method() == Get &&
            (path == "/" || path == "/index.html" || path == "/app.js" ||
             path == "/styles.css");
        if (api || static_asset) {
          chain();
          return;
        }
        Json::Value body(Json::objectValue);
        body["code"] = "E_NOT_FOUND";
        body["message"] = "resource not found";
        callback(JsonResponse(std::move(body), k404NotFound));
      });

  app().registerHandler(
      "/api/v1/setup/status",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        security::DeviceState state;
        bool runtime_pending = false;
        bool security_enabled = false;
        {
          std::scoped_lock lock(StateMutex());
          state = GlobalState().device_state;
          runtime_pending = GlobalState().runtime_pending_peer.has_value();
          security_enabled = GlobalState().args.app_config != nullptr &&
                             GlobalState().args.app_config->security.enabled;
        }
        if (!security_enabled) {
          callback(SecurityErrorResponse(
              {"E_ACCESS_DENIED", "request denied"}));
          return;
        }
        Json::Value body(Json::objectValue);
        const bool required = runtime_pending ||
                              state == security::DeviceState::kDefault;
        body["required"] = required;
        if (required) {
          auto peer = NormalizePeerIp(request->peerAddr().toIp());
          if (!peer.ok()) {
            callback(SecurityUnavailableResponse());
            return;
          }
          body["tls"] = "ready";
          body["peer_ip"] = std::move(peer).value();
          body["phase"] = runtime_pending ? "runtime_pending"
                                           : "administrator";
        }
        callback(JsonResponse(std::move(body)));
      },
      {Get});

  app().registerHandler(
      "/api/v1/setup/initialize",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        auto peer = NormalizePeerIp(request->peerAddr().toIp());
        const std::string actual_peer = peer.ok() ? peer.value() : "";
        AuthorizeRequest(
            request, std::move(callback),
            [request, actual_peer](
                std::optional<security::Principal>, HttpCallback callback) {
              auto parsed = ParseSetupJson(request->getBody(),
                                           request->getHeader("content-type"));
              if (!parsed.ok()) {
                callback(SecurityErrorResponse(parsed.error()));
                return;
              }
              std::shared_ptr<security::BootstrapService> bootstrap;
              std::shared_ptr<BoundedWorker> worker;
              RuntimeStartCallback runtime_start;
              {
                std::scoped_lock lock(StateMutex());
                bootstrap = GlobalState().args.bootstrap_service;
                worker = GlobalState().security_worker;
                runtime_start = GlobalState().args.runtime_start_callback;
              }
              if (!bootstrap || !worker || actual_peer.empty()) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto parsed_request =
                  std::make_shared<ParsedSetupRequest>(std::move(parsed).value());
              auto submitted = worker->Submit(
                  [parsed_request, actual_peer, bootstrap, runtime_start,
                   callback,
                   event_loop = app().getLoop()]() mutable {
                    try {
                      security::BootstrapRequest bootstrap_request;
                      bootstrap_request.username = parsed_request->username;
                      bootstrap_request.password =
                          std::move(parsed_request->password);
                      bootstrap_request.confirmed_peer_ip =
                          parsed_request->confirmed_peer_ip;
                      bootstrap_request.actual_peer_ip = actual_peer;
                      bool transition_allowed = false;
                      {
                        std::scoped_lock lock(StateMutex());
                        const auto& state = GlobalState();
                        transition_allowed =
                            !state.runtime_pending_peer.has_value() &&
                            state.device_state == security::DeviceState::kDefault;
                      }
                      if (!transition_allowed) {
                        QueueResponse(
                            event_loop, std::move(callback),
                            SecurityErrorResponse(
                                {"E_ACCESS_DENIED", "request denied"}));
                        return;
                      }
                      auto initialized =
                          bootstrap->Initialize(std::move(bootstrap_request));
                      if (!initialized.ok()) {
                        QueueResponse(event_loop, std::move(callback),
                                      BootstrapErrorResponse(
                                          initialized.error()));
                        return;
                      }
                      {
                        std::scoped_lock lock(StateMutex());
                        GlobalState().runtime_pending_peer = actual_peer;
                        GlobalState().device_state =
                            security::DeviceState::kDefault;
                      }
                      if (!runtime_start) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityUnavailableResponse());
                        return;
                      }
                      auto runtime = runtime_start();
                      if (!runtime.ok()) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityUnavailableResponse());
                        return;
                      }
                      bool transition_completed = false;
                      {
                        std::scoped_lock lock(StateMutex());
                        if (GlobalState().runtime_pending_peer.has_value() &&
                            *GlobalState().runtime_pending_peer == actual_peer) {
                          GlobalState().device_state =
                              security::DeviceState::kOperational;
                          GlobalState().runtime_pending_peer.reset();
                          transition_completed = true;
                        }
                      }
                      if (!transition_completed) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityUnavailableResponse());
                        return;
                      }
                      Json::Value response(Json::objectValue);
                      response["required"] = false;
                      response["runtime"] = "running";
                      QueueResponse(event_loop, std::move(callback),
                                    JsonResponse(std::move(response)));
                    } catch (...) {
                      QueueResponse(event_loop, std::move(callback),
                                    SecurityUnavailableResponse());
                    }
                  });
              if (!submitted.ok()) {
                callback(SecurityUnavailableResponse());
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/setup/runtime",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        auto peer = NormalizePeerIp(request->peerAddr().toIp());
        const std::string actual_peer = peer.ok() ? peer.value() : "";
        AuthorizeRequest(
            request, std::move(callback),
            [request, actual_peer](
                std::optional<security::Principal>, HttpCallback callback) {
              auto validated = ValidateEmptyJsonObject(
                  request->getBody(), request->getHeader("content-type"));
              if (!validated.ok()) {
                callback(SecurityErrorResponse(validated.error()));
                return;
              }
              std::shared_ptr<BoundedWorker> worker;
              RuntimeStartCallback runtime_start;
              {
                std::scoped_lock lock(StateMutex());
                worker = GlobalState().security_worker;
                runtime_start = GlobalState().args.runtime_start_callback;
              }
              if (!worker || !runtime_start || actual_peer.empty()) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto submitted = worker->Submit(
                  [actual_peer, runtime_start, callback,
                   event_loop = app().getLoop()]() mutable {
                    try {
                      bool transition_allowed = false;
                      {
                        std::scoped_lock lock(StateMutex());
                        const auto& state = GlobalState();
                        transition_allowed =
                            state.runtime_pending_peer.has_value() &&
                            *state.runtime_pending_peer == actual_peer &&
                            state.device_state == security::DeviceState::kDefault;
                      }
                      if (!transition_allowed) {
                        QueueResponse(
                            event_loop, std::move(callback),
                            SecurityErrorResponse(
                                {"E_ACCESS_DENIED", "request denied"}));
                        return;
                      }
                      auto runtime = runtime_start();
                      if (!runtime.ok()) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityUnavailableResponse());
                        return;
                      }
                      bool transition_completed = false;
                      {
                        std::scoped_lock lock(StateMutex());
                        auto& state = GlobalState();
                        if (state.runtime_pending_peer.has_value() &&
                            *state.runtime_pending_peer == actual_peer) {
                          state.device_state =
                              security::DeviceState::kOperational;
                          state.runtime_pending_peer.reset();
                          transition_completed = true;
                        }
                      }
                      if (!transition_completed) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityUnavailableResponse());
                        return;
                      }
                      Json::Value response(Json::objectValue);
                      response["required"] = false;
                      response["runtime"] = "running";
                      QueueResponse(event_loop, std::move(callback),
                                    JsonResponse(std::move(response)));
                    } catch (...) {
                      QueueResponse(event_loop, std::move(callback),
                                    SecurityUnavailableResponse());
                    }
                  });
              if (!submitted.ok()) {
                callback(SecurityUnavailableResponse());
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/auth/login",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        const std::string peer_ip = request->peerAddr().toIp();
        AuthorizeRequest(
            request, std::move(callback),
            [request, peer_ip](
                std::optional<security::Principal>, HttpCallback callback) {
              auto parsed = ParseLoginJson(request->getBody(),
                                           request->getHeader("content-type"));
              if (!parsed.ok()) {
                callback(SecurityErrorResponse(parsed.error()));
                return;
              }
              std::shared_ptr<security::AuthService> auth;
              std::shared_ptr<BoundedWorker> worker;
              {
                std::scoped_lock lock(StateMutex());
                auth = GlobalState().args.auth_service;
                worker = GlobalState().security_worker;
              }
              if (!auth || !worker) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto parsed_request =
                  std::make_shared<ParsedLoginRequest>(std::move(parsed).value());
              auto submitted = worker->Submit(
                  [parsed_request, peer_ip, auth, callback,
                   event_loop = app().getLoop()]() mutable {
                    try {
                      security::LoginRequest login_request;
                      login_request.username = parsed_request->username;
                      login_request.password = std::move(parsed_request->password);
                      login_request.peer_ip = peer_ip;
                      auto login = auth->Login(std::move(login_request));
                      if (!login.ok()) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityErrorResponse(login.error()));
                        return;
                      }
                      auto result = std::move(login).value();
                      Json::Value response_body(Json::objectValue);
                      response_body["role"] = "administrator";
                      response_body["idle_expires_at_seconds"] =
                          static_cast<Json::Int64>(
                              result.idle_expires_at_seconds);
                      auto response = JsonResponse(std::move(response_body));
                      response->addCookie(SessionCookie(
                          EncodeSessionToken(result.session_token)));
                      QueueResponse(event_loop, std::move(callback),
                                    std::move(response));
                    } catch (...) {
                      QueueResponse(event_loop, std::move(callback),
                                    SecurityUnavailableResponse());
                    }
                  });
              if (!submitted.ok()) {
                callback(SecurityUnavailableResponse());
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/auth/me",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](std::optional<security::Principal> principal,
               HttpCallback callback) {
              if (!principal.has_value()) {
                callback(SecurityErrorResponse(
                    {"E_AUTHENTICATION_REQUIRED", "authentication required"}));
                return;
              }
              Json::Value body(Json::objectValue);
              body["username"] = principal->username;
              body["role"] = principal->role == security::UserRole::kAdministrator
                                   ? "administrator"
                                   : "viewer";
              callback(JsonResponse(std::move(body)));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/auth/logout",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        const std::string peer_ip = request->peerAddr().toIp();
        AuthorizeRequest(
            request, std::move(callback),
            [request, peer_ip](std::optional<security::Principal>,
                               HttpCallback callback) {
              auto token =
                  ParseSessionCookieHeaders(request->getRawCookieHeaders());
              if (!token.ok()) {
                callback(SecurityErrorResponse(token.error()));
                return;
              }
              std::shared_ptr<security::AuthService> auth;
              std::shared_ptr<BoundedWorker> worker;
              {
                std::scoped_lock lock(StateMutex());
                auth = GlobalState().args.auth_service;
                worker = GlobalState().security_worker;
              }
              if (!auth || !worker) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto secure_token = std::make_shared<common::SecureBytes>(
                  std::move(token).value());
              auto submitted = worker->Submit(
                  [secure_token, peer_ip, auth, callback,
                   event_loop = app().getLoop()]() mutable {
                    try {
                      auto logged_out = auth->Logout(
                          {secure_token->data(), secure_token->size()}, peer_ip);
                      secure_token->clear();
                      if (!logged_out.ok()) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityErrorResponse(logged_out.error()));
                        return;
                      }
                      Json::Value body(Json::objectValue);
                      body["logged_out"] = true;
                      auto response = JsonResponse(std::move(body));
                      response->addCookie(SessionCookie("", 0));
                      QueueResponse(event_loop, std::move(callback),
                                    std::move(response));
                    } catch (...) {
                      secure_token->clear();
                      QueueResponse(event_loop, std::move(callback),
                                    SecurityUnavailableResponse());
                    }
                  });
              if (!submitted.ok()) {
                secure_token->clear();
                callback(SecurityUnavailableResponse());
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/health",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](std::optional<security::Principal>, HttpCallback callback) {
              std::string status;
              {
                std::scoped_lock lock(StateMutex());
                status = GlobalState().args.health_status;
              }
              callback(JsonResponse(BuildHealthJson(status)));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/cameras",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](std::optional<security::Principal>, HttpCallback callback) {
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
                  cameras.append(BuildCameraStatusJsonValue(camera));
                }
              }
              body["cameras"] = std::move(cameras);
              body["ai"] = ai_status_provider
                               ? BuildAiStatusJson(ai_status_provider())
                               : BuildAiStatusJson(ai_enabled);
              callback(JsonResponse(std::move(body)));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/cameras/{1}/snapshot.jpg",
      [](const HttpRequestPtr& request, DrogonCallback&& callback,
         const std::string& camera_id) {
        AuthorizeRequest(
            request, std::move(callback),
            [camera_id](std::optional<security::Principal>,
                        HttpCallback callback) {
              SnapshotCallback snapshot_callback;
              {
                std::scoped_lock lock(StateMutex());
                snapshot_callback = GlobalState().args.snapshot_callback;
              }
              callback(BuildSnapshotResponse(snapshot_callback, camera_id));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/cameras/{1}/preview.mjpeg",
      [](const HttpRequestPtr& request, DrogonCallback&& callback,
         const std::string& camera_id) {
        AuthorizeRequest(
            request, std::move(callback),
            [camera_id](std::optional<security::Principal>,
                        HttpCallback callback) {
              MjpegPreviewOpenCallback preview_stream_callback;
              {
                std::scoped_lock lock(StateMutex());
                preview_stream_callback =
                    GlobalState().args.preview_stream_callback;
              }
              callback(BuildMjpegPreviewResponse(preview_stream_callback,
                                                 camera_id));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/cameras/{1}/live.mp4",
      [](const HttpRequestPtr& request, DrogonCallback&& callback,
         const std::string& camera_id) {
        AuthorizeRequest(
            request, std::move(callback),
            [camera_id](std::optional<security::Principal>,
                        HttpCallback callback) {
              LiveMp4OpenCallback live_stream_callback;
              {
                std::scoped_lock lock(StateMutex());
                live_stream_callback =
                    GlobalState().args.live_stream_callback;
              }
              callback(BuildLiveMp4Response(live_stream_callback, camera_id));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/ai/detections",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](std::optional<security::Principal>, HttpCallback callback) {
              DetectionSnapshotProvider provider;
              {
                std::scoped_lock lock(StateMutex());
                provider = GlobalState().args.detection_snapshot_provider;
              }
              callback(BuildDetectionSnapshotResponse(provider));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/runtime/restart",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [request](std::optional<security::Principal>,
                      HttpCallback callback) {
              auto validated = ValidateEmptyJsonObject(
                  request->getBody(), request->getHeader("content-type"));
              if (!validated.ok()) {
                callback(SecurityErrorResponse(validated.error()));
                return;
              }
              RuntimeStartCallback restart;
              std::shared_ptr<BoundedWorker> worker;
              {
                std::scoped_lock lock(StateMutex());
                restart = GlobalState().args.runtime_start_callback;
                worker = GlobalState().security_worker;
              }
              if (!worker) {
                callback(BuildRuntimeRestartResponse({}));
                return;
              }
              auto submitted = worker->Submit(
                  [restart = std::move(restart), callback,
                   event_loop = app().getLoop()]() mutable {
                    QueueResponse(
                        event_loop, std::move(callback),
                        BuildRuntimeRestartResponse(restart));
                  });
              if (!submitted.ok()) {
                callback(SecurityUnavailableResponse());
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/ai/restart",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](std::optional<security::Principal>, HttpCallback callback) {
              AiControlCallback restart;
              AiStatusProvider status;
              {
                std::scoped_lock lock(StateMutex());
                restart = GlobalState().args.ai_restart_callback;
                status = GlobalState().args.ai_status_provider;
              }
              callback(BuildAiRestartResponse(restart, status));
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/ai/detections/stream",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        const std::string last_event_id = request->getHeader("Last-Event-ID");
        AuthorizeRequest(
            request, std::move(callback),
            [last_event_id](std::optional<security::Principal>,
                            HttpCallback callback) mutable {
              DetectionSnapshotProvider snapshot_provider;
              DetectionEventSubscriber subscriber;
              {
                std::scoped_lock lock(StateMutex());
                snapshot_provider =
                    GlobalState().args.detection_snapshot_provider;
                subscriber = GlobalState().args.detection_event_subscriber;
              }
              DetectionSnapshotProvider provider_for_check = snapshot_provider;
              auto pending = std::make_shared<DetectionSsePendingResponse>(
                  std::move(snapshot_provider), std::move(callback));
              if (!subscriber) {
                pending->CompleteWithSnapshot();
                return;
              }
              pending->SetSubscription(subscriber(
                  [pending](const ai::DetectionEvent& event) {
                    pending->CompleteWithEvent(event);
                  }));
              if (provider_for_check) {
                const auto snapshot = provider_for_check();
                if (last_event_id.empty() ||
                    last_event_id != BuildDetectionSseId(snapshot)) {
                  pending->CompleteWithSnapshot();
                  return;
                }
              }
              app().getLoop()->runAfter(kDetectionSsePendingTimeout, [pending] {
                pending->CompleteWithSnapshot();
              });
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/stream",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](std::optional<security::Principal>, HttpCallback callback) {
              const config::AppConfig* config = nullptr;
              std::string public_base_url;
              SecureStreamDiagnosticsProvider diagnostics_provider;
              {
                std::scoped_lock lock(StateMutex());
                config = GlobalState().args.app_config;
                public_base_url = GlobalState().args.public_base_url;
                diagnostics_provider =
                    GlobalState().args.secure_stream_diagnostics_provider;
              }
              if (config == nullptr) {
                Json::Value body(Json::objectValue);
                body["code"] = "E_CONFIG";
                body["message"] = "service config unavailable";
                callback(JsonResponse(std::move(body),
                                      k500InternalServerError));
                return;
              }
              std::optional<SecureStreamDiagnostics> diagnostics;
              if (diagnostics_provider) {
                diagnostics = diagnostics_provider();
              }
              callback(JsonResponse(BuildStreamJson(
                  public_base_url, config->secure_rtsp, diagnostics)));
            });
      },
      {Get});
}

}  // namespace

namespace internal {

std::thread StartServiceThreadWithTlsOwner(
    std::optional<security::ResolvedTlsMaterial> tls_material,
    std::function<void()> run) {
  return std::thread(
      [tls_material = std::move(tls_material), run = std::move(run)]() mutable {
        (void)tls_material;
        run();
      });
}

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

  return common::Result<void>::Err(
      {"E_SERVICE_THREAD_STOP_TIMEOUT",
       "service thread stop timed out; thread remains joinable"});
}

}  // namespace internal

Json::Value BuildHealthJson(const std::string& status) {
  Json::Value json(Json::objectValue);
  json["status"] = status;
  return json;
}

Json::Value BuildCameraStatusJson(const CameraStatus& camera) {
  return BuildCameraStatusJsonValue(camera);
}

Json::Value BuildAiStatusJson(const AiServiceStatus& status) {
  Json::Value json(Json::objectValue);
  json["enabled"] = status.enabled;
  json["backend"] = status.backend;
  json["state"] = status.state;
  json["model_count"] = static_cast<Json::UInt64>(status.model_count);
  json["runner_count"] = static_cast<Json::UInt64>(status.runner_count);
  json["reason"] = status.reason;

  Json::Value models(Json::arrayValue);
  for (const auto& model : status.models) {
    Json::Value model_json(Json::objectValue);
    model_json["id"] = model.id;
    model_json["kind"] = model.kind;
    model_json["input_width"] = model.input_width;
    model_json["input_height"] = model.input_height;
    model_json["input_format"] = model.input_format;
    model_json["letterbox"] = model.letterbox;
    model_json["output_name"] = model.output_name;
    model_json["confidence_threshold"] = model.confidence_threshold;
    model_json["labels"] = model.labels;
    models.append(std::move(model_json));
  }
  json["models"] = std::move(models);

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

drogon::HttpResponsePtr BuildRuntimeRestartResponse(
    const RuntimeStartCallback& restart_callback) {
  common::Result<void> restarted = common::Result<void>::Err(
      {"E_RUNTIME_UNAVAILABLE", "camera runtime is unavailable"});
  try {
    if (restart_callback) {
      restarted = restart_callback();
    }
  } catch (...) {
  }
  if (!restarted.ok()) {
    Json::Value body(Json::objectValue);
    body["code"] = "E_RUNTIME_UNAVAILABLE";
    body["message"] = "camera runtime is unavailable";
    return JsonResponse(std::move(body), drogon::k503ServiceUnavailable);
  }

  Json::Value body(Json::objectValue);
  body["runtime"] = "running";
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
  json["frame_timestamp_ns"] =
      static_cast<Json::Int64>(event.frame_timestamp.count());

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

    Json::Value keypoints(Json::arrayValue);
    for (const auto& keypoint : detection.keypoints) {
      Json::Value keypoint_json(Json::objectValue);
      keypoint_json["name"] = keypoint.name;
      keypoint_json["x"] = keypoint.x;
      keypoint_json["y"] = keypoint.y;
      keypoint_json["confidence"] = keypoint.confidence;
      keypoints.append(std::move(keypoint_json));
    }
    detection_json["keypoints"] = std::move(keypoints);

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
    const config::HttpConfig& http_config,
    const security::ResolvedTlsMaterial& tls_material) {
  ServiceListenerConfig listener;
  listener.bind_address = http_config.bind_ip;
  listener.port = http_config.port;
  listener.use_tls = true;
  listener.certificate_path = tls_material.certificate_path.string();
  listener.private_key_path = tls_material.private_key_path.string();
  listener.tls_material = tls_material;
  return listener;
}

common::Result<void> ValidateHttpTlsConfigFiles(
    const config::HttpConfig& http_config) {
  if (!http_config.enabled || !http_config.tls.enabled) {
    return common::Result<void>::Ok();
  }

  const bool has_certificate = !http_config.tls.certificate_path.empty();
  const bool has_private_key = !http_config.tls.private_key_path.empty();
  if (has_certificate != has_private_key) {
    return common::Result<void>::Err(
        {"E_HTTP_TLS_REQUIRED",
         "a complete HTTP TLS certificate and private-key pair is required"});
  }
  if (!has_certificate) {
    if (http_config.tls.allow_development_self_signed_tls) {
      return common::Result<void>::Ok();
    }
    return common::Result<void>::Err(
        {"E_HTTP_TLS_REQUIRED", "configured HTTP TLS material is required"});
  }

  auto resolved = security::ResolveTlsMaterial(http_config.tls, {});
  if (!resolved.ok()) {
    return common::Result<void>::Err(
        {"E_HTTP_TLS_CERT",
         "failed to validate configured HTTP TLS certificate/key files"});
  }
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

drogon::HttpResponsePtr BuildMjpegPreviewResponse(
    const MjpegPreviewOpenCallback& preview_stream_callback,
    const std::string& camera_id) {
  if (!preview_stream_callback) {
    return JsonResponse(BuildPreviewErrorJson("E_PREVIEW_UNAVAILABLE"),
                        drogon::k503ServiceUnavailable);
  }

  common::Result<MjpegPreviewStreamCallback> opened =
      common::Result<MjpegPreviewStreamCallback>::Err(
          {"E_PREVIEW_UNAVAILABLE", "MJPEG preview is unavailable"});
  try {
    opened = preview_stream_callback(camera_id);
  } catch (...) {
    return JsonResponse(BuildPreviewErrorJson("E_PREVIEW_UNAVAILABLE"),
                        drogon::k503ServiceUnavailable);
  }
  if (!opened.ok()) {
    return JsonResponse(BuildPreviewErrorJson(opened.error().code),
                        drogon::k503ServiceUnavailable);
  }

  auto stream = std::move(opened).value();
  if (!stream) {
    return JsonResponse(BuildPreviewErrorJson("E_PREVIEW_UNAVAILABLE"),
                        drogon::k503ServiceUnavailable);
  }
  auto response = drogon::HttpResponse::newStreamResponse(
      stream, "", drogon::CT_CUSTOM,
      "multipart/x-mixed-replace; boundary=cf-frame");
  response->setStatusCode(drogon::k200OK);
  response->addHeader("Content-Encoding", "identity");
  return response;
}

drogon::HttpResponsePtr BuildLiveMp4Response(
    const LiveMp4OpenCallback& live_stream_callback,
    const std::string& camera_id) {
  if (!live_stream_callback) {
    return JsonResponse(BuildLiveErrorJson("E_LIVE_UNAVAILABLE"),
                        drogon::k503ServiceUnavailable);
  }

  common::Result<LiveMp4StreamCallback> opened =
      common::Result<LiveMp4StreamCallback>::Err(
          {"E_LIVE_UNAVAILABLE", "live preview is unavailable"});
  try {
    opened = live_stream_callback(camera_id);
  } catch (...) {
    return JsonResponse(BuildLiveErrorJson("E_LIVE_UNAVAILABLE"),
                        drogon::k503ServiceUnavailable);
  }
  if (!opened.ok()) {
    return JsonResponse(BuildLiveErrorJson(opened.error().code),
                        drogon::k503ServiceUnavailable);
  }

  auto stream = std::move(opened).value();
  if (!stream) {
    return JsonResponse(BuildLiveErrorJson("E_LIVE_UNAVAILABLE"),
                        drogon::k503ServiceUnavailable);
  }
  auto response = drogon::HttpResponse::newStreamResponse(
      stream, "", drogon::CT_CUSTOM, "video/mp4");
  response->setStatusCode(drogon::k200OK);
  response->addHeader("Content-Encoding", "identity");
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
  if (args.app_config->security.enabled &&
      (!args.app_config->http.enabled || !args.app_config->http.tls.enabled)) {
    return common::Result<void>::Err(
        {"E_HTTP_TLS_REQUIRED", "security requires an HTTPS listener"});
  }

  try {
    ServiceInitArgs effective_args = args;
    security::DeviceState initial_device_state =
        security::DeviceState::kDefault;
    std::shared_ptr<BoundedWorker> security_worker;
    if (args.app_config->security.enabled) {
      if (!effective_args.security_store) {
        auto opened = security::SecurityStore::Open(
            {args.app_config->security.state_directory});
        if (!opened.ok()) {
          return common::Result<void>::Err(opened.error());
        }
        effective_args.security_store =
            std::shared_ptr<security::SecurityStore>(std::move(opened).value());
      }
      auto state = effective_args.security_store->State();
      if (!state.ok()) {
        return common::Result<void>::Err(state.error());
      }
      initial_device_state = state.value();
      if (initial_device_state == security::DeviceState::kDefault &&
          !effective_args.runtime_start_callback) {
        return common::Result<void>::Err(
            {"E_SERVICE_CONFIG",
             "default security state requires runtime_start_callback"});
      }
      if (!effective_args.bootstrap_service) {
        effective_args.bootstrap_service =
            std::make_shared<security::BootstrapService>(
                *effective_args.security_store, *args.app_config,
                security::BuildReservedIdentities(*args.app_config));
      }
      if (!effective_args.auth_service) {
        effective_args.auth_service = std::make_shared<security::AuthService>(
            *effective_args.security_store);
      }
      security_worker = std::make_shared<BoundedWorker>(16U);
    }

    std::optional<security::ResolvedTlsMaterial> tls_material;
    if (args.app_config->http.tls.enabled) {
      auto resolved = security::ResolveTlsMaterial(
          args.app_config->http.tls,
          args.app_config->security.state_directory);
      if (!resolved.ok()) {
        return common::Result<void>::Err(resolved.error());
      }
      tls_material = std::move(resolved).value();
    }
    std::shared_ptr<ServiceStartupSignal> startup_signal;
    {
      std::scoped_lock lock(StateMutex());
      GlobalState().args = effective_args;
      GlobalState().security_worker = security_worker;
      GlobalState().device_state = initial_device_state;
      GlobalState().runtime_pending_peer.reset();
      GlobalState().shutting_down = false;
      security_worker_ = security_worker;
      {
        std::lock_guard shutdown_lock(shutdown_mutex_);
        if (!shutdown_thread_started_) {
          shutdown_thread_ =
              std::thread([this] { RunShutdownCoordinator(); });
          shutdown_thread_started_ = true;
        }
      }
      if (!initialized_) {
        const auto web_root = std::filesystem::absolute(args.document_root);
        ServiceListenerConfig listener;
        if (tls_material.has_value()) {
          tls_material_ = *tls_material;
          listener = BuildServiceListenerConfig(args.app_config->http,
                                                *tls_material_);
        } else {
          listener.bind_address = args.app_config->http.bind_ip;
          listener.port = args.app_config->http.port;
        }
        drogon::app().setThreadNum(4);
        drogon::app().disableSession();
        drogon::app().setClientMaxBodySize(kMaximumSecurityBodyBytes);
        drogon::app().setClientMaxMemoryBodySize(kMaximumSecurityBodyBytes);
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
        server_thread_ = internal::StartServiceThreadWithTlsOwner(
            tls_material_, [startup_signal, thread_completion] {
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
          auto error = common::Result<void>::Err(
              {"E_SERVICE_START",
               startup.error().message + "; " + stopped.error().message});
          Stop();
          return error;
        }
        Stop();
        return startup;
      }
    }
  } catch (const std::exception& ex) {
    Stop();
    return common::Result<void>::Err(
        {"E_SERVICE_START", std::string("failed to start service: ") + ex.what()});
  } catch (...) {
    Stop();
    return common::Result<void>::Err(
        {"E_SERVICE_START", "failed to start service"});
  }

  return common::Result<void>::Ok();
}

void ServiceApp::RunShutdownCoordinator() noexcept {
  trantor::EventLoop* drain_loop = nullptr;
  {
    std::unique_lock shutdown_lock(shutdown_mutex_);
    shutdown_condition_.wait(
        shutdown_lock, [this] { return shutdown_requested_; });
    drain_loop = shutdown_drain_loop_;
  }
  PerformShutdown(drain_loop);
  shutdown_condition_.notify_all();
}

void ServiceApp::PerformShutdown(trantor::EventLoop* drain_loop) noexcept {
  try {
    std::shared_ptr<BoundedWorker> security_worker;
    {
      std::scoped_lock lock(StateMutex());
      GlobalState().shutting_down = true;
      security_worker = GlobalState().security_worker;
    }
    if (security_worker) {
      security_worker->Stop();
    }

    if (running_ || server_thread_.joinable()) {
      try {
        auto drained = std::make_shared<std::promise<void>>();
        auto drained_future = drained->get_future();
        auto* loop = drain_loop != nullptr ? drain_loop : drogon::app().getLoop();
        loop->runAfter(0.01, [drained] {
          try {
            drained->set_value();
          } catch (...) {
          }
        });
        if (drained_future.wait_for(kServiceThreadStopTimeout) !=
            std::future_status::ready) {
          common::Logger::instance().log(
              common::Logger::Level::kWarn,
              "service event-loop response drain timed out");
        }
      } catch (...) {
        common::Logger::instance().log(
            common::Logger::Level::kWarn,
            "failed to schedule service response drain");
      }

      drogon::app().quit();
      if (server_thread_.joinable()) {
        if (server_thread_done_.valid() &&
            server_thread_done_.wait_for(kServiceThreadStopTimeout) !=
                std::future_status::ready) {
          common::Logger::instance().log(
              common::Logger::Level::kWarn,
              "service thread stop timed out; waiting for safe join");
        }
        server_thread_.join();
      }
      running_ = false;
    }
  } catch (...) {
    common::Logger::instance().log(common::Logger::Level::kWarn,
                                   "service shutdown failed");
  }

  {
    std::scoped_lock lock(StateMutex());
    GlobalState().args = {};
    GlobalState().security_worker.reset();
    GlobalState().device_state = security::DeviceState::kDefault;
    GlobalState().runtime_pending_peer.reset();
  }
  security_worker_.reset();
  tls_material_.reset();
  server_thread_done_ = {};
}

void ServiceApp::JoinShutdownCoordinator() noexcept {
  std::thread join_owner;
  {
    std::unique_lock shutdown_lock(shutdown_mutex_);
    shutdown_condition_.wait(
        shutdown_lock, [this] { return !shutdown_join_in_progress_; });
    if (!shutdown_thread_started_ || shutdown_thread_released_) {
      return;
    }
    shutdown_join_in_progress_ = true;
    shutdown_thread_released_ = true;
    join_owner = std::move(shutdown_thread_);
  }
  join_owner.join();
  {
    std::lock_guard shutdown_lock(shutdown_mutex_);
    shutdown_join_in_progress_ = false;
  }
  shutdown_condition_.notify_all();
}

void ServiceApp::BeginShutdown() noexcept {
  std::shared_ptr<BoundedWorker> security_worker;
  {
    std::scoped_lock lock(StateMutex());
    GlobalState().shutting_down = true;
    security_worker = GlobalState().security_worker;
  }
  if (security_worker) {
    try {
      security_worker->Stop();
    } catch (...) {
      common::Logger::instance().log(
          common::Logger::Level::kWarn,
          "failed to quiesce service security worker");
    }
  }
}

void ServiceApp::Stop() {
  auto* current_loop = trantor::EventLoop::getEventLoopOfCurrentThread();
  bool on_service_loop = false;
  if (current_loop != nullptr && drogon::app().isRunning()) {
    on_service_loop = current_loop == drogon::app().getLoop();
    for (std::size_t index = 0;
         !on_service_loop && index < drogon::app().getThreadNum(); ++index) {
      on_service_loop = current_loop == drogon::app().getIOLoop(index);
    }
  }
  BeginShutdown();

  bool coordinator_started = false;
  {
    std::lock_guard shutdown_lock(shutdown_mutex_);
    if (on_service_loop && shutdown_drain_loop_ == nullptr) {
      shutdown_drain_loop_ = current_loop;
    }
    shutdown_requested_ = true;
    coordinator_started = shutdown_thread_started_;
  }
  shutdown_condition_.notify_all();

  if (!coordinator_started) {
    PerformShutdown(nullptr);
    return;
  }
  if (!on_service_loop) {
    JoinShutdownCoordinator();
  }
}

}  // namespace camera_firmware::service
