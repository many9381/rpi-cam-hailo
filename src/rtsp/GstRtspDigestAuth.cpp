#include "camera_firmware/rtsp/GstRtspDigestAuth.hpp"

#include <gst/rtsp-server/rtsp-context.h>
#include <gst/rtsp-server/rtsp-token.h>
#include <gst/rtsp/gstrtspdefs.h>
#include <gst/rtsp/gstrtspmessage.h>

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <new>
#include <string_view>
#include <utility>

#include "camera_firmware/common/Logger.hpp"

namespace camera_firmware::rtsp {

struct GstCfRtspDigestAuthState {
  std::mutex mutex;
  std::condition_variable drained;
  RtspDigestVerifier* verifier{nullptr};
  std::size_t active_callbacks{0U};
  bool closing{false};
};

struct _GstCfRtspDigestAuth {
  GstRTSPAuth parent;
  GstCfRtspDigestAuthState* state;
  GstRTSPToken* viewer_token;
};

struct _GstCfRtspDigestAuthClass {
  GstRTSPAuthClass parent_class;
};

using GstCfRtspDigestAuth = struct _GstCfRtspDigestAuth;
using GstCfRtspDigestAuthClass = struct _GstCfRtspDigestAuthClass;

G_DEFINE_FINAL_TYPE(GstCfRtspDigestAuth,
                    gst_cf_rtsp_digest_auth,
                    GST_TYPE_RTSP_AUTH)

namespace {

using common::Logger;

constexpr std::string_view kViewerRole = "viewer";

class ActiveAdapterCallback {
 public:
  explicit ActiveAdapterCallback(GstCfRtspDigestAuth* self) noexcept {
    if (self == nullptr || self->state == nullptr) {
      return;
    }
    try {
      std::lock_guard lock(self->state->mutex);
      if (self->state->closing || self->state->verifier == nullptr) {
        return;
      }
      state_ = self->state;
      verifier_ = state_->verifier;
      ++state_->active_callbacks;
    } catch (...) {
      state_ = nullptr;
      verifier_ = nullptr;
    }
  }

  ~ActiveAdapterCallback() {
    if (state_ == nullptr) {
      return;
    }
    try {
      std::lock_guard lock(state_->mutex);
      if (state_->active_callbacks != 0U) {
        --state_->active_callbacks;
      }
      if (state_->active_callbacks == 0U) {
        state_->drained.notify_all();
      }
    } catch (...) {
    }
  }

  ActiveAdapterCallback(const ActiveAdapterCallback&) = delete;
  ActiveAdapterCallback& operator=(const ActiveAdapterCallback&) = delete;

  [[nodiscard]] RtspDigestVerifier* verifier() const noexcept {
    return verifier_;
  }

 private:
  GstCfRtspDigestAuthState* state_{nullptr};
  RtspDigestVerifier* verifier_{nullptr};
};

void LogAdapterFailure(std::string_view code,
                       std::string_view category) noexcept {
  try {
    std::string message;
    message.reserve(code.size() + category.size() + 24U);
    message.append(code);
    message.append(": category=");
    message.append(category);
    Logger::instance().log(Logger::Level::kError, message);
  } catch (...) {
  }
}

void ClearAuthenticateHeaders(GstRTSPMessage* response) {
  if (response == nullptr) {
    return;
  }
  while (gst_rtsp_message_remove_header(
             response, GST_RTSP_HDR_WWW_AUTHENTICATE, 0) == GST_RTSP_OK) {
  }
}

void ClearContextToken(GstRTSPContext* context) {
  if (context != nullptr) {
    context->token = nullptr;
  }
}

void AddDigestChallenges(RtspDigestVerifier* verifier,
                         GstRTSPContext* context,
                         bool stale) {
  if (context == nullptr || context->response == nullptr) {
    LogAdapterFailure("E_RTSP_AUTH_RESPONSE", "adapter-state");
    return;
  }

  ClearAuthenticateHeaders(context->response);
  if (verifier == nullptr) {
    LogAdapterFailure("E_RTSP_AUTH_CHALLENGE", "verifier-state");
    return;
  }

  auto challenges = verifier->BuildChallenges(stale);
  if (!challenges.ok()) {
    LogAdapterFailure("E_RTSP_AUTH_CHALLENGE", "digest-provider");
    return;
  }

  for (const auto& challenge : challenges.value()) {
    if (gst_rtsp_message_add_header(context->response,
                                    GST_RTSP_HDR_WWW_AUTHENTICATE,
                                    challenge.c_str()) != GST_RTSP_OK) {
      ClearAuthenticateHeaders(context->response);
      LogAdapterFailure("E_RTSP_AUTH_RESPONSE", "gstreamer-header");
      return;
    }
  }
}

RtspDigestVerifyStatus VerifyContextRequest(RtspDigestVerifier* verifier,
                                            GstRTSPContext* context) {
  if (verifier == nullptr || context == nullptr ||
      context->request == nullptr) {
    LogAdapterFailure("E_RTSP_AUTH_VERIFY", "adapter-state");
    return RtspDigestVerifyStatus::kRejected;
  }

  gchar* authorization = nullptr;
  if (gst_rtsp_message_get_header(context->request,
                                  GST_RTSP_HDR_AUTHORIZATION,
                                  &authorization,
                                  0) != GST_RTSP_OK ||
      authorization == nullptr) {
    return RtspDigestVerifyStatus::kRejected;
  }
  gchar* extra_authorization = nullptr;
  if (gst_rtsp_message_get_header(context->request,
                                  GST_RTSP_HDR_AUTHORIZATION,
                                  &extra_authorization,
                                  1) == GST_RTSP_OK) {
    return RtspDigestVerifyStatus::kRejected;
  }

  GstRTSPMethod request_method = GST_RTSP_INVALID;
  const gchar* request_target = nullptr;
  GstRTSPVersion version = GST_RTSP_VERSION_INVALID;
  if (gst_rtsp_message_parse_request(context->request,
                                     &request_method,
                                     &request_target,
                                     &version) != GST_RTSP_OK ||
      request_target == nullptr) {
    return RtspDigestVerifyStatus::kRejected;
  }
  const gchar* method_text = gst_rtsp_method_as_text(request_method);
  if (method_text == nullptr) {
    return RtspDigestVerifyStatus::kRejected;
  }

  auto verified =
      verifier->Verify({method_text, request_target, authorization});
  if (!verified.ok()) {
    LogAdapterFailure("E_RTSP_AUTH_VERIFY", "digest-provider");
    return RtspDigestVerifyStatus::kRejected;
  }
  return verified.value();
}

void SendUnauthorized(RtspDigestVerifier* verifier,
                      GstRTSPContext* context,
                      bool stale) {
  if (context == nullptr || context->request == nullptr ||
      context->response == nullptr || context->client == nullptr) {
    LogAdapterFailure("E_RTSP_AUTH_RESPONSE", "adapter-state");
    return;
  }

  (void)gst_rtsp_message_unset(context->response);
  if (gst_rtsp_message_init_response(context->response,
                                     GST_RTSP_STS_UNAUTHORIZED,
                                     gst_rtsp_status_as_text(
                                         GST_RTSP_STS_UNAUTHORIZED),
                                     context->request) != GST_RTSP_OK) {
    LogAdapterFailure("E_RTSP_AUTH_RESPONSE", "gstreamer-init");
    return;
  }
  AddDigestChallenges(verifier, context, stale);
  if (gst_rtsp_client_send_message(context->client,
                                   context->session,
                                   context->response) != GST_RTSP_OK) {
    LogAdapterFailure("E_RTSP_AUTH_RESPONSE", "gstreamer-send");
  }
}

gboolean Authenticate(GstRTSPAuth* auth, GstRTSPContext* context) {
  if (context == nullptr) {
    return FALSE;
  }
  ClearContextToken(context);
  auto* self = reinterpret_cast<GstCfRtspDigestAuth*>(auth);
  ActiveAdapterCallback callback(self);
  const auto status = VerifyContextRequest(callback.verifier(), context);
  if (status != RtspDigestVerifyStatus::kAuthenticated ||
      self->viewer_token == nullptr) {
    return FALSE;
  }
  context->token = self->viewer_token;
  return TRUE;
}

gboolean ParentCheck(GstRTSPAuth* auth,
                     GstRTSPContext* context,
                     const gchar* check) {
  auto* parent =
      GST_RTSP_AUTH_CLASS(gst_cf_rtsp_digest_auth_parent_class);
  return parent->check != nullptr ? parent->check(auth, context, check) : FALSE;
}

gboolean Check(GstRTSPAuth* auth,
               GstRTSPContext* context,
               const gchar* check) {
  auto* self = reinterpret_cast<GstCfRtspDigestAuth*>(auth);
  if (g_strcmp0(check, GST_RTSP_AUTH_CHECK_CONNECT) == 0) {
    return ParentCheck(auth, context, check);
  }
  if (g_strcmp0(check, GST_RTSP_AUTH_CHECK_URL) == 0 &&
      context != nullptr && context->method == GST_RTSP_OPTIONS) {
    ClearContextToken(context);
    return TRUE;
  }
  if (g_strcmp0(check, GST_RTSP_AUTH_CHECK_URL) == 0) {
    if (context == nullptr) {
      return FALSE;
    }
    ClearContextToken(context);
    ActiveAdapterCallback callback(self);
    const auto status = VerifyContextRequest(callback.verifier(), context);
    if (status == RtspDigestVerifyStatus::kAuthenticated &&
        self->viewer_token != nullptr) {
      context->token = self->viewer_token;
      return TRUE;
    }
    SendUnauthorized(callback.verifier(), context,
                     status == RtspDigestVerifyStatus::kStale);
    return FALSE;
  }
  return ParentCheck(auth, context, check);
}

void GenerateAuthenticateHeader(GstRTSPAuth* auth,
                                GstRTSPContext* context) {
  auto* self = reinterpret_cast<GstCfRtspDigestAuth*>(auth);
  ActiveAdapterCallback callback(self);
  AddDigestChallenges(callback.verifier(), context, false);
}

common::Result<void> ShutdownAdapter(GstCfRtspDigestAuth* self) {
  if (self == nullptr || self->state == nullptr) {
    return common::Result<void>::Err(
        {"E_RTSP_AUTH_STATE", "RTSP Digest auth state is unavailable"});
  }
  try {
    RtspDigestVerifier* verifier = nullptr;
    {
      std::unique_lock lock(self->state->mutex);
      self->state->closing = true;
      self->state->drained.wait(
          lock, [self] { return self->state->active_callbacks == 0U; });
      verifier = self->state->verifier;
    }
    if (verifier != nullptr) {
      verifier->Clear();
    }
    return common::Result<void>::Ok();
  } catch (...) {
    return common::Result<void>::Err(
        {"E_RTSP_AUTH_STATE", "RTSP Digest auth shutdown failed"});
  }
}

void Finalize(GObject* object) {
  auto* self = reinterpret_cast<GstCfRtspDigestAuth*>(object);
  if (self->state != nullptr) {
    (void)ShutdownAdapter(self);
    delete self->state->verifier;
    self->state->verifier = nullptr;
    delete self->state;
    self->state = nullptr;
  }
  if (self->viewer_token != nullptr) {
    gst_rtsp_token_unref(self->viewer_token);
    self->viewer_token = nullptr;
  }
  G_OBJECT_CLASS(gst_cf_rtsp_digest_auth_parent_class)->finalize(object);
}

}  // namespace

void gst_cf_rtsp_digest_auth_class_init(GstCfRtspDigestAuthClass* klass) {
  auto* object_class = G_OBJECT_CLASS(klass);
  object_class->finalize = Finalize;

  auto* auth_class = GST_RTSP_AUTH_CLASS(klass);
  auth_class->authenticate = Authenticate;
  auth_class->check = Check;
  auth_class->generate_authenticate_header = GenerateAuthenticateHeader;
}

void gst_cf_rtsp_digest_auth_init(GstCfRtspDigestAuth* self) {
  self->state = nullptr;
  self->viewer_token = gst_rtsp_token_new(GST_RTSP_TOKEN_MEDIA_FACTORY_ROLE,
                                           G_TYPE_STRING,
                                           kViewerRole.data(),
                                           nullptr);
  gst_rtsp_auth_set_supported_methods(GST_RTSP_AUTH(self),
                                      GST_RTSP_AUTH_DIGEST);
}

common::Result<GstRTSPAuth*> NewGstCfRtspDigestAuth(
    const config::RtspClientAuthConfig& config,
    RtspDigestVerifierDependencies dependencies) {
  auto verifier =
      RtspDigestVerifier::Create(config, std::move(dependencies));
  if (!verifier.ok()) {
    return common::Result<GstRTSPAuth*>::Err(verifier.error());
  }

  auto* self = static_cast<GstCfRtspDigestAuth*>(
      g_object_new(gst_cf_rtsp_digest_auth_get_type(), nullptr));
  if (self == nullptr || self->viewer_token == nullptr) {
    if (self != nullptr) {
      g_object_unref(self);
    }
    return common::Result<GstRTSPAuth*>::Err(
        {"E_RTSP_AUTH_ADAPTER", "failed to allocate RTSP Digest auth adapter"});
  }
  self->state = new (std::nothrow) GstCfRtspDigestAuthState();
  if (self->state == nullptr) {
    g_object_unref(self);
    return common::Result<GstRTSPAuth*>::Err(
        {"E_RTSP_AUTH_ADAPTER", "failed to allocate RTSP Digest auth state"});
  }
  self->state->verifier = std::move(verifier).value().release();
  return common::Result<GstRTSPAuth*>::Ok(GST_RTSP_AUTH(self));
}

common::Result<void> ReloadGstCfRtspDigestCredentials(GstRTSPAuth* auth) {
  if (!IsGstCfRtspDigestAuth(auth)) {
    return common::Result<void>::Err(
        {"E_RTSP_AUTH_TYPE", "RTSP auth object does not support credential reload"});
  }
  auto* self = reinterpret_cast<GstCfRtspDigestAuth*>(auth);
  ActiveAdapterCallback callback(self);
  if (callback.verifier() == nullptr) {
    return common::Result<void>::Err(
        {"E_RTSP_AUTH_STATE", "RTSP Digest verifier is unavailable"});
  }
  return callback.verifier()->ReloadCredentials();
}

common::Result<void> ShutdownGstCfRtspDigestAuth(GstRTSPAuth* auth) {
  if (!IsGstCfRtspDigestAuth(auth)) {
    return common::Result<void>::Err(
        {"E_RTSP_AUTH_TYPE", "RTSP auth object does not support shutdown"});
  }
  return ShutdownAdapter(reinterpret_cast<GstCfRtspDigestAuth*>(auth));
}

bool IsGstCfRtspDigestAuth(GstRTSPAuth* auth) noexcept {
  return auth != nullptr && G_TYPE_CHECK_INSTANCE_TYPE(
                                auth, gst_cf_rtsp_digest_auth_get_type());
}

}  // namespace camera_firmware::rtsp
