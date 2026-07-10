#include "GstRtspClientLifecycle.hpp"

#include <condition_variable>
#include <mutex>
#include <new>
#include <unordered_set>
#include <utility>

#include <gst/rtsp-server/rtsp-client.h>

namespace camera_firmware::rtsp::internal {

namespace {

GstRTSPFilterResult CloseClient(GstRTSPServer*, GstRTSPClient*, gpointer) {
  return GST_RTSP_FILTER_REMOVE;
}

}  // namespace

struct GstRtspClientLifecycle::Impl {
  static void OnClientClosed(GstRTSPClient* client, gpointer user_data) {
    auto* self = static_cast<Impl*>(user_data);
    if (self == nullptr) {
      return;
    }
    g_signal_handlers_disconnect_by_data(client, self);
    try {
      std::lock_guard lock(self->mutex);
      self->clients.erase(client);
      if (self->clients.empty()) {
        self->drained.notify_all();
      }
    } catch (...) {
    }
  }

  static void OnClientConnected(GstRTSPServer*,
                                GstRTSPClient* client,
                                gpointer user_data) {
    auto* self = static_cast<Impl*>(user_data);
    if (self == nullptr || client == nullptr) {
      return;
    }

    bool close_client = false;
    try {
      std::lock_guard lock(self->mutex);
      if (self->closing) {
        close_client = true;
      } else {
        self->clients.insert(client);
        const gulong handler = g_signal_connect_data(
            client,
            "closed",
            G_CALLBACK(OnClientClosed),
            self,
            nullptr,
            G_CONNECT_AFTER);
        if (handler == 0U) {
          self->clients.erase(client);
          if (self->clients.empty()) {
            self->drained.notify_all();
          }
          close_client = true;
        }
      }
    } catch (...) {
      close_client = true;
    }

    if (close_client) {
      gst_rtsp_client_close(client);
    }
  }

  void CloseAndWait() noexcept {
    {
      std::lock_guard lock(mutex);
      closing = true;
    }
    (void)gst_rtsp_server_client_filter(server, CloseClient, nullptr);
    std::unique_lock lock(mutex);
    drained.wait(lock, [this] { return clients.empty(); });
  }

  void Detach() noexcept {
    if (client_connected_handler != 0U) {
      g_signal_handler_disconnect(server, client_connected_handler);
      client_connected_handler = 0U;
    }
    if (server != nullptr) {
      g_object_unref(server);
      server = nullptr;
    }
  }

  GstRTSPServer* server{nullptr};
  gulong client_connected_handler{0U};
  std::mutex mutex;
  std::condition_variable drained;
  std::unordered_set<GstRTSPClient*> clients;
  bool closing{false};
};

GstRtspClientLifecycle::GstRtspClientLifecycle(
    std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

GstRtspClientLifecycle::~GstRtspClientLifecycle() {
  if (impl_ == nullptr) {
    return;
  }
  impl_->CloseAndWait();
  impl_->Detach();
}

common::Result<std::unique_ptr<GstRtspClientLifecycle>>
GstRtspClientLifecycle::Attach(GstRTSPServer* server) {
  if (server == nullptr || !GST_IS_RTSP_SERVER(server)) {
    return common::Result<std::unique_ptr<GstRtspClientLifecycle>>::Err(
        {"E_RTSP_CLIENT_LIFECYCLE", "RTSP server is unavailable"});
  }

  auto lifecycle = std::unique_ptr<GstRtspClientLifecycle>(
      new (std::nothrow) GstRtspClientLifecycle(nullptr));
  if (lifecycle == nullptr) {
    return common::Result<std::unique_ptr<GstRtspClientLifecycle>>::Err(
        {"E_RTSP_CLIENT_LIFECYCLE",
         "failed to allocate RTSP client lifecycle owner"});
  }
  std::unique_ptr<Impl> impl;
  try {
    impl = std::make_unique<Impl>();
  } catch (...) {
    return common::Result<std::unique_ptr<GstRtspClientLifecycle>>::Err(
        {"E_RTSP_CLIENT_LIFECYCLE",
         "failed to allocate RTSP client lifecycle state"});
  }
  impl->server = static_cast<GstRTSPServer*>(g_object_ref(server));
  impl->client_connected_handler = g_signal_connect_data(
      impl->server,
      "client-connected",
      G_CALLBACK(Impl::OnClientConnected),
      impl.get(),
      nullptr,
      G_CONNECT_DEFAULT);
  if (impl->client_connected_handler == 0U) {
    g_object_unref(impl->server);
    impl->server = nullptr;
    return common::Result<std::unique_ptr<GstRtspClientLifecycle>>::Err(
        {"E_RTSP_CLIENT_LIFECYCLE",
         "failed to observe RTSP client lifecycle"});
  }

  lifecycle->impl_ = std::move(impl);
  return common::Result<std::unique_ptr<GstRtspClientLifecycle>>::Ok(
      std::move(lifecycle));
}

void GstRtspClientLifecycle::CloseAndWait() noexcept {
  if (impl_ != nullptr) {
    impl_->CloseAndWait();
  }
}

}  // namespace camera_firmware::rtsp::internal
