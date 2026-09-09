#include "GstRtspClientLifecycle.hpp"

#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/rtsp/GstRtspDigestAuth.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <gst/rtsp-server/rtsp-client.h>
#include <gst/rtsp-server/rtsp-media-factory.h>
#include <gst/rtsp-server/rtsp-mount-points.h>
#include <gst/rtsp-server/rtsp-server.h>
#include <gtest/gtest.h>

namespace {

using camera_firmware::rtsp::internal::GstRtspClientLifecycle;
using namespace std::chrono_literals;

int FindFreeLoopbackPort() {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return 19555;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    close(fd);
    return 19555;
  }
  socklen_t size = sizeof(address);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
    close(fd);
    return 19555;
  }
  const int port = ntohs(address.sin_port);
  close(fd);
  return port;
}

int ConnectLoopback(int port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(static_cast<std::uint16_t>(port));
  if (connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) !=
      0) {
    close(fd);
    return -1;
  }
  return fd;
}

struct RequestGate {
  std::mutex mutex;
  std::condition_variable changed;
  bool entered{false};
  bool released{false};
};

struct ServerDeleter {
  void operator()(GstRTSPServer* server) const {
    if (server != nullptr) {
      g_object_unref(server);
    }
  }
};

struct ClientDeleter {
  void operator()(GstRTSPClient* client) const {
    if (client != nullptr) {
      g_object_unref(client);
    }
  }
};

TEST(GstRtspClientLifecycleTest, RejectsNullServer) {
  auto lifecycle = GstRtspClientLifecycle::Attach(nullptr);

  ASSERT_FALSE(lifecycle.ok());
  EXPECT_EQ(lifecycle.error().code, "E_RTSP_CLIENT_LIFECYCLE");
}

TEST(GstRtspClientLifecycleTest,
     CloseAndWaitBlocksUntilTrackedClientDispatchCloses) {
  gst_init(nullptr, nullptr);
  std::unique_ptr<GstRTSPServer, ServerDeleter> server(gst_rtsp_server_new());
  ASSERT_NE(server, nullptr);
  auto attached = GstRtspClientLifecycle::Attach(server.get());
  ASSERT_TRUE(attached.ok()) << attached.error().message;
  auto lifecycle = std::move(attached).value();
  std::unique_ptr<GstRTSPClient, ClientDeleter> client(gst_rtsp_client_new());
  ASSERT_NE(client, nullptr);
  g_signal_emit_by_name(server.get(), "client-connected", client.get());

  auto stopping = std::async(std::launch::async,
                             [&lifecycle] { lifecycle->CloseAndWait(); });

  EXPECT_EQ(stopping.wait_for(20ms), std::future_status::timeout);
  g_signal_emit_by_name(client.get(), "closed");
  EXPECT_EQ(stopping.wait_for(1s), std::future_status::ready);
  stopping.get();
}

TEST(GstRtspClientLifecycleTest, CloseAndWaitIsTerminalForLateClients) {
  gst_init(nullptr, nullptr);
  std::unique_ptr<GstRTSPServer, ServerDeleter> server(gst_rtsp_server_new());
  ASSERT_NE(server, nullptr);
  auto attached = GstRtspClientLifecycle::Attach(server.get());
  ASSERT_TRUE(attached.ok()) << attached.error().message;
  auto lifecycle = std::move(attached).value();

  lifecycle->CloseAndWait();

  std::unique_ptr<GstRTSPClient, ClientDeleter> client(gst_rtsp_client_new());
  ASSERT_NE(client, nullptr);
  g_signal_emit_by_name(server.get(), "client-connected", client.get());
  auto repeated = std::async(std::launch::async,
                             [&lifecycle] { lifecycle->CloseAndWait(); });
  EXPECT_EQ(repeated.wait_for(1s), std::future_status::ready);
  repeated.get();
}

TEST(GstRtspClientLifecycleTest,
     CloseAndWaitCoversActiveManagedRequestDispatch) {
  gst_init(nullptr, nullptr);
  const auto credentials =
      std::filesystem::temp_directory_path() /
      ("cf-client-lifecycle-" + std::to_string(getpid()) + ".credentials");
  {
    std::ofstream out(credentials, std::ios::binary | std::ios::trunc);
    out << "CFDIGEST1\noperator:rpi-camera:sha-256:" << std::string(64U, '0')
        << "\n";
  }
  std::filesystem::permissions(
      credentials,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace);

  auto gate = std::make_shared<RequestGate>();
  camera_firmware::rtsp::RtspDigestVerifierDependencies dependencies;
  dependencies.nonce.now_seconds = [gate] {
    std::unique_lock lock(gate->mutex);
    gate->entered = true;
    gate->changed.notify_all();
    gate->changed.wait(lock, [&gate] { return gate->released; });
    return std::uint64_t{1000U};
  };
  dependencies.nonce.random_bytes = [](std::size_t size) {
    camera_firmware::common::SecureBytes bytes;
    bytes.resize(size);
    std::fill(bytes.data(), bytes.data() + bytes.size(), 0xA5U);
    return camera_firmware::common::Result<
        camera_firmware::common::SecureBytes>::Ok(std::move(bytes));
  };
  camera_firmware::config::RtspClientAuthConfig auth_config;
  auth_config.enabled = true;
  auth_config.realm = "rpi-camera";
  auth_config.credential_file = credentials.string();
  auth_config.algorithms = {"sha-256"};
  auth_config.nonce_ttl_seconds = 30U;
  auto auth_result = camera_firmware::rtsp::NewGstCfRtspDigestAuth(
      auth_config, std::move(dependencies));
  ASSERT_TRUE(auth_result.ok()) << auth_result.error().message;
  GstRTSPAuth* auth = auth_result.value();

  std::unique_ptr<GstRTSPServer, ServerDeleter> server(gst_rtsp_server_new());
  ASSERT_NE(server, nullptr);
  const int port = FindFreeLoopbackPort();
  const std::string service = std::to_string(port);
  gst_rtsp_server_set_address(server.get(), "127.0.0.1");
  gst_rtsp_server_set_service(server.get(), service.c_str());
  gst_rtsp_server_set_auth(server.get(), auth);
  GstRTSPMountPoints* mounts = gst_rtsp_server_get_mount_points(server.get());
  GstRTSPMediaFactory* factory = gst_rtsp_media_factory_new();
  gst_rtsp_media_factory_set_launch(
      factory, "( videotestsrc ! rtph264pay name=pay0 pt=96 )");
  gst_rtsp_mount_points_add_factory(mounts, "/blocked", factory);
  g_object_unref(mounts);
  auto attached = GstRtspClientLifecycle::Attach(server.get());
  ASSERT_TRUE(attached.ok()) << attached.error().message;
  auto lifecycle = std::move(attached).value();

  GMainContext* context = g_main_context_new();
  GMainLoop* loop = g_main_loop_new(context, FALSE);
  const guint source_id = gst_rtsp_server_attach(server.get(), context);
  ASSERT_NE(source_id, 0U);
  std::thread loop_thread([context, loop] {
    g_main_context_push_thread_default(context);
    g_main_loop_run(loop);
    g_main_context_pop_thread_default(context);
  });

  const int client_fd = ConnectLoopback(port);
  EXPECT_GE(client_fd, 0);
  const std::string request = "DESCRIBE rtsp://127.0.0.1:" + service +
                              "/blocked RTSP/1.0\r\nCSeq: 1\r\n\r\n";
  const ssize_t sent = client_fd >= 0 ? send(client_fd, request.data(),
                                             request.size(), MSG_NOSIGNAL)
                                      : -1;
  EXPECT_EQ(sent, static_cast<ssize_t>(request.size()));
  bool request_entered = false;
  {
    std::unique_lock lock(gate->mutex);
    request_entered =
        gate->changed.wait_for(lock, 1s, [&gate] { return gate->entered; });
  }
  EXPECT_TRUE(request_entered);

  GSource* listener = g_main_context_find_source_by_id(context, source_id);
  EXPECT_NE(listener, nullptr);
  if (listener != nullptr) {
    g_source_destroy(listener);
  }
  auto stopping = std::async(std::launch::async,
                             [&lifecycle] { lifecycle->CloseAndWait(); });
  if (request_entered) {
    EXPECT_EQ(stopping.wait_for(20ms), std::future_status::timeout);
  }
  {
    std::lock_guard lock(gate->mutex);
    gate->released = true;
  }
  gate->changed.notify_all();
  const auto stopped = stopping.wait_for(1s);
  EXPECT_EQ(stopped, std::future_status::ready);
  if (stopped == std::future_status::ready) {
    stopping.get();
  }

  if (client_fd >= 0) {
    close(client_fd);
  }
  g_main_loop_quit(loop);
  g_main_context_wakeup(context);
  loop_thread.join();
  lifecycle.reset();
  gst_rtsp_server_set_auth(server.get(), nullptr);
  g_object_unref(auth);
  g_main_loop_unref(loop);
  g_main_context_unref(context);
  std::filesystem::remove(credentials);
}

}  // namespace
