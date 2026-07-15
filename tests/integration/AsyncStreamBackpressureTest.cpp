#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <future>
#include <memory>
#include <thread>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <trantor/net/EventLoopThread.h>
#include <trantor/net/TcpServer.h>

#ifndef TRANTOR_CAMERA_FIRMWARE_BOUNDED_ASYNC_STREAM
#error "camera-firmware bounded async stream patch is required"
#endif

static_assert(trantor::kAsyncStreamPendingByteLimit == 1U * 1024U * 1024U);

namespace {

class SocketFd {
 public:
  explicit SocketFd(int descriptor = -1) noexcept : descriptor_(descriptor) {}
  ~SocketFd() {
    if (descriptor_ >= 0) {
      (void)::close(descriptor_);
    }
  }

  SocketFd(const SocketFd&) = delete;
  SocketFd& operator=(const SocketFd&) = delete;
  SocketFd(SocketFd&& other) noexcept
      : descriptor_(std::exchange(other.descriptor_, -1)) {}
  SocketFd& operator=(SocketFd&&) = delete;

  [[nodiscard]] int get() const noexcept { return descriptor_; }

 private:
  int descriptor_;
};

std::uint16_t ReserveLoopbackPort() {
  SocketFd socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (socket.get() < 0) {
    return 0U;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (::bind(socket.get(), reinterpret_cast<sockaddr*>(&address),
             sizeof(address)) != 0) {
    return 0U;
  }
  socklen_t size = sizeof(address);
  if (::getsockname(socket.get(), reinterpret_cast<sockaddr*>(&address),
                    &size) != 0) {
    return 0U;
  }
  return ntohs(address.sin_port);
}

SocketFd ConnectWithoutReading(std::uint16_t port) {
  SocketFd socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (socket.get() < 0) {
    return socket;
  }
  const int buffer_size = 4096;
  (void)::setsockopt(socket.get(), SOL_SOCKET, SO_RCVBUF, &buffer_size,
                     sizeof(buffer_size));

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(port);
  for (int attempt = 0; attempt < 100; ++attempt) {
    if (::connect(socket.get(), reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) == 0) {
      return socket;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return SocketFd();
}

TEST(AsyncStreamBackpressureTest, RejectsProducerBeforeSlowPeerQueues16MiB) {
  const auto port = ReserveLoopbackPort();
  ASSERT_NE(port, 0U);

  trantor::EventLoopThread loop_thread;
  loop_thread.run();
  auto server = std::make_unique<trantor::TcpServer>(
      loop_thread.getLoop(), trantor::InetAddress("127.0.0.1", port),
      "async-stream-backpressure");
  server->setAfterAcceptSockOptCallback([](int descriptor) {
    const int buffer_size = 4096;
    (void)::setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &buffer_size,
                       sizeof(buffer_size));
  });

  std::promise<trantor::AsyncStreamPtr> connected;
  auto connected_future = connected.get_future();
  std::atomic_bool stream_published{false};
  server->setConnectionCallback(
      [&connected, &stream_published](const trantor::TcpConnectionPtr& peer) {
        if (peer->connected() && !stream_published.exchange(true)) {
          connected.set_value(peer->sendAsyncStream());
        }
      });
  server->start();

  auto client = ConnectWithoutReading(port);
  ASSERT_GE(client.get(), 0);
  ASSERT_EQ(connected_future.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
  auto stream = connected_future.get();
  ASSERT_NE(stream, nullptr);

  constexpr std::size_t kChunkBytes = 16U * 1024U;
  constexpr std::size_t kMaximumAcceptedBytes = 16U * 1024U * 1024U;
  std::array<char, kChunkBytes> chunk{};
  std::size_t accepted_bytes = 0U;
  while (accepted_bytes < kMaximumAcceptedBytes &&
         stream->send(chunk.data(), chunk.size())) {
    accepted_bytes += chunk.size();
  }

  EXPECT_LT(accepted_bytes, kMaximumAcceptedBytes);
  stream->close();
  (void)::shutdown(client.get(), SHUT_RDWR);

  std::promise<void> server_destroyed;
  auto server_destroyed_future = server_destroyed.get_future();
  loop_thread.getLoop()->queueInLoop([&server, &server_destroyed] {
    server.reset();
    server_destroyed.set_value();
  });
  ASSERT_EQ(server_destroyed_future.wait_for(std::chrono::seconds(2)),
            std::future_status::ready);
}

}  // namespace
