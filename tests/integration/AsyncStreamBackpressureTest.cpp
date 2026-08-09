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

// A trial that hit a setup problem (no free port, no connection) rather than
// running the scenario. The child treats it as a hard failure so a broken
// environment cannot masquerade as a clean run.
constexpr int kTrialSetupFailedExitCode = 20;
// The scenario reproduces within the first ~10 trials (the unguarded build
// aborts in under 100 ms), so this is deep margin, not a tight race, while
// staying well inside the target's ctest timeout even under a saturated
// -j build.
constexpr int kTeardownTrials = 64;

// One teardown trial: an idle async stream (its node sits at the front of
// the write buffer list with nothing to write, so the channel is not
// writing) whose peer resets at the same moment the producer closes the
// stream. The abort needs handleClose (disableAll, status -> Disconnected,
// connectDestroyed queued) to run between the close callback being queued
// and its execution, so that the unguarded close branch re-enables writing
// on a connection whose channel is about to be removed. The interleaving is
// scheduler-dependent, so the trial is repeated with a varied pre-close
// yield; a single hit aborts the process.
// Returns true if the trial completed without the loop wedging.
bool RunOneAsyncStreamTeardownTrial(int index) {
  const auto port = ReserveLoopbackPort();
  if (port == 0U) {
    return false;
  }
  trantor::EventLoopThread loop_thread;
  loop_thread.run();
  auto* loop = loop_thread.getLoop();
  auto server = std::make_unique<trantor::TcpServer>(
      loop, trantor::InetAddress("127.0.0.1", port), "async-stream-teardown");

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
  if (client.get() < 0) {
    return false;
  }
  if (connected_future.wait_for(std::chrono::seconds(2)) !=
      std::future_status::ready) {
    return false;
  }
  auto stream = connected_future.get();
  if (!stream) {
    return false;
  }

  // A small write that drains immediately: the async node stays at the
  // front of the write buffer list with zero remaining bytes and the
  // channel stops writing — the idle live-stream state.
  const char marker = 'x';
  (void)stream->send(&marker, 1U);
  std::this_thread::sleep_for(std::chrono::milliseconds(2));

  // Reset the peer and close the stream as close together as possible so
  // their in-loop tasks interleave. The pre-close yield count, varied per
  // trial, walks the close callback across the handleClose/connectDestroyed
  // boundary over successive trials.
  struct linger hard_reset {
    1, 0
  };
  (void)::setsockopt(client.get(), SOL_SOCKET, SO_LINGER, &hard_reset,
                     sizeof(hard_reset));

  std::promise<void> reset_ready;
  auto reset_ready_future = reset_ready.get_future();
  std::thread resetter([&client, &reset_ready] {
    reset_ready.set_value();
    SocketFd discard(std::move(client));
  });
  reset_ready_future.wait();
  for (int spin = 0; spin < (index % 32); ++spin) {
    std::this_thread::yield();
  }
  stream->close();
  resetter.join();

  std::this_thread::sleep_for(std::chrono::milliseconds(5));

  std::promise<void> server_destroyed;
  auto server_destroyed_future = server_destroyed.get_future();
  loop->queueInLoop([&server, &server_destroyed] {
    server.reset();
    server_destroyed.set_value();
  });
  return server_destroyed_future.wait_for(std::chrono::seconds(2)) ==
         std::future_status::ready;
}

// Body of the death-test child. Extracted to a function because ASSERT_EXIT
// is a macro: an unparenthesised comma in its first argument (the linger
// initialiser) would be read as a macro argument separator.
[[noreturn]] void RunAsyncStreamTeardownRaceChild() {
  for (int index = 0; index < kTeardownTrials; ++index) {
    if (!RunOneAsyncStreamTeardownTrial(index)) {
      // _exit, not exit: the child was forked with a running EventLoopThread,
      // and atexit/static destructors must not run in it.
      ::_exit(kTrialSetupFailedExitCode);
    }
  }
  ::_exit(0);
}

TEST(AsyncStreamTeardownTest, PeerResetRacingAsyncCloseDoesNotAbortTheProcess) {
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  // Pins the teardown race that aborted the live firmware: a cross-thread
  // AsyncStream close whose in-loop task runs after the peer's handleClose
  // has disabled the channel re-enables writing on the dead connection,
  // and Channel::remove() in connectDestroyed then finds events_ !=
  // kNoneEvent and aborts. The scenario runs in the death-test child so the
  // abort, when the defect is present, kills the child, not the suite. Exit
  // 0 means all trials survived; a signal exit means the assert fired.
  ASSERT_EXIT(RunAsyncStreamTeardownRaceChild(),
              ::testing::ExitedWithCode(0), "");
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
