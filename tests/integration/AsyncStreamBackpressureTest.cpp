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

#include <cstdio>
#include <string>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <gtest/gtest.h>
#include <trantor/net/EventLoopThread.h>
#include <trantor/net/TLSPolicy.h>
#include <trantor/net/TcpConnection.h>
#include <trantor/net/TcpServer.h>

#ifndef TRANTOR_CAMERA_FIRMWARE_BOUNDED_ASYNC_STREAM
#error "camera-firmware bounded async stream patch is required"
#endif

static_assert(trantor::kAsyncStreamPendingByteLimit == 4U * 1024U * 1024U);

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

// Reserve an ephemeral loopback port and HOLD it open (leaked fd) for the life
// of the process. Closing the reservation before the TcpServer binds leaves a
// window where the kernel can reassign the port; the server's later bind() then
// fails and trantor's Socket::bindAddress calls exit(1), killing the process.
// Holding the socket bound (SO_REUSEADDR, never listened on) reserves the port,
// and SO_REUSEADDR lets the server (reUseAddr=true by default) bind it too.
std::uint16_t ReserveLoopbackPort() {
  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0U;
  }
  const int reuse = 1;
  if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
    (void)::close(fd);
    return 0U;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    (void)::close(fd);
    return 0U;
  }
  socklen_t size = sizeof(address);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
    (void)::close(fd);
    return 0U;
  }
  // Leak the reservation socket so the port stays held until the server binds.
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
  ASSERT_EXIT(RunAsyncStreamTeardownRaceChild(), ::testing::ExitedWithCode(0),
              "");
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

// ---------------------------------------------------------------------------
// TLS teardown death test.
//
// writeRaw() is reached only from the TLS write callback (onSslWrite). Its
// partial-write branch re-arms write interest; the bug this pins is that it
// did so unconditionally, even when the connection had already left
// Connected. forceClose() reproduces that deterministically inside one
// in-loop task: it sets status_ to Disconnecting, calls handleClose()
// (status_ -> Disconnected, disableAll()), then tlsProviderPtr_->close(),
// which flushes a close alert through onSslWrite -> writeRaw(). If the peer
// socket buffer is full (the client completed the handshake and then stopped
// reading), that write EAGAINs and the unguarded branch calls enableWriting()
// on a channel handleClose() just disabled. connectDestroyed() then reaches
// Channel::remove(), whose assert(events_ == kNoneEvent) aborts the process.
// The guard (status_ == Connected) keeps writeRaw() from re-arming here.

// Minimal self-signed RSA cert + key written to disk for the TLS server.
bool WriteSelfSignedCert(const std::string& cert_path,
                         const std::string& key_path) {
  EVP_PKEY* pkey = EVP_RSA_gen(2048);
  if (pkey == nullptr) {
    return false;
  }
  X509* cert = X509_new();
  if (cert == nullptr) {
    EVP_PKEY_free(pkey);
    return false;
  }
  bool ok = true;
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  X509_gmtime_adj(X509_getm_notBefore(cert), 0);
  X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60L * 24L * 365L);
  ok = ok && X509_set_pubkey(cert, pkey) == 1;
  X509_NAME* name = X509_get_subject_name(cert);
  ok = ok &&
       X509_NAME_add_entry_by_txt(
           name, "CN", MBSTRING_ASC,
           reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) == 1;
  ok = ok && X509_set_issuer_name(cert, name) == 1;
  ok = ok && X509_sign(cert, pkey, EVP_sha256()) > 0;
  if (ok) {
    FILE* key_file = ::fopen(key_path.c_str(), "wb");
    ok = key_file != nullptr &&
         PEM_write_PrivateKey(key_file, pkey, nullptr, nullptr, 0, nullptr,
                              nullptr) == 1;
    if (key_file != nullptr) {
      (void)::fclose(key_file);
    }
  }
  if (ok) {
    FILE* cert_file = ::fopen(cert_path.c_str(), "wb");
    ok = cert_file != nullptr && PEM_write_X509(cert_file, cert) == 1;
    if (cert_file != nullptr) {
      (void)::fclose(cert_file);
    }
  }
  X509_free(cert);
  EVP_PKEY_free(pkey);
  return ok;
}

// A blocking TLS client that completes the handshake and then never reads, so
// the server's writes back up and its socket send buffer fills. SSL_set_fd
// uses a BIO_NOCLOSE socket BIO, so the fd is owned here, not by SSL_free.
class TlsClient {
 public:
  explicit TlsClient(std::uint16_t port) {
    fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0) {
      return;
    }
    const int buffer_size = 4096;
    (void)::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &buffer_size,
                       sizeof(buffer_size));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    bool connected = false;
    for (int attempt = 0; attempt < 100; ++attempt) {
      if (::connect(fd_, reinterpret_cast<sockaddr*>(&address),
                    sizeof(address)) == 0) {
        connected = true;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!connected) {
      return;
    }
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (ctx_ == nullptr) {
      return;
    }
    ssl_ = SSL_new(ctx_);
    if (ssl_ == nullptr) {
      return;
    }
    SSL_set_fd(ssl_, fd_);
    handshaked_ = SSL_connect(ssl_) == 1;
  }

  ~TlsClient() {
    if (ssl_ != nullptr) {
      SSL_free(ssl_);
    }
    if (ctx_ != nullptr) {
      SSL_CTX_free(ctx_);
    }
    if (fd_ >= 0) {
      (void)::close(fd_);
    }
  }

  TlsClient(const TlsClient&) = delete;
  TlsClient& operator=(const TlsClient&) = delete;

  [[nodiscard]] bool handshaked() const noexcept { return handshaked_; }

 private:
  int fd_ = -1;
  SSL_CTX* ctx_ = nullptr;
  SSL* ssl_ = nullptr;
  bool handshaked_ = false;
};

// One TLS teardown trial: handshake, back the server's send buffer up, then
// forceClose() so the close-alert flush hits writeRaw() with a full buffer
// after the channel is disabled. Returns false only on a setup failure.
bool RunOneTlsTeardownTrial(const std::string& cert_path,
                            const std::string& key_path) {
  const auto port = ReserveLoopbackPort();
  if (port == 0U) {
    return false;
  }
  trantor::EventLoopThread loop_thread;
  loop_thread.run();
  auto* loop = loop_thread.getLoop();
  auto server = std::make_unique<trantor::TcpServer>(
      loop, trantor::InetAddress("127.0.0.1", port), "tls-teardown");
  server->enableSSL(
      trantor::TLSPolicy::defaultServerPolicy(cert_path, key_path));
  server->setAfterAcceptSockOptCallback([](int descriptor) {
    const int buffer_size = 4096;
    (void)::setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &buffer_size,
                       sizeof(buffer_size));
  });

  std::promise<trantor::TcpConnectionPtr> connected;
  auto connected_future = connected.get_future();
  std::atomic_bool published{false};
  server->setConnectionCallback(
      [&connected, &published](const trantor::TcpConnectionPtr& peer) {
        if (peer->connected() && !published.exchange(true)) {
          connected.set_value(peer);
        }
      });
  server->start();

  TlsClient client(port);
  if (!client.handshaked()) {
    return false;
  }
  if (connected_future.wait_for(std::chrono::seconds(2)) !=
      std::future_status::ready) {
    return false;
  }
  auto peer = connected_future.get();
  if (!peer) {
    return false;
  }

  // Fill the send buffer and force the close in one in-loop step, with no
  // event iteration between them: send() partial-writes and buffers the rest
  // (socket buffer now full because the client never reads), then forceClose()
  // runs synchronously in the loop thread — handleClose() disables the channel
  // and close() flushes the ~24-byte close alert through onSslWrite ->
  // writeRaw(). With no drain window the tiny alert also EAGAINs, so the
  // partial-write branch runs while status_ is Disconnected. Any sleep here
  // lets TCP free enough space for the alert to write whole, and the branch is
  // never reached — the bug hid behind exactly that timing.
  const std::string blob(256U * 1024U, 'x');
  loop->queueInLoop([peer, blob] {
    peer->send(blob.data(), blob.size());
    peer->forceClose();
  });

  // connectDestroyed() is queued by the close callback; it reaches
  // Channel::remove() and aborts if writeRaw() re-armed write interest above.
  std::promise<void> server_destroyed;
  auto server_destroyed_future = server_destroyed.get_future();
  loop->queueInLoop([&server, &server_destroyed] {
    server.reset();
    server_destroyed.set_value();
  });
  return server_destroyed_future.wait_for(std::chrono::seconds(2)) ==
         std::future_status::ready;
}

// The reproduction is deterministic (the tiny close alert EAGAINs whenever the
// send buffer is full, with no timing window), so one trial suffices; a few
// add margin against a one-off setup hiccup (port reuse, handshake timing).
constexpr int kTlsTeardownTrials = 4;

// Death-test child body (extracted because ASSERT_EXIT is a macro). Under the
// threadsafe death-test style the child re-executes the binary and regenerates
// its own cert (a different pid than the parent's), so it removes them here;
// _exit skips atexit handlers, so the unlinks are explicit.
[[noreturn]] void RunTlsTeardownChild(const std::string& cert_path,
                                      const std::string& key_path) {
  for (int index = 0; index < kTlsTeardownTrials; ++index) {
    if (!RunOneTlsTeardownTrial(cert_path, key_path)) {
      (void)::unlink(cert_path.c_str());
      (void)::unlink(key_path.c_str());
      ::_exit(kTrialSetupFailedExitCode);
    }
  }
  (void)::unlink(cert_path.c_str());
  (void)::unlink(key_path.c_str());
  ::_exit(0);
}

TEST(TlsTeardownTest, CloseAlertFlushAfterDisableDoesNotAbortTheProcess) {
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  const std::string base =
      ::testing::TempDir() + "/tls-teardown-" + std::to_string(::getpid());
  const std::string cert_path = base + ".crt";
  const std::string key_path = base + ".key";
  ASSERT_TRUE(WriteSelfSignedCert(cert_path, key_path));

  // Exit 0 means every trial survived the close-alert flush; a signal exit
  // means Channel::remove()'s assert fired on a channel writeRaw() re-armed
  // after handleClose() disabled it.
  ASSERT_EXIT(RunTlsTeardownChild(cert_path, key_path),
              ::testing::ExitedWithCode(0), "");

  (void)::unlink(cert_path.c_str());
  (void)::unlink(key_path.c_str());
}

}  // namespace
