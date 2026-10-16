#include "camera_firmware/rtsp/GstRtspDigestAuth.hpp"

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"

#include <gst/gst.h>
#include <gst/rtsp-server/rtsp-context.h>
#include <gst/rtsp-server/rtsp-server.h>
#include <gst/rtsp/gstrtspmessage.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace camera_firmware::rtsp {
namespace {

using common::Result;
using common::SecureBytes;

constexpr std::string_view kRealm = "rpi-camera";
constexpr std::string_view kUsername = "operator";
constexpr std::string_view kOldPassword = "old-camera-secret";
constexpr std::string_view kNewPassword = "new-camera-secret";
constexpr std::string_view kUri = "rtsp://camera.local/imx708/main";
constexpr std::string_view kMethod = "DESCRIBE";
constexpr std::string_view kCnonce = "adapter-client-random";
constexpr std::string_view kNonceCount = "00000001";

std::span<const unsigned char> Bytes(std::string_view value) {
  return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 40> path{"/tmp/cf-gst-rtsp-auth-XXXXXX"};
    char* created = ::mkdtemp(path.data());
    if (created == nullptr) {
      throw std::system_error(errno, std::generic_category(), "mkdtemp");
    }
    path_ = created;
  }

  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  [[nodiscard]] std::filesystem::path File(std::string_view name) const {
    return path_ / name;
  }

 private:
  std::filesystem::path path_;
};

void WriteAll(int descriptor, std::string_view content) {
  std::size_t offset = 0U;
  while (offset < content.size()) {
    const ssize_t written =
        ::write(descriptor, content.data() + offset, content.size() - offset);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      throw std::system_error(errno, std::generic_category(), "write");
    }
    offset += static_cast<std::size_t>(written);
  }
}

void WriteFile(const std::filesystem::path& path, std::string_view content) {
  const int descriptor =
      ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (descriptor < 0) {
    throw std::system_error(errno, std::generic_category(), "open");
  }
  try {
    if (::fchmod(descriptor, 0600) != 0) {
      throw std::system_error(errno, std::generic_category(), "fchmod");
    }
    WriteAll(descriptor, content);
  } catch (...) {
    (void)::close(descriptor);
    throw;
  }
  if (::close(descriptor) != 0) {
    throw std::system_error(errno, std::generic_category(), "close");
  }
}

std::string Hex(const SecureBytes& bytes) {
  constexpr std::string_view kHex = "0123456789abcdef";
  std::string output(bytes.size() * 2U, '0');
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    output[index * 2U] = kHex[bytes.data()[index] >> 4U];
    output[index * 2U + 1U] = kHex[bytes.data()[index] & 0x0fU];
  }
  return output;
}

std::string CredentialRecord(std::string_view password,
                             RtspDigestAlgorithm algorithm) {
  auto ha1 =
      ComputeRtspDigestHa1(algorithm, kUsername, kRealm, Bytes(password));
  if (!ha1.ok()) {
    throw std::runtime_error("failed to calculate test credential");
  }
  return std::string(kUsername) + ":" + std::string(kRealm) + ":" +
         std::string(RtspDigestConfigName(algorithm)) + ":" + Hex(ha1.value()) +
         "\n";
}

std::string CredentialFile(std::string_view password,
                           bool include_md5 = false) {
  std::string content = "CFDIGEST1\n";
  content += CredentialRecord(password, RtspDigestAlgorithm::kSha256);
  if (include_md5) {
    content += CredentialRecord(password, RtspDigestAlgorithm::kMd5);
  }
  return content;
}

struct DeterministicNonceInputs {
  std::shared_ptr<std::atomic<std::uint64_t>> now =
      std::make_shared<std::atomic<std::uint64_t>>(100U);
  std::shared_ptr<std::atomic<unsigned int>> calls =
      std::make_shared<std::atomic<unsigned int>>(0U);
  std::shared_ptr<std::atomic<bool>> fail_nonce_random =
      std::make_shared<std::atomic<bool>>(false);
  std::shared_ptr<std::atomic<bool>> block_next_clock =
      std::make_shared<std::atomic<bool>>(false);
  std::shared_ptr<std::mutex> clock_mutex = std::make_shared<std::mutex>();
  std::shared_ptr<std::condition_variable> clock_condition =
      std::make_shared<std::condition_variable>();
  std::shared_ptr<bool> clock_entered = std::make_shared<bool>(false);
  std::shared_ptr<bool> release_clock = std::make_shared<bool>(false);

  RtspDigestVerifierDependencies Dependencies() const {
    RtspDigestVerifierDependencies dependencies;
    dependencies.nonce.now_seconds =
        [clock = now, block = block_next_clock, mutex = clock_mutex,
         condition = clock_condition, entered = clock_entered,
         release = release_clock]() {
          if (block->exchange(false, std::memory_order_acq_rel)) {
            std::unique_lock lock(*mutex);
            *entered = true;
            condition->notify_all();
            condition->wait(lock, [&release] { return *release; });
          }
          return clock->load(std::memory_order_relaxed);
        };
    dependencies.nonce.random_bytes =
        [counter = calls, fail_nonce = fail_nonce_random](std::size_t size) {
          if (size != 32U && size != 16U) {
            return Result<SecureBytes>::Err(
                {"E_TEST_RANDOM", "unexpected random byte request"});
          }
          if (size == 16U && fail_nonce->load(std::memory_order_acquire)) {
            return Result<SecureBytes>::Err(
                {"E_TEST_RANDOM", "injected nonce random failure"});
          }
          const unsigned int call =
              counter->fetch_add(1U, std::memory_order_relaxed);
          SecureBytes bytes;
          bytes.resize(size);
          const auto seed = static_cast<unsigned char>(
              (size == 32U ? 0x20U : 0x80U) + (call & 0x0fU));
          for (std::size_t index = 0U; index < size; ++index) {
            bytes.data()[index] = static_cast<unsigned char>(
                seed + static_cast<unsigned char>(index));
          }
          return Result<SecureBytes>::Ok(std::move(bytes));
        };
    return dependencies;
  }
};

config::RtspClientAuthConfig AuthConfig(
    const std::filesystem::path& credentials, bool include_md5 = false) {
  config::RtspClientAuthConfig config;
  config.enabled = true;
  config.realm = kRealm;
  config.credential_file = credentials.string();
  config.algorithms = include_md5 ? std::vector<std::string>{"sha-256", "md5"}
                                  : std::vector<std::string>{"sha-256"};
  config.nonce_ttl_seconds = 30U;
  return config;
}

struct AuthDeleter {
  void operator()(GstRTSPAuth* auth) const {
    if (auth != nullptr) {
      g_object_unref(auth);
    }
  }
};

using AuthPtr = std::unique_ptr<GstRTSPAuth, AuthDeleter>;

class CurrentRtspContext {
 public:
  explicit CurrentRtspContext(GstRTSPContext* context) : context_(context) {
    gst_rtsp_context_push_current(context_);
  }

  ~CurrentRtspContext() { gst_rtsp_context_pop_current(context_); }

  CurrentRtspContext(const CurrentRtspContext&) = delete;
  CurrentRtspContext& operator=(const CurrentRtspContext&) = delete;

 private:
  GstRTSPContext* context_;
};

void ClearContextToken(GstRTSPContext* context) {
  context->token = nullptr;
}

AuthPtr CreateAuth(const config::RtspClientAuthConfig& config,
                   const DeterministicNonceInputs& inputs) {
  auto created = NewGstCfRtspDigestAuth(config, inputs.Dependencies());
  EXPECT_TRUE(created.ok())
      << (created.ok() ? std::string{} : created.error().message);
  return AuthPtr(created.ok() ? created.value() : nullptr);
}

std::string Header(GstRTSPMessage* message, GstRTSPHeaderField field,
                   int index) {
  gchar* value = nullptr;
  if (gst_rtsp_message_get_header(message, field, &value, index) !=
          GST_RTSP_OK ||
      value == nullptr) {
    return {};
  }
  return value;
}

std::string ChallengeNonce(std::string_view challenge) {
  constexpr std::string_view kPrefix = "nonce=\"";
  const std::size_t begin = challenge.find(kPrefix);
  if (begin == std::string_view::npos) {
    throw std::runtime_error("challenge nonce is missing");
  }
  const std::size_t value_begin = begin + kPrefix.size();
  const std::size_t end = challenge.find('"', value_begin);
  if (end == std::string_view::npos) {
    throw std::runtime_error("challenge nonce is unterminated");
  }
  return std::string(challenge.substr(value_begin, end - value_begin));
}

std::string BuildAuthorization(std::string_view password,
                               std::string_view nonce,
                               std::string_view method = kMethod) {
  auto ha1 = ComputeRtspDigestHa1(RtspDigestAlgorithm::kSha256, kUsername,
                                  kRealm, Bytes(password));
  if (!ha1.ok()) {
    throw std::runtime_error("failed to calculate test HA1");
  }
  auto response = ComputeRtspDigestResponse(
      RtspDigestAlgorithm::kSha256, {ha1.value().data(), ha1.value().size()},
      method, kUri, nonce, kNonceCount, kCnonce);
  if (!response.ok()) {
    throw std::runtime_error("failed to calculate test response");
  }
  return "Digest username=\"" + std::string(kUsername) + "\", realm=\"" +
         std::string(kRealm) + "\", nonce=\"" + std::string(nonce) +
         "\", uri=\"" + std::string(kUri) + "\", response=\"" +
         Hex(response.value()) +
         "\", algorithm=SHA-256, qop=auth, nc=" + std::string(kNonceCount) +
         ", cnonce=\"" + std::string(kCnonce) + "\"";
}

std::string IssueChallenge(GstRTSPAuth* auth) {
  GstRTSPMessage request{};
  GstRTSPMessage response{};
  EXPECT_EQ(gst_rtsp_message_init_request(&request, GST_RTSP_DESCRIBE,
                                          std::string(kUri).c_str()),
            GST_RTSP_OK);
  EXPECT_EQ(gst_rtsp_message_init_response(&response, GST_RTSP_STS_UNAUTHORIZED,
                                           nullptr, &request),
            GST_RTSP_OK);
  GstRTSPContext context{};
  context.request = &request;
  context.response = &response;
  context.method = GST_RTSP_DESCRIBE;

  auto* klass = GST_RTSP_AUTH_GET_CLASS(auth);
  klass->generate_authenticate_header(auth, &context);
  const std::string challenge =
      Header(&response, GST_RTSP_HDR_WWW_AUTHENTICATE, 0);
  const std::string nonce = ChallengeNonce(challenge);
  (void)gst_rtsp_message_unset(&response);
  (void)gst_rtsp_message_unset(&request);
  return nonce;
}

gboolean CheckUrl(GstRTSPAuth* auth, GstRTSPContext* context) {
  CurrentRtspContext current(context);
  auto* klass = GST_RTSP_AUTH_GET_CLASS(auth);
  return klass->check(auth, context, GST_RTSP_AUTH_CHECK_URL);
}

struct SentMessageCapture {
  int count{0};
  GstRTSPResult response_parse_result{GST_RTSP_ERROR};
  GstRTSPStatusCode status{GST_RTSP_STS_OK};
  std::vector<std::string> challenges;
};

gboolean CaptureSentMessage(GstRTSPClient*, GstRTSPMessage* message, gboolean,
                            gpointer user_data) {
  auto* capture = static_cast<SentMessageCapture*>(user_data);
  ++capture->count;
  capture->response_parse_result = gst_rtsp_message_parse_response(
      message, &capture->status, nullptr, nullptr);
  for (int index = 0;; ++index) {
    const std::string challenge =
        Header(message, GST_RTSP_HDR_WWW_AUTHENTICATE, index);
    if (challenge.empty()) {
      break;
    }
    capture->challenges.push_back(challenge);
  }
  return TRUE;
}

TEST(GstRtspDigestAuthTest, FactoryCreatesCustomAuthWithoutDefaultToken) {
  TemporaryDirectory directory;
  const auto credentials = directory.File("credentials");
  WriteFile(credentials, CredentialFile(kOldPassword));
  DeterministicNonceInputs inputs;

  AuthPtr auth = CreateAuth(AuthConfig(credentials), inputs);

  ASSERT_NE(auth, nullptr);
  EXPECT_TRUE(IsGstCfRtspDigestAuth(auth.get()));
  EXPECT_EQ(G_OBJECT_TYPE(auth.get()), gst_cf_rtsp_digest_auth_get_type());
  EXPECT_TRUE(g_type_test_flags(G_OBJECT_TYPE(auth.get()), G_TYPE_FLAG_FINAL));
  EXPECT_EQ(gst_rtsp_auth_get_default_token(auth.get()), nullptr);
  EXPECT_EQ(gst_rtsp_auth_get_supported_methods(auth.get()),
            GST_RTSP_AUTH_DIGEST);
}

TEST(GstRtspDigestAuthTest, OptionsUrlCheckDoesNotRequireAuthorization) {
  TemporaryDirectory directory;
  const auto credentials = directory.File("credentials");
  WriteFile(credentials, CredentialFile(kOldPassword));
  DeterministicNonceInputs inputs;
  AuthPtr auth = CreateAuth(AuthConfig(credentials), inputs);
  ASSERT_NE(auth, nullptr);

  GstRTSPMessage request{};
  ASSERT_EQ(gst_rtsp_message_init_request(&request, GST_RTSP_OPTIONS,
                                          std::string(kUri).c_str()),
            GST_RTSP_OK);
  GstRTSPContext context{};
  context.request = &request;
  context.method = GST_RTSP_OPTIONS;
  GstRTSPToken* previous = gst_rtsp_token_new_empty();
  context.token = previous;

  EXPECT_TRUE(CheckUrl(auth.get(), &context));
  EXPECT_EQ(context.token, nullptr);

  ClearContextToken(&context);
  gst_rtsp_token_unref(previous);
  (void)gst_rtsp_message_unset(&request);
}

TEST(GstRtspDigestAuthTest, ProtectedUrlCheckCreatesViewerToken) {
  TemporaryDirectory directory;
  const auto credentials = directory.File("credentials");
  WriteFile(credentials, CredentialFile(kOldPassword));
  DeterministicNonceInputs inputs;
  AuthPtr auth = CreateAuth(AuthConfig(credentials), inputs);
  ASSERT_NE(auth, nullptr);
  const std::string nonce = IssueChallenge(auth.get());
  const std::string authorization = BuildAuthorization(kOldPassword, nonce);

  GstRTSPMessage request{};
  ASSERT_EQ(gst_rtsp_message_init_request(&request, GST_RTSP_DESCRIBE,
                                          std::string(kUri).c_str()),
            GST_RTSP_OK);
  ASSERT_EQ(gst_rtsp_message_add_header(&request, GST_RTSP_HDR_AUTHORIZATION,
                                        authorization.c_str()),
            GST_RTSP_OK);
  GstRTSPContext context{};
  context.request = &request;
  context.method = GST_RTSP_DESCRIBE;

  EXPECT_TRUE(CheckUrl(auth.get(), &context));
  ASSERT_NE(context.token, nullptr);
  EXPECT_STREQ(gst_rtsp_token_get_string(context.token,
                                         GST_RTSP_TOKEN_MEDIA_FACTORY_ROLE),
               "viewer");
  const gint viewer_refcount = GST_MINI_OBJECT_REFCOUNT_VALUE(context.token);
  EXPECT_EQ(viewer_refcount, 1);

  ClearContextToken(&context);
  (void)gst_rtsp_message_unset(&request);

  const std::string next_nonce = IssueChallenge(auth.get());
  const std::string next_authorization =
      BuildAuthorization(kOldPassword, next_nonce);
  ASSERT_EQ(gst_rtsp_message_init_request(&request, GST_RTSP_DESCRIBE,
                                          std::string(kUri).c_str()),
            GST_RTSP_OK);
  ASSERT_EQ(gst_rtsp_message_add_header(&request, GST_RTSP_HDR_AUTHORIZATION,
                                        next_authorization.c_str()),
            GST_RTSP_OK);
  context.request = &request;

  EXPECT_TRUE(CheckUrl(auth.get(), &context));
  ASSERT_NE(context.token, nullptr);
  EXPECT_EQ(GST_MINI_OBJECT_REFCOUNT_VALUE(context.token), viewer_refcount);

  ClearContextToken(&context);
  (void)gst_rtsp_message_unset(&request);
}

TEST(GstRtspDigestAuthTest, OptionsWithSessionSelectorsRequiresAuthorization) {
  TemporaryDirectory directory;
  const auto credentials = directory.File("credentials");
  WriteFile(credentials, CredentialFile(kOldPassword));
  DeterministicNonceInputs inputs;
  AuthPtr auth = CreateAuth(AuthConfig(credentials), inputs);
  ASSERT_NE(auth, nullptr);

  for (const auto header :
       {GST_RTSP_HDR_SESSION, GST_RTSP_HDR_PIPELINED_REQUESTS}) {
    for (const char* value : {"active-session", ""}) {
      GstRTSPMessage request{};
      GstRTSPMessage response{};
      ASSERT_EQ(gst_rtsp_message_init_request(&request, GST_RTSP_OPTIONS,
                                              std::string(kUri).c_str()),
                GST_RTSP_OK);
      ASSERT_EQ(gst_rtsp_message_add_header(&request, header, value),
                GST_RTSP_OK);
      GstRTSPClient* client = gst_rtsp_client_new();
      SentMessageCapture capture;
      gst_rtsp_client_set_send_func(client, CaptureSentMessage, &capture,
                                    nullptr);
      GstRTSPContext context{};
      context.client = client;
      context.request = &request;
      context.response = &response;
      context.method = GST_RTSP_OPTIONS;

      EXPECT_FALSE(CheckUrl(auth.get(), &context));
      EXPECT_EQ(context.token, nullptr);
      EXPECT_EQ(capture.count, 1);
      EXPECT_EQ(capture.status, GST_RTSP_STS_UNAUTHORIZED);
      EXPECT_EQ(capture.challenges.size(), 1U);

      gst_object_unref(client);
      (void)gst_rtsp_message_unset(&request);
      (void)gst_rtsp_message_unset(&response);
    }
  }
}

TEST(GstRtspDigestAuthTest, RejectedRequestDoesNotWatchExistingSession) {
  TemporaryDirectory directory;
  const auto credentials = directory.File("credentials");
  WriteFile(credentials, CredentialFile(kOldPassword));
  DeterministicNonceInputs inputs;
  AuthPtr auth = CreateAuth(AuthConfig(credentials), inputs);
  ASSERT_NE(auth, nullptr);

  GstRTSPSessionPool* pool = gst_rtsp_session_pool_new();
  GstRTSPSession* session = gst_rtsp_session_pool_create(pool);
  GstRTSPClient* client = gst_rtsp_client_new();
  gst_rtsp_client_set_session_pool(client, pool);
  gst_rtsp_client_set_auth(client, auth.get());
  SentMessageCapture capture;
  gst_rtsp_client_set_send_func(client, CaptureSentMessage, &capture, nullptr);
  GstRTSPMessage request{};
  ASSERT_EQ(gst_rtsp_message_init_request(&request, GST_RTSP_PLAY,
                                          std::string(kUri).c_str()),
            GST_RTSP_OK);
  ASSERT_EQ(
      gst_rtsp_message_add_header(&request, GST_RTSP_HDR_SESSION,
                                  gst_rtsp_session_get_sessionid(session)),
      GST_RTSP_OK);
  ASSERT_EQ(gst_rtsp_message_add_header(&request, GST_RTSP_HDR_CSEQ, "1"),
            GST_RTSP_OK);

  const gint64 fixed_now = g_get_monotonic_time();
  const gint timeout_before =
      gst_rtsp_session_next_timeout_usec(session, fixed_now);
  ASSERT_GT(timeout_before, 0);
  // next_timeout_usec returns milliseconds; separate any accidental touch
  // from the initial value without waiting for the real session to expire.
  g_usleep(5000);
  EXPECT_EQ(gst_rtsp_client_handle_message(client, &request), GST_RTSP_OK);
  EXPECT_EQ(capture.status, GST_RTSP_STS_UNAUTHORIZED);
  EXPECT_EQ(gst_rtsp_session_next_timeout_usec(session, fixed_now),
            timeout_before);
  GList* watched = gst_rtsp_client_session_filter(client, nullptr, nullptr);
  EXPECT_EQ(g_list_length(watched), 0U);
  g_list_free_full(watched, g_object_unref);

  (void)gst_rtsp_message_unset(&request);
  gst_rtsp_session_pool_remove(pool, session);
  g_object_unref(session);
  g_object_unref(client);
  g_object_unref(pool);
}

TEST(GstRtspDigestAuthTest, UnsolicitedResponseDoesNotWatchExistingSession) {
  gst_init(nullptr, nullptr);
  GstRTSPSessionPool* pool = gst_rtsp_session_pool_new();
  GstRTSPSession* session = gst_rtsp_session_pool_create(pool);
  GstRTSPClient* client = gst_rtsp_client_new();
  gst_rtsp_client_set_session_pool(client, pool);
  GstRTSPMessage response{};
  ASSERT_EQ(gst_rtsp_message_init_response(&response, GST_RTSP_STS_OK, nullptr,
                                           nullptr),
            GST_RTSP_OK);
  ASSERT_EQ(
      gst_rtsp_message_add_header(&response, GST_RTSP_HDR_SESSION,
                                  gst_rtsp_session_get_sessionid(session)),
      GST_RTSP_OK);
  ASSERT_EQ(gst_rtsp_message_add_header(&response, GST_RTSP_HDR_CSEQ, "1"),
            GST_RTSP_OK);

  const gint64 fixed_now = g_get_monotonic_time();
  const gint timeout_before =
      gst_rtsp_session_next_timeout_usec(session, fixed_now);
  ASSERT_GT(timeout_before, 0);
  g_usleep(5000);
  EXPECT_EQ(gst_rtsp_client_handle_message(client, &response), GST_RTSP_OK);
  EXPECT_EQ(gst_rtsp_session_next_timeout_usec(session, fixed_now),
            timeout_before);
  GList* watched = gst_rtsp_client_session_filter(client, nullptr, nullptr);
  EXPECT_EQ(g_list_length(watched), 0U);
  g_list_free_full(watched, g_object_unref);

  (void)gst_rtsp_message_unset(&response);
  gst_rtsp_session_pool_remove(pool, session);
  g_object_unref(session);
  g_object_unref(client);
  g_object_unref(pool);
}

TEST(GstRtspDigestAuthTest,
     ResponseForAuthenticatedSessionStillReachesHandler) {
  TemporaryDirectory directory;
  const auto credentials = directory.File("credentials");
  WriteFile(credentials, CredentialFile(kOldPassword));
  DeterministicNonceInputs inputs;
  AuthPtr auth = CreateAuth(AuthConfig(credentials), inputs);
  ASSERT_NE(auth, nullptr);
  const auto authorization =
      BuildAuthorization(kOldPassword, IssueChallenge(auth.get()), "OPTIONS");
  GstRTSPSessionPool* pool = gst_rtsp_session_pool_new();
  GstRTSPSession* session = gst_rtsp_session_pool_create(pool);
  GstRTSPClient* client = gst_rtsp_client_new();
  gst_rtsp_client_set_session_pool(client, pool);
  gst_rtsp_client_set_auth(client, auth.get());
  SentMessageCapture sent;
  gst_rtsp_client_set_send_func(client, CaptureSentMessage, &sent, nullptr);
  GstRTSPMessage request{};
  ASSERT_EQ(gst_rtsp_message_init_request(&request, GST_RTSP_OPTIONS,
                                          std::string(kUri).c_str()),
            GST_RTSP_OK);
  gst_rtsp_message_add_header(&request, GST_RTSP_HDR_CSEQ, "1");
  gst_rtsp_message_add_header(&request, GST_RTSP_HDR_SESSION,
                              gst_rtsp_session_get_sessionid(session));
  gst_rtsp_message_add_header(&request, GST_RTSP_HDR_AUTHORIZATION,
                              authorization.c_str());
  ASSERT_EQ(gst_rtsp_client_handle_message(client, &request), GST_RTSP_OK);
  ASSERT_EQ(sent.count, 1);
  ASSERT_EQ(sent.status, GST_RTSP_STS_OK);

  struct HandledResponse {
    int count{0};
    GstRTSPSession* session{nullptr};
  } handled;
  const auto handler =
      +[](GstRTSPClient*, GstRTSPContext* context, gpointer data) {
        auto* capture = static_cast<HandledResponse*>(data);
        ++capture->count;
        capture->session = context->session;
      };
  g_signal_connect(client, "handle-response", G_CALLBACK(handler), &handled);
  GstRTSPMessage response{};
  gst_rtsp_message_init_response(&response, GST_RTSP_STS_OK, nullptr, nullptr);
  gst_rtsp_message_add_header(&response, GST_RTSP_HDR_CSEQ, "2");
  gst_rtsp_message_add_header(&response, GST_RTSP_HDR_SESSION,
                              gst_rtsp_session_get_sessionid(session));
  const gint64 fixed_now = g_get_monotonic_time();
  const gint timeout_before =
      gst_rtsp_session_next_timeout_usec(session, fixed_now);
  g_usleep(5000);
  EXPECT_EQ(gst_rtsp_client_handle_message(client, &response), GST_RTSP_OK);
  EXPECT_EQ(handled.count, 1);
  EXPECT_EQ(handled.session, session);
  EXPECT_GT(gst_rtsp_session_next_timeout_usec(session, fixed_now),
            timeout_before);
  GList* watched = gst_rtsp_client_session_filter(client, nullptr, nullptr);
  EXPECT_EQ(g_list_length(watched), 1U);
  EXPECT_EQ(watched == nullptr ? nullptr : watched->data, session);
  g_list_free_full(watched, g_object_unref);

  (void)gst_rtsp_message_unset(&request);
  (void)gst_rtsp_message_unset(&response);
  gst_rtsp_session_pool_remove(pool, session);
  g_object_unref(session);
  g_object_unref(client);
  g_object_unref(pool);
}

TEST(GstRtspDigestAuthTest, UnauthorizedCheckAddsOnlyDigestChallenges) {
  TemporaryDirectory directory;
  const auto credentials = directory.File("credentials");
  WriteFile(credentials, CredentialFile(kOldPassword, true));
  DeterministicNonceInputs inputs;
  AuthPtr auth = CreateAuth(AuthConfig(credentials, true), inputs);
  ASSERT_NE(auth, nullptr);

  GstRTSPMessage request{};
  GstRTSPMessage response{};
  ASSERT_EQ(gst_rtsp_message_init_request(&request, GST_RTSP_DESCRIBE,
                                          std::string(kUri).c_str()),
            GST_RTSP_OK);
  ASSERT_EQ(gst_rtsp_message_add_header(&request, GST_RTSP_HDR_AUTHORIZATION,
                                        "Digest malformed"),
            GST_RTSP_OK);
  ASSERT_EQ(gst_rtsp_message_add_header(&request, GST_RTSP_HDR_AUTHORIZATION,
                                        "Basic Zm9vOmJhcg=="),
            GST_RTSP_OK);
  GstRTSPClient* client = gst_rtsp_client_new();
  ASSERT_NE(client, nullptr);
  SentMessageCapture capture;
  gst_rtsp_client_set_send_func(client, CaptureSentMessage, &capture, nullptr);
  GstRTSPContext context{};
  context.client = client;
  context.request = &request;
  context.response = &response;
  context.method = GST_RTSP_DESCRIBE;
  GstRTSPToken* previous = gst_rtsp_token_new_empty();
  context.token = previous;

  EXPECT_FALSE(CheckUrl(auth.get(), &context));
  EXPECT_EQ(context.token, nullptr);
  ASSERT_EQ(capture.count, 1);
  ASSERT_EQ(capture.response_parse_result, GST_RTSP_OK);
  EXPECT_EQ(capture.status, GST_RTSP_STS_UNAUTHORIZED);
  ASSERT_EQ(capture.challenges.size(), 2U);
  const std::string& sha = capture.challenges[0];
  const std::string& md5 = capture.challenges[1];
  EXPECT_EQ(sha.find("Digest "), 0U);
  EXPECT_NE(sha.find("algorithm=SHA-256"), std::string::npos);
  EXPECT_EQ(md5.find("Digest "), 0U);
  EXPECT_NE(md5.find("algorithm=MD5"), std::string::npos);
  EXPECT_EQ(sha.find("Basic"), std::string::npos);
  EXPECT_EQ(md5.find("Basic"), std::string::npos);
  ClearContextToken(&context);
  gst_rtsp_token_unref(previous);
  gst_object_unref(client);
  (void)gst_rtsp_message_unset(&request);
}

TEST(GstRtspDigestAuthTest,
     ChallengeFailureSendsSingleUnauthorizedWithoutHeaders) {
  TemporaryDirectory directory;
  const auto credentials = directory.File("credentials");
  WriteFile(credentials, CredentialFile(kOldPassword));
  DeterministicNonceInputs inputs;
  AuthPtr auth = CreateAuth(AuthConfig(credentials), inputs);
  ASSERT_NE(auth, nullptr);
  inputs.fail_nonce_random->store(true, std::memory_order_release);

  GstRTSPMessage request{};
  GstRTSPMessage response{};
  ASSERT_EQ(gst_rtsp_message_init_request(&request, GST_RTSP_DESCRIBE,
                                          std::string(kUri).c_str()),
            GST_RTSP_OK);
  GstRTSPClient* client = gst_rtsp_client_new();
  ASSERT_NE(client, nullptr);
  SentMessageCapture capture;
  gst_rtsp_client_set_send_func(client, CaptureSentMessage, &capture, nullptr);
  GstRTSPContext context{};
  context.client = client;
  context.request = &request;
  context.response = &response;
  context.method = GST_RTSP_DESCRIBE;

  EXPECT_FALSE(CheckUrl(auth.get(), &context));
  EXPECT_EQ(capture.count, 1);
  EXPECT_EQ(capture.status, GST_RTSP_STS_UNAUTHORIZED);
  EXPECT_TRUE(capture.challenges.empty());

  gst_object_unref(client);
  (void)gst_rtsp_message_unset(&request);
}

TEST(GstRtspDigestAuthTest, ShutdownWaitsForActiveVerificationAndIsTerminal) {
  TemporaryDirectory directory;
  const auto credentials = directory.File("credentials");
  WriteFile(credentials, CredentialFile(kOldPassword));
  DeterministicNonceInputs inputs;
  AuthPtr auth = CreateAuth(AuthConfig(credentials), inputs);
  ASSERT_NE(auth, nullptr);
  const std::string nonce = IssueChallenge(auth.get());
  const std::string authorization = BuildAuthorization(kOldPassword, nonce);

  GstRTSPMessage request{};
  ASSERT_EQ(gst_rtsp_message_init_request(&request, GST_RTSP_DESCRIBE,
                                          std::string(kUri).c_str()),
            GST_RTSP_OK);
  ASSERT_EQ(gst_rtsp_message_add_header(&request, GST_RTSP_HDR_AUTHORIZATION,
                                        authorization.c_str()),
            GST_RTSP_OK);
  GstRTSPContext context{};
  context.request = &request;
  context.method = GST_RTSP_DESCRIBE;
  inputs.block_next_clock->store(true, std::memory_order_release);

  std::atomic<bool> check_completed{false};
  std::atomic<bool> shutdown_started{false};
  std::atomic<bool> shutdown_completed{false};
  gboolean check_result = FALSE;
  bool shutdown_ok = false;
  std::thread check_thread([&] {
    check_result = CheckUrl(auth.get(), &context);
    check_completed.store(true, std::memory_order_release);
  });
  {
    std::unique_lock lock(*inputs.clock_mutex);
    inputs.clock_condition->wait(lock,
                                 [&inputs] { return *inputs.clock_entered; });
  }
  std::thread shutdown_thread([&] {
    shutdown_started.store(true, std::memory_order_release);
    auto shutdown = ShutdownGstCfRtspDigestAuth(auth.get());
    shutdown_ok = shutdown.ok();
    shutdown_completed.store(true, std::memory_order_release);
  });
  while (!shutdown_started.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  EXPECT_FALSE(shutdown_completed.load(std::memory_order_acquire));

  {
    std::lock_guard lock(*inputs.clock_mutex);
    *inputs.release_clock = true;
  }
  inputs.clock_condition->notify_all();
  check_thread.join();
  shutdown_thread.join();

  EXPECT_TRUE(check_completed.load(std::memory_order_acquire));
  EXPECT_TRUE(check_result);
  EXPECT_TRUE(shutdown_ok);
  EXPECT_TRUE(shutdown_completed.load(std::memory_order_acquire));
  auto reload = ReloadGstCfRtspDigestCredentials(auth.get());
  EXPECT_FALSE(reload.ok());

  ClearContextToken(&context);
  (void)gst_rtsp_message_unset(&request);
}

TEST(GstRtspDigestAuthTest, ReloadRejectsBaseAuthAndReloadsCustomAuth) {
  GstRTSPAuth* base_auth = gst_rtsp_auth_new();
  ASSERT_NE(base_auth, nullptr);
  auto base_reload = ReloadGstCfRtspDigestCredentials(base_auth);
  EXPECT_FALSE(base_reload.ok());
  g_object_unref(base_auth);

  TemporaryDirectory directory;
  const auto credentials = directory.File("credentials");
  WriteFile(credentials, CredentialFile(kOldPassword));
  DeterministicNonceInputs inputs;
  AuthPtr auth = CreateAuth(AuthConfig(credentials), inputs);
  ASSERT_NE(auth, nullptr);
  WriteFile(credentials, CredentialFile(kNewPassword));

  auto reloaded = ReloadGstCfRtspDigestCredentials(auth.get());

  ASSERT_TRUE(reloaded.ok()) << reloaded.error().message;
  const std::string nonce = IssueChallenge(auth.get());
  const std::string authorization = BuildAuthorization(kNewPassword, nonce);
  GstRTSPMessage request{};
  ASSERT_EQ(gst_rtsp_message_init_request(&request, GST_RTSP_DESCRIBE,
                                          std::string(kUri).c_str()),
            GST_RTSP_OK);
  ASSERT_EQ(gst_rtsp_message_add_header(&request, GST_RTSP_HDR_AUTHORIZATION,
                                        authorization.c_str()),
            GST_RTSP_OK);
  GstRTSPContext context{};
  context.request = &request;
  context.method = GST_RTSP_DESCRIBE;
  EXPECT_TRUE(CheckUrl(auth.get(), &context));
  ASSERT_NE(context.token, nullptr);
  ClearContextToken(&context);
  (void)gst_rtsp_message_unset(&request);
}

}  // namespace
}  // namespace camera_firmware::rtsp
