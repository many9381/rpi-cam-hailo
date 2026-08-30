#include "camera_firmware/rtsp/RtspDigestVerifier.hpp"

#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
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
constexpr std::string_view kPassword = "camera-secret";
constexpr std::string_view kMethod = "DESCRIBE";
constexpr std::string_view kUri = "rtsp://camera.local/imx708/main";
constexpr std::string_view kCnonce = "client-random-value";
constexpr std::string_view kNonceCount = "00000001";
constexpr std::string_view kHeaderErrorMessage =
    "RTSP Digest Authorization header is invalid";

std::span<const unsigned char> Bytes(std::string_view value) {
  return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 40> path{"/tmp/cf-rtsp-verifier-XXXXXX"};
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

std::string HexForTest(const SecureBytes& bytes, bool uppercase = false) {
  constexpr std::string_view kLower = "0123456789abcdef";
  constexpr std::string_view kUpper = "0123456789ABCDEF";
  const std::string_view alphabet = uppercase ? kUpper : kLower;
  std::string output(bytes.size() * 2U, '0');
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    output[index * 2U] = alphabet[bytes.data()[index] >> 4U];
    output[index * 2U + 1U] = alphabet[bytes.data()[index] & 0x0fU];
  }
  return output;
}

std::string CredentialRecord(std::string_view username,
                             std::string_view password,
                             RtspDigestAlgorithm algorithm) {
  auto ha1 = ComputeRtspDigestHa1(algorithm, username, kRealm,
                                  Bytes(password));
  if (!ha1.ok()) {
    throw std::runtime_error("failed to calculate test HA1");
  }
  return std::string(username) + ":" + std::string(kRealm) + ":" +
         std::string(RtspDigestConfigName(algorithm)) + ":" +
         HexForTest(ha1.value()) + "\n";
}

std::string CredentialFile(std::string_view password,
                           bool include_md5 = false) {
  std::string content = "CFDIGEST1\n";
  content += CredentialRecord(kUsername, password,
                              RtspDigestAlgorithm::kSha256);
  if (include_md5) {
    content += CredentialRecord(kUsername, password,
                                RtspDigestAlgorithm::kMd5);
  }
  return content;
}

struct DeterministicNonceInputs {
  std::shared_ptr<std::atomic<std::uint64_t>> now =
      std::make_shared<std::atomic<std::uint64_t>>(100U);
  std::shared_ptr<std::atomic<std::size_t>> random_calls =
      std::make_shared<std::atomic<std::size_t>>(0U);

  RtspDigestVerifierDependencies Dependencies() const {
    RtspDigestVerifierDependencies dependencies;
    dependencies.nonce.now_seconds = [clock = now]() {
      return clock->load(std::memory_order_relaxed);
    };
    dependencies.nonce.random_bytes =
        [calls = random_calls](std::size_t size) {
          const std::size_t call =
              calls->fetch_add(1U, std::memory_order_relaxed);
          if (size != 32U && size != 16U) {
            return Result<SecureBytes>::Err(
                {"E_TEST", "unexpected random byte count"});
          }
          SecureBytes bytes;
          bytes.resize(size);
          const unsigned char seed = static_cast<unsigned char>(
              size == 32U ? 0x10U : 0x80U + (call & 0x3fU));
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
    const std::filesystem::path& credential_file,
    bool include_md5 = false) {
  config::RtspClientAuthConfig config;
  config.enabled = true;
  config.realm = kRealm;
  config.credential_file = credential_file.string();
  config.algorithms = include_md5
                          ? std::vector<std::string>{"sha-256", "md5"}
                          : std::vector<std::string>{"sha-256"};
  config.nonce_ttl_seconds = 30U;
  return config;
}

std::unique_ptr<RtspDigestVerifier> CreateVerifier(
    const config::RtspClientAuthConfig& config,
    const DeterministicNonceInputs& inputs) {
  auto created = RtspDigestVerifier::Create(config, inputs.Dependencies());
  EXPECT_TRUE(created.ok())
      << (created.ok() ? std::string{} : created.error().message);
  return created.ok() ? std::move(created).value() : nullptr;
}

std::string MakeAuthorization(
    std::string_view username, std::string_view realm, std::string_view nonce,
    std::string_view uri, std::string_view response,
    std::string_view algorithm = "SHA-256", std::string_view qop = "auth",
    std::string_view nonce_count = kNonceCount,
    std::string_view cnonce = kCnonce) {
  return "Digest username=\"" + std::string(username) + "\", realm=\"" +
         std::string(realm) + "\", nonce=\"" + std::string(nonce) +
         "\", uri=\"" + std::string(uri) + "\", response=\"" +
         std::string(response) + "\", algorithm=" +
         std::string(algorithm) + ", qop=" + std::string(qop) + ", nc=" +
         std::string(nonce_count) + ", cnonce=\"" +
         std::string(cnonce) + "\"";
}

std::string ParserHeader() {
  return MakeAuthorization(kUsername, kRealm, std::string(76U, 'N'), kUri,
                           std::string(64U, 'a'));
}

std::string ReplaceOnce(std::string input, std::string_view from,
                        std::string_view to) {
  const std::size_t position = input.find(from);
  if (position == std::string::npos) {
    throw std::runtime_error("test replacement source not found");
  }
  input.replace(position, from.size(), to);
  return input;
}

void ExpectHeaderError(std::string_view header) {
  auto parsed = ParseRtspDigestAuthorization(header);
  ASSERT_FALSE(parsed.ok());
  EXPECT_EQ(parsed.error().code, "E_RTSP_AUTH_HEADER");
  EXPECT_EQ(parsed.error().message, kHeaderErrorMessage);
  EXPECT_EQ(parsed.error().message.find("operator"), std::string::npos);
  EXPECT_EQ(parsed.error().message.find(kRealm), std::string::npos);
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

std::string BuildValidAuthorization(
    std::string_view username, std::string_view password,
    std::string_view nonce, RtspDigestAlgorithm algorithm,
    std::string_view method = kMethod, std::string_view uri = kUri,
    std::string_view nonce_count = kNonceCount,
    std::string_view cnonce = kCnonce, bool uppercase_response = false) {
  auto ha1 = ComputeRtspDigestHa1(algorithm, username, kRealm,
                                  Bytes(password));
  if (!ha1.ok()) {
    throw std::runtime_error("failed to calculate test HA1");
  }
  auto response = ComputeRtspDigestResponse(
      algorithm, {ha1.value().data(), ha1.value().size()}, method, uri, nonce,
      nonce_count, cnonce);
  if (!response.ok()) {
    throw std::runtime_error("failed to calculate test response");
  }
  return MakeAuthorization(username, kRealm, nonce, uri,
                           HexForTest(response.value(), uppercase_response),
                           RtspDigestProtocolName(algorithm), "auth",
                           nonce_count, cnonce);
}

RtspDigestVerifyStatus VerifyStatus(RtspDigestVerifier* verifier,
                                    std::string_view authorization,
                                    std::string_view method = kMethod,
                                    std::string_view uri = kUri) {
  auto verified = verifier->Verify({method, uri, authorization});
  EXPECT_TRUE(verified.ok())
      << (verified.ok() ? std::string{} : verified.error().message);
  return verified.ok() ? verified.value()
                       : RtspDigestVerifyStatus::kRejected;
}

std::string IssueChallengeNonce(RtspDigestVerifier* verifier) {
  auto challenges = verifier->BuildChallenges(false);
  EXPECT_TRUE(challenges.ok())
      << (challenges.ok() ? std::string{} : challenges.error().message);
  EXPECT_TRUE(challenges.ok() && !challenges.value().empty());
  return challenges.ok() && !challenges.value().empty()
             ? ChallengeNonce(challenges.value().front())
             : std::string{};
}

TEST(RtspDigestVerifierTest, ParsesCompleteSha256Authorization) {
  const std::string response(64U, 'A');
  const std::string header =
      "dIgEsT UserName=\"quote\\\"and\\\\slash\", REALM=\"rpi-camera\", "
      "NONCE=\"" +
      std::string(76U, 'N') +
      "\", URI=\"rtsp://camera.local/imx708/main\", RESPONSE=\"" + response +
      "\", ALGORITHM=sHa-256, QOP=AuTh, NC=0000000A, "
      "CNONCE=\"client-random-value\"";

  auto parsed = ParseRtspDigestAuthorization(header);

  ASSERT_TRUE(parsed.ok()) << parsed.error().message;
  EXPECT_EQ(parsed.value().username, "quote\"and\\slash");
  EXPECT_EQ(parsed.value().realm, kRealm);
  EXPECT_EQ(parsed.value().nonce, std::string(76U, 'N'));
  EXPECT_EQ(parsed.value().uri, kUri);
  EXPECT_EQ(parsed.value().cnonce, kCnonce);
  EXPECT_EQ(parsed.value().algorithm, RtspDigestAlgorithm::kSha256);
  EXPECT_EQ(parsed.value().nonce_count, 10U);
  EXPECT_EQ(std::string_view(parsed.value().nonce_count_text.data(),
                             parsed.value().nonce_count_text.size()),
            "0000000A");
  ASSERT_EQ(parsed.value().response.size(), 32U);
  EXPECT_TRUE(std::all_of(
      parsed.value().response.data(),
      parsed.value().response.data() + parsed.value().response.size(),
      [](unsigned char value) { return value == 0xaaU; }));
}

TEST(RtspDigestVerifierTest, RejectsBasicAndHeadersOver8KiB) {
  ExpectHeaderError("Basic Zm9vOmJhcg==");

  std::string exact_limit = ParserHeader();
  ASSERT_LT(exact_limit.size(), 8192U);
  exact_limit.append(8192U - exact_limit.size(), ' ');
  auto parsed = ParseRtspDigestAuthorization(exact_limit);
  ASSERT_TRUE(parsed.ok()) << parsed.error().message;

  exact_limit.push_back(' ');
  ExpectHeaderError(exact_limit);
}

TEST(RtspDigestVerifierTest, RejectsMissingDuplicateAndUnknownDirectives) {
  const std::string complete = ParserHeader();
  const std::string missing = ReplaceOnce(
      complete, ", cnonce=\"client-random-value\"", "");
  const std::string duplicate = complete + ", USERNAME=\"other\"";
  const std::string unknown = complete + ", opaque=\"value\"";

  ExpectHeaderError(missing);
  ExpectHeaderError(duplicate);
  ExpectHeaderError(unknown);
}

TEST(RtspDigestVerifierTest, RejectsAuthIntSessUserhashAndMd5ByDefault) {
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "qop=auth", "qop=auth-int"));
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "algorithm=SHA-256",
                                "algorithm=SHA-256-sess"));
  ExpectHeaderError(ParserHeader() + ", userhash=true");

  auto md5_parsed = ParseRtspDigestAuthorization(
      MakeAuthorization(kUsername, kRealm, std::string(76U, 'N'), kUri,
                        std::string(32U, 'a'), "MD5"));
  ASSERT_TRUE(md5_parsed.ok()) << md5_parsed.error().message;
  EXPECT_EQ(md5_parsed.value().algorithm, RtspDigestAlgorithm::kMd5);

  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string nonce = IssueChallengeNonce(verifier.get());
  const std::string authorization = BuildValidAuthorization(
      kUsername, kPassword, nonce, RtspDigestAlgorithm::kMd5);

  EXPECT_EQ(VerifyStatus(verifier.get(), authorization),
            RtspDigestVerifyStatus::kRejected);
}

TEST(RtspDigestVerifierTest, RejectsWrongRealmMethodUriAndResponseLength) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string nonce = IssueChallengeNonce(verifier.get());
  const std::string valid = BuildValidAuthorization(
      kUsername, kPassword, nonce, RtspDigestAlgorithm::kSha256);
  const std::string wrong_realm =
      ReplaceOnce(valid, "realm=\"rpi-camera\"", "realm=\"other\"");
  const std::string short_response = ReplaceOnce(
      valid, "response=\"", "response=\"0");

  EXPECT_EQ(VerifyStatus(verifier.get(), wrong_realm),
            RtspDigestVerifyStatus::kRejected);
  EXPECT_EQ(VerifyStatus(verifier.get(), valid, "SETUP"),
            RtspDigestVerifyStatus::kRejected);
  EXPECT_EQ(VerifyStatus(verifier.get(), valid, kMethod,
                         "rtsp://camera.local/other"),
            RtspDigestVerifyStatus::kRejected);
  EXPECT_EQ(VerifyStatus(verifier.get(), short_response),
            RtspDigestVerifyStatus::kRejected);
}

TEST(RtspDigestVerifierTest, RejectsZeroOrMalformedNonceCount) {
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "nc=00000001",
                                "nc=00000000"));
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "nc=00000001",
                                "nc=0000001"));
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "nc=00000001",
                                "nc=0000000g"));
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "nc=00000001",
                                "nc=\"00000001\""));
}

TEST(RtspDigestVerifierTest, RejectsControlCharactersAndBadQuoting) {
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "username=\"operator\"",
                                "username=operator"));
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "algorithm=SHA-256",
                                "algorithm=\"SHA-256\""));
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "qop=auth", "qop=\"auth\""));
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "username=\"operator\"",
                                "username=\"bad\rname\""));
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "username=\"operator\"",
                                "username=\"bad\\\x1fname\""));
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "username=\"operator\"",
                                "username=\"unterminated"));
  ExpectHeaderError(ReplaceOnce(ParserHeader(), "username=\"operator\"",
                                "username=\"trailing\\\""));
}

TEST(RtspDigestVerifierTest, RejectsQuotedPairsInResponseDigest) {
  std::string escaped_response;
  escaped_response.reserve(128U);
  for (std::size_t index = 0U; index < 64U; ++index) {
    escaped_response += "\\a";
  }

  ExpectHeaderError(MakeAuthorization(kUsername, kRealm,
                                      std::string(76U, 'N'), kUri,
                                      escaped_response));
}

TEST(RtspDigestVerifierTest, RejectedPartialResponseIsZeroizedAndAudited) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string malformed = ParserHeader() + ", opaque=value";
  const common::ZeroizeAudit before = verifier->zeroize_audit();

  EXPECT_EQ(VerifyStatus(verifier.get(), malformed),
            RtspDigestVerifyStatus::kRejected);

  const common::ZeroizeAudit after = verifier->zeroize_audit();
  EXPECT_EQ(after.count, before.count + 1U);
  EXPECT_TRUE(after.last_verified);
}

TEST(RtspDigestVerifierTest, EnforcesDecodedFieldBounds) {
  const std::string response(64U, 'a');
  auto exact = ParseRtspDigestAuthorization(MakeAuthorization(
      std::string(64U, 'u'), std::string(128U, 'r'),
      std::string(76U, 'n'), std::string(4096U, 'p'), response, "SHA-256",
      "auth", kNonceCount, std::string(256U, 'c')));
  ASSERT_TRUE(exact.ok()) << exact.error().message;

  ExpectHeaderError(MakeAuthorization(
      std::string(65U, 'u'), kRealm, std::string(76U, 'n'), kUri, response));
  ExpectHeaderError(MakeAuthorization(
      kUsername, std::string(129U, 'r'), std::string(76U, 'n'), kUri,
      response));
  ExpectHeaderError(MakeAuthorization(kUsername, kRealm,
                                      std::string(75U, 'n'), kUri, response));
  ExpectHeaderError(MakeAuthorization(kUsername, kRealm,
                                      std::string(77U, 'n'), kUri, response));
  ExpectHeaderError(MakeAuthorization(
      kUsername, kRealm, std::string(76U, 'n'), std::string(4097U, 'p'),
      response));
  ExpectHeaderError(MakeAuthorization(
      kUsername, kRealm, std::string(76U, 'n'), kUri, response, "SHA-256",
      "auth", kNonceCount, std::string(257U, 'c')));
}

TEST(RtspDigestVerifierTest, BuildsSha256ChallengeWithOneFreshNonce) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);

  auto challenges = verifier->BuildChallenges(false);

  ASSERT_TRUE(challenges.ok()) << challenges.error().message;
  ASSERT_EQ(challenges.value().size(), 1U);
  const std::string nonce = ChallengeNonce(challenges.value().front());
  EXPECT_EQ(nonce.size(), 76U);
  EXPECT_EQ(challenges.value().front(),
            "Digest realm=\"rpi-camera\", nonce=\"" + nonce +
                "\", algorithm=SHA-256, qop=\"auth\", charset=UTF-8");
  EXPECT_EQ(inputs.random_calls->load(std::memory_order_relaxed), 2U);
}

TEST(RtspDigestVerifierTest, BuildsSha256ThenMd5ChallengesWhenEnabled) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword, true));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path, true), inputs);
  ASSERT_NE(verifier, nullptr);

  auto challenges = verifier->BuildChallenges(true);

  ASSERT_TRUE(challenges.ok()) << challenges.error().message;
  ASSERT_EQ(challenges.value().size(), 2U);
  const std::string sha_nonce = ChallengeNonce(challenges.value()[0]);
  const std::string md5_nonce = ChallengeNonce(challenges.value()[1]);
  EXPECT_EQ(sha_nonce, md5_nonce);
  EXPECT_NE(challenges.value()[0].find("algorithm=SHA-256"),
            std::string::npos);
  EXPECT_NE(challenges.value()[1].find("algorithm=MD5"), std::string::npos);
  EXPECT_NE(challenges.value()[0].find(", stale=true"), std::string::npos);
  EXPECT_NE(challenges.value()[1].find(", stale=true"), std::string::npos);
  EXPECT_EQ(inputs.random_calls->load(std::memory_order_relaxed), 2U);
}

TEST(RtspDigestVerifierTest, AuthenticatesCorrectSha256Request) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string nonce = IssueChallengeNonce(verifier.get());
  const std::string authorization = BuildValidAuthorization(
      kUsername, kPassword, nonce, RtspDigestAlgorithm::kSha256, kMethod, kUri,
      "0000000A", kCnonce, true);

  EXPECT_EQ(VerifyStatus(verifier.get(), authorization),
            RtspDigestVerifyStatus::kAuthenticated);
}

TEST(RtspDigestVerifierTest, UnknownUserExecutesDigestPathThenRejects) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string nonce = IssueChallengeNonce(verifier.get());
  const std::string unknown = BuildValidAuthorization(
      "missing-user", "guessed-secret", nonce,
      RtspDigestAlgorithm::kSha256);
  const std::string known = BuildValidAuthorization(
      kUsername, kPassword, nonce, RtspDigestAlgorithm::kSha256);
  const common::ZeroizeAudit before_unknown = verifier->zeroize_audit();

  EXPECT_EQ(VerifyStatus(verifier.get(), unknown),
            RtspDigestVerifyStatus::kRejected);
  const common::ZeroizeAudit after_unknown = verifier->zeroize_audit();
  EXPECT_EQ(after_unknown.count, before_unknown.count + 3U);
  EXPECT_TRUE(after_unknown.last_verified);
  EXPECT_EQ(VerifyStatus(verifier.get(), known),
            RtspDigestVerifyStatus::kAuthenticated);
}

TEST(RtspDigestVerifierTest, RejectsWrongPasswordAndReplay) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string nonce = IssueChallengeNonce(verifier.get());
  const std::string wrong = BuildValidAuthorization(
      kUsername, "wrong-secret", nonce, RtspDigestAlgorithm::kSha256);
  const std::string valid = BuildValidAuthorization(
      kUsername, kPassword, nonce, RtspDigestAlgorithm::kSha256);

  EXPECT_EQ(VerifyStatus(verifier.get(), wrong),
            RtspDigestVerifyStatus::kRejected);
  EXPECT_EQ(VerifyStatus(verifier.get(), valid),
            RtspDigestVerifyStatus::kAuthenticated);
  EXPECT_EQ(VerifyStatus(verifier.get(), valid),
            RtspDigestVerifyStatus::kRejected);
}

TEST(RtspDigestVerifierTest, ReturnsStaleOnlyForCorrectExpiredDigest) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string nonce = IssueChallengeNonce(verifier.get());
  const std::string authorization = BuildValidAuthorization(
      kUsername, kPassword, nonce, RtspDigestAlgorithm::kSha256);
  inputs.now->store(131U, std::memory_order_relaxed);

  EXPECT_EQ(VerifyStatus(verifier.get(), authorization),
            RtspDigestVerifyStatus::kStale);
}

TEST(RtspDigestVerifierTest, IncorrectExpiredDigestDoesNotRevealStale) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string nonce = IssueChallengeNonce(verifier.get());
  const std::string wrong = BuildValidAuthorization(
      kUsername, "wrong-secret", nonce, RtspDigestAlgorithm::kSha256);
  const std::string unknown = BuildValidAuthorization(
      "missing-user", "guessed-secret", nonce,
      RtspDigestAlgorithm::kSha256);
  inputs.now->store(131U, std::memory_order_relaxed);

  EXPECT_EQ(VerifyStatus(verifier.get(), wrong),
            RtspDigestVerifyStatus::kRejected);
  EXPECT_EQ(VerifyStatus(verifier.get(), unknown),
            RtspDigestVerifyStatus::kRejected);
}

TEST(RtspDigestVerifierTest, ReloadUsesNewCredentialsAndRetiresOldHa1) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile("old-secret"));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);

  const std::string before_nonce = IssueChallengeNonce(verifier.get());
  const std::string before = BuildValidAuthorization(
      kUsername, "old-secret", before_nonce, RtspDigestAlgorithm::kSha256);
  EXPECT_EQ(VerifyStatus(verifier.get(), before),
            RtspDigestVerifyStatus::kAuthenticated);

  WriteFile(path, CredentialFile("new-secret"));
  const common::ZeroizeAudit before_reload = verifier->zeroize_audit();
  auto reloaded = verifier->ReloadCredentials();
  ASSERT_TRUE(reloaded.ok()) << reloaded.error().message;
  const common::ZeroizeAudit after_reload = verifier->zeroize_audit();
  EXPECT_GT(after_reload.count, before_reload.count);
  EXPECT_TRUE(after_reload.last_verified);

  const std::string old_nonce = IssueChallengeNonce(verifier.get());
  const std::string old_authorization = BuildValidAuthorization(
      kUsername, "old-secret", old_nonce, RtspDigestAlgorithm::kSha256);
  EXPECT_EQ(VerifyStatus(verifier.get(), old_authorization),
            RtspDigestVerifyStatus::kRejected);

  const std::string new_nonce = IssueChallengeNonce(verifier.get());
  const std::string new_authorization = BuildValidAuthorization(
      kUsername, "new-secret", new_nonce, RtspDigestAlgorithm::kSha256);
  EXPECT_EQ(VerifyStatus(verifier.get(), new_authorization),
            RtspDigestVerifyStatus::kAuthenticated);
}

TEST(RtspDigestVerifierTest, AuthenticatesMd5OnlyWhenExplicitlyEnabled) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword, true));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path, true), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string nonce = IssueChallengeNonce(verifier.get());
  const std::string authorization = BuildValidAuthorization(
      kUsername, kPassword, nonce, RtspDigestAlgorithm::kMd5);

  EXPECT_EQ(VerifyStatus(verifier.get(), authorization),
            RtspDigestVerifyStatus::kAuthenticated);
}

// Legacy RFC 2069 MD5 authorization: no algorithm, qop, nc, or cnonce. This is
// what GStreamer/FFmpeg/live555 send. Accepted only when MD5 is enabled.
TEST(RtspDigestVerifierTest, AuthenticatesRfc2069Md5WithoutQop) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword, true));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path, true), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string nonce = IssueChallengeNonce(verifier.get());

  auto ha1 = ComputeRtspDigestHa1(RtspDigestAlgorithm::kMd5, kUsername, kRealm,
                                  Bytes(kPassword));
  ASSERT_TRUE(ha1.ok());
  auto response = ComputeRtspDigestResponse(
      RtspDigestAlgorithm::kMd5, {ha1.value().data(), ha1.value().size()},
      kMethod, kUri, nonce, /*nonce_count=*/"", /*cnonce=*/"",
      /*with_qop=*/false);
  ASSERT_TRUE(response.ok());
  const std::string authorization =
      "Digest username=\"" + std::string(kUsername) + "\", realm=\"" +
      std::string(kRealm) + "\", nonce=\"" + nonce + "\", uri=\"" +
      std::string(kUri) + "\", response=\"" + HexForTest(response.value()) +
      "\"";

  auto parsed = ParseRtspDigestAuthorization(authorization);
  ASSERT_TRUE(parsed.ok()) << "parser rejected the RFC 2069 header";
  EXPECT_EQ(parsed.value().algorithm, RtspDigestAlgorithm::kMd5);
  EXPECT_FALSE(parsed.value().has_qop);

  EXPECT_EQ(VerifyStatus(verifier.get(), authorization),
            RtspDigestVerifyStatus::kAuthenticated);
}

// A legacy RFC 2069 nonce is single-use: replaying the same authorization a
// second time is rejected (there is no nonce count to advance).
TEST(RtspDigestVerifierTest, Rfc2069Md5NonceIsSingleUse) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword, true));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path, true), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string nonce = IssueChallengeNonce(verifier.get());

  auto ha1 = ComputeRtspDigestHa1(RtspDigestAlgorithm::kMd5, kUsername, kRealm,
                                  Bytes(kPassword));
  ASSERT_TRUE(ha1.ok());
  auto response = ComputeRtspDigestResponse(
      RtspDigestAlgorithm::kMd5, {ha1.value().data(), ha1.value().size()},
      kMethod, kUri, nonce, /*nonce_count=*/"", /*cnonce=*/"",
      /*with_qop=*/false);
  ASSERT_TRUE(response.ok());
  const std::string authorization =
      "Digest username=\"" + std::string(kUsername) + "\", realm=\"" +
      std::string(kRealm) + "\", nonce=\"" + nonce + "\", uri=\"" +
      std::string(kUri) + "\", response=\"" + HexForTest(response.value()) +
      "\"";

  EXPECT_EQ(VerifyStatus(verifier.get(), authorization),
            RtspDigestVerifyStatus::kAuthenticated);
  EXPECT_EQ(VerifyStatus(verifier.get(), authorization),
            RtspDigestVerifyStatus::kRejected);
}

// The same RFC 2069 MD5 authorization is rejected when MD5 is not enabled.
TEST(RtspDigestVerifierTest, RejectsRfc2069Md5WhenMd5Disabled) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);
  const std::string nonce = IssueChallengeNonce(verifier.get());

  auto ha1 = ComputeRtspDigestHa1(RtspDigestAlgorithm::kMd5, kUsername, kRealm,
                                  Bytes(kPassword));
  ASSERT_TRUE(ha1.ok());
  auto response = ComputeRtspDigestResponse(
      RtspDigestAlgorithm::kMd5, {ha1.value().data(), ha1.value().size()},
      kMethod, kUri, nonce, /*nonce_count=*/"", /*cnonce=*/"",
      /*with_qop=*/false);
  ASSERT_TRUE(response.ok());
  const std::string authorization =
      "Digest username=\"" + std::string(kUsername) + "\", realm=\"" +
      std::string(kRealm) + "\", nonce=\"" + nonce + "\", uri=\"" +
      std::string(kUri) + "\", response=\"" + HexForTest(response.value()) +
      "\"";

  EXPECT_EQ(VerifyStatus(verifier.get(), authorization),
            RtspDigestVerifyStatus::kRejected);
}

TEST(RtspDigestVerifierTest, CreateLoadsCredentialsFailClosed) {
  TemporaryDirectory directory;
  DeterministicNonceInputs inputs;
  auto created = RtspDigestVerifier::Create(
      AuthConfig(directory.File("missing")), inputs.Dependencies());

  ASSERT_FALSE(created.ok());
  EXPECT_EQ(created.error().code, "E_RTSP_AUTH_CREDENTIALS");
}

TEST(RtspDigestVerifierTest, CreateRejectsUnsafeRealmAtPublicBoundary) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  const std::array<std::string, 6> unsafe_realms{
      "bad realm", "bad:realm", "bad\"realm", "bad\\realm", "bad\rrealm",
      std::string(129U, 'r')};

  for (const auto& unsafe_realm : unsafe_realms) {
    SCOPED_TRACE(unsafe_realm.size());
    DeterministicNonceInputs inputs;
    auto config = AuthConfig(path);
    config.realm = unsafe_realm;

    auto created =
        RtspDigestVerifier::Create(config, inputs.Dependencies());

    ASSERT_FALSE(created.ok());
    EXPECT_EQ(inputs.random_calls->load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(created.error().message.find(unsafe_realm), std::string::npos);
  }
}

TEST(RtspDigestVerifierTest, ClearIsTerminalForOwnedSecurityState) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path, CredentialFile(kPassword));
  DeterministicNonceInputs inputs;
  auto verifier = CreateVerifier(AuthConfig(path), inputs);
  ASSERT_NE(verifier, nullptr);
  const common::ZeroizeAudit before_clear = verifier->zeroize_audit();
  verifier->Clear();
  const common::ZeroizeAudit after_clear = verifier->zeroize_audit();

  auto challenges = verifier->BuildChallenges(false);
  auto reload = verifier->ReloadCredentials();
  auto verified = verifier->Verify({kMethod, kUri, ParserHeader()});

  EXPECT_FALSE(challenges.ok());
  EXPECT_FALSE(reload.ok());
  EXPECT_FALSE(verified.ok());
  EXPECT_GT(after_clear.count, before_clear.count);
  EXPECT_TRUE(after_clear.last_verified);
}

}  // namespace
}  // namespace camera_firmware::rtsp
