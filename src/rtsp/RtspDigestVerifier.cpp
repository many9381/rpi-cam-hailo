#include "camera_firmware/rtsp/RtspDigestVerifier.hpp"

#include "camera_firmware/rtsp/RtspDigestCredentials.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace camera_firmware::rtsp {
namespace {

constexpr std::size_t kMaximumHeaderBytes = 8192U;
constexpr std::size_t kMaximumUsernameBytes = 64U;
constexpr std::size_t kMaximumRealmBytes = 128U;
constexpr std::size_t kNonceTextBytes = 76U;
constexpr std::size_t kMaximumUriBytes = 4096U;
constexpr std::size_t kMaximumCnonceBytes = 256U;
constexpr std::size_t kDirectiveCount = 9U;
constexpr std::size_t kNonceCountTextBytes = 8U;

constexpr std::string_view kHeaderErrorMessage =
    "RTSP Digest Authorization header is invalid";
constexpr std::string_view kInternalErrorMessage =
    "RTSP Digest authentication operation failed";
constexpr std::string_view kConfigErrorMessage =
    "RTSP Digest authentication configuration is invalid";

enum class Directive : std::size_t {
  kUsername = 0U,
  kRealm,
  kNonce,
  kUri,
  kResponse,
  kAlgorithm,
  kQop,
  kNonceCount,
  kCnonce,
};

common::Error HeaderError() {
  return {"E_RTSP_AUTH_HEADER", std::string(kHeaderErrorMessage)};
}

common::Error InternalError() {
  return {"E_RTSP_AUTH_INTERNAL", std::string(kInternalErrorMessage)};
}

common::Error ConfigError() {
  return {"E_RTSP_AUTH_CONFIG", std::string(kConfigErrorMessage)};
}

template <typename T>
common::Result<T> HeaderFailure() {
  return common::Result<T>::Err(HeaderError());
}

template <typename T>
common::Result<T> InternalFailure() {
  return common::Result<T>::Err(InternalError());
}

unsigned char AsciiLower(unsigned char value) noexcept {
  if (value >= static_cast<unsigned char>('A') &&
      value <= static_cast<unsigned char>('Z')) {
    return static_cast<unsigned char>(value + ('a' - 'A'));
  }
  return value;
}

bool AsciiCaseEqual(std::string_view left, std::string_view right) noexcept {
  if (left.size() != right.size()) {
    return false;
  }
  for (std::size_t index = 0U; index < left.size(); ++index) {
    if (AsciiLower(static_cast<unsigned char>(left[index])) !=
        AsciiLower(static_cast<unsigned char>(right[index]))) {
      return false;
    }
  }
  return true;
}

bool IsVisibleAscii(unsigned char value) noexcept {
  return value >= 0x21U && value <= 0x7eU;
}

bool IsTokenCharacter(unsigned char value) noexcept {
  if ((value >= static_cast<unsigned char>('a') &&
       value <= static_cast<unsigned char>('z')) ||
      (value >= static_cast<unsigned char>('A') &&
       value <= static_cast<unsigned char>('Z')) ||
      (value >= static_cast<unsigned char>('0') &&
       value <= static_cast<unsigned char>('9'))) {
    return true;
  }
  switch (value) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~':
      return true;
    default:
      return false;
  }
}

int HexValue(unsigned char value) noexcept {
  if (value >= static_cast<unsigned char>('0') &&
      value <= static_cast<unsigned char>('9')) {
    return value - static_cast<unsigned char>('0');
  }
  const unsigned char lowered = AsciiLower(value);
  if (lowered >= static_cast<unsigned char>('a') &&
      lowered <= static_cast<unsigned char>('f')) {
    return lowered - static_cast<unsigned char>('a') + 10;
  }
  return -1;
}

bool FindDirective(std::string_view name, Directive* directive) noexcept {
  struct DirectiveName {
    std::string_view name;
    Directive directive;
  };
  static constexpr std::array<DirectiveName, kDirectiveCount> kNames{{
      {"username", Directive::kUsername},
      {"realm", Directive::kRealm},
      {"nonce", Directive::kNonce},
      {"uri", Directive::kUri},
      {"response", Directive::kResponse},
      {"algorithm", Directive::kAlgorithm},
      {"qop", Directive::kQop},
      {"nc", Directive::kNonceCount},
      {"cnonce", Directive::kCnonce},
  }};
  for (const auto& candidate : kNames) {
    if (AsciiCaseEqual(name, candidate.name)) {
      *directive = candidate.directive;
      return true;
    }
  }
  return false;
}

class AuthorizationParser {
 public:
  explicit AuthorizationParser(std::string_view header) noexcept
      : header_(header) {}

  bool Parse(RtspDigestAuthorization* authorization) {
    if (header_.empty() || header_.size() > kMaximumHeaderBytes ||
        !std::all_of(header_.begin(), header_.end(), [](unsigned char value) {
          return value >= 0x20U && value <= 0x7eU;
        })) {
      return false;
    }

    SkipSpaces();
    const std::string_view scheme = ParseToken();
    if (!AsciiCaseEqual(scheme, "Digest") || position_ == header_.size() ||
        header_[position_] != ' ') {
      return false;
    }
    SkipSpaces();
    if (position_ == header_.size()) {
      return false;
    }

    while (position_ < header_.size()) {
      const std::string_view name = ParseToken();
      Directive directive{};
      if (name.empty() || !FindDirective(name, &directive)) {
        return false;
      }
      const std::size_t directive_index =
          static_cast<std::size_t>(directive);
      if (seen_[directive_index]) {
        return false;
      }

      SkipSpaces();
      if (!Consume('=')) {
        return false;
      }
      SkipSpaces();
      if (!ParseValue(directive, authorization)) {
        return false;
      }
      seen_[directive_index] = true;

      SkipSpaces();
      if (position_ == header_.size()) {
        break;
      }
      if (!Consume(',')) {
        return false;
      }
      SkipSpaces();
      if (position_ == header_.size()) {
        return false;
      }
    }

    const auto seen = [this](Directive directive) {
      return seen_[static_cast<std::size_t>(directive)];
    };
    // Mandatory directives, present in both RFC 2069 and RFC 2617/7616.
    if (!seen(Directive::kUsername) || !seen(Directive::kRealm) ||
        !seen(Directive::kNonce) || !seen(Directive::kUri) ||
        !seen(Directive::kResponse)) {
      return false;
    }
    // algorithm is optional; RFC 2069/7616 default it to MD5 when absent.
    if (!seen(Directive::kAlgorithm)) {
      authorization->algorithm = RtspDigestAlgorithm::kMd5;
    }
    // qop is optional. When present (RFC 2617/7616) it REQUIRES nc and cnonce;
    // when absent (legacy RFC 2069) nc and cnonce MUST also be absent. This
    // lets MD5-only clients that omit qop (GStreamer/FFmpeg/live555)
    // authenticate over the RTSPS TLS control channel.
    const bool has_qop = seen(Directive::kQop);
    if (has_qop) {
      if (!seen(Directive::kNonceCount) || !seen(Directive::kCnonce)) {
        return false;
      }
    } else if (seen(Directive::kNonceCount) || seen(Directive::kCnonce)) {
      return false;
    }
    authorization->has_qop = has_qop;
    return authorization->response.size() ==
           RtspDigestSize(authorization->algorithm);
  }

 private:
  bool ParseValue(Directive directive,
                  RtspDigestAuthorization* authorization) {
    switch (directive) {
      case Directive::kUsername:
        return ParseQuoted(&authorization->username, kMaximumUsernameBytes);
      case Directive::kRealm:
        return ParseQuoted(&authorization->realm, kMaximumRealmBytes);
      case Directive::kNonce:
        return ParseQuoted(&authorization->nonce, kNonceTextBytes) &&
               authorization->nonce.size() == kNonceTextBytes;
      case Directive::kUri:
        return ParseQuoted(&authorization->uri, kMaximumUriBytes);
      case Directive::kResponse:
        return ParseResponse(&authorization->response);
      case Directive::kAlgorithm:
        return ParseAlgorithm(&authorization->algorithm);
      case Directive::kQop:
        return AsciiCaseEqual(ParseOptionallyQuotedToken(), "auth");
      case Directive::kNonceCount:
        return ParseNonceCount(authorization);
      case Directive::kCnonce:
        return ParseQuoted(&authorization->cnonce, kMaximumCnonceBytes);
    }
    return false;
  }

  bool ParseQuoted(std::string* output, std::size_t maximum_size) {
    if (!Consume('"')) {
      return false;
    }
    while (position_ < header_.size()) {
      unsigned char value =
          static_cast<unsigned char>(header_[position_++]);
      if (value == static_cast<unsigned char>('"')) {
        return !output->empty();
      }
      if (value == static_cast<unsigned char>('\\')) {
        if (position_ == header_.size()) {
          return false;
        }
        value = static_cast<unsigned char>(header_[position_++]);
      }
      if (!IsVisibleAscii(value) || output->size() == maximum_size) {
        return false;
      }
      output->push_back(static_cast<char>(value));
    }
    return false;
  }

  bool ParseResponse(common::SecureBytes* output) {
    if (!Consume('"')) {
      return false;
    }
    int high_nibble = -1;
    std::size_t encoded_size = 0U;
    while (position_ < header_.size()) {
      unsigned char value =
          static_cast<unsigned char>(header_[position_++]);
      if (value == static_cast<unsigned char>('"')) {
        return encoded_size != 0U && high_nibble < 0;
      }
      if (value == static_cast<unsigned char>('\\')) {
        return false;
      }
      if (!IsVisibleAscii(value) || encoded_size == 64U) {
        return false;
      }
      const int nibble = HexValue(value);
      if (nibble < 0) {
        return false;
      }
      ++encoded_size;
      if (high_nibble < 0) {
        high_nibble = nibble;
        continue;
      }
      const unsigned char decoded = static_cast<unsigned char>(
          (static_cast<unsigned int>(high_nibble) << 4U) |
          static_cast<unsigned int>(nibble));
      output->append(&decoded, 1U);
      high_nibble = -1;
    }
    return false;
  }

  // RFC 7616 defines algorithm and qop as unquoted tokens, but several clients
  // (notably ffmpeg) send them quoted, e.g. algorithm="MD5", qop="auth".
  // Accept both a bare token and a quoted token so those clients authenticate.
  std::string_view ParseOptionallyQuotedToken() noexcept {
    if (position_ < header_.size() && header_[position_] == '"') {
      ++position_;
      const std::string_view token = ParseToken();
      if (!Consume('"')) {
        return {};
      }
      return token;
    }
    return ParseToken();
  }

  bool ParseAlgorithm(RtspDigestAlgorithm* algorithm) {
    const std::string_view token = ParseOptionallyQuotedToken();
    if (AsciiCaseEqual(token, "SHA-256")) {
      *algorithm = RtspDigestAlgorithm::kSha256;
      return true;
    }
    if (AsciiCaseEqual(token, "MD5")) {
      *algorithm = RtspDigestAlgorithm::kMd5;
      return true;
    }
    return false;
  }

  bool ParseNonceCount(RtspDigestAuthorization* authorization) {
    const std::string_view token = ParseToken();
    if (token.size() != kNonceCountTextBytes) {
      return false;
    }
    std::uint32_t decoded = 0U;
    for (std::size_t index = 0U; index < token.size(); ++index) {
      const int nibble = HexValue(static_cast<unsigned char>(token[index]));
      if (nibble < 0) {
        return false;
      }
      authorization->nonce_count_text[index] = token[index];
      decoded = static_cast<std::uint32_t>(
          (decoded << 4U) | static_cast<std::uint32_t>(nibble));
    }
    if (decoded == 0U) {
      return false;
    }
    authorization->nonce_count = decoded;
    return true;
  }

  std::string_view ParseToken() noexcept {
    const std::size_t begin = position_;
    while (position_ < header_.size() &&
           IsTokenCharacter(
               static_cast<unsigned char>(header_[position_]))) {
      ++position_;
    }
    return header_.substr(begin, position_ - begin);
  }

  bool Consume(char expected) noexcept {
    if (position_ == header_.size() || header_[position_] != expected) {
      return false;
    }
    ++position_;
    return true;
  }

  void SkipSpaces() noexcept {
    while (position_ < header_.size() && header_[position_] == ' ') {
      ++position_;
    }
  }

  std::string_view header_;
  std::size_t position_{0U};
  std::array<bool, kDirectiveCount> seen_{};
};

bool AlgorithmEnabled(const std::vector<RtspDigestAlgorithm>& algorithms,
                      RtspDigestAlgorithm requested) noexcept {
  return std::find(algorithms.begin(), algorithms.end(), requested) !=
         algorithms.end();
}

void AccumulateAudit(common::ZeroizeAudit addition,
                     common::ZeroizeAudit* total) noexcept {
  if (addition.count >
      std::numeric_limits<std::size_t>::max() - total->count) {
    total->count = std::numeric_limits<std::size_t>::max();
  } else {
    total->count += addition.count;
  }
  total->last_verified = total->last_verified && addition.last_verified;
}

common::ZeroizeAudit CleanseRequestSecret(
    common::SecureBytes* secret) noexcept {
  const common::ZeroizeAudit before = secret->zeroize_audit();
  secret->clear();
  const common::ZeroizeAudit after = secret->zeroize_audit();
  return {after.count - before.count,
          before.last_verified && after.last_verified};
}

struct RequestSecretAuditState {
  std::mutex mutex;
  common::ZeroizeAudit audit;
};

void RecordRequestSecretAudit(common::ZeroizeAudit retired,
                              RequestSecretAuditState* state) noexcept {
  if (state == nullptr) {
    return;
  }
  try {
    std::lock_guard lock(state->mutex);
    AccumulateAudit(retired, &state->audit);
  } catch (...) {
  }
}

class ParsedResponseRetirement {
 public:
  ParsedResponseRetirement(common::SecureBytes* response,
                           RequestSecretAuditState* audit) noexcept
      : response_(response), audit_(audit) {}

  ~ParsedResponseRetirement() {
    if (audit_ != nullptr) {
      RecordRequestSecretAudit(CleanseRequestSecret(response_), audit_);
    }
  }

  ParsedResponseRetirement(const ParsedResponseRetirement&) = delete;
  ParsedResponseRetirement& operator=(const ParsedResponseRetirement&) =
      delete;

 private:
  common::SecureBytes* response_;
  RequestSecretAuditState* audit_;
};

class RequestSecrets {
 public:
  explicit RequestSecrets(RequestSecretAuditState* audit) noexcept
      : audit_(audit) {}

  ~RequestSecrets() {
    common::ZeroizeAudit retired;
    AccumulateAudit(CleanseRequestSecret(&response), &retired);
    AccumulateAudit(CleanseRequestSecret(&ha1), &retired);
    AccumulateAudit(CleanseRequestSecret(&expected), &retired);
    RecordRequestSecretAudit(retired, audit_);
  }

  RequestSecrets(const RequestSecrets&) = delete;
  RequestSecrets& operator=(const RequestSecrets&) = delete;

  common::SecureBytes response;
  common::SecureBytes ha1;
  common::SecureBytes expected;

 private:
  RequestSecretAuditState* audit_;
};

common::Result<std::vector<RtspDigestAlgorithm>> ParseConfiguredAlgorithms(
    const config::RtspClientAuthConfig& config) {
  if (!config.enabled || config.realm.empty() ||
      config.credential_file.empty() || config.algorithms.empty() ||
      config.algorithms.size() > 2U || config.nonce_ttl_seconds < 30U ||
      config.nonce_ttl_seconds > 3600U) {
    return common::Result<std::vector<RtspDigestAlgorithm>>::Err(
        ConfigError());
  }

  bool sha256 = false;
  bool md5 = false;
  for (const auto& configured : config.algorithms) {
    auto parsed = ParseRtspDigestAlgorithm(configured);
    if (!parsed.ok()) {
      return common::Result<std::vector<RtspDigestAlgorithm>>::Err(
          ConfigError());
    }
    switch (parsed.value()) {
      case RtspDigestAlgorithm::kSha256:
        if (sha256) {
          return common::Result<std::vector<RtspDigestAlgorithm>>::Err(
              ConfigError());
        }
        sha256 = true;
        break;
      case RtspDigestAlgorithm::kMd5:
        if (md5) {
          return common::Result<std::vector<RtspDigestAlgorithm>>::Err(
              ConfigError());
        }
        md5 = true;
        break;
    }
  }
  if (!sha256) {
    return common::Result<std::vector<RtspDigestAlgorithm>>::Err(
        ConfigError());
  }

  std::vector<RtspDigestAlgorithm> algorithms;
  try {
    algorithms.reserve(md5 ? 2U : 1U);
    algorithms.push_back(RtspDigestAlgorithm::kSha256);
    if (md5) {
      algorithms.push_back(RtspDigestAlgorithm::kMd5);
    }
  } catch (...) {
    return common::Result<std::vector<RtspDigestAlgorithm>>::Err(
        InternalError());
  }
  return common::Result<std::vector<RtspDigestAlgorithm>>::Ok(
      std::move(algorithms));
}

common::Result<void> PreflightAlgorithms(
    const std::vector<RtspDigestAlgorithm>& algorithms) {
  for (const RtspDigestAlgorithm algorithm : algorithms) {
    auto preflight = RtspDigestHash(algorithm, {});
    if (!preflight.ok()) {
      return common::Result<void>::Err(preflight.error());
    }
    preflight.value().clear();
  }
  return common::Result<void>::Ok();
}

common::Result<RtspDigestAuthorization> ParseAuthorization(
    std::string_view header, RequestSecretAuditState* audit) {
  try {
    RtspDigestAuthorization authorization;
    ParsedResponseRetirement response_retirement(&authorization.response,
                                                  audit);
    AuthorizationParser parser(header);
    if (!parser.Parse(&authorization)) {
      return HeaderFailure<RtspDigestAuthorization>();
    }
    return common::Result<RtspDigestAuthorization>::Ok(
        std::move(authorization));
  } catch (const std::bad_alloc&) {
    return InternalFailure<RtspDigestAuthorization>();
  } catch (...) {
    return InternalFailure<RtspDigestAuthorization>();
  }
}

}  // namespace

struct RtspDigestVerifier::Impl {
  std::string realm;
  std::filesystem::path credential_path;
  std::vector<RtspDigestAlgorithm> algorithms;
  std::unique_ptr<RtspDigestCredentialStore> credentials;
  std::unique_ptr<RtspDigestNonceManager> nonces;
  RequestSecretAuditState request_secret_audit;
};

common::Result<RtspDigestAuthorization> ParseRtspDigestAuthorization(
    std::string_view header) {
  return ParseAuthorization(header, nullptr);
}

RtspDigestVerifier::RtspDigestVerifier(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

RtspDigestVerifier::~RtspDigestVerifier() { Clear(); }

common::Result<std::unique_ptr<RtspDigestVerifier>> RtspDigestVerifier::Create(
    const config::RtspClientAuthConfig& config,
    RtspDigestVerifierDependencies dependencies) {
  try {
    auto algorithms = ParseConfiguredAlgorithms(config);
    if (!algorithms.ok()) {
      return common::Result<std::unique_ptr<RtspDigestVerifier>>::Err(
          algorithms.error());
    }
    auto preflight = PreflightAlgorithms(algorithms.value());
    if (!preflight.ok()) {
      return common::Result<std::unique_ptr<RtspDigestVerifier>>::Err(
          preflight.error());
    }

    RtspDigestCredentialPolicy policy;
    policy.realm = config.realm;
    policy.algorithms = algorithms.value();
    auto credentials =
        RtspDigestCredentialStore::Create(std::move(policy));
    if (!credentials.ok()) {
      return common::Result<std::unique_ptr<RtspDigestVerifier>>::Err(
          credentials.error());
    }
    const std::filesystem::path credential_path(config.credential_file);
    auto reloaded = credentials.value()->Reload(credential_path);
    if (!reloaded.ok()) {
      return common::Result<std::unique_ptr<RtspDigestVerifier>>::Err(
          reloaded.error());
    }

    auto nonces = RtspDigestNonceManager::Create(
        std::chrono::seconds(config.nonce_ttl_seconds),
        std::move(dependencies.nonce));
    if (!nonces.ok()) {
      return common::Result<std::unique_ptr<RtspDigestVerifier>>::Err(
          nonces.error());
    }

    auto impl = std::make_unique<Impl>();
    impl->realm = config.realm;
    impl->credential_path = credential_path;
    impl->algorithms = std::move(algorithms).value();
    impl->credentials = std::move(credentials).value();
    impl->nonces = std::move(nonces).value();

    auto verifier = std::unique_ptr<RtspDigestVerifier>(
        new RtspDigestVerifier(std::move(impl)));
    return common::Result<std::unique_ptr<RtspDigestVerifier>>::Ok(
        std::move(verifier));
  } catch (...) {
    return InternalFailure<std::unique_ptr<RtspDigestVerifier>>();
  }
}

common::Result<RtspDigestVerifyStatus> RtspDigestVerifier::Verify(
    const RtspDigestVerifyRequest& request) {
  auto parsed =
      ParseAuthorization(request.authorization, &impl_->request_secret_audit);
  if (!parsed.ok()) {
    if (parsed.error().code == "E_RTSP_AUTH_HEADER") {
      return common::Result<RtspDigestVerifyStatus>::Ok(
          RtspDigestVerifyStatus::kRejected);
    }
    return common::Result<RtspDigestVerifyStatus>::Err(parsed.error());
  }
  RtspDigestAuthorization authorization = std::move(parsed).value();
  RequestSecrets secrets(&impl_->request_secret_audit);
  secrets.response = std::move(authorization.response);

  if (!AlgorithmEnabled(impl_->algorithms, authorization.algorithm) ||
      authorization.realm != impl_->realm ||
      authorization.uri != request.request_uri) {
    return common::Result<RtspDigestVerifyStatus>::Ok(
        RtspDigestVerifyStatus::kRejected);
  }

  auto validation = impl_->nonces->Validate(authorization.nonce);
  if (!validation.ok()) {
    return common::Result<RtspDigestVerifyStatus>::Err(validation.error());
  }
  if (validation.value().status == RtspDigestNonceStatus::kInvalid) {
    return common::Result<RtspDigestVerifyStatus>::Ok(
        RtspDigestVerifyStatus::kRejected);
  }

  auto credential = impl_->credentials->Lookup(authorization.username,
                                               authorization.algorithm);
  if (!credential.ok()) {
    return common::Result<RtspDigestVerifyStatus>::Err(credential.error());
  }
  const bool credential_matched = credential.value().matched;
  secrets.ha1 = std::move(credential.value().ha1);

  const std::string_view nonce_count_text(
      authorization.nonce_count_text.data(),
      authorization.nonce_count_text.size());
  auto expected = ComputeRtspDigestResponse(
      authorization.algorithm,
      {secrets.ha1.data(), secrets.ha1.size()},
      request.method, authorization.uri, authorization.nonce,
      nonce_count_text, authorization.cnonce, authorization.has_qop);
  if (!expected.ok()) {
    return common::Result<RtspDigestVerifyStatus>::Err(expected.error());
  }
  secrets.expected = std::move(expected).value();

  const bool digest_equal = RtspDigestConstantTimeEqual(
      {secrets.expected.data(), secrets.expected.size()},
      {secrets.response.data(), secrets.response.size()});
  if (!credential_matched || !digest_equal) {
    return common::Result<RtspDigestVerifyStatus>::Ok(
        RtspDigestVerifyStatus::kRejected);
  }
  if (validation.value().status == RtspDigestNonceStatus::kExpired) {
    return common::Result<RtspDigestVerifyStatus>::Ok(
        RtspDigestVerifyStatus::kStale);
  }

  auto committed = impl_->nonces->Commit(
      authorization.username, validation.value(), authorization.nonce_count,
      authorization.has_qop);
  if (!committed.ok()) {
    return common::Result<RtspDigestVerifyStatus>::Err(committed.error());
  }
  return common::Result<RtspDigestVerifyStatus>::Ok(
      committed.value() ? RtspDigestVerifyStatus::kAuthenticated
                        : RtspDigestVerifyStatus::kRejected);
}

common::Result<std::vector<std::string>>
RtspDigestVerifier::BuildChallenges(bool stale) {
  auto nonce = impl_->nonces->Issue();
  if (!nonce.ok()) {
    return common::Result<std::vector<std::string>>::Err(nonce.error());
  }

  try {
    std::vector<std::string> challenges;
    challenges.reserve(impl_->algorithms.size());
    for (const RtspDigestAlgorithm algorithm : impl_->algorithms) {
      std::string challenge = "Digest realm=\"" + impl_->realm +
                              "\", nonce=\"" + nonce.value() +
                              "\", algorithm=" +
                              std::string(RtspDigestProtocolName(algorithm)) +
                              ", qop=\"auth\", charset=UTF-8";
      if (stale) {
        challenge += ", stale=true";
      }
      challenges.push_back(std::move(challenge));
    }
    return common::Result<std::vector<std::string>>::Ok(
        std::move(challenges));
  } catch (...) {
    return InternalFailure<std::vector<std::string>>();
  }
}

common::Result<void> RtspDigestVerifier::ReloadCredentials() {
  return impl_->credentials->Reload(impl_->credential_path);
}

void RtspDigestVerifier::Clear() noexcept {
  impl_->credentials->Clear();
  impl_->nonces->Clear();
}

common::ZeroizeAudit RtspDigestVerifier::zeroize_audit() const noexcept {
  common::ZeroizeAudit total;
  try {
    std::lock_guard lock(impl_->request_secret_audit.mutex);
    AccumulateAudit(impl_->request_secret_audit.audit, &total);
  } catch (...) {
    total.last_verified = false;
  }
  AccumulateAudit(impl_->credentials->zeroize_audit(), &total);
  AccumulateAudit(impl_->nonces->zeroize_audit(), &total);
  return total;
}

}  // namespace camera_firmware::rtsp
