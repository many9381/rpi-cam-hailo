#include "camera_firmware/rtsp/RtspDigestNonce.hpp"

#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <list>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <openssl/crypto.h>

namespace camera_firmware::rtsp {
namespace {

constexpr unsigned char kNonceVersion = 0x01U;
constexpr std::size_t kNonceKeyBytes = 32U;
constexpr std::size_t kNonceTimestampOffset = 1U;
constexpr std::size_t kNonceTimestampBytes = 8U;
constexpr std::size_t kNonceRandomOffset =
    kNonceTimestampOffset + kNonceTimestampBytes;
constexpr std::size_t kNonceRandomBytes = 16U;
constexpr std::size_t kNoncePrefixBytes =
    kNonceRandomOffset + kNonceRandomBytes;
constexpr std::size_t kNonceTagBytes = 32U;
constexpr std::size_t kNonceRawBytes = kNoncePrefixBytes + kNonceTagBytes;
constexpr std::size_t kNonceEncodedBytes = 76U;
constexpr std::size_t kReplayIdentifierBytes = 32U;
constexpr std::size_t kMaximumReplayCapacity = 4096U;
static_assert(kNonceRawBytes == 57U);
static_assert(kNonceRawBytes % 3U == 0U);
static_assert((kNonceRawBytes / 3U) * 4U == kNonceEncodedBytes);
constexpr char kBase64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
constexpr std::string_view kConfigurationInvalid =
    "nonce configuration is invalid";
constexpr std::string_view kOperationFailed = "nonce operation failed";

common::Error NonceError(std::string_view message) {
  return {"E_RTSP_AUTH_NONCE", std::string(message)};
}

template <typename T>
common::Result<T> NonceFailure(std::string_view message) {
  return common::Result<T>::Err(NonceError(message));
}

void AccumulateAudit(common::ZeroizeAudit addition,
                     common::ZeroizeAudit* total) noexcept {
  if (addition.count > std::numeric_limits<std::size_t>::max() - total->count) {
    total->count = std::numeric_limits<std::size_t>::max();
  } else {
    total->count += addition.count;
  }
  total->last_verified = total->last_verified && addition.last_verified;
}

common::ZeroizeAudit CleanseSecureBytes(common::SecureBytes* bytes) noexcept {
  const common::ZeroizeAudit before = bytes->zeroize_audit();
  bytes->clear();
  const common::ZeroizeAudit after = bytes->zeroize_audit();
  return {after.count - before.count, after.last_verified};
}

bool CleanseAndVerify(unsigned char* data, std::size_t size) noexcept {
  if (data == nullptr || size == 0U) {
    return true;
  }
  OPENSSL_cleanse(data, size);
  return std::all_of(data, data + size,
                     [](unsigned char byte) { return byte == 0U; });
}

int DecodeBase64UrlByte(unsigned char byte) noexcept {
  if (byte >= static_cast<unsigned char>('A') &&
      byte <= static_cast<unsigned char>('Z')) {
    return static_cast<int>(byte - static_cast<unsigned char>('A'));
  }
  if (byte >= static_cast<unsigned char>('a') &&
      byte <= static_cast<unsigned char>('z')) {
    return 26 + static_cast<int>(byte - static_cast<unsigned char>('a'));
  }
  if (byte >= static_cast<unsigned char>('0') &&
      byte <= static_cast<unsigned char>('9')) {
    return 52 + static_cast<int>(byte - static_cast<unsigned char>('0'));
  }
  if (byte == static_cast<unsigned char>('-')) {
    return 62;
  }
  if (byte == static_cast<unsigned char>('_')) {
    return 63;
  }
  return -1;
}

bool DecodeNonce(std::string_view encoded,
                 std::array<unsigned char, kNonceRawBytes>* decoded) noexcept {
  if (encoded.size() != kNonceEncodedBytes) {
    return false;
  }

  std::size_t output = 0U;
  for (std::size_t input = 0U; input < encoded.size(); input += 4U) {
    const int first =
        DecodeBase64UrlByte(static_cast<unsigned char>(encoded[input]));
    const int second =
        DecodeBase64UrlByte(static_cast<unsigned char>(encoded[input + 1U]));
    const int third =
        DecodeBase64UrlByte(static_cast<unsigned char>(encoded[input + 2U]));
    const int fourth =
        DecodeBase64UrlByte(static_cast<unsigned char>(encoded[input + 3U]));
    if (first < 0 || second < 0 || third < 0 || fourth < 0) {
      return false;
    }

    (*decoded)[output++] =
        static_cast<unsigned char>((static_cast<unsigned int>(first) << 2U) |
                                   (static_cast<unsigned int>(second) >> 4U));
    (*decoded)[output++] =
        static_cast<unsigned char>((static_cast<unsigned int>(second) << 4U) |
                                   (static_cast<unsigned int>(third) >> 2U));
    (*decoded)[output++] =
        static_cast<unsigned char>((static_cast<unsigned int>(third) << 6U) |
                                   static_cast<unsigned int>(fourth));
  }
  return output == decoded->size();
}

std::string EncodeNonce(const std::array<unsigned char, kNonceRawBytes>& raw) {
  std::string encoded;
  encoded.resize(kNonceEncodedBytes);
  std::size_t output = 0U;
  for (std::size_t input = 0U; input < raw.size(); input += 3U) {
    const unsigned int value =
        (static_cast<unsigned int>(raw[input]) << 16U) |
        (static_cast<unsigned int>(raw[input + 1U]) << 8U) |
        static_cast<unsigned int>(raw[input + 2U]);
    encoded[output++] = kBase64UrlAlphabet[(value >> 18U) & 0x3fU];
    encoded[output++] = kBase64UrlAlphabet[(value >> 12U) & 0x3fU];
    encoded[output++] = kBase64UrlAlphabet[(value >> 6U) & 0x3fU];
    encoded[output++] = kBase64UrlAlphabet[value & 0x3fU];
  }
  return encoded;
}

void WriteBigEndian64(std::uint64_t value, unsigned char* output) noexcept {
  for (std::size_t index = 0U; index < kNonceTimestampBytes; ++index) {
    const std::size_t shift = (kNonceTimestampBytes - 1U - index) * 8U;
    output[index] = static_cast<unsigned char>((value >> shift) & 0xffU);
  }
}

std::uint64_t ReadBigEndian64(const unsigned char* input) noexcept {
  std::uint64_t value = 0U;
  for (std::size_t index = 0U; index < kNonceTimestampBytes; ++index) {
    value = (value << 8U) | static_cast<std::uint64_t>(input[index]);
  }
  return value;
}

bool IsAllZero(
    const std::array<unsigned char, kReplayIdentifierBytes>& value) noexcept {
  return std::all_of(value.begin(), value.end(),
                     [](unsigned char byte) { return byte == 0U; });
}

struct ReplayEntry {
  ReplayEntry() = default;
  ~ReplayEntry() {
    (void)CleanseAndVerify(identifier.data(), identifier.size());
    expires_at = 0U;
    highest_count = 0U;
  }

  ReplayEntry(const ReplayEntry&) = delete;
  ReplayEntry& operator=(const ReplayEntry&) = delete;
  ReplayEntry(ReplayEntry&&) = delete;
  ReplayEntry& operator=(ReplayEntry&&) = delete;

  std::array<unsigned char, kReplayIdentifierBytes> identifier{};
  std::uint64_t expires_at{0U};
  std::uint32_t highest_count{0U};
};

struct PendingReplayIdentifier {
  common::SecureBytes bytes;
};

using PendingReplayIdentifiers =
    std::list<std::shared_ptr<PendingReplayIdentifier>>;

struct NonceLifecycle {
  std::mutex mutex;
  std::condition_variable drained;
  std::size_t active_operations{0U};
  bool closing{false};
  bool terminal{false};
};

class ActiveNonceOperation {
 public:
  explicit ActiveNonceOperation(NonceLifecycle* lifecycle)
      : lifecycle_(lifecycle) {
    std::lock_guard lock(lifecycle_->mutex);
    if (lifecycle_->closing || lifecycle_->terminal) {
      lifecycle_ = nullptr;
      return;
    }
    ++lifecycle_->active_operations;
  }

  ~ActiveNonceOperation() {
    if (lifecycle_ == nullptr) {
      return;
    }
    try {
      std::lock_guard lock(lifecycle_->mutex);
      if (lifecycle_->active_operations != 0U) {
        --lifecycle_->active_operations;
      }
      if (lifecycle_->active_operations == 0U) {
        lifecycle_->drained.notify_all();
      }
    } catch (...) {
      // swallowed: destructors must not throw; the drained signal is best
      // effort
    }
  }

  ActiveNonceOperation(const ActiveNonceOperation&) = delete;
  ActiveNonceOperation& operator=(const ActiveNonceOperation&) = delete;

  [[nodiscard]] bool active() const noexcept { return lifecycle_ != nullptr; }

 private:
  NonceLifecycle* lifecycle_;
};

bool LifecycleAccepting(NonceLifecycle* lifecycle) {
  std::lock_guard lock(lifecycle->mutex);
  return !lifecycle->closing && !lifecycle->terminal;
}

class PendingReplayRegistration {
 public:
  PendingReplayRegistration(NonceLifecycle* lifecycle,
                            PendingReplayIdentifiers* registrations,
                            common::ZeroizeAudit* audit)
      : lifecycle_(lifecycle), registrations_(registrations), audit_(audit) {}

  ~PendingReplayRegistration() { Retire(); }

  PendingReplayRegistration(const PendingReplayRegistration&) = delete;
  PendingReplayRegistration& operator=(const PendingReplayRegistration&) =
      delete;

  common::Result<void> Register(common::SecureBytes identifier) {
    try {
      pending_ = std::make_shared<PendingReplayIdentifier>();
      std::lock_guard lock(lifecycle_->mutex);
      registrations_->push_back(pending_);
      registered_ = true;
      pending_->bytes = std::move(identifier);
      return common::Result<void>::Ok();
    } catch (...) {
      identifier.clear();
      return common::Result<void>::Err(NonceError(kOperationFailed));
    }
  }

  common::Result<common::SecureBytes> Take() {
    try {
      std::lock_guard lock(lifecycle_->mutex);
      if (!registered_ || pending_ == nullptr ||
          pending_->bytes.size() != kReplayIdentifierBytes) {
        return NonceFailure<common::SecureBytes>(kOperationFailed);
      }
      const auto registration =
          std::find(registrations_->begin(), registrations_->end(), pending_);
      if (registration == registrations_->end()) {
        return NonceFailure<common::SecureBytes>(kOperationFailed);
      }
      common::SecureBytes identifier = std::move(pending_->bytes);
      registrations_->erase(registration);
      registered_ = false;
      return common::Result<common::SecureBytes>::Ok(std::move(identifier));
    } catch (...) {
      return NonceFailure<common::SecureBytes>(kOperationFailed);
    }
  }

 private:
  void Retire() noexcept {
    if (pending_ == nullptr) {
      return;
    }
    try {
      std::lock_guard lock(lifecycle_->mutex);
      if (registered_) {
        const auto registration =
            std::find(registrations_->begin(), registrations_->end(), pending_);
        if (registration != registrations_->end()) {
          registrations_->erase(registration);
        }
        registered_ = false;
      }
      AccumulateAudit(CleanseSecureBytes(&pending_->bytes), audit_);
    } catch (...) {
      pending_->bytes.clear();
    }
  }

  NonceLifecycle* lifecycle_;
  PendingReplayIdentifiers* registrations_;
  common::ZeroizeAudit* audit_;
  std::shared_ptr<PendingReplayIdentifier> pending_;
  bool registered_{false};
};

common::ZeroizeAudit CleanseReplayEntry(ReplayEntry* entry) noexcept {
  const bool verified =
      CleanseAndVerify(entry->identifier.data(), entry->identifier.size());
  entry->expires_at = 0U;
  entry->highest_count = 0U;
  return {1U, verified};
}

std::uint64_t DefaultNowSeconds() {
  const auto elapsed = std::chrono::steady_clock::now().time_since_epoch();
  const auto seconds =
      std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
  return seconds <= 0 ? 0U : static_cast<std::uint64_t>(seconds);
}

std::function<common::Result<common::SecureBytes>(std::size_t)>
ResolveRandomBytes(crypto::CryptoProvider* provider) {
  if (provider != nullptr) {
    return [provider](std::size_t size) { return provider->RandomBytes(size); };
  }
  return RtspDigestRandomBytes;
}

}  // namespace

struct RtspDigestNonceManager::Impl {
  std::uint64_t ttl_seconds{0U};
  std::size_t replay_capacity{0U};
  RtspDigestNonceDependencies dependencies;
  common::SecureBytes hmac_key;
  std::list<ReplayEntry> replay_entries;
  PendingReplayIdentifiers pending_identifiers;
  common::ZeroizeAudit audit;
  std::recursive_mutex commit_sequence;
  mutable NonceLifecycle lifecycle;

  common::Result<common::SecureBytes> CopyHmacKeyWhileActive() const {
    if (hmac_key.size() != kNonceKeyBytes) {
      return NonceFailure<common::SecureBytes>(kOperationFailed);
    }
    common::SecureBytes copy;
    try {
      copy.assign(hmac_key.data(), hmac_key.size());
    } catch (...) {
      return NonceFailure<common::SecureBytes>(kOperationFailed);
    }
    return common::Result<common::SecureBytes>::Ok(std::move(copy));
  }
};

namespace {

common::Result<common::SecureBytes> BuildReplayIdentifier(
    std::string_view username,
    const std::array<unsigned char, kReplayIdentifierBytes>& nonce_id) {
  common::SecureBytes input;
  try {
    input.assign(reinterpret_cast<const unsigned char*>(username.data()),
                 username.size());
    const unsigned char separator = 0U;
    input.append(&separator, 1U);
    input.append(nonce_id.data(), nonce_id.size());
  } catch (...) {
    return NonceFailure<common::SecureBytes>(kOperationFailed);
  }

  auto identifier = RtspDigestHash(RtspDigestAlgorithm::kSha256,
                                   {input.data(), input.size()});
  if (!identifier.ok() || identifier.value().size() != kReplayIdentifierBytes) {
    return NonceFailure<common::SecureBytes>(kOperationFailed);
  }
  return common::Result<common::SecureBytes>::Ok(std::move(identifier).value());
}

}  // namespace

RtspDigestNonceManager::RtspDigestNonceManager(
    std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

RtspDigestNonceManager::~RtspDigestNonceManager() {
  Clear();
}

common::Result<std::unique_ptr<RtspDigestNonceManager>>
RtspDigestNonceManager::Create(std::chrono::seconds ttl,
                               RtspDigestNonceDependencies dependencies,
                               std::size_t replay_capacity) {
  if (ttl.count() <= 0 || replay_capacity == 0U ||
      replay_capacity > kMaximumReplayCapacity) {
    return NonceFailure<std::unique_ptr<RtspDigestNonceManager>>(
        kConfigurationInvalid);
  }

  try {
    if (!dependencies.now_seconds) {
      dependencies.now_seconds = DefaultNowSeconds;
    }
    if (!dependencies.random_bytes) {
      dependencies.random_bytes = ResolveRandomBytes(dependencies.provider);
    }

    auto key = dependencies.random_bytes(kNonceKeyBytes);
    if (!key.ok() || key.value().size() != kNonceKeyBytes) {
      return NonceFailure<std::unique_ptr<RtspDigestNonceManager>>(
          kOperationFailed);
    }

    auto impl = std::make_unique<Impl>();
    impl->ttl_seconds = static_cast<std::uint64_t>(ttl.count());
    impl->replay_capacity = replay_capacity;
    impl->dependencies = std::move(dependencies);
    impl->hmac_key = std::move(key).value();

    auto manager = std::unique_ptr<RtspDigestNonceManager>(
        new RtspDigestNonceManager(std::move(impl)));
    return common::Result<std::unique_ptr<RtspDigestNonceManager>>::Ok(
        std::move(manager));
  } catch (...) {
    return NonceFailure<std::unique_ptr<RtspDigestNonceManager>>(
        kOperationFailed);
  }
}

common::Result<std::string> RtspDigestNonceManager::Issue() {
  try {
    if (!LifecycleAccepting(&impl_->lifecycle)) {
      return NonceFailure<std::string>(kOperationFailed);
    }
    auto random = impl_->dependencies.random_bytes(kNonceRandomBytes);
    if (!random.ok() || random.value().size() != kNonceRandomBytes) {
      return NonceFailure<std::string>(kOperationFailed);
    }
    const std::uint64_t now = impl_->dependencies.now_seconds();
    if (now > std::numeric_limits<std::uint64_t>::max() - impl_->ttl_seconds) {
      return NonceFailure<std::string>(kOperationFailed);
    }

    ActiveNonceOperation operation(&impl_->lifecycle);
    if (!operation.active()) {
      return NonceFailure<std::string>(kOperationFailed);
    }
    auto key = impl_->CopyHmacKeyWhileActive();
    if (!key.ok()) {
      return NonceFailure<std::string>(key.error().message);
    }

    std::array<unsigned char, kNonceRawBytes> raw{};
    raw[0] = kNonceVersion;
    WriteBigEndian64(now, raw.data() + kNonceTimestampOffset);
    std::copy_n(random.value().data(), kNonceRandomBytes,
                raw.data() + kNonceRandomOffset);

    auto tag = RtspDigestHmacSha256({key.value().data(), key.value().size()},
                                    {raw.data(), kNoncePrefixBytes});
    if (!tag.ok() || tag.value().size() != kNonceTagBytes) {
      return NonceFailure<std::string>(kOperationFailed);
    }
    std::copy_n(tag.value().data(), kNonceTagBytes,
                raw.data() + kNoncePrefixBytes);
    return common::Result<std::string>::Ok(EncodeNonce(raw));
  } catch (...) {
    return NonceFailure<std::string>(kOperationFailed);
  }
}

common::Result<RtspDigestNonceValidation> RtspDigestNonceManager::Validate(
    std::string_view nonce) const {
  try {
    if (!LifecycleAccepting(&impl_->lifecycle)) {
      return NonceFailure<RtspDigestNonceValidation>(kOperationFailed);
    }
    std::array<unsigned char, kNonceRawBytes> raw{};
    if (!DecodeNonce(nonce, &raw) || raw[0] != kNonceVersion) {
      return common::Result<RtspDigestNonceValidation>::Ok({});
    }

    {
      ActiveNonceOperation operation(&impl_->lifecycle);
      if (!operation.active()) {
        return NonceFailure<RtspDigestNonceValidation>(kOperationFailed);
      }
      auto key = impl_->CopyHmacKeyWhileActive();
      if (!key.ok()) {
        return NonceFailure<RtspDigestNonceValidation>(key.error().message);
      }
      auto expected_tag =
          RtspDigestHmacSha256({key.value().data(), key.value().size()},
                               {raw.data(), kNoncePrefixBytes});
      if (!expected_tag.ok() || expected_tag.value().size() != kNonceTagBytes) {
        return NonceFailure<RtspDigestNonceValidation>(kOperationFailed);
      }
      if (!RtspDigestConstantTimeEqual(
              {expected_tag.value().data(), expected_tag.value().size()},
              {raw.data() + kNoncePrefixBytes, kNonceTagBytes})) {
        return common::Result<RtspDigestNonceValidation>::Ok({});
      }
    }

    const std::uint64_t issued_at =
        ReadBigEndian64(raw.data() + kNonceTimestampOffset);
    if (!LifecycleAccepting(&impl_->lifecycle)) {
      return NonceFailure<RtspDigestNonceValidation>(kOperationFailed);
    }
    const std::uint64_t now = impl_->dependencies.now_seconds();

    ActiveNonceOperation operation(&impl_->lifecycle);
    if (!operation.active()) {
      return NonceFailure<RtspDigestNonceValidation>(kOperationFailed);
    }
    if (issued_at > now ||
        issued_at >
            std::numeric_limits<std::uint64_t>::max() - impl_->ttl_seconds) {
      return common::Result<RtspDigestNonceValidation>::Ok({});
    }

    auto nonce_id = RtspDigestHash(
        RtspDigestAlgorithm::kSha256,
        {reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size()});
    if (!nonce_id.ok() || nonce_id.value().size() != kReplayIdentifierBytes) {
      return NonceFailure<RtspDigestNonceValidation>(kOperationFailed);
    }

    RtspDigestNonceValidation validation;
    validation.expires_at = issued_at + impl_->ttl_seconds;
    validation.status = now > validation.expires_at
                            ? RtspDigestNonceStatus::kExpired
                            : RtspDigestNonceStatus::kValid;
    std::copy_n(nonce_id.value().data(), validation.nonce_id.size(),
                validation.nonce_id.begin());
    return common::Result<RtspDigestNonceValidation>::Ok(std::move(validation));
  } catch (...) {
    return NonceFailure<RtspDigestNonceValidation>(kOperationFailed);
  }
}

common::Result<bool> RtspDigestNonceManager::Commit(
    std::string_view username, const RtspDigestNonceValidation& validation,
    std::uint32_t nonce_count, bool with_qop) {
  try {
    if (!LifecycleAccepting(&impl_->lifecycle)) {
      return NonceFailure<bool>(kOperationFailed);
    }
    // A qop=auth request MUST carry a non-zero nonce count. A legacy RFC 2069
    // request (with_qop=false) carries none; nonce_count is then 0 and the
    // nonce becomes single-use via the monotonic check below.
    if (validation.status != RtspDigestNonceStatus::kValid ||
        (with_qop && nonce_count == 0U) || validation.expires_at == 0U ||
        IsAllZero(validation.nonce_id)) {
      return common::Result<bool>::Ok(false);
    }

    std::lock_guard sequence_lock(impl_->commit_sequence);
    PendingReplayRegistration pending(
        &impl_->lifecycle, &impl_->pending_identifiers, &impl_->audit);
    {
      ActiveNonceOperation build_operation(&impl_->lifecycle);
      if (!build_operation.active()) {
        return NonceFailure<bool>(kOperationFailed);
      }
      auto identifier = BuildReplayIdentifier(username, validation.nonce_id);
      if (!identifier.ok()) {
        return NonceFailure<bool>(identifier.error().message);
      }
      auto registered = pending.Register(std::move(identifier).value());
      if (!registered.ok()) {
        return NonceFailure<bool>(registered.error().message);
      }
    }
    if (!LifecycleAccepting(&impl_->lifecycle)) {
      return NonceFailure<bool>(kOperationFailed);
    }
    const std::uint64_t now = impl_->dependencies.now_seconds();

    ActiveNonceOperation operation(&impl_->lifecycle);
    if (!operation.active()) {
      return NonceFailure<bool>(kOperationFailed);
    }
    if (now > validation.expires_at) {
      return common::Result<bool>::Ok(false);
    }

    auto taken_identifier = pending.Take();
    if (!taken_identifier.ok()) {
      return NonceFailure<bool>(taken_identifier.error().message);
    }
    common::SecureBytes identifier = std::move(taken_identifier).value();

    std::unique_lock state_lock(impl_->lifecycle.mutex);

    for (auto entry = impl_->replay_entries.begin();
         entry != impl_->replay_entries.end();) {
      if (now <= entry->expires_at) {
        ++entry;
        continue;
      }
      AccumulateAudit(CleanseReplayEntry(&*entry), &impl_->audit);
      entry = impl_->replay_entries.erase(entry);
    }

    const std::span<const unsigned char> requested_identifier(
        identifier.data(), identifier.size());
    for (auto& entry : impl_->replay_entries) {
      if (!RtspDigestConstantTimeEqual(
              requested_identifier,
              {entry.identifier.data(), entry.identifier.size()})) {
        continue;
      }
      if (nonce_count <= entry.highest_count) {
        return common::Result<bool>::Ok(false);
      }
      entry.highest_count = nonce_count;
      entry.expires_at = validation.expires_at;
      return common::Result<bool>::Ok(true);
    }

    if (impl_->replay_entries.size() >= impl_->replay_capacity) {
      return common::Result<bool>::Ok(false);
    }

    impl_->replay_entries.emplace_back();
    ReplayEntry& entry = impl_->replay_entries.back();
    std::copy_n(identifier.data(), entry.identifier.size(),
                entry.identifier.begin());
    entry.expires_at = validation.expires_at;
    entry.highest_count = nonce_count;
    return common::Result<bool>::Ok(true);
  } catch (...) {
    return NonceFailure<bool>(kOperationFailed);
  }
}

void RtspDigestNonceManager::Clear() noexcept {
  try {
    std::unique_lock lock(impl_->lifecycle.mutex);
    if (impl_->lifecycle.terminal) {
      return;
    }
    impl_->lifecycle.closing = true;
    impl_->lifecycle.drained.wait(
        lock, [this] { return impl_->lifecycle.active_operations == 0U; });
    if (impl_->lifecycle.terminal) {
      return;
    }
    AccumulateAudit(CleanseSecureBytes(&impl_->hmac_key), &impl_->audit);
    for (auto& entry : impl_->replay_entries) {
      AccumulateAudit(CleanseReplayEntry(&entry), &impl_->audit);
    }
    impl_->replay_entries.clear();
    for (auto& pending : impl_->pending_identifiers) {
      AccumulateAudit(CleanseSecureBytes(&pending->bytes), &impl_->audit);
    }
    impl_->pending_identifiers.clear();
    impl_->lifecycle.terminal = true;
  } catch (...) {
    // swallowed: this terminal cleanse is noexcept; the audit tally is best
    // effort
  }
}

common::ZeroizeAudit RtspDigestNonceManager::zeroize_audit() const noexcept {
  try {
    std::lock_guard lock(impl_->lifecycle.mutex);
    return impl_->audit;
  } catch (...) {
    return {0U, false};
  }
}

}  // namespace camera_firmware::rtsp
