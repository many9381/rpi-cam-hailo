#include "camera_firmware/integrity/IntegrityVerifier.hpp"

#if defined(CAMERA_FIRMWARE_INTEGRITY_TESTING)
#include "IntegrityVerifierTestAccess.hpp"
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstddef>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace camera_firmware::integrity {
namespace {

constexpr std::size_t kMaximumManifestBytes = std::size_t{1024} * 1024U;
constexpr std::size_t kExpectedSignatureBytes = 64U;
constexpr std::size_t kReadBufferSize = std::size_t{32} * 1024U;
constexpr std::size_t kMaximumPathBytes = 4096U;
constexpr unsigned int kMaximumEintrRetries = 3U;

enum class VerificationFaultPoint {
  kReportReserve,
  kReportItemCopy,
  kReportItemAppend,
};

struct VerificationHooks {
  std::function<void()> before_artifact_read;
  std::function<ssize_t(int, void*, std::size_t)> read;
  std::function<void(VerificationFaultPoint)> inject_fault;
};

using EvpPkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;

class UniqueFd {
 public:
  explicit UniqueFd(int descriptor = -1) noexcept : descriptor_(descriptor) {}
  ~UniqueFd() {
    if (descriptor_ >= 0) {
      (void)::close(descriptor_);
    }
  }
  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;
  UniqueFd(UniqueFd&& other) noexcept
      : descriptor_(std::exchange(other.descriptor_, -1)) {}
  UniqueFd& operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
      if (descriptor_ >= 0) {
        (void)::close(descriptor_);
      }
      descriptor_ = std::exchange(other.descriptor_, -1);
    }
    return *this;
  }
  [[nodiscard]] int get() const noexcept { return descriptor_; }

 private:
  int descriptor_;
};

common::Error ArtifactAccessError() {
  return {"E_INTEGRITY_ARTIFACT_ACCESS", "Unable to access integrity artifact"};
}
common::Error ArtifactPathError() {
  return {"E_INTEGRITY_ARTIFACT_PATH", "Integrity artifact path is invalid"};
}
common::Error ArtifactTypeError() {
  return {"E_INTEGRITY_ARTIFACT_TYPE", "Integrity artifact is not a regular file"};
}
common::Error ArtifactReadError() {
  return {"E_INTEGRITY_ARTIFACT_READ", "Unable to read integrity artifact"};
}
common::Error ArtifactChangedError() {
  return {"E_INTEGRITY_ARTIFACT_CHANGED", "Integrity artifact changed while reading"};
}
common::Error ArtifactSizeError() {
  return {"E_INTEGRITY_ARTIFACT_SIZE", "Integrity artifact exceeds its size limit"};
}
common::Error SignatureFormatError() {
  return {"E_INTEGRITY_SIGNATURE_FORMAT", "Integrity signature has invalid format"};
}
common::Error SignatureInvalidError() {
  return {"E_INTEGRITY_SIGNATURE_INVALID", "Integrity signature verification failed"};
}
common::Error PublicKeyError() {
  return {"E_INTEGRITY_PUBLIC_KEY", "Integrity public key is invalid"};
}
common::Error ManifestContractError() {
  return {"E_INTEGRITY_MANIFEST_CONTRACT", "Integrity manifest does not match active process"};
}
const common::Error kResourceError{"E_INTEGRITY_RESOURCE",
                                   "Integrity verification resource failure"};

bool IsAbsoluteNormalizedPath(const std::filesystem::path& path) {
  const auto& native = path.native();
  return !path.empty() && native.size() <= kMaximumPathBytes &&
         native.find('\0') == std::string::npos && path.is_absolute() &&
         native == path.lexically_normal().native();
}

int OpenNoFollow(const std::filesystem::path& path, int flags) noexcept {
  unsigned int retries = 0U;
  while (true) {
    const int descriptor = ::open(path.c_str(), flags);
    if (descriptor >= 0 || errno != EINTR || retries++ == kMaximumEintrRetries) {
      return descriptor;
    }
  }
}

bool FstatNoIntr(int descriptor, struct stat* status) noexcept {
  unsigned int retries = 0U;
  while (true) {
    if (::fstat(descriptor, status) == 0) {
      return true;
    }
    if (errno != EINTR || retries++ == kMaximumEintrRetries) {
      return false;
    }
  }
}

bool SameSnapshot(const struct stat& before, const struct stat& after) noexcept {
  return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
         before.st_size == after.st_size &&
         before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
         before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
         before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
         before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

common::Result<std::vector<unsigned char>> ReadRegularFile(
    const std::filesystem::path& path, std::size_t maximum_size,
    const VerificationHooks& hooks) {
  UniqueFd descriptor(
      OpenNoFollow(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW));
  if (descriptor.get() < 0) {
    return common::Result<std::vector<unsigned char>>::Err(
        errno == ELOOP ? ArtifactTypeError() : ArtifactAccessError());
  }
  struct stat initial_status {};
  if (!FstatNoIntr(descriptor.get(), &initial_status)) {
    return common::Result<std::vector<unsigned char>>::Err(ArtifactReadError());
  }
  if (!S_ISREG(initial_status.st_mode)) {
    return common::Result<std::vector<unsigned char>>::Err(ArtifactTypeError());
  }
  if (initial_status.st_size < 0 ||
      static_cast<std::uintmax_t>(initial_status.st_size) > maximum_size) {
    return common::Result<std::vector<unsigned char>>::Err(ArtifactSizeError());
  }

  try {
    if (hooks.before_artifact_read) {
      hooks.before_artifact_read();
    }
    std::vector<unsigned char> bytes;
    bytes.reserve(static_cast<std::size_t>(initial_status.st_size));
    std::array<unsigned char, kReadBufferSize> buffer{};
    unsigned int eintr_retries = 0U;
    while (true) {
      const std::size_t remaining = maximum_size + 1U - bytes.size();
      const std::size_t requested = std::min(buffer.size(), remaining);
      const ssize_t count = hooks.read
                                ? hooks.read(descriptor.get(), buffer.data(), requested)
                                : ::read(descriptor.get(), buffer.data(), requested);
      if (count > 0) {
        bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + count);
        if (bytes.size() > maximum_size) {
          return common::Result<std::vector<unsigned char>>::Err(ArtifactSizeError());
        }
        eintr_retries = 0U;
        continue;
      }
      if (count == 0) {
        break;
      }
      if (errno == EINTR && eintr_retries++ < kMaximumEintrRetries) {
        continue;
      }
      return common::Result<std::vector<unsigned char>>::Err(ArtifactReadError());
    }

    struct stat final_status {};
    if (!FstatNoIntr(descriptor.get(), &final_status)) {
      return common::Result<std::vector<unsigned char>>::Err(ArtifactReadError());
    }
    if (!SameSnapshot(initial_status, final_status)) {
      return common::Result<std::vector<unsigned char>>::Err(ArtifactChangedError());
    }
    UniqueFd path_descriptor(OpenNoFollow(path, O_PATH | O_CLOEXEC | O_NOFOLLOW));
    struct stat path_status {};
    if (path_descriptor.get() < 0 || !FstatNoIntr(path_descriptor.get(), &path_status) ||
        !S_ISREG(path_status.st_mode) || path_status.st_dev != initial_status.st_dev ||
        path_status.st_ino != initial_status.st_ino) {
      return common::Result<std::vector<unsigned char>>::Err(ArtifactChangedError());
    }
    return common::Result<std::vector<unsigned char>>::Ok(std::move(bytes));
  } catch (const std::exception&) {
    return common::Result<std::vector<unsigned char>>::Err(ArtifactReadError());
  }
}

bool MeetsActiveProcessContract(const IntegrityManifest& manifest,
                                const std::filesystem::path& active_executable,
                                const std::filesystem::path& active_config) {
  if (!IsAbsoluteNormalizedPath(active_executable) ||
      !IsAbsoluteNormalizedPath(active_config)) {
    return false;
  }
  bool has_firmware = false;
  bool has_configuration = false;
  bool has_kernel = false;
  bool executable_matches = false;
  bool config_matches = false;
  for (const IntegrityEntry& entry : manifest.files) {
    has_firmware = has_firmware || entry.category == IntegrityCategory::kFirmware;
    has_configuration = has_configuration ||
                        entry.category == IntegrityCategory::kConfiguration;
    has_kernel = has_kernel || entry.category == IntegrityCategory::kKernel;
    executable_matches = executable_matches ||
                         (entry.category == IntegrityCategory::kFirmware &&
                          entry.path == active_executable);
    config_matches = config_matches ||
                     (entry.category == IntegrityCategory::kConfiguration &&
                      entry.path == active_config);
  }
  return has_firmware && has_configuration && has_kernel && executable_matches &&
         config_matches;
}

bool HasOnlyPemWhitespace(BIO* bio) {
  std::array<char, 256U> buffer{};
  while (BIO_ctrl_pending(bio) > 0L) {
    const int count = BIO_read(bio, buffer.data(), static_cast<int>(buffer.size()));
    if (count <= 0) {
      return false;
    }
    for (int index = 0; index < count; ++index) {
      if (std::isspace(static_cast<unsigned char>(buffer[static_cast<std::size_t>(index)])) ==
          0) {
        return false;
      }
    }
  }
  return true;
}

}  // namespace

common::Result<void> VerifyEd25519Signature(
    std::span<const unsigned char> manifest,
    std::span<const unsigned char> signature,
    std::string_view public_key_pem,
    crypto::CryptoProvider& provider) {
  if (signature.size() != kExpectedSignatureBytes) {
    return common::Result<void>::Err(SignatureFormatError());
  }
  if (public_key_pem.empty() ||
      public_key_pem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return common::Result<void>::Err(PublicKeyError());
  }
  Bio bio(BIO_new_mem_buf(public_key_pem.data(), static_cast<int>(public_key_pem.size())),
          BIO_free);
  EvpPkey key(bio ? PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr) : nullptr,
              EVP_PKEY_free);
  if (!key || !HasOnlyPemWhitespace(bio.get()) ||
      !EVP_PKEY_is_a(key.get(), "ED25519")) {
    return common::Result<void>::Err(PublicKeyError());
  }
  // The PEM decode above stays exactly as it was; only the signature check
  // itself moves behind the crypto provider. Ed25519 PEM keys (PKCS8/SPKI)
  // are wrappers around the same raw bytes the provider's contract takes, so
  // extracting them here is lossless.
  std::array<unsigned char, crypto::kEd25519PublicKeyBytes> raw_public_key{};
  std::size_t raw_public_key_size = raw_public_key.size();
  if (EVP_PKEY_get_raw_public_key(key.get(), raw_public_key.data(),
                                  &raw_public_key_size) != 1 ||
      raw_public_key_size != raw_public_key.size()) {
    return common::Result<void>::Err(PublicKeyError());
  }
  const auto verified = provider.VerifyEd25519(manifest, signature, raw_public_key);
  // Do not propagate E_CRYPTO_UNAVAILABLE (or any other provider error): fold
  // it into the same signature-invalid error a genuine mismatch returns, so
  // callers see exactly the error set they saw before this migration.
  if (!verified.ok() || !verified.value()) {
    return common::Result<void>::Err(SignatureInvalidError());
  }
  return common::Result<void>::Ok();
}

namespace {

common::Result<IntegrityVerificationReport> VerifyIntegrityManifestImpl(
    const std::filesystem::path& manifest_path,
    const std::filesystem::path& signature_path,
    std::string_view public_key_pem,
    const std::filesystem::path& active_executable,
    const std::filesystem::path& active_config,
    crypto::CryptoProvider& provider,
    const VerificationHooks& hooks) {
  if (!IsAbsoluteNormalizedPath(manifest_path) ||
      !IsAbsoluteNormalizedPath(signature_path)) {
    return common::Result<IntegrityVerificationReport>::Err(ArtifactPathError());
  }
  if (!IsAbsoluteNormalizedPath(active_executable) ||
      !IsAbsoluteNormalizedPath(active_config)) {
    return common::Result<IntegrityVerificationReport>::Err(ManifestContractError());
  }
  const auto manifest_bytes = ReadRegularFile(manifest_path, kMaximumManifestBytes,
                                              hooks);
  if (!manifest_bytes.ok()) {
    return common::Result<IntegrityVerificationReport>::Err(manifest_bytes.error());
  }
  const auto signature_bytes = ReadRegularFile(signature_path,
                                               kExpectedSignatureBytes + 1U,
                                               hooks);
  if (!signature_bytes.ok()) {
    return common::Result<IntegrityVerificationReport>::Err(signature_bytes.error());
  }
  const auto signature = VerifyEd25519Signature(
      manifest_bytes.value(), signature_bytes.value(), public_key_pem, provider);
  if (!signature.ok()) {
    return common::Result<IntegrityVerificationReport>::Err(signature.error());
  }
  const auto manifest = ParseIntegrityManifest(
      {reinterpret_cast<const char*>(manifest_bytes.value().data()),
       manifest_bytes.value().size()});
  if (!manifest.ok()) {
    return common::Result<IntegrityVerificationReport>::Err(manifest.error());
  }
  if (!MeetsActiveProcessContract(manifest.value(), active_executable, active_config)) {
    return common::Result<IntegrityVerificationReport>::Err(ManifestContractError());
  }

  IntegrityVerificationReport report;
  report.passed = true;
  if (hooks.inject_fault) {
    hooks.inject_fault(VerificationFaultPoint::kReportReserve);
  }
  report.items.reserve(manifest.value().files.size());
  for (const IntegrityEntry& entry : manifest.value().files) {
    if (hooks.inject_fault) {
      hooks.inject_fault(VerificationFaultPoint::kReportItemCopy);
    }
    IntegrityItemResult item{entry.id, entry.category, false, ""};
    const auto actual = DigestRegularFile(entry.path);
    if (!actual.ok()) {
      item.code = actual.error().code;
      report.passed = false;
    } else if (CRYPTO_memcmp(actual.value().data(), entry.expected_sha256.data(),
                             entry.expected_sha256.size()) != 0) {
      item.code = "E_INTEGRITY_DIGEST_MISMATCH";
      report.passed = false;
    } else {
      item.passed = true;
      item.code = "OK";
    }
    if (hooks.inject_fault) {
      hooks.inject_fault(VerificationFaultPoint::kReportItemAppend);
    }
    report.items.push_back(std::move(item));
  }
  return common::Result<IntegrityVerificationReport>::Ok(std::move(report));
}

common::Result<IntegrityVerificationReport> VerifyIntegrityManifestBoundary(
    const std::filesystem::path& manifest_path,
    const std::filesystem::path& signature_path,
    std::string_view public_key_pem,
    const std::filesystem::path& active_executable,
    const std::filesystem::path& active_config,
    crypto::CryptoProvider& provider,
    const VerificationHooks& hooks) {
  try {
    return VerifyIntegrityManifestImpl(
        manifest_path, signature_path, public_key_pem, active_executable,
        active_config, provider, hooks);
  } catch (const std::exception&) {
    return common::Result<IntegrityVerificationReport>::ErrFromStaticLifetime(
        kResourceError);
  }
}

}  // namespace

common::Result<IntegrityVerificationReport> VerifyIntegrityManifest(
    const std::filesystem::path& manifest_path,
    const std::filesystem::path& signature_path,
    std::string_view public_key_pem,
    const std::filesystem::path& active_executable,
    const std::filesystem::path& active_config,
    crypto::CryptoProvider& provider) {
  return VerifyIntegrityManifestBoundary(manifest_path, signature_path,
                                         public_key_pem, active_executable,
                                         active_config, provider, {});
}

#if defined(CAMERA_FIRMWARE_INTEGRITY_TESTING)

namespace testing {

common::Result<IntegrityVerificationReport>
VerifyIntegrityManifestWithArtifactReadHook(
    const std::filesystem::path& manifest_path,
    const std::filesystem::path& signature_path,
    std::string_view public_key_pem,
    const std::filesystem::path& active_executable,
    const std::filesystem::path& active_config,
    crypto::CryptoProvider& provider,
    ArtifactReadHook hook) {
  VerificationHooks hooks;
  hooks.before_artifact_read = std::move(hook);
  return VerifyIntegrityManifestBoundary(
      manifest_path, signature_path, public_key_pem, active_executable,
      active_config, provider, hooks);
}

common::Result<IntegrityVerificationReport>
VerifyIntegrityManifestWithTestHooks(
    const std::filesystem::path& manifest_path,
    const std::filesystem::path& signature_path,
    std::string_view public_key_pem,
    const std::filesystem::path& active_executable,
    const std::filesystem::path& active_config,
    crypto::CryptoProvider& provider,
    IntegrityVerifierTestHooks test_hooks) {
  VerificationHooks hooks;
  hooks.before_artifact_read = std::move(test_hooks.before_artifact_read);
  hooks.read = std::move(test_hooks.read);
  if (test_hooks.inject_fault) {
    hooks.inject_fault =
        [inject_fault = std::move(test_hooks.inject_fault)](
            VerificationFaultPoint point) {
          switch (point) {
            case VerificationFaultPoint::kReportReserve:
              inject_fault(VerifierFaultPoint::kReportReserve);
              return;
            case VerificationFaultPoint::kReportItemCopy:
              inject_fault(VerifierFaultPoint::kReportItemCopy);
              return;
            case VerificationFaultPoint::kReportItemAppend:
              inject_fault(VerifierFaultPoint::kReportItemAppend);
              return;
          }
        };
  }
  return VerifyIntegrityManifestBoundary(
      manifest_path, signature_path, public_key_pem, active_executable,
      active_config, provider, hooks);
}

}  // namespace testing

#endif

}  // namespace camera_firmware::integrity
