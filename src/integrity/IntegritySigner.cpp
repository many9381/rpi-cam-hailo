#include "camera_firmware/integrity/IntegritySigner.hpp"

#if defined(CAMERA_FIRMWARE_INTEGRITY_TESTING)
#include "IntegritySignerTestAccess.hpp"
#endif

#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <yaml-cpp/yaml.h>

namespace camera_firmware::integrity {
namespace {

constexpr std::size_t kMaximumArtifactBytes = std::size_t{1024} * 1024U;
constexpr std::size_t kMaximumPathBytes = 4096U;
constexpr std::size_t kMaximumTemporaryAttempts = 128U;
constexpr unsigned int kMaximumEintrRetries = 3U;

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

class CleanseGuard {
 public:
  CleanseGuard(void* data, std::size_t size) noexcept
      : data_(data), size_(size) {}
  ~CleanseGuard() { OPENSSL_cleanse(data_, size_); }
  CleanseGuard(const CleanseGuard&) = delete;
  CleanseGuard& operator=(const CleanseGuard&) = delete;

 private:
  void* data_;
  std::size_t size_;
};

class TemporaryFileCleanup {
 public:
  TemporaryFileCleanup(int directory, std::string name) noexcept
      : directory_(directory), name_(std::move(name)) {}
  ~TemporaryFileCleanup() {
    if (active_) {
      (void)::unlinkat(directory_, name_.c_str(), 0);
    }
  }
  TemporaryFileCleanup(const TemporaryFileCleanup&) = delete;
  TemporaryFileCleanup& operator=(const TemporaryFileCleanup&) = delete;
  void Release() noexcept { active_ = false; }

 private:
  int directory_;
  std::string name_;
  bool active_{true};
};

const common::Error kManifestError{"E_INTEGRITY_TOOL_MANIFEST",
                                   "Unable to process integrity manifest"};
const common::Error kPrivateKeyError{"E_INTEGRITY_TOOL_PRIVATE_KEY",
                                     "Unable to use integrity private key"};
const common::Error kOutputError{"E_INTEGRITY_TOOL_OUTPUT",
                                 "Unable to publish integrity artifact"};
const common::Error kResourceError{"E_INTEGRITY_TOOL_RESOURCE",
                                   "Integrity tool resource failure"};

bool IsAbsoluteNormalizedPath(const std::filesystem::path& path) {
  const auto& native = path.native();
  return !path.empty() && native.size() <= kMaximumPathBytes &&
         native.find('\0') == std::string::npos && path.is_absolute() &&
         native == path.lexically_normal().native();
}

int OpenNoIntr(const std::filesystem::path& path, int flags, mode_t mode = 0U) {
  unsigned int retries = 0U;
  while (true) {
    const int descriptor = mode == 0U ? ::open(path.c_str(), flags)
                                      : ::open(path.c_str(), flags, mode);
    if (descriptor >= 0 || errno != EINTR ||
        retries++ == kMaximumEintrRetries) {
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

bool FstatAtNoIntr(int directory, const char* name, struct stat* status,
                   int flags) noexcept {
  unsigned int retries = 0U;
  while (true) {
    if (::fstatat(directory, name, status, flags) == 0) {
      return true;
    }
    if (errno != EINTR || retries++ == kMaximumEintrRetries) {
      return false;
    }
  }
}

int RenameAt2NoIntr(int old_directory, const char* old_name, int new_directory,
                    const char* new_name, unsigned int flags) noexcept {
  unsigned int retries = 0U;
  while (true) {
#if defined(SYS_renameat2)
    const int result =
        static_cast<int>(::syscall(SYS_renameat2, old_directory, old_name,
                                   new_directory, new_name, flags));
#else
    errno = ENOSYS;
    const int result = -1;
#endif
    if (result == 0 || errno != EINTR || retries++ == kMaximumEintrRetries) {
      return result;
    }
  }
}

bool UnlinkAtNoIntr(int directory, const char* name) noexcept {
  unsigned int retries = 0U;
  while (true) {
    if (::unlinkat(directory, name, 0) == 0) {
      return true;
    }
    if (errno != EINTR || retries++ == kMaximumEintrRetries) {
      return false;
    }
  }
}

bool FsyncNoIntr(int descriptor) noexcept {
  unsigned int retries = 0U;
  while (true) {
    if (::fsync(descriptor) == 0) {
      return true;
    }
    if (errno != EINTR || retries++ == kMaximumEintrRetries) {
      return false;
    }
  }
}

bool SameSnapshot(const struct stat& before,
                  const struct stat& after) noexcept {
  return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
         before.st_size == after.st_size &&
         before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
         before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
         before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
         before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

bool SameIdentity(const struct stat& before,
                  const struct stat& after) noexcept {
  return before.st_dev == after.st_dev && before.st_ino == after.st_ino;
}

bool WriteAllBounded(int descriptor,
                     std::span<const unsigned char> bytes) noexcept {
  std::size_t offset = 0U;
  unsigned int retries = 0U;
  while (offset < bytes.size()) {
    const ssize_t written =
        ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
    if (written > 0) {
      offset += static_cast<std::size_t>(written);
      retries = 0U;
      continue;
    }
    if (written < 0 && errno == EINTR && retries++ < kMaximumEintrRetries) {
      continue;
    }
    return false;
  }
  return true;
}

bool HasOnlyPemWhitespace(BIO* bio) {
  std::array<char, 256U> buffer{};
  const CleanseGuard cleanse(buffer.data(), buffer.size());
  while (BIO_ctrl_pending(bio) > 0L) {
    const int count =
        BIO_read(bio, buffer.data(), static_cast<int>(buffer.size()));
    if (count <= 0) {
      return false;
    }
    for (int index = 0; index < count; ++index) {
      if (std::isspace(static_cast<unsigned char>(
              buffer[static_cast<std::size_t>(index)])) == 0) {
        return false;
      }
    }
  }
  return true;
}

common::Result<std::vector<unsigned char>> ReadRegularFile(
    const std::filesystem::path& path, std::size_t maximum_size,
    const common::Error& error) {
  if (!IsAbsoluteNormalizedPath(path)) {
    return common::Result<std::vector<unsigned char>>::ErrFromStaticLifetime(
        error);
  }
  UniqueFd descriptor(
      OpenNoIntr(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW));
  if (descriptor.get() < 0) {
    return common::Result<std::vector<unsigned char>>::ErrFromStaticLifetime(
        error);
  }
  struct stat initial {};
  if (!FstatNoIntr(descriptor.get(), &initial) || !S_ISREG(initial.st_mode) ||
      initial.st_size < 0 ||
      static_cast<std::uintmax_t>(initial.st_size) > maximum_size) {
    return common::Result<std::vector<unsigned char>>::ErrFromStaticLifetime(
        error);
  }

  try {
    std::vector<unsigned char> bytes(maximum_size + 1U, 0U);
    const CleanseGuard cleanse(bytes.data(), bytes.size());
    std::size_t size = 0U;
    unsigned int retries = 0U;
    while (size < bytes.size()) {
      const ssize_t count =
          ::read(descriptor.get(), bytes.data() + size, bytes.size() - size);
      if (count > 0) {
        size += static_cast<std::size_t>(count);
        retries = 0U;
        continue;
      }
      if (count == 0) {
        break;
      }
      if (errno == EINTR && retries++ < kMaximumEintrRetries) {
        continue;
      }
      return common::Result<std::vector<unsigned char>>::ErrFromStaticLifetime(
          error);
    }
    if (size > maximum_size) {
      return common::Result<std::vector<unsigned char>>::ErrFromStaticLifetime(
          error);
    }
    struct stat final_status {};
    if (!FstatNoIntr(descriptor.get(), &final_status) ||
        !SameSnapshot(initial, final_status)) {
      return common::Result<std::vector<unsigned char>>::ErrFromStaticLifetime(
          error);
    }
    UniqueFd path_descriptor(OpenNoIntr(path, O_PATH | O_CLOEXEC | O_NOFOLLOW));
    struct stat path_status {};
    if (path_descriptor.get() < 0 ||
        !FstatNoIntr(path_descriptor.get(), &path_status) ||
        !S_ISREG(path_status.st_mode) || path_status.st_dev != initial.st_dev ||
        path_status.st_ino != initial.st_ino) {
      return common::Result<std::vector<unsigned char>>::ErrFromStaticLifetime(
          error);
    }
    std::vector<unsigned char> result(bytes.begin(), bytes.begin() + size);
    return common::Result<std::vector<unsigned char>>::Ok(std::move(result));
  } catch (...) {
    return common::Result<std::vector<unsigned char>>::ErrFromStaticLifetime(
        kResourceError);
  }
}

common::Result<EvpPkey> ReadEd25519PrivateKey(
    const std::filesystem::path& private_key_path) {
  if (!IsAbsoluteNormalizedPath(private_key_path)) {
    return common::Result<EvpPkey>::ErrFromStaticLifetime(kPrivateKeyError);
  }
  UniqueFd descriptor(OpenNoIntr(
      private_key_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW));
  if (descriptor.get() < 0) {
    return common::Result<EvpPkey>::ErrFromStaticLifetime(kPrivateKeyError);
  }
  struct stat initial {};
  if (!FstatNoIntr(descriptor.get(), &initial) || !S_ISREG(initial.st_mode) ||
      initial.st_size <= 0 ||
      static_cast<std::uintmax_t>(initial.st_size) > kMaximumArtifactBytes) {
    return common::Result<EvpPkey>::ErrFromStaticLifetime(kPrivateKeyError);
  }
  try {
    // Keep every possible PEM byte in one bounded buffer and cleanse it on
    // every exit.
    std::vector<unsigned char> bytes(kMaximumArtifactBytes + 1U, 0U);
    const CleanseGuard cleanse(bytes.data(), bytes.size());
    std::size_t size = 0U;
    unsigned int retries = 0U;
    while (size < bytes.size()) {
      const ssize_t count =
          ::read(descriptor.get(), bytes.data() + size, bytes.size() - size);
      if (count > 0) {
        size += static_cast<std::size_t>(count);
        retries = 0U;
        continue;
      }
      if (count == 0) {
        break;
      }
      if (errno == EINTR && retries++ < kMaximumEintrRetries) {
        continue;
      }
      return common::Result<EvpPkey>::ErrFromStaticLifetime(kPrivateKeyError);
    }
    if (size == 0U || size > kMaximumArtifactBytes ||
        size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
      return common::Result<EvpPkey>::ErrFromStaticLifetime(kPrivateKeyError);
    }
    struct stat final_status {};
    if (!FstatNoIntr(descriptor.get(), &final_status) ||
        !SameSnapshot(initial, final_status)) {
      return common::Result<EvpPkey>::ErrFromStaticLifetime(kPrivateKeyError);
    }
    UniqueFd path_descriptor(
        OpenNoIntr(private_key_path, O_PATH | O_CLOEXEC | O_NOFOLLOW));
    struct stat path_status {};
    if (path_descriptor.get() < 0 ||
        !FstatNoIntr(path_descriptor.get(), &path_status) ||
        !S_ISREG(path_status.st_mode) || path_status.st_dev != initial.st_dev ||
        path_status.st_ino != initial.st_ino) {
      return common::Result<EvpPkey>::ErrFromStaticLifetime(kPrivateKeyError);
    }
    Bio bio(BIO_new_mem_buf(bytes.data(), static_cast<int>(size)), BIO_free);
    EvpPkey key(
        bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)
            : nullptr,
        EVP_PKEY_free);
    if (!key || !HasOnlyPemWhitespace(bio.get()) ||
        !EVP_PKEY_is_a(key.get(), "ED25519")) {
      return common::Result<EvpPkey>::ErrFromStaticLifetime(kPrivateKeyError);
    }
    return common::Result<EvpPkey>::Ok(std::move(key));
  } catch (...) {
    return common::Result<EvpPkey>::ErrFromStaticLifetime(kResourceError);
  }
}

std::atomic<unsigned long long> g_temporary_sequence{0U};

}  // namespace

common::Result<std::string> SerializeIntegrityManifest(
    const IntegrityManifest& manifest) {
  try {
    YAML::Node root(YAML::NodeType::Map);
    root["schema_version"] = manifest.schema_version;
    root["product"] = manifest.product;
    root["created_at"] = manifest.created_at;
    YAML::Node files(YAML::NodeType::Sequence);
    for (const IntegrityEntry& entry : manifest.files) {
      YAML::Node file(YAML::NodeType::Map);
      file["id"] = entry.id;
      file["category"] = std::string(IntegrityCategoryName(entry.category));
      file["path"] = entry.path.string();
      file["sha256"] = HexSha256(entry.expected_sha256);
      files.push_back(file);
    }
    root["files"] = files;
    YAML::Emitter emitter;
    emitter << root;
    if (!emitter.good()) {
      return common::Result<std::string>::ErrFromStaticLifetime(kManifestError);
    }
    std::string bytes(emitter.c_str(), emitter.size());
    bytes.push_back('\n');
    const auto parsed = ParseIntegrityManifest(bytes);
    if (!parsed.ok()) {
      return common::Result<std::string>::ErrFromStaticLifetime(kManifestError);
    }
    return common::Result<std::string>::Ok(std::move(bytes));
  } catch (...) {
    return common::Result<std::string>::ErrFromStaticLifetime(kResourceError);
  }
}

common::Result<std::vector<unsigned char>> ReadIntegrityManifestForSigning(
    const std::filesystem::path& path) {
  return ReadRegularFile(path, kMaximumArtifactBytes, kManifestError);
}

common::Result<std::array<unsigned char, 64U>> SignIntegrityManifest(
    std::span<const unsigned char> bytes,
    const std::filesystem::path& private_key_path,
    crypto::CryptoProvider& provider) {
  const auto private_key = ReadEd25519PrivateKey(private_key_path);
  if (!private_key.ok()) {
    return common::Result<std::array<unsigned char, 64U>>::Err(
        private_key.error());
  }
  // The PEM decode above stays exactly as it was; only the signing operation
  // itself moves behind the crypto provider, which takes a raw 32-byte seed
  // rather than an EVP_PKEY. Ed25519 PEM keys (PKCS8) are wrappers around
  // that same seed, so extracting it here is lossless. The seed is signing
  // key material: CleanseGuard zeroizes it on every exit from this function,
  // including error returns.
  std::array<unsigned char, crypto::kEd25519SeedBytes> seed{};
  const CleanseGuard seed_cleanse(seed.data(), seed.size());
  std::size_t seed_size = seed.size();
  if (EVP_PKEY_get_raw_private_key(private_key.value().get(), seed.data(),
                                   &seed_size) != 1 ||
      seed_size != seed.size()) {
    return common::Result<std::array<unsigned char, 64U>>::
        ErrFromStaticLifetime(kPrivateKeyError);
  }
  const auto signature = provider.SignEd25519(bytes, seed);
  // Do not propagate E_CRYPTO_UNAVAILABLE (or any other provider error): fold
  // it into the same error this function already returned for a failed sign.
  if (!signature.ok()) {
    return common::Result<std::array<unsigned char, 64U>>::
        ErrFromStaticLifetime(kPrivateKeyError);
  }
  return common::Result<std::array<unsigned char, 64U>>::Ok(signature.value());
}

namespace {

common::Result<void> WriteIntegrityArtifactAtomicallyImpl(
    const std::filesystem::path& output, std::span<const unsigned char> bytes,
    const std::function<void()>* before_publish) {
  if (!IsAbsoluteNormalizedPath(output) || output.filename().empty()) {
    return common::Result<void>::ErrFromStaticLifetime(kOutputError);
  }
  UniqueFd directory(OpenNoIntr(
      output.parent_path(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  struct stat directory_status {};
  if (directory.get() < 0 || !FstatNoIntr(directory.get(), &directory_status) ||
      !S_ISDIR(directory_status.st_mode)) {
    return common::Result<void>::ErrFromStaticLifetime(kOutputError);
  }

  const std::string base = output.filename().string();
  for (std::size_t attempt = 0U; attempt < kMaximumTemporaryAttempts;
       ++attempt) {
    const std::string temporary =
        "." + base + ".tmp-" + std::to_string(::getpid()) + "-" +
        std::to_string(g_temporary_sequence.fetch_add(1U));
    UniqueFd file(::openat(directory.get(), temporary.c_str(),
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                           S_IRUSR | S_IWUSR));
    if (file.get() < 0) {
      if (errno == EEXIST) {
        continue;
      }
      return common::Result<void>::ErrFromStaticLifetime(kOutputError);
    }
    TemporaryFileCleanup cleanup(directory.get(), temporary);
    if (::fchmod(file.get(), S_IRUSR | S_IWUSR) != 0 ||
        !WriteAllBounded(file.get(), bytes) || !FsyncNoIntr(file.get())) {
      return common::Result<void>::ErrFromStaticLifetime(kOutputError);
    }

    struct stat destination {};
    const bool destination_exists = FstatAtNoIntr(
        directory.get(), base.c_str(), &destination, AT_SYMLINK_NOFOLLOW);
    if (!destination_exists && errno != ENOENT) {
      return common::Result<void>::ErrFromStaticLifetime(kOutputError);
    }
    if (destination_exists && !S_ISREG(destination.st_mode)) {
      return common::Result<void>::ErrFromStaticLifetime(kOutputError);
    }
    if (before_publish != nullptr) {
      (*before_publish)();
    }

    if (!destination_exists) {
      if (RenameAt2NoIntr(directory.get(), temporary.c_str(), directory.get(),
                          base.c_str(), RENAME_NOREPLACE) != 0) {
        return common::Result<void>::ErrFromStaticLifetime(kOutputError);
      }
      cleanup.Release();
    } else {
      if (RenameAt2NoIntr(directory.get(), temporary.c_str(), directory.get(),
                          base.c_str(), RENAME_EXCHANGE) != 0) {
        return common::Result<void>::ErrFromStaticLifetime(kOutputError);
      }
      cleanup.Release();

      struct stat replaced {};
      if (!FstatAtNoIntr(directory.get(), temporary.c_str(), &replaced,
                         AT_SYMLINK_NOFOLLOW) ||
          !S_ISREG(replaced.st_mode) || !SameIdentity(destination, replaced)) {
        if (RenameAt2NoIntr(directory.get(), temporary.c_str(), directory.get(),
                            base.c_str(), RENAME_EXCHANGE) == 0) {
          (void)UnlinkAtNoIntr(directory.get(), temporary.c_str());
        }
        return common::Result<void>::ErrFromStaticLifetime(kOutputError);
      }
      if (!UnlinkAtNoIntr(directory.get(), temporary.c_str())) {
        return common::Result<void>::ErrFromStaticLifetime(kOutputError);
      }
    }
    if (!FsyncNoIntr(directory.get())) {
      return common::Result<void>::ErrFromStaticLifetime(kOutputError);
    }
    return common::Result<void>::Ok();
  }
  return common::Result<void>::ErrFromStaticLifetime(kOutputError);
}

}  // namespace

common::Result<void> WriteIntegrityArtifactAtomically(
    const std::filesystem::path& output, std::span<const unsigned char> bytes) {
  return WriteIntegrityArtifactAtomicallyImpl(output, bytes, nullptr);
}

#if defined(CAMERA_FIRMWARE_INTEGRITY_TESTING)
namespace testing {

common::Result<void> WriteIntegrityArtifactAtomicallyWithPrePublishHook(
    const std::filesystem::path& output, std::span<const unsigned char> bytes,
    std::function<void()> before_publish) {
  return WriteIntegrityArtifactAtomicallyImpl(output, bytes, &before_publish);
}

}  // namespace testing
#endif

}  // namespace camera_firmware::integrity
