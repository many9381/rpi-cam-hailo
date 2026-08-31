#include "camera_firmware/integrity/SafeFileDigest.hpp"

#if defined(CAMERA_FIRMWARE_INTEGRITY_TESTING)
#include "SafeFileDigestTestAccess.hpp"
#endif

#include <array>
#include <cerrno>
#include <cstddef>
#include <functional>
#include <memory>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace camera_firmware::integrity {
namespace {

constexpr std::size_t kReadBufferSize = 32U * 1024U;
constexpr unsigned int kMaximumEintrRetries = 3U;
constexpr std::size_t kHexCharactersPerByte = 2U;
constexpr char kHexDigits[] = "0123456789abcdef";

using EvpMdContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using DigestReadHook = std::function<void()>;

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

class OpenSslCleanseGuard {
 public:
  OpenSslCleanseGuard(void* data, std::size_t size) noexcept
      : data_(data), size_(size) {}

  ~OpenSslCleanseGuard() { OPENSSL_cleanse(data_, size_); }

  OpenSslCleanseGuard(const OpenSslCleanseGuard&) = delete;
  OpenSslCleanseGuard& operator=(const OpenSslCleanseGuard&) = delete;

 private:
  void* data_;
  std::size_t size_;
};

common::Error FileAccessError() {
  return {"E_INTEGRITY_FILE_ACCESS", "Unable to access integrity file"};
}

common::Error FileTypeError() {
  return {"E_INTEGRITY_FILE_TYPE", "Integrity input is not a regular file"};
}

common::Error FileChangedError() {
  return {"E_INTEGRITY_FILE_CHANGED", "Integrity input changed while hashing"};
}

common::Error FileReadError() {
  return {"E_INTEGRITY_FILE_READ", "Unable to read integrity file"};
}

common::Error DigestFormatError() {
  return {"E_INTEGRITY_DIGEST_FORMAT", "SHA-256 digest has invalid format"};
}

common::Error CryptoError() {
  return {"E_INTEGRITY_CRYPTO", "Integrity digest operation failed"};
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

int HexValue(char value) noexcept {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  return -1;
}

common::Result<Sha256Digest> DigestRegularFileImpl(
    const std::filesystem::path& path, DigestReadHook hook) {
  UniqueFd descriptor(
      OpenNoFollow(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW));
  if (descriptor.get() < 0) {
    return common::Result<Sha256Digest>::Err(
        errno == ELOOP ? FileTypeError() : FileAccessError());
  }

  struct stat initial_status {};
  if (!FstatNoIntr(descriptor.get(), &initial_status)) {
    return common::Result<Sha256Digest>::Err(FileReadError());
  }
  if (!S_ISREG(initial_status.st_mode)) {
    return common::Result<Sha256Digest>::Err(FileTypeError());
  }

  std::array<unsigned char, kReadBufferSize> buffer{};
  const OpenSslCleanseGuard buffer_cleanse(buffer.data(), buffer.size());
  try {
    if (hook) {
      hook();
    }
  } catch (...) {
    return common::Result<Sha256Digest>::Err(FileReadError());
  }

  EvpMdContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
    return common::Result<Sha256Digest>::Err(CryptoError());
  }

  unsigned int eintr_retries = 0U;
  while (true) {
    const ssize_t count = ::read(descriptor.get(), buffer.data(), buffer.size());
    if (count > 0) {
      eintr_retries = 0U;
      if (EVP_DigestUpdate(context.get(), buffer.data(),
                           static_cast<std::size_t>(count)) != 1) {
        return common::Result<Sha256Digest>::Err(CryptoError());
      }
      continue;
    }
    if (count == 0) {
      break;
    }
    if (errno == EINTR && eintr_retries++ < kMaximumEintrRetries) {
      continue;
    }
    return common::Result<Sha256Digest>::Err(FileReadError());
  }

  Sha256Digest digest{};
  unsigned int digest_size = 0U;
  if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1 ||
      digest_size != digest.size()) {
    return common::Result<Sha256Digest>::Err(CryptoError());
  }

  struct stat final_status {};
  if (!FstatNoIntr(descriptor.get(), &final_status)) {
    return common::Result<Sha256Digest>::Err(FileReadError());
  }
  if (!SameSnapshot(initial_status, final_status)) {
    return common::Result<Sha256Digest>::Err(FileChangedError());
  }

  UniqueFd path_descriptor(
      OpenNoFollow(path, O_PATH | O_CLOEXEC | O_NOFOLLOW));
  if (path_descriptor.get() < 0) {
    return common::Result<Sha256Digest>::Err(FileChangedError());
  }
  struct stat path_status {};
  if (!FstatNoIntr(path_descriptor.get(), &path_status) ||
      !S_ISREG(path_status.st_mode) ||
      path_status.st_dev != initial_status.st_dev ||
      path_status.st_ino != initial_status.st_ino) {
    return common::Result<Sha256Digest>::Err(FileChangedError());
  }

  return common::Result<Sha256Digest>::Ok(digest);
}

}  // namespace

common::Result<Sha256Digest> DigestRegularFile(
    const std::filesystem::path& path) {
  return DigestRegularFileImpl(path, {});
}

#if defined(CAMERA_FIRMWARE_INTEGRITY_TESTING)

namespace testing {
common::Result<Sha256Digest> DigestRegularFileWithReadHook(
    const std::filesystem::path& path, DigestReadHook hook) {
  return DigestRegularFileImpl(path, std::move(hook));
}

}  // namespace testing

#endif

std::string HexSha256(const Sha256Digest& digest) {
  std::string result;
  result.resize(digest.size() * kHexCharactersPerByte);
  for (std::size_t index = 0U; index < digest.size(); ++index) {
    result[index * kHexCharactersPerByte] = kHexDigits[digest[index] >> 4U];
    result[index * kHexCharactersPerByte + 1U] =
        kHexDigits[digest[index] & 0x0fU];
  }
  return result;
}

common::Result<Sha256Digest> ParseSha256(std::string_view value) {
  if (value.size() != Sha256Digest{}.size() * kHexCharactersPerByte) {
    return common::Result<Sha256Digest>::Err(DigestFormatError());
  }

  Sha256Digest digest{};
  for (std::size_t index = 0U; index < digest.size(); ++index) {
    const int high = HexValue(value[index * kHexCharactersPerByte]);
    const int low = HexValue(value[index * kHexCharactersPerByte + 1U]);
    if (high < 0 || low < 0) {
      return common::Result<Sha256Digest>::Err(DigestFormatError());
    }
    digest[index] = static_cast<unsigned char>((high << 4U) | low);
  }
  return common::Result<Sha256Digest>::Ok(digest);
}

}  // namespace camera_firmware::integrity
