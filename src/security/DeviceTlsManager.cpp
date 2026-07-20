#include "camera_firmware/security/DeviceTlsManager.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <climits>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "camera_firmware/common/SecureBytes.hpp"

extern "C" int camera_firmware_tls_rename_noreplace(
    int old_directory,
    const char* old_name,
    int new_directory,
    const char* new_name);

namespace camera_firmware::security {

namespace detail {

struct ResolvedTlsHandles {
  int certificate{-1};
  int private_key{-1};

  ~ResolvedTlsHandles() {
    if (certificate >= 0) {
      (void)::close(certificate);
    }
    if (private_key >= 0) {
      (void)::close(private_key);
    }
  }
};

}  // namespace detail

namespace {

constexpr std::string_view kIdentityDirectory = "device-tls";
constexpr std::string_view kCertificateName = "certificate.pem";
constexpr std::string_view kPrivateKeyName = "private-key.pem";
constexpr std::string_view kTemporaryPrefix = ".device-tls.tmp-";
constexpr mode_t kStateDirectoryMode = 0700;
constexpr mode_t kIdentityDirectoryMode = 0700;
constexpr mode_t kPrivateKeyMode = 0600;
constexpr mode_t kCertificateMode = 0644;
constexpr std::size_t kMaximumPemBytes = 1024U * 1024U;
constexpr long kCertificateLifetimeSeconds = 5L * 365L * 24L * 60L * 60L;

class UniqueFd {
 public:
  UniqueFd() = default;
  explicit UniqueFd(int descriptor) noexcept : descriptor_(descriptor) {}
  ~UniqueFd() { Reset(); }

  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;
  UniqueFd(UniqueFd&& other) noexcept
      : descriptor_(std::exchange(other.descriptor_, -1)) {}
  UniqueFd& operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
      Reset();
      descriptor_ = std::exchange(other.descriptor_, -1);
    }
    return *this;
  }

  void Reset(int descriptor = -1) noexcept {
    if (descriptor_ >= 0) {
      (void)::close(descriptor_);
    }
    descriptor_ = descriptor;
  }

  [[nodiscard]] int Release() noexcept {
    return std::exchange(descriptor_, -1);
  }

  [[nodiscard]] int get() const noexcept { return descriptor_; }
  [[nodiscard]] bool valid() const noexcept { return descriptor_ >= 0; }

 private:
  int descriptor_{-1};
};

class DirectoryLock {
 public:
  explicit DirectoryLock(int descriptor) noexcept : descriptor_(descriptor) {}
  ~DirectoryLock() {
    if (locked_) {
      (void)::flock(descriptor_, LOCK_UN);
    }
  }

  DirectoryLock(const DirectoryLock&) = delete;
  DirectoryLock& operator=(const DirectoryLock&) = delete;

  bool Lock() noexcept {
    int result = 0;
    do {
      result = ::flock(descriptor_, LOCK_EX);
    } while (result != 0 && errno == EINTR);
    locked_ = result == 0;
    return locked_;
  }

 private:
  int descriptor_;
  bool locked_{false};
};

struct DirectoryStreamCloser {
  void operator()(DIR* directory) const noexcept {
    if (directory != nullptr) {
      (void)::closedir(directory);
    }
  }
};

using DirectoryStreamPtr = std::unique_ptr<DIR, DirectoryStreamCloser>;

class SecretMemoryBio {
 public:
  SecretMemoryBio() : bio_(BIO_new(BIO_s_mem())) {}
  ~SecretMemoryBio() {
    if (bio_ != nullptr) {
      BUF_MEM* memory = nullptr;
      BIO_get_mem_ptr(bio_, &memory);
      if (memory != nullptr && memory->data != nullptr && memory->length != 0U) {
        OPENSSL_cleanse(memory->data, memory->length);
      }
      BIO_free(bio_);
    }
  }

  SecretMemoryBio(const SecretMemoryBio&) = delete;
  SecretMemoryBio& operator=(const SecretMemoryBio&) = delete;

  [[nodiscard]] BIO* get() const noexcept { return bio_; }

 private:
  BIO* bio_{nullptr};
};

bool FsyncRetryEintr(int descriptor) noexcept {
  int result = 0;
  do {
    result = ::fsync(descriptor);
  } while (result != 0 && errno == EINTR);
  return result == 0;
}

class TemporaryIdentityDirectory {
 public:
  TemporaryIdentityDirectory(int parent, std::string name) noexcept
      : parent_(parent), name_(std::move(name)) {}
  ~TemporaryIdentityDirectory() { Cleanup(); }

  TemporaryIdentityDirectory(const TemporaryIdentityDirectory&) = delete;
  TemporaryIdentityDirectory& operator=(const TemporaryIdentityDirectory&) =
      delete;

  void Published() noexcept { active_ = false; }

 private:
  void Cleanup() noexcept {
    if (!active_) {
      return;
    }
    UniqueFd directory(::openat(parent_, name_.c_str(),
                                O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                    O_NOFOLLOW));
    if (directory.valid()) {
      (void)::unlinkat(directory.get(), kPrivateKeyName.data(), 0);
      (void)::unlinkat(directory.get(), kCertificateName.data(), 0);
      (void)FsyncRetryEintr(directory.get());
    }
    if (::unlinkat(parent_, name_.c_str(), AT_REMOVEDIR) == 0) {
      (void)FsyncRetryEintr(parent_);
    }
  }

  int parent_;
  std::string name_;
  bool active_{true};
};

using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

int RejectEncryptedPemPassword(char*, int, int, void*) { return 0; }

std::vector<std::string> ExpectedDnsNames();

template <typename T>
common::Result<T> TlsError(std::string code, std::string message) {
  ERR_clear_error();
  return common::Result<T>::Err({std::move(code), std::move(message)});
}

common::Result<void> TlsError(std::string code, std::string message) {
  ERR_clear_error();
  return common::Result<void>::Err({std::move(code), std::move(message)});
}

bool HasMode(const struct stat& status, mode_t expected) {
  return (status.st_mode & 0777) == expected;
}

bool CertificateModeIsProtected(const struct stat& status) {
  const mode_t mode = status.st_mode & 0777;
  return (mode & ~kCertificateMode) == 0 && (mode & 0400) != 0;
}

bool IsProtectedDirectory(const struct stat& status, uid_t owner,
                          mode_t expected_mode) {
  return S_ISDIR(status.st_mode) && !S_ISLNK(status.st_mode) &&
         status.st_uid == owner && HasMode(status, expected_mode);
}

bool HasOneExtension(X509* certificate, int nid) {
  const int first = X509_get_ext_by_NID(certificate, nid, -1);
  return first >= 0 && X509_get_ext_by_NID(certificate, nid, first) < 0;
}

bool GeneratedCertificateExtensionsAreExact(X509* certificate) {
  constexpr int kGeneratedExtensionCount = 4;
  if (X509_get_ext_count(certificate) != kGeneratedExtensionCount) {
    return false;
  }

  int critical = -1;
  std::unique_ptr<BASIC_CONSTRAINTS, decltype(&BASIC_CONSTRAINTS_free)>
      constraints(static_cast<BASIC_CONSTRAINTS*>(X509_get_ext_d2i(
                      certificate, NID_basic_constraints, &critical, nullptr)),
                  BASIC_CONSTRAINTS_free);
  if (!HasOneExtension(certificate, NID_basic_constraints) || !constraints ||
      critical != 1 || constraints->ca != 0 || constraints->pathlen != nullptr) {
    return false;
  }

  critical = -1;
  std::unique_ptr<ASN1_BIT_STRING, decltype(&ASN1_BIT_STRING_free)> key_usage(
      static_cast<ASN1_BIT_STRING*>(
          X509_get_ext_d2i(certificate, NID_key_usage, &critical, nullptr)),
      ASN1_BIT_STRING_free);
  if (!HasOneExtension(certificate, NID_key_usage) || !key_usage ||
      critical != 1 || ASN1_BIT_STRING_get_bit(key_usage.get(), 0) != 1) {
    return false;
  }
  for (int bit = 1; bit <= 8; ++bit) {
    if (ASN1_BIT_STRING_get_bit(key_usage.get(), bit) != 0) {
      return false;
    }
  }

  critical = -1;
  std::unique_ptr<EXTENDED_KEY_USAGE, decltype(&EXTENDED_KEY_USAGE_free)>
      extended_usage(static_cast<EXTENDED_KEY_USAGE*>(X509_get_ext_d2i(
                         certificate, NID_ext_key_usage, &critical, nullptr)),
                     EXTENDED_KEY_USAGE_free);
  if (!HasOneExtension(certificate, NID_ext_key_usage) || !extended_usage ||
      critical != 0 || sk_ASN1_OBJECT_num(extended_usage.get()) != 1 ||
      OBJ_obj2nid(sk_ASN1_OBJECT_value(extended_usage.get(), 0)) !=
          NID_server_auth) {
    return false;
  }

  critical = -1;
  std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names(
      static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(
          certificate, NID_subject_alt_name, &critical, nullptr)),
      GENERAL_NAMES_free);
  if (!HasOneExtension(certificate, NID_subject_alt_name) || !names ||
      critical != 0) {
    return false;
  }

  std::vector<std::string> dns_names;
  std::vector<std::vector<unsigned char>> ip_addresses;
  for (int index = 0; index < sk_GENERAL_NAME_num(names.get()); ++index) {
    const GENERAL_NAME* name = sk_GENERAL_NAME_value(names.get(), index);
    if (name->type == GEN_DNS) {
      const int size = ASN1_STRING_length(name->d.dNSName);
      const unsigned char* data = ASN1_STRING_get0_data(name->d.dNSName);
      if (size <= 0 || data == nullptr ||
          std::find(data, data + size, '\0') != data + size) {
        return false;
      }
      dns_names.emplace_back(reinterpret_cast<const char*>(data),
                             static_cast<std::size_t>(size));
    } else if (name->type == GEN_IPADD) {
      const int size = ASN1_STRING_length(name->d.iPAddress);
      const unsigned char* data = ASN1_STRING_get0_data(name->d.iPAddress);
      if ((size != 4 && size != 16) || data == nullptr) {
        return false;
      }
      ip_addresses.emplace_back(data, data + size);
    } else {
      return false;
    }
  }

  auto expected_dns_names = ExpectedDnsNames();
  std::sort(dns_names.begin(), dns_names.end());
  std::sort(expected_dns_names.begin(), expected_dns_names.end());
  std::sort(ip_addresses.begin(), ip_addresses.end());
  std::vector<std::vector<unsigned char>> expected_ip_addresses{
      {127U, 0U, 0U, 1U},
      {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
       0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}};
  std::sort(expected_ip_addresses.begin(), expected_ip_addresses.end());
  return dns_names == expected_dns_names &&
         ip_addresses == expected_ip_addresses;
}

bool GeneratedCertificateValidityIsBounded(X509* certificate) {
  int days = 0;
  int seconds = 0;
  if (ASN1_TIME_diff(&days, &seconds,
                     X509_get0_notBefore(certificate),
                     X509_get0_notAfter(certificate)) != 1 ||
      days < 0 || seconds < 0) {
    return false;
  }
  constexpr long long kMaximumValiditySeconds =
      static_cast<long long>(kCertificateLifetimeSeconds) + 300LL;
  const long long validity_seconds =
      static_cast<long long>(days) * 24LL * 60LL * 60LL + seconds;
  return validity_seconds > 0 && validity_seconds <= kMaximumValiditySeconds;
}

bool GeneratedCertificateProfileIsValid(X509* certificate) {
  int digest_nid = NID_undef;
  int public_key_nid = NID_undef;
  int security_bits = 0;
  std::uint32_t signature_flags = 0;
  return X509_get_version(certificate) == 2 &&
         X509_get_signature_info(certificate, &digest_nid, &public_key_nid,
                                 &security_bits, &signature_flags) == 1 &&
         digest_nid == NID_sha256 &&
         X509_get_signature_nid(certificate) == NID_ecdsa_with_SHA256 &&
         GeneratedCertificateExtensionsAreExact(certificate) &&
         GeneratedCertificateValidityIsBounded(certificate);
}

struct OpenedPemFile {
  UniqueFd descriptor;
  common::SecureBytes bytes;
};

struct PreparedTlsMaterial {
  OpenedPemFile certificate;
  OpenedPemFile private_key;
  bool generated_for_development{false};
};

struct PinnedPemSnapshot {
  struct stat status {};
  common::SecureBytes bytes;
};

bool SamePemSnapshot(const struct stat& first,
                     const struct stat& second) noexcept {
  return first.st_dev == second.st_dev && first.st_ino == second.st_ino &&
         first.st_size == second.st_size && first.st_mtim.tv_sec == second.st_mtim.tv_sec &&
         first.st_mtim.tv_nsec == second.st_mtim.tv_nsec &&
         first.st_ctim.tv_sec == second.st_ctim.tv_sec &&
         first.st_ctim.tv_nsec == second.st_ctim.tv_nsec;
}

class PrivatePemCleanser {
 public:
  explicit PrivatePemCleanser(common::SecureBytes& bytes) noexcept
      : bytes_(bytes) {}
  ~PrivatePemCleanser() {
    if (active_ && bytes_.size() != 0U) {
      OPENSSL_cleanse(bytes_.data(), bytes_.size());
      bytes_.clear();
    }
  }

  PrivatePemCleanser(const PrivatePemCleanser&) = delete;
  PrivatePemCleanser& operator=(const PrivatePemCleanser&) = delete;
  void Release() noexcept { active_ = false; }

 private:
  common::SecureBytes& bytes_;
  bool active_{true};
};

class PemInspectionBufferCleanser {
 public:
  PemInspectionBufferCleanser(void* data, std::size_t size) noexcept
      : data_(data), size_(size) {}
  ~PemInspectionBufferCleanser() { OPENSSL_cleanse(data_, size_); }

  PemInspectionBufferCleanser(const PemInspectionBufferCleanser&) = delete;
  PemInspectionBufferCleanser& operator=(
      const PemInspectionBufferCleanser&) = delete;

 private:
  void* data_;
  std::size_t size_;
};

common::Result<PinnedPemSnapshot> ReadPinnedPemSnapshot(int descriptor,
                                                         bool private_key) {
  struct stat initial {};
  if (::fstat(descriptor, &initial) != 0 || !S_ISREG(initial.st_mode) ||
      S_ISLNK(initial.st_mode) || initial.st_uid != ::geteuid() ||
      initial.st_nlink != 1 ||
      (private_key ? !HasMode(initial, kPrivateKeyMode)
                   : !CertificateModeIsProtected(initial)) ||
      initial.st_size <= 0 ||
      static_cast<unsigned long long>(initial.st_size) > kMaximumPemBytes) {
    return TlsError<PinnedPemSnapshot>("E_SECURITY_TLS_HEALTH",
                                       "TLS identity health check failed");
  }

  PinnedPemSnapshot snapshot;
  snapshot.status = initial;
  PrivatePemCleanser cleanser(snapshot.bytes);
  try {
    snapshot.bytes.resize(static_cast<std::size_t>(initial.st_size));
  } catch (...) {
    return TlsError<PinnedPemSnapshot>("E_SECURITY_TLS_HEALTH",
                                       "TLS identity health check failed");
  }
  std::size_t offset = 0U;
  while (offset < snapshot.bytes.size()) {
    const ssize_t read_size =
        ::pread(descriptor, snapshot.bytes.data() + offset,
                snapshot.bytes.size() - offset, static_cast<off_t>(offset));
    if (read_size < 0 && errno == EINTR) {
      continue;
    }
    if (read_size <= 0) {
      return TlsError<PinnedPemSnapshot>("E_SECURITY_TLS_HEALTH",
                                         "TLS identity health check failed");
    }
    offset += static_cast<std::size_t>(read_size);
  }
  struct stat final_status {};
  if (::fstat(descriptor, &final_status) != 0 ||
      !S_ISREG(final_status.st_mode) || S_ISLNK(final_status.st_mode) ||
      final_status.st_uid != ::geteuid() || final_status.st_nlink != 1 ||
      (private_key ? !HasMode(final_status, kPrivateKeyMode)
                   : !CertificateModeIsProtected(final_status)) ||
      !SamePemSnapshot(initial, final_status)) {
    return TlsError<PinnedPemSnapshot>("E_SECURITY_TLS_HEALTH",
                                       "TLS identity health check failed");
  }
  if (private_key) {
    cleanser.Release();
  }
  return common::Result<PinnedPemSnapshot>::Ok(std::move(snapshot));
}

bool HasOnlyWhitespaceRemaining(BIO* input) noexcept {
  std::array<unsigned char, 256> buffer{};
  const PemInspectionBufferCleanser cleanser(buffer.data(), buffer.size());
  while (true) {
    const int read_size = BIO_read(input, buffer.data(), buffer.size());
    if (read_size == 0) {
      return true;
    }
    if (read_size < 0) {
      return false;
    }
    for (int index = 0; index < read_size; ++index) {
      if (std::isspace(buffer[static_cast<std::size_t>(index)]) == 0) {
        return false;
      }
    }
  }
}

bool IsTemporaryIdentityName(std::string_view name) {
  if (!name.starts_with(kTemporaryPrefix) ||
      name.size() != kTemporaryPrefix.size() + 24U) {
    return false;
  }
  return std::all_of(name.begin() +
                         static_cast<std::ptrdiff_t>(kTemporaryPrefix.size()),
                     name.end(), [](unsigned char value) {
                       return (value >= '0' && value <= '9') ||
                              (value >= 'a' && value <= 'f');
                     });
}

struct ValidatedStaleEntry {
  std::string name;
  dev_t device{0};
  ino_t inode{0};
};

common::Result<ValidatedStaleEntry> ValidateStaleEntry(
    int directory,
    std::string_view name,
    mode_t expected_mode) {
  struct stat path_status {};
  if (::fstatat(directory, name.data(), &path_status, AT_SYMLINK_NOFOLLOW) != 0 ||
      !S_ISREG(path_status.st_mode) || S_ISLNK(path_status.st_mode) ||
      path_status.st_uid != ::geteuid() || path_status.st_nlink != 1 ||
      !HasMode(path_status, expected_mode) || path_status.st_size <= 0 ||
      static_cast<unsigned long long>(path_status.st_size) > kMaximumPemBytes) {
    return TlsError<ValidatedStaleEntry>(
        "E_HTTP_TLS_IDENTITY", "stale TLS identity entry is unsafe");
  }
  UniqueFd descriptor(::openat(directory, name.data(),
                               O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  struct stat descriptor_status {};
  if (!descriptor.valid() ||
      ::fstat(descriptor.get(), &descriptor_status) != 0 ||
      descriptor_status.st_dev != path_status.st_dev ||
      descriptor_status.st_ino != path_status.st_ino ||
      !S_ISREG(descriptor_status.st_mode) ||
      descriptor_status.st_uid != ::geteuid() ||
      descriptor_status.st_nlink != 1 ||
      !HasMode(descriptor_status, expected_mode)) {
    return TlsError<ValidatedStaleEntry>(
        "E_HTTP_TLS_IDENTITY", "stale TLS identity entry changed during scan");
  }
  return common::Result<ValidatedStaleEntry>::Ok(
      {std::string(name), path_status.st_dev, path_status.st_ino});
}

bool StaleEntryStillMatches(int directory,
                            const ValidatedStaleEntry& entry,
                            mode_t expected_mode) {
  struct stat status {};
  return ::fstatat(directory, entry.name.c_str(), &status,
                   AT_SYMLINK_NOFOLLOW) == 0 &&
         S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
         status.st_dev == entry.device && status.st_ino == entry.inode &&
         status.st_uid == ::geteuid() && status.st_nlink == 1 &&
         HasMode(status, expected_mode);
}

common::Result<void> ScavengeTemporaryIdentity(int state_directory,
                                               std::string_view name) {
  struct stat path_status {};
  if (::fstatat(state_directory, name.data(), &path_status,
                AT_SYMLINK_NOFOLLOW) != 0 ||
      !IsProtectedDirectory(path_status, ::geteuid(), kIdentityDirectoryMode)) {
    return TlsError("E_HTTP_TLS_IDENTITY",
                    "stale TLS identity directory is unsafe");
  }
  UniqueFd directory(::openat(state_directory, name.data(),
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  struct stat descriptor_status {};
  if (!directory.valid() || ::fstat(directory.get(), &descriptor_status) != 0 ||
      descriptor_status.st_dev != path_status.st_dev ||
      descriptor_status.st_ino != path_status.st_ino ||
      !IsProtectedDirectory(descriptor_status, ::geteuid(),
                            kIdentityDirectoryMode)) {
    return TlsError("E_HTTP_TLS_IDENTITY",
                    "stale TLS identity directory changed during scan");
  }

  UniqueFd scan_descriptor(::openat(directory.get(), ".",
                                    O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                        O_NOFOLLOW));
  DIR* raw_entries =
      scan_descriptor.valid() ? ::fdopendir(scan_descriptor.Release()) : nullptr;
  DirectoryStreamPtr entries(raw_entries);
  if (!entries) {
    return TlsError("E_HTTP_TLS_IDENTITY",
                    "failed to scan stale TLS identity directory");
  }

  std::optional<ValidatedStaleEntry> certificate;
  std::optional<ValidatedStaleEntry> private_key;
  while (true) {
    errno = 0;
    const struct dirent* entry = ::readdir(entries.get());
    if (entry == nullptr) {
      if (errno != 0) {
        return TlsError("E_HTTP_TLS_IDENTITY",
                        "failed while scanning stale TLS identity directory");
      }
      break;
    }
    const std::string_view entry_name(entry->d_name);
    if (entry_name == "." || entry_name == "..") {
      continue;
    }
    if (entry_name == kCertificateName && !certificate.has_value()) {
      auto validated =
          ValidateStaleEntry(directory.get(), entry_name, kCertificateMode);
      if (!validated.ok()) {
        return TlsError(validated.error().code, validated.error().message);
      }
      certificate = std::move(validated).value();
      continue;
    }
    if (entry_name == kPrivateKeyName && !private_key.has_value()) {
      auto validated =
          ValidateStaleEntry(directory.get(), entry_name, kPrivateKeyMode);
      if (!validated.ok()) {
        return TlsError(validated.error().code, validated.error().message);
      }
      private_key = std::move(validated).value();
      continue;
    }
    return TlsError("E_HTTP_TLS_IDENTITY",
                    "stale TLS identity directory has unexpected entries");
  }
  entries.reset();

  if (private_key.has_value() &&
      (!StaleEntryStillMatches(directory.get(), *private_key,
                               kPrivateKeyMode) ||
       ::unlinkat(directory.get(), private_key->name.c_str(), 0) != 0)) {
    return TlsError("E_HTTP_TLS_IDENTITY",
                    "failed to remove stale TLS private key");
  }
  if (certificate.has_value() &&
      (!StaleEntryStillMatches(directory.get(), *certificate,
                               kCertificateMode) ||
       ::unlinkat(directory.get(), certificate->name.c_str(), 0) != 0)) {
    return TlsError("E_HTTP_TLS_IDENTITY",
                    "failed to remove stale TLS certificate");
  }
  if (!FsyncRetryEintr(directory.get()) ||
      ::unlinkat(state_directory, name.data(), AT_REMOVEDIR) != 0) {
    return TlsError("E_HTTP_TLS_DURABILITY",
                    "failed to remove stale TLS identity directory");
  }
  return common::Result<void>::Ok();
}

common::Result<void> ScavengeTemporaryIdentities(int state_directory) {
  UniqueFd scan_descriptor(::openat(state_directory, ".",
                                    O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                        O_NOFOLLOW));
  DIR* raw_entries =
      scan_descriptor.valid() ? ::fdopendir(scan_descriptor.Release()) : nullptr;
  DirectoryStreamPtr entries(raw_entries);
  if (!entries) {
    return TlsError("E_HTTP_TLS_IDENTITY",
                    "failed to scan protected TLS state directory");
  }

  std::vector<std::string> temporary_names;
  while (true) {
    errno = 0;
    const struct dirent* entry = ::readdir(entries.get());
    if (entry == nullptr) {
      if (errno != 0) {
        return TlsError(
            "E_HTTP_TLS_IDENTITY",
            "failed while scanning protected TLS state directory");
      }
      break;
    }
    const std::string_view name(entry->d_name);
    if (!name.starts_with(kTemporaryPrefix)) {
      continue;
    }
    if (!IsTemporaryIdentityName(name)) {
      return TlsError("E_HTTP_TLS_IDENTITY",
                      "stale TLS identity has an unsafe temporary name");
    }
    temporary_names.emplace_back(name);
  }
  entries.reset();

  for (const auto& name : temporary_names) {
    auto removed = ScavengeTemporaryIdentity(state_directory, name);
    if (!removed.ok()) {
      return removed;
    }
  }
  if (!temporary_names.empty() && !FsyncRetryEintr(state_directory)) {
    return TlsError("E_HTTP_TLS_DURABILITY",
                    "failed to sync stale TLS cleanup");
  }
  return common::Result<void>::Ok();
}

common::Result<UniqueFd> OpenProtectedStateDirectory(
    const std::filesystem::path& state_directory) {
  if (state_directory.empty()) {
    return TlsError<UniqueFd>("E_HTTP_TLS_IDENTITY",
                              "protected TLS state directory is empty");
  }

  std::error_code path_error;
  const auto absolute =
      std::filesystem::absolute(state_directory, path_error).lexically_normal();
  if (path_error) {
    return TlsError<UniqueFd>("E_HTTP_TLS_IDENTITY",
                              "protected TLS state directory is invalid");
  }

  struct stat path_status {};
  if (::lstat(absolute.c_str(), &path_status) != 0 ||
      !IsProtectedDirectory(path_status, ::geteuid(), kStateDirectoryMode)) {
    return TlsError<UniqueFd>(
        "E_HTTP_TLS_IDENTITY",
        "protected TLS state directory has unsafe ownership, type, or mode");
  }

  UniqueFd directory(::open(absolute.c_str(), O_RDONLY | O_DIRECTORY |
                                                   O_CLOEXEC | O_NOFOLLOW));
  struct stat descriptor_status {};
  if (!directory.valid() || ::fstat(directory.get(), &descriptor_status) != 0 ||
      !IsProtectedDirectory(descriptor_status, ::geteuid(),
                            kStateDirectoryMode) ||
      path_status.st_dev != descriptor_status.st_dev ||
      path_status.st_ino != descriptor_status.st_ino) {
    return TlsError<UniqueFd>("E_HTTP_TLS_IDENTITY",
                              "failed to anchor protected TLS state directory");
  }
  return common::Result<UniqueFd>::Ok(std::move(directory));
}

common::Result<OpenedPemFile> OpenGeneratedPemFile(
    int directory, std::string_view name, mode_t expected_mode,
    bool certificate_file) {
  UniqueFd input(::openat(directory, name.data(),
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  struct stat status {};
  if (!input.valid() || ::fstat(input.get(), &status) != 0 ||
      !S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
      status.st_uid != ::geteuid() || status.st_nlink != 1 ||
      (certificate_file ? !CertificateModeIsProtected(status)
                        : !HasMode(status, expected_mode)) ||
      status.st_size <= 0 ||
      static_cast<unsigned long long>(status.st_size) > kMaximumPemBytes) {
    return TlsError<OpenedPemFile>(
        "E_HTTP_TLS_IDENTITY",
        "generated TLS identity has unsafe file ownership, type, mode, or size");
  }

  common::SecureBytes bytes;
  try {
    bytes.resize(static_cast<std::size_t>(status.st_size));
  } catch (...) {
    return TlsError<OpenedPemFile>("E_HTTP_TLS_IDENTITY",
                                   "failed to allocate TLS file buffer");
  }
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t read_size =
        ::pread(input.get(), bytes.data() + offset, bytes.size() - offset,
                static_cast<off_t>(offset));
    if (read_size < 0 && errno == EINTR) {
      continue;
    }
    if (read_size <= 0) {
      bytes.clear();
      return TlsError<OpenedPemFile>("E_HTTP_TLS_IDENTITY",
                                     "failed to read TLS identity file");
    }
    offset += static_cast<std::size_t>(read_size);
  }
  return common::Result<OpenedPemFile>::Ok(
      {std::move(input), std::move(bytes)});
}

common::Result<void> ValidatePemPair(const common::SecureBytes& certificate_pem,
                                     const common::SecureBytes& private_key_pem,
                                     bool require_development_profile) {
  if (certificate_pem.size() > static_cast<std::size_t>(INT_MAX) ||
      private_key_pem.size() > static_cast<std::size_t>(INT_MAX)) {
    return TlsError("E_HTTP_TLS_IDENTITY", "TLS identity file is too large");
  }

  BioPtr certificate_bio(
      BIO_new_mem_buf(certificate_pem.data(),
                      static_cast<int>(certificate_pem.size())),
      BIO_free);
  BioPtr private_key_bio(
      BIO_new_mem_buf(private_key_pem.data(),
                      static_cast<int>(private_key_pem.size())),
      BIO_free);
  X509Ptr certificate(
      certificate_bio
          ? PEM_read_bio_X509(certificate_bio.get(), nullptr, nullptr, nullptr)
          : nullptr,
      X509_free);
  KeyPtr private_key(
      private_key_bio ? PEM_read_bio_PrivateKey(private_key_bio.get(), nullptr,
                                                RejectEncryptedPemPassword,
                                                nullptr)
                      : nullptr,
      EVP_PKEY_free);
  if (!certificate || !private_key ||
      X509_cmp_current_time(X509_get0_notBefore(certificate.get())) >= 0 ||
      X509_cmp_current_time(X509_get0_notAfter(certificate.get())) <= 0 ||
      X509_check_private_key(certificate.get(), private_key.get()) != 1) {
    return TlsError("E_HTTP_TLS_IDENTITY",
                    "TLS certificate and private key are invalid or mismatched");
  }

  if (!require_development_profile) {
    return common::Result<void>::Ok();
  }

  std::array<char, 80> group_name{};
  std::size_t group_name_length = 0;
  KeyPtr public_key(X509_get_pubkey(certificate.get()), EVP_PKEY_free);
  if (!EVP_PKEY_is_a(private_key.get(), "EC") ||
      EVP_PKEY_get_group_name(private_key.get(), group_name.data(),
                              group_name.size(), &group_name_length) != 1 ||
      std::string_view(group_name.data()) != "prime256v1" || !public_key ||
      !GeneratedCertificateProfileIsValid(certificate.get()) ||
      X509_NAME_cmp(X509_get_subject_name(certificate.get()),
                    X509_get_issuer_name(certificate.get())) != 0 ||
      X509_verify(certificate.get(), public_key.get()) != 1 ||
      X509_check_host(certificate.get(), "localhost", 0, 0, nullptr) != 1 ||
      X509_check_host(certificate.get(), "camera.local", 0, 0, nullptr) != 1 ||
      X509_check_ip_asc(certificate.get(), "127.0.0.1", 0) != 1 ||
      X509_check_ip_asc(certificate.get(), "::1", 0) != 1) {
    return TlsError("E_HTTP_TLS_IDENTITY",
                    "generated TLS identity does not match its required profile");
  }
  return common::Result<void>::Ok();
}

common::Result<std::pair<OpenedPemFile, OpenedPemFile>>
OpenValidatedGeneratedIdentity(int state_directory) {
  UniqueFd identity(::openat(state_directory, kIdentityDirectory.data(),
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  struct stat status {};
  if (!identity.valid() || ::fstat(identity.get(), &status) != 0 ||
      !IsProtectedDirectory(status, ::geteuid(), kIdentityDirectoryMode)) {
    return TlsError<std::pair<OpenedPemFile, OpenedPemFile>>(
        "E_HTTP_TLS_IDENTITY", "generated TLS identity directory is unsafe");
  }

  auto certificate = OpenGeneratedPemFile(identity.get(), kCertificateName,
                                          kCertificateMode, true);
  if (!certificate.ok()) {
    return TlsError<std::pair<OpenedPemFile, OpenedPemFile>>(
        certificate.error().code, certificate.error().message);
  }
  auto private_key =
      OpenGeneratedPemFile(identity.get(), kPrivateKeyName, kPrivateKeyMode,
                           false);
  if (!private_key.ok()) {
    return TlsError<std::pair<OpenedPemFile, OpenedPemFile>>(
        private_key.error().code, private_key.error().message);
  }
  auto valid = ValidatePemPair(certificate.value().bytes,
                               private_key.value().bytes, true);
  if (!valid.ok()) {
    return TlsError<std::pair<OpenedPemFile, OpenedPemFile>>(
        valid.error().code, valid.error().message);
  }
  return common::Result<std::pair<OpenedPemFile, OpenedPemFile>>::Ok(
      {std::move(certificate).value(), std::move(private_key).value()});
}

common::Result<OpenedPemFile> OpenConfiguredPem(
    const std::filesystem::path& path, bool private_key) {
  UniqueFd input(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  struct stat status {};
  if (!input.valid() || ::fstat(input.get(), &status) != 0 ||
      !S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
      status.st_uid != ::geteuid() || status.st_nlink != 1 ||
      (private_key ? !HasMode(status, kPrivateKeyMode)
                   : !CertificateModeIsProtected(status)) ||
      status.st_size <= 0 ||
      static_cast<unsigned long long>(status.st_size) > kMaximumPemBytes) {
    return TlsError<OpenedPemFile>(
        "E_HTTP_TLS_IDENTITY", "configured TLS identity file is unsafe");
  }

  common::SecureBytes bytes;
  bytes.resize(static_cast<std::size_t>(status.st_size));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t read_size =
        ::pread(input.get(), bytes.data() + offset, bytes.size() - offset,
                static_cast<off_t>(offset));
    if (read_size < 0 && errno == EINTR) {
      continue;
    }
    if (read_size <= 0) {
      bytes.clear();
      return TlsError<OpenedPemFile>(
          "E_HTTP_TLS_IDENTITY", "failed to read configured TLS identity");
    }
    offset += static_cast<std::size_t>(read_size);
  }
  return common::Result<OpenedPemFile>::Ok(
      {std::move(input), std::move(bytes)});
}

common::Result<PreparedTlsMaterial> ValidateConfiguredIdentity(
    const config::HttpTlsConfig& tls) {
  auto certificate = OpenConfiguredPem(tls.certificate_path, false);
  if (!certificate.ok()) {
    return TlsError<PreparedTlsMaterial>(certificate.error().code,
                                         certificate.error().message);
  }
  auto private_key = OpenConfiguredPem(tls.private_key_path, true);
  if (!private_key.ok()) {
    return TlsError<PreparedTlsMaterial>(private_key.error().code,
                                         private_key.error().message);
  }
  auto valid = ValidatePemPair(certificate.value().bytes,
                               private_key.value().bytes, false);
  if (!valid.ok()) {
    return TlsError<PreparedTlsMaterial>(valid.error().code,
                                         valid.error().message);
  }
  return common::Result<PreparedTlsMaterial>::Ok(
      {std::move(certificate).value(), std::move(private_key).value(), false});
}

bool AddExtension(X509* certificate, int nid, const char* value) {
  X509V3_CTX context;
  X509V3_set_ctx_nodb(&context);
  X509V3_set_ctx(&context, certificate, certificate, nullptr, nullptr, 0);
  X509_EXTENSION* raw =
      X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char*>(value));
  std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
      raw, X509_EXTENSION_free);
  return extension && X509_add_ext(certificate, extension.get(), -1) == 1;
}

bool IsDnsHostname(std::string_view hostname) {
  return !hostname.empty() && hostname.size() <= 253U &&
         std::all_of(hostname.begin(), hostname.end(), [](unsigned char value) {
           return (value >= 'a' && value <= 'z') ||
                  (value >= 'A' && value <= 'Z') ||
                  (value >= '0' && value <= '9') || value == '-' || value == '.';
         });
}

std::vector<std::string> ExpectedDnsNames() {
  std::vector<std::string> names{"localhost", "camera.local"};
  std::array<char, 256> hostname{};
  if (::gethostname(hostname.data(), hostname.size()) == 0) {
    hostname.back() = '\0';
    const std::string_view value(hostname.data());
    if (IsDnsHostname(value) && value != "localhost" &&
        value != "camera.local") {
      names.emplace_back(value);
    }
  }
  return names;
}

std::string SubjectAlternativeNames() {
  std::string names;
  for (const auto& value : ExpectedDnsNames()) {
    if (!names.empty()) {
      names += ',';
    }
    names += "DNS:";
    names += value;
  }
  names += ",IP:127.0.0.1,IP:::1";
  return names;
}

common::Result<std::pair<std::vector<unsigned char>, common::SecureBytes>>
GeneratePemIdentity() {
  KeyPtr private_key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"),
                     EVP_PKEY_free);
  X509Ptr certificate(X509_new(), X509_free);
  common::SecureBytes serial_bytes;
  serial_bytes.resize(16U);
  if (!private_key || !certificate ||
      RAND_bytes(serial_bytes.data(), static_cast<int>(serial_bytes.size())) !=
          1) {
    return TlsError<std::pair<std::vector<unsigned char>, common::SecureBytes>>(
        "E_HTTP_TLS_GENERATE", "failed to initialize development TLS identity");
  }
  serial_bytes.data()[0] &= 0x7fU;
  serial_bytes.data()[serial_bytes.size() - 1U] |= 0x01U;
  BnPtr serial(BN_bin2bn(serial_bytes.data(),
                        static_cast<int>(serial_bytes.size()), nullptr),
               BN_free);
  if (!serial ||
      BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(certificate.get())) ==
          nullptr ||
      X509_set_version(certificate.get(), 2) != 1 ||
      X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -300) == nullptr ||
      X509_gmtime_adj(X509_getm_notAfter(certificate.get()),
                      kCertificateLifetimeSeconds) == nullptr ||
      X509_set_pubkey(certificate.get(), private_key.get()) != 1) {
    return TlsError<std::pair<std::vector<unsigned char>, common::SecureBytes>>(
        "E_HTTP_TLS_GENERATE", "failed to construct development certificate");
  }

  X509_NAME* subject = X509_get_subject_name(certificate.get());
  constexpr unsigned char kCommonName[] = "camera.local";
  constexpr unsigned char kOrganization[] = "Camera Firmware Development";
  const std::string subject_alternative_names = SubjectAlternativeNames();
  if (subject == nullptr ||
      X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, kCommonName, -1, -1,
                                 0) != 1 ||
      X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC, kOrganization, -1,
                                 -1, 0) != 1 ||
      X509_set_issuer_name(certificate.get(), subject) != 1 ||
      !AddExtension(certificate.get(), NID_basic_constraints,
                    "critical,CA:FALSE") ||
      !AddExtension(certificate.get(), NID_key_usage,
                    "critical,digitalSignature") ||
      !AddExtension(certificate.get(), NID_ext_key_usage, "serverAuth") ||
      !AddExtension(certificate.get(), NID_subject_alt_name,
                    subject_alternative_names.c_str()) ||
      X509_sign(certificate.get(), private_key.get(), EVP_sha256()) <= 0) {
    return TlsError<std::pair<std::vector<unsigned char>, common::SecureBytes>>(
        "E_HTTP_TLS_GENERATE", "failed to sign development certificate");
  }

  BioPtr certificate_bio(BIO_new(BIO_s_mem()), BIO_free);
  SecretMemoryBio private_key_bio;
  if (!certificate_bio || !private_key_bio.get() ||
      PEM_write_bio_X509(certificate_bio.get(), certificate.get()) != 1 ||
      PEM_write_bio_PrivateKey(private_key_bio.get(), private_key.get(), nullptr,
                               nullptr, 0, nullptr, nullptr) != 1) {
    return TlsError<std::pair<std::vector<unsigned char>, common::SecureBytes>>(
        "E_HTTP_TLS_GENERATE", "failed to serialize development TLS identity");
  }

  BUF_MEM* certificate_memory = nullptr;
  BUF_MEM* private_key_memory = nullptr;
  BIO_get_mem_ptr(certificate_bio.get(), &certificate_memory);
  BIO_get_mem_ptr(private_key_bio.get(), &private_key_memory);
  if (certificate_memory == nullptr || certificate_memory->data == nullptr ||
      certificate_memory->length == 0U || private_key_memory == nullptr ||
      private_key_memory->data == nullptr || private_key_memory->length == 0U) {
    return TlsError<std::pair<std::vector<unsigned char>, common::SecureBytes>>(
        "E_HTTP_TLS_GENERATE", "development TLS serialization was empty");
  }

  std::vector<unsigned char> certificate_pem(
      certificate_memory->data,
      certificate_memory->data + certificate_memory->length);
  common::SecureBytes private_key_pem;
  private_key_pem.assign(
      reinterpret_cast<const unsigned char*>(private_key_memory->data),
      private_key_memory->length);
  return common::Result<
      std::pair<std::vector<unsigned char>, common::SecureBytes>>::Ok(
      {std::move(certificate_pem), std::move(private_key_pem)});
}

common::Result<void> WriteDurableFile(int directory, std::string_view name,
                                      std::span<const unsigned char> bytes,
                                      mode_t mode) {
  UniqueFd output(::openat(directory, name.data(),
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                           mode));
  if (!output.valid() || ::fchmod(output.get(), mode) != 0) {
    return TlsError("E_HTTP_TLS_GENERATE",
                    "failed to create protected TLS identity file");
  }
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t written =
        ::write(output.get(), bytes.data() + offset, bytes.size() - offset);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return TlsError("E_HTTP_TLS_GENERATE",
                      "failed to write protected TLS identity file");
    }
    offset += static_cast<std::size_t>(written);
  }
  if (!FsyncRetryEintr(output.get())) {
    return TlsError("E_HTTP_TLS_DURABILITY",
                    "failed to sync protected TLS identity file");
  }
  return common::Result<void>::Ok();
}

common::Result<std::string> CreateTemporaryDirectory(int state_directory) {
  for (int attempt = 0; attempt < 32; ++attempt) {
    common::SecureBytes random;
    random.resize(12U);
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
      return TlsError<std::string>("E_HTTP_TLS_GENERATE",
                                   "failed to name temporary TLS directory");
    }
    constexpr char kHex[] = "0123456789abcdef";
    std::string name(kTemporaryPrefix);
    name.reserve(kTemporaryPrefix.size() + random.size() * 2U);
    for (std::size_t index = 0; index < random.size(); ++index) {
      name.push_back(kHex[random.data()[index] >> 4U]);
      name.push_back(kHex[random.data()[index] & 0x0fU]);
    }
    if (::mkdirat(state_directory, name.c_str(), kIdentityDirectoryMode) == 0) {
      return common::Result<std::string>::Ok(std::move(name));
    }
    if (errno != EEXIST) {
      return TlsError<std::string>("E_HTTP_TLS_GENERATE",
                                   "failed to create temporary TLS directory");
    }
  }
  return TlsError<std::string>("E_HTTP_TLS_GENERATE",
                               "failed to reserve temporary TLS directory");
}

common::Result<void> PublishGeneratedIdentity(int state_directory) {
  auto generated = GeneratePemIdentity();
  if (!generated.ok()) {
    return TlsError(generated.error().code, generated.error().message);
  }
  auto temporary_name = CreateTemporaryDirectory(state_directory);
  if (!temporary_name.ok()) {
    return TlsError(temporary_name.error().code, temporary_name.error().message);
  }
  TemporaryIdentityDirectory cleanup(state_directory, temporary_name.value());
  UniqueFd temporary(::openat(state_directory, temporary_name.value().c_str(),
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  struct stat status {};
  if (!temporary.valid() ||
      ::fchmod(temporary.get(), kIdentityDirectoryMode) != 0 ||
      ::fstat(temporary.get(), &status) != 0 ||
      !IsProtectedDirectory(status, ::geteuid(), kIdentityDirectoryMode)) {
    return TlsError("E_HTTP_TLS_GENERATE",
                    "temporary TLS identity directory is unsafe");
  }

  auto key_write = WriteDurableFile(
      temporary.get(), kPrivateKeyName,
      {generated.value().second.data(), generated.value().second.size()},
      kPrivateKeyMode);
  if (!key_write.ok()) {
    return key_write;
  }
  auto certificate_write = WriteDurableFile(
      temporary.get(), kCertificateName,
      {generated.value().first.data(), generated.value().first.size()},
      kCertificateMode);
  if (!certificate_write.ok()) {
    return certificate_write;
  }
  if (!FsyncRetryEintr(temporary.get())) {
    return TlsError("E_HTTP_TLS_DURABILITY",
                    "failed to sync temporary TLS identity directory");
  }

  const int rename_result = camera_firmware_tls_rename_noreplace(
      state_directory, temporary_name.value().c_str(), state_directory,
      kIdentityDirectory.data());
  if (rename_result != 0) {
    if (errno == EEXIST) {
      auto winner = OpenValidatedGeneratedIdentity(state_directory);
      if (winner.ok()) {
        return common::Result<void>::Ok();
      }
      return TlsError(winner.error().code, winner.error().message);
    }
    return TlsError("E_HTTP_TLS_DURABILITY",
                    "failed to publish development TLS identity");
  }
  cleanup.Published();
  if (!FsyncRetryEintr(state_directory)) {
    return TlsError("E_HTTP_TLS_DURABILITY",
                    "failed to sync protected TLS state directory");
  }
  return common::Result<void>::Ok();
}

common::Result<PreparedTlsMaterial> ResolveGeneratedIdentity(
    const std::filesystem::path& state_directory) {
  auto protected_directory = OpenProtectedStateDirectory(state_directory);
  if (!protected_directory.ok()) {
    return TlsError<PreparedTlsMaterial>(protected_directory.error().code,
                                         protected_directory.error().message);
  }
  DirectoryLock lock(protected_directory.value().get());
  if (!lock.Lock()) {
    return TlsError<PreparedTlsMaterial>("E_HTTP_TLS_IDENTITY",
                                         "failed to lock TLS state directory");
  }

  auto scavenged =
      ScavengeTemporaryIdentities(protected_directory.value().get());
  if (!scavenged.ok()) {
    return TlsError<PreparedTlsMaterial>(scavenged.error().code,
                                         scavenged.error().message);
  }

  struct stat identity_status {};
  if (::fstatat(protected_directory.value().get(), kIdentityDirectory.data(),
                &identity_status, AT_SYMLINK_NOFOLLOW) != 0) {
    if (errno == ENOENT) {
      auto published =
          PublishGeneratedIdentity(protected_directory.value().get());
      if (!published.ok()) {
        return TlsError<PreparedTlsMaterial>(published.error().code,
                                             published.error().message);
      }
    } else {
      return TlsError<PreparedTlsMaterial>(
          "E_HTTP_TLS_IDENTITY", "failed to inspect development TLS identity");
    }
  }

  auto opened =
      OpenValidatedGeneratedIdentity(protected_directory.value().get());
  if (!opened.ok()) {
    return TlsError<PreparedTlsMaterial>(opened.error().code,
                                         opened.error().message);
  }
  auto files = std::move(opened).value();
  return common::Result<PreparedTlsMaterial>::Ok(
      {std::move(files.first), std::move(files.second), true});
}

}  // namespace

ResolvedTlsMaterial::ResolvedTlsMaterial(
    std::filesystem::path certificate,
    std::filesystem::path private_key,
    bool generated,
    std::shared_ptr<detail::ResolvedTlsHandles> handles) noexcept
    : certificate_path(std::move(certificate)),
      private_key_path(std::move(private_key)),
      generated_for_development(generated),
      handles_(std::move(handles)) {}

common::Result<ResolvedTlsMaterial> ResolveTlsMaterial(
    const config::HttpTlsConfig& tls,
    const std::filesystem::path& protected_state_directory) {
  try {
    const auto finalize = [](PreparedTlsMaterial prepared) {
      auto handles = std::make_shared<detail::ResolvedTlsHandles>();
      handles->certificate = prepared.certificate.descriptor.Release();
      handles->private_key = prepared.private_key.descriptor.Release();
      const auto certificate_path =
          "/proc/self/fd/" + std::to_string(handles->certificate);
      const auto private_key_path =
          "/proc/self/fd/" + std::to_string(handles->private_key);
      return common::Result<ResolvedTlsMaterial>::Ok(ResolvedTlsMaterial(
          certificate_path, private_key_path,
          prepared.generated_for_development, std::move(handles)));
    };

    if (!tls.enabled) {
      return TlsError<ResolvedTlsMaterial>("E_HTTP_TLS_REQUIRED",
                                           "HTTPS is required");
    }
    const bool has_certificate = !tls.certificate_path.empty();
    const bool has_private_key = !tls.private_key_path.empty();
    if (has_certificate != has_private_key) {
      return TlsError<ResolvedTlsMaterial>(
          "E_HTTP_TLS_REQUIRED",
          "a complete HTTP TLS certificate and private-key pair is required");
    }
    if (has_certificate) {
      auto prepared = ValidateConfiguredIdentity(tls);
      if (!prepared.ok()) {
        return TlsError<ResolvedTlsMaterial>(prepared.error().code,
                                             prepared.error().message);
      }
      return finalize(std::move(prepared).value());
    }
    if (!tls.allow_development_self_signed_tls) {
      return TlsError<ResolvedTlsMaterial>(
          "E_HTTP_TLS_REQUIRED", "configured HTTP TLS material is required");
    }
    auto prepared = ResolveGeneratedIdentity(protected_state_directory);
    if (!prepared.ok()) {
      return TlsError<ResolvedTlsMaterial>(prepared.error().code,
                                           prepared.error().message);
    }
    return finalize(std::move(prepared).value());
  } catch (...) {
    return TlsError<ResolvedTlsMaterial>(
        "E_HTTP_TLS_GENERATE", "failed to resolve HTTP TLS identity");
  }
}

common::Result<void> CheckTlsMaterialHealth(
    const ResolvedTlsMaterial& material,
    std::chrono::system_clock::time_point now) {
  const auto failure = [] {
    return TlsError("E_SECURITY_TLS_HEALTH", "TLS identity health check failed");
  };
  try {
    if (!material.handles_ || material.handles_->certificate < 0 ||
        material.handles_->private_key < 0) {
      return failure();
    }
    auto certificate =
        ReadPinnedPemSnapshot(material.handles_->certificate, false);
    if (!certificate.ok()) {
      return failure();
    }
    auto private_key = ReadPinnedPemSnapshot(material.handles_->private_key, true);
    if (!private_key.ok()) {
      return failure();
    }
    PrivatePemCleanser private_key_cleanser(private_key.value().bytes);

    BioPtr certificate_bio(
        BIO_new_mem_buf(certificate.value().bytes.data(),
                        static_cast<int>(certificate.value().bytes.size())),
        BIO_free);
    BioPtr private_key_bio(
        BIO_new_mem_buf(private_key.value().bytes.data(),
                        static_cast<int>(private_key.value().bytes.size())),
        BIO_free);
    X509Ptr parsed_certificate(
        certificate_bio
            ? PEM_read_bio_X509(certificate_bio.get(), nullptr, nullptr, nullptr)
            : nullptr,
        X509_free);
    KeyPtr parsed_private_key(
        private_key_bio
            ? PEM_read_bio_PrivateKey(private_key_bio.get(), nullptr,
                                      RejectEncryptedPemPassword, nullptr)
            : nullptr,
        EVP_PKEY_free);
    std::time_t current_time =
        std::chrono::system_clock::to_time_t(now);
    const int not_before_comparison =
        parsed_certificate
            ? ASN1_TIME_cmp_time_t(
                  X509_get0_notBefore(parsed_certificate.get()), current_time)
            : -2;
    const int not_after_comparison =
        parsed_certificate
            ? ASN1_TIME_cmp_time_t(
                  X509_get0_notAfter(parsed_certificate.get()), current_time)
            : -2;
    if (!parsed_certificate || !parsed_private_key ||
        !HasOnlyWhitespaceRemaining(certificate_bio.get()) ||
        !HasOnlyWhitespaceRemaining(private_key_bio.get()) ||
        not_before_comparison == -2 || not_after_comparison == -2 ||
        not_before_comparison > 0 || not_after_comparison < 0 ||
        X509_check_private_key(parsed_certificate.get(),
                               parsed_private_key.get()) != 1) {
      return failure();
    }
    return common::Result<void>::Ok();
  } catch (...) {
    return failure();
  }
}

}  // namespace camera_firmware::security
