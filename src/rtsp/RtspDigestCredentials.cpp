#include "camera_firmware/rtsp/RtspDigestCredentials.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <limits>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/rand.h>

namespace camera_firmware::rtsp {
namespace {

constexpr std::size_t kMaximumCredentialFileBytes = 65536U;
constexpr std::size_t kMaximumUsernameBytes = 64U;
constexpr std::size_t kMaximumRealmBytes = 128U;
constexpr std::size_t kMaximumUsers = 64U;
constexpr std::size_t kMaximumRecords = 128U;
constexpr std::size_t kTemporaryRandomBytes = 16U;
constexpr std::size_t kMaximumTemporaryCreateAttempts = 128U;
constexpr std::string_view kFileHeader = "CFDIGEST1";
constexpr std::string_view kTemporaryPrefix = ".cf-rtsp-credentials-";
constexpr std::string_view kPolicyInvalid =
    "credential policy is invalid";
constexpr std::string_view kLookupInvalid =
    "credential lookup request is invalid";
constexpr std::string_view kProvisionInvalid =
    "credential provisioning request is invalid";
constexpr std::string_view kPermissionsInvalid =
    "credential file permissions are invalid";
constexpr std::string_view kSizeInvalid =
    "credential file size is invalid";
constexpr std::string_view kFormatInvalid =
    "credential file format is invalid";
constexpr std::string_view kReadFailed =
    "credential file could not be read";
constexpr std::string_view kReplaceFailed =
    "credential file could not be replaced";
constexpr std::string_view kDurabilityUnconfirmed =
    "credential file replacement durability could not be confirmed";
constexpr std::string_view kOperationFailed =
    "credential operation failed";

common::Error CredentialError(std::string_view message) {
  return {"E_RTSP_AUTH_CREDENTIALS", std::string(message)};
}

template <typename T>
common::Result<T> CredentialFailure(std::string_view message) {
  return common::Result<T>::Err(CredentialError(message));
}

common::Result<void> CredentialFailureVoid(std::string_view message) {
  return common::Result<void>::Err(CredentialError(message));
}

class UniqueFd {
 public:
  explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}
  ~UniqueFd() {
    if (fd_ >= 0) {
      (void)::close(fd_);
    }
  }

  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;

  UniqueFd(UniqueFd&& other) noexcept
      : fd_(std::exchange(other.fd_, -1)) {}

  UniqueFd& operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
      if (fd_ >= 0) {
        (void)::close(fd_);
      }
      fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
  }

  [[nodiscard]] int get() const noexcept { return fd_; }

  bool Close() noexcept {
    if (fd_ < 0) {
      return true;
    }
    const int fd = std::exchange(fd_, -1);
    return ::close(fd) == 0;
  }

 private:
  int fd_;
};

struct AlgorithmPolicy {
  bool sha256{false};
  bool md5{false};
};

struct CredentialRecord {
  std::vector<unsigned char> username;
  RtspDigestAlgorithm algorithm{RtspDigestAlgorithm::kSha256};
  common::SecureBytes ha1;
};

struct CredentialState {
  std::vector<CredentialRecord> records;
};

struct LoadedCredentialState {
  bool exists{false};
  CredentialState state;
};

struct DummyHa1 {
  RtspDigestAlgorithm algorithm{RtspDigestAlgorithm::kSha256};
  common::SecureBytes bytes;
};

bool IsKnownAlgorithm(RtspDigestAlgorithm algorithm) noexcept {
  switch (algorithm) {
    case RtspDigestAlgorithm::kSha256:
    case RtspDigestAlgorithm::kMd5:
      return true;
  }
  return false;
}

bool IsEnabled(const AlgorithmPolicy& policy,
               RtspDigestAlgorithm algorithm) noexcept {
  switch (algorithm) {
    case RtspDigestAlgorithm::kSha256:
      return policy.sha256;
    case RtspDigestAlgorithm::kMd5:
      return policy.md5;
  }
  return false;
}

bool IsVisibleAscii(std::string_view value, std::size_t maximum) noexcept {
  return !value.empty() && value.size() <= maximum &&
         std::all_of(value.begin(), value.end(), [](unsigned char byte) {
           return byte >= 0x21U && byte <= 0x7eU;
         });
}

bool IsVisibleAscii(std::span<const unsigned char> value,
                    std::size_t maximum) noexcept {
  return !value.empty() && value.size() <= maximum &&
         std::all_of(value.begin(), value.end(), [](unsigned char byte) {
           return byte >= 0x21U && byte <= 0x7eU;
         });
}

bool IsValidRealm(std::string_view realm) noexcept {
  return IsVisibleAscii(realm, kMaximumRealmBytes) &&
         realm.find_first_of(":\"\\\r\n") == std::string_view::npos;
}

bool IsValidUsername(std::string_view username) noexcept {
  return IsVisibleAscii(username, kMaximumUsernameBytes) &&
         username.find(':') == std::string_view::npos;
}

common::Result<AlgorithmPolicy> ValidatePolicy(
    const RtspDigestCredentialPolicy& policy) {
  if (!IsValidRealm(policy.realm) || policy.algorithms.empty() ||
      policy.algorithms.size() > 2U) {
    return CredentialFailure<AlgorithmPolicy>(kPolicyInvalid);
  }

  AlgorithmPolicy enabled;
  for (const RtspDigestAlgorithm algorithm : policy.algorithms) {
    if (!IsKnownAlgorithm(algorithm)) {
      return CredentialFailure<AlgorithmPolicy>(kPolicyInvalid);
    }
    bool* selected = algorithm == RtspDigestAlgorithm::kSha256
                         ? &enabled.sha256
                         : &enabled.md5;
    if (*selected) {
      return CredentialFailure<AlgorithmPolicy>(kPolicyInvalid);
    }
    *selected = true;
  }
  if (!enabled.sha256 || (enabled.md5 && policy.algorithms.size() != 2U)) {
    return CredentialFailure<AlgorithmPolicy>(kPolicyInvalid);
  }
  return common::Result<AlgorithmPolicy>::Ok(enabled);
}

bool BytesEqual(std::span<const unsigned char> left,
                std::span<const unsigned char> right) noexcept {
  return left.size() == right.size() &&
         std::equal(left.begin(), left.end(), right.begin());
}

bool BytesEqual(std::span<const unsigned char> left,
                std::string_view right) noexcept {
  return left.size() == right.size() &&
         std::equal(left.begin(), left.end(), right.begin(),
                    [](unsigned char byte, char character) {
                      return byte == static_cast<unsigned char>(character);
                    });
}

bool UsernameEqual(const std::vector<unsigned char>& left,
                   std::span<const unsigned char> right) noexcept {
  return BytesEqual({left.data(), left.size()}, right);
}

bool UsernameEqual(const std::vector<unsigned char>& left,
                   std::string_view right) noexcept {
  return BytesEqual({left.data(), left.size()}, right);
}

std::size_t FindByte(std::span<const unsigned char> bytes,
                     std::size_t begin, unsigned char value) noexcept {
  for (std::size_t index = begin; index < bytes.size(); ++index) {
    if (bytes[index] == value) {
      return index;
    }
  }
  return bytes.size();
}

bool SplitRecordLine(
    std::span<const unsigned char> line,
    std::array<std::span<const unsigned char>, 4U>* fields) noexcept {
  std::array<std::size_t, 3U> separators{};
  std::size_t separator_count = 0U;
  for (std::size_t index = 0U; index < line.size(); ++index) {
    if (line[index] != static_cast<unsigned char>(':')) {
      continue;
    }
    if (separator_count == separators.size()) {
      return false;
    }
    separators[separator_count++] = index;
  }
  if (separator_count != separators.size()) {
    return false;
  }

  (*fields)[0] = line.first(separators[0]);
  (*fields)[1] = line.subspan(separators[0] + 1U,
                              separators[1] - separators[0] - 1U);
  (*fields)[2] = line.subspan(separators[1] + 1U,
                              separators[2] - separators[1] - 1U);
  (*fields)[3] = line.subspan(separators[2] + 1U);
  return true;
}

common::Result<RtspDigestAlgorithm> ParseCredentialAlgorithm(
    std::span<const unsigned char> value) {
  if (BytesEqual(value, "sha-256")) {
    return common::Result<RtspDigestAlgorithm>::Ok(
        RtspDigestAlgorithm::kSha256);
  }
  if (BytesEqual(value, "md5")) {
    return common::Result<RtspDigestAlgorithm>::Ok(
        RtspDigestAlgorithm::kMd5);
  }
  return CredentialFailure<RtspDigestAlgorithm>(kFormatInvalid);
}

bool IsLowercaseHex(std::span<const unsigned char> value) noexcept {
  return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
    return (byte >= static_cast<unsigned char>('0') &&
            byte <= static_cast<unsigned char>('9')) ||
           (byte >= static_cast<unsigned char>('a') &&
            byte <= static_cast<unsigned char>('f'));
  });
}

common::Result<CredentialState> ParseCredentialBytes(
    const common::SecureBytes& bytes, std::string_view realm,
    const AlgorithmPolicy& policy) {
  const std::span<const unsigned char> content(bytes.data(), bytes.size());
  if (content.empty() || content.back() != static_cast<unsigned char>('\n')) {
    return CredentialFailure<CredentialState>(kFormatInvalid);
  }

  const std::size_t header_end = FindByte(content, 0U, '\n');
  if (header_end == content.size() ||
      !BytesEqual(content.first(header_end), kFileHeader)) {
    return CredentialFailure<CredentialState>(kFormatInvalid);
  }

  CredentialState state;
  std::size_t user_count = 0U;
  bool has_sha256 = false;
  std::size_t cursor = header_end + 1U;
  while (cursor < content.size()) {
    const std::size_t line_end = FindByte(content, cursor, '\n');
    if (line_end == content.size() || line_end == cursor ||
        state.records.size() == kMaximumRecords) {
      return CredentialFailure<CredentialState>(kFormatInvalid);
    }
    const auto line = content.subspan(cursor, line_end - cursor);
    std::array<std::span<const unsigned char>, 4U> fields;
    if (!SplitRecordLine(line, &fields) ||
        !IsVisibleAscii(fields[0], kMaximumUsernameBytes) ||
        !BytesEqual(fields[1], realm)) {
      return CredentialFailure<CredentialState>(kFormatInvalid);
    }

    auto parsed_algorithm = ParseCredentialAlgorithm(fields[2]);
    if (!parsed_algorithm.ok() ||
        !IsEnabled(policy, parsed_algorithm.value())) {
      return CredentialFailure<CredentialState>(kFormatInvalid);
    }
    const RtspDigestAlgorithm algorithm = parsed_algorithm.value();
    const std::size_t digest_size = RtspDigestSize(algorithm);
    if (digest_size == 0U || fields[3].size() != digest_size * 2U ||
        !IsLowercaseHex(fields[3])) {
      return CredentialFailure<CredentialState>(kFormatInvalid);
    }

    bool known_user = false;
    for (const auto& record : state.records) {
      if (!UsernameEqual(record.username, fields[0])) {
        continue;
      }
      known_user = true;
      if (record.algorithm == algorithm) {
        return CredentialFailure<CredentialState>(kFormatInvalid);
      }
    }
    if (!known_user && ++user_count > kMaximumUsers) {
      return CredentialFailure<CredentialState>(kFormatInvalid);
    }

    const std::string_view hex(
        reinterpret_cast<const char*>(fields[3].data()), fields[3].size());
    auto decoded = DecodeRtspDigestHex(hex, digest_size);
    if (!decoded.ok()) {
      return CredentialFailure<CredentialState>(kFormatInvalid);
    }

    CredentialRecord record;
    record.username.assign(fields[0].begin(), fields[0].end());
    record.algorithm = algorithm;
    record.ha1 = std::move(decoded).value();
    state.records.push_back(std::move(record));
    has_sha256 = has_sha256 || algorithm == RtspDigestAlgorithm::kSha256;
    cursor = line_end + 1U;
  }

  if (!has_sha256) {
    return CredentialFailure<CredentialState>(kFormatInvalid);
  }
  return common::Result<CredentialState>::Ok(std::move(state));
}

int OpenReadOnlyNoFollow(const std::filesystem::path& path) noexcept {
  int fd;
  do {
    fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  } while (fd < 0 && errno == EINTR);
  return fd;
}

bool FstatNoIntr(int fd, struct stat* status) noexcept {
  int result;
  do {
    result = ::fstat(fd, status);
  } while (result != 0 && errno == EINTR);
  return result == 0;
}

common::Result<LoadedCredentialState> LoadCredentialFile(
    int opened_fd, std::string_view realm, const AlgorithmPolicy& policy) {
  UniqueFd fd(opened_fd);

  struct stat status {};
  if (!FstatNoIntr(fd.get(), &status)) {
    return CredentialFailure<LoadedCredentialState>(kReadFailed);
  }
  if (!S_ISREG(status.st_mode) ||
      (status.st_uid != ::geteuid() && status.st_uid != 0U) ||
      (status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return CredentialFailure<LoadedCredentialState>(kPermissionsInvalid);
  }
  if (status.st_size <= 0 ||
      static_cast<unsigned long long>(status.st_size) >
          kMaximumCredentialFileBytes) {
    return CredentialFailure<LoadedCredentialState>(kSizeInvalid);
  }

  common::SecureBytes file_bytes;
  try {
    file_bytes.resize(static_cast<std::size_t>(status.st_size));
  } catch (...) {
    return CredentialFailure<LoadedCredentialState>(kOperationFailed);
  }

  std::size_t offset = 0U;
  while (offset < file_bytes.size()) {
    const ssize_t count =
        ::read(fd.get(), file_bytes.data() + offset, file_bytes.size() - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      file_bytes.clear();
      return CredentialFailure<LoadedCredentialState>(kReadFailed);
    }
    offset += static_cast<std::size_t>(count);
  }

  struct stat final_status {};
  if (!FstatNoIntr(fd.get(), &final_status) ||
      final_status.st_size != status.st_size) {
    file_bytes.clear();
    return CredentialFailure<LoadedCredentialState>(kReadFailed);
  }

  common::Result<CredentialState> parsed =
      CredentialFailure<CredentialState>(kOperationFailed);
  try {
    parsed = ParseCredentialBytes(file_bytes, realm, policy);
  } catch (...) {
    file_bytes.clear();
    return CredentialFailure<LoadedCredentialState>(kOperationFailed);
  }
  file_bytes.clear();
  if (!parsed.ok()) {
    return CredentialFailure<LoadedCredentialState>(parsed.error().message);
  }

  LoadedCredentialState loaded;
  loaded.exists = true;
  loaded.state = std::move(parsed).value();
  return common::Result<LoadedCredentialState>::Ok(std::move(loaded));
}

common::Result<LoadedCredentialState> LoadCredentialFile(
    const std::filesystem::path& path, std::string_view realm,
    const AlgorithmPolicy& policy, bool allow_missing) {
  const int opened_fd = OpenReadOnlyNoFollow(path);
  if (opened_fd < 0) {
    if (allow_missing && errno == ENOENT) {
      return common::Result<LoadedCredentialState>::Ok({});
    }
    return CredentialFailure<LoadedCredentialState>(
        errno == ELOOP ? kPermissionsInvalid : kReadFailed);
  }
  return LoadCredentialFile(opened_fd, realm, policy);
}

int OpenAtReadOnlyNoFollow(int parent_fd, const char* name) noexcept {
  int fd;
  do {
    fd = ::openat(parent_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  } while (fd < 0 && errno == EINTR);
  return fd;
}

common::Result<LoadedCredentialState> LoadCredentialAt(
    int parent_fd, const std::string& target_name, std::string_view realm,
    const AlgorithmPolicy& policy, bool allow_missing) {
  const int opened_fd =
      OpenAtReadOnlyNoFollow(parent_fd, target_name.c_str());
  if (opened_fd < 0) {
    if (allow_missing && errno == ENOENT) {
      return common::Result<LoadedCredentialState>::Ok({});
    }
    return CredentialFailure<LoadedCredentialState>(
        errno == ELOOP ? kPermissionsInvalid : kReadFailed);
  }
  return LoadCredentialFile(opened_fd, realm, policy);
}

common::ZeroizeAudit CleanseState(CredentialState* state) noexcept {
  common::ZeroizeAudit audit;
  for (auto& record : state->records) {
    const common::ZeroizeAudit before = record.ha1.zeroize_audit();
    record.ha1.clear();
    const common::ZeroizeAudit after = record.ha1.zeroize_audit();
    audit.count += after.count - before.count;
    audit.last_verified = audit.last_verified && after.last_verified;
  }
  state->records.clear();
  return audit;
}

common::ZeroizeAudit CleanseDummies(
    std::vector<DummyHa1>* dummy_ha1s) noexcept {
  common::ZeroizeAudit audit;
  for (auto& dummy : *dummy_ha1s) {
    const common::ZeroizeAudit before = dummy.bytes.zeroize_audit();
    dummy.bytes.clear();
    const common::ZeroizeAudit after = dummy.bytes.zeroize_audit();
    audit.count += after.count - before.count;
    audit.last_verified = audit.last_verified && after.last_verified;
  }
  dummy_ha1s->clear();
  return audit;
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

bool CheckedAdd(std::size_t value, std::size_t* total) noexcept {
  if (value > std::numeric_limits<std::size_t>::max() - *total) {
    return false;
  }
  *total += value;
  return true;
}

int AlgorithmSortOrder(RtspDigestAlgorithm algorithm) noexcept {
  switch (algorithm) {
    case RtspDigestAlgorithm::kSha256:
      return 0;
    case RtspDigestAlgorithm::kMd5:
      return 1;
  }
  return 2;
}

bool RecordLess(const CredentialRecord& left,
                const CredentialRecord& right) noexcept {
  if (left.username != right.username) {
    return std::lexicographical_compare(
        left.username.begin(), left.username.end(), right.username.begin(),
        right.username.end());
  }
  return AlgorithmSortOrder(left.algorithm) <
         AlgorithmSortOrder(right.algorithm);
}

common::Result<common::SecureBytes> SerializeCredentials(
    const CredentialState& state, std::string_view realm) {
  std::size_t total_size = kFileHeader.size() + 1U;
  for (const auto& record : state.records) {
    const std::string_view algorithm = RtspDigestConfigName(record.algorithm);
    if (algorithm.empty() || record.ha1.size() != RtspDigestSize(record.algorithm) ||
        !CheckedAdd(record.username.size(), &total_size) ||
        !CheckedAdd(1U, &total_size) ||
        !CheckedAdd(realm.size(), &total_size) ||
        !CheckedAdd(1U, &total_size) ||
        !CheckedAdd(algorithm.size(), &total_size) ||
        !CheckedAdd(1U, &total_size) ||
        record.ha1.size() > std::numeric_limits<std::size_t>::max() / 2U ||
        !CheckedAdd(record.ha1.size() * 2U, &total_size) ||
        !CheckedAdd(1U, &total_size) ||
        total_size > kMaximumCredentialFileBytes) {
      return CredentialFailure<common::SecureBytes>(kProvisionInvalid);
    }
  }

  common::SecureBytes serialized;
  try {
    serialized.resize(total_size);
  } catch (...) {
    return CredentialFailure<common::SecureBytes>(kOperationFailed);
  }

  std::size_t offset = 0U;
  const auto append = [&serialized, &offset](const unsigned char* data,
                                              std::size_t size) {
    if (size != 0U) {
      std::memcpy(serialized.data() + offset, data, size);
      offset += size;
    }
  };
  const auto append_string = [&append](std::string_view value) {
    append(reinterpret_cast<const unsigned char*>(value.data()), value.size());
  };
  const unsigned char colon = ':';
  const unsigned char newline = '\n';
  append_string(kFileHeader);
  append(&newline, 1U);
  for (const auto& record : state.records) {
    append(record.username.data(), record.username.size());
    append(&colon, 1U);
    append_string(realm);
    append(&colon, 1U);
    append_string(RtspDigestConfigName(record.algorithm));
    append(&colon, 1U);
    auto encoded = EncodeRtspDigestLowerHex(
        {record.ha1.data(), record.ha1.size()});
    if (!encoded.ok()) {
      serialized.clear();
      return CredentialFailure<common::SecureBytes>(kOperationFailed);
    }
    append(encoded.value().data(), encoded.value().size());
    append(&newline, 1U);
  }
  if (offset != serialized.size()) {
    serialized.clear();
    return CredentialFailure<common::SecureBytes>(kOperationFailed);
  }
  return common::Result<common::SecureBytes>::Ok(std::move(serialized));
}

bool Fchmod0600(int fd) noexcept {
  int result;
  do {
    result = ::fchmod(fd, 0600);
  } while (result != 0 && errno == EINTR);
  return result == 0;
}

bool WriteAll(int fd, const common::SecureBytes& bytes) noexcept {
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    const ssize_t count =
        ::write(fd, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      return false;
    }
    offset += static_cast<std::size_t>(count);
  }
  return true;
}

bool FsyncNoIntr(int fd) noexcept {
  int result;
  do {
    result = ::fsync(fd);
  } while (result != 0 && errno == EINTR);
  return result == 0;
}

void UnlinkAtNoIntr(int parent_fd, const char* name) noexcept {
  int result;
  do {
    result = ::unlinkat(parent_fd, name, 0);
  } while (result != 0 && errno == EINTR);
}

int OpenDirectory(const std::filesystem::path& path) noexcept {
  int fd;
  do {
    fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY);
  } while (fd < 0 && errno == EINTR);
  return fd;
}

struct TemporaryFile {
  TemporaryFile(int parent, std::string temporary_name,
                int temporary_fd) noexcept
      : parent_fd(parent),
        name(std::move(temporary_name)),
        fd(temporary_fd),
        linked(true) {}

  ~TemporaryFile() { Cleanup(); }

  TemporaryFile(const TemporaryFile&) = delete;
  TemporaryFile& operator=(const TemporaryFile&) = delete;

  TemporaryFile(TemporaryFile&& other) noexcept
      : parent_fd(std::exchange(other.parent_fd, -1)),
        name(std::move(other.name)),
        fd(std::move(other.fd)),
        linked(std::exchange(other.linked, false)) {}

  TemporaryFile& operator=(TemporaryFile&& other) noexcept {
    if (this != &other) {
      Cleanup();
      parent_fd = std::exchange(other.parent_fd, -1);
      name = std::move(other.name);
      fd = std::move(other.fd);
      linked = std::exchange(other.linked, false);
    }
    return *this;
  }

  void Cleanup() noexcept {
    (void)fd.Close();
    if (linked) {
      UnlinkAtNoIntr(parent_fd, name.c_str());
      linked = false;
    }
  }

  void MarkRenamed() noexcept { linked = false; }

  int parent_fd{-1};
  std::string name;
  UniqueFd fd;
  bool linked{false};
};

common::Result<std::string> GenerateTemporaryName() {
  std::array<unsigned char, kTemporaryRandomBytes> random_bytes{};
  if (RAND_bytes(random_bytes.data(),
                 static_cast<int>(random_bytes.size())) != 1) {
    return CredentialFailure<std::string>(kOperationFailed);
  }

  static constexpr char kHex[] = "0123456789abcdef";
  std::string name(kTemporaryPrefix);
  name.reserve(kTemporaryPrefix.size() + random_bytes.size() * 2U);
  for (const unsigned char byte : random_bytes) {
    name.push_back(kHex[byte >> 4U]);
    name.push_back(kHex[byte & 0x0fU]);
  }
  return common::Result<std::string>::Ok(std::move(name));
}

common::Result<TemporaryFile> CreateTemporaryFileAt(int parent_fd) {
  for (std::size_t attempt = 0U;
       attempt < kMaximumTemporaryCreateAttempts; ++attempt) {
    auto generated_name = GenerateTemporaryName();
    if (!generated_name.ok()) {
      return CredentialFailure<TemporaryFile>(generated_name.error().message);
    }
    std::string name = std::move(generated_name).value();

    while (true) {
      const int fd = ::openat(
          parent_fd, name.c_str(),
          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
      if (fd >= 0) {
        return common::Result<TemporaryFile>::Ok(
            TemporaryFile(parent_fd, std::move(name), fd));
      }
      if (errno == EINTR) {
        continue;
      }
      if (errno == EEXIST) {
        break;
      }
      return CredentialFailure<TemporaryFile>(kReplaceFailed);
    }
  }
  return CredentialFailure<TemporaryFile>(kReplaceFailed);
}

common::Result<void> WriteAtomicCredentialFile(
    UniqueFd* parent_fd, const std::string& target_name,
    const common::SecureBytes& serialized) {
  auto created = CreateTemporaryFileAt(parent_fd->get());
  if (!created.ok()) {
    return CredentialFailureVoid(created.error().message);
  }
  TemporaryFile temporary = std::move(created).value();

  const auto fail_before_rename = [&temporary]() {
    temporary.Cleanup();
    return CredentialFailureVoid(kReplaceFailed);
  };

  if (!Fchmod0600(temporary.fd.get()) ||
      !WriteAll(temporary.fd.get(), serialized) ||
      !FsyncNoIntr(temporary.fd.get()) || !temporary.fd.Close()) {
    return fail_before_rename();
  }
  if (::renameat(parent_fd->get(), temporary.name.c_str(), parent_fd->get(),
                 target_name.c_str()) != 0) {
    return fail_before_rename();
  }
  temporary.MarkRenamed();
  const bool parent_synced = FsyncNoIntr(parent_fd->get());
  const bool parent_closed = parent_fd->Close();
  if (!parent_synced || !parent_closed) {
    return CredentialFailureVoid(kDurabilityUnconfirmed);
  }
  return common::Result<void>::Ok();
}

bool HasSha256RecordFor(const CredentialState& state,
                        std::string_view username) noexcept {
  return std::any_of(state.records.begin(), state.records.end(),
                     [username](const CredentialRecord& record) {
                       return record.algorithm ==
                                  RtspDigestAlgorithm::kSha256 &&
                              UsernameEqual(record.username, username);
                     });
}

std::size_t CountUsers(const CredentialState& state) noexcept {
  std::size_t count = 0U;
  for (std::size_t index = 0U; index < state.records.size(); ++index) {
    bool seen = false;
    for (std::size_t previous = 0U; previous < index; ++previous) {
      if (state.records[previous].username == state.records[index].username) {
        seen = true;
        break;
      }
    }
    if (!seen) {
      ++count;
    }
  }
  return count;
}

common::Result<void> UpsertCredential(
    CredentialState* state, const RtspDigestProvisionRequest& request,
    common::SecureBytes ha1) {
  for (auto& record : state->records) {
    if (record.algorithm == request.algorithm &&
        UsernameEqual(record.username, request.username)) {
      record.ha1 = std::move(ha1);
      return common::Result<void>::Ok();
    }
  }

  const bool known_user = std::any_of(
      state->records.begin(), state->records.end(),
      [&request](const CredentialRecord& record) {
        return UsernameEqual(record.username, request.username);
      });
  if (state->records.size() == kMaximumRecords ||
      (!known_user && CountUsers(*state) == kMaximumUsers)) {
    return CredentialFailureVoid(kProvisionInvalid);
  }

  CredentialRecord record;
  record.username.assign(request.username.begin(), request.username.end());
  record.algorithm = request.algorithm;
  record.ha1 = std::move(ha1);
  state->records.push_back(std::move(record));
  return common::Result<void>::Ok();
}

}  // namespace

struct RtspDigestCredentialStore::Impl {
  std::string realm;
  AlgorithmPolicy policy;
  std::vector<DummyHa1> dummy_ha1s;
  CredentialState credentials;
  common::ZeroizeAudit audit;
  bool terminal{false};
  mutable std::mutex mutex;
};

RtspDigestCredentialStore::RtspDigestCredentialStore(
    std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

RtspDigestCredentialStore::~RtspDigestCredentialStore() { Clear(); }

common::Result<std::unique_ptr<RtspDigestCredentialStore>>
RtspDigestCredentialStore::Create(RtspDigestCredentialPolicy policy) {
  try {
    auto validated = ValidatePolicy(policy);
    if (!validated.ok()) {
      return CredentialFailure<std::unique_ptr<RtspDigestCredentialStore>>(
          kPolicyInvalid);
    }

    auto impl = std::make_unique<Impl>();
    impl->realm = std::move(policy.realm);
    impl->policy = validated.value();
    impl->dummy_ha1s.reserve(policy.algorithms.size());
    for (const RtspDigestAlgorithm algorithm : policy.algorithms) {
      auto random = RtspDigestRandomBytes(RtspDigestSize(algorithm));
      if (!random.ok()) {
        return CredentialFailure<std::unique_ptr<RtspDigestCredentialStore>>(
            kOperationFailed);
      }
      DummyHa1 dummy;
      dummy.algorithm = algorithm;
      dummy.bytes = std::move(random).value();
      impl->dummy_ha1s.push_back(std::move(dummy));
    }

    auto store = std::unique_ptr<RtspDigestCredentialStore>(
        new RtspDigestCredentialStore(std::move(impl)));
    return common::Result<std::unique_ptr<RtspDigestCredentialStore>>::Ok(
        std::move(store));
  } catch (...) {
    return CredentialFailure<std::unique_ptr<RtspDigestCredentialStore>>(
        kOperationFailed);
  }
}

common::Result<void> RtspDigestCredentialStore::Reload(
    const std::filesystem::path& path) {
  try {
    {
      std::lock_guard lock(impl_->mutex);
      if (impl_->terminal) {
        return CredentialFailureVoid(kOperationFailed);
      }
    }
    auto loaded = LoadCredentialFile(path, impl_->realm, impl_->policy, false);
    if (!loaded.ok()) {
      return CredentialFailureVoid(loaded.error().message);
    }

    CredentialState candidate = std::move(loaded).value().state;
    std::lock_guard lock(impl_->mutex);
    if (impl_->terminal) {
      AccumulateAudit(CleanseState(&candidate), &impl_->audit);
      return CredentialFailureVoid(kOperationFailed);
    }
    std::swap(impl_->credentials, candidate);
    AccumulateAudit(CleanseState(&candidate), &impl_->audit);
    return common::Result<void>::Ok();
  } catch (...) {
    return CredentialFailureVoid(kOperationFailed);
  }
}

common::Result<RtspDigestCredentialLookup>
RtspDigestCredentialStore::Lookup(std::string_view username,
                                  RtspDigestAlgorithm algorithm) const {
  if (!IsKnownAlgorithm(algorithm) || !IsEnabled(impl_->policy, algorithm)) {
    return CredentialFailure<RtspDigestCredentialLookup>(kLookupInvalid);
  }

  try {
    std::lock_guard lock(impl_->mutex);
    if (impl_->terminal) {
      return CredentialFailure<RtspDigestCredentialLookup>(kOperationFailed);
    }
    const common::SecureBytes* source = nullptr;
    bool matched = false;
    for (const auto& record : impl_->credentials.records) {
      if (record.algorithm == algorithm &&
          UsernameEqual(record.username, username)) {
        source = &record.ha1;
        matched = true;
        break;
      }
    }
    if (source == nullptr) {
      for (const auto& dummy : impl_->dummy_ha1s) {
        if (dummy.algorithm == algorithm) {
          source = &dummy.bytes;
          break;
        }
      }
    }
    if (source == nullptr) {
      return CredentialFailure<RtspDigestCredentialLookup>(kOperationFailed);
    }

    RtspDigestCredentialLookup lookup;
    lookup.ha1.assign(source->data(), source->size());
    lookup.matched = matched;
    return common::Result<RtspDigestCredentialLookup>::Ok(std::move(lookup));
  } catch (...) {
    return CredentialFailure<RtspDigestCredentialLookup>(kOperationFailed);
  }
}

void RtspDigestCredentialStore::Clear() noexcept {
  try {
    std::lock_guard lock(impl_->mutex);
    if (impl_->terminal) {
      return;
    }
    AccumulateAudit(CleanseState(&impl_->credentials), &impl_->audit);
    AccumulateAudit(CleanseDummies(&impl_->dummy_ha1s), &impl_->audit);
    impl_->terminal = true;
  } catch (...) {
  }
}

common::ZeroizeAudit RtspDigestCredentialStore::zeroize_audit() const noexcept {
  try {
    std::lock_guard lock(impl_->mutex);
    return impl_->audit;
  } catch (...) {
    return {0U, false};
  }
}

common::Result<void> ProvisionRtspDigestCredential(
    const RtspDigestProvisionRequest& request,
    std::span<const unsigned char> password) {
  try {
    if (request.path.empty() || !IsValidUsername(request.username) ||
        !IsValidRealm(request.realm) || !IsKnownAlgorithm(request.algorithm) ||
        (request.algorithm == RtspDigestAlgorithm::kMd5 &&
         !request.allow_md5) ||
        (password.data() == nullptr && !password.empty()) ||
        request.path.native().find('\0') != std::string::npos) {
      return CredentialFailureVoid(kProvisionInvalid);
    }

    std::filesystem::path parent = request.path.parent_path();
    if (parent.empty()) {
      parent = ".";
    }
    const std::string target_name = request.path.filename().string();
    if (target_name.empty() || target_name == "." || target_name == ".." ||
        target_name.find('/') != std::string::npos ||
        target_name.find('\0') != std::string::npos) {
      return CredentialFailureVoid(kProvisionInvalid);
    }

    UniqueFd parent_fd(OpenDirectory(parent));
    if (parent_fd.get() < 0) {
      return CredentialFailureVoid(kReplaceFailed);
    }

    AlgorithmPolicy policy{true, true};
    auto loaded = LoadCredentialAt(parent_fd.get(), target_name, request.realm,
                                   policy, true);
    if (!loaded.ok()) {
      return CredentialFailureVoid(loaded.error().message);
    }
    CredentialState state = std::move(loaded).value().state;
    if (request.algorithm == RtspDigestAlgorithm::kMd5 &&
        !HasSha256RecordFor(state, request.username)) {
      return CredentialFailureVoid(kProvisionInvalid);
    }

    auto computed = ComputeRtspDigestHa1(request.algorithm, request.username,
                                         request.realm, password);
    if (!computed.ok()) {
      return CredentialFailureVoid(kOperationFailed);
    }
    auto upserted =
        UpsertCredential(&state, request, std::move(computed).value());
    if (!upserted.ok()) {
      return CredentialFailureVoid(upserted.error().message);
    }
    std::sort(state.records.begin(), state.records.end(), RecordLess);

    auto serialized = SerializeCredentials(state, request.realm);
    if (!serialized.ok()) {
      return CredentialFailureVoid(serialized.error().message);
    }
    return WriteAtomicCredentialFile(&parent_fd, target_name,
                                     serialized.value());
  } catch (...) {
    return CredentialFailureVoid(kOperationFailed);
  }
}

}  // namespace camera_firmware::rtsp
