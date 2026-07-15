#include "camera_firmware/settings/RuntimeSettingsStore.hpp"

#include "RuntimeSettingsDocumentCodec.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" ssize_t camera_firmware_settings_write(int, const void*, size_t);
extern "C" int camera_firmware_settings_fdatasync(int);
extern "C" int camera_firmware_settings_renameat(
    int, const char*, int, const char*);
extern "C" int camera_firmware_settings_unlinkat(int, const char*, int);
extern "C" int camera_firmware_settings_fsync(int);

namespace camera_firmware::settings {
namespace {

static_assert(std::is_nothrow_move_constructible_v<RuntimeSettingsDocument>);
static_assert(std::is_nothrow_move_assignable_v<RuntimeSettingsDocument>);

constexpr mode_t kStateDirectoryMode = 0700;
constexpr mode_t kSettingsFileMode = 0600;
constexpr mode_t kPermissionAndSpecialModeMask = 07777;
constexpr std::size_t kMaximumDocumentBytes = 16U * 1024U;
constexpr std::size_t kMaximumInterruptedRetries = 128U;
constexpr std::size_t kMaximumTemporaryNameAttempts = 128U;
constexpr std::string_view kSettingsName = "runtime-settings.json";
constexpr std::string_view kTemporaryPrefix = ".runtime-settings.json.tmp-";
constexpr std::string_view kRollbackName =
    ".runtime-settings.json.rollback";
constexpr std::string_view kPreviousName =
    ".runtime-settings.json.previous";

enum class DurableMarkerState { kNone, kRollback, kPrevious };

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

  [[nodiscard]] int get() const noexcept { return descriptor_; }
  [[nodiscard]] bool valid() const noexcept { return descriptor_ >= 0; }

  int Release() noexcept { return std::exchange(descriptor_, -1); }

  void Reset(int descriptor = -1) noexcept {
    if (descriptor_ >= 0) {
      (void)::close(descriptor_);
    }
    descriptor_ = descriptor;
  }

 private:
  int descriptor_{-1};
};

class DirectoryAnchor {
 public:
  explicit DirectoryAnchor(std::vector<UniqueFd> descriptors)
      : descriptors_(std::move(descriptors)) {}

  DirectoryAnchor(const DirectoryAnchor&) = delete;
  DirectoryAnchor& operator=(const DirectoryAnchor&) = delete;
  DirectoryAnchor(DirectoryAnchor&&) noexcept = default;
  DirectoryAnchor& operator=(DirectoryAnchor&&) noexcept = default;

  [[nodiscard]] std::size_t size() const noexcept {
    return descriptors_.size();
  }
  [[nodiscard]] int descriptor(std::size_t index) const noexcept {
    return descriptors_[index].get();
  }
  [[nodiscard]] int state_directory_descriptor() const noexcept {
    return descriptors_.back().get();
  }

 private:
  std::vector<UniqueFd> descriptors_;
};

class TemporaryFile {
 public:
  TemporaryFile(int directory, std::string name)
      : directory_(directory), name_(std::move(name)) {}
  ~TemporaryFile() { (void)Remove(); }

  TemporaryFile(const TemporaryFile&) = delete;
  TemporaryFile& operator=(const TemporaryFile&) = delete;

  [[nodiscard]] const std::string& name() const noexcept { return name_; }
  void MarkRenamed() noexcept { renamed_ = true; }
  bool Remove() noexcept {
    if (renamed_) {
      return true;
    }
    int result;
    do {
      result = ::unlinkat(directory_, name_.c_str(), 0);
    } while (result != 0 && errno == EINTR);
    if (result == 0 || errno == ENOENT) {
      renamed_ = true;
      return true;
    }
    return false;
  }

 private:
  int directory_;
  std::string name_;
  bool renamed_{false};
};

template <typename T>
common::Result<T> Error(std::string code, std::string message) {
  return common::Result<T>::Err({std::move(code), std::move(message)});
}

common::Result<void> Error(std::string code, std::string message) {
  return common::Result<void>::Err({std::move(code), std::move(message)});
}

template <typename T>
common::Result<T> DurableStoreError() {
  return Error<T>("E_RUNTIME_SETTINGS_STORE",
                  "runtime settings persistence failed");
}

bool SameObject(const struct stat& first, const struct stat& second) noexcept {
  return first.st_dev == second.st_dev && first.st_ino == second.st_ino;
}

int OpenDirectoryAtNoFollow(int parent, const char* name) noexcept {
  int descriptor;
  do {
    descriptor = ::openat(parent, name,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (descriptor < 0 && errno == EINTR);
  return descriptor;
}

common::Result<DirectoryAnchor> OpenDirectoryPathNoSymlinks(
    const std::filesystem::path& path) {
  if (!path.is_absolute()) {
    return Error<DirectoryAnchor>(
        "E_RUNTIME_SETTINGS_PATH",
        "runtime settings state directory is invalid");
  }

  std::vector<UniqueFd> descriptors;
  UniqueFd root(OpenDirectoryAtNoFollow(AT_FDCWD, "/"));
  if (!root.valid()) {
    return Error<DirectoryAnchor>(
        "E_RUNTIME_SETTINGS_PATH",
        "runtime settings state directory is unavailable");
  }
  descriptors.push_back(std::move(root));

  for (const auto& component : path.relative_path()) {
    const std::string name = component.string();
    if (name.empty()) {
      continue;
    }
    if (name == "." || name == ".." ||
        name.find('/') != std::string::npos ||
        name.find('\0') != std::string::npos) {
      return Error<DirectoryAnchor>(
          "E_RUNTIME_SETTINGS_PATH",
          "runtime settings state directory is invalid");
    }
    UniqueFd child(
        OpenDirectoryAtNoFollow(descriptors.back().get(), name.c_str()));
    if (!child.valid()) {
      return Error<DirectoryAnchor>(
          "E_RUNTIME_SETTINGS_PATH",
          "runtime settings state directory is unavailable");
    }
    descriptors.push_back(std::move(child));
  }
  return common::Result<DirectoryAnchor>::Ok(
      DirectoryAnchor(std::move(descriptors)));
}

common::Result<struct stat> ValidateStateDirectory(int descriptor,
                                                   uid_t expected_owner) {
  struct stat status {};
  if (::fstat(descriptor, &status) != 0 || !S_ISDIR(status.st_mode)) {
    return Error<struct stat>("E_RUNTIME_SETTINGS_PATH",
                              "runtime settings state directory is invalid");
  }
  if ((status.st_mode & kPermissionAndSpecialModeMask) !=
      kStateDirectoryMode) {
    return Error<struct stat>(
        "E_RUNTIME_SETTINGS_STATE_MODE",
        "runtime settings state directory must have mode 0700");
  }
  if (status.st_uid != expected_owner) {
    return Error<struct stat>(
        "E_RUNTIME_SETTINGS_STATE_OWNER",
        "runtime settings state directory must be owned by the effective user");
  }
  return common::Result<struct stat>::Ok(status);
}

common::Result<void> VerifyDirectoryAnchor(
    const std::filesystem::path& path, const DirectoryAnchor& anchored,
    uid_t expected_owner) {
  auto current = OpenDirectoryPathNoSymlinks(path);
  if (!current.ok()) {
    return Error(current.error().code, current.error().message);
  }
  if (current.value().size() != anchored.size()) {
    return Error("E_RUNTIME_SETTINGS_PATH",
                 "runtime settings directory chain changed");
  }
  for (std::size_t index = 0U; index < anchored.size(); ++index) {
    struct stat anchored_status {};
    struct stat current_status {};
    if (::fstat(anchored.descriptor(index), &anchored_status) != 0 ||
        ::fstat(current.value().descriptor(index), &current_status) != 0 ||
        !SameObject(anchored_status, current_status)) {
      return Error("E_RUNTIME_SETTINGS_PATH",
                   "runtime settings directory chain changed");
    }
  }
  auto current_status =
      ValidateStateDirectory(current.value().state_directory_descriptor(),
                             expected_owner);
  if (!current_status.ok()) {
    return Error(current_status.error().code, current_status.error().message);
  }
  return common::Result<void>::Ok();
}

bool VerifyDirectoryAnchorNoThrow(const std::filesystem::path& path,
                                  const DirectoryAnchor& anchored,
                                  uid_t expected_owner) noexcept {
  try {
    return VerifyDirectoryAnchor(path, anchored, expected_owner).ok();
  } catch (...) {
    return false;
  }
}

common::Result<std::optional<std::string>> ReadDocument(
    int directory_descriptor, uid_t expected_owner, std::string_view name) {
  int raw_descriptor;
  do {
    raw_descriptor = ::openat(directory_descriptor, name.data(),
                              O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
  } while (raw_descriptor < 0 && errno == EINTR);
  if (raw_descriptor < 0) {
    if (errno == ENOENT) {
      return common::Result<std::optional<std::string>>::Ok(std::nullopt);
    }
    return Error<std::optional<std::string>>(
        "E_RUNTIME_SETTINGS_PATH", "runtime settings document is unavailable");
  }
  UniqueFd descriptor(raw_descriptor);

  struct stat opened_status {};
  if (::fstat(descriptor.get(), &opened_status) != 0 ||
      !S_ISREG(opened_status.st_mode)) {
    return Error<std::optional<std::string>>(
        "E_RUNTIME_SETTINGS_PATH",
        "runtime settings document must be a regular file");
  }
  if ((opened_status.st_mode & kPermissionAndSpecialModeMask) !=
      kSettingsFileMode) {
    return Error<std::optional<std::string>>(
        "E_RUNTIME_SETTINGS_FILE_MODE",
        "runtime settings document must have mode 0600");
  }
  if (opened_status.st_uid != expected_owner) {
    return Error<std::optional<std::string>>(
        "E_RUNTIME_SETTINGS_FILE_OWNER",
        "runtime settings document must be owned by the effective user");
  }

  std::string content;
  content.reserve(std::min<std::size_t>(
      opened_status.st_size > 0
          ? static_cast<std::size_t>(opened_status.st_size)
          : 0U,
      kMaximumDocumentBytes + 1U));
  std::array<char, 4096U> buffer{};
  while (content.size() <= kMaximumDocumentBytes) {
    const std::size_t remaining =
        kMaximumDocumentBytes + 1U - content.size();
    const ssize_t count = ::read(descriptor.get(), buffer.data(),
                                 std::min(buffer.size(), remaining));
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      return Error<std::optional<std::string>>(
          "E_RUNTIME_SETTINGS_PATH", "runtime settings document read failed");
    }
    if (count == 0) {
      break;
    }
    content.append(buffer.data(), static_cast<std::size_t>(count));
  }

  struct stat current_entry {};
  if (::fstatat(directory_descriptor, name.data(), &current_entry,
                AT_SYMLINK_NOFOLLOW) != 0 ||
      !S_ISREG(current_entry.st_mode) ||
      !SameObject(opened_status, current_entry)) {
    return Error<std::optional<std::string>>(
        "E_RUNTIME_SETTINGS_PATH", "runtime settings document changed");
  }
  return common::Result<std::optional<std::string>>::Ok(std::move(content));
}

std::string NextTemporaryName() {
  static std::atomic<std::uint64_t> sequence{0U};
  return std::string(kTemporaryPrefix) + std::to_string(::getpid()) + "-" +
         std::to_string(sequence.fetch_add(1U, std::memory_order_relaxed));
}

common::Result<std::pair<UniqueFd, std::string>> CreateTemporaryFile(
    int directory_descriptor, uid_t expected_owner) {
  for (std::size_t attempt = 0U; attempt < kMaximumTemporaryNameAttempts;
       ++attempt) {
    std::string name = NextTemporaryName();
    int raw_descriptor;
    do {
      raw_descriptor = ::openat(directory_descriptor, name.c_str(),
                                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                    O_CLOEXEC,
                                kSettingsFileMode);
    } while (raw_descriptor < 0 && errno == EINTR);
    if (raw_descriptor < 0 && errno == EEXIST) {
      continue;
    }
    if (raw_descriptor < 0) {
      return DurableStoreError<std::pair<UniqueFd, std::string>>();
    }

    UniqueFd descriptor(raw_descriptor);
    if (::fchmod(descriptor.get(), kSettingsFileMode) != 0) {
      int result;
      do {
        result = ::unlinkat(directory_descriptor, name.c_str(), 0);
      } while (result != 0 && errno == EINTR);
      return DurableStoreError<std::pair<UniqueFd, std::string>>();
    }
    struct stat status {};
    if (::fstat(descriptor.get(), &status) != 0 ||
        !S_ISREG(status.st_mode) || status.st_uid != expected_owner ||
        (status.st_mode & kPermissionAndSpecialModeMask) !=
            kSettingsFileMode) {
      int result;
      do {
        result = ::unlinkat(directory_descriptor, name.c_str(), 0);
      } while (result != 0 && errno == EINTR);
      return DurableStoreError<std::pair<UniqueFd, std::string>>();
    }
    return common::Result<std::pair<UniqueFd, std::string>>::Ok(
        {std::move(descriptor), std::move(name)});
  }
  return DurableStoreError<std::pair<UniqueFd, std::string>>();
}

common::Result<std::unique_ptr<TemporaryFile>> PreserveCurrentDocument(
    int directory_descriptor, uid_t expected_owner) {
  struct stat current_status {};
  int status_result;
  do {
    status_result = ::fstatat(directory_descriptor, kSettingsName.data(),
                              &current_status, AT_SYMLINK_NOFOLLOW);
  } while (status_result != 0 && errno == EINTR);
  if (status_result != 0) {
    if (errno == ENOENT) {
      return common::Result<std::unique_ptr<TemporaryFile>>::Ok(nullptr);
    }
    return DurableStoreError<std::unique_ptr<TemporaryFile>>();
  }
  if (!S_ISREG(current_status.st_mode) ||
      current_status.st_uid != expected_owner ||
      (current_status.st_mode & kPermissionAndSpecialModeMask) !=
          kSettingsFileMode) {
    return DurableStoreError<std::unique_ptr<TemporaryFile>>();
  }

  for (std::size_t attempt = 0U; attempt < kMaximumTemporaryNameAttempts;
       ++attempt) {
    std::string backup_name = NextTemporaryName() + "-rollback";
    int link_result;
    do {
      link_result = ::linkat(directory_descriptor, kSettingsName.data(),
                             directory_descriptor, backup_name.c_str(), 0);
    } while (link_result != 0 && errno == EINTR);
    if (link_result != 0 && errno == EEXIST) {
      continue;
    }
    if (link_result != 0) {
      return DurableStoreError<std::unique_ptr<TemporaryFile>>();
    }

    auto backup =
        std::make_unique<TemporaryFile>(directory_descriptor, backup_name);
    struct stat backup_status {};
    struct stat current_after_link {};
    if (::fstatat(directory_descriptor, backup_name.c_str(), &backup_status,
                  AT_SYMLINK_NOFOLLOW) != 0 ||
        ::fstatat(directory_descriptor, kSettingsName.data(),
                  &current_after_link, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(backup_status.st_mode) ||
        backup_status.st_uid != expected_owner ||
        (backup_status.st_mode & kPermissionAndSpecialModeMask) !=
            kSettingsFileMode ||
        !SameObject(current_status, backup_status) ||
        !SameObject(backup_status, current_after_link)) {
      return DurableStoreError<std::unique_ptr<TemporaryFile>>();
    }
    return common::Result<std::unique_ptr<TemporaryFile>>::Ok(
        std::move(backup));
  }
  return DurableStoreError<std::unique_ptr<TemporaryFile>>();
}

bool WriteAll(int descriptor, std::string_view content) noexcept {
  std::size_t offset = 0U;
  std::size_t interrupted = 0U;
  while (offset < content.size()) {
    const ssize_t written = camera_firmware_settings_write(
        descriptor, content.data() + offset, content.size() - offset);
    if (written < 0 && errno == EINTR &&
        interrupted < kMaximumInterruptedRetries) {
      ++interrupted;
      continue;
    }
    if (written <= 0) {
      return false;
    }
    offset += static_cast<std::size_t>(written);
  }
  return true;
}

template <typename Call>
bool RetryInterrupted(Call&& call) noexcept {
  std::size_t interrupted = 0U;
  for (;;) {
    if (call() == 0) {
      return true;
    }
    if (errno != EINTR || interrupted >= kMaximumInterruptedRetries) {
      return false;
    }
    ++interrupted;
  }
}

}  // namespace

struct RuntimeSettingsStore::Impl {
  Impl(std::filesystem::path state_directory_value,
       DirectoryAnchor directory_anchor_value,
       RuntimeSettingsDocument snapshot_value,
       config::AppConfig base_config_value,
       CameraProfileCatalog profiles_value,
       uid_t effective_user_value,
       DurableMarkerState marker_state_value,
       bool has_previous_marker_value)
      : state_directory(std::move(state_directory_value)),
        directory_anchor(std::move(directory_anchor_value)),
        snapshot(std::move(snapshot_value)),
        base_config(std::move(base_config_value)),
        profiles(std::move(profiles_value)),
        effective_user(effective_user_value),
        marker_state(marker_state_value),
        has_previous_marker(has_previous_marker_value) {}

  common::Result<void> RemovePreviousMarker() {
    if (marker_state != DurableMarkerState::kPrevious) {
      return common::Result<void>::Ok();
    }
    const int directory_descriptor =
        directory_anchor.state_directory_descriptor();
    if (!RetryInterrupted([&] {
          return camera_firmware_settings_unlinkat(
              directory_descriptor, kPreviousName.data(), 0);
        })) {
      return DurableStoreError<void>();
    }
    marker_state = DurableMarkerState::kNone;
    has_previous_marker = false;
    if (!RetryInterrupted([&] {
          return camera_firmware_settings_fsync(directory_descriptor);
        })) {
      return DurableStoreError<void>();
    }
    return common::Result<void>::Ok();
  }

  common::Result<void> BeginProtectedMutation() {
    if (marker_state == DurableMarkerState::kRollback) {
      return common::Result<void>::Ok();
    }
    if (marker_state != DurableMarkerState::kNone) {
      return DurableStoreError<void>();
    }

    const int directory_descriptor =
        directory_anchor.state_directory_descriptor();
    struct stat current_status {};
    if (::fstatat(directory_descriptor, kSettingsName.data(), &current_status,
                  AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(current_status.st_mode) ||
        current_status.st_uid != effective_user ||
        (current_status.st_mode & kPermissionAndSpecialModeMask) !=
            kSettingsFileMode) {
      return DurableStoreError<void>();
    }

    int link_result;
    do {
      link_result = ::linkat(directory_descriptor, kSettingsName.data(),
                             directory_descriptor, kRollbackName.data(), 0);
    } while (link_result != 0 && errno == EINTR);
    if (link_result != 0) {
      return DurableStoreError<void>();
    }
    marker_state = DurableMarkerState::kRollback;

    do {
      link_result = ::linkat(directory_descriptor, kSettingsName.data(),
                             directory_descriptor, kPreviousName.data(), 0);
    } while (link_result != 0 && errno == EINTR);
    if (link_result != 0) {
      poisoned = true;
      return DurableStoreError<void>();
    }
    has_previous_marker = true;

    struct stat marker_status {};
    struct stat previous_status {};
    struct stat current_after_link {};
    if (::fstatat(directory_descriptor, kRollbackName.data(), &marker_status,
                  AT_SYMLINK_NOFOLLOW) != 0 ||
        ::fstatat(directory_descriptor, kPreviousName.data(), &previous_status,
                  AT_SYMLINK_NOFOLLOW) != 0 ||
        ::fstatat(directory_descriptor, kSettingsName.data(),
                  &current_after_link, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(marker_status.st_mode) ||
        marker_status.st_uid != effective_user ||
        (marker_status.st_mode & kPermissionAndSpecialModeMask) !=
            kSettingsFileMode ||
        !SameObject(marker_status, previous_status) ||
        !SameObject(current_status, marker_status) ||
        !SameObject(marker_status, current_after_link) ||
        !RetryInterrupted([&] {
          return camera_firmware_settings_fsync(directory_descriptor);
        })) {
      poisoned = true;
      return DurableStoreError<void>();
    }
    return common::Result<void>::Ok();
  }

  bool RollbackProtectedMutation() noexcept {
    const char* marker_name = nullptr;
    bool previous_remains = false;
    if (marker_state == DurableMarkerState::kRollback) {
      marker_name = kRollbackName.data();
      previous_remains = has_previous_marker;
    } else if (marker_state == DurableMarkerState::kPrevious) {
      marker_name = kPreviousName.data();
    } else {
      return false;
    }
    const int directory_descriptor =
        directory_anchor.state_directory_descriptor();
    if (!RetryInterrupted([&] {
          return camera_firmware_settings_renameat(
              directory_descriptor, marker_name, directory_descriptor,
              kSettingsName.data());
        })) {
      return false;
    }
    marker_state = previous_remains ? DurableMarkerState::kPrevious
                                    : DurableMarkerState::kNone;
    has_previous_marker = previous_remains;
    return RetryInterrupted([&] {
      return camera_firmware_settings_fsync(directory_descriptor);
    });
  }

  bool CommitProtectedMutation() noexcept {
    if (marker_state != DurableMarkerState::kRollback) {
      return false;
    }
    const int directory_descriptor =
        directory_anchor.state_directory_descriptor();
    if (!has_previous_marker) {
      int link_result;
      do {
        link_result = ::linkat(directory_descriptor, kRollbackName.data(),
                               directory_descriptor, kPreviousName.data(), 0);
      } while (link_result != 0 && errno == EINTR);
      if (link_result != 0) {
        return false;
      }
      has_previous_marker = true;
    }
    if (!RetryInterrupted([&] {
          return camera_firmware_settings_unlinkat(
              directory_descriptor, kRollbackName.data(), 0);
        })) {
      return false;
    }
    marker_state = DurableMarkerState::kPrevious;
    if (RetryInterrupted([&] {
          return camera_firmware_settings_fsync(directory_descriptor);
        })) {
      return true;
    }

    int link_result;
    do {
      link_result = ::linkat(directory_descriptor, kPreviousName.data(),
                             directory_descriptor, kRollbackName.data(), 0);
    } while (link_result != 0 && errno == EINTR);
    if (link_result == 0) {
      marker_state = DurableMarkerState::kRollback;
      if (!RetryInterrupted([&] {
            return camera_firmware_settings_fsync(directory_descriptor);
          })) {
        poisoned = true;
      }
    }
    return false;
  }

  common::Result<void> Persist(const RuntimeSettingsDocument& candidate,
                               bool protect_active) {
    auto encoded = internal::EncodeRuntimeSettingsDocument(
        candidate, base_config, profiles);
    if (!encoded.ok()) {
      return Error(encoded.error().code, encoded.error().message);
    }
    if (!VerifyDirectoryAnchor(state_directory, directory_anchor,
                               effective_user)
             .ok()) {
      return DurableStoreError<void>();
    }
    auto marker_removed = RemovePreviousMarker();
    if (!marker_removed.ok()) {
      return DurableStoreError<void>();
    }

    const int directory_descriptor =
        directory_anchor.state_directory_descriptor();
    auto created = CreateTemporaryFile(directory_descriptor, effective_user);
    if (!created.ok()) {
      return DurableStoreError<void>();
    }
    UniqueFd temporary_descriptor = std::move(created.value().first);
    TemporaryFile temporary_file(directory_descriptor,
                                 std::move(created.value().second));

    if (!WriteAll(temporary_descriptor.get(), encoded.value()) ||
        !RetryInterrupted([&] {
          return camera_firmware_settings_fdatasync(temporary_descriptor.get());
        })) {
      return DurableStoreError<void>();
    }

    const int descriptor_to_close = temporary_descriptor.Release();
    if (::close(descriptor_to_close) != 0) {
      return DurableStoreError<void>();
    }
    if (!VerifyDirectoryAnchor(state_directory, directory_anchor,
                               effective_user)
             .ok()) {
      return DurableStoreError<void>();
    }
    if (protect_active && marker_state == DurableMarkerState::kNone) {
      auto protected_mutation = BeginProtectedMutation();
      if (!protected_mutation.ok()) {
        return DurableStoreError<void>();
      }
    }
    const bool uses_durable_marker =
        marker_state == DurableMarkerState::kRollback;
    std::unique_ptr<TemporaryFile> previous_document;
    if (!uses_durable_marker) {
      auto preserved =
          PreserveCurrentDocument(directory_descriptor, effective_user);
      if (!preserved.ok()) {
        return DurableStoreError<void>();
      }
      previous_document = std::move(preserved).value();
    }
    if (previous_document != nullptr &&
        !RetryInterrupted([&] {
          return camera_firmware_settings_fsync(directory_descriptor);
        })) {
      (void)previous_document->Remove();
      (void)RetryInterrupted([&] {
        return camera_firmware_settings_fsync(directory_descriptor);
      });
      return DurableStoreError<void>();
    }
    if (!RetryInterrupted([&] {
          return camera_firmware_settings_renameat(
              directory_descriptor, temporary_file.name().c_str(),
              directory_descriptor, kSettingsName.data());
        })) {
      return DurableStoreError<void>();
    }
    temporary_file.MarkRenamed();
    if (!RetryInterrupted([&] {
          return camera_firmware_settings_fsync(directory_descriptor);
        }) ||
        !VerifyDirectoryAnchorNoThrow(state_directory, directory_anchor,
                                      effective_user)) {
      bool restored = false;
      if (uses_durable_marker) {
        restored = RollbackProtectedMutation();
      } else if (previous_document != nullptr) {
        restored = RetryInterrupted([&] {
          return camera_firmware_settings_renameat(
              directory_descriptor, previous_document->name().c_str(),
              directory_descriptor, kSettingsName.data());
        });
        if (restored) {
          previous_document->MarkRenamed();
        }
      } else {
        restored = RetryInterrupted([&] {
          return camera_firmware_settings_unlinkat(
              directory_descriptor, kSettingsName.data(), 0);
        });
      }
      const bool rollback_synced =
          uses_durable_marker
              ? restored
              : restored && RetryInterrupted([&] {
                  return camera_firmware_settings_fsync(
                      directory_descriptor);
                });
      if (!rollback_synced) {
        poisoned = true;
      }
      return DurableStoreError<void>();
    }
    if (uses_durable_marker && !CommitProtectedMutation()) {
      if (RollbackProtectedMutation()) {
        return DurableStoreError<void>();
      }
      if (marker_state == DurableMarkerState::kPrevious &&
          VerifyDirectoryAnchorNoThrow(state_directory, directory_anchor,
                                       effective_user)) {
        return common::Result<void>::Ok();
      }
      poisoned = true;
      return DurableStoreError<void>();
    }
    if (previous_document != nullptr && previous_document->Remove()) {
      (void)RetryInterrupted([&] {
        return camera_firmware_settings_fsync(directory_descriptor);
      });
    }
    return common::Result<void>::Ok();
  }

  template <typename Mutation>
  common::Result<RuntimeSettingsDocument> Mutate(
      std::uint64_t expected_revision, bool allow_recovery_replacement,
      bool protect_active, Mutation&& mutation) {
    std::lock_guard lock(mutex);
    if (poisoned) {
      return DurableStoreError<RuntimeSettingsDocument>();
    }
    if (expected_revision != snapshot.revision) {
      return Error<RuntimeSettingsDocument>(
          "E_RUNTIME_SETTINGS_REVISION", "runtime settings revision is stale");
    }
    if (marker_state == DurableMarkerState::kRollback &&
        !allow_recovery_replacement) {
      return DurableStoreError<RuntimeSettingsDocument>();
    }
    if (snapshot.recovery_required && !allow_recovery_replacement) {
      return Error<RuntimeSettingsDocument>(
          "E_RUNTIME_SETTINGS_RECOVERY_REQUIRED",
          "runtime settings recovery requires an explicit save");
    }
    if (snapshot.revision == std::numeric_limits<std::uint64_t>::max()) {
      return Error<RuntimeSettingsDocument>(
          "E_RUNTIME_SETTINGS_REVISION_OVERFLOW",
          "runtime settings revision cannot be incremented");
    }

    RuntimeSettingsDocument candidate = snapshot;
    auto mutated = mutation(candidate);
    if (!mutated.ok()) {
      return Error<RuntimeSettingsDocument>(mutated.error().code,
                                             mutated.error().message);
    }
    ++candidate.revision;
    candidate.recovery_required = false;
    candidate.recovery_code.clear();
    std::optional<RuntimeSettingsDocument> prepared_result;
    try {
      prepared_result.emplace(candidate);
    } catch (...) {
      return DurableStoreError<RuntimeSettingsDocument>();
    }
    auto persisted = Persist(candidate, protect_active);
    if (!persisted.ok()) {
      return Error<RuntimeSettingsDocument>(persisted.error().code,
                                             persisted.error().message);
    }
    snapshot = std::move(candidate);
    return common::Result<RuntimeSettingsDocument>::Ok(
        std::move(*prepared_result));
  }

  std::filesystem::path state_directory;
  DirectoryAnchor directory_anchor;
  RuntimeSettingsDocument snapshot;
  config::AppConfig base_config;
  CameraProfileCatalog profiles;
  uid_t effective_user;
  DurableMarkerState marker_state{DurableMarkerState::kNone};
  bool has_previous_marker{false};
  bool poisoned{false};
  mutable std::mutex mutex;
};

RuntimeSettingsStore::RuntimeSettingsStore(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

RuntimeSettingsStore::~RuntimeSettingsStore() = default;

common::Result<std::unique_ptr<RuntimeSettingsStore>> RuntimeSettingsStore::Open(
    const std::filesystem::path& state_directory, RuntimeSettings base_active,
    const config::AppConfig& base_config,
    const CameraProfileCatalog& profiles) {
  try {
    if (!ValidateRuntimeSettings(base_active, base_config, profiles).ok() ||
        state_directory.empty() ||
        state_directory.native().find('\0') != std::string::npos) {
      return Error<std::unique_ptr<RuntimeSettingsStore>>(
          "E_RUNTIME_SETTINGS_PATH", "runtime settings store is invalid");
    }

    std::error_code path_error;
    auto absolute_directory =
        std::filesystem::absolute(state_directory, path_error);
    if (path_error) {
      return Error<std::unique_ptr<RuntimeSettingsStore>>(
          "E_RUNTIME_SETTINGS_PATH",
          "runtime settings state directory is invalid");
    }

    auto opened_directory = OpenDirectoryPathNoSymlinks(absolute_directory);
    if (!opened_directory.ok()) {
      return Error<std::unique_ptr<RuntimeSettingsStore>>(
          opened_directory.error().code, opened_directory.error().message);
    }
    const uid_t effective_user = ::geteuid();
    auto directory_status =
        ValidateStateDirectory(
            opened_directory.value().state_directory_descriptor(),
            effective_user);
    if (!directory_status.ok()) {
      return Error<std::unique_ptr<RuntimeSettingsStore>>(
          directory_status.error().code, directory_status.error().message);
    }
    auto anchor_status = VerifyDirectoryAnchor(
        absolute_directory, opened_directory.value(), effective_user);
    if (!anchor_status.ok()) {
      return Error<std::unique_ptr<RuntimeSettingsStore>>(
          anchor_status.error().code, anchor_status.error().message);
    }

    const int directory_descriptor =
        opened_directory.value().state_directory_descriptor();
    auto document_text =
        ReadDocument(directory_descriptor, effective_user, kSettingsName);
    if (!document_text.ok()) {
      return Error<std::unique_ptr<RuntimeSettingsStore>>(
          document_text.error().code, document_text.error().message);
    }
    auto rollback_text =
        ReadDocument(directory_descriptor, effective_user, kRollbackName);
    if (!rollback_text.ok()) {
      return Error<std::unique_ptr<RuntimeSettingsStore>>(
          rollback_text.error().code, rollback_text.error().message);
    }
    auto previous_text =
        ReadDocument(directory_descriptor, effective_user, kPreviousName);
    if (!previous_text.ok()) {
      return Error<std::unique_ptr<RuntimeSettingsStore>>(
          previous_text.error().code, previous_text.error().message);
    }
    anchor_status = VerifyDirectoryAnchor(
        absolute_directory, opened_directory.value(), effective_user);
    if (!anchor_status.ok()) {
      return Error<std::unique_ptr<RuntimeSettingsStore>>(
          anchor_status.error().code, anchor_status.error().message);
    }

    RuntimeSettingsDocument snapshot;
    DurableMarkerState marker_state = DurableMarkerState::kNone;
    const bool has_previous_marker = previous_text.value().has_value();
    if (rollback_text.value().has_value()) {
      marker_state = DurableMarkerState::kRollback;
      if (!rollback_text.value()->empty()) {
        auto decoded = internal::DecodeRuntimeSettingsDocument(
            *rollback_text.value(), base_config, profiles);
        if (decoded.ok()) {
          snapshot = std::move(decoded).value();
        } else {
          snapshot.active = base_active;
        }
      } else {
        snapshot.active = base_active;
      }
      snapshot.recovery_required = true;
      snapshot.recovery_code =
          "E_RUNTIME_SETTINGS_STORE_INDETERMINATE";
    } else {
      marker_state = previous_text.value().has_value()
                         ? DurableMarkerState::kPrevious
                         : DurableMarkerState::kNone;
      if (!document_text.value().has_value()) {
        snapshot.active = std::move(base_active);
      } else {
        auto decoded = internal::DecodeRuntimeSettingsDocument(
            *document_text.value(), base_config, profiles);
        if (decoded.ok()) {
          snapshot = std::move(decoded).value();
        } else {
          snapshot.active = std::move(base_active);
          snapshot.recovery_required = true;
          snapshot.recovery_code = "E_RUNTIME_SETTINGS_DOCUMENT";
        }
      }
    }

    auto impl = std::make_unique<Impl>(
        std::move(absolute_directory), std::move(opened_directory).value(),
        std::move(snapshot), base_config, profiles, effective_user,
        marker_state, has_previous_marker);
    return common::Result<std::unique_ptr<RuntimeSettingsStore>>::Ok(
        std::unique_ptr<RuntimeSettingsStore>(
            new RuntimeSettingsStore(std::move(impl))));
  } catch (...) {
    return Error<std::unique_ptr<RuntimeSettingsStore>>(
        "E_RUNTIME_SETTINGS_STORE", "runtime settings store open failed");
  }
}

RuntimeSettingsDocument RuntimeSettingsStore::Snapshot() const {
  std::lock_guard lock(impl_->mutex);
  RuntimeSettingsDocument snapshot = impl_->snapshot;
  if (impl_->poisoned ||
      impl_->marker_state == DurableMarkerState::kRollback) {
    snapshot.recovery_required = true;
    snapshot.recovery_code = "E_RUNTIME_SETTINGS_STORE_INDETERMINATE";
  }
  return snapshot;
}

common::Result<RuntimeSettingsDocument> RuntimeSettingsStore::SavePending(
    std::uint64_t expected_revision, RuntimeSettings pending) {
  return impl_->Mutate(expected_revision, true,
                       false,
                       [pending = std::move(pending)](
                           RuntimeSettingsDocument& candidate) mutable {
                         candidate.pending = std::move(pending);
                         return common::Result<void>::Ok();
                       });
}

common::Result<RuntimeSettingsDocument> RuntimeSettingsStore::DiscardPending(
    std::uint64_t expected_revision) {
  return impl_->Mutate(expected_revision, false,
                       false,
                       [](RuntimeSettingsDocument& candidate) {
                         if (!candidate.pending.has_value()) {
                           return Error("E_RUNTIME_SETTINGS_NO_PENDING",
                                        "runtime settings have no pending state");
                         }
                         candidate.pending.reset();
                         return common::Result<void>::Ok();
                       });
}

common::Result<RuntimeSettingsDocument> RuntimeSettingsStore::PromotePending(
    std::uint64_t expected_revision) {
  return impl_->Mutate(expected_revision, false,
                       true,
                       [](RuntimeSettingsDocument& candidate) {
                         if (!candidate.pending.has_value()) {
                           return Error("E_RUNTIME_SETTINGS_NO_PENDING",
                                        "runtime settings have no pending state");
                         }
                         candidate.active = std::move(*candidate.pending);
                         candidate.pending.reset();
                         candidate.last_apply = {ApplyStatus::kSuccess, "", false};
                         return common::Result<void>::Ok();
                       });
}

common::Result<RuntimeSettingsDocument>
RuntimeSettingsStore::RecordApplyFailure(std::uint64_t expected_revision,
                                         std::string code, bool restored) {
  return impl_->Mutate(expected_revision, false,
                       false,
                       [code = std::move(code), restored](
                           RuntimeSettingsDocument& candidate) mutable {
                         candidate.last_apply = {
                             ApplyStatus::kFailed, std::move(code), restored};
                         return common::Result<void>::Ok();
                       });
}

}  // namespace camera_firmware::settings
