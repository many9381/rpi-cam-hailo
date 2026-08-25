#include "RuntimeSettingsDocumentCodec.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

extern "C" int __real_fstat(int descriptor, struct stat* status);
extern "C" ssize_t __real_camera_firmware_settings_write(
    int descriptor, const void* data, size_t size);
extern "C" int __real_camera_firmware_settings_fdatasync(int descriptor);
extern "C" int __real_camera_firmware_settings_renameat(
    int old_directory, const char* old_name, int new_directory,
    const char* new_name);
extern "C" int __real_camera_firmware_settings_unlinkat(
    int directory, const char* name, int flags);
extern "C" int __real_camera_firmware_settings_fsync(int descriptor);

namespace {

using camera_firmware::config::AiModelConfig;
using camera_firmware::config::AppConfig;
using camera_firmware::settings::ApplyStatus;
using camera_firmware::settings::CameraProfileCatalog;
using camera_firmware::settings::RuntimeSettings;
using camera_firmware::settings::RuntimeSettingsDocument;
using camera_firmware::settings::RuntimeSettingsStore;
using camera_firmware::settings::internal::DecodeRuntimeSettingsDocument;
using camera_firmware::settings::internal::EncodeRuntimeSettingsDocument;

static_assert(std::is_nothrow_move_constructible_v<RuntimeSettingsDocument>);
static_assert(std::is_nothrow_move_assignable_v<RuntimeSettingsDocument>);
static_assert(noexcept(camera_firmware::common::Result<
                       RuntimeSettingsDocument>::Ok(
    std::declval<RuntimeSettingsDocument>())));
static_assert(noexcept(camera_firmware::common::Result<void>::Ok()));

constexpr std::string_view kSettingsName = "runtime-settings.json";
constexpr std::string_view kTemporaryPrefix = ".runtime-settings.json.tmp-";
constexpr std::string_view kRollbackName =
    ".runtime-settings.json.rollback";
constexpr std::string_view kPreviousName =
    ".runtime-settings.json.previous";

bool spoof_directory_owner{false};
bool spoof_file_owner{false};
bool spoof_temporary_special_mode{false};
int interrupted_writes{0};
std::size_t maximum_write_size{0U};
bool fail_write{false};
bool fail_fdatasync{false};
bool fail_renameat{false};
bool fail_fsync{false};
int fail_renameat_on_call{0};
int fail_unlinkat_on_call{0};
int fail_fsync_on_call{0};
int fail_fsync_from_call{0};
int settings_renameat_calls{0};
int settings_unlinkat_calls{0};
int settings_fsync_calls{0};
int settings_write_calls{0};

void ResetStoreHooks() {
  spoof_directory_owner = false;
  spoof_file_owner = false;
  spoof_temporary_special_mode = false;
  interrupted_writes = 0;
  maximum_write_size = 0U;
  fail_write = false;
  fail_fdatasync = false;
  fail_renameat = false;
  fail_fsync = false;
  fail_renameat_on_call = 0;
  fail_unlinkat_on_call = 0;
  fail_fsync_on_call = 0;
  fail_fsync_from_call = 0;
  settings_renameat_calls = 0;
  settings_unlinkat_calls = 0;
  settings_fsync_calls = 0;
  settings_write_calls = 0;
}

class StoreHooksScope {
 public:
  StoreHooksScope() { ResetStoreHooks(); }
  ~StoreHooksScope() { ResetStoreHooks(); }
};

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 48U> pattern{"/tmp/cf-runtime-settings-XXXXXX"};
    char* created = ::mkdtemp(pattern.data());
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

  [[nodiscard]] std::filesystem::path Path(std::string_view name) const {
    return path_ / name;
  }

 private:
  std::filesystem::path path_;
};

class ScopedUmask {
 public:
  explicit ScopedUmask(mode_t mode) : previous_(::umask(mode)) {}
  ~ScopedUmask() { ::umask(previous_); }

 private:
  mode_t previous_;
};

void MakeDirectory(const std::filesystem::path& path, mode_t mode = 0700) {
  if (::mkdir(path.c_str(), mode) != 0 || ::chmod(path.c_str(), mode) != 0) {
    throw std::system_error(errno, std::generic_category(), "mkdir");
  }
}

void WriteFile(const std::filesystem::path& path, std::string_view content,
               mode_t mode = 0600) {
  const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC |
                                                  O_NOFOLLOW | O_CLOEXEC,
                                mode);
  if (descriptor < 0 || ::fchmod(descriptor, mode) != 0) {
    const int error = errno;
    if (descriptor >= 0) {
      (void)::close(descriptor);
    }
    throw std::system_error(error, std::generic_category(), "open test file");
  }
  std::size_t offset = 0U;
  while (offset < content.size()) {
    const ssize_t written =
        ::write(descriptor, content.data() + offset, content.size() - offset);
    if (written <= 0) {
      const int error = errno;
      (void)::close(descriptor);
      throw std::system_error(error, std::generic_category(), "write test file");
    }
    offset += static_cast<std::size_t>(written);
  }
  if (::close(descriptor) != 0) {
    throw std::system_error(errno, std::generic_category(), "close test file");
  }
}

std::string ReadFile(const std::filesystem::path& path) {
  const int descriptor = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (descriptor < 0) {
    throw std::system_error(errno, std::generic_category(), "open test file");
  }
  std::string content;
  std::array<char, 4096U> buffer{};
  for (;;) {
    const ssize_t count = ::read(descriptor, buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      const int error = errno;
      (void)::close(descriptor);
      throw std::system_error(error, std::generic_category(), "read test file");
    }
    if (count == 0) {
      break;
    }
    content.append(buffer.data(), static_cast<std::size_t>(count));
  }
  if (::close(descriptor) != 0) {
    throw std::system_error(errno, std::generic_category(), "close test file");
  }
  return content;
}

mode_t FileMode(const std::filesystem::path& path) {
  struct stat status {};
  if (::lstat(path.c_str(), &status) != 0) {
    return 0;
  }
  return status.st_mode & 07777;
}

bool IsTemporaryDescriptor(int descriptor) {
  std::array<char, 64U> proc_path{};
  const int path_length =
      std::snprintf(proc_path.data(), proc_path.size(), "/proc/self/fd/%d",
                    descriptor);
  if (path_length <= 0 ||
      static_cast<std::size_t>(path_length) >= proc_path.size()) {
    return false;
  }
  std::array<char, 512U> target{};
  const ssize_t target_length =
      ::readlink(proc_path.data(), target.data(), target.size());
  if (target_length <= 0) {
    return false;
  }
  const std::string_view target_path(target.data(),
                                     static_cast<std::size_t>(target_length));
  const auto separator = target_path.find_last_of('/');
  const std::string_view name =
      separator == std::string_view::npos
          ? target_path
          : target_path.substr(separator + 1U);
  return name.starts_with(kTemporaryPrefix);
}

std::size_t TemporaryFileCount(const std::filesystem::path& state) {
  std::size_t count = 0U;
  for (const auto& entry : std::filesystem::directory_iterator(state)) {
    if (entry.path().filename().string().starts_with(kTemporaryPrefix)) {
      ++count;
    }
  }
  return count;
}

AiModelConfig MakeModel(std::string id, std::string hef_path,
                        std::string output_name, float threshold) {
  AiModelConfig model;
  model.id = std::move(id);
  model.kind = "object_detection";
  model.hef_path = std::move(hef_path);
  model.output_name = std::move(output_name);
  model.confidence_threshold = threshold;
  return model;
}

AppConfig MakeBaseConfig() {
  AppConfig base;
  base.secure_rtsp.enabled = false;
  base.security.enabled = false;
  base.ai.enabled = true;
  base.ai.backend = "hailo";
  base.ai.models = {
      MakeModel("objects", "/private/models/objects.hef", "objects/output",
                0.40F),
      MakeModel("pose", "/private/models/pose.hef", "pose/output", 0.35F),
  };
  base.camera.ai.enabled = true;
  base.camera.ai.model_ids = {"objects", "pose"};
  return base;
}

RuntimeSettings MakeBaseActive() {
  return {
      .camera = {"imx708-1080p50", 6000U, 25U},
      .sub_stream = {false, 640U, 360U, 15U, 1000U},
      .models = {{"objects", true, 0.40F}, {"pose", true, 0.35F}},
  };
}

RuntimeSettings MakePending() {
  return {
      .camera = {"imx708-1080p30", 8000U, 30U},
      .sub_stream = {false, 640U, 360U, 15U, 1000U},
      .models = {{"objects", true, 0.55F}, {"pose", false, 0.25F}},
  };
}

RuntimeSettingsDocument MakeDocument() {
  RuntimeSettingsDocument document;
  document.revision = 7U;
  document.active = MakeBaseActive();
  document.pending = MakePending();
  document.last_apply = {ApplyStatus::kFailed, "E_CAMERA_START", true};
  document.recovery_required = true;
  document.recovery_code = "E_RUNTIME_SETTINGS_DOCUMENT";
  return document;
}

const CameraProfileCatalog& Catalog() {
  static const CameraProfileCatalog catalog = CameraProfileCatalog::Rpi5Imx708();
  return catalog;
}

void ExpectSettingsEqual(const RuntimeSettings& actual,
                         const RuntimeSettings& expected) {
  EXPECT_EQ(actual.camera.profile_id, expected.camera.profile_id);
  EXPECT_EQ(actual.camera.bitrate_kbps, expected.camera.bitrate_kbps);
  EXPECT_EQ(actual.camera.gop, expected.camera.gop);
  EXPECT_EQ(actual.sub_stream.enabled, expected.sub_stream.enabled);
  EXPECT_EQ(actual.sub_stream.width, expected.sub_stream.width);
  EXPECT_EQ(actual.sub_stream.height, expected.sub_stream.height);
  EXPECT_EQ(actual.sub_stream.fps, expected.sub_stream.fps);
  EXPECT_EQ(actual.sub_stream.bitrate_kbps, expected.sub_stream.bitrate_kbps);
  ASSERT_EQ(actual.models.size(), expected.models.size());
  for (std::size_t index = 0; index < expected.models.size(); ++index) {
    EXPECT_EQ(actual.models[index].id, expected.models[index].id);
    EXPECT_EQ(actual.models[index].enabled, expected.models[index].enabled);
    EXPECT_FLOAT_EQ(actual.models[index].confidence_threshold,
                    expected.models[index].confidence_threshold);
  }
}

void ExpectDocumentsEqual(const RuntimeSettingsDocument& actual,
                          const RuntimeSettingsDocument& expected) {
  EXPECT_EQ(actual.revision, expected.revision);
  ExpectSettingsEqual(actual.active, expected.active);
  ASSERT_EQ(actual.pending.has_value(), expected.pending.has_value());
  if (expected.pending.has_value()) {
    ExpectSettingsEqual(*actual.pending, *expected.pending);
  }
  EXPECT_EQ(actual.last_apply.status, expected.last_apply.status);
  EXPECT_EQ(actual.last_apply.code, expected.last_apply.code);
  EXPECT_EQ(actual.last_apply.restored, expected.last_apply.restored);
  EXPECT_FALSE(actual.recovery_required);
  EXPECT_TRUE(actual.recovery_code.empty());
}

std::string ValidDocument(std::uint64_t revision = 7U,
                          bool include_pending = true,
                          std::string_view status = "failed",
                          std::string_view code = "E_CAMERA_START",
                          bool restored = true) {
  const std::string pending = include_pending
                                  ? R"json({"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30},"models":[{"id":"objects","enabled":true,"confidence_threshold":0.55},{"id":"pose","enabled":false,"confidence_threshold":0.25}]})json"
                                  : "null";
  return std::string(R"json({"schema_version":1,"revision":)json") +
         std::to_string(revision) + R"json(,"active":{"camera":{"profile_id":"imx708-1080p50","bitrate_kbps":6000,"gop":25},"models":[{"id":"objects","enabled":true,"confidence_threshold":0.4},{"id":"pose","enabled":true,"confidence_threshold":0.35}]},"pending":)json" +
         pending + R"json(,"last_apply":{"status":")json" +
         std::string(status) + R"json(","code":")json" + std::string(code) +
         R"json(","restored":)json" + (restored ? "true" : "false") + "}}";
}

std::string ReplaceOnce(std::string input, std::string_view from,
                        std::string_view to) {
  const auto position = input.find(from);
  if (position == std::string::npos) {
    throw std::runtime_error("test JSON marker was not found");
  }
  input.replace(position, from.size(), to);
  return input;
}

// ValidDocument() with a valid (disabled, base-geometry) sub_stream object
// inserted into the active settings, for tests that need to mutate the
// sub_stream shape itself.
std::string ValidDocumentWithActiveSubStream() {
  return ReplaceOnce(
      ValidDocument(), "\"gop\":25},\"models\":",
      "\"gop\":25},\"sub_stream\":{\"enabled\":false,\"width\":640,\"height\":360,\"fps\":15,\"bitrate_kbps\":1000},\"models\":");
}

void ExpectDecodeFailure(std::string_view document) {
  const auto decoded =
      DecodeRuntimeSettingsDocument(document, MakeBaseConfig(), Catalog());
  ASSERT_FALSE(decoded.ok());
  EXPECT_EQ(decoded.error().code, "E_RUNTIME_SETTINGS_DOCUMENT");
}

void ExpectSnapshotEqual(const RuntimeSettingsDocument& actual,
                         const RuntimeSettingsDocument& expected) {
  EXPECT_EQ(actual.revision, expected.revision);
  ExpectSettingsEqual(actual.active, expected.active);
  ASSERT_EQ(actual.pending.has_value(), expected.pending.has_value());
  if (expected.pending.has_value()) {
    ExpectSettingsEqual(*actual.pending, *expected.pending);
  }
  EXPECT_EQ(actual.last_apply.status, expected.last_apply.status);
  EXPECT_EQ(actual.last_apply.code, expected.last_apply.code);
  EXPECT_EQ(actual.last_apply.restored, expected.last_apply.restored);
  EXPECT_EQ(actual.recovery_required, expected.recovery_required);
  EXPECT_EQ(actual.recovery_code, expected.recovery_code);
}

std::unique_ptr<RuntimeSettingsStore> OpenStore(
    const std::filesystem::path& state) {
  auto opened = RuntimeSettingsStore::Open(state, MakeBaseActive(),
                                           MakeBaseConfig(), Catalog());
  if (!opened.ok()) {
    throw std::runtime_error(opened.error().code + ": " +
                             opened.error().message);
  }
  return std::move(opened).value();
}

void ExpectDurableFailureWithoutPublication(
    RuntimeSettingsStore& store, const std::filesystem::path& state,
    const RuntimeSettingsDocument& before) {
  const auto saved = store.SavePending(before.revision, MakePending());
  ASSERT_FALSE(saved.ok());
  EXPECT_EQ(saved.error().code, "E_RUNTIME_SETTINGS_STORE");
  ExpectSnapshotEqual(store.Snapshot(), before);
  EXPECT_EQ(TemporaryFileCount(state), 0U);
}

}  // namespace

extern "C" int __wrap_fstat(int descriptor, struct stat* status) {
  const int result = __real_fstat(descriptor, status);
  if (result == 0 &&
      ((spoof_directory_owner && S_ISDIR(status->st_mode)) ||
       (spoof_file_owner && S_ISREG(status->st_mode)))) {
    status->st_uid = ::geteuid() == 0 ? 1U : ::geteuid() + 1U;
  }
  if (result == 0 && spoof_temporary_special_mode &&
      S_ISREG(status->st_mode) && IsTemporaryDescriptor(descriptor)) {
    status->st_mode |= S_ISUID;
  }
  return result;
}

extern "C" ssize_t __wrap_camera_firmware_settings_write(
    int descriptor, const void* data, size_t size) {
  ++settings_write_calls;
  if (interrupted_writes > 0) {
    --interrupted_writes;
    errno = EINTR;
    return -1;
  }
  if (fail_write) {
    errno = EIO;
    return -1;
  }
  if (maximum_write_size != 0U && size > maximum_write_size) {
    size = maximum_write_size;
  }
  return __real_camera_firmware_settings_write(descriptor, data, size);
}

extern "C" int __wrap_camera_firmware_settings_fdatasync(int descriptor) {
  if (fail_fdatasync) {
    errno = EIO;
    return -1;
  }
  return __real_camera_firmware_settings_fdatasync(descriptor);
}

extern "C" int __wrap_camera_firmware_settings_renameat(
    int old_directory, const char* old_name, int new_directory,
    const char* new_name) {
  ++settings_renameat_calls;
  if (fail_renameat || settings_renameat_calls == fail_renameat_on_call) {
    errno = EIO;
    return -1;
  }
  return __real_camera_firmware_settings_renameat(
      old_directory, old_name, new_directory, new_name);
}

extern "C" int __wrap_camera_firmware_settings_unlinkat(
    int directory, const char* name, int flags) {
  ++settings_unlinkat_calls;
  if (settings_unlinkat_calls == fail_unlinkat_on_call) {
    errno = EIO;
    return -1;
  }
  return __real_camera_firmware_settings_unlinkat(directory, name, flags);
}

extern "C" int __wrap_camera_firmware_settings_fsync(int descriptor) {
  ++settings_fsync_calls;
  if (fail_fsync || settings_fsync_calls == fail_fsync_on_call ||
      (fail_fsync_from_call > 0 &&
       settings_fsync_calls >= fail_fsync_from_call)) {
    errno = EIO;
    return -1;
  }
  return __real_camera_firmware_settings_fsync(descriptor);
}

TEST(RuntimeSettingsStoreTest, DecodesVersionOneDocumentWithPendingSettings) {
  const auto decoded = DecodeRuntimeSettingsDocument(
      ValidDocument(), MakeBaseConfig(), Catalog());

  ASSERT_TRUE(decoded.ok()) << decoded.error().message;
  ExpectDocumentsEqual(decoded.value(), MakeDocument());
}

TEST(RuntimeSettingsStoreTest, DecodesNullPendingAndNeverApplyResult) {
  const auto decoded = DecodeRuntimeSettingsDocument(
      ValidDocument(0U, false, "never", "", false), MakeBaseConfig(),
      Catalog());

  ASSERT_TRUE(decoded.ok()) << decoded.error().message;
  EXPECT_EQ(decoded.value().revision, 0U);
  ExpectSettingsEqual(decoded.value().active, MakeBaseActive());
  EXPECT_FALSE(decoded.value().pending.has_value());
  EXPECT_EQ(decoded.value().last_apply.status, ApplyStatus::kNever);
  EXPECT_TRUE(decoded.value().last_apply.code.empty());
  EXPECT_FALSE(decoded.value().last_apply.restored);
}

TEST(RuntimeSettingsStoreTest,
     EncodesCanonicalCompactDocumentWithoutRecoveryOrUnmanagedData) {
  const auto encoded = EncodeRuntimeSettingsDocument(MakeDocument(),
                                                     MakeBaseConfig(), Catalog());

  ASSERT_TRUE(encoded.ok()) << encoded.error().message;
  EXPECT_EQ(
      encoded.value(),
      R"json({"schema_version":1,"revision":7,"active":{"camera":{"profile_id":"imx708-1080p50","bitrate_kbps":6000,"gop":25},"sub_stream":{"enabled":false,"width":640,"height":360,"fps":15,"bitrate_kbps":1000},"models":[{"id":"objects","enabled":true,"confidence_threshold":0.4},{"id":"pose","enabled":true,"confidence_threshold":0.35}]},"pending":{"camera":{"profile_id":"imx708-1080p30","bitrate_kbps":8000,"gop":30},"sub_stream":{"enabled":false,"width":640,"height":360,"fps":15,"bitrate_kbps":1000},"models":[{"id":"objects","enabled":true,"confidence_threshold":0.55},{"id":"pose","enabled":false,"confidence_threshold":0.25}]},"last_apply":{"status":"failed","code":"E_CAMERA_START","restored":true}})json");
  EXPECT_EQ(encoded.value().find("recovery_required"), std::string::npos);
  EXPECT_EQ(encoded.value().find("recovery_code"), std::string::npos);
  EXPECT_EQ(encoded.value().find("hef_path"), std::string::npos);
  EXPECT_EQ(encoded.value().find("output_name"), std::string::npos);
  EXPECT_EQ(encoded.value().find("/private/models"), std::string::npos);
}

TEST(RuntimeSettingsStoreTest, RoundTripsEnabledSubStream) {
  RuntimeSettingsDocument doc = MakeDocument();
  doc.active.sub_stream = {true, 1280U, 720U, 25U, 3000U};
  const auto encoded = EncodeRuntimeSettingsDocument(doc, MakeBaseConfig(), Catalog());
  ASSERT_TRUE(encoded.ok());
  const auto decoded = DecodeRuntimeSettingsDocument(encoded.value(), MakeBaseConfig(), Catalog());
  ASSERT_TRUE(decoded.ok());
  EXPECT_TRUE(decoded.value().active.sub_stream.enabled);
  EXPECT_EQ(decoded.value().active.sub_stream.width, 1280U);
  EXPECT_EQ(decoded.value().active.sub_stream.height, 720U);
  EXPECT_EQ(decoded.value().active.sub_stream.fps, 25U);
  EXPECT_EQ(decoded.value().active.sub_stream.bitrate_kbps, 3000U);
}

TEST(RuntimeSettingsStoreTest,
     LegacyDocumentWithoutSubStreamDecodesDisabledWithBaseGeometry) {
  const auto decoded = DecodeRuntimeSettingsDocument(ValidDocument(), MakeBaseConfig(), Catalog());
  ASSERT_TRUE(decoded.ok());
  const auto& sub = decoded.value().active.sub_stream;
  EXPECT_FALSE(sub.enabled);
  EXPECT_EQ(sub.width, 640U);       // from MakeBaseConfig().camera.sub_stream
  EXPECT_EQ(sub.height, 360U);
  EXPECT_EQ(sub.fps, 15U);
  EXPECT_EQ(sub.bitrate_kbps, 1000U);
}

TEST(RuntimeSettingsStoreTest, RejectsMalformedActiveSubStreamObject) {
  const std::string base = ValidDocumentWithActiveSubStream();
  // Sanity: the unmutated base document decodes successfully, so a failure
  // below is attributable to the mutation, not a malformed base fixture.
  const auto sanity = DecodeRuntimeSettingsDocument(base, MakeBaseConfig(), Catalog());
  ASSERT_TRUE(sanity.ok()) << sanity.error().message;

  // 1. non-bool `enabled`.
  ExpectDecodeFailure(ReplaceOnce(base, "\"enabled\":false,\"width\":640",
                                  "\"enabled\":1,\"width\":640"));
  ExpectDecodeFailure(ReplaceOnce(base, "\"enabled\":false,\"width\":640",
                                  "\"enabled\":\"false\",\"width\":640"));

  // 2. missing required key (drop "fps").
  ExpectDecodeFailure(ReplaceOnce(base, "\"fps\":15,", ""));

  // 3. extra/unknown key inside sub_stream (must be rejected by the inner
  // HasExactKeys, which requires exactly the five known keys).
  ExpectDecodeFailure(ReplaceOnce(base, "\"bitrate_kbps\":1000},\"models\":",
                                  "\"bitrate_kbps\":1000,\"foo\":0},\"models\":"));

  // 4. fractional / negative numeric field (must fail DecodeUnsigned).
  ExpectDecodeFailure(ReplaceOnce(base, "\"width\":640,", "\"width\":-1,"));
  ExpectDecodeFailure(ReplaceOnce(base, "\"width\":640,", "\"width\":640.5,"));
}

TEST(RuntimeSettingsStoreTest, RoundTripsMaximumUnsignedRevision) {
  const auto decoded = DecodeRuntimeSettingsDocument(
      ValidDocument(std::numeric_limits<std::uint64_t>::max()), MakeBaseConfig(),
      Catalog());

  ASSERT_TRUE(decoded.ok()) << decoded.error().message;
  EXPECT_EQ(decoded.value().revision, std::numeric_limits<std::uint64_t>::max());
}

TEST(RuntimeSettingsStoreTest, RejectsStrictSchemaAndSyntaxViolations) {
  std::vector<std::pair<std::string, std::string>> invalid_documents;
  invalid_documents.emplace_back(
      "duplicate key", ReplaceOnce(ValidDocument(), "\"schema_version\":1,",
                                   "\"schema_version\":1,\"schema_version\":1,"));
  invalid_documents.emplace_back(
      "root unknown key", ReplaceOnce(ValidDocument(), "\"revision\":7,",
                                       "\"revision\":7,\"unknown\":true,"));
  invalid_documents.emplace_back(
      "root missing key", ReplaceOnce(ValidDocument(), "\"revision\":7,", ""));
  invalid_documents.emplace_back(
      "active unknown key", ReplaceOnce(ValidDocument(), "\"camera\":{",
                                         "\"unknown\":true,\"camera\":{"));
  invalid_documents.emplace_back(
      "camera unknown key", ReplaceOnce(ValidDocument(), "\"profile_id\":",
                                         "\"unknown\":true,\"profile_id\":"));
  invalid_documents.emplace_back(
      "camera missing key", ReplaceOnce(ValidDocument(), ",\"gop\":25", ""));
  invalid_documents.emplace_back(
      "model unknown key", ReplaceOnce(ValidDocument(), "\"id\":\"objects\",",
                                        "\"id\":\"objects\",\"hef_path\":\"/secret.hef\","));
  invalid_documents.emplace_back(
      "last apply unknown key", ReplaceOnce(ValidDocument(), "\"status\":\"failed\",",
                                             "\"status\":\"failed\",\"extra\":true,"));
  invalid_documents.emplace_back(
      "pending wrong type", ReplaceOnce(ValidDocument(), "\"pending\":{",
                                          "\"pending\":\"invalid\",\"removed\":{"));
  invalid_documents.emplace_back("trailing data", ValidDocument() + " true");
  invalid_documents.emplace_back(
      "nonfinite", ReplaceOnce(ValidDocument(), "\"confidence_threshold\":0.55",
                                "\"confidence_threshold\":NaN"));
  invalid_documents.emplace_back(
      "floating revision", ReplaceOnce(ValidDocument(), "\"revision\":7",
                                        "\"revision\":7.0"));
  invalid_documents.emplace_back(
      "negative revision", ReplaceOnce(ValidDocument(), "\"revision\":7",
                                        "\"revision\":-1"));
  invalid_documents.emplace_back(
      "overflow revision", ReplaceOnce(ValidDocument(), "\"revision\":7",
                                        "\"revision\":18446744073709551616"));
  invalid_documents.emplace_back(
      "floating bitrate", ReplaceOnce(ValidDocument(), "\"bitrate_kbps\":8000",
                                       "\"bitrate_kbps\":8000.0"));
  invalid_documents.emplace_back(
      "unsupported schema", ReplaceOnce(ValidDocument(), "\"schema_version\":1",
                                          "\"schema_version\":2"));
  invalid_documents.emplace_back(
      "unknown status", ReplaceOnce(ValidDocument(), "\"status\":\"failed\"",
                                     "\"status\":\"unknown\""));
  invalid_documents.emplace_back(
      "never restored", ReplaceOnce(ValidDocument(), "\"status\":\"failed\"",
                                     "\"status\":\"never\""));
  invalid_documents.emplace_back(
      "success code", ReplaceOnce(ValidDocument(), "\"status\":\"failed\"",
                                    "\"status\":\"success\""));
  invalid_documents.emplace_back(
      "invalid managed settings", ReplaceOnce(ValidDocument(), "\"gop\":30",
                                               "\"gop\":301"));
  invalid_documents.emplace_back(
      "unknown active profile",
      ReplaceOnce(ValidDocument(), "imx708-1080p50", "unknown-profile"));
  invalid_documents.emplace_back(
      "unknown pending model",
      ReplaceOnce(ValidDocument(), "\"id\":\"pose\",\"enabled\":false",
                  "\"id\":\"unknown\",\"enabled\":false"));
  invalid_documents.emplace_back(
      "wrong model order", ReplaceOnce(ValidDocument(),
                                        "{\"id\":\"objects\",\"enabled\":true,\"confidence_threshold\":0.55},{\"id\":\"pose\",\"enabled\":false,\"confidence_threshold\":0.25}",
                                        "{\"id\":\"pose\",\"enabled\":false,\"confidence_threshold\":0.25},{\"id\":\"objects\",\"enabled\":true,\"confidence_threshold\":0.55}"));

  auto invalid_utf8 = ValidDocument();
  const auto utf8_marker = invalid_utf8.find("imx708-1080p50");
  ASSERT_NE(utf8_marker, std::string::npos);
  invalid_utf8[utf8_marker] = static_cast<char>(0xc0);
  invalid_documents.emplace_back("invalid UTF-8", std::move(invalid_utf8));
  invalid_documents.emplace_back("oversized", std::string(16U * 1024U + 1U, 'x'));

  for (const auto& [name, document] : invalid_documents) {
    SCOPED_TRACE(name);
    ExpectDecodeFailure(document);
  }
}

TEST(RuntimeSettingsStoreTest, RejectsInvalidDocumentStatesDuringEncoding) {
  auto invalid = MakeDocument();
  invalid.active.models[0].confidence_threshold =
      std::numeric_limits<float>::quiet_NaN();
  auto encoded = EncodeRuntimeSettingsDocument(invalid, MakeBaseConfig(), Catalog());
  ASSERT_FALSE(encoded.ok());
  EXPECT_EQ(encoded.error().code, "E_RUNTIME_SETTINGS_DOCUMENT");

  invalid = MakeDocument();
  invalid.last_apply = {ApplyStatus::kSuccess, "E_UNEXPECTED", false};
  encoded = EncodeRuntimeSettingsDocument(invalid, MakeBaseConfig(), Catalog());
  ASSERT_FALSE(encoded.ok());
  EXPECT_EQ(encoded.error().code, "E_RUNTIME_SETTINGS_DOCUMENT");
}

TEST(RuntimeSettingsStoreTest,
     MissingFileBootsBaseAtRevisionZeroWithoutCreatingDocument) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);

  auto store = OpenStore(state);

  RuntimeSettingsDocument expected;
  expected.active = MakeBaseActive();
  ExpectSnapshotEqual(store->Snapshot(), expected);
  EXPECT_FALSE(std::filesystem::exists(state / kSettingsName));
}

TEST(RuntimeSettingsStoreTest, LoadsValidActiveAndPendingDocument) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  WriteFile(state / kSettingsName, ValidDocument());

  auto store = OpenStore(state);

  auto expected = MakeDocument();
  expected.recovery_required = false;
  expected.recovery_code.clear();
  ExpectSnapshotEqual(store->Snapshot(), expected);
}

TEST(RuntimeSettingsStoreTest, LoadsValidDocumentWithoutPendingSettings) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  WriteFile(state / kSettingsName,
            ValidDocument(4U, false, "success", "", false));

  auto store = OpenStore(state);

  const auto snapshot = store->Snapshot();
  EXPECT_EQ(snapshot.revision, 4U);
  ExpectSettingsEqual(snapshot.active, MakeBaseActive());
  EXPECT_FALSE(snapshot.pending.has_value());
  EXPECT_EQ(snapshot.last_apply.status, ApplyStatus::kSuccess);
  EXPECT_FALSE(snapshot.recovery_required);
}

TEST(RuntimeSettingsStoreTest,
     InvalidDocumentIsRetainedAndExplicitSaveClearsRecovery) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  const auto settings_path = state / kSettingsName;
  MakeDirectory(state);
  const std::string invalid = "{invalid runtime settings bytes\n";
  WriteFile(settings_path, invalid);

  auto store = OpenStore(state);
  const auto recovery = store->Snapshot();
  EXPECT_EQ(recovery.revision, 0U);
  ExpectSettingsEqual(recovery.active, MakeBaseActive());
  EXPECT_FALSE(recovery.pending.has_value());
  EXPECT_EQ(recovery.last_apply.status, ApplyStatus::kNever);
  EXPECT_TRUE(recovery.recovery_required);
  EXPECT_EQ(recovery.recovery_code, "E_RUNTIME_SETTINGS_DOCUMENT");
  EXPECT_EQ(ReadFile(settings_path), invalid);

  const auto saved = store->SavePending(0U, MakePending());

  ASSERT_TRUE(saved.ok()) << saved.error().message;
  EXPECT_EQ(saved.value().revision, 1U);
  ASSERT_TRUE(saved.value().pending.has_value());
  ExpectSettingsEqual(*saved.value().pending, MakePending());
  EXPECT_FALSE(saved.value().recovery_required);
  EXPECT_TRUE(saved.value().recovery_code.empty());
  EXPECT_NE(ReadFile(settings_path), invalid);
  EXPECT_EQ(FileMode(settings_path), 0600);
}

TEST(RuntimeSettingsStoreTest,
     RecoveryRejectsNonSaveMutationsWithoutChangingMemoryOrDisk) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  const auto settings_path = state / kSettingsName;
  MakeDirectory(state);
  const std::string invalid = "retained invalid runtime settings\n";
  WriteFile(settings_path, invalid);
  auto store = OpenStore(state);
  const auto before = store->Snapshot();
  ASSERT_TRUE(before.recovery_required);

  const auto discarded = store->DiscardPending(0U);
  ASSERT_FALSE(discarded.ok());
  EXPECT_EQ(discarded.error().code,
            "E_RUNTIME_SETTINGS_RECOVERY_REQUIRED");
  const auto promoted = store->PromotePending(0U);
  ASSERT_FALSE(promoted.ok());
  EXPECT_EQ(promoted.error().code,
            "E_RUNTIME_SETTINGS_RECOVERY_REQUIRED");
  const auto recorded =
      store->RecordApplyFailure(0U, "E_CAMERA_START", true);
  EXPECT_FALSE(recorded.ok());
  if (!recorded.ok()) {
    EXPECT_EQ(recorded.error().code,
              "E_RUNTIME_SETTINGS_RECOVERY_REQUIRED");
  }

  ExpectSnapshotEqual(store->Snapshot(), before);
  EXPECT_EQ(ReadFile(settings_path), invalid);
  EXPECT_EQ(FileMode(settings_path), 0600);
}

TEST(RuntimeSettingsStoreTest,
     RejectsUnprotectedSymlinkedAndForeignOwnedStateDirectories) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto permissive = root.Path("permissive");
  MakeDirectory(permissive, 0750);
  auto opened = RuntimeSettingsStore::Open(
      permissive, MakeBaseActive(), MakeBaseConfig(), Catalog());
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_STATE_MODE");

  const auto target = root.Path("target");
  const auto symlink = root.Path("symlink");
  MakeDirectory(target);
  ASSERT_EQ(::symlink(target.c_str(), symlink.c_str()), 0);
  opened = RuntimeSettingsStore::Open(symlink, MakeBaseActive(),
                                      MakeBaseConfig(), Catalog());
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_PATH");

  const auto parent_target = root.Path("parent-target");
  const auto parent_link = root.Path("parent-link");
  MakeDirectory(parent_target);
  MakeDirectory(parent_target / "state");
  ASSERT_EQ(::symlink(parent_target.c_str(), parent_link.c_str()), 0);
  opened = RuntimeSettingsStore::Open(parent_link / "state", MakeBaseActive(),
                                      MakeBaseConfig(), Catalog());
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_PATH");

  spoof_directory_owner = true;
  opened = RuntimeSettingsStore::Open(target, MakeBaseActive(),
                                      MakeBaseConfig(), Catalog());
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_STATE_OWNER");
}

TEST(RuntimeSettingsStoreTest,
     RejectsOriginalDotAndDotDotComponentsWithoutLexicalRewrite) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  const auto symlink_target = root.Path("symlink-target");
  const auto symlink = root.Path("symlink");
  MakeDirectory(state);
  MakeDirectory(symlink_target);
  ASSERT_EQ(::symlink(symlink_target.c_str(), symlink.c_str()), 0);

  const std::vector<std::filesystem::path> rejected_paths = {
      root.Path("missing") / ".." / "state",
      symlink / ".." / "state",
      state / ".",
  };
  for (const auto& rejected_path : rejected_paths) {
    SCOPED_TRACE(rejected_path);
    const auto opened = RuntimeSettingsStore::Open(
        rejected_path, MakeBaseActive(), MakeBaseConfig(), Catalog());

    EXPECT_FALSE(opened.ok());
    if (!opened.ok()) {
      EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_PATH");
    }
  }
}

TEST(RuntimeSettingsStoreTest, RejectsSpecialPermissionBitsOnStateDirectory) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  for (const mode_t mode : {04700, 02700, 01700}) {
    SCOPED_TRACE(mode);
    const auto state = root.Path("state-" + std::to_string(mode));
    MakeDirectory(state, mode);
    ASSERT_EQ(FileMode(state), mode);

    const auto opened = RuntimeSettingsStore::Open(
        state, MakeBaseActive(), MakeBaseConfig(), Catalog());

    ASSERT_FALSE(opened.ok());
    EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_STATE_MODE");
  }
}

TEST(RuntimeSettingsStoreTest,
     RejectsSymlinkNonRegularWrongModeAndForeignOwnedDocuments) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  const auto settings_path = state / kSettingsName;
  MakeDirectory(state);

  const auto target = root.Path("target");
  WriteFile(target, ValidDocument());
  ASSERT_EQ(::symlink(target.c_str(), settings_path.c_str()), 0);
  auto opened = RuntimeSettingsStore::Open(
      state, MakeBaseActive(), MakeBaseConfig(), Catalog());
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_PATH");
  ASSERT_EQ(::unlink(settings_path.c_str()), 0);

  ASSERT_EQ(::mkdir(settings_path.c_str(), 0600), 0);
  opened = RuntimeSettingsStore::Open(state, MakeBaseActive(),
                                      MakeBaseConfig(), Catalog());
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_PATH");
  ASSERT_EQ(::rmdir(settings_path.c_str()), 0);

  WriteFile(settings_path, ValidDocument(), 0640);
  opened = RuntimeSettingsStore::Open(state, MakeBaseActive(),
                                      MakeBaseConfig(), Catalog());
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_FILE_MODE");
  ASSERT_EQ(::unlink(settings_path.c_str()), 0);

  WriteFile(settings_path, ValidDocument());
  spoof_file_owner = true;
  opened = RuntimeSettingsStore::Open(state, MakeBaseActive(),
                                      MakeBaseConfig(), Catalog());
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_FILE_OWNER");
}

TEST(RuntimeSettingsStoreTest, RejectsSpecialPermissionBitsOnSettingsDocument) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  const auto settings_path = state / kSettingsName;
  MakeDirectory(state);
  for (const mode_t mode : {04600, 02600, 01600}) {
    SCOPED_TRACE(mode);
    WriteFile(settings_path, ValidDocument());
    ASSERT_EQ(::chmod(settings_path.c_str(), mode), 0);
    ASSERT_EQ(FileMode(settings_path), mode);

    const auto opened = RuntimeSettingsStore::Open(
        state, MakeBaseActive(), MakeBaseConfig(), Catalog());

    ASSERT_FALSE(opened.ok());
    EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_FILE_MODE");
    ASSERT_EQ(::unlink(settings_path.c_str()), 0);
  }
}

TEST(RuntimeSettingsStoreTest, RejectsUnprotectedTransactionMarkers) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  const auto target = root.Path("target");
  MakeDirectory(state);
  WriteFile(target, ValidDocument());

  for (const auto name : {kRollbackName, kPreviousName}) {
    const auto marker = state / name;
    ASSERT_EQ(::symlink(target.c_str(), marker.c_str()), 0);
    auto opened = RuntimeSettingsStore::Open(
        state, MakeBaseActive(), MakeBaseConfig(), Catalog());
    ASSERT_FALSE(opened.ok());
    EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_PATH");
    ASSERT_EQ(::unlink(marker.c_str()), 0);

    WriteFile(marker, ValidDocument(), 0640);
    opened = RuntimeSettingsStore::Open(
        state, MakeBaseActive(), MakeBaseConfig(), Catalog());
    ASSERT_FALSE(opened.ok());
    EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_FILE_MODE");
    ASSERT_EQ(::unlink(marker.c_str()), 0);
  }

  WriteFile(state / kRollbackName, ValidDocument());
  spoof_file_owner = true;
  const auto opened = RuntimeSettingsStore::Open(
      state, MakeBaseActive(), MakeBaseConfig(), Catalog());
  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_RUNTIME_SETTINGS_FILE_OWNER");
}

TEST(RuntimeSettingsStoreTest,
     RejectsSpecialPermissionBitsOnTemporaryDocumentBeforeWrite) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto before = store->Snapshot();
  spoof_temporary_special_mode = true;

  const auto saved = store->SavePending(0U, MakePending());

  ASSERT_FALSE(saved.ok());
  EXPECT_EQ(saved.error().code, "E_RUNTIME_SETTINGS_STORE");
  ExpectSnapshotEqual(store->Snapshot(), before);
  EXPECT_EQ(TemporaryFileCount(state), 0U);
  EXPECT_FALSE(std::filesystem::exists(state / kSettingsName));
}

TEST(RuntimeSettingsStoreTest, DurableSaveRetriesInterruptedAndShortWrites) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);
  interrupted_writes = 2;
  maximum_write_size = 7U;

  const auto saved = store->SavePending(0U, MakePending());

  ASSERT_TRUE(saved.ok()) << saved.error().message;
  EXPECT_GT(settings_write_calls, 3);
  EXPECT_EQ(saved.value().revision, 1U);
  auto reopened = OpenStore(state);
  ExpectSnapshotEqual(reopened->Snapshot(), saved.value());
}

TEST(RuntimeSettingsStoreTest,
     DurableFailuresDoNotPublishAndCleanPreRenameTemporaryFiles) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto before = store->Snapshot();

  fail_write = true;
  ExpectDurableFailureWithoutPublication(*store, state, before);
  fail_write = false;

  fail_fdatasync = true;
  ExpectDurableFailureWithoutPublication(*store, state, before);
  fail_fdatasync = false;

  fail_renameat = true;
  ExpectDurableFailureWithoutPublication(*store, state, before);
  fail_renameat = false;

  fail_fsync_on_call = settings_fsync_calls + 1;
  ExpectDurableFailureWithoutPublication(*store, state, before);
}

TEST(RuntimeSettingsStoreTest,
     PostRenameSyncFailureRestoresMissingDocumentAcrossReopen) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  const auto settings_path = state / kSettingsName;
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto before = store->Snapshot();
  ASSERT_FALSE(std::filesystem::exists(settings_path));
  fail_fsync_on_call = 1;

  const auto saved = store->SavePending(before.revision, MakePending());

  ASSERT_FALSE(saved.ok());
  EXPECT_EQ(saved.error().code, "E_RUNTIME_SETTINGS_STORE");
  ExpectSnapshotEqual(store->Snapshot(), before);
  EXPECT_EQ(TemporaryFileCount(state), 0U);
  EXPECT_FALSE(std::filesystem::exists(settings_path));
  auto reopened = OpenStore(state);
  ExpectSnapshotEqual(reopened->Snapshot(), before);
}

TEST(RuntimeSettingsStoreTest,
     PostRenameSyncFailureRestoresExistingDocumentAcrossReopen) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  const auto settings_path = state / kSettingsName;
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto first = store->SavePending(0U, MakePending());
  ASSERT_TRUE(first.ok()) << first.error().message;
  const auto before = store->Snapshot();
  const auto document_before = ReadFile(settings_path);
  settings_fsync_calls = 0;
  fail_fsync_on_call = 2;

  const auto saved = store->SavePending(before.revision, MakeBaseActive());

  ASSERT_FALSE(saved.ok());
  EXPECT_EQ(saved.error().code, "E_RUNTIME_SETTINGS_STORE");
  ExpectSnapshotEqual(store->Snapshot(), before);
  EXPECT_EQ(TemporaryFileCount(state), 0U);
  EXPECT_EQ(ReadFile(settings_path), document_before);
  auto reopened = OpenStore(state);
  ExpectSnapshotEqual(reopened->Snapshot(), before);
}

TEST(RuntimeSettingsStoreTest,
     FailedExistingDocumentRollbackPoisonsFurtherMutations) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto first = store->SavePending(0U, MakePending());
  ASSERT_TRUE(first.ok()) << first.error().message;
  settings_fsync_calls = 0;
  settings_renameat_calls = 0;
  fail_fsync_on_call = 2;
  fail_renameat_on_call = 2;

  const auto saved = store->SavePending(1U, MakeBaseActive());

  ASSERT_FALSE(saved.ok());
  EXPECT_EQ(saved.error().code, "E_RUNTIME_SETTINGS_STORE");
  const auto poisoned = store->Snapshot();
  EXPECT_TRUE(poisoned.recovery_required);
  EXPECT_EQ(poisoned.recovery_code,
            "E_RUNTIME_SETTINGS_STORE_INDETERMINATE");
  const auto retried = store->SavePending(poisoned.revision, MakePending());
  ASSERT_FALSE(retried.ok());
  EXPECT_EQ(retried.error().code, "E_RUNTIME_SETTINGS_STORE");
}

TEST(RuntimeSettingsStoreTest,
     FailedPromotionRollbackRemainsRecoveryRequiredAcrossReopen) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto saved = store->SavePending(0U, MakePending());
  ASSERT_TRUE(saved.ok()) << saved.error().message;
  const auto before = store->Snapshot();
  settings_fsync_calls = 0;
  settings_renameat_calls = 0;
  fail_fsync_on_call = 2;
  fail_renameat_on_call = 2;

  const auto promoted = store->PromotePending(before.revision);

  ASSERT_FALSE(promoted.ok());
  EXPECT_EQ(promoted.error().code, "E_RUNTIME_SETTINGS_STORE");
  fail_fsync_on_call = 0;
  fail_renameat_on_call = 0;
  auto reopened = OpenStore(state);
  const auto recovered = reopened->Snapshot();
  EXPECT_TRUE(recovered.recovery_required);
  EXPECT_EQ(recovered.recovery_code,
            "E_RUNTIME_SETTINGS_STORE_INDETERMINATE");
  EXPECT_EQ(recovered.revision, before.revision);
  ExpectSettingsEqual(recovered.active, before.active);
  ASSERT_TRUE(recovered.pending.has_value());
  ExpectSettingsEqual(*recovered.pending, *before.pending);

  const auto repaired =
      reopened->SavePending(recovered.revision, *recovered.pending);
  ASSERT_TRUE(repaired.ok()) << repaired.error().message;
  EXPECT_FALSE(repaired.value().recovery_required);
  auto clean_reopen = OpenStore(state);
  ExpectSnapshotEqual(clean_reopen->Snapshot(), repaired.value());
  EXPECT_FALSE(std::filesystem::exists(state / kRollbackName));
}

TEST(RuntimeSettingsStoreTest,
     SuccessfulPromotionMarkerReopensCleanAndClearsOnNextMutation) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto saved = store->SavePending(0U, MakePending());
  ASSERT_TRUE(saved.ok()) << saved.error().message;

  const auto promoted = store->PromotePending(saved.value().revision);

  ASSERT_TRUE(promoted.ok()) << promoted.error().message;
  EXPECT_TRUE(std::filesystem::exists(state / kPreviousName));
  EXPECT_FALSE(std::filesystem::exists(state / kRollbackName));
  auto reopened = OpenStore(state);
  ExpectSnapshotEqual(reopened->Snapshot(), promoted.value());

  const auto saved_again =
      reopened->SavePending(promoted.value().revision, MakePending());
  ASSERT_TRUE(saved_again.ok()) << saved_again.error().message;
  EXPECT_FALSE(std::filesystem::exists(state / kPreviousName));
  EXPECT_FALSE(std::filesystem::exists(state / kRollbackName));
  auto final_reopen = OpenStore(state);
  ExpectSnapshotEqual(final_reopen->Snapshot(), saved_again.value());
}

TEST(RuntimeSettingsStoreTest,
     PromotionMarkerSyncFailureDurablyRestoresPreviousDocument) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto saved = store->SavePending(0U, MakePending());
  ASSERT_TRUE(saved.ok()) << saved.error().message;
  const auto before = store->Snapshot();
  settings_fsync_calls = 0;
  fail_fsync_on_call = 3;

  const auto promoted = store->PromotePending(before.revision);

  ASSERT_FALSE(promoted.ok());
  EXPECT_EQ(promoted.error().code, "E_RUNTIME_SETTINGS_STORE");
  ExpectSnapshotEqual(store->Snapshot(), before);
  EXPECT_FALSE(std::filesystem::exists(state / kRollbackName));
  EXPECT_TRUE(std::filesystem::exists(state / kPreviousName));
  fail_fsync_on_call = 0;
  auto reopened = OpenStore(state);
  ExpectSnapshotEqual(reopened->Snapshot(), before);
}

TEST(RuntimeSettingsStoreTest,
     PromotionCommitSyncAndRollbackFailureReopensPreviousRecovery) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto saved = store->SavePending(0U, MakePending());
  ASSERT_TRUE(saved.ok()) << saved.error().message;
  const auto before = store->Snapshot();
  settings_fsync_calls = 0;
  settings_renameat_calls = 0;
  fail_fsync_on_call = 3;
  fail_renameat_on_call = 2;

  const auto promoted = store->PromotePending(saved.value().revision);

  ASSERT_FALSE(promoted.ok());
  EXPECT_EQ(promoted.error().code, "E_RUNTIME_SETTINGS_STORE");
  EXPECT_GE(settings_fsync_calls, 4);
  EXPECT_TRUE(store->Snapshot().recovery_required);
  fail_fsync_on_call = 0;
  fail_renameat_on_call = 0;
  auto reopened = OpenStore(state);
  const auto recovered = reopened->Snapshot();
  EXPECT_TRUE(recovered.recovery_required);
  EXPECT_EQ(recovered.recovery_code,
            "E_RUNTIME_SETTINGS_STORE_INDETERMINATE");
  EXPECT_EQ(recovered.revision, before.revision);
  ExpectSettingsEqual(recovered.active, before.active);
  ASSERT_TRUE(recovered.pending.has_value());
  ExpectSettingsEqual(*recovered.pending, *before.pending);
}

TEST(RuntimeSettingsStoreTest,
     FailedMissingDocumentRollbackPoisonsFurtherMutations) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);
  fail_fsync_on_call = 1;
  fail_unlinkat_on_call = 1;

  const auto saved = store->SavePending(0U, MakePending());

  ASSERT_FALSE(saved.ok());
  EXPECT_EQ(saved.error().code, "E_RUNTIME_SETTINGS_STORE");
  const auto poisoned = store->Snapshot();
  EXPECT_TRUE(poisoned.recovery_required);
  EXPECT_EQ(poisoned.recovery_code,
            "E_RUNTIME_SETTINGS_STORE_INDETERMINATE");
}

TEST(RuntimeSettingsStoreTest,
     FailedRollbackSyncPoisonsFurtherMutations) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto first = store->SavePending(0U, MakePending());
  ASSERT_TRUE(first.ok()) << first.error().message;
  settings_fsync_calls = 0;
  fail_fsync_from_call = 2;

  const auto saved = store->SavePending(1U, MakeBaseActive());

  ASSERT_FALSE(saved.ok());
  EXPECT_EQ(saved.error().code, "E_RUNTIME_SETTINGS_STORE");
  const auto poisoned = store->Snapshot();
  EXPECT_TRUE(poisoned.recovery_required);
  EXPECT_EQ(poisoned.recovery_code,
            "E_RUNTIME_SETTINGS_STORE_INDETERMINATE");
}

TEST(RuntimeSettingsStoreTest, MutationsEnforceRevisionAndPendingSemantics) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);

  auto result = store->DiscardPending(0U);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_RUNTIME_SETTINGS_NO_PENDING");
  result = store->PromotePending(0U);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_RUNTIME_SETTINGS_NO_PENDING");

  result = store->SavePending(1U, MakePending());
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_RUNTIME_SETTINGS_REVISION");
  EXPECT_EQ(store->Snapshot().revision, 0U);

  const auto saved = store->SavePending(0U, MakePending());
  ASSERT_TRUE(saved.ok());
  EXPECT_EQ(saved.value().revision, 1U);
  result = store->DiscardPending(0U);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_RUNTIME_SETTINGS_REVISION");

  const auto discarded = store->DiscardPending(1U);
  ASSERT_TRUE(discarded.ok());
  EXPECT_EQ(discarded.value().revision, 2U);
  EXPECT_FALSE(discarded.value().pending.has_value());
  ExpectSettingsEqual(discarded.value().active, MakeBaseActive());

  const auto saved_again = store->SavePending(2U, MakePending());
  ASSERT_TRUE(saved_again.ok());
  const auto promoted = store->PromotePending(3U);
  ASSERT_TRUE(promoted.ok());
  EXPECT_EQ(promoted.value().revision, 4U);
  ExpectSettingsEqual(promoted.value().active, MakePending());
  EXPECT_FALSE(promoted.value().pending.has_value());
  EXPECT_EQ(promoted.value().last_apply.status, ApplyStatus::kSuccess);
  EXPECT_TRUE(promoted.value().last_apply.code.empty());
  EXPECT_FALSE(promoted.value().last_apply.restored);
}

TEST(RuntimeSettingsStoreTest,
     StaleRevisionRejectsEveryMutationWithoutChangingMemoryOrDisk) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  const auto settings_path = state / kSettingsName;
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto saved = store->SavePending(0U, MakePending());
  ASSERT_TRUE(saved.ok());
  const std::string durable_before = ReadFile(settings_path);

  auto save_stale = store->SavePending(0U, MakeBaseActive());
  ASSERT_FALSE(save_stale.ok());
  EXPECT_EQ(save_stale.error().code, "E_RUNTIME_SETTINGS_REVISION");
  auto discard_stale = store->DiscardPending(0U);
  ASSERT_FALSE(discard_stale.ok());
  EXPECT_EQ(discard_stale.error().code, "E_RUNTIME_SETTINGS_REVISION");
  auto promote_stale = store->PromotePending(0U);
  ASSERT_FALSE(promote_stale.ok());
  EXPECT_EQ(promote_stale.error().code, "E_RUNTIME_SETTINGS_REVISION");
  auto failure_stale =
      store->RecordApplyFailure(0U, "E_CAMERA_START", false);
  ASSERT_FALSE(failure_stale.ok());
  EXPECT_EQ(failure_stale.error().code, "E_RUNTIME_SETTINGS_REVISION");

  ExpectSnapshotEqual(store->Snapshot(), saved.value());
  EXPECT_EQ(ReadFile(settings_path), durable_before);
}

TEST(RuntimeSettingsStoreTest,
     ApplyFailureRecordingPreservesPendingAndPersistsResult) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);
  ASSERT_TRUE(store->SavePending(0U, MakePending()).ok());

  const auto failed =
      store->RecordApplyFailure(1U, "E_CAMERA_START", true);

  ASSERT_TRUE(failed.ok()) << failed.error().message;
  EXPECT_EQ(failed.value().revision, 2U);
  ASSERT_TRUE(failed.value().pending.has_value());
  ExpectSettingsEqual(*failed.value().pending, MakePending());
  EXPECT_EQ(failed.value().last_apply.status, ApplyStatus::kFailed);
  EXPECT_EQ(failed.value().last_apply.code, "E_CAMERA_START");
  EXPECT_TRUE(failed.value().last_apply.restored);
  auto reopened = OpenStore(state);
  ExpectSnapshotEqual(reopened->Snapshot(), failed.value());
}

TEST(RuntimeSettingsStoreTest, RevisionOverflowRejectsEveryMutation) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  WriteFile(state / kSettingsName,
            ValidDocument(std::numeric_limits<std::uint64_t>::max()));
  auto store = OpenStore(state);
  const auto before = store->Snapshot();

  auto saved = store->SavePending(before.revision, MakePending());
  ASSERT_FALSE(saved.ok());
  EXPECT_EQ(saved.error().code, "E_RUNTIME_SETTINGS_REVISION_OVERFLOW");
  auto discarded = store->DiscardPending(before.revision);
  ASSERT_FALSE(discarded.ok());
  EXPECT_EQ(discarded.error().code, "E_RUNTIME_SETTINGS_REVISION_OVERFLOW");
  auto promoted = store->PromotePending(before.revision);
  ASSERT_FALSE(promoted.ok());
  EXPECT_EQ(promoted.error().code, "E_RUNTIME_SETTINGS_REVISION_OVERFLOW");
  auto failed =
      store->RecordApplyFailure(before.revision, "E_CAMERA_START", false);
  ASSERT_FALSE(failed.ok());
  EXPECT_EQ(failed.error().code, "E_RUNTIME_SETTINGS_REVISION_OVERFLOW");
  ExpectSnapshotEqual(store->Snapshot(), before);
}

TEST(RuntimeSettingsStoreTest, DetectsStateDirectoryPathInodeSubstitution) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  const auto displaced = root.Path("displaced");
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto before = store->Snapshot();
  ASSERT_EQ(::rename(state.c_str(), displaced.c_str()), 0);
  MakeDirectory(state);

  const auto saved = store->SavePending(0U, MakePending());

  ASSERT_FALSE(saved.ok());
  EXPECT_EQ(saved.error().code, "E_RUNTIME_SETTINGS_STORE");
  ExpectSnapshotEqual(store->Snapshot(), before);
  EXPECT_FALSE(std::filesystem::exists(state / kSettingsName));
  EXPECT_FALSE(std::filesystem::exists(displaced / kSettingsName));
}

TEST(RuntimeSettingsStoreTest,
     DetectsAncestorSubstitutionThatPreservesFinalDirectoryInode) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto parent = root.Path("parent");
  const auto displaced_parent = root.Path("displaced-parent");
  const auto state = parent / "state";
  MakeDirectory(parent);
  MakeDirectory(state);
  auto store = OpenStore(state);
  const auto before = store->Snapshot();

  ASSERT_EQ(::rename(parent.c_str(), displaced_parent.c_str()), 0);
  MakeDirectory(parent);
  ASSERT_EQ(::rename((displaced_parent / "state").c_str(), state.c_str()), 0);

  const auto saved = store->SavePending(0U, MakePending());

  ASSERT_FALSE(saved.ok());
  EXPECT_EQ(saved.error().code, "E_RUNTIME_SETTINGS_STORE");
  ExpectSnapshotEqual(store->Snapshot(), before);
  EXPECT_FALSE(std::filesystem::exists(state / kSettingsName));
  EXPECT_EQ(TemporaryFileCount(state), 0U);
}

TEST(RuntimeSettingsStoreTest, RestrictiveUmaskStillCreatesExactModeDocument) {
  StoreHooksScope hooks;
  TemporaryDirectory root;
  const auto state = root.Path("state");
  MakeDirectory(state);
  auto store = OpenStore(state);

  camera_firmware::common::Result<RuntimeSettingsDocument> saved = [&] {
    ScopedUmask umask(0777);
    return store->SavePending(0U, MakePending());
  }();

  ASSERT_TRUE(saved.ok()) << saved.error().message;
  EXPECT_EQ(FileMode(state / kSettingsName), 0600);
  EXPECT_EQ(FileMode(state), 0700);
}
