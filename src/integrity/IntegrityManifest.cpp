#include "camera_firmware/integrity/IntegrityManifest.hpp"

#if defined(CAMERA_FIRMWARE_INTEGRITY_TESTING)
#include "IntegrityManifestTestAccess.hpp"
#endif

#include <cctype>
#include <cstddef>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include <yaml-cpp/eventhandler.h>
#include <yaml-cpp/parser.h>
#include <yaml-cpp/yaml.h>

namespace camera_firmware::integrity {
namespace {

constexpr std::size_t kMaximumManifestBytes = std::size_t{1024} * 1024U;
constexpr std::size_t kMaximumPathBytes = 4096U;
constexpr std::size_t kMaximumYamlDepth = 16U;
constexpr std::size_t kMaximumYamlEvents =
    kMaximumIntegrityManifestEntries * 10U + 16U;

struct RestrictedYamlRejected {};

class RestrictedYamlEventHandler final : public YAML::EventHandler {
 public:
  explicit RestrictedYamlEventHandler(std::string_view source)
      : source_(source) {}

  void OnDocumentStart(const YAML::Mark&) override {
    CountEvent();
    if (++document_count_ != 1U) {
      throw RestrictedYamlRejected{};
    }
  }

  void OnDocumentEnd() override { CountEvent(); }

  void OnNull(const YAML::Mark& mark, YAML::anchor_t anchor) override {
    CountEvent();
    RejectAnchor(anchor);
    if (MarkPointsToBang(mark)) {
      throw RestrictedYamlRejected{};
    }
  }

  void OnAlias(const YAML::Mark&, YAML::anchor_t) override {
    throw RestrictedYamlRejected{};
  }

  void OnScalar(const YAML::Mark& mark, const std::string& tag,
                YAML::anchor_t anchor, const std::string&) override {
    CountEvent();
    RejectTagOrAnchor(mark, tag, anchor);
  }

  void OnSequenceStart(const YAML::Mark& mark, const std::string& tag,
                       YAML::anchor_t anchor,
                       YAML::EmitterStyle::value) override {
    CountEvent();
    RejectTagOrAnchor(mark, tag, anchor);
    EnterContainer();
  }

  void OnSequenceEnd() override {
    CountEvent();
    LeaveContainer();
  }

  void OnMapStart(const YAML::Mark& mark, const std::string& tag,
                  YAML::anchor_t anchor,
                  YAML::EmitterStyle::value) override {
    CountEvent();
    RejectTagOrAnchor(mark, tag, anchor);
    EnterContainer();
  }

  void OnMapEnd() override {
    CountEvent();
    LeaveContainer();
  }

  void OnAnchor(const YAML::Mark&, const std::string&) override {
    throw RestrictedYamlRejected{};
  }

 private:
  void CountEvent() {
    if (++event_count_ > kMaximumYamlEvents) {
      throw RestrictedYamlRejected{};
    }
  }

  void EnterContainer() {
    if (++depth_ > kMaximumYamlDepth) {
      throw RestrictedYamlRejected{};
    }
  }

  void LeaveContainer() {
    if (depth_ == 0U) {
      throw RestrictedYamlRejected{};
    }
    --depth_;
  }

  static void RejectAnchor(YAML::anchor_t anchor) {
    if (anchor != YAML::NullAnchor) {
      throw RestrictedYamlRejected{};
    }
  }

  void RejectTagOrAnchor(const YAML::Mark& mark, const std::string& tag,
                         YAML::anchor_t anchor) const {
    RejectAnchor(anchor);
    if (!tag.empty() && tag != "?" && tag != "!") {
      throw RestrictedYamlRejected{};
    }
    if (tag == "!" &&
        (mark.is_null() || mark.pos < 0 ||
         static_cast<std::size_t>(mark.pos) >= source_.size() ||
         MarkPointsToBang(mark))) {
      throw RestrictedYamlRejected{};
    }
  }

  [[nodiscard]] bool MarkPointsToBang(const YAML::Mark& mark) const noexcept {
    return !mark.is_null() && mark.pos >= 0 &&
           static_cast<std::size_t>(mark.pos) < source_.size() &&
           source_[static_cast<std::size_t>(mark.pos)] == '!';
  }

  std::string_view source_;
  std::size_t document_count_{0U};
  std::size_t event_count_{0U};
  std::size_t depth_{0U};
};

common::Error ManifestFormatError() {
  return {"E_INTEGRITY_MANIFEST_FORMAT", "Integrity manifest has invalid format"};
}

bool IsAllowedIdCharacter(unsigned char value) {
  return std::isalnum(value) != 0 || value == '-' || value == '_' ||
         value == '.';
}

bool IsValidId(std::string_view value) {
  if (value.empty() || value.size() > kMaximumIntegrityIdBytes) {
    return false;
  }
  for (const unsigned char character : value) {
    if (character > 0x7fU || !IsAllowedIdCharacter(character)) {
      return false;
    }
  }
  return true;
}

bool IsLeapYear(unsigned int year) {
  return year % 4U == 0U && (year % 100U != 0U || year % 400U == 0U);
}

unsigned int DaysInMonth(unsigned int year, unsigned int month) {
  constexpr unsigned int kDays[] = {31U, 28U, 31U, 30U, 31U, 30U,
                                    31U, 31U, 30U, 31U, 30U, 31U};
  if (month == 2U && IsLeapYear(year)) {
    return 29U;
  }
  return kDays[month - 1U];
}

bool IsDigitAt(std::string_view value, std::size_t offset) {
  return offset < value.size() && value[offset] >= '0' && value[offset] <= '9';
}

unsigned int ParseDigits(std::string_view value, std::size_t offset,
                         std::size_t count) {
  unsigned int parsed = 0U;
  for (std::size_t index = 0U; index < count; ++index) {
    parsed = parsed * 10U + static_cast<unsigned int>(value[offset + index] - '0');
  }
  return parsed;
}

bool IsRfc3339Utc(std::string_view value) {
  if (value.size() < 20U || value[4] != '-' || value[7] != '-' ||
      value[10] != 'T' || value[13] != ':' || value[16] != ':') {
    return false;
  }
  for (const std::size_t index : {0U, 1U, 2U, 3U, 5U, 6U, 8U, 9U, 11U,
                                  12U, 14U, 15U, 17U, 18U}) {
    if (!IsDigitAt(value, index)) {
      return false;
    }
  }
  std::size_t suffix = 19U;
  if (value[suffix] == '.') {
    ++suffix;
    const std::size_t fraction_start = suffix;
    while (suffix < value.size() && value[suffix] >= '0' && value[suffix] <= '9') {
      ++suffix;
    }
    if (suffix == fraction_start) {
      return false;
    }
  }
  if (suffix + 1U != value.size() || value[suffix] != 'Z') {
    return false;
  }

  const unsigned int year = ParseDigits(value, 0U, 4U);
  const unsigned int month = ParseDigits(value, 5U, 2U);
  const unsigned int day = ParseDigits(value, 8U, 2U);
  const unsigned int hour = ParseDigits(value, 11U, 2U);
  const unsigned int minute = ParseDigits(value, 14U, 2U);
  const unsigned int second = ParseDigits(value, 17U, 2U);
  return year != 0U && month >= 1U && month <= 12U && day >= 1U &&
         day <= DaysInMonth(year, month) && hour <= 23U && minute <= 59U &&
         second <= 59U;
}

bool IsAbsoluteNormalizedPath(const std::filesystem::path& path) {
  const auto& native = path.native();
  return !path.empty() && native.size() <= kMaximumPathBytes &&
         native.find('\0') == std::string::npos && path.is_absolute() &&
         path.native() == path.lexically_normal().native();
}

bool PassesRestrictedYamlPreflight(std::string_view yaml) {
  std::istringstream input{std::string(yaml)};
  YAML::Parser parser(input);
  RestrictedYamlEventHandler handler(yaml);
  if (!parser.HandleNextDocument(handler)) {
    return false;
  }
  return !parser.HandleNextDocument(handler);
}

bool HasExactKeys(const YAML::Node& node,
                  std::initializer_list<std::string_view> allowed) {
  if (!node.IsMap() || node.size() != allowed.size()) {
    return false;
  }
  std::set<std::string> keys;
  for (const auto& item : node) {
    if (!item.first.IsScalar()) {
      return false;
    }
    const std::string key = item.first.as<std::string>();
    bool is_allowed = false;
    for (const std::string_view candidate : allowed) {
      if (key == candidate) {
        is_allowed = true;
        break;
      }
    }
    if (!is_allowed || !keys.insert(key).second) {
      return false;
    }
  }
  return true;
}

common::Result<std::string> RequiredScalar(const YAML::Node& node,
                                            std::string_view key) {
  const YAML::Node value = node[std::string(key)];
  if (!value || !value.IsScalar()) {
    return common::Result<std::string>::Err(ManifestFormatError());
  }
  return common::Result<std::string>::Ok(value.as<std::string>());
}

}  // namespace

std::string_view IntegrityCategoryName(IntegrityCategory category) noexcept {
  switch (category) {
    case IntegrityCategory::kFirmware:
      return "firmware";
    case IntegrityCategory::kLibrary:
      return "library";
    case IntegrityCategory::kConfiguration:
      return "configuration";
    case IntegrityCategory::kWebAsset:
      return "web_asset";
    case IntegrityCategory::kKernel:
      return "kernel";
    case IntegrityCategory::kKernelModule:
      return "kernel_module";
  }
  return "unknown";
}

common::Result<IntegrityCategory> ParseIntegrityCategory(std::string_view value) {
  if (value == "firmware") {
    return common::Result<IntegrityCategory>::Ok(IntegrityCategory::kFirmware);
  }
  if (value == "library") {
    return common::Result<IntegrityCategory>::Ok(IntegrityCategory::kLibrary);
  }
  if (value == "configuration") {
    return common::Result<IntegrityCategory>::Ok(IntegrityCategory::kConfiguration);
  }
  if (value == "web_asset") {
    return common::Result<IntegrityCategory>::Ok(IntegrityCategory::kWebAsset);
  }
  if (value == "kernel") {
    return common::Result<IntegrityCategory>::Ok(IntegrityCategory::kKernel);
  }
  if (value == "kernel_module") {
    return common::Result<IntegrityCategory>::Ok(IntegrityCategory::kKernelModule);
  }
  return common::Result<IntegrityCategory>::Err(ManifestFormatError());
}

common::Result<IntegrityManifest> ParseIntegrityManifest(std::string_view yaml) {
  if (yaml.size() > kMaximumManifestBytes) {
    return common::Result<IntegrityManifest>::Err(ManifestFormatError());
  }
  try {
    if (!PassesRestrictedYamlPreflight(yaml)) {
      return common::Result<IntegrityManifest>::Err(ManifestFormatError());
    }
    const YAML::Node root = YAML::Load(std::string(yaml));
    if (!HasExactKeys(root, {"schema_version", "product", "created_at", "files"})) {
      return common::Result<IntegrityManifest>::Err(ManifestFormatError());
    }

    const auto schema = RequiredScalar(root, "schema_version");
    const auto product = RequiredScalar(root, "product");
    const auto created_at = RequiredScalar(root, "created_at");
    const YAML::Node files = root["files"];
    if (!schema.ok() || !product.ok() || !created_at.ok() || !files.IsSequence() ||
        files.size() == 0U ||
        files.size() > kMaximumIntegrityManifestEntries) {
      return common::Result<IntegrityManifest>::Err(ManifestFormatError());
    }
    if (schema.value() != "1" || product.value() != "camera-firmware" ||
        !IsRfc3339Utc(created_at.value())) {
      return common::Result<IntegrityManifest>::Err(ManifestFormatError());
    }

    IntegrityManifest manifest;
    manifest.product = product.value();
    manifest.created_at = created_at.value();
    manifest.files.reserve(files.size());
    std::set<std::string> ids;
    std::set<std::filesystem::path> paths;
    for (const YAML::Node& file : files) {
      if (!HasExactKeys(file, {"id", "category", "path", "sha256"})) {
        return common::Result<IntegrityManifest>::Err(ManifestFormatError());
      }
      const auto id = RequiredScalar(file, "id");
      const auto category = RequiredScalar(file, "category");
      const auto path_text = RequiredScalar(file, "path");
      const auto hash = RequiredScalar(file, "sha256");
      if (!id.ok() || !category.ok() || !path_text.ok() || !hash.ok() ||
          !IsValidId(id.value())) {
        return common::Result<IntegrityManifest>::Err(ManifestFormatError());
      }
      const auto parsed_category = ParseIntegrityCategory(category.value());
      const auto parsed_hash = ParseSha256(hash.value());
      const std::filesystem::path path(path_text.value());
      if (!parsed_category.ok() || !parsed_hash.ok() ||
          !IsAbsoluteNormalizedPath(path) || path_text.value().find('\0') != std::string::npos ||
          !ids.insert(id.value()).second || !paths.insert(path).second) {
        return common::Result<IntegrityManifest>::Err(ManifestFormatError());
      }
      manifest.files.push_back(
          {id.value(), parsed_category.value(), path, parsed_hash.value()});
    }
    return common::Result<IntegrityManifest>::Ok(std::move(manifest));
  } catch (const RestrictedYamlRejected&) {
    return common::Result<IntegrityManifest>::Err(ManifestFormatError());
  } catch (const YAML::Exception&) {
    return common::Result<IntegrityManifest>::Err(ManifestFormatError());
  } catch (const std::exception&) {
    return common::Result<IntegrityManifest>::Err(ManifestFormatError());
  }
}

#if defined(CAMERA_FIRMWARE_INTEGRITY_TESTING)

namespace testing {

bool RestrictedYamlPreflightAcceptsForTest(std::string_view yaml) {
  if (yaml.size() > kMaximumManifestBytes) {
    return false;
  }
  try {
    return PassesRestrictedYamlPreflight(yaml);
  } catch (const RestrictedYamlRejected&) {
    return false;
  } catch (const YAML::Exception&) {
    return false;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace testing

#endif

}  // namespace camera_firmware::integrity
