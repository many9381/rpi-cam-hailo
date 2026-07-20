#include "camera_firmware/integrity/IntegritySigner.hpp"

#include <array>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "camera_firmware/integrity/IntegrityManifest.hpp"
#include "camera_firmware/integrity/SafeFileDigest.hpp"

namespace {

using camera_firmware::common::Error;
using camera_firmware::common::Result;
using camera_firmware::integrity::DigestRegularFile;
using camera_firmware::integrity::IntegrityCategory;
using camera_firmware::integrity::IntegrityEntry;
using camera_firmware::integrity::IntegrityManifest;
using camera_firmware::integrity::kMaximumIntegrityManifestEntries;
using camera_firmware::integrity::ParseIntegrityCategory;
using camera_firmware::integrity::ReadIntegrityManifestForSigning;
using camera_firmware::integrity::SerializeIntegrityManifest;
using camera_firmware::integrity::SignIntegrityManifest;
using camera_firmware::integrity::WriteIntegrityArtifactAtomically;

constexpr std::size_t kMaximumPathBytes = 4096U;

const Error kUsageError{"E_INTEGRITY_TOOL_USAGE", "Invalid integrity tool arguments"};
const Error kEntryError{"E_INTEGRITY_TOOL_ENTRY", "Invalid integrity tool entry"};
const Error kCreateError{"E_INTEGRITY_TOOL_CREATE", "Unable to create integrity manifest"};
const Error kSignError{"E_INTEGRITY_TOOL_SIGN", "Unable to sign integrity manifest"};

struct CreateOptions {
  std::filesystem::path output;
  std::vector<IntegrityEntry> entries;
};

struct SignOptions {
  std::filesystem::path manifest;
  std::filesystem::path private_key;
  std::filesystem::path output;
};

bool IsAbsoluteNormalizedPath(const std::filesystem::path& path) {
  const auto& native = path.native();
  return !path.empty() && native.size() <= kMaximumPathBytes &&
         native.find('\0') == std::string::npos && path.is_absolute() &&
         native == path.lexically_normal().native();
}

bool IsValidId(std::string_view value) {
  if (value.empty() ||
      value.size() >
          camera_firmware::integrity::kMaximumIntegrityIdBytes) {
    return false;
  }
  for (const unsigned char character : value) {
    if (!((character >= 'a' && character <= 'z') ||
          (character >= 'A' && character <= 'Z') ||
          (character >= '0' && character <= '9') || character == '-' ||
          character == '_' || character == '.')) {
      return false;
    }
  }
  return true;
}

Result<IntegrityEntry> ParseEntry(std::string_view value) {
  const std::size_t first = value.find(':');
  if (first == std::string_view::npos) {
    return Result<IntegrityEntry>::ErrFromStaticLifetime(kEntryError);
  }
  const std::size_t second = value.find(':', first + 1U);
  if (second == std::string_view::npos) {
    return Result<IntegrityEntry>::ErrFromStaticLifetime(kEntryError);
  }
  const auto category = ParseIntegrityCategory(value.substr(0U, first));
  const std::string_view id = value.substr(first + 1U, second - first - 1U);
  const std::filesystem::path path(value.substr(second + 1U));
  if (!category.ok() || !IsValidId(id) || !IsAbsoluteNormalizedPath(path)) {
    return Result<IntegrityEntry>::ErrFromStaticLifetime(kEntryError);
  }
  return Result<IntegrityEntry>::Ok(
      {std::string(id), category.value(), path, {}});
}

Result<CreateOptions> ParseCreateOptions(int argc, char** argv) {
  CreateOptions options;
  bool has_output = false;
  std::set<std::string> ids;
  std::set<std::filesystem::path> paths;
  for (int index = 2; index < argc; ++index) {
    const std::string_view option(argv[index]);
    if ((option != "--output" && option != "--entry") || index + 1 >= argc) {
      return Result<CreateOptions>::ErrFromStaticLifetime(kUsageError);
    }
    const std::string_view value(argv[++index]);
    if (value.empty() || value.starts_with("--")) {
      return Result<CreateOptions>::ErrFromStaticLifetime(kUsageError);
    }
    if (option == "--output") {
      if (has_output) {
        return Result<CreateOptions>::ErrFromStaticLifetime(kUsageError);
      }
      options.output = std::filesystem::path(value);
      has_output = true;
      continue;
    }
    if (options.entries.size() >= kMaximumIntegrityManifestEntries) {
      return Result<CreateOptions>::ErrFromStaticLifetime(kUsageError);
    }
    const auto entry = ParseEntry(value);
    if (!entry.ok()) {
      return Result<CreateOptions>::Err(entry.error());
    }
    if (!ids.insert(entry.value().id).second ||
        !paths.insert(entry.value().path).second) {
      return Result<CreateOptions>::ErrFromStaticLifetime(kEntryError);
    }
    options.entries.push_back(entry.value());
  }
  if (!has_output || options.entries.empty() || !IsAbsoluteNormalizedPath(options.output)) {
    return Result<CreateOptions>::ErrFromStaticLifetime(kUsageError);
  }
  return Result<CreateOptions>::Ok(std::move(options));
}

Result<SignOptions> ParseSignOptions(int argc, char** argv) {
  SignOptions options;
  bool has_manifest = false;
  bool has_private_key = false;
  bool has_output = false;
  for (int index = 2; index < argc; ++index) {
    const std::string_view option(argv[index]);
    if ((option != "--manifest" && option != "--private-key" && option != "--output") ||
        index + 1 >= argc) {
      return Result<SignOptions>::ErrFromStaticLifetime(kUsageError);
    }
    const std::string_view value(argv[++index]);
    if (value.empty() || value.starts_with("--")) {
      return Result<SignOptions>::ErrFromStaticLifetime(kUsageError);
    }
    if (option == "--manifest") {
      if (has_manifest) {
        return Result<SignOptions>::ErrFromStaticLifetime(kUsageError);
      }
      options.manifest = std::filesystem::path(value);
      has_manifest = true;
    } else if (option == "--private-key") {
      if (has_private_key) {
        return Result<SignOptions>::ErrFromStaticLifetime(kUsageError);
      }
      options.private_key = std::filesystem::path(value);
      has_private_key = true;
    } else {
      if (has_output) {
        return Result<SignOptions>::ErrFromStaticLifetime(kUsageError);
      }
      options.output = std::filesystem::path(value);
      has_output = true;
    }
  }
  if (!has_manifest || !has_private_key || !has_output ||
      !IsAbsoluteNormalizedPath(options.manifest) ||
      !IsAbsoluteNormalizedPath(options.private_key) ||
      !IsAbsoluteNormalizedPath(options.output)) {
    return Result<SignOptions>::ErrFromStaticLifetime(kUsageError);
  }
  return Result<SignOptions>::Ok(std::move(options));
}

Result<std::string> UtcTimestamp() {
  const std::time_t now = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now());
  std::tm utc {};
  if (::gmtime_r(&now, &utc) == nullptr) {
    return Result<std::string>::ErrFromStaticLifetime(kCreateError);
  }
  std::array<char, 21U> output{};
  if (std::strftime(output.data(), output.size(), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0U) {
    return Result<std::string>::ErrFromStaticLifetime(kCreateError);
  }
  return Result<std::string>::Ok(output.data());
}

Result<void> CreateManifest(CreateOptions options) {
  for (IntegrityEntry& entry : options.entries) {
    const auto digest = DigestRegularFile(entry.path);
    if (!digest.ok()) {
      return Result<void>::ErrFromStaticLifetime(kCreateError);
    }
    entry.expected_sha256 = digest.value();
  }
  std::sort(options.entries.begin(), options.entries.end(),
            [](const IntegrityEntry& left, const IntegrityEntry& right) {
              return left.id < right.id;
            });
  const auto timestamp = UtcTimestamp();
  if (!timestamp.ok()) {
    return Result<void>::Err(timestamp.error());
  }
  IntegrityManifest manifest{1U, "camera-firmware", timestamp.value(),
                             std::move(options.entries)};
  const auto serialized = SerializeIntegrityManifest(manifest);
  if (!serialized.ok()) {
    return Result<void>::Err(serialized.error());
  }
  const std::span<const unsigned char> bytes(
      reinterpret_cast<const unsigned char*>(serialized.value().data()),
      serialized.value().size());
  return WriteIntegrityArtifactAtomically(options.output, bytes);
}

Result<void> SignManifest(const SignOptions& options) {
  const auto manifest = ReadIntegrityManifestForSigning(options.manifest);
  if (!manifest.ok()) {
    return Result<void>::Err(manifest.error());
  }
  const auto signature = SignIntegrityManifest(manifest.value(), options.private_key);
  if (!signature.ok()) {
    return Result<void>::Err(signature.error());
  }
  return WriteIntegrityArtifactAtomically(options.output, signature.value());
}

void PrintError(const Error& error) {
  (void)std::fputs(error.code.c_str(), stderr);
  (void)std::fputc('\n', stderr);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    PrintError(kUsageError);
    return 2;
  }
  const std::string_view command(argv[1]);
  if (command == "create") {
    const auto options = ParseCreateOptions(argc, argv);
    if (!options.ok()) {
      PrintError(options.error());
      return 2;
    }
    const auto created = CreateManifest(options.value());
    if (!created.ok()) {
      PrintError(created.error());
      return 1;
    }
    return 0;
  }
  if (command == "sign") {
    const auto options = ParseSignOptions(argc, argv);
    if (!options.ok()) {
      PrintError(options.error());
      return 2;
    }
    const auto signed_manifest = SignManifest(options.value());
    if (!signed_manifest.ok()) {
      PrintError(signed_manifest.error());
      return 1;
    }
    return 0;
  }
  PrintError(kUsageError);
  return 2;
}
