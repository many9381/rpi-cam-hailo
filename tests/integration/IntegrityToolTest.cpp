#include "camera_firmware/integrity/IntegrityManifest.hpp"
#include "camera_firmware/integrity/IntegrityVerifier.hpp"
#include "unit/integrity/IntegrityTestSupport.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <openssl/pem.h>

#include <gtest/gtest.h>

#ifndef CF_INTEGRITY_TOOL
#error "CF_INTEGRITY_TOOL must name the integrity executable"
#endif

namespace {

using camera_firmware::integrity::ParseIntegrityManifest;
using camera_firmware::integrity::VerifyIntegrityManifest;
using camera_firmware::integrity::testing::EphemeralEcKey;
using camera_firmware::integrity::testing::EphemeralEd25519Key;
using camera_firmware::integrity::testing::TemporaryDirectory;
using camera_firmware::integrity::testing::WriteFile;

struct ProcessResult {
  int exit_code{-1};
  std::string output;
};

bool WriteAll(int descriptor, std::span<const unsigned char> bytes) {
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    const ssize_t written =
        ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
    if (written > 0) {
      offset += static_cast<std::size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

ProcessResult RunTool(const std::vector<std::string>& arguments) {
  int output_pipe[2]{};
  if (::pipe(output_pipe) != 0) {
    return {};
  }
  const pid_t child = ::fork();
  if (child == 0) {
    (void)::dup2(output_pipe[1], STDOUT_FILENO);
    (void)::dup2(output_pipe[1], STDERR_FILENO);
    (void)::close(output_pipe[0]);
    (void)::close(output_pipe[1]);

    std::vector<char*> argv;
    argv.reserve(arguments.size() + 2U);
    argv.push_back(const_cast<char*>(CF_INTEGRITY_TOOL));
    for (const std::string& argument : arguments) {
      argv.push_back(const_cast<char*>(argument.c_str()));
    }
    argv.push_back(nullptr);
    ::execv(CF_INTEGRITY_TOOL, argv.data());
    _exit(127);
  }
  (void)::close(output_pipe[1]);
  if (child < 0) {
    (void)::close(output_pipe[0]);
    return {};
  }

  ProcessResult result;
  std::array<char, 256U> buffer{};
  while (true) {
    const ssize_t count = ::read(output_pipe[0], buffer.data(), buffer.size());
    if (count > 0) {
      result.output.append(buffer.data(), static_cast<std::size_t>(count));
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
  (void)::close(output_pipe[0]);
  int status = 0;
  if (::waitpid(child, &status, 0) == child && WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  }
  return result;
}

std::string ReadFile(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::vector<unsigned char> ReadBytes(const std::filesystem::path& path) {
  const std::string text = ReadFile(path);
  return {text.begin(), text.end()};
}

void WritePrivateKey(const std::filesystem::path& path, EVP_PKEY* key) {
  BIO* bio = BIO_new_file(path.c_str(), "w");
  ASSERT_NE(bio, nullptr);
  ASSERT_EQ(PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr,
                                     nullptr),
            1);
  ASSERT_EQ(BIO_free(bio), 1);
  ASSERT_EQ(::chmod(path.c_str(), S_IRUSR | S_IWUSR), 0);
}

void ExpectMode0600(const std::filesystem::path& path) {
  struct stat status {};
  ASSERT_EQ(::stat(path.c_str(), &status), 0);
  EXPECT_EQ(status.st_mode & 0777, 0600);
}

std::size_t TemporaryOutputCount(const std::filesystem::path& directory,
                                 std::string_view output_name) {
  std::size_t count = 0U;
  for (const auto& entry : std::filesystem::directory_iterator(directory)) {
    if (entry.path().filename().string().starts_with(
            std::string(".") + std::string(output_name) + ".tmp-")) {
      ++count;
    }
  }
  return count;
}

class IntegrityToolTest : public ::testing::Test {
 protected:
  void SetUp() override {
    firmware_ = directory_.path() / "firmware";
    configuration_ = directory_.path() / "configuration";
    kernel_ = directory_.path() / "kernel";
    WriteFile(firmware_, "firmware bytes\n");
    WriteFile(configuration_, "configuration bytes\n");
    WriteFile(kernel_, "kernel bytes\n");
  }

  std::vector<std::string> CreateArguments(const std::filesystem::path& output) const {
    return {"create", "--output", output.string(), "--entry",
            "firmware:firmware:" + firmware_.string(), "--entry",
            "configuration:configuration:" + configuration_.string(), "--entry",
            "kernel:kernel:" + kernel_.string()};
  }

  TemporaryDirectory directory_;
  std::filesystem::path firmware_;
  std::filesystem::path configuration_;
  std::filesystem::path kernel_;
};

TEST_F(IntegrityToolTest, CreatesSortedStrictManifestWithColonPath) {
  const auto colon_path = directory_.path() / "kernel:copy";
  std::filesystem::copy_file(kernel_, colon_path);
  const auto manifest = directory_.path() / "manifest.yaml";
  auto arguments = CreateArguments(manifest);
  arguments[arguments.size() - 1U] = "kernel:z-kernel:" + colon_path.string();
  arguments[4] = "firmware:a-firmware:" + firmware_.string();
  arguments[6] = "configuration:m-configuration:" + configuration_.string();

  const auto result = RunTool(arguments);

  ASSERT_EQ(result.exit_code, 0) << result.output;
  EXPECT_TRUE(result.output.empty());
  const std::string bytes = ReadFile(manifest);
  const auto parsed = ParseIntegrityManifest(bytes);
  ASSERT_TRUE(parsed.ok()) << parsed.error().code;
  ASSERT_EQ(parsed.value().files.size(), 3U);
  EXPECT_EQ(parsed.value().files[0].id, "a-firmware");
  EXPECT_EQ(parsed.value().files[1].id, "m-configuration");
  EXPECT_EQ(parsed.value().files[2].id, "z-kernel");
  EXPECT_EQ(parsed.value().files[2].path, colon_path);
  ExpectMode0600(manifest);
}

TEST_F(IntegrityToolTest, RejectsDuplicateIdsPathsAndInvalidEntriesBeforeOutput) {
  const auto manifest = directory_.path() / "manifest.yaml";
  WriteFile(manifest, "preserved\n");
  const std::vector<std::vector<std::string>> invalid_invocations = {
      {"create", "--output", manifest.string(), "--entry",
       "firmware:duplicate:" + firmware_.string(), "--entry",
       "configuration:duplicate:" + configuration_.string()},
      {"create", "--output", manifest.string(), "--entry",
       "firmware:firmware:" + firmware_.string(), "--entry",
       "configuration:configuration:" + firmware_.string()},
      {"create", "--output", manifest.string(), "--entry",
       "firmware:bad id:" + firmware_.string()},
      {"create", "--output", manifest.string(), "--entry",
       "firmware:" + std::string(65U, 'a') + ":" + firmware_.string()},
      {"create", "--output", manifest.string(), "--entry",
       "firmware:firmware:relative"},
      {"create", "--output", manifest.string()},
  };

  for (const auto& arguments : invalid_invocations) {
    const auto result = RunTool(arguments);
    EXPECT_NE(result.exit_code, 0) << result.output;
    EXPECT_EQ(ReadFile(manifest), "preserved\n");
  }
}

TEST_F(IntegrityToolTest, RejectsSymlinkInputsAndUnsafeOutputsWithoutReplacement) {
  const auto input_link = directory_.path() / "firmware-link";
  const auto manifest = directory_.path() / "manifest.yaml";
  const auto protected_target = directory_.path() / "protected";
  const auto output_link = directory_.path() / "output-link";
  ASSERT_EQ(::symlink(firmware_.c_str(), input_link.c_str()), 0);
  WriteFile(protected_target, "protected\n");
  ASSERT_EQ(::symlink(protected_target.c_str(), output_link.c_str()), 0);

  auto symlink_input = CreateArguments(manifest);
  symlink_input[4] = "firmware:firmware:" + input_link.string();
  auto result = RunTool(symlink_input);
  EXPECT_NE(result.exit_code, 0) << result.output;
  EXPECT_FALSE(std::filesystem::exists(manifest));

  result = RunTool(CreateArguments(output_link));
  EXPECT_NE(result.exit_code, 0) << result.output;
  EXPECT_EQ(ReadFile(protected_target), "protected\n");
}

TEST_F(IntegrityToolTest, PublishesAtomicallyAndCleansTemporaryFileOnFailure) {
  const auto manifest = directory_.path() / "manifest.yaml";
  WriteFile(manifest, "old manifest\n");
  auto invalid = CreateArguments(manifest);
  invalid[4] = "firmware:firmware:" + (directory_.path() / "missing").string();

  const auto failed = RunTool(invalid);

  EXPECT_NE(failed.exit_code, 0) << failed.output;
  EXPECT_EQ(ReadFile(manifest), "old manifest\n");
  EXPECT_EQ(TemporaryOutputCount(directory_.path(), "manifest.yaml"), 0U);

  const auto created = RunTool(CreateArguments(manifest));
  ASSERT_EQ(created.exit_code, 0) << created.output;
  EXPECT_NE(ReadFile(manifest), "old manifest\n");
  ExpectMode0600(manifest);
}

TEST_F(IntegrityToolTest, SignsExactManifestBytesAndRoundTripsRuntimeVerifier) {
  const auto manifest = directory_.path() / "manifest.yaml";
  const auto signature = directory_.path() / "manifest.sig";
  const auto private_key = directory_.path() / "private.pem";
  EphemeralEd25519Key key;
  WritePrivateKey(private_key, key.key());
  ASSERT_EQ(RunTool(CreateArguments(manifest)).exit_code, 0);

  const auto result = RunTool({"sign", "--manifest", manifest.string(),
                               "--private-key", private_key.string(), "--output",
                               signature.string()});

  ASSERT_EQ(result.exit_code, 0) << result.output;
  EXPECT_TRUE(result.output.empty());
  EXPECT_EQ(ReadBytes(signature).size(), 64U);
  ExpectMode0600(signature);
  const auto verified = VerifyIntegrityManifest(manifest, signature, key.PublicPem(),
                                                firmware_, configuration_);
  ASSERT_TRUE(verified.ok()) << verified.error().code;
  EXPECT_TRUE(verified.value().passed);
}

TEST_F(IntegrityToolTest, RejectsWrongTrailingAndSymlinkPrivateKeysWithoutLeakingBytes) {
  const auto manifest = directory_.path() / "manifest.yaml";
  const auto signature = directory_.path() / "manifest.sig";
  const auto ec_key = directory_.path() / "ec.pem";
  const auto ed_key = directory_.path() / "ed.pem";
  const auto link = directory_.path() / "key-link";
  EphemeralEcKey ec;
  EphemeralEd25519Key ed;
  WritePrivateKey(ec_key, ec.key());
  WritePrivateKey(ed_key, ed.key());
  ASSERT_EQ(RunTool(CreateArguments(manifest)).exit_code, 0);

  auto result = RunTool({"sign", "--manifest", manifest.string(), "--private-key",
                         ec_key.string(), "--output", signature.string()});
  EXPECT_NE(result.exit_code, 0) << result.output;
  EXPECT_EQ(result.output.find(ReadFile(ec_key)), std::string::npos);
  EXPECT_EQ(result.output.find("-----BEGIN"), std::string::npos);

  std::ofstream trailing(ed_key, std::ios::app | std::ios::binary);
  trailing << "trailing";
  trailing.close();
  result = RunTool({"sign", "--manifest", manifest.string(), "--private-key",
                    ed_key.string(), "--output", signature.string()});
  EXPECT_NE(result.exit_code, 0) << result.output;
  EXPECT_EQ(result.output.find("trailing"), std::string::npos);

  ASSERT_EQ(::symlink(ec_key.c_str(), link.c_str()), 0);
  result = RunTool({"sign", "--manifest", manifest.string(), "--private-key",
                    link.string(), "--output", signature.string()});
  EXPECT_NE(result.exit_code, 0) << result.output;
}

TEST_F(IntegrityToolTest, RejectsInvalidOptionsAndUnsafeManifestInput) {
  const auto manifest = directory_.path() / "manifest.yaml";
  const auto signature = directory_.path() / "manifest.sig";
  const auto key_path = directory_.path() / "private.pem";
  const auto manifest_link = directory_.path() / "manifest-link";
  EphemeralEd25519Key key;
  WritePrivateKey(key_path, key.key());
  ASSERT_EQ(RunTool(CreateArguments(manifest)).exit_code, 0);
  ASSERT_EQ(::symlink(manifest.c_str(), manifest_link.c_str()), 0);
  const std::vector<std::vector<std::string>> invalid_invocations = {
      {"create", "--unknown"},
      {"create", "--output", manifest.string(), "--output", manifest.string(),
       "--entry", "firmware:firmware:" + firmware_.string()},
      {"sign", "--manifest", manifest.string(), "--private-key", key_path.string(),
       "--output", signature.string(), "--entry", "ignored"},
      {"sign", "--manifest", manifest_link.string(), "--private-key", key_path.string(),
       "--output", signature.string()},
  };

  for (const auto& arguments : invalid_invocations) {
    const auto result = RunTool(arguments);
    EXPECT_NE(result.exit_code, 0) << result.output;
    EXPECT_EQ(result.output.find(key_path.string()), std::string::npos);
    EXPECT_EQ(result.output.find("-----BEGIN"), std::string::npos);
  }
}

TEST_F(IntegrityToolTest, RejectsMoreThanManifestEntryLimitBeforeHashing) {
  const auto manifest = directory_.path() / "manifest.yaml";
  std::vector<std::string> arguments{"create", "--output", manifest.string()};
  for (std::size_t index = 0U; index <= 4096U; ++index) {
    arguments.emplace_back("--entry");
    arguments.push_back("firmware:file-" + std::to_string(index) + ":" +
                        (directory_.path() / ("missing-" + std::to_string(index))).string());
  }

  const auto result = RunTool(arguments);

  EXPECT_EQ(result.exit_code, 2) << result.output;
  EXPECT_EQ(result.output, "E_INTEGRITY_TOOL_USAGE\n");
  EXPECT_FALSE(std::filesystem::exists(manifest));
}

}  // namespace
