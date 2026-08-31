#include "SafeFileDigestTestAccess.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

#include <sys/stat.h>

#include <openssl/crypto.h>
#include <gtest/gtest.h>

#include <stdlib.h>

namespace camera_firmware::integrity {
namespace {

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 48U> pattern{"/tmp/camera-firmware-digest-XXXXXX"};
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

  [[nodiscard]] const std::filesystem::path& path() const noexcept {
    return path_;
  }

 private:
  std::filesystem::path path_;
};

void WriteFile(const std::filesystem::path& path, std::string_view content) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  ASSERT_TRUE(output.is_open());
  output.write(content.data(), static_cast<std::streamsize>(content.size()));
  ASSERT_TRUE(output.good());
}

Sha256Digest DigestFromHex(std::string_view hex) {
  const auto parsed = ParseSha256(hex);
  EXPECT_TRUE(parsed.ok());
  return parsed.value();
}

TEST(SafeFileDigestTest, HashesKnownContent) {
  TemporaryDirectory directory;
  const auto file = directory.path() / "known";
  WriteFile(file, "abc");

  const auto result = DigestRegularFile(file);

  ASSERT_TRUE(result.ok());
  const Sha256Digest expected = DigestFromHex(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  EXPECT_EQ(CRYPTO_memcmp(result.value().data(), expected.data(),
                          expected.size()),
            0);
}

TEST(SafeFileDigestTest, RejectsMissingFileWithoutDisclosingPath) {
  TemporaryDirectory directory;
  const auto missing = directory.path() / "private-source-path";

  const auto result = DigestRegularFile(missing);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_FILE_ACCESS");
  EXPECT_EQ(result.error().message, "Unable to access integrity file");
  EXPECT_EQ(result.error().message.find(missing.string()), std::string::npos);
}

TEST(SafeFileDigestTest, RejectsSymbolicLink) {
  TemporaryDirectory directory;
  const auto target = directory.path() / "target";
  const auto link = directory.path() / "link";
  WriteFile(target, "contents");
  std::filesystem::create_symlink(target, link);

  const auto result = DigestRegularFile(link);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_FILE_TYPE");
  EXPECT_EQ(result.error().message, "Integrity input is not a regular file");
}

TEST(SafeFileDigestTest, RejectsDirectory) {
  TemporaryDirectory directory;

  const auto result = DigestRegularFile(directory.path());

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_FILE_TYPE");
  EXPECT_EQ(result.error().message, "Integrity input is not a regular file");
}

TEST(SafeFileDigestTest, RejectsFifoWithoutBlocking) {
  TemporaryDirectory directory;
  const auto fifo = directory.path() / "integrity-input";
  ASSERT_EQ(::mkfifo(fifo.c_str(), 0600), 0) << std::strerror(errno);

  const auto result = DigestRegularFile(fifo);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_FILE_TYPE");
  EXPECT_EQ(result.error().message, "Integrity input is not a regular file");
}

TEST(SafeFileDigestTest, FormatsDigestAsStableLowercaseHex) {
  const Sha256Digest digest = DigestFromHex(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

  EXPECT_EQ(HexSha256(digest),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
}

TEST(SafeFileDigestTest, RejectsUppercaseSha256) {
  const auto result = ParseSha256(
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_DIGEST_FORMAT");
  EXPECT_EQ(result.error().message, "SHA-256 digest has invalid format");
}

TEST(SafeFileDigestTest, RejectsMalformedSha256) {
  for (const std::string_view value : {
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015a",
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ag",
       }) {
    const auto result = ParseSha256(value);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_DIGEST_FORMAT");
    EXPECT_EQ(result.error().message, "SHA-256 digest has invalid format");
  }
}

TEST(SafeFileDigestTest, RejectsFileReplacedWhileHashing) {
  TemporaryDirectory directory;
  const auto file = directory.path() / "integrity-input";
  const auto replacement = directory.path() / "replacement";
  WriteFile(file, "original contents");
  WriteFile(replacement, "replacement contents");

  const auto result = testing::DigestRegularFileWithReadHook(
      file, [&] { std::filesystem::rename(replacement, file); });

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_FILE_CHANGED");
  EXPECT_EQ(result.error().message, "Integrity input changed while hashing");
}

TEST(SafeFileDigestTest, RejectsFileMutatedWhileHashing) {
  TemporaryDirectory directory;
  const auto file = directory.path() / "integrity-input";
  const std::string original = "original contents";
  const std::string mutated = "mutated contents!";
  ASSERT_EQ(original.size(), mutated.size());
  WriteFile(file, original);

  const auto result = testing::DigestRegularFileWithReadHook(
      file, [&] { WriteFile(file, mutated); });

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_FILE_CHANGED");
  EXPECT_EQ(result.error().message, "Integrity input changed while hashing");
}

}  // namespace
}  // namespace camera_firmware::integrity
