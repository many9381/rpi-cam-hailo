#include "camera_firmware/rtsp/RtspDigestCredentials.hpp"

#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

using camera_firmware::common::SecureBytes;
using camera_firmware::rtsp::ComputeRtspDigestHa1;
using camera_firmware::rtsp::ProvisionRtspDigestCredential;
using camera_firmware::rtsp::RtspDigestAlgorithm;
using camera_firmware::rtsp::RtspDigestConstantTimeEqual;
using camera_firmware::rtsp::RtspDigestCredentialPolicy;
using camera_firmware::rtsp::RtspDigestCredentialStore;
using camera_firmware::rtsp::RtspDigestProvisionRequest;

constexpr std::string_view kRealm = "rpi-camera";

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 40> path{"/tmp/cf-rtsp-credentials-XXXXXX"};
    char* created = ::mkdtemp(path.data());
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

  [[nodiscard]] std::filesystem::path File(std::string_view name) const {
    return path_ / name;
  }

  [[nodiscard]] const std::filesystem::path& path() const noexcept {
    return path_;
  }

 private:
  std::filesystem::path path_;
};

class ScopedFileSizeLimit {
 public:
  explicit ScopedFileSizeLimit(rlim_t limit) {
    if (::getrlimit(RLIMIT_FSIZE, &original_limit_) != 0) {
      throw std::system_error(errno, std::generic_category(), "getrlimit");
    }

    struct sigaction ignored_action {};
    ignored_action.sa_handler = SIG_IGN;
    (void)::sigemptyset(&ignored_action.sa_mask);
    if (::sigaction(SIGXFSZ, &ignored_action, &original_action_) != 0) {
      throw std::system_error(errno, std::generic_category(), "sigaction");
    }
    action_changed_ = true;

    struct rlimit limited = original_limit_;
    limited.rlim_cur = limit;
    if (::setrlimit(RLIMIT_FSIZE, &limited) != 0) {
      (void)::sigaction(SIGXFSZ, &original_action_, nullptr);
      action_changed_ = false;
      throw std::system_error(errno, std::generic_category(), "setrlimit");
    }
    limit_changed_ = true;
  }

  ~ScopedFileSizeLimit() {
    if (limit_changed_) {
      (void)::setrlimit(RLIMIT_FSIZE, &original_limit_);
    }
    if (action_changed_) {
      (void)::sigaction(SIGXFSZ, &original_action_, nullptr);
    }
  }

  ScopedFileSizeLimit(const ScopedFileSizeLimit&) = delete;
  ScopedFileSizeLimit& operator=(const ScopedFileSizeLimit&) = delete;

 private:
  struct rlimit original_limit_ {};
  struct sigaction original_action_ {};
  bool action_changed_{false};
  bool limit_changed_{false};
};

std::span<const unsigned char> Bytes(std::string_view value) {
  return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}

void WriteAllForTest(int fd, std::string_view content) {
  std::size_t offset = 0U;
  while (offset < content.size()) {
    const ssize_t written =
        ::write(fd, content.data() + offset, content.size() - offset);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      throw std::system_error(errno, std::generic_category(), "write");
    }
    offset += static_cast<std::size_t>(written);
  }
}

void WriteFile(const std::filesystem::path& path, std::string_view content,
               mode_t mode = 0600) {
  const int fd =
      ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    throw std::system_error(errno, std::generic_category(), "open");
  }
  try {
    if (::fchmod(fd, mode) != 0) {
      throw std::system_error(errno, std::generic_category(), "fchmod");
    }
    WriteAllForTest(fd, content);
  } catch (...) {
    (void)::close(fd);
    throw;
  }
  if (::close(fd) != 0) {
    throw std::system_error(errno, std::generic_category(), "close");
  }
}

std::string HexForTest(const SecureBytes& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output(bytes.size() * 2U, '0');
  for (std::size_t index = 0U; index < bytes.size(); ++index) {
    output[index * 2U] = kHex[bytes.data()[index] >> 4U];
    output[index * 2U + 1U] = kHex[bytes.data()[index] & 0x0fU];
  }
  return output;
}

std::string Record(std::string_view username, std::string_view realm,
                   RtspDigestAlgorithm algorithm,
                   std::string_view password) {
  auto ha1 = ComputeRtspDigestHa1(algorithm, username, realm, Bytes(password));
  if (!ha1.ok()) {
    throw std::runtime_error("failed to compute test HA1");
  }
  const std::string_view algorithm_name =
      algorithm == RtspDigestAlgorithm::kSha256 ? "sha-256" : "md5";
  return std::string(username) + ":" + std::string(realm) + ":" +
         std::string(algorithm_name) + ":" + HexForTest(ha1.value()) + "\n";
}

std::string CredentialFile(const std::vector<std::string>& records) {
  std::string content = "CFDIGEST1\n";
  for (const auto& record : records) {
    content += record;
  }
  return content;
}

std::string ReadFileForTest(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input),
          std::istreambuf_iterator<char>()};
}

RtspDigestCredentialPolicy Sha256Policy(
    std::string realm = std::string(kRealm)) {
  return {std::move(realm), {RtspDigestAlgorithm::kSha256}};
}

RtspDigestCredentialPolicy CompatibilityPolicy(
    std::string realm = std::string(kRealm)) {
  return {std::move(realm),
          {RtspDigestAlgorithm::kSha256, RtspDigestAlgorithm::kMd5}};
}

std::unique_ptr<RtspDigestCredentialStore> CreateStore(
    RtspDigestCredentialPolicy policy = Sha256Policy()) {
  auto created = RtspDigestCredentialStore::Create(std::move(policy));
  if (!created.ok()) {
    throw std::runtime_error("failed to create credential store");
  }
  return std::move(created).value();
}

void ExpectCredentialError(const camera_firmware::common::Error& error) {
  EXPECT_EQ(error.code, "E_RTSP_AUTH_CREDENTIALS");
}

std::size_t DirectoryEntryCount(const std::filesystem::path& path) {
  return static_cast<std::size_t>(
      std::distance(std::filesystem::directory_iterator(path),
                    std::filesystem::directory_iterator()));
}

TEST(RtspDigestCredentialsTest, LoadsStrictVersionedSha256File) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path,
            CredentialFile({Record("operator", kRealm,
                                   RtspDigestAlgorithm::kSha256, "secret")}));
  auto store = CreateStore();

  auto reloaded = store->Reload(path);
  auto lookup = store->Lookup("operator", RtspDigestAlgorithm::kSha256);
  auto expected = ComputeRtspDigestHa1(RtspDigestAlgorithm::kSha256,
                                       "operator", kRealm, Bytes("secret"));

  ASSERT_TRUE(reloaded.ok()) << reloaded.error().message;
  ASSERT_TRUE(lookup.ok()) << lookup.error().message;
  ASSERT_TRUE(expected.ok()) << expected.error().message;
  EXPECT_TRUE(lookup.value().matched);
  EXPECT_TRUE(RtspDigestConstantTimeEqual(
      {lookup.value().ha1.data(), lookup.value().ha1.size()},
      {expected.value().data(), expected.value().size()}));
}

TEST(RtspDigestCredentialsTest, ReturnsDummyHa1ForUnknownUser) {
  auto store = CreateStore();

  auto first = store->Lookup("missing-one", RtspDigestAlgorithm::kSha256);
  auto second = store->Lookup("missing-two", RtspDigestAlgorithm::kSha256);

  ASSERT_TRUE(first.ok()) << first.error().message;
  ASSERT_TRUE(second.ok()) << second.error().message;
  EXPECT_FALSE(first.value().matched);
  EXPECT_FALSE(second.value().matched);
  EXPECT_EQ(first.value().ha1.size(), 32U);
  EXPECT_TRUE(RtspDigestConstantTimeEqual(
      {first.value().ha1.data(), first.value().ha1.size()},
      {second.value().ha1.data(), second.value().ha1.size()}));
}

TEST(RtspDigestCredentialsTest, ReturnsDummyHa1ForMissingAlgorithmRecord) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path,
            CredentialFile({Record("operator", kRealm,
                                   RtspDigestAlgorithm::kSha256, "secret")}));
  auto store = CreateStore(CompatibilityPolicy());
  ASSERT_TRUE(store->Reload(path).ok());

  auto missing = store->Lookup("operator", RtspDigestAlgorithm::kMd5);
  auto unknown = store->Lookup("unknown", RtspDigestAlgorithm::kMd5);

  ASSERT_TRUE(missing.ok()) << missing.error().message;
  ASSERT_TRUE(unknown.ok()) << unknown.error().message;
  EXPECT_FALSE(missing.value().matched);
  EXPECT_FALSE(unknown.value().matched);
  EXPECT_EQ(missing.value().ha1.size(), 16U);
  EXPECT_TRUE(RtspDigestConstantTimeEqual(
      {missing.value().ha1.data(), missing.value().ha1.size()},
      {unknown.value().ha1.data(), unknown.value().ha1.size()}));
}

TEST(RtspDigestCredentialsTest, RejectsSymlinkAndGroupReadableFile) {
  TemporaryDirectory directory;
  const auto target = directory.File("target");
  const auto symlink = directory.File("symlink");
  const auto group_readable = directory.File("group-readable");
  const auto valid = CredentialFile({Record(
      "operator", kRealm, RtspDigestAlgorithm::kSha256, "secret")});
  WriteFile(target, valid);
  std::filesystem::create_symlink(target, symlink);
  WriteFile(group_readable, valid, 0640);
  auto store = CreateStore();

  auto symlink_result = store->Reload(symlink);
  auto mode_result = store->Reload(group_readable);

  ASSERT_FALSE(symlink_result.ok());
  ASSERT_FALSE(mode_result.ok());
  ExpectCredentialError(symlink_result.error());
  ExpectCredentialError(mode_result.error());
  EXPECT_EQ(mode_result.error().message,
            "credential file permissions are invalid");
}

TEST(RtspDigestCredentialsTest,
     RejectsWrongRealmUppercaseHexAndBlankLine) {
  TemporaryDirectory directory;
  const auto wrong_realm = directory.File("wrong-realm");
  const auto uppercase = directory.File("uppercase");
  const auto blank = directory.File("blank");
  WriteFile(wrong_realm,
            CredentialFile({Record("operator", "other-realm",
                                   RtspDigestAlgorithm::kSha256, "secret")}));
  std::string uppercase_record =
      Record("operator", kRealm, RtspDigestAlgorithm::kSha256, "secret");
  const auto digest = uppercase_record.rfind(':') + 1U;
  std::transform(uppercase_record.begin() + static_cast<std::ptrdiff_t>(digest),
                 uppercase_record.end(), uppercase_record.begin() +
                                                    static_cast<std::ptrdiff_t>(digest),
                 [](unsigned char value) {
                   return static_cast<char>(value >= 'a' && value <= 'f'
                                                ? value - ('a' - 'A')
                                                : value);
                 });
  WriteFile(uppercase, CredentialFile({uppercase_record}));
  WriteFile(blank,
            CredentialFile({Record("operator", kRealm,
                                   RtspDigestAlgorithm::kSha256, "secret"),
                            "\n"}));
  auto store = CreateStore();

  auto wrong_realm_result = store->Reload(wrong_realm);
  auto uppercase_result = store->Reload(uppercase);
  auto blank_result = store->Reload(blank);

  ASSERT_FALSE(wrong_realm_result.ok());
  ASSERT_FALSE(uppercase_result.ok());
  ASSERT_FALSE(blank_result.ok());
  EXPECT_EQ(wrong_realm_result.error().message,
            "credential file format is invalid");
  EXPECT_EQ(uppercase_result.error().message,
            "credential file format is invalid");
  EXPECT_EQ(blank_result.error().message,
            "credential file format is invalid");
}

TEST(RtspDigestCredentialsTest, RejectsDuplicateRecordAndMoreThan64Users) {
  TemporaryDirectory directory;
  const auto duplicate = directory.File("duplicate");
  const auto too_many_users = directory.File("too-many-users");
  const std::string repeated = Record(
      "operator", kRealm, RtspDigestAlgorithm::kSha256, "secret");
  WriteFile(duplicate, CredentialFile({repeated, repeated}));
  std::vector<std::string> records;
  for (std::size_t index = 0U; index < 65U; ++index) {
    records.push_back(Record("user" + std::to_string(index), kRealm,
                             RtspDigestAlgorithm::kSha256, "secret"));
  }
  WriteFile(too_many_users, CredentialFile(records));
  auto store = CreateStore();

  auto duplicate_result = store->Reload(duplicate);
  auto users_result = store->Reload(too_many_users);

  ASSERT_FALSE(duplicate_result.ok());
  ASSERT_FALSE(users_result.ok());
  ExpectCredentialError(duplicate_result.error());
  ExpectCredentialError(users_result.error());
}

TEST(RtspDigestCredentialsTest, AcceptsSixtyFourUsersAnd128Records) {
  TemporaryDirectory directory;
  const auto path = directory.File("maximum-records");
  std::vector<std::string> records;
  for (std::size_t index = 0U; index < 64U; ++index) {
    const std::string username = "user" + std::to_string(index);
    records.push_back(Record(username, kRealm,
                             RtspDigestAlgorithm::kSha256, "secret"));
    records.push_back(
        Record(username, kRealm, RtspDigestAlgorithm::kMd5, "secret"));
  }
  WriteFile(path, CredentialFile(records));
  auto store = CreateStore(CompatibilityPolicy());

  auto result = store->Reload(path);
  auto lookup = store->Lookup("user63", RtspDigestAlgorithm::kMd5);

  ASSERT_TRUE(result.ok()) << result.error().message;
  ASSERT_TRUE(lookup.ok()) << lookup.error().message;
  EXPECT_TRUE(lookup.value().matched);
}

TEST(RtspDigestCredentialsTest,
     RejectsMd5RecordWhenCompatibilityIsDisabled) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path,
            CredentialFile({Record("operator", kRealm,
                                   RtspDigestAlgorithm::kSha256, "secret"),
                            Record("operator", kRealm,
                                   RtspDigestAlgorithm::kMd5, "secret")}));
  auto store = CreateStore();

  auto result = store->Reload(path);

  ASSERT_FALSE(result.ok());
  ExpectCredentialError(result.error());
}

TEST(RtspDigestCredentialsTest,
     RejectsMd5OnlyFileEvenWhenCompatibilityIsEnabled) {
  TemporaryDirectory directory;
  const auto path = directory.File("md5-only");
  WriteFile(path, CredentialFile({Record("operator", kRealm,
                                        RtspDigestAlgorithm::kMd5,
                                        "secret")}));
  auto store = CreateStore(CompatibilityPolicy());

  auto result = store->Reload(path);

  ASSERT_FALSE(result.ok());
  ExpectCredentialError(result.error());
}

TEST(RtspDigestCredentialsTest, FailedReloadKeepsPreviousCredentials) {
  TemporaryDirectory directory;
  const auto initial = directory.File("initial");
  const auto invalid = directory.File("invalid");
  WriteFile(initial,
            CredentialFile({Record("operator", kRealm,
                                   RtspDigestAlgorithm::kSha256, "first")}));
  WriteFile(invalid, "CFDIGEST1\ninvalid\n");
  auto store = CreateStore();
  ASSERT_TRUE(store->Reload(initial).ok());

  auto failed = store->Reload(invalid);
  auto lookup = store->Lookup("operator", RtspDigestAlgorithm::kSha256);
  auto expected = ComputeRtspDigestHa1(RtspDigestAlgorithm::kSha256,
                                       "operator", kRealm, Bytes("first"));

  ASSERT_FALSE(failed.ok());
  ASSERT_TRUE(lookup.ok()) << lookup.error().message;
  ASSERT_TRUE(expected.ok()) << expected.error().message;
  EXPECT_TRUE(lookup.value().matched);
  EXPECT_TRUE(RtspDigestConstantTimeEqual(
      {lookup.value().ha1.data(), lookup.value().ha1.size()},
      {expected.value().data(), expected.value().size()}));
}

TEST(RtspDigestCredentialsTest,
     SuccessfulReloadZeroizesRetiredCredentials) {
  TemporaryDirectory directory;
  const auto first = directory.File("first");
  const auto second = directory.File("second");
  WriteFile(first,
            CredentialFile({Record("operator", kRealm,
                                   RtspDigestAlgorithm::kSha256, "first")}));
  WriteFile(second,
            CredentialFile({Record("operator", kRealm,
                                   RtspDigestAlgorithm::kSha256, "second")}));
  auto store = CreateStore();
  ASSERT_TRUE(store->Reload(first).ok());
  const auto before_reload = store->zeroize_audit();

  auto reloaded = store->Reload(second);
  const auto after_reload = store->zeroize_audit();

  ASSERT_TRUE(reloaded.ok()) << reloaded.error().message;
  EXPECT_GT(after_reload.count, before_reload.count);
  EXPECT_TRUE(after_reload.last_verified);

  store->Clear();
  const auto after_clear = store->zeroize_audit();
  EXPECT_GT(after_clear.count, after_reload.count);
  EXPECT_TRUE(after_clear.last_verified);
}

TEST(RtspDigestCredentialsTest,
     ConcurrentLookupAndReloadReturnOnlyCompleteHa1Values) {
  TemporaryDirectory directory;
  const auto old_path = directory.File("old");
  const auto new_path = directory.File("new");
  WriteFile(old_path,
            CredentialFile({Record("operator", kRealm,
                                   RtspDigestAlgorithm::kSha256, "old-pass")}));
  WriteFile(new_path,
            CredentialFile({Record("operator", kRealm,
                                   RtspDigestAlgorithm::kSha256, "new-pass")}));
  auto expected_old = ComputeRtspDigestHa1(
      RtspDigestAlgorithm::kSha256, "operator", kRealm, Bytes("old-pass"));
  auto expected_new = ComputeRtspDigestHa1(
      RtspDigestAlgorithm::kSha256, "operator", kRealm, Bytes("new-pass"));
  ASSERT_TRUE(expected_old.ok());
  ASSERT_TRUE(expected_new.ok());
  auto store = CreateStore();
  ASSERT_TRUE(store->Reload(old_path).ok());

  std::atomic<bool> reader_ready{false};
  std::atomic<bool> stop{false};
  std::atomic<bool> invalid_lookup{false};
  std::atomic<std::size_t> lookup_count{0U};
  std::thread reader([&] {
    reader_ready.store(true);
    while (!stop.load()) {
      auto lookup =
          store->Lookup("operator", RtspDigestAlgorithm::kSha256);
      const bool valid =
          lookup.ok() && lookup.value().matched &&
          (RtspDigestConstantTimeEqual(
               {lookup.value().ha1.data(), lookup.value().ha1.size()},
               {expected_old.value().data(), expected_old.value().size()}) ||
           RtspDigestConstantTimeEqual(
               {lookup.value().ha1.data(), lookup.value().ha1.size()},
               {expected_new.value().data(), expected_new.value().size()}));
      if (!valid) {
        invalid_lookup.store(true);
      }
      ++lookup_count;
    }
  });
  while (!reader_ready.load() || lookup_count.load() == 0U) {
    std::this_thread::yield();
  }

  bool reloads_succeeded = true;
  for (std::size_t iteration = 0U; iteration < 200U; ++iteration) {
    const auto& path = iteration % 2U == 0U ? new_path : old_path;
    if (!store->Reload(path).ok()) {
      reloads_succeeded = false;
      break;
    }
  }
  stop.store(true);
  reader.join();

  EXPECT_TRUE(reloads_succeeded);
  EXPECT_FALSE(invalid_lookup.load());
  EXPECT_GT(lookup_count.load(), 0U);
}

TEST(RtspDigestCredentialsTest,
     ClearTerminallyCleansesActiveAndDummyHa1Values) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  WriteFile(path,
            CredentialFile({Record("operator", kRealm,
                                   RtspDigestAlgorithm::kSha256, "secret"),
                            Record("operator", kRealm,
                                   RtspDigestAlgorithm::kMd5, "secret")}));
  auto store = CreateStore(CompatibilityPolicy());
  ASSERT_TRUE(store->Reload(path).ok());
  const auto before = store->zeroize_audit();

  store->Clear();

  const auto after = store->zeroize_audit();
  EXPECT_EQ(after.count - before.count, 4U);
  EXPECT_TRUE(after.last_verified);
  auto sha_lookup =
      store->Lookup("operator", RtspDigestAlgorithm::kSha256);
  auto md5_lookup = store->Lookup("operator", RtspDigestAlgorithm::kMd5);
  ASSERT_FALSE(sha_lookup.ok());
  ASSERT_FALSE(md5_lookup.ok());
  ExpectCredentialError(sha_lookup.error());
  ExpectCredentialError(md5_lookup.error());
  EXPECT_EQ(sha_lookup.error().message, "credential operation failed");
  EXPECT_EQ(md5_lookup.error().message, "credential operation failed");
}

TEST(RtspDigestCredentialsTest, ProvisionWritesMode0600AndReplacesAtomically) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  RtspDigestProvisionRequest request{path, "operator", std::string(kRealm),
                                     RtspDigestAlgorithm::kSha256, false};

  auto first = ProvisionRtspDigestCredential(request, Bytes("first"));
  struct stat first_stat {};
  ASSERT_TRUE(first.ok()) << first.error().message;
  ASSERT_EQ(::stat(path.c_str(), &first_stat), 0);
  EXPECT_EQ(first_stat.st_mode & 0777, 0600);
  EXPECT_EQ(DirectoryEntryCount(directory.path()), 1U);

  auto second = ProvisionRtspDigestCredential(request, Bytes("second"));
  struct stat second_stat {};
  ASSERT_TRUE(second.ok()) << second.error().message;
  ASSERT_EQ(::stat(path.c_str(), &second_stat), 0);
  EXPECT_NE(second_stat.st_ino, first_stat.st_ino);
  EXPECT_EQ(second_stat.st_mode & 0777, 0600);
  EXPECT_EQ(DirectoryEntryCount(directory.path()), 1U);

  auto store = CreateStore();
  ASSERT_TRUE(store->Reload(path).ok());
  auto lookup = store->Lookup("operator", RtspDigestAlgorithm::kSha256);
  auto expected = ComputeRtspDigestHa1(RtspDigestAlgorithm::kSha256,
                                       "operator", kRealm, Bytes("second"));
  ASSERT_TRUE(lookup.ok()) << lookup.error().message;
  ASSERT_TRUE(expected.ok()) << expected.error().message;
  EXPECT_TRUE(lookup.value().matched);
  EXPECT_TRUE(RtspDigestConstantTimeEqual(
      {lookup.value().ha1.data(), lookup.value().ha1.size()},
      {expected.value().data(), expected.value().size()}));
}

TEST(RtspDigestCredentialsTest,
     ConcurrentReadersObserveOnlyCompleteAtomicReplacements) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  RtspDigestProvisionRequest request{path, "operator", std::string(kRealm),
                                     RtspDigestAlgorithm::kSha256, false};
  ASSERT_TRUE(
      ProvisionRtspDigestCredential(request, Bytes("old-password")).ok());
  const std::string old_content =
      CredentialFile({Record("operator", kRealm,
                             RtspDigestAlgorithm::kSha256, "old-password")});
  const std::string new_content =
      CredentialFile({Record("operator", kRealm,
                             RtspDigestAlgorithm::kSha256, "new-password")});

  std::atomic<bool> reader_ready{false};
  std::atomic<bool> stop{false};
  std::atomic<bool> invalid_content{false};
  std::atomic<std::size_t> read_count{0U};
  std::thread reader([&] {
    reader_ready.store(true);
    while (!stop.load()) {
      const std::string observed = ReadFileForTest(path);
      if (observed != old_content && observed != new_content) {
        invalid_content.store(true);
      }
      ++read_count;
    }
  });
  while (!reader_ready.load() || read_count.load() == 0U) {
    std::this_thread::yield();
  }

  bool replacements_succeeded = true;
  for (std::size_t iteration = 0U; iteration < 20U; ++iteration) {
    const std::string_view password =
        iteration % 2U == 0U ? "new-password" : "old-password";
    if (!ProvisionRtspDigestCredential(request, Bytes(password)).ok()) {
      replacements_succeeded = false;
      break;
    }
  }
  stop.store(true);
  reader.join();

  EXPECT_TRUE(replacements_succeeded);
  EXPECT_FALSE(invalid_content.load());
  EXPECT_GT(read_count.load(), 0U);
}

TEST(RtspDigestCredentialsTest, ProvisionRequiresSha256BeforeMd5) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  RtspDigestProvisionRequest md5_request{path, "operator", std::string(kRealm),
                                         RtspDigestAlgorithm::kMd5, true};

  auto missing_sha =
      ProvisionRtspDigestCredential(md5_request, Bytes("secret"));

  ASSERT_FALSE(missing_sha.ok());
  ExpectCredentialError(missing_sha.error());
  EXPECT_FALSE(std::filesystem::exists(path));

  RtspDigestProvisionRequest sha_request{
      path, "operator", std::string(kRealm),
      RtspDigestAlgorithm::kSha256, true};
  ASSERT_TRUE(
      ProvisionRtspDigestCredential(sha_request, Bytes("secret")).ok());
  auto added_md5 =
      ProvisionRtspDigestCredential(md5_request, Bytes("secret"));

  ASSERT_TRUE(added_md5.ok()) << added_md5.error().message;
  auto store = CreateStore(CompatibilityPolicy());
  ASSERT_TRUE(store->Reload(path).ok());
  auto sha_lookup =
      store->Lookup("operator", RtspDigestAlgorithm::kSha256);
  auto md5_lookup = store->Lookup("operator", RtspDigestAlgorithm::kMd5);
  ASSERT_TRUE(sha_lookup.ok());
  ASSERT_TRUE(md5_lookup.ok());
  EXPECT_TRUE(sha_lookup.value().matched);
  EXPECT_TRUE(md5_lookup.value().matched);
}

TEST(RtspDigestCredentialsTest,
     Sha256RotationPreservesExistingMd5WithoutAllowMd5) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  RtspDigestProvisionRequest sha_request{
      path, "operator", std::string(kRealm),
      RtspDigestAlgorithm::kSha256, false};
  RtspDigestProvisionRequest md5_request{path, "operator", std::string(kRealm),
                                         RtspDigestAlgorithm::kMd5, true};
  ASSERT_TRUE(
      ProvisionRtspDigestCredential(sha_request, Bytes("old-password")).ok());
  ASSERT_TRUE(
      ProvisionRtspDigestCredential(md5_request, Bytes("old-password")).ok());

  auto rotated =
      ProvisionRtspDigestCredential(sha_request, Bytes("new-password"));

  ASSERT_TRUE(rotated.ok()) << rotated.error().message;
  auto store = CreateStore(CompatibilityPolicy());
  ASSERT_TRUE(store->Reload(path).ok());
  auto sha_lookup =
      store->Lookup("operator", RtspDigestAlgorithm::kSha256);
  auto md5_lookup = store->Lookup("operator", RtspDigestAlgorithm::kMd5);
  auto expected_sha = ComputeRtspDigestHa1(
      RtspDigestAlgorithm::kSha256, "operator", kRealm,
      Bytes("new-password"));
  auto expected_md5 = ComputeRtspDigestHa1(
      RtspDigestAlgorithm::kMd5, "operator", kRealm, Bytes("old-password"));
  ASSERT_TRUE(sha_lookup.ok());
  ASSERT_TRUE(md5_lookup.ok());
  ASSERT_TRUE(expected_sha.ok());
  ASSERT_TRUE(expected_md5.ok());
  EXPECT_TRUE(sha_lookup.value().matched);
  EXPECT_TRUE(md5_lookup.value().matched);
  EXPECT_TRUE(RtspDigestConstantTimeEqual(
      {sha_lookup.value().ha1.data(), sha_lookup.value().ha1.size()},
      {expected_sha.value().data(), expected_sha.value().size()}));
  EXPECT_TRUE(RtspDigestConstantTimeEqual(
      {md5_lookup.value().ha1.data(), md5_lookup.value().ha1.size()},
      {expected_md5.value().data(), expected_md5.value().size()}));
}

TEST(RtspDigestCredentialsTest,
     AnotherUsersSha256DoesNotAuthorizeMd5Provisioning) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  RtspDigestProvisionRequest alice_sha{
      path, "alice", std::string(kRealm),
      RtspDigestAlgorithm::kSha256, true};
  RtspDigestProvisionRequest bob_md5{path, "bob", std::string(kRealm),
                                     RtspDigestAlgorithm::kMd5, true};
  ASSERT_TRUE(
      ProvisionRtspDigestCredential(alice_sha, Bytes("alice-pass")).ok());

  auto result =
      ProvisionRtspDigestCredential(bob_md5, Bytes("bob-pass"));

  ASSERT_FALSE(result.ok());
  ExpectCredentialError(result.error());
  auto store = CreateStore(CompatibilityPolicy());
  ASSERT_TRUE(store->Reload(path).ok());
  auto alice = store->Lookup("alice", RtspDigestAlgorithm::kSha256);
  auto bob = store->Lookup("bob", RtspDigestAlgorithm::kMd5);
  ASSERT_TRUE(alice.ok());
  ASSERT_TRUE(bob.ok());
  EXPECT_TRUE(alice.value().matched);
  EXPECT_FALSE(bob.value().matched);
}

TEST(RtspDigestCredentialsTest, RejectsInvalidPoliciesAndLookupAlgorithms) {
  const auto invalid = static_cast<RtspDigestAlgorithm>(99);
  std::vector<RtspDigestCredentialPolicy> policies;
  policies.push_back({"", {RtspDigestAlgorithm::kSha256}});
  policies.push_back({"bad:realm", {RtspDigestAlgorithm::kSha256}});
  policies.push_back({std::string(129U, 'r'),
                      {RtspDigestAlgorithm::kSha256}});
  policies.push_back({std::string(kRealm), {}});
  policies.push_back({std::string(kRealm), {RtspDigestAlgorithm::kMd5}});
  policies.push_back({std::string(kRealm),
                      {RtspDigestAlgorithm::kSha256,
                       RtspDigestAlgorithm::kSha256}});
  policies.push_back({std::string(kRealm),
                      {RtspDigestAlgorithm::kSha256, invalid}});

  for (auto& policy : policies) {
    auto created = RtspDigestCredentialStore::Create(std::move(policy));
    ASSERT_FALSE(created.ok());
    ExpectCredentialError(created.error());
  }

  auto store = CreateStore();
  auto invalid_lookup = store->Lookup("operator", invalid);
  auto disabled_lookup = store->Lookup("operator", RtspDigestAlgorithm::kMd5);
  ASSERT_FALSE(invalid_lookup.ok());
  ASSERT_FALSE(disabled_lookup.ok());
  ExpectCredentialError(invalid_lookup.error());
  ExpectCredentialError(disabled_lookup.error());
}

TEST(RtspDigestCredentialsTest, RejectsNonRegularEmptyAndOversizedFiles) {
  TemporaryDirectory directory;
  const auto empty = directory.File("empty");
  const auto oversized = directory.File("oversized");
  WriteFile(empty, "");
  WriteFile(oversized, std::string(65537U, 'x'));
  auto store = CreateStore();

  auto directory_result = store->Reload(directory.path());
  auto empty_result = store->Reload(empty);
  auto oversized_result = store->Reload(oversized);

  ASSERT_FALSE(directory_result.ok());
  ASSERT_FALSE(empty_result.ok());
  ASSERT_FALSE(oversized_result.ok());
  ExpectCredentialError(directory_result.error());
  ExpectCredentialError(empty_result.error());
  ExpectCredentialError(oversized_result.error());
}

TEST(RtspDigestCredentialsTest, AppliesInclusiveCredentialFileSizeBounds) {
  TemporaryDirectory directory;
  const auto one_byte = directory.File("one-byte");
  const auto maximum = directory.File("maximum-size");
  WriteFile(one_byte, "\n");
  std::string maximum_content(65536U, 'x');
  maximum_content.back() = '\n';
  WriteFile(maximum, maximum_content);
  auto store = CreateStore();

  auto one_byte_result = store->Reload(one_byte);
  auto maximum_result = store->Reload(maximum);

  ASSERT_FALSE(one_byte_result.ok());
  ASSERT_FALSE(maximum_result.ok());
  EXPECT_EQ(one_byte_result.error().message,
            "credential file format is invalid");
  EXPECT_EQ(maximum_result.error().message,
            "credential file format is invalid");
}

TEST(RtspDigestCredentialsTest, RejectsMalformedLineBoundariesAndFields) {
  TemporaryDirectory directory;
  const std::vector<std::pair<std::string, std::string>> invalid_files = {
      {"wrong-header", "cfdigest1\n" +
                           Record("operator", kRealm,
                                  RtspDigestAlgorithm::kSha256, "secret")},
      {"no-final-lf", "CFDIGEST1\noperator:rpi-camera:sha-256:" +
                          std::string(64U, '0')},
      {"crlf", "CFDIGEST1\r\noperator:rpi-camera:sha-256:" +
                   std::string(64U, '0') + "\r\n"},
      {"comment", "CFDIGEST1\n#comment\n"},
      {"too-few-fields", "CFDIGEST1\noperator:rpi-camera:sha-256\n"},
      {"too-many-fields", "CFDIGEST1\noperator:rpi-camera:sha-256:" +
                              std::string(64U, '0') + ":extra\n"},
      {"uppercase-algorithm", "CFDIGEST1\noperator:rpi-camera:SHA-256:" +
                                  std::string(64U, '0') + "\n"},
      {"space-username", "CFDIGEST1\nbad user:rpi-camera:sha-256:" +
                             std::string(64U, '0') + "\n"},
      {"long-username", "CFDIGEST1\n" + std::string(65U, 'u') +
                            ":rpi-camera:sha-256:" +
                            std::string(64U, '0') + "\n"},
      {"nul-username", std::string("CFDIGEST1\nbad\0user:rpi-camera:sha-256:",
                                    38U) +
                           std::string(64U, '0') + "\n"},
  };
  auto store = CreateStore();

  for (const auto& [name, content] : invalid_files) {
    const auto path = directory.File(name);
    WriteFile(path, content);
    auto result = store->Reload(path);
    ASSERT_FALSE(result.ok()) << name;
    ExpectCredentialError(result.error());
  }
}

TEST(RtspDigestCredentialsTest, AcceptsMaximumLengthVisibleUsername) {
  TemporaryDirectory directory;
  const auto path = directory.File("maximum-username");
  const std::string username(64U, 'u');
  WriteFile(path, CredentialFile({Record(username, kRealm,
                                        RtspDigestAlgorithm::kSha256,
                                        "secret")}));
  auto store = CreateStore();

  auto reloaded = store->Reload(path);
  auto lookup = store->Lookup(username, RtspDigestAlgorithm::kSha256);

  ASSERT_TRUE(reloaded.ok()) << reloaded.error().message;
  ASSERT_TRUE(lookup.ok()) << lookup.error().message;
  EXPECT_TRUE(lookup.value().matched);
}

TEST(RtspDigestCredentialsTest, AcceptsMaximumLengthVisibleRealm) {
  TemporaryDirectory directory;
  const auto path = directory.File("maximum-realm");
  const std::string realm(128U, 'r');
  WriteFile(path, CredentialFile({Record("operator", realm,
                                        RtspDigestAlgorithm::kSha256,
                                        "secret")}));
  auto store = CreateStore(Sha256Policy(realm));

  auto reloaded = store->Reload(path);
  auto lookup = store->Lookup("operator", RtspDigestAlgorithm::kSha256);

  ASSERT_TRUE(reloaded.ok()) << reloaded.error().message;
  ASSERT_TRUE(lookup.ok()) << lookup.error().message;
  EXPECT_TRUE(lookup.value().matched);
}

TEST(RtspDigestCredentialsTest,
     CredentialErrorsDoNotExposeSensitiveInputs) {
  TemporaryDirectory directory;
  const auto path = directory.File("secret-path-fragment");
  WriteFile(path,
            "CFDIGEST1\nsecret-user:secret-realm:sha-256:secret-record\n");
  auto store = CreateStore();

  auto result = store->Reload(path);

  ASSERT_FALSE(result.ok());
  ExpectCredentialError(result.error());
  EXPECT_EQ(result.error().message, "credential file format is invalid");
  EXPECT_EQ(result.error().message.find("secret"), std::string::npos);
  EXPECT_EQ(result.error().message.find(path.string()), std::string::npos);
}

TEST(RtspDigestCredentialsTest,
     ProvisionPreservesRecordsAndWritesUsernameAlgorithmOrder) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  RtspDigestProvisionRequest bob{path, "bob", std::string(kRealm),
                                 RtspDigestAlgorithm::kSha256, true};
  RtspDigestProvisionRequest alice_sha{
      path, "alice", std::string(kRealm),
      RtspDigestAlgorithm::kSha256, true};
  RtspDigestProvisionRequest alice_md5{
      path, "alice", std::string(kRealm), RtspDigestAlgorithm::kMd5, true};

  ASSERT_TRUE(ProvisionRtspDigestCredential(bob, Bytes("bob-pass")).ok());
  ASSERT_TRUE(
      ProvisionRtspDigestCredential(alice_sha, Bytes("alice-pass")).ok());
  ASSERT_TRUE(
      ProvisionRtspDigestCredential(alice_md5, Bytes("alice-pass")).ok());

  const std::string expected =
      CredentialFile({Record("alice", kRealm, RtspDigestAlgorithm::kSha256,
                             "alice-pass"),
                      Record("alice", kRealm, RtspDigestAlgorithm::kMd5,
                             "alice-pass"),
                      Record("bob", kRealm, RtspDigestAlgorithm::kSha256,
                             "bob-pass")});
  EXPECT_EQ(ReadFileForTest(path), expected);
}

TEST(RtspDigestCredentialsTest,
     ProvisionRejectsInvalidExistingFileWithoutReplacingIt) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  const std::string invalid = "CFDIGEST1\ninvalid-existing-record\n";
  WriteFile(path, invalid);
  RtspDigestProvisionRequest request{path, "operator", std::string(kRealm),
                                     RtspDigestAlgorithm::kSha256, false};

  auto result = ProvisionRtspDigestCredential(request, Bytes("secret"));

  ASSERT_FALSE(result.ok());
  ExpectCredentialError(result.error());
  EXPECT_EQ(ReadFileForTest(path), invalid);
  EXPECT_EQ(DirectoryEntryCount(directory.path()), 1U);
}

TEST(RtspDigestCredentialsTest, ProvisionRejectsInvalidRequests) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  const auto invalid = static_cast<RtspDigestAlgorithm>(99);
  std::vector<RtspDigestProvisionRequest> requests = {
      {path, "", std::string(kRealm), RtspDigestAlgorithm::kSha256, false},
      {path, std::string(65U, 'u'), std::string(kRealm),
       RtspDigestAlgorithm::kSha256, false},
      {path, "bad user", std::string(kRealm),
       RtspDigestAlgorithm::kSha256, false},
      {path, "operator", "", RtspDigestAlgorithm::kSha256, false},
      {path, "operator", "bad:realm", RtspDigestAlgorithm::kSha256, false},
      {path, "operator", std::string(kRealm), invalid, false},
      {path, "operator", std::string(kRealm), RtspDigestAlgorithm::kMd5,
       false},
  };

  for (const auto& request : requests) {
    auto result = ProvisionRtspDigestCredential(request, Bytes("secret"));
    ASSERT_FALSE(result.ok());
    ExpectCredentialError(result.error());
  }
  EXPECT_FALSE(std::filesystem::exists(path));
}

TEST(RtspDigestCredentialsTest,
     ProvisionFailureBeforeRenameLeavesNoTemporaryFile) {
  TemporaryDirectory directory;
  const auto missing_parent = directory.File("missing") / "credentials";
  RtspDigestProvisionRequest request{
      missing_parent, "operator", std::string(kRealm),
      RtspDigestAlgorithm::kSha256, false};

  auto result = ProvisionRtspDigestCredential(request, Bytes("secret"));

  ASSERT_FALSE(result.ok());
  ExpectCredentialError(result.error());
  EXPECT_EQ(DirectoryEntryCount(directory.path()), 0U);
}

TEST(RtspDigestCredentialsTest,
     ProvisionWriteFailureAfterTempCreationCleansTemporaryFile) {
  TemporaryDirectory directory;
  const auto path = directory.File("credentials");
  struct rlimit current_limit {};
  ASSERT_EQ(::getrlimit(RLIMIT_FSIZE, &current_limit), 0);
  if (current_limit.rlim_max != RLIM_INFINITY &&
      current_limit.rlim_max < 1U) {
    GTEST_SKIP() << "RLIMIT_FSIZE hard limit cannot support this test";
  }
  RtspDigestProvisionRequest request{path, "operator", std::string(kRealm),
                                     RtspDigestAlgorithm::kSha256, false};

  auto result = [&] {
    ScopedFileSizeLimit limit(1U);
    return ProvisionRtspDigestCredential(request, Bytes("secret"));
  }();

  ASSERT_FALSE(result.ok());
  ExpectCredentialError(result.error());
  EXPECT_EQ(result.error().message, "credential file could not be replaced");
  EXPECT_FALSE(std::filesystem::exists(path));
  EXPECT_EQ(DirectoryEntryCount(directory.path()), 0U);
}

}  // namespace
