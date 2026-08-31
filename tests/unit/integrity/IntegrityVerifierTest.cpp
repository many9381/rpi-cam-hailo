#include "IntegrityTestSupport.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <gtest/gtest.h>

#include "camera_firmware/crypto/OpenSslCryptoProvider.hpp"
#include "camera_firmware/integrity/IntegrityVerifier.hpp"
#include "camera_firmware/integrity/SafeFileDigest.hpp"
#include "IntegrityVerifierTestAccess.hpp"

namespace {

thread_local bool g_fail_test_allocations = false;

void* AllocateForIntegrityTest(std::size_t size) {
  if (g_fail_test_allocations) {
    throw std::bad_alloc{};
  }
  if (void* allocation = std::malloc(size == 0U ? 1U : size)) {
    return allocation;
  }
  throw std::bad_alloc{};
}

class AllocationFailureReset {
 public:
  ~AllocationFailureReset() { g_fail_test_allocations = false; }
};

}  // namespace

void* operator new(std::size_t size) { return AllocateForIntegrityTest(size); }
void* operator new[](std::size_t size) { return AllocateForIntegrityTest(size); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
  try {
    return AllocateForIntegrityTest(size);
  } catch (...) {
    return nullptr;
  }
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
  try {
    return AllocateForIntegrityTest(size);
  } catch (...) {
    return nullptr;
  }
}
void operator delete(void* allocation) noexcept { std::free(allocation); }
void operator delete[](void* allocation) noexcept { std::free(allocation); }
void operator delete(void* allocation, const std::nothrow_t&) noexcept {
  std::free(allocation);
}
void operator delete[](void* allocation, const std::nothrow_t&) noexcept {
  std::free(allocation);
}
void operator delete(void* allocation, std::size_t) noexcept {
  std::free(allocation);
}
void operator delete[](void* allocation, std::size_t) noexcept {
  std::free(allocation);
}

namespace camera_firmware::integrity {
namespace {

using testing::EphemeralEd25519Key;
using testing::EphemeralEcKey;
using testing::TemporaryDirectory;
using testing::AppendFile;
using testing::WriteFile;

std::string Entry(std::string_view id, std::string_view category,
                  const std::filesystem::path& path, std::string_view digest) {
  return "  - id: " + std::string(id) + "\n"
         "    category: " + std::string(category) + "\n"
         "    path: " + path.string() + "\n"
         "    sha256: " + std::string(digest) + "\n";
}

std::string DigestFor(const std::filesystem::path& path) {
  const auto digest = DigestRegularFile(path);
  EXPECT_TRUE(digest.ok());
  return HexSha256(digest.value());
}

struct SignedManifest {
  TemporaryDirectory directory;
  EphemeralEd25519Key key;
  std::filesystem::path firmware = directory.path() / "firmware";
  std::filesystem::path config = directory.path() / "config.yaml";
  std::filesystem::path kernel = directory.path() / "kernel";
  std::filesystem::path manifest = directory.path() / "manifest.yaml";
  std::filesystem::path signature = directory.path() / "manifest.sig";

  SignedManifest() {
    WriteFile(firmware, "firmware");
    WriteFile(config, "configuration");
    WriteFile(kernel, "kernel");
  }

  [[nodiscard]] std::string Text(std::string_view extra = {}) const {
    return "schema_version: 1\nproduct: camera-firmware\n"
           "created_at: '2026-07-19T00:00:00Z'\nfiles:\n" +
           Entry("firmware", "firmware", firmware, DigestFor(firmware)) +
           Entry("configuration", "configuration", config, DigestFor(config)) +
           Entry("kernel", "kernel", kernel, DigestFor(kernel)) + std::string(extra);
  }

  void WriteSigned(std::string_view text) {
    WriteFile(manifest, text);
    const auto signature_bytes = key.Sign(text);
    WriteFile(signature, {reinterpret_cast<const char*>(signature_bytes.data()),
                          signature_bytes.size()});
  }
};

TEST(IntegrityVerifierTest, VerificationRefusesWhenProviderNotSelfTested) {
  EphemeralEd25519Key key;
  const std::string text = "signed bytes";
  const auto signature = key.Sign(text);
  const std::span<const unsigned char> message(
      reinterpret_cast<const unsigned char*>(text.data()), text.size());
  const std::string public_pem = key.PublicPem();
  crypto::OpenSslCryptoProvider provider;  // deliberately not self-tested

  const auto result =
      VerifyEd25519Signature(message, signature, public_pem, provider);

  ASSERT_FALSE(result.ok());
  EXPECT_NE(result.error().code, "E_CRYPTO_UNAVAILABLE")
      << "the provider error must be folded into an integrity error";
}

TEST(IntegrityVerifierTest, VerifiesSignedManifestAndReturnsOrderedReport) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  const auto result = VerifyIntegrityManifest(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(), fixture.firmware,
      fixture.config, provider);

  ASSERT_TRUE(result.ok());
  EXPECT_TRUE(result.value().passed);
  ASSERT_EQ(result.value().items.size(), 3U);
  EXPECT_EQ(result.value().items[0].id, "firmware");
  EXPECT_EQ(result.value().items[1].id, "configuration");
  EXPECT_EQ(result.value().items[2].id, "kernel");
  EXPECT_EQ(result.value().items[0].code, "OK");
}

TEST(IntegrityVerifierTest, RejectsInvalidSignatureLengths) {
  EphemeralEd25519Key key;
  const std::string text = "signed bytes";
  const auto signature = key.Sign(text);
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  for (const std::size_t length : {63U, 65U}) {
    std::vector<unsigned char> invalid(length, 0U);
    std::copy_n(signature.begin(), std::min(signature.size(), invalid.size()),
                invalid.begin());
    const auto result = VerifyEd25519Signature(
        {reinterpret_cast<const unsigned char*>(text.data()), text.size()}, invalid,
        key.PublicPem(), provider);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_SIGNATURE_FORMAT");
  }
}

TEST(IntegrityVerifierTest, RejectsWrongLengthSignatureArtifacts) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  for (const std::size_t length : {63U, 65U}) {
    const std::string invalid(length, 'x');
    WriteFile(fixture.signature, invalid);
    const auto result = VerifyIntegrityManifest(
        fixture.manifest, fixture.signature, fixture.key.PublicPem(), fixture.firmware,
        fixture.config, provider);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_SIGNATURE_FORMAT");
  }
}

TEST(IntegrityVerifierTest, RejectsChangedManifestWrongKeyAndMalformedPem) {
  SignedManifest fixture;
  const std::string text = fixture.Text();
  fixture.WriteSigned(text);
  const auto signature = fixture.key.Sign(text);
  EphemeralEd25519Key wrong_key;
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  for (const auto [bytes, pem] : {
           std::pair<std::string, std::string>{text + "# changed\n", fixture.key.PublicPem()},
           {text, wrong_key.PublicPem()},
           {text, "not a PEM"},
       }) {
    const auto result = VerifyEd25519Signature(
        {reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()}, signature,
        pem, provider);
    ASSERT_FALSE(result.ok());
    EXPECT_TRUE(result.error().code == "E_INTEGRITY_SIGNATURE_INVALID" ||
                result.error().code == "E_INTEGRITY_PUBLIC_KEY");
    EXPECT_EQ(result.error().message.find("BEGIN"), std::string::npos);
  }
}

TEST(IntegrityVerifierTest, RejectsNonEd25519AndTrailingPublicPems) {
  SignedManifest fixture;
  const std::string text = fixture.Text();
  const auto signature = fixture.key.Sign(text);
  EphemeralEcKey non_ed25519;
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  for (const std::string& pem : {non_ed25519.PublicPem(),
                                 fixture.key.PublicPem() + "trailing-data"}) {
    const auto result = VerifyEd25519Signature(
        {reinterpret_cast<const unsigned char*>(text.data()), text.size()}, signature, pem,
        provider);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_PUBLIC_KEY");
  }
}

TEST(IntegrityVerifierTest, RejectsManifestAndSignatureSymlinks) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  const auto manifest_link = fixture.directory.path() / "manifest-link";
  const auto signature_link = fixture.directory.path() / "signature-link";
  std::filesystem::create_symlink(fixture.manifest, manifest_link);
  std::filesystem::create_symlink(fixture.signature, signature_link);
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  for (const auto& [manifest, signature] : {
           std::pair{manifest_link, fixture.signature},
           {fixture.manifest, signature_link},
       }) {
    const auto result = VerifyIntegrityManifest(
        manifest, signature, fixture.key.PublicPem(), fixture.firmware, fixture.config,
        provider);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_ARTIFACT_TYPE");
  }
}

TEST(IntegrityVerifierTest, RejectsInvalidArtifactPathsAtPublicBoundary) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  std::string nul_manifest = fixture.manifest.string();
  nul_manifest.push_back('\0');
  nul_manifest += "suffix";
  std::string nul_signature = fixture.signature.string();
  nul_signature.push_back('\0');
  nul_signature += "suffix";
  const std::filesystem::path overlong = "/" + std::string(4096U, 'a');
  const std::filesystem::path noncanonical =
      fixture.directory.path() / "nested/../manifest.yaml";

  for (const auto& [manifest, signature] : {
           std::pair{std::filesystem::path{}, fixture.signature},
           {std::filesystem::path{nul_manifest}, fixture.signature},
           {overlong, fixture.signature},
           {noncanonical, fixture.signature},
           {fixture.manifest, std::filesystem::path{}},
           {fixture.manifest, std::filesystem::path{nul_signature}},
           {fixture.manifest, overlong},
       }) {
    const auto result = VerifyIntegrityManifest(
        manifest, signature, fixture.key.PublicPem(), fixture.firmware,
        fixture.config, provider);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_ARTIFACT_PATH");
    EXPECT_EQ(result.error().message.find(fixture.directory.path().string()),
              std::string::npos);
  }
}

TEST(IntegrityVerifierTest, RejectsInvalidActivePathsAtPublicBoundary) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  std::string nul_config = fixture.config.string();
  nul_config.push_back('\0');
  nul_config += "suffix";
  std::string nul_executable = fixture.firmware.string();
  nul_executable.push_back('\0');
  nul_executable += "suffix";
  const std::filesystem::path overlong = "/" + std::string(4096U, 'a');
  for (const auto& [executable, config] : {
           std::pair{std::filesystem::path{}, fixture.config},
           {fixture.firmware, std::filesystem::path{}},
           {std::filesystem::path{nul_executable}, fixture.config},
           {overlong, fixture.config},
           {fixture.firmware, std::filesystem::path{nul_config}},
           {fixture.firmware, overlong},
       }) {
    const auto result = VerifyIntegrityManifest(
        fixture.manifest, fixture.signature, fixture.key.PublicPem(), executable,
        config, provider);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_CONTRACT");
  }
}

TEST(IntegrityVerifierTest, RejectsNonRegularArtifactsWithoutBlocking) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  const auto fifo = fixture.directory.path() / "manifest.fifo";
  ASSERT_EQ(::mkfifo(fifo.c_str(), 0600), 0) << std::strerror(errno);
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  for (const auto& manifest : {
           fifo,
           fixture.directory.path(),
           std::filesystem::path{"/dev/null"},
       }) {
    const auto result = VerifyIntegrityManifest(
        manifest, fixture.signature, fixture.key.PublicPem(), fixture.firmware,
        fixture.config, provider);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_ARTIFACT_TYPE");
  }
}

TEST(IntegrityVerifierTest, ReturnsEveryEntryFailureWithoutLeakingPathsOrHashes) {
  SignedManifest fixture;
  const auto library = fixture.directory.path() / "library";
  WriteFile(library, "library");
  fixture.WriteSigned(fixture.Text(Entry("library", "library", library,
                                        DigestFor(library))));
  WriteFile(fixture.config, "changed config");
  WriteFile(library, "changed library");
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  const auto result = VerifyIntegrityManifest(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(), fixture.firmware,
      fixture.config, provider);

  ASSERT_TRUE(result.ok());
  EXPECT_FALSE(result.value().passed);
  ASSERT_EQ(result.value().items.size(), 4U);
  EXPECT_TRUE(result.value().items[0].passed);
  EXPECT_FALSE(result.value().items[1].passed);
  EXPECT_FALSE(result.value().items[3].passed);
  EXPECT_EQ(result.value().items[1].code, "E_INTEGRITY_DIGEST_MISMATCH");
  EXPECT_EQ(result.value().items[1].id, "configuration");
  EXPECT_EQ(result.value().items[1].id.find(fixture.config.string()), std::string::npos);
}

TEST(IntegrityVerifierTest, RejectsManifestContractAndChecksSignatureBeforeYaml) {
  SignedManifest fixture;
  const std::string malformed = "not: [valid yaml";
  fixture.WriteSigned(malformed);
  const auto invalid_signature = std::array<unsigned char, 64U>{};
  WriteFile(fixture.signature, {reinterpret_cast<const char*>(invalid_signature.data()),
                                invalid_signature.size()});
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  const auto signature_first = VerifyIntegrityManifest(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(), fixture.firmware,
      fixture.config, provider);
  ASSERT_FALSE(signature_first.ok());
  EXPECT_EQ(signature_first.error().code, "E_INTEGRITY_SIGNATURE_INVALID");

  fixture.WriteSigned(fixture.Text());
  const auto contract = VerifyIntegrityManifest(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(),
      std::filesystem::path("relative-executable"), fixture.config, provider);
  ASSERT_FALSE(contract.ok());
  EXPECT_EQ(contract.error().code, "E_INTEGRITY_MANIFEST_CONTRACT");
}

TEST(IntegrityVerifierTest, RejectsOversizedManifestAndActivePathMismatch) {
  SignedManifest fixture;
  std::string oversized(1024U * 1024U + 1U, '#');
  WriteFile(fixture.manifest, oversized);
  const std::array<unsigned char, 64U> signature{};
  WriteFile(fixture.signature,
            {reinterpret_cast<const char*>(signature.data()), signature.size()});
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  const auto oversized_result = VerifyIntegrityManifest(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(), fixture.firmware,
      fixture.config, provider);
  ASSERT_FALSE(oversized_result.ok());
  EXPECT_EQ(oversized_result.error().code, "E_INTEGRITY_ARTIFACT_SIZE");

  fixture.WriteSigned(fixture.Text());
  const auto mismatch = VerifyIntegrityManifest(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(),
      fixture.directory.path() / "other-firmware", fixture.config, provider);
  ASSERT_FALSE(mismatch.ok());
  EXPECT_EQ(mismatch.error().code, "E_INTEGRITY_MANIFEST_CONTRACT");
}

TEST(IntegrityVerifierTest, RejectsManifestMissingRequiredKernelCategory) {
  SignedManifest fixture;
  const std::string missing_kernel =
      "schema_version: 1\nproduct: camera-firmware\n"
      "created_at: '2026-07-19T00:00:00Z'\nfiles:\n" +
      Entry("firmware", "firmware", fixture.firmware, DigestFor(fixture.firmware)) +
      Entry("configuration", "configuration", fixture.config, DigestFor(fixture.config));
  fixture.WriteSigned(missing_kernel);
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  const auto result = VerifyIntegrityManifest(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(), fixture.firmware,
      fixture.config, provider);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_CONTRACT");
}

TEST(IntegrityVerifierTest, RejectsWrongAndNonCanonicalActiveConfigInputs) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  for (const auto& config : {fixture.directory.path() / "other-config",
                             fixture.directory.path() / "nested/../config.yaml"}) {
    const auto result = VerifyIntegrityManifest(
        fixture.manifest, fixture.signature, fixture.key.PublicPem(), fixture.firmware,
        config, provider);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_CONTRACT");
  }
}

TEST(IntegrityVerifierTest, RejectsManifestMutationAndReplacementWhileReading) {
  for (const bool replace : {false, true}) {
    SignedManifest fixture;
    fixture.WriteSigned(fixture.Text());
    crypto::OpenSslCryptoProvider provider;
    ASSERT_TRUE(provider.SelfTest().ok());
    const auto replacement = fixture.directory.path() / "replacement";
    if (replace) {
      WriteFile(replacement, "replacement manifest");
    }
    const auto result = testing::VerifyIntegrityManifestWithArtifactReadHook(
        fixture.manifest, fixture.signature, fixture.key.PublicPem(), fixture.firmware,
        fixture.config, provider, [&] {
          if (replace) {
            std::filesystem::rename(replacement, fixture.manifest);
          } else {
            WriteFile(fixture.manifest, "mutated manifest bytes");
          }
        });
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_ARTIFACT_CHANGED");
  }
}

TEST(IntegrityVerifierTest, RejectsSignatureMutationAndReplacementWhileReading) {
  for (const bool replace : {false, true}) {
    SignedManifest fixture;
    fixture.WriteSigned(fixture.Text());
    crypto::OpenSslCryptoProvider provider;
    ASSERT_TRUE(provider.SelfTest().ok());
    const auto replacement = fixture.directory.path() / "replacement.sig";
    if (replace) {
      WriteFile(replacement, std::string(64U, 'r'));
    }
    std::size_t artifact_index = 0U;
    const auto result = testing::VerifyIntegrityManifestWithArtifactReadHook(
        fixture.manifest, fixture.signature, fixture.key.PublicPem(),
        fixture.firmware, fixture.config, provider, [&] {
          if (artifact_index++ != 1U) {
            return;
          }
          if (replace) {
            std::filesystem::rename(replacement, fixture.signature);
          } else {
            WriteFile(fixture.signature, std::string(64U, 'm'));
          }
        });
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_ARTIFACT_CHANGED");
  }
}

TEST(IntegrityVerifierTest, RejectsArtifactGrowthWhileReading) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  std::size_t artifact_index = 0U;

  const auto result = testing::VerifyIntegrityManifestWithArtifactReadHook(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(),
      fixture.firmware, fixture.config, provider, [&] {
        if (artifact_index++ == 0U) {
          AppendFile(fixture.manifest, "# growth\n");
        }
      });

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_ARTIFACT_CHANGED");
}

TEST(IntegrityVerifierTest, RetriesInterruptedArtifactReads) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  std::size_t read_calls = 0U;
  testing::IntegrityVerifierTestHooks hooks;
  hooks.read = [&](int descriptor, void* buffer, std::size_t size) -> ssize_t {
    if (read_calls++ == 0U) {
      errno = EINTR;
      return -1;
    }
    return ::read(descriptor, buffer, size);
  };

  const auto result = testing::VerifyIntegrityManifestWithTestHooks(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(),
      fixture.firmware, fixture.config, provider, std::move(hooks));

  ASSERT_TRUE(result.ok()) << result.error().message;
  EXPECT_TRUE(result.value().passed);
  EXPECT_GT(read_calls, 1U);
}

TEST(IntegrityVerifierTest, BoundsRepeatedInterruptedArtifactReads) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  std::size_t read_calls = 0U;
  testing::IntegrityVerifierTestHooks hooks;
  hooks.read = [&](int, void*, std::size_t) -> ssize_t {
    ++read_calls;
    errno = EINTR;
    return -1;
  };

  const auto result = testing::VerifyIntegrityManifestWithTestHooks(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(),
      fixture.firmware, fixture.config, provider, std::move(hooks));

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_ARTIFACT_READ");
  EXPECT_EQ(read_calls, 4U);
}

TEST(IntegrityVerifierTest, ConvertsReportAllocationFailuresToStableError) {
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  for (const auto expected : {
           testing::VerifierFaultPoint::kReportReserve,
           testing::VerifierFaultPoint::kReportItemCopy,
           testing::VerifierFaultPoint::kReportItemAppend,
       }) {
    SignedManifest fixture;
    fixture.WriteSigned(fixture.Text());
    testing::IntegrityVerifierTestHooks hooks;
    hooks.inject_fault = [expected](testing::VerifierFaultPoint actual) {
      if (actual == expected) {
        throw std::bad_alloc{};
      }
    };

    const auto result = testing::VerifyIntegrityManifestWithTestHooks(
        fixture.manifest, fixture.signature, fixture.key.PublicPem(),
        fixture.firmware, fixture.config, provider, std::move(hooks));

    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_RESOURCE");
    EXPECT_EQ(result.error().message.find(fixture.directory.path().string()),
              std::string::npos);
  }
}

TEST(IntegrityVerifierTest, ConvertsOrdinaryReportExceptionsToStableError) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  testing::IntegrityVerifierTestHooks hooks;
  hooks.inject_fault = [](testing::VerifierFaultPoint point) {
    if (point == testing::VerifierFaultPoint::kReportItemCopy) {
      throw std::runtime_error("injected report copy failure");
    }
  };

  const auto result = testing::VerifyIntegrityManifestWithTestHooks(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(),
      fixture.firmware, fixture.config, provider, std::move(hooks));

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_RESOURCE");
  EXPECT_EQ(result.error().message.find("injected"), std::string::npos);
}

TEST(IntegrityVerifierTest, ReturnsStaticErrorDuringSustainedAllocationFailure) {
  SignedManifest fixture;
  fixture.WriteSigned(fixture.Text());
  crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());
  testing::IntegrityVerifierTestHooks hooks;
  hooks.inject_fault = [](testing::VerifierFaultPoint point) {
    if (point == testing::VerifierFaultPoint::kReportReserve) {
      g_fail_test_allocations = true;
      throw std::bad_alloc{};
    }
  };
  AllocationFailureReset reset_allocations;

  const auto result = testing::VerifyIntegrityManifestWithTestHooks(
      fixture.manifest, fixture.signature, fixture.key.PublicPem(),
      fixture.firmware, fixture.config, provider, std::move(hooks));
  g_fail_test_allocations = false;

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_RESOURCE");
}

}  // namespace
}  // namespace camera_firmware::integrity
