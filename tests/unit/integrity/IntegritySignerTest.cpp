#include "IntegritySignerTestAccess.hpp"
#include "IntegrityTestSupport.hpp"

#include "camera_firmware/crypto/OpenSslCryptoProvider.hpp"
#include "camera_firmware/integrity/IntegritySigner.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#include <unistd.h>

#include <gtest/gtest.h>

extern "C" void __real_OPENSSL_cleanse(void* pointer, std::size_t length);

namespace {

using camera_firmware::integrity::testing::TemporaryDirectory;
using camera_firmware::integrity::testing::WriteFile;
using camera_firmware::integrity::testing::
    WriteIntegrityArtifactAtomicallyWithPrePublishHook;

bool observe_pem_remainder_cleanse{false};
std::size_t pem_remainder_cleanse_calls{0U};

std::string PrivatePem(EVP_PKEY* key) {
  camera_firmware::integrity::testing::BioPtr bio(BIO_new(BIO_s_mem()),
                                                  BIO_free);
  if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0,
                                       nullptr, nullptr) != 1) {
    throw std::runtime_error("PEM_write_bio_PrivateKey");
  }
  return camera_firmware::integrity::testing::ReadBio(bio.get());
}

TEST(IntegritySignerTest, RejectsDestinationChangedToSymlinkBeforePublication) {
  TemporaryDirectory directory;
  const auto output = directory.path() / "manifest.yaml";
  const auto protected_target = directory.path() / "protected";
  WriteFile(output, "old manifest\n");
  WriteFile(protected_target, "protected\n");
  const std::array<unsigned char, 4U> replacement{'n', 'e', 'w', '\n'};

  const auto result = WriteIntegrityArtifactAtomicallyWithPrePublishHook(
      output, replacement, [&] {
        ASSERT_TRUE(std::filesystem::remove(output));
        ASSERT_EQ(::symlink(protected_target.c_str(), output.c_str()), 0);
      });

  EXPECT_FALSE(result.ok());
  EXPECT_TRUE(std::filesystem::is_symlink(output));
  std::ifstream protected_input(protected_target, std::ios::binary);
  const std::string protected_bytes{
      std::istreambuf_iterator<char>(protected_input),
      std::istreambuf_iterator<char>()};
  EXPECT_EQ(protected_bytes, "protected\n");
}

TEST(IntegritySignerTest, CleansesTrailingPrivatePemInspectionBuffer) {
  TemporaryDirectory directory;
  camera_firmware::integrity::testing::EphemeralEd25519Key first;
  camera_firmware::integrity::testing::EphemeralEd25519Key second;
  const auto private_key_path = directory.path() / "private.pem";
  WriteFile(private_key_path,
            PrivatePem(first.key()) + PrivatePem(second.key()));
  ASSERT_EQ(::chmod(private_key_path.c_str(), 0600), 0);
  const std::array<unsigned char, 4U> manifest{'t', 'e', 's', 't'};

  camera_firmware::crypto::OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  pem_remainder_cleanse_calls = 0U;
  observe_pem_remainder_cleanse = true;
  const auto signed_manifest =
      camera_firmware::integrity::SignIntegrityManifest(
          manifest, private_key_path, provider);
  observe_pem_remainder_cleanse = false;

  EXPECT_FALSE(signed_manifest.ok());
  EXPECT_GE(pem_remainder_cleanse_calls, 1U);
}

}  // namespace

extern "C" void __wrap_OPENSSL_cleanse(void* pointer, std::size_t length) {
  __real_OPENSSL_cleanse(pointer, length);
  if (observe_pem_remainder_cleanse && length == 256U) {
    ++pem_remainder_cleanse_calls;
  }
}
