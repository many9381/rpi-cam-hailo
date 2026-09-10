#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "camera_firmware/crypto/OpenSslCryptoProvider.hpp"

namespace camera_firmware::crypto {
namespace {

common::SecureBytes Bytes(std::string_view text) {
  common::SecureBytes value;
  value.resize(text.size());
  std::copy(text.begin(), text.end(), value.data());
  return value;
}

TEST(OpenSslCryptoProviderTest, StartsUninitializedAndRefusesEveryOperation) {
  OpenSslCryptoProvider provider;
  ASSERT_EQ(provider.Status(), ProviderStatus::kUninitialized);

  const std::array<unsigned char, kEd25519SeedBytes> seed{};
  const std::array<unsigned char, kEd25519PublicKeyBytes> public_key{};
  const std::array<unsigned char, kEd25519SignatureBytes> signature{};
  const std::array<unsigned char, kAesGcmKeyBytes> key{};
  const std::array<unsigned char, kAesGcmNonceBytes> nonce{};
  const std::array<unsigned char, 16U> payload{};
  std::array<unsigned char, 16U> out{};
  std::array<unsigned char, kAesGcmTagBytes> tag{};

  const auto expect_unavailable = [](const auto& result) {
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_CRYPTO_UNAVAILABLE");
  };

  expect_unavailable(provider.RandomBytes(16U));
  expect_unavailable(provider.RandomBytesPrivate(16U));
  expect_unavailable(provider.DeriveKeyPbkdf2(Bytes("pw"), seed, 1000U, 32U));
  expect_unavailable(provider.SignEd25519(payload, seed));
  expect_unavailable(provider.VerifyEd25519(payload, signature, public_key));
  expect_unavailable(provider.SealAesGcm(key, nonce, payload, {}, out, tag));
  expect_unavailable(provider.OpenAesGcm(key, nonce, payload, {}, tag, out));
}

TEST(OpenSslCryptoProviderTest, SelfTestPassesAndUnlocksOperations) {
  OpenSslCryptoProvider provider;

  auto report = provider.SelfTest();
  ASSERT_TRUE(report.ok()) << report.error().message;
  EXPECT_TRUE(report.value().passed);
  EXPECT_FALSE(report.value().items.empty());
  for (const auto& item : report.value().items) {
    EXPECT_TRUE(item.passed) << item.id << " " << item.code;
  }
  EXPECT_EQ(provider.Status(), ProviderStatus::kOperational);

  auto random = provider.RandomBytes(32U);
  ASSERT_TRUE(random.ok()) << random.error().message;
  EXPECT_EQ(random.value().size(), 32U);

  auto random_private = provider.RandomBytesPrivate(32U);
  ASSERT_TRUE(random_private.ok()) << random_private.error().message;
  EXPECT_EQ(random_private.value().size(), 32U);
}

TEST(OpenSslCryptoProviderTest, SelfTestIsRepeatable) {
  OpenSslCryptoProvider provider;

  auto first = provider.SelfTest();
  ASSERT_TRUE(first.ok()) << first.error().message;
  ASSERT_TRUE(first.value().passed);
  ASSERT_FALSE(first.value().items.empty());
  std::vector<std::string> first_ids;
  for (const auto& item : first.value().items) {
    first_ids.push_back(item.id);
  }

  auto second = provider.SelfTest();
  ASSERT_TRUE(second.ok()) << second.error().message;

  // The manual self-test route (POST /api/v1/system/self-tests) depends on
  // every call re-running all four checks, not short-circuiting because
  // status_ already reads kOperational from the first call. Assert the
  // second report actually carries the same item set, all passing, rather
  // than merely being `.ok()` (which a short-circuit returning an empty
  // report would also satisfy).
  EXPECT_TRUE(second.value().passed);
  ASSERT_EQ(second.value().items.size(), first_ids.size());
  for (std::size_t index = 0U; index < second.value().items.size(); ++index) {
    const auto& item = second.value().items[index];
    EXPECT_EQ(item.id, first_ids[index]);
    EXPECT_TRUE(item.passed) << item.id << " " << item.code;
  }
  EXPECT_EQ(provider.Status(), ProviderStatus::kOperational);
}

// ---------------------------------------------------------------------------
// Known-answer tests.
//
// Every expected value below is a literal copied from a published source (see
// the comment above each vector); none is computed by the code under test.
// ---------------------------------------------------------------------------

// PBKDF2-HMAC-SHA256, password = "password", salt = "salt", 4096 iterations,
// 32-byte output.
//
// RFC 6070 defines exactly this password/salt/iteration-count combination,
// but only for PBKDF2-HMAC-SHA1 (RFC 6070 has no SHA-256 output). The 32-byte
// SHA-256 expected value below was computed independently with Python 3's
// standard-library `hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 4096,
// dklen=32)`, and its first 20 bytes were cross-checked against the
// independent, pure-Go vector in golang.org/x/crypto's
// `pbkdf2/pbkdf2_test.go` `sha256TestVectors` table (itself attributed there
// to the widely-cited
// http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors),
// which matched byte for byte.
constexpr std::array<unsigned char, 8U> kPbkdf2Password{'p', 'a', 's', 's',
                                                        'w', 'o', 'r', 'd'};
constexpr std::array<unsigned char, 4U> kPbkdf2Salt{'s', 'a', 'l', 't'};
constexpr std::uint32_t kPbkdf2Iterations = 4096U;
constexpr std::array<unsigned char, 32U> kPbkdf2Expected{
    0xc5U, 0xe4U, 0x78U, 0xd5U, 0x92U, 0x88U, 0xc8U, 0x41U, 0xaaU, 0x53U, 0x0dU,
    0xb6U, 0x84U, 0x5cU, 0x4cU, 0x8dU, 0x96U, 0x28U, 0x93U, 0xa0U, 0x01U, 0xceU,
    0x4eU, 0x11U, 0xa4U, 0x96U, 0x38U, 0x73U, 0xaaU, 0x98U, 0x13U, 0x4aU};

TEST(OpenSslCryptoProviderTest, Pbkdf2Hmac256KnownAnswer) {
  OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  common::SecureBytes password;
  password.assign(kPbkdf2Password.data(), kPbkdf2Password.size());
  auto derived =
      provider.DeriveKeyPbkdf2(password, kPbkdf2Salt, kPbkdf2Iterations, 32U);
  ASSERT_TRUE(derived.ok()) << derived.error().message;
  ASSERT_EQ(derived.value().size(), kPbkdf2Expected.size());
  EXPECT_TRUE(std::equal(kPbkdf2Expected.begin(), kPbkdf2Expected.end(),
                         derived.value().data()));
}

// Ed25519, RFC 8032 section 7.1, "TEST 1" (the zero-length message case).
// Bytes below were extracted programmatically from the RFC's own text
// (https://www.rfc-editor.org/rfc/rfc8032.txt, lines 1306-1320) and then
// independently cross-checked: deriving the public key from the seed and
// signing the empty message with Python's `cryptography` package
// (`Ed25519PrivateKey.from_private_bytes`) reproduced this exact public key
// and signature.
constexpr std::array<unsigned char, kEd25519SeedBytes> kEd25519Seed{
    0x9dU, 0x61U, 0xb1U, 0x9dU, 0xefU, 0xfdU, 0x5aU, 0x60U, 0xbaU, 0x84U, 0x4aU,
    0xf4U, 0x92U, 0xecU, 0x2cU, 0xc4U, 0x44U, 0x49U, 0xc5U, 0x69U, 0x7bU, 0x32U,
    0x69U, 0x19U, 0x70U, 0x3bU, 0xacU, 0x03U, 0x1cU, 0xaeU, 0x7fU, 0x60U};
constexpr std::array<unsigned char, kEd25519PublicKeyBytes> kEd25519PublicKey{
    0xd7U, 0x5aU, 0x98U, 0x01U, 0x82U, 0xb1U, 0x0aU, 0xb7U, 0xd5U, 0x4bU, 0xfeU,
    0xd3U, 0xc9U, 0x64U, 0x07U, 0x3aU, 0x0eU, 0xe1U, 0x72U, 0xf3U, 0xdaU, 0xa6U,
    0x23U, 0x25U, 0xafU, 0x02U, 0x1aU, 0x68U, 0xf7U, 0x07U, 0x51U, 0x1aU};
constexpr std::array<unsigned char, kEd25519SignatureBytes> kEd25519Signature{
    0xe5U, 0x56U, 0x43U, 0x00U, 0xc3U, 0x60U, 0xacU, 0x72U, 0x90U, 0x86U, 0xe2U,
    0xccU, 0x80U, 0x6eU, 0x82U, 0x8aU, 0x84U, 0x87U, 0x7fU, 0x1eU, 0xb8U, 0xe5U,
    0xd9U, 0x74U, 0xd8U, 0x73U, 0xe0U, 0x65U, 0x22U, 0x49U, 0x01U, 0x55U, 0x5fU,
    0xb8U, 0x82U, 0x15U, 0x90U, 0xa3U, 0x3bU, 0xacU, 0xc6U, 0x1eU, 0x39U, 0x70U,
    0x1cU, 0xf9U, 0xb4U, 0x6bU, 0xd2U, 0x5bU, 0xf5U, 0xf0U, 0x59U, 0x5bU, 0xbeU,
    0x24U, 0x65U, 0x51U, 0x41U, 0x43U, 0x8eU, 0x7aU, 0x10U, 0x0bU};

TEST(OpenSslCryptoProviderTest, Ed25519KnownAnswer) {
  OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  const std::span<const unsigned char> empty_message;
  auto signature = provider.SignEd25519(empty_message, kEd25519Seed);
  ASSERT_TRUE(signature.ok()) << signature.error().message;
  EXPECT_EQ(signature.value(), kEd25519Signature);

  auto verified = provider.VerifyEd25519(empty_message, signature.value(),
                                         kEd25519PublicKey);
  ASSERT_TRUE(verified.ok()) << verified.error().message;
  EXPECT_TRUE(verified.value());
}

TEST(OpenSslCryptoProviderTest, VerifyEd25519RejectsMismatchWithoutError) {
  OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  // A well-formed signature that simply does not match this message: "does
  // not verify" must be Ok(false), not an error.
  const std::array<unsigned char, 1U> different_message{
      static_cast<unsigned char>('x')};
  auto verified = provider.VerifyEd25519(different_message, kEd25519Signature,
                                         kEd25519PublicKey);
  ASSERT_TRUE(verified.ok()) << verified.error().message;
  EXPECT_FALSE(verified.value());
}

TEST(OpenSslCryptoProviderTest,
     VerifyEd25519ReportsErrorForMalformedKeyLength) {
  OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  const std::array<unsigned char, kEd25519PublicKeyBytes - 1U> short_key{};
  const std::span<const unsigned char> empty_message;
  auto verified =
      provider.VerifyEd25519(empty_message, kEd25519Signature, short_key);
  ASSERT_FALSE(verified.ok());
  EXPECT_NE(verified.error().code, "E_CRYPTO_UNAVAILABLE");
}

// AES-256-GCM. Vectors copied verbatim from the existing known-answer test at
// src/security/SecuritySelfTest.cpp:35-43 (`kAes256Key`, `kAesGcmIv`,
// `kAesGcmPlaintext`, `kAesGcmCiphertext`, `kAesGcmTag`), not re-derived.
constexpr std::array<unsigned char, kAesGcmKeyBytes> kAesKey{};
constexpr std::array<unsigned char, kAesGcmNonceBytes> kAesIv{};
constexpr std::array<unsigned char, 16U> kAesPlaintext{};
constexpr std::array<unsigned char, 16U> kAesCiphertext{
    0xceU, 0xa7U, 0x40U, 0x3dU, 0x4dU, 0x60U, 0x6bU, 0x6eU,
    0x07U, 0x4eU, 0xc5U, 0xd3U, 0xbaU, 0xf3U, 0x9dU, 0x18U};
constexpr std::array<unsigned char, kAesGcmTagBytes> kAesTag{
    0xd0U, 0xd1U, 0xc8U, 0xa7U, 0x99U, 0x99U, 0x6bU, 0xf0U,
    0x26U, 0x5bU, 0x98U, 0xb5U, 0xd4U, 0x8aU, 0xb9U, 0x19U};

TEST(OpenSslCryptoProviderTest, AesGcmKnownAnswer) {
  OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  std::array<unsigned char, 16U> ciphertext{};
  std::array<unsigned char, kAesGcmTagBytes> tag{};
  auto sealed =
      provider.SealAesGcm(kAesKey, kAesIv, kAesPlaintext, {}, ciphertext, tag);
  ASSERT_TRUE(sealed.ok()) << sealed.error().message;
  EXPECT_EQ(ciphertext, kAesCiphertext);
  EXPECT_EQ(tag, kAesTag);

  std::array<unsigned char, 16U> plaintext{};
  auto opened =
      provider.OpenAesGcm(kAesKey, kAesIv, ciphertext, {}, tag, plaintext);
  ASSERT_TRUE(opened.ok()) << opened.error().message;
  EXPECT_EQ(plaintext, kAesPlaintext);
}

TEST(OpenSslCryptoProviderTest, OpenAesGcmRejectsTamperedTag) {
  OpenSslCryptoProvider provider;
  ASSERT_TRUE(provider.SelfTest().ok());

  std::array<unsigned char, kAesGcmTagBytes> tampered_tag = kAesTag;
  tampered_tag.front() ^= 0x01U;
  std::array<unsigned char, 16U> plaintext{};
  auto opened = provider.OpenAesGcm(kAesKey, kAesIv, kAesCiphertext, {},
                                    tampered_tag, plaintext);
  EXPECT_FALSE(opened.ok());
}

}  // namespace
}  // namespace camera_firmware::crypto
