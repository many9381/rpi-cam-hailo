#include "camera_firmware/crypto/OpenSslCryptoProvider.hpp"

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "camera_firmware/common/SecureBytes.hpp"

namespace camera_firmware::crypto {
namespace {

// ---------------------------------------------------------------------------
// Gate helper. Every public operation on OpenSslCryptoProvider begins with
// this check; SelfTest() must never route through it, or the provider could
// never leave ProviderStatus::kUninitialized.
// ---------------------------------------------------------------------------

template <typename T>
common::Result<T> Unavailable() {
  return common::Result<T>::Err(
      {"E_CRYPTO_UNAVAILABLE", "cryptographic provider is unavailable"});
}

// ---------------------------------------------------------------------------
// RAII deleters, matching src/security/PasswordHasher.cpp and
// src/integrity/IntegritySigner.cpp / IntegrityVerifier.cpp.
// ---------------------------------------------------------------------------

struct KdfDeleter {
  void operator()(EVP_KDF* kdf) const noexcept { EVP_KDF_free(kdf); }
};

struct KdfContextDeleter {
  void operator()(EVP_KDF_CTX* context) const noexcept {
    EVP_KDF_CTX_free(context);
  }
};

using EvpPkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpMdContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EvpCipherContext =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

// ---------------------------------------------------------------------------
// File-local raw OpenSSL helpers.
//
// These do the actual cryptographic work with no reference to status_ at
// all. Both the gated public methods and SelfTest() call these; SelfTest()
// is the only caller that may invoke them while status_ is
// kUninitialized, because it is what proves the provider is safe to use.
// ---------------------------------------------------------------------------

bool RawRandomBytes(std::span<unsigned char> out) {
  if (out.size() > static_cast<std::size_t>(INT_MAX)) {
    return false;
  }
  return RAND_bytes(out.data(), static_cast<int>(out.size())) == 1;
}

// Draws from OpenSSL's private DRBG instance, mirroring
// src/security/AuthService.cpp's DefaultRandom (RAND_priv_bytes), which this
// method is intended to replace for callers that were relying on that
// separate, non-public randomness pool.
bool RawRandomBytesPrivate(std::span<unsigned char> out) {
  if (out.size() > static_cast<std::size_t>(INT_MAX)) {
    return false;
  }
  return RAND_priv_bytes(out.data(), static_cast<int>(out.size())) == 1;
}

// Mirrors src/security/PasswordHasher.cpp:79-122 (DefaultDerive), generalised
// to write into a caller-supplied output span instead of allocating one.
bool RawDeriveKeyPbkdf2(std::span<const unsigned char> password,
                        std::span<const unsigned char> salt,
                        std::uint32_t iterations,
                        std::span<unsigned char> out) {
  std::unique_ptr<EVP_KDF, KdfDeleter> kdf(
      EVP_KDF_fetch(nullptr, "PBKDF2", nullptr));
  if (!kdf) {
    return false;
  }
  std::unique_ptr<EVP_KDF_CTX, KdfContextDeleter> context(
      EVP_KDF_CTX_new(kdf.get()));
  if (!context) {
    return false;
  }

  char digest[] = "SHA256";
  std::array<OSSL_PARAM, 5> parameters = {
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_PASSWORD,
          const_cast<unsigned char*>(password.data()), password.size()),
      OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(salt.data()),
          salt.size()),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations),
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0U),
      OSSL_PARAM_construct_end()};
  return EVP_KDF_derive(context.get(), out.data(), out.size(),
                        parameters.data()) == 1;
}

// Mirrors src/integrity/IntegritySigner.cpp's SignIntegrityManifest, except
// the key is constructed from a raw 32-byte seed
// (EVP_PKEY_new_raw_private_key) rather than read from a PEM file, because
// this interface's contract takes a raw seed rather than a key path.
bool RawSignEd25519(std::span<const unsigned char> message,
                    std::span<const unsigned char> seed,
                    std::array<unsigned char, kEd25519SignatureBytes>&
                        signature_out) {
  EvpPkey key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                           seed.data(), seed.size()),
              EVP_PKEY_free);
  if (!key) {
    return false;
  }
  EvpMdContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  std::size_t signature_size = signature_out.size();
  return context != nullptr &&
         EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr,
                            key.get()) == 1 &&
         EVP_DigestSign(context.get(), signature_out.data(), &signature_size,
                        message.data(), message.size()) == 1 &&
         signature_size == signature_out.size();
}

// Mirrors src/integrity/IntegrityVerifier.cpp's VerifyEd25519Signature,
// except the key is constructed from raw 32-byte public key bytes
// (EVP_PKEY_new_raw_public_key) rather than parsed from PEM.
//
// Returns the raw EVP_DigestVerify convention: 1 for "signature matches", 0
// for "signature is well-formed but does not match", and a negative value
// for "could not even attempt verification" (bad key material, allocation
// failure, ...).
int RawVerifyEd25519(std::span<const unsigned char> message,
                     std::span<const unsigned char> signature,
                     std::span<const unsigned char> public_key) {
  EvpPkey key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                          public_key.data(),
                                          public_key.size()),
              EVP_PKEY_free);
  if (!key) {
    return -1;
  }
  EvpMdContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!context || EVP_DigestVerifyInit(context.get(), nullptr, nullptr,
                                       nullptr, key.get()) != 1) {
    return -1;
  }
  return EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                          message.data(), message.size());
}

// Mirrors src/security/SecuritySelfTest.cpp:247-296 (RunAes256GcmKat's
// encrypt half), generalised to arbitrary key/nonce/plaintext/AAD spans
// instead of the fixed self-test vector, and to report failure via bool
// instead of aggregating into a single self-test predicate.
bool RawSealAesGcm(std::span<const unsigned char> key,
                   std::span<const unsigned char> nonce,
                   std::span<const unsigned char> plaintext,
                   std::span<const unsigned char> associated_data,
                   std::span<unsigned char> ciphertext_out,
                   std::span<unsigned char> tag_out) {
  EvpCipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!context ||
      EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(),
                         nonce.data()) != 1) {
    return false;
  }
  if (!associated_data.empty()) {
    int aad_written = 0;
    if (EVP_EncryptUpdate(context.get(), nullptr, &aad_written,
                          associated_data.data(),
                          static_cast<int>(associated_data.size())) != 1) {
      return false;
    }
  }
  int written = 0;
  int final_written = 0;
  return EVP_EncryptUpdate(context.get(), ciphertext_out.data(), &written,
                           plaintext.data(),
                           static_cast<int>(plaintext.size())) == 1 &&
         static_cast<std::size_t>(written) == plaintext.size() &&
         EVP_EncryptFinal_ex(context.get(), ciphertext_out.data() + written,
                             &final_written) == 1 &&
         final_written == 0 &&
         EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
                             static_cast<int>(tag_out.size()),
                             tag_out.data()) == 1;
}

// Mirrors src/security/SecuritySelfTest.cpp:220-245 (DecryptAesGcm),
// generalised the same way as RawSealAesGcm above.
bool RawOpenAesGcm(std::span<const unsigned char> key,
                   std::span<const unsigned char> nonce,
                   std::span<const unsigned char> ciphertext,
                   std::span<const unsigned char> associated_data,
                   std::span<const unsigned char> tag,
                   std::span<unsigned char> plaintext_out) {
  EvpCipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!context ||
      EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(),
                         nonce.data()) != 1) {
    return false;
  }
  if (!associated_data.empty()) {
    int aad_written = 0;
    if (EVP_DecryptUpdate(context.get(), nullptr, &aad_written,
                          associated_data.data(),
                          static_cast<int>(associated_data.size())) != 1) {
      return false;
    }
  }
  int written = 0;
  int final_written = 0;
  return EVP_DecryptUpdate(context.get(), plaintext_out.data(), &written,
                           ciphertext.data(),
                           static_cast<int>(ciphertext.size())) == 1 &&
         static_cast<std::size_t>(written) == ciphertext.size() &&
         EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG,
                             static_cast<int>(tag.size()),
                             const_cast<unsigned char*>(tag.data())) == 1 &&
         EVP_DecryptFinal_ex(context.get(), plaintext_out.data() + written,
                             &final_written) == 1 &&
         final_written == 0;
}

// ---------------------------------------------------------------------------
// Known-answer vectors used only by SelfTest(). Provenance for each is
// recorded in tests/unit/crypto/CryptoProviderTest.cpp, which uses the same
// literals.
// ---------------------------------------------------------------------------

// PBKDF2-HMAC-SHA256, password = "password", salt = "salt", 4096 iterations.
constexpr std::array<unsigned char, 8U> kSelfTestPbkdf2Password{
    'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
constexpr std::array<unsigned char, 4U> kSelfTestPbkdf2Salt{'s', 'a', 'l',
                                                             't'};
constexpr std::uint32_t kSelfTestPbkdf2Iterations = 4096U;
constexpr std::array<unsigned char, 32U> kSelfTestPbkdf2Expected{
    0xc5U, 0xe4U, 0x78U, 0xd5U, 0x92U, 0x88U, 0xc8U, 0x41U,
    0xaaU, 0x53U, 0x0dU, 0xb6U, 0x84U, 0x5cU, 0x4cU, 0x8dU,
    0x96U, 0x28U, 0x93U, 0xa0U, 0x01U, 0xceU, 0x4eU, 0x11U,
    0xa4U, 0x96U, 0x38U, 0x73U, 0xaaU, 0x98U, 0x13U, 0x4aU};

// Ed25519, RFC 8032 section 7.1, TEST 1 (empty message).
constexpr std::array<unsigned char, kEd25519SeedBytes> kSelfTestEd25519Seed{
    0x9dU, 0x61U, 0xb1U, 0x9dU, 0xefU, 0xfdU, 0x5aU, 0x60U,
    0xbaU, 0x84U, 0x4aU, 0xf4U, 0x92U, 0xecU, 0x2cU, 0xc4U,
    0x44U, 0x49U, 0xc5U, 0x69U, 0x7bU, 0x32U, 0x69U, 0x19U,
    0x70U, 0x3bU, 0xacU, 0x03U, 0x1cU, 0xaeU, 0x7fU, 0x60U};
constexpr std::array<unsigned char, kEd25519PublicKeyBytes>
    kSelfTestEd25519PublicKey{0xd7U, 0x5aU, 0x98U, 0x01U, 0x82U, 0xb1U, 0x0aU,
                              0xb7U, 0xd5U, 0x4bU, 0xfeU, 0xd3U, 0xc9U, 0x64U,
                              0x07U, 0x3aU, 0x0eU, 0xe1U, 0x72U, 0xf3U, 0xdaU,
                              0xa6U, 0x23U, 0x25U, 0xafU, 0x02U, 0x1aU, 0x68U,
                              0xf7U, 0x07U, 0x51U, 0x1aU};
constexpr std::array<unsigned char, kEd25519SignatureBytes>
    kSelfTestEd25519Signature{
        0xe5U, 0x56U, 0x43U, 0x00U, 0xc3U, 0x60U, 0xacU, 0x72U, 0x90U, 0x86U,
        0xe2U, 0xccU, 0x80U, 0x6eU, 0x82U, 0x8aU, 0x84U, 0x87U, 0x7fU, 0x1eU,
        0xb8U, 0xe5U, 0xd9U, 0x74U, 0xd8U, 0x73U, 0xe0U, 0x65U, 0x22U, 0x49U,
        0x01U, 0x55U, 0x5fU, 0xb8U, 0x82U, 0x15U, 0x90U, 0xa3U, 0x3bU, 0xacU,
        0xc6U, 0x1eU, 0x39U, 0x70U, 0x1cU, 0xf9U, 0xb4U, 0x6bU, 0xd2U, 0x5bU,
        0xf5U, 0xf0U, 0x59U, 0x5bU, 0xbeU, 0x24U, 0x65U, 0x51U, 0x41U, 0x43U,
        0x8eU, 0x7aU, 0x10U, 0x0bU};

// AES-256-GCM. Copied verbatim from src/security/SecuritySelfTest.cpp:35-43
// (kAes256Key, kAesGcmIv, kAesGcmPlaintext, kAesGcmCiphertext, kAesGcmTag).
constexpr std::array<unsigned char, kAesGcmKeyBytes> kSelfTestAesKey{};
constexpr std::array<unsigned char, kAesGcmNonceBytes> kSelfTestAesIv{};
constexpr std::array<unsigned char, 16U> kSelfTestAesPlaintext{};
constexpr std::array<unsigned char, 16U> kSelfTestAesCiphertext{
    0xceU, 0xa7U, 0x40U, 0x3dU, 0x4dU, 0x60U, 0x6bU, 0x6eU,
    0x07U, 0x4eU, 0xc5U, 0xd3U, 0xbaU, 0xf3U, 0x9dU, 0x18U};
constexpr std::array<unsigned char, kAesGcmTagBytes> kSelfTestAesTag{
    0xd0U, 0xd1U, 0xc8U, 0xa7U, 0x99U, 0x99U, 0x6bU, 0xf0U,
    0x26U, 0x5bU, 0x98U, 0xb5U, 0xd4U, 0x8aU, 0xb9U, 0x19U};

// ---------------------------------------------------------------------------
// SelfTest()'s per-family known-answer checks. Each is defensive: an
// exception anywhere is treated as a failed self-test, matching the style of
// src/security/SecuritySelfTest.cpp's RunSha256Kat / RunHmacSha256Kat /
// RunAes256GcmKat.
// ---------------------------------------------------------------------------

bool RunRandomBytesSelfTest() noexcept {
  try {
    // There is no known-answer output for a CSPRNG. The self test instead
    // confirms the generator is seeded and willing to produce output, which
    // is the only property that can be checked without an oracle.
    std::array<unsigned char, 32U> buffer{};
    return RAND_status() == 1 && RawRandomBytes(buffer);
  } catch (...) {
    return false;
  }
}

// Exercises the private DRBG (RandomBytesPrivate) the same way
// RunRandomBytesSelfTest exercises the public one: no known-answer output
// exists for a CSPRNG, so this only confirms the private DRBG is willing to
// produce output. Uses RawRandomBytesPrivate directly rather than going
// through RandomBytesPrivate(), for the same reason every other self-test
// helper here bypasses the public gated methods: SelfTest() runs while
// status_ is still kUninitialized, and the gated methods refuse to run then.
bool RunRandomBytesPrivateSelfTest() noexcept {
  try {
    std::array<unsigned char, 32U> buffer{};
    return RawRandomBytesPrivate(buffer);
  } catch (...) {
    return false;
  }
}

bool RunPbkdf2SelfTest() noexcept {
  try {
    std::array<unsigned char, 32U> output{};
    return RawDeriveKeyPbkdf2(kSelfTestPbkdf2Password, kSelfTestPbkdf2Salt,
                              kSelfTestPbkdf2Iterations, output) &&
           CRYPTO_memcmp(output.data(), kSelfTestPbkdf2Expected.data(),
                        output.size()) == 0;
  } catch (...) {
    return false;
  }
}

bool RunEd25519SelfTest() noexcept {
  try {
    std::array<unsigned char, kEd25519SignatureBytes> signature{};
    if (!RawSignEd25519({}, kSelfTestEd25519Seed, signature)) {
      return false;
    }
    if (CRYPTO_memcmp(signature.data(), kSelfTestEd25519Signature.data(),
                      signature.size()) != 0) {
      return false;
    }
    return RawVerifyEd25519({}, signature, kSelfTestEd25519PublicKey) == 1;
  } catch (...) {
    return false;
  }
}

bool RunAes256GcmSelfTest() noexcept {
  try {
    // ciphertext/tag/decrypted are self-test scratch space, not secrets (the
    // key and plaintext are published known-answer constants), but this
    // codebase's defensive posture is to cleanse cryptographic scratch
    // buffers unconditionally rather than reason about which ones matter
    // (see common::SecureBytes, and src/security/SecuritySelfTest.cpp's
    // SensitiveBytes, which cleansed these same buffer roles before this
    // known-answer test moved here). common::SecureBytes's destructor
    // OPENSSL_cleanses its storage on every path out of this function,
    // including the early returns below.
    common::SecureBytes ciphertext;
    common::SecureBytes tag;
    ciphertext.resize(16U);
    tag.resize(kAesGcmTagBytes);
    if (!RawSealAesGcm(kSelfTestAesKey, kSelfTestAesIv, kSelfTestAesPlaintext,
                       {},
                       std::span<unsigned char>(ciphertext.data(),
                                                ciphertext.size()),
                       std::span<unsigned char>(tag.data(), tag.size()))) {
      return false;
    }
    if (CRYPTO_memcmp(ciphertext.data(), kSelfTestAesCiphertext.data(),
                      ciphertext.size()) != 0 ||
        CRYPTO_memcmp(tag.data(), kSelfTestAesTag.data(), tag.size()) != 0) {
      return false;
    }
    common::SecureBytes decrypted;
    decrypted.resize(16U);
    if (!RawOpenAesGcm(
            kSelfTestAesKey, kSelfTestAesIv,
            std::span<const unsigned char>(ciphertext.data(),
                                           ciphertext.size()),
            {},
            std::span<const unsigned char>(tag.data(), tag.size()),
            std::span<unsigned char>(decrypted.data(), decrypted.size()))) {
      return false;
    }
    return CRYPTO_memcmp(decrypted.data(), kSelfTestAesPlaintext.data(),
                         decrypted.size()) == 0;
  } catch (...) {
    return false;
  }
}

}  // namespace

common::Result<SelfTestReport> OpenSslCryptoProvider::SelfTest() {
  // The whole body is guarded so no exception (e.g. bad_alloc from
  // report.items.push_back) can escape without status_ being updated first.
  // A provider that failed to complete its self-test must never be left
  // kOperational — see src/security/SecuritySelfTest.cpp's
  // RunSecuritySelfTests, which this mirrors.
  try {
    SelfTestReport report;
    report.items.reserve(5U);
    bool overall_passed = true;

    const auto record = [&report, &overall_passed](std::string id,
                                                    bool passed) {
      SelfTestItem item;
      item.id = std::move(id);
      item.passed = passed;
      item.code = passed ? "OK" : "E_CRYPTO_SELF_TEST_FAILED";
      overall_passed = overall_passed && passed;
      report.items.push_back(std::move(item));
    };

    record("pbkdf2_hmac_sha256", RunPbkdf2SelfTest());
    record("random_bytes", RunRandomBytesSelfTest());
    record("random_bytes_private", RunRandomBytesPrivateSelfTest());
    record("ed25519", RunEd25519SelfTest());
    record("aes_256_gcm", RunAes256GcmSelfTest());

    report.passed = overall_passed;
    status_.store(overall_passed ? ProviderStatus::kOperational
                                 : ProviderStatus::kFailed);
    return common::Result<SelfTestReport>::Ok(std::move(report));
  } catch (...) {
    status_.store(ProviderStatus::kFailed);
    return common::Result<SelfTestReport>::Err(
        {"E_CRYPTO_SELF_TEST_REPORT",
         "crypto provider self-test report is unavailable"});
  }
}

ProviderStatus OpenSslCryptoProvider::Status() const noexcept {
  return status_.load();
}

common::Result<common::SecureBytes> OpenSslCryptoProvider::RandomBytes(
    std::size_t output_size) {
  if (status_.load() != ProviderStatus::kOperational) {
    return Unavailable<common::SecureBytes>();
  }
  common::SecureBytes output;
  try {
    output.resize(output_size);
  } catch (...) {
    return common::Result<common::SecureBytes>::Err(
        {"E_CRYPTO_RANDOM", "random generation failed"});
  }
  if (!RawRandomBytes(std::span<unsigned char>(output.data(), output.size()))) {
    return common::Result<common::SecureBytes>::Err(
        {"E_CRYPTO_RANDOM", "random generation failed"});
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

common::Result<common::SecureBytes>
OpenSslCryptoProvider::RandomBytesPrivate(std::size_t output_size) {
  if (status_.load() != ProviderStatus::kOperational) {
    return Unavailable<common::SecureBytes>();
  }
  common::SecureBytes output;
  try {
    output.resize(output_size);
  } catch (...) {
    return common::Result<common::SecureBytes>::Err(
        {"E_CRYPTO_RANDOM", "random generation failed"});
  }
  if (!RawRandomBytesPrivate(
          std::span<unsigned char>(output.data(), output.size()))) {
    return common::Result<common::SecureBytes>::Err(
        {"E_CRYPTO_RANDOM", "random generation failed"});
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

common::Result<common::SecureBytes> OpenSslCryptoProvider::DeriveKeyPbkdf2(
    const common::SecureBytes& password,
    std::span<const unsigned char> salt,
    std::uint32_t iterations,
    std::size_t output_size) {
  if (status_.load() != ProviderStatus::kOperational) {
    return Unavailable<common::SecureBytes>();
  }
  common::SecureBytes output;
  try {
    output.resize(output_size);
  } catch (...) {
    return common::Result<common::SecureBytes>::Err(
        {"E_CRYPTO_KDF", "key derivation failed"});
  }
  if (!RawDeriveKeyPbkdf2(
          std::span<const unsigned char>(password.data(), password.size()),
          salt, iterations,
          std::span<unsigned char>(output.data(), output.size()))) {
    return common::Result<common::SecureBytes>::Err(
        {"E_CRYPTO_KDF", "key derivation failed"});
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

common::Result<std::array<unsigned char, kEd25519SignatureBytes>>
OpenSslCryptoProvider::SignEd25519(
    std::span<const unsigned char> message,
    std::span<const unsigned char> private_key_seed) {
  using ResultT = common::Result<std::array<unsigned char, kEd25519SignatureBytes>>;
  if (status_.load() != ProviderStatus::kOperational) {
    return Unavailable<std::array<unsigned char, kEd25519SignatureBytes>>();
  }
  if (private_key_seed.size() != kEd25519SeedBytes) {
    return ResultT::Err(
        {"E_CRYPTO_INVALID_KEY", "Ed25519 private key seed has invalid length"});
  }
  std::array<unsigned char, kEd25519SignatureBytes> signature{};
  if (!RawSignEd25519(message, private_key_seed, signature)) {
    return ResultT::Err({"E_CRYPTO_SIGN_FAILED", "Ed25519 signing failed"});
  }
  return ResultT::Ok(signature);
}

common::Result<bool> OpenSslCryptoProvider::VerifyEd25519(
    std::span<const unsigned char> message,
    std::span<const unsigned char> signature,
    std::span<const unsigned char> public_key) {
  if (status_.load() != ProviderStatus::kOperational) {
    return Unavailable<bool>();
  }
  if (public_key.size() != kEd25519PublicKeyBytes) {
    return common::Result<bool>::Err(
        {"E_CRYPTO_INVALID_KEY", "Ed25519 public key has invalid length"});
  }
  if (signature.size() != kEd25519SignatureBytes) {
    return common::Result<bool>::Err(
        {"E_CRYPTO_INVALID_SIGNATURE",
         "Ed25519 signature has invalid length"});
  }
  const int verify_result = RawVerifyEd25519(message, signature, public_key);
  if (verify_result < 0) {
    return common::Result<bool>::Err(
        {"E_CRYPTO_VERIFY_FAILED", "Ed25519 verification failed"});
  }
  return common::Result<bool>::Ok(verify_result == 1);
}

common::Result<void> OpenSslCryptoProvider::SealAesGcm(
    std::span<const unsigned char> key,
    std::span<const unsigned char> nonce,
    std::span<const unsigned char> plaintext,
    std::span<const unsigned char> associated_data,
    std::span<unsigned char> ciphertext_out,
    std::span<unsigned char> tag_out) {
  if (status_.load() != ProviderStatus::kOperational) {
    return Unavailable<void>();
  }
  if (key.size() != kAesGcmKeyBytes || nonce.size() != kAesGcmNonceBytes ||
      tag_out.size() != kAesGcmTagBytes ||
      ciphertext_out.size() != plaintext.size() ||
      plaintext.size() > static_cast<std::size_t>(INT_MAX) ||
      associated_data.size() > static_cast<std::size_t>(INT_MAX)) {
    return common::Result<void>::Err(
        {"E_CRYPTO_INVALID_ARGUMENT", "AES-GCM seal arguments are invalid"});
  }
  if (!RawSealAesGcm(key, nonce, plaintext, associated_data, ciphertext_out,
                     tag_out)) {
    return common::Result<void>::Err(
        {"E_CRYPTO_SEAL_FAILED", "AES-GCM seal failed"});
  }
  return common::Result<void>::Ok();
}

common::Result<void> OpenSslCryptoProvider::OpenAesGcm(
    std::span<const unsigned char> key,
    std::span<const unsigned char> nonce,
    std::span<const unsigned char> ciphertext,
    std::span<const unsigned char> associated_data,
    std::span<const unsigned char> tag,
    std::span<unsigned char> plaintext_out) {
  if (status_.load() != ProviderStatus::kOperational) {
    return Unavailable<void>();
  }
  if (key.size() != kAesGcmKeyBytes || nonce.size() != kAesGcmNonceBytes ||
      tag.size() != kAesGcmTagBytes ||
      plaintext_out.size() != ciphertext.size() ||
      ciphertext.size() > static_cast<std::size_t>(INT_MAX) ||
      associated_data.size() > static_cast<std::size_t>(INT_MAX)) {
    return common::Result<void>::Err(
        {"E_CRYPTO_INVALID_ARGUMENT", "AES-GCM open arguments are invalid"});
  }
  if (!RawOpenAesGcm(key, nonce, ciphertext, associated_data, tag,
                     plaintext_out)) {
    return common::Result<void>::Err(
        {"E_CRYPTO_AUTH_FAILED", "AES-GCM open failed authentication"});
  }
  return common::Result<void>::Ok();
}

}  // namespace camera_firmware::crypto
