#include "camera_firmware/security/PasswordHasher.hpp"

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

namespace camera_firmware::security {
namespace {

constexpr const char* kPasswordAlgorithm = "pbkdf2-hmac-sha256";

template <typename T>
common::Result<T> HasherError(std::string code, std::string message) {
  return common::Result<T>::Err({std::move(code), std::move(message)});
}

class AuditedScratch {
 public:
  explicit AuditedScratch(PasswordScratchAuditCallback* audit) noexcept
      : audit_(audit) {}

  ~AuditedScratch() {
    const common::ZeroizeAudit before = bytes.zeroize_audit();
    const bool contained_bytes = bytes.size() != 0U;
    bytes.clear();
    const common::ZeroizeAudit after = bytes.zeroize_audit();
    if (!contained_bytes || audit_ == nullptr || !*audit_) {
      return;
    }
    try {
      (*audit_)({after.count - before.count, after.last_verified});
    } catch (...) {
    }
  }

  common::SecureBytes bytes;

 private:
  PasswordScratchAuditCallback* audit_;
};

common::Result<common::SecureBytes> DefaultRandom(std::size_t output_size) {
  common::SecureBytes output;
  try {
    output.resize(output_size);
  } catch (...) {
    return HasherError<common::SecureBytes>("E_PASSWORD_RANDOM",
                                            "random generation failed");
  }
  if (output_size > static_cast<std::size_t>(INT_MAX) ||
      RAND_bytes(output.data(), static_cast<int>(output.size())) != 1) {
    return HasherError<common::SecureBytes>("E_PASSWORD_RANDOM",
                                            "random generation failed");
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

struct KdfDeleter {
  void operator()(EVP_KDF* kdf) const noexcept { EVP_KDF_free(kdf); }
};

struct KdfContextDeleter {
  void operator()(EVP_KDF_CTX* context) const noexcept {
    EVP_KDF_CTX_free(context);
  }
};

common::Result<common::SecureBytes> DefaultDerive(
    const common::SecureBytes& password,
    std::span<const unsigned char> salt,
    std::uint32_t iterations,
    std::size_t output_size) {
  std::unique_ptr<EVP_KDF, KdfDeleter> kdf(
      EVP_KDF_fetch(nullptr, "PBKDF2", nullptr));
  if (!kdf) {
    return HasherError<common::SecureBytes>("E_PASSWORD_HASH",
                                            "password derivation failed");
  }
  std::unique_ptr<EVP_KDF_CTX, KdfContextDeleter> context(
      EVP_KDF_CTX_new(kdf.get()));
  if (!context) {
    return HasherError<common::SecureBytes>("E_PASSWORD_HASH",
                                            "password derivation failed");
  }

  common::SecureBytes output;
  try {
    output.resize(output_size);
  } catch (...) {
    return HasherError<common::SecureBytes>("E_PASSWORD_HASH",
                                            "password derivation failed");
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
  if (EVP_KDF_derive(context.get(), output.data(), output.size(),
                     parameters.data()) != 1) {
    return HasherError<common::SecureBytes>("E_PASSWORD_HASH",
                                            "password derivation failed");
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

bool IsValidRecord(const PasswordRecord& record) {
  return record.algorithm == kPasswordAlgorithm &&
         record.iterations >= kPasswordMinAcceptedIterations &&
         record.iterations <= kPasswordMaxAcceptedIterations &&
         record.salt.size() == kPasswordSaltBytes &&
         record.derived.size() == kPasswordDerivedBytes;
}

}  // namespace

common::Result<PasswordRecord> DerivePassword(
    const common::SecureBytes& password,
    PasswordHasherDependencies dependencies) {
  AuditedScratch salt_scratch(&dependencies.scratch_audit);
  AuditedScratch derived_scratch(&dependencies.scratch_audit);
  try {
    auto random = dependencies.random_bytes
                      ? dependencies.random_bytes(kPasswordSaltBytes)
                      : dependencies.provider
                            ? dependencies.provider->RandomBytes(
                                  kPasswordSaltBytes)
                            : DefaultRandom(kPasswordSaltBytes);
    if (!random.ok()) {
      return HasherError<PasswordRecord>("E_PASSWORD_RANDOM",
                                         "password salt generation failed");
    }
    salt_scratch.bytes = std::move(random).value();
    if (salt_scratch.bytes.size() != kPasswordSaltBytes) {
      return HasherError<PasswordRecord>("E_PASSWORD_RANDOM",
                                         "password salt generation failed");
    }

    const std::span<const unsigned char> salt(salt_scratch.bytes.data(),
                                               salt_scratch.bytes.size());
    auto derived = dependencies.derive_bytes
                       ? dependencies.derive_bytes(
                             password, salt, kPasswordKdfIterations,
                             kPasswordDerivedBytes)
                       : dependencies.provider
                             ? dependencies.provider->DeriveKeyPbkdf2(
                                   password, salt, kPasswordKdfIterations,
                                   kPasswordDerivedBytes)
                             : DefaultDerive(password, salt,
                                             kPasswordKdfIterations,
                                             kPasswordDerivedBytes);
    if (!derived.ok()) {
      return HasherError<PasswordRecord>("E_PASSWORD_HASH",
                                         "password derivation failed");
    }
    derived_scratch.bytes = std::move(derived).value();
    if (derived_scratch.bytes.size() != kPasswordDerivedBytes) {
      return HasherError<PasswordRecord>("E_PASSWORD_HASH",
                                         "password derivation failed");
    }

    PasswordRecord record;
    record.salt.assign(salt_scratch.bytes.data(), salt_scratch.bytes.size());
    record.derived.assign(derived_scratch.bytes.data(),
                          derived_scratch.bytes.size());
    return common::Result<PasswordRecord>::Ok(std::move(record));
  } catch (...) {
    return HasherError<PasswordRecord>("E_PASSWORD_HASH",
                                       "password derivation failed");
  }
}

common::Result<bool> VerifyPassword(
    const common::SecureBytes& password,
    const PasswordRecord& record) {
  if (!IsValidRecord(record)) {
    return HasherError<bool>("E_PASSWORD_RECORD",
                             "stored password record is invalid");
  }

  AuditedScratch candidate(nullptr);
  try {
    auto derived = DefaultDerive(password,
                                 {record.salt.data(), record.salt.size()},
                                 record.iterations, kPasswordDerivedBytes);
    if (!derived.ok()) {
      return HasherError<bool>("E_PASSWORD_HASH",
                               "password verification failed");
    }
    candidate.bytes = std::move(derived).value();
    if (candidate.bytes.size() != kPasswordDerivedBytes) {
      return HasherError<bool>("E_PASSWORD_HASH",
                               "password verification failed");
    }
    return common::Result<bool>::Ok(
        CRYPTO_memcmp(candidate.bytes.data(), record.derived.data(),
                      kPasswordDerivedBytes) == 0);
  } catch (...) {
    return HasherError<bool>("E_PASSWORD_HASH",
                             "password verification failed");
  }
}

}  // namespace camera_firmware::security
