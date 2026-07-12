#include "camera_firmware/security/PasswordHasher.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

#include <gtest/gtest.h>
#include <openssl/crypto.h>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"

namespace camera_firmware::security {
namespace {

common::SecureBytes Bytes(std::string_view value) {
  common::SecureBytes bytes;
  bytes.assign(reinterpret_cast<const unsigned char*>(value.data()),
               value.size());
  return bytes;
}

common::SecureBytes FilledBytes(std::size_t size, unsigned char value) {
  common::SecureBytes bytes;
  bytes.resize(size);
  std::fill(bytes.data(), bytes.data() + bytes.size(), value);
  return bytes;
}

bool ConstantTimeEqual(const common::SecureBytes& left,
                       const common::SecureBytes& right) {
  return left.size() == right.size() &&
         CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

class DeterministicRandom {
 public:
  PasswordRandomCallback Callback() {
    return [this](std::size_t size) {
      common::SecureBytes output;
      output.resize(size);
      for (std::size_t index = 0; index < size; ++index) {
        output.data()[index] = next_++;
      }
      return common::Result<common::SecureBytes>::Ok(std::move(output));
    };
  }

 private:
  unsigned char next_{1U};
};

struct CleanseAuditLog {
  std::size_t count{0U};
  bool last_verified{false};

  PasswordScratchAuditCallback Callback() {
    return [this](common::ZeroizeAudit audit) {
      ++count;
      last_verified = audit.count > 0U && audit.last_verified;
    };
  }
};

PasswordRecord RecordWithIterations(std::uint32_t iterations) {
  PasswordRecord record;
  record.iterations = iterations;
  record.salt = FilledBytes(kPasswordSaltBytes, 0x5aU);
  record.derived = FilledBytes(kPasswordDerivedBytes, 0xa5U);
  return record;
}

TEST(PasswordHasherTest, UsesUniqueSaltAndVerifiesPassword) {
  DeterministicRandom random;
  auto first = DerivePassword(Bytes("NorthStar!9"), random.Callback());
  auto second = DerivePassword(Bytes("NorthStar!9"), random.Callback());
  ASSERT_TRUE(first.ok()) << first.error().message;
  ASSERT_TRUE(second.ok()) << second.error().message;
  EXPECT_EQ(first.value().algorithm, "pbkdf2-hmac-sha256");
  EXPECT_EQ(first.value().iterations, 600000U);
  EXPECT_EQ(first.value().salt.size(), 16U);
  EXPECT_EQ(first.value().derived.size(), 32U);
  EXPECT_FALSE(ConstantTimeEqual(first.value().salt, second.value().salt));

  const auto accepted = VerifyPassword(Bytes("NorthStar!9"), first.value());
  const auto rejected = VerifyPassword(Bytes("WrongPass!9"), first.value());
  ASSERT_TRUE(accepted.ok()) << accepted.error().message;
  ASSERT_TRUE(rejected.ok()) << rejected.error().message;
  EXPECT_TRUE(accepted.value());
  EXPECT_FALSE(rejected.value());
}

TEST(PasswordHasherTest, PublicVerificationApiHasExactlyTwoArguments) {
  using VerifySignature = common::Result<bool> (*)(
      const common::SecureBytes&, const PasswordRecord&);
  VerifySignature verify = &VerifyPassword;
  EXPECT_NE(verify, nullptr);
}

TEST(PasswordHasherTest, RejectsPartialInjectedRandomAndKdfOutputs) {
  PasswordHasherDependencies short_random;
  short_random.random_bytes = [](std::size_t size) {
    return common::Result<common::SecureBytes>::Ok(
        FilledBytes(size - 1U, 0x5aU));
  };
  auto random_result =
      DerivePassword(Bytes("NorthStar!9"), std::move(short_random));
  ASSERT_FALSE(random_result.ok());
  EXPECT_EQ(random_result.error().code, "E_PASSWORD_RANDOM");

  DeterministicRandom random;
  PasswordHasherDependencies short_kdf;
  short_kdf.random_bytes = random.Callback();
  short_kdf.derive_bytes =
      [](const common::SecureBytes&, std::span<const unsigned char>,
         std::uint32_t, std::size_t size) {
        return common::Result<common::SecureBytes>::Ok(
            FilledBytes(size - 1U, 0xa5U));
      };
  auto kdf_result =
      DerivePassword(Bytes("NorthStar!9"), std::move(short_kdf));
  ASSERT_FALSE(kdf_result.ok());
  EXPECT_EQ(kdf_result.error().code, "E_PASSWORD_HASH");
}

TEST(PasswordHasherTest, CleansesKdfScratchOnSuccessAndFailure) {
  CleanseAuditLog success_audit;
  DeterministicRandom success_random;
  PasswordHasherDependencies success;
  success.random_bytes = success_random.Callback();
  success.scratch_audit = success_audit.Callback();
  auto succeeded = DerivePassword(Bytes("NorthStar!9"), std::move(success));
  ASSERT_TRUE(succeeded.ok()) << succeeded.error().message;
  EXPECT_GE(success_audit.count, 2U);
  EXPECT_TRUE(success_audit.last_verified);

  CleanseAuditLog failure_audit;
  DeterministicRandom failure_random;
  PasswordHasherDependencies failure;
  failure.random_bytes = failure_random.Callback();
  failure.derive_bytes =
      [](const common::SecureBytes&, std::span<const unsigned char>,
         std::uint32_t, std::size_t size) {
        return common::Result<common::SecureBytes>::Ok(
            FilledBytes(size - 1U, 0xa5U));
      };
  failure.scratch_audit = failure_audit.Callback();

  const auto failed =
      DerivePassword(Bytes("NorthStar!9"), std::move(failure));

  ASSERT_FALSE(failed.ok());
  EXPECT_EQ(failed.error().code, "E_PASSWORD_HASH");
  EXPECT_GE(failure_audit.count, 2U);
  EXPECT_TRUE(failure_audit.last_verified);
}

TEST(PasswordHasherTest, SecureRecordFieldsCleanseOnOverwriteAndShutdown) {
  DeterministicRandom random;
  auto record = DerivePassword(Bytes("NorthStar!9"), random.Callback());
  ASSERT_TRUE(record.ok()) << record.error().message;

  const unsigned char replacement[] = {1U, 2U, 3U};
  record.value().derived.assign(replacement, sizeof(replacement));
  EXPECT_GE(record.value().derived.zeroize_audit().count, 1U);
  EXPECT_TRUE(record.value().derived.zeroize_audit().last_verified);

  record.value().salt.clear();
  EXPECT_GE(record.value().salt.zeroize_audit().count, 1U);
  EXPECT_TRUE(record.value().salt.zeroize_audit().last_verified);
}

TEST(PasswordHasherTest, AcceptsStoredIterationCompatibilityBoundaries) {
  auto minimum = RecordWithIterations(kPasswordMinAcceptedIterations);
  auto maximum = RecordWithIterations(kPasswordMaxAcceptedIterations);

  const auto minimum_result =
      VerifyPassword(Bytes("NorthStar!9"), minimum);
  const auto maximum_result =
      VerifyPassword(Bytes("NorthStar!9"), maximum);

  ASSERT_TRUE(minimum_result.ok()) << minimum_result.error().message;
  ASSERT_TRUE(maximum_result.ok()) << maximum_result.error().message;
  EXPECT_FALSE(minimum_result.value());
  EXPECT_FALSE(maximum_result.value());
}

TEST(PasswordHasherTest, RejectsIterationsImmediatelyOutsideCompatibilityBounds) {
  auto below = RecordWithIterations(kPasswordMinAcceptedIterations - 1U);
  auto above = RecordWithIterations(kPasswordMaxAcceptedIterations + 1U);

  const auto below_result = VerifyPassword(Bytes("NorthStar!9"), below);
  const auto above_result = VerifyPassword(Bytes("NorthStar!9"), above);

  ASSERT_FALSE(below_result.ok());
  ASSERT_FALSE(above_result.ok());
  EXPECT_EQ(below_result.error().code, "E_PASSWORD_RECORD");
  EXPECT_EQ(above_result.error().code, "E_PASSWORD_RECORD");
}

TEST(PasswordHasherTest, MatchesPbkdf2HmacSha256KnownAnswerVector) {
  constexpr std::array<unsigned char, 32> expected = {
      0x61U, 0x5eU, 0xeeU, 0xe6U, 0x52U, 0xa9U, 0xfeU, 0x1cU,
      0xf9U, 0xf4U, 0x27U, 0xd6U, 0x21U, 0x85U, 0x26U, 0xa9U,
      0x37U, 0xadU, 0xd0U, 0x18U, 0x07U, 0x98U, 0x54U, 0xb2U,
      0xaaU, 0x11U, 0x87U, 0x5dU, 0x75U, 0x98U, 0x37U, 0xacU};
  PasswordRecord record;
  record.iterations = 4096U;
  record.salt = Bytes("0123456789abcdef");
  record.derived.assign(expected.data(), expected.size());

  const auto accepted = VerifyPassword(Bytes("password"), record);
  const auto rejected = VerifyPassword(Bytes("Password"), record);

  ASSERT_TRUE(accepted.ok()) << accepted.error().message;
  ASSERT_TRUE(rejected.ok()) << rejected.error().message;
  EXPECT_TRUE(accepted.value());
  EXPECT_FALSE(rejected.value());
}

TEST(PasswordHasherTest, RejectsEveryInvalidNonIterationRecordField) {
  auto record = RecordWithIterations(kPasswordKdfIterations);

  record.algorithm = "pbkdf2-hmac-sha1";
  EXPECT_EQ(VerifyPassword(Bytes("NorthStar!9"), record).error().code,
            "E_PASSWORD_RECORD");
  record.algorithm = "pbkdf2-hmac-sha256";
  record.salt.resize(kPasswordSaltBytes - 1U);
  EXPECT_EQ(VerifyPassword(Bytes("NorthStar!9"), record).error().code,
            "E_PASSWORD_RECORD");
  record.salt.resize(kPasswordSaltBytes);
  record.derived.resize(kPasswordDerivedBytes - 1U);
  EXPECT_EQ(VerifyPassword(Bytes("NorthStar!9"), record).error().code,
            "E_PASSWORD_RECORD");
}

}  // namespace
}  // namespace camera_firmware::security
