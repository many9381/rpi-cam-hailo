#include "camera_firmware/security/PasswordPolicy.hpp"

#include <array>
#include <string_view>

#include <gtest/gtest.h>

#include "camera_firmware/common/SecureBytes.hpp"

namespace camera_firmware::security {
namespace {

common::SecureBytes Bytes(std::string_view value) {
  common::SecureBytes bytes;
  bytes.assign(reinterpret_cast<const unsigned char*>(value.data()),
               value.size());
  return bytes;
}

constexpr std::array<std::string_view, 4> kReservedIdentities = {
    "camera", "imx708", "hailo", "raspberry-pi"};

void ExpectUsernameError(std::string_view username, std::string_view code) {
  const auto result = ValidateInitialUsername(username, kReservedIdentities);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, code);
  if (!username.empty()) {
    EXPECT_EQ(result.error().message.find(username), std::string::npos);
  }
}

void ExpectPasswordError(std::string_view password, std::string_view code) {
  auto secret = Bytes(password);
  const auto result = ValidatePassword("operator.one", secret);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, code);
  EXPECT_EQ(result.error().message.find(password), std::string::npos);
}

TEST(PasswordPolicyTest, AcceptsCompliantInitialCredential) {
  auto password = Bytes("NorthStar!9");
  EXPECT_TRUE(
      ValidateInitialUsername("operator.one", kReservedIdentities).ok());
  EXPECT_TRUE(ValidatePassword("operator.one", password).ok());
}

TEST(PasswordPolicyTest, RejectsReservedAndGuessableUsernames) {
  ExpectUsernameError("admin", "E_USERNAME_RESERVED");
  ExpectUsernameError("camera-admin", "E_USERNAME_RESERVED");
  ExpectUsernameError("imx708", "E_USERNAME_RESERVED");
  ExpectUsernameError("ROOT", "E_USERNAME_RESERVED");
  ExpectUsernameError("ops-ROOT", "E_USERNAME_RESERVED");
  ExpectUsernameError("ops-user", "E_USERNAME_RESERVED");
}

TEST(PasswordPolicyTest, EnforcesExactUsernameBoundsAndLeadingLetter) {
  EXPECT_TRUE(ValidateInitialUsername("Abc12", kReservedIdentities).ok());
  EXPECT_TRUE(
      ValidateInitialUsername("A1234567890123456789012345678901",
                              kReservedIdentities)
          .ok());

  ExpectUsernameError("Abc1", "E_USERNAME_FORMAT");
  ExpectUsernameError("A12345678901234567890123456789012",
                      "E_USERNAME_FORMAT");
  ExpectUsernameError("1operator", "E_USERNAME_FORMAT");
  ExpectUsernameError(".operator", "E_USERNAME_FORMAT");
  ExpectUsernameError("_operator", "E_USERNAME_FORMAT");
  ExpectUsernameError("-operator", "E_USERNAME_FORMAT");
  ExpectUsernameError("operator one", "E_USERNAME_FORMAT");
  ExpectUsernameError("operator/one", "E_USERNAME_FORMAT");
}

TEST(PasswordPolicyTest, RejectsReservedStandaloneTokensIgnoringCase) {
  ExpectUsernameError("root.operator", "E_USERNAME_RESERVED");
  ExpectUsernameError("ops_ADMIN", "E_USERNAME_RESERVED");
  ExpectUsernameError("ops-administrator", "E_USERNAME_RESERVED");
  ExpectUsernameError("ops-camera", "E_USERNAME_RESERVED");
  ExpectUsernameError("ops-imx708", "E_USERNAME_RESERVED");
  ExpectUsernameError("ops.HAILO", "E_USERNAME_RESERVED");
  ExpectUsernameError("ops-raspberry-pi", "E_USERNAME_RESERVED");

  EXPECT_TRUE(
      ValidateInitialUsername("rooted.userx", kReservedIdentities).ok());
  EXPECT_TRUE(
      ValidateInitialUsername("opsimx708x", kReservedIdentities).ok());
}

TEST(PasswordPolicyTest, RejectsPasswordsOutsideExactByteBounds) {
  ExpectPasswordError("Short!9A", "E_PASSWORD_LENGTH");
  ExpectPasswordError(std::string(129, 'A'), "E_PASSWORD_LENGTH");
}

TEST(PasswordPolicyTest, AcceptsPasswordsAtExactByteBounds) {
  EXPECT_TRUE(ValidatePassword("operator.one", Bytes("Aa!5bcDef")).ok());
  std::string maximum;
  for (int index = 0; index < 32; ++index) {
    maximum += "Az!7";
  }
  ASSERT_EQ(maximum.size(), 128U);
  EXPECT_TRUE(ValidatePassword("operator.one", Bytes(maximum)).ok());
}

TEST(PasswordPolicyTest, RejectsNonPrintableOrSpaceAsciiBytes) {
  ExpectPasswordError("North Star!9", "E_PASSWORD_ASCII");
  ExpectPasswordError(std::string("North\nStar!9"), "E_PASSWORD_ASCII");
  ExpectPasswordError(std::string("North\x7fStar!9", 12), "E_PASSWORD_ASCII");
}

TEST(PasswordPolicyTest, RejectsMissingCharacterClasses) {
  ExpectPasswordError("Northstar9", "E_PASSWORD_CLASS");
  ExpectPasswordError("NORTHSTAR!9", "E_PASSWORD_CLASS");
  ExpectPasswordError("NorthStar!!", "E_PASSWORD_CLASS");
  ExpectPasswordError("NorthStar99", "E_PASSWORD_CLASS");
}

TEST(PasswordPolicyTest, RejectsOnlyExactUsernameEqualityIgnoringCase) {
  ExpectPasswordError("OpErAtOr.OnE", "E_PASSWORD_USERNAME");
  EXPECT_TRUE(
      ValidatePassword("operator.one", Bytes("X!9OPERATOR.ONEz")).ok());
}

TEST(PasswordPolicyTest, RejectsThreeRepeatedAsciiLettersOrDigits) {
  ExpectPasswordError("Nort111!h", "E_PASSWORD_REPEAT");
  ExpectPasswordError("NortAAA!9h", "E_PASSWORD_REPEAT");
  ExpectPasswordError("Nortaaa!9H", "E_PASSWORD_REPEAT");
  EXPECT_TRUE(ValidatePassword("operator.one", Bytes("Nort11!hA")).ok());
  EXPECT_TRUE(ValidatePassword("operator.one", Bytes("Abc!!!!9xy")).ok());
}

TEST(PasswordPolicyTest, RejectsForwardAndReverseKeyboardSequences) {
  constexpr std::array<std::string_view, 8> passwords = {
      "North1234!Z", "North4321!Z", "NorthQwer!9", "NorthRewq!9",
      "NorthAsdf!9", "NorthFdsa!9", "NorthZxcv!9", "NorthVcxz!9"};
  for (const std::string_view password : passwords) {
    ExpectPasswordError(password, "E_PASSWORD_SEQUENCE");
  }
}

}  // namespace
}  // namespace camera_firmware::security
