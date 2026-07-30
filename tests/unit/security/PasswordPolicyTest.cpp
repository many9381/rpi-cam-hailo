#include "camera_firmware/security/PasswordPolicy.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

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

// A tiny, purpose-built JSON reader for tests/data/password-policy-vectors.json.
// It understands exactly the shape that file uses (an object holding a
// "vectors" array of flat string/bool objects) and nothing more; it is not a
// general JSON parser.
struct PasswordVector {
  std::string username;
  std::string password;
  bool accept = false;
  std::string rule;
};

class MiniJsonReader {
 public:
  explicit MiniJsonReader(std::string_view text) : text_(text) {}

  std::vector<PasswordVector> ReadVectors() {
    SkipWhitespace();
    Expect('{');
    std::vector<PasswordVector> vectors;
    bool found_vectors = false;
    SkipWhitespace();
    if (Peek() != '}') {
      while (true) {
        SkipWhitespace();
        const std::string key = ParseString();
        SkipWhitespace();
        Expect(':');
        SkipWhitespace();
        if (key == "vectors") {
          vectors = ParseVectorArray();
          found_vectors = true;
        } else {
          SkipValue();
        }
        SkipWhitespace();
        if (Peek() == ',') {
          Advance();
          continue;
        }
        break;
      }
    }
    SkipWhitespace();
    Expect('}');
    if (!found_vectors) {
      throw std::runtime_error("vector file is missing a top-level 'vectors' array");
    }
    return vectors;
  }

 private:
  std::string_view text_;
  std::size_t pos_ = 0U;

  [[nodiscard]] char Peek() const {
    if (pos_ >= text_.size()) {
      throw std::runtime_error("unexpected end of vector file");
    }
    return text_[pos_];
  }

  char Advance() {
    const char value = Peek();
    ++pos_;
    return value;
  }

  void Expect(char expected) {
    const char actual = Advance();
    if (actual != expected) {
      throw std::runtime_error("malformed vector file: expected '" +
                               std::string(1, expected) + "'");
    }
  }

  void SkipWhitespace() {
    while (pos_ < text_.size() &&
           (text_[pos_] == ' ' || text_[pos_] == '\t' ||
            text_[pos_] == '\n' || text_[pos_] == '\r')) {
      ++pos_;
    }
  }

  std::string ParseString() {
    Expect('"');
    std::string value;
    while (true) {
      const char byte = Advance();
      if (byte == '"') {
        break;
      }
      if (byte == '\\') {
        const char escaped = Advance();
        switch (escaped) {
          case '"':
            value.push_back('"');
            break;
          case '\\':
            value.push_back('\\');
            break;
          case '/':
            value.push_back('/');
            break;
          case 'n':
            value.push_back('\n');
            break;
          case 't':
            value.push_back('\t');
            break;
          default:
            throw std::runtime_error("unsupported escape in vector file");
        }
        continue;
      }
      value.push_back(byte);
    }
    return value;
  }

  bool ParseBool() {
    if (text_.substr(pos_, 4U) == "true") {
      pos_ += 4U;
      return true;
    }
    if (text_.substr(pos_, 5U) == "false") {
      pos_ += 5U;
      return false;
    }
    throw std::runtime_error("expected boolean literal in vector file");
  }

  void SkipValue() {
    SkipWhitespace();
    const char next = Peek();
    if (next == '"') {
      ParseString();
    } else if (next == 't' || next == 'f') {
      ParseBool();
    } else {
      throw std::runtime_error("unsupported value in vector file");
    }
  }

  std::vector<PasswordVector> ParseVectorArray() {
    std::vector<PasswordVector> vectors;
    Expect('[');
    SkipWhitespace();
    if (Peek() != ']') {
      while (true) {
        SkipWhitespace();
        vectors.push_back(ParseVectorObject());
        SkipWhitespace();
        if (Peek() == ',') {
          Advance();
          continue;
        }
        break;
      }
    }
    SkipWhitespace();
    Expect(']');
    return vectors;
  }

  PasswordVector ParseVectorObject() {
    PasswordVector vector;
    Expect('{');
    SkipWhitespace();
    if (Peek() != '}') {
      while (true) {
        SkipWhitespace();
        const std::string key = ParseString();
        SkipWhitespace();
        Expect(':');
        SkipWhitespace();
        if (key == "username") {
          vector.username = ParseString();
        } else if (key == "password") {
          vector.password = ParseString();
        } else if (key == "accept") {
          vector.accept = ParseBool();
        } else if (key == "rule") {
          vector.rule = ParseString();
        } else {
          SkipValue();
        }
        SkipWhitespace();
        if (Peek() == ',') {
          Advance();
          continue;
        }
        break;
      }
    }
    SkipWhitespace();
    Expect('}');
    return vector;
  }
};

std::vector<PasswordVector> LoadSharedPasswordPolicyVectors() {
  const std::filesystem::path path = std::filesystem::path(CF_SOURCE_DIR) /
                                     "tests/data/password-policy-vectors.json";
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    throw std::runtime_error("unable to open shared password policy vector file: " +
                             path.string());
  }
  std::ostringstream buffer;
  buffer << input.rdbuf();
  // `contents` must outlive the parser: MiniJsonReader only stores a
  // string_view over it.
  const std::string contents = buffer.str();
  MiniJsonReader reader(contents);
  return reader.ReadVectors();
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

// This is the C++ half of the drift-closing pin described in Task 3: both the
// server (here) and the browser mirror (web/src/security/setupPolicy.ts) read
// tests/data/password-policy-vectors.json and must reach the same verdict on
// every entry. If one implementation drifts from the other, this test or its
// TypeScript counterpart (setupPolicy.test.ts) fails.
TEST(PasswordPolicyTest, MatchesSharedPasswordPolicyVectorFile) {
  const std::unordered_map<std::string, std::string> kRuleToErrorCode = {
      {"length", "E_PASSWORD_LENGTH"},   {"charset", "E_PASSWORD_ASCII"},
      {"uppercase", "E_PASSWORD_CLASS"}, {"lowercase", "E_PASSWORD_CLASS"},
      {"digit", "E_PASSWORD_CLASS"},     {"special", "E_PASSWORD_CLASS"},
      {"username", "E_PASSWORD_USERNAME"},
      {"repeat", "E_PASSWORD_REPEAT"},
      {"sequence", "E_PASSWORD_SEQUENCE"},
  };

  const std::vector<PasswordVector> vectors = LoadSharedPasswordPolicyVectors();
  ASSERT_FALSE(vectors.empty());

  for (std::size_t index = 0; index < vectors.size(); ++index) {
    const PasswordVector& vector = vectors[index];
    SCOPED_TRACE(::testing::Message() << "vector index " << index
                                       << " username=" << vector.username);
    const auto result =
        ValidatePassword(vector.username, Bytes(vector.password));
    if (vector.accept) {
      EXPECT_TRUE(result.ok());
    } else {
      ASSERT_FALSE(result.ok());
      const auto found = kRuleToErrorCode.find(vector.rule);
      ASSERT_NE(found, kRuleToErrorCode.end())
          << "vector names unknown rule '" << vector.rule << "'";
      EXPECT_EQ(result.error().code, found->second);
    }
  }
}

}  // namespace
}  // namespace camera_firmware::security
