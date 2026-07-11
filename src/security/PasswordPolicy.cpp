#include "camera_firmware/security/PasswordPolicy.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>
#include <utility>

namespace camera_firmware::security {
namespace {

constexpr std::size_t kMinUsernameBytes = 5U;
constexpr std::size_t kMaxUsernameBytes = 32U;
constexpr std::size_t kMinPasswordBytes = 9U;
constexpr std::size_t kMaxPasswordBytes = 128U;
constexpr std::size_t kProhibitedRepeatBytes = 3U;
constexpr std::size_t kProhibitedSequenceBytes = 4U;

constexpr std::array<std::string_view, 7> kBuiltInReservedIdentities = {
    "admin", "administrator", "camera", "camera-admin",
    "guest", "root",          "user"};
constexpr std::array<std::string_view, 4> kKeyboardRows = {
    "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"};

common::Result<void> PolicyError(std::string code, std::string message) {
  return common::Result<void>::Err({std::move(code), std::move(message)});
}

constexpr bool IsAsciiUpper(unsigned char byte) {
  return byte >= 'A' && byte <= 'Z';
}

constexpr bool IsAsciiLower(unsigned char byte) {
  return byte >= 'a' && byte <= 'z';
}

constexpr bool IsAsciiDigit(unsigned char byte) {
  return byte >= '0' && byte <= '9';
}

constexpr bool IsAsciiLetter(unsigned char byte) {
  return IsAsciiUpper(byte) || IsAsciiLower(byte);
}

constexpr unsigned char AsciiLower(unsigned char byte) {
  return IsAsciiUpper(byte) ? static_cast<unsigned char>(byte + ('a' - 'A'))
                            : byte;
}

bool IsUsernameCharacter(unsigned char byte) {
  return IsAsciiLetter(byte) || IsAsciiDigit(byte) ||
         byte == '.' || byte == '_' || byte == '-';
}

bool IsIdentityDelimiter(char byte) {
  return byte == '.' || byte == '_' || byte == '-';
}

std::string LowerUsername(std::string_view username) {
  std::string lowered;
  lowered.reserve(username.size());
  std::transform(username.begin(), username.end(), std::back_inserter(lowered),
                 [](char byte) {
                   return static_cast<char>(
                       AsciiLower(static_cast<unsigned char>(byte)));
                 });
  return lowered;
}

bool EqualsUsername(const common::SecureBytes& password,
                    std::string_view lowered_username) {
  if (password.size() != lowered_username.size()) {
    return false;
  }
  for (std::size_t index = 0; index < lowered_username.size(); ++index) {
    if (AsciiLower(password.data()[index]) !=
        static_cast<unsigned char>(lowered_username[index])) {
      return false;
    }
  }
  return true;
}

bool ContainsReservedToken(std::string_view username,
                           std::string_view reserved_identity) {
  if (reserved_identity.empty() || username.size() < reserved_identity.size()) {
    return false;
  }
  std::size_t offset = username.find(reserved_identity);
  while (offset != std::string_view::npos) {
    const std::size_t end = offset + reserved_identity.size();
    const bool starts_token =
        offset == 0U || IsIdentityDelimiter(username[offset - 1U]);
    const bool ends_token =
        end == username.size() || IsIdentityDelimiter(username[end]);
    if (starts_token && ends_token) {
      return true;
    }
    offset = username.find(reserved_identity, offset + 1U);
  }
  return false;
}

bool HasRepeatedLetterOrDigit(const common::SecureBytes& password) {
  std::size_t run = 1U;
  for (std::size_t index = 1U; index < password.size(); ++index) {
    const unsigned char byte = password.data()[index];
    const bool covered = IsAsciiLetter(byte) || IsAsciiDigit(byte);
    run = covered && byte == password.data()[index - 1U] ? run + 1U : 1U;
    if (run >= kProhibitedRepeatBytes) {
      return true;
    }
  }
  return false;
}

bool MatchesKeyboardSequenceAt(const common::SecureBytes& password,
                               std::size_t offset,
                               std::string_view row,
                               bool reverse) {
  for (std::size_t start = 0;
       start + kProhibitedSequenceBytes <= row.size(); ++start) {
    bool matches = true;
    for (std::size_t index = 0; index < kProhibitedSequenceBytes; ++index) {
      const std::size_t row_index =
          reverse ? row.size() - 1U - start - index : start + index;
      if (AsciiLower(password.data()[offset + index]) !=
          static_cast<unsigned char>(row[row_index])) {
        matches = false;
        break;
      }
    }
    if (matches) {
      return true;
    }
  }
  return false;
}

bool HasKeyboardSequence(const common::SecureBytes& password) {
  if (password.size() < kProhibitedSequenceBytes) {
    return false;
  }
  for (std::size_t offset = 0;
       offset <= password.size() - kProhibitedSequenceBytes; ++offset) {
    for (const std::string_view row : kKeyboardRows) {
      if (MatchesKeyboardSequenceAt(password, offset, row, false) ||
          MatchesKeyboardSequenceAt(password, offset, row, true)) {
        return true;
      }
    }
  }
  return false;
}

}  // namespace

common::Result<void> ValidateInitialUsername(
    std::string_view username,
    std::span<const std::string_view> reserved_identities) {
  const std::string lowered = LowerUsername(username);
  const bool built_in_identity =
      std::any_of(kBuiltInReservedIdentities.begin(),
                  kBuiltInReservedIdentities.end(),
                  [&lowered](std::string_view identity) {
                    return ContainsReservedToken(lowered, identity);
                  });
  const bool supplied_identity =
      std::any_of(reserved_identities.begin(), reserved_identities.end(),
                  [&lowered](std::string_view identity) {
                    return ContainsReservedToken(lowered,
                                                 LowerUsername(identity));
                  });
  if (built_in_identity || supplied_identity) {
    return PolicyError("E_USERNAME_RESERVED",
                       "credential identity is reserved or guessable");
  }

  if (username.size() < kMinUsernameBytes ||
      username.size() > kMaxUsernameBytes ||
      !IsAsciiLetter(static_cast<unsigned char>(username.front()))) {
    return PolicyError("E_USERNAME_FORMAT",
                       "credential identity format is invalid");
  }
  if (!std::all_of(username.begin() + 1, username.end(), [](char byte) {
        return IsUsernameCharacter(static_cast<unsigned char>(byte));
      })) {
    return PolicyError("E_USERNAME_FORMAT",
                       "credential identity format is invalid");
  }

  return common::Result<void>::Ok();
}

common::Result<void> ValidatePassword(
    std::string_view username,
    const common::SecureBytes& password) {
  if (password.size() < kMinPasswordBytes ||
      password.size() > kMaxPasswordBytes) {
    return PolicyError("E_PASSWORD_LENGTH", "password length is invalid");
  }

  bool has_upper = false;
  bool has_lower = false;
  bool has_digit = false;
  bool has_special = false;
  for (std::size_t index = 0; index < password.size(); ++index) {
    const unsigned char byte = password.data()[index];
    if (byte < 0x21U || byte > 0x7eU) {
      return PolicyError("E_PASSWORD_ASCII",
                         "password contains a prohibited byte");
    }
    has_upper = has_upper || IsAsciiUpper(byte);
    has_lower = has_lower || IsAsciiLower(byte);
    has_digit = has_digit || IsAsciiDigit(byte);
    has_special = has_special ||
                  (!IsAsciiUpper(byte) && !IsAsciiLower(byte) &&
                   !IsAsciiDigit(byte));
  }

  if (EqualsUsername(password, LowerUsername(username))) {
    return PolicyError("E_PASSWORD_USERNAME",
                       "password must not equal the administrator username");
  }
  if (!has_upper || !has_lower || !has_digit || !has_special) {
    return PolicyError("E_PASSWORD_CLASS",
                       "password does not meet character class policy");
  }
  if (HasRepeatedLetterOrDigit(password)) {
    return PolicyError("E_PASSWORD_REPEAT",
                       "password contains a repeated character pattern");
  }
  if (HasKeyboardSequence(password)) {
    return PolicyError("E_PASSWORD_SEQUENCE",
                       "password contains a keyboard sequence");
  }
  return common::Result<void>::Ok();
}

}  // namespace camera_firmware::security
