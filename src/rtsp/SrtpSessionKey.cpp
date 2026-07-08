#include "camera_firmware/rtsp/SrtpSessionKey.hpp"

#include <array>
#include <cstddef>

namespace camera_firmware::rtsp {

namespace {

constexpr std::size_t kHexCharsPerByte = 2;

int HexValue(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

template <std::size_t Size>
void ZeroizeArray(std::array<unsigned char, Size>& bytes) noexcept {
  volatile unsigned char* cursor = bytes.data();
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    cursor[index] = 0U;
  }
}

}  // namespace

common::Result<SrtpSessionKey> SrtpSessionKey::FromHex(std::string_view hex) {
  if (hex.size() != kAes128IcmHmacSha180Bytes * kHexCharsPerByte) {
    return common::Result<SrtpSessionKey>::Err(
        {"E_SRTP_KEY_LENGTH",
         "SRTP AES-128-ICM/HMAC-SHA1-80 session keys must be 30 bytes"});
  }

  std::array<unsigned char, kAes128IcmHmacSha180Bytes> bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    const int high = HexValue(hex[index * kHexCharsPerByte]);
    const int low = HexValue(hex[index * kHexCharsPerByte + 1]);
    if (high < 0 || low < 0) {
      ZeroizeArray(bytes);
      return common::Result<SrtpSessionKey>::Err(
          {"E_SRTP_KEY_HEX", "SRTP session key contains non-hex characters"});
    }
    bytes[index] = static_cast<unsigned char>((high << 4) | low);
  }

  SrtpSessionKey key;
  key.bytes_.assign(bytes.data(), bytes.size());
  ZeroizeArray(bytes);

  // libsrtp2 2.7.0 is present on the target, but the installed package does
  // not include implementation source proving srtp_dealloc() cleanses internal
  // key schedules. Tests and claims in this firmware therefore cover only
  // firmware-owned key material held in SecureBytes.
  return common::Result<SrtpSessionKey>::Ok(std::move(key));
}

const unsigned char* SrtpSessionKey::data() const noexcept {
  return bytes_.data();
}

std::size_t SrtpSessionKey::size() const noexcept { return bytes_.size(); }

std::size_t SrtpSessionKey::zeroize_count_for_test() const noexcept {
  return bytes_.zeroize_count_for_test();
}

}  // namespace camera_firmware::rtsp
