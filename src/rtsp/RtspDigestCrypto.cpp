#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"

#include <climits>
#include <cstddef>
#include <initializer_list>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#include <utility>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

namespace camera_firmware::rtsp {

namespace {

constexpr std::size_t kSha256Bytes = 32U;
constexpr std::size_t kMd5Bytes = 16U;
constexpr std::size_t kHexCharsPerByte = 2U;
constexpr unsigned char kColon = ':';
constexpr unsigned char kEmptyHmacKey = 0U;
constexpr std::string_view kAuthSeparator = ":auth:";

using EvpMdContext =
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EvpMac = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
using EvpMacContext =
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;

common::Error CryptoError() {
  return {"E_RTSP_AUTH_CRYPTO", "RTSP digest cryptographic operation failed"};
}

common::Error FormatError() {
  return {"E_RTSP_AUTH_FORMAT", "RTSP digest input has invalid format"};
}

const EVP_MD* DigestForAlgorithm(RtspDigestAlgorithm algorithm) noexcept {
  switch (algorithm) {
    case RtspDigestAlgorithm::kSha256:
      return EVP_sha256();
    case RtspDigestAlgorithm::kMd5:
      return EVP_md5();
  }
  return nullptr;
}

bool CheckedAdd(std::size_t value, std::size_t* total) noexcept {
  if (value > std::numeric_limits<std::size_t>::max() - *total) {
    return false;
  }
  *total += value;
  return true;
}

bool ValidateCombinedSize(
    std::initializer_list<std::size_t> sizes) noexcept {
  std::size_t total = 0U;
  for (const std::size_t size : sizes) {
    if (!CheckedAdd(size, &total)) {
      return false;
    }
  }
  return true;
}

void Append(common::SecureBytes& output, std::string_view value) {
  output.append(reinterpret_cast<const unsigned char*>(value.data()),
                value.size());
}

int HexValue(char value) noexcept {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }
  return -1;
}

}  // namespace

common::Result<RtspDigestAlgorithm> ParseRtspDigestAlgorithm(
    std::string_view value) {
  if (value == "sha-256") {
    return common::Result<RtspDigestAlgorithm>::Ok(
        RtspDigestAlgorithm::kSha256);
  }
  if (value == "md5") {
    return common::Result<RtspDigestAlgorithm>::Ok(RtspDigestAlgorithm::kMd5);
  }
  return common::Result<RtspDigestAlgorithm>::Err(FormatError());
}

std::string_view RtspDigestConfigName(RtspDigestAlgorithm algorithm) {
  switch (algorithm) {
    case RtspDigestAlgorithm::kSha256:
      return "sha-256";
    case RtspDigestAlgorithm::kMd5:
      return "md5";
  }
  return {};
}

std::string_view RtspDigestProtocolName(RtspDigestAlgorithm algorithm) {
  switch (algorithm) {
    case RtspDigestAlgorithm::kSha256:
      return "SHA-256";
    case RtspDigestAlgorithm::kMd5:
      return "MD5";
  }
  return {};
}

std::size_t RtspDigestSize(RtspDigestAlgorithm algorithm) {
  switch (algorithm) {
    case RtspDigestAlgorithm::kSha256:
      return kSha256Bytes;
    case RtspDigestAlgorithm::kMd5:
      return kMd5Bytes;
  }
  return 0U;
}

common::Result<common::SecureBytes> RtspDigestHash(
    RtspDigestAlgorithm algorithm,
    std::span<const unsigned char> data) {
  const EVP_MD* digest = DigestForAlgorithm(algorithm);
  const std::size_t expected_size = RtspDigestSize(algorithm);
  if (digest == nullptr || expected_size == 0U) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }

  EvpMdContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!context || EVP_DigestInit_ex(context.get(), digest, nullptr) != 1 ||
      EVP_DigestUpdate(context.get(), data.data(), data.size()) != 1) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }

  common::SecureBytes output;
  try {
    output.resize(expected_size);
  } catch (...) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }

  unsigned int output_size = 0U;
  if (EVP_DigestFinal_ex(context.get(), output.data(), &output_size) != 1 ||
      output_size != expected_size) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

common::Result<common::SecureBytes> RtspDigestRandomBytes(std::size_t size) {
  if (size > static_cast<std::size_t>(INT_MAX)) {
    return common::Result<common::SecureBytes>::Err(FormatError());
  }

  common::SecureBytes output;
  try {
    output.resize(size);
  } catch (...) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  if (size != 0U &&
      RAND_bytes(output.data(), static_cast<int>(size)) != 1) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

common::Result<common::SecureBytes> RtspDigestHmacSha256(
    std::span<const unsigned char> key,
    std::span<const unsigned char> data) {
  EvpMac mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr), EVP_MAC_free);
  if (!mac) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  EvpMacContext context(EVP_MAC_CTX_new(mac.get()), EVP_MAC_CTX_free);
  if (!context) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }

  char digest_name[] = "SHA256";
  OSSL_PARAM parameters[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0U),
      OSSL_PARAM_construct_end()};
  const unsigned char* key_data = key.empty() ? &kEmptyHmacKey : key.data();
  if (EVP_MAC_init(context.get(), key_data, key.size(), parameters) != 1 ||
      EVP_MAC_update(context.get(), data.data(), data.size()) != 1) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }

  common::SecureBytes output;
  try {
    output.resize(kSha256Bytes);
  } catch (...) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  std::size_t output_size = 0U;
  if (EVP_MAC_final(context.get(), output.data(), &output_size,
                    output.size()) != 1 ||
      output_size != kSha256Bytes) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

common::Result<common::SecureBytes> DecodeRtspDigestHex(
    std::string_view hex, std::size_t expected_bytes) {
  if (expected_bytes >
          std::numeric_limits<std::size_t>::max() / kHexCharsPerByte ||
      hex.size() != expected_bytes * kHexCharsPerByte) {
    return common::Result<common::SecureBytes>::Err(FormatError());
  }

  common::SecureBytes output;
  try {
    output.resize(expected_bytes);
  } catch (...) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  for (std::size_t index = 0; index < expected_bytes; ++index) {
    const int high = HexValue(hex[index * kHexCharsPerByte]);
    const int low = HexValue(hex[index * kHexCharsPerByte + 1U]);
    if (high < 0 || low < 0) {
      return common::Result<common::SecureBytes>::Err(FormatError());
    }
    output.data()[index] =
        static_cast<unsigned char>((high << 4U) | low);
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

common::Result<common::SecureBytes> EncodeRtspDigestLowerHex(
    std::span<const unsigned char> bytes) {
  static constexpr unsigned char kHex[] = "0123456789abcdef";
  if (bytes.size() >
      std::numeric_limits<std::size_t>::max() / kHexCharsPerByte) {
    return common::Result<common::SecureBytes>::Err(FormatError());
  }

  common::SecureBytes output;
  try {
    output.resize(bytes.size() * kHexCharsPerByte);
  } catch (...) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    output.data()[index * kHexCharsPerByte] = kHex[bytes[index] >> 4U];
    output.data()[index * kHexCharsPerByte + 1U] =
        kHex[bytes[index] & 0x0fU];
  }
  return common::Result<common::SecureBytes>::Ok(std::move(output));
}

common::Result<common::SecureBytes> ComputeRtspDigestHa1(
    RtspDigestAlgorithm algorithm,
    std::string_view username,
    std::string_view realm,
    std::span<const unsigned char> password) {
  if (DigestForAlgorithm(algorithm) == nullptr) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  if (!ValidateCombinedSize(
          {username.size(), 1U, realm.size(), 1U, password.size()})) {
    return common::Result<common::SecureBytes>::Err(FormatError());
  }

  common::SecureBytes a1;
  try {
    Append(a1, username);
    a1.append(&kColon, 1U);
    Append(a1, realm);
    a1.append(&kColon, 1U);
    a1.append(password.data(), password.size());
  } catch (...) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  return RtspDigestHash(algorithm, {a1.data(), a1.size()});
}

common::Result<common::SecureBytes> ComputeRtspDigestResponse(
    RtspDigestAlgorithm algorithm,
    std::span<const unsigned char> ha1,
    std::string_view method,
    std::string_view uri,
    std::string_view nonce,
    std::string_view nonce_count,
    std::string_view cnonce,
    bool with_qop) {
  const std::size_t digest_size = RtspDigestSize(algorithm);
  if (DigestForAlgorithm(algorithm) == nullptr || digest_size == 0U) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  if (ha1.size() != digest_size ||
      !ValidateCombinedSize({method.size(), 1U, uri.size()})) {
    return common::Result<common::SecureBytes>::Err(FormatError());
  }

  common::SecureBytes a2;
  try {
    Append(a2, method);
    a2.append(&kColon, 1U);
    Append(a2, uri);
  } catch (...) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }

  auto ha2 = RtspDigestHash(algorithm, {a2.data(), a2.size()});
  if (!ha2.ok()) {
    return common::Result<common::SecureBytes>::Err(ha2.error());
  }
  auto encoded_ha1 = EncodeRtspDigestLowerHex(ha1);
  if (!encoded_ha1.ok()) {
    return common::Result<common::SecureBytes>::Err(encoded_ha1.error());
  }
  auto encoded_ha2 = EncodeRtspDigestLowerHex(
      {ha2.value().data(), ha2.value().size()});
  if (!encoded_ha2.ok()) {
    return common::Result<common::SecureBytes>::Err(encoded_ha2.error());
  }

  const bool size_ok =
      with_qop
          ? ValidateCombinedSize(
                {encoded_ha1.value().size(), 1U, nonce.size(), 1U,
                 nonce_count.size(), 1U, cnonce.size(), kAuthSeparator.size(),
                 encoded_ha2.value().size()})
          : ValidateCombinedSize({encoded_ha1.value().size(), 1U, nonce.size(),
                                   1U, encoded_ha2.value().size()});
  if (!size_ok) {
    return common::Result<common::SecureBytes>::Err(FormatError());
  }

  common::SecureBytes response_input;
  try {
    response_input.append(encoded_ha1.value().data(),
                          encoded_ha1.value().size());
    response_input.append(&kColon, 1U);
    Append(response_input, nonce);
    if (with_qop) {
      // RFC 2617/7616: HA1:nonce:nc:cnonce:qop:HA2
      response_input.append(&kColon, 1U);
      Append(response_input, nonce_count);
      response_input.append(&kColon, 1U);
      Append(response_input, cnonce);
      Append(response_input, kAuthSeparator);
    } else {
      // RFC 2069: HA1:nonce:HA2
      response_input.append(&kColon, 1U);
    }
    response_input.append(encoded_ha2.value().data(),
                          encoded_ha2.value().size());
  } catch (...) {
    return common::Result<common::SecureBytes>::Err(CryptoError());
  }
  return RtspDigestHash(
      algorithm, {response_input.data(), response_input.size()});
}

bool RtspDigestConstantTimeEqual(std::span<const unsigned char> left,
                                 std::span<const unsigned char> right) {
  if (left.size() != right.size()) {
    return false;
  }
  if (left.empty()) {
    return true;
  }
  return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

}  // namespace camera_firmware::rtsp
