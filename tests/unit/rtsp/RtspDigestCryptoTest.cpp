#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"

#include <array>
#include <climits>
#include <cstddef>
#include <limits>
#include <span>
#include <string>

#include <gtest/gtest.h>

namespace {

using camera_firmware::common::SecureBytes;
using camera_firmware::rtsp::ComputeRtspDigestHa1;
using camera_firmware::rtsp::ComputeRtspDigestResponse;
using camera_firmware::rtsp::DecodeRtspDigestHex;
using camera_firmware::rtsp::EncodeRtspDigestLowerHex;
using camera_firmware::rtsp::ParseRtspDigestAlgorithm;
using camera_firmware::rtsp::RtspDigestAlgorithm;
using camera_firmware::rtsp::RtspDigestConfigName;
using camera_firmware::rtsp::RtspDigestConstantTimeEqual;
using camera_firmware::rtsp::RtspDigestHash;
using camera_firmware::rtsp::RtspDigestHmacSha256;
using camera_firmware::rtsp::RtspDigestProtocolName;
using camera_firmware::rtsp::RtspDigestRandomBytes;
using camera_firmware::rtsp::RtspDigestSize;

std::string HexForTest(const SecureBytes& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output(bytes.size() * 2U, '0');
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    output[i * 2U] = kHex[bytes.data()[i] >> 4U];
    output[i * 2U + 1U] = kHex[bytes.data()[i] & 0x0fU];
  }
  return output;
}

TEST(RtspDigestCryptoTest, MatchesRfc7616Sha256Response) {
  const std::array<unsigned char, 14> password{
      'C', 'i', 'r', 'c', 'l', 'e', ' ', 'o', 'f', ' ',
      'L', 'i', 'f', 'e'};
  auto ha1 = ComputeRtspDigestHa1(
      RtspDigestAlgorithm::kSha256, "Mufasa", "http-auth@example.org",
      password);
  ASSERT_TRUE(ha1.ok()) << ha1.error().message;

  auto response = ComputeRtspDigestResponse(
      RtspDigestAlgorithm::kSha256,
      {ha1.value().data(), ha1.value().size()}, "GET", "/dir/index.html",
      "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", "00000001",
      "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");

  ASSERT_TRUE(response.ok()) << response.error().message;
  EXPECT_EQ(HexForTest(response.value()),
            "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1");
}

TEST(RtspDigestCryptoTest, MatchesRfc7616Md5CompatibilityResponse) {
  const std::array<unsigned char, 14> password{
      'C', 'i', 'r', 'c', 'l', 'e', ' ', 'o', 'f', ' ',
      'L', 'i', 'f', 'e'};
  auto ha1 = ComputeRtspDigestHa1(
      RtspDigestAlgorithm::kMd5, "Mufasa", "http-auth@example.org",
      password);
  ASSERT_TRUE(ha1.ok()) << ha1.error().message;

  auto response = ComputeRtspDigestResponse(
      RtspDigestAlgorithm::kMd5,
      {ha1.value().data(), ha1.value().size()}, "GET", "/dir/index.html",
      "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", "00000001",
      "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");

  ASSERT_TRUE(response.ok()) << response.error().message;
  EXPECT_EQ(HexForTest(response.value()),
            "8ca523f5e9506fed4657c9700eebdbec");
}

TEST(RtspDigestCryptoTest, MatchesRfc4231HmacSha256Vector) {
  const std::array<unsigned char, 20> key{
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
  const std::array<unsigned char, 8> data{'H', 'i', ' ', 'T',
                                           'h', 'e', 'r', 'e'};

  auto mac = RtspDigestHmacSha256(key, data);

  ASSERT_TRUE(mac.ok()) << mac.error().message;
  EXPECT_EQ(HexForTest(mac.value()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST(RtspDigestCryptoTest, ComputesHmacSha256WithEmptyKeyAndData) {
  const std::span<const unsigned char> empty;

  auto mac = RtspDigestHmacSha256(empty, empty);

  ASSERT_TRUE(mac.ok()) << mac.error().message;
  EXPECT_EQ(HexForTest(mac.value()),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
}

TEST(RtspDigestCryptoTest, HashesEmptyInputWithSupportedAlgorithms) {
  const std::span<const unsigned char> empty;

  auto sha256 = RtspDigestHash(RtspDigestAlgorithm::kSha256, empty);
  auto md5 = RtspDigestHash(RtspDigestAlgorithm::kMd5, empty);

  ASSERT_TRUE(sha256.ok()) << sha256.error().message;
  ASSERT_TRUE(md5.ok()) << md5.error().message;
  EXPECT_EQ(HexForTest(sha256.value()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  EXPECT_EQ(HexForTest(md5.value()),
            "d41d8cd98f00b204e9800998ecf8427e");
}

TEST(RtspDigestCryptoTest, ParsesAndNamesSupportedAlgorithms) {
  auto sha256 = ParseRtspDigestAlgorithm("sha-256");
  auto md5 = ParseRtspDigestAlgorithm("md5");

  ASSERT_TRUE(sha256.ok()) << sha256.error().message;
  ASSERT_TRUE(md5.ok()) << md5.error().message;
  EXPECT_EQ(sha256.value(), RtspDigestAlgorithm::kSha256);
  EXPECT_EQ(md5.value(), RtspDigestAlgorithm::kMd5);
  EXPECT_EQ(RtspDigestConfigName(sha256.value()), "sha-256");
  EXPECT_EQ(RtspDigestConfigName(md5.value()), "md5");
  EXPECT_EQ(RtspDigestProtocolName(sha256.value()), "SHA-256");
  EXPECT_EQ(RtspDigestProtocolName(md5.value()), "MD5");
  EXPECT_EQ(RtspDigestSize(sha256.value()), 32U);
  EXPECT_EQ(RtspDigestSize(md5.value()), 16U);
}

TEST(RtspDigestCryptoTest, RejectsUnsupportedAlgorithmName) {
  auto parsed = ParseRtspDigestAlgorithm("SHA-256");

  ASSERT_FALSE(parsed.ok());
  EXPECT_EQ(parsed.error().code, "E_RTSP_AUTH_FORMAT");
}

TEST(RtspDigestCryptoTest, InvalidEnumHasNoAlgorithmNames) {
  const auto invalid = static_cast<RtspDigestAlgorithm>(99);

  EXPECT_TRUE(RtspDigestConfigName(invalid).empty());
  EXPECT_TRUE(RtspDigestProtocolName(invalid).empty());
}

TEST(RtspDigestCryptoTest, InvalidEnumHasZeroDigestSize) {
  const auto invalid = static_cast<RtspDigestAlgorithm>(99);

  EXPECT_EQ(RtspDigestSize(invalid), 0U);
}

TEST(RtspDigestCryptoTest, RejectsInvalidEnumForHashWithoutFallback) {
  const auto invalid = static_cast<RtspDigestAlgorithm>(99);
  const std::array<unsigned char, 1> input{0x01};

  auto hashed = RtspDigestHash(invalid, input);

  ASSERT_FALSE(hashed.ok());
  EXPECT_EQ(hashed.error().code, "E_RTSP_AUTH_CRYPTO");
}

TEST(RtspDigestCryptoTest, RejectsInvalidEnumForHa1WithoutFallback) {
  const auto invalid = static_cast<RtspDigestAlgorithm>(99);
  const std::span<const unsigned char> empty_password;

  auto ha1 = ComputeRtspDigestHa1(
      invalid, "username", "realm", empty_password);

  ASSERT_FALSE(ha1.ok());
  EXPECT_EQ(ha1.error().code, "E_RTSP_AUTH_CRYPTO");
}

TEST(RtspDigestCryptoTest, RejectsInvalidEnumForResponseWithoutFallback) {
  const auto invalid = static_cast<RtspDigestAlgorithm>(99);
  const std::span<const unsigned char> empty_ha1;

  auto response = ComputeRtspDigestResponse(
      invalid, empty_ha1, "GET", "/", "nonce", "00000001", "cnonce");

  ASSERT_FALSE(response.ok());
  EXPECT_EQ(response.error().code, "E_RTSP_AUTH_CRYPTO");
}

TEST(RtspDigestCryptoTest, DecodesLowercaseAndUppercaseHex) {
  auto lowercase = DecodeRtspDigestHex("00abcdef", 4U);
  auto uppercase = DecodeRtspDigestHex("00ABCDEF", 4U);

  ASSERT_TRUE(lowercase.ok()) << lowercase.error().message;
  ASSERT_TRUE(uppercase.ok()) << uppercase.error().message;
  EXPECT_EQ(HexForTest(lowercase.value()), "00abcdef");
  EXPECT_EQ(HexForTest(uppercase.value()), "00abcdef");
}

TEST(RtspDigestCryptoTest, RejectsMalformedOddAndWrongLengthHex) {
  auto malformed = DecodeRtspDigestHex("00ag", 2U);
  auto odd = DecodeRtspDigestHex("abc", 2U);
  auto wrong_length = DecodeRtspDigestHex("0011", 3U);

  ASSERT_FALSE(malformed.ok());
  ASSERT_FALSE(odd.ok());
  ASSERT_FALSE(wrong_length.ok());
  EXPECT_EQ(malformed.error().code, "E_RTSP_AUTH_FORMAT");
  EXPECT_EQ(odd.error().code, "E_RTSP_AUTH_FORMAT");
  EXPECT_EQ(wrong_length.error().code, "E_RTSP_AUTH_FORMAT");
}

TEST(RtspDigestCryptoTest, RejectsHexExpectedLengthOverflow) {
  auto decoded = DecodeRtspDigestHex(
      "", std::numeric_limits<std::size_t>::max());

  ASSERT_FALSE(decoded.ok());
  EXPECT_EQ(decoded.error().code, "E_RTSP_AUTH_FORMAT");
}

TEST(RtspDigestCryptoTest, EncodesDigestAsLowercaseHexInSecureStorage) {
  const std::array<unsigned char, 4> bytes{0x00, 0xab, 0xcd, 0xef};

  auto encoded = EncodeRtspDigestLowerHex(bytes);

  ASSERT_TRUE(encoded.ok()) << encoded.error().message;
  ASSERT_EQ(encoded.value().size(), 8U);
  EXPECT_EQ(HexForTest(encoded.value()), "3030616263646566");
}

TEST(RtspDigestCryptoTest, EncodesEmptyBytesAsEmptySecureBytes) {
  const std::span<const unsigned char> empty;

  auto encoded = EncodeRtspDigestLowerHex(empty);

  ASSERT_TRUE(encoded.ok()) << encoded.error().message;
  EXPECT_EQ(encoded.value().size(), 0U);
}

TEST(RtspDigestCryptoTest, DecodesEmptyHexAsEmptySecureBytes) {
  auto decoded = DecodeRtspDigestHex("", 0U);

  ASSERT_TRUE(decoded.ok()) << decoded.error().message;
  EXPECT_EQ(decoded.value().size(), 0U);
}

TEST(RtspDigestCryptoTest, ConstantTimeCompareChecksLengthAndContent) {
  const std::array<unsigned char, 4> expected{0x00, 0x11, 0x22, 0x33};
  const std::array<unsigned char, 4> same{0x00, 0x11, 0x22, 0x33};
  const std::array<unsigned char, 4> changed{0x00, 0x11, 0x22, 0x34};
  const std::array<unsigned char, 3> shorter{0x00, 0x11, 0x22};

  EXPECT_TRUE(RtspDigestConstantTimeEqual(expected, same));
  EXPECT_FALSE(RtspDigestConstantTimeEqual(expected, changed));
  EXPECT_FALSE(RtspDigestConstantTimeEqual(expected, shorter));
}

TEST(RtspDigestCryptoTest, ConstantTimeCompareHandlesEmptySpans) {
  const std::span<const unsigned char> empty;
  const std::array<unsigned char, 1> nonempty{0x00};

  EXPECT_TRUE(RtspDigestConstantTimeEqual(empty, empty));
  EXPECT_FALSE(RtspDigestConstantTimeEqual(empty, nonempty));
  EXPECT_FALSE(RtspDigestConstantTimeEqual(nonempty, empty));
}

TEST(RtspDigestCryptoTest, GeneratesExactRandomLength) {
  auto random = RtspDigestRandomBytes(32U);

  ASSERT_TRUE(random.ok()) << random.error().message;
  EXPECT_EQ(random.value().size(), 32U);
}

TEST(RtspDigestCryptoTest, GeneratesZeroLengthRandomBytes) {
  auto random = RtspDigestRandomBytes(0U);

  ASSERT_TRUE(random.ok()) << random.error().message;
  EXPECT_EQ(random.value().size(), 0U);
}

TEST(RtspDigestCryptoTest, RejectsRandomLengthAboveOpenSslLimit) {
  const auto too_large = static_cast<std::size_t>(INT_MAX) + 1U;

  auto random = RtspDigestRandomBytes(too_large);

  ASSERT_FALSE(random.ok());
  EXPECT_EQ(random.error().code, "E_RTSP_AUTH_FORMAT");
}

TEST(RtspDigestCryptoTest, RejectsWrongSizedHa1ForResponse) {
  const std::array<unsigned char, 31> wrong_size_ha1{};

  auto response = ComputeRtspDigestResponse(
      RtspDigestAlgorithm::kSha256, wrong_size_ha1, "GET", "/", "nonce",
      "00000001", "cnonce");

  ASSERT_FALSE(response.ok());
  EXPECT_EQ(response.error().code, "E_RTSP_AUTH_FORMAT");
}

}  // namespace
