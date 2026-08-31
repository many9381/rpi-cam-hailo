#pragma once

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"

#include <cstddef>
#include <span>
#include <string_view>

namespace camera_firmware::rtsp {

enum class RtspDigestAlgorithm { kSha256, kMd5 };

common::Result<RtspDigestAlgorithm> ParseRtspDigestAlgorithm(
    std::string_view value);
std::string_view RtspDigestConfigName(RtspDigestAlgorithm algorithm);
std::string_view RtspDigestProtocolName(RtspDigestAlgorithm algorithm);
std::size_t RtspDigestSize(RtspDigestAlgorithm algorithm);
common::Result<common::SecureBytes> RtspDigestHash(
    RtspDigestAlgorithm algorithm,
    std::span<const unsigned char> data);
common::Result<common::SecureBytes> RtspDigestRandomBytes(std::size_t size);
common::Result<common::SecureBytes> RtspDigestHmacSha256(
    std::span<const unsigned char> key,
    std::span<const unsigned char> data);
common::Result<common::SecureBytes> DecodeRtspDigestHex(
    std::string_view hex, std::size_t expected_bytes);
common::Result<common::SecureBytes> EncodeRtspDigestLowerHex(
    std::span<const unsigned char> bytes);
common::Result<common::SecureBytes> ComputeRtspDigestHa1(
    RtspDigestAlgorithm algorithm,
    std::string_view username,
    std::string_view realm,
    std::span<const unsigned char> password);
// Computes the RTSP Digest response. When with_qop is true (the default), the
// RFC 2617/7616 quality-of-protection form is used:
//   H(HA1:nonce:nc:cnonce:auth:HA2)
// When with_qop is false, the legacy RFC 2069 form is used (nonce_count and
// cnonce are ignored):
//   H(HA1:nonce:HA2)
// The RFC 2069 form exists so MD5-only RTSP clients that do not send qop
// (GStreamer/FFmpeg/live555) can authenticate; the exchange is carried inside
// the RTSPS TLS control channel.
common::Result<common::SecureBytes> ComputeRtspDigestResponse(
    RtspDigestAlgorithm algorithm,
    std::span<const unsigned char> ha1,
    std::string_view method,
    std::string_view uri,
    std::string_view nonce,
    std::string_view nonce_count,
    std::string_view cnonce,
    bool with_qop = true);
bool RtspDigestConstantTimeEqual(std::span<const unsigned char> left,
                                 std::span<const unsigned char> right);

}  // namespace camera_firmware::rtsp
