#include "camera_firmware/rtsp/SrtpSessionKey.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>

#if defined(CAMERA_FIRMWARE_HAS_OPENSSL)
#include <openssl/crypto.h>
#endif

namespace camera_firmware::rtsp {

namespace {

constexpr std::size_t kHexCharsPerByte = 2;
constexpr std::size_t kMaxSessionKeyFileBytes = 4096;

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

void ZeroizeMemory(unsigned char* data, std::size_t size) noexcept {
  if (data == nullptr || size == 0U) {
    return;
  }
#if defined(CAMERA_FIRMWARE_HAS_OPENSSL)
  OPENSSL_cleanse(data, size);
#else
  volatile unsigned char* cursor = data;
  for (std::size_t index = 0; index < size; ++index) {
    cursor[index] = 0U;
  }
#endif
}

class ZeroizingByteBuffer {
 public:
  ZeroizingByteBuffer() = default;
  ~ZeroizingByteBuffer() { clear(); }

  ZeroizingByteBuffer(const ZeroizingByteBuffer&) = delete;
  ZeroizingByteBuffer& operator=(const ZeroizingByteBuffer&) = delete;

  bool append(const unsigned char* data, std::size_t size) {
    if (size > bytes_.size() - size_) {
      return false;
    }
    std::copy(data, data + size, bytes_.data() + size_);
    size_ += size;
    return true;
  }

  void trim_ascii_whitespace() {
    std::size_t write_index = 0;
    for (std::size_t read_index = 0; read_index < size_; ++read_index) {
      const unsigned char c = bytes_[read_index];
      if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
        continue;
      }
      bytes_[write_index++] = c;
    }
    if (write_index != size_) {
      ZeroizeMemory(bytes_.data() + write_index, size_ - write_index);
      size_ = write_index;
      ++zeroize_count_;
    }
  }

  void clear() noexcept {
    if (size_ == 0U) {
      return;
    }
    ZeroizeMemory(bytes_.data(), size_);
    ++zeroize_count_;
    size_ = 0;
  }

  const unsigned char* data() const noexcept { return bytes_.data(); }
  std::size_t size() const noexcept { return size_; }
  std::size_t zeroize_count() const noexcept { return zeroize_count_; }

 private:
  std::array<unsigned char, kMaxSessionKeyFileBytes> bytes_{};
  std::size_t size_{0};
  std::size_t zeroize_count_{0};
};

void PublishDiagnostics(const ZeroizingByteBuffer& buffer,
                        SessionKeyLoadDiagnostics* diagnostics) {
  if (diagnostics != nullptr) {
    diagnostics->temporary_zeroize_count = buffer.zeroize_count();
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

std::size_t SrtpSessionKey::size() const noexcept {
  return bytes_.size();
}

std::size_t SrtpSessionKey::zeroize_count_for_test() const noexcept {
  return bytes_.zeroize_count_for_test();
}

common::Result<SrtpSessionKey> LoadSrtpSessionKey(
    const config::SessionKeyConfig& session_key_config,
    SessionKeyLoadDiagnostics* diagnostics) {
  if (diagnostics != nullptr) {
    diagnostics->temporary_zeroize_count = 0;
  }
  if (session_key_config.source != "file") {
    return common::Result<SrtpSessionKey>::Err(
        {"E_SRTP_KEY_SOURCE",
         "only file-backed SRTP session keys are supported"});
  }
  if (session_key_config.encoding != "hex") {
    return common::Result<SrtpSessionKey>::Err(
        {"E_SRTP_KEY_ENCODING", "only hex SRTP session keys are supported"});
  }

  FILE* file = std::fopen(session_key_config.path.c_str(), "rb");
  if (file == nullptr) {
    return common::Result<SrtpSessionKey>::Err(
        {"E_SRTP_KEY_IO", "failed to read SRTP session key file"});
  }

  ZeroizingByteBuffer buffer;
  std::array<unsigned char, 256> chunk{};
  bool too_large = false;
  while (true) {
    const std::size_t read = std::fread(chunk.data(), 1, chunk.size(), file);
    if (read > 0U) {
      if (!buffer.append(chunk.data(), read)) {
        too_large = true;
        ZeroizeArray(chunk);
        break;
      }
      ZeroizeArray(chunk);
    }
    if (read < chunk.size()) {
      if (std::ferror(file) != 0) {
        static_cast<void>(std::fclose(file));  // read-only stream
        ZeroizeArray(chunk);
        buffer.clear();
        PublishDiagnostics(buffer, diagnostics);
        return common::Result<SrtpSessionKey>::Err(
            {"E_SRTP_KEY_IO", "failed to read SRTP session key file"});
      }
      break;
    }
  }
  static_cast<void>(std::fclose(file));  // read-only stream
  ZeroizeArray(chunk);

  if (too_large) {
    buffer.clear();
    PublishDiagnostics(buffer, diagnostics);
    return common::Result<SrtpSessionKey>::Err(
        {"E_SRTP_KEY_TOO_LARGE",
         "SRTP session key file exceeds the maximum supported size"});
  }

  buffer.trim_ascii_whitespace();
  auto parsed = SrtpSessionKey::FromHex(std::string_view(
      reinterpret_cast<const char*>(buffer.data()), buffer.size()));
  buffer.clear();
  PublishDiagnostics(buffer, diagnostics);
  if (!parsed.ok()) {
    return common::Result<SrtpSessionKey>::Err(parsed.error());
  }

  return common::Result<SrtpSessionKey>::Ok(std::move(parsed).value());
}

}  // namespace camera_firmware::rtsp
