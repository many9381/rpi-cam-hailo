#pragma once

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/config/AppConfig.hpp"

#include <cstddef>
#include <string_view>

namespace camera_firmware::rtsp {

class SrtpSessionKey {
 public:
  static constexpr std::size_t kAes128IcmHmacSha180Bytes = 30;

  SrtpSessionKey() = default;
  ~SrtpSessionKey() = default;

  SrtpSessionKey(const SrtpSessionKey&) = delete;
  SrtpSessionKey& operator=(const SrtpSessionKey&) = delete;

  SrtpSessionKey(SrtpSessionKey&&) noexcept = default;
  SrtpSessionKey& operator=(SrtpSessionKey&&) noexcept = default;

  static common::Result<SrtpSessionKey> FromHex(std::string_view hex);

  [[nodiscard]] const unsigned char* data() const noexcept;
  [[nodiscard]] std::size_t size() const noexcept;
  [[nodiscard]] std::size_t zeroize_count_for_test() const noexcept;

 private:
  common::SecureBytes bytes_;
};

struct SessionKeyLoadDiagnostics {
  std::size_t temporary_zeroize_count{0};
};

common::Result<SrtpSessionKey> LoadSrtpSessionKey(
    const config::SessionKeyConfig& session_key_config,
    SessionKeyLoadDiagnostics* diagnostics = nullptr);

}  // namespace camera_firmware::rtsp
