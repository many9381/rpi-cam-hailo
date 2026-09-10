#include "camera_firmware/rtsp/SrtpSessionKey.hpp"

#include "camera_firmware/config/AppConfig.hpp"

#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

TEST(SrtpSessionKeyTest, ParsesThirtyByteHexKey) {
  auto key = camera_firmware::rtsp::SrtpSessionKey::FromHex(
      "00112233445566778899aabbccddeeff00112233445566778899aabbccdd");
  ASSERT_TRUE(key.ok()) << key.error().message;
  EXPECT_EQ(key.value().size(), 30u);
}

TEST(SrtpSessionKeyTest, RejectsWrongLength) {
  auto key = camera_firmware::rtsp::SrtpSessionKey::FromHex("0011");
  ASSERT_FALSE(key.ok());
  EXPECT_EQ(key.error().code, "E_SRTP_KEY_LENGTH");
}

TEST(SrtpSessionKeyTest, FileLoaderZeroizesTemporaryStorageOnSuccess) {
  const auto key_path =
      std::filesystem::temp_directory_path() / "cf-loader-success.hex";
  {
    std::ofstream out(key_path);
    out << std::string(60, 'a') << "\n";
  }

  camera_firmware::config::SessionKeyConfig config;
  config.path = key_path.string();
  camera_firmware::rtsp::SessionKeyLoadDiagnostics diagnostics;

  auto loaded = camera_firmware::rtsp::LoadSrtpSessionKey(config, &diagnostics);

  std::filesystem::remove(key_path);
  ASSERT_TRUE(loaded.ok()) << loaded.error().message;
  EXPECT_EQ(loaded.value().size(),
            camera_firmware::rtsp::SrtpSessionKey::kAes128IcmHmacSha180Bytes);
  EXPECT_GE(diagnostics.temporary_zeroize_count, 1u);
}

TEST(SrtpSessionKeyTest, FileLoaderZeroizesTemporaryStorageOnParseError) {
  const auto key_path =
      std::filesystem::temp_directory_path() / "cf-loader-error.hex";
  {
    std::ofstream out(key_path);
    out << "not-a-valid-srtp-key";
  }

  camera_firmware::config::SessionKeyConfig config;
  config.path = key_path.string();
  camera_firmware::rtsp::SessionKeyLoadDiagnostics diagnostics;

  auto loaded = camera_firmware::rtsp::LoadSrtpSessionKey(config, &diagnostics);

  std::filesystem::remove(key_path);
  ASSERT_FALSE(loaded.ok());
  EXPECT_GE(diagnostics.temporary_zeroize_count, 1u);
}

TEST(SrtpSessionKeyTest, FileLoaderRejectsOversizedTemporaryKeyFile) {
  const auto key_path =
      std::filesystem::temp_directory_path() / "cf-loader-oversized.hex";
  {
    std::ofstream out(key_path);
    out << std::string(4097, 'a');
  }

  camera_firmware::config::SessionKeyConfig config;
  config.path = key_path.string();
  camera_firmware::rtsp::SessionKeyLoadDiagnostics diagnostics;

  auto loaded = camera_firmware::rtsp::LoadSrtpSessionKey(config, &diagnostics);

  std::filesystem::remove(key_path);
  ASSERT_FALSE(loaded.ok());
  EXPECT_EQ(loaded.error().code, "E_SRTP_KEY_TOO_LARGE");
  EXPECT_GE(diagnostics.temporary_zeroize_count, 1u);
}
