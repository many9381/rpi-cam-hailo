#include "camera_firmware/rtsp/SrtpSessionKey.hpp"

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
