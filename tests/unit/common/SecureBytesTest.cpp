#include "camera_firmware/common/SecureBytes.hpp"

#include <array>
#include <utility>

#include <gtest/gtest.h>

using camera_firmware::common::SecureBytes;

TEST(SecureBytesTest, ClearZeroizesOwnedBytes) {
  std::array<unsigned char, 4> bytes{0x11, 0x22, 0x33, 0x44};
  SecureBytes secure;
  secure.assign(bytes.data(), bytes.size());
  ASSERT_EQ(secure.size(), 4u);

  secure.clear();

  EXPECT_EQ(secure.size(), 0u);
  EXPECT_EQ(secure.zeroize_count_for_test(), 1u);
}

TEST(SecureBytesTest, MoveTransfersOwnershipWithoutExtraCopy) {
  std::array<unsigned char, 2> bytes{0xaa, 0xbb};
  SecureBytes secure;
  secure.assign(bytes.data(), bytes.size());

  SecureBytes moved(std::move(secure));

  EXPECT_EQ(moved.size(), 2u);
  EXPECT_EQ(secure.size(), 0u);
}

TEST(SecureBytesTest, ReassignZeroizesExistingOwnedBytesBeforeOverwrite) {
  std::array<unsigned char, 4> initial{0x10, 0x20, 0x30, 0x40};
  std::array<unsigned char, 4> replacement{0xaa, 0xbb, 0xcc, 0xdd};
  SecureBytes secure;
  secure.assign(initial.data(), initial.size());

  secure.assign(replacement.data(), replacement.size());

  ASSERT_EQ(secure.size(), replacement.size());
  EXPECT_EQ(secure.zeroize_count_for_test(), 1u);
  EXPECT_EQ(secure.data()[0], replacement[0]);
  EXPECT_EQ(secure.data()[1], replacement[1]);
  EXPECT_EQ(secure.data()[2], replacement[2]);
  EXPECT_EQ(secure.data()[3], replacement[3]);
}
