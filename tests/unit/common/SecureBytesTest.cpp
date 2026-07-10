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

TEST(SecureBytesTest, MoveAssignmentPreservesDestinationCleanupAudit) {
  const std::array<unsigned char, 3> secret{0x10, 0x20, 0x30};
  SecureBytes destination;
  destination.assign(secret.data(), secret.size());
  SecureBytes source;

  destination = std::move(source);

  EXPECT_EQ(destination.size(), 0U);
  EXPECT_EQ(destination.zeroize_audit().count, 1U);
  EXPECT_TRUE(destination.zeroize_audit().last_verified);
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

TEST(SecureBytesTest, AppendPreservesBytesWithoutLeavingAnUncleansedOwner) {
  const std::array<unsigned char, 3> first{0x10, 0x20, 0x30};
  const std::array<unsigned char, 2> second{0x40, 0x50};
  SecureBytes secure;
  secure.assign(first.data(), first.size());

  secure.append(second.data(), second.size());

  ASSERT_EQ(secure.size(), 5U);
  EXPECT_EQ(secure.data()[0], 0x10);
  EXPECT_EQ(secure.data()[4], 0x50);
  EXPECT_GE(secure.zeroize_audit().count, 1U);
  EXPECT_TRUE(secure.zeroize_audit().last_verified);
}

TEST(SecureBytesTest, ClearVerifiesBytesAreZeroBeforeRelease) {
  const std::array<unsigned char, 4> secret{1, 2, 3, 4};
  SecureBytes secure;
  secure.assign(secret.data(), secret.size());

  secure.clear();

  EXPECT_EQ(secure.size(), 0U);
  EXPECT_EQ(secure.zeroize_audit().count, 1U);
  EXPECT_TRUE(secure.zeroize_audit().last_verified);
}

TEST(SecureBytesTest, ResizeCleansesReplacedAllocation) {
  const std::array<unsigned char, 4> secret{1, 2, 3, 4};
  SecureBytes secure;
  secure.assign(secret.data(), secret.size());

  secure.resize(8U);

  ASSERT_EQ(secure.size(), 8U);
  EXPECT_EQ(secure.data()[0], 1U);
  EXPECT_EQ(secure.data()[3], 4U);
  EXPECT_EQ(secure.data()[7], 0U);
  EXPECT_GE(secure.zeroize_audit().count, 1U);
  EXPECT_TRUE(secure.zeroize_audit().last_verified);
}
