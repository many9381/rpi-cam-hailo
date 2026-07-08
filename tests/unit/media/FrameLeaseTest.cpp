#include "camera_firmware/media/FrameLease.hpp"

#include <gtest/gtest.h>
#include <stdexcept>

TEST(FrameLeaseTest, InvalidHandleAccessThrowsLogicError) {
  camera_firmware::media::FrameLease lease;

  EXPECT_THROW((void)lease.handle(), std::logic_error);
  EXPECT_THROW((void)*lease, std::logic_error);
}

TEST(FrameLeaseTest, InvalidArrowAccessThrowsLogicError) {
  camera_firmware::media::FrameLease lease;

  EXPECT_THROW((void)lease.operator->(), std::logic_error);
}

TEST(FrameLeaseTest, ReleaseRunsOnceAfterLastCloneDrops) {
  int releases = 0;
  camera_firmware::media::FrameHandle h;
  h.width = 640;
  {
    camera_firmware::media::FrameLease lease(h, [&] { ++releases; });
    auto clone = lease.CloneRef();
    EXPECT_EQ(releases, 0);
  }
  EXPECT_EQ(releases, 1);
}
