#include "camera_firmware/media/FrameLease.hpp"

#include <gtest/gtest.h>

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
