#include "camera_firmware/ai/AiFrameTap.hpp"

#include <gtest/gtest.h>

#include "camera_firmware/media/FrameLease.hpp"

TEST(AiFrameTapTest, KeepsLatestFrameOnly) {
  camera_firmware::ai::AiFrameTap tap;
  camera_firmware::media::FrameHandle h;
  h.sequence = 42;

  tap.PublishLatest(camera_firmware::media::FrameLease(h, [] {}));

  auto latest = tap.Latest();

  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(latest->handle().sequence, 42u);
}

TEST(AiFrameTapTest, ReplacesOlderFrameWithLatestOnly) {
  camera_firmware::ai::AiFrameTap tap;
  int releases = 0;

  camera_firmware::media::FrameHandle first;
  first.sequence = 1;
  tap.PublishLatest(
      camera_firmware::media::FrameLease(first, [&] { ++releases; }));

  camera_firmware::media::FrameHandle second;
  second.sequence = 2;
  tap.PublishLatest(
      camera_firmware::media::FrameLease(second, [&] { ++releases; }));

  auto latest = tap.Latest();

  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(latest->handle().sequence, 2u);
  EXPECT_EQ(releases, 1);
}

TEST(AiFrameTapTest, LatestCloneRefPreservesReleaseCallbackSemantics) {
  camera_firmware::ai::AiFrameTap tap;
  int releases = 0;

  camera_firmware::media::FrameHandle handle;
  handle.sequence = 7;
  tap.PublishLatest(
      camera_firmware::media::FrameLease(handle, [&] { ++releases; }));

  auto first = tap.Latest();
  auto second = tap.Latest();

  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(first->handle().sequence, 7u);
  EXPECT_EQ(second->handle().sequence, 7u);
  EXPECT_EQ(releases, 0);

  first.reset();
  second.reset();
  EXPECT_EQ(releases, 0);
}
