#include "camera_firmware/media/EncodedRing.hpp"

#include <chrono>
#include <cstdint>

#include <gtest/gtest.h>

TEST(EncodedRingTest, SlowReaderDoesNotBlockPublisher) {
  camera_firmware::media::EncodedRing ring(2);
  auto reader = ring.NewReader();
  for (int i = 0; i < 10; ++i) {
    camera_firmware::media::EncodedAccessUnit au;
    au.sequence = i;
    au.bytes = {0, 0, 1, static_cast<std::uint8_t>(i)};
    ring.Publish(au);
  }
  auto latest = reader.WaitNext(std::chrono::milliseconds(10));
  ASSERT_TRUE(latest.has_value());
  EXPECT_GE(latest->sequence, 8u);
  EXPECT_GT(ring.overrun_total(), 0u);
}
