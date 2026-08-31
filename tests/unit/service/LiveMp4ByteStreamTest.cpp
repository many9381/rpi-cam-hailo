#include "LiveMp4ByteStream.hpp"

#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace {

namespace media = camera_firmware::media;
using namespace std::chrono_literals;

media::FragmentRingLimits TestLimits() {
  return {.max_fragments = 4U, .max_bytes = 1024U, .max_readers = 2U};
}

std::vector<std::uint8_t> SmallInit() {
  return std::vector<std::uint8_t>(8U, 0xA1U);
}

std::vector<std::uint8_t> SmallFragment() {
  return std::vector<std::uint8_t>(8U, 0xB2U);
}

}  // namespace

TEST(LiveMp4ByteStreamTest, WaitTimeoutKeepsTheStreamAliveUntilNextFragment) {
  media::FragmentRing ring(TestLimits());
  ASSERT_TRUE(ring.BeginGeneration(SmallInit()).ok());
  auto opened = ring.OpenReader();
  ASSERT_TRUE(opened.ok()) << opened.error().message;
  LiveMp4ByteStream stream(std::move(opened).value(),
                            /*stale_timeout=*/std::chrono::milliseconds{30},
                            /*maximum_idle=*/std::chrono::milliseconds{10000});

  char buffer[1024];
  ASSERT_GT(stream.Read(buffer, sizeof buffer), 0U);  // init segment

  // Publish the next fragment 200ms later -- several stale_timeout ticks.
  std::thread publisher([&] {
    std::this_thread::sleep_for(std::chrono::milliseconds{200});
    ASSERT_TRUE(ring.Publish(SmallFragment(), /*random_access=*/true).ok());
  });
  const auto n = stream.Read(buffer, sizeof buffer);  // must survive the gap
  publisher.join();
  EXPECT_GT(n, 0U);
}

TEST(LiveMp4ByteStreamTest, IdleBeyondMaximumIdleEndsTheStream) {
  media::FragmentRing ring(TestLimits());
  ASSERT_TRUE(ring.BeginGeneration(SmallInit()).ok());
  auto opened = ring.OpenReader();
  ASSERT_TRUE(opened.ok()) << opened.error().message;
  LiveMp4ByteStream stream(std::move(opened).value(),
                            /*stale_timeout=*/std::chrono::milliseconds{20},
                            /*maximum_idle=*/std::chrono::milliseconds{60});

  char buffer[1024];
  ASSERT_GT(stream.Read(buffer, sizeof buffer), 0U);  // init segment

  const auto started = std::chrono::steady_clock::now();
  const auto n = stream.Read(buffer, sizeof buffer);  // nothing ever published
  const auto elapsed = std::chrono::steady_clock::now() - started;

  EXPECT_EQ(n, 0U);
  EXPECT_GE(elapsed, std::chrono::milliseconds{60});
}
