#include "camera_firmware/media/EncodedRing.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

namespace {

camera_firmware::media::EncodedAccessUnit MakeAu(
    std::uint64_t sequence, std::vector<std::uint8_t> payload) {
  camera_firmware::media::EncodedAccessUnit au;
  au.sequence = sequence;
  au.bytes = std::make_shared<const std::vector<std::uint8_t>>(
      std::move(payload));
  return au;
}

}  // namespace

TEST(EncodedRingTest, SlowReaderDoesNotBlockPublisher) {
  camera_firmware::media::EncodedRing ring(2);
  auto reader = ring.NewReader();
  for (int i = 0; i < 10; ++i) {
    ring.Publish(MakeAu(static_cast<std::uint64_t>(i),
                        {0, 0, 1, static_cast<std::uint8_t>(i)}));
  }
  auto latest = reader.WaitNext(std::chrono::milliseconds(10));
  ASSERT_TRUE(latest.has_value());
  EXPECT_GE(latest->sequence, 8u);
  EXPECT_GT(ring.overrun_total(), 0u);
}

TEST(EncodedRingTest, ReadersShareTheAccessUnitStorage) {
  // WaitNext must hand every reader a reference to the SAME immutable byte
  // buffer, not a per-reader deep copy — the whole point of the shared_ptr
  // payload is one allocation per access unit regardless of reader count.
  camera_firmware::media::EncodedRing ring(4);
  auto first = ring.NewReader();
  auto second = ring.NewReader();
  ring.Publish(MakeAu(1U, {0, 0, 1, 42}));

  auto a = first.WaitNext(std::chrono::milliseconds(10));
  auto b = second.WaitNext(std::chrono::milliseconds(10));
  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());
  ASSERT_NE(a->bytes, nullptr);
  EXPECT_EQ(a->bytes.get(), b->bytes.get());
  EXPECT_EQ((*a->bytes)[3], 42U);
}
