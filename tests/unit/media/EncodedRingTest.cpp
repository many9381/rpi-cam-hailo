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
  au.bytes =
      std::make_shared<const std::vector<std::uint8_t>>(std::move(payload));
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

TEST(EncodedRingTest, SkippedTotalCountsFramesAReaderMissed) {
  camera_firmware::media::EncodedRing ring(2);
  auto reader = ring.NewReader();
  EXPECT_EQ(reader.skipped_total(), 0u);

  // Publish 5 into a capacity-2 ring without reading: publish indices 0..4,
  // only 3 and 4 remain. The reader's cursor sat at 0, so its next read skips
  // indices 0, 1, 2 -> three frames missed.
  for (int i = 0; i < 5; ++i) {
    ring.Publish(MakeAu(static_cast<std::uint64_t>(i),
                        {0, 0, 1, static_cast<std::uint8_t>(i)}));
  }
  auto first = reader.WaitNext(std::chrono::milliseconds(10));
  ASSERT_TRUE(first.has_value());
  EXPECT_EQ(first->sequence, 3u);
  EXPECT_EQ(reader.skipped_total(), 3u);

  // Reading the remaining in-ring frame skips nothing more.
  auto second = reader.WaitNext(std::chrono::milliseconds(10));
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(second->sequence, 4u);
  EXPECT_EQ(reader.skipped_total(), 3u);
}

TEST(EncodedRingTest, SkippedTotalIsPerReaderNotGlobal) {
  camera_firmware::media::EncodedRing ring(2);
  auto fast = ring.NewReader();
  auto slow = ring.NewReader();

  ring.Publish(MakeAu(0U, {0, 0, 1, 0}));
  // Fast reader keeps up: reads index 0 before it slides out.
  auto a = fast.WaitNext(std::chrono::milliseconds(10));
  ASSERT_TRUE(a.has_value());

  // Now publish 3 more (indices 1,2,3); capacity 2 keeps only 2,3.
  for (int i = 1; i <= 3; ++i) {
    ring.Publish(MakeAu(static_cast<std::uint64_t>(i),
                        {0, 0, 1, static_cast<std::uint8_t>(i)}));
  }
  // Fast reader was at index 1, which slid out -> it skips index 1 (1 frame).
  auto b = fast.WaitNext(std::chrono::milliseconds(10));
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(b->sequence, 2u);
  EXPECT_EQ(fast.skipped_total(), 1u);

  // Slow reader never read: cursor at 0, first read jumps to index 2 -> skips
  // indices 0, 1 (2 frames). Independent of the fast reader's count.
  auto c = slow.WaitNext(std::chrono::milliseconds(10));
  ASSERT_TRUE(c.has_value());
  EXPECT_EQ(c->sequence, 2u);
  EXPECT_EQ(slow.skipped_total(), 2u);
  EXPECT_EQ(fast.skipped_total(), 1u);
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
