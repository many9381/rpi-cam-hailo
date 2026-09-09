#include "camera_firmware/media/FragmentRing.hpp"

#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace std::chrono_literals;
namespace media = camera_firmware::media;

std::vector<std::uint8_t> Bytes(std::size_t size, std::uint8_t value) {
  return std::vector<std::uint8_t>(size, value);
}

media::FragmentedMp4Chunk ReadRequired(media::FragmentRing::Reader& reader) {
  auto result = reader.WaitNext(20ms);
  EXPECT_TRUE(result.ok()) << result.error().message;
  if (!result.ok() || !result.value().has_value()) {
    return {};
  }
  return *result.value();
}

}  // namespace

TEST(FragmentRingTest, ReaderGetsInitThenLatestRandomAccessFragment) {
  media::FragmentRing ring(
      {.max_fragments = 4U, .max_bytes = 1024U, .max_readers = 2U});
  const auto generation = ring.BeginGeneration(Bytes(12U, 0x11U));
  ASSERT_TRUE(generation.ok()) << generation.error().message;
  ASSERT_TRUE(ring.Publish(Bytes(10U, 0x21U), true).ok());
  ASSERT_TRUE(ring.Publish(Bytes(10U, 0x22U), false).ok());
  ASSERT_TRUE(ring.Publish(Bytes(10U, 0x23U), true).ok());

  auto opened = ring.OpenReader();
  ASSERT_TRUE(opened.ok()) << opened.error().message;
  auto reader = std::move(opened).value();
  const auto init = ReadRequired(reader);
  const auto fragment = ReadRequired(reader);

  EXPECT_EQ(init.kind, media::FragmentedMp4ChunkKind::kInitialization);
  EXPECT_EQ(init.generation, generation.value());
  ASSERT_TRUE(init.bytes);
  EXPECT_EQ(*init.bytes, Bytes(12U, 0x11U));
  EXPECT_EQ(fragment.kind, media::FragmentedMp4ChunkKind::kMediaFragment);
  EXPECT_EQ(fragment.sequence, 3U);
  EXPECT_TRUE(fragment.random_access);
  ASSERT_TRUE(fragment.bytes);
  EXPECT_EQ(*fragment.bytes, Bytes(10U, 0x23U));
}

TEST(FragmentRingTest, SlowReaderJumpsToLatestRetainedRandomAccessFragment) {
  media::FragmentRing ring(
      {.max_fragments = 2U, .max_bytes = 1024U, .max_readers = 1U});
  ASSERT_TRUE(ring.BeginGeneration(Bytes(8U, 0x10U)).ok());
  ASSERT_TRUE(ring.Publish(Bytes(8U, 0x31U), true).ok());
  auto opened = ring.OpenReader();
  ASSERT_TRUE(opened.ok());
  auto reader = std::move(opened).value();
  EXPECT_EQ(ReadRequired(reader).kind,
            media::FragmentedMp4ChunkKind::kInitialization);

  ASSERT_TRUE(ring.Publish(Bytes(8U, 0x32U), true).ok());
  ASSERT_TRUE(ring.Publish(Bytes(8U, 0x33U), true).ok());
  const auto fragment = ReadRequired(reader);

  EXPECT_EQ(fragment.sequence, 3U);
  ASSERT_TRUE(fragment.bytes);
  EXPECT_EQ(*fragment.bytes, Bytes(8U, 0x33U));
  EXPECT_EQ(ring.overrun_total(), 1U);
}

TEST(FragmentRingTest, GenerationReplacementTerminatesOldReader) {
  media::FragmentRing ring(
      {.max_fragments = 2U, .max_bytes = 1024U, .max_readers = 2U});
  const auto first_generation = ring.BeginGeneration(Bytes(8U, 0x41U));
  ASSERT_TRUE(first_generation.ok());
  auto first_opened = ring.OpenReader();
  ASSERT_TRUE(first_opened.ok());
  auto first_reader = std::move(first_opened).value();
  EXPECT_EQ(ReadRequired(first_reader).generation, first_generation.value());

  const auto second_generation = ring.BeginGeneration(Bytes(8U, 0x42U));
  ASSERT_TRUE(second_generation.ok());
  EXPECT_GT(second_generation.value(), first_generation.value());
  const auto old_read = first_reader.WaitNext(20ms);
  ASSERT_FALSE(old_read.ok());
  EXPECT_EQ(old_read.error().code, "E_LIVE_GENERATION");

  auto second_opened = ring.OpenReader();
  ASSERT_TRUE(second_opened.ok());
  auto second_reader = std::move(second_opened).value();
  const auto second_init = ReadRequired(second_reader);
  EXPECT_EQ(second_init.generation, second_generation.value());
  ASSERT_TRUE(second_init.bytes);
  EXPECT_EQ(*second_init.bytes, Bytes(8U, 0x42U));
}

TEST(FragmentRingTest, EnforcesReaderAndRetainedByteLimits) {
  media::FragmentRing ring(
      {.max_fragments = 4U, .max_bytes = 28U, .max_readers = 1U});
  ASSERT_TRUE(ring.BeginGeneration(Bytes(8U, 0x51U)).ok());
  ASSERT_TRUE(ring.Publish(Bytes(10U, 0x52U), true).ok());
  ASSERT_TRUE(ring.Publish(Bytes(10U, 0x53U), true).ok());
  EXPECT_EQ(ring.retained_bytes(), 28U);
  ASSERT_TRUE(ring.Publish(Bytes(10U, 0x54U), true).ok());
  EXPECT_EQ(ring.retained_bytes(), 28U);
  EXPECT_EQ(ring.overrun_total(), 1U);

  auto first = ring.OpenReader();
  ASSERT_TRUE(first.ok());
  auto second = ring.OpenReader();
  ASSERT_FALSE(second.ok());
  EXPECT_EQ(second.error().code, "E_LIVE_CAPACITY");
  EXPECT_EQ(ring.active_readers(), 1U);

  auto reader = std::move(first).value();
  reader = {};
  EXPECT_EQ(ring.active_readers(), 0U);
}

TEST(FragmentRingTest, InvalidateWakesBlockedReader) {
  media::FragmentRing ring(
      {.max_fragments = 2U, .max_bytes = 1024U, .max_readers = 1U});
  ASSERT_TRUE(ring.BeginGeneration(Bytes(8U, 0x61U)).ok());
  auto opened = ring.OpenReader();
  ASSERT_TRUE(opened.ok());
  auto reader = std::move(opened).value();
  (void)ReadRequired(reader);

  std::promise<void> wait_next_starting;
  auto wait_next_starting_future = wait_next_starting.get_future();
  auto blocked = std::async(std::launch::async, [&] {
    wait_next_starting.set_value();
    return reader.WaitNext(std::chrono::seconds(5));
  });
  ASSERT_EQ(wait_next_starting_future.wait_for(1s), std::future_status::ready);

  ring.Invalidate();

  ASSERT_EQ(blocked.wait_for(200ms), std::future_status::ready);
  const auto result = blocked.get();
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_LIVE_GENERATION");
}

TEST(FragmentRingTest, CancelWakesBlockedReaderWithoutInvalidatingGeneration) {
  media::FragmentRing ring(
      {.max_fragments = 2U, .max_bytes = 1024U, .max_readers = 1U});
  ASSERT_TRUE(ring.BeginGeneration(Bytes(8U, 0x62U)).ok());
  auto opened = ring.OpenReader();
  ASSERT_TRUE(opened.ok());
  auto reader = std::move(opened).value();
  (void)ReadRequired(reader);

  auto blocked = std::async(std::launch::async, [&] {
    return reader.WaitNext(std::chrono::seconds(5));
  });
  const auto wait_deadline = media::FragmentRing::Clock::now() + 1s;
  while (ring.waiting_readers() != 1U &&
         media::FragmentRing::Clock::now() < wait_deadline) {
    std::this_thread::yield();
  }
  ASSERT_EQ(ring.waiting_readers(), 1U);

  reader.Cancel();

  ASSERT_EQ(blocked.wait_for(200ms), std::future_status::ready);
  const auto result = blocked.get();
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_LIVE_CANCELLED");
  EXPECT_FALSE(reader.valid());
  EXPECT_EQ(ring.active_readers(), 0U);

  reader.Cancel();
  EXPECT_EQ(ring.active_readers(), 0U);

  auto replacement = ring.OpenReader();
  ASSERT_TRUE(replacement.ok()) << replacement.error().message;
  EXPECT_EQ(ReadRequired(replacement.value()).kind,
            media::FragmentedMp4ChunkKind::kInitialization);
}

TEST(FragmentRingTest, OversizedFragmentInvalidatesGeneration) {
  media::FragmentRing ring(
      {.max_fragments = 2U, .max_bytes = 20U, .max_readers = 1U});
  ASSERT_TRUE(ring.BeginGeneration(Bytes(8U, 0x71U)).ok());
  auto opened = ring.OpenReader();
  ASSERT_TRUE(opened.ok());
  auto reader = std::move(opened).value();
  (void)ReadRequired(reader);

  const auto published = ring.Publish(Bytes(13U, 0x72U), true);

  ASSERT_FALSE(published.ok());
  EXPECT_EQ(published.error().code, "E_LIVE_LIMIT");
  const auto read = reader.WaitNext(20ms);
  ASSERT_FALSE(read.ok());
  EXPECT_EQ(read.error().code, "E_LIVE_GENERATION");
  auto next_open = ring.OpenReader();
  ASSERT_FALSE(next_open.ok());
  EXPECT_EQ(next_open.error().code, "E_LIVE_UNAVAILABLE");
}

TEST(FragmentRingTest, RejectsNewReaderForStaleGeneration) {
  auto now = media::FragmentRing::Clock::time_point{};
  media::FragmentRing ring(
      {.max_fragments = 2U, .max_bytes = 1024U, .max_readers = 1U},
      [&now] { return now; });
  ASSERT_TRUE(ring.BeginGeneration(Bytes(8U, 0x81U)).ok());
  ASSERT_TRUE(ring.Publish(Bytes(8U, 0x82U), true).ok());

  now += 2001ms;
  const auto opened = ring.OpenReader(2000ms);

  ASSERT_FALSE(opened.ok());
  EXPECT_EQ(opened.error().code, "E_LIVE_STALE");
}

TEST(FragmentRingTest, PublicationRefreshesReaderAdmissionDeadline) {
  auto now = media::FragmentRing::Clock::time_point{};
  media::FragmentRing ring(
      {.max_fragments = 2U, .max_bytes = 1024U, .max_readers = 1U},
      [&now] { return now; });
  ASSERT_TRUE(ring.BeginGeneration(Bytes(8U, 0x91U)).ok());

  now += 1900ms;
  ASSERT_TRUE(ring.Publish(Bytes(8U, 0x92U), true).ok());
  now += 1900ms;
  auto opened = ring.OpenReader(2000ms);

  ASSERT_TRUE(opened.ok()) << opened.error().message;
}
