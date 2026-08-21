#include "camera_firmware/media/IsoBmffAssembler.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

namespace {

std::vector<std::uint8_t> Box(std::string_view type,
                              std::size_t payload_size = 0U) {
  std::vector<std::uint8_t> bytes(8U + payload_size, 0U);
  const auto size = static_cast<std::uint32_t>(bytes.size());
  bytes[0] = static_cast<std::uint8_t>(size >> 24U);
  bytes[1] = static_cast<std::uint8_t>(size >> 16U);
  bytes[2] = static_cast<std::uint8_t>(size >> 8U);
  bytes[3] = static_cast<std::uint8_t>(size);
  for (std::size_t index = 0; index < 4U; ++index) {
    bytes[4U + index] = static_cast<std::uint8_t>(type[index]);
  }
  return bytes;
}

std::vector<std::uint8_t> ExtendedBox(std::string_view type,
                                      std::size_t payload_size) {
  std::vector<std::uint8_t> bytes(16U + payload_size, 0U);
  bytes[3] = 1U;
  for (std::size_t index = 0; index < 4U; ++index) {
    bytes[4U + index] = static_cast<std::uint8_t>(type[index]);
  }
  const auto size = static_cast<std::uint64_t>(bytes.size());
  for (std::size_t index = 0; index < 8U; ++index) {
    bytes[8U + index] = static_cast<std::uint8_t>(
        size >> static_cast<unsigned int>((7U - index) * 8U));
  }
  return bytes;
}

void Append(std::vector<std::uint8_t>& destination,
            const std::vector<std::uint8_t>& source) {
  destination.insert(destination.end(), source.begin(), source.end());
}

}  // namespace

TEST(IsoBmffAssemblerTest, PublishesCompleteInitAndMediaSegments) {
  const auto ftyp = Box("ftyp", 4U);
  const auto moov = Box("moov", 5U);
  const auto moof = Box("moof", 6U);
  const auto mdat = Box("mdat", 7U);
  std::vector<std::uint8_t> input;
  Append(input, ftyp);
  Append(input, moov);
  Append(input, moof);
  Append(input, mdat);

  camera_firmware::media::IsoBmffAssembler assembler;
  const auto result = assembler.Push(input);

  ASSERT_TRUE(result.ok()) << result.error().message;
  ASSERT_EQ(result.value().size(), 2U);
  EXPECT_EQ(result.value()[0].kind,
            camera_firmware::media::IsoBmffSegmentKind::kInitialization);
  std::vector<std::uint8_t> expected_init;
  Append(expected_init, ftyp);
  Append(expected_init, moov);
  EXPECT_EQ(result.value()[0].bytes, expected_init);
  EXPECT_EQ(result.value()[1].kind,
            camera_firmware::media::IsoBmffSegmentKind::kMediaFragment);
  std::vector<std::uint8_t> expected_fragment;
  Append(expected_fragment, moof);
  Append(expected_fragment, mdat);
  EXPECT_EQ(result.value()[1].bytes, expected_fragment);
  EXPECT_TRUE(assembler.Finish().ok());
}

TEST(IsoBmffAssemblerTest, HandlesSplitAndExtendedBoxHeaders) {
  const auto ftyp = Box("ftyp");
  const auto moov = ExtendedBox("moov", 9U);
  camera_firmware::media::IsoBmffAssembler assembler;

  ASSERT_TRUE(assembler.Push(std::span(ftyp).first(5U)).ok());
  std::vector<std::uint8_t> middle(ftyp.begin() + 5, ftyp.end());
  middle.insert(middle.end(), moov.begin(), moov.begin() + 11);
  const auto partial = assembler.Push(middle);
  ASSERT_TRUE(partial.ok()) << partial.error().message;
  EXPECT_TRUE(partial.value().empty());

  const auto completed = assembler.Push(
      std::span(moov).subspan(11U));

  ASSERT_TRUE(completed.ok()) << completed.error().message;
  ASSERT_EQ(completed.value().size(), 1U);
  EXPECT_EQ(completed.value()[0].kind,
            camera_firmware::media::IsoBmffSegmentKind::kInitialization);
}

TEST(IsoBmffAssemblerTest, WholeBoxPushesLeaveNothingBuffered) {
  // Steady state for mp4mux streamable output: every Push carries whole
  // boxes, so nothing should remain staged between calls.
  const auto ftyp = Box("ftyp");
  const auto moov = Box("moov");
  camera_firmware::media::IsoBmffAssembler assembler;

  std::vector<std::uint8_t> init(ftyp);
  init.insert(init.end(), moov.begin(), moov.end());
  const auto pushed = assembler.Push(init);
  ASSERT_TRUE(pushed.ok()) << pushed.error().message;
  ASSERT_EQ(pushed.value().size(), 1U);
  EXPECT_EQ(assembler.buffered_bytes(), 0U);
}

TEST(IsoBmffAssemblerTest, StagesOnlyThePartialTailAcrossPushes) {
  const auto ftyp = Box("ftyp");
  const auto moov = Box("moov");
  camera_firmware::media::IsoBmffAssembler assembler;

  std::vector<std::uint8_t> first(ftyp);
  first.insert(first.end(), moov.begin(), moov.begin() + 3);
  const auto partial = assembler.Push(first);
  ASSERT_TRUE(partial.ok()) << partial.error().message;
  EXPECT_TRUE(partial.value().empty());
  // Only moov's 3 dangling bytes stay staged; the complete ftyp box has
  // already been consumed into the init accumulator.
  EXPECT_EQ(assembler.buffered_bytes(), 3U + ftyp.size());

  const auto completed = assembler.Push(std::span(moov).subspan(3U));
  ASSERT_TRUE(completed.ok()) << completed.error().message;
  ASSERT_EQ(completed.value().size(), 1U);
  EXPECT_EQ(assembler.buffered_bytes(), 0U);
}

TEST(IsoBmffAssemblerTest, RejectsInvalidLengthsAndTopLevelOrder) {
  camera_firmware::media::IsoBmffAssembler assembler;
  auto zero_length = Box("ftyp");
  zero_length[0] = 0U;
  zero_length[1] = 0U;
  zero_length[2] = 0U;
  zero_length[3] = 0U;
  auto result = assembler.Push(zero_length);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_FMP4_BOX");

  assembler.Reset();
  auto undersized = Box("ftyp");
  undersized[3] = 7U;
  result = assembler.Push(undersized);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_FMP4_BOX");

  assembler.Reset();
  result = assembler.Push(Box("moov"));
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_FMP4_SEQUENCE");

  assembler.Reset();
  std::vector<std::uint8_t> init;
  Append(init, Box("ftyp"));
  Append(init, Box("moov"));
  ASSERT_TRUE(assembler.Push(init).ok());
  result = assembler.Push(Box("mdat"));
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_FMP4_SEQUENCE");
}

TEST(IsoBmffAssemblerTest, EnforcesBoxAndBufferedByteLimits) {
  camera_firmware::media::IsoBmffAssemblerLimits limits;
  limits.max_buffer_bytes = 24U;
  limits.max_box_bytes = 20U;
  limits.max_init_segment_bytes = 24U;
  limits.max_media_fragment_bytes = 24U;
  camera_firmware::media::IsoBmffAssembler assembler(limits);

  const auto oversized = assembler.Push(Box("ftyp", 13U));

  ASSERT_FALSE(oversized.ok());
  EXPECT_EQ(oversized.error().code, "E_FMP4_LIMIT");

  assembler.Reset();
  const std::vector<std::uint8_t> partial_header(7U, 0U);
  ASSERT_TRUE(assembler.Push(partial_header).ok());
  const std::vector<std::uint8_t> excessive_pending(18U, 0U);
  const auto excessive = assembler.Push(excessive_pending);
  ASSERT_FALSE(excessive.ok());
  EXPECT_EQ(excessive.error().code, "E_FMP4_LIMIT");
}

TEST(IsoBmffAssemblerTest, FinishRejectsTruncatedBox) {
  camera_firmware::media::IsoBmffAssembler assembler;
  const auto ftyp = Box("ftyp", 8U);
  ASSERT_TRUE(assembler.Push(std::span(ftyp).first(10U)).ok());

  const auto finished = assembler.Finish();

  ASSERT_FALSE(finished.ok());
  EXPECT_EQ(finished.error().code, "E_FMP4_TRUNCATED");
}
