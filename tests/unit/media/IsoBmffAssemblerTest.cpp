#include "camera_firmware/media/IsoBmffAssembler.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
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

namespace {

void AppendBigEndian32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 24U));
  out.push_back(static_cast<std::uint8_t>(value >> 16U));
  out.push_back(static_cast<std::uint8_t>(value >> 8U));
  out.push_back(static_cast<std::uint8_t>(value));
}

std::vector<std::uint8_t> FullBox(const char* type,
                                  std::uint32_t version_and_flags,
                                  const std::vector<std::uint8_t>& payload) {
  std::vector<std::uint8_t> out;
  AppendBigEndian32(out, static_cast<std::uint32_t>(12U + payload.size()));
  out.insert(out.end(), type, type + 4);
  AppendBigEndian32(out, version_and_flags);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

std::vector<std::uint8_t> Container(const char* type,
                                    const std::vector<std::uint8_t>& children) {
  std::vector<std::uint8_t> out;
  AppendBigEndian32(out, static_cast<std::uint32_t>(8U + children.size()));
  out.insert(out.end(), type, type + 4);
  out.insert(out.end(), children.begin(), children.end());
  return out;
}

// Builds moof{ mfhd, traf{ tfhd, trun } }. Passing std::nullopt omits the
// respective sample-flags field from the box.
std::vector<std::uint8_t> MoofFragment(
    std::optional<std::uint32_t> tfhd_default_sample_flags,
    std::optional<std::uint32_t> trun_first_sample_flags) {
  std::vector<std::uint8_t> tfhd_payload;
  AppendBigEndian32(tfhd_payload, 1U);  // track_ID
  std::uint32_t tfhd_flags = 0U;
  if (tfhd_default_sample_flags.has_value()) {
    tfhd_flags |= 0x000020U;
    AppendBigEndian32(tfhd_payload, *tfhd_default_sample_flags);
  }
  const auto tfhd = FullBox("tfhd", tfhd_flags, tfhd_payload);

  std::uint32_t trun_flags = 0x000001U;  // data-offset present
  std::vector<std::uint8_t> trun_payload;
  AppendBigEndian32(trun_payload, 2U);  // sample_count
  AppendBigEndian32(trun_payload, 0U);  // data_offset
  if (trun_first_sample_flags.has_value()) {
    trun_flags |= 0x000004U;  // first-sample-flags present
    AppendBigEndian32(trun_payload, *trun_first_sample_flags);
  }
  const auto trun = FullBox("trun", trun_flags, trun_payload);

  std::vector<std::uint8_t> traf_children(tfhd);
  traf_children.insert(traf_children.end(), trun.begin(), trun.end());
  const auto traf = Container("traf", traf_children);

  const auto mfhd = FullBox("mfhd", 0U, {0U, 0U, 0U, 1U});
  std::vector<std::uint8_t> moof_children(mfhd);
  moof_children.insert(moof_children.end(), traf.begin(), traf.end());
  auto fragment = Container("moof", moof_children);

  const auto mdat = Box("mdat");
  fragment.insert(fragment.end(), mdat.begin(), mdat.end());
  return fragment;
}

constexpr std::uint32_t kNonSyncBit = 0x00010000U;

// mp4mux's actual trun shape (flags 0x701): data_offset + per-sample
// duration/size/flags entries, no first-sample-flags field.
std::vector<std::uint8_t> MoofWithPerSampleFlags(
    std::uint32_t first_entry_flags) {
  const auto tfhd = FullBox("tfhd", 0U, {0U, 0U, 0U, 1U});

  std::vector<std::uint8_t> trun_payload;
  AppendBigEndian32(trun_payload, 2U);   // sample_count
  AppendBigEndian32(trun_payload, 0U);   // data_offset
  AppendBigEndian32(trun_payload, 20U);  // entry0 duration
  AppendBigEndian32(trun_payload, 999U); // entry0 size
  AppendBigEndian32(trun_payload, first_entry_flags);
  AppendBigEndian32(trun_payload, 20U);  // entry1 duration
  AppendBigEndian32(trun_payload, 888U); // entry1 size
  AppendBigEndian32(trun_payload, kNonSyncBit | 0xC0U);
  const auto trun = FullBox("trun", 0x000701U, trun_payload);

  std::vector<std::uint8_t> traf_children(tfhd);
  traf_children.insert(traf_children.end(), trun.begin(), trun.end());
  const auto traf = Container("traf", traf_children);
  const auto mfhd = FullBox("mfhd", 0U, {0U, 0U, 0U, 1U});
  std::vector<std::uint8_t> moof_children(mfhd);
  moof_children.insert(moof_children.end(), traf.begin(), traf.end());
  auto fragment = Container("moof", moof_children);
  const auto mdat = Box("mdat");
  fragment.insert(fragment.end(), mdat.begin(), mdat.end());
  return fragment;
}

}  // namespace

TEST(IsoBmffAssemblerTest, RandomAccessReadsPerSampleFlagsLikeMp4mux) {
  EXPECT_TRUE(camera_firmware::media::IsFragmentRandomAccess(
      MoofWithPerSampleFlags(0x00000040U)));  // observed sync entry0
  EXPECT_FALSE(camera_firmware::media::IsFragmentRandomAccess(
      MoofWithPerSampleFlags(kNonSyncBit | 0xC0U)));  // observed mid-GOP
}

TEST(IsoBmffAssemblerTest, RandomAccessFollowsTrunFirstSampleFlags) {
  EXPECT_TRUE(camera_firmware::media::IsFragmentRandomAccess(
      MoofFragment(std::nullopt, 0x02000000U)));
  EXPECT_FALSE(camera_firmware::media::IsFragmentRandomAccess(
      MoofFragment(std::nullopt, kNonSyncBit)));
}

TEST(IsoBmffAssemblerTest, RandomAccessFallsBackToTfhdDefaultFlags) {
  EXPECT_TRUE(camera_firmware::media::IsFragmentRandomAccess(
      MoofFragment(0x02000000U, std::nullopt)));
  EXPECT_FALSE(camera_firmware::media::IsFragmentRandomAccess(
      MoofFragment(kNonSyncBit, std::nullopt)));
  // trun first-sample flags outrank the tfhd default.
  EXPECT_TRUE(camera_firmware::media::IsFragmentRandomAccess(
      MoofFragment(kNonSyncBit, 0x02000000U)));
}

TEST(IsoBmffAssemblerTest, RandomAccessIsConservativeWhenFlagsAreAbsent) {
  EXPECT_FALSE(camera_firmware::media::IsFragmentRandomAccess(
      MoofFragment(std::nullopt, std::nullopt)));
  EXPECT_FALSE(camera_firmware::media::IsFragmentRandomAccess(Box("mdat")));
  EXPECT_FALSE(camera_firmware::media::IsFragmentRandomAccess({}));
}

TEST(IsoBmffAssemblerTest, FinishRejectsTruncatedBox) {
  camera_firmware::media::IsoBmffAssembler assembler;
  const auto ftyp = Box("ftyp", 8U);
  ASSERT_TRUE(assembler.Push(std::span(ftyp).first(10U)).ok());

  const auto finished = assembler.Finish();

  ASSERT_FALSE(finished.ok());
  EXPECT_EQ(finished.error().code, "E_FMP4_TRUNCATED");
}
