#include "camera_firmware/media/FragmentedMp4Hub.hpp"

#include <x264.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace std::chrono_literals;
namespace media = camera_firmware::media;

struct X264Deleter {
  void operator()(x264_t* encoder) const noexcept {
    if (encoder != nullptr) {
      x264_encoder_close(encoder);
    }
  }
};

std::vector<media::EncodedAccessUnit> EncodeAnnexBFrames(int width, int height,
                                                         int fps, int gop,
                                                         int frame_count) {
  x264_param_t params{};
  EXPECT_EQ(x264_param_default_preset(&params, "ultrafast", "zerolatency"), 0);
  params.i_width = width;
  params.i_height = height;
  params.i_csp = X264_CSP_I420;
  params.i_fps_num = fps;
  params.i_fps_den = 1;
  params.i_timebase_num = 1;
  params.i_timebase_den = fps;
  params.i_threads = 1;
  params.i_keyint_max = gop;
  params.i_keyint_min = gop;
  params.i_bframe = 0;
  params.b_annexb = 1;
  params.b_repeat_headers = 1;
  params.b_vfr_input = 0;
  params.i_log_level = X264_LOG_NONE;
  EXPECT_EQ(x264_param_apply_profile(&params, "baseline"), 0);
  std::unique_ptr<x264_t, X264Deleter> encoder(x264_encoder_open(&params));
  x264_param_cleanup(&params);
  EXPECT_TRUE(encoder);
  if (!encoder) {
    return {};
  }

  x264_picture_t input{};
  x264_picture_t output{};
  EXPECT_EQ(x264_picture_alloc(&input, X264_CSP_I420, width, height), 0);
  x264_picture_init(&output);

  std::vector<media::EncodedAccessUnit> access_units;
  for (int frame = 0; frame < frame_count; ++frame) {
    std::memset(input.img.plane[0], 16 + (frame % 180),
                static_cast<std::size_t>(input.img.i_stride[0]) * height);
    std::memset(input.img.plane[1], 128,
                static_cast<std::size_t>(input.img.i_stride[1]) * height / 2U);
    std::memset(input.img.plane[2], 128,
                static_cast<std::size_t>(input.img.i_stride[2]) * height / 2U);
    input.i_pts = frame;

    x264_nal_t* nals = nullptr;
    int nal_count = 0;
    const int encoded =
        x264_encoder_encode(encoder.get(), &nals, &nal_count, &input, &output);
    EXPECT_GT(encoded, 0);
    if (encoded <= 0) {
      continue;
    }

    media::EncodedAccessUnit access_unit;
    access_unit.sequence = static_cast<std::uint64_t>(frame);
    access_unit.timestamp =
        std::chrono::nanoseconds((1000000000LL * frame) / fps);
    access_unit.is_key_frame = output.b_keyframe != 0;
    std::vector<std::uint8_t> payload;
    for (int index = 0; index < nal_count; ++index) {
      payload.insert(payload.end(), nals[index].p_payload,
                     nals[index].p_payload + nals[index].i_payload);
    }
    access_unit.bytes =
        std::make_shared<const std::vector<std::uint8_t>>(std::move(payload));
    access_units.push_back(std::move(access_unit));
  }
  x264_picture_clean(&input);
  return access_units;
}

std::vector<std::string> TopLevelBoxTypes(
    const std::vector<std::uint8_t>& bytes) {
  std::vector<std::string> types;
  std::size_t offset = 0U;
  while (offset + 8U <= bytes.size()) {
    std::uint64_t size =
        (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
        (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
        (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
        static_cast<std::uint32_t>(bytes[offset + 3U]);
    std::size_t header = 8U;
    if (size == 1U) {
      if (offset + 16U > bytes.size()) {
        return {};
      }
      header = 16U;
      size = 0U;
      for (std::size_t index = 0U; index < 8U; ++index) {
        size = (size << 8U) | bytes[offset + 8U + index];
      }
    }
    if (size < header || size > bytes.size() - offset) {
      return {};
    }
    types.emplace_back(
        reinterpret_cast<const char*>(bytes.data() + offset + 4U), 4U);
    offset += static_cast<std::size_t>(size);
  }
  if (offset != bytes.size()) {
    return {};
  }
  return types;
}

media::FragmentedMp4Chunk ReadRequired(media::FragmentRing::Reader& reader) {
  const auto read = reader.WaitNext(1s);
  EXPECT_TRUE(read.ok()) << read.error().message;
  if (!read.ok() || !read.value().has_value()) {
    return {};
  }
  return *read.value();
}

}  // namespace

TEST(FragmentedMp4HubTest, RejectsInvalidVideoConfiguration) {
  media::EncodedRing encoded_ring(8U);
  media::FragmentedMp4Hub hub(encoded_ring);
  media::FragmentedMp4HubConfig config;
  config.fps = 0U;

  const auto started = hub.Start(config);

  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, "E_FMP4_CONFIG");
}

TEST(FragmentedMp4HubTest, PackagesOneEncodeForSharedReaders) {
  constexpr int kWidth = 320;
  constexpr int kHeight = 180;
  constexpr int kFps = 50;
  media::EncodedRing encoded_ring(128U);
  media::FragmentedMp4Hub hub(encoded_ring);
  media::FragmentedMp4HubConfig config;
  config.width = kWidth;
  config.height = kHeight;
  config.fps = kFps;
  config.fragment_duration_ms = 200U;
  config.ring_limits = {
      .max_fragments = 8U, .max_bytes = 4U * 1024U * 1024U, .max_readers = 2U};
  ASSERT_TRUE(hub.Start(config).ok());

  const auto access_units = EncodeAnnexBFrames(kWidth, kHeight, kFps, 10, 45);
  ASSERT_EQ(access_units.size(), 45U);
  for (const auto& access_unit : access_units) {
    encoded_ring.Publish(access_unit);
  }

  bool packaged = false;
  for (int attempt = 0; attempt < 150; ++attempt) {
    const auto status = hub.Status();
    if (status.pushed_access_units == 45U && status.published_fragments >= 4U) {
      packaged = true;
      break;
    }
    std::this_thread::sleep_for(20ms);
  }
  ASSERT_TRUE(packaged) << hub.Status().last_error_code << ": "
                        << hub.Status().last_error_message;

  auto first_opened = hub.OpenReader();
  auto second_opened = hub.OpenReader();
  ASSERT_TRUE(first_opened.ok()) << first_opened.error().message;
  ASSERT_TRUE(second_opened.ok()) << second_opened.error().message;
  auto first = std::move(first_opened).value();
  auto second = std::move(second_opened).value();

  const auto first_init = ReadRequired(first);
  const auto second_init = ReadRequired(second);
  const auto first_fragment = ReadRequired(first);
  const auto second_fragment = ReadRequired(second);

  auto blocked = std::async(std::launch::async, [&first] {
    return first.WaitNext(std::chrono::seconds(5));
  });
  ASSERT_EQ(blocked.wait_for(30ms), std::future_status::timeout);
  hub.Stop();
  ASSERT_EQ(blocked.wait_for(200ms), std::future_status::ready);
  const auto stopped_read = blocked.get();
  ASSERT_FALSE(stopped_read.ok());
  EXPECT_EQ(stopped_read.error().code, "E_LIVE_GENERATION");

  ASSERT_TRUE(first_init.bytes);
  ASSERT_TRUE(second_init.bytes);
  EXPECT_EQ(first_init.bytes.get(), second_init.bytes.get());
  EXPECT_EQ(TopLevelBoxTypes(*first_init.bytes),
            (std::vector<std::string>{"ftyp", "moov"}));
  ASSERT_TRUE(first_fragment.bytes);
  ASSERT_TRUE(second_fragment.bytes);
  EXPECT_EQ(first_fragment.sequence, second_fragment.sequence);
  EXPECT_EQ(first_fragment.bytes.get(), second_fragment.bytes.get());
  EXPECT_EQ(TopLevelBoxTypes(*first_fragment.bytes),
            (std::vector<std::string>{"moof", "mdat"}));
  EXPECT_TRUE(first_fragment.random_access);
}
