#include "camera_firmware/media/IsoBmffAssembler.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace camera_firmware::media {
namespace {

std::uint32_t ReadBigEndian32(std::span<const std::uint8_t> bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
         (static_cast<std::uint32_t>(bytes[1]) << 16U) |
         (static_cast<std::uint32_t>(bytes[2]) << 8U) |
         static_cast<std::uint32_t>(bytes[3]);
}

std::uint64_t ReadBigEndian64(std::span<const std::uint8_t> bytes) {
  std::uint64_t value = 0U;
  for (std::size_t index = 0; index < 8U; ++index) {
    value = (value << 8U) | bytes[index];
  }
  return value;
}

bool AppendWithinLimit(std::vector<std::uint8_t>& destination,
                       std::span<const std::uint8_t> source,
                       std::size_t limit) {
  if (destination.size() > limit || source.size() > limit - destination.size()) {
    return false;
  }
  destination.insert(destination.end(), source.begin(), source.end());
  return true;
}

}  // namespace

IsoBmffAssembler::IsoBmffAssembler(IsoBmffAssemblerLimits limits)
    : limits_(limits) {
  if (limits_.max_buffer_bytes < 8U || limits_.max_box_bytes < 8U ||
      limits_.max_init_segment_bytes < 16U ||
      limits_.max_media_fragment_bytes < 16U) {
    throw std::invalid_argument("ISO BMFF assembler limits are too small");
  }
}

common::Result<std::vector<IsoBmffSegment>> IsoBmffAssembler::Push(
    std::span<const std::uint8_t> bytes) {
  using Result = common::Result<std::vector<IsoBmffSegment>>;
  const auto fail = [this](std::string code, std::string message) {
    Reset();
    return Result::Err({std::move(code), std::move(message)});
  };

  if (pending_bytes_.size() > limits_.max_buffer_bytes ||
      bytes.size() > limits_.max_buffer_bytes - pending_bytes_.size()) {
    return fail("E_FMP4_LIMIT", "fragmented MP4 input exceeds buffer limit");
  }

  // Steady state (mp4mux streamable output) delivers whole boxes per Push,
  // so parse straight from the caller's span and stage only a trailing
  // partial box. Only when a previous Push left a partial tail do we fall
  // back to staging the input behind it.
  std::span<const std::uint8_t> parse_view = bytes;
  const bool staged = !pending_bytes_.empty();
  if (staged) {
    pending_bytes_.insert(pending_bytes_.end(), bytes.begin(), bytes.end());
    parse_view = std::span<const std::uint8_t>(pending_bytes_);
  }

  std::vector<IsoBmffSegment> output;
  std::size_t consumed = 0U;
  while (parse_view.size() - consumed >= 8U) {
    const auto remaining = parse_view.subspan(consumed);
    const std::uint32_t compact_size = ReadBigEndian32(remaining.first(4U));
    std::size_t header_size = 8U;
    std::uint64_t box_size = compact_size;
    if (compact_size == 0U) {
      return fail("E_FMP4_BOX", "zero-length ISO BMFF box is not streamable");
    }
    if (compact_size == 1U) {
      header_size = 16U;
      if (remaining.size() < header_size) {
        break;
      }
      box_size = ReadBigEndian64(remaining.subspan(8U, 8U));
    }
    if (box_size < header_size) {
      return fail("E_FMP4_BOX", "ISO BMFF box length is smaller than header");
    }
    if (box_size > limits_.max_box_bytes ||
        box_size > std::numeric_limits<std::size_t>::max()) {
      return fail("E_FMP4_LIMIT", "ISO BMFF box exceeds configured limit");
    }
    const auto checked_box_size = static_cast<std::size_t>(box_size);
    if (remaining.size() < checked_box_size) {
      break;
    }

    const std::string type(
        reinterpret_cast<const char*>(remaining.data() + 4U), 4U);
    const auto box = remaining.first(checked_box_size);
    if (!init_complete_) {
      if (!seen_ftyp_ && type != "ftyp") {
        return fail("E_FMP4_SEQUENCE",
                    "fragmented MP4 initialization must begin with ftyp");
      }
      if (type == "moof" || type == "mdat" ||
          (seen_ftyp_ && type == "ftyp")) {
        return fail("E_FMP4_SEQUENCE",
                    "invalid box order in fragmented MP4 initialization");
      }
      if (!AppendWithinLimit(init_bytes_, box,
                             limits_.max_init_segment_bytes)) {
        return fail("E_FMP4_LIMIT",
                    "fragmented MP4 initialization exceeds configured limit");
      }
      if (type == "ftyp") {
        seen_ftyp_ = true;
      }
      if (type == "moov") {
        output.push_back(
            {IsoBmffSegmentKind::kInitialization, std::move(init_bytes_)});
        init_bytes_.clear();
        init_complete_ = true;
      }
    } else if (!awaiting_mdat_) {
      if (type != "moof") {
        return fail("E_FMP4_SEQUENCE",
                    "fragmented MP4 media fragment must begin with moof");
      }
      if (!AppendWithinLimit(fragment_bytes_, box,
                             limits_.max_media_fragment_bytes)) {
        return fail("E_FMP4_LIMIT",
                    "fragmented MP4 media fragment exceeds configured limit");
      }
      awaiting_mdat_ = true;
    } else {
      if (type != "mdat") {
        return fail("E_FMP4_SEQUENCE",
                    "fragmented MP4 moof must be followed by mdat");
      }
      if (!AppendWithinLimit(fragment_bytes_, box,
                             limits_.max_media_fragment_bytes)) {
        return fail("E_FMP4_LIMIT",
                    "fragmented MP4 media fragment exceeds configured limit");
      }
      output.push_back(
          {IsoBmffSegmentKind::kMediaFragment, std::move(fragment_bytes_)});
      fragment_bytes_.clear();
      awaiting_mdat_ = false;
    }
    consumed += checked_box_size;
  }

  if (staged) {
    if (consumed != 0U) {
      pending_bytes_.erase(pending_bytes_.begin(),
                           pending_bytes_.begin() +
                               static_cast<std::ptrdiff_t>(consumed));
    }
  } else {
    const auto tail = parse_view.subspan(consumed);
    pending_bytes_.assign(tail.begin(), tail.end());
  }
  return Result::Ok(std::move(output));
}

common::Result<void> IsoBmffAssembler::Finish() const {
  if (!pending_bytes_.empty() || !init_complete_ || awaiting_mdat_ ||
      !init_bytes_.empty() || !fragment_bytes_.empty()) {
    return common::Result<void>::Err(
        {"E_FMP4_TRUNCATED", "fragmented MP4 stream ended mid-segment"});
  }
  return common::Result<void>::Ok();
}

void IsoBmffAssembler::Reset() noexcept {
  pending_bytes_.clear();
  init_bytes_.clear();
  fragment_bytes_.clear();
  seen_ftyp_ = false;
  init_complete_ = false;
  awaiting_mdat_ = false;
}

std::size_t IsoBmffAssembler::buffered_bytes() const noexcept {
  return pending_bytes_.size() + init_bytes_.size() + fragment_bytes_.size();
}

}  // namespace camera_firmware::media
