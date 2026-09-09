#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::media {

enum class IsoBmffSegmentKind {
  kInitialization,
  kMediaFragment,
};

struct IsoBmffSegment {
  IsoBmffSegmentKind kind{IsoBmffSegmentKind::kInitialization};
  std::vector<std::uint8_t> bytes;
};

// True when the media fragment's first sample is a sync sample (IDR): the
// trun first-sample-flags, falling back to the tfhd default-sample-flags.
// Absent flags or malformed boxes conservatively report false, so only
// provably keyframe-led fragments are advertised as join points.
[[nodiscard]] bool IsFragmentRandomAccess(
    std::span<const std::uint8_t> fragment) noexcept;

struct IsoBmffAssemblerLimits {
  std::size_t max_buffer_bytes{std::size_t{32} * 1024U * 1024U};
  std::size_t max_box_bytes{std::size_t{16} * 1024U * 1024U};
  std::size_t max_init_segment_bytes{std::size_t{2} * 1024U * 1024U};
  std::size_t max_media_fragment_bytes{std::size_t{16} * 1024U * 1024U};
};

class IsoBmffAssembler {
 public:
  explicit IsoBmffAssembler(IsoBmffAssemblerLimits limits = {});

  [[nodiscard]] common::Result<std::vector<IsoBmffSegment>> Push(
      std::span<const std::uint8_t> bytes);
  [[nodiscard]] common::Result<void> Finish() const;
  void Reset() noexcept;
  [[nodiscard]] std::size_t buffered_bytes() const noexcept;

 private:
  IsoBmffAssemblerLimits limits_;
  std::vector<std::uint8_t> pending_bytes_;
  std::vector<std::uint8_t> init_bytes_;
  std::vector<std::uint8_t> fragment_bytes_;
  bool seen_ftyp_{false};
  bool init_complete_{false};
  bool awaiting_mdat_{false};
};

}  // namespace camera_firmware::media
