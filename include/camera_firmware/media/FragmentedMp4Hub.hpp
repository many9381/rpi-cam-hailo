#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/media/EncodedRing.hpp"
#include "camera_firmware/media/FragmentRing.hpp"
#include "camera_firmware/media/IsoBmffAssembler.hpp"

namespace camera_firmware::media {

struct FragmentedMp4HubConfig {
  unsigned int width{1920U};
  unsigned int height{1080U};
  unsigned int fps{50U};
  unsigned int fragment_duration_ms{500U};
  unsigned int stale_timeout_ms{2000U};
  FragmentRingLimits ring_limits;
  IsoBmffAssemblerLimits assembler_limits;
};

struct FragmentedMp4HubStatus {
  std::string state{"stopped"};
  std::uint64_t input_access_units{0U};
  std::uint64_t pushed_access_units{0U};
  std::uint64_t dropped_until_keyframe{0U};
  std::uint64_t input_error_count{0U};
  std::uint64_t published_fragments{0U};
  std::uint64_t generation{0U};
  std::uint64_t ring_overrun_total{0U};
  std::size_t retained_bytes{0U};
  std::size_t active_readers{0U};
  std::string last_error_code;
  std::string last_error_message;
};

class FragmentedMp4Hub {
 public:
  explicit FragmentedMp4Hub(EncodedRing& encoded_ring);
  ~FragmentedMp4Hub();

  FragmentedMp4Hub(const FragmentedMp4Hub&) = delete;
  FragmentedMp4Hub& operator=(const FragmentedMp4Hub&) = delete;
  FragmentedMp4Hub(FragmentedMp4Hub&&) = delete;
  FragmentedMp4Hub& operator=(FragmentedMp4Hub&&) = delete;

  [[nodiscard]] common::Result<void> Start(
      const FragmentedMp4HubConfig& config);
  void Stop() noexcept;
  [[nodiscard]] common::Result<FragmentRing::Reader> OpenReader();
  [[nodiscard]] FragmentedMp4HubStatus Status() const;

 private:
  struct Impl;

  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::media
