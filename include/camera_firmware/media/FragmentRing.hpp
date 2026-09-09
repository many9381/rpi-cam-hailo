#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::media {

enum class FragmentedMp4ChunkKind {
  kInitialization,
  kMediaFragment,
};

struct FragmentedMp4Chunk {
  FragmentedMp4ChunkKind kind{FragmentedMp4ChunkKind::kInitialization};
  std::uint64_t generation{0U};
  std::uint64_t sequence{0U};
  bool random_access{false};
  std::shared_ptr<const std::vector<std::uint8_t>> bytes;
};

struct FragmentRingLimits {
  std::size_t max_fragments{8U};
  std::size_t max_bytes{std::size_t{32} * 1024U * 1024U};
  std::size_t max_readers{4U};
};

class FragmentRing {
 public:
  using Clock = std::chrono::steady_clock;
  using NowCallback = std::function<Clock::time_point()>;

  class Reader {
   public:
    Reader() = default;

    [[nodiscard]] common::Result<std::optional<FragmentedMp4Chunk>> WaitNext(
        std::chrono::milliseconds timeout);
    void Cancel() noexcept;
    [[nodiscard]] bool valid() const noexcept;

   private:
    struct CursorState;

    explicit Reader(std::shared_ptr<CursorState> cursor);

    std::shared_ptr<CursorState> cursor_;

    friend class FragmentRing;
  };

  explicit FragmentRing(FragmentRingLimits limits = {});
  FragmentRing(FragmentRingLimits limits, NowCallback now);

  [[nodiscard]] common::Result<std::uint64_t> BeginGeneration(
      std::vector<std::uint8_t> initialization_segment);
  [[nodiscard]] common::Result<void> Publish(
      std::vector<std::uint8_t> media_fragment, bool random_access);
  void Invalidate() noexcept;
  [[nodiscard]] common::Result<Reader> OpenReader();
  [[nodiscard]] common::Result<Reader> OpenReader(
      std::chrono::milliseconds maximum_age);

  [[nodiscard]] std::uint64_t generation() const noexcept;
  [[nodiscard]] std::uint64_t overrun_total() const noexcept;
  [[nodiscard]] std::size_t retained_bytes() const noexcept;
  [[nodiscard]] std::size_t active_readers() const noexcept;
  [[nodiscard]] std::size_t waiting_readers() const noexcept;

 private:
  struct SharedState;

  [[nodiscard]] common::Result<Reader> OpenReaderInternal(
      std::optional<std::chrono::milliseconds> maximum_age);

  std::shared_ptr<SharedState> state_;
};

}  // namespace camera_firmware::media
