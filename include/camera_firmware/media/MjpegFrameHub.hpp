#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/media/JpegEncoder.hpp"
#include "camera_firmware/media/SnapshotTap.hpp"

namespace camera_firmware::media {

struct MjpegFrameHubSharedState;
class MjpegFrameHub;
class MjpegFrameHubTestAccess;

struct MjpegFrameHubDependencies {
  using Clock = std::chrono::steady_clock;
  using NowCallback = std::function<Clock::time_point()>;
  using EncodeCallback = std::function<common::Result<JpegImage>(
      const FrameLease&, unsigned int, unsigned int)>;

  NowCallback now;
  EncodeCallback encode;
};

class MjpegStreamReader {
 public:
  ~MjpegStreamReader();

  MjpegStreamReader(const MjpegStreamReader&) = delete;
  MjpegStreamReader& operator=(const MjpegStreamReader&) = delete;
  MjpegStreamReader(MjpegStreamReader&&) = delete;
  MjpegStreamReader& operator=(MjpegStreamReader&&) = delete;

  [[nodiscard]] std::size_t Read(char* output, std::size_t capacity);

 private:
  friend class MjpegFrameHub;

  MjpegStreamReader(std::shared_ptr<MjpegFrameHubSharedState> state,
                    std::string camera_id,
                    std::uint64_t run_epoch);

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class MjpegFrameHub {
 public:
  MjpegFrameHub(SnapshotTap& tap,
                const config::HttpPreviewConfig& config,
                MjpegFrameHubDependencies dependencies = {});
  ~MjpegFrameHub();

  MjpegFrameHub(const MjpegFrameHub&) = delete;
  MjpegFrameHub& operator=(const MjpegFrameHub&) = delete;
  MjpegFrameHub(MjpegFrameHub&&) = delete;
  MjpegFrameHub& operator=(MjpegFrameHub&&) = delete;

  [[nodiscard]] common::Result<void> Start();
  void Stop() noexcept;
  [[nodiscard]] common::Result<std::shared_ptr<MjpegStreamReader>> Open(
      std::string_view camera_id);

 private:
  friend class MjpegFrameHubTestAccess;

  [[nodiscard]] common::Result<void> StartWithoutWorkerForTest();
  void SetBeforeWorkerStartForTest(std::function<void()> callback);
  [[nodiscard]] bool WaitForBlockedReaderForTest(
      std::chrono::milliseconds timeout);
  void PublishLatestFrame();
  void WorkerLoop() noexcept;

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::media
