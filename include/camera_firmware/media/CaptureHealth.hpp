#pragma once

#include <chrono>
#include <optional>
#include <string>

namespace camera_firmware::media {

// Guarded by the pipeline mutex. Use arrival time, never sensor or wall time.
class CaptureHealth {
 public:
  using TimePoint = std::chrono::steady_clock::time_point;

  void Start(TimePoint now) {
    started_ = now;
    last_frame_.reset();
  }
  void Frame(TimePoint now) { last_frame_ = now; }

  [[nodiscard]] std::string ErrorCode(TimePoint now) const {
    if (!last_frame_) {
      return now - started_ >= std::chrono::seconds(10) ? "E_CAMERA_NO_FRAMES"
                                                        : "";
    }
    return now - *last_frame_ >= std::chrono::seconds(5)
               ? "E_CAMERA_CAPTURE_STALLED"
               : "";
  }

  [[nodiscard]] std::string State(TimePoint now) const {
    if (!ErrorCode(now).empty())
      return "error";
    return last_frame_ ? "running" : "starting";
  }

 private:
  TimePoint started_{};
  std::optional<TimePoint> last_frame_;
};

}  // namespace camera_firmware::media
