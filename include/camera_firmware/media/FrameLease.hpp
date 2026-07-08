#pragma once

#include <functional>
#include <memory>

#include "camera_firmware/media/FrameTypes.hpp"

namespace camera_firmware::media {

class FrameLease {
 public:
  using ReleaseCallback = std::function<void()>;

  FrameLease() = default;
  FrameLease(FrameHandle handle, ReleaseCallback release_callback);

  [[nodiscard]] FrameLease CloneRef() const;
  [[nodiscard]] bool valid() const noexcept;

  [[nodiscard]] const FrameHandle& handle() const;
  [[nodiscard]] const FrameHandle* operator->() const;
  [[nodiscard]] const FrameHandle& operator*() const;

 private:
  struct SharedState;

  explicit FrameLease(std::shared_ptr<SharedState> shared_state);

  std::shared_ptr<SharedState> shared_state_;
};

}  // namespace camera_firmware::media
