#include "camera_firmware/media/FrameLease.hpp"

#include <stdexcept>
#include <utility>

namespace camera_firmware::media {

struct FrameLease::SharedState {
  SharedState(FrameHandle frame_handle, ReleaseCallback callback)
      : handle(std::move(frame_handle)),
        release_callback(std::move(callback)) {}

  FrameHandle handle;
  ReleaseCallback release_callback;

  ~SharedState() {
    if (release_callback) {
      release_callback();
    }
  }
};

FrameLease::FrameLease(FrameHandle handle, ReleaseCallback release_callback)
    : shared_state_(std::make_shared<SharedState>(std::move(handle),
                                                  std::move(release_callback))) {}

FrameLease::FrameLease(std::shared_ptr<SharedState> shared_state)
    : shared_state_(std::move(shared_state)) {}

FrameLease FrameLease::CloneRef() const {
  return FrameLease(shared_state_);
}

bool FrameLease::valid() const noexcept { return static_cast<bool>(shared_state_); }

const FrameHandle& FrameLease::handle() const {
  if (!valid()) {
    throw std::logic_error("FrameLease has no frame handle");
  }
  return shared_state_->handle;
}

const FrameHandle* FrameLease::operator->() const { return &handle(); }

const FrameHandle& FrameLease::operator*() const { return handle(); }

}  // namespace camera_firmware::media
