#include "camera_firmware/ai/DetectionEventStore.hpp"

#include <algorithm>

namespace camera_firmware::ai {

struct DetectionEventStore::SharedState {
  mutable std::mutex mutex;
  std::vector<DetectionEvent> events;
};

DetectionEventStore::DetectionEventStore(DetectionBus& bus)
    : state_(std::make_shared<SharedState>()),
      subscription_(bus.Subscribe([state = std::weak_ptr<SharedState>(state_)](
                                      const DetectionEvent& event) {
        if (auto locked = state.lock()) {
          Record(locked, event);
        }
      })) {}

std::vector<DetectionEvent> DetectionEventStore::Snapshot() const {
  return Snapshot(state_);
}

std::function<std::vector<DetectionEvent>()>
DetectionEventStore::SnapshotProvider() const {
  std::weak_ptr<SharedState> weak_state = state_;
  return [weak_state] {
    if (auto state = weak_state.lock()) {
      return Snapshot(state);
    }
    return std::vector<DetectionEvent>{};
  };
}

void DetectionEventStore::Record(const std::shared_ptr<SharedState>& state,
                                 const DetectionEvent& event) {
  std::lock_guard lock(state->mutex);
  const auto same_binding = [&event](const DetectionEvent& stored) {
    return stored.camera_id == event.camera_id &&
           stored.model_id == event.model_id;
  };
  const auto existing =
      std::find_if(state->events.begin(), state->events.end(), same_binding);
  if (existing != state->events.end()) {
    *existing = event;
    return;
  }
  state->events.push_back(event);
}

std::vector<DetectionEvent> DetectionEventStore::Snapshot(
    const std::shared_ptr<SharedState>& state) {
  if (state == nullptr) {
    return {};
  }
  std::lock_guard lock(state->mutex);
  return state->events;
}

}  // namespace camera_firmware::ai
