#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include "camera_firmware/ai/AiTypes.hpp"
#include "camera_firmware/ai/DetectionBus.hpp"

namespace camera_firmware::ai {

class DetectionEventStore {
 public:
  explicit DetectionEventStore(DetectionBus& bus);

  DetectionEventStore(const DetectionEventStore&) = delete;
  DetectionEventStore& operator=(const DetectionEventStore&) = delete;
  DetectionEventStore(DetectionEventStore&&) = delete;
  DetectionEventStore& operator=(DetectionEventStore&&) = delete;
  ~DetectionEventStore() = default;

  [[nodiscard]] std::vector<DetectionEvent> Snapshot() const;
  [[nodiscard]] std::function<std::vector<DetectionEvent>()>
  SnapshotProvider() const;

 private:
  struct SharedState;

  static void Record(const std::shared_ptr<SharedState>& state,
                     const DetectionEvent& event);
  static std::vector<DetectionEvent> Snapshot(
      const std::shared_ptr<SharedState>& state);

  std::shared_ptr<SharedState> state_;
  DetectionBus::Subscription subscription_;
};

}  // namespace camera_firmware::ai
