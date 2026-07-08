#include "camera_firmware/ai/DetectionBus.hpp"

#include <utility>
#include <vector>

namespace camera_firmware::ai {

DetectionBus::Subscription::Subscription(
    std::weak_ptr<SharedState> shared_state, std::uint64_t subscriber_id) noexcept
    : shared_state_(std::move(shared_state)), subscriber_id_(subscriber_id) {}

DetectionBus::Subscription::Subscription(Subscription&& other) noexcept
    : shared_state_(std::move(other.shared_state_)),
      subscriber_id_(std::exchange(other.subscriber_id_, 0)) {}

DetectionBus::Subscription& DetectionBus::Subscription::operator=(
    Subscription&& other) noexcept {
  if (this == &other) {
    return *this;
  }

  Reset();
  shared_state_ = std::move(other.shared_state_);
  subscriber_id_ = std::exchange(other.subscriber_id_, 0);
  return *this;
}

DetectionBus::Subscription::~Subscription() { Reset(); }

bool DetectionBus::Subscription::valid() const noexcept {
  return !shared_state_.expired();
}

void DetectionBus::Subscription::Reset() noexcept {
  if (auto shared_state = shared_state_.lock()) {
    Unsubscribe(shared_state, subscriber_id_);
    subscriber_id_ = 0;
  }
  shared_state_.reset();
}

DetectionBus::Subscription DetectionBus::Subscribe(Handler handler) {
  std::lock_guard lock(shared_state_->mutex);
  const auto subscriber_id = shared_state_->next_subscriber_id++;
  shared_state_->subscribers.emplace(subscriber_id, std::move(handler));
  return Subscription(shared_state_, subscriber_id);
}

void DetectionBus::Publish(const DetectionEvent& event) const {
  std::vector<Handler> handlers;
  {
    std::lock_guard lock(shared_state_->mutex);
    handlers.reserve(shared_state_->subscribers.size());
    for (const auto& [subscriber_id, handler] : shared_state_->subscribers) {
      (void)subscriber_id;
      handlers.push_back(handler);
    }
  }

  for (const auto& handler : handlers) {
    handler(event);
  }
}

void DetectionBus::Unsubscribe(const std::shared_ptr<SharedState>& shared_state,
                               std::uint64_t subscriber_id) noexcept {
  std::lock_guard lock(shared_state->mutex);
  shared_state->subscribers.erase(subscriber_id);
}

}  // namespace camera_firmware::ai
