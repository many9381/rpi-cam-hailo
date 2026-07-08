#include "camera_firmware/ai/AiFrameTap.hpp"

#include <condition_variable>
#include <mutex>
#include <utility>
#include <vector>

namespace camera_firmware::ai {

struct AiFrameTap::SubscriberSlot {
  explicit SubscriberSlot(Subscriber callback) : subscriber(std::move(callback)) {}

  std::mutex mutex;
  std::condition_variable idle;
  Subscriber subscriber;
  std::uint64_t active_callbacks{0};
  bool subscribed{true};
};

AiFrameTap::Subscription::Subscription(
    std::weak_ptr<SharedState> shared_state, std::uint64_t subscriber_id) noexcept
    : shared_state_(std::move(shared_state)), subscriber_id_(subscriber_id) {}

AiFrameTap::Subscription::Subscription(Subscription&& other) noexcept
    : shared_state_(std::move(other.shared_state_)),
      subscriber_id_(std::exchange(other.subscriber_id_, 0)) {}

AiFrameTap::Subscription& AiFrameTap::Subscription::operator=(
    Subscription&& other) noexcept {
  if (this == &other) {
    return *this;
  }

  Reset();
  shared_state_ = std::move(other.shared_state_);
  subscriber_id_ = std::exchange(other.subscriber_id_, 0);
  return *this;
}

AiFrameTap::Subscription::~Subscription() { Reset(); }

bool AiFrameTap::Subscription::valid() const noexcept {
  return !shared_state_.expired();
}

void AiFrameTap::Subscription::Reset() noexcept {
  std::shared_ptr<SubscriberSlot> subscriber;
  if (auto shared_state = shared_state_.lock()) {
    {
      std::lock_guard lock(shared_state->mutex);
      auto it = shared_state->subscribers.find(subscriber_id_);
      if (it != shared_state->subscribers.end()) {
        subscriber = it->second;
      }
    }
    Unsubscribe(shared_state, subscriber_id_);
    subscriber_id_ = 0;
  }
  if (subscriber != nullptr) {
    CancelSubscriber(subscriber);
  }
  shared_state_.reset();
}

void AiFrameTap::PublishLatest(media::FrameLease frame) {
  std::vector<std::shared_ptr<SubscriberSlot>> subscribers;
  std::optional<media::FrameLease> delivered;
  {
    std::lock_guard lock(shared_state_->mutex);
    shared_state_->latest = std::move(frame);
    if (shared_state_->subscribers.empty()) {
      return;
    }
    delivered = shared_state_->latest->CloneRef();
    subscribers.reserve(shared_state_->subscribers.size());
    for (const auto& [subscriber_id, subscriber] :
         shared_state_->subscribers) {
      (void)subscriber_id;
      subscribers.push_back(subscriber);
    }
  }

  for (std::size_t index = 0; index < subscribers.size(); ++index) {
    if (index + 1U < subscribers.size()) {
      InvokeSubscriber(subscribers[index], delivered->CloneRef());
    } else {
      InvokeSubscriber(subscribers[index], std::move(*delivered));
    }
  }
}

std::optional<media::FrameLease> AiFrameTap::Latest() const {
  std::lock_guard lock(shared_state_->mutex);
  if (!shared_state_->latest.has_value()) {
    return std::nullopt;
  }
  return shared_state_->latest->CloneRef();
}

AiFrameTap::Subscription AiFrameTap::Subscribe(Subscriber subscriber) {
  std::lock_guard lock(shared_state_->mutex);
  const auto subscriber_id = shared_state_->next_subscriber_id++;
  shared_state_->subscribers.emplace(
      subscriber_id, std::make_shared<SubscriberSlot>(std::move(subscriber)));
  return Subscription(shared_state_, subscriber_id);
}

void AiFrameTap::Unsubscribe(const std::shared_ptr<SharedState>& shared_state,
                             std::uint64_t subscriber_id) noexcept {
  std::lock_guard lock(shared_state->mutex);
  shared_state->subscribers.erase(subscriber_id);
}

void AiFrameTap::CancelSubscriber(
    const std::shared_ptr<SubscriberSlot>& subscriber) noexcept {
  std::unique_lock lock(subscriber->mutex);
  subscriber->subscribed = false;
  subscriber->subscriber = nullptr;
  subscriber->idle.wait(lock, [&subscriber] {
    return subscriber->active_callbacks == 0U;
  });
}

void AiFrameTap::InvokeSubscriber(
    const std::shared_ptr<SubscriberSlot>& subscriber,
    media::FrameLease frame) {
  struct ActiveCallbackGuard {
    explicit ActiveCallbackGuard(
        std::shared_ptr<SubscriberSlot> guarded_subscriber) noexcept
        : subscriber(std::move(guarded_subscriber)) {}

    ActiveCallbackGuard(const ActiveCallbackGuard&) = delete;
    ActiveCallbackGuard& operator=(const ActiveCallbackGuard&) = delete;

    ~ActiveCallbackGuard() {
      std::unique_lock lock(subscriber->mutex);
      if (subscriber->active_callbacks > 0U) {
        --subscriber->active_callbacks;
      }
      if (subscriber->active_callbacks == 0U) {
        lock.unlock();
        subscriber->idle.notify_all();
      }
    }

    std::shared_ptr<SubscriberSlot> subscriber;
  };

  Subscriber callback;
  {
    std::lock_guard lock(subscriber->mutex);
    if (!subscriber->subscribed || !subscriber->subscriber) {
      return;
    }
    ++subscriber->active_callbacks;
    callback = subscriber->subscriber;
  }

  ActiveCallbackGuard guard(subscriber);
  callback(std::move(frame));
}

}  // namespace camera_firmware::ai
