#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>

#include "camera_firmware/media/FrameLease.hpp"

namespace camera_firmware::ai {

class AiFrameTap {
 private:
  struct SharedState;
  struct SubscriberSlot;

 public:
  using Subscriber = std::function<void(media::FrameLease)>;

  class Subscription {
   public:
    Subscription() = default;
    Subscription(const Subscription&) = delete;
    Subscription& operator=(const Subscription&) = delete;
    Subscription(Subscription&& other) noexcept;
    Subscription& operator=(Subscription&& other) noexcept;
    ~Subscription();

    [[nodiscard]] bool valid() const noexcept;

   private:
    friend class AiFrameTap;

    Subscription(std::weak_ptr<SharedState> shared_state,
                 std::uint64_t subscriber_id) noexcept;
    void Reset() noexcept;

    std::weak_ptr<SharedState> shared_state_;
    std::uint64_t subscriber_id_{0};
  };

  void PublishLatest(media::FrameLease frame);
  [[nodiscard]] std::optional<media::FrameLease> Latest() const;
  [[nodiscard]] Subscription Subscribe(Subscriber subscriber);

 private:
  struct SharedState {
    mutable std::mutex mutex;
    std::optional<media::FrameLease> latest;
    std::unordered_map<std::uint64_t, std::shared_ptr<SubscriberSlot>>
        subscribers;
    std::uint64_t next_subscriber_id{1};
  };

  static void Unsubscribe(const std::shared_ptr<SharedState>& shared_state,
                          std::uint64_t subscriber_id) noexcept;
  static void CancelSubscriber(
      const std::shared_ptr<SubscriberSlot>& subscriber) noexcept;
  static void InvokeSubscriber(
      const std::shared_ptr<SubscriberSlot>& subscriber,
      media::FrameLease frame);

  std::shared_ptr<SharedState> shared_state_{std::make_shared<SharedState>()};
};

}  // namespace camera_firmware::ai
