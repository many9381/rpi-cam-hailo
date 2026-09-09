#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "camera_firmware/ai/AiTypes.hpp"

namespace camera_firmware::ai {

class DetectionBus {
 private:
  struct SharedState;

 public:
  using Handler = std::function<void(const DetectionEvent&)>;

  DetectionBus() = default;
  DetectionBus(const DetectionBus&) = delete;
  DetectionBus& operator=(const DetectionBus&) = delete;
  DetectionBus(DetectionBus&&) = delete;
  DetectionBus& operator=(DetectionBus&&) = delete;
  ~DetectionBus() = default;

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
    friend class DetectionBus;

    Subscription(std::weak_ptr<SharedState> shared_state,
                 std::uint64_t subscriber_id) noexcept;
    void Reset() noexcept;

    std::weak_ptr<SharedState> shared_state_;
    std::uint64_t subscriber_id_{0};
  };

  class Publisher {
   public:
    Publisher() = default;

    [[nodiscard]] bool valid() const noexcept;
    void Publish(const DetectionEvent& event) const;

   private:
    friend class DetectionBus;

    explicit Publisher(std::weak_ptr<SharedState> shared_state) noexcept;

    std::weak_ptr<SharedState> shared_state_;
  };

  [[nodiscard]] Subscription Subscribe(Handler handler);
  [[nodiscard]] Publisher PublisherHandle() const noexcept;
  void Publish(const DetectionEvent& event) const;

 private:
  struct SharedState {
    mutable std::mutex mutex;
    std::unordered_map<std::uint64_t, Handler> subscribers;
    std::uint64_t next_subscriber_id{1};
  };

  static void Unsubscribe(const std::shared_ptr<SharedState>& shared_state,
                          std::uint64_t subscriber_id) noexcept;
  static void PublishToState(const std::shared_ptr<SharedState>& shared_state,
                             const DetectionEvent& event);

  std::shared_ptr<SharedState> shared_state_{std::make_shared<SharedState>()};
};

}  // namespace camera_firmware::ai
