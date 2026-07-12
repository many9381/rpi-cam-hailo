#include "camera_firmware/service/BoundedWorker.hpp"

#include <condition_variable>
#include <deque>
#include <utility>

namespace camera_firmware::service {
namespace {

common::Result<void> Unavailable() {
  return common::Result<void>::Err(
      {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
}

}  // namespace

struct BoundedWorker::State {
  explicit State(std::size_t queue_capacity) : capacity(queue_capacity) {}

  const std::size_t capacity;
  std::mutex mutex;
  std::condition_variable condition;
  std::deque<std::function<void()>> tasks;
  bool accepting{true};
  bool stopping{false};
};

BoundedWorker::BoundedWorker(std::size_t capacity)
    : state_(std::make_shared<State>(capacity)),
      worker_([state = state_] { Run(state); }),
      worker_id_(worker_.get_id()) {}

BoundedWorker::~BoundedWorker() {
  Stop();
  std::thread detach_owner;
  {
    std::unique_lock lifecycle_lock(lifecycle_mutex_);
    lifecycle_condition_.wait(
        lifecycle_lock, [this] { return !join_in_progress_; });
    if (!worker_released_) {
      detach_owner = std::move(worker_);
      worker_released_ = true;
    }
  }
  if (detach_owner.joinable()) {
    detach_owner.detach();
  }
}

common::Result<void> BoundedWorker::Submit(std::function<void()> task) {
  if (!task) {
    return Unavailable();
  }
  const auto state = state_;
  {
    std::lock_guard lock(state->mutex);
    if (!state->accepting || state->tasks.size() >= state->capacity) {
      return Unavailable();
    }
    state->tasks.push_back(std::move(task));
    state->condition.notify_one();
  }
  return common::Result<void>::Ok();
}

void BoundedWorker::Stop() noexcept {
  const auto state = state_;
  {
    std::lock_guard queue_lock(state->mutex);
    state->accepting = false;
    state->stopping = true;
    state->condition.notify_all();
  }
  if (worker_id_ == std::this_thread::get_id()) {
    return;
  }

  std::thread join_owner;
  {
    std::unique_lock lifecycle_lock(lifecycle_mutex_);
    lifecycle_condition_.wait(
        lifecycle_lock, [this] { return !join_in_progress_; });
    if (worker_released_) {
      return;
    }
    join_in_progress_ = true;
    worker_released_ = true;
    join_owner = std::move(worker_);
  }

  join_owner.join();
  {
    std::lock_guard lifecycle_lock(lifecycle_mutex_);
    join_in_progress_ = false;
  }
  lifecycle_condition_.notify_all();
}

void BoundedWorker::Run(const std::shared_ptr<State>& state) noexcept {
  for (;;) {
    std::function<void()> task;
    {
      std::unique_lock lock(state->mutex);
      state->condition.wait(
          lock, [&state] { return state->stopping || !state->tasks.empty(); });
      if (state->tasks.empty()) {
        if (state->stopping) {
          return;
        }
        continue;
      }
      task = std::move(state->tasks.front());
      state->tasks.pop_front();
    }
    try {
      task();
    } catch (...) {
    }
  }
}

}  // namespace camera_firmware::service
