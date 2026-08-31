#pragma once

#include <cstddef>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::service {

class BoundedWorker {
 public:
  explicit BoundedWorker(std::size_t capacity = 16U);
  ~BoundedWorker();

  BoundedWorker(const BoundedWorker&) = delete;
  BoundedWorker& operator=(const BoundedWorker&) = delete;
  BoundedWorker(BoundedWorker&&) = delete;
  BoundedWorker& operator=(BoundedWorker&&) = delete;

  [[nodiscard]] common::Result<void> Submit(std::function<void()> task);
  void Stop() noexcept;

 private:
  struct State;
  static void Run(const std::shared_ptr<State>& state) noexcept;

  std::shared_ptr<State> state_;
  std::mutex lifecycle_mutex_;
  std::condition_variable lifecycle_condition_;
  std::thread worker_;
  const std::thread::id worker_id_;
  bool join_in_progress_{false};
  bool worker_released_{false};
};

}  // namespace camera_firmware::service
