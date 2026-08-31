#include "camera_firmware/security/LoginRateLimiter.hpp"

namespace camera_firmware::security {

LoginRateLimiter::LoginRateLimiter() : LoginRateLimiter(Config{}) {}

LoginRateLimiter::LoginRateLimiter(Config config) : config_(config) {
  if (config_.window_seconds <= 0) {
    config_.window_seconds = 1;
  }
}

bool LoginRateLimiter::Allow(const std::string& ip, std::int64_t now_seconds) {
  std::scoped_lock lock(mutex_);

  const std::int64_t window = now_seconds / config_.window_seconds;
  if (!window_seen_ || window != window_index_) {
    window_index_ = window;
    window_seen_ = true;
    global_count_ = 0;
    per_ip_counts_.clear();
  }

  // Check the global cap before touching the per-IP map so a many-IP flood
  // cannot grow the map past the global limit within a window.
  if (config_.global_limit > 0 && global_count_ >= config_.global_limit) {
    return false;
  }
  if (config_.per_ip_limit > 0) {
    int& count = per_ip_counts_[ip];
    if (count >= config_.per_ip_limit) {
      return false;
    }
    ++count;
  }
  ++global_count_;
  return true;
}

}  // namespace camera_firmware::security
