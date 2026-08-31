#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace camera_firmware::security {

// Fixed-window request-rate limiter for POST /api/v1/auth/login in the default
// state. The initial account no longer locks there (its credential is public,
// so a lock only denies setup), which leaves login open to flooding: each
// attempt still pays for a password verification and writes an audit row, and
// the audit ring is finite, so an unbounded flood can evict the setup trail
// (bootstrap_completed / initial_account_deleted). This caps attempts per peer
// and in aggregate per window; throttled attempts are rejected before any
// verification or audit write. A limit of 0 disables that dimension.
//
// The per-IP map is cleared every window and never grows past the global limit
// within one, so a many-IP flood cannot exhaust memory.
class LoginRateLimiter {
 public:
  struct Config {
    std::int64_t window_seconds{60};
    int per_ip_limit{30};
    int global_limit{120};
  };

  LoginRateLimiter();
  explicit LoginRateLimiter(Config config);
  LoginRateLimiter(const LoginRateLimiter&) = delete;
  LoginRateLimiter& operator=(const LoginRateLimiter&) = delete;

  // Record an attempt from `ip` at `now_seconds` and report whether it is
  // within the limits. A rejected attempt does not consume further allowance.
  [[nodiscard]] bool Allow(const std::string& ip, std::int64_t now_seconds);

 private:
  Config config_;
  std::mutex mutex_;
  std::int64_t window_index_{0};
  bool window_seen_{false};
  int global_count_{0};
  std::unordered_map<std::string, int> per_ip_counts_;
};

}  // namespace camera_firmware::security
