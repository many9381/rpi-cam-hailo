#include "camera_firmware/security/LoginRateLimiter.hpp"

#include <gtest/gtest.h>

namespace {

using camera_firmware::security::LoginRateLimiter;

LoginRateLimiter MakeLimiter() {
  return LoginRateLimiter(
      {.window_seconds = 60, .per_ip_limit = 3, .global_limit = 5});
}

TEST(LoginRateLimiterTest, AllowsUpToThePerIpLimitThenThrottles) {
  auto limiter = MakeLimiter();
  EXPECT_TRUE(limiter.Allow("10.0.0.1", 1000));
  EXPECT_TRUE(limiter.Allow("10.0.0.1", 1000));
  EXPECT_TRUE(limiter.Allow("10.0.0.1", 1001));
  EXPECT_FALSE(limiter.Allow("10.0.0.1", 1002));  // fourth within the window
}

TEST(LoginRateLimiterTest, ResetsWhenTheWindowAdvances) {
  auto limiter = MakeLimiter();
  // Windows are aligned to multiples of window_seconds: [960, 1020) here.
  for (int i = 0; i < 3; ++i) {
    EXPECT_TRUE(limiter.Allow("10.0.0.1", 960 + i));
  }
  EXPECT_FALSE(limiter.Allow("10.0.0.1", 1019));  // still window [960, 1020)
  EXPECT_TRUE(limiter.Allow("10.0.0.1", 1020));   // window [1020, 1080) resets it
}

TEST(LoginRateLimiterTest, PerIpCountsAreIndependent) {
  auto limiter = MakeLimiter();
  for (int i = 0; i < 3; ++i) {
    EXPECT_TRUE(limiter.Allow("10.0.0.1", 1000));
  }
  EXPECT_FALSE(limiter.Allow("10.0.0.1", 1000));
  EXPECT_TRUE(limiter.Allow("10.0.0.2", 1000));  // a different peer is unaffected
}

TEST(LoginRateLimiterTest, GlobalLimitCapsTheTotalAcrossIps) {
  auto limiter = MakeLimiter();  // global limit 5
  EXPECT_TRUE(limiter.Allow("10.0.0.1", 1000));
  EXPECT_TRUE(limiter.Allow("10.0.0.2", 1000));
  EXPECT_TRUE(limiter.Allow("10.0.0.3", 1000));
  EXPECT_TRUE(limiter.Allow("10.0.0.4", 1000));
  EXPECT_TRUE(limiter.Allow("10.0.0.5", 1000));   // fifth reaches the global cap
  EXPECT_FALSE(limiter.Allow("10.0.0.6", 1000));  // a fresh IP is still throttled
}

TEST(LoginRateLimiterTest, GlobalCapAlsoResetsWithTheWindow) {
  auto limiter = MakeLimiter();
  for (int i = 1; i <= 5; ++i) {
    EXPECT_TRUE(limiter.Allow("10.0.0." + std::to_string(i), 1000));
  }
  EXPECT_FALSE(limiter.Allow("10.0.0.9", 1000));
  EXPECT_TRUE(limiter.Allow("10.0.0.9", 1060));  // window advanced
}

TEST(LoginRateLimiterTest, ZeroLimitDisablesThatDimension) {
  LoginRateLimiter limiter(
      {.window_seconds = 60, .per_ip_limit = 0, .global_limit = 0});
  for (int i = 0; i < 100; ++i) {
    EXPECT_TRUE(limiter.Allow("10.0.0.1", 1000));  // no cap when limits are 0
  }
}

}  // namespace
