#include "camera_firmware/media/SubStreamTap.hpp"

#include <atomic>
#include <chrono>
#include <thread>

#include <gtest/gtest.h>

#include "camera_firmware/media/FrameLease.hpp"

namespace {

using camera_firmware::media::FrameHandle;
using camera_firmware::media::FrameLease;
using camera_firmware::media::SubStreamTap;

// Mirror the FrameLease release-counter pattern from FrameLeaseTest.cpp /
// EncodeMailboxTest.cpp: a default FrameHandle plus a release lambda that
// increments a counter so tests can observe when a lease is dropped.
FrameLease MakeLease(int& counter) {
  FrameHandle handle;
  return FrameLease(handle, [&counter] { ++counter; });
}

TEST(SubStreamTapTest, DisarmedUntilActiveAndRequested) {
  SubStreamTap tap;
  EXPECT_FALSE(tap.ConsumeDemand());
  tap.RequestNext();
  EXPECT_FALSE(tap.ConsumeDemand());  // not active yet
  tap.SetActive(true);
  tap.RequestNext();
  EXPECT_TRUE(tap.ConsumeDemand());
  EXPECT_FALSE(tap.ConsumeDemand());  // one-shot
}

TEST(SubStreamTapTest, InactiveGateBlocksDemandEvenAfterRequest) {
  SubStreamTap tap;
  tap.SetActive(true);
  tap.RequestNext();
  tap.SetActive(false);
  EXPECT_FALSE(tap.ConsumeDemand());
  tap.RequestNext();
  EXPECT_FALSE(tap.ConsumeDemand());
}

TEST(SubStreamTapTest, PublishThenWaitNextReturnsTheLease) {
  SubStreamTap tap;
  tap.SetActive(true);
  int releases = 0;
  tap.PublishLatest(MakeLease(releases));

  auto got = tap.WaitNext(std::chrono::milliseconds(10));
  ASSERT_TRUE(got.has_value());
  EXPECT_TRUE(got->valid());
}

TEST(SubStreamTapTest, PublishSupersedesReleasesStaleLease) {
  SubStreamTap tap;
  tap.SetActive(true);
  int first = 0, second = 0;
  tap.PublishLatest(MakeLease(first));
  EXPECT_EQ(first, 0);
  tap.PublishLatest(MakeLease(second));
  EXPECT_EQ(first, 1);  // stale dropped
  auto got = tap.WaitNext(std::chrono::milliseconds(10));
  ASSERT_TRUE(got.has_value());
}

TEST(SubStreamTapTest, DeactivateWakesWaiterWithNullopt) {
  SubStreamTap tap;
  tap.SetActive(true);
  std::atomic_bool got_value{true};
  std::thread t(
      [&] { got_value = tap.WaitNext(std::chrono::seconds(2)).has_value(); });
  // Give the waiter a chance to actually enter the wait before deactivating.
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  tap.SetActive(false);
  t.join();
  EXPECT_FALSE(got_value.load());
}

TEST(SubStreamTapTest, CloseWakesWaiterWithNulloptPermanently) {
  SubStreamTap tap;
  tap.SetActive(true);
  std::atomic_bool got_value{true};
  std::thread t(
      [&] { got_value = tap.WaitNext(std::chrono::seconds(2)).has_value(); });
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  tap.Close();
  t.join();
  EXPECT_FALSE(got_value.load());

  // Closed permanently: further waits return nullopt immediately.
  auto got = tap.WaitNext(std::chrono::milliseconds(10));
  EXPECT_FALSE(got.has_value());
}

TEST(SubStreamTapTest, WaitNextTimesOutWithNulloptWhenNothingPending) {
  SubStreamTap tap;
  tap.SetActive(true);
  auto got = tap.WaitNext(std::chrono::milliseconds(10));
  EXPECT_FALSE(got.has_value());
}

TEST(SubStreamTapTest, SetActiveFalseReleasesPendingLeaseOutsideLock) {
  SubStreamTap tap;
  tap.SetActive(true);
  int releases = 0;
  tap.PublishLatest(MakeLease(releases));
  EXPECT_EQ(releases, 0);
  tap.SetActive(false);
  EXPECT_EQ(releases, 1);
}

TEST(SubStreamTapTest, ActiveReflectsSetActive) {
  SubStreamTap tap;
  EXPECT_FALSE(tap.active());
  tap.SetActive(true);
  EXPECT_TRUE(tap.active());
  tap.SetActive(false);
  EXPECT_FALSE(tap.active());
}

TEST(SubStreamTapTest, PublishAfterCloseIsDroppedImmediately) {
  SubStreamTap tap;
  tap.SetActive(true);
  tap.Close();

  int releases = 0;
  tap.PublishLatest(MakeLease(releases));
  // A publish that races shutdown must not linger; its lease releases at once
  // instead of being stored where nothing will ever read or free it.
  EXPECT_EQ(releases, 1);
  EXPECT_FALSE(tap.WaitNext(std::chrono::milliseconds(10)).has_value());
}

// Mirrors EncodeMailboxTest.ReopenReturnsAClosedMailboxToService: a runtime
// restart reuses this same tap instance (it is a persistent member of the
// runtime graph, see SubStreamEncoder::Impl::Start()'s tap.Reopen() call),
// so after Close() permanently shut it down, Reopen() must bring it back to
// service for a fresh SubStreamEncoder run -- and must not double-release
// whatever lease Close() already dropped on the way out.
TEST(SubStreamTapTest, ReopenAfterCloseRestoresService) {
  SubStreamTap tap;
  tap.SetActive(true);
  int stale_releases = 0;
  int fresh_releases = 0;

  tap.PublishLatest(MakeLease(stale_releases));
  tap.Close();
  EXPECT_EQ(stale_releases, 1);  // Close() drops the pending lease.

  tap.Reopen();
  EXPECT_EQ(stale_releases, 1);  // Reopen() must not double-release it.

  tap.SetActive(true);
  tap.RequestNext();
  EXPECT_TRUE(tap.ConsumeDemand());

  tap.PublishLatest(MakeLease(fresh_releases));
  auto got = tap.WaitNext(std::chrono::milliseconds(50));
  ASSERT_TRUE(got.has_value());
  EXPECT_TRUE(got->valid());
  EXPECT_EQ(fresh_releases, 0);
  EXPECT_EQ(stale_releases, 1);
}

TEST(SubStreamTapTest, PublishWhileInactiveIsDropped) {
  SubStreamTap tap;
  int releases = 0;
  tap.PublishLatest(MakeLease(releases));
  // Never active: the lease must not be squirreled away for a later window.
  EXPECT_EQ(releases, 1);

  tap.SetActive(true);
  EXPECT_FALSE(tap.WaitNext(std::chrono::milliseconds(10)).has_value());
}

}  // namespace
