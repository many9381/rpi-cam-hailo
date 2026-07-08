#include "camera_firmware/ai/AiFrameTap.hpp"

#include <chrono>
#include <future>

#include <gtest/gtest.h>

#include "camera_firmware/media/FrameLease.hpp"

TEST(AiFrameTapTest, KeepsLatestFrameOnly) {
  camera_firmware::ai::AiFrameTap tap;
  camera_firmware::media::FrameHandle h;
  h.sequence = 42;

  tap.PublishLatest(camera_firmware::media::FrameLease(h, [] {}));

  auto latest = tap.Latest();

  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(latest->handle().sequence, 42u);
}

TEST(AiFrameTapTest, ReplacesOlderFrameWithLatestOnly) {
  camera_firmware::ai::AiFrameTap tap;
  int releases = 0;

  camera_firmware::media::FrameHandle first;
  first.sequence = 1;
  tap.PublishLatest(
      camera_firmware::media::FrameLease(first, [&] { ++releases; }));

  camera_firmware::media::FrameHandle second;
  second.sequence = 2;
  tap.PublishLatest(
      camera_firmware::media::FrameLease(second, [&] { ++releases; }));

  auto latest = tap.Latest();

  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(latest->handle().sequence, 2u);
  EXPECT_EQ(releases, 1);
}

TEST(AiFrameTapTest, LatestCloneRefPreservesReleaseCallbackSemantics) {
  camera_firmware::ai::AiFrameTap tap;
  int releases = 0;

  camera_firmware::media::FrameHandle handle;
  handle.sequence = 7;
  tap.PublishLatest(
      camera_firmware::media::FrameLease(handle, [&] { ++releases; }));

  auto first = tap.Latest();
  auto second = tap.Latest();

  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(first->handle().sequence, 7u);
  EXPECT_EQ(second->handle().sequence, 7u);
  EXPECT_EQ(releases, 0);

  first.reset();
  second.reset();
  EXPECT_EQ(releases, 0);
}

TEST(AiFrameTapTest, NotifiesSubscriberWithCloneOfLatestFrame) {
  camera_firmware::ai::AiFrameTap tap;
  std::uint64_t delivered_sequence = 0;

  auto subscription = tap.Subscribe(
      [&delivered_sequence](camera_firmware::media::FrameLease frame) {
        delivered_sequence = frame.handle().sequence;
      });

  camera_firmware::media::FrameHandle handle;
  handle.sequence = 11;
  tap.PublishLatest(camera_firmware::media::FrameLease(handle, [] {}));

  EXPECT_TRUE(subscription.valid());
  EXPECT_EQ(delivered_sequence, 11u);
}

TEST(AiFrameTapTest, SubscriberCanReadLatestWithoutDeadlock) {
  camera_firmware::ai::AiFrameTap tap;
  bool saw_latest = false;
  std::uint64_t latest_sequence = 0;

  auto subscription =
      tap.Subscribe([&tap, &saw_latest, &latest_sequence](
                        camera_firmware::media::FrameLease) {
        auto latest = tap.Latest();
        saw_latest = latest.has_value();
        if (latest.has_value()) {
          latest_sequence = latest->handle().sequence;
        }
      });

  camera_firmware::media::FrameHandle handle;
  handle.sequence = 12;
  auto publish = std::async(std::launch::async, [&tap, handle] {
    tap.PublishLatest(camera_firmware::media::FrameLease(handle, [] {}));
  });

  EXPECT_EQ(publish.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  publish.get();
  EXPECT_TRUE(subscription.valid());
  EXPECT_TRUE(saw_latest);
  EXPECT_EQ(latest_sequence, 12u);
}

TEST(AiFrameTapTest, UnsubscribeWaitsForInFlightCallback) {
  camera_firmware::ai::AiFrameTap tap;
  std::promise<void> callback_started;
  std::promise<void> release_callback;
  auto release_future = release_callback.get_future();

  auto subscription = tap.Subscribe(
      [&callback_started, &release_future](
          camera_firmware::media::FrameLease) mutable {
        callback_started.set_value();
        release_future.wait();
      });

  camera_firmware::media::FrameHandle handle;
  handle.sequence = 13;
  auto publish = std::async(std::launch::async, [&tap, handle] {
    tap.PublishLatest(camera_firmware::media::FrameLease(handle, [] {}));
  });

  ASSERT_EQ(callback_started.get_future().wait_for(std::chrono::seconds(1)),
            std::future_status::ready);

  auto unsubscribe = std::async(std::launch::async, [&subscription] {
    subscription = camera_firmware::ai::AiFrameTap::Subscription{};
  });
  EXPECT_EQ(unsubscribe.wait_for(std::chrono::milliseconds(50)),
            std::future_status::timeout);

  release_callback.set_value();
  EXPECT_EQ(publish.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  EXPECT_EQ(unsubscribe.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
}

TEST(AiFrameTapTest, UnsubscribePreventsFutureCallbacks) {
  camera_firmware::ai::AiFrameTap tap;
  int deliveries = 0;

  auto subscription =
      tap.Subscribe([&deliveries](camera_firmware::media::FrameLease) {
        ++deliveries;
      });
  subscription = camera_firmware::ai::AiFrameTap::Subscription{};

  camera_firmware::media::FrameHandle handle;
  handle.sequence = 14;
  tap.PublishLatest(camera_firmware::media::FrameLease(handle, [] {}));

  EXPECT_EQ(deliveries, 0);
}
