#include "camera_firmware/media/EncodeMailbox.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <thread>

#include <gtest/gtest.h>

#include "camera_firmware/media/FrameLease.hpp"

namespace {

using camera_firmware::media::EncodeJob;
using camera_firmware::media::EncodeMailbox;
using camera_firmware::media::FrameHandle;
using camera_firmware::media::FrameLease;

// A sentinel buffer pointer: the mailbox only carries it, never dereferences.
const libcamera::FrameBuffer* FakeBuffer(std::uintptr_t value) {
  return reinterpret_cast<const libcamera::FrameBuffer*>(value);
}

EncodeJob MakeJob(std::uintptr_t buffer_value, int& release_counter) {
  FrameHandle handle;
  return EncodeJob{
      FakeBuffer(buffer_value),
      FrameLease(handle, [&release_counter] { ++release_counter; })};
}

TEST(EncodeMailboxTest, TakeReturnsThePublishedJob) {
  EncodeMailbox mailbox;
  int releases = 0;
  mailbox.Publish(MakeJob(0x10, releases));

  auto job = mailbox.Take();
  ASSERT_TRUE(job.has_value());
  EXPECT_EQ(job->buffer, FakeBuffer(0x10));
  EXPECT_TRUE(job->lease.valid());
}

TEST(EncodeMailboxTest, PublishSupersedesAndReleasesTheStaleJob) {
  EncodeMailbox mailbox;
  int first_releases = 0;
  int second_releases = 0;

  mailbox.Publish(MakeJob(0x10, first_releases));
  // No Take between the two publishes: the first job is stale and its lease
  // must release so its capture buffer requeues instead of stalling.
  EXPECT_EQ(first_releases, 0);
  mailbox.Publish(MakeJob(0x20, second_releases));
  EXPECT_EQ(first_releases, 1);

  auto job = mailbox.Take();
  ASSERT_TRUE(job.has_value());
  EXPECT_EQ(job->buffer, FakeBuffer(0x20));
}

TEST(EncodeMailboxTest, TakeBlocksUntilAJobIsPublished) {
  EncodeMailbox mailbox;
  int releases = 0;
  std::atomic_bool took{false};

  std::promise<void> entered;
  auto entered_future = entered.get_future();
  std::thread consumer([&] {
    entered.set_value();
    auto job = mailbox.Take();
    took = job.has_value();
  });

  entered_future.wait();
  // The consumer is blocked in Take(); give it a moment, then feed it.
  EXPECT_FALSE(took.load());
  mailbox.Publish(MakeJob(0x30, releases));
  consumer.join();
  EXPECT_TRUE(took.load());
}

TEST(EncodeMailboxTest, CloseWakesABlockedTakeWithNullopt) {
  EncodeMailbox mailbox;
  std::atomic_bool has_value{true};

  std::promise<void> entered;
  auto entered_future = entered.get_future();
  std::thread consumer([&] {
    entered.set_value();
    auto job = mailbox.Take();
    has_value = job.has_value();
  });

  entered_future.wait();
  mailbox.Close();
  consumer.join();
  EXPECT_FALSE(has_value.load());
}

TEST(EncodeMailboxTest, CloseDropsThePendingJobAndTakeReturnsNullopt) {
  EncodeMailbox mailbox;
  int releases = 0;
  mailbox.Publish(MakeJob(0x40, releases));

  mailbox.Close();
  // Close must release the undelivered job so its buffer requeues on shutdown.
  EXPECT_EQ(releases, 1);
  EXPECT_FALSE(mailbox.Take().has_value());
}

TEST(EncodeMailboxTest, PublishAfterCloseIsDroppedImmediately) {
  EncodeMailbox mailbox;
  int releases = 0;
  mailbox.Close();

  mailbox.Publish(MakeJob(0x50, releases));
  // A publish that races shutdown must not linger; its lease releases at once.
  EXPECT_EQ(releases, 1);
  EXPECT_FALSE(mailbox.Take().has_value());
}

TEST(EncodeMailboxTest, ReopenReturnsAClosedMailboxToService) {
  EncodeMailbox mailbox;
  int stale_releases = 0;
  int fresh_releases = 0;

  mailbox.Publish(MakeJob(0x60, stale_releases));
  mailbox.Close();
  EXPECT_EQ(stale_releases, 1);

  // A profile-change restart reuses the instance: after Reopen it must accept
  // and deliver frames again.
  mailbox.Reopen();
  mailbox.Publish(MakeJob(0x70, fresh_releases));
  auto job = mailbox.Take();
  ASSERT_TRUE(job.has_value());
  EXPECT_EQ(job->buffer, FakeBuffer(0x70));
}

}  // namespace
