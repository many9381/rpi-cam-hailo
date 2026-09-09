#include "camera_firmware/service/SessionStreamRegistry.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <future>
#include <memory>
#include <thread>

#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace camera_firmware::service {

namespace internal {
void SetSessionStreamBatchMarkPauseForTesting(
    std::promise<void>* first_marked,
    std::shared_future<void> release_marking) noexcept;
void FailNextSessionStreamRevocationThreadLaunchesForTesting(
    std::size_t count) noexcept;
void ResetSessionStreamLeaseStateDestructionsForTesting() noexcept;
std::size_t SessionStreamLeaseStateDestructionsForTesting() noexcept;
}  // namespace internal

namespace {

security::SessionIdentity Identity(unsigned char tag) {
  security::SessionIdentity identity;
  identity.bytes.fill(tag);
  return identity;
}

TEST(SessionStreamRegistryTest, RevokeBeforeHandlerInvokesHandlerOnceOnAttach) {
  SessionStreamRegistry registry;
  auto lease = registry.Acquire(Identity(7));
  const std::array revoked{Identity(7)};
  registry.Revoke(revoked);
  std::atomic_size_t calls{0U};

  lease->SetRevocationHandler([&] { calls.fetch_add(1U); });
  lease->SetRevocationHandler([&] { calls.fetch_add(1U); });

  EXPECT_TRUE(lease->revoked());
  EXPECT_EQ(calls.load(), 1U);
}

TEST(SessionStreamRegistryTest,
     LateHandlerMayDropLastLeaseOwnerDuringSynchronousInvocation) {
  const auto child = ::fork();
  ASSERT_NE(child, -1);
  if (child == 0) {
    internal::ResetSessionStreamLeaseStateDestructionsForTesting();
    SessionStreamRegistry registry;
    auto lease = registry.Acquire(Identity(14));
    const std::array revoked{Identity(14)};
    registry.Revoke(revoked);
    std::atomic_size_t calls{0U};
    std::atomic_bool destroyed_during_handler{false};

    lease->SetRevocationHandler([&] {
      calls.fetch_add(1U, std::memory_order_relaxed);
      lease.reset();
      destroyed_during_handler.store(
          internal::SessionStreamLeaseStateDestructionsForTesting() != 0U,
          std::memory_order_relaxed);
    });

    _exit(calls.load(std::memory_order_relaxed) == 1U && !lease &&
                  !destroyed_during_handler.load(std::memory_order_relaxed) &&
                  internal::SessionStreamLeaseStateDestructionsForTesting() ==
                      1U
              ? 0
              : 1);
  }

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(SessionStreamRegistryTest, RevokeAfterHandlerInvokesHandlerOnce) {
  SessionStreamRegistry registry;
  auto lease = registry.Acquire(Identity(7));
  std::atomic_size_t calls{0U};
  lease->SetRevocationHandler([&] { calls.fetch_add(1U); });
  const std::array revoked{Identity(7)};

  registry.Revoke(revoked);
  registry.Revoke(revoked);

  EXPECT_TRUE(lease->revoked());
  EXPECT_EQ(calls.load(), 1U);
}

TEST(SessionStreamRegistryTest, RevokeAffectsEveryLeaseForExactIdentityOnly) {
  SessionStreamRegistry registry;
  auto first = registry.Acquire(Identity(7));
  auto second = registry.Acquire(Identity(7));
  auto newer = registry.Acquire(Identity(8));
  const std::array revoked{Identity(7)};

  registry.Revoke(revoked);

  EXPECT_TRUE(first->revoked());
  EXPECT_TRUE(second->revoked());
  EXPECT_FALSE(newer->revoked());
}

TEST(SessionStreamRegistryTest,
     RevokeMarksAndSignalsLaterLeaseWhileEarlierHandlerIsBlocked) {
  SessionStreamRegistry registry;
  auto first = registry.Acquire(Identity(7));
  auto second = registry.Acquire(Identity(7));
  std::promise<void> first_entered;
  auto first_entered_future = first_entered.get_future();
  std::promise<void> release_first;
  auto release_first_future = release_first.get_future().share();
  std::promise<void> second_signalled;
  auto second_signalled_future = second_signalled.get_future();
  first->SetRevocationHandler([&] {
    first_entered.set_value();
    release_first_future.wait();
  });
  second->SetRevocationHandler([&] { second_signalled.set_value(); });
  const std::array revoked{Identity(7)};

  auto revoking =
      std::async(std::launch::async, [&] { registry.Revoke(revoked); });
  const bool first_started =
      first_entered_future.wait_for(std::chrono::seconds(1)) ==
      std::future_status::ready;
  EXPECT_TRUE(first_started);
  if (first_started) {
    EXPECT_TRUE(second->revoked());
    EXPECT_EQ(second_signalled_future.wait_for(std::chrono::milliseconds(100)),
              std::future_status::ready);
  }
  release_first.set_value();
  ASSERT_EQ(revoking.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  revoking.get();
}

TEST(SessionStreamRegistryTest, ExactRevokeAllowsSameIdentityReacquisition) {
  SessionStreamRegistry registry;
  const auto identity = Identity(13);
  const std::array revoked{identity};
  auto original = registry.Acquire(identity);

  registry.Revoke(revoked);
  auto reacquired = registry.Acquire(identity);

  EXPECT_TRUE(original->revoked());
  EXPECT_FALSE(reacquired->revoked());
  registry.Revoke(revoked);
  EXPECT_TRUE(reacquired->revoked());
}

TEST(SessionStreamRegistryTest, RevokeAllRevokesEveryCurrentLease) {
  SessionStreamRegistry registry;
  auto first = registry.Acquire(Identity(1));
  auto second = registry.Acquire(Identity(2));

  registry.RevokeAll();

  EXPECT_TRUE(first->revoked());
  EXPECT_TRUE(second->revoked());
  auto acquired_after_revoke_all = registry.Acquire(Identity(1));
  EXPECT_FALSE(acquired_after_revoke_all->revoked());
}

TEST(SessionStreamRegistryTest,
     HandlerRegistrationConcurrentWithRevokeIsExactOnce) {
  for (std::size_t iteration = 0; iteration < 200U; ++iteration) {
    SessionStreamRegistry registry;
    auto lease = registry.Acquire(Identity(9));
    std::atomic_size_t calls{0U};
    std::promise<void> start;
    auto start_signal = start.get_future().share();
    std::thread registration([&] {
      start_signal.wait();
      lease->SetRevocationHandler([&] { calls.fetch_add(1U); });
    });
    std::thread revocation([&] {
      start_signal.wait();
      const std::array revoked{Identity(9)};
      registry.Revoke(revoked);
    });

    start.set_value();
    registration.join();
    revocation.join();

    EXPECT_TRUE(lease->revoked());
    EXPECT_EQ(calls.load(), 1U);
  }
}

TEST(SessionStreamRegistryTest,
     LateHandlerAfterFirstMarkWaitsUntilEntireBatchIsRevoked) {
  SessionStreamRegistry registry;
  auto first = registry.Acquire(Identity(10));
  auto second = registry.Acquire(Identity(10));
  std::promise<void> first_marked;
  auto first_marked_future = first_marked.get_future();
  std::promise<void> release_marking;
  auto release_marking_future = release_marking.get_future().share();
  internal::SetSessionStreamBatchMarkPauseForTesting(&first_marked,
                                                     release_marking_future);
  const std::array revoked{Identity(10)};
  auto revoking =
      std::async(std::launch::async, [&] { registry.Revoke(revoked); });
  ASSERT_EQ(first_marked_future.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  ASSERT_TRUE(first->revoked());
  ASSERT_FALSE(second->revoked());

  std::atomic_bool observed_second_revoked{false};
  auto attaching = std::async(std::launch::async, [&] {
    first->SetRevocationHandler([&] {
      observed_second_revoked.store(second->revoked(),
                                    std::memory_order_release);
    });
  });
  EXPECT_EQ(attaching.wait_for(std::chrono::milliseconds(100)),
            std::future_status::timeout);

  release_marking.set_value();
  ASSERT_EQ(revoking.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  revoking.get();
  ASSERT_EQ(attaching.wait_for(std::chrono::seconds(1)),
            std::future_status::ready);
  attaching.get();
  EXPECT_TRUE(observed_second_revoked.load(std::memory_order_acquire));
  internal::SetSessionStreamBatchMarkPauseForTesting(nullptr, {});
}

TEST(SessionStreamRegistryTest,
     ThreadLaunchFailureFallsBackWithoutLosingPendingHandlers) {
  SessionStreamRegistry registry;
  constexpr std::size_t kLeaseCount = 40U;
  std::vector<std::shared_ptr<SessionStreamLease>> leases;
  leases.reserve(kLeaseCount);
  std::atomic_size_t calls{0U};
  for (std::size_t index = 0U; index < kLeaseCount; ++index) {
    auto lease = registry.Acquire(Identity(11));
    lease->SetRevocationHandler(
        [&] { calls.fetch_add(1U, std::memory_order_relaxed); });
    leases.push_back(std::move(lease));
  }
  internal::FailNextSessionStreamRevocationThreadLaunchesForTesting(
      kLeaseCount);
  const std::array revoked{Identity(11)};

  registry.Revoke(revoked);

  EXPECT_EQ(calls.load(std::memory_order_relaxed), kLeaseCount);
  for (const auto& lease : leases) {
    EXPECT_TRUE(lease->revoked());
  }
  internal::FailNextSessionStreamRevocationThreadLaunchesForTesting(0U);
}

TEST(SessionStreamRegistryTest,
     CallbacksExecuteOutsideRegistryAndLeaseMutexes) {
  SessionStreamRegistry registry;
  auto lease = registry.Acquire(Identity(3));
  std::atomic_bool returned_from_nested_calls{false};
  lease->SetRevocationHandler([&] {
    lease->SetRevocationHandler([] {});
    auto nested = registry.Acquire(Identity(4));
    const std::array nested_identity{Identity(4)};
    registry.Revoke(nested_identity);
    returned_from_nested_calls.store(nested->revoked());
  });
  const std::array revoked{Identity(3)};

  registry.Revoke(revoked);

  EXPECT_TRUE(returned_from_nested_calls.load());
}

TEST(SessionStreamRegistryTest, LeaseMayBeDestroyedBeforeRegistry) {
  SessionStreamRegistry registry;
  {
    auto lease = registry.Acquire(Identity(5));
    EXPECT_FALSE(lease->revoked());
  }

  const std::array revoked{Identity(5)};
  EXPECT_NO_THROW(registry.Revoke(revoked));
}

TEST(SessionStreamRegistryTest, RegistryMayBeDestroyedBeforeLease) {
  std::shared_ptr<SessionStreamLease> lease;
  {
    SessionStreamRegistry registry;
    lease = registry.Acquire(Identity(6));
  }

  EXPECT_FALSE(lease->revoked());
  EXPECT_NO_THROW(lease.reset());
}

TEST(SessionStreamRegistryTest, DestroyedLeasesDoNotAffectLaterLease) {
  SessionStreamRegistry registry;
  for (std::size_t tag = 0; tag < 512U; ++tag) {
    auto lease = registry.Acquire(Identity(static_cast<unsigned char>(tag)));
    ASSERT_FALSE(lease->revoked());
  }
  auto survivor = registry.Acquire(Identity(42));
  const std::array other_identity{Identity(41)};

  registry.Revoke(other_identity);

  EXPECT_FALSE(survivor->revoked());
}

}  // namespace
}  // namespace camera_firmware::service
