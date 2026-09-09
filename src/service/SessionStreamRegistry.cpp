#include "camera_firmware/service/SessionStreamRegistry.hpp"

#include "SessionStreamRegistryInternal.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <future>
#include <limits>
#include <map>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace camera_firmware::service {
namespace internal {

struct SessionStreamLeaseState;

thread_local SessionStreamLeaseState* active_revocation_origin = nullptr;
thread_local std::uint8_t active_revocation_kind = 0U;

class HandlerOriginScope {
 public:
  HandlerOriginScope(SessionStreamLeaseState* origin,
                     std::uint8_t kind) noexcept
      : previous_origin_(active_revocation_origin),
        previous_kind_(active_revocation_kind) {
    active_revocation_origin = origin;
    active_revocation_kind = kind;
  }

  ~HandlerOriginScope() {
    active_revocation_origin = previous_origin_;
    active_revocation_kind = previous_kind_;
  }

 private:
  SessionStreamLeaseState* previous_origin_{nullptr};
  std::uint8_t previous_kind_{0U};
};

namespace {

#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
struct BatchMarkPause {
  std::mutex mutex;
  std::promise<void>* first_marked{nullptr};
  std::shared_future<void> release_marking;
};

BatchMarkPause& BatchMarkPauseForTesting() {
  static BatchMarkPause pause;
  return pause;
}

void PauseAfterFirstMarkForTesting() {
  std::promise<void>* first_marked = nullptr;
  std::shared_future<void> release_marking;
  {
    auto& pause = BatchMarkPauseForTesting();
    std::lock_guard lock(pause.mutex);
    first_marked = pause.first_marked;
    release_marking = pause.release_marking;
    pause.first_marked = nullptr;
    pause.release_marking = {};
  }
  if (first_marked != nullptr) {
    try {
      first_marked->set_value();
    } catch (...) {
      // swallowed: set_value throws if the promise was already satisfied; the
      // waiter is released either way
    }
  }
  if (release_marking.valid()) {
    release_marking.wait();
  }
}

std::atomic_size_t& FailedThreadLaunchesForTesting() {
  static std::atomic_size_t remaining{0U};
  return remaining;
}

std::atomic_size_t& LeaseStateDestructionCounterForTesting() {
  static std::atomic_size_t destructions{0U};
  return destructions;
}

bool ConsumeThreadLaunchFailureForTesting() noexcept {
  auto& remaining = FailedThreadLaunchesForTesting();
  auto count = remaining.load(std::memory_order_relaxed);
  while (count != 0U) {
    if (remaining.compare_exchange_weak(
            count, count - 1U, std::memory_order_relaxed)) {
      return true;
    }
  }
  return false;
}
#else
void PauseAfterFirstMarkForTesting() {}

bool ConsumeThreadLaunchFailureForTesting() noexcept {
  return false;
}
#endif

}  // namespace

struct SessionStreamRegistryState {
  struct Entry {
    std::uint64_t registration_id{0U};
    std::weak_ptr<SessionStreamLeaseState> lease;
  };

  void Remove(const security::SessionIdentity& identity,
              std::uint64_t registration_id) {
    std::lock_guard lock(mutex);
    const auto found = leases.find(identity);
    if (found == leases.end()) {
      return;
    }
    std::erase_if(found->second, [registration_id](const Entry& entry) {
      return entry.registration_id == registration_id ||
             entry.lease.expired();
    });
    if (found->second.empty()) {
      leases.erase(found);
    }
  }

  std::mutex mutex;
  std::map<security::SessionIdentity, std::vector<Entry>> leases;
  std::atomic_uint64_t next_registration_id{1U};
};

SessionStreamLeaseState::SessionStreamLeaseState(
    std::weak_ptr<SessionStreamRegistryState> registry_owner,
    const security::SessionIdentity& session_identity,
    std::uint64_t id)
    : registry(std::move(registry_owner)),
      identity(session_identity),
      registration_id(id) {}

SessionStreamLeaseState::~SessionStreamLeaseState() {
#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
  LeaseStateDestructionCounterForTesting().fetch_add(
      1U, std::memory_order_relaxed);
#endif
  if (auto owner = registry.lock()) {
    owner->Remove(identity, registration_id);
  }
}

void SessionStreamLeaseState::MarkRevokedLocked() noexcept {
  std::lock_guard lock(mutex);
  is_revoked.store(true, std::memory_order_release);
}

void SessionStreamLeaseState::InvokePending() noexcept {
  std::shared_ptr<StreamRevocationHandler> invoke;
  {
    std::lock_guard lock(mutex);
    if (!is_revoked.load(std::memory_order_acquire) || !handler_attached ||
        handler_invoked) {
      return;
    }
    handler_invoked = true;
    invoke = handler;
  }
  if (!invoke || !*invoke) {
    return;
  }
  try {
    (*invoke)();
  } catch (...) {
    // swallowed: revocation handlers are external code; the registry state is
    // already consistent
  }
  {
    std::lock_guard lock(mutex);
    if (handler == invoke) {
      handler.reset();
    }
  }
}

SessionStreamTerminalElection
SessionStreamLeaseState::TryBeginTerminalElection() {
  auto state = shared_from_this();
  std::unique_lock lock(mutex);
  const bool accepted = !is_revoked.load(std::memory_order_acquire);
  if (!accepted) {
    lock.unlock();
    InvokePending();
  }
  return SessionStreamTerminalElection(
      std::move(state), std::move(lock), accepted);
}

void SessionStreamLeaseState::SetHandler(
    StreamRevocationHandler new_handler) {
  auto stored = std::make_shared<StreamRevocationHandler>(
      std::move(new_handler));
  if (auto owner = registry.lock()) {
    std::lock_guard registry_lock(owner->mutex);
    std::lock_guard lease_lock(mutex);
    if (handler_attached) {
      return;
    }
    handler_attached = true;
    handler = std::move(stored);
  } else {
    std::lock_guard lease_lock(mutex);
    if (handler_attached) {
      return;
    }
    handler_attached = true;
    handler = std::move(stored);
  }
  InvokePending();
}

constexpr std::size_t kMaximumRevocationWorkers = 32U;

void InvokeMarked(
    const std::vector<std::shared_ptr<SessionStreamLeaseState>>& leases) {
  if (leases.empty()) {
    return;
  }
  auto* const revocation_origin = active_revocation_origin;
  const auto revocation_kind = active_revocation_kind;
  std::atomic_size_t next_index{0U};
  const auto invoke_next = [&] {
    HandlerOriginScope origin_scope(revocation_origin, revocation_kind);
    while (true) {
      const auto index = next_index.fetch_add(1U, std::memory_order_relaxed);
      if (index >= leases.size()) {
        return;
      }
      leases[index]->InvokePending();
    }
  };

  std::array<std::thread, kMaximumRevocationWorkers - 1U> threads;
  std::size_t launched = 0U;
  const auto worker_count =
      std::min(leases.size(), kMaximumRevocationWorkers);
  for (; launched + 1U < worker_count; ++launched) {
    try {
      if (ConsumeThreadLaunchFailureForTesting()) {
        throw std::system_error(
            std::make_error_code(std::errc::resource_unavailable_try_again));
      }
      threads[launched] = std::thread(invoke_next);
    } catch (...) {
      break;
    }
  }
  invoke_next();
  for (std::size_t index = 0U; index < launched; ++index) {
    if (threads[index].joinable()) {
      threads[index].join();
    }
  }
}

#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
void SetSessionStreamBatchMarkPauseForTesting(
    std::promise<void>* first_marked,
    std::shared_future<void> release_marking) noexcept {
  auto& pause = BatchMarkPauseForTesting();
  std::lock_guard lock(pause.mutex);
  pause.first_marked = first_marked;
  pause.release_marking = std::move(release_marking);
}

void FailNextSessionStreamRevocationThreadLaunchesForTesting(
    std::size_t count) noexcept {
  FailedThreadLaunchesForTesting().store(count, std::memory_order_relaxed);
}

void ResetSessionStreamLeaseStateDestructionsForTesting() noexcept {
  LeaseStateDestructionCounterForTesting().store(0U,
                                                 std::memory_order_relaxed);
}

std::size_t SessionStreamLeaseStateDestructionsForTesting() noexcept {
  return LeaseStateDestructionCounterForTesting().load(
      std::memory_order_relaxed);
}
#endif

}  // namespace internal

internal::SessionStreamRevocationScope::SessionStreamRevocationScope(
    const std::shared_ptr<SessionStreamLease>& lease) noexcept
    : SessionStreamRevocationScope(lease, Origin::kSend) {}

internal::SessionStreamRevocationScope::SessionStreamRevocationScope(
    const std::shared_ptr<SessionStreamLease>& lease,
    Origin origin) noexcept
    : previous_(internal::active_revocation_origin),
      previous_origin_(internal::active_revocation_kind) {
  internal::active_revocation_origin =
      lease ? lease->state_.get() : nullptr;
  internal::active_revocation_kind = static_cast<std::uint8_t>(origin);
}

internal::SessionStreamRevocationScope::~SessionStreamRevocationScope() {
  internal::active_revocation_origin = previous_;
  internal::active_revocation_kind = previous_origin_;
}

bool internal::SessionStreamRevocationScope::HandlerOriginatesFromSend()
    noexcept {
  return internal::active_revocation_kind ==
         static_cast<std::uint8_t>(Origin::kSend);
}

bool internal::SessionStreamRevocationScope::HandlerOriginatesFromRead(
    const std::shared_ptr<SessionStreamLease>& lease) noexcept {
  return lease && internal::active_revocation_origin == lease->state_.get() &&
         internal::active_revocation_kind ==
             static_cast<std::uint8_t>(Origin::kRead);
}

SessionStreamLease::SessionStreamLease(
    std::shared_ptr<internal::SessionStreamLeaseState> state) noexcept
    : state_(std::move(state)) {}

void SessionStreamLease::SetRevocationHandler(
    StreamRevocationHandler handler) {
  auto state = state_;
  state->SetHandler(std::move(handler));
}

bool SessionStreamLease::revoked() const noexcept {
  return state_->is_revoked.load(std::memory_order_acquire);
}

std::shared_ptr<internal::SessionStreamRegistryState>
SessionStreamRegistry::MakeState() {
  return std::make_shared<internal::SessionStreamRegistryState>();
}

std::shared_ptr<SessionStreamLease> SessionStreamRegistry::Acquire(
    const security::SessionIdentity& identity) {
  const auto registration_id =
      state_->next_registration_id.fetch_add(1U, std::memory_order_relaxed);
  auto lease_state = std::make_shared<internal::SessionStreamLeaseState>(
      state_, identity, registration_id);
  {
    std::lock_guard lock(state_->mutex);
    auto [entry, inserted] = state_->leases.try_emplace(identity);
    auto& entries = entry->second;
    try {
      entries.reserve(entries.size() + 1U);
    } catch (...) {
      if (inserted) {
        state_->leases.erase(entry);
      }
      throw;
    }
    std::erase_if(entries, [](const auto& entry) {
      return entry.lease.expired();
    });
    entries.push_back({registration_id, lease_state});
  }
  return std::shared_ptr<SessionStreamLease>(
      new SessionStreamLease(std::move(lease_state)));
}

void SessionStreamRegistry::Revoke(
    std::span<const security::SessionIdentity> identities) {
  std::vector<std::shared_ptr<internal::SessionStreamLeaseState>> leases;
  {
    std::lock_guard lock(state_->mutex);
    std::size_t maximum_leases = 0U;
    for (const auto& identity : identities) {
      const auto found = state_->leases.find(identity);
      if (found == state_->leases.end()) {
        continue;
      }
      if (found->second.size() >
          std::numeric_limits<std::size_t>::max() - maximum_leases) {
        throw std::length_error("too many session stream leases");
      }
      maximum_leases += found->second.size();
    }
    leases.reserve(maximum_leases);
    for (const auto& identity : identities) {
      const auto found = state_->leases.find(identity);
      if (found == state_->leases.end()) {
        continue;
      }
      for (const auto& entry : found->second) {
        if (auto lease = entry.lease.lock()) {
          leases.push_back(std::move(lease));
        }
      }
    }
    for (std::size_t index = 0U; index < leases.size(); ++index) {
      leases[index]->MarkRevokedLocked();
      if (index == 0U) {
        internal::PauseAfterFirstMarkForTesting();
      }
    }
    for (const auto& identity : identities) {
      const auto found = state_->leases.find(identity);
      if (found == state_->leases.end()) {
        continue;
      }
      state_->leases.erase(found);
    }
  }
  internal::InvokeMarked(leases);
}

void SessionStreamRegistry::RevokeAll() {
  std::vector<std::shared_ptr<internal::SessionStreamLeaseState>> leases;
  {
    std::lock_guard lock(state_->mutex);
    std::size_t maximum_leases = 0U;
    for (const auto& [identity, entries] : state_->leases) {
      (void)identity;
      if (entries.size() >
          std::numeric_limits<std::size_t>::max() - maximum_leases) {
        throw std::length_error("too many session stream leases");
      }
      maximum_leases += entries.size();
    }
    leases.reserve(maximum_leases);
    for (const auto& [identity, entries] : state_->leases) {
      (void)identity;
      for (const auto& entry : entries) {
        if (auto lease = entry.lease.lock()) {
          leases.push_back(std::move(lease));
        }
      }
    }
    for (std::size_t index = 0U; index < leases.size(); ++index) {
      leases[index]->MarkRevokedLocked();
      if (index == 0U) {
        internal::PauseAfterFirstMarkForTesting();
      }
    }
    state_->leases.clear();
  }
  internal::InvokeMarked(leases);
}

}  // namespace camera_firmware::service
