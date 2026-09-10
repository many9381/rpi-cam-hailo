#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>

#include "camera_firmware/service/SessionStreamRegistry.hpp"

namespace camera_firmware::service::internal {

struct SessionStreamRegistryState;

class SessionStreamTerminalElection {
 public:
  SessionStreamTerminalElection(SessionStreamTerminalElection&&) noexcept =
      default;
  SessionStreamTerminalElection& operator=(
      SessionStreamTerminalElection&&) noexcept = default;
  ~SessionStreamTerminalElection() = default;

  SessionStreamTerminalElection(const SessionStreamTerminalElection&) = delete;
  SessionStreamTerminalElection& operator=(
      const SessionStreamTerminalElection&) = delete;

  [[nodiscard]] explicit operator bool() const noexcept { return accepted_; }

 private:
  friend struct SessionStreamLeaseState;

  SessionStreamTerminalElection(std::shared_ptr<SessionStreamLeaseState> state,
                                std::unique_lock<std::mutex> lock,
                                bool accepted) noexcept
      : state_(std::move(state)), lock_(std::move(lock)), accepted_(accepted) {}

  std::shared_ptr<SessionStreamLeaseState> state_;
  std::unique_lock<std::mutex> lock_;
  bool accepted_{false};
};

struct SessionStreamLeaseState
    : public std::enable_shared_from_this<SessionStreamLeaseState> {
  SessionStreamLeaseState(
      std::weak_ptr<SessionStreamRegistryState> registry_owner,
      const security::SessionIdentity& session_identity, std::uint64_t id);
  ~SessionStreamLeaseState();

  void SetHandler(StreamRevocationHandler new_handler);
  void MarkRevokedLocked() noexcept;
  void InvokePending() noexcept;
  [[nodiscard]] SessionStreamTerminalElection TryBeginTerminalElection();

  std::weak_ptr<SessionStreamRegistryState> registry;
  security::SessionIdentity identity;
  std::uint64_t registration_id{0U};
  std::mutex mutex;
  std::atomic_bool is_revoked{false};
  std::shared_ptr<StreamRevocationHandler> handler;
  bool handler_attached{false};
  bool handler_invoked{false};
};

}  // namespace camera_firmware::service::internal
