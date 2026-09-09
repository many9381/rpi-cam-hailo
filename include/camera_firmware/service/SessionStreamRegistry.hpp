#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>

#include "camera_firmware/security/SecurityTypes.hpp"

namespace camera_firmware::service {

class SessionStreamLease;

namespace internal {
struct SessionStreamLeaseState;
struct SessionStreamRegistryState;
class LiveMp4PumpState;
class DetectionSsePendingResponse;
class SessionStreamRevocationScope;
}  // namespace internal

using StreamRevocationHandler = std::function<void()>;

class SessionStreamRegistry;

class SessionStreamLease {
 public:
  void SetRevocationHandler(StreamRevocationHandler handler);
  [[nodiscard]] bool revoked() const noexcept;

 private:
  friend class SessionStreamRegistry;
  friend class internal::DetectionSsePendingResponse;
  friend class internal::SessionStreamRevocationScope;

  explicit SessionStreamLease(
      std::shared_ptr<internal::SessionStreamLeaseState> state) noexcept;

  std::shared_ptr<internal::SessionStreamLeaseState> state_;
};

namespace internal {
class SessionStreamRevocationScope {
 private:
  friend class LiveMp4PumpState;

  enum class Origin : std::uint8_t {
    kSend = 1U,
    kRead = 2U,
    kCancel = 3U,
  };

  explicit SessionStreamRevocationScope(
      const std::shared_ptr<SessionStreamLease>& lease) noexcept;
  SessionStreamRevocationScope(const std::shared_ptr<SessionStreamLease>& lease,
                               Origin origin) noexcept;
  ~SessionStreamRevocationScope();

 public:
  SessionStreamRevocationScope(const SessionStreamRevocationScope&) = delete;
  SessionStreamRevocationScope& operator=(const SessionStreamRevocationScope&) =
      delete;

 private:
  [[nodiscard]] static bool HandlerOriginatesFromSend() noexcept;
  [[nodiscard]] static bool HandlerOriginatesFromRead(
      const std::shared_ptr<SessionStreamLease>& lease) noexcept;

  SessionStreamLeaseState* previous_{nullptr};
  std::uint8_t previous_origin_{0U};
};

}  // namespace internal

class SessionStreamRegistry {
 public:
  std::shared_ptr<SessionStreamLease> Acquire(
      const security::SessionIdentity& identity);
  void Revoke(std::span<const security::SessionIdentity> identities);
  void RevokeAll();

 private:
  static std::shared_ptr<internal::SessionStreamRegistryState> MakeState();

  std::shared_ptr<internal::SessionStreamRegistryState> state_{MakeState()};
};

}  // namespace camera_firmware::service
