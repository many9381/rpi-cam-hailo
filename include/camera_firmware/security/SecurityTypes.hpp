#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <functional>
#include <span>
#include <vector>

namespace camera_firmware::security {

inline constexpr std::size_t kSessionIdentityBytes = 32U;

enum class UserRole { kAdministrator, kViewer };

struct SessionIdentity {
  std::array<unsigned char, kSessionIdentityBytes> bytes{};

  SessionIdentity() = default;
  SessionIdentity(const SessionIdentity& other) noexcept;
  SessionIdentity& operator=(const SessionIdentity& other) noexcept;
  SessionIdentity(SessionIdentity&& other) noexcept;
  SessionIdentity& operator=(SessionIdentity&& other) noexcept;
  ~SessionIdentity() noexcept;

  void Clear() noexcept;

  auto operator<=>(const SessionIdentity&) const = default;
};

using SessionRevocationCallback =
    std::function<void(std::span<const SessionIdentity>)>;
using GlobalStreamRevocationCallback = std::function<void()>;

void PublishSessionRevocations(
    std::vector<SessionIdentity>& identities,
    const SessionRevocationCallback& revoke_sessions,
    const GlobalStreamRevocationCallback& revoke_all_streams) noexcept;

}  // namespace camera_firmware::security
