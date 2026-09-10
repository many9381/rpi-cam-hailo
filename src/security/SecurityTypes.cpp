#include "camera_firmware/security/SecurityTypes.hpp"

#include <exception>

#include <openssl/crypto.h>

namespace camera_firmware::security {

SessionIdentity::SessionIdentity(const SessionIdentity& other) noexcept =
    default;

SessionIdentity& SessionIdentity::operator=(
    const SessionIdentity& other) noexcept {
  if (this != &other) {
    Clear();
    bytes = other.bytes;
  }
  return *this;
}

SessionIdentity::SessionIdentity(SessionIdentity&& other) noexcept
    : bytes(other.bytes) {
  other.Clear();
}

SessionIdentity& SessionIdentity::operator=(SessionIdentity&& other) noexcept {
  if (this != &other) {
    Clear();
    bytes = other.bytes;
    other.Clear();
  }
  return *this;
}

SessionIdentity::~SessionIdentity() noexcept {
  Clear();
}

void SessionIdentity::Clear() noexcept {
  ::OPENSSL_cleanse(bytes.data(), bytes.size());
}

void PublishSessionRevocations(
    std::vector<SessionIdentity>& identities,
    const SessionRevocationCallback& revoke_sessions,
    const GlobalStreamRevocationCallback& revoke_all_streams) noexcept {
  if (identities.empty() || !revoke_sessions) {
    return;
  }
  try {
    revoke_sessions(identities);
    return;
  } catch (...) {
    // swallowed: fall through to the broader stream revocation when the session
    // hook throws
  }

  if (revoke_all_streams) {
    try {
      revoke_all_streams();
      return;
    } catch (...) {
      // swallowed: fall through to clearing the identities when the stream hook
      // throws
    }
  }
  for (auto& identity : identities) {
    identity.Clear();
  }
  std::terminate();
}

}  // namespace camera_firmware::security
