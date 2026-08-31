#pragma once

#include "camera_firmware/security/SecurityStore.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace camera_firmware::security {

class AuditLogServiceTestAccess {
 public:
  static common::Result<void> InsertSession(
      SecurityStore& store,
      SecurityStore::Transaction& transaction,
      std::span<const unsigned char> token_hash,
      std::int64_t user_id,
      std::string_view role,
      std::int64_t now_seconds,
      std::int64_t expires_at_seconds,
      std::string_view normalized_peer_ip,
      std::int64_t management_expires_at_seconds) {
    return store.InsertSession(transaction, token_hash, user_id, role,
                               now_seconds, expires_at_seconds,
                               normalized_peer_ip,
                               management_expires_at_seconds);
  }

  static common::Result<std::optional<std::int64_t>>
  ReadNextManagementExpiry(SecurityStore& store,
                           SecurityStore::Transaction& transaction) {
    return store.ReadNextManagementExpiry(transaction);
  }

  static common::Result<std::size_t> ExpireLapsedManagementAuthority(
      SecurityStore& store,
      SecurityStore::Transaction& transaction,
      std::int64_t now_seconds) {
    return store.ExpireLapsedManagementAuthority(transaction, now_seconds);
  }

  static common::Result<void> RefreshManagementDeadline(
      SecurityStore& store,
      SecurityStore::Transaction& transaction,
      std::int64_t session_id,
      std::int64_t management_expires_at_seconds) {
    return store.RefreshManagementDeadline(transaction, session_id,
                                           management_expires_at_seconds);
  }

  static common::Result<void> InsertCommittedEvent(
      SecurityStore& store,
      std::int64_t now_seconds,
      std::string_view event_type = "test_event") {
    auto started = store.BeginTransaction();
    if (!started.ok()) {
      return common::Result<void>::Err(started.error());
    }
    auto transaction = std::move(started).value();
    auto inserted = store.InsertAuditEvent(
        transaction, now_seconds, event_type, "success", std::nullopt,
        "192.0.2.10", "test_detail");
    if (!inserted.ok()) {
      if (transaction.active()) {
        (void)transaction.Rollback();
      }
      return common::Result<void>::Err(inserted.error());
    }
    auto committed = transaction.Commit();
    if (!committed.ok() && transaction.active()) {
      (void)transaction.Rollback();
    }
    return committed;
  }

  static common::Result<StoredManagedUser> InsertViewer(
      SecurityStore& store,
      std::string canonical_username,
      std::string display_username,
      PasswordRecord password,
      std::int64_t now_seconds,
      const SecurityMutationContext& context) {
    return store.InsertViewer(
        std::move(canonical_username), std::move(display_username),
        std::move(password), now_seconds, context);
  }
};

}  // namespace camera_firmware::security
