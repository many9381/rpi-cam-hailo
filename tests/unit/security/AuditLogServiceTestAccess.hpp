#pragma once

#include "camera_firmware/security/SecurityStore.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace camera_firmware::security {

class AuditLogServiceTestAccess {
 public:
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
