#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/security/PasswordHasher.hpp"

namespace camera_firmware::security {

class BootstrapService;

enum class DeviceState { kDefault, kOperational };

struct SecurityStoreConfig {
  std::filesystem::path state_directory;
};

struct BootstrapRecord {
  std::string canonical_username;
  std::string display_username;
  PasswordRecord password;
  std::string normalized_peer_ip;
  std::int64_t completed_at_seconds{0};
};

using CredentialInstaller = std::function<common::Result<void>()>;

class SecurityStore {
 private:
  struct Impl;

 public:
  class Transaction {
   public:
    ~Transaction();

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    Transaction(Transaction&& other) noexcept;
    Transaction& operator=(Transaction&& other) = delete;

    common::Result<void> Commit();
    common::Result<void> Rollback();
    [[nodiscard]] bool active() const noexcept;

   private:
    friend class SecurityStore;
    Transaction(std::shared_ptr<Impl> impl,
                std::unique_lock<std::mutex> connection_lease) noexcept;

    std::shared_ptr<Impl> impl_;
    std::unique_lock<std::mutex> connection_lease_;
    bool active_{false};
  };

  static common::Result<std::unique_ptr<SecurityStore>> Open(
      SecurityStoreConfig config);
  ~SecurityStore();

  SecurityStore(const SecurityStore&) = delete;
  SecurityStore& operator=(const SecurityStore&) = delete;

  common::Result<Transaction> BeginTransaction();
  // Lock order: BootstrapService mutex, connection lease, credential installer.
  common::Result<void> InitializeDevice(
      BootstrapRecord record,
      const CredentialInstaller& install_credential);
  common::Result<DeviceState> State() const;
  [[nodiscard]] const std::filesystem::path& state_directory() const noexcept;
  [[nodiscard]] const std::filesystem::path& database_path() const noexcept;

 private:
  friend class BootstrapService;

  explicit SecurityStore(std::shared_ptr<Impl> impl) noexcept;
  common::Result<void> InitializeSchema();
  common::Result<DeviceState> StateUnderConnectionLease() const;
  common::Result<void> InstallBootstrapRtspCredential(
      const std::filesystem::path& configured_path,
      std::string_view username,
      std::string_view realm,
      std::span<const unsigned char> password) const;

  std::shared_ptr<Impl> impl_;
};

}  // namespace camera_firmware::security
