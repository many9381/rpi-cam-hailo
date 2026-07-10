#pragma once

#include <filesystem>
#include <memory>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::security {

enum class DeviceState { kDefault, kOperational };

struct SecurityStoreConfig {
  std::filesystem::path state_directory;
};

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

    common::Result<void> SetDeviceState(DeviceState state);
    common::Result<void> Commit();
    common::Result<void> Rollback();
    [[nodiscard]] bool active() const noexcept;

   private:
    friend class SecurityStore;
    explicit Transaction(std::shared_ptr<Impl> impl) noexcept;

    std::shared_ptr<Impl> impl_;
    bool active_{false};
  };

  static common::Result<std::unique_ptr<SecurityStore>> Open(
      SecurityStoreConfig config);
  ~SecurityStore();

  SecurityStore(const SecurityStore&) = delete;
  SecurityStore& operator=(const SecurityStore&) = delete;

  common::Result<Transaction> BeginTransaction();
  common::Result<DeviceState> State() const;
  [[nodiscard]] const std::filesystem::path& state_directory() const noexcept;
  [[nodiscard]] const std::filesystem::path& database_path() const noexcept;

 private:
  explicit SecurityStore(std::shared_ptr<Impl> impl) noexcept;
  common::Result<void> InitializeSchema();

  std::shared_ptr<Impl> impl_;
};

}  // namespace camera_firmware::security
