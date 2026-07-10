#pragma once

#include <cstddef>
#include <vector>

namespace camera_firmware::common {

struct ZeroizeAudit {
  std::size_t count{0};
  bool last_verified{true};
};

class SecureBytes {
 public:
  SecureBytes() = default;
  ~SecureBytes();

  SecureBytes(const SecureBytes&) = delete;
  SecureBytes& operator=(const SecureBytes&) = delete;

  SecureBytes(SecureBytes&& other) noexcept;
  SecureBytes& operator=(SecureBytes&& other) noexcept;

  void assign(const unsigned char* data, std::size_t size);
  void resize(std::size_t size);
  void append(const unsigned char* data, std::size_t size);
  void clear() noexcept;

  [[nodiscard]] unsigned char* data() noexcept;
  [[nodiscard]] const unsigned char* data() const noexcept;
  [[nodiscard]] std::size_t size() const noexcept;
  [[nodiscard]] ZeroizeAudit zeroize_audit() const noexcept;
  [[nodiscard]] std::size_t zeroize_count_for_test() const noexcept;

 private:
  void cleanse_owned_bytes() noexcept;

  std::vector<unsigned char> bytes_;
  std::size_t zeroize_count_{0};
  bool last_zeroize_verified_{true};
};

}  // namespace camera_firmware::common
