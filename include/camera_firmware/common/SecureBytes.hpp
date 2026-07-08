#pragma once

#include <cstddef>
#include <vector>

namespace camera_firmware::common {

class SecureBytes {
 public:
  SecureBytes() = default;
  ~SecureBytes();

  SecureBytes(const SecureBytes&) = delete;
  SecureBytes& operator=(const SecureBytes&) = delete;

  SecureBytes(SecureBytes&& other) noexcept;
  SecureBytes& operator=(SecureBytes&& other) noexcept;

  void assign(const unsigned char* data, std::size_t size);
  void clear() noexcept;

  [[nodiscard]] const unsigned char* data() const noexcept;
  [[nodiscard]] std::size_t size() const noexcept;
  [[nodiscard]] std::size_t zeroize_count_for_test() const noexcept;

 private:
  std::vector<unsigned char> bytes_;
  std::size_t zeroize_count_{0};
};

}  // namespace camera_firmware::common
