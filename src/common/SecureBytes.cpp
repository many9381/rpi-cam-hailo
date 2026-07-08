#include "camera_firmware/common/SecureBytes.hpp"

#include <algorithm>
#include <utility>

#if defined(CAMERA_FIRMWARE_HAS_OPENSSL)
#include <openssl/crypto.h>
#endif

namespace camera_firmware::common {

namespace {

void ZeroizeBuffer(unsigned char* data, std::size_t size) noexcept {
  if (data == nullptr || size == 0U) {
    return;
  }

#if defined(CAMERA_FIRMWARE_HAS_OPENSSL)
  OPENSSL_cleanse(data, size);
#else
  volatile unsigned char* cursor = data;
  for (std::size_t index = 0; index < size; ++index) {
    cursor[index] = 0U;
  }
#endif
}

}  // namespace

SecureBytes::~SecureBytes() { clear(); }

SecureBytes::SecureBytes(SecureBytes&& other) noexcept
    : bytes_(std::move(other.bytes_)),
      zeroize_count_(std::exchange(other.zeroize_count_, 0U)) {}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept {
  if (this == &other) {
    return *this;
  }

  clear();
  bytes_ = std::move(other.bytes_);
  zeroize_count_ = std::exchange(other.zeroize_count_, 0U);
  return *this;
}

void SecureBytes::assign(const unsigned char* data, std::size_t size) {
  if (size == 0U) {
    clear();
    return;
  }

  std::vector<unsigned char> replacement(data, data + size);

  if (!bytes_.empty()) {
    ZeroizeBuffer(bytes_.data(), bytes_.size());
    ++zeroize_count_;
  }

  bytes_.swap(replacement);
}

void SecureBytes::clear() noexcept {
  if (bytes_.empty()) {
    return;
  }

  ZeroizeBuffer(bytes_.data(), bytes_.size());
  ++zeroize_count_;
  bytes_.clear();
  bytes_.shrink_to_fit();
}

const unsigned char* SecureBytes::data() const noexcept {
  return bytes_.data();
}

std::size_t SecureBytes::size() const noexcept { return bytes_.size(); }

std::size_t SecureBytes::zeroize_count_for_test() const noexcept {
  return zeroize_count_;
}

}  // namespace camera_firmware::common
