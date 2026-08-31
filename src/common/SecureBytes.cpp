#include "camera_firmware/common/SecureBytes.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include <openssl/crypto.h>

namespace camera_firmware::common {

namespace {

bool CleanseAndVerify(unsigned char* data, std::size_t size) noexcept {
  if (data == nullptr || size == 0U) {
    return true;
  }

  OPENSSL_cleanse(data, size);
  return std::all_of(data, data + size,
                     [](unsigned char byte) { return byte == 0U; });
}

void CleanseReplacement(std::vector<unsigned char>& replacement) noexcept {
  (void)CleanseAndVerify(replacement.data(), replacement.size());
}

}  // namespace

SecureBytes::~SecureBytes() { clear(); }

SecureBytes::SecureBytes(SecureBytes&& other) noexcept
    : bytes_(std::move(other.bytes_)),
      zeroize_count_(std::exchange(other.zeroize_count_, 0U)),
      last_zeroize_verified_(
          std::exchange(other.last_zeroize_verified_, true)) {}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept {
  if (this == &other) {
    return *this;
  }

  const bool cleansed_destination = !bytes_.empty();
  clear();
  bytes_ = std::move(other.bytes_);
  const std::size_t source_zeroize_count =
      std::exchange(other.zeroize_count_, 0U);
  const bool source_last_zeroize_verified =
      std::exchange(other.last_zeroize_verified_, true);
  zeroize_count_ += source_zeroize_count;
  if (!cleansed_destination && source_zeroize_count != 0U) {
    last_zeroize_verified_ = source_last_zeroize_verified;
  }
  return *this;
}

void SecureBytes::assign(const unsigned char* data, std::size_t size) {
  std::vector<unsigned char> replacement;
  try {
    replacement.resize(size);
    if (size != 0U) {
      std::copy_n(data, size, replacement.data());
    }
  } catch (...) {
    CleanseReplacement(replacement);
    throw;
  }

  cleanse_owned_bytes();
  bytes_.swap(replacement);
}

void SecureBytes::resize(std::size_t size) {
  std::vector<unsigned char> replacement;
  try {
    replacement.resize(size);
    const std::size_t retained_size = std::min(bytes_.size(), size);
    if (retained_size != 0U) {
      std::copy_n(bytes_.data(), retained_size, replacement.data());
    }
  } catch (...) {
    CleanseReplacement(replacement);
    throw;
  }

  cleanse_owned_bytes();
  bytes_.swap(replacement);
}

void SecureBytes::append(const unsigned char* data, std::size_t size) {
  std::vector<unsigned char> replacement;
  const std::size_t existing_size = bytes_.size();
  if (size > replacement.max_size() - existing_size) {
    throw std::length_error("SecureBytes append exceeds maximum size");
  }

  try {
    replacement.resize(existing_size + size);
    if (existing_size != 0U) {
      std::copy_n(bytes_.data(), existing_size, replacement.data());
    }
    if (size != 0U) {
      std::copy_n(data, size, replacement.data() + existing_size);
    }
  } catch (...) {
    CleanseReplacement(replacement);
    throw;
  }

  cleanse_owned_bytes();
  bytes_.swap(replacement);
}

void SecureBytes::cleanse_owned_bytes() noexcept {
  if (bytes_.empty()) {
    return;
  }

  last_zeroize_verified_ = CleanseAndVerify(bytes_.data(), bytes_.size());
  ++zeroize_count_;
}

void SecureBytes::clear() noexcept {
  cleanse_owned_bytes();
  std::vector<unsigned char>().swap(bytes_);
}

unsigned char* SecureBytes::data() noexcept {
  return bytes_.data();
}

const unsigned char* SecureBytes::data() const noexcept {
  return bytes_.data();
}

std::size_t SecureBytes::size() const noexcept { return bytes_.size(); }

ZeroizeAudit SecureBytes::zeroize_audit() const noexcept {
  return {zeroize_count_, last_zeroize_verified_};
}

std::size_t SecureBytes::zeroize_count_for_test() const noexcept {
  return zeroize_count_;
}

}  // namespace camera_firmware::common
