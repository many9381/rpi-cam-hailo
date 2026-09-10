#pragma once

#include <array>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <gtest/gtest.h>

#include <stdlib.h>

namespace camera_firmware::integrity::testing {

using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using MdContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 50U> pattern{"/tmp/camera-firmware-integrity-XXXXXX"};
    char* created = ::mkdtemp(pattern.data());
    if (created == nullptr) {
      throw std::system_error(errno, std::generic_category(), "mkdtemp");
    }
    path_ = created;
  }

  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept {
    return path_;
  }

 private:
  std::filesystem::path path_;
};

inline void WriteFile(const std::filesystem::path& path,
                      std::string_view data) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  ASSERT_TRUE(output.is_open());
  output.write(data.data(), static_cast<std::streamsize>(data.size()));
  ASSERT_TRUE(output.good());
}

inline void AppendFile(const std::filesystem::path& path,
                       std::string_view data) {
  std::ofstream output(path, std::ios::binary | std::ios::app);
  ASSERT_TRUE(output.is_open());
  output.write(data.data(), static_cast<std::streamsize>(data.size()));
  ASSERT_TRUE(output.good());
}

inline std::string ReadBio(BIO* bio) {
  char* data = nullptr;
  const long length = BIO_get_mem_data(bio, &data);
  EXPECT_GT(length, 0L);
  return {data, static_cast<std::size_t>(length)};
}

class EphemeralEd25519Key {
 public:
  EphemeralEd25519Key()
      : key_(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free) {
    if (!key_) {
      throw std::runtime_error("EVP_PKEY_Q_keygen");
    }
  }

  [[nodiscard]] std::string PublicPem() const {
    BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_PUBKEY(bio.get(), key_.get()) != 1) {
      throw std::runtime_error("PEM_write_bio_PUBKEY");
    }
    return ReadBio(bio.get());
  }

  [[nodiscard]] EVP_PKEY* key() const noexcept { return key_.get(); }

  [[nodiscard]] std::array<unsigned char, 64U> Sign(
      std::string_view data) const {
    MdContextPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    std::array<unsigned char, 64U> signature{};
    std::size_t size = signature.size();
    if (!context ||
        EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr,
                           key_.get()) != 1 ||
        EVP_DigestSign(context.get(), signature.data(), &size,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.size()) != 1 ||
        size != signature.size()) {
      throw std::runtime_error("EVP_DigestSign");
    }
    return signature;
  }

 private:
  KeyPtr key_{nullptr, EVP_PKEY_free};
};

class EphemeralEcKey {
 public:
  EphemeralEcKey()
      : key_(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"),
             EVP_PKEY_free) {
    if (!key_) {
      throw std::runtime_error("EVP_PKEY_Q_keygen");
    }
  }

  [[nodiscard]] std::string PublicPem() const {
    BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_PUBKEY(bio.get(), key_.get()) != 1) {
      throw std::runtime_error("PEM_write_bio_PUBKEY");
    }
    return ReadBio(bio.get());
  }

  [[nodiscard]] EVP_PKEY* key() const noexcept { return key_.get(); }

 private:
  KeyPtr key_{nullptr, EVP_PKEY_free};
};

}  // namespace camera_firmware::integrity::testing
