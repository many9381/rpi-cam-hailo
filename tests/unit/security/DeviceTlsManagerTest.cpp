#include "camera_firmware/security/DeviceTlsManager.hpp"

#include <algorithm>
#include <array>
#include <barrier>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

extern "C" int __real_fstat(int descriptor, struct stat* status);
extern "C" int __real_close(int descriptor);
extern "C" int __real_fsync(int descriptor);
extern "C" int __real_camera_firmware_tls_rename_noreplace(
    int old_directory,
    const char* old_name,
    int new_directory,
    const char* new_name);

namespace {

std::optional<ino_t> spoofed_owner_inode;
int interrupted_close_descriptor{-1};
int interrupted_close_calls{0};
bool fail_rename_noreplace{false};
bool interrupt_cleanup_fsync{false};
std::array<int, 2> interrupted_fsync_descriptors{-1, -1};
std::array<int, 2> interrupted_fsync_calls{0, 0};

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 40> pattern{"/tmp/cf-device-tls-XXXXXX"};
    char* created = ::mkdtemp(pattern.data());
    if (created == nullptr) {
      throw std::system_error(errno, std::generic_category(), "mkdtemp");
    }
    path_ = created;
  }

  ~TemporaryDirectory() {
    spoofed_owner_inode.reset();
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

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

camera_firmware::config::HttpTlsConfig DevelopmentTls() {
  camera_firmware::config::HttpTlsConfig tls;
  tls.enabled = true;
  tls.allow_development_self_signed_tls = true;
  return tls;
}

camera_firmware::config::HttpTlsConfig ProductionTls() {
  camera_firmware::config::HttpTlsConfig tls;
  tls.enabled = true;
  return tls;
}

mode_t FileMode(const std::filesystem::path& path) {
  struct stat status {};
  if (::stat(path.c_str(), &status) != 0) {
    throw std::system_error(errno, std::generic_category(), "stat");
  }
  return status.st_mode & 0777;
}

struct stat FileStatus(const std::filesystem::path& path) {
  struct stat status {};
  if (::stat(path.c_str(), &status) != 0) {
    throw std::system_error(errno, std::generic_category(), "stat");
  }
  return status;
}

std::filesystem::path LiveCertificate(const TemporaryDirectory& state) {
  return state.path() / "device-tls" / "certificate.pem";
}

std::filesystem::path LivePrivateKey(const TemporaryDirectory& state) {
  return state.path() / "device-tls" / "private-key.pem";
}

X509Ptr LoadCertificate(const std::filesystem::path& path) {
  BioPtr bio(BIO_new_file(path.c_str(), "r"), BIO_free);
  if (!bio) {
    return {nullptr, X509_free};
  }
  return {PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free};
}

KeyPtr LoadPrivateKey(const std::filesystem::path& path) {
  BioPtr bio(BIO_new_file(path.c_str(), "r"), BIO_free);
  if (!bio) {
    return {nullptr, EVP_PKEY_free};
  }
  return {PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr),
          EVP_PKEY_free};
}

std::vector<unsigned char> CertificateFingerprint(
    const std::filesystem::path& path) {
  auto certificate = LoadCertificate(path);
  if (!certificate) {
    return {};
  }
  std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
  unsigned int size = 0;
  if (X509_digest(certificate.get(), EVP_sha256(), digest.data(), &size) != 1) {
    return {};
  }
  digest.resize(size);
  return digest;
}

void RewriteCertificateAsExpired(
    const camera_firmware::security::ResolvedTlsMaterial& material) {
  auto certificate = LoadCertificate(material.certificate_path);
  auto private_key = LoadPrivateKey(material.private_key_path);
  ASSERT_TRUE(certificate);
  ASSERT_TRUE(private_key);
  ASSERT_NE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -7200),
            nullptr);
  ASSERT_NE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), -3600),
            nullptr);
  ASSERT_GT(X509_sign(certificate.get(), private_key.get(), EVP_sha256()), 0);

  BIO* output = BIO_new_file(material.certificate_path.c_str(), "w");
  ASSERT_NE(output, nullptr);
  ASSERT_EQ(PEM_write_bio_X509(output, certificate.get()), 1);
  ASSERT_EQ(BIO_free(output), 1);
  ASSERT_EQ(::chmod(material.certificate_path.c_str(), 0644), 0);
}

void RemoveCertificateExtensions(X509* certificate, int nid) {
  int index = -1;
  while ((index = X509_get_ext_by_NID(certificate, nid, -1)) >= 0) {
    X509_EXTENSION* extension = X509_delete_ext(certificate, index);
    X509_EXTENSION_free(extension);
  }
}

void AddCertificateExtension(X509* certificate, int nid, const char* value) {
  X509V3_CTX context;
  X509V3_set_ctx_nodb(&context);
  X509V3_set_ctx(&context, certificate, certificate, nullptr, nullptr, 0);
  X509_EXTENSION* extension =
      X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char*>(value));
  ASSERT_NE(extension, nullptr);
  ASSERT_EQ(X509_add_ext(certificate, extension, -1), 1);
  X509_EXTENSION_free(extension);
}

void RewriteGeneratedCertificate(
    const TemporaryDirectory& state,
    const std::function<void(X509*)>& alter,
    const EVP_MD* digest = EVP_sha256()) {
  auto certificate = LoadCertificate(LiveCertificate(state));
  auto private_key = LoadPrivateKey(LivePrivateKey(state));
  ASSERT_TRUE(certificate);
  ASSERT_TRUE(private_key);
  alter(certificate.get());
  ASSERT_GT(X509_sign(certificate.get(), private_key.get(), digest), 0);
  BioPtr output(BIO_new_file(LiveCertificate(state).c_str(), "w"), BIO_free);
  ASSERT_TRUE(output);
  ASSERT_EQ(PEM_write_bio_X509(output.get(), certificate.get()), 1);
  ASSERT_EQ(::chmod(LiveCertificate(state).c_str(), 0644), 0);
}

std::vector<std::filesystem::path> TemporaryIdentityEntries(
    const std::filesystem::path& state_directory) {
  std::vector<std::filesystem::path> entries;
  for (const auto& entry :
       std::filesystem::directory_iterator(state_directory)) {
    if (entry.path().filename().string().starts_with(".device-tls.tmp-")) {
      entries.push_back(entry.path());
    }
  }
  return entries;
}

std::filesystem::path CreateStaleTemporaryIdentity(
    const TemporaryDirectory& state,
    const TemporaryDirectory& source,
    std::string_view suffix,
    bool include_certificate,
    bool include_private_key) {
  const auto temporary =
      state.path() / (std::string(".device-tls.tmp-") + std::string(suffix));
  std::filesystem::create_directory(temporary);
  if (::chmod(temporary.c_str(), 0700) != 0) {
    throw std::system_error(errno, std::generic_category(), "chmod temp");
  }
  if (include_certificate) {
    std::filesystem::copy_file(LiveCertificate(source),
                               temporary / "certificate.pem");
    if (::chmod((temporary / "certificate.pem").c_str(), 0644) != 0) {
      throw std::system_error(errno, std::generic_category(), "chmod cert");
    }
  }
  if (include_private_key) {
    std::filesystem::copy_file(LivePrivateKey(source),
                               temporary / "private-key.pem");
    if (::chmod((temporary / "private-key.pem").c_str(), 0600) != 0) {
      throw std::system_error(errno, std::generic_category(), "chmod key");
    }
  }
  return temporary;
}

TEST(DeviceTlsManagerTest, ProductionMissingOrIncompletePairFailsClosed) {
  TemporaryDirectory state;
  auto missing = camera_firmware::security::ResolveTlsMaterial(
      ProductionTls(), state.path());
  ASSERT_FALSE(missing.ok());
  EXPECT_EQ(missing.error().code, "E_HTTP_TLS_REQUIRED");

  auto incomplete_tls = DevelopmentTls();
  incomplete_tls.certificate_path = "/configured/certificate.pem";
  auto incomplete = camera_firmware::security::ResolveTlsMaterial(
      incomplete_tls, state.path());
  ASSERT_FALSE(incomplete.ok());
  EXPECT_EQ(incomplete.error().code, "E_HTTP_TLS_REQUIRED");

  auto disabled_tls = ProductionTls();
  disabled_tls.enabled = false;
  auto disabled = camera_firmware::security::ResolveTlsMaterial(
      disabled_tls, state.path());
  ASSERT_FALSE(disabled.ok());
  EXPECT_EQ(disabled.error().code, "E_HTTP_TLS_REQUIRED");
}

TEST(DeviceTlsManagerTest, GeneratesAndReusesProtectedDevelopmentIdentity) {
  TemporaryDirectory state;
  auto first = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), state.path());
  ASSERT_TRUE(first.ok()) << first.error().message;
  ASSERT_TRUE(first.value().generated_for_development);
  EXPECT_EQ(FileMode(first.value().private_key_path), 0600);
  EXPECT_EQ(FileMode(first.value().certificate_path), 0644);
  EXPECT_EQ(FileStatus(first.value().private_key_path).st_uid, ::geteuid());
  EXPECT_EQ(FileStatus(first.value().certificate_path).st_uid, ::geteuid());
  const auto fingerprint =
      CertificateFingerprint(first.value().certificate_path);
  ASSERT_FALSE(fingerprint.empty());

  auto second = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), state.path());
  ASSERT_TRUE(second.ok()) << second.error().message;
  EXPECT_TRUE(second.value().generated_for_development);
  EXPECT_EQ(CertificateFingerprint(second.value().certificate_path),
            fingerprint);
  EXPECT_TRUE(first.value().certificate_path.string().starts_with(
      "/proc/self/fd/"));
  EXPECT_TRUE(first.value().private_key_path.string().starts_with(
      "/proc/self/fd/"));
}

TEST(DeviceTlsManagerTest, ConstructsProcPathsBeforeMovingDescriptorOwner) {
  std::ifstream input(std::filesystem::path(CF_SOURCE_DIR) /
                      "src/security/DeviceTlsManager.cpp");
  ASSERT_TRUE(input.is_open());
  const std::string source((std::istreambuf_iterator<char>(input)),
                           std::istreambuf_iterator<char>());

  const auto finalize = source.find("const auto finalize =");
  ASSERT_NE(finalize, std::string::npos);
  const auto certificate_path =
      source.find("const auto certificate_path =", finalize);
  const auto private_key_path =
      source.find("const auto private_key_path =", finalize);
  const auto owner_move = source.find("std::move(handles)", finalize);

  ASSERT_NE(certificate_path, std::string::npos);
  ASSERT_NE(private_key_path, std::string::npos);
  ASSERT_NE(owner_move, std::string::npos);
  EXPECT_LT(certificate_path, owner_move);
  EXPECT_LT(private_key_path, owner_move);
}

TEST(DeviceTlsManagerTest, ConfiguredIdentityRequiresProtectedMetadata) {
  TemporaryDirectory state;
  auto generated = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), state.path());
  ASSERT_TRUE(generated.ok()) << generated.error().message;

  auto configured_tls = ProductionTls();
  configured_tls.certificate_path = LiveCertificate(state).string();
  configured_tls.private_key_path = LivePrivateKey(state).string();
  auto configured = camera_firmware::security::ResolveTlsMaterial(
      configured_tls, {});
  ASSERT_TRUE(configured.ok()) << configured.error().message;
  EXPECT_FALSE(configured.value().generated_for_development);

  ASSERT_EQ(::chmod(LivePrivateKey(state).c_str(), 0400), 0);
  auto narrow_key_mode = camera_firmware::security::ResolveTlsMaterial(
      configured_tls, {});
  ASSERT_FALSE(narrow_key_mode.ok());
  EXPECT_EQ(narrow_key_mode.error().code, "E_HTTP_TLS_IDENTITY");
  ASSERT_EQ(::chmod(LivePrivateKey(state).c_str(), 0600), 0);

  ASSERT_EQ(::chmod(LiveCertificate(state).c_str(), 0664), 0);
  auto broad_certificate_mode = camera_firmware::security::ResolveTlsMaterial(
      configured_tls, {});
  ASSERT_FALSE(broad_certificate_mode.ok());
  EXPECT_EQ(broad_certificate_mode.error().code, "E_HTTP_TLS_IDENTITY");
  ASSERT_EQ(::chmod(LiveCertificate(state).c_str(), 0644), 0);

  spoofed_owner_inode = FileStatus(LivePrivateKey(state)).st_ino;
  auto wrong_owner = camera_firmware::security::ResolveTlsMaterial(
      configured_tls, {});
  spoofed_owner_inode.reset();
  ASSERT_FALSE(wrong_owner.ok());
  EXPECT_EQ(wrong_owner.error().code, "E_HTTP_TLS_IDENTITY");
}

TEST(DeviceTlsManagerTest, ResolvedMaterialRemainsBoundAfterLivePathReplacement) {
  TemporaryDirectory generated_state;
  TemporaryDirectory replacement_state;
  auto generated = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), generated_state.path());
  auto replacement = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), replacement_state.path());
  ASSERT_TRUE(generated.ok()) << generated.error().message;
  ASSERT_TRUE(replacement.ok()) << replacement.error().message;
  const int certificate_descriptor =
      std::stoi(generated.value().certificate_path.filename().string());
  const int private_key_descriptor =
      std::stoi(generated.value().private_key_path.filename().string());
  EXPECT_EQ(::lseek(certificate_descriptor, 0, SEEK_CUR), 0);
  EXPECT_EQ(::lseek(private_key_descriptor, 0, SEEK_CUR), 0);
  const auto generated_fingerprint =
      CertificateFingerprint(generated.value().certificate_path);
  const auto replacement_fingerprint =
      CertificateFingerprint(replacement.value().certificate_path);
  ASSERT_NE(generated_fingerprint, replacement_fingerprint);

  std::filesystem::rename(generated_state.path() / "device-tls",
                          generated_state.path() / "validated-device-tls");
  std::filesystem::rename(replacement_state.path() / "device-tls",
                          generated_state.path() / "device-tls");

  EXPECT_EQ(CertificateFingerprint(generated.value().certificate_path),
            generated_fingerprint);

  auto configured_tls = ProductionTls();
  configured_tls.certificate_path =
      (generated_state.path() / "validated-device-tls" / "certificate.pem")
          .string();
  configured_tls.private_key_path =
      (generated_state.path() / "validated-device-tls" / "private-key.pem")
          .string();
  auto configured = camera_firmware::security::ResolveTlsMaterial(
      configured_tls, {});
  ASSERT_TRUE(configured.ok()) << configured.error().message;
  std::filesystem::rename(generated_state.path() / "validated-device-tls",
                          replacement_state.path() / "configured-original");

  EXPECT_EQ(CertificateFingerprint(configured.value().certificate_path),
            generated_fingerprint);
}

TEST(DeviceTlsManagerTest, InterruptedLinuxCloseIsNeverRetried) {
  TemporaryDirectory state;
  {
    auto resolved = camera_firmware::security::ResolveTlsMaterial(
        DevelopmentTls(), state.path());
    ASSERT_TRUE(resolved.ok()) << resolved.error().message;
    interrupted_close_descriptor =
        std::stoi(resolved.value().certificate_path.filename().string());
    interrupted_close_calls = 0;
  }

  EXPECT_EQ(interrupted_close_calls, 1);
  interrupted_close_descriptor = -1;
}

TEST(DeviceTlsManagerTest, GeneratedIdentityUsesEcP256MatchingKeyAndDeviceSans) {
  TemporaryDirectory state;
  auto resolved = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), state.path());
  ASSERT_TRUE(resolved.ok()) << resolved.error().message;

  auto certificate = LoadCertificate(resolved.value().certificate_path);
  auto private_key = LoadPrivateKey(resolved.value().private_key_path);
  ASSERT_TRUE(certificate);
  ASSERT_TRUE(private_key);
  EXPECT_TRUE(EVP_PKEY_is_a(private_key.get(), "EC"));
  std::array<char, 80> group_name{};
  std::size_t group_name_length = 0;
  ASSERT_EQ(EVP_PKEY_get_group_name(private_key.get(), group_name.data(),
                                    group_name.size(), &group_name_length),
            1);
  EXPECT_EQ(std::string(group_name.data()), "prime256v1");
  EXPECT_EQ(X509_check_private_key(certificate.get(), private_key.get()), 1);
  EXPECT_EQ(X509_check_host(certificate.get(), "localhost", 0, 0, nullptr), 1);
  EXPECT_EQ(X509_check_host(certificate.get(), "camera.local", 0, 0, nullptr),
            1);
  EXPECT_EQ(X509_check_ip_asc(certificate.get(), "127.0.0.1", 0), 1);
  EXPECT_EQ(X509_check_ip_asc(certificate.get(), "::1", 0), 1);
}

TEST(DeviceTlsManagerTest, RejectsGeneratedIdentityWithWrongModeOrOwner) {
  TemporaryDirectory mode_state;
  auto mode_material = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), mode_state.path());
  ASSERT_TRUE(mode_material.ok()) << mode_material.error().message;
  ASSERT_EQ(::chmod(LivePrivateKey(mode_state).c_str(), 0640), 0);
  auto wrong_mode = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), mode_state.path());
  ASSERT_FALSE(wrong_mode.ok());
  EXPECT_EQ(wrong_mode.error().code, "E_HTTP_TLS_IDENTITY");

  TemporaryDirectory owner_state;
  auto owner_material = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), owner_state.path());
  ASSERT_TRUE(owner_material.ok()) << owner_material.error().message;
  spoofed_owner_inode = FileStatus(LivePrivateKey(owner_state)).st_ino;
  auto wrong_owner = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), owner_state.path());
  spoofed_owner_inode.reset();
  ASSERT_FALSE(wrong_owner.ok());
  EXPECT_EQ(wrong_owner.error().code, "E_HTTP_TLS_IDENTITY");
}

TEST(DeviceTlsManagerTest, RejectsSymlinkWrongTypeAndMalformedGeneratedFiles) {
  TemporaryDirectory symlink_state;
  auto symlink_material = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), symlink_state.path());
  ASSERT_TRUE(symlink_material.ok()) << symlink_material.error().message;
  ASSERT_TRUE(std::filesystem::remove(LivePrivateKey(symlink_state)));
  ASSERT_EQ(::symlink(LiveCertificate(symlink_state).c_str(),
                      LivePrivateKey(symlink_state).c_str()),
            0);
  auto symlinked = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), symlink_state.path());
  ASSERT_FALSE(symlinked.ok());
  EXPECT_EQ(symlinked.error().code, "E_HTTP_TLS_IDENTITY");

  TemporaryDirectory type_state;
  auto type_material = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), type_state.path());
  ASSERT_TRUE(type_material.ok()) << type_material.error().message;
  ASSERT_TRUE(std::filesystem::remove(LiveCertificate(type_state)));
  ASSERT_TRUE(std::filesystem::create_directory(LiveCertificate(type_state)));
  auto wrong_type = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), type_state.path());
  ASSERT_FALSE(wrong_type.ok());
  EXPECT_EQ(wrong_type.error().code, "E_HTTP_TLS_IDENTITY");

  TemporaryDirectory malformed_state;
  auto malformed_material = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), malformed_state.path());
  ASSERT_TRUE(malformed_material.ok()) << malformed_material.error().message;
  const int descriptor = ::open(LiveCertificate(malformed_state).c_str(),
                                O_WRONLY | O_TRUNC | O_CLOEXEC);
  ASSERT_GE(descriptor, 0);
  constexpr std::string_view malformed = "not a certificate\n";
  ASSERT_EQ(::write(descriptor, malformed.data(), malformed.size()),
            static_cast<ssize_t>(malformed.size()));
  ASSERT_EQ(::close(descriptor), 0);
  auto rejected = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), malformed_state.path());
  ASSERT_FALSE(rejected.ok());
  EXPECT_EQ(rejected.error().code, "E_HTTP_TLS_IDENTITY");
  EXPECT_TRUE(TemporaryIdentityEntries(malformed_state.path()).empty());
}

TEST(DeviceTlsManagerTest, RejectsMismatchedAndExpiredGeneratedPairs) {
  TemporaryDirectory first_state;
  TemporaryDirectory second_state;
  auto first = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), first_state.path());
  auto second = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), second_state.path());
  ASSERT_TRUE(first.ok()) << first.error().message;
  ASSERT_TRUE(second.ok()) << second.error().message;
  std::filesystem::copy_file(LivePrivateKey(second_state),
                             LivePrivateKey(first_state),
                             std::filesystem::copy_options::overwrite_existing);
  ASSERT_EQ(::chmod(LivePrivateKey(first_state).c_str(), 0600), 0);
  auto mismatched = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), first_state.path());
  ASSERT_FALSE(mismatched.ok());
  EXPECT_EQ(mismatched.error().code, "E_HTTP_TLS_IDENTITY");

  TemporaryDirectory expired_state;
  auto expired_material = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), expired_state.path());
  ASSERT_TRUE(expired_material.ok()) << expired_material.error().message;
  RewriteCertificateAsExpired(expired_material.value());
  auto expired = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), expired_state.path());
  ASSERT_FALSE(expired.ok());
  EXPECT_EQ(expired.error().code, "E_HTTP_TLS_IDENTITY");
}

TEST(DeviceTlsManagerTest, RejectsAlteredGeneratedCertificateProfile) {
  struct Alteration {
    const char* name;
    std::function<void(X509*)> alter;
    const EVP_MD* digest;
  };
  const std::vector<Alteration> alterations{
      {"not X509v3", [](X509* certificate) {
         while (X509_get_ext_count(certificate) > 0) {
           X509_EXTENSION* extension = X509_delete_ext(certificate, 0);
           X509_EXTENSION_free(extension);
         }
         ASSERT_EQ(X509_set_version(certificate, 1), 1);
       }, EVP_sha256()},
      {"not SHA-256", [](X509*) {}, EVP_sha384()},
      {"CA true", [](X509* certificate) {
         RemoveCertificateExtensions(certificate, NID_basic_constraints);
         AddCertificateExtension(certificate, NID_basic_constraints,
                                 "critical,CA:TRUE");
       }, EVP_sha256()},
      {"wrong key usage", [](X509* certificate) {
         RemoveCertificateExtensions(certificate, NID_key_usage);
         AddCertificateExtension(certificate, NID_key_usage,
                                 "critical,keyEncipherment");
       }, EVP_sha256()},
      {"wrong extended key usage", [](X509* certificate) {
         RemoveCertificateExtensions(certificate, NID_ext_key_usage);
         AddCertificateExtension(certificate, NID_ext_key_usage,
                                 "clientAuth");
       }, EVP_sha256()},
      {"non-exact SAN set", [](X509* certificate) {
         RemoveCertificateExtensions(certificate, NID_subject_alt_name);
         AddCertificateExtension(
             certificate, NID_subject_alt_name,
             "DNS:localhost,DNS:camera.local,DNS:unexpected.local,"
             "IP:127.0.0.1,IP:::1");
       }, EVP_sha256()},
      {"overlong validity", [](X509* certificate) {
         ASSERT_NE(X509_gmtime_adj(X509_getm_notBefore(certificate), -300),
                   nullptr);
         ASSERT_NE(X509_gmtime_adj(X509_getm_notAfter(certificate),
                                   6L * 365L * 24L * 60L * 60L),
                   nullptr);
       }, EVP_sha256()},
      {"extra noncritical extension", [](X509* certificate) {
         AddCertificateExtension(certificate, NID_netscape_comment,
                                 "unexpected");
       }, EVP_sha256()},
      {"extra critical extension", [](X509* certificate) {
         AddCertificateExtension(certificate, NID_netscape_comment,
                                 "critical,unexpected");
       }, EVP_sha256()},
  };

  for (const auto& alteration : alterations) {
    SCOPED_TRACE(alteration.name);
    TemporaryDirectory state;
    auto generated = camera_firmware::security::ResolveTlsMaterial(
        DevelopmentTls(), state.path());
    ASSERT_TRUE(generated.ok()) << generated.error().message;
    RewriteGeneratedCertificate(state, alteration.alter, alteration.digest);
    if (std::string_view(alteration.name) == "not X509v3") {
      auto rewritten = LoadCertificate(LiveCertificate(state));
      ASSERT_TRUE(rewritten);
      ASSERT_EQ(X509_get_version(rewritten.get()), 1);
    }

    auto reused = camera_firmware::security::ResolveTlsMaterial(
        DevelopmentTls(), state.path());

    ASSERT_FALSE(reused.ok());
    EXPECT_EQ(reused.error().code, "E_HTTP_TLS_IDENTITY");
  }
}

TEST(DeviceTlsManagerTest, ConcurrentGenerationPublishesOneReusableIdentity) {
  TemporaryDirectory state;
  constexpr std::size_t kCallers = 8;
  std::barrier start(static_cast<std::ptrdiff_t>(kCallers));
  std::vector<std::future<std::vector<unsigned char>>> calls;
  calls.reserve(kCallers);
  for (std::size_t index = 0; index < kCallers; ++index) {
    calls.push_back(std::async(std::launch::async, [&] {
      start.arrive_and_wait();
      auto result = camera_firmware::security::ResolveTlsMaterial(
          DevelopmentTls(), state.path());
      if (!result.ok()) {
        return std::vector<unsigned char>{};
      }
      return CertificateFingerprint(result.value().certificate_path);
    }));
  }

  std::vector<unsigned char> winner;
  for (auto& call : calls) {
    auto fingerprint = call.get();
    ASSERT_FALSE(fingerprint.empty());
    if (winner.empty()) {
      winner = fingerprint;
    }
    EXPECT_EQ(fingerprint, winner);
  }
  EXPECT_TRUE(TemporaryIdentityEntries(state.path()).empty());
}

TEST(DeviceTlsManagerTest, ForkedGeneratorsReuseOneStableIdentity) {
  TemporaryDirectory state;
  constexpr std::size_t kProcesses = 4U;
  struct ChildResult {
    int ok{0};
    std::array<unsigned char, 32> fingerprint{};
  };
  int start_pipe[2]{};
  int result_pipe[2]{};
  ASSERT_EQ(::pipe2(start_pipe, O_CLOEXEC), 0);
  ASSERT_EQ(::pipe2(result_pipe, O_CLOEXEC), 0);
  std::array<pid_t, kProcesses> children{};
  for (std::size_t index = 0; index < kProcesses; ++index) {
    children[index] = ::fork();
    ASSERT_GE(children[index], 0);
    if (children[index] == 0) {
      (void)::close(start_pipe[1]);
      (void)::close(result_pipe[0]);
      unsigned char start = 0;
      ChildResult child_result;
      if (::read(start_pipe[0], &start, 1U) == 1) {
        auto resolved = camera_firmware::security::ResolveTlsMaterial(
            DevelopmentTls(), state.path());
        if (resolved.ok()) {
          const auto fingerprint =
              CertificateFingerprint(resolved.value().certificate_path);
          if (fingerprint.size() == child_result.fingerprint.size()) {
            child_result.ok = 1;
            std::copy(fingerprint.begin(), fingerprint.end(),
                      child_result.fingerprint.begin());
          }
        }
      }
      (void)::write(result_pipe[1], &child_result, sizeof(child_result));
      _exit(child_result.ok == 1 ? 0 : 1);
    }
  }
  ASSERT_EQ(::close(start_pipe[0]), 0);
  ASSERT_EQ(::close(result_pipe[1]), 0);
  std::array<unsigned char, kProcesses> starts{};
  ASSERT_EQ(::write(start_pipe[1], starts.data(), starts.size()),
            static_cast<ssize_t>(starts.size()));
  ASSERT_EQ(::close(start_pipe[1]), 0);

  std::optional<std::array<unsigned char, 32>> winner;
  for (std::size_t index = 0; index < kProcesses; ++index) {
    ChildResult child_result;
    ASSERT_EQ(::read(result_pipe[0], &child_result, sizeof(child_result)),
              static_cast<ssize_t>(sizeof(child_result)));
    ASSERT_EQ(child_result.ok, 1);
    if (!winner.has_value()) {
      winner = child_result.fingerprint;
    }
    EXPECT_EQ(child_result.fingerprint, *winner);
  }
  ASSERT_EQ(::close(result_pipe[0]), 0);
  for (pid_t child : children) {
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
  }
  EXPECT_TRUE(TemporaryIdentityEntries(state.path()).empty());
}

TEST(DeviceTlsManagerTest, UnsupportedAtomicRenameFailsClosedWithoutResidue) {
  TemporaryDirectory state;
  fail_rename_noreplace = true;

  auto result = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), state.path());

  fail_rename_noreplace = false;
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_HTTP_TLS_DURABILITY");
  EXPECT_FALSE(std::filesystem::exists(state.path() / "device-tls"));
  EXPECT_TRUE(TemporaryIdentityEntries(state.path()).empty());
}

TEST(DeviceTlsManagerTest, RestartScavengesCompleteAndPrivateOnlyStaleTemps) {
  TemporaryDirectory source;
  auto source_material = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), source.path());
  ASSERT_TRUE(source_material.ok()) << source_material.error().message;

  TemporaryDirectory fresh_state;
  const auto complete = CreateStaleTemporaryIdentity(
      fresh_state, source, "00112233445566778899aabb", true, true);
  auto generated = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), fresh_state.path());
  ASSERT_TRUE(generated.ok()) << generated.error().message;
  EXPECT_FALSE(std::filesystem::exists(complete));

  const auto private_only = CreateStaleTemporaryIdentity(
      fresh_state, source, "ffeeddccbbaa998877665544", false, true);
  auto reused = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), fresh_state.path());
  ASSERT_TRUE(reused.ok()) << reused.error().message;
  EXPECT_FALSE(std::filesystem::exists(private_only));
  EXPECT_TRUE(TemporaryIdentityEntries(fresh_state.path()).empty());
}

TEST(DeviceTlsManagerTest, RetriesInterruptedStaleCleanupDirectoryAndParentSyncs) {
  TemporaryDirectory state;
  auto generated = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), state.path());
  ASSERT_TRUE(generated.ok()) << generated.error().message;
  const auto stale = CreateStaleTemporaryIdentity(
      state, state, "1234567890abcdef12345678", true, true);

  interrupted_fsync_descriptors.fill(-1);
  interrupted_fsync_calls.fill(0);
  interrupted_close_descriptor = -1;
  interrupted_close_calls = 0;
  interrupt_cleanup_fsync = true;
  auto reused = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), state.path());
  interrupt_cleanup_fsync = false;

  ASSERT_TRUE(reused.ok()) << reused.error().message;
  EXPECT_FALSE(std::filesystem::exists(stale));
  EXPECT_EQ(interrupted_fsync_calls[0], 2);
  EXPECT_EQ(interrupted_fsync_calls[1], 2);
  EXPECT_NE(interrupted_fsync_descriptors[0],
            interrupted_fsync_descriptors[1]);
  EXPECT_EQ(interrupted_close_calls, 0);
}

TEST(DeviceTlsManagerTest, UnsafeStaleTemporaryIdentityFailsClosed) {
  TemporaryDirectory source;
  auto source_material = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), source.path());
  ASSERT_TRUE(source_material.ok()) << source_material.error().message;

  TemporaryDirectory state;
  const auto unsafe = state.path() /
                      ".device-tls.tmp-0123456789abcdef01234567";
  ASSERT_TRUE(std::filesystem::create_directory(unsafe));
  ASSERT_EQ(::chmod(unsafe.c_str(), 0700), 0);
  ASSERT_EQ(::symlink(LivePrivateKey(source).c_str(),
                      (unsafe / "private-key.pem").c_str()),
            0);

  auto result = camera_firmware::security::ResolveTlsMaterial(
      DevelopmentTls(), state.path());

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_HTTP_TLS_IDENTITY");
  EXPECT_TRUE(std::filesystem::is_symlink(unsafe / "private-key.pem"));
}

TEST(DeviceTlsManagerTest, PublicationFailureRemovesWrittenTemporaryIdentity) {
  TemporaryDirectory state;
  const int notifications = ::inotify_init1(IN_CLOEXEC);
  ASSERT_GE(notifications, 0);
  ASSERT_GE(::inotify_add_watch(notifications, state.path().c_str(), IN_CREATE),
            0);

  auto generation = std::async(std::launch::async, [&] {
    return camera_firmware::security::ResolveTlsMaterial(DevelopmentTls(),
                                                         state.path());
  });

  struct pollfd notification_poll {
    notifications, POLLIN, 0
  };
  ASSERT_EQ(::poll(&notification_poll, 1, 2000), 1);
  std::array<char, 4096> events{};
  const ssize_t event_bytes = ::read(notifications, events.data(), events.size());
  ASSERT_GT(event_bytes, 0);
  bool saw_temporary_directory = false;
  for (std::size_t offset = 0;
       offset < static_cast<std::size_t>(event_bytes);) {
    const auto* event =
        reinterpret_cast<const struct inotify_event*>(events.data() + offset);
    if (event->len != 0U &&
        std::string_view(event->name).starts_with(".device-tls.tmp-")) {
      saw_temporary_directory = true;
      break;
    }
    offset += sizeof(struct inotify_event) + event->len;
  }
  ASSERT_TRUE(saw_temporary_directory);
  ASSERT_EQ(::mkdir((state.path() / "device-tls").c_str(), 0700), 0);

  auto result = generation.get();
  ASSERT_EQ(::close(notifications), 0);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_HTTP_TLS_IDENTITY");
  EXPECT_TRUE(TemporaryIdentityEntries(state.path()).empty());
}

}  // namespace

extern "C" int __wrap_fstat(int descriptor, struct stat* status) {
  const int result = __real_fstat(descriptor, status);
  if (result == 0 && spoofed_owner_inode.has_value() &&
      status->st_ino == *spoofed_owner_inode) {
    status->st_uid = status->st_uid == 0 ? 1 : status->st_uid - 1;
  }
  return result;
}

extern "C" int __wrap_close(int descriptor) {
  if (descriptor == interrupted_close_descriptor) {
    ++interrupted_close_calls;
    if (interrupted_close_calls == 1) {
      const int result = __real_close(descriptor);
      if (result == 0) {
        errno = EINTR;
        return -1;
      }
      return result;
    }
  }
  return __real_close(descriptor);
}

extern "C" int __wrap_fsync(int descriptor) {
  if (interrupt_cleanup_fsync) {
    std::size_t slot = interrupted_fsync_descriptors.size();
    for (std::size_t index = 0; index < interrupted_fsync_descriptors.size();
         ++index) {
      if (interrupted_fsync_descriptors[index] == descriptor) {
        slot = index;
        break;
      }
      if (slot == interrupted_fsync_descriptors.size() &&
          interrupted_fsync_descriptors[index] < 0) {
        slot = index;
      }
    }
    if (slot < interrupted_fsync_descriptors.size()) {
      interrupted_fsync_descriptors[slot] = descriptor;
      ++interrupted_fsync_calls[slot];
      if (interrupted_fsync_calls[slot] == 1) {
        errno = EINTR;
        return -1;
      }
    }
  }
  return __real_fsync(descriptor);
}

extern "C" int __wrap_camera_firmware_tls_rename_noreplace(
    int old_directory,
    const char* old_name,
    int new_directory,
    const char* new_name) {
  if (fail_rename_noreplace) {
    errno = ENOSYS;
    return -1;
  }
  return __real_camera_firmware_tls_rename_noreplace(
      old_directory, old_name, new_directory, new_name);
}
