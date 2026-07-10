#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/rtsp/RtspDigestCredentials.hpp"
#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <termios.h>
#include <unistd.h>

#include <glib.h>

namespace {

using camera_firmware::common::Result;
using camera_firmware::common::SecureBytes;
using camera_firmware::rtsp::ParseRtspDigestAlgorithm;
using camera_firmware::rtsp::ProvisionRtspDigestCredential;
using camera_firmware::rtsp::RtspDigestAlgorithm;
using camera_firmware::rtsp::RtspDigestProvisionRequest;

constexpr std::size_t kMaximumPasswordBytes = 1024U;
constexpr std::size_t kPasswordInputBytes = kMaximumPasswordBytes + 1U;

struct Options {
  std::filesystem::path file;
  std::string username;
  std::string realm;
  RtspDigestAlgorithm algorithm{RtspDigestAlgorithm::kSha256};
  bool password_stdin{false};
  bool allow_md5{false};
};

class OwnedFd {
 public:
  explicit OwnedFd(int fd = -1) noexcept : fd_(fd) {}
  ~OwnedFd() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  OwnedFd(const OwnedFd&) = delete;
  OwnedFd& operator=(const OwnedFd&) = delete;

  [[nodiscard]] int get() const noexcept { return fd_; }

 private:
  int fd_{-1};
};

class TerminalEchoGuard {
 public:
  static Result<TerminalEchoGuard> Disable(int fd) {
    termios original{};
    if (tcgetattr(fd, &original) != 0) {
      return Result<TerminalEchoGuard>::Err(
          {"E_RTSP_CREDENTIAL_INPUT", "failed to read terminal settings"});
    }
    termios hidden = original;
    hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    if (tcsetattr(fd, TCSAFLUSH, &hidden) != 0) {
      return Result<TerminalEchoGuard>::Err(
          {"E_RTSP_CREDENTIAL_INPUT", "failed to disable terminal echo"});
    }
    return Result<TerminalEchoGuard>::Ok(TerminalEchoGuard(fd, original));
  }

  ~TerminalEchoGuard() { (void)Restore(); }

  TerminalEchoGuard(const TerminalEchoGuard&) = delete;
  TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;

  TerminalEchoGuard(TerminalEchoGuard&& other) noexcept
      : fd_(other.fd_), original_(other.original_), active_(other.active_) {
    other.active_ = false;
  }

  TerminalEchoGuard& operator=(TerminalEchoGuard&&) = delete;

  bool Restore() noexcept {
    if (!active_) {
      return true;
    }
    if (tcsetattr(fd_, TCSAFLUSH, &original_) != 0) {
      return false;
    }
    active_ = false;
    return true;
  }

 private:
  TerminalEchoGuard(int fd, const termios& original) noexcept
      : fd_(fd), original_(original), active_(true) {}

  int fd_{-1};
  termios original_{};
  bool active_{false};
};

Result<Options> UsageError() {
  return Result<Options>::Err(
      {"E_RTSP_CREDENTIAL_USAGE", "invalid credential command arguments"});
}

Result<Options> ParseOptions(int argc, char** argv) {
  if (argc < 2 || std::string_view(argv[1]) != "set") {
    return UsageError();
  }

  Options options;
  std::optional<std::string> algorithm;
  bool has_file = false;
  bool has_username = false;
  bool has_realm = false;
  bool has_algorithm = false;

  for (int index = 2; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument.starts_with("--password") &&
        argument != "--password-stdin") {
      return UsageError();
    }
    if (argument == "--password-stdin") {
      if (options.password_stdin) {
        return UsageError();
      }
      options.password_stdin = true;
      continue;
    }
    if (argument == "--allow-md5") {
      if (options.allow_md5) {
        return UsageError();
      }
      options.allow_md5 = true;
      continue;
    }
    if (argument != "--file" && argument != "--username" &&
        argument != "--realm" && argument != "--algorithm") {
      return UsageError();
    }
    if (index + 1 >= argc) {
      return UsageError();
    }
    const std::string_view value(argv[++index]);
    if (value.empty() || value.starts_with("--")) {
      return UsageError();
    }
    if (argument == "--file") {
      if (has_file) {
        return UsageError();
      }
      options.file = std::filesystem::path(value);
      has_file = true;
    } else if (argument == "--username") {
      if (has_username) {
        return UsageError();
      }
      options.username.assign(value);
      has_username = true;
    } else if (argument == "--realm") {
      if (has_realm) {
        return UsageError();
      }
      options.realm.assign(value);
      has_realm = true;
    } else {
      if (has_algorithm) {
        return UsageError();
      }
      algorithm = std::string(value);
      has_algorithm = true;
    }
  }

  if (!has_file || !has_username || !has_realm || !has_algorithm) {
    return UsageError();
  }
  auto parsed_algorithm = ParseRtspDigestAlgorithm(*algorithm);
  if (!parsed_algorithm.ok()) {
    return UsageError();
  }
  options.algorithm = parsed_algorithm.value();
  if ((options.algorithm == RtspDigestAlgorithm::kMd5 && !options.allow_md5) ||
      (options.algorithm == RtspDigestAlgorithm::kSha256 &&
       options.allow_md5)) {
    return UsageError();
  }
  return Result<Options>::Ok(std::move(options));
}

Result<SecureBytes> PasswordPolicyError() {
  return Result<SecureBytes>::Err(
      {"E_RTSP_CREDENTIAL_PASSWORD", "password input violates policy"});
}

Result<bool> ReadInputByte(int fd, unsigned char* destination) {
  ssize_t received = -1;
  do {
    received = read(fd, destination, 1U);
  } while (received < 0 && errno == EINTR);
  if (received < 0) {
    return Result<bool>::Err(
        {"E_RTSP_CREDENTIAL_INPUT", "failed to read password input"});
  }
  return Result<bool>::Ok(received == 1);
}

Result<SecureBytes> ReadPassword(int fd) {
  SecureBytes input;
  try {
    input.resize(kPasswordInputBytes);
  } catch (...) {
    return Result<SecureBytes>::Err(
        {"E_RTSP_CREDENTIAL_INPUT", "failed to allocate password input"});
  }

  const bool require_eof_after_terminator = isatty(fd) == 0;
  std::size_t password_size = 0U;
  bool terminated = false;
  while (true) {
    auto received = ReadInputByte(fd, input.data() + password_size);
    if (!received.ok()) {
      return Result<SecureBytes>::Err(received.error());
    }
    if (!received.value()) {
      if (!terminated) {
        return PasswordPolicyError();
      }
      break;
    }
    if (terminated) {
      return PasswordPolicyError();
    }

    const unsigned char byte = input.data()[password_size];
    if (byte == '\n') {
      terminated = true;
      if (!require_eof_after_terminator) {
        break;
      }
      continue;
    }
    if (byte == '\r') {
      auto line_feed = ReadInputByte(fd, input.data() + password_size);
      if (!line_feed.ok()) {
        return Result<SecureBytes>::Err(line_feed.error());
      }
      if (!line_feed.value() || input.data()[password_size] != '\n') {
        return PasswordPolicyError();
      }
      terminated = true;
      if (!require_eof_after_terminator) {
        break;
      }
      continue;
    }
    if (byte == 0U || password_size >= kMaximumPasswordBytes) {
      return PasswordPolicyError();
    }
    ++password_size;
  }

  if (password_size == 0U) {
    return PasswordPolicyError();
  }
  if (!g_utf8_validate(reinterpret_cast<const gchar*>(input.data()),
                       static_cast<gssize>(password_size),
                       nullptr)) {
    return PasswordPolicyError();
  }

  try {
    input.resize(password_size);
  } catch (...) {
    return Result<SecureBytes>::Err(
        {"E_RTSP_CREDENTIAL_INPUT", "failed to retain password input"});
  }
  return Result<SecureBytes>::Ok(std::move(input));
}

Result<SecureBytes> ReadPasswordFromTty() {
  OwnedFd terminal(open("/dev/tty", O_RDONLY | O_CLOEXEC | O_NOCTTY));
  if (terminal.get() < 0) {
    return Result<SecureBytes>::Err(
        {"E_RTSP_CREDENTIAL_INPUT", "failed to open controlling terminal"});
  }
  auto echo = TerminalEchoGuard::Disable(terminal.get());
  if (!echo.ok()) {
    return Result<SecureBytes>::Err(echo.error());
  }
  auto password = ReadPassword(terminal.get());
  if (!echo.value().Restore()) {
    return Result<SecureBytes>::Err(
        {"E_RTSP_CREDENTIAL_INPUT", "failed to restore terminal settings"});
  }
  return password;
}

int ReportError(std::string_view code, std::string_view category, int status) {
  std::fprintf(stderr,
               "%.*s: category=%.*s\n",
               static_cast<int>(code.size()),
               code.data(),
               static_cast<int>(category.size()),
               category.data());
  return status;
}

int Run(int argc, char** argv) {
  auto options = ParseOptions(argc, argv);
  if (!options.ok()) {
    return ReportError(options.error().code, "arguments", 2);
  }

  auto password = options.value().password_stdin
                      ? ReadPassword(STDIN_FILENO)
                      : ReadPasswordFromTty();
  if (!password.ok()) {
    const bool policy = password.error().code == "E_RTSP_CREDENTIAL_PASSWORD";
    return ReportError(password.error().code,
                       policy ? "password-policy" : "input",
                       policy ? 2 : 1);
  }

  RtspDigestProvisionRequest request;
  request.path = options.value().file;
  request.username = options.value().username;
  request.realm = options.value().realm;
  request.algorithm = options.value().algorithm;
  request.allow_md5 = options.value().allow_md5;
  auto provisioned = ProvisionRtspDigestCredential(
      request,
      std::span<const unsigned char>(password.value().data(),
                                     password.value().size()));
  password.value().clear();
  if (!provisioned.ok()) {
    return ReportError(provisioned.error().code, "provision", 1);
  }

  std::fputs("RTSP Digest credential updated\n", stdout);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    return Run(argc, argv);
  } catch (...) {
    return ReportError("E_RTSP_CREDENTIAL_INTERNAL", "internal", 1);
  }
}
