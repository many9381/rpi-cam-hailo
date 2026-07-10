#include "camera_firmware/rtsp/RtspDigestCredentials.hpp"
#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <iterator>
#include <span>
#include <signal.h>
#include <string>
#include <string_view>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#ifndef CF_RTSP_DIGEST_CREDENTIAL_TOOL
#error "CF_RTSP_DIGEST_CREDENTIAL_TOOL must name the credential executable"
#endif

namespace {

using camera_firmware::rtsp::ComputeRtspDigestHa1;
using camera_firmware::rtsp::RtspDigestAlgorithm;
using camera_firmware::rtsp::RtspDigestConstantTimeEqual;
using camera_firmware::rtsp::RtspDigestCredentialPolicy;
using camera_firmware::rtsp::RtspDigestCredentialStore;

constexpr std::size_t kMaximumPasswordBytes = 1024U;

struct ProcessResult {
  int exit_code{-1};
  std::string output;
  std::string command_line;
  bool echo_disabled{false};
  bool echo_restored{false};
};

struct SetInvocation {
  std::filesystem::path file;
  std::string username{"operator"};
  std::string realm{"rpi-camera"};
  std::string algorithm{"sha-256"};
  bool allow_md5{false};
  bool forbidden_password_flag{false};
  bool forbidden_password_assignment{false};
  bool invalid_password_stdin_assignment{false};
  bool repeated_password_stdin{false};
  bool repeated_allow_md5{false};
  bool repeated_file{false};
  bool missing_realm{false};
  bool unknown_flag{false};
};

std::string ReadFile(const std::filesystem::path& path);

std::string ReadCommandLine(pid_t child) {
  const auto path =
      std::filesystem::path("/proc") / std::to_string(child) / "cmdline";
  for (int attempt = 0; attempt < 100; ++attempt) {
    std::string command_line = ReadFile(path);
    if (command_line.find("rtsp-digest-credential") != std::string::npos) {
      return command_line;
    }
    usleep(1000U);
  }
  return {};
}

bool WriteAll(int fd, std::span<const unsigned char> bytes) {
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    const ssize_t written =
        write(fd, bytes.data() + offset, bytes.size() - offset);
    if (written > 0) {
      offset += static_cast<std::size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

ProcessResult RunSet(const SetInvocation& invocation,
                     std::span<const unsigned char> stdin_bytes,
                     std::size_t split_at = 0U) {
  int input_pipe[2]{};
  int output_pipe[2]{};
  if (pipe(input_pipe) != 0) {
    return {};
  }
  if (pipe(output_pipe) != 0) {
    close(input_pipe[0]);
    close(input_pipe[1]);
    return {};
  }

  const pid_t child = fork();
  if (child == 0) {
    (void)dup2(input_pipe[0], STDIN_FILENO);
    (void)dup2(output_pipe[1], STDOUT_FILENO);
    (void)dup2(output_pipe[1], STDERR_FILENO);
    close(input_pipe[0]);
    close(input_pipe[1]);
    close(output_pipe[0]);
    close(output_pipe[1]);

    const std::string file = invocation.file.string();
    if (invocation.forbidden_password_flag) {
      execl(CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            "set",
            "--file",
            file.c_str(),
            "--username",
            invocation.username.c_str(),
            "--realm",
            invocation.realm.c_str(),
            "--algorithm",
            invocation.algorithm.c_str(),
            "--password",
            static_cast<char*>(nullptr));
    } else if (invocation.forbidden_password_assignment) {
      execl(CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            "set",
            "--file",
            file.c_str(),
            "--username",
            invocation.username.c_str(),
            "--realm",
            invocation.realm.c_str(),
            "--algorithm",
            invocation.algorithm.c_str(),
            "--password=not-secret",
            static_cast<char*>(nullptr));
    } else if (invocation.invalid_password_stdin_assignment) {
      execl(CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            "set",
            "--file",
            file.c_str(),
            "--username",
            invocation.username.c_str(),
            "--realm",
            invocation.realm.c_str(),
            "--algorithm",
            invocation.algorithm.c_str(),
            "--password-stdin=1",
            static_cast<char*>(nullptr));
    } else if (invocation.repeated_password_stdin) {
      execl(CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            "set",
            "--file",
            file.c_str(),
            "--username",
            invocation.username.c_str(),
            "--realm",
            invocation.realm.c_str(),
            "--algorithm",
            invocation.algorithm.c_str(),
            "--password-stdin",
            "--password-stdin",
            static_cast<char*>(nullptr));
    } else if (invocation.repeated_allow_md5) {
      execl(CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            "set",
            "--file",
            file.c_str(),
            "--username",
            invocation.username.c_str(),
            "--realm",
            invocation.realm.c_str(),
            "--algorithm",
            invocation.algorithm.c_str(),
            "--allow-md5",
            "--allow-md5",
            "--password-stdin",
            static_cast<char*>(nullptr));
    } else if (invocation.repeated_file) {
      execl(CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            "set",
            "--file",
            file.c_str(),
            "--file",
            file.c_str(),
            "--username",
            invocation.username.c_str(),
            "--realm",
            invocation.realm.c_str(),
            "--algorithm",
            invocation.algorithm.c_str(),
            "--password-stdin",
            static_cast<char*>(nullptr));
    } else if (invocation.missing_realm) {
      execl(CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            "set",
            "--file",
            file.c_str(),
            "--username",
            invocation.username.c_str(),
            "--algorithm",
            invocation.algorithm.c_str(),
            "--password-stdin",
            static_cast<char*>(nullptr));
    } else if (invocation.unknown_flag) {
      execl(CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            "set",
            "--file",
            file.c_str(),
            "--username",
            invocation.username.c_str(),
            "--realm",
            invocation.realm.c_str(),
            "--algorithm",
            invocation.algorithm.c_str(),
            "--unknown",
            "--password-stdin",
            static_cast<char*>(nullptr));
    } else if (invocation.allow_md5) {
      execl(CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            "set",
            "--file",
            file.c_str(),
            "--username",
            invocation.username.c_str(),
            "--realm",
            invocation.realm.c_str(),
            "--algorithm",
            invocation.algorithm.c_str(),
            "--allow-md5",
            "--password-stdin",
            static_cast<char*>(nullptr));
    } else {
      execl(CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            CF_RTSP_DIGEST_CREDENTIAL_TOOL,
            "set",
            "--file",
            file.c_str(),
            "--username",
            invocation.username.c_str(),
            "--realm",
            invocation.realm.c_str(),
            "--algorithm",
            invocation.algorithm.c_str(),
            "--password-stdin",
            static_cast<char*>(nullptr));
    }
    _exit(127);
  }

  close(input_pipe[0]);
  close(output_pipe[1]);
  if (child < 0) {
    close(input_pipe[1]);
    close(output_pipe[0]);
    return {};
  }
  std::string command_line = ReadCommandLine(child);
  struct sigaction ignored {};
  struct sigaction previous {};
  ignored.sa_handler = SIG_IGN;
  sigemptyset(&ignored.sa_mask);
  (void)sigaction(SIGPIPE, &ignored, &previous);
  bool input_written = true;
  if (split_at != 0U && split_at < stdin_bytes.size()) {
    input_written = WriteAll(input_pipe[1], stdin_bytes.first(split_at));
    usleep(20000U);
    input_written =
        WriteAll(input_pipe[1], stdin_bytes.subspan(split_at)) && input_written;
  } else {
    input_written = WriteAll(input_pipe[1], stdin_bytes);
  }
  close(input_pipe[1]);
  (void)sigaction(SIGPIPE, &previous, nullptr);

  std::string output;
  char chunk[256]{};
  while (true) {
    const ssize_t received = read(output_pipe[0], chunk, sizeof(chunk));
    if (received > 0) {
      output.append(chunk, static_cast<std::size_t>(received));
      continue;
    }
    if (received < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
  close(output_pipe[0]);

  int status = 0;
  pid_t waited = -1;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  ProcessResult result;
  result.output = std::move(output);
  result.command_line = std::move(command_line);
  if (input_written && waited == child && WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  }
  return result;
}

ProcessResult RunSetFromTty(const SetInvocation& invocation,
                            std::span<const unsigned char> tty_bytes) {
  const int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) {
    if (master >= 0) {
      close(master);
    }
    return {};
  }
  char* slave_name = ptsname(master);
  if (slave_name == nullptr) {
    close(master);
    return {};
  }

  const pid_t child = fork();
  if (child == 0) {
    (void)setsid();
    const int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0 || ioctl(slave, TIOCSCTTY, 0) != 0) {
      _exit(126);
    }
    (void)dup2(slave, STDIN_FILENO);
    (void)dup2(slave, STDOUT_FILENO);
    (void)dup2(slave, STDERR_FILENO);
    if (slave > STDERR_FILENO) {
      close(slave);
    }
    close(master);
    const std::string file = invocation.file.string();
    execl(CF_RTSP_DIGEST_CREDENTIAL_TOOL,
          CF_RTSP_DIGEST_CREDENTIAL_TOOL,
          "set",
          "--file",
          file.c_str(),
          "--username",
          invocation.username.c_str(),
          "--realm",
          invocation.realm.c_str(),
          "--algorithm",
          invocation.algorithm.c_str(),
          static_cast<char*>(nullptr));
    _exit(127);
  }
  if (child < 0) {
    close(master);
    return {};
  }

  ProcessResult result;
  result.command_line = ReadCommandLine(child);
  termios settings{};
  for (int attempt = 0; attempt < 1000; ++attempt) {
    if (tcgetattr(master, &settings) == 0 &&
        (settings.c_lflag & ECHO) == 0) {
      result.echo_disabled = true;
      break;
    }
    usleep(1000U);
  }
  const bool input_written = WriteAll(master, tty_bytes);

  char chunk[256]{};
  while (true) {
    const ssize_t received = read(master, chunk, sizeof(chunk));
    if (received > 0) {
      result.output.append(chunk, static_cast<std::size_t>(received));
      continue;
    }
    if (received < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
  int status = 0;
  pid_t waited = -1;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  result.echo_restored =
      tcgetattr(master, &settings) == 0 && (settings.c_lflag & ECHO) != 0;
  close(master);
  if (input_written && waited == child && WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  }
  return result;
}

std::vector<unsigned char> PasswordInput(std::string_view password) {
  std::vector<unsigned char> bytes(password.begin(), password.end());
  bytes.push_back('\n');
  return bytes;
}

std::string ReadFile(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input),
          std::istreambuf_iterator<char>()};
}

struct FileIdentity {
  mode_t mode{0};
  ino_t inode{0};
};

FileIdentity InspectFile(const std::filesystem::path& path) {
  struct stat info {};
  if (stat(path.c_str(), &info) != 0) {
    return {};
  }
  return {static_cast<mode_t>(info.st_mode & 0777), info.st_ino};
}

void ExpectLoadableHa1(const std::filesystem::path& path,
                       RtspDigestAlgorithm algorithm,
                       std::span<const unsigned char> password,
                       std::vector<RtspDigestAlgorithm> algorithms = {
                           RtspDigestAlgorithm::kSha256}) {
  auto store = RtspDigestCredentialStore::Create(
      RtspDigestCredentialPolicy{"rpi-camera", std::move(algorithms)});
  ASSERT_TRUE(store.ok()) << store.error().message;
  ASSERT_TRUE(store.value()->Reload(path).ok());
  auto lookup = store.value()->Lookup("operator", algorithm);
  ASSERT_TRUE(lookup.ok()) << lookup.error().message;
  ASSERT_TRUE(lookup.value().matched);
  auto expected = ComputeRtspDigestHa1(
      algorithm, "operator", "rpi-camera", password);
  ASSERT_TRUE(expected.ok()) << expected.error().message;
  EXPECT_TRUE(RtspDigestConstantTimeEqual(lookup.value().ha1.data() == nullptr
                                             ? std::span<const unsigned char>{}
                                             : std::span<const unsigned char>(
                                                   lookup.value().ha1.data(),
                                                   lookup.value().ha1.size()),
                                         std::span<const unsigned char>(
                                             expected.value().data(),
                                             expected.value().size())));
}

class RtspDigestCredentialCliTest : public testing::Test {
 protected:
  void SetUp() override {
    static std::atomic<unsigned int> sequence{0U};
    directory_ = std::filesystem::temp_directory_path() /
                 ("cf-rtsp-digest-cli-" + std::to_string(getpid()) + "-" +
                  std::to_string(sequence.fetch_add(1U)));
    std::filesystem::create_directories(directory_);
    credential_file_ = directory_ / "users.credentials";
  }

  void TearDown() override { std::filesystem::remove_all(directory_); }

  std::filesystem::path directory_;
  std::filesystem::path credential_file_;
};

TEST_F(RtspDigestCredentialCliTest, CreatesLoadableSha256FileFromStdin) {
  const auto password = PasswordInput("correct horse battery staple");
  auto result = RunSet({credential_file_}, password);

  ASSERT_EQ(result.exit_code, 0) << result.output;
  EXPECT_NE(result.command_line.find("rtsp-digest-credential"),
            std::string::npos);
  EXPECT_EQ(result.command_line.find("correct horse battery staple"),
            std::string::npos);
  EXPECT_EQ(result.output.find("correct horse battery staple"),
            std::string::npos);
  EXPECT_EQ(result.output.find(credential_file_.string()), std::string::npos);
  EXPECT_EQ(InspectFile(credential_file_).mode, 0600);
  ExpectLoadableHa1(credential_file_,
                    RtspDigestAlgorithm::kSha256,
                    std::span(password).first(password.size() - 1U));
}

TEST_F(RtspDigestCredentialCliTest, ReadsFromTtyWithoutEchoAndRestoresTermios) {
  const auto password = PasswordInput("tty-only-password");

  auto result = RunSetFromTty({credential_file_}, password);

  ASSERT_EQ(result.exit_code, 0) << result.output;
  EXPECT_TRUE(result.echo_disabled);
  EXPECT_TRUE(result.echo_restored);
  EXPECT_EQ(result.command_line.find("tty-only-password"), std::string::npos);
  EXPECT_EQ(result.output.find("tty-only-password"), std::string::npos);
  ExpectLoadableHa1(credential_file_,
                    RtspDigestAlgorithm::kSha256,
                    std::span(password).first(password.size() - 1U));

  const std::vector<unsigned char> empty_password = {'\n'};
  auto rejected = RunSetFromTty({credential_file_}, empty_password);
  EXPECT_EQ(rejected.exit_code, 2) << rejected.output;
  EXPECT_TRUE(rejected.echo_disabled);
  EXPECT_TRUE(rejected.echo_restored);

  const std::vector<unsigned char> unterminated_password = {
      't', 't', 'y', 0x04U, 0x04U};
  auto eof_rejected =
      RunSetFromTty({credential_file_}, unterminated_password);
  EXPECT_EQ(eof_rejected.exit_code, 2) << eof_rejected.output;
  EXPECT_TRUE(eof_rejected.echo_disabled);
  EXPECT_TRUE(eof_rejected.echo_restored);
}

TEST_F(RtspDigestCredentialCliTest, UpdatesExistingFileAtomically) {
  const auto old_password = PasswordInput("old-password");
  ASSERT_EQ(RunSet({credential_file_}, old_password).exit_code, 0);
  const auto before = InspectFile(credential_file_);
  const auto new_password = PasswordInput("new-password");

  auto result = RunSet({credential_file_}, new_password);

  ASSERT_EQ(result.exit_code, 0) << result.output;
  const auto after = InspectFile(credential_file_);
  EXPECT_EQ(after.mode, 0600);
  EXPECT_NE(after.inode, before.inode);
  ExpectLoadableHa1(credential_file_,
                    RtspDigestAlgorithm::kSha256,
                    std::span(new_password).first(new_password.size() - 1U));
}

TEST_F(RtspDigestCredentialCliTest,
       AcceptsPasswordLengthBoundariesAndCrLf) {
  const auto one_byte = PasswordInput("x");
  ASSERT_EQ(RunSet({credential_file_}, one_byte).exit_code, 0);
  ExpectLoadableHa1(credential_file_,
                    RtspDigestAlgorithm::kSha256,
                    std::span(one_byte).first(1U));

  std::vector<unsigned char> maximum(kMaximumPasswordBytes, 'm');
  maximum.push_back('\n');
  ASSERT_EQ(RunSet({credential_file_}, maximum).exit_code, 0);
  ExpectLoadableHa1(credential_file_,
                    RtspDigestAlgorithm::kSha256,
                    std::span(maximum).first(kMaximumPasswordBytes));

  std::vector<unsigned char> maximum_crlf(kMaximumPasswordBytes, 'r');
  maximum_crlf.push_back('\r');
  maximum_crlf.push_back('\n');
  ASSERT_EQ(RunSet({credential_file_}, maximum_crlf).exit_code, 0);
  ExpectLoadableHa1(credential_file_,
                    RtspDigestAlgorithm::kSha256,
                    std::span(maximum_crlf).first(kMaximumPasswordBytes));

  std::vector<unsigned char> crlf = {'c', 'r', 'l', 'f', '\r', '\n'};
  ASSERT_EQ(RunSet({credential_file_}, crlf).exit_code, 0);
  ExpectLoadableHa1(credential_file_,
                    RtspDigestAlgorithm::kSha256,
                    std::span(crlf).first(4U));
}

TEST_F(RtspDigestCredentialCliTest, RejectsPasswordArgument) {
  SetInvocation invocation{credential_file_};
  invocation.forbidden_password_flag = true;

  auto result = RunSet(invocation, {});

  EXPECT_EQ(result.exit_code, 2) << result.output;
  EXPECT_FALSE(std::filesystem::exists(credential_file_));
}

TEST_F(RtspDigestCredentialCliTest, RejectsMd5WithoutExplicitAllowFlag) {
  SetInvocation invocation{credential_file_};
  invocation.algorithm = "md5";

  auto result = RunSet(invocation, {});

  EXPECT_EQ(result.exit_code, 2) << result.output;
  EXPECT_FALSE(std::filesystem::exists(credential_file_));
}

TEST_F(RtspDigestCredentialCliTest,
       RejectsRepeatedMissingUnknownAndInvalidAllowArguments) {
  std::vector<SetInvocation> invocations;
  SetInvocation repeated{credential_file_};
  repeated.repeated_file = true;
  invocations.push_back(repeated);
  SetInvocation missing{credential_file_};
  missing.missing_realm = true;
  invocations.push_back(missing);
  SetInvocation unknown{credential_file_};
  unknown.unknown_flag = true;
  invocations.push_back(unknown);
  SetInvocation invalid_allow{credential_file_};
  invalid_allow.allow_md5 = true;
  invocations.push_back(invalid_allow);
  SetInvocation password_assignment{credential_file_};
  password_assignment.forbidden_password_assignment = true;
  invocations.push_back(password_assignment);
  SetInvocation stdin_assignment{credential_file_};
  stdin_assignment.invalid_password_stdin_assignment = true;
  invocations.push_back(stdin_assignment);
  SetInvocation repeated_stdin{credential_file_};
  repeated_stdin.repeated_password_stdin = true;
  invocations.push_back(repeated_stdin);
  SetInvocation repeated_allow{credential_file_};
  repeated_allow.algorithm = "md5";
  repeated_allow.repeated_allow_md5 = true;
  invocations.push_back(repeated_allow);

  for (const auto& invocation : invocations) {
    auto result = RunSet(invocation, {});
    EXPECT_EQ(result.exit_code, 2) << result.output;
    EXPECT_EQ(result.output.find(credential_file_.string()), std::string::npos);
    EXPECT_FALSE(std::filesystem::exists(credential_file_));
  }
}

TEST_F(RtspDigestCredentialCliTest, CreatesMd5AlongsideRequiredSha256) {
  const auto password = PasswordInput("dual-algorithm-password");
  ASSERT_EQ(RunSet({credential_file_}, password).exit_code, 0);
  SetInvocation invocation{credential_file_};
  invocation.algorithm = "md5";
  invocation.allow_md5 = true;

  auto result = RunSet(invocation, password);

  ASSERT_EQ(result.exit_code, 0) << result.output;
  ExpectLoadableHa1(credential_file_,
                    RtspDigestAlgorithm::kSha256,
                    std::span(password).first(password.size() - 1U),
                    {RtspDigestAlgorithm::kSha256, RtspDigestAlgorithm::kMd5});
  ExpectLoadableHa1(credential_file_,
                    RtspDigestAlgorithm::kMd5,
                    std::span(password).first(password.size() - 1U),
                    {RtspDigestAlgorithm::kSha256, RtspDigestAlgorithm::kMd5});
}

TEST_F(RtspDigestCredentialCliTest,
       RejectsEmptyInvalidUtf8AndOversizedInput) {
  const auto valid_password = PasswordInput("preserved-password");
  ASSERT_EQ(RunSet({credential_file_}, valid_password).exit_code, 0);
  const std::string original = ReadFile(credential_file_);
  const std::vector<std::vector<unsigned char>> invalid_inputs = {
      {'\n'},
      {'n', 'o', '-', 't', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'o', 'r'},
      {0xC3U, 0x28U, '\n'},
      {'a', 0U, 'b', '\n'},
      {'a', '\n', 'b'},
      std::vector<unsigned char>(1025U, 'x'),
      std::vector<unsigned char>(kMaximumPasswordBytes, 'm'),
  };

  for (const auto& input : invalid_inputs) {
    auto result = RunSet({credential_file_}, input);
    EXPECT_EQ(result.exit_code, 2) << result.output;
    EXPECT_EQ(ReadFile(credential_file_), original);
  }
}

TEST_F(RtspDigestCredentialCliTest,
       RejectsTrailingDataRegardlessOfPipeSegmentation) {
  const std::vector<unsigned char> split_input = {
      'a', 'b', 'c', '\n', 'j', 'u', 'n', 'k'};

  auto result = RunSet({credential_file_}, split_input, 4U);

  EXPECT_EQ(result.exit_code, 2) << result.output;
  EXPECT_FALSE(std::filesystem::exists(credential_file_));
}

TEST_F(RtspDigestCredentialCliTest,
       ProvisioningFailureUsesRuntimeExitWithoutSensitiveOutput) {
  SetInvocation invocation{directory_ / "missing" / "users.credentials"};
  const auto password = PasswordInput("runtime-failure-password");

  auto result = RunSet(invocation, password);

  EXPECT_EQ(result.exit_code, 1) << result.output;
  EXPECT_EQ(result.output.find("runtime-failure-password"), std::string::npos);
  EXPECT_EQ(result.output.find(invocation.file.string()), std::string::npos);
  EXPECT_EQ(result.output.find(invocation.username), std::string::npos);
  EXPECT_EQ(result.output.find(invocation.realm), std::string::npos);
}

TEST_F(RtspDigestCredentialCliTest,
       FailedProvisioningPreservesExistingFile) {
  const auto old_password = PasswordInput("preserved-on-failure");
  ASSERT_EQ(RunSet({credential_file_}, old_password).exit_code, 0);
  const std::string original = ReadFile(credential_file_);
  std::filesystem::permissions(
      directory_,
      std::filesystem::perms::owner_read |
          std::filesystem::perms::owner_exec,
      std::filesystem::perm_options::replace);
  const auto new_password = PasswordInput("must-not-replace");

  auto result = RunSet({credential_file_}, new_password);

  std::filesystem::permissions(
      directory_,
      std::filesystem::perms::owner_all,
      std::filesystem::perm_options::replace);
  EXPECT_EQ(result.exit_code, 1) << result.output;
  EXPECT_EQ(ReadFile(credential_file_), original);
}

}  // namespace
