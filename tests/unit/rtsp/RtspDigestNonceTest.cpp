#include "camera_firmware/rtsp/RtspDigestNonce.hpp"

#include "camera_firmware/rtsp/RtspDigestCrypto.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <sys/wait.h>
#include <unistd.h>

namespace camera_firmware::rtsp {
namespace {

using common::Result;
using common::SecureBytes;
using namespace std::chrono_literals;

constexpr std::uint64_t kVectorTimestamp = 0x0102030405060708ULL;
constexpr std::string_view kVectorNonce =
    "AQECAwQFBgcIoKGio6SlpqeoqaqrrK2ur8FpK5ujTDBJ7uqgrjfiQnxNIcHV4rUI_"
    "Lie3qwQ4MTA";
constexpr std::string_view kWrongVersionAuthenticatedNonce =
    "AgECAwQFBgcIoKGio6SlpqeoqaqrrK2urykyflBvwU48Kl-tMM2rptyFnyxqciMf5xr"
    "BaZzcZ6Vf";

common::Error TestDependencyError() {
  return {"E_TEST", "test dependency failed"};
}

Result<SecureBytes> SecureSequence(std::size_t size, unsigned char first) {
  SecureBytes bytes;
  bytes.resize(size);
  for (std::size_t index = 0U; index < size; ++index) {
    bytes.data()[index] =
        static_cast<unsigned char>(first + static_cast<unsigned char>(index));
  }
  return Result<SecureBytes>::Ok(std::move(bytes));
}

struct DeterministicInputs {
  std::shared_ptr<std::atomic<std::uint64_t>> now =
      std::make_shared<std::atomic<std::uint64_t>>(100U);
  std::shared_ptr<std::atomic<std::size_t>> random_calls =
      std::make_shared<std::atomic<std::size_t>>(0U);

  RtspDigestNonceDependencies Dependencies() const {
    RtspDigestNonceDependencies dependencies;
    dependencies.now_seconds = [clock = now]() {
      return clock->load(std::memory_order_relaxed);
    };
    dependencies.random_bytes = [calls = random_calls](std::size_t size) {
      const std::size_t call = calls->fetch_add(1U, std::memory_order_relaxed);
      if (call == 0U) {
        if (size != 32U) {
          return Result<SecureBytes>::Err(TestDependencyError());
        }
        return SecureSequence(32U, 0x00U);
      }
      if (size != 16U) {
        return Result<SecureBytes>::Err(TestDependencyError());
      }
      const unsigned char first = static_cast<unsigned char>(
          0xa0U + static_cast<unsigned char>((call - 1U) * 0x10U));
      return SecureSequence(16U, first);
    };
    return dependencies;
  }
};

std::unique_ptr<RtspDigestNonceManager> CreateManager(
    const DeterministicInputs& inputs, std::chrono::seconds ttl = 5s,
    std::size_t replay_capacity = 4096U) {
  auto created = RtspDigestNonceManager::Create(ttl, inputs.Dependencies(),
                                                replay_capacity);
  EXPECT_TRUE(created.ok())
      << (created.ok() ? std::string{} : created.error().message);
  if (!created.ok()) {
    return nullptr;
  }
  return std::move(created).value();
}

void ExpectNonceError(const common::Error& error) {
  EXPECT_EQ(error.code, "E_RTSP_AUTH_NONCE");
  EXPECT_FALSE(error.message.empty());
  EXPECT_EQ(error.message.find("username"), std::string::npos);
  EXPECT_EQ(error.message.find("AQECA"), std::string::npos);
}

bool ChildCompletesWithin(std::chrono::milliseconds timeout,
                          const std::function<int()>& child_operation) {
  const pid_t child = ::fork();
  if (child < 0) {
    return false;
  }
  if (child == 0) {
    const int result = child_operation();
    ::_exit(result);
  }

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  int status = 0;
  while (std::chrono::steady_clock::now() < deadline) {
    const pid_t waited = ::waitpid(child, &status, WNOHANG);
    if (waited == child) {
      return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    if (waited < 0) {
      if (errno == EINTR) {
        continue;
      }
      (void)::kill(child, SIGKILL);
      while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
      }
      return false;
    }
    std::this_thread::sleep_for(10ms);
  }

  (void)::kill(child, SIGKILL);
  while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  return false;
}

RtspDigestNonceValidation IssueAndValidate(RtspDigestNonceManager* manager,
                                           std::string* nonce = nullptr) {
  auto issued = manager->Issue();
  EXPECT_TRUE(issued.ok()) << (issued.ok() ? std::string{}
                                           : issued.error().message);
  if (!issued.ok()) {
    return {};
  }
  auto validated = manager->Validate(issued.value());
  EXPECT_TRUE(validated.ok())
      << (validated.ok() ? std::string{} : validated.error().message);
  if (nonce != nullptr) {
    *nonce = issued.value();
  }
  return validated.ok() ? validated.value() : RtspDigestNonceValidation{};
}

TEST(RtspDigestNonceTest, IssuesFixedLengthHmacAuthenticatedNonce) {
  DeterministicInputs inputs;
  inputs.now->store(kVectorTimestamp, std::memory_order_relaxed);
  auto manager = CreateManager(inputs, 30s);
  ASSERT_NE(manager, nullptr);

  auto issued = manager->Issue();
  ASSERT_TRUE(issued.ok()) << issued.error().message;
  EXPECT_EQ(issued.value(), kVectorNonce);
  EXPECT_EQ(issued.value().size(), 76U);
  EXPECT_TRUE(std::all_of(
      issued.value().begin(), issued.value().end(), [](unsigned char byte) {
        return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
               (byte >= '0' && byte <= '9') || byte == '-' || byte == '_';
      }));

  auto validated = manager->Validate(issued.value());
  ASSERT_TRUE(validated.ok()) << validated.error().message;
  EXPECT_EQ(validated.value().status, RtspDigestNonceStatus::kValid);
  EXPECT_EQ(validated.value().expires_at, kVectorTimestamp + 30U);

  const auto nonce_bytes = std::span<const unsigned char>(
      reinterpret_cast<const unsigned char*>(issued.value().data()),
      issued.value().size());
  auto expected_id = RtspDigestHash(RtspDigestAlgorithm::kSha256, nonce_bytes);
  ASSERT_TRUE(expected_id.ok()) << expected_id.error().message;
  ASSERT_EQ(expected_id.value().size(), validated.value().nonce_id.size());
  EXPECT_TRUE(
      std::equal(expected_id.value().data(),
                 expected_id.value().data() + expected_id.value().size(),
                 validated.value().nonce_id.begin()));
}

TEST(RtspDigestNonceTest, RejectsTamperedAndFutureNonce) {
  DeterministicInputs inputs;
  inputs.now->store(kVectorTimestamp, std::memory_order_relaxed);
  auto manager = CreateManager(inputs);
  ASSERT_NE(manager, nullptr);
  auto issued = manager->Issue();
  ASSERT_TRUE(issued.ok()) << issued.error().message;

  std::string tampered = issued.value();
  tampered[20] = tampered[20] == 'A' ? 'B' : 'A';
  auto tampered_result = manager->Validate(tampered);
  ASSERT_TRUE(tampered_result.ok()) << tampered_result.error().message;
  EXPECT_EQ(tampered_result.value().status, RtspDigestNonceStatus::kInvalid);

  auto wrong_version = manager->Validate(kWrongVersionAuthenticatedNonce);
  ASSERT_TRUE(wrong_version.ok()) << wrong_version.error().message;
  EXPECT_EQ(wrong_version.value().status, RtspDigestNonceStatus::kInvalid);

  inputs.now->store(kVectorTimestamp - 1U, std::memory_order_relaxed);
  auto future_result = manager->Validate(issued.value());
  ASSERT_TRUE(future_result.ok()) << future_result.error().message;
  EXPECT_EQ(future_result.value().status, RtspDigestNonceStatus::kInvalid);
}

TEST(RtspDigestNonceTest, DefaultDependenciesIssueValidNonce) {
  auto created = RtspDigestNonceManager::Create(5s);
  ASSERT_TRUE(created.ok()) << created.error().message;

  auto issued = created.value()->Issue();
  ASSERT_TRUE(issued.ok()) << issued.error().message;
  auto validated = created.value()->Validate(issued.value());

  ASSERT_TRUE(validated.ok()) << validated.error().message;
  EXPECT_EQ(validated.value().status, RtspDigestNonceStatus::kValid);
}

TEST(RtspDigestNonceTest, ClassifiesValidNonceAsExpiredAfterTtl) {
  DeterministicInputs inputs;
  auto manager = CreateManager(inputs, 5s);
  ASSERT_NE(manager, nullptr);
  auto issued = manager->Issue();
  ASSERT_TRUE(issued.ok()) << issued.error().message;

  inputs.now->store(106U, std::memory_order_relaxed);
  auto validated = manager->Validate(issued.value());

  ASSERT_TRUE(validated.ok()) << validated.error().message;
  EXPECT_EQ(validated.value().status, RtspDigestNonceStatus::kExpired);
  EXPECT_EQ(validated.value().expires_at, 105U);
  EXPECT_FALSE(std::all_of(validated.value().nonce_id.begin(),
                           validated.value().nonce_id.end(),
                           [](unsigned char byte) { return byte == 0U; }));
}

TEST(RtspDigestNonceTest, AcceptsStrictlyIncreasingNonceCount) {
  DeterministicInputs inputs;
  auto manager = CreateManager(inputs);
  ASSERT_NE(manager, nullptr);
  const auto validation = IssueAndValidate(manager.get());
  ASSERT_EQ(validation.status, RtspDigestNonceStatus::kValid);

  auto first = manager->Commit("operator", validation, 1U);
  auto second = manager->Commit("operator", validation, 2U);
  auto later = manager->Commit("operator", validation, 100U);

  ASSERT_TRUE(first.ok()) << first.error().message;
  ASSERT_TRUE(second.ok()) << second.error().message;
  ASSERT_TRUE(later.ok()) << later.error().message;
  EXPECT_TRUE(first.value());
  EXPECT_TRUE(second.value());
  EXPECT_TRUE(later.value());
}

TEST(RtspDigestNonceTest, RejectsZeroRepeatedAndDecreasingNonceCount) {
  DeterministicInputs inputs;
  auto manager = CreateManager(inputs);
  ASSERT_NE(manager, nullptr);
  const auto validation = IssueAndValidate(manager.get());
  ASSERT_EQ(validation.status, RtspDigestNonceStatus::kValid);

  auto zero = manager->Commit("operator", validation, 0U);
  auto accepted = manager->Commit("operator", validation, 2U);
  auto repeated = manager->Commit("operator", validation, 2U);
  auto decreasing = manager->Commit("operator", validation, 1U);

  ASSERT_TRUE(zero.ok());
  ASSERT_TRUE(accepted.ok());
  ASSERT_TRUE(repeated.ok());
  ASSERT_TRUE(decreasing.ok());
  EXPECT_FALSE(zero.value());
  EXPECT_TRUE(accepted.value());
  EXPECT_FALSE(repeated.value());
  EXPECT_FALSE(decreasing.value());
}

TEST(RtspDigestNonceTest, PrunesExpiredReplayEntriesBeforeCapacityCheck) {
  DeterministicInputs inputs;
  auto manager = CreateManager(inputs, 5s, 1U);
  ASSERT_NE(manager, nullptr);
  auto first_validation = IssueAndValidate(manager.get());
  ASSERT_EQ(first_validation.status, RtspDigestNonceStatus::kValid);
  auto first_commit = manager->Commit("first", first_validation, 1U);
  ASSERT_TRUE(first_commit.ok());
  ASSERT_TRUE(first_commit.value());

  inputs.now->store(106U, std::memory_order_relaxed);
  auto second_validation = IssueAndValidate(manager.get());
  ASSERT_EQ(second_validation.status, RtspDigestNonceStatus::kValid);
  auto second_commit = manager->Commit("second", second_validation, 1U);

  ASSERT_TRUE(second_commit.ok()) << second_commit.error().message;
  EXPECT_TRUE(second_commit.value());
  const auto audit = manager->zeroize_audit();
  EXPECT_GE(audit.count, 1U);
  EXPECT_TRUE(audit.last_verified);
}

TEST(RtspDigestNonceTest, FailsClosedWhenLiveReplayCapacityIsFull) {
  DeterministicInputs inputs;
  auto manager = CreateManager(inputs, 5s, 1U);
  ASSERT_NE(manager, nullptr);
  const auto validation = IssueAndValidate(manager.get());
  ASSERT_EQ(validation.status, RtspDigestNonceStatus::kValid);

  auto first = manager->Commit("first", validation, 1U);
  auto full = manager->Commit("second", validation, 1U);
  auto existing_update = manager->Commit("first", validation, 2U);

  ASSERT_TRUE(first.ok());
  ASSERT_TRUE(full.ok());
  ASSERT_TRUE(existing_update.ok());
  EXPECT_TRUE(first.value());
  EXPECT_FALSE(full.value());
  EXPECT_TRUE(existing_update.value());
}

TEST(RtspDigestNonceTest, ConcurrentCommitAcceptsOnlyOneIdenticalCount) {
  DeterministicInputs inputs;
  auto manager = CreateManager(inputs);
  ASSERT_NE(manager, nullptr);
  const auto validation = IssueAndValidate(manager.get());
  ASSERT_EQ(validation.status, RtspDigestNonceStatus::kValid);

  constexpr std::size_t kThreadCount = 16U;
  std::barrier start(static_cast<std::ptrdiff_t>(kThreadCount));
  std::atomic<std::size_t> accepted{0U};
  std::atomic<std::size_t> errors{0U};
  std::vector<std::thread> threads;
  threads.reserve(kThreadCount);
  for (std::size_t index = 0U; index < kThreadCount; ++index) {
    threads.emplace_back([&]() {
      start.arrive_and_wait();
      auto committed = manager->Commit("operator", validation, 1U);
      if (!committed.ok()) {
        errors.fetch_add(1U, std::memory_order_relaxed);
      } else if (committed.value()) {
        accepted.fetch_add(1U, std::memory_order_relaxed);
      }
    });
  }
  for (auto& thread : threads) {
    thread.join();
  }

  EXPECT_EQ(errors.load(std::memory_order_relaxed), 0U);
  EXPECT_EQ(accepted.load(std::memory_order_relaxed), 1U);
}

TEST(RtspDigestNonceTest, DependencyCallbackCanReenterManagerWithoutDeadlock) {
  EXPECT_TRUE(ChildCompletesWithin(2s, [] {
    RtspDigestNonceManager* manager_view = nullptr;
    bool reenter_manager = false;
    bool nested_commit_succeeded = false;
    RtspDigestNonceDependencies dependencies;
    dependencies.now_seconds = [&] {
      if (reenter_manager && manager_view != nullptr) {
        reenter_manager = false;
        RtspDigestNonceValidation nested_validation;
        nested_validation.status = RtspDigestNonceStatus::kValid;
        nested_validation.nonce_id[0] = 2U;
        nested_validation.expires_at = 105U;
        auto nested = manager_view->Commit("nested", nested_validation, 1U);
        nested_commit_succeeded = nested.ok() && nested.value();
      }
      return 100U;
    };
    dependencies.random_bytes = [](std::size_t size) {
      return SecureSequence(size, 0x00U);
    };
    auto created = RtspDigestNonceManager::Create(5s, std::move(dependencies));
    if (!created.ok()) {
      return 1;
    }
    auto manager = std::move(created).value();
    manager_view = manager.get();

    RtspDigestNonceValidation validation;
    validation.status = RtspDigestNonceStatus::kValid;
    validation.nonce_id[0] = 1U;
    validation.expires_at = 105U;
    reenter_manager = true;
    auto committed = manager->Commit("operator", validation, 1U);
    return nested_commit_succeeded && committed.ok() && committed.value() ? 0
                                                                          : 2;
  }));
}

TEST(RtspDigestNonceTest,
     ClearDuringDependencyCallbackPreventsIssueAfterShutdown) {
  EXPECT_TRUE(ChildCompletesWithin(2s, [] {
    struct BlockingRandomState {
      std::mutex mutex;
      std::condition_variable condition;
      std::size_t calls{0U};
      bool issue_entered{false};
      bool release_issue{false};
    };

    auto state = std::make_shared<BlockingRandomState>();
    RtspDigestNonceDependencies dependencies;
    dependencies.now_seconds = [] { return 100U; };
    dependencies.random_bytes = [state](std::size_t size) {
      std::unique_lock lock(state->mutex);
      ++state->calls;
      if (state->calls == 1U) {
        lock.unlock();
        return SecureSequence(size, 0x00U);
      }
      state->issue_entered = true;
      state->condition.notify_all();
      state->condition.wait(lock, [state] { return state->release_issue; });
      lock.unlock();
      return SecureSequence(size, 0xa0U);
    };
    auto created = RtspDigestNonceManager::Create(5s, std::move(dependencies));
    if (!created.ok()) {
      return 1;
    }
    auto manager = std::move(created).value();
    bool issue_succeeded = true;
    std::thread issue([&] { issue_succeeded = manager->Issue().ok(); });
    bool issue_entered = false;
    {
      std::unique_lock lock(state->mutex);
      issue_entered = state->condition.wait_for(
          lock, 1s, [state] { return state->issue_entered; });
      if (!issue_entered) {
        state->release_issue = true;
      }
    }
    if (!issue_entered) {
      state->condition.notify_all();
      issue.join();
      return 2;
    }

    manager->Clear();
    {
      std::lock_guard lock(state->mutex);
      state->release_issue = true;
    }
    state->condition.notify_all();
    issue.join();
    return !issue_succeeded && !manager->Issue().ok() ? 0 : 3;
  }));
}

TEST(RtspDigestNonceTest,
     ClearFromCommitCallbackZeroizesPendingReplayIdentifier) {
  RtspDigestNonceManager* manager_view = nullptr;
  bool clear_during_commit = false;
  RtspDigestNonceDependencies dependencies;
  dependencies.now_seconds = [&] {
    if (clear_during_commit && manager_view != nullptr) {
      clear_during_commit = false;
      manager_view->Clear();
    }
    return 100U;
  };
  dependencies.random_bytes = [](std::size_t size) {
    return SecureSequence(size, 0x00U);
  };
  auto created = RtspDigestNonceManager::Create(5s, std::move(dependencies));
  ASSERT_TRUE(created.ok()) << created.error().message;
  auto manager = std::move(created).value();
  manager_view = manager.get();
  const auto before = manager->zeroize_audit();

  RtspDigestNonceValidation validation;
  validation.status = RtspDigestNonceStatus::kValid;
  validation.nonce_id[0] = 1U;
  validation.expires_at = 105U;
  clear_during_commit = true;
  auto committed = manager->Commit("operator", validation, 1U);
  const auto after = manager->zeroize_audit();

  ASSERT_FALSE(committed.ok());
  ExpectNonceError(committed.error());
  EXPECT_GE(after.count, before.count + 2U);
  EXPECT_TRUE(after.last_verified);
  EXPECT_FALSE(manager->Issue().ok());
}

TEST(RtspDigestNonceTest, ClearZeroizesHmacKeyAndReplayIdentifiers) {
  DeterministicInputs inputs;
  auto manager = CreateManager(inputs, 5s, 4U);
  ASSERT_NE(manager, nullptr);
  std::string nonce;
  const auto validation = IssueAndValidate(manager.get(), &nonce);
  ASSERT_EQ(validation.status, RtspDigestNonceStatus::kValid);
  ASSERT_TRUE(manager->Commit("first", validation, 1U).value());
  ASSERT_TRUE(manager->Commit("second", validation, 1U).value());
  const auto before = manager->zeroize_audit();

  manager->Clear();
  const auto after = manager->zeroize_audit();

  EXPECT_GE(after.count, before.count + 3U);
  EXPECT_TRUE(after.last_verified);
  auto issued_after_clear = manager->Issue();
  auto validated_after_clear = manager->Validate(nonce);
  auto committed_after_clear = manager->Commit("first", validation, 2U);
  ASSERT_FALSE(issued_after_clear.ok());
  ASSERT_FALSE(validated_after_clear.ok());
  ASSERT_FALSE(committed_after_clear.ok());
  ExpectNonceError(issued_after_clear.error());
  ExpectNonceError(validated_after_clear.error());
  ExpectNonceError(committed_after_clear.error());

  manager->Clear();
  EXPECT_EQ(manager->zeroize_audit().count, after.count);
}

TEST(RtspDigestNonceTest, RejectsMalformedBase64UrlNonceEncodings) {
  DeterministicInputs inputs;
  auto manager = CreateManager(inputs);
  ASSERT_NE(manager, nullptr);
  auto issued = manager->Issue();
  ASSERT_TRUE(issued.ok()) << issued.error().message;

  std::vector<std::string> malformed = {
      issued.value().substr(1U),
      issued.value() + "A",
      issued.value(),
      issued.value(),
      issued.value(),
  };
  malformed[2][5] = '+';
  malformed[3][5] = '/';
  malformed[4][5] = '=';

  for (const auto& nonce : malformed) {
    auto result = manager->Validate(nonce);
    ASSERT_TRUE(result.ok()) << result.error().message;
    EXPECT_EQ(result.value().status, RtspDigestNonceStatus::kInvalid);
  }
}

TEST(RtspDigestNonceTest, UsesInclusiveExpiryBoundaryConsistently) {
  DeterministicInputs inputs;
  auto manager = CreateManager(inputs, 5s);
  ASSERT_NE(manager, nullptr);
  std::string nonce;
  (void)IssueAndValidate(manager.get(), &nonce);

  inputs.now->store(105U, std::memory_order_relaxed);
  auto at_boundary = manager->Validate(nonce);
  ASSERT_TRUE(at_boundary.ok()) << at_boundary.error().message;
  ASSERT_EQ(at_boundary.value().status, RtspDigestNonceStatus::kValid);
  auto committed = manager->Commit("operator", at_boundary.value(), 1U);
  ASSERT_TRUE(committed.ok()) << committed.error().message;
  EXPECT_TRUE(committed.value());

  inputs.now->store(106U, std::memory_order_relaxed);
  auto after_boundary = manager->Validate(nonce);
  ASSERT_TRUE(after_boundary.ok()) << after_boundary.error().message;
  EXPECT_EQ(after_boundary.value().status, RtspDigestNonceStatus::kExpired);
  auto late_commit = manager->Commit("operator", at_boundary.value(), 2U);
  ASSERT_TRUE(late_commit.ok()) << late_commit.error().message;
  EXPECT_FALSE(late_commit.value());
}

TEST(RtspDigestNonceTest, RejectsInvalidConfigurationAndKeyGeneration) {
  DeterministicInputs inputs;
  auto zero_ttl = RtspDigestNonceManager::Create(0s, inputs.Dependencies(), 1U);
  auto negative_ttl =
      RtspDigestNonceManager::Create(-1s, inputs.Dependencies(), 1U);
  auto zero_capacity =
      RtspDigestNonceManager::Create(5s, inputs.Dependencies(), 0U);
  auto excessive_capacity =
      RtspDigestNonceManager::Create(5s, inputs.Dependencies(), 4097U);

  RtspDigestNonceDependencies wrong_key;
  wrong_key.now_seconds = [] { return 100U; };
  wrong_key.random_bytes = [](std::size_t) {
    return SecureSequence(31U, 0x10U);
  };
  auto wrong_key_size =
      RtspDigestNonceManager::Create(5s, std::move(wrong_key), 1U);

  RtspDigestNonceDependencies failed_key;
  failed_key.now_seconds = [] { return 100U; };
  failed_key.random_bytes = [](std::size_t) {
    return Result<SecureBytes>::Err(TestDependencyError());
  };
  auto key_failure =
      RtspDigestNonceManager::Create(5s, std::move(failed_key), 1U);

  RtspDigestNonceDependencies throwing_key;
  throwing_key.now_seconds = [] { return 100U; };
  throwing_key.random_bytes = [](std::size_t) -> Result<SecureBytes> {
    throw std::runtime_error("dependency exception");
  };
  auto key_exception =
      RtspDigestNonceManager::Create(5s, std::move(throwing_key), 1U);

  ASSERT_FALSE(zero_ttl.ok());
  ASSERT_FALSE(negative_ttl.ok());
  ASSERT_FALSE(zero_capacity.ok());
  ASSERT_FALSE(excessive_capacity.ok());
  ASSERT_FALSE(wrong_key_size.ok());
  ASSERT_FALSE(key_failure.ok());
  ASSERT_FALSE(key_exception.ok());
  ExpectNonceError(zero_ttl.error());
  ExpectNonceError(negative_ttl.error());
  ExpectNonceError(zero_capacity.error());
  ExpectNonceError(excessive_capacity.error());
  ExpectNonceError(wrong_key_size.error());
  ExpectNonceError(key_failure.error());
  ExpectNonceError(key_exception.error());
}

TEST(RtspDigestNonceTest, RejectsNonceRandomAndClockFailures) {
  auto calls = std::make_shared<std::size_t>(0U);
  RtspDigestNonceDependencies wrong_random;
  wrong_random.now_seconds = [] { return 100U; };
  wrong_random.random_bytes = [calls](std::size_t) {
    ++*calls;
    return *calls == 1U ? SecureSequence(32U, 0x00U)
                        : SecureSequence(15U, 0xa0U);
  };
  auto wrong_manager =
      RtspDigestNonceManager::Create(5s, std::move(wrong_random));
  ASSERT_TRUE(wrong_manager.ok()) << wrong_manager.error().message;
  auto wrong_size = wrong_manager.value()->Issue();
  ASSERT_FALSE(wrong_size.ok());
  ExpectNonceError(wrong_size.error());

  auto throwing_calls = std::make_shared<std::size_t>(0U);
  RtspDigestNonceDependencies throwing_random;
  throwing_random.now_seconds = [] { return 100U; };
  throwing_random.random_bytes =
      [throwing_calls](std::size_t) -> Result<SecureBytes> {
    ++*throwing_calls;
    if (*throwing_calls == 1U) {
      return SecureSequence(32U, 0x00U);
    }
    throw std::runtime_error("nonce random exception");
  };
  auto throwing_manager =
      RtspDigestNonceManager::Create(5s, std::move(throwing_random));
  ASSERT_TRUE(throwing_manager.ok()) << throwing_manager.error().message;
  auto random_exception = throwing_manager.value()->Issue();
  ASSERT_FALSE(random_exception.ok());
  ExpectNonceError(random_exception.error());

  auto failed_calls = std::make_shared<std::size_t>(0U);
  RtspDigestNonceDependencies failed_random;
  failed_random.now_seconds = [] { return 100U; };
  failed_random.random_bytes =
      [failed_calls](std::size_t) -> Result<SecureBytes> {
    ++*failed_calls;
    if (*failed_calls == 1U) {
      return SecureSequence(32U, 0x00U);
    }
    return Result<SecureBytes>::Err(TestDependencyError());
  };
  auto failed_manager =
      RtspDigestNonceManager::Create(5s, std::move(failed_random));
  ASSERT_TRUE(failed_manager.ok()) << failed_manager.error().message;
  auto random_failure = failed_manager.value()->Issue();
  ASSERT_FALSE(random_failure.ok());
  ExpectNonceError(random_failure.error());

  DeterministicInputs inputs;
  auto manager = CreateManager(inputs);
  ASSERT_NE(manager, nullptr);
  inputs.now->store(std::numeric_limits<std::uint64_t>::max() - 1U,
                    std::memory_order_relaxed);
  auto overflow = manager->Issue();
  ASSERT_FALSE(overflow.ok());
  ExpectNonceError(overflow.error());

  DeterministicInputs clock_inputs;
  RtspDigestNonceDependencies throwing_clock = clock_inputs.Dependencies();
  throwing_clock.now_seconds = []() -> std::uint64_t {
    throw std::runtime_error("clock exception");
  };
  auto clock_manager =
      RtspDigestNonceManager::Create(5s, std::move(throwing_clock));
  ASSERT_TRUE(clock_manager.ok()) << clock_manager.error().message;
  auto clock_exception = clock_manager.value()->Issue();
  ASSERT_FALSE(clock_exception.ok());
  ExpectNonceError(clock_exception.error());
}

TEST(RtspDigestNonceTest, RejectsInvalidValidationStatesWithoutMutation) {
  DeterministicInputs inputs;
  auto manager = CreateManager(inputs);
  ASSERT_NE(manager, nullptr);
  RtspDigestNonceValidation invalid;
  invalid.status = RtspDigestNonceStatus::kInvalid;
  invalid.expires_at = 1000U;
  RtspDigestNonceValidation expired = invalid;
  expired.status = RtspDigestNonceStatus::kExpired;
  RtspDigestNonceValidation unknown = invalid;
  unknown.status = static_cast<RtspDigestNonceStatus>(99);

  auto invalid_result = manager->Commit("operator", invalid, 1U);
  auto expired_result = manager->Commit("operator", expired, 1U);
  auto unknown_result = manager->Commit("operator", unknown, 1U);

  ASSERT_TRUE(invalid_result.ok());
  ASSERT_TRUE(expired_result.ok());
  ASSERT_TRUE(unknown_result.ok());
  EXPECT_FALSE(invalid_result.value());
  EXPECT_FALSE(expired_result.value());
  EXPECT_FALSE(unknown_result.value());

  const auto valid = IssueAndValidate(manager.get());
  auto commit = manager->Commit("operator", valid, 1U);
  ASSERT_TRUE(commit.ok());
  EXPECT_TRUE(commit.value());

  manager->Clear();
  auto terminal_invalid = manager->Commit("operator", invalid, 1U);
  ASSERT_FALSE(terminal_invalid.ok());
  ExpectNonceError(terminal_invalid.error());
}

}  // namespace
}  // namespace camera_firmware::rtsp
