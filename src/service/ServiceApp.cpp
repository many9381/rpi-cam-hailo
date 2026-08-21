#include "camera_firmware/service/ServiceApp.hpp"

#include "SessionStreamRegistryInternal.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <json/writer.h>
#include <openssl/crypto.h>
#include <trantor/net/EventLoop.h>

#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/common/ThreadTuning.hpp"
#include "camera_firmware/security/AuditLogService.hpp"
#include "camera_firmware/security/UserManagementService.hpp"
#include "camera_firmware/service/AuditLogHttp.hpp"
#include "camera_firmware/service/RuntimeSettingsHttp.hpp"
#include "camera_firmware/service/SecurityRequestGate.hpp"
#include "camera_firmware/service/ServiceStartup.hpp"
#include "camera_firmware/service/SystemProtectionHttp.hpp"
#include "camera_firmware/service/UserManagementHttp.hpp"

namespace camera_firmware::service {
namespace internal {

#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
namespace {

struct LiveMp4StartPause {
  std::mutex mutex;
  std::promise<void>* published{nullptr};
  std::shared_future<void> release_publication;
  std::atomic_size_t stop_calls_during_start{0U};
};

LiveMp4StartPause& LiveMp4StartPauseForTesting() {
  static LiveMp4StartPause pause;
  return pause;
}

void PauseAfterLiveMp4StartPublicationForTesting() noexcept {
  std::promise<void>* published = nullptr;
  std::shared_future<void> release_publication;
  {
    auto& pause = LiveMp4StartPauseForTesting();
    std::lock_guard lock(pause.mutex);
    published = pause.published;
    release_publication = pause.release_publication;
    pause.published = nullptr;
    pause.release_publication = {};
  }
  if (published != nullptr) {
    try {
      published->set_value();
    } catch (...) {
    }
  }
  if (release_publication.valid()) {
    release_publication.wait();
  }
}

void RecordLiveMp4StopDuringStartForTesting() noexcept {
  LiveMp4StartPauseForTesting().stop_calls_during_start.fetch_add(
      1U, std::memory_order_relaxed);
}

}  // namespace

void SetLiveMp4StartPublicationPauseForTesting(
    std::promise<void>* published,
    std::shared_future<void> release_publication) noexcept {
  auto& pause = LiveMp4StartPauseForTesting();
  std::lock_guard lock(pause.mutex);
  pause.published = published;
  pause.release_publication = std::move(release_publication);
  pause.stop_calls_during_start.store(0U, std::memory_order_relaxed);
}

std::size_t LiveMp4StopCallsDuringStartForTesting() noexcept {
  return LiveMp4StartPauseForTesting().stop_calls_during_start.load(
      std::memory_order_relaxed);
}

namespace {
std::atomic_bool fail_next_detection_sse_event_merge{false};
std::atomic_bool fail_next_runtime_callback_lease_allocation{false};
std::atomic_bool fail_next_live_mp4_pump_allocation{false};
std::atomic_bool force_next_login_role_invalid{false};
std::atomic_bool fail_next_user_management_pre_submit{false};
std::atomic_bool fail_next_authorization_dispatch_queue{false};
std::atomic_bool fail_next_terminal_response_queue{false};
using UserManagementRequestBodyCleanupObserverForTesting = void (*)(
    std::size_t,
    bool,
    bool) noexcept;
std::atomic<UserManagementRequestBodyCleanupObserverForTesting>
    user_management_request_body_cleanup_observer{nullptr};
}

void FailNextDetectionSseEventMergeForTesting() noexcept {
  fail_next_detection_sse_event_merge.store(true, std::memory_order_release);
}

bool ConsumeDetectionSseEventMergeFailureForTesting() noexcept {
  return fail_next_detection_sse_event_merge.exchange(
      false, std::memory_order_acq_rel);
}

void FailNextRuntimeCallbackLeaseAllocationForTesting() noexcept {
  fail_next_runtime_callback_lease_allocation.store(
      true, std::memory_order_release);
}

bool ConsumeRuntimeCallbackLeaseAllocationFailureForTesting() noexcept {
  return fail_next_runtime_callback_lease_allocation.exchange(
      false, std::memory_order_acq_rel);
}

void FailNextLiveMp4PumpAllocationForTesting() noexcept {
  fail_next_live_mp4_pump_allocation.store(true, std::memory_order_release);
}

bool ConsumeLiveMp4PumpAllocationFailureForTesting() noexcept {
  return fail_next_live_mp4_pump_allocation.exchange(
      false, std::memory_order_acq_rel);
}

void ForceNextLoginRoleInvalidForTesting() noexcept {
  force_next_login_role_invalid.store(true, std::memory_order_release);
}

bool ConsumeForcedInvalidLoginRoleForTesting() noexcept {
  return force_next_login_role_invalid.exchange(false,
                                                  std::memory_order_acq_rel);
}

void FailNextUserManagementPreSubmitForTesting() noexcept {
  fail_next_user_management_pre_submit.store(true, std::memory_order_release);
}

void ResetUserManagementPreSubmitFailureForTesting() noexcept {
  fail_next_user_management_pre_submit.store(false, std::memory_order_release);
}

bool ConsumeUserManagementPreSubmitFailureForTesting() noexcept {
  return fail_next_user_management_pre_submit.exchange(
      false, std::memory_order_acq_rel);
}

void FailNextAuthorizationDispatchQueueForTesting() noexcept {
  fail_next_authorization_dispatch_queue.store(true,
                                                std::memory_order_release);
}

void ResetAuthorizationDispatchQueueFailureForTesting() noexcept {
  fail_next_authorization_dispatch_queue.store(false,
                                                std::memory_order_release);
}

bool ConsumeAuthorizationDispatchQueueFailureForTesting() noexcept {
  return fail_next_authorization_dispatch_queue.exchange(
      false, std::memory_order_acq_rel);
}

void FailNextTerminalResponseQueueForTesting() noexcept {
  fail_next_terminal_response_queue.store(true, std::memory_order_release);
}

void ResetTerminalResponseQueueFailureForTesting() noexcept {
  fail_next_terminal_response_queue.store(false, std::memory_order_release);
}

bool ConsumeTerminalResponseQueueFailureForTesting() noexcept {
  return fail_next_terminal_response_queue.exchange(false,
                                                      std::memory_order_acq_rel);
}

void SetUserManagementRequestBodyCleanupObserverForTesting(
    UserManagementRequestBodyCleanupObserverForTesting observer) noexcept {
  user_management_request_body_cleanup_observer.store(
      observer, std::memory_order_release);
}

void ResetUserManagementRequestBodyCleanupObserverForTesting() noexcept {
  user_management_request_body_cleanup_observer.store(
      nullptr, std::memory_order_release);
}

void NotifyUserManagementRequestBodyCleanupForTesting(
    std::size_t source_size,
    bool source_cleansed,
    bool copied_to_secure_owner) noexcept {
  const auto observer = user_management_request_body_cleanup_observer.load(
      std::memory_order_acquire);
  if (observer == nullptr) {
    return;
  }
  try {
    observer(source_size, source_cleansed, copied_to_secure_owner);
  } catch (...) {
  }
}
#else
namespace {

void PauseAfterLiveMp4StartPublicationForTesting() noexcept {}

void RecordLiveMp4StopDuringStartForTesting() noexcept {}

bool ConsumeDetectionSseEventMergeFailureForTesting() noexcept {
  return false;
}

bool ConsumeRuntimeCallbackLeaseAllocationFailureForTesting() noexcept {
  return false;
}

bool ConsumeLiveMp4PumpAllocationFailureForTesting() noexcept {
  return false;
}

bool ConsumeForcedInvalidLoginRoleForTesting() noexcept {
  return false;
}

bool ConsumeUserManagementPreSubmitFailureForTesting() noexcept {
  return false;
}

bool ConsumeAuthorizationDispatchQueueFailureForTesting() noexcept {
  return false;
}

bool ConsumeTerminalResponseQueueFailureForTesting() noexcept {
  return false;
}

void NotifyUserManagementRequestBodyCleanupForTesting(
    std::size_t,
    bool,
    bool) noexcept {}

}  // namespace
#endif

class RuntimeCallbackLifecycle final
    : public std::enable_shared_from_this<RuntimeCallbackLifecycle> {
 public:
  class Lease;

  class CallbackScope final {
   public:
    ~CallbackScope() {
      active_callback_ = previous_;
    }

    CallbackScope(const CallbackScope&) = delete;
    CallbackScope& operator=(const CallbackScope&) = delete;

   private:
    friend class RuntimeCallbackLifecycle::Lease;

    explicit CallbackScope(std::shared_ptr<RuntimeCallbackLifecycle> owner)
        : owner_(std::move(owner)), previous_(active_callback_) {
      active_callback_ = owner_.get();
    }

    std::shared_ptr<RuntimeCallbackLifecycle> owner_;
    RuntimeCallbackLifecycle* previous_{nullptr};
  };

  class Lease final {
   public:
    ~Lease() {
      if (armed_ && owner_) {
        owner_->Release();
      }
    }

    Lease(const Lease&) = delete;
    Lease& operator=(const Lease&) = delete;

    [[nodiscard]] CallbackScope EnterCallback() const {
      return CallbackScope(owner_);
    }

   private:
    friend class RuntimeCallbackLifecycle;

    explicit Lease(std::shared_ptr<RuntimeCallbackLifecycle> owner)
        : owner_(std::move(owner)) {}

    void Arm() noexcept {
      armed_ = true;
    }

    std::shared_ptr<RuntimeCallbackLifecycle> owner_;
    bool armed_{false};
  };

  [[nodiscard]] std::shared_ptr<Lease> TryAcquire() {
    auto unarmed = std::unique_ptr<Lease>(new Lease(shared_from_this()));
    if (ConsumeRuntimeCallbackLeaseAllocationFailureForTesting()) {
      throw std::bad_alloc();
    }
    auto lease = std::shared_ptr<Lease>(std::move(unarmed));
    std::lock_guard lock(mutex_);
    if (!accepting_) {
      return {};
    }
    ++active_;
    lease->Arm();
    return lease;
  }

  void CloseAdmission() noexcept {
    std::lock_guard lock(mutex_);
    accepting_ = false;
  }

  void WaitForDrain() noexcept {
    std::unique_lock lock(mutex_);
    changed_.wait(lock, [this] { return active_ == 0U; });
  }

  [[nodiscard]] bool IsCurrentCallbackThread() const noexcept {
    return active_callback_ == this;
  }

 private:
  void Release() noexcept {
    {
      std::lock_guard lock(mutex_);
      if (active_ != 0U) {
        --active_;
      }
    }
    changed_.notify_all();
  }

  std::mutex mutex_;
  std::condition_variable changed_;
  std::size_t active_{0U};
  bool accepting_{true};
  inline static thread_local RuntimeCallbackLifecycle* active_callback_ =
      nullptr;
};

class LiveMp4PumpManager;

// trantor's AsyncStream::send() returning false conflates two situations:
// the per-connection pending-byte cap was reached (transient backpressure)
// or the peer connection is gone. Pump() retries the same chunk on this
// cadence rather than dropping it, and gives up only after this much
// continuous stall -- at which point a genuine disconnect (or lease
// revocation, checked every retry) exits the pump promptly regardless.
constexpr std::chrono::milliseconds kLiveMp4BackpressureRetryDelay{50};
constexpr std::chrono::seconds kLiveMp4BackpressureGiveUpAfter{10};

#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
namespace {

struct LiveMp4BackpressureTimingOverride {
  std::atomic<std::int64_t> retry_delay_ms{-1};
  std::atomic<std::int64_t> give_up_after_ms{-1};
};

LiveMp4BackpressureTimingOverride&
LiveMp4BackpressureTimingOverrideForTesting() {
  static LiveMp4BackpressureTimingOverride timing;
  return timing;
}

}  // namespace

void OverrideLiveMp4BackpressureTimingForTesting(
    std::chrono::milliseconds retry_delay,
    std::chrono::milliseconds give_up_after) noexcept {
  auto& timing = LiveMp4BackpressureTimingOverrideForTesting();
  timing.retry_delay_ms.store(retry_delay.count(), std::memory_order_relaxed);
  timing.give_up_after_ms.store(give_up_after.count(),
                                std::memory_order_relaxed);
}

void ResetLiveMp4BackpressureTimingForTesting() noexcept {
  auto& timing = LiveMp4BackpressureTimingOverrideForTesting();
  timing.retry_delay_ms.store(-1, std::memory_order_relaxed);
  timing.give_up_after_ms.store(-1, std::memory_order_relaxed);
}
#endif

std::chrono::milliseconds LiveMp4BackpressureRetryDelay() noexcept {
#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
  const auto override_ms = LiveMp4BackpressureTimingOverrideForTesting()
                               .retry_delay_ms.load(std::memory_order_relaxed);
  if (override_ms >= 0) {
    return std::chrono::milliseconds{override_ms};
  }
#endif
  return kLiveMp4BackpressureRetryDelay;
}

std::chrono::milliseconds LiveMp4BackpressureGiveUpAfter() noexcept {
#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
  const auto override_ms =
      LiveMp4BackpressureTimingOverrideForTesting().give_up_after_ms.load(
          std::memory_order_relaxed);
  if (override_ms >= 0) {
    return std::chrono::milliseconds{override_ms};
  }
#endif
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      kLiveMp4BackpressureGiveUpAfter);
}

class LiveMp4PumpState final {
 public:
  static std::shared_ptr<LiveMp4PumpState> Create(
      LiveMp4StreamHandle stream,
      std::size_t maximum_response_bytes,
      std::shared_ptr<SessionStreamLease> stream_lease) {
    struct OpenedStreamGuard {
      ~OpenedStreamGuard() {
        if (!armed || !stream.cancel) {
          return;
        }
        try {
          stream.cancel();
        } catch (...) {
        }
      }

      LiveMp4StreamHandle& stream;
      bool armed{true};
    } guard{stream};
    if (ConsumeLiveMp4PumpAllocationFailureForTesting()) {
      throw std::bad_alloc();
    }
    auto* raw_pump = new LiveMp4PumpState(
        std::move(stream), maximum_response_bytes, stream_lease);
    guard.armed = false;
    auto pump = std::shared_ptr<LiveMp4PumpState>(raw_pump);
    if (stream_lease) {
      std::weak_ptr weak_pump = pump;
      stream_lease->SetRevocationHandler([weak_pump] {
        if (const auto current = weak_pump.lock()) {
          current->CancelAndClose();
        }
      });
    }
    return pump;
  }

  ~LiveMp4PumpState() {
    CancelAndClose();
  }

  bool AttachOutput(trantor::AsyncStreamPtr output) {
    auto shared_output = std::shared_ptr<trantor::AsyncStream>(
        std::move(output));
    std::shared_ptr<trantor::AsyncStream> close_immediately;
    bool start = false;
    {
      std::lock_guard lock(mutex_);
      if (terminal_ || started_) {
        close_immediately = std::move(shared_output);
      } else {
        started_ = true;
        output_ = std::move(shared_output);
        start = true;
      }
    }
    Close(std::move(close_immediately));
    return start;
  }

  void Pump() noexcept {
    std::array<char, 16U * 1024U> buffer{};
    std::size_t sent_bytes = 0U;
    const bool unbounded = maximum_response_bytes_ == 0U;
    try {
      while (unbounded || sent_bytes < maximum_response_bytes_) {
        std::shared_ptr<SessionStreamLease> callback_lease;
        LiveMp4PumpManager* owner_manager = nullptr;
        if (!ActiveBeforeRead(callback_lease, owner_manager)) {
          break;
        }
        const auto capacity =
            unbounded ? buffer.size()
                      : std::min(buffer.size(),
                                 maximum_response_bytes_ - sent_bytes);
        std::size_t size = 0U;
        {
          SessionStreamRevocationScope revocation_scope(
              callback_lease, SessionStreamRevocationScope::Origin::kRead);
          MediaCallbackScope callback_scope(owner_manager);
          size = stream_.read(buffer.data(), capacity);
        }
        if (size == 0U || size > capacity) {
          break;
        }
        bool sent_ok = SendUnlessActive(buffer.data(), size);
        auto stall_started = std::chrono::steady_clock::time_point{};
        while (!sent_ok) {
          std::shared_ptr<SessionStreamLease> recheck_lease;
          LiveMp4PumpManager* recheck_manager = nullptr;
          if (!ActiveBeforeRead(recheck_lease, recheck_manager)) {
            break;  // revoked/terminal -- outer loop will observe and exit
          }
          const auto now = std::chrono::steady_clock::now();
          if (stall_started == std::chrono::steady_clock::time_point{}) {
            stall_started = now;
          } else if (now - stall_started >= LiveMp4BackpressureGiveUpAfter()) {
            break;  // peer genuinely dead or stalled beyond tolerance
          }
          std::this_thread::sleep_for(LiveMp4BackpressureRetryDelay());
          sent_ok = SendUnlessActive(buffer.data(), size);
        }
        if (!sent_ok) {
          break;
        }
        sent_bytes += size;
      }
    } catch (...) {
    }
    CancelAndClose();
  }

  void CancelAndClose() noexcept {
    terminal_requested_.store(true, std::memory_order_release);
    std::shared_ptr<trantor::AsyncStream> output;
    LiveMp4CancelCallback cancel;
    std::shared_ptr<SessionStreamLease> stream_lease;
    LiveMp4PumpManager* owner_manager = nullptr;
    bool defer_media_cancel = false;
    {
      std::unique_lock lock(mutex_);
      terminal_ = true;
      if (send_in_progress_) {
        if (sending_thread_ == std::this_thread::get_id() ||
            SessionStreamRevocationScope::HandlerOriginatesFromSend()) {
          finalization_pending_ = true;
          return;
        }
        send_changed_.wait(lock, [this] { return !send_in_progress_; });
      }
      defer_media_cancel =
          SessionStreamRevocationScope::HandlerOriginatesFromRead(
              stream_lease_);
      if (!output_closed_) {
        output_closed_ = true;
        output = std::move(output_);
      }
      if (!defer_media_cancel && !media_cancelled_) {
        media_cancelled_ = true;
        cancel = std::move(stream_.cancel);
      }
      if (!defer_media_cancel) {
        stream_lease = std::move(stream_lease_);
      }
      owner_manager = owner_manager_;
    }
    Close(std::move(output));
    if (defer_media_cancel) {
      return;
    }
    if (cancel) {
      try {
        SessionStreamRevocationScope revocation_scope(
            stream_lease, SessionStreamRevocationScope::Origin::kCancel);
        MediaCallbackScope callback_scope(owner_manager);
        cancel();
      } catch (...) {
      }
    }
    stream_lease.reset();
  }

 private:
  friend class LiveMp4PumpManager;

  class MediaCallbackScope final {
   public:
    explicit MediaCallbackScope(LiveMp4PumpManager* manager) noexcept
        : previous_manager_(active_media_callback_manager_) {
      active_media_callback_manager_ = manager;
    }

    ~MediaCallbackScope() {
      active_media_callback_manager_ = previous_manager_;
    }

    MediaCallbackScope(const MediaCallbackScope&) = delete;
    MediaCallbackScope& operator=(const MediaCallbackScope&) = delete;

   private:
    LiveMp4PumpManager* previous_manager_{nullptr};
  };

  LiveMp4PumpState(LiveMp4StreamHandle stream,
                   std::size_t maximum_response_bytes,
                   std::shared_ptr<SessionStreamLease> stream_lease) noexcept
      : stream_(std::move(stream)),
        maximum_response_bytes_(maximum_response_bytes),
        stream_lease_(std::move(stream_lease)) {}

  void SetOwnerManager(LiveMp4PumpManager* manager) noexcept {
    std::lock_guard lock(mutex_);
    if (owner_manager_ == nullptr) {
      owner_manager_ = manager;
    }
  }

  [[nodiscard]] static LiveMp4PumpManager*
  CurrentMediaCallbackManager() noexcept {
    return active_media_callback_manager_;
  }

  bool ActiveBeforeRead(
      std::shared_ptr<SessionStreamLease>& callback_lease,
      LiveMp4PumpManager*& owner_manager) {
    if (terminal_requested_.load(std::memory_order_acquire)) {
      return false;
    }
    std::lock_guard lock(mutex_);
    const bool active =
        !terminal_requested_.load(std::memory_order_relaxed) && !terminal_ &&
        (!stream_lease_ || !stream_lease_->revoked()) &&
        static_cast<bool>(stream_.read);
    if (active) {
      callback_lease = stream_lease_;
      owner_manager = owner_manager_;
    }
    return active;
  }

  bool SendUnlessActive(const char* data, std::size_t size) {
    if (terminal_requested_.load(std::memory_order_acquire)) {
      return false;
    }
    std::shared_ptr<trantor::AsyncStream> output;
    std::shared_ptr<SessionStreamLease> stream_lease;
    {
      std::lock_guard lock(mutex_);
      if (terminal_requested_.load(std::memory_order_relaxed) || terminal_ ||
          (stream_lease_ && stream_lease_->revoked()) || !output_ ||
          send_in_progress_) {
        return false;
      }
      output = output_;
      stream_lease = stream_lease_;
      send_in_progress_ = true;
      sending_thread_ = std::this_thread::get_id();
    }

    bool sent = false;
    std::exception_ptr failure;
    try {
      internal::SessionStreamRevocationScope revocation_scope(stream_lease);
      sent = output->send(data, size);
    } catch (...) {
      failure = std::current_exception();
    }

    bool finalize = false;
    {
      std::lock_guard lock(mutex_);
      send_in_progress_ = false;
      sending_thread_ = {};
      finalize = finalization_pending_ || terminal_ ||
                 terminal_requested_.load(std::memory_order_relaxed);
      finalization_pending_ = false;
    }
    send_changed_.notify_all();
    if (finalize) {
      CancelAndClose();
    }
    if (failure) {
      std::rethrow_exception(failure);
    }
    return sent && !terminal_requested_.load(std::memory_order_acquire);
  }

  static void Close(std::shared_ptr<trantor::AsyncStream> output) noexcept {
    if (!output) {
      return;
    }
    try {
      output->close();
    } catch (...) {
    }
  }

  std::mutex mutex_;
  std::condition_variable send_changed_;
  LiveMp4StreamHandle stream_;
  std::size_t maximum_response_bytes_{0U};
  std::shared_ptr<SessionStreamLease> stream_lease_;
  std::shared_ptr<trantor::AsyncStream> output_;
  std::atomic_bool terminal_requested_{false};
  bool terminal_{false};
  bool started_{false};
  bool output_closed_{false};
  bool media_cancelled_{false};
  bool send_in_progress_{false};
  bool finalization_pending_{false};
  std::thread::id sending_thread_;
  LiveMp4PumpManager* owner_manager_{nullptr};
  inline static thread_local LiveMp4PumpManager*
      active_media_callback_manager_ = nullptr;
};

class LiveMp4PumpManager final {
 public:
  explicit LiveMp4PumpManager(
      std::size_t maximum_pumps = kMaximumServiceConnections)
      : maximum_pumps_(
            std::min(maximum_pumps, kMaximumServiceConnections)) {
    entries_.reserve(maximum_pumps_);
    pump_thread_ids_.reserve(maximum_pumps_);
  }

  ~LiveMp4PumpManager() {
    Stop();
  }

  void Start(const std::shared_ptr<LiveMp4PumpState>& pump,
             trantor::AsyncStreamPtr output) {
    if (pump) {
      pump->SetOwnerManager(this);
    }
    bool admitted = false;
    {
      std::lock_guard lock(mutex_);
      if (lifecycle_ == Lifecycle::kRunning) {
        ++starts_in_progress_;
        admitted = true;
      }
    }
    if (!admitted) {
      if (pump) {
        (void)pump->AttachOutput(std::move(output));
        pump->CancelAndClose();
      }
      return;
    }

    const auto finish_start = [this] {
      {
        std::lock_guard lock(mutex_);
        --starts_in_progress_;
      }
      lifecycle_changed_.notify_all();
    };
    bool cancel_pump = false;
    bool pump_published = false;
    try {
      auto completed = TakeCompleted();
      Join(completed);
      if (pump && pump->AttachOutput(std::move(output))) {
        std::lock_guard lock(mutex_);
        if (lifecycle_ != Lifecycle::kRunning ||
            entries_.size() >= maximum_pumps_) {
          cancel_pump = true;
        } else {
          auto done = std::make_shared<std::atomic_bool>(false);
          auto start = std::make_shared<std::promise<void>>();
          auto start_signal = start->get_future().share();
          std::thread thread([pump, done, start_signal] {
            common::NameCurrentThread("live-pump");
            start_signal.wait();
            pump->Pump();
            done->store(true, std::memory_order_release);
          });
          pump_thread_ids_.push_back(thread.get_id());
          entries_.push_back(Entry{pump, std::move(thread), std::move(done)});
          start->set_value();
          pump_published = true;
        }
      }
    } catch (...) {
      cancel_pump = static_cast<bool>(pump);
    }
    if (pump_published) {
      PauseAfterLiveMp4StartPublicationForTesting();
    }
    finish_start();
    if (cancel_pump) {
      pump->CancelAndClose();
    }
  }

  void Stop() noexcept {
    std::vector<Entry> entries;
    std::array<std::shared_ptr<LiveMp4PumpState>,
               kMaximumServiceConnections>
        pump_thread_cancellations;
    std::size_t pump_thread_cancellation_count = 0U;
    bool called_from_pump_thread = false;
    const auto current_thread = std::this_thread::get_id();
    {
      std::unique_lock lock(mutex_);
      const bool pump_thread = IsPumpThreadLocked(current_thread);
      if (lifecycle_ == Lifecycle::kStopped) {
        return;
      }
      if (!pump_thread && starts_in_progress_ != 0U) {
        RecordLiveMp4StopDuringStartForTesting();
      }
      lifecycle_ = Lifecycle::kStopping;
      if (pump_thread) {
        called_from_pump_thread = true;
        for (const auto& entry : entries_) {
          if (pump_thread_cancellation_count >=
              pump_thread_cancellations.size()) {
            break;
          }
          pump_thread_cancellations[pump_thread_cancellation_count++] =
              entry.pump;
        }
      } else {
        if (stop_owner_active_) {
          lifecycle_changed_.wait(
              lock, [this] { return lifecycle_ == Lifecycle::kStopped; });
          return;
        }
        stop_owner_active_ = true;
        lifecycle_changed_.wait(
            lock, [this] { return starts_in_progress_ == 0U; });
        entries.swap(entries_);
      }
    }
    if (called_from_pump_thread) {
      for (std::size_t index = 0U;
           index < pump_thread_cancellation_count; ++index) {
        pump_thread_cancellations[index]->CancelAndClose();
      }
      return;
    }
    for (const auto& entry : entries) {
      if (entry.pump) {
        const auto& pump = entry.pump;
        pump->CancelAndClose();
      }
    }
    Join(entries);
    {
      std::lock_guard lock(mutex_);
      pump_thread_ids_.clear();
      stop_owner_active_ = false;
      lifecycle_ = Lifecycle::kStopped;
    }
    lifecycle_changed_.notify_all();
  }

  [[nodiscard]] bool IsPumpThread() const noexcept {
    std::lock_guard lock(mutex_);
    return IsPumpThreadLocked(std::this_thread::get_id());
  }

  [[nodiscard]] bool IsCurrentMediaCallback() const noexcept {
    return LiveMp4PumpState::CurrentMediaCallbackManager() == this;
  }

 private:
  struct Entry {
    std::shared_ptr<LiveMp4PumpState> pump;
    std::thread thread;
    std::shared_ptr<std::atomic_bool> done;
  };

  enum class Lifecycle {
    kRunning,
    kStopping,
    kStopped,
  };

  std::vector<Entry> TakeCompleted() {
    std::vector<Entry> completed;
    std::lock_guard lock(mutex_);
    completed.reserve(entries_.size());
    auto entry = entries_.begin();
    while (entry != entries_.end()) {
      if (entry->done->load(std::memory_order_acquire)) {
        const auto id = entry->thread.get_id();
        std::erase(pump_thread_ids_, id);
        completed.push_back(std::move(*entry));
        entry = entries_.erase(entry);
      } else {
        ++entry;
      }
    }
    return completed;
  }

  static void Join(std::vector<Entry>& entries) noexcept {
    for (auto& entry : entries) {
      if (entry.thread.joinable()) {
        entry.thread.join();
      }
    }
  }

  [[nodiscard]] bool IsPumpThreadLocked(std::thread::id id) const noexcept {
    return std::find(pump_thread_ids_.begin(), pump_thread_ids_.end(), id) !=
           pump_thread_ids_.end();
  }

  const std::size_t maximum_pumps_;
  mutable std::mutex mutex_;
  std::condition_variable lifecycle_changed_;
  std::vector<Entry> entries_;
  std::vector<std::thread::id> pump_thread_ids_;
  std::size_t starts_in_progress_{0U};
  bool stop_owner_active_{false};
  Lifecycle lifecycle_{Lifecycle::kRunning};
};

}  // namespace internal

namespace {

struct ServiceState {
  ServiceInitArgs args;
  std::shared_ptr<security::AuthService> auth_service;
  std::shared_ptr<security::AuditLogService> audit_log_service;
  std::shared_ptr<security::UserManagementService> user_management_service;
  std::shared_ptr<BoundedWorker> security_worker;
  std::shared_ptr<BoundedWorker> runtime_settings_worker;
  std::shared_ptr<internal::LiveMp4PumpManager> live_pump_manager;
  std::shared_ptr<internal::RuntimeCallbackLifecycle> runtime_lifecycle;
  security::DeviceState device_state{security::DeviceState::kDefault};
  std::optional<std::string> runtime_pending_peer;
  // The plaintext of the per-device initial account, held for setup/status to
  // serve while the device is uninitialized. Guarded by StateMutex() like every
  // other member here, which is what makes it safe to read from Drogon's
  // several handler threads. Cleared once setup completes; never written to the
  // store, a log line, or an audit record.
  std::optional<security::InitialAccountCredential> initial_account;
  bool shutting_down{false};
};

constexpr std::size_t kMaximumTransportBodyBytes = 64U * 1024U;
static_assert(kMaximumTransportBodyBytes >
              kMaximumRuntimeSettingsBodyBytes);
constexpr std::chrono::milliseconds kServiceThreadStopTimeout{2000};
constexpr std::chrono::seconds kDetectionSsePendingTimeout{15};
constexpr std::uint32_t kDetectionSseReconnectMs{200};

double SafeMilliseconds(double milliseconds) {
  return std::isfinite(milliseconds) && milliseconds >= 0.0
             ? milliseconds
             : 0.0;
}

ServiceState& GlobalState() {
  static ServiceState state;
  return state;
}

std::mutex& StateMutex() {
  static std::mutex mutex;
  return mutex;
}

bool IsRegisteredApiRoute(std::string_view path, drogon::HttpMethod method) {
  if (path == "/api/v1/audit/status" ||
      path == "/api/v1/audit/events") {
    return method == drogon::Get;
  }
  if (path == "/api/v1/system/protection") {
    return method == drogon::Get;
  }
  if (path == "/api/v1/system/self-tests" ||
      path == "/api/v1/system/integrity-checks") {
    return method == drogon::Post;
  }
  if (path == "/api/v1/security/users") {
    return method == drogon::Get || method == drogon::Post;
  }
  constexpr std::string_view users_prefix = "/api/v1/security/users/";
  if (path.starts_with(users_prefix)) {
    const auto remainder = path.substr(users_prefix.size());
    const auto slash = remainder.find('/');
    if (slash == std::string_view::npos) {
      return method == drogon::Delete && !remainder.empty();
    }
    const auto id = remainder.substr(0U, slash);
    const auto suffix = remainder.substr(slash);
    return !id.empty() && method == drogon::Put &&
           (suffix == "/enabled" || suffix == "/password");
  }
  if (path == "/api/v1/security/management-ips") {
    return method == drogon::Get;
  }
  constexpr std::string_view management_ips_prefix =
      "/api/v1/security/management-ips/";
  if (path.starts_with(management_ips_prefix)) {
    const auto remainder = path.substr(management_ips_prefix.size());
    const auto slash = remainder.find('/');
    if (slash == std::string_view::npos) {
      return method == drogon::Post && !remainder.empty();
    }
    const auto role = remainder.substr(0U, slash);
    const auto id = remainder.substr(slash + 1U);
    return !role.empty() && !id.empty() &&
           id.find('/') == std::string_view::npos &&
           (method == drogon::Put || method == drogon::Delete);
  }
  if (path == "/api/v1/auth/password") {
    return method == drogon::Put;
  }
  if (method == drogon::Get) {
    if (path == "/api/v1/setup/status" || path == "/api/v1/auth/me" ||
        path == "/api/v1/health" ||
        path == "/api/v1/monitoring/cameras" || path == "/api/v1/cameras" ||
        path == "/api/v1/ai/detections" ||
        path == "/api/v1/ai/detections/stream" ||
        path == "/api/v1/stream" ||
        path == "/api/v1/settings/runtime") {
      return true;
    }
    constexpr std::string_view prefix = "/api/v1/cameras/";
    constexpr std::array<std::string_view, 2> suffixes = {
        "/snapshot.jpg", "/live.mp4"};
    for (const auto suffix : suffixes) {
      if (path.starts_with(prefix) && path.ends_with(suffix) &&
          path.size() > prefix.size() + suffix.size()) {
        const auto camera_id = path.substr(
            prefix.size(), path.size() - prefix.size() - suffix.size());
        if (camera_id.find('/') == std::string_view::npos) {
          return true;
        }
      }
    }
    return false;
  }
  if (method == drogon::Put && path == "/api/v1/settings/runtime") {
    return true;
  }
  return method == drogon::Post &&
         (path == "/api/v1/setup/initialize" ||
          path == "/api/v1/setup/runtime" ||
          path == "/api/v1/auth/login" ||
          path == "/api/v1/auth/logout" ||
          path == "/api/v1/auth/reauthenticate" ||
          path == "/api/v1/runtime/restart" ||
          path == "/api/v1/ai/restart" ||
          path == "/api/v1/settings/runtime/apply" ||
          path == "/api/v1/settings/runtime/discard");
}

std::string ExtractPublicHost(std::string_view public_base_url) {
  std::string_view authority = public_base_url;
  if (const std::size_t scheme_pos = authority.find("://");
      scheme_pos != std::string_view::npos) {
    authority.remove_prefix(scheme_pos + 3);
  }

  const std::size_t path_pos = authority.find_first_of("/?#");
  if (path_pos != std::string_view::npos) {
    authority = authority.substr(0, path_pos);
  }

  if (authority.empty()) {
    return "127.0.0.1";
  }

  if (const std::size_t at_pos = authority.rfind('@');
      at_pos != std::string_view::npos) {
    authority.remove_prefix(at_pos + 1);
  }

  if (authority.front() == '[') {
    const std::size_t bracket_pos = authority.find(']');
    if (bracket_pos != std::string_view::npos) {
      return std::string(authority.substr(0, bracket_pos + 1));
    }
    return std::string(authority);
  }

  const std::size_t port_pos = authority.find(':');
  if (port_pos != std::string_view::npos) {
    authority = authority.substr(0, port_pos);
  }

  if (authority.empty()) {
    return "127.0.0.1";
  }
  return std::string(authority);
}

std::string BuildRtspUrl(std::string_view public_base_url,
                         const config::SecureRtspConfig& secure_rtsp) {
  const std::string scheme = secure_rtsp.control_tls ? "rtsps" : "rtsp";
  return scheme + "://" + ExtractPublicHost(public_base_url) + ":" +
         std::to_string(secure_rtsp.port) + secure_rtsp.mount;
}

Json::Value BuildCameraStatusJsonValue(const CameraStatus& camera) {
  Json::Value json(Json::objectValue);
  json["id"] = camera.id;
  json["state"] = camera.state;
  json["snapshot_available"] = camera.snapshot_available;
  json["width"] = camera.width;
  json["height"] = camera.height;
  json["configured_fps"] = camera.configured_fps;
  json["capture_fps"] = camera.capture_fps;
  json["encoded_fps"] = camera.encoded_fps;
  json["captured_frames"] = Json::UInt64(camera.captured_frames);
  json["encoded_frames"] = Json::UInt64(camera.encoded_frames);
  json["capture_error_count"] = Json::UInt64(camera.capture_error_count);
  json["encode_error_count"] = Json::UInt64(camera.encode_error_count);
  json["last_encode_ms"] = camera.last_encode_ms;
  json["encoded_ring_overruns"] = Json::UInt64(camera.encoded_ring_overruns);
  return json;
}

Json::Value BuildMonitoringCameraJsonValue(const CameraStatus& camera) {
  Json::Value json(Json::objectValue);
  json["id"] = camera.id;
  json["state"] = camera.state;
  json["width"] = camera.width;
  json["height"] = camera.height;
  json["snapshot_available"] = camera.snapshot_available;
  return json;
}

Json::Value BuildSnapshotUnavailableJson() {
  Json::Value json(Json::objectValue);
  json["code"] = "E_NO_SNAPSHOT";
  json["message"] = "snapshot unavailable";
  return json;
}

Json::Value BuildLiveErrorJson(std::string_view code) {
  Json::Value json(Json::objectValue);
  if (code == "E_LIVE_CAPACITY") {
    json["code"] = "E_LIVE_CAPACITY";
    json["message"] = "live preview reader capacity is full";
  } else {
    json["code"] = "E_LIVE_UNAVAILABLE";
    json["message"] = "live preview is unavailable";
  }
  return json;
}

drogon::HttpResponsePtr BuildManagedLiveMp4Response(
    const CancellableLiveMp4OpenCallback& live_stream_callback,
    const std::string& camera_id,
    std::size_t maximum_response_bytes,
    std::shared_ptr<SessionStreamLease> stream_lease,
    std::shared_ptr<internal::LiveMp4PumpManager> pump_manager,
    std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease>
        runtime_lease = {});

CancellableLiveMp4OpenCallback AdaptLegacyLiveMp4OpenCallback(
    LiveMp4OpenCallback legacy_callback) {
  if (!legacy_callback) {
    return {};
  }
  return [legacy_callback = std::move(legacy_callback)](
             const std::string& requested_camera_id) mutable
      -> common::Result<LiveMp4StreamHandle> {
    auto opened = legacy_callback(requested_camera_id);
    if (!opened.ok()) {
      return common::Result<LiveMp4StreamHandle>::Err(opened.error());
    }
    auto stream = std::make_shared<LiveMp4StreamCallback>(
        std::move(opened).value());
    if (!*stream) {
      return common::Result<LiveMp4StreamHandle>::Err(
          {"E_LIVE_UNAVAILABLE", "live preview is unavailable"});
    }
    return common::Result<LiveMp4StreamHandle>::Ok({
        .read = [stream](char* output, std::size_t capacity) {
          return (*stream)(output, capacity);
        },
        .cancel = [stream] { (void)(*stream)(nullptr, 0U); },
    });
  };
}

Json::Value BuildSecureMediaJson(
    const config::SecureRtspConfig& secure_rtsp) {
  Json::Value json(Json::objectValue);
  json["control_scheme"] = secure_rtsp.control_tls ? "rtsps" : "rtsp";
  json["media_profile"] = secure_rtsp.media_srtp ? "RTP/SAVPF" : "RTP/AVP";
  json["keying"] =
      secure_rtsp.media_srtp && secure_rtsp.keying == "sdes-over-rtsps"
          ? "SDES-over-RTSPS"
          : "none";
  json["requires_tls_control_channel"] =
      secure_rtsp.media_srtp && secure_rtsp.keying == "sdes-over-rtsps";
  return json;
}

drogon::HttpResponsePtr JsonResponse(Json::Value json,
                                     drogon::HttpStatusCode status =
                                         drogon::k200OK) {
  auto response = drogon::HttpResponse::newHttpJsonResponse(std::move(json));
  response->setStatusCode(status);
  return response;
}

std::optional<std::string_view> SerializeUserRole(
    security::UserRole role) noexcept {
  switch (role) {
    case security::UserRole::kAdministrator:
      return "administrator";
    case security::UserRole::kViewer:
      return "viewer";
  }
  return std::nullopt;
}

using DrogonCallback =
    std::function<void(const drogon::HttpResponsePtr&)>;

class TerminalResponse {
 public:
  TerminalResponse(trantor::EventLoop* event_loop, DrogonCallback callback)
      : event_loop_(event_loop), callback_(std::move(callback)) {}

  void Respond(drogon::HttpResponsePtr response) {
    if (completed_.exchange(true)) {
      return;
    }
    callback_(response);
  }

  void Queue(drogon::HttpResponsePtr response) {
    if (completed_.exchange(true)) {
      return;
    }
    try {
      if (internal::ConsumeTerminalResponseQueueFailureForTesting()) {
        throw std::bad_alloc();
      }
      auto queued_callback = callback_;
      event_loop_->queueInLoop(
          [callback = std::move(queued_callback),
           response = std::move(response)]() mutable { callback(response); });
    } catch (...) {
      completed_.store(false);
      throw;
    }
  }

 private:
  trantor::EventLoop* event_loop_;
  DrogonCallback callback_;
  std::atomic<bool> completed_{false};
};

}  // namespace

namespace internal {

#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
std::optional<std::string_view> SerializeUserRoleForTesting(
    security::UserRole role) noexcept {
  return SerializeUserRole(role);
}

bool HasRetainedUserManagementServiceForTesting() noexcept {
  std::scoped_lock lock(StateMutex());
  return static_cast<bool>(GlobalState().user_management_service);
}

common::Result<std::vector<security::ManagedUser>>
ListRetainedUsersForTesting() {
  std::shared_ptr<security::UserManagementService> service;
  std::shared_ptr<security::SecurityStore> store;
  {
    std::scoped_lock lock(StateMutex());
    service = GlobalState().user_management_service;
    store = GlobalState().args.security_store;
  }
  if (!service || !store) {
    return common::Result<std::vector<security::ManagedUser>>::Err(
        {"E_USER_MANAGEMENT_UNAVAILABLE", "user management unavailable"});
  }
  return service->ListUsers();
}
#endif

class DetectionSsePendingResponse {
 public:
  using ResponseCallback =
      std::function<void(const drogon::HttpResponsePtr&)>;

  static std::shared_ptr<DetectionSsePendingResponse> Create(
      DetectionSnapshotProvider detection_snapshot_provider,
      ResponseCallback response_callback,
      std::shared_ptr<SessionStreamLease> stream_lease,
      std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease>
          runtime_lease);

  DetectionSsePendingResponse(const DetectionSsePendingResponse&) = delete;
  DetectionSsePendingResponse& operator=(
      const DetectionSsePendingResponse&) = delete;

  bool AttachSubscription(const DetectionEventSubscriber& subscriber,
                          ai::DetectionBus::Handler handler);
  bool CompleteInitialSnapshotIfChanged(std::string_view last_event_id);
  void SetTimeoutCancellation(std::function<void()> cancel_timeout);
  void CompleteWithEvent(const ai::DetectionEvent& event);
  void CompleteWithSnapshot();
  void Revoke();

 private:
  struct State;

  class RuntimeCallbackGuard {
   public:
    explicit RuntimeCallbackGuard(DetectionSsePendingResponse& owner) noexcept
        : owner_(owner) {}
    ~RuntimeCallbackGuard() { owner_.EndRuntimeCallback(); }

    RuntimeCallbackGuard(const RuntimeCallbackGuard&) = delete;
    RuntimeCallbackGuard& operator=(const RuntimeCallbackGuard&) = delete;

   private:
    DetectionSsePendingResponse& owner_;
  };

  explicit DetectionSsePendingResponse(std::shared_ptr<State> state) noexcept;
  bool BeginRuntimeCallback(bool claim_terminal);
  bool ClaimTerminalFromActiveCallback();
  void EndRuntimeCallback() noexcept;
  std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease>
  EndRuntimeCallbackLocked();
  void CompleteFromProvider(const ai::DetectionEvent* event);
  void Finish(std::vector<ai::DetectionEvent> events);

  std::shared_ptr<State> state_;
};

}  // namespace internal

namespace {

using internal::DetectionSsePendingResponse;

class HttpCallback {
 public:
  HttpCallback() = default;
  explicit HttpCallback(std::shared_ptr<TerminalResponse> terminal)
      : terminal_(std::move(terminal)) {}

  void operator()(drogon::HttpResponsePtr response) const {
    terminal_->Respond(std::move(response));
  }

  void Queue(drogon::HttpResponsePtr response) const {
    terminal_->Queue(std::move(response));
  }

  explicit operator bool() const noexcept {
    return static_cast<bool>(terminal_);
  }

 private:
  std::shared_ptr<TerminalResponse> terminal_;
};

struct AuthorizedRequest {
  std::optional<security::Principal> principal;
  std::shared_ptr<SessionStreamLease> stream_lease;
};

using AuthorizedContinuation =
    std::function<void(AuthorizedRequest, HttpCallback)>;

drogon::HttpResponsePtr SecurityErrorResponse(const common::Error& error) {
  Json::Value body(Json::objectValue);
  body["code"] = error.code;
  drogon::HttpStatusCode status = drogon::k403Forbidden;
  std::string message = "request denied";
  if (error.code == "E_AUTHENTICATION_REQUIRED" ||
      error.code == "E_AUTHENTICATION_FAILED") {
    status = drogon::k401Unauthorized;
    message = "authentication required";
  } else if (error.code == "E_MANAGEMENT_REAUTHENTICATION_REQUIRED") {
    status = drogon::k401Unauthorized;
    message = "management reauthentication required";
  } else if (error.code == "E_SECURITY_UNAVAILABLE" ||
             error.code == "E_AUTHENTICATION_UNAVAILABLE" ||
             error.code == "E_AUTHENTICATION_STORE") {
    status = drogon::k503ServiceUnavailable;
    body["code"] = "E_SECURITY_UNAVAILABLE";
    message = "security service unavailable";
  } else if (error.code == "E_REQUEST_TOO_LARGE") {
    status = drogon::k413RequestEntityTooLarge;
    message = "request could not be processed";
  } else if (error.code == "E_INVALID_REQUEST") {
    status = drogon::k400BadRequest;
    message = "request could not be processed";
  }
  body["message"] = message;
  return JsonResponse(std::move(body), status);
}

drogon::HttpResponsePtr SecurityUnavailableResponse() {
  return SecurityErrorResponse(
      {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
}

drogon::HttpResponsePtr BootstrapErrorResponse(const common::Error& error) {
  // E_MANAGEMENT_IP_INVALID and E_MANAGEMENT_IP_LIMIT come from the submitted
  // management-IP list and are the operator's to fix, so they answer 400 with
  // their own code rather than collapsing into a 503 the wizard would report
  // as a device fault.
  const bool validation =
      error.code == "E_BOOTSTRAP_PEER" ||
      error.code.starts_with("E_USERNAME_") ||
      error.code.starts_with("E_PASSWORD_") ||
      error.code.starts_with("E_MANAGEMENT_IP_");
  if (!validation && error.code != "E_BOOTSTRAP_UNAVAILABLE") {
    return SecurityUnavailableResponse();
  }
  Json::Value body(Json::objectValue);
  body["code"] = error.code;
  body["message"] = validation ? "device setup request is invalid"
                                : "device setup is already complete";
  return JsonResponse(std::move(body),
                      validation ? drogon::k400BadRequest
                                 : drogon::k409Conflict);
}

class AsyncAuthorization final
    : public std::enable_shared_from_this<AsyncAuthorization> {
 public:
  AsyncAuthorization(trantor::EventLoop* event_loop,
                     DrogonCallback callback,
                     AuthorizedContinuation continuation)
      : event_loop_(event_loop),
        terminal_(HttpCallback(std::make_shared<TerminalResponse>(
            event_loop, std::move(callback)))),
        continuation_(std::move(continuation)) {}

  void Deny(common::Error error) {
    auto response = SecurityErrorResponse(error);
    Dispatch([response = std::move(response)](HttpCallback terminal,
                                               AuthorizedContinuation) {
      terminal(response);
    });
  }

  void Allow(AuthorizedRequest authorized_request) {
    Dispatch([authorized_request = std::move(authorized_request)](
                 HttpCallback terminal,
                 AuthorizedContinuation continuation) mutable {
      try {
        continuation(std::move(authorized_request), terminal);
      } catch (...) {
        terminal(SecurityUnavailableResponse());
      }
    });
  }

 private:
  using DispatchAction =
      std::function<void(HttpCallback, AuthorizedContinuation)>;

  void Dispatch(DispatchAction action) {
    if (completed_.exchange(true)) {
      return;
    }
    try {
      if (internal::ConsumeAuthorizationDispatchQueueFailureForTesting()) {
        throw std::bad_alloc();
      }
      auto terminal = terminal_;
      auto continuation = continuation_;
      event_loop_->queueInLoop(
          [action = std::move(action), terminal = std::move(terminal),
           continuation = std::move(continuation)]() mutable {
            action(std::move(terminal), std::move(continuation));
          });
    } catch (...) {
      completed_.store(false);
      throw;
    }
  }

  trantor::EventLoop* event_loop_;
  HttpCallback terminal_;
  AuthorizedContinuation continuation_;
  std::atomic<bool> completed_{false};
};

struct SecurityDependencies {
  bool enabled{false};
  bool shutting_down{false};
  std::string expected_origin;
  std::shared_ptr<security::SecurityStore> store;
  std::shared_ptr<security::AuthService> auth_service;
  std::shared_ptr<SessionStreamRegistry> stream_registry;
  std::shared_ptr<BoundedWorker> worker;
};

struct AdministratorUserDependencies {
  bool shutting_down{false};
  std::shared_ptr<security::UserManagementService> service;
  std::shared_ptr<BoundedWorker> worker;
};

struct AuditLogDependencies {
  bool shutting_down{false};
  std::shared_ptr<security::AuditLogService> service;
  std::shared_ptr<BoundedWorker> worker;

  [[nodiscard]] bool Available() const noexcept {
    return !shutting_down && service && worker;
  }
};

struct RuntimeSettingsDependencies {
  bool security_enabled{false};
  bool shutting_down{false};
  RuntimeSettingsSnapshotCallback snapshot;
  RuntimeSettingsSaveCallback save;
  RuntimeSettingsApplyCallback apply;
  RuntimeSettingsDiscardCallback discard;
  ProtectionRuntimeAllowedCallback protection_runtime_allowed;
  ProtectionRuntimeControlGate protection_runtime_control_gate;
  std::shared_ptr<BoundedWorker> worker;

  [[nodiscard]] bool Available() const noexcept {
    return security_enabled && !shutting_down && snapshot && save && apply &&
           discard && worker;
  }
};

struct SystemProtectionDependencies {
  bool security_enabled{false};
  bool shutting_down{false};
  ProtectionSnapshotCallback snapshot;
  ProtectionStartCheckCallback start;
  std::shared_ptr<internal::RuntimeCallbackLifecycle> runtime_lifecycle;

  [[nodiscard]] bool Available() const noexcept {
    return security_enabled && !shutting_down && snapshot && start &&
           runtime_lifecycle;
  }
};

bool HasCompleteRuntimeSettingsCallbacks(const ServiceInitArgs& args) {
  return args.runtime_settings_snapshot_callback &&
         args.runtime_settings_save_callback &&
         args.runtime_settings_apply_callback &&
         args.runtime_settings_discard_callback;
}

RuntimeSettingsDependencies CopyRuntimeSettingsDependencies() {
  std::scoped_lock lock(StateMutex());
  const auto& state = GlobalState();
  return {
      state.args.app_config != nullptr &&
          state.args.app_config->security.enabled,
      state.shutting_down,
      state.args.runtime_settings_snapshot_callback,
      state.args.runtime_settings_save_callback,
      state.args.runtime_settings_apply_callback,
      state.args.runtime_settings_discard_callback,
      state.args.protection_runtime_allowed_callback,
      state.args.protection_runtime_control_gate,
      state.runtime_settings_worker,
  };
}

SystemProtectionDependencies CopySystemProtectionDependencies() {
  std::scoped_lock lock(StateMutex());
  const auto& state = GlobalState();
  return {
      state.args.app_config != nullptr &&
          state.args.app_config->security.enabled,
      state.shutting_down,
      state.args.protection_snapshot_callback,
      state.args.protection_start_check_callback,
      state.runtime_lifecycle,
  };
}

common::Result<security::ProtectionActor> BuildProtectionActor(
    const drogon::HttpRequestPtr& request,
    const AuthorizedRequest& authorized_request) {
  if (!request || !authorized_request.principal.has_value()) {
    return common::Result<security::ProtectionActor>::Err(
        {"E_PROTECTION_UNAVAILABLE", "system protection is unavailable"});
  }
  auto peer = NormalizePeerIp(request->peerAddr().toIp());
  if (!peer.ok()) {
    return common::Result<security::ProtectionActor>::Err(
        {"E_PROTECTION_UNAVAILABLE", "system protection is unavailable"});
  }
  security::ProtectionActor actor;
  actor.user_id = authorized_request.principal->user_id;
  actor.username = authorized_request.principal->username;
  actor.peer_ip = std::move(peer).value();
  return common::Result<security::ProtectionActor>::Ok(std::move(actor));
}

bool RuntimeControlAllowed(
    const ProtectionRuntimeAllowedCallback& protection_runtime_allowed) {
  if (!protection_runtime_allowed) {
    return false;
  }
  try {
    return protection_runtime_allowed();
  } catch (...) {
    return false;
  }
}

bool RuntimeSettingsBecameUnavailable(
    const std::shared_ptr<BoundedWorker>& worker) {
  std::scoped_lock lock(StateMutex());
  const auto& state = GlobalState();
  return state.shutting_down || !state.runtime_settings_worker ||
         state.runtime_settings_worker != worker;
}

SecurityDependencies CopySecurityDependencies() {
  std::scoped_lock lock(StateMutex());
  const auto& state = GlobalState();
  return {state.args.app_config != nullptr &&
              state.args.app_config->security.enabled,
          state.shutting_down,
          state.args.public_base_url,
          state.args.security_store,
          state.auth_service,
          state.args.stream_registry,
          state.security_worker};
}

AdministratorUserDependencies CopyAdministratorUserDependencies() {
  std::scoped_lock lock(StateMutex());
  const auto& state = GlobalState();
  return {state.shutting_down, state.user_management_service,
          state.security_worker};
}

AuditLogDependencies CopyAuditLogDependencies() {
  std::scoped_lock lock(StateMutex());
  const auto& state = GlobalState();
  return {state.shutting_down, state.audit_log_service,
          state.security_worker};
}

common::Result<security::UserMutationContext> BuildUserMutationContext(
    const drogon::HttpRequestPtr& request,
    const AuthorizedRequest& authorized_request) {
  if (!request || !authorized_request.principal.has_value()) {
    return common::Result<security::UserMutationContext>::Err(
        {"E_AUTHENTICATION_REQUIRED", "authentication required"});
  }
  auto peer = NormalizePeerIp(request->peerAddr().toIp());
  if (!peer.ok()) {
    return common::Result<security::UserMutationContext>::Err(
        {"E_USER_MANAGEMENT_UNAVAILABLE", "user management unavailable"});
  }
  security::UserMutationContext context;
  context.actor = *authorized_request.principal;
  context.normalized_peer_ip = std::move(peer).value();
  return common::Result<security::UserMutationContext>::Ok(
      std::move(context));
}

void CleanseSecretRequestBody(const drogon::HttpRequestPtr& request,
                              std::string_view body,
                              bool copied_to_secure_owner) noexcept {
  bool source_cleansed = true;
  if (!body.empty()) {
    OPENSSL_cleanse(const_cast<char*>(body.data()), body.size());
    source_cleansed = std::all_of(body.begin(), body.end(), [](char value) {
      return value == '\0';
    });
  }
  try {
    request->setBody(std::string{});
  } catch (...) {
  }
  internal::NotifyUserManagementRequestBodyCleanupForTesting(
      body.size(), source_cleansed, copied_to_secure_owner);
}

common::Result<common::SecureBytes> CopySecretRequestBody(
    const drogon::HttpRequestPtr& request) {
  if (!request) {
    return common::Result<common::SecureBytes>::Err(
        {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
  }
  const std::string_view body = request->getBody();
  if (body.size() > kMaximumSecurityBodyBytes) {
    CleanseSecretRequestBody(request, body, false);
    return common::Result<common::SecureBytes>::Err(
        {"E_REQUEST_TOO_LARGE", "request could not be processed"});
  }
  try {
    common::SecureBytes secure_body;
    if (!body.empty()) {
      secure_body.assign(reinterpret_cast<const unsigned char*>(body.data()),
                         body.size());
    }
    CleanseSecretRequestBody(request, body, true);
    return common::Result<common::SecureBytes>::Ok(std::move(secure_body));
  } catch (...) {
    CleanseSecretRequestBody(request, body, false);
    return common::Result<common::SecureBytes>::Err(
        {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
  }
}

bool RequiresSessionStreamLease(std::string_view path,
                                std::string_view method) {
  if (method != "GET") {
    return false;
  }
  if (path == "/api/v1/ai/detections/stream") {
    return true;
  }
  constexpr std::string_view camera_prefix = "/api/v1/cameras/";
  constexpr std::string_view live_suffix = "/live.mp4";
  return path.starts_with(camera_prefix) && path.ends_with(live_suffix) &&
         path.size() > camera_prefix.size() + live_suffix.size();
}

const security::SessionIdentity& ServiceLifecycleIdentity() {
  static const security::SessionIdentity identity = [] {
    security::SessionIdentity value;
    value.bytes.fill(0xa5U);
    return value;
  }();
  return identity;
}

void AuthorizeRequest(const drogon::HttpRequestPtr& request,
                      DrogonCallback callback,
                      AuthorizedContinuation continuation) {
  auto completion = std::make_shared<AsyncAuthorization>(
      drogon::app().getLoop(), std::move(callback), std::move(continuation));
  try {
    const auto dependencies = CopySecurityDependencies();
    if (dependencies.shutting_down) {
      completion->Deny(
          {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
      return;
    }
    if (!dependencies.enabled) {
      AuthorizedRequest authorized_request;
      bool shutting_down = false;
      {
        std::scoped_lock lock(StateMutex());
        auto& state = GlobalState();
        shutting_down = state.shutting_down;
        if (!shutting_down && request && state.args.stream_registry &&
            RequiresSessionStreamLease(request->path(),
                                       request->methodString())) {
          authorized_request.stream_lease =
              state.args.stream_registry->Acquire(ServiceLifecycleIdentity());
        }
      }
      if (shutting_down) {
        completion->Deny(
            {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
      } else {
        completion->Allow(std::move(authorized_request));
      }
      return;
    }
    if (!request || !dependencies.store || !dependencies.auth_service ||
        !dependencies.stream_registry || !dependencies.worker) {
      completion->Deny(
          {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
      return;
    }

    auto normalized_peer = NormalizePeerIp(request->peerAddr().toIp());
    if (!normalized_peer.ok()) {
      completion->Deny({"E_ACCESS_DENIED", "request denied"});
      return;
    }
    SecurityRequestContext context;
    context.path = request->path();
    context.method = request->methodString();
    context.normalized_peer_ip = std::move(normalized_peer).value();
    context.origin = request->getHeader("origin");
    context.expected_origin = dependencies.expected_origin;
    context.has_management_header =
        request->getHeader("x-camera-request") == "management";
    std::shared_ptr<common::SecureBytes> session_token;
    auto parsed_token =
        ParseSessionCookieHeaders(request->getRawCookieHeaders());
    if (parsed_token.ok()) {
      session_token = std::make_shared<common::SecureBytes>(
          std::move(parsed_token).value());
    }

    auto submitted = dependencies.worker->Submit(
        [context = std::move(context), session_token,
         dependencies, completion]() mutable {
          try {
            auto state = dependencies.store->State();
            if (!state.ok()) {
              completion->Deny(
                  {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
              return;
            }
            std::optional<std::string> runtime_pending_peer;
            security::DeviceState process_state;
            {
              std::scoped_lock lock(StateMutex());
              runtime_pending_peer = GlobalState().runtime_pending_peer;
              process_state = GlobalState().device_state;
            }
            context.state = runtime_pending_peer.has_value()
                                ? security::DeviceState::kDefault
                                : process_state;
            const bool setup_initialize =
                context.path == "/api/v1/setup/initialize";
            const bool setup_runtime =
                context.path == "/api/v1/setup/runtime";
            // While runtime_pending_peer is set, the gate's kDefault block
            // also admits auth/login, auth/logout and auth/me (Task 2). By
            // this point Initialize() has already created the real
            // administrator account and its management-ip entry, so those
            // routes act on live credentials, not the discarded initial
            // account. They get the same peer pin as setup/initialize and
            // setup/runtime: only the peer who confirmed setup may use them
            // until the runtime finishes starting. A non-pinned peer is
            // denied here, before AuthService spends a password
            // verification and an unconditional audit-trail write on it.
            const bool runtime_pending_scoped_route =
                setup_initialize || setup_runtime ||
                context.path == "/api/v1/auth/login" ||
                context.path == "/api/v1/auth/logout" ||
                context.path == "/api/v1/auth/me";
            if (runtime_pending_scoped_route &&
                runtime_pending_peer.has_value() &&
                context.normalized_peer_ip != *runtime_pending_peer) {
              completion->Deny({"E_ACCESS_DENIED", "request denied"});
              return;
            }
            const bool login = context.path == "/api/v1/auth/login" &&
                               context.method == "POST";
            if (context.state == security::DeviceState::kOperational &&
                !setup_initialize) {
              auto management = dependencies.store->IsManagementPeer(
                  context.normalized_peer_ip);
              if (!management.ok()) {
                completion->Deny({"E_SECURITY_UNAVAILABLE",
                                  "security service unavailable"});
                return;
              }
              context.peer_is_management = management.value();
              if (!login && context.peer_is_management && session_token) {
                if (session_token->size() != 0U) {
                  const auto activity =
                      RouteRefreshesManagementDeadline(context.path,
                                                       context.method)
                          ? security::ManagementActivity::kManagement
                          : security::ManagementActivity::kNone;
                  auto principal = dependencies.auth_service->Verify(
                      {session_token->data(), session_token->size()},
                      context.normalized_peer_ip, activity);
                  if (principal.ok()) {
                    context.principal = std::move(principal).value();
                  } else if (principal.error().code ==
                             "E_AUTHENTICATION_UNAVAILABLE") {
                    completion->Deny({"E_SECURITY_UNAVAILABLE",
                                      "security service unavailable"});
                    return;
                  }
                }
              }
            } else if (context.state == security::DeviceState::kDefault &&
                       !login && session_token &&
                       session_token->size() != 0U) {
              // The other arm of the same two-valued state. Without it
              // auth/me and setup/initialize have no principal to check and
              // deny every request in default state, including the initial
              // account's own.
              //
              // The management-peer precondition the operational arm applies
              // is not repeated here, and cannot be: an uninitialized device
              // has no management_ips row. Nothing is given up by dropping it.
              // A genuinely uninitialized device has no management peers to
              // distinguish, and during the runtime_pending window the peer
              // pin above has already narrowed this to the single peer that
              // confirmed setup — which is the management peer Initialize()
              // just registered.
              //
              // ManagementActivity::kNone: none of the four routes reachable
              // here is a management operation, so none should extend a
              // management-authority deadline. Verify() still refuses a
              // session whose deadline has already lapsed.
              auto principal = dependencies.auth_service->Verify(
                  {session_token->data(), session_token->size()},
                  context.normalized_peer_ip,
                  security::ManagementActivity::kNone);
              if (principal.ok()) {
                context.principal = std::move(principal).value();
              } else if (principal.error().code ==
                         "E_AUTHENTICATION_UNAVAILABLE") {
                completion->Deny({"E_SECURITY_UNAVAILABLE",
                                  "security service unavailable"});
                return;
              }
            }
            auto authorized = AuthorizeSecurityRequest(context);
            if (!authorized.ok()) {
              completion->Deny(authorized.error());
              return;
            }
            AuthorizedRequest authorized_request;
            authorized_request.principal = std::move(context.principal);
            if (authorized_request.principal.has_value() &&
                RequiresSessionStreamLease(context.path, context.method)) {
              authorized_request.stream_lease =
                  dependencies.stream_registry->Acquire(
                      authorized_request.principal->session_identity);
            }
            completion->Allow(std::move(authorized_request));
          } catch (...) {
            completion->Deny(
                {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
          }
        });
    if (!submitted.ok()) {
      completion->Deny(submitted.error());
    }
  } catch (...) {
    try {
      completion->Deny(
          {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
    } catch (...) {
    }
  }
}

void QueueResponse(trantor::EventLoop* event_loop,
                   const HttpCallback& callback,
                   drogon::HttpResponsePtr response) {
  (void)event_loop;
  callback.Queue(std::move(response));
}

drogon::HttpResponsePtr AuditLogUnavailableResponse() {
  return BuildAuditLogErrorResponse(
      {"E_AUDIT_UNAVAILABLE", "audit records unavailable"});
}

DrogonCallback AuditRouteCallback(DrogonCallback callback) {
  return [callback = std::move(callback)](
             const drogon::HttpResponsePtr& response) {
    if (response &&
        response->statusCode() == drogon::k503ServiceUnavailable) {
      callback(AuditLogUnavailableResponse());
      return;
    }
    callback(response);
  };
}

void QueueAuditLogResponse(trantor::EventLoop* event_loop,
                           const HttpCallback& callback,
                           drogon::HttpResponsePtr response) noexcept {
  try {
    QueueResponse(event_loop, callback, std::move(response));
  } catch (...) {
    try {
      QueueResponse(event_loop, callback, AuditLogUnavailableResponse());
    } catch (...) {
    }
  }
}

void SubmitAuthorizedAuditStatus(
    security::Principal principal,
    AuditLogDependencies dependencies,
    const HttpCallback& callback,
    trantor::EventLoop* event_loop) {
  if (!dependencies.Available()) {
    callback(AuditLogUnavailableResponse());
    return;
  }
  const auto submitted = dependencies.worker->Submit(
      [service = dependencies.service, principal = std::move(principal),
       callback, event_loop]() mutable {
        drogon::HttpResponsePtr response;
        try {
          const auto status = service->ReadStatus(principal);
          response = status.ok()
                         ? JsonResponse(BuildAuditStatusJson(status.value()))
                         : BuildAuditLogErrorResponse(status.error());
        } catch (...) {
          response = AuditLogUnavailableResponse();
        }
        QueueAuditLogResponse(event_loop, callback, std::move(response));
      });
  if (!submitted.ok()) {
    callback(AuditLogUnavailableResponse());
  }
}

void SubmitAuthorizedAuditEvents(
    security::Principal principal,
    security::AuditQueryParameters parameters,
    AuditLogDependencies dependencies,
    const HttpCallback& callback,
    trantor::EventLoop* event_loop) {
  if (!dependencies.Available()) {
    callback(AuditLogUnavailableResponse());
    return;
  }
  const auto submitted = dependencies.worker->Submit(
      [service = dependencies.service, principal = std::move(principal),
       parameters = std::move(parameters), callback, event_loop]() mutable {
        drogon::HttpResponsePtr response;
        try {
          const auto events = service->ListEvents(parameters, principal);
          response = events.ok()
                         ? JsonResponse(BuildAuditEventPageJson(events.value()))
                         : BuildAuditLogErrorResponse(events.error());
        } catch (...) {
          response = AuditLogUnavailableResponse();
        }
        QueueAuditLogResponse(event_loop, callback, std::move(response));
      });
  if (!submitted.ok()) {
    callback(AuditLogUnavailableResponse());
  }
}

void HandleAuditStatusRequest(const drogon::HttpRequestPtr& request,
                              AuthorizedRequest authorized_request,
                              HttpCallback callback) {
  try {
    if (!authorized_request.principal.has_value() ||
        authorized_request.principal->role !=
            security::UserRole::kAdministrator) {
      callback(BuildAuditLogErrorResponse(
          {"E_AUDIT_FORBIDDEN", "administrator required"}));
      return;
    }
    if (!request || !request->getBody().empty()) {
      callback(BuildAuditLogErrorResponse(
          {"E_AUDIT_QUERY_INVALID", "request body must be empty"}));
      return;
    }
    const auto query = ValidateEmptyAuditStatusQuery(request->query());
    if (!query.ok()) {
      callback(BuildAuditLogErrorResponse(query.error()));
      return;
    }
    security::Principal principal =
        std::move(*authorized_request.principal);
    SubmitAuthorizedAuditStatus(std::move(principal),
                                CopyAuditLogDependencies(),
                                callback,
                                drogon::app().getLoop());
  } catch (...) {
    callback(AuditLogUnavailableResponse());
  }
}

void HandleAuditEventRequest(const drogon::HttpRequestPtr& request,
                             AuthorizedRequest authorized_request,
                             HttpCallback callback) {
  try {
    if (!authorized_request.principal.has_value() ||
        authorized_request.principal->role !=
            security::UserRole::kAdministrator) {
      callback(BuildAuditLogErrorResponse(
          {"E_AUDIT_FORBIDDEN", "administrator required"}));
      return;
    }
    if (!request || !request->getBody().empty()) {
      callback(BuildAuditLogErrorResponse(
          {"E_AUDIT_QUERY_INVALID", "request body must be empty"}));
      return;
    }
    auto query = ParseAuditEventQuery(request->query());
    if (!query.ok()) {
      callback(BuildAuditLogErrorResponse(query.error()));
      return;
    }
    security::Principal principal =
        std::move(*authorized_request.principal);
    auto parameters = std::move(query).value();
    SubmitAuthorizedAuditEvents(std::move(principal), std::move(parameters),
                                CopyAuditLogDependencies(),
                                callback,
                                drogon::app().getLoop());
  } catch (...) {
    callback(AuditLogUnavailableResponse());
  }
}

drogon::HttpResponsePtr RuntimeSettingsUnavailableResponse() {
  return BuildRuntimeSettingsErrorResponse(
      {"E_SETTINGS_UNAVAILABLE", "runtime settings are unavailable"});
}

drogon::HttpResponsePtr RuntimeSettingsBusyResponse() {
  return BuildRuntimeSettingsErrorResponse(
      {"E_SETTINGS_BUSY", "runtime settings are busy"});
}

void QueueRuntimeSettingsResult(
    trantor::EventLoop* event_loop,
    HttpCallback callback,
    common::Result<settings::RuntimeSettingsSnapshot> result) {
  if (result.ok()) {
    QueueResponse(event_loop, std::move(callback),
                  BuildRuntimeSettingsSnapshotResponse(result.value()));
    return;
  }
  QueueResponse(event_loop, std::move(callback),
                BuildRuntimeSettingsErrorResponse(result.error()));
}

std::string EncodeSessionToken(common::SecureBytes& token) {
  static constexpr std::array<char, 16> kHex = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string encoded(token.size() * 2U, '0');
  for (std::size_t index = 0; index < token.size(); ++index) {
    encoded[index * 2U] = kHex[token.data()[index] >> 4U];
    encoded[index * 2U + 1U] = kHex[token.data()[index] & 0x0fU];
  }
  token.clear();
  return encoded;
}

drogon::Cookie SessionCookie(std::string value, int max_age = -1) {
  drogon::Cookie cookie(std::string(kSessionCookieName), std::move(value));
  cookie.setSecure(true);
  cookie.setHttpOnly(true);
  cookie.setSameSite(drogon::Cookie::SameSite::kStrict);
  cookie.setPath("/");
  if (max_age >= 0) {
    cookie.setMaxAge(max_age);
  }
  return cookie;
}

std::string CompactJson(Json::Value json) {
  Json::StreamWriterBuilder writer;
  writer["indentation"] = "";
  return Json::writeString(writer, json);
}

class ThreadCompletionReporter {
 public:
  explicit ThreadCompletionReporter(
      std::shared_ptr<std::promise<void>> completion)
      : completion_(std::move(completion)) {}

  ~ThreadCompletionReporter() noexcept {
    if (!completion_) {
      return;
    }
    try {
      completion_->set_value();
    } catch (...) {
    }
  }

 private:
  std::shared_ptr<std::promise<void>> completion_;
};

void RegisterHandlers() {
  using namespace drogon;

  app().registerPreSendingAdvice(
      [](const HttpRequestPtr&, const HttpResponsePtr& response) {
        response->addHeader("Cache-Control", "no-store");
        response->addHeader("Strict-Transport-Security", "max-age=31536000");
        response->addHeader("X-Content-Type-Options", "nosniff");
        response->addHeader("Referrer-Policy", "no-referrer");
        response->addHeader("X-Frame-Options", "DENY");
        response->addHeader(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' blob:; object-src 'none'; "
            "media-src 'self' blob:; "
            "base-uri 'none'; "
            "frame-ancestors 'none'");
      });

  app().registerPreRoutingAdvice(
      [](const HttpRequestPtr& request, AdviceCallback&& callback,
         AdviceChainCallback&& chain) {
        const std::string_view path = request->path();
        const bool api = IsRegisteredApiRoute(path, request->method());
        const bool static_asset =
            request->method() == Get &&
            (path == "/" || path == "/index.html" || path == "/app.js" ||
             path == "/styles.css");
        if (api || static_asset) {
          chain();
          return;
        }
        Json::Value body(Json::objectValue);
        body["code"] = "E_NOT_FOUND";
        body["message"] = "resource not found";
        callback(JsonResponse(std::move(body), k404NotFound));
      });

  app().registerHandler(
      "/api/v1/setup/status",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        security::DeviceState state;
        bool runtime_pending = false;
        bool security_enabled = false;
        std::string initial_username;
        std::string initial_password;
        {
          std::scoped_lock lock(StateMutex());
          state = GlobalState().device_state;
          runtime_pending = GlobalState().runtime_pending_peer.has_value();
          security_enabled = GlobalState().args.app_config != nullptr &&
                             GlobalState().args.app_config->security.enabled;
          if (GlobalState().initial_account.has_value()) {
            const auto& account = *GlobalState().initial_account;
            initial_username = account.username;
            initial_password.assign(
                reinterpret_cast<const char*>(account.password.data()),
                account.password.size());
          }
        }
        if (!security_enabled) {
          callback(SecurityErrorResponse(
              {"E_ACCESS_DENIED", "request denied"}));
          return;
        }
        Json::Value body(Json::objectValue);
        const bool required = runtime_pending ||
                              state == security::DeviceState::kDefault;
        body["required"] = required;
        if (required) {
          auto peer = NormalizePeerIp(request->peerAddr().toIp());
          if (!peer.ok()) {
            callback(SecurityUnavailableResponse());
            return;
          }
          body["tls"] = "ready";
          body["peer_ip"] = std::move(peer).value();
          body["phase"] = runtime_pending ? "runtime_pending"
                                           : "administrator";
          // Only the administrator phase shows the initial credential; once the
          // device is operational both members are absent, not empty.
          if (!runtime_pending && !initial_username.empty()) {
            body["initial_username"] = initial_username;
            body["initial_password"] = initial_password;
          }
        }
        callback(JsonResponse(std::move(body)));
      },
      {Get});

  app().registerHandler(
      "/api/v1/setup/initialize",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        std::shared_ptr<common::SecureBytes> secure_body;
        std::optional<common::Error> body_error;
        try {
          auto copied = CopySecretRequestBody(request);
          if (copied.ok()) {
            secure_body = std::make_shared<common::SecureBytes>(
                std::move(copied).value());
          } else {
            body_error.emplace(copied.error());
          }
        } catch (...) {
          if (secure_body) {
            secure_body->clear();
          }
          callback(SecurityUnavailableResponse());
          return;
        }
        auto peer = NormalizePeerIp(request->peerAddr().toIp());
        const std::string actual_peer = peer.ok() ? peer.value() : "";
        AuthorizeRequest(
            request, std::move(callback),
            [request, actual_peer, secure_body,
             body_error = std::move(body_error)](
                AuthorizedRequest authorized_request,
                HttpCallback callback) mutable {
              // Claiming the administrator account requires proving you can
              // read the device's login screen. The generated password is the
              // whole of this feature's security value; if this endpoint stayed
              // sessionless, any peer that can reach the device could claim the
              // account without ever knowing it and the login screen would be
              // decorative.
              //
              // Checked before the body is parsed: an unauthenticated peer's
              // JSON is not worth reading.
              //
              // setup/runtime deliberately does not acquire this requirement.
              // It is the recovery path for a failed runtime_start(), and by
              // the time it runs the initial account has been deleted inside
              // Initialize()'s transaction, so no session could satisfy it.
              std::optional<std::string> initial_username;
              std::shared_ptr<security::BootstrapService> bootstrap;
              std::shared_ptr<BoundedWorker> worker;
              RuntimeStartCallback runtime_start;
              ProtectionRuntimeControlGate runtime_control_gate;
              {
                std::scoped_lock lock(StateMutex());
                bootstrap = GlobalState().args.bootstrap_service;
                worker = GlobalState().security_worker;
                runtime_start = GlobalState().args.runtime_start_callback;
                runtime_control_gate =
                    GlobalState().args.protection_runtime_control_gate;
                if (GlobalState().initial_account.has_value()) {
                  initial_username = GlobalState().initial_account->username;
                }
              }
              // Read and answered before the session check, not after it: with
              // security disabled the whole authorization path is skipped and
              // no request carries a principal, so checking the session first
              // would turn this route's "security unavailable" into a
              // misleading "authentication required".
              if (!bootstrap || !worker || actual_peer.empty()) {
                callback(SecurityUnavailableResponse());
                return;
              }
              if (!authorized_request.principal.has_value()) {
                callback(SecurityErrorResponse(
                    {"E_AUTHENTICATION_REQUIRED", "authentication required"}));
                return;
              }
              // Authenticated but not the account this endpoint belongs to.
              // Reachable only during the runtime_pending window, where the
              // administrator now exists and the initial account does not; an
              // empty `initial_username` fails closed for the same reason.
              if (!initial_username.has_value() ||
                  authorized_request.principal->username != *initial_username) {
                callback(SecurityErrorResponse(
                    {"E_ACCESS_DENIED", "request denied"}));
                return;
              }
              if (body_error.has_value()) {
                callback(SecurityErrorResponse(*body_error));
                return;
              }
              if (!secure_body) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto parsed = ParseSetupJson(
                  std::move(*secure_body), request->getHeader("content-type"));
              secure_body->clear();
              if (!parsed.ok()) {
                callback(SecurityErrorResponse(parsed.error()));
                return;
              }
              auto parsed_request =
                  std::make_shared<ParsedSetupRequest>(std::move(parsed).value());
              auto submitted = worker->Submit(
                  [parsed_request, actual_peer, bootstrap, runtime_start,
                   runtime_control_gate, callback,
                   event_loop = app().getLoop()]() mutable {
                    try {
                      security::BootstrapRequest bootstrap_request;
                      bootstrap_request.username = parsed_request->username;
                      bootstrap_request.password =
                          std::move(parsed_request->password);
                      bootstrap_request.confirmed_peer_ip =
                          parsed_request->confirmed_peer_ip;
                      bootstrap_request.actual_peer_ip = actual_peer;
                      bootstrap_request.management_ips =
                          std::move(parsed_request->management_ips);
                      bool transition_allowed = false;
                      {
                        std::scoped_lock lock(StateMutex());
                        const auto& state = GlobalState();
                        transition_allowed =
                            !state.runtime_pending_peer.has_value() &&
                            state.device_state == security::DeviceState::kDefault;
                      }
                      if (!transition_allowed) {
                        QueueResponse(
                            event_loop, std::move(callback),
                            SecurityErrorResponse(
                                {"E_ACCESS_DENIED", "request denied"}));
                        return;
                      }
                      auto initialized =
                          bootstrap->Initialize(std::move(bootstrap_request));
                      if (!initialized.ok()) {
                        QueueResponse(event_loop, std::move(callback),
                                      BootstrapErrorResponse(
                                          initialized.error()));
                        return;
                      }
                      {
                        std::scoped_lock lock(StateMutex());
                        GlobalState().runtime_pending_peer = actual_peer;
                        GlobalState().device_state =
                            security::DeviceState::kDefault;
                        // Initialize() deleted the initial account inside the
                        // transaction that just committed, so the plaintext is
                        // dead here, not at transition_completed below. If
                        // runtime_start() fails the device stays in
                        // runtime_pending indefinitely, and keeping it that
                        // long would both leave a dead credential resident and
                        // leave the setup/initialize guard above comparing
                        // against a name that no longer identifies anything —
                        // an administrator who took the initial account's name
                        // would match it.
                        GlobalState().initial_account.reset();
                      }
                      if (!runtime_start) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityUnavailableResponse());
                        return;
                      }
                      std::optional<common::Result<void>> runtime;
                      bool runtime_admitted = true;
                      if (runtime_control_gate) {
                        runtime_admitted = runtime_control_gate(
                            [&] { runtime = runtime_start(); });
                      } else {
                        runtime = runtime_start();
                      }
                      if (!runtime_admitted || !runtime.has_value() ||
                          !runtime->ok()) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityUnavailableResponse());
                        return;
                      }
                      bool transition_completed = false;
                      {
                        std::scoped_lock lock(StateMutex());
                        if (GlobalState().runtime_pending_peer.has_value() &&
                            *GlobalState().runtime_pending_peer == actual_peer) {
                          GlobalState().device_state =
                              security::DeviceState::kOperational;
                          GlobalState().runtime_pending_peer.reset();
                          // The account behind this plaintext was deleted in
                          // Initialize's transaction; drop the in-memory copy
                          // so setup/status stops serving it.
                          GlobalState().initial_account.reset();
                          transition_completed = true;
                        }
                      }
                      if (!transition_completed) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityUnavailableResponse());
                        return;
                      }
                      Json::Value response(Json::objectValue);
                      response["required"] = false;
                      response["runtime"] = "running";
                      QueueResponse(event_loop, std::move(callback),
                                    JsonResponse(std::move(response)));
                    } catch (...) {
                      QueueResponse(event_loop, std::move(callback),
                                    SecurityUnavailableResponse());
                    }
                  });
              if (!submitted.ok()) {
                callback(SecurityUnavailableResponse());
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/setup/runtime",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        auto peer = NormalizePeerIp(request->peerAddr().toIp());
        const std::string actual_peer = peer.ok() ? peer.value() : "";
        AuthorizeRequest(
            request, std::move(callback),
            [request, actual_peer](
                AuthorizedRequest, HttpCallback callback) {
              auto validated = ValidateEmptyJsonObject(
                  request->getBody(), request->getHeader("content-type"));
              if (!validated.ok()) {
                callback(SecurityErrorResponse(validated.error()));
                return;
              }
              std::shared_ptr<BoundedWorker> worker;
              RuntimeStartCallback runtime_start;
              ProtectionRuntimeControlGate runtime_control_gate;
              {
                std::scoped_lock lock(StateMutex());
                worker = GlobalState().security_worker;
                runtime_start = GlobalState().args.runtime_start_callback;
                runtime_control_gate =
                    GlobalState().args.protection_runtime_control_gate;
              }
              if (!worker || !runtime_start || actual_peer.empty()) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto submitted = worker->Submit(
                  [actual_peer, runtime_start, runtime_control_gate, callback,
                   event_loop = app().getLoop()]() mutable {
                    try {
                      bool transition_allowed = false;
                      {
                        std::scoped_lock lock(StateMutex());
                        const auto& state = GlobalState();
                        transition_allowed =
                            state.runtime_pending_peer.has_value() &&
                            *state.runtime_pending_peer == actual_peer &&
                            state.device_state == security::DeviceState::kDefault;
                      }
                      if (!transition_allowed) {
                        QueueResponse(
                            event_loop, std::move(callback),
                            SecurityErrorResponse(
                                {"E_ACCESS_DENIED", "request denied"}));
                        return;
                      }
                      std::optional<common::Result<void>> runtime;
                      bool runtime_admitted = true;
                      if (runtime_control_gate) {
                        runtime_admitted = runtime_control_gate(
                            [&] { runtime = runtime_start(); });
                      } else {
                        runtime = runtime_start();
                      }
                      if (!runtime_admitted || !runtime.has_value() ||
                          !runtime->ok()) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityUnavailableResponse());
                        return;
                      }
                      bool transition_completed = false;
                      {
                        std::scoped_lock lock(StateMutex());
                        auto& state = GlobalState();
                        if (state.runtime_pending_peer.has_value() &&
                            *state.runtime_pending_peer == actual_peer) {
                          state.device_state =
                              security::DeviceState::kOperational;
                          state.runtime_pending_peer.reset();
                          // Setup completed through the runtime-retry path; the
                          // initial account was already deleted by Initialize,
                          // so drop the plaintext here too.
                          state.initial_account.reset();
                          transition_completed = true;
                        }
                      }
                      if (!transition_completed) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityUnavailableResponse());
                        return;
                      }
                      Json::Value response(Json::objectValue);
                      response["required"] = false;
                      response["runtime"] = "running";
                      QueueResponse(event_loop, std::move(callback),
                                    JsonResponse(std::move(response)));
                    } catch (...) {
                      QueueResponse(event_loop, std::move(callback),
                                    SecurityUnavailableResponse());
                    }
                  });
              if (!submitted.ok()) {
                callback(SecurityUnavailableResponse());
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/auth/login",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        std::shared_ptr<common::SecureBytes> secure_body;
        std::optional<common::Error> body_error;
        try {
          auto copied = CopySecretRequestBody(request);
          if (copied.ok()) {
            secure_body = std::make_shared<common::SecureBytes>(
                std::move(copied).value());
          } else {
            body_error.emplace(copied.error());
          }
        } catch (...) {
          if (secure_body) {
            secure_body->clear();
          }
          callback(SecurityUnavailableResponse());
          return;
        }
        const std::string peer_ip = request->peerAddr().toIp();
        AuthorizeRequest(
            request, std::move(callback),
            [request, peer_ip, secure_body,
             body_error = std::move(body_error)](
                AuthorizedRequest, HttpCallback callback) mutable {
              if (body_error.has_value()) {
                callback(SecurityErrorResponse(*body_error));
                return;
              }
              if (!secure_body) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto parsed = ParseLoginJson(
                  std::move(*secure_body), request->getHeader("content-type"));
              secure_body->clear();
              if (!parsed.ok()) {
                callback(SecurityErrorResponse(parsed.error()));
                return;
              }
              std::shared_ptr<security::AuthService> auth;
              std::shared_ptr<BoundedWorker> worker;
              {
                std::scoped_lock lock(StateMutex());
                auth = GlobalState().auth_service;
                worker = GlobalState().security_worker;
              }
              if (!auth || !worker) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto parsed_request =
                  std::make_shared<ParsedLoginRequest>(std::move(parsed).value());
              auto submitted = worker->Submit(
                  [parsed_request, peer_ip, auth, callback,
                   event_loop = app().getLoop()]() mutable {
                    try {
                      security::LoginRequest login_request;
                      login_request.username = parsed_request->username;
                      login_request.password = std::move(parsed_request->password);
                      login_request.peer_ip = peer_ip;
                      auto login = auth->Login(std::move(login_request));
                      if (!login.ok()) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityErrorResponse(login.error()));
                        return;
                      }
                      auto result = std::move(login).value();
                      const auto role = SerializeUserRole(result.role);
                      if (!role.has_value()) {
                        result.session_token.clear();
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityUnavailableResponse());
                        return;
                      }
                      Json::Value response_body(Json::objectValue);
                      response_body["role"] = std::string(*role);
                      response_body["idle_expires_at_seconds"] =
                          static_cast<Json::Int64>(
                              result.idle_expires_at_seconds);
                      auto response = JsonResponse(std::move(response_body));
                      response->addCookie(SessionCookie(
                          EncodeSessionToken(result.session_token)));
                      QueueResponse(event_loop, std::move(callback),
                                    std::move(response));
                    } catch (...) {
                      QueueResponse(event_loop, std::move(callback),
                                    SecurityUnavailableResponse());
                    }
                  });
              if (!submitted.ok()) {
                callback(SecurityUnavailableResponse());
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/auth/me",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [request](AuthorizedRequest authorized_request,
                      HttpCallback callback) {
              auto& principal = authorized_request.principal;
              if (!principal.has_value()) {
                callback(SecurityErrorResponse(
                    {"E_AUTHENTICATION_REQUIRED", "authentication required"}));
                return;
              }
              const auto request_body =
                  ValidateEmptyRequestBody(request->getBody());
              if (!request_body.ok()) {
                callback(SecurityErrorResponse(request_body.error()));
                return;
              }
              const auto role = SerializeUserRole(principal->role);
              if (!role.has_value()) {
                callback(SecurityUnavailableResponse());
                return;
              }
              Json::Value body(Json::objectValue);
              body["username"] = principal->username;
              body["role"] = std::string(*role);
              callback(JsonResponse(std::move(body)));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/security/users",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [request](AuthorizedRequest authorized_request,
                      HttpCallback callback) {
              try {
                if (!authorized_request.principal.has_value()) {
                  callback(SecurityErrorResponse(
                      {"E_AUTHENTICATION_REQUIRED", "authentication required"}));
                  return;
                }
                const auto body = ValidateEmptyRequestBody(
                    request->getBody());
                if (!body.ok()) {
                  callback(BuildUserManagementErrorResponse(body.error()));
                  return;
                }
                const auto dependencies = CopyAdministratorUserDependencies();
                if (dependencies.shutting_down || !dependencies.service ||
                    !dependencies.worker) {
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                auto submitted = dependencies.worker->Submit(
                    [service = dependencies.service, callback,
                     event_loop = app().getLoop()]() mutable {
                      try {
                        auto listed = service->ListUsers();
                        if (!listed.ok()) {
                          QueueResponse(event_loop, std::move(callback),
                                        BuildUserManagementErrorResponse(
                                            listed.error()));
                          return;
                        }
                        Json::Value body(Json::objectValue);
                        Json::Value users(Json::arrayValue);
                        for (const auto& user : listed.value()) {
                          users.append(BuildManagedUserJson(user));
                        }
                        body["users"] = std::move(users);
                        QueueResponse(event_loop, std::move(callback),
                                      JsonResponse(std::move(body)));
                      } catch (...) {
                        QueueResponse(event_loop, std::move(callback),
                                      BuildUserManagementErrorResponse(
                                          {"E_USER_MANAGEMENT_UNAVAILABLE",
                                           "user management unavailable"}));
                      }
                    });
                if (!submitted.ok()) {
                  callback(BuildUserManagementErrorResponse(submitted.error()));
                }
              } catch (...) {
                callback(BuildUserManagementErrorResponse(
                    {"E_USER_MANAGEMENT_UNAVAILABLE",
                     "user management unavailable"}));
              }
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/security/users",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        std::shared_ptr<common::SecureBytes> secure_body;
        std::optional<common::Error> body_error;
        try {
          auto copied = CopySecretRequestBody(request);
          if (copied.ok()) {
            secure_body = std::make_shared<common::SecureBytes>(
                std::move(copied).value());
          } else {
            body_error.emplace(copied.error());
          }
        } catch (...) {
          if (secure_body) {
            secure_body->clear();
          }
          callback(BuildUserManagementErrorResponse(
              {"E_USER_MANAGEMENT_UNAVAILABLE",
               "user management unavailable"}));
          return;
        }
        AuthorizeRequest(
            request, std::move(callback),
            [request, secure_body,
             body_error = std::move(body_error)](
                AuthorizedRequest authorized_request,
                HttpCallback callback) mutable {
              std::shared_ptr<ParsedCreateViewerRequest> parsed_request;
              try {
                if (body_error.has_value()) {
                  callback(BuildUserManagementErrorResponse(*body_error));
                  return;
                }
                if (!secure_body) {
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                auto context =
                    BuildUserMutationContext(request, authorized_request);
                if (!context.ok()) {
                  callback(BuildUserManagementErrorResponse(context.error()));
                  return;
                }
                auto parsed = ParseCreateViewerJson(
                    std::move(*secure_body), request->getHeader("content-type"));
                secure_body->clear();
                if (!parsed.ok()) {
                  callback(BuildUserManagementErrorResponse(parsed.error()));
                  return;
                }
                if (internal::
                        ConsumeUserManagementPreSubmitFailureForTesting()) {
                  throw std::bad_alloc();
                }
                const auto dependencies = CopyAdministratorUserDependencies();
                if (dependencies.shutting_down || !dependencies.service ||
                    !dependencies.worker) {
                  parsed.value().password.clear();
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                parsed_request = std::make_shared<ParsedCreateViewerRequest>(
                    std::move(parsed).value());
                auto submitted = dependencies.worker->Submit(
                    [service = dependencies.service,
                     context = std::move(context).value(),
                     parsed_request, callback,
                     event_loop = app().getLoop()]() mutable {
                      try {
                        auto created = service->CreateViewer(
                            std::move(parsed_request->username),
                            std::move(parsed_request->password), context);
                        parsed_request->password.clear();
                        if (!created.ok()) {
                          QueueResponse(event_loop, std::move(callback),
                                        BuildUserManagementErrorResponse(
                                            created.error()));
                          return;
                        }
                        Json::Value body(Json::objectValue);
                        body["user"] = BuildManagedUserJson(created.value());
                        QueueResponse(event_loop, std::move(callback),
                                      JsonResponse(std::move(body), k201Created));
                      } catch (...) {
                        parsed_request->password.clear();
                        QueueResponse(event_loop, std::move(callback),
                                      BuildUserManagementErrorResponse(
                                          {"E_USER_MANAGEMENT_UNAVAILABLE",
                                           "user management unavailable"}));
                      }
                    });
                if (!submitted.ok()) {
                  parsed_request->password.clear();
                  callback(BuildUserManagementErrorResponse(submitted.error()));
                }
              } catch (...) {
                if (secure_body) {
                  secure_body->clear();
                }
                if (parsed_request) {
                  parsed_request->password.clear();
                }
                callback(BuildUserManagementErrorResponse(
                    {"E_USER_MANAGEMENT_UNAVAILABLE",
                     "user management unavailable"}));
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/security/users/{1}/enabled",
      [](const HttpRequestPtr& request, DrogonCallback&& callback,
         const std::string& raw_user_id) {
        AuthorizeRequest(
            request, std::move(callback),
            [request, raw_user_id](AuthorizedRequest authorized_request,
                                   HttpCallback callback) {
              try {
                auto context =
                    BuildUserMutationContext(request, authorized_request);
                if (!context.ok()) {
                  callback(BuildUserManagementErrorResponse(context.error()));
                  return;
                }
                auto user_id = ParseManagedResourceId(raw_user_id);
                auto parsed = ParseSetViewerEnabledJson(
                    request->getBody(), request->getHeader("content-type"));
                if (!user_id.ok()) {
                  callback(BuildUserManagementErrorResponse(user_id.error()));
                  return;
                }
                if (!parsed.ok()) {
                  callback(BuildUserManagementErrorResponse(parsed.error()));
                  return;
                }
                const auto dependencies = CopyAdministratorUserDependencies();
                if (dependencies.shutting_down || !dependencies.service ||
                    !dependencies.worker) {
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                auto submitted = dependencies.worker->Submit(
                    [service = dependencies.service, user_id = user_id.value(),
                     enabled = parsed.value().enabled,
                     context = std::move(context).value(), callback,
                     event_loop = app().getLoop()]() mutable {
                      try {
                        auto updated =
                            service->SetViewerEnabled(user_id, enabled, context);
                        if (!updated.ok()) {
                          QueueResponse(event_loop, std::move(callback),
                                        BuildUserManagementErrorResponse(
                                            updated.error()));
                          return;
                        }
                        Json::Value body(Json::objectValue);
                        body["updated"] = true;
                        QueueResponse(event_loop, std::move(callback),
                                      JsonResponse(std::move(body)));
                      } catch (...) {
                        QueueResponse(event_loop, std::move(callback),
                                      BuildUserManagementErrorResponse(
                                          {"E_USER_MANAGEMENT_UNAVAILABLE",
                                           "user management unavailable"}));
                      }
                    });
                if (!submitted.ok()) {
                  callback(BuildUserManagementErrorResponse(submitted.error()));
                }
              } catch (...) {
                callback(BuildUserManagementErrorResponse(
                    {"E_USER_MANAGEMENT_UNAVAILABLE",
                     "user management unavailable"}));
              }
            });
      },
      {Put});

  app().registerHandler(
      "/api/v1/security/users/{1}/password",
      [](const HttpRequestPtr& request, DrogonCallback&& callback,
         const std::string& raw_user_id) {
        std::shared_ptr<common::SecureBytes> secure_body;
        std::optional<common::Error> body_error;
        try {
          auto copied = CopySecretRequestBody(request);
          if (copied.ok()) {
            secure_body = std::make_shared<common::SecureBytes>(
                std::move(copied).value());
          } else {
            body_error.emplace(copied.error());
          }
        } catch (...) {
          if (secure_body) {
            secure_body->clear();
          }
          callback(BuildUserManagementErrorResponse(
              {"E_USER_MANAGEMENT_UNAVAILABLE",
               "user management unavailable"}));
          return;
        }
        AuthorizeRequest(
            request, std::move(callback),
            [request, raw_user_id, secure_body,
             body_error = std::move(body_error)](
                AuthorizedRequest authorized_request,
                HttpCallback callback) mutable {
              std::shared_ptr<ParsedPasswordResetRequest> parsed_request;
              try {
                if (body_error.has_value()) {
                  callback(BuildUserManagementErrorResponse(*body_error));
                  return;
                }
                if (!secure_body) {
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                auto context =
                    BuildUserMutationContext(request, authorized_request);
                if (!context.ok()) {
                  callback(BuildUserManagementErrorResponse(context.error()));
                  return;
                }
                auto user_id = ParseManagedResourceId(raw_user_id);
                if (!user_id.ok()) {
                  callback(BuildUserManagementErrorResponse(user_id.error()));
                  return;
                }
                auto parsed = ParsePasswordResetJson(
                    std::move(*secure_body), request->getHeader("content-type"));
                secure_body->clear();
                if (!parsed.ok()) {
                  callback(BuildUserManagementErrorResponse(parsed.error()));
                  return;
                }
                const auto dependencies = CopyAdministratorUserDependencies();
                if (dependencies.shutting_down || !dependencies.service ||
                    !dependencies.worker) {
                  parsed.value().password.clear();
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                parsed_request = std::make_shared<ParsedPasswordResetRequest>(
                    std::move(parsed).value());
                auto submitted = dependencies.worker->Submit(
                    [service = dependencies.service, user_id = user_id.value(),
                     context = std::move(context).value(), parsed_request,
                     callback,
                     event_loop = app().getLoop()]() mutable {
                      try {
                        auto reset = service->ResetViewerPassword(
                            user_id, std::move(parsed_request->password), context);
                        parsed_request->password.clear();
                        if (!reset.ok()) {
                          QueueResponse(event_loop, std::move(callback),
                                        BuildUserManagementErrorResponse(
                                            reset.error()));
                          return;
                        }
                        Json::Value body(Json::objectValue);
                        body["password_reset"] = true;
                        QueueResponse(event_loop, std::move(callback),
                                      JsonResponse(std::move(body)));
                      } catch (...) {
                        parsed_request->password.clear();
                        QueueResponse(event_loop, std::move(callback),
                                      BuildUserManagementErrorResponse(
                                          {"E_USER_MANAGEMENT_UNAVAILABLE",
                                           "user management unavailable"}));
                      }
                    });
                if (!submitted.ok()) {
                  parsed_request->password.clear();
                  callback(BuildUserManagementErrorResponse(submitted.error()));
                }
              } catch (...) {
                if (secure_body) {
                  secure_body->clear();
                }
                if (parsed_request) {
                  parsed_request->password.clear();
                }
                callback(BuildUserManagementErrorResponse(
                    {"E_USER_MANAGEMENT_UNAVAILABLE",
                     "user management unavailable"}));
              }
            });
      },
      {Put});

  app().registerHandler(
      "/api/v1/security/users/{1}",
      [](const HttpRequestPtr& request, DrogonCallback&& callback,
         const std::string& raw_user_id) {
        AuthorizeRequest(
            request, std::move(callback),
            [request, raw_user_id](AuthorizedRequest authorized_request,
                                   HttpCallback callback) {
              try {
                auto context =
                    BuildUserMutationContext(request, authorized_request);
                if (!context.ok()) {
                  callback(BuildUserManagementErrorResponse(context.error()));
                  return;
                }
                const auto body = ValidateEmptyRequestBody(request->getBody());
                const auto user_id = ParseManagedResourceId(raw_user_id);
                if (!body.ok()) {
                  callback(BuildUserManagementErrorResponse(body.error()));
                  return;
                }
                if (!user_id.ok()) {
                  callback(BuildUserManagementErrorResponse(user_id.error()));
                  return;
                }
                const auto dependencies = CopyAdministratorUserDependencies();
                if (dependencies.shutting_down || !dependencies.service ||
                    !dependencies.worker) {
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                auto submitted = dependencies.worker->Submit(
                    [service = dependencies.service, user_id = user_id.value(),
                     context = std::move(context).value(), callback,
                     event_loop = app().getLoop()]() mutable {
                      try {
                        auto deleted = service->DeleteViewer(user_id, context);
                        if (!deleted.ok()) {
                          QueueResponse(event_loop, std::move(callback),
                                        BuildUserManagementErrorResponse(
                                            deleted.error()));
                          return;
                        }
                        Json::Value body(Json::objectValue);
                        body["deleted"] = true;
                        QueueResponse(event_loop, std::move(callback),
                                      JsonResponse(std::move(body)));
                      } catch (...) {
                        QueueResponse(event_loop, std::move(callback),
                                      BuildUserManagementErrorResponse(
                                          {"E_USER_MANAGEMENT_UNAVAILABLE",
                                           "user management unavailable"}));
                      }
                    });
                if (!submitted.ok()) {
                  callback(BuildUserManagementErrorResponse(submitted.error()));
                }
              } catch (...) {
                callback(BuildUserManagementErrorResponse(
                    {"E_USER_MANAGEMENT_UNAVAILABLE",
                     "user management unavailable"}));
              }
            });
      },
      {Delete});

  app().registerHandler(
      "/api/v1/security/management-ips",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [request](AuthorizedRequest, HttpCallback callback) {
              try {
                const auto request_body =
                    ValidateEmptyRequestBody(request->getBody());
                if (!request_body.ok()) {
                  callback(BuildUserManagementErrorResponse(
                      request_body.error()));
                  return;
                }
                const auto dependencies = CopyAdministratorUserDependencies();
                if (dependencies.shutting_down || !dependencies.service ||
                    !dependencies.worker) {
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                auto peer = NormalizePeerIp(request->peerAddr().toIp());
                if (!peer.ok()) {
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                std::string current_peer_ip = std::move(peer).value();
                auto submitted = dependencies.worker->Submit(
                    [service = dependencies.service,
                     current_peer_ip = std::move(current_peer_ip), callback,
                     event_loop = app().getLoop()]() mutable {
                      try {
                        auto listed = service->ListManagementIps();
                        if (!listed.ok()) {
                          QueueResponse(event_loop, std::move(callback),
                                        BuildUserManagementErrorResponse(
                                            listed.error()));
                          return;
                        }
                        QueueResponse(event_loop, std::move(callback),
                                      JsonResponse(BuildManagementIpListJson(
                                          listed.value(), current_peer_ip)));
                      } catch (...) {
                        QueueResponse(event_loop, std::move(callback),
                                      BuildUserManagementErrorResponse(
                                          {"E_USER_MANAGEMENT_UNAVAILABLE",
                                           "user management unavailable"}));
                      }
                    });
                if (!submitted.ok()) {
                  callback(BuildUserManagementErrorResponse(submitted.error()));
                }
              } catch (...) {
                callback(BuildUserManagementErrorResponse(
                    {"E_USER_MANAGEMENT_UNAVAILABLE",
                     "user management unavailable"}));
              }
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/security/management-ips/{1}",
      [](const HttpRequestPtr& request, DrogonCallback&& callback,
         const std::string& raw_role) {
        AuthorizeRequest(
            request, std::move(callback),
            [request, raw_role](AuthorizedRequest authorized_request,
                                HttpCallback callback) {
              try {
                auto role = ParseManagedRole(raw_role);
                if (!role.ok()) {
                  callback(BuildUserManagementErrorResponse(role.error()));
                  return;
                }
                auto parsed = ParseManagementIpJson(
                    request->getBody(), request->getHeader("content-type"));
                if (!parsed.ok()) {
                  callback(BuildUserManagementErrorResponse(parsed.error()));
                  return;
                }
                auto context =
                    BuildUserMutationContext(request, authorized_request);
                if (!context.ok()) {
                  callback(BuildUserManagementErrorResponse(context.error()));
                  return;
                }
                const auto dependencies = CopyAdministratorUserDependencies();
                if (dependencies.shutting_down || !dependencies.service ||
                    !dependencies.worker) {
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                auto submitted = dependencies.worker->Submit(
                    [service = dependencies.service, role = role.value(),
                     address = std::move(parsed).value().address,
                     context = std::move(context).value(), callback,
                     event_loop = app().getLoop()]() mutable {
                      try {
                        auto created = service->AddManagementIp(
                            role, std::move(address), context);
                        address.clear();
                        if (!created.ok()) {
                          QueueResponse(event_loop, std::move(callback),
                                        BuildUserManagementErrorResponse(
                                            created.error()));
                          return;
                        }
                        Json::Value body(Json::objectValue);
                        body["management_ip"] =
                            BuildManagementIpJson(created.value());
                        QueueResponse(event_loop, std::move(callback),
                                      JsonResponse(std::move(body),
                                                   drogon::k201Created));
                      } catch (...) {
                        address.clear();
                        QueueResponse(event_loop, std::move(callback),
                                      BuildUserManagementErrorResponse(
                                          {"E_USER_MANAGEMENT_UNAVAILABLE",
                                           "user management unavailable"}));
                      }
                    });
                if (!submitted.ok()) {
                  callback(BuildUserManagementErrorResponse(submitted.error()));
                }
              } catch (...) {
                callback(BuildUserManagementErrorResponse(
                    {"E_USER_MANAGEMENT_UNAVAILABLE",
                     "user management unavailable"}));
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/security/management-ips/{1}/{2}",
      [](const HttpRequestPtr& request, DrogonCallback&& callback,
         const std::string& raw_role, const std::string& raw_id) {
        AuthorizeRequest(
            request, std::move(callback),
            [request, raw_role,
             raw_id](AuthorizedRequest authorized_request,
                     HttpCallback callback) {
              try {
                auto role = ParseManagedRole(raw_role);
                auto management_ip_id = ParseManagedResourceId(raw_id);
                if (!role.ok()) {
                  callback(BuildUserManagementErrorResponse(role.error()));
                  return;
                }
                if (!management_ip_id.ok()) {
                  callback(BuildUserManagementErrorResponse(
                      management_ip_id.error()));
                  return;
                }
                auto parsed = ParseManagementIpJson(
                    request->getBody(), request->getHeader("content-type"));
                if (!parsed.ok()) {
                  callback(BuildUserManagementErrorResponse(parsed.error()));
                  return;
                }
                auto context =
                    BuildUserMutationContext(request, authorized_request);
                if (!context.ok()) {
                  callback(BuildUserManagementErrorResponse(context.error()));
                  return;
                }
                const auto dependencies = CopyAdministratorUserDependencies();
                if (dependencies.shutting_down || !dependencies.service ||
                    !dependencies.worker) {
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                auto submitted = dependencies.worker->Submit(
                    [service = dependencies.service,
                     management_ip_id = management_ip_id.value(),
                     role = role.value(),
                     address = std::move(parsed).value().address,
                     context = std::move(context).value(), callback,
                     event_loop = app().getLoop()]() mutable {
                      try {
                        auto updated = service->UpdateManagementIp(
                            management_ip_id, role, std::move(address), context);
                        address.clear();
                        if (!updated.ok()) {
                          QueueResponse(event_loop, std::move(callback),
                                        BuildUserManagementErrorResponse(
                                            updated.error()));
                          return;
                        }
                        Json::Value body(Json::objectValue);
                        body["updated"] = true;
                        QueueResponse(event_loop, std::move(callback),
                                      JsonResponse(std::move(body)));
                      } catch (...) {
                        address.clear();
                        QueueResponse(event_loop, std::move(callback),
                                      BuildUserManagementErrorResponse(
                                          {"E_USER_MANAGEMENT_UNAVAILABLE",
                                           "user management unavailable"}));
                      }
                    });
                if (!submitted.ok()) {
                  callback(BuildUserManagementErrorResponse(submitted.error()));
                }
              } catch (...) {
                callback(BuildUserManagementErrorResponse(
                    {"E_USER_MANAGEMENT_UNAVAILABLE",
                     "user management unavailable"}));
              }
            });
      },
      {Put});

  app().registerHandler(
      "/api/v1/security/management-ips/{1}/{2}",
      [](const HttpRequestPtr& request, DrogonCallback&& callback,
         const std::string& raw_role, const std::string& raw_id) {
        AuthorizeRequest(
            request, std::move(callback),
            [request, raw_role,
             raw_id](AuthorizedRequest authorized_request,
                     HttpCallback callback) {
              try {
                auto role = ParseManagedRole(raw_role);
                auto management_ip_id = ParseManagedResourceId(raw_id);
                if (!role.ok()) {
                  callback(BuildUserManagementErrorResponse(role.error()));
                  return;
                }
                if (!management_ip_id.ok()) {
                  callback(BuildUserManagementErrorResponse(
                      management_ip_id.error()));
                  return;
                }
                const auto body = ValidateEmptyRequestBody(request->getBody());
                if (!body.ok()) {
                  callback(BuildUserManagementErrorResponse(body.error()));
                  return;
                }
                auto context =
                    BuildUserMutationContext(request, authorized_request);
                if (!context.ok()) {
                  callback(BuildUserManagementErrorResponse(context.error()));
                  return;
                }
                const auto dependencies = CopyAdministratorUserDependencies();
                if (dependencies.shutting_down || !dependencies.service ||
                    !dependencies.worker) {
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                auto submitted = dependencies.worker->Submit(
                    [service = dependencies.service,
                     management_ip_id = management_ip_id.value(),
                     role = role.value(),
                     context = std::move(context).value(), callback,
                     event_loop = app().getLoop()]() mutable {
                      try {
                        auto deleted = service->DeleteManagementIp(
                            management_ip_id, role, context);
                        if (!deleted.ok()) {
                          QueueResponse(event_loop, std::move(callback),
                                        BuildUserManagementErrorResponse(
                                            deleted.error()));
                          return;
                        }
                        Json::Value body(Json::objectValue);
                        body["deleted"] = true;
                        QueueResponse(event_loop, std::move(callback),
                                      JsonResponse(std::move(body)));
                      } catch (...) {
                        QueueResponse(event_loop, std::move(callback),
                                      BuildUserManagementErrorResponse(
                                          {"E_USER_MANAGEMENT_UNAVAILABLE",
                                           "user management unavailable"}));
                      }
                    });
                if (!submitted.ok()) {
                  callback(BuildUserManagementErrorResponse(submitted.error()));
                }
              } catch (...) {
                callback(BuildUserManagementErrorResponse(
                    {"E_USER_MANAGEMENT_UNAVAILABLE",
                     "user management unavailable"}));
              }
            });
      },
      {Delete});

  app().registerHandler(
      "/api/v1/auth/password",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        std::shared_ptr<common::SecureBytes> secure_body;
        std::optional<common::Error> body_error;
        try {
          auto copied = CopySecretRequestBody(request);
          if (copied.ok()) {
            secure_body = std::make_shared<common::SecureBytes>(
                std::move(copied).value());
          } else {
            body_error.emplace(copied.error());
          }
        } catch (...) {
          if (secure_body) {
            secure_body->clear();
          }
          callback(BuildUserManagementErrorResponse(
              {"E_USER_MANAGEMENT_UNAVAILABLE",
               "user management unavailable"}));
          return;
        }
        AuthorizeRequest(
            request, std::move(callback),
            [request, secure_body,
             body_error = std::move(body_error)](
                AuthorizedRequest authorized_request,
                HttpCallback callback) mutable {
              std::shared_ptr<ParsedOwnPasswordRequest> parsed_request;
              try {
                if (body_error.has_value()) {
                  callback(BuildUserManagementErrorResponse(*body_error));
                  return;
                }
                if (!secure_body) {
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                auto context =
                    BuildUserMutationContext(request, authorized_request);
                if (!context.ok()) {
                  callback(BuildUserManagementErrorResponse(context.error()));
                  return;
                }
                auto parsed = ParseOwnPasswordJson(
                    std::move(*secure_body),
                    request->getHeader("content-type"));
                secure_body->clear();
                if (!parsed.ok()) {
                  callback(BuildUserManagementErrorResponse(parsed.error()));
                  return;
                }
                const auto dependencies = CopyAdministratorUserDependencies();
                if (dependencies.shutting_down || !dependencies.service ||
                    !dependencies.worker) {
                  parsed.value().current_password.clear();
                  parsed.value().replacement_password.clear();
                  callback(BuildUserManagementErrorResponse(
                      {"E_USER_MANAGEMENT_UNAVAILABLE",
                       "user management unavailable"}));
                  return;
                }
                parsed_request = std::make_shared<ParsedOwnPasswordRequest>(
                    std::move(parsed).value());
                auto submitted = dependencies.worker->Submit(
                    [service = dependencies.service,
                     context = std::move(context).value(), parsed_request,
                     callback, event_loop = app().getLoop()]() mutable {
                      try {
                        auto changed = service->ChangeOwnPassword(
                            std::move(parsed_request->current_password),
                            std::move(parsed_request->replacement_password),
                            context);
                        parsed_request->current_password.clear();
                        parsed_request->replacement_password.clear();
                        if (!changed.ok()) {
                          QueueResponse(event_loop, std::move(callback),
                                        BuildUserManagementErrorResponse(
                                            changed.error()));
                          return;
                        }
                        Json::Value body(Json::objectValue);
                        body["password_changed"] = true;
                        body["logged_out"] = true;
                        auto response = JsonResponse(std::move(body));
                        response->addCookie(SessionCookie("", 0));
                        QueueResponse(event_loop, std::move(callback),
                                      std::move(response));
                      } catch (...) {
                        parsed_request->current_password.clear();
                        parsed_request->replacement_password.clear();
                        QueueResponse(event_loop, std::move(callback),
                                      BuildUserManagementErrorResponse(
                                          {"E_USER_MANAGEMENT_UNAVAILABLE",
                                           "user management unavailable"}));
                      }
                    });
                if (!submitted.ok()) {
                  parsed_request->current_password.clear();
                  parsed_request->replacement_password.clear();
                  callback(BuildUserManagementErrorResponse(submitted.error()));
                }
              } catch (...) {
                if (secure_body) {
                  secure_body->clear();
                }
                if (parsed_request) {
                  parsed_request->current_password.clear();
                  parsed_request->replacement_password.clear();
                }
                callback(BuildUserManagementErrorResponse(
                    {"E_USER_MANAGEMENT_UNAVAILABLE",
                     "user management unavailable"}));
              }
            });
      },
      {Put});

  app().registerHandler(
      "/api/v1/auth/logout",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        const std::string peer_ip = request->peerAddr().toIp();
        AuthorizeRequest(
            request, std::move(callback),
            [request, peer_ip](AuthorizedRequest,
                               HttpCallback callback) {
              auto token =
                  ParseSessionCookieHeaders(request->getRawCookieHeaders());
              if (!token.ok()) {
                callback(SecurityErrorResponse(token.error()));
                return;
              }
              std::shared_ptr<security::AuthService> auth;
              std::shared_ptr<BoundedWorker> worker;
              {
                std::scoped_lock lock(StateMutex());
                auth = GlobalState().auth_service;
                worker = GlobalState().security_worker;
              }
              if (!auth || !worker) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto secure_token = std::make_shared<common::SecureBytes>(
                  std::move(token).value());
              auto submitted = worker->Submit(
                  [secure_token, peer_ip, auth, callback,
                   event_loop = app().getLoop()]() mutable {
                    try {
                      auto logged_out = auth->Logout(
                          {secure_token->data(), secure_token->size()}, peer_ip);
                      secure_token->clear();
                      if (!logged_out.ok()) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityErrorResponse(logged_out.error()));
                        return;
                      }
                      Json::Value body(Json::objectValue);
                      body["logged_out"] = true;
                      auto response = JsonResponse(std::move(body));
                      response->addCookie(SessionCookie("", 0));
                      QueueResponse(event_loop, std::move(callback),
                                    std::move(response));
                    } catch (...) {
                      secure_token->clear();
                      QueueResponse(event_loop, std::move(callback),
                                    SecurityUnavailableResponse());
                    }
                  });
              if (!submitted.ok()) {
                secure_token->clear();
                callback(SecurityUnavailableResponse());
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/auth/reauthenticate",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        std::shared_ptr<common::SecureBytes> secure_body;
        std::optional<common::Error> body_error;
        try {
          auto copied = CopySecretRequestBody(request);
          if (copied.ok()) {
            secure_body = std::make_shared<common::SecureBytes>(
                std::move(copied).value());
          } else {
            body_error.emplace(copied.error());
          }
        } catch (...) {
          if (secure_body) {
            secure_body->clear();
          }
          callback(SecurityUnavailableResponse());
          return;
        }
        const std::string peer_ip = request->peerAddr().toIp();
        AuthorizeRequest(
            request, std::move(callback),
            [request, peer_ip, secure_body,
             body_error = std::move(body_error)](
                AuthorizedRequest, HttpCallback callback) mutable {
              if (body_error.has_value()) {
                callback(SecurityErrorResponse(*body_error));
                return;
              }
              if (!secure_body) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto parsed = ParseReauthenticateJson(
                  std::move(*secure_body), request->getHeader("content-type"));
              secure_body->clear();
              if (!parsed.ok()) {
                callback(SecurityErrorResponse(parsed.error()));
                return;
              }
              auto token =
                  ParseSessionCookieHeaders(request->getRawCookieHeaders());
              if (!token.ok()) {
                callback(SecurityErrorResponse(token.error()));
                return;
              }
              std::shared_ptr<security::AuthService> auth;
              std::shared_ptr<BoundedWorker> worker;
              {
                std::scoped_lock lock(StateMutex());
                auth = GlobalState().auth_service;
                worker = GlobalState().security_worker;
              }
              if (!auth || !worker) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto secure_token = std::make_shared<common::SecureBytes>(
                  std::move(token).value());
              auto secure_password = std::make_shared<common::SecureBytes>(
                  std::move(parsed).value());
              auto submitted = worker->Submit(
                  [secure_token, secure_password, peer_ip, auth, callback,
                   event_loop = app().getLoop()]() mutable {
                    try {
                      auto renewed = auth->Reauthenticate(
                          {secure_token->data(), secure_token->size()},
                          peer_ip, std::move(*secure_password));
                      secure_password->clear();
                      secure_token->clear();
                      if (!renewed.ok()) {
                        QueueResponse(event_loop, std::move(callback),
                                      SecurityErrorResponse(renewed.error()));
                        return;
                      }
                      Json::Value body(Json::objectValue);
                      body["management_expires_at_seconds"] =
                          static_cast<Json::Int64>(renewed.value());
                      QueueResponse(event_loop, std::move(callback),
                                    JsonResponse(std::move(body)));
                    } catch (...) {
                      secure_password->clear();
                      secure_token->clear();
                      QueueResponse(event_loop, std::move(callback),
                                    SecurityUnavailableResponse());
                    }
                  });
              if (!submitted.ok()) {
                secure_password->clear();
                secure_token->clear();
                callback(SecurityUnavailableResponse());
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/health",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](AuthorizedRequest, HttpCallback callback) {
              std::string status;
              {
                std::scoped_lock lock(StateMutex());
                status = GlobalState().args.health_status;
              }
              callback(JsonResponse(BuildHealthJson(status)));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/audit/status",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, AuditRouteCallback(std::move(callback)),
            [request](AuthorizedRequest authorized_request,
                      HttpCallback callback) {
              HandleAuditStatusRequest(request,
                                       std::move(authorized_request),
                                       std::move(callback));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/audit/events",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, AuditRouteCallback(std::move(callback)),
            [request](AuthorizedRequest authorized_request,
                      HttpCallback callback) {
              HandleAuditEventRequest(request,
                                      std::move(authorized_request),
                                      std::move(callback));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/system/protection",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](AuthorizedRequest, HttpCallback callback) {
              const auto dependencies = CopySystemProtectionDependencies();
              if (!dependencies.Available()) {
                callback(BuildSystemProtectionStatusResponse({}));
                return;
              }
              std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease>
                  runtime_lease;
              try {
                runtime_lease = dependencies.runtime_lifecycle->TryAcquire();
              } catch (...) {
                callback(BuildSystemProtectionStatusResponse({}));
                return;
              }
              if (!runtime_lease) {
                callback(BuildSystemProtectionStatusResponse({}));
                return;
              }
              callback(BuildSystemProtectionStatusResponse(
                  [snapshot = dependencies.snapshot,
                   runtime_lease = std::move(runtime_lease)] {
                    auto callback_scope = runtime_lease->EnterCallback();
                    return snapshot();
                  }));
            });
      },
      {Get});

  const auto register_protection_start = [](
      std::string path, security::ProtectionSuite suite) {
    app().registerHandler(
        std::move(path),
        [suite](const HttpRequestPtr& request, DrogonCallback&& callback) {
          AuthorizeRequest(
              request, std::move(callback),
              [request, suite](AuthorizedRequest authorized_request,
                               HttpCallback callback) {
                const auto dependencies = CopySystemProtectionDependencies();
                if (!dependencies.Available()) {
                  callback(BuildSystemProtectionStartResponse({}));
                  return;
                }
                auto body = ValidateEmptyJsonObject(
                    request->getBody(), request->getHeader("content-type"));
                if (!body.ok()) {
                  callback(SecurityErrorResponse(body.error()));
                  return;
                }
                auto actor = BuildProtectionActor(request, authorized_request);
                if (!actor.ok()) {
                  callback(BuildSystemProtectionStartResponse({}));
                  return;
                }
                std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease>
                    runtime_lease;
                try {
                  runtime_lease =
                      dependencies.runtime_lifecycle->TryAcquire();
                } catch (...) {
                  callback(BuildSystemProtectionStartResponse({}));
                  return;
                }
                if (!runtime_lease) {
                  callback(BuildSystemProtectionStartResponse({}));
                  return;
                }
                callback(BuildSystemProtectionStartResponse(
                    [start = dependencies.start, suite,
                     actor = std::move(actor).value(),
                     runtime_lease = std::move(runtime_lease)]() mutable {
                      auto callback_scope = runtime_lease->EnterCallback();
                      return start(suite, std::move(actor));
                    }));
              });
        },
        {Post});
  };
  register_protection_start("/api/v1/system/self-tests",
                            security::ProtectionSuite::kSelfTest);
  register_protection_start("/api/v1/system/integrity-checks",
                            security::ProtectionSuite::kIntegrity);

  app().registerHandler(
      "/api/v1/settings/runtime",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](AuthorizedRequest, HttpCallback callback) {
              const auto dependencies = CopyRuntimeSettingsDependencies();
              if (!dependencies.Available()) {
                callback(RuntimeSettingsUnavailableResponse());
                return;
              }
              callback(internal::ExecuteUnrestrictedRuntimeOperation([&] {
                try {
                  return BuildRuntimeSettingsSnapshotResponse(
                      dependencies.snapshot());
                } catch (...) {
                  return RuntimeSettingsUnavailableResponse();
                }
              }));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/settings/runtime",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [request](AuthorizedRequest,
                      HttpCallback callback) {
              const auto dependencies = CopyRuntimeSettingsDependencies();
              if (!dependencies.Available()) {
                callback(RuntimeSettingsUnavailableResponse());
                return;
              }
              auto parsed = ParseRuntimeSettingsUpdateJson(
                  request->getBody(), request->getHeader("content-type"));
              if (!parsed.ok()) {
                callback(BuildRuntimeSettingsErrorResponse(parsed.error()));
                return;
              }
              auto response = internal::ExecuteUnrestrictedRuntimeOperation(
                  [&]() -> drogon::HttpResponsePtr {
                    auto submitted = dependencies.worker->Submit(
                        [save = dependencies.save,
                         update = std::move(parsed).value(), callback,
                         event_loop = app().getLoop()]() mutable {
                          try {
                            auto result = save(update.expected_revision,
                                               std::move(update.settings));
                            QueueRuntimeSettingsResult(
                                event_loop, std::move(callback),
                                std::move(result));
                          } catch (...) {
                            QueueResponse(
                                event_loop, std::move(callback),
                                RuntimeSettingsUnavailableResponse());
                          }
                        });
                    if (!submitted.ok()) {
                      return RuntimeSettingsBecameUnavailable(
                                 dependencies.worker)
                                 ? RuntimeSettingsUnavailableResponse()
                                 : RuntimeSettingsBusyResponse();
                    }
                    return {};
                  });
              if (response) {
                callback(std::move(response));
              }
            });
      },
      {Put});

  app().registerHandler(
      "/api/v1/settings/runtime/apply",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [request](AuthorizedRequest,
                      HttpCallback callback) {
              const auto dependencies = CopyRuntimeSettingsDependencies();
              if (!dependencies.Available()) {
                callback(RuntimeSettingsUnavailableResponse());
                return;
              }
              std::optional<RuntimeSettingsCommandRequest> command;
              auto response = internal::
                  ExecuteSequentialProtectedRuntimeControlCommand(
                      dependencies.protection_runtime_allowed,
                      [&]() -> drogon::HttpResponsePtr {
                        auto parsed = ParseRuntimeSettingsCommandJson(
                            request->getBody(),
                            request->getHeader("content-type"));
                        if (!parsed.ok()) {
                          return BuildRuntimeSettingsErrorResponse(
                              parsed.error());
                        }
                        command = std::move(parsed).value();
                        return {};
                      },
                      [&]() -> drogon::HttpResponsePtr {
                        auto submitted = dependencies.worker->Submit(
                            [apply = dependencies.apply,
                             protection_runtime_control_gate =
                                 dependencies.protection_runtime_control_gate,
                             command = std::move(*command), callback,
                             event_loop = app().getLoop()]() mutable {
                              try {
                                auto response = internal::
                                    ExecuteAtomicallyProtectedRuntimeControlCommand(
                                        protection_runtime_control_gate,
                                        [&] {
                                          return BuildRuntimeSettingsApplyResponse(
                                              apply(command.expected_revision));
                                        });
                                QueueResponse(
                                    event_loop, std::move(callback),
                                    std::move(response));
                              } catch (...) {
                                QueueResponse(
                                    event_loop, std::move(callback),
                                    RuntimeSettingsUnavailableResponse());
                              }
                            });
                        if (!submitted.ok()) {
                          return RuntimeSettingsBecameUnavailable(
                                     dependencies.worker)
                                     ? RuntimeSettingsUnavailableResponse()
                                     : RuntimeSettingsBusyResponse();
                        }
                        return {};
                      });
              if (response) {
                callback(std::move(response));
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/settings/runtime/discard",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [request](AuthorizedRequest,
                      HttpCallback callback) {
              const auto dependencies = CopyRuntimeSettingsDependencies();
              if (!dependencies.Available()) {
                callback(RuntimeSettingsUnavailableResponse());
                return;
              }
              auto parsed = ParseRuntimeSettingsCommandJson(
                  request->getBody(), request->getHeader("content-type"));
              if (!parsed.ok()) {
                callback(BuildRuntimeSettingsErrorResponse(parsed.error()));
                return;
              }
              auto response = internal::ExecuteUnrestrictedRuntimeOperation(
                  [&]() -> drogon::HttpResponsePtr {
                    auto submitted = dependencies.worker->Submit(
                        [discard = dependencies.discard,
                         command = std::move(parsed).value(), callback,
                         event_loop = app().getLoop()]() mutable {
                          try {
                            auto result = discard(command.expected_revision);
                            QueueRuntimeSettingsResult(
                                event_loop, std::move(callback),
                                std::move(result));
                          } catch (...) {
                            QueueResponse(
                                event_loop, std::move(callback),
                                RuntimeSettingsUnavailableResponse());
                          }
                        });
                    if (!submitted.ok()) {
                      return RuntimeSettingsBecameUnavailable(
                                 dependencies.worker)
                                 ? RuntimeSettingsUnavailableResponse()
                                 : RuntimeSettingsBusyResponse();
                    }
                    return {};
                  });
              if (response) {
                callback(std::move(response));
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/monitoring/cameras",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](AuthorizedRequest, HttpCallback callback) {
              CameraStatusProvider provider;
              {
                std::scoped_lock lock(StateMutex());
                provider = GlobalState().args.camera_status_provider;
              }

              Json::Value body(Json::objectValue);
              Json::Value cameras(Json::arrayValue);
              if (provider) {
                for (const auto& camera : provider()) {
                  cameras.append(BuildMonitoringCameraJsonValue(camera));
                }
              }
              body["cameras"] = std::move(cameras);
              callback(JsonResponse(std::move(body)));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/cameras",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](AuthorizedRequest, HttpCallback callback) {
              Json::Value body(Json::objectValue);
              Json::Value cameras(Json::arrayValue);
              CameraStatusProvider provider;
              AiStatusProvider ai_status_provider;
              bool ai_enabled = false;
              {
                std::scoped_lock lock(StateMutex());
                provider = GlobalState().args.camera_status_provider;
                ai_status_provider = GlobalState().args.ai_status_provider;
                ai_enabled = GlobalState().args.ai_enabled;
              }
              if (provider) {
                for (const auto& camera : provider()) {
                  cameras.append(BuildCameraStatusJsonValue(camera));
                }
              }
              body["cameras"] = std::move(cameras);
              body["ai"] = ai_status_provider
                               ? BuildAiStatusJson(ai_status_provider())
                               : BuildAiStatusJson(ai_enabled);
              callback(JsonResponse(std::move(body)));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/cameras/{1}/snapshot.jpg",
      [](const HttpRequestPtr& request, DrogonCallback&& callback,
         const std::string& camera_id) {
        AuthorizeRequest(
            request, std::move(callback),
            [camera_id](AuthorizedRequest,
                        HttpCallback callback) {
              SnapshotCallback snapshot_callback;
              {
                std::scoped_lock lock(StateMutex());
                snapshot_callback = GlobalState().args.snapshot_callback;
              }
              callback(BuildSnapshotResponse(snapshot_callback, camera_id));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/cameras/{1}/live.mp4",
      [](const HttpRequestPtr& request, DrogonCallback&& callback,
         const std::string& camera_id) {
        AuthorizeRequest(
            request, std::move(callback),
            [camera_id](AuthorizedRequest authorized_request,
                        HttpCallback callback) mutable {
              CancellableLiveMp4OpenCallback live_stream_callback;
              std::shared_ptr<internal::LiveMp4PumpManager> pump_manager;
              std::shared_ptr<internal::RuntimeCallbackLifecycle>
                  runtime_lifecycle;
              {
                std::scoped_lock lock(StateMutex());
                live_stream_callback =
                    GlobalState().args.cancellable_live_stream_callback;
                if (!live_stream_callback) {
                  live_stream_callback = AdaptLegacyLiveMp4OpenCallback(
                      GlobalState().args.live_stream_callback);
                }
                pump_manager = GlobalState().live_pump_manager;
                runtime_lifecycle = GlobalState().runtime_lifecycle;
              }
              std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease>
                  runtime_lease;
              try {
                runtime_lease = runtime_lifecycle
                                    ? runtime_lifecycle->TryAcquire()
                                    : nullptr;
              } catch (...) {
                callback(SecurityUnavailableResponse());
                return;
              }
              if (!runtime_lease ||
                  (authorized_request.stream_lease &&
                   authorized_request.stream_lease->revoked())) {
                callback(SecurityUnavailableResponse());
                return;
              }
              callback(BuildManagedLiveMp4Response(
                  live_stream_callback, camera_id,
                  kDefaultLiveMp4ResponseByteLimit,
                  std::move(authorized_request.stream_lease),
                  std::move(pump_manager), std::move(runtime_lease)));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/ai/detections",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](AuthorizedRequest, HttpCallback callback) {
              DetectionSnapshotProvider provider;
              {
                std::scoped_lock lock(StateMutex());
                provider = GlobalState().args.detection_snapshot_provider;
              }
              callback(BuildDetectionSnapshotResponse(provider));
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/runtime/restart",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [request](AuthorizedRequest,
                      HttpCallback callback) {
              RuntimeStartCallback restart;
              ProtectionRuntimeAllowedCallback protection_runtime_allowed;
              ProtectionRuntimeControlGate protection_runtime_control_gate;
              std::shared_ptr<BoundedWorker> worker;
              {
                std::scoped_lock lock(StateMutex());
                restart = GlobalState().args.runtime_start_callback;
                protection_runtime_allowed =
                    GlobalState().args.protection_runtime_allowed_callback;
                protection_runtime_control_gate =
                    GlobalState().args.protection_runtime_control_gate;
                worker = GlobalState().security_worker;
              }
              auto response = internal::
                  ExecuteSequentialProtectedRuntimeControlCommand(
                      protection_runtime_allowed,
                      [&]() -> drogon::HttpResponsePtr {
                        auto validated = ValidateEmptyJsonObject(
                            request->getBody(),
                            request->getHeader("content-type"));
                        return validated.ok()
                                   ? drogon::HttpResponsePtr{}
                                   : SecurityErrorResponse(validated.error());
                      },
                      [&]() -> drogon::HttpResponsePtr {
                        if (!worker) {
                          return BuildRuntimeRestartResponse({});
                        }
                        auto submitted = worker->Submit(
                            [restart = std::move(restart),
                             protection_runtime_control_gate =
                                 std::move(protection_runtime_control_gate),
                             callback,
                             event_loop = app().getLoop()]() mutable {
                              try {
                                auto response = internal::
                                    ExecuteAtomicallyProtectedRuntimeControlCommand(
                                        protection_runtime_control_gate,
                                        [&] {
                                          return BuildRuntimeRestartResponse(
                                              restart);
                                        });
                                QueueResponse(event_loop, std::move(callback),
                                              std::move(response));
                              } catch (...) {
                                QueueResponse(event_loop, std::move(callback),
                                              SecurityUnavailableResponse());
                              }
                            });
                        return submitted.ok() ? drogon::HttpResponsePtr{}
                                              : SecurityUnavailableResponse();
                      });
              if (response) {
                callback(std::move(response));
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/ai/restart",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](AuthorizedRequest, HttpCallback callback) {
              AiControlCallback restart;
              AiStatusProvider status;
              ProtectionRuntimeAllowedCallback protection_runtime_allowed;
              ProtectionRuntimeControlGate protection_runtime_control_gate;
              std::shared_ptr<BoundedWorker> worker;
              {
                std::scoped_lock lock(StateMutex());
                restart = GlobalState().args.ai_restart_callback;
                status = GlobalState().args.ai_status_provider;
                protection_runtime_allowed =
                    GlobalState().args.protection_runtime_allowed_callback;
                protection_runtime_control_gate =
                    GlobalState().args.protection_runtime_control_gate;
                worker = GlobalState().security_worker;
              }
              auto admitted = internal::ExecuteProtectedRuntimeControlCommand(
                  protection_runtime_allowed,
                  [] { return drogon::HttpResponsePtr{}; });
              if (admitted) {
                callback(std::move(admitted));
                return;
              }
              auto dispatched = internal::
                  DispatchAtomicallyProtectedRuntimeControlCommand(
                      worker, std::move(protection_runtime_control_gate),
                      [restart = std::move(restart),
                       status = std::move(status)] {
                        return BuildAiRestartResponse(restart, status);
                      },
                      [callback, event_loop = app().getLoop()](
                          drogon::HttpResponsePtr response) mutable {
                        QueueResponse(event_loop, std::move(callback),
                                      std::move(response));
                      });
              if (!dispatched.ok()) {
                callback(SecurityUnavailableResponse());
              }
            });
      },
      {Post});

  app().registerHandler(
      "/api/v1/ai/detections/stream",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        const std::string last_event_id = request->getHeader("Last-Event-ID");
        AuthorizeRequest(
            request, std::move(callback),
            [last_event_id](AuthorizedRequest authorized_request,
                            HttpCallback callback) mutable {
              DetectionSnapshotProvider snapshot_provider;
              DetectionEventSubscriber subscriber;
              std::shared_ptr<internal::RuntimeCallbackLifecycle>
                  runtime_lifecycle;
              {
                std::scoped_lock lock(StateMutex());
                snapshot_provider =
                    GlobalState().args.detection_snapshot_provider;
                subscriber = GlobalState().args.detection_event_subscriber;
                runtime_lifecycle = GlobalState().runtime_lifecycle;
              }
              std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease>
                  runtime_lease;
              try {
                runtime_lease = runtime_lifecycle
                                    ? runtime_lifecycle->TryAcquire()
                                    : nullptr;
              } catch (...) {
                callback(SecurityUnavailableResponse());
                return;
              }
              if (!runtime_lease ||
                  (authorized_request.stream_lease &&
                   authorized_request.stream_lease->revoked())) {
                callback(SecurityUnavailableResponse());
                return;
              }
              auto pending = DetectionSsePendingResponse::Create(
                  std::move(snapshot_provider),
                  [callback = std::move(callback)](
                      const drogon::HttpResponsePtr& response) mutable {
                    try {
                      callback.Queue(response);
                    } catch (...) {
                      callback.Queue(response);
                    }
                  },
                  std::move(authorized_request.stream_lease),
                  std::move(runtime_lease));
              if (!subscriber) {
                pending->CompleteWithSnapshot();
                return;
              }
              std::weak_ptr weak_pending = pending;
              if (!pending->AttachSubscription(
                      subscriber,
                      [weak_pending](const ai::DetectionEvent& event) {
                        if (const auto current = weak_pending.lock()) {
                          current->CompleteWithEvent(event);
                        }
                      })) {
                return;
              }
              if (!pending->CompleteInitialSnapshotIfChanged(last_event_id)) {
                return;
              }
              auto* event_loop = app().getLoop();
              const auto timeout = event_loop->runAfter(
                  kDetectionSsePendingTimeout,
                  [pending] { pending->CompleteWithSnapshot(); });
              pending->SetTimeoutCancellation([event_loop, timeout] {
                event_loop->invalidateTimer(timeout);
              });
            });
      },
      {Get});

  app().registerHandler(
      "/api/v1/stream",
      [](const HttpRequestPtr& request, DrogonCallback&& callback) {
        AuthorizeRequest(
            request, std::move(callback),
            [](AuthorizedRequest, HttpCallback callback) {
              const config::AppConfig* config = nullptr;
              std::string public_base_url;
              SecureStreamDiagnosticsProvider diagnostics_provider;
              {
                std::scoped_lock lock(StateMutex());
                config = GlobalState().args.app_config;
                public_base_url = GlobalState().args.public_base_url;
                diagnostics_provider =
                    GlobalState().args.secure_stream_diagnostics_provider;
              }
              if (config == nullptr) {
                Json::Value body(Json::objectValue);
                body["code"] = "E_CONFIG";
                body["message"] = "service config unavailable";
                callback(JsonResponse(std::move(body),
                                      k500InternalServerError));
                return;
              }
              std::optional<SecureStreamDiagnostics> diagnostics;
              if (diagnostics_provider) {
                diagnostics = diagnostics_provider();
              }
              callback(JsonResponse(BuildStreamJson(
                  public_base_url, config->secure_rtsp, diagnostics)));
            });
      },
      {Get});
}

}  // namespace

namespace internal {

drogon::HttpResponsePtr ExecuteProtectedRuntimeControlCommand(
    const ProtectionRuntimeAllowedCallback& protection_runtime_allowed,
    const std::function<drogon::HttpResponsePtr()>& command) {
  if (!RuntimeControlAllowed(protection_runtime_allowed)) {
    return BuildProtectionRestrictedResponse();
  }
  return command();
}

drogon::HttpResponsePtr ExecuteSequentialProtectedRuntimeControlCommand(
    const ProtectionRuntimeAllowedCallback& protection_runtime_allowed,
    const std::function<drogon::HttpResponsePtr()>& validate,
    const std::function<drogon::HttpResponsePtr()>& command) {
  auto restricted = ExecuteProtectedRuntimeControlCommand(
      protection_runtime_allowed, [] { return drogon::HttpResponsePtr{}; });
  if (restricted) {
    return restricted;
  }
  auto validation_error = validate();
  if (validation_error) {
    return validation_error;
  }
  return ExecuteProtectedRuntimeControlCommand(protection_runtime_allowed,
                                                command);
}

drogon::HttpResponsePtr ExecuteAtomicallyProtectedRuntimeControlCommand(
    const ProtectionRuntimeControlGate& protection_runtime_control_gate,
    const std::function<drogon::HttpResponsePtr()>& command) {
  if (!protection_runtime_control_gate || !command) {
    return BuildProtectionRestrictedResponse();
  }
  drogon::HttpResponsePtr response;
  if (!protection_runtime_control_gate([&] { response = command(); })) {
    return BuildProtectionRestrictedResponse();
  }
  return response;
}

common::Result<void> DispatchAtomicallyProtectedRuntimeControlCommand(
    const std::shared_ptr<BoundedWorker>& worker,
    ProtectionRuntimeControlGate protection_runtime_control_gate,
    std::function<drogon::HttpResponsePtr()> command,
    std::function<void(drogon::HttpResponsePtr)> complete) {
  if (!worker || !command || !complete) {
    return common::Result<void>::Err(
        {"E_SECURITY_UNAVAILABLE", "security service unavailable"});
  }
  return worker->Submit(
      [protection_runtime_control_gate =
           std::move(protection_runtime_control_gate),
       command = std::move(command), complete = std::move(complete)]() mutable {
        drogon::HttpResponsePtr response;
        try {
          response = ExecuteAtomicallyProtectedRuntimeControlCommand(
              protection_runtime_control_gate, command);
        } catch (...) {
          response = SecurityUnavailableResponse();
        }
        complete(std::move(response));
      });
}

drogon::HttpResponsePtr ExecuteUnrestrictedRuntimeOperation(
    const std::function<drogon::HttpResponsePtr()>& operation) {
  return operation();
}

void InstallDefaultProtectionRuntimeAllowedCallback(
    ServiceInitArgs& args, bool security_enabled) {
  if (!args.protection_runtime_allowed_callback) {
    args.protection_runtime_allowed_callback = [security_enabled] {
      return !security_enabled;
    };
  }
  if (!security_enabled && !args.protection_runtime_control_gate) {
    args.protection_runtime_control_gate =
        [](const std::function<void()>& command) {
          if (!command) {
            return false;
          }
          command();
          return true;
        };
  }
}

#if defined(CAMERA_FIRMWARE_SERVICE_TESTING)
using AuditHandlerCallbackForTesting =
    std::function<void(const drogon::HttpResponsePtr&)>;

void HandleAuthorizedAuditStatusForTesting(
    security::Principal principal,
    std::shared_ptr<security::AuditLogService> service,
    std::shared_ptr<BoundedWorker> worker,
    bool shutting_down,
    trantor::EventLoop* event_loop,
    AuditHandlerCallbackForTesting callback) {
  HttpCallback terminal(std::make_shared<TerminalResponse>(
      event_loop, std::move(callback)));
  try {
    SubmitAuthorizedAuditStatus(
        std::move(principal),
        {shutting_down, std::move(service), std::move(worker)}, terminal,
        event_loop);
  } catch (...) {
    terminal(AuditLogUnavailableResponse());
  }
}

void HandleAuthorizedAuditEventsForTesting(
    security::Principal principal,
    security::AuditQueryParameters parameters,
    std::shared_ptr<security::AuditLogService> service,
    std::shared_ptr<BoundedWorker> worker,
    bool shutting_down,
    trantor::EventLoop* event_loop,
    AuditHandlerCallbackForTesting callback) {
  HttpCallback terminal(std::make_shared<TerminalResponse>(
      event_loop, std::move(callback)));
  try {
    SubmitAuthorizedAuditEvents(
        std::move(principal), std::move(parameters),
        {shutting_down, std::move(service), std::move(worker)}, terminal,
        event_loop);
  } catch (...) {
    terminal(AuditLogUnavailableResponse());
  }
}

void InstallAuditDependenciesForShutdownTesting(
    std::shared_ptr<security::AuditLogService> service,
    std::shared_ptr<BoundedWorker> worker) noexcept {
  std::scoped_lock lock(StateMutex());
  auto& state = GlobalState();
  state.audit_log_service = std::move(service);
  state.security_worker = std::move(worker);
  state.shutting_down = false;
}

std::shared_ptr<BoundedWorker>
ReplaceAuditAuthorizationWorkerForTesting(
    std::shared_ptr<BoundedWorker> worker) noexcept {
  std::scoped_lock lock(StateMutex());
  return std::exchange(GlobalState().security_worker, std::move(worker));
}

std::shared_ptr<security::SecurityStore>
ReplaceAuditAuthorizationStoreForTesting(
    std::shared_ptr<security::SecurityStore> store) noexcept {
  std::scoped_lock lock(StateMutex());
  return std::exchange(GlobalState().args.security_store, std::move(store));
}

std::shared_ptr<security::AuthService>
ReplaceAuditAuthorizationServiceForTesting(
    std::shared_ptr<security::AuthService> auth_service) noexcept {
  std::scoped_lock lock(StateMutex());
  return std::exchange(GlobalState().auth_service, std::move(auth_service));
}

bool ReplaceAuditAuthorizationShutdownForTesting(bool shutting_down) noexcept {
  std::scoped_lock lock(StateMutex());
  return std::exchange(GlobalState().shutting_down, shutting_down);
}

bool AuditShutdownStartedForTesting() noexcept {
  std::scoped_lock lock(StateMutex());
  return GlobalState().shutting_down;
}
#endif

struct DetectionSsePendingResponse::State {
  DetectionSnapshotProvider detection_snapshot_provider;
  ResponseCallback response_callback;
  std::shared_ptr<SessionStreamLease> stream_lease;
  std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease> runtime_lease;
  std::mutex mutex;
  ai::DetectionBus::Subscription subscription;
  std::function<void()> cancel_timeout;
  std::size_t active_runtime_callbacks{0U};
  bool revoke_requested{false};
  bool terminal_claimed{false};
  bool finishing_started{false};
  bool finish_external_done{false};
  bool completed{false};
};

DetectionSsePendingResponse::DetectionSsePendingResponse(
    std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

std::shared_ptr<DetectionSsePendingResponse>
DetectionSsePendingResponse::Create(
    DetectionSnapshotProvider detection_snapshot_provider,
    ResponseCallback response_callback,
    std::shared_ptr<SessionStreamLease> stream_lease,
    std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease>
        runtime_lease) {
  auto state = std::make_shared<State>();
  state->detection_snapshot_provider =
      std::move(detection_snapshot_provider);
  state->response_callback = std::move(response_callback);
  state->stream_lease = std::move(stream_lease);
  state->runtime_lease = std::move(runtime_lease);
  auto pending = std::shared_ptr<DetectionSsePendingResponse>(
      new DetectionSsePendingResponse(std::move(state)));
  if (pending->state_->stream_lease) {
    std::weak_ptr weak_pending = pending;
    pending->state_->stream_lease->SetRevocationHandler([weak_pending] {
      if (const auto current = weak_pending.lock()) {
        current->Revoke();
      }
    });
  }
  return pending;
}

bool DetectionSsePendingResponse::BeginRuntimeCallback(
    bool claim_terminal) {
  std::shared_ptr<SessionStreamLease> stream_lease;
  {
    std::lock_guard lock(state_->mutex);
    if (state_->completed || state_->revoke_requested ||
        state_->terminal_claimed) {
      return false;
    }
    stream_lease = state_->stream_lease;
  }
  std::optional<internal::SessionStreamTerminalElection> election;
  if (stream_lease) {
    election.emplace(stream_lease->state_->TryBeginTerminalElection());
    if (!*election) {
      return false;
    }
  }
  std::lock_guard lock(state_->mutex);
  if (state_->completed || state_->revoke_requested ||
      state_->terminal_claimed) {
    return false;
  }
  if (claim_terminal) {
    state_->terminal_claimed = true;
  }
  ++state_->active_runtime_callbacks;
  return true;
}

bool DetectionSsePendingResponse::ClaimTerminalFromActiveCallback() {
  std::shared_ptr<SessionStreamLease> stream_lease;
  {
    std::lock_guard lock(state_->mutex);
    if (state_->completed || state_->revoke_requested ||
        state_->terminal_claimed) {
      return false;
    }
    stream_lease = state_->stream_lease;
  }
  std::optional<internal::SessionStreamTerminalElection> election;
  if (stream_lease) {
    election.emplace(stream_lease->state_->TryBeginTerminalElection());
    if (!*election) {
      return false;
    }
  }
  std::lock_guard lock(state_->mutex);
  if (state_->completed || state_->revoke_requested ||
      state_->terminal_claimed) {
    return false;
  }
  state_->terminal_claimed = true;
  return true;
}

std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease>
DetectionSsePendingResponse::EndRuntimeCallbackLocked() {
  if (state_->active_runtime_callbacks != 0U) {
    --state_->active_runtime_callbacks;
  }
  if (state_->active_runtime_callbacks == 0U &&
      state_->finish_external_done && !state_->completed) {
    state_->completed = true;
    return std::move(state_->runtime_lease);
  }
  return {};
}

bool DetectionSsePendingResponse::AttachSubscription(
    const DetectionEventSubscriber& subscriber,
    ai::DetectionBus::Handler handler) {
  if (!BeginRuntimeCallback(false)) {
    return false;
  }
  RuntimeCallbackGuard runtime_callback_guard(*this);
  ai::DetectionBus::Subscription subscription;
  bool callback_failed = false;
  try {
    auto callback_scope = state_->runtime_lease->EnterCallback();
    subscription = subscriber(std::move(handler));
  } catch (...) {
    callback_failed = true;
  }

  bool attached = false;
  {
    std::lock_guard lock(state_->mutex);
    if (!callback_failed && !state_->completed &&
        !state_->revoke_requested && !state_->terminal_claimed) {
      state_->subscription = std::move(subscription);
      attached = true;
    }
  }
  if (!attached) {
    try {
      auto callback_scope = state_->runtime_lease->EnterCallback();
      subscription = {};
    } catch (...) {
      subscription = {};
    }
  }

  bool can_continue = false;
  {
    std::lock_guard lock(state_->mutex);
    can_continue = !state_->completed && !state_->revoke_requested &&
                   !state_->terminal_claimed;
  }
  if (callback_failed && can_continue) {
    CompleteWithSnapshot();
  }
  return !callback_failed && can_continue;
}

bool DetectionSsePendingResponse::CompleteInitialSnapshotIfChanged(
    std::string_view last_event_id) {
  if (!state_->detection_snapshot_provider) {
    std::lock_guard lock(state_->mutex);
    return !state_->completed && !state_->revoke_requested &&
           !state_->terminal_claimed;
  }
  if (!BeginRuntimeCallback(false)) {
    return false;
  }
  RuntimeCallbackGuard runtime_callback_guard(*this);

  std::vector<ai::DetectionEvent> snapshot;
  bool callback_failed = false;
  bool snapshot_matches = false;
  try {
    auto callback_scope = state_->runtime_lease->EnterCallback();
    snapshot = state_->detection_snapshot_provider();
    snapshot_matches =
        !last_event_id.empty() &&
        last_event_id == BuildDetectionSseId(snapshot);
  } catch (...) {
    callback_failed = true;
  }

  const bool finish_snapshot =
      (callback_failed || !snapshot_matches) &&
      ClaimTerminalFromActiveCallback();
  bool can_continue = false;
  if (!callback_failed && snapshot_matches) {
    std::lock_guard lock(state_->mutex);
    can_continue = !state_->completed && !state_->revoke_requested &&
                   !state_->terminal_claimed;
  }
  if (finish_snapshot) {
    Finish(std::move(snapshot));
  }
  return can_continue;
}

void DetectionSsePendingResponse::SetTimeoutCancellation(
    std::function<void()> cancel_timeout) {
  std::function<void()> cancel_immediately;
  {
    std::lock_guard lock(state_->mutex);
    if (state_->completed || state_->revoke_requested ||
        state_->terminal_claimed) {
      cancel_immediately = std::move(cancel_timeout);
    } else {
      state_->cancel_timeout = std::move(cancel_timeout);
    }
  }
  if (cancel_immediately) {
    try {
      cancel_immediately();
    } catch (...) {
    }
  }
}

void DetectionSsePendingResponse::CompleteWithEvent(
    const ai::DetectionEvent& event) {
  CompleteFromProvider(&event);
}

void DetectionSsePendingResponse::CompleteWithSnapshot() {
  CompleteFromProvider(nullptr);
}

void DetectionSsePendingResponse::CompleteFromProvider(
    const ai::DetectionEvent* event) {
  if (!BeginRuntimeCallback(true)) {
    return;
  }
  RuntimeCallbackGuard runtime_callback_guard(*this);
  std::vector<ai::DetectionEvent> snapshot;
  try {
    if (state_->detection_snapshot_provider) {
      auto callback_scope = state_->runtime_lease->EnterCallback();
      snapshot = state_->detection_snapshot_provider();
    }
    if (event != nullptr) {
      if (internal::ConsumeDetectionSseEventMergeFailureForTesting()) {
        throw std::bad_alloc();
      }
      snapshot =
          MergeDetectionSnapshotWithEvent(std::move(snapshot), *event);
    }
  } catch (...) {
    snapshot.clear();
  }
  Finish(std::move(snapshot));
}

void DetectionSsePendingResponse::EndRuntimeCallback() noexcept {
  std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease> runtime_lease;
  {
    std::lock_guard lock(state_->mutex);
    runtime_lease = EndRuntimeCallbackLocked();
  }
  runtime_lease.reset();
}

void DetectionSsePendingResponse::Revoke() {
  bool finish_revoke = false;
  {
    std::lock_guard lock(state_->mutex);
    state_->revoke_requested = true;
    if (!state_->completed && !state_->terminal_claimed) {
      state_->terminal_claimed = true;
      finish_revoke = true;
    }
  }
  if (finish_revoke) {
    Finish({});
  }
}

void DetectionSsePendingResponse::Finish(
    std::vector<ai::DetectionEvent> events) {
  ResponseCallback callback;
  ai::DetectionBus::Subscription subscription;
  std::shared_ptr<SessionStreamLease> stream_lease;
  std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease> runtime_lease;
  std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease>
      callback_runtime_lease;
  std::function<void()> cancel_timeout;
  {
    std::lock_guard lock(state_->mutex);
    if (state_->finishing_started) {
      return;
    }
    state_->finishing_started = true;
    callback = std::move(state_->response_callback);
    subscription = std::move(state_->subscription);
    stream_lease = std::move(state_->stream_lease);
    cancel_timeout = std::move(state_->cancel_timeout);
    callback_runtime_lease = state_->runtime_lease;
  }
  try {
    auto callback_scope = callback_runtime_lease->EnterCallback();
    subscription = {};
  } catch (...) {
    subscription = {};
  }
  stream_lease.reset();
  if (cancel_timeout) {
    try {
      auto callback_scope = callback_runtime_lease->EnterCallback();
      cancel_timeout();
    } catch (...) {
    }
  }
  if (callback) {
    try {
      auto callback_scope = callback_runtime_lease->EnterCallback();
      callback(BuildDetectionSseResponse(events));
    } catch (...) {
    }
  }
  {
    std::lock_guard lock(state_->mutex);
    state_->finish_external_done = true;
    if (state_->active_runtime_callbacks == 0U && !state_->completed) {
      state_->completed = true;
      runtime_lease = std::move(state_->runtime_lease);
    }
  }
  runtime_lease.reset();
}

}  // namespace internal

namespace internal {

std::thread StartServiceThreadWithTlsOwner(
    std::optional<security::ResolvedTlsMaterial> tls_material,
    std::function<void()> run) {
  return std::thread(
      [tls_material = std::move(tls_material), run = std::move(run)]() mutable {
        (void)tls_material;
        run();
      });
}

common::Result<void> StopServiceThreadWithin(
    std::thread& service_thread,
    const std::shared_future<void>& service_thread_done,
    std::chrono::milliseconds timeout,
    const std::function<void()>& request_stop) {
  if (request_stop) {
    request_stop();
  }
  if (!service_thread.joinable()) {
    return common::Result<void>::Ok();
  }
  if (service_thread_done.valid() &&
      service_thread_done.wait_for(timeout) == std::future_status::ready) {
    service_thread.join();
    return common::Result<void>::Ok();
  }

  return common::Result<void>::Err(
      {"E_SERVICE_THREAD_STOP_TIMEOUT",
       "service thread stop timed out; thread remains joinable"});
}

}  // namespace internal

Json::Value BuildHealthJson(const std::string& status) {
  Json::Value json(Json::objectValue);
  json["status"] = status;
  return json;
}

Json::Value BuildCameraStatusJson(const CameraStatus& camera) {
  return BuildCameraStatusJsonValue(camera);
}

Json::Value BuildAiStatusJson(const AiServiceStatus& status) {
  Json::Value json(Json::objectValue);
  json["enabled"] = status.enabled;
  json["backend"] = status.backend;
  json["state"] = status.state;
  json["model_count"] = static_cast<Json::UInt64>(status.model_count);
  json["runner_count"] = static_cast<Json::UInt64>(status.runner_count);
  json["reason"] = status.reason;

  Json::Value models(Json::arrayValue);
  for (const auto& model : status.models) {
    Json::Value model_json(Json::objectValue);
    model_json["id"] = model.id;
    model_json["kind"] = model.kind;
    model_json["input_width"] = model.input_width;
    model_json["input_height"] = model.input_height;
    model_json["input_format"] = model.input_format;
    model_json["letterbox"] = model.letterbox;
    model_json["output_name"] = model.output_name;
    model_json["confidence_threshold"] = model.confidence_threshold;
    model_json["labels"] = model.labels;
    models.append(std::move(model_json));
  }
  json["models"] = std::move(models);

  Json::Value runners(Json::arrayValue);
  for (const auto& runner : status.runners) {
    Json::Value runner_json(Json::objectValue);
    runner_json["camera_id"] = runner.camera_id;
    runner_json["model_id"] = runner.model_id;
    runner_json["model_kind"] = runner.model_kind;
    runner_json["submitted_frames"] =
        static_cast<Json::UInt64>(runner.submitted_frames);
    runner_json["processed_frames"] =
        static_cast<Json::UInt64>(runner.processed_frames);
    runner_json["dropped_frames"] =
        static_cast<Json::UInt64>(runner.dropped_frames);
    runner_json["last_preprocess_ms"] =
        SafeMilliseconds(runner.last_preprocess_ms);
    runner_json["last_inference_ms"] =
        SafeMilliseconds(runner.last_inference_ms);
    runner_json["last_processed_sequence"] =
        static_cast<Json::UInt64>(runner.last_processed_sequence);
    runner_json["last_error_code"] = runner.last_error_code;
    runner_json["last_error_message"] = runner.last_error_message;
    runners.append(std::move(runner_json));
  }
  json["runners"] = std::move(runners);
  return json;
}

Json::Value BuildAiStatusJson(bool requested) {
  AiServiceStatus status;
  if (requested) {
    status.enabled = true;
    status.backend = "hailo";
    status.state = "backend_unavailable";
    status.reason = "Hailo backend is not implemented in this build";
  }
  return BuildAiStatusJson(status);
}

drogon::HttpResponsePtr BuildAiRestartResponse(
    const AiControlCallback& restart_callback,
    const AiStatusProvider& ai_status_provider) {
  if (!restart_callback) {
    Json::Value body(Json::objectValue);
    body["code"] = "E_AI_CONTROL_UNAVAILABLE";
    body["message"] = "AI restart control is unavailable";
    return JsonResponse(std::move(body), drogon::k503ServiceUnavailable);
  }

  auto restarted = restart_callback();
  if (!restarted.ok()) {
    Json::Value body(Json::objectValue);
    body["code"] = restarted.error().code;
    body["message"] = restarted.error().message;
    return JsonResponse(std::move(body), drogon::k500InternalServerError);
  }

  Json::Value body(Json::objectValue);
  body["status"] = "restarted";
  if (ai_status_provider) {
    body["ai"] = BuildAiStatusJson(ai_status_provider());
  }
  return JsonResponse(std::move(body));
}

drogon::HttpResponsePtr BuildRuntimeRestartResponse(
    const RuntimeStartCallback& restart_callback) {
  common::Result<void> restarted = common::Result<void>::Err(
      {"E_RUNTIME_UNAVAILABLE", "camera runtime is unavailable"});
  try {
    if (restart_callback) {
      restarted = restart_callback();
    }
  } catch (...) {
  }
  if (!restarted.ok()) {
    Json::Value body(Json::objectValue);
    body["code"] = "E_RUNTIME_UNAVAILABLE";
    body["message"] = "camera runtime is unavailable";
    return JsonResponse(std::move(body), drogon::k503ServiceUnavailable);
  }

  Json::Value body(Json::objectValue);
  body["runtime"] = "running";
  return JsonResponse(std::move(body));
}

Json::Value BuildDetectionEventJson(const ai::DetectionEvent& event) {
  Json::Value json(Json::objectValue);
  json["camera_id"] = event.camera_id;
  json["model_id"] = event.model_id;
  json["model_kind"] = event.model_kind;
  json["result_state"] = event.result_state;
  json["frame_sequence"] =
      static_cast<Json::UInt64>(event.frame_sequence);
  json["frame_timestamp_ns"] =
      static_cast<Json::Int64>(event.frame_timestamp.count());

  Json::Value detections(Json::arrayValue);
  for (const auto& detection : event.detections) {
    if (detection.class_id < 0) {
      continue;
    }
    Json::Value detection_json(Json::objectValue);
    detection_json["class_id"] = static_cast<Json::Int>(detection.class_id);
    detection_json["label"] = detection.label;
    detection_json["confidence"] = detection.confidence;

    Json::Value box(Json::objectValue);
    box["x"] = detection.box.x;
    box["y"] = detection.box.y;
    box["width"] = detection.box.width;
    box["height"] = detection.box.height;
    detection_json["box"] = std::move(box);

    Json::Value keypoints(Json::arrayValue);
    for (const auto& keypoint : detection.keypoints) {
      Json::Value keypoint_json(Json::objectValue);
      keypoint_json["name"] = keypoint.name;
      keypoint_json["x"] = keypoint.x;
      keypoint_json["y"] = keypoint.y;
      keypoint_json["confidence"] = keypoint.confidence;
      keypoints.append(std::move(keypoint_json));
    }
    detection_json["keypoints"] = std::move(keypoints);

    detections.append(std::move(detection_json));
  }
  json["detections"] = std::move(detections);
  return json;
}

Json::Value BuildDetectionSnapshotJson(
    const std::vector<ai::DetectionEvent>& events) {
  Json::Value json(Json::objectValue);
  Json::Value event_array(Json::arrayValue);
  for (const auto& event : events) {
    event_array.append(BuildDetectionEventJson(event));
  }
  json["events"] = std::move(event_array);
  return json;
}

drogon::HttpResponsePtr BuildDetectionSnapshotResponse(
    const DetectionSnapshotProvider& detection_snapshot_provider) {
  std::vector<ai::DetectionEvent> events;
  if (detection_snapshot_provider) {
    events = detection_snapshot_provider();
  }
  return JsonResponse(BuildDetectionSnapshotJson(events));
}

std::string BuildDetectionSseEvent(
    const std::vector<ai::DetectionEvent>& events) {
  return "id: " + BuildDetectionSseId(events) +
         "\nretry: " + std::to_string(kDetectionSseReconnectMs) +
         "\nevent: detections\ndata: " +
         CompactJson(BuildDetectionSnapshotJson(events)) + "\n\n";
}

std::string BuildDetectionSseId(
    const std::vector<ai::DetectionEvent>& events) {
  if (events.empty()) {
    return "empty";
  }

  std::vector<std::string> parts;
  parts.reserve(events.size());
  for (const auto& event : events) {
    parts.push_back(event.camera_id + "/" + event.model_id + "/" +
                    std::to_string(event.frame_sequence) + "/" +
                    event.result_state);
  }
  std::sort(parts.begin(), parts.end());

  std::string id;
  for (const auto& part : parts) {
    if (!id.empty()) {
      id += "|";
    }
    id += part;
  }
  return id;
}

std::vector<ai::DetectionEvent> MergeDetectionSnapshotWithEvent(
    std::vector<ai::DetectionEvent> events,
    const ai::DetectionEvent& event) {
  const auto same_binding = [&event](const ai::DetectionEvent& stored) {
    return stored.camera_id == event.camera_id &&
           stored.model_id == event.model_id;
  };
  const auto existing =
      std::find_if(events.begin(), events.end(), same_binding);
  if (existing != events.end()) {
    *existing = event;
  } else {
    events.push_back(event);
  }
  return events;
}

drogon::HttpResponsePtr BuildDetectionSseResponse(
    const std::vector<ai::DetectionEvent>& events) {
  auto response = drogon::HttpResponse::newHttpResponse();
  response->setStatusCode(drogon::k200OK);
  response->setContentTypeCodeAndCustomString(drogon::CT_CUSTOM,
                                              "text/event-stream");
  response->addHeader("Cache-Control", "no-cache");
  response->addHeader("X-Accel-Buffering", "no");
  response->setBody(BuildDetectionSseEvent(events));
  return response;
}

Json::Value BuildStreamJson(
    std::string_view public_base_url,
    const config::SecureRtspConfig& secure_rtsp,
    const std::optional<SecureStreamDiagnostics>& diagnostics) {
  Json::Value json(Json::objectValue);
  json["url"] = BuildRtspUrl(public_base_url, secure_rtsp);
  json["control_tls"] = secure_rtsp.control_tls;
  json["media_srtp"] = secure_rtsp.media_srtp;
  Json::Value secure_media = BuildSecureMediaJson(secure_rtsp);
  if (diagnostics.has_value()) {
    secure_media["per_media_key_zeroize_count"] =
        Json::UInt64(diagnostics->per_media_key_zeroize_count);
  }
  json["secure_media"] = std::move(secure_media);
  return json;
}

ServiceListenerConfig BuildServiceListenerConfig(
    const config::HttpConfig& http_config,
    const security::ResolvedTlsMaterial& tls_material) {
  ServiceListenerConfig listener;
  listener.bind_address = http_config.bind_ip;
  listener.port = http_config.port;
  listener.use_tls = true;
  listener.certificate_path = tls_material.certificate_path.string();
  listener.private_key_path = tls_material.private_key_path.string();
  listener.tls_material = tls_material;
  return listener;
}

namespace {

common::Result<void> ValidateHttpTlsConfigShape(
    const config::HttpConfig& http_config) {
  if (!http_config.enabled || !http_config.tls.enabled) {
    return common::Result<void>::Ok();
  }

  const bool has_certificate = !http_config.tls.certificate_path.empty();
  const bool has_private_key = !http_config.tls.private_key_path.empty();
  if (has_certificate != has_private_key) {
    return common::Result<void>::Err(
        {"E_HTTP_TLS_REQUIRED",
         "a complete HTTP TLS certificate and private-key pair is required"});
  }
  if (!has_certificate &&
      !http_config.tls.allow_development_self_signed_tls) {
    return common::Result<void>::Err(
        {"E_HTTP_TLS_REQUIRED", "configured HTTP TLS material is required"});
  }
  return common::Result<void>::Ok();
}

}  // namespace

common::Result<void> ValidateHttpTlsConfigFiles(
    const config::HttpConfig& http_config, crypto::CryptoProvider& provider) {
  auto shape = ValidateHttpTlsConfigShape(http_config);
  if (!shape.ok()) {
    return shape;
  }
  if (!http_config.enabled || !http_config.tls.enabled ||
      http_config.tls.certificate_path.empty()) {
    return shape;
  }

  auto resolved = security::ResolveTlsMaterial(http_config.tls, {}, provider);
  if (!resolved.ok()) {
    return common::Result<void>::Err(
        {"E_HTTP_TLS_CERT",
         "failed to validate configured HTTP TLS certificate/key files"});
  }
  return common::Result<void>::Ok();
}

namespace internal {

common::Result<std::optional<security::ResolvedTlsMaterial>>
SelectServiceTlsMaterial(const ServiceInitArgs& args) {
  auto shape = ValidateHttpTlsConfigShape(args.app_config->http);
  if (!shape.ok()) {
    return common::Result<
        std::optional<security::ResolvedTlsMaterial>>::Err(shape.error());
  }
  if (!args.app_config->http.tls.enabled) {
    return common::Result<
        std::optional<security::ResolvedTlsMaterial>>::Ok(std::nullopt);
  }
  if (args.tls_material) {
    return common::Result<
        std::optional<security::ResolvedTlsMaterial>>::Ok(args.tls_material);
  }

  // ServiceApp does not own a CryptoProvider and must never construct one of
  // its own (that provider would be un-self-tested-before-boot-gated and
  // have no established owner/lifetime). The provider main.cpp constructs
  // and self-tests at boot must already be threaded through args.provider;
  // if it is not, fail closed rather than silently self-provisioning.
  if (args.provider == nullptr) {
    return common::Result<std::optional<security::ResolvedTlsMaterial>>::Err(
        {"E_CRYPTO_UNAVAILABLE",
         "no cryptographic provider was supplied for TLS material "
         "resolution"});
  }
  auto resolved = security::ResolveTlsMaterial(
      args.app_config->http.tls,
      args.app_config->security.state_directory,
      *args.provider);
  if (!resolved.ok()) {
    return common::Result<
        std::optional<security::ResolvedTlsMaterial>>::Err(resolved.error());
  }
  return common::Result<std::optional<security::ResolvedTlsMaterial>>::Ok(
      std::move(resolved).value());
}

}  // namespace internal

drogon::HttpResponsePtr BuildSnapshotResponse(
    const SnapshotCallback& snapshot_callback,
    const std::string& camera_id) {
  if (!snapshot_callback) {
    return JsonResponse(BuildSnapshotUnavailableJson(),
                        drogon::k503ServiceUnavailable);
  }

  auto snapshot = snapshot_callback(camera_id);
  if (!snapshot.has_value() || snapshot->empty()) {
    return JsonResponse(BuildSnapshotUnavailableJson(),
                        drogon::k503ServiceUnavailable);
  }

  auto response = drogon::HttpResponse::newHttpResponse();
  response->setStatusCode(drogon::k200OK);
  response->setContentTypeCode(drogon::CT_IMAGE_JPG);
  response->setBody(std::move(*snapshot));
  return response;
}

drogon::HttpResponsePtr BuildCancellableLiveMp4Response(
    const CancellableLiveMp4OpenCallback& live_stream_callback,
    const std::string& camera_id,
    std::size_t maximum_response_bytes,
    std::shared_ptr<SessionStreamLease> stream_lease) {
  static const auto pump_manager =
      std::make_shared<internal::LiveMp4PumpManager>();
  return BuildManagedLiveMp4Response(
      live_stream_callback, camera_id, maximum_response_bytes,
      std::move(stream_lease), pump_manager);
}

drogon::HttpResponsePtr BuildLiveMp4Response(
    const LiveMp4OpenCallback& live_stream_callback,
    const std::string& camera_id,
    std::size_t maximum_response_bytes,
    std::shared_ptr<SessionStreamLease> stream_lease) {
  auto cancellable = AdaptLegacyLiveMp4OpenCallback(live_stream_callback);
  return BuildCancellableLiveMp4Response(
      cancellable, camera_id, maximum_response_bytes,
      std::move(stream_lease));
}

namespace {

drogon::HttpResponsePtr BuildManagedLiveMp4Response(
    const CancellableLiveMp4OpenCallback& live_stream_callback,
    const std::string& camera_id,
    std::size_t maximum_response_bytes,
    std::shared_ptr<SessionStreamLease> stream_lease,
    std::shared_ptr<internal::LiveMp4PumpManager> pump_manager,
    std::shared_ptr<internal::RuntimeCallbackLifecycle::Lease>
        runtime_lease) {
  if (!live_stream_callback) {
    return JsonResponse(BuildLiveErrorJson("E_LIVE_UNAVAILABLE"),
                        drogon::k503ServiceUnavailable);
  }

  common::Result<LiveMp4StreamHandle> opened =
      common::Result<LiveMp4StreamHandle>::Err(
          {"E_LIVE_UNAVAILABLE", "live preview is unavailable"});
  try {
    if (runtime_lease) {
      auto callback_scope = runtime_lease->EnterCallback();
      opened = live_stream_callback(camera_id);
    } else {
      opened = live_stream_callback(camera_id);
    }
  } catch (...) {
    return JsonResponse(BuildLiveErrorJson("E_LIVE_UNAVAILABLE"),
                        drogon::k503ServiceUnavailable);
  }
  if (!opened.ok()) {
    return JsonResponse(BuildLiveErrorJson(opened.error().code),
                        drogon::k503ServiceUnavailable);
  }

  auto stream = std::move(opened).value();
  if (!stream.read || !stream.cancel || !pump_manager) {
    return JsonResponse(BuildLiveErrorJson("E_LIVE_UNAVAILABLE"),
                        drogon::k503ServiceUnavailable);
  }
  std::shared_ptr<internal::LiveMp4PumpState> pump;
  try {
    pump = internal::LiveMp4PumpState::Create(
        std::move(stream), maximum_response_bytes, std::move(stream_lease));
  } catch (...) {
    return JsonResponse(BuildLiveErrorJson("E_LIVE_UNAVAILABLE"),
                        drogon::k503ServiceUnavailable);
  }
  auto response = drogon::HttpResponse::newAsyncStreamResponse(
      [pump, pump_manager](trantor::AsyncStreamPtr output) {
        try {
          pump_manager->Start(pump, std::move(output));
        } catch (...) {
          pump->CancelAndClose();
        }
      },
      drogon::CT_CUSTOM, "video/mp4");
  response->setStatusCode(drogon::k200OK);
  response->addHeader("Content-Encoding", "identity");
  return response;
}

}  // namespace

ServiceApp::~ServiceApp() {
  const bool on_live_pump =
      live_pump_manager_ && live_pump_manager_->IsPumpThread();
  const bool on_media_callback =
      live_pump_manager_ && live_pump_manager_->IsCurrentMediaCallback();
  const bool on_runtime_callback =
      runtime_lifecycle_ && runtime_lifecycle_->IsCurrentCallbackThread();
  if (on_live_pump || on_media_callback || on_runtime_callback) {
    common::Logger::instance().log(
        common::Logger::Level::kError,
        "ServiceApp destroyed from a managed callback");
    std::terminate();
  }
  Stop();
}

common::Result<void> ServiceApp::Init(const ServiceInitArgs& args) {
  if (args.app_config == nullptr) {
    return common::Result<void>::Err(
        {"E_SERVICE_CONFIG", "ServiceApp::Init requires app_config"});
  }
  const bool protection_configured =
      !args.app_config->self_protection.manifest_path.empty() ||
      !args.app_config->self_protection.signature_path.empty();
  if (args.app_config->security.enabled && protection_configured &&
      !args.protection_runtime_control_gate) {
    return common::Result<void>::Err(
        {"E_SERVICE_CONFIG",
         "self-protection requires an atomic runtime control gate"});
  }
  if (args.app_config->security.enabled &&
      (!args.app_config->http.enabled || !args.app_config->http.tls.enabled)) {
    return common::Result<void>::Err(
        {"E_HTTP_TLS_REQUIRED", "security requires an HTTPS listener"});
  }
  auto selected_tls_material = internal::SelectServiceTlsMaterial(args);
  if (!selected_tls_material.ok()) {
    return common::Result<void>::Err(selected_tls_material.error());
  }

  try {
    ServiceInitArgs effective_args = args;
    internal::InstallDefaultProtectionRuntimeAllowedCallback(
        effective_args, args.app_config->security.enabled);
    if (!effective_args.stream_registry) {
      effective_args.stream_registry =
          std::make_shared<SessionStreamRegistry>();
    }
    auto live_pump_manager =
        std::make_shared<internal::LiveMp4PumpManager>();
    auto runtime_lifecycle =
        std::make_shared<internal::RuntimeCallbackLifecycle>();
    security::DeviceState initial_device_state =
        security::DeviceState::kDefault;
    std::optional<security::InitialAccountCredential> initial_account;
    std::shared_ptr<security::UserManagementService> user_management_service;
    std::shared_ptr<security::AuditLogService> audit_log_service;
    std::shared_ptr<security::AuthService> auth_service;
    std::shared_ptr<BoundedWorker> security_worker;
    std::shared_ptr<BoundedWorker> runtime_settings_worker;
    if (args.app_config->security.enabled) {
      if (!effective_args.security_store) {
        auto opened = security::SecurityStore::Open(
            {args.app_config->security.state_directory,
             args.app_config->security.audit.max_events,
             args.app_config->security.audit.warning_percent});
        if (!opened.ok()) {
          return common::Result<void>::Err(opened.error());
        }
        effective_args.security_store =
            std::shared_ptr<security::SecurityStore>(std::move(opened).value());
      }
      auto state = effective_args.security_store->State();
      if (!state.ok()) {
        return common::Result<void>::Err(state.error());
      }
      initial_device_state = state.value();
      if (initial_device_state == security::DeviceState::kDefault &&
          !effective_args.runtime_start_callback) {
        return common::Result<void>::Err(
            {"E_SERVICE_CONFIG",
             "default security state requires runtime_start_callback"});
      }
      if (!effective_args.bootstrap_service) {
        effective_args.bootstrap_service =
            std::make_shared<security::BootstrapService>(
                *effective_args.security_store, *args.app_config,
                security::BuildReservedIdentities(*args.app_config));
      }
      // First boot: mint the per-device account the operator signs in with to
      // run setup. The plaintext returned here is held in memory only.
      if (initial_device_state == security::DeviceState::kDefault) {
        auto credential =
            effective_args.bootstrap_service->EnsureInitialAccount();
        if (!credential.ok()) {
          return common::Result<void>::Err(credential.error());
        }
        initial_account = std::move(credential).value();
      }
      std::weak_ptr weak_registry = effective_args.stream_registry;
      const auto revoke_sessions =
          [weak_registry](
              std::span<const security::SessionIdentity> identities) {
            if (const auto registry = weak_registry.lock()) {
              registry->Revoke(identities);
            }
          };
      const auto revoke_all_streams = [weak_registry] {
        if (const auto registry = weak_registry.lock()) {
          registry->RevokeAll();
        }
      };
      security::AuthServiceRuntimeHooks hooks;
      hooks.revoke_sessions = revoke_sessions;
      hooks.revoke_all_streams = revoke_all_streams;
      security::AuthServiceDependencies auth_dependencies;
      if (effective_args.auth_service_dependencies_provider) {
        auth_dependencies =
            effective_args.auth_service_dependencies_provider();
      }
      // The account Login() accepts while the device is uninitialized. Assigned
      // rather than merged, and assigned from the same optional that decides
      // whether an initial account was minted at all: a device that booted
      // operational leaves it empty, and no test provider can supply one on its
      // behalf.
      auth_dependencies.initial_account_username =
          initial_account.has_value()
              ? std::optional<std::string>(initial_account->username)
              : std::nullopt;
      auth_service = std::shared_ptr<security::AuthService>(
          new security::AuthService(
              *effective_args.security_store, std::move(auth_dependencies),
              std::move(hooks), {}, [](security::UserRole role) {
                if (internal::ConsumeForcedInvalidLoginRoleForTesting()) {
                  role = static_cast<security::UserRole>(-1);
                }
                return SerializeUserRole(role).has_value();
              }));
      security_worker = std::make_shared<BoundedWorker>(16U);
      audit_log_service = std::make_shared<security::AuditLogService>(
          *effective_args.security_store);
      security::UserManagementDependencies user_management_dependencies;
      user_management_dependencies.revoke_sessions = revoke_sessions;
      user_management_dependencies.revoke_all_streams = revoke_all_streams;
      user_management_service =
          std::make_shared<security::UserManagementService>(
              *effective_args.security_store,
              security::BuildReservedIdentities(*args.app_config),
              std::move(user_management_dependencies));
      if (HasCompleteRuntimeSettingsCallbacks(effective_args)) {
        runtime_settings_worker = std::make_shared<BoundedWorker>(1U);
      }
    }

    std::optional<security::ResolvedTlsMaterial> tls_material =
        std::move(selected_tls_material).value();
    std::shared_ptr<ServiceStartupSignal> startup_signal;
    {
      std::scoped_lock lock(StateMutex());
      GlobalState().args = effective_args;
      GlobalState().auth_service = auth_service;
      GlobalState().audit_log_service = audit_log_service;
      GlobalState().user_management_service = user_management_service;
      GlobalState().security_worker = security_worker;
      GlobalState().runtime_settings_worker = runtime_settings_worker;
      GlobalState().live_pump_manager = live_pump_manager;
      GlobalState().runtime_lifecycle = runtime_lifecycle;
      GlobalState().device_state = initial_device_state;
      GlobalState().initial_account = std::move(initial_account);
      GlobalState().runtime_pending_peer.reset();
      GlobalState().shutting_down = false;
      security_worker_ = security_worker;
      runtime_settings_worker_ = runtime_settings_worker;
      stream_registry_ = effective_args.stream_registry;
      live_pump_manager_ = live_pump_manager;
      runtime_lifecycle_ = runtime_lifecycle;
      {
        std::lock_guard shutdown_lock(shutdown_mutex_);
        if (!shutdown_thread_started_) {
          shutdown_thread_ =
              std::thread([this] { RunShutdownCoordinator(); });
          shutdown_thread_started_ = true;
        }
      }
      if (!initialized_) {
        const auto web_root = std::filesystem::absolute(args.document_root);
        ServiceListenerConfig listener;
        if (tls_material.has_value()) {
          tls_material_ = *tls_material;
          listener = BuildServiceListenerConfig(args.app_config->http,
                                                *tls_material_);
        } else {
          listener.bind_address = args.app_config->http.bind_ip;
          listener.port = args.app_config->http.port;
        }
        drogon::app().setThreadNum(4);
        drogon::app().disableSession();
        drogon::app().setMaxConnectionNum(kMaximumServiceConnections);
        drogon::app().setMaxConnectionNumPerIP(
            kMaximumServiceConnectionsPerIp);
        drogon::app().setClientMaxBodySize(kMaximumTransportBodyBytes);
        drogon::app().setClientMaxMemoryBodySize(
            kMaximumTransportBodyBytes);
        drogon::app().setDocumentRoot(web_root.string());
        drogon::app().addListener(listener.bind_address,
                                  listener.port,
                                  listener.use_tls,
                                  listener.certificate_path,
                                  listener.private_key_path);
        RegisterHandlers();
        initialized_ = true;
      }
      if (!drogon::app().isRunning()) {
        startup_signal = std::make_shared<ServiceStartupSignal>();
        auto thread_completion = std::make_shared<std::promise<void>>();
        server_thread_done_ = thread_completion->get_future().share();
        drogon::app().registerBeginningAdvice(
            [startup_signal] { startup_signal->ReportReady(); });
        server_thread_ = internal::StartServiceThreadWithTlsOwner(
            tls_material_, [startup_signal, thread_completion] {
              ThreadCompletionReporter completion_reporter(thread_completion);
              try {
                drogon::app().run();
                startup_signal->ReportError(
                    {"E_SERVICE_START",
                     "Drogon service stopped before reporting startup readiness"});
              } catch (const std::exception& ex) {
                startup_signal->ReportError(
                    {"E_SERVICE_START",
                     std::string("failed to start service: ") + ex.what()});
              } catch (...) {
                startup_signal->ReportError(
                    {"E_SERVICE_START",
                     "failed to start service: unknown Drogon exception"});
              }
            });
        running_ = true;
      }
    }

    if (startup_signal) {
      auto startup = startup_signal->Wait();
      if (!startup.ok()) {
        auto stopped = internal::StopServiceThreadWithin(
            server_thread_,
            server_thread_done_,
            kServiceThreadStopTimeout,
            [] { drogon::app().quit(); });
        running_ = false;
        if (!stopped.ok()) {
          auto error = common::Result<void>::Err(
              {"E_SERVICE_START",
               startup.error().message + "; " + stopped.error().message});
          Stop();
          return error;
        }
        Stop();
        return startup;
      }
    }
  } catch (const std::exception& ex) {
    Stop();
    return common::Result<void>::Err(
        {"E_SERVICE_START", std::string("failed to start service: ") + ex.what()});
  } catch (...) {
    Stop();
    return common::Result<void>::Err(
        {"E_SERVICE_START", "failed to start service"});
  }

  return common::Result<void>::Ok();
}

void ServiceApp::RunShutdownCoordinator() noexcept {
  trantor::EventLoop* drain_loop = nullptr;
  {
    std::unique_lock shutdown_lock(shutdown_mutex_);
    shutdown_condition_.wait(
        shutdown_lock, [this] { return shutdown_requested_; });
    drain_loop = shutdown_drain_loop_;
  }
  PerformShutdown(drain_loop);
  shutdown_condition_.notify_all();
}

void ServiceApp::PerformShutdown(trantor::EventLoop* drain_loop) noexcept {
  try {
    std::shared_ptr<BoundedWorker> security_worker;
    std::shared_ptr<BoundedWorker> runtime_settings_worker;
    std::shared_ptr<SessionStreamRegistry> stream_registry;
    std::shared_ptr<internal::LiveMp4PumpManager> live_pump_manager;
    std::shared_ptr<internal::RuntimeCallbackLifecycle> runtime_lifecycle;
    {
      std::scoped_lock lock(StateMutex());
      GlobalState().shutting_down = true;
      security_worker = GlobalState().security_worker;
      runtime_settings_worker = GlobalState().runtime_settings_worker;
      stream_registry = GlobalState().args.stream_registry;
      live_pump_manager = GlobalState().live_pump_manager;
      runtime_lifecycle = GlobalState().runtime_lifecycle;
      if (runtime_lifecycle) {
        runtime_lifecycle->CloseAdmission();
      }
    }
    if (stream_registry) {
      try {
        stream_registry->RevokeAll();
      } catch (...) {
        common::Logger::instance().log(
            common::Logger::Level::kWarn,
            "failed to revoke active service streams during shutdown");
      }
    }
    if (security_worker) {
      try {
        security_worker->Stop();
      } catch (...) {
        common::Logger::instance().log(
            common::Logger::Level::kWarn,
            "failed to quiesce service security worker");
      }
    }
    if (runtime_settings_worker) {
      try {
        runtime_settings_worker->Stop();
      } catch (...) {
        common::Logger::instance().log(
            common::Logger::Level::kWarn,
            "failed to quiesce runtime settings worker");
      }
    }
    if (stream_registry) {
      try {
        stream_registry->RevokeAll();
      } catch (...) {
        common::Logger::instance().log(
            common::Logger::Level::kWarn,
            "failed to revoke drained service streams during shutdown");
      }
    }
    if (runtime_lifecycle) {
      try {
        runtime_lifecycle->WaitForDrain();
      } catch (...) {
        common::Logger::instance().log(
            common::Logger::Level::kWarn,
            "failed to drain service runtime callbacks during shutdown");
      }
    }
    if (live_pump_manager) {
      try {
        live_pump_manager->Stop();
      } catch (...) {
        common::Logger::instance().log(
            common::Logger::Level::kWarn,
            "failed to stop live stream pumps during shutdown");
      }
    }

    if (running_ || server_thread_.joinable()) {
      try {
        auto drained = std::make_shared<std::promise<void>>();
        auto drained_future = drained->get_future();
        auto* loop = drain_loop != nullptr ? drain_loop : drogon::app().getLoop();
        loop->runAfter(0.01, [drained] {
          try {
            drained->set_value();
          } catch (...) {
          }
        });
        if (drained_future.wait_for(kServiceThreadStopTimeout) !=
            std::future_status::ready) {
          common::Logger::instance().log(
              common::Logger::Level::kWarn,
              "service event-loop response drain timed out");
        }
      } catch (...) {
        common::Logger::instance().log(
            common::Logger::Level::kWarn,
            "failed to schedule service response drain");
      }

      drogon::app().quit();
      if (server_thread_.joinable()) {
        if (server_thread_done_.valid() &&
            server_thread_done_.wait_for(kServiceThreadStopTimeout) !=
                std::future_status::ready) {
          common::Logger::instance().log(
              common::Logger::Level::kWarn,
              "service thread stop timed out; waiting for safe join");
        }
        server_thread_.join();
      }
      running_ = false;
    }
  } catch (...) {
    common::Logger::instance().log(common::Logger::Level::kWarn,
                                   "service shutdown failed");
  }

  {
    std::scoped_lock lock(StateMutex());
    GlobalState().args = {};
    GlobalState().auth_service.reset();
    GlobalState().audit_log_service.reset();
    GlobalState().user_management_service.reset();
    GlobalState().security_worker.reset();
    GlobalState().runtime_settings_worker.reset();
    GlobalState().live_pump_manager.reset();
    GlobalState().runtime_lifecycle.reset();
    GlobalState().device_state = security::DeviceState::kDefault;
    GlobalState().runtime_pending_peer.reset();
    // GlobalState() is a function-local static, so without this the SecureBytes
    // cleansing destructor would not run until a later Init() overwrites it or
    // the process exits, leaving a live credential resident in a stopped
    // service.
    GlobalState().initial_account.reset();
  }
  security_worker_.reset();
  runtime_settings_worker_.reset();
  stream_registry_.reset();
  live_pump_manager_.reset();
  runtime_lifecycle_.reset();
  tls_material_.reset();
  server_thread_done_ = {};
}

void ServiceApp::JoinShutdownCoordinator() noexcept {
  std::thread join_owner;
  {
    std::unique_lock shutdown_lock(shutdown_mutex_);
    shutdown_condition_.wait(
        shutdown_lock, [this] { return !shutdown_join_in_progress_; });
    if (!shutdown_thread_started_ || shutdown_thread_released_) {
      return;
    }
    shutdown_join_in_progress_ = true;
    shutdown_thread_released_ = true;
    join_owner = std::move(shutdown_thread_);
  }
  join_owner.join();
  {
    std::lock_guard shutdown_lock(shutdown_mutex_);
    shutdown_join_in_progress_ = false;
  }
  shutdown_condition_.notify_all();
}

void ServiceApp::BeginShutdown() noexcept {
  std::shared_ptr<BoundedWorker> security_worker;
  std::shared_ptr<BoundedWorker> runtime_settings_worker;
  std::shared_ptr<SessionStreamRegistry> stream_registry;
  std::shared_ptr<internal::LiveMp4PumpManager> live_pump_manager;
  std::shared_ptr<internal::RuntimeCallbackLifecycle> runtime_lifecycle;
  {
    std::scoped_lock lock(StateMutex());
    GlobalState().shutting_down = true;
    security_worker = GlobalState().security_worker;
    runtime_settings_worker = GlobalState().runtime_settings_worker;
    stream_registry = GlobalState().args.stream_registry;
    live_pump_manager = GlobalState().live_pump_manager;
    runtime_lifecycle = GlobalState().runtime_lifecycle;
    if (runtime_lifecycle) {
      runtime_lifecycle->CloseAdmission();
    }
  }
  const bool on_media_callback =
      live_pump_manager && live_pump_manager->IsCurrentMediaCallback();
  const bool on_runtime_callback =
      runtime_lifecycle && runtime_lifecycle->IsCurrentCallbackThread();
  if (on_media_callback || on_runtime_callback) {
    if (stream_registry) {
      try {
        stream_registry->RevokeAll();
      } catch (...) {
        common::Logger::instance().log(
            common::Logger::Level::kWarn,
            "failed to revoke service streams during callback shutdown");
      }
    }
    return;
  }
  if (stream_registry) {
    try {
      stream_registry->RevokeAll();
    } catch (...) {
      common::Logger::instance().log(
          common::Logger::Level::kWarn,
          "failed to revoke active service streams during shutdown");
    }
  }
  if (security_worker) {
    try {
      security_worker->Stop();
    } catch (...) {
      common::Logger::instance().log(
          common::Logger::Level::kWarn,
          "failed to quiesce service security worker");
    }
  }
  if (runtime_settings_worker) {
    try {
      runtime_settings_worker->Stop();
    } catch (...) {
      common::Logger::instance().log(
          common::Logger::Level::kWarn,
          "failed to quiesce runtime settings worker");
    }
  }
  if (stream_registry) {
    try {
      stream_registry->RevokeAll();
    } catch (...) {
      common::Logger::instance().log(
          common::Logger::Level::kWarn,
          "failed to revoke service streams during shutdown");
    }
  }
  if (runtime_lifecycle) {
    try {
      if (!runtime_lifecycle->IsCurrentCallbackThread()) {
        runtime_lifecycle->WaitForDrain();
      }
    } catch (...) {
      common::Logger::instance().log(
          common::Logger::Level::kWarn,
          "failed to drain service runtime callbacks during shutdown");
    }
  }
  if (live_pump_manager && !on_media_callback) {
    try {
      live_pump_manager->Stop();
    } catch (...) {
      common::Logger::instance().log(
          common::Logger::Level::kWarn,
          "failed to stop live stream pumps during shutdown");
    }
  }
}

void ServiceApp::Stop() {
  std::shared_ptr<internal::LiveMp4PumpManager> live_pump_manager;
  std::shared_ptr<internal::RuntimeCallbackLifecycle> runtime_lifecycle;
  {
    std::scoped_lock lock(StateMutex());
    live_pump_manager = GlobalState().live_pump_manager;
    runtime_lifecycle = GlobalState().runtime_lifecycle;
  }
  const bool on_live_pump =
      live_pump_manager && live_pump_manager->IsPumpThread();
  const bool on_media_callback =
      live_pump_manager && live_pump_manager->IsCurrentMediaCallback();
  const bool on_runtime_callback =
      runtime_lifecycle && runtime_lifecycle->IsCurrentCallbackThread();
  auto* current_loop = trantor::EventLoop::getEventLoopOfCurrentThread();
  bool on_service_loop = false;
  if (current_loop != nullptr && drogon::app().isRunning()) {
    on_service_loop = current_loop == drogon::app().getLoop();
    for (std::size_t index = 0;
         !on_service_loop && index < drogon::app().getThreadNum(); ++index) {
      on_service_loop = current_loop == drogon::app().getIOLoop(index);
    }
  }
  BeginShutdown();

  bool coordinator_started = false;
  {
    std::lock_guard shutdown_lock(shutdown_mutex_);
    if (on_service_loop && shutdown_drain_loop_ == nullptr) {
      shutdown_drain_loop_ = current_loop;
    }
    shutdown_requested_ = true;
    coordinator_started = shutdown_thread_started_;
  }
  shutdown_condition_.notify_all();

  if (!coordinator_started) {
    if (on_live_pump || on_media_callback || on_runtime_callback) {
      return;
    }
    PerformShutdown(nullptr);
    return;
  }
  if (!on_service_loop && !on_live_pump && !on_media_callback &&
      !on_runtime_callback) {
    JoinShutdownCoordinator();
  }
}

}  // namespace camera_firmware::service
