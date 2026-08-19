#include "camera_firmware/common/ThreadTuning.hpp"

#include <cerrno>

#include <pthread.h>
#include <sys/resource.h>
#include <unistd.h>

namespace camera_firmware::common {

void NameCurrentThread(const char* name) noexcept {
  (void)pthread_setname_np(pthread_self(), name);  // >15 chars fails silently
}

bool DeprioritizeCurrentThread(int nice_delta) noexcept {
  const auto tid = static_cast<id_t>(::gettid());
  errno = 0;
  const int current = getpriority(PRIO_PROCESS, tid);
  if (errno != 0) {
    return false;
  }
  return setpriority(PRIO_PROCESS, tid, current + nice_delta) == 0;
}

}  // namespace camera_firmware::common
