#pragma once

namespace camera_firmware::common {

// Sets the calling thread's name (visible in `top -H`,
// /proc/<pid>/task/<tid>/comm). Names longer than 15 characters
// (pthread_setname_np's limit, excluding the NUL terminator) fail silently.
void NameCurrentThread(const char* name) noexcept;

// Lowers (or raises, if negative) the calling thread's scheduling priority by
// `nice_delta` relative to its current value. Returns false if the priority
// could not be read or set. Raising priority requires privileges; only
// lowering (a positive delta) is expected to succeed unprivileged.
bool DeprioritizeCurrentThread(int nice_delta) noexcept;

}  // namespace camera_firmware::common
