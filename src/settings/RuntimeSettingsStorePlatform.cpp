#include <cstddef>
#include <cstdio>

#include <unistd.h>

extern "C" ssize_t camera_firmware_settings_write(int descriptor,
                                                  const void* data,
                                                  size_t size) {
  return ::write(descriptor, data, size);
}

extern "C" int camera_firmware_settings_fdatasync(int descriptor) {
  return ::fdatasync(descriptor);
}

extern "C" int camera_firmware_settings_renameat(int old_directory,
                                                 const char* old_name,
                                                 int new_directory,
                                                 const char* new_name) {
  return ::renameat(old_directory, old_name, new_directory, new_name);
}

extern "C" int camera_firmware_settings_unlinkat(int directory,
                                                 const char* name, int flags) {
  return ::unlinkat(directory, name, flags);
}

extern "C" int camera_firmware_settings_fsync(int descriptor) {
  return ::fsync(descriptor);
}
