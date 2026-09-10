#include <linux/fs.h>
#include <sys/syscall.h>
#include <unistd.h>

extern "C" int camera_firmware_tls_rename_noreplace(int old_directory,
                                                    const char* old_name,
                                                    int new_directory,
                                                    const char* new_name) {
  return static_cast<int>(::syscall(SYS_renameat2, old_directory, old_name,
                                    new_directory, new_name, RENAME_NOREPLACE));
}
