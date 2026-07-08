#pragma once

#include <mutex>
#include <string_view>

namespace camera_firmware::common {

class Logger {
 public:
  enum class Level {
    kDebug,
    kInfo,
    kWarn,
    kError,
  };

  static Logger& instance() noexcept;

  void log(Level level, std::string_view message);

 private:
  Logger() = default;

  std::mutex mutex_;
};

}  // namespace camera_firmware::common
