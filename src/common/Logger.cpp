#include "camera_firmware/common/Logger.hpp"

#include <iostream>

namespace camera_firmware::common {

namespace {

const char* ToString(Logger::Level level) noexcept {
  switch (level) {
    case Logger::Level::kDebug:
      return "DEBUG";
    case Logger::Level::kInfo:
      return "INFO";
    case Logger::Level::kWarn:
      return "WARN";
    case Logger::Level::kError:
      return "ERROR";
  }

  return "UNKNOWN";
}

}  // namespace

Logger& Logger::instance() noexcept {
  static Logger logger;
  return logger;
}

void Logger::log(Level level, std::string_view message) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::clog << '[' << ToString(level) << "] " << message << '\n';
}

}  // namespace camera_firmware::common
