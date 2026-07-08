#include "camera_firmware/config/AppConfig.hpp"

#include <yaml-cpp/yaml.h>

#include <exception>
#include <string>

namespace camera_firmware::config {
namespace {

template <typename T>
void AssignIfPresent(const YAML::Node& node, const char* key, T& value) {
  const YAML::Node child = node[key];
  if (child) {
    value = child.as<T>();
  }
}

common::Result<AppConfig> SessionKeyError() {
  return common::Result<AppConfig>::Err(
      {"E_CONFIG_SESSION_KEY",
       "secure_rtsp.session_key.path is required when SRTP is enabled"});
}

}  // namespace

common::Result<AppConfig> LoadConfigFile(const std::string& path) {
  try {
    const YAML::Node root = YAML::LoadFile(path);

    AppConfig config;
    const YAML::Node secure_rtsp = root["secure_rtsp"];
    if (secure_rtsp) {
      AssignIfPresent(secure_rtsp, "enabled", config.secure_rtsp.enabled);
      AssignIfPresent(secure_rtsp, "control_tls", config.secure_rtsp.control_tls);
      AssignIfPresent(secure_rtsp, "media_srtp", config.secure_rtsp.media_srtp);
      AssignIfPresent(secure_rtsp, "bind_ip", config.secure_rtsp.bind_ip);
      AssignIfPresent(secure_rtsp, "port", config.secure_rtsp.port);
      AssignIfPresent(secure_rtsp, "mount", config.secure_rtsp.mount);

      const YAML::Node session_key = secure_rtsp["session_key"];
      if (session_key) {
        AssignIfPresent(session_key, "source", config.secure_rtsp.session_key.source);
        AssignIfPresent(session_key, "path", config.secure_rtsp.session_key.path);
        AssignIfPresent(session_key, "encoding",
                        config.secure_rtsp.session_key.encoding);
        AssignIfPresent(session_key, "zeroize_on_reload",
                        config.secure_rtsp.session_key.zeroize_on_reload);
      }
    }

    if (config.secure_rtsp.enabled && config.secure_rtsp.media_srtp &&
        config.secure_rtsp.session_key.path.empty()) {
      return SessionKeyError();
    }

    return common::Result<AppConfig>::Ok(std::move(config));
  } catch (const YAML::BadFile& ex) {
    return common::Result<AppConfig>::Err(
        {"E_CONFIG_IO", std::string("failed to read config file: ") + ex.what()});
  } catch (const YAML::Exception& ex) {
    return common::Result<AppConfig>::Err(
        {"E_CONFIG_PARSE", std::string("failed to parse config file: ") + ex.what()});
  } catch (const std::exception& ex) {
    return common::Result<AppConfig>::Err(
        {"E_CONFIG_PARSE", std::string("failed to load config file: ") + ex.what()});
  }
}

}  // namespace camera_firmware::config
