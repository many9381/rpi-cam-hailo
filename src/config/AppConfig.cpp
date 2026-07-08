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

common::Result<AppConfig> TlsCertificateError() {
  return common::Result<AppConfig>::Err(
      {"E_CONFIG_TLS_CERT",
       "secure_rtsp.tls_certificate_path and tls_private_key_path are required "
       "when control_tls is enabled unless "
       "allow_development_self_signed_tls is true"});
}

common::Result<AppConfig> HttpTlsError() {
  return common::Result<AppConfig>::Err(
      {"E_CONFIG_HTTP_TLS",
       "http.tls.certificate_path and private_key_path are required together "
       "when http.tls.enabled is true"});
}

}  // namespace

common::Result<void> ValidateSecureRtspSemantics(
    const SecureRtspConfig& config) {
  if (!config.enabled) {
    return common::Result<void>::Ok();
  }

  if (!config.media_srtp) {
    return common::Result<void>::Ok();
  }

  if (config.keying != "sdes-over-rtsps") {
    return common::Result<void>::Err(
        {"E_CONFIG_SRTP_KEYING",
         "only secure_rtsp.keying=sdes-over-rtsps is supported"});
  }

  if (!config.control_tls) {
    return common::Result<void>::Err(
        {"E_CONFIG_SRTP_KEYING",
         "secure_rtsp.keying=sdes-over-rtsps requires control_tls=true"});
  }

  return common::Result<void>::Ok();
}

common::Result<AppConfig> LoadConfigFile(const std::string& path) {
  try {
    const YAML::Node root = YAML::LoadFile(path);

    AppConfig config;
    const YAML::Node platform = root["platform"];
    if (platform) {
      AssignIfPresent(platform, "target", config.platform.target);
    }

    const YAML::Node camera = root["camera"];
    if (camera) {
      AssignIfPresent(camera, "id", config.camera.id);
      const YAML::Node source = camera["source"];
      if (source) {
        AssignIfPresent(source, "backend", config.camera.source.backend);
        AssignIfPresent(source, "camera_index",
                        config.camera.source.camera_index);
      }
      const YAML::Node video = camera["video"];
      if (video) {
        AssignIfPresent(video, "width", config.camera.video.width);
        AssignIfPresent(video, "height", config.camera.video.height);
        AssignIfPresent(video, "fps", config.camera.video.fps);
        AssignIfPresent(video, "format", config.camera.video.format);
      }
      const YAML::Node encoder = camera["encoder"];
      if (encoder) {
        AssignIfPresent(encoder, "backend", config.camera.encoder.backend);
        AssignIfPresent(encoder, "bitrate_kbps",
                        config.camera.encoder.bitrate_kbps);
        AssignIfPresent(encoder, "gop", config.camera.encoder.gop);
      }
    }

    const YAML::Node http = root["http"];
    if (http) {
      AssignIfPresent(http, "enabled", config.http.enabled);
      AssignIfPresent(http, "bind_ip", config.http.bind_ip);
      AssignIfPresent(http, "port", config.http.port);
      AssignIfPresent(http, "web_root", config.http.web_root);
      AssignIfPresent(http, "public_base_url", config.http.public_base_url);
      const YAML::Node tls = http["tls"];
      if (tls) {
        AssignIfPresent(tls, "enabled", config.http.tls.enabled);
        AssignIfPresent(tls, "certificate_path",
                        config.http.tls.certificate_path);
        AssignIfPresent(tls, "private_key_path",
                        config.http.tls.private_key_path);
      }
    }

    const YAML::Node ai = root["ai"];
    if (ai) {
      AssignIfPresent(ai, "enabled", config.ai.enabled);
      AssignIfPresent(ai, "backend", config.ai.backend);
    }

    const YAML::Node secure_rtsp = root["secure_rtsp"];
    if (secure_rtsp) {
      AssignIfPresent(secure_rtsp, "enabled", config.secure_rtsp.enabled);
      AssignIfPresent(secure_rtsp, "control_tls", config.secure_rtsp.control_tls);
      AssignIfPresent(secure_rtsp, "media_srtp", config.secure_rtsp.media_srtp);
      AssignIfPresent(secure_rtsp, "keying", config.secure_rtsp.keying);
      AssignIfPresent(secure_rtsp,
                      "allow_development_self_signed_tls",
                      config.secure_rtsp.allow_development_self_signed_tls);
      AssignIfPresent(secure_rtsp, "bind_ip", config.secure_rtsp.bind_ip);
      AssignIfPresent(secure_rtsp, "port", config.secure_rtsp.port);
      AssignIfPresent(secure_rtsp, "mount", config.secure_rtsp.mount);
      AssignIfPresent(secure_rtsp,
                      "tls_certificate_path",
                      config.secure_rtsp.tls_certificate_path);
      AssignIfPresent(secure_rtsp,
                      "tls_private_key_path",
                      config.secure_rtsp.tls_private_key_path);

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
    auto secure_rtsp_semantics =
        ValidateSecureRtspSemantics(config.secure_rtsp);
    if (!secure_rtsp_semantics.ok()) {
      return common::Result<AppConfig>::Err(secure_rtsp_semantics.error());
    }
    if (config.secure_rtsp.enabled && config.secure_rtsp.control_tls) {
      const bool has_cert = !config.secure_rtsp.tls_certificate_path.empty();
      const bool has_key = !config.secure_rtsp.tls_private_key_path.empty();
      if (has_cert != has_key ||
          (!config.secure_rtsp.allow_development_self_signed_tls &&
           !has_cert)) {
        return TlsCertificateError();
      }
    }
    if (config.http.enabled && config.http.tls.enabled) {
      const bool has_cert = !config.http.tls.certificate_path.empty();
      const bool has_key = !config.http.tls.private_key_path.empty();
      if (!has_cert || !has_key) {
        return HttpTlsError();
      }
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
