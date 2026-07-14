#include "camera_firmware/config/AppConfig.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <exception>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

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

std::vector<std::string> ReadStringList(const YAML::Node& node) {
  std::vector<std::string> values;
  if (!node || !node.IsSequence()) {
    return values;
  }
  values.reserve(node.size());
  for (const auto& item : node) {
    values.push_back(item.as<std::string>());
  }
  return values;
}

bool IsVisibleAuthField(std::string_view value, std::size_t maximum) {
  return !value.empty() && value.size() <= maximum &&
         std::all_of(value.begin(), value.end(), [](unsigned char ch) {
           return ch >= 0x21U && ch <= 0x7eU;
         });
}

bool IsLexicallyBeneath(const std::filesystem::path& path,
                        const std::filesystem::path& directory) {
  const auto normalized_path = path.lexically_normal();
  const auto normalized_directory = directory.lexically_normal();
  if (normalized_path.empty() || normalized_directory.empty()) {
    return false;
  }

  auto path_component = normalized_path.begin();
  for (auto directory_component = normalized_directory.begin();
       directory_component != normalized_directory.end(); ++directory_component,
            ++path_component) {
    if (path_component == normalized_path.end() ||
        *path_component != *directory_component) {
      return false;
    }
  }
  return path_component != normalized_path.end();
}

}  // namespace

common::Result<void> ValidateAiConfigSemantics(
    const AiConfig& ai_config,
    const CameraConfig& camera_config) {
  if (!ai_config.enabled) {
    if (camera_config.ai.enabled) {
      return common::Result<void>::Err(
          {"E_CONFIG_AI_BACKEND",
           "camera.ai.enabled requires ai.enabled=true"});
    }
    return common::Result<void>::Ok();
  }

  if (ai_config.backend != "hailo") {
    return common::Result<void>::Err(
        {"E_CONFIG_AI_BACKEND", "only ai.backend=hailo is supported"});
  }

  std::unordered_set<std::string> model_ids;
  for (const auto& model : ai_config.models) {
    if (model.id.empty()) {
      return common::Result<void>::Err(
          {"E_CONFIG_AI_MODEL", "ai.models[].id is required"});
    }
    if (!model_ids.insert(model.id).second) {
      return common::Result<void>::Err(
          {"E_CONFIG_AI_MODEL_DUPLICATE",
           "duplicate ai.models[].id: " + model.id});
    }
    if (model.kind != "object_detection" && model.kind != "pose") {
      return common::Result<void>::Err(
          {"E_CONFIG_AI_MODEL",
           "unsupported ai.models[].kind for model " + model.id});
    }
    if (model.hef_path.empty()) {
      return common::Result<void>::Err(
          {"E_CONFIG_AI_MODEL",
           "ai.models[].hef_path is required for model " + model.id});
    }
    if (model.input.width == 0U || model.input.height == 0U) {
      return common::Result<void>::Err(
          {"E_CONFIG_AI_MODEL",
           "ai.models[].input width and height must be positive for model " +
               model.id});
    }
    constexpr std::uint64_t kRgbChannels = 3U;
    const auto input_row_bytes =
        static_cast<std::uint64_t>(model.input.height) * kRgbChannels;
    if (static_cast<std::uint64_t>(model.input.width) >
        kMaximumAiModelInputBytes / input_row_bytes) {
      return common::Result<void>::Err(
          {"E_CONFIG_AI_MODEL",
           "ai.models[].input exceeds the RGB8 memory limit for model " +
               model.id});
    }
    if (model.input.format != "rgb8") {
      return common::Result<void>::Err(
          {"E_CONFIG_AI_MODEL",
           "only ai.models[].input.format=rgb8 is supported"});
    }
    if (model.confidence_threshold < 0.0F ||
        model.confidence_threshold > 1.0F) {
      return common::Result<void>::Err(
          {"E_CONFIG_AI_MODEL",
           "ai.models[].confidence_threshold must be between 0 and 1"});
    }
  }

  if (camera_config.ai.enabled) {
    if (camera_config.ai.model_ids.empty()) {
      return common::Result<void>::Err(
          {"E_CONFIG_AI_CAMERA_MODEL",
           "camera.ai.model_ids must not be empty when camera.ai.enabled=true"});
    }
    std::unordered_set<std::string> camera_model_ids;
    for (const auto& model_id : camera_config.ai.model_ids) {
      if (!camera_model_ids.insert(model_id).second) {
        return common::Result<void>::Err(
            {"E_CONFIG_AI_CAMERA_MODEL",
             "duplicate camera.ai.model_ids entry: " + model_id});
      }
      if (!model_ids.contains(model_id)) {
        return common::Result<void>::Err(
            {"E_CONFIG_AI_CAMERA_MODEL",
             "camera.ai.model_ids references unknown model: " + model_id});
      }
    }
  }

  return common::Result<void>::Ok();
}

common::Result<void> ValidateSecureRtspSemantics(
    const SecureRtspConfig& config) {
  if (config.client_auth.enabled) {
    if (!config.enabled || !config.control_tls) {
      return common::Result<void>::Err(
          {"E_CONFIG_RTSP_AUTH_TLS",
           "secure_rtsp.client_auth requires enabled RTSPS"});
    }
    if (!IsVisibleAuthField(config.client_auth.realm, 128U) ||
        config.client_auth.realm.find_first_of(":\"\\\r\n") !=
            std::string::npos) {
      return common::Result<void>::Err(
          {"E_CONFIG_RTSP_AUTH_REALM",
           "secure_rtsp.client_auth.realm is invalid"});
    }
    if (config.client_auth.credential_file.empty()) {
      return common::Result<void>::Err(
          {"E_CONFIG_RTSP_AUTH",
           "secure_rtsp.client_auth.credential_file is required"});
    }
    const std::unordered_set<std::string> algorithms(
        config.client_auth.algorithms.begin(),
        config.client_auth.algorithms.end());
    if (algorithms.size() != config.client_auth.algorithms.size() ||
        !algorithms.contains("sha-256") ||
        (algorithms.size() == 2U && !algorithms.contains("md5")) ||
        algorithms.size() > 2U) {
      return common::Result<void>::Err(
          {"E_CONFIG_RTSP_AUTH_ALGORITHM",
           "secure_rtsp.client_auth.algorithms is invalid"});
    }
    if (config.client_auth.nonce_ttl_seconds < 30U ||
        config.client_auth.nonce_ttl_seconds > 3600U) {
      return common::Result<void>::Err(
          {"E_CONFIG_RTSP_AUTH",
           "secure_rtsp.client_auth.nonce_ttl_seconds is invalid"});
    }
  }

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

common::Result<void> ValidateHttpSnapshotSemantics(
    const HttpSnapshotConfig& config) {
  if (config.stale_timeout_ms < 500U ||
      config.stale_timeout_ms > 10000U) {
    return common::Result<void>::Err(
        {"E_CONFIG_HTTP_SNAPSHOT", "http.snapshot configuration is invalid"});
  }

  return common::Result<void>::Ok();
}

common::Result<void> ValidateHttpLiveSemantics(const HttpLiveConfig& config) {
  if (config.fragment_duration_ms < 100U ||
      config.fragment_duration_ms > 5000U || config.max_clients < 1U ||
      config.max_clients > 16U || config.ring_fragments < 2U ||
      config.ring_fragments > 64U || config.stale_timeout_ms < 500U ||
      config.stale_timeout_ms > 10000U ||
      static_cast<std::uint64_t>(config.stale_timeout_ms) <
          static_cast<std::uint64_t>(config.fragment_duration_ms) * 2U) {
    return common::Result<void>::Err(
        {"E_CONFIG_HTTP_LIVE", "http.live configuration is invalid"});
  }
  return common::Result<void>::Ok();
}

common::Result<void> ValidateSecuritySemantics(const AppConfig& config) {
  if (!config.security.enabled) {
    return common::Result<void>::Ok();
  }

  if (!config.http.enabled || !config.http.tls.enabled) {
    return common::Result<void>::Err(
        {"E_SECURITY_TLS", "security requires enabled HTTPS"});
  }
  if (!config.http.public_base_url.starts_with("https://")) {
    return common::Result<void>::Err(
        {"E_SECURITY_PUBLIC_URL", "security requires an https public URL"});
  }
  if (!config.secure_rtsp.client_auth.enabled ||
      config.secure_rtsp.client_auth.algorithms.size() != 1U ||
      config.secure_rtsp.client_auth.algorithms.front() != "sha-256") {
    return common::Result<void>::Err(
        {"E_SECURITY_RTSP_AUTH",
         "security requires SHA-256 RTSP Digest authentication"});
  }
  if (!IsLexicallyBeneath(config.secure_rtsp.client_auth.credential_file,
                          config.security.state_directory)) {
    return common::Result<void>::Err(
        {"E_SECURITY_CREDENTIAL_PATH",
         "RTSP credentials must be located beneath the security state directory"});
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
        AssignIfPresent(encoder, "preset", config.camera.encoder.preset);
      }
      const YAML::Node camera_ai = camera["ai"];
      if (camera_ai) {
        AssignIfPresent(camera_ai, "enabled", config.camera.ai.enabled);
        config.camera.ai.model_ids = ReadStringList(camera_ai["model_ids"]);
      }
    }

    const YAML::Node http = root["http"];
    if (http) {
      if (http["preview"].IsDefined()) {
        return common::Result<AppConfig>::Err(
            {"E_CONFIG_HTTP_PREVIEW_RETIRED",
             "http.preview is retired; use http.snapshot and http.live"});
      }
      AssignIfPresent(http, "enabled", config.http.enabled);
      AssignIfPresent(http, "bind_ip", config.http.bind_ip);
      AssignIfPresent(http, "port", config.http.port);
      AssignIfPresent(http, "web_root", config.http.web_root);
      AssignIfPresent(http, "public_base_url", config.http.public_base_url);
      const YAML::Node snapshot = http["snapshot"];
      if (snapshot) {
        AssignIfPresent(snapshot, "stale_timeout_ms",
                        config.http.snapshot.stale_timeout_ms);
      }
      const YAML::Node live = http["live"];
      if (live) {
        AssignIfPresent(live, "enabled", config.http.live.enabled);
        AssignIfPresent(live, "fragment_duration_ms",
                        config.http.live.fragment_duration_ms);
        AssignIfPresent(live, "max_clients", config.http.live.max_clients);
        AssignIfPresent(live, "ring_fragments",
                        config.http.live.ring_fragments);
        AssignIfPresent(live, "stale_timeout_ms",
                        config.http.live.stale_timeout_ms);
      }
      const YAML::Node tls = http["tls"];
      if (tls) {
        AssignIfPresent(tls, "enabled", config.http.tls.enabled);
        AssignIfPresent(tls, "allow_development_self_signed_tls",
                        config.http.tls.allow_development_self_signed_tls);
        AssignIfPresent(tls, "certificate_path",
                        config.http.tls.certificate_path);
        AssignIfPresent(tls, "private_key_path",
                        config.http.tls.private_key_path);
      }
    }

    const YAML::Node security = root["security"];
    if (security) {
      AssignIfPresent(security, "enabled", config.security.enabled);
      AssignIfPresent(security, "state_directory",
                      config.security.state_directory);
    }

    const YAML::Node ai = root["ai"];
    if (ai) {
      AssignIfPresent(ai, "enabled", config.ai.enabled);
      AssignIfPresent(ai, "backend", config.ai.backend);
      const YAML::Node models = ai["models"];
      if (models && models.IsSequence()) {
        config.ai.models.clear();
        for (const auto& model : models) {
          AiModelConfig parsed_model;
          AssignIfPresent(model, "id", parsed_model.id);
          AssignIfPresent(model, "kind", parsed_model.kind);
          AssignIfPresent(model, "hef_path", parsed_model.hef_path);
          AssignIfPresent(model, "output_name", parsed_model.output_name);
          AssignIfPresent(model, "confidence_threshold",
                          parsed_model.confidence_threshold);
          AssignIfPresent(model, "labels", parsed_model.labels);
          const YAML::Node input = model["input"];
          if (input) {
            AssignIfPresent(input, "width", parsed_model.input.width);
            AssignIfPresent(input, "height", parsed_model.input.height);
            AssignIfPresent(input, "format", parsed_model.input.format);
            AssignIfPresent(input, "letterbox", parsed_model.input.letterbox);
          }
          config.ai.models.push_back(std::move(parsed_model));
        }
      }
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

      const YAML::Node client_auth = secure_rtsp["client_auth"];
      if (client_auth) {
        AssignIfPresent(client_auth, "enabled",
                        config.secure_rtsp.client_auth.enabled);
        AssignIfPresent(client_auth, "realm",
                        config.secure_rtsp.client_auth.realm);
        AssignIfPresent(client_auth, "credential_file",
                        config.secure_rtsp.client_auth.credential_file);
        const YAML::Node algorithms = client_auth["algorithms"];
        if (algorithms) {
          config.secure_rtsp.client_auth.algorithms =
              ReadStringList(algorithms);
        }
        AssignIfPresent(client_auth, "nonce_ttl_seconds",
                        config.secure_rtsp.client_auth.nonce_ttl_seconds);
      }

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
    auto ai_semantics = ValidateAiConfigSemantics(config.ai, config.camera);
    if (!ai_semantics.ok()) {
      return common::Result<AppConfig>::Err(ai_semantics.error());
    }
    auto secure_rtsp_semantics =
        ValidateSecureRtspSemantics(config.secure_rtsp);
    if (!secure_rtsp_semantics.ok()) {
      return common::Result<AppConfig>::Err(secure_rtsp_semantics.error());
    }
    auto http_snapshot_semantics =
        ValidateHttpSnapshotSemantics(config.http.snapshot);
    if (!http_snapshot_semantics.ok()) {
      return common::Result<AppConfig>::Err(http_snapshot_semantics.error());
    }
    auto http_live_semantics = ValidateHttpLiveSemantics(config.http.live);
    if (!http_live_semantics.ok()) {
      return common::Result<AppConfig>::Err(http_live_semantics.error());
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
      if (has_cert != has_key ||
          (!config.http.tls.allow_development_self_signed_tls && !has_cert)) {
        return HttpTlsError();
      }
    }

    auto security_semantics = ValidateSecuritySemantics(config);
    if (!security_semantics.ok()) {
      return common::Result<AppConfig>::Err(security_semantics.error());
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
