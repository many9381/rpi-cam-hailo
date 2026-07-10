#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::config {

struct SessionKeyConfig {
  std::string source{"file"};
  std::string path;
  std::string encoding{"hex"};
  bool zeroize_on_reload{true};
};

struct RtspClientAuthConfig {
  bool enabled{false};
  std::string realm;
  std::string credential_file;
  std::vector<std::string> algorithms{"sha-256"};
  std::uint32_t nonce_ttl_seconds{300};
};

struct SecureRtspConfig {
  bool enabled{true};
  bool control_tls{true};
  bool media_srtp{true};
  std::string keying{"sdes-over-rtsps"};
  bool allow_development_self_signed_tls{false};
  std::string bind_ip{"0.0.0.0"};
  int port{8555};
  std::string mount{"/imx708/main"};
  std::string tls_certificate_path;
  std::string tls_private_key_path;
  SessionKeyConfig session_key;
  RtspClientAuthConfig client_auth;
};

struct PlatformConfig {
  std::string target{"rpi5"};
};

struct CameraSourceConfig {
  std::string backend{"libcamera"};
  unsigned int camera_index{0};
};

struct CameraVideoConfig {
  unsigned int width{1536};
  unsigned int height{864};
  unsigned int fps{30};
  std::string format{"nv12"};
};

struct CameraEncoderConfig {
  std::string backend{"x264"};
  unsigned int bitrate_kbps{3000};
  unsigned int gop{30};
};

struct AiModelInputConfig {
  unsigned int width{640};
  unsigned int height{640};
  std::string format{"rgb8"};
  bool letterbox{true};
};

struct AiModelConfig {
  std::string id;
  std::string kind{"object_detection"};
  std::string hef_path;
  std::string output_name;
  AiModelInputConfig input;
  float confidence_threshold{0.40F};
  std::string labels{"coco80"};
};

struct CameraAiConfig {
  bool enabled{false};
  std::vector<std::string> model_ids;
};

struct CameraConfig {
  std::string id{"imx708-main"};
  CameraSourceConfig source;
  CameraVideoConfig video;
  CameraEncoderConfig encoder;
  CameraAiConfig ai;
};

struct HttpTlsConfig {
  bool enabled{false};
  bool allow_development_self_signed_tls{false};
  std::string certificate_path;
  std::string private_key_path;
};

struct HttpConfig {
  bool enabled{true};
  std::string bind_ip{"0.0.0.0"};
  std::uint16_t port{8080};
  std::string web_root{"web"};
  std::string public_base_url{"http://127.0.0.1:8080"};
  HttpTlsConfig tls;
};

struct AiConfig {
  bool enabled{false};
  std::string backend{"disabled"};
  std::vector<AiModelConfig> models;
};

struct SecurityConfig {
  bool enabled{true};
  std::string state_directory{"/var/lib/camera-firmware/security"};
};

struct AppConfig {
  PlatformConfig platform;
  CameraConfig camera;
  HttpConfig http;
  AiConfig ai;
  SecureRtspConfig secure_rtsp;
  SecurityConfig security;
};

common::Result<AppConfig> LoadConfigFile(const std::string& path);
common::Result<void> ValidateAiConfigSemantics(
    const AiConfig& ai_config,
    const CameraConfig& camera_config);
common::Result<void> ValidateSecureRtspSemantics(
    const SecureRtspConfig& config);
common::Result<void> ValidateSecuritySemantics(const AppConfig& config);

}  // namespace camera_firmware::config
