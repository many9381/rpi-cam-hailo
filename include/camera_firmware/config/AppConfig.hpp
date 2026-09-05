#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "camera_firmware/common/Result.hpp"

namespace camera_firmware::config {

inline constexpr std::uint64_t kMaximumAiModelInputBytes =
    16U * 1024U * 1024U;

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
  unsigned int width{1920};
  unsigned int height{1080};
  unsigned int fps{50};
  std::string format{"nv12"};
};

// Encoder bitrate bounds, matched to the runtime-settings validator
// (settings::kMin/kMaxBitrateKbps). A floor is required, not just non-zero:
// the near-CBR VBV buffer is bitrate_kbps/2, so a sub-2kbps bitrate would
// round the buffer to 0 and silently disable VBV.
inline constexpr unsigned int kMinEncoderBitrateKbps = 500U;
inline constexpr unsigned int kMaxEncoderBitrateKbps = 20000U;

struct CameraEncoderConfig {
  std::string backend{"x264"};
  unsigned int bitrate_kbps{6000};
  unsigned int gop{25};
  std::string preset{"ultrafast"};
};

struct CameraSubStreamConfig {
  bool enabled{false};
  unsigned int width{640};
  unsigned int height{360};
  unsigned int fps{15};
  unsigned int bitrate_kbps{1000};
  unsigned int gop{30};
  std::string mount{"/imx708/sub"};
};

// One on-screen-display item. `type` is timestamp | camera_name | custom_text,
// `position` one of the four corners; `text` is the custom text (unused for
// the other types). Set only through runtime settings, never parsed from YAML.
struct CameraOsdItem {
  std::string type;
  std::string text;
  std::string position;
};

struct CameraOsdConfig {
  bool enabled{false};
  std::vector<CameraOsdItem> items;
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
  unsigned int max_fps{0};
};

struct CameraConfig {
  std::string id{"imx708-main"};
  CameraSourceConfig source;
  CameraVideoConfig video;
  CameraEncoderConfig encoder;
  CameraSubStreamConfig sub_stream;
  CameraOsdConfig osd;
  CameraAiConfig ai;
};

struct HttpTlsConfig {
  bool enabled{false};
  bool allow_development_self_signed_tls{false};
  std::string certificate_path;
  std::string private_key_path;
};

struct HttpSnapshotConfig {
  unsigned int stale_timeout_ms{2000};
};

struct HttpLiveConfig {
  bool enabled{true};
  unsigned int fragment_duration_ms{500U};
  unsigned int max_clients{4U};
  unsigned int ring_fragments{8U};
  unsigned int stale_timeout_ms{2000U};
};

struct HttpConfig {
  bool enabled{true};
  std::string bind_ip{"0.0.0.0"};
  std::uint16_t port{8080};
  std::string web_root{"web/dist"};
  std::string public_base_url{"http://127.0.0.1:8080"};
  HttpTlsConfig tls;
  HttpSnapshotConfig snapshot;
  HttpLiveConfig live;
};

struct AiConfig {
  bool enabled{false};
  std::string backend{"disabled"};
  std::vector<AiModelConfig> models;
};

struct AuditConfig {
  std::uint64_t max_events{50000U};
  std::uint32_t warning_percent{90U};
};

struct SecurityConfig {
  bool enabled{true};
  std::string state_directory{"/var/lib/camera-firmware/security"};
  AuditConfig audit;
};

struct SelfProtectionConfig {
  std::string manifest_path;
  std::string signature_path;
  std::uint32_t interval_hours{24U};
};

struct AppConfig {
  PlatformConfig platform;
  CameraConfig camera;
  HttpConfig http;
  AiConfig ai;
  SecureRtspConfig secure_rtsp;
  SecurityConfig security;
  SelfProtectionConfig self_protection;
};

common::Result<AppConfig> LoadConfigFile(const std::string& path);
common::Result<void> ValidateAppConfigSemantics(const AppConfig& config);
// Unconditional (checked even when disabled) so a stored or derived item the
// web client would refuse to render can never reach the pipeline or the UI.
common::Result<void> ValidateCameraOsdSemantics(const CameraOsdConfig& config);
common::Result<void> ValidateAiConfigSemantics(
    const AiConfig& ai_config,
    const CameraConfig& camera_config);
common::Result<void> ValidateSecureRtspSemantics(
    const SecureRtspConfig& config);
common::Result<void> ValidateHttpSnapshotSemantics(
    const HttpSnapshotConfig& config);
common::Result<void> ValidateHttpLiveSemantics(const HttpLiveConfig& config);
common::Result<void> ValidateSecuritySemantics(const AppConfig& config);

}  // namespace camera_firmware::config
