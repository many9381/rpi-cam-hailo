#include "camera_firmware/rtsp/SecureRtspServer.hpp"

#include <gst/app/gstappsrc.h>
#include <gst/gst.h>
#include <gst/rtsp-server/rtsp-server.h>
#include <gio/gio.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#if defined(CAMERA_FIRMWARE_HAS_OPENSSL)
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/rtsp/SrtpSessionKey.hpp"

namespace camera_firmware::rtsp {
namespace {

using camera_firmware::common::Error;
using camera_firmware::common::Logger;
using camera_firmware::common::Result;

constexpr const char* kSecureEncoderName = "cfsecuresrtpenc";

GQuark SecureKeyQuark() {
  return g_quark_from_static_string("camera-firmware-secure-srtp-key");
}

GQuark SecureAttachFailureQuark() {
  return g_quark_from_static_string("camera-firmware-secure-attach-failure");
}

std::atomic<std::size_t>& PerMediaKeyZeroizeCount() {
  static std::atomic<std::size_t> count{0};
  return count;
}

struct MediaFeedState {
  explicit MediaFeedState(media::EncodedRing& ring) : reader(ring.NewReader()) {}

  media::EncodedRing::Reader reader;
};

void ZeroizeMemory(unsigned char* data, std::size_t size) noexcept {
  if (data == nullptr || size == 0U) {
    return;
  }
#if defined(CAMERA_FIRMWARE_HAS_OPENSSL)
  OPENSSL_cleanse(data, size);
#else
  volatile unsigned char* cursor = data;
  for (std::size_t index = 0; index < size; ++index) {
    cursor[index] = 0U;
  }
#endif
}

void ZeroizeString(std::string& value) noexcept {
  if (value.empty()) {
    return;
  }
  ZeroizeMemory(reinterpret_cast<unsigned char*>(value.data()), value.size());
  value.clear();
}

std::size_t ZeroizeGstBuffer(GstBuffer* buffer) {
  if (buffer == nullptr) {
    return 0;
  }
  GstMapInfo map{};
  if (!gst_buffer_map(buffer, &map, GST_MAP_WRITE)) {
    return 0;
  }
  ZeroizeMemory(map.data, map.size);
  const std::size_t zeroized = map.size;
  gst_buffer_unmap(buffer, &map);
  return zeroized;
}

void ZeroizeAndUnrefGstBuffer(gpointer user_data) {
  auto* buffer = static_cast<GstBuffer*>(user_data);
  if (ZeroizeGstBuffer(buffer) > 0U) {
    PerMediaKeyZeroizeCount().fetch_add(1U, std::memory_order_relaxed);
  }
  gst_buffer_unref(buffer);
}

void SetAttachFailure(GstRTSPMedia* media, const char* message) {
  g_object_set_qdata_full(G_OBJECT(media),
                          SecureAttachFailureQuark(),
                          g_strdup(message),
                          g_free);
}

GstBuffer* BufferFromBytes(const unsigned char* data, std::size_t size) {
  GstBuffer* buffer = gst_buffer_new_allocate(nullptr, size, nullptr);
  GstMapInfo map{};
  if (!gst_buffer_map(buffer, &map, GST_MAP_WRITE)) {
    gst_buffer_unref(buffer);
    return nullptr;
  }
  std::copy(data, data + size, map.data);
  gst_buffer_unmap(buffer, &map);
  return buffer;
}

GstBuffer* BufferFromSessionKey(const SrtpSessionKey& session_key) {
  return BufferFromBytes(session_key.data(), session_key.size());
}

GstElement* NewSecureEncoder(GstRTSPMedia* media) {
  auto* key = static_cast<GstBuffer*>(
      g_object_get_qdata(G_OBJECT(media), SecureKeyQuark()));
  if (key == nullptr) {
    SetAttachFailure(
        media,
        "E_SRTP_KEY_MISSING: secure media has no session-key buffer attached");
    return nullptr;
  }

  GstElement* encoder = gst_element_factory_make(kSecureEncoderName, nullptr);
  if (encoder == nullptr) {
    SetAttachFailure(
        media,
        "E_SRTP_PLUGIN_NOT_ATTACHED: cfsecuresrtpenc element factory not found");
    return nullptr;
  }

  g_object_set(encoder, "session-key", key, nullptr);
  return encoder;
}

GstElement* RequestRtpEncoder(GstElement*, guint, gpointer user_data) {
  return NewSecureEncoder(GST_RTSP_MEDIA(user_data));
}

GstElement* RequestRtcpEncoder(GstElement*, guint, gpointer user_data) {
  return NewSecureEncoder(GST_RTSP_MEDIA(user_data));
}

struct _CfSecureRtspMedia {
  GstRTSPMedia parent;
};

struct _CfSecureRtspMediaClass {
  GstRTSPMediaClass parent_class;
};

using CfSecureRtspMedia = struct _CfSecureRtspMedia;
using CfSecureRtspMediaClass = struct _CfSecureRtspMediaClass;

G_DEFINE_TYPE(CfSecureRtspMedia, cf_secure_rtsp_media, GST_TYPE_RTSP_MEDIA)

Result<void> AttachSecureEncoderHooks(GstRTSPMedia* media, GstElement* rtpbin) {
  GstElementFactory* factory = gst_element_factory_find(kSecureEncoderName);
  if (factory == nullptr) {
    SetAttachFailure(
        media,
        "E_SRTP_PLUGIN_NOT_ATTACHED: cfsecuresrtpenc element factory not found");
    return Result<void>::Err(
        {"E_SRTP_PLUGIN_NOT_ATTACHED",
         "secure RTSP requires project element cfsecuresrtpenc"});
  }
  gst_object_unref(factory);

  if (g_object_get_qdata(G_OBJECT(media), SecureKeyQuark()) == nullptr) {
    SetAttachFailure(
        media,
        "E_SRTP_KEY_MISSING: secure media has no session-key buffer attached");
    return Result<void>::Err(
        {"E_SRTP_KEY_MISSING",
         "secure RTSP media setup is missing its SRTP session-key buffer"});
  }

  g_signal_connect(rtpbin,
                   "request-rtp-encoder",
                   G_CALLBACK(RequestRtpEncoder),
                   media);
  g_signal_connect(rtpbin,
                   "request-rtcp-encoder",
                   G_CALLBACK(RequestRtcpEncoder),
                   media);
  return Result<void>::Ok();
}

gboolean SetupSecureRtpbin(GstRTSPMedia* media, GstElement* rtpbin) {
  auto* parent_class =
      GST_RTSP_MEDIA_CLASS(cf_secure_rtsp_media_parent_class);
  if (parent_class->setup_rtpbin != nullptr &&
      !parent_class->setup_rtpbin(media, rtpbin)) {
    return FALSE;
  }

  return AttachSecureEncoderHooks(media, rtpbin).ok() ? TRUE : FALSE;
}

void cf_secure_rtsp_media_class_init(CfSecureRtspMediaClass* klass) {
  auto* media_class = GST_RTSP_MEDIA_CLASS(klass);
  media_class->setup_rtpbin = SetupSecureRtpbin;
}

void cf_secure_rtsp_media_init(CfSecureRtspMedia*) {}

GType SecureRtspMediaGType() { return cf_secure_rtsp_media_get_type(); }

void FeedNeedData(GstAppSrc* appsrc, guint, gpointer user_data) {
  auto* state = static_cast<MediaFeedState*>(user_data);
  auto access_unit = state->reader.WaitNext(std::chrono::milliseconds(20));
  if (!access_unit.has_value() || access_unit->bytes.empty()) {
    return;
  }

  GstBuffer* buffer =
      gst_buffer_new_allocate(nullptr, access_unit->bytes.size(), nullptr);
  GstMapInfo map{};
  if (!gst_buffer_map(buffer, &map, GST_MAP_WRITE)) {
    gst_buffer_unref(buffer);
    return;
  }
  std::copy(access_unit->bytes.begin(), access_unit->bytes.end(), map.data);
  gst_buffer_unmap(buffer, &map);

  GST_BUFFER_PTS(buffer) =
      static_cast<GstClockTime>(access_unit->timestamp.count());
  GST_BUFFER_DTS(buffer) = GST_BUFFER_PTS(buffer);
  (void)gst_app_src_push_buffer(appsrc, buffer);
}

void DestroyFeedState(gpointer user_data) {
  delete static_cast<MediaFeedState*>(user_data);
}

void ConfigureAppSrc(GstRTSPMedia* rtsp_media, media::EncodedRing& encoded_ring) {
  GstElement* element = gst_rtsp_media_get_element(rtsp_media);
  if (element == nullptr) {
    return;
  }

  GstElement* source = gst_bin_get_by_name_recurse_up(GST_BIN(element), "feedsrc");
  if (source != nullptr && GST_IS_APP_SRC(source)) {
    GstCaps* caps = gst_caps_new_simple("video/x-h264",
                                        "stream-format",
                                        G_TYPE_STRING,
                                        "byte-stream",
                                        "alignment",
                                        G_TYPE_STRING,
                                        "au",
                                        nullptr);
    gst_app_src_set_caps(GST_APP_SRC(source), caps);
    gst_caps_unref(caps);
    gst_app_src_set_stream_type(GST_APP_SRC(source), GST_APP_STREAM_TYPE_STREAM);
    gst_app_src_set_max_buffers(GST_APP_SRC(source), 8);
    g_object_set(source, "is-live", TRUE, "format", GST_FORMAT_TIME, nullptr);

    GstAppSrcCallbacks callbacks{};
    callbacks.need_data = FeedNeedData;
    gst_app_src_set_callbacks(GST_APP_SRC(source),
                              &callbacks,
                              new MediaFeedState(encoded_ring),
                              DestroyFeedState);
    gst_object_unref(source);
  }
  gst_object_unref(element);
}

Result<GTlsCertificate*> CertificateError(const std::string& message) {
  return Result<GTlsCertificate*>::Err({"E_RTSP_TLS_CERT", message});
}

Result<GTlsCertificate*> LoadTlsCertificateFromFiles(
    const config::SecureRtspConfig& config) {
  GError* error = nullptr;
  GTlsCertificate* certificate =
      g_tls_certificate_new_from_files(config.tls_certificate_path.c_str(),
                                       config.tls_private_key_path.c_str(),
                                       &error);
  if (certificate == nullptr) {
    std::string message =
        "failed to load RTSP TLS certificate/key files from configured paths";
    if (error != nullptr) {
      message += ": ";
      message += error->message;
      g_error_free(error);
    }
    return CertificateError(message);
  }
  return Result<GTlsCertificate*>::Ok(certificate);
}

Result<GTlsCertificate*> NewDevelopmentCertificate() {
#if !defined(CAMERA_FIRMWARE_HAS_OPENSSL)
  return CertificateError(
      "development self-signed TLS requires OpenSSL support at build time");
#else
  EVP_PKEY* private_key =
      EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
  if (private_key == nullptr) {
    return CertificateError("failed to generate development TLS private key");
  }

  X509* certificate = X509_new();
  if (certificate == nullptr) {
    EVP_PKEY_free(private_key);
    return CertificateError("failed to allocate development TLS certificate");
  }

  bool ok = X509_set_version(certificate, 2) == 1;
  ok = ok && ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) == 1;
  ok = ok && X509_gmtime_adj(X509_getm_notBefore(certificate), 0) != nullptr;
  ok = ok &&
       X509_gmtime_adj(X509_getm_notAfter(certificate),
                       30L * 24L * 60L * 60L) != nullptr;
  ok = ok && X509_set_pubkey(certificate, private_key) == 1;

  X509_NAME* subject = X509_get_subject_name(certificate);
  static constexpr unsigned char kCommonName[] = "camera-firmware-dev";
  ok = ok && subject != nullptr;
  ok = ok && X509_NAME_add_entry_by_txt(subject,
                                        "CN",
                                        MBSTRING_ASC,
                                        kCommonName,
                                        -1,
                                        -1,
                                        0) == 1;
  ok = ok && X509_set_issuer_name(certificate, subject) == 1;
  ok = ok && X509_sign(certificate, private_key, EVP_sha256()) > 0;
  if (!ok) {
    X509_free(certificate);
    EVP_PKEY_free(private_key);
    return CertificateError(
        "failed to build development self-signed TLS certificate");
  }

  BIO* bio = BIO_new(BIO_s_mem());
  if (bio == nullptr) {
    X509_free(certificate);
    EVP_PKEY_free(private_key);
    return CertificateError("failed to allocate development TLS PEM buffer");
  }

  ok = PEM_write_bio_X509(bio, certificate) == 1 &&
       PEM_write_bio_PrivateKey(
           bio, private_key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
  X509_free(certificate);
  EVP_PKEY_free(private_key);
  if (!ok) {
    BIO_free(bio);
    return CertificateError("failed to serialize development TLS certificate");
  }

  BUF_MEM* memory = nullptr;
  BIO_get_mem_ptr(bio, &memory);
  if (memory == nullptr || memory->data == nullptr || memory->length == 0U) {
    BIO_free(bio);
    return CertificateError("development TLS PEM buffer is empty");
  }

  std::string pem(memory->data, memory->length);
  OPENSSL_cleanse(memory->data, memory->length);
  BIO_free(bio);

  GError* error = nullptr;
  GTlsCertificate* tls_certificate =
      g_tls_certificate_new_from_pem(pem.data(),
                                     static_cast<gssize>(pem.size()),
                                     &error);
  ZeroizeString(pem);
  if (tls_certificate == nullptr) {
    std::string message =
        "failed to create development self-signed RTSP TLS certificate";
    if (error != nullptr) {
      message += ": ";
      message += error->message;
      g_error_free(error);
    }
    return CertificateError(message);
  }

  Logger::instance().log(
      Logger::Level::kWarn,
      "using development self-signed RTSP TLS certificate from explicit config");
  return Result<GTlsCertificate*>::Ok(tls_certificate);
#endif
}

Result<GTlsCertificate*> NewTlsCertificate(
    const config::SecureRtspConfig& config) {
  const bool has_cert = !config.tls_certificate_path.empty();
  const bool has_key = !config.tls_private_key_path.empty();
  if (has_cert && has_key) {
    return LoadTlsCertificateFromFiles(config);
  }
  if (has_cert != has_key) {
    return CertificateError(
        "both secure_rtsp.tls_certificate_path and tls_private_key_path must "
        "be configured together");
  }
  if (config.allow_development_self_signed_tls) {
    return NewDevelopmentCertificate();
  }
  return CertificateError(
      "secure_rtsp.tls_certificate_path and tls_private_key_path are required "
      "when control_tls is enabled unless allow_development_self_signed_tls is "
      "true");
}

std::string ElementFactoryName(GstElement* element) {
  if (element == nullptr) {
    return {};
  }
  GstElementFactory* factory = gst_element_get_factory(element);
  if (factory == nullptr) {
    return {};
  }
  const gchar* name = gst_plugin_feature_get_name(GST_PLUGIN_FEATURE(factory));
  return name != nullptr ? std::string(name) : std::string();
}

}  // namespace

struct SecureRtspServer::Impl {
  ~Impl() { Stop(); }

  static void OnMediaConfigure(GstRTSPMediaFactory*,
                               GstRTSPMedia* media,
                               gpointer user_data) {
    static_cast<Impl*>(user_data)->ConfigureRtspMedia(media);
  }

  Result<void> Start(const config::SecureRtspConfig& config,
                     media::EncodedRing& encoded_ring) {
    if (running) {
      return Result<void>::Err({"E_RTSP_ALREADY_RUNNING",
                                "SecureRtspServer is already running"});
    }
    if (!config.enabled) {
      Logger::instance().log(Logger::Level::kInfo, "RTSP disabled by config");
      return Result<void>::Ok();
    }
    auto semantics = config::ValidateSecureRtspSemantics(config);
    if (!semantics.ok()) {
      return Result<void>::Err(semantics.error());
    }

    gst_init(nullptr, nullptr);

    if (config.media_srtp) {
      auto verification = VerifySecureEncoderHooks();
      if (!verification.ok()) {
        return Result<void>::Err(verification.error());
      }
      auto loaded_key = LoadSrtpSessionKey(config.session_key);
      if (!loaded_key.ok()) {
        return Result<void>::Err(loaded_key.error());
      }
      session_key = std::move(loaded_key).value();
    }

    server = gst_rtsp_server_new();
    gst_rtsp_server_set_address(server, config.bind_ip.c_str());
    const std::string service = std::to_string(config.port);
    gst_rtsp_server_set_service(server, service.c_str());

    if (config.control_tls) {
      auth = gst_rtsp_auth_new();
      auto certificate = NewTlsCertificate(config);
      if (!certificate.ok()) {
        Stop();
        return Result<void>::Err(certificate.error());
      }
      gst_rtsp_auth_set_tls_certificate(auth, certificate.value());
      tls_certificate = certificate.value();
      gst_rtsp_auth_set_tls_authentication_mode(auth, G_TLS_AUTHENTICATION_NONE);
      gst_rtsp_server_set_auth(server, auth);
    }

    mounts = gst_rtsp_server_get_mount_points(server);
    factory = gst_rtsp_media_factory_new();
    gst_rtsp_media_factory_set_launch(
        factory,
        "( appsrc name=feedsrc is-live=true format=time do-timestamp=true "
        "! h264parse config-interval=1 "
        "! rtph264pay name=pay0 pt=96 config-interval=1 )");
    gst_rtsp_media_factory_set_shared(factory, TRUE);
    gst_rtsp_media_factory_set_enable_rtcp(factory, TRUE);
    if (config.media_srtp) {
      gst_rtsp_media_factory_set_profiles(factory, GST_RTSP_PROFILE_SAVPF);
      gst_rtsp_media_factory_set_media_gtype(factory, SecureRtspMediaGType());
    }
    g_signal_connect(factory,
                     "media-configure",
                     G_CALLBACK(OnMediaConfigure),
                     this);
    ring = &encoded_ring;
    media_srtp_enabled = config.media_srtp;

    gst_rtsp_mount_points_add_factory(mounts, config.mount.c_str(), factory);

    context = g_main_context_new();
    source_id = gst_rtsp_server_attach(server, context);
    if (source_id == 0) {
      Stop();
      return Result<void>::Err(
          {"E_RTSP_ATTACH", "failed to attach RTSP server to main context"});
    }

    loop = g_main_loop_new(context, FALSE);
    stop_requested.store(false, std::memory_order_release);
    thread = std::thread([this] {
      g_main_context_push_thread_default(context);
      if (!stop_requested.load(std::memory_order_acquire)) {
        g_main_loop_run(loop);
      }
      g_main_context_pop_thread_default(context);
    });
    running = true;
    Logger::instance().log(Logger::Level::kInfo,
                           "RTSP ready at " + BuildRtspUrl(config_cache));
    return Result<void>::Ok();
  }

  void ConfigureRtspMedia(GstRTSPMedia* media) {
    if (media_srtp_enabled) {
      gst_rtsp_media_set_profiles(media, GST_RTSP_PROFILE_SAVPF);
      GstBuffer* media_key_buffer =
          session_key.size() > 0U ? BufferFromSessionKey(session_key) : nullptr;
      if (media_key_buffer != nullptr) {
        g_object_set_qdata_full(G_OBJECT(media),
                                SecureKeyQuark(),
                                media_key_buffer,
                                ZeroizeAndUnrefGstBuffer);
      } else {
        SetAttachFailure(
            media,
            "E_SRTP_KEY_BUFFER: failed to allocate per-media SRTP key buffer");
      }
    }
    if (ring != nullptr) {
      ConfigureAppSrc(media, *ring);
    }
  }

  void Stop() {
    stop_requested.store(true, std::memory_order_release);
    if (loop != nullptr) {
      if (context != nullptr) {
        auto* loop_to_quit =
            static_cast<GMainLoop*>(g_main_loop_ref(loop));
        g_main_context_invoke_full(
            context,
            G_PRIORITY_DEFAULT,
            [](gpointer user_data) -> gboolean {
              g_main_loop_quit(static_cast<GMainLoop*>(user_data));
              return G_SOURCE_REMOVE;
            },
            loop_to_quit,
            [](gpointer user_data) {
              g_main_loop_unref(static_cast<GMainLoop*>(user_data));
            });
      }
      g_main_loop_quit(loop);
    }
    if (context != nullptr) {
      g_main_context_wakeup(context);
    }
    if (thread.joinable()) {
      thread.join();
    }
    if (source_id != 0 && context != nullptr) {
      g_source_remove(source_id);
      source_id = 0;
    }
    if (loop != nullptr) {
      g_main_loop_unref(loop);
      loop = nullptr;
    }
    if (factory != nullptr) {
      gst_object_unref(factory);
      factory = nullptr;
    }
    if (mounts != nullptr) {
      gst_object_unref(mounts);
      mounts = nullptr;
    }
    if (auth != nullptr) {
      gst_object_unref(auth);
      auth = nullptr;
    }
    if (tls_certificate != nullptr) {
      g_object_unref(tls_certificate);
      tls_certificate = nullptr;
    }
    if (server != nullptr) {
      gst_object_unref(server);
      server = nullptr;
    }
    if (context != nullptr) {
      g_main_context_unref(context);
      context = nullptr;
    }
    session_key = SrtpSessionKey();
    ring = nullptr;
    media_srtp_enabled = false;
    running = false;
    Logger::instance().log(Logger::Level::kInfo, "SRTP key cleanup complete");
  }

  GstRTSPServer* server{nullptr};
  GstRTSPMountPoints* mounts{nullptr};
  GstRTSPMediaFactory* factory{nullptr};
  GstRTSPAuth* auth{nullptr};
  GTlsCertificate* tls_certificate{nullptr};
  GMainContext* context{nullptr};
  GMainLoop* loop{nullptr};
  guint source_id{0};
  std::thread thread;
  media::EncodedRing* ring{nullptr};
  SrtpSessionKey session_key;
  std::atomic<bool> stop_requested{false};
  bool media_srtp_enabled{false};
  bool running{false};
  config::SecureRtspConfig config_cache;
};

std::string BuildRtspUrl(const config::SecureRtspConfig& config) {
  const std::string scheme = config.control_tls ? "rtsps" : "rtsp";
  return scheme + "://" + config.bind_ip + ":" + std::to_string(config.port) +
         config.mount;
}

Result<void> RegisterBuildTreeSecureSrtpPluginPath(const std::string& path) {
  if (path.empty()) {
    return Result<void>::Ok();
  }
  gst_init(nullptr, nullptr);
  (void)gst_registry_scan_path(gst_registry_get(), path.c_str());
  GstElementFactory* factory = gst_element_factory_find(kSecureEncoderName);
  if (factory == nullptr) {
    return Result<void>::Err(
        {"E_SRTP_PLUGIN_PATH", "failed to scan secure SRTP plugin path"});
  }
  gst_object_unref(factory);
  return Result<void>::Ok();
}

Result<void> VerifySecureMediaPath() {
  auto probe = VerifySecureEncoderHooks();
  if (!probe.ok()) {
    return Result<void>::Err(probe.error());
  }
  return Result<void>::Ok();
}

SecureMediaDescription DescribeSecureMedia(
    const config::SecureRtspConfig& config) {
  SecureMediaDescription description;
  description.control_scheme = config.control_tls ? "rtsps" : "rtsp";
  description.media_profile = config.media_srtp ? "RTP/SAVPF" : "RTP/AVP";
  description.keying =
      config.media_srtp && config.keying == "sdes-over-rtsps"
          ? "SDES-over-RTSPS"
          : "none";
  description.requires_tls_control_channel =
      config.media_srtp && config.keying == "sdes-over-rtsps";
  return description;
}

Result<void> ValidateSecureRtspConfigFiles(
    const config::SecureRtspConfig& config) {
  if (!config.enabled) {
    return Result<void>::Ok();
  }
  auto semantics = config::ValidateSecureRtspSemantics(config);
  if (!semantics.ok()) {
    return Result<void>::Err(semantics.error());
  }
  if (config.media_srtp) {
    auto key = LoadSrtpSessionKey(config.session_key);
    if (!key.ok()) {
      return Result<void>::Err(key.error());
    }
  }
  if (config.control_tls) {
    auto certificate = NewTlsCertificate(config);
    if (!certificate.ok()) {
      return Result<void>::Err(certificate.error());
    }
    g_object_unref(certificate.value());
  }
  return Result<void>::Ok();
}

Result<SecureEncoderHookProbe> VerifySecureEncoderHooks() {
  gst_init(nullptr, nullptr);
  const std::size_t zeroize_count_before =
      PerMediaKeyZeroizeCount().load(std::memory_order_relaxed);
  GstElement* rtpbin = gst_element_factory_make("rtpbin", nullptr);
  if (rtpbin == nullptr) {
    return Result<SecureEncoderHookProbe>::Err(
        {"E_SRTP_RTPBIN",
         "secure RTSP encoder hook verification could not create rtpbin"});
  }

  GstElement* pipeline = gst_pipeline_new("cf-secure-hook-probe");
  if (pipeline == nullptr) {
    gst_object_unref(rtpbin);
    return Result<SecureEncoderHookProbe>::Err(
        {"E_SRTP_HOOK_PROBE",
         "secure RTSP encoder hook verification could not create pipeline"});
  }
  GstRTSPMedia* media = gst_rtsp_media_new(pipeline);
  if (media == nullptr) {
    gst_object_unref(pipeline);
    gst_object_unref(rtpbin);
    return Result<SecureEncoderHookProbe>::Err(
        {"E_SRTP_HOOK_PROBE",
         "secure RTSP encoder hook verification could not create RTSP media"});
  }

  std::array<unsigned char, SrtpSessionKey::kAes128IcmHmacSha180Bytes>
      dummy_key{};
  dummy_key.fill(0x42U);
  GstBuffer* key_buffer =
      BufferFromBytes(dummy_key.data(), dummy_key.size());
  ZeroizeMemory(dummy_key.data(), dummy_key.size());
  if (key_buffer == nullptr) {
    gst_object_unref(media);
    gst_object_unref(rtpbin);
    return Result<SecureEncoderHookProbe>::Err(
        {"E_SRTP_KEY_BUFFER",
         "secure RTSP encoder hook verification could not allocate key buffer"});
  }
  g_object_set_qdata_full(G_OBJECT(media),
                          SecureKeyQuark(),
                          key_buffer,
                          ZeroizeAndUnrefGstBuffer);

  auto attached = AttachSecureEncoderHooks(media, rtpbin);
  if (!attached.ok()) {
    gst_object_unref(media);
    gst_object_unref(rtpbin);
    return Result<SecureEncoderHookProbe>::Err(attached.error());
  }

  GstElement* rtp_encoder = nullptr;
  GstElement* rtcp_encoder = nullptr;
  g_signal_emit_by_name(rtpbin, "request-rtp-encoder", 0U, &rtp_encoder);
  g_signal_emit_by_name(rtpbin, "request-rtcp-encoder", 0U, &rtcp_encoder);

  SecureEncoderHookProbe probe;
  probe.rtp_element_factory_name = ElementFactoryName(rtp_encoder);
  probe.rtcp_element_factory_name = ElementFactoryName(rtcp_encoder);

  if (rtp_encoder != nullptr) {
    gst_object_unref(rtp_encoder);
  }
  if (rtcp_encoder != nullptr) {
    gst_object_unref(rtcp_encoder);
  }
  gst_object_unref(media);
  gst_object_unref(rtpbin);
  probe.per_media_key_zeroize_count =
      PerMediaKeyZeroizeCount().load(std::memory_order_relaxed) -
      zeroize_count_before;

  if (probe.rtp_element_factory_name != kSecureEncoderName) {
    return Result<SecureEncoderHookProbe>::Err(
        {"E_SRTP_ENCODER_REQUEST",
         "request-rtp-encoder did not return cfsecuresrtpenc; refusing stock "
         "srtpenc fallback"});
  }
  if (probe.rtcp_element_factory_name != kSecureEncoderName) {
    return Result<SecureEncoderHookProbe>::Err(
        {"E_SRTP_ENCODER_REQUEST",
         "request-rtcp-encoder did not return cfsecuresrtpenc; refusing stock "
         "srtpenc fallback"});
  }

  return Result<SecureEncoderHookProbe>::Ok(std::move(probe));
}

SecureRtspServer::SecureRtspServer() : impl_(std::make_unique<Impl>()) {}

SecureRtspServer::~SecureRtspServer() = default;

Result<void> SecureRtspServer::Start(const config::SecureRtspConfig& config,
                                     media::EncodedRing& encoded_ring) {
  impl_->config_cache = config;
  return impl_->Start(config, encoded_ring);
}

void SecureRtspServer::Stop() { impl_->Stop(); }

}  // namespace camera_firmware::rtsp
