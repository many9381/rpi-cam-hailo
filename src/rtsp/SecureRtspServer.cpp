#include "camera_firmware/rtsp/SecureRtspServer.hpp"

#include "GstRtspClientLifecycle.hpp"

#include <gst/app/gstappsrc.h>
#include <gst/gst.h>
#include <gst/rtsp-server/rtsp-server.h>
#include <gst/rtsp-server/rtsp-sdp.h>
#include <gio/gio.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(CAMERA_FIRMWARE_HAS_OPENSSL)
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/common/ThreadTuning.hpp"
#include "camera_firmware/rtsp/GstRtspDigestAuth.hpp"
#include "camera_firmware/rtsp/RtspDigestVerifier.hpp"
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

std::atomic<std::size_t>& PerMediaKeyZeroizeCounter() {
  static std::atomic<std::size_t> count{0};
  return count;
}

std::atomic<std::size_t>& PerMediaKeyAllocationCounter() {
  static std::atomic<std::size_t> count{0};
  return count;
}

GstRTSPFilterResult CloseManagedClient(GstRTSPServer*, GstRTSPClient*,
                                       gpointer) {
  return GST_RTSP_FILTER_REMOVE;
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
    PerMediaKeyZeroizeCounter().fetch_add(1U, std::memory_order_relaxed);
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

GstElement* NewSecureEncoder(GstRTSPMedia* media,
                             std::string_view sink_pad_name) {
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
  const std::string pad_name(sink_pad_name);
  GstPad* sink = gst_element_request_pad_simple(encoder, pad_name.c_str());
  if (sink == nullptr) {
    gst_object_unref(encoder);
    SetAttachFailure(
        media,
        "E_SRTP_ENCODER_PAD: secure encoder request pad is unavailable");
    return nullptr;
  }
  gst_object_unref(sink);
  return encoder;
}

GstElement* RequestRtpEncoder(GstElement* rtpbin,
                              guint session,
                              gpointer user_data) {
  g_signal_stop_emission_by_name(rtpbin, "request-rtp-encoder");
  return NewSecureEncoder(GST_RTSP_MEDIA(user_data),
                          "rtp_sink_" + std::to_string(session));
}

GstElement* RequestRtcpEncoder(GstElement* rtpbin,
                               guint session,
                               gpointer user_data) {
  g_signal_stop_emission_by_name(rtpbin, "request-rtcp-encoder");
  return NewSecureEncoder(GST_RTSP_MEDIA(user_data),
                          "rtcp_sink_" + std::to_string(session));
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

bool AddSdesCryptoAttribute(GstRTSPMedia* media, GstSDPMedia* sdp_media) {
  auto* key = static_cast<GstBuffer*>(
      g_object_get_qdata(G_OBJECT(media), SecureKeyQuark()));
  if (key == nullptr) {
    SetAttachFailure(media,
                     "E_SRTP_KEY_MISSING: secure SDP has no session key");
    return false;
  }
  GstMapInfo map{};
  const bool mapped = gst_buffer_map(key, &map, GST_MAP_READ);
  if (!mapped || map.data == nullptr ||
      map.size != SrtpSessionKey::kAes128IcmHmacSha180Bytes) {
    if (mapped) {
      gst_buffer_unmap(key, &map);
    }
    SetAttachFailure(media,
                     "E_SRTP_KEY_LENGTH: secure SDP session key is invalid");
    return false;
  }

  gchar* encoded = g_base64_encode(map.data, map.size);
  gst_buffer_unmap(key, &map);
  if (encoded == nullptr) {
    SetAttachFailure(media,
                     "E_SRTP_KEY_ENCODE: secure SDP key encoding failed");
    return false;
  }
  gchar* attribute = g_strdup_printf(
      "1 AES_CM_128_HMAC_SHA1_80 inline:%s", encoded);
  bool added = attribute != nullptr &&
               gst_sdp_media_add_attribute(sdp_media, "crypto", attribute) ==
                   GST_SDP_OK;
  ZeroizeMemory(reinterpret_cast<unsigned char*>(encoded),
                std::strlen(encoded));
  g_free(encoded);
  if (attribute != nullptr) {
    ZeroizeMemory(reinterpret_cast<unsigned char*>(attribute),
                  std::strlen(attribute));
    g_free(attribute);
  }
  if (!added) {
    SetAttachFailure(media,
                     "E_SRTP_SDP: secure SDP crypto attribute failed");
  }
  return added;
}

gboolean SetupSecureSdp(GstRTSPMedia* media,
                        GstSDPMessage* sdp,
                        GstSDPInfo* info) {
  gchar* range =
      gst_rtsp_media_get_range_string(media, FALSE, GST_RTSP_RANGE_NPT);
  if (range == nullptr) {
    return FALSE;
  }
  const bool range_added =
      gst_sdp_message_add_attribute(sdp, "range", range) == GST_SDP_OK;
  g_free(range);
  if (!range_added) {
    return FALSE;
  }

  const guint stream_count = gst_rtsp_media_n_streams(media);
  for (guint index = 0U; index < stream_count; ++index) {
    GstRTSPStream* stream = gst_rtsp_media_get_stream(media, index);
    GstCaps* source_caps =
        stream != nullptr ? gst_rtsp_stream_get_caps(stream) : nullptr;
    if (source_caps == nullptr) {
      return FALSE;
    }
    GstCaps* public_caps = gst_caps_copy(source_caps);
    gst_caps_unref(source_caps);
    if (public_caps == nullptr || gst_caps_is_empty(public_caps)) {
      if (public_caps != nullptr) {
        gst_caps_unref(public_caps);
      }
      return FALSE;
    }
    for (guint structure_index = 0U;
         structure_index < gst_caps_get_size(public_caps);
         ++structure_index) {
      GstStructure* structure =
          gst_caps_get_structure(public_caps, structure_index);
      gst_structure_set_name(structure, "application/x-rtp");
      gst_structure_remove_fields(structure,
                                  "srtp-cipher",
                                  "srtp-auth",
                                  "srtcp-cipher",
                                  "srtcp-auth",
                                  "srtp-key",
                                  nullptr);
    }

    GstSDPMessage* stream_sdp = nullptr;
    if (gst_sdp_message_new(&stream_sdp) != GST_SDP_OK ||
        stream_sdp == nullptr ||
        !gst_rtsp_sdp_make_media(stream_sdp,
                                 info,
                                 stream,
                                 public_caps,
                                 GST_RTSP_PROFILE_SAVPF)) {
      gst_caps_unref(public_caps);
      if (stream_sdp != nullptr) {
        gst_sdp_message_free(stream_sdp);
      }
      return FALSE;
    }
    gst_caps_unref(public_caps);

    const GstSDPMedia* generated = gst_sdp_message_get_media(stream_sdp, 0U);
    GstSDPMedia* media_copy = nullptr;
    const bool copied = generated != nullptr &&
                        gst_sdp_media_copy(generated, &media_copy) == GST_SDP_OK;
    gst_sdp_message_free(stream_sdp);
    if (!copied || media_copy == nullptr) {
      return FALSE;
    }
    const bool added = AddSdesCryptoAttribute(media, media_copy) &&
                       gst_sdp_message_add_media(sdp, media_copy) == GST_SDP_OK;
    gst_sdp_media_free(media_copy);
    if (!added) {
      return FALSE;
    }
  }
  return TRUE;
}

void cf_secure_rtsp_media_class_init(CfSecureRtspMediaClass* klass) {
  auto* media_class = GST_RTSP_MEDIA_CLASS(klass);
  media_class->setup_rtpbin = SetupSecureRtpbin;
  media_class->setup_sdp = SetupSecureSdp;
}

void cf_secure_rtsp_media_init(CfSecureRtspMedia*) {}

GType SecureRtspMediaGType() { return cf_secure_rtsp_media_get_type(); }

void FeedNeedData(GstAppSrc* appsrc, guint, gpointer user_data) {
  auto* state = static_cast<MediaFeedState*>(user_data);
  auto access_unit = state->reader.WaitNext(std::chrono::milliseconds(20));
  if (!access_unit.has_value() || access_unit->bytes == nullptr ||
      access_unit->bytes->empty()) {
    return;
  }

  // Zero-copy handoff: borrow the refcounted access-unit payload; the
  // destroy-notify releases the reference when GStreamer is done with it.
  auto* keepalive = new std::shared_ptr<const std::vector<std::uint8_t>>(
      access_unit->bytes);
  GstBuffer* buffer = gst_buffer_new_wrapped_full(
      GST_MEMORY_FLAG_READONLY,
      const_cast<std::uint8_t*>((*keepalive)->data()), (*keepalive)->size(),
      0U, (*keepalive)->size(), keepalive, [](gpointer pointer) {
        delete static_cast<
            std::shared_ptr<const std::vector<std::uint8_t>>*>(pointer);
      });
  if (buffer == nullptr) {
    delete keepalive;
    return;
  }

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
  struct TrackedMediaKey {
    GstRTSPMedia* media{nullptr};
    gulong unprepared_handler{0U};
  };

  ~Impl() { Stop(); }

  static void OnMediaConfigure(GstRTSPMediaFactory*,
                               GstRTSPMedia* media,
                               gpointer user_data) {
    static_cast<Impl*>(user_data)->ConfigureRtspMedia(media);
  }

  static void OnMediaUnprepared(GstRTSPMedia* media, gpointer user_data) {
    static_cast<Impl*>(user_data)->ReleaseTrackedMediaKey(media);
  }

  static void OnSubMediaConfigure(GstRTSPMediaFactory*,
                                  GstRTSPMedia* media,
                                  gpointer user_data) {
    static_cast<Impl*>(user_data)->ConfigureSubRtspMedia(media);
  }

  static void OnSubMediaUnprepared(GstRTSPMedia*, gpointer user_data) {
    auto* impl = static_cast<Impl*>(user_data);
    if (impl->sub_on_deactivate) {
      impl->sub_on_deactivate();
    }
  }

  // Builds a media factory with the shared launch string / TLS / SRTP /
  // permissions setup used by every mount, and connects the supplied
  // media-configure callback. The caller owns registering it with the
  // mount points and clearing the returned pointer once ownership transfers.
  GstRTSPMediaFactory* BuildMountFactory(const config::SecureRtspConfig& config,
                                        GCallback configure_callback,
                                        gpointer configure_user_data) {
    GstRTSPMediaFactory* new_factory = gst_rtsp_media_factory_new();
    gst_rtsp_media_factory_set_launch(
        new_factory,
        "( appsrc name=feedsrc is-live=true format=time do-timestamp=true "
        "! h264parse config-interval=1 "
        "! rtph264pay name=pay0 pt=96 config-interval=1 )");
    gst_rtsp_media_factory_set_shared(new_factory, TRUE);
    gst_rtsp_media_factory_set_enable_rtcp(new_factory, TRUE);
    gst_rtsp_media_factory_set_stop_on_disconnect(new_factory, TRUE);
    if (config.media_srtp) {
      gst_rtsp_media_factory_set_profiles(new_factory, GST_RTSP_PROFILE_SAVPF);
      gst_rtsp_media_factory_set_media_gtype(new_factory,
                                             SecureRtspMediaGType());
    }
    if (config.client_auth.enabled) {
      GstRTSPPermissions* permissions = gst_rtsp_permissions_new();
      gst_rtsp_permissions_add_role(
          permissions,
          "viewer",
          GST_RTSP_PERM_MEDIA_FACTORY_ACCESS,
          G_TYPE_BOOLEAN,
          TRUE,
          GST_RTSP_PERM_MEDIA_FACTORY_CONSTRUCT,
          G_TYPE_BOOLEAN,
          TRUE,
          nullptr);
      gst_rtsp_media_factory_set_permissions(new_factory, permissions);
      gst_rtsp_permissions_unref(permissions);
    }
    g_signal_connect(new_factory, "media-configure", configure_callback,
                     configure_user_data);
    return new_factory;
  }

  Result<void> Start(const config::SecureRtspConfig& config,
                     media::EncodedRing& encoded_ring,
                     const media::SubMountDescriptor* sub) {
    if (running) {
      return Result<void>::Err({"E_RTSP_ALREADY_RUNNING",
                                "SecureRtspServer is already running"});
    }
    config_cache = config;
    ResetRuntimeKeyBaselines();
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
      ResetRuntimeKeyBaselines();
      auto loaded_key = LoadSrtpSessionKey(config.session_key);
      if (!loaded_key.ok()) {
        return Result<void>::Err(loaded_key.error());
      }
      session_key = std::move(loaded_key).value();
    }

    server = gst_rtsp_server_new();
    auto tracked_clients = internal::GstRtspClientLifecycle::Attach(server);
    if (!tracked_clients.ok()) {
      Stop();
      return Result<void>::Err(tracked_clients.error());
    }
    client_lifecycle = std::move(tracked_clients).value();
    gst_rtsp_server_set_address(server, config.bind_ip.c_str());
    const std::string service = std::to_string(config.port);
    gst_rtsp_server_set_service(server, service.c_str());

    if (config.control_tls) {
      if (config.client_auth.enabled) {
        auto created = NewGstCfRtspDigestAuth(config.client_auth);
        if (!created.ok()) {
          Stop();
          return Result<void>::Err(created.error());
        }
        auth = created.value();
      } else {
        auth = gst_rtsp_auth_new();
      }
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
    ring = &encoded_ring;
    media_srtp_enabled = config.media_srtp;
    factory = BuildMountFactory(config, G_CALLBACK(OnMediaConfigure), this);

    gst_rtsp_mount_points_add_factory(mounts, config.mount.c_str(), factory);
    factory = nullptr;
    factory_mounted = true;

    if (sub != nullptr) {
      sub_ring = sub->ring;
      sub_on_activate = sub->on_activate;
      sub_on_deactivate = sub->on_deactivate;
      sub_mount_path = sub->mount;
      sub_factory =
          BuildMountFactory(config, G_CALLBACK(OnSubMediaConfigure), this);
      gst_rtsp_mount_points_add_factory(mounts, sub->mount.c_str(),
                                        sub_factory);
      sub_factory = nullptr;
      sub_factory_mounted = true;
    }

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
      camera_firmware::common::NameCurrentThread("rtsp-loop");
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

  Result<void> ReloadClientCredentials() {
    if (!running) {
      return Result<void>::Err(
          {"E_RTSP_NOT_RUNNING", "RTSP server is not running"});
    }
    if (!config_cache.client_auth.enabled) {
      return Result<void>::Err(
          {"E_RTSP_AUTH_DISABLED", "RTSP client authentication is disabled"});
    }
    if (!IsGstCfRtspDigestAuth(auth)) {
      return Result<void>::Err(
          {"E_RTSP_AUTH_TYPE", "RTSP server is not using custom Digest auth"});
    }
    return ReloadGstCfRtspDigestCredentials(auth);
  }

  bool TrackMediaKey(GstRTSPMedia* media) noexcept {
    auto* retained_media = g_object_ref(media);
    std::lock_guard lock(media_key_mutex);
    const gulong handler = g_signal_connect(media,
                                            "unprepared",
                                            G_CALLBACK(OnMediaUnprepared),
                                            this);
    if (handler == 0U) {
      g_object_unref(retained_media);
      return false;
    }
    try {
      tracked_media_keys.push_back(TrackedMediaKey{retained_media, handler});
    } catch (...) {
      g_signal_handler_disconnect(media, handler);
      g_object_unref(retained_media);
      return false;
    }
    return true;
  }

  void ReleaseTrackedMediaKey(GstRTSPMedia* media) noexcept {
    g_object_set_qdata_full(G_OBJECT(media), SecureKeyQuark(), nullptr, nullptr);

    TrackedMediaKey tracked;
    {
      std::lock_guard lock(media_key_mutex);
      const auto found = std::find_if(
          tracked_media_keys.begin(),
          tracked_media_keys.end(),
          [media](const TrackedMediaKey& candidate) {
            return candidate.media == media;
          });
      if (found == tracked_media_keys.end()) {
        return;
      }
      tracked = *found;
      tracked_media_keys.erase(found);
    }

    g_signal_handler_disconnect(tracked.media, tracked.unprepared_handler);
    g_object_unref(tracked.media);
  }

  void ClearTrackedMediaKeys() noexcept {
    std::vector<TrackedMediaKey> tracked;
    {
      std::lock_guard lock(media_key_mutex);
      tracked.swap(tracked_media_keys);
    }
    for (const auto& entry : tracked) {
      g_signal_handler_disconnect(entry.media, entry.unprepared_handler);
      g_object_set_qdata_full(
          G_OBJECT(entry.media), SecureKeyQuark(), nullptr, nullptr);
      g_object_unref(entry.media);
    }
  }

  // Attaches the per-media SRTP session key (and tracks it for cleanup on
  // "unprepared") when SRTP media is enabled. Shared by every mount so both
  // the main and sub media get identical secure-media wiring.
  void AttachSrtpKeyIfEnabled(GstRTSPMedia* media) {
    if (!media_srtp_enabled) {
      return;
    }
    gst_rtsp_media_set_profiles(media, GST_RTSP_PROFILE_SAVPF);
    GstBuffer* media_key_buffer =
        session_key.size() > 0U ? BufferFromSessionKey(session_key) : nullptr;
    if (media_key_buffer != nullptr) {
      g_object_set_qdata_full(G_OBJECT(media),
                              SecureKeyQuark(),
                              media_key_buffer,
                              ZeroizeAndUnrefGstBuffer);
      if (TrackMediaKey(media)) {
        PerMediaKeyAllocationCounter().fetch_add(1U,
                                                 std::memory_order_relaxed);
      } else {
        g_object_set_qdata_full(
            G_OBJECT(media), SecureKeyQuark(), nullptr, nullptr);
        SetAttachFailure(
            media,
            "E_SRTP_KEY_TRACKING: failed to track per-media SRTP key");
      }
    } else {
      SetAttachFailure(
          media,
          "E_SRTP_KEY_BUFFER: failed to allocate per-media SRTP key buffer");
    }
  }

  void ConfigureRtspMedia(GstRTSPMedia* media) {
    AttachSrtpKeyIfEnabled(media);
    if (ring != nullptr) {
      ConfigureAppSrc(media, *ring);
    }
  }

  void ConfigureSubRtspMedia(GstRTSPMedia* media) {
    AttachSrtpKeyIfEnabled(media);
    if (sub_ring != nullptr) {
      ConfigureAppSrc(media, *sub_ring);
    }
    // The sub media is on-demand: "unprepared" always fires the deactivate
    // edge, independent of whether SRTP key tracking connected its own
    // "unprepared" handler above. GObject cleans this connection up when the
    // media object is destroyed, so no explicit tracking/disconnect needed.
    g_signal_connect(media, "unprepared", G_CALLBACK(OnSubMediaUnprepared),
                     this);
    if (sub_on_activate) {
      sub_on_activate();
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
      GSource* source =
          g_main_context_find_source_by_id(context, source_id);
      if (source != nullptr) {
        g_source_destroy(source);
      }
      source_id = 0;
    }
    if (loop != nullptr) {
      g_main_loop_unref(loop);
      loop = nullptr;
    }
    if (client_lifecycle != nullptr) {
      client_lifecycle->CloseAndWait();
      client_lifecycle.reset();
    } else if (server != nullptr) {
      (void)gst_rtsp_server_client_filter(server, CloseManagedClient, nullptr);
    }
    ClearTrackedMediaKeys();
    if (IsGstCfRtspDigestAuth(auth)) {
      auto shutdown = ShutdownGstCfRtspDigestAuth(auth);
      if (!shutdown.ok()) {
        Logger::instance().log(Logger::Level::kError,
                               shutdown.error().code +
                                   ": category=adapter-shutdown");
      }
    }
    if (factory_mounted && mounts != nullptr) {
      gst_rtsp_mount_points_remove_factory(mounts, config_cache.mount.c_str());
      factory_mounted = false;
    }
    if (factory != nullptr) {
      g_object_unref(factory);
      factory = nullptr;
    }
    if (sub_factory_mounted && mounts != nullptr) {
      gst_rtsp_mount_points_remove_factory(mounts, sub_mount_path.c_str());
      sub_factory_mounted = false;
    }
    if (sub_factory != nullptr) {
      g_object_unref(sub_factory);
      sub_factory = nullptr;
    }
    if (server != nullptr && mounts != nullptr) {
      gst_rtsp_server_set_mount_points(server, nullptr);
    }
    if (mounts != nullptr) {
      g_object_unref(mounts);
      mounts = nullptr;
    }
    if (server != nullptr && auth != nullptr) {
      gst_rtsp_server_set_auth(server, nullptr);
    }
    if (auth != nullptr) {
      g_object_unref(auth);
      auth = nullptr;
    }
    if (tls_certificate != nullptr) {
      g_object_unref(tls_certificate);
      tls_certificate = nullptr;
    }
    if (server != nullptr) {
      g_object_unref(server);
      server = nullptr;
    }
    if (context != nullptr) {
      g_main_context_unref(context);
      context = nullptr;
    }
    session_key = SrtpSessionKey();
    ring = nullptr;
    sub_ring = nullptr;
    sub_on_activate = nullptr;
    sub_on_deactivate = nullptr;
    sub_mount_path.clear();
    media_srtp_enabled = false;
    running = false;
    Logger::instance().log(Logger::Level::kInfo, "SRTP key cleanup complete");
  }

  void ResetRuntimeKeyBaselines() noexcept {
    per_media_key_allocation_baseline.store(
        PerMediaKeyAllocationCounter().load(std::memory_order_relaxed),
        std::memory_order_relaxed);
    per_media_key_zeroize_baseline.store(
        PerMediaKeyZeroizeCounter().load(std::memory_order_relaxed),
        std::memory_order_relaxed);
  }

  [[nodiscard]] std::size_t RuntimePerMediaKeyAllocationCount() const noexcept {
    const std::size_t current =
        PerMediaKeyAllocationCounter().load(std::memory_order_relaxed);
    const std::size_t baseline =
        per_media_key_allocation_baseline.load(std::memory_order_relaxed);
    if (current < baseline) {
      return 0;
    }
    return current - baseline;
  }

  [[nodiscard]] std::size_t RuntimePerMediaKeyZeroizeCount() const noexcept {
    const std::size_t current =
        PerMediaKeyZeroizeCounter().load(std::memory_order_relaxed);
    const std::size_t baseline =
        per_media_key_zeroize_baseline.load(std::memory_order_relaxed);
    if (current < baseline) {
      return 0;
    }
    return current - baseline;
  }

  GstRTSPServer* server{nullptr};
  std::unique_ptr<internal::GstRtspClientLifecycle> client_lifecycle;
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
  bool factory_mounted{false};
  bool running{false};
  // Optional second ("sub-stream") mount; only populated when a
  // SubMountDescriptor is passed to Start.
  GstRTSPMediaFactory* sub_factory{nullptr};
  media::EncodedRing* sub_ring{nullptr};
  std::function<void()> sub_on_activate;
  std::function<void()> sub_on_deactivate;
  std::string sub_mount_path;
  bool sub_factory_mounted{false};
  std::mutex media_key_mutex;
  std::vector<TrackedMediaKey> tracked_media_keys;
  std::mutex lifecycle_mutex;
  std::atomic<std::size_t> per_media_key_allocation_baseline{
      PerMediaKeyAllocationCounter().load(std::memory_order_relaxed)};
  std::atomic<std::size_t> per_media_key_zeroize_baseline{
      PerMediaKeyZeroizeCounter().load(std::memory_order_relaxed)};
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
  if (config.client_auth.enabled) {
    auto verifier = RtspDigestVerifier::Create(config.client_auth);
    if (!verifier.ok()) {
      return Result<void>::Err(verifier.error());
    }
    auto loaded = std::move(verifier).value();
    loaded->Clear();
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
      PerMediaKeyZeroizeCounter().load(std::memory_order_relaxed);
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
      PerMediaKeyZeroizeCounter().load(std::memory_order_relaxed) -
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
                                     media::EncodedRing& main_ring,
                                     const media::SubMountDescriptor* sub) {
  std::lock_guard lock(impl_->lifecycle_mutex);
  impl_->config_cache = config;
  return impl_->Start(config, main_ring, sub);
}

Result<void> SecureRtspServer::ReloadClientCredentials() {
  std::lock_guard lock(impl_->lifecycle_mutex);
  return impl_->ReloadClientCredentials();
}

void SecureRtspServer::Stop() {
  std::lock_guard lock(impl_->lifecycle_mutex);
  impl_->Stop();
}

std::size_t SecureRtspServer::PerMediaKeyAllocationCount() const noexcept {
  return impl_->RuntimePerMediaKeyAllocationCount();
}

std::size_t SecureRtspServer::PerMediaKeyZeroizeCount() const noexcept {
  return impl_->RuntimePerMediaKeyZeroizeCount();
}

}  // namespace camera_firmware::rtsp
