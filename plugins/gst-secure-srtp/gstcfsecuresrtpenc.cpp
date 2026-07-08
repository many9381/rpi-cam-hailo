#include "gstcfsecuresrtpenc.hpp"

#include "camera_firmware/common/SecureBytes.hpp"
#include "camera_firmware/rtsp/SrtpSessionKey.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <string_view>

#include <srtp2/srtp.h>

#if defined(CAMERA_FIRMWARE_HAS_OPENSSL)
#include <openssl/crypto.h>
#endif

namespace {

using camera_firmware::common::SecureBytes;
using camera_firmware::rtsp::SrtpSessionKey;

constexpr std::string_view kRtpCipherDefault = "aes-128-icm";
constexpr std::string_view kRtpAuthDefault = "hmac-sha1-80";

enum {
  PROP_0,
  PROP_SESSION_KEY,
  PROP_RTP_CIPHER,
  PROP_RTP_AUTH,
  PROP_ZEROIZE_COUNT,
  PROP_CAPS_KEY_ZEROIZE_COUNT,
};

GstStaticPadTemplate kRtpSinkTemplate =
    GST_STATIC_PAD_TEMPLATE("rtp_sink_%u",
                            GST_PAD_SINK,
                            GST_PAD_REQUEST,
                            GST_STATIC_CAPS("application/x-rtp"));

GstStaticPadTemplate kRtpSrcTemplate =
    GST_STATIC_PAD_TEMPLATE("rtp_src_%u",
                            GST_PAD_SRC,
                            GST_PAD_SOMETIMES,
                            GST_STATIC_CAPS("application/x-srtp"));

GstStaticPadTemplate kRtcpSinkTemplate =
    GST_STATIC_PAD_TEMPLATE("rtcp_sink_%u",
                            GST_PAD_SINK,
                            GST_PAD_REQUEST,
                            GST_STATIC_CAPS("application/x-rtcp"));

GstStaticPadTemplate kRtcpSrcTemplate =
    GST_STATIC_PAD_TEMPLATE("rtcp_src_%u",
                            GST_PAD_SRC,
                            GST_PAD_SOMETIMES,
                            GST_STATIC_CAPS("application/x-srtcp"));

std::once_flag g_srtp_init_once;

void InitSrtpOnce() { (void)srtp_init(); }

bool PadNameMatches(const gchar* name, const char* prefix) {
  return name != nullptr && g_str_has_prefix(name, prefix);
}

}  // namespace

struct _GstCfSecureSrtpEnc {
  GstElement parent;

  GMutex lock;
  GstPad* rtp_sink;
  GstPad* rtp_src;
  GstPad* rtcp_sink;
  GstPad* rtcp_src;
  SecureBytes* session_key;
  srtp_t rtp_session;
  gchar* rtp_cipher;
  gchar* rtp_auth;
  bool rtp_cipher_supported;
  bool rtp_auth_supported;
  std::shared_ptr<std::atomic_uint>* caps_key_zeroize_count;
};

G_DEFINE_TYPE(GstCfSecureSrtpEnc, gst_cf_secure_srtp_enc, GST_TYPE_ELEMENT)

namespace {

void ZeroizeMemory(guint8* data, std::size_t size) noexcept {
  if (data == nullptr || size == 0U) {
    return;
  }
#if defined(CAMERA_FIRMWARE_HAS_OPENSSL)
  OPENSSL_cleanse(data, size);
#else
  volatile guint8* cursor = data;
  for (std::size_t index = 0; index < size; ++index) {
    cursor[index] = 0U;
  }
#endif
}

struct CapsKeyMemory {
  guint8* data{nullptr};
  std::size_t size{0};
  std::shared_ptr<std::atomic_uint> zeroize_count;
};

void DestroyCapsKeyMemory(gpointer user_data) {
  auto* memory = static_cast<CapsKeyMemory*>(user_data);
  if (memory == nullptr) {
    return;
  }
  ZeroizeMemory(memory->data, memory->size);
  if (memory->data != nullptr) {
    g_free(memory->data);
  }
  if (memory->size > 0U && memory->zeroize_count) {
    memory->zeroize_count->fetch_add(1U, std::memory_order_relaxed);
  }
  delete memory;
}

GstBuffer* BufferFromSessionKey(GstCfSecureSrtpEnc* self) {
  const SecureBytes& session_key = *self->session_key;
  if (session_key.size() == 0U) {
    return nullptr;
  }

  auto* data = static_cast<guint8*>(g_malloc(session_key.size()));
  if (data == nullptr) {
    return nullptr;
  }
  std::copy(session_key.data(), session_key.data() + session_key.size(), data);

  auto* memory = new CapsKeyMemory{
      data,
      session_key.size(),
      self->caps_key_zeroize_count != nullptr
          ? *self->caps_key_zeroize_count
          : std::shared_ptr<std::atomic_uint>()};
  return gst_buffer_new_wrapped_full(
      GST_MEMORY_FLAG_READONLY,
      data,
      session_key.size(),
      0,
      session_key.size(),
      memory,
      DestroyCapsKeyMemory);
}

GstCaps* CapsForSecureMedia(GstCfSecureSrtpEnc* self,
                            bool rtcp,
                            const GstCaps* upstream_caps) {
  const char* secure_media_type =
      rtcp ? "application/x-srtcp" : "application/x-srtp";
  GstCaps* caps = (upstream_caps != nullptr &&
                   !gst_caps_is_empty(upstream_caps) &&
                   !gst_caps_is_any(upstream_caps))
                      ? gst_caps_copy(upstream_caps)
                      : gst_caps_new_empty_simple(secure_media_type);
  GstBuffer* key_buffer = BufferFromSessionKey(self);

  const guint structure_count = gst_caps_get_size(caps);
  for (guint index = 0; index < structure_count; ++index) {
    GstStructure* structure = gst_caps_get_structure(caps, index);
    gst_structure_set_name(structure, secure_media_type);
    gst_structure_set(structure,
                      "srtp-cipher",
                      G_TYPE_STRING,
                      self->rtp_cipher,
                      "srtp-auth",
                      G_TYPE_STRING,
                      self->rtp_auth,
                      "srtcp-cipher",
                      G_TYPE_STRING,
                      self->rtp_cipher,
                      "srtcp-auth",
                      G_TYPE_STRING,
                      self->rtp_auth,
                      nullptr);
    if (key_buffer != nullptr) {
      gst_structure_set(structure,
                        "srtp-key",
                        GST_TYPE_BUFFER,
                        key_buffer,
                        nullptr);
    }
  }

  if (key_buffer != nullptr) {
    gst_buffer_unref(key_buffer);
  }

  return caps;
}

void CloseSrtpSession(GstCfSecureSrtpEnc* self) {
  if (self->rtp_session == nullptr) {
    return;
  }
  (void)srtp_dealloc(self->rtp_session);
  self->rtp_session = nullptr;
}

void ClearSessionKey(GstCfSecureSrtpEnc* self) {
  if (self->session_key != nullptr) {
    self->session_key->clear();
  }
}

guint ZeroizeCount(const GstCfSecureSrtpEnc* self) {
  if (self->session_key == nullptr) {
    return 0;
  }
  return static_cast<guint>(
      std::min<std::size_t>(self->session_key->zeroize_count_for_test(),
                            G_MAXUINT));
}

guint CapsKeyZeroizeCount(const GstCfSecureSrtpEnc* self) {
  if (self->caps_key_zeroize_count == nullptr ||
      !*self->caps_key_zeroize_count) {
    return 0;
  }
  return (*self->caps_key_zeroize_count)->load(std::memory_order_relaxed);
}

bool AssignSessionKeyFromBuffer(GstCfSecureSrtpEnc* self, GstBuffer* buffer) {
  CloseSrtpSession(self);

  if (buffer == nullptr) {
    ClearSessionKey(self);
    return true;
  }

  GstMapInfo map{};
  if (!gst_buffer_map(buffer, &map, GST_MAP_READ)) {
    ClearSessionKey(self);
    GST_ELEMENT_ERROR(self,
                      RESOURCE,
                      READ,
                      ("Unable to map SRTP session-key buffer"),
                      (nullptr));
    return false;
  }

  const bool valid_size =
      map.size == SrtpSessionKey::kAes128IcmHmacSha180Bytes;
  if (valid_size) {
    self->session_key->assign(map.data, map.size);
  }
  gst_buffer_unmap(buffer, &map);

  if (!valid_size) {
    ClearSessionKey(self);
    GST_ELEMENT_ERROR(self,
                      STREAM,
                      FORMAT,
                      ("SRTP session-key must be 30 bytes"),
                      (nullptr));
    return false;
  }

  return true;
}

bool EnsureRtpSession(GstCfSecureSrtpEnc* self) {
  if (self->rtp_session != nullptr) {
    return true;
  }

  if (!self->rtp_cipher_supported || !self->rtp_auth_supported) {
    GST_ELEMENT_ERROR(
        self,
        STREAM,
        FORMAT,
        ("Unsupported SRTP RTP crypto policy"),
        ("Only rtp-cipher=%s and rtp-auth=%s are implemented",
         kRtpCipherDefault.data(),
         kRtpAuthDefault.data()));
    return false;
  }

  if (self->session_key == nullptr ||
      self->session_key->size() !=
          SrtpSessionKey::kAes128IcmHmacSha180Bytes) {
    GST_ELEMENT_ERROR(self,
                      STREAM,
                      FAILED,
                      ("SRTP session-key has not been configured"),
                      (nullptr));
    return false;
  }

  std::call_once(g_srtp_init_once, InitSrtpOnce);

  srtp_policy_t policy{};
  srtp_crypto_policy_set_rtp_default(&policy.rtp);
  srtp_crypto_policy_set_rtcp_default(&policy.rtcp);
  policy.ssrc.type = ssrc_any_outbound;
  policy.key = const_cast<unsigned char*>(self->session_key->data());
  policy.window_size = 128;
  policy.allow_repeat_tx = 1;

  srtp_t session = nullptr;
  const srtp_err_status_t status = srtp_create(&session, &policy);
  if (status != srtp_err_status_ok) {
    self->session_key->clear();
    GST_ELEMENT_ERROR(self,
                      STREAM,
                      FAILED,
                      ("Unable to create SRTP session"),
                      ("libsrtp status %d", status));
    return false;
  }

  self->rtp_session = session;
  return true;
}

void SetSupportedCryptoProperty(GstCfSecureSrtpEnc* self,
                                const GValue* value,
                                gchar** stored_value,
                                bool* supported,
                                std::string_view implemented_value,
                                const char* property_name) {
  const gchar* requested_value = g_value_get_string(value);
  if (g_strcmp0(requested_value, implemented_value.data()) != 0) {
    CloseSrtpSession(self);
    *supported = false;
    GST_ELEMENT_ERROR(self,
                      STREAM,
                      FORMAT,
                      ("Unsupported SRTP RTP crypto property"),
                      ("%s=%s is not implemented; use %s",
                       property_name,
                       requested_value != nullptr ? requested_value : "(null)",
                       implemented_value.data()));
    return;
  }

  CloseSrtpSession(self);
  g_free(*stored_value);
  *stored_value = g_strdup(implemented_value.data());
  *supported = true;
}

bool PushSecureCaps(GstCfSecureSrtpEnc* self,
                    GstPad* pad,
                    bool rtcp,
                    const GstCaps* upstream_caps) {
  g_mutex_lock(&self->lock);
  GstCaps* caps = CapsForSecureMedia(self, rtcp, upstream_caps);
  g_mutex_unlock(&self->lock);
  const gboolean pushed = gst_pad_push_event(pad, gst_event_new_caps(caps));
  gst_caps_unref(caps);
  return pushed == TRUE;
}

gboolean SinkEvent(GstPad* pad, GstObject* parent, GstEvent* event) {
  auto* self = GST_CF_SECURE_SRTP_ENC(parent);
  const bool rtcp = pad == self->rtcp_sink;
  GstPad* src = rtcp ? self->rtcp_src : self->rtp_src;

  if (GST_EVENT_TYPE(event) == GST_EVENT_CAPS) {
    GstCaps* upstream_caps = nullptr;
    gst_event_parse_caps(event, &upstream_caps);
    const bool pushed = PushSecureCaps(self, src, rtcp, upstream_caps);
    gst_event_unref(event);
    return pushed ? TRUE : FALSE;
  }

  return gst_pad_event_default(pad, parent, event);
}

GstFlowReturn ProtectBuffer(GstCfSecureSrtpEnc* self,
                            GstBuffer* buffer,
                            GstPad* src,
                            bool rtcp) {
  GstMapInfo input_map{};
  if (!gst_buffer_map(buffer, &input_map, GST_MAP_READ)) {
    gst_buffer_unref(buffer);
    return GST_FLOW_ERROR;
  }

  const gsize output_capacity = input_map.size + SRTP_MAX_TRAILER_LEN;
  GstBuffer* output = gst_buffer_new_allocate(nullptr, output_capacity, nullptr);
  GstMapInfo output_map{};
  if (!gst_buffer_map(output, &output_map, GST_MAP_WRITE)) {
    gst_buffer_unmap(buffer, &input_map);
    gst_buffer_unref(buffer);
    gst_buffer_unref(output);
    return GST_FLOW_ERROR;
  }

  std::memcpy(output_map.data, input_map.data, input_map.size);
  int output_length = static_cast<int>(input_map.size);
  g_mutex_lock(&self->lock);
  const bool ready = EnsureRtpSession(self);
  const srtp_err_status_t status =
      ready ? (rtcp ? srtp_protect_rtcp(self->rtp_session,
                                        output_map.data,
                                        &output_length)
                    : srtp_protect(self->rtp_session,
                                   output_map.data,
                                   &output_length))
            : srtp_err_status_fail;
  g_mutex_unlock(&self->lock);

  gst_buffer_unmap(output, &output_map);
  gst_buffer_unmap(buffer, &input_map);

  if (status != srtp_err_status_ok) {
    gst_buffer_unref(buffer);
    gst_buffer_unref(output);
    GST_ELEMENT_ERROR(self,
                      STREAM,
                      FAILED,
                      (rtcp ? "Unable to protect RTCP packet"
                            : "Unable to protect RTP packet"),
                      ("libsrtp status %d", status));
    return GST_FLOW_ERROR;
  }

  gst_buffer_set_size(output, static_cast<gsize>(output_length));
  gst_buffer_copy_into(output, buffer, GST_BUFFER_COPY_METADATA, 0, -1);
  gst_buffer_unref(buffer);

  GstCaps* current_caps = gst_pad_get_current_caps(src);
  if (current_caps == nullptr) {
    GstPad* sink = rtcp ? self->rtcp_sink : self->rtp_sink;
    GstCaps* upstream_caps = gst_pad_get_current_caps(sink);
    (void)PushSecureCaps(self, src, rtcp, upstream_caps);
    if (upstream_caps != nullptr) {
      gst_caps_unref(upstream_caps);
    }
  } else {
    gst_caps_unref(current_caps);
  }

  return gst_pad_push(src, output);
}

GstFlowReturn RtpChain(GstPad* pad, GstObject* parent, GstBuffer* buffer) {
  auto* self = GST_CF_SECURE_SRTP_ENC(parent);
  return ProtectBuffer(self, buffer, self->rtp_src, false);
}

GstFlowReturn RtcpChain(GstPad* pad, GstObject* parent, GstBuffer* buffer) {
  auto* self = GST_CF_SECURE_SRTP_ENC(parent);
  return ProtectBuffer(self, buffer, self->rtcp_src, true);
}

GstPad* CreatePad(GstCfSecureSrtpEnc* self,
                  GstStaticPadTemplate* static_template,
                  const gchar* name) {
  GstPadTemplate* pad_template =
      gst_static_pad_template_get(static_template);
  GstPad* pad = gst_pad_new_from_template(pad_template, name);
  gst_object_unref(pad_template);
  gst_pad_use_fixed_caps(pad);
  return pad;
}

GstPad* RequestNewPad(GstElement* element,
                      GstPadTemplate* template_info,
                      const gchar* name,
                      const GstCaps* caps) {
  auto* self = GST_CF_SECURE_SRTP_ENC(element);
  const gchar* template_name = GST_PAD_TEMPLATE_NAME_TEMPLATE(template_info);

  g_mutex_lock(&self->lock);
  if (PadNameMatches(template_name, "rtp_sink_")) {
    if (self->rtp_sink != nullptr) {
      g_mutex_unlock(&self->lock);
      return nullptr;
    }
    const gchar* sink_name = name != nullptr ? name : "rtp_sink_0";
    self->rtp_sink = CreatePad(self, &kRtpSinkTemplate, sink_name);
    self->rtp_src = CreatePad(self, &kRtpSrcTemplate, "rtp_src_0");
    gst_pad_set_event_function(self->rtp_sink, SinkEvent);
    gst_pad_set_chain_function(self->rtp_sink, RtpChain);
    gst_element_add_pad(element, self->rtp_src);
    gst_element_add_pad(element, self->rtp_sink);
    g_mutex_unlock(&self->lock);
    return self->rtp_sink;
  }

  if (PadNameMatches(template_name, "rtcp_sink_")) {
    if (self->rtcp_sink != nullptr) {
      g_mutex_unlock(&self->lock);
      return nullptr;
    }
    const gchar* sink_name = name != nullptr ? name : "rtcp_sink_0";
    self->rtcp_sink = CreatePad(self, &kRtcpSinkTemplate, sink_name);
    self->rtcp_src = CreatePad(self, &kRtcpSrcTemplate, "rtcp_src_0");
    gst_pad_set_event_function(self->rtcp_sink, SinkEvent);
    gst_pad_set_chain_function(self->rtcp_sink, RtcpChain);
    gst_element_add_pad(element, self->rtcp_src);
    gst_element_add_pad(element, self->rtcp_sink);
    g_mutex_unlock(&self->lock);
    return self->rtcp_sink;
  }

  g_mutex_unlock(&self->lock);
  return nullptr;
}

void ReleasePad(GstElement* element, GstPad* pad) {
  auto* self = GST_CF_SECURE_SRTP_ENC(element);

  g_mutex_lock(&self->lock);
  if (pad == self->rtp_sink || pad == self->rtp_src) {
    if (self->rtp_sink != nullptr) {
      gst_element_remove_pad(element, self->rtp_sink);
      self->rtp_sink = nullptr;
    }
    if (self->rtp_src != nullptr) {
      gst_element_remove_pad(element, self->rtp_src);
      self->rtp_src = nullptr;
    }
  } else if (pad == self->rtcp_sink || pad == self->rtcp_src) {
    if (self->rtcp_sink != nullptr) {
      gst_element_remove_pad(element, self->rtcp_sink);
      self->rtcp_sink = nullptr;
    }
    if (self->rtcp_src != nullptr) {
      gst_element_remove_pad(element, self->rtcp_src);
      self->rtcp_src = nullptr;
    }
  }
  g_mutex_unlock(&self->lock);
}

void SetProperty(GObject* object,
                 guint property_id,
                 const GValue* value,
                 GParamSpec* pspec) {
  auto* self = GST_CF_SECURE_SRTP_ENC(object);

  switch (property_id) {
    case PROP_SESSION_KEY: {
      auto* buffer = static_cast<GstBuffer*>(g_value_get_boxed(value));
      g_mutex_lock(&self->lock);
      (void)AssignSessionKeyFromBuffer(self, buffer);
      g_mutex_unlock(&self->lock);
      break;
    }
    case PROP_RTP_CIPHER:
      g_mutex_lock(&self->lock);
      SetSupportedCryptoProperty(self,
                                 value,
                                 &self->rtp_cipher,
                                 &self->rtp_cipher_supported,
                                 kRtpCipherDefault,
                                 "rtp-cipher");
      g_mutex_unlock(&self->lock);
      break;
    case PROP_RTP_AUTH:
      g_mutex_lock(&self->lock);
      SetSupportedCryptoProperty(self,
                                 value,
                                 &self->rtp_auth,
                                 &self->rtp_auth_supported,
                                 kRtpAuthDefault,
                                 "rtp-auth");
      g_mutex_unlock(&self->lock);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
      break;
  }
}

void GetProperty(GObject* object,
                 guint property_id,
                 GValue* value,
                 GParamSpec* pspec) {
  auto* self = GST_CF_SECURE_SRTP_ENC(object);

  switch (property_id) {
    case PROP_RTP_CIPHER:
      g_mutex_lock(&self->lock);
      g_value_set_string(value, self->rtp_cipher);
      g_mutex_unlock(&self->lock);
      break;
    case PROP_RTP_AUTH:
      g_mutex_lock(&self->lock);
      g_value_set_string(value, self->rtp_auth);
      g_mutex_unlock(&self->lock);
      break;
    case PROP_ZEROIZE_COUNT:
      g_mutex_lock(&self->lock);
      g_value_set_uint(value, ZeroizeCount(self));
      g_mutex_unlock(&self->lock);
      break;
    case PROP_CAPS_KEY_ZEROIZE_COUNT:
      g_mutex_lock(&self->lock);
      g_value_set_uint(value, CapsKeyZeroizeCount(self));
      g_mutex_unlock(&self->lock);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
      break;
  }
}

GstStateChangeReturn ChangeState(GstElement* element,
                                 GstStateChange transition) {
  auto* self = GST_CF_SECURE_SRTP_ENC(element);

  if (transition == GST_STATE_CHANGE_READY_TO_NULL) {
    g_mutex_lock(&self->lock);
    CloseSrtpSession(self);
    ClearSessionKey(self);
    g_mutex_unlock(&self->lock);
  }

  return GST_ELEMENT_CLASS(gst_cf_secure_srtp_enc_parent_class)
      ->change_state(element, transition);
}

void Finalize(GObject* object) {
  auto* self = GST_CF_SECURE_SRTP_ENC(object);

  g_mutex_lock(&self->lock);
  CloseSrtpSession(self);
  ClearSessionKey(self);
  delete self->session_key;
  self->session_key = nullptr;
  delete self->caps_key_zeroize_count;
  self->caps_key_zeroize_count = nullptr;
  g_mutex_unlock(&self->lock);

  g_free(self->rtp_cipher);
  g_free(self->rtp_auth);
  g_mutex_clear(&self->lock);

  G_OBJECT_CLASS(gst_cf_secure_srtp_enc_parent_class)->finalize(object);
}

gboolean PluginInit(GstPlugin* plugin) {
  return gst_element_register(plugin,
                              "cfsecuresrtpenc",
                              GST_RANK_NONE,
                              GST_TYPE_CF_SECURE_SRTP_ENC);
}

}  // namespace

static void gst_cf_secure_srtp_enc_class_init(
    GstCfSecureSrtpEncClass* klass) {
  auto* object_class = G_OBJECT_CLASS(klass);
  auto* element_class = GST_ELEMENT_CLASS(klass);

  object_class->set_property = SetProperty;
  object_class->get_property = GetProperty;
  object_class->finalize = Finalize;

  element_class->request_new_pad = RequestNewPad;
  element_class->release_pad = ReleasePad;
  element_class->change_state = ChangeState;

  g_object_class_install_property(
      object_class,
      PROP_SESSION_KEY,
      g_param_spec_boxed("session-key",
                         "Session key",
                         "30-byte SRTP master key and salt buffer",
                         GST_TYPE_BUFFER,
                         static_cast<GParamFlags>(G_PARAM_WRITABLE |
                                                  G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property(
      object_class,
      PROP_RTP_CIPHER,
      g_param_spec_string("rtp-cipher",
                          "RTP cipher",
                          "RTP cipher suite",
                          kRtpCipherDefault.data(),
                          static_cast<GParamFlags>(G_PARAM_READWRITE |
                                                   G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property(
      object_class,
      PROP_RTP_AUTH,
      g_param_spec_string("rtp-auth",
                          "RTP auth",
                          "RTP authentication suite",
                          kRtpAuthDefault.data(),
                          static_cast<GParamFlags>(G_PARAM_READWRITE |
                                                   G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property(
      object_class,
      PROP_ZEROIZE_COUNT,
      g_param_spec_uint("zeroize-count",
                        "Zeroize count",
                        "Number of firmware-owned session key zeroizations",
                        0,
                        G_MAXUINT,
                        0,
                        static_cast<GParamFlags>(G_PARAM_READABLE |
                                                 G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property(
      object_class,
      PROP_CAPS_KEY_ZEROIZE_COUNT,
      g_param_spec_uint("caps-key-zeroize-count",
                        "Caps key zeroize count",
                        "Number of caps-owned session key zeroizations",
                        0,
                        G_MAXUINT,
                        0,
                        static_cast<GParamFlags>(G_PARAM_READABLE |
                                                 G_PARAM_STATIC_STRINGS)));

  gst_element_class_add_static_pad_template(element_class, &kRtpSinkTemplate);
  gst_element_class_add_static_pad_template(element_class, &kRtpSrcTemplate);
  gst_element_class_add_static_pad_template(element_class, &kRtcpSinkTemplate);
  gst_element_class_add_static_pad_template(element_class, &kRtcpSrcTemplate);

  gst_element_class_set_static_metadata(element_class,
                                        "Camera firmware secure SRTP encoder",
                                        "Codec/Encoder/Network/SRTP",
                                        "Protects RTP packets with libsrtp",
                                        "camera-firmware");
}

static void gst_cf_secure_srtp_enc_init(GstCfSecureSrtpEnc* self) {
  g_mutex_init(&self->lock);
  self->session_key = new SecureBytes();
  self->caps_key_zeroize_count =
      new std::shared_ptr<std::atomic_uint>(
          std::make_shared<std::atomic_uint>(0U));
  self->rtp_cipher = g_strdup(kRtpCipherDefault.data());
  self->rtp_auth = g_strdup(kRtpAuthDefault.data());
  self->rtp_cipher_supported = true;
  self->rtp_auth_supported = true;
}

GST_PLUGIN_DEFINE(GST_VERSION_MAJOR,
                  GST_VERSION_MINOR,
                  cfsecuresrtp,
                  "Camera firmware secure SRTP encoder",
                  PluginInit,
                  "0.1.0",
                  "proprietary",
                  "camera-firmware",
                  "https://example.invalid/camera-firmware")
