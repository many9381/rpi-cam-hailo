#include <cstring>
#include <string>
#include <vector>

#include <gst/check/gstharness.h>
#include <gst/gst.h>
#include <gtest/gtest.h>

namespace {

GstBuffer* MakeKey(unsigned char fill) {
  GstBuffer* buffer = gst_buffer_new_allocate(nullptr, 30, nullptr);
  GstMapInfo map;
  gst_buffer_map(buffer, &map, GST_MAP_WRITE);
  std::memset(map.data, fill, map.size);
  gst_buffer_unmap(buffer, &map);
  return buffer;
}

GstBuffer* MakeRtpPacket() {
  constexpr gsize input_size = 12;
  GstBuffer* input = gst_buffer_new_allocate(nullptr, input_size, nullptr);
  GstMapInfo map;
  gst_buffer_map(input, &map, GST_MAP_WRITE);
  std::memset(map.data, 0, map.size);
  map.data[0] = 0x80;
  map.data[1] = 96;
  map.data[2] = 0x12;
  map.data[3] = 0x34;
  map.data[4] = 0x00;
  map.data[5] = 0x00;
  map.data[6] = 0x00;
  map.data[7] = 0x01;
  map.data[8] = 0x01;
  map.data[9] = 0x02;
  map.data[10] = 0x03;
  map.data[11] = 0x04;
  gst_buffer_unmap(input, &map);
  return input;
}

GstBuffer* MakeRtcpPacket() {
  constexpr gsize input_size = 8;
  GstBuffer* input = gst_buffer_new_allocate(nullptr, input_size, nullptr);
  GstMapInfo map;
  gst_buffer_map(input, &map, GST_MAP_WRITE);
  std::memset(map.data, 0, map.size);
  map.data[0] = 0x80;
  map.data[1] = 200;
  map.data[2] = 0x00;
  map.data[3] = 0x01;
  map.data[4] = 0x01;
  map.data[5] = 0x02;
  map.data[6] = 0x03;
  map.data[7] = 0x04;
  gst_buffer_unmap(input, &map);
  return input;
}

GstHarness* MakeRtpHarness() {
  GstElement* element = gst_element_factory_make("cfsecuresrtpenc", nullptr);
  if (element == nullptr) {
    return nullptr;
  }

  GstPad* requested_pad =
      gst_element_request_pad_simple(element, "rtp_sink_%u");
  if (requested_pad == nullptr) {
    gst_object_unref(element);
    return nullptr;
  }
  gst_object_unref(requested_pad);

  GstHarness* harness =
      gst_harness_new_with_element(element, "rtp_sink_0", "rtp_src_0");
  gst_object_unref(element);
  return harness;
}

GstHarness* MakeRtcpHarness() {
  GstElement* element = gst_element_factory_make("cfsecuresrtpenc", nullptr);
  if (element == nullptr) {
    return nullptr;
  }

  GstPad* requested_pad =
      gst_element_request_pad_simple(element, "rtcp_sink_%u");
  if (requested_pad == nullptr) {
    gst_object_unref(element);
    return nullptr;
  }
  gst_object_unref(requested_pad);

  GstHarness* harness =
      gst_harness_new_with_element(element, "rtcp_sink_0", "rtcp_src_0");
  gst_object_unref(element);
  return harness;
}

void SetRtpCaps(GstHarness* harness) {
  GstCaps* rtp_caps = gst_caps_new_simple(
      "application/x-rtp", "media", G_TYPE_STRING, "video", "payload",
      G_TYPE_INT, 96, "clock-rate", G_TYPE_INT, 90000, "encoding-name",
      G_TYPE_STRING, "H264", nullptr);
  gst_harness_set_src_caps(harness, rtp_caps);
}

void SetRtcpCaps(GstHarness* harness) {
  GstCaps* rtcp_caps = gst_caps_new_empty_simple("application/x-rtcp");
  gst_harness_set_src_caps(harness, rtcp_caps);
}

void ExpectSecureCaps(GstCaps* caps, const char* media_type) {
  ASSERT_NE(caps, nullptr);
  const GstStructure* structure = gst_caps_get_structure(caps, 0);
  ASSERT_NE(structure, nullptr);
  EXPECT_STREQ(gst_structure_get_name(structure), media_type);
  const char* cipher = gst_structure_get_string(structure, "srtp-cipher");
  ASSERT_NE(cipher, nullptr);
  EXPECT_STREQ(cipher, "aes-128-icm");
  const char* auth = gst_structure_get_string(structure, "srtp-auth");
  ASSERT_NE(auth, nullptr);
  EXPECT_STREQ(auth, "hmac-sha1-80");
  const char* rtcp_cipher = gst_structure_get_string(structure, "srtcp-cipher");
  ASSERT_NE(rtcp_cipher, nullptr);
  EXPECT_STREQ(rtcp_cipher, "aes-128-icm");
  const char* rtcp_auth = gst_structure_get_string(structure, "srtcp-auth");
  ASSERT_NE(rtcp_auth, nullptr);
  EXPECT_STREQ(rtcp_auth, "hmac-sha1-80");
  const GValue* key_value = gst_structure_get_value(structure, "srtp-key");
  ASSERT_NE(key_value, nullptr);
  auto* key_buffer = static_cast<GstBuffer*>(g_value_get_boxed(key_value));
  ASSERT_NE(key_buffer, nullptr);
  EXPECT_EQ(gst_buffer_get_size(key_buffer), 30u);
}

void ExpectForwardedRtpFields(GstCaps* caps) {
  ASSERT_NE(caps, nullptr);
  const GstStructure* structure = gst_caps_get_structure(caps, 0);
  ASSERT_NE(structure, nullptr);
  const char* media = gst_structure_get_string(structure, "media");
  ASSERT_NE(media, nullptr);
  EXPECT_STREQ(media, "video");
  gint payload = 0;
  ASSERT_TRUE(gst_structure_get_int(structure, "payload", &payload));
  EXPECT_EQ(payload, 96);
  gint clock_rate = 0;
  ASSERT_TRUE(gst_structure_get_int(structure, "clock-rate", &clock_rate));
  EXPECT_EQ(clock_rate, 90000);
  const char* encoding_name =
      gst_structure_get_string(structure, "encoding-name");
  ASSERT_NE(encoding_name, nullptr);
  EXPECT_STREQ(encoding_name, "H264");
}

struct CapturedDebugLog {
  std::vector<std::string> messages;
};

void CaptureDebugLog(GstDebugCategory*, GstDebugLevel, const gchar*,
                     const gchar*, gint, GObject*, GstDebugMessage* message,
                     gpointer user_data) {
  auto* captured = static_cast<CapturedDebugLog*>(user_data);
  const gchar* text = gst_debug_message_get(message);
  if (text != nullptr) {
    captured->messages.emplace_back(text);
  }
}

}  // namespace

TEST(CfSecureSrtpEncTest, ReplacingSessionKeyZeroizesOldFirmwareBuffer) {
  gst_init(nullptr, nullptr);
  GstElement* enc = gst_element_factory_make("cfsecuresrtpenc", nullptr);
  ASSERT_NE(enc, nullptr);

  GstBuffer* first = MakeKey(0x11);
  GstBuffer* second = MakeKey(0x22);
  g_object_set(enc, "session-key", first, nullptr);
  g_object_set(enc, "session-key", second, nullptr);

  guint zeroize_count = 0;
  g_object_get(enc, "zeroize-count", &zeroize_count, nullptr);
  EXPECT_GE(zeroize_count, 1u);

  gst_buffer_unref(first);
  gst_buffer_unref(second);
  gst_object_unref(enc);
}

TEST(CfSecureSrtpEncTest, InvalidReplacementZeroizesOldFirmwareBuffer) {
  gst_init(nullptr, nullptr);
  GstElement* enc = gst_element_factory_make("cfsecuresrtpenc", nullptr);
  ASSERT_NE(enc, nullptr);

  GstBuffer* first = MakeKey(0x11);
  GstBuffer* invalid = gst_buffer_new_allocate(nullptr, 2, nullptr);
  g_object_set(enc, "session-key", first, nullptr);
  g_object_set(enc, "session-key", invalid, nullptr);

  guint zeroize_count = 0;
  g_object_get(enc, "zeroize-count", &zeroize_count, nullptr);
  EXPECT_GE(zeroize_count, 1u);

  gst_buffer_unref(first);
  gst_buffer_unref(invalid);
  gst_object_unref(enc);
}

TEST(CfSecureSrtpEncTest, StateTeardownZeroizesFirmwareBuffer) {
  gst_init(nullptr, nullptr);
  GstElement* enc = gst_element_factory_make("cfsecuresrtpenc", nullptr);
  ASSERT_NE(enc, nullptr);

  GstBuffer* key = MakeKey(0x44);
  g_object_set(enc, "session-key", key, nullptr);
  ASSERT_EQ(gst_element_set_state(enc, GST_STATE_READY),
            GST_STATE_CHANGE_SUCCESS);
  ASSERT_EQ(gst_element_set_state(enc, GST_STATE_NULL),
            GST_STATE_CHANGE_SUCCESS);

  guint zeroize_count = 0;
  g_object_get(enc, "zeroize-count", &zeroize_count, nullptr);
  EXPECT_GE(zeroize_count, 1u);

  gst_buffer_unref(key);
  gst_object_unref(enc);
}

TEST(CfSecureSrtpEncTest, ProtectsRtpBufferAndOutputsSrtpCaps) {
  gst_init(nullptr, nullptr);

  GstHarness* harness = MakeRtpHarness();
  ASSERT_NE(harness, nullptr);

  GstBuffer* key = MakeKey(0x33);
  g_object_set(harness->element, "session-key", key, nullptr);
  gst_buffer_unref(key);

  SetRtpCaps(harness);
  constexpr gsize input_size = 12;
  GstBuffer* input = MakeRtpPacket();

  ASSERT_EQ(gst_harness_push(harness, input), GST_FLOW_OK);
  GstBuffer* output = gst_harness_pull(harness);
  ASSERT_NE(output, nullptr);

  GstCaps* output_caps = gst_pad_get_current_caps(harness->sinkpad);
  ExpectSecureCaps(output_caps, "application/x-srtp");
  ExpectForwardedRtpFields(output_caps);
  gst_caps_unref(output_caps);

  EXPECT_GT(gst_buffer_get_size(output), input_size);
  gst_buffer_unref(output);
  gst_harness_teardown(harness);
}

TEST(CfSecureSrtpEncTest, ProtectsRtcpBufferAndOutputsSrtcpCaps) {
  gst_init(nullptr, nullptr);

  GstHarness* harness = MakeRtcpHarness();
  ASSERT_NE(harness, nullptr);

  GstBuffer* key = MakeKey(0x77);
  g_object_set(harness->element, "session-key", key, nullptr);
  gst_buffer_unref(key);

  SetRtcpCaps(harness);
  constexpr gsize input_size = 8;
  GstBuffer* input = MakeRtcpPacket();

  ASSERT_EQ(gst_harness_push(harness, input), GST_FLOW_OK);
  GstBuffer* output = gst_harness_pull(harness);
  ASSERT_NE(output, nullptr);

  GstCaps* output_caps = gst_pad_get_current_caps(harness->sinkpad);
  ExpectSecureCaps(output_caps, "application/x-srtcp");
  gst_caps_unref(output_caps);

  EXPECT_GT(gst_buffer_get_size(output), input_size);
  gst_buffer_unref(output);
  gst_harness_teardown(harness);
}

TEST(CfSecureSrtpEncTest, CapsOwnedSessionKeyBufferZeroizesWhenReleased) {
  gst_init(nullptr, nullptr);
  GstElement* enc = gst_element_factory_make("cfsecuresrtpenc", nullptr);
  ASSERT_NE(enc, nullptr);

  GstBuffer* key = MakeKey(0x11);
  g_object_set(enc, "session-key", key, nullptr);
  gst_buffer_unref(key);

  GstPad* sink = gst_element_request_pad_simple(enc, "rtp_sink_%u");
  ASSERT_NE(sink, nullptr);
  GstPad* src = gst_element_get_static_pad(enc, "rtp_src_0");
  ASSERT_NE(src, nullptr);
  GstPad* peer_sink = gst_pad_new("peer_sink", GST_PAD_SINK);
  ASSERT_NE(peer_sink, nullptr);
  gst_pad_set_active(sink, TRUE);
  gst_pad_set_active(src, TRUE);
  gst_pad_set_active(peer_sink, TRUE);
  ASSERT_EQ(gst_pad_link(src, peer_sink), GST_PAD_LINK_OK);

  GstCaps* rtp_caps = gst_caps_new_simple(
      "application/x-rtp", "media", G_TYPE_STRING, "video", "clock-rate",
      G_TYPE_INT, 90000, "encoding-name", G_TYPE_STRING, "H264", nullptr);
  CapturedDebugLog captured_log;
  gst_debug_add_log_function(CaptureDebugLog, &captured_log, nullptr);
  const gboolean caps_sent =
      gst_pad_send_event(sink, gst_event_new_caps(rtp_caps));
  gst_caps_unref(rtp_caps);

  gst_element_release_request_pad(enc, sink);
  gst_object_unref(sink);
  gst_pad_unlink(src, peer_sink);
  gst_pad_set_active(peer_sink, FALSE);
  gst_object_unref(peer_sink);
  gst_object_unref(src);

  guint caps_zeroize_count = 0;
  g_object_get(enc, "caps-key-zeroize-count", &caps_zeroize_count, nullptr);
  EXPECT_GE(caps_zeroize_count, 1u);
  gst_debug_remove_log_function_by_data(&captured_log);
  EXPECT_TRUE(caps_sent);
  for (const auto& message : captured_log.messages) {
    EXPECT_EQ(message.find("1111111111111111"), std::string::npos);
  }

  gst_object_unref(enc);
}

TEST(CfSecureSrtpEncTest, UnsupportedRtpCipherFailsBeforeSessionSetup) {
  gst_init(nullptr, nullptr);

  GstHarness* harness = MakeRtpHarness();
  ASSERT_NE(harness, nullptr);

  GstBuffer* key = MakeKey(0x55);
  g_object_set(harness->element, "session-key", key, nullptr);
  gst_buffer_unref(key);

  g_object_set(harness->element, "rtp-cipher", "aes-256-icm", nullptr);

  gchar* configured_cipher = nullptr;
  g_object_get(harness->element, "rtp-cipher", &configured_cipher, nullptr);
  ASSERT_NE(configured_cipher, nullptr);
  EXPECT_STREQ(configured_cipher, "aes-128-icm");
  g_free(configured_cipher);

  SetRtpCaps(harness);
  EXPECT_EQ(gst_harness_push(harness, MakeRtpPacket()), GST_FLOW_ERROR);
  gst_harness_teardown(harness);
}

TEST(CfSecureSrtpEncTest, UnsupportedRtpAuthFailsBeforeSessionSetup) {
  gst_init(nullptr, nullptr);

  GstHarness* harness = MakeRtpHarness();
  ASSERT_NE(harness, nullptr);

  GstBuffer* key = MakeKey(0x66);
  g_object_set(harness->element, "session-key", key, nullptr);
  gst_buffer_unref(key);

  g_object_set(harness->element, "rtp-auth", "hmac-sha1-32", nullptr);

  gchar* configured_auth = nullptr;
  g_object_get(harness->element, "rtp-auth", &configured_auth, nullptr);
  ASSERT_NE(configured_auth, nullptr);
  EXPECT_STREQ(configured_auth, "hmac-sha1-80");
  g_free(configured_auth);

  SetRtpCaps(harness);
  EXPECT_EQ(gst_harness_push(harness, MakeRtpPacket()), GST_FLOW_ERROR);
  gst_harness_teardown(harness);
}
