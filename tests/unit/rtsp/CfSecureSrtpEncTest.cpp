#include <cstring>

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

void SetRtpCaps(GstHarness* harness) {
  GstCaps* rtp_caps = gst_caps_new_simple(
      "application/x-rtp", "media", G_TYPE_STRING, "video",
      "clock-rate", G_TYPE_INT, 90000, "encoding-name", G_TYPE_STRING,
      "H264", nullptr);
  gst_harness_set_src_caps(harness, rtp_caps);
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
  ASSERT_NE(output_caps, nullptr);
  const GstStructure* structure = gst_caps_get_structure(output_caps, 0);
  ASSERT_NE(structure, nullptr);
  EXPECT_STREQ(gst_structure_get_name(structure), "application/x-srtp");
  gst_caps_unref(output_caps);

  EXPECT_GT(gst_buffer_get_size(output), input_size);
  gst_buffer_unref(output);
  gst_harness_teardown(harness);
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
