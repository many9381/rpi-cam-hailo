#pragma once

#include <gst/gst.h>

G_BEGIN_DECLS

#define GST_TYPE_CF_SECURE_SRTP_ENC (gst_cf_secure_srtp_enc_get_type())
G_DECLARE_FINAL_TYPE(GstCfSecureSrtpEnc, gst_cf_secure_srtp_enc, GST,
                     CF_SECURE_SRTP_ENC, GstElement)

G_END_DECLS
