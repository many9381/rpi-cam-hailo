#pragma once

#include <gst/rtsp-server/rtsp-auth.h>

#include "camera_firmware/common/Result.hpp"
#include "camera_firmware/config/AppConfig.hpp"
#include "camera_firmware/rtsp/RtspDigestVerifier.hpp"

namespace camera_firmware::rtsp {

GType gst_cf_rtsp_digest_auth_get_type();

common::Result<GstRTSPAuth*> NewGstCfRtspDigestAuth(
    const config::RtspClientAuthConfig& config,
    RtspDigestVerifierDependencies dependencies = {});
common::Result<void> ReloadGstCfRtspDigestCredentials(GstRTSPAuth* auth);
common::Result<void> ShutdownGstCfRtspDigestAuth(GstRTSPAuth* auth);
bool IsGstCfRtspDigestAuth(GstRTSPAuth* auth) noexcept;

}  // namespace camera_firmware::rtsp
