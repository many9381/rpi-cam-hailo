#pragma once

#include "camera_firmware/common/Result.hpp"

#include <memory>

#include <gst/rtsp-server/rtsp-server.h>

namespace camera_firmware::rtsp::internal {

class GstRtspClientLifecycle {
 public:
  static common::Result<std::unique_ptr<GstRtspClientLifecycle>> Attach(
      GstRTSPServer* server);

  ~GstRtspClientLifecycle();

  GstRtspClientLifecycle(const GstRtspClientLifecycle&) = delete;
  GstRtspClientLifecycle& operator=(const GstRtspClientLifecycle&) = delete;

  void CloseAndWait() noexcept;

 private:
  struct Impl;

  explicit GstRtspClientLifecycle(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace camera_firmware::rtsp::internal
