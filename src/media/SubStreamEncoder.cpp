#include "camera_firmware/media/SubStreamEncoder.hpp"

#include <sys/mman.h>
#include <x264.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include "camera_firmware/media/FrameLease.hpp"
#include "camera_firmware/media/FrameTypes.hpp"
#include "camera_firmware/media/Nv12Downscaler.hpp"

namespace camera_firmware::media {
namespace {

using camera_firmware::common::Result;

// Duplicated (not shared) from CameraPipeline.cpp per the task-4 ruling:
// these are ~10 lines each and CameraPipeline's copies are out of scope for
// this change.
struct X264EncoderDeleter {
  void operator()(x264_t* encoder) const noexcept {
    if (encoder != nullptr) {
      x264_encoder_close(encoder);
    }
  }
};

using X264Encoder = std::unique_ptr<x264_t, X264EncoderDeleter>;

std::vector<std::uint8_t> CopyNalPayloads(x264_nal_t* nals, int nal_count) {
  std::vector<std::uint8_t> bytes;
  if (nals == nullptr || nal_count <= 0) {
    return bytes;
  }

  std::size_t total_size = 0;
  for (int index = 0; index < nal_count; ++index) {
    total_size += static_cast<std::size_t>(std::max(nals[index].i_payload, 0));
  }
  bytes.reserve(total_size);

  for (int index = 0; index < nal_count; ++index) {
    const int payload_size = nals[index].i_payload;
    if (payload_size <= 0 || nals[index].p_payload == nullptr) {
      continue;
    }
    bytes.insert(bytes.end(), nals[index].p_payload,
                 nals[index].p_payload + payload_size);
  }
  return bytes;
}

// FrameHandle carries a DMABUF fd + offset/length/stride, not a mapped
// pointer (that mapping is CameraPipeline's own private cache, keyed on the
// libcamera FrameBuffer* it never hands us). So, like JpegEncoder's snapshot
// path, we mmap the plane read-only ourselves for the duration of one frame.
struct MappedPlane {
  const std::uint8_t* data{nullptr};
  void* mapping{nullptr};
  std::size_t mapping_size{0};

  MappedPlane() = default;
  MappedPlane(const std::uint8_t* plane_data, void* mapped_address,
              std::size_t mapped_size) noexcept
      : data(plane_data), mapping(mapped_address), mapping_size(mapped_size) {}
  MappedPlane(const MappedPlane&) = delete;
  MappedPlane& operator=(const MappedPlane&) = delete;
  MappedPlane(MappedPlane&& other) noexcept
      : data(std::exchange(other.data, nullptr)),
        mapping(std::exchange(other.mapping, nullptr)),
        mapping_size(std::exchange(other.mapping_size, 0U)) {}
  MappedPlane& operator=(MappedPlane&&) = delete;

  ~MappedPlane() {
    if (mapping != nullptr && mapping != MAP_FAILED) {
      (void)::munmap(mapping, mapping_size);
    }
  }
};

bool CheckedAdd(std::size_t left, std::size_t right, std::size_t& result) {
  if (left > std::numeric_limits<std::size_t>::max() - right) {
    return false;
  }
  result = left + right;
  return true;
}

std::optional<MappedPlane> MapPlaneReadOnly(const FramePlane& plane) {
  if (plane.dmabuf_fd < 0 || plane.length == 0U) {
    return std::nullopt;
  }

  std::size_t mapping_size = 0U;
  if (!CheckedAdd(plane.offset, plane.length, mapping_size) ||
      mapping_size == 0U) {
    return std::nullopt;
  }

  void* mapping = ::mmap(nullptr, mapping_size, PROT_READ, MAP_SHARED,
                         plane.dmabuf_fd, 0);
  if (mapping == MAP_FAILED) {
    return std::nullopt;
  }

  const auto* bytes = static_cast<const std::uint8_t*>(mapping);
  return MappedPlane(bytes + plane.offset, mapping, mapping_size);
}

}  // namespace

struct SubStreamEncoder::Impl {
  Impl(SubStreamTap& t, EncodedRing& ring, SubStreamEncoderParams p)
      : tap(t),
        out_ring(ring),
        params(std::move(p)),
        downscaler(params.src_width, params.src_height, params.dst_width,
                   params.dst_height) {}

  ~Impl() { Stop(); }

  Result<void> Start() {
    if (running.load()) {
      return Result<void>::Err(
          {"E_SUBENC_RUNNING", "sub-stream encoder is already running"});
    }
    if (!downscaler.valid()) {
      return Result<void>::Err(
          {"E_SUBENC_SCALER", "failed to create sub-stream NV12 downscaler"});
    }

    x264_param_t x264_params{};
    if (x264_param_default_preset(&x264_params, params.preset.c_str(),
                                  "zerolatency") < 0) {
      return Result<void>::Err(
          {"E_SUBENC_ENCODER", "failed to initialize sub x264 preset"});
    }
    x264_params.i_width = params.dst_width;
    x264_params.i_height = params.dst_height;
    x264_params.i_csp = X264_CSP_NV12;
    x264_params.i_fps_num = static_cast<int>(params.fps);
    x264_params.i_fps_den = 1;
    x264_params.i_timebase_num = 1;
    x264_params.i_timebase_den = static_cast<int>(params.fps);
    x264_params.i_threads = 0;
    x264_params.i_keyint_max = static_cast<int>(params.gop);
    x264_params.i_keyint_min = static_cast<int>(params.gop);
    x264_params.i_bframe = 0;
    x264_params.rc.i_rc_method = X264_RC_ABR;
    x264_params.rc.i_bitrate = static_cast<int>(params.bitrate_kbps);
    x264_params.rc.i_vbv_max_bitrate = static_cast<int>(params.bitrate_kbps);
    x264_params.rc.i_vbv_buffer_size =
        static_cast<int>(params.bitrate_kbps / 2U);
    x264_params.b_annexb = 1;
    x264_params.b_repeat_headers = 1;
    x264_params.b_vfr_input = 0;
    x264_params.i_log_level = X264_LOG_WARNING;
    if (x264_param_apply_profile(&x264_params, "baseline") < 0) {
      x264_param_cleanup(&x264_params);
      return Result<void>::Err(
          {"E_SUBENC_ENCODER", "failed to apply sub x264 baseline profile"});
    }

    encoder.reset(x264_encoder_open(&x264_params));
    x264_param_cleanup(&x264_params);
    if (encoder == nullptr) {
      return Result<void>::Err(
          {"E_SUBENC_ENCODER", "failed to open sub x264 encoder"});
    }

    next_pts = 0;
    running.store(true);
    worker = std::thread([this] { RunLoop(); });
    return Result<void>::Ok();
  }

  void Stop() {
    running.store(false);
    tap.Close();
    if (worker.joinable()) {
      worker.join();
    }
    // Join before releasing x264/downscaler: the worker thread must no
    // longer be touching either once we tear them down here.
    encoder.reset();
  }

  void RunLoop() {
    constexpr auto kPollTimeout = std::chrono::milliseconds(20);
    tap.RequestNext();
    while (running.load(std::memory_order_relaxed)) {
      auto lease = tap.WaitNext(kPollTimeout);
      if (!lease.has_value()) {
        // WaitNext returns immediately (not after the timeout) whenever the
        // tap is inactive -- e.g. no sub-stream RTSP client connected yet.
        // Back off ourselves so that window doesn't become a busy-spin.
        if (!tap.active()) {
          std::this_thread::sleep_for(kPollTimeout);
        }
        continue;
      }
      ProcessFrame(*lease);
      tap.RequestNext();
    }
  }

  void ProcessFrame(const FrameLease& lease) {
    const FrameHandle& handle = lease.handle();
    if (handle.format != "NV12" || handle.plane_count < 2U) {
      ++error_count;
      return;
    }

    auto y_mapped = MapPlaneReadOnly(handle.planes[0]);
    auto uv_mapped = MapPlaneReadOnly(handle.planes[1]);
    if (!y_mapped.has_value() || !uv_mapped.has_value()) {
      ++error_count;
      return;
    }

    // Real dmabuf capture buffers are padded: the plane stride is usually
    // != width. Use the handle's actual strides, not width, or real frames
    // get read back skewed.
    Nv12Plane src{};
    src.y = y_mapped->data;
    src.uv = uv_mapped->data;
    src.y_stride = static_cast<int>(handle.planes[0].stride);
    src.uv_stride = static_cast<int>(handle.planes[1].stride);
    src.width = params.src_width;
    src.height = params.src_height;

    if (!downscaler.Scale(src, scaled_buffer)) {
      ++error_count;
      return;
    }

    const auto dst_width = static_cast<std::size_t>(params.dst_width);
    const auto dst_height = static_cast<std::size_t>(params.dst_height);
    const std::size_t y_size = dst_width * dst_height;
    if (scaled_buffer.size() < y_size) {
      ++error_count;
      return;
    }

    x264_picture_t picture_in{};
    x264_picture_t picture_out{};
    x264_picture_init(&picture_in);
    x264_picture_init(&picture_out);
    picture_in.img.i_csp = X264_CSP_NV12;
    picture_in.img.i_plane = 2;
    picture_in.img.i_stride[0] = params.dst_width;
    picture_in.img.i_stride[1] = params.dst_width;
    picture_in.img.plane[0] = scaled_buffer.data();
    picture_in.img.plane[1] = scaled_buffer.data() + y_size;
    picture_in.i_pts = static_cast<std::int64_t>(next_pts++);

    x264_nal_t* nals = nullptr;
    int nal_count = 0;
    const int status = x264_encoder_encode(encoder.get(), &nals, &nal_count,
                                           &picture_in, &picture_out);
    if (status < 0) {
      ++error_count;
      return;
    }

    auto payload = CopyNalPayloads(nals, nal_count);
    if (payload.empty()) {
      // Mirrors CameraPipeline::RunEncoderLoop: an encode call that yields
      // no NAL bytes is treated the same as an encode failure, not silently
      // skipped, so error_count reflects the encoder actually falling
      // behind or misbehaving.
      ++error_count;
      return;
    }

    EncodedAccessUnit access_unit;
    access_unit.sequence = handle.sequence;
    access_unit.timestamp = handle.timestamp;
    access_unit.is_key_frame = picture_out.b_keyframe != 0;
    access_unit.bytes =
        std::make_shared<const std::vector<std::uint8_t>>(std::move(payload));

    ++encoded_frames;
    out_ring.Publish(std::move(access_unit));
  }

  SubStreamTap& tap;
  EncodedRing& out_ring;
  SubStreamEncoderParams params;
  Nv12Downscaler downscaler;
  X264Encoder encoder;
  std::thread worker;
  std::atomic<bool> running{false};
  std::atomic<std::uint64_t> encoded_frames{0};
  std::atomic<std::uint64_t> error_count{0};
  std::uint64_t next_pts{0};
  std::vector<std::uint8_t> scaled_buffer;
};

SubStreamEncoder::SubStreamEncoder(SubStreamTap& tap, EncodedRing& out_ring,
                                   SubStreamEncoderParams params)
    : impl_(std::make_unique<Impl>(tap, out_ring, std::move(params))) {}

SubStreamEncoder::~SubStreamEncoder() {
  if (impl_) {
    impl_->Stop();
  }
}

common::Result<void> SubStreamEncoder::Start() { return impl_->Start(); }

void SubStreamEncoder::Stop() { impl_->Stop(); }

std::uint64_t SubStreamEncoder::encoded_frames() const noexcept {
  return impl_->encoded_frames.load();
}

std::uint64_t SubStreamEncoder::error_count() const noexcept {
  return impl_->error_count.load();
}

}  // namespace camera_firmware::media
