#include "camera_firmware/media/CameraPipeline.hpp"

#include <libcamera/camera.h>
#include <libcamera/camera_manager.h>
#include <libcamera/control_ids.h>
#include <libcamera/controls.h>
#include <libcamera/formats.h>
#include <libcamera/framebuffer_allocator.h>
#include <libcamera/request.h>
#include <libcamera/stream.h>
#include <sys/mman.h>
#include <x264.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "camera_firmware/ai/AiFrameTap.hpp"
#include "camera_firmware/common/Logger.hpp"
#include "camera_firmware/media/CameraTiming.hpp"
#include "camera_firmware/media/LoresGeometry.hpp"

namespace camera_firmware::media {
namespace {

using camera_firmware::common::Logger;
using camera_firmware::common::Result;

constexpr unsigned int kDefaultBufferCount = 4;

struct X264EncoderDeleter {
  void operator()(x264_t* encoder) const noexcept {
    if (encoder != nullptr) {
      x264_encoder_close(encoder);
    }
  }
};

using X264Encoder = std::unique_ptr<x264_t, X264EncoderDeleter>;

struct MappedPlane {
  void* address{nullptr};
  std::size_t length{0};
};

struct MappedBuffer {
  std::vector<MappedPlane> planes;
};

struct RequeueContext {
  std::mutex mutex;
  std::shared_ptr<libcamera::Camera> camera;
  bool running{false};
};

void UnmapBuffer(MappedBuffer& buffer) {
  for (auto& plane : buffer.planes) {
    if (plane.address != nullptr && plane.address != MAP_FAILED) {
      (void)munmap(plane.address, plane.length);
      plane.address = nullptr;
      plane.length = 0;
    }
  }
}

void RequeueRequest(std::weak_ptr<RequeueContext> weak_context,
                    libcamera::Request* request) {
  auto context = weak_context.lock();
  if (context == nullptr || request == nullptr) {
    return;
  }

  std::scoped_lock lock(context->mutex);
  if (!context->running || context->camera == nullptr) {
    return;
  }

  request->reuse(libcamera::Request::ReuseBuffers);
  const int status = context->camera->queueRequest(request);
  if (status != 0) {
    Logger::instance().log(Logger::Level::kError,
                           "failed to requeue libcamera request");
    context->running = false;
  }
}

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
    bytes.insert(bytes.end(),
                 nals[index].p_payload,
                 nals[index].p_payload + payload_size);
  }
  return bytes;
}

}  // namespace

struct CameraPipeline::Impl {
  Impl(SnapshotTap& snapshot, ai::AiFrameTap& ai, EncodedRing& encoded)
      : snapshot_tap(snapshot), ai_frame_tap(ai), encoded_ring(encoded) {}

  ~Impl() { Stop(); }

  Result<void> ValidateConfigOnly(const config::AppConfig& config) {
    if (config.platform.target != "rpi5") {
      return Result<void>::Err(
          {"E_PLATFORM_CONFIG", "only platform.target=rpi5 is supported"});
    }
    if (config.camera.id.empty()) {
      return Result<void>::Err(
          {"E_CAMERA_CONFIG", "camera.id must not be empty"});
    }
    if (config.camera.source.backend != "libcamera") {
      return Result<void>::Err(
          {"E_CAMERA_CONFIG", "only camera.source.backend=libcamera is supported"});
    }
    if (config.camera.video.format != "nv12") {
      return Result<void>::Err(
          {"E_CAMERA_CONFIG", "only camera.video.format=nv12 is supported"});
    }
    if (config.camera.video.width == 0U || config.camera.video.height == 0U ||
        config.camera.video.fps == 0U) {
      return Result<void>::Err(
          {"E_CAMERA_CONFIG", "camera video dimensions and fps must be non-zero"});
    }
    if (config.camera.encoder.backend != "x264") {
      return Result<void>::Err(
          {"E_CAMERA_CONFIG", "only camera.encoder.backend=x264 is supported"});
    }
    if (config.camera.encoder.bitrate_kbps == 0U ||
        config.camera.encoder.gop == 0U ||
        config.camera.encoder.preset.empty()) {
      return Result<void>::Err(
          {"E_CAMERA_CONFIG",
           "camera encoder bitrate, gop, and preset must be configured"});
    }
    if (config.secure_rtsp.mount.empty() || config.secure_rtsp.mount[0] != '/') {
      return Result<void>::Err(
          {"E_CAMERA_CONFIG", "secure_rtsp.mount must start with /"});
    }
    Logger::instance().log(Logger::Level::kInfo,
                           "camera pipeline config valid without opening camera");
    return Result<void>::Ok();
  }

  Result<void> Start(const config::AppConfig& config) {
    auto validation = ValidateConfigOnly(config);
    if (!validation.ok()) {
      return validation;
    }
    {
      std::scoped_lock lock(mutex);
      if (running || state == "starting") {
        return Result<void>::Err(
            {"E_CAMERA_ALREADY_RUNNING", "camera pipeline is already running"});
      }
      configured_camera = config.camera;
      camera_id = config.camera.id;
      output_width = config.camera.video.width;
      output_height = config.camera.video.height;
      capture_rate.Reset();
      encoded_rate.Reset();
      captured_frames = 0U;
      encoded_frames = 0U;
      capture_error_count = 0U;
      encode_error_count = 0U;
      state = "starting";
    }

    manager = std::make_unique<libcamera::CameraManager>();
    const int start_status = manager->start();
    if (start_status != 0) {
      manager.reset();
      SetStoppedState("error");
      return Result<void>::Err(
          {"E_CAMERA_MANAGER", "failed to start libcamera CameraManager"});
    }

    auto cameras = manager->cameras();
    if (cameras.empty()) {
      manager->stop();
      manager.reset();
      SetStoppedState("no-camera");
      return Result<void>::Err(
          {"E_CAMERA_NOT_FOUND", "no libcamera cameras detected"});
    }

    if (configured_camera.source.camera_index >= cameras.size()) {
      cameras.clear();
      manager->stop();
      manager.reset();
      SetStoppedState("no-camera");
      return Result<void>::Err(
          {"E_CAMERA_NOT_FOUND", "configured libcamera index is unavailable"});
    }

    camera = cameras[configured_camera.source.camera_index];
    cameras.clear();
    if (camera->acquire() != 0) {
      camera.reset();
      manager->stop();
      manager.reset();
      SetStoppedState("error");
      return Result<void>::Err(
          {"E_CAMERA_ACQUIRE", "failed to acquire libcamera camera"});
    }

    auto configured = ConfigureCamera(config);
    if (!configured.ok()) {
      Stop();
      return configured;
    }

    auto allocated = AllocateBuffers();
    if (!allocated.ok()) {
      Stop();
      return allocated;
    }

    auto mapped = MapBuffers();
    if (!mapped.ok()) {
      Stop();
      return mapped;
    }

    auto encoder_result = ConfigureEncoder();
    if (!encoder_result.ok()) {
      Stop();
      return encoder_result;
    }

    auto request_result = CreateRequests();
    if (!request_result.ok()) {
      Stop();
      return request_result;
    }

    const auto next_source_epoch = snapshot_tap.BeginSourceRun();
    {
      std::scoped_lock lock(mutex);
      source_epoch = next_source_epoch;
    }

    requeue_context = std::make_shared<RequeueContext>();
    {
      std::scoped_lock context_lock(requeue_context->mutex);
      requeue_context->camera = camera;
      requeue_context->running = true;
    }

    const auto frame_duration_limits =
        FixedFrameDurationLimits(configured_camera.video.fps);
    if (!frame_duration_limits.ok()) {
      Stop();
      return Result<void>::Err(frame_duration_limits.error());
    }
    libcamera::ControlList controls(camera->controls());
    controls.set(libcamera::controls::FrameDurationLimits,
                 frame_duration_limits.value());

    camera->requestCompleted.connect(this, &Impl::OnRequestComplete);
    if (camera->start(&controls) != 0) {
      Stop();
      return Result<void>::Err(
          {"E_CAMERA_START", "failed to start libcamera capture"});
    }
    camera_started = true;

    {
      std::scoped_lock lock(mutex);
      running = true;
      state = "running";
    }

    for (auto& request : requests) {
      if (camera->queueRequest(request.get()) != 0) {
        Stop();
        return Result<void>::Err(
            {"E_CAMERA_QUEUE", "failed to queue libcamera capture request"});
      }
    }

    Logger::instance().log(Logger::Level::kInfo,
                           "camera pipeline running: " + camera_id +
                               " NV12 " +
                               std::to_string(stream_config.size.width) + "x" +
                               std::to_string(stream_config.size.height));
    return Result<void>::Ok();
  }

  void Stop() {
    std::shared_ptr<libcamera::Camera> camera_to_stop;
    std::unique_ptr<libcamera::CameraManager> manager_to_stop;
    bool should_stop_camera = false;
    SnapshotTap::SourceEpoch source_epoch_to_end = 0U;

    {
      std::scoped_lock lock(mutex);
      if (!running && state == "stopped" && manager == nullptr) {
        return;
      }
      running = false;
      state = "stopping";
      should_stop_camera = camera_started;
      camera_started = false;
      source_epoch_to_end = source_epoch;
      source_epoch = 0U;
      camera_to_stop = camera;
      if (requeue_context != nullptr) {
        std::scoped_lock context_lock(requeue_context->mutex);
        requeue_context->running = false;
        requeue_context->camera.reset();
      }
    }

    if (source_epoch_to_end != 0U) {
      snapshot_tap.EndSourceRun(source_epoch_to_end);
    }

    if (camera_to_stop != nullptr) {
      camera_to_stop->requestCompleted.disconnect(this);
      if (should_stop_camera) {
        (void)camera_to_stop->stop();
      }
    }

    {
      std::scoped_lock lock(mutex);
      requests.clear();
      for (auto& [buffer, mapping] : mapped_buffers) {
        (void)buffer;
        UnmapBuffer(mapping);
      }
      mapped_buffers.clear();
      encoder.reset();
      allocator.reset();
      camera_config.reset();
      stream = nullptr;
      requeue_context.reset();
      if (camera != nullptr) {
        camera->release();
        camera.reset();
      }
      if (manager != nullptr) {
        manager_to_stop = std::move(manager);
      }
      state = "stopped";
    }

    camera_to_stop.reset();
    if (manager_to_stop != nullptr) {
      manager_to_stop->stop();
    }
  }

  std::vector<CameraPipelineStatus> Status() const {
    std::scoped_lock lock(mutex);
    return {BuildStatus(snapshot_tap.Latest().has_value())};
  }

  std::vector<CameraPipelineStatus> Status(
      std::chrono::milliseconds maximum_snapshot_age) const {
    std::scoped_lock lock(mutex);
    return {BuildStatus(snapshot_tap.HasFreshFrame(maximum_snapshot_age))};
  }

  CameraPipelineStatus BuildStatus(bool snapshot_available) const {
    CameraPipelineStatus status;
    status.id = camera_id;
    status.state = state;
    status.snapshot_available = snapshot_available;
    status.width = output_width;
    status.height = output_height;
    status.configured_fps = configured_camera.video.fps;
    status.capture_fps = capture_rate.FramesPerSecond();
    status.encoded_fps = encoded_rate.FramesPerSecond();
    status.captured_frames = captured_frames;
    status.encoded_frames = encoded_frames;
    status.capture_error_count = capture_error_count;
    status.encode_error_count = encode_error_count;
    status.ai_source = ai_uses_lores ? "lores" : "main-fallback";
    return status;
  }

  Result<void> ConfigureCamera(const config::AppConfig& config) {
    const unsigned int model_width = ResolveAiLoresWidth(config);
    const LoresSize lores = ComputeLoresSize(configured_camera.video.width,
                                             configured_camera.video.height,
                                             model_width);
    const bool want_lores = lores.width > 0U && lores.height > 0U;

    std::vector<libcamera::StreamRole> roles = {
        libcamera::StreamRole::VideoRecording};
    if (want_lores) {
      roles.push_back(libcamera::StreamRole::Viewfinder);
    }
    camera_config = camera->generateConfiguration(roles);
    if (camera_config == nullptr || camera_config->empty()) {
      return Result<void>::Err(
          {"E_CAMERA_CONFIG", "camera did not provide a video stream config"});
    }

    auto& main_cfg = camera_config->at(0);
    main_cfg.pixelFormat = libcamera::formats::NV12;
    main_cfg.size.width = configured_camera.video.width;
    main_cfg.size.height = configured_camera.video.height;
    main_cfg.bufferCount = std::max(main_cfg.bufferCount, kDefaultBufferCount);

    const bool have_lores_slot = want_lores && camera_config->size() >= 2U;
    if (have_lores_slot) {
      auto& lores_cfg = camera_config->at(1);
      lores_cfg.pixelFormat = libcamera::formats::NV12;
      lores_cfg.size.width = lores.width;
      lores_cfg.size.height = lores.height;
      lores_cfg.bufferCount = std::max(lores_cfg.bufferCount, kDefaultBufferCount);
    }

    const auto validation = camera_config->validate();
    if (validation == libcamera::CameraConfiguration::Invalid) {
      return Result<void>::Err(
          {"E_CAMERA_CONFIG", "failed to validate NV12 video camera config"});
    }
    if (camera->configure(camera_config.get()) != 0) {
      return Result<void>::Err(
          {"E_CAMERA_CONFIGURE", "failed to configure libcamera for NV12 video"});
    }

    auto& validated_main = camera_config->at(0);
    stream = validated_main.stream();
    stream_config = validated_main;
    if (stream == nullptr ||
        stream_config.pixelFormat != libcamera::formats::NV12) {
      return Result<void>::Err(
          {"E_CAMERA_FORMAT", "libcamera did not accept NV12 video format"});
    }
    if (stream_config.stride == 0U || stream_config.size.width == 0U ||
        stream_config.size.height == 0U) {
      return Result<void>::Err(
          {"E_CAMERA_CONFIG", "libcamera returned an invalid stream geometry"});
    }

    bool uses_lores = false;
    lores_stream = nullptr;
    if (have_lores_slot) {
      auto& validated_lores = camera_config->at(1);
      libcamera::Stream* candidate = validated_lores.stream();
      if (candidate != nullptr &&
          validated_lores.pixelFormat == libcamera::formats::NV12 &&
          validated_lores.stride > 0U && validated_lores.size.width > 0U &&
          validated_lores.size.height > 0U) {
        lores_stream = candidate;
        lores_stream_config = validated_lores;
        lores_width = validated_lores.size.width;
        lores_height = validated_lores.size.height;
        uses_lores = true;
      }
    }
    if (want_lores && !uses_lores) {
      Logger::instance().log(
          Logger::Level::kWarn,
          "AI lores stream unavailable; falling back to downscaling the main "
          "stream for inference");
    }

    {
      std::scoped_lock lock(mutex);
      output_width = stream_config.size.width;
      output_height = stream_config.size.height;
      ai_uses_lores = uses_lores;
    }
    return Result<void>::Ok();
  }

  Result<void> AllocateBuffers() {
    allocator = std::make_unique<libcamera::FrameBufferAllocator>(camera);
    const int allocated = allocator->allocate(stream);
    if (allocated < 0) {
      return Result<void>::Err(
          {"E_CAMERA_ALLOCATE", "failed to allocate libcamera frame buffers"});
    }
    const auto& buffers = allocator->buffers(stream);
    if (buffers.empty()) {
      return Result<void>::Err(
          {"E_CAMERA_ALLOCATE", "libcamera allocated no frame buffers"});
    }
    if (ai_uses_lores) {
      const int lores_allocated = allocator->allocate(lores_stream);
      if (lores_allocated < 0 ||
          allocator->buffers(lores_stream).empty()) {
        return Result<void>::Err(
            {"E_CAMERA_ALLOCATE", "failed to allocate lores frame buffers"});
      }
    }
    return Result<void>::Ok();
  }

  Result<void> MapBuffers() {
    for (const auto& buffer : allocator->buffers(stream)) {
      MappedBuffer mapped;
      for (const auto& plane : buffer->planes()) {
        if (plane.fd.get() < 0 ||
            plane.offset == libcamera::FrameBuffer::Plane::kInvalidOffset ||
            plane.length == 0U) {
          UnmapBuffer(mapped);
          return Result<void>::Err(
              {"E_CAMERA_DMABUF", "libcamera returned invalid DMABUF plane"});
        }

        const std::size_t map_length =
            static_cast<std::size_t>(plane.offset) + plane.length;
        void* address =
            mmap(nullptr, map_length, PROT_READ, MAP_SHARED, plane.fd.get(), 0);
        if (address == MAP_FAILED) {
          UnmapBuffer(mapped);
          return Result<void>::Err(
              {"E_CAMERA_MMAP", "failed to mmap libcamera DMABUF plane"});
        }
        mapped.planes.push_back({address, map_length});
      }
      mapped_buffers.emplace(buffer.get(), std::move(mapped));
    }
    return Result<void>::Ok();
  }

  Result<void> ConfigureEncoder() {
    x264_param_t params{};
    const auto policy = ResolveX264RuntimePolicy(configured_camera.encoder);
    if (x264_param_default_preset(&params, policy.preset.c_str(),
                                  "zerolatency") < 0) {
      return Result<void>::Err(
          {"E_H264_ENCODER", "failed to initialize x264 preset"});
    }
    params.i_width = static_cast<int>(stream_config.size.width);
    params.i_height = static_cast<int>(stream_config.size.height);
    params.i_csp = X264_CSP_NV12;
    params.i_fps_num = static_cast<int>(configured_camera.video.fps);
    params.i_fps_den = 1;
    params.i_timebase_num = 1;
    params.i_timebase_den = static_cast<int>(configured_camera.video.fps);
    params.i_threads = policy.threads;
    params.i_keyint_max = static_cast<int>(configured_camera.encoder.gop);
    params.i_keyint_min = static_cast<int>(configured_camera.encoder.gop);
    params.i_bframe = 0;
    params.rc.i_rc_method = X264_RC_ABR;
    params.rc.i_bitrate =
        static_cast<int>(configured_camera.encoder.bitrate_kbps);
    params.rc.i_vbv_max_bitrate = policy.vbv_max_bitrate_kbps;
    params.rc.i_vbv_buffer_size = policy.vbv_buffer_size_kbits;
    params.b_annexb = 1;
    params.b_repeat_headers = 1;
    params.b_vfr_input = 0;
    params.i_log_level = X264_LOG_WARNING;
    if (x264_param_apply_profile(&params, "baseline") < 0) {
      x264_param_cleanup(&params);
      return Result<void>::Err(
          {"E_H264_ENCODER", "failed to apply x264 baseline profile"});
    }

    encoder.reset(x264_encoder_open(&params));
    x264_param_cleanup(&params);
    if (encoder == nullptr) {
      return Result<void>::Err(
          {"E_H264_ENCODER", "failed to open x264 encoder"});
    }
    next_pts = 0;
    return Result<void>::Ok();
  }

  Result<void> CreateRequests() {
    const auto& main_buffers = allocator->buffers(stream);
    const std::vector<std::unique_ptr<libcamera::FrameBuffer>>* lores_buffers =
        ai_uses_lores ? &allocator->buffers(lores_stream) : nullptr;
    if (lores_buffers != nullptr && lores_buffers->size() != main_buffers.size()) {
      return Result<void>::Err(
          {"E_CAMERA_REQUEST", "main and lores buffer counts differ"});
    }
    for (std::size_t index = 0; index < main_buffers.size(); ++index) {
      auto request = camera->createRequest();
      if (request == nullptr) {
        return Result<void>::Err(
            {"E_CAMERA_REQUEST", "failed to create libcamera request"});
      }
      if (request->addBuffer(stream, main_buffers[index].get()) != 0) {
        return Result<void>::Err(
            {"E_CAMERA_REQUEST", "failed to attach frame buffer to request"});
      }
      if (lores_buffers != nullptr &&
          request->addBuffer(lores_stream, (*lores_buffers)[index].get()) != 0) {
        return Result<void>::Err(
            {"E_CAMERA_REQUEST", "failed to attach lores buffer to request"});
      }
      requests.push_back(std::move(request));
    }
    return Result<void>::Ok();
  }

  void OnRequestComplete(libcamera::Request* request) {
    std::scoped_lock lock(mutex);
    if (!running || request == nullptr ||
        request->status() == libcamera::Request::RequestCancelled) {
      return;
    }

    libcamera::FrameBuffer* main_buffer = request->findBuffer(stream);
    if (main_buffer == nullptr) {
      ++capture_error_count;
      RequeueRequest(requeue_context, request);
      return;
    }
    if (main_buffer->metadata().status != libcamera::FrameMetadata::FrameSuccess &&
        main_buffer->metadata().status != libcamera::FrameMetadata::FrameStartup) {
      ++capture_error_count;
      RequeueRequest(requeue_context, request);
      return;
    }

    const auto frame_timestamp =
        std::chrono::nanoseconds(main_buffer->metadata().timestamp);
    ++captured_frames;
    capture_rate.Record(frame_timestamp);

    auto main_frame = BuildFrameHandle(*main_buffer, stream_config.size.width,
                                       stream_config.size.height,
                                       stream_config.stride);
    if (!main_frame.ok()) {
      ++capture_error_count;
      Logger::instance().log(Logger::Level::kError, main_frame.error().message);
      RequeueRequest(requeue_context, request);
      return;
    }

    auto encoded = EncodeBuffer(*main_buffer, main_frame.value());
    if (encoded.ok() && !encoded.value().bytes.empty()) {
      ++encoded_frames;
      encoded_rate.Record(frame_timestamp);
      encoded_ring.Publish(std::move(encoded).value());
    } else if (!encoded.ok()) {
      ++encode_error_count;
      Logger::instance().log(Logger::Level::kError, encoded.error().message);
    } else {
      ++encode_error_count;
    }

    std::weak_ptr<RequeueContext> weak_context = requeue_context;
    // Owns nothing; its only job is to run the requeue when the last lease
    // that captured it drops. shared_ptr<void>(nullptr, deleter) is non-empty
    // (use_count 1) and calls the deleter with nullptr on destruction.
    auto requeue_guard = std::shared_ptr<void>(
        nullptr, [weak_context, request](void*) {
          RequeueRequest(weak_context, request);
        });

    FrameLease main_lease(std::move(main_frame).value(),
                          [requeue_guard] {});
    snapshot_tap.Publish(main_lease.CloneRef(), source_epoch);

    if (ai_uses_lores) {
      libcamera::FrameBuffer* lores_buffer = request->findBuffer(lores_stream);
      if (lores_buffer != nullptr &&
          (lores_buffer->metadata().status ==
               libcamera::FrameMetadata::FrameSuccess ||
           lores_buffer->metadata().status ==
               libcamera::FrameMetadata::FrameStartup)) {
        auto lores_frame = BuildFrameHandle(*lores_buffer, lores_width,
                                            lores_height,
                                            lores_stream_config.stride);
        if (lores_frame.ok()) {
          FrameLease lores_lease(std::move(lores_frame).value(),
                                 [requeue_guard] {});
          ai_frame_tap.PublishLatest(std::move(lores_lease));
        }
      }
      // A missing or failed lores buffer drops this AI frame only; latest-wins
      // tolerates it and the main frame has already been encoded.
    } else {
      ai_frame_tap.PublishLatest(main_lease.CloneRef());
    }
  }

  Result<FrameHandle> BuildFrameHandle(const libcamera::FrameBuffer& buffer,
                                       unsigned int width,
                                       unsigned int height,
                                       unsigned int stride) const {
    const auto& planes = buffer.planes();
    if (planes.empty()) {
      return Result<FrameHandle>::Err(
          {"E_CAMERA_DMABUF", "completed frame has no DMABUF planes"});
    }

    FrameHandle handle;
    handle.camera_id = camera_id;
    handle.format = "NV12";
    handle.width = width;
    handle.height = height;
    handle.sequence = buffer.metadata().sequence;
    handle.timestamp = std::chrono::nanoseconds(buffer.metadata().timestamp);

    const std::size_t y_size =
        static_cast<std::size_t>(stride) * handle.height;
    if (planes[0].length < y_size) {
      return Result<FrameHandle>::Err(
          {"E_CAMERA_DMABUF", "NV12 luma plane is shorter than expected"});
    }

    handle.planes[0] = FramePlane{
        .dmabuf_fd = planes[0].fd.get(),
        .offset = planes[0].offset,
        .length = y_size,
        .stride = stride,
    };

    if (planes.size() >= 2U) {
      handle.planes[1] = FramePlane{
          .dmabuf_fd = planes[1].fd.get(),
          .offset = planes[1].offset,
          .length = planes[1].length,
          .stride = stride,
      };
    } else {
      const std::size_t uv_offset =
          static_cast<std::size_t>(planes[0].offset) + y_size;
      const std::size_t mapped_end =
          static_cast<std::size_t>(planes[0].offset) + planes[0].length;
      if (uv_offset >= mapped_end) {
        return Result<FrameHandle>::Err(
            {"E_CAMERA_DMABUF", "NV12 chroma plane offset exceeds DMABUF"});
      }
      handle.planes[1] = FramePlane{
          .dmabuf_fd = planes[0].fd.get(),
          .offset = uv_offset,
          .length = mapped_end - uv_offset,
          .stride = stride,
      };
    }
    handle.plane_count = 2;
    return Result<FrameHandle>::Ok(std::move(handle));
  }

  Result<EncodedAccessUnit> EncodeBuffer(const libcamera::FrameBuffer& buffer,
                                         const FrameHandle& frame) {
    const auto mapped = mapped_buffers.find(&buffer);
    if (mapped == mapped_buffers.end() || mapped->second.planes.empty()) {
      return Result<EncodedAccessUnit>::Err(
          {"E_H264_ENCODER", "completed frame buffer is not mapped"});
    }

    const auto& planes = buffer.planes();
    auto* y_plane = static_cast<std::uint8_t*>(mapped->second.planes[0].address) +
                    planes[0].offset;
    std::uint8_t* uv_plane = nullptr;
    if (planes.size() >= 2U) {
      if (mapped->second.planes.size() < 2U) {
        return Result<EncodedAccessUnit>::Err(
            {"E_H264_ENCODER", "NV12 chroma DMABUF plane is not mapped"});
      }
      uv_plane = static_cast<std::uint8_t*>(mapped->second.planes[1].address) +
                 planes[1].offset;
    } else {
      uv_plane = y_plane + frame.planes[0].length;
    }

    x264_picture_t picture_in{};
    x264_picture_t picture_out{};
    x264_picture_init(&picture_in);
    x264_picture_init(&picture_out);
    picture_in.img.i_csp = X264_CSP_NV12;
    picture_in.img.i_plane = 2;
    picture_in.img.i_stride[0] = static_cast<int>(stream_config.stride);
    picture_in.img.i_stride[1] = static_cast<int>(stream_config.stride);
    picture_in.img.plane[0] = y_plane;
    picture_in.img.plane[1] = uv_plane;
    picture_in.i_pts = static_cast<int64_t>(next_pts++);

    x264_nal_t* nals = nullptr;
    int nal_count = 0;
    const int status =
        x264_encoder_encode(encoder.get(), &nals, &nal_count, &picture_in,
                            &picture_out);
    if (status < 0) {
      return Result<EncodedAccessUnit>::Err(
          {"E_H264_ENCODER", "x264 failed to encode NV12 frame"});
    }

    EncodedAccessUnit access_unit;
    access_unit.sequence = frame.sequence;
    access_unit.timestamp = frame.timestamp;
    access_unit.is_key_frame = picture_out.b_keyframe != 0;
    access_unit.bytes = CopyNalPayloads(nals, nal_count);
    return Result<EncodedAccessUnit>::Ok(std::move(access_unit));
  }

  void SetStoppedState(const std::string& next_state) {
    std::scoped_lock lock(mutex);
    state = next_state;
    running = false;
  }

  SnapshotTap& snapshot_tap;
  ai::AiFrameTap& ai_frame_tap;
  EncodedRing& encoded_ring;
  mutable std::mutex mutex;
  std::unique_ptr<libcamera::CameraManager> manager;
  std::shared_ptr<libcamera::Camera> camera;
  std::unique_ptr<libcamera::CameraConfiguration> camera_config;
  std::unique_ptr<libcamera::FrameBufferAllocator> allocator;
  libcamera::Stream* stream{nullptr};
  libcamera::StreamConfiguration stream_config;
  libcamera::Stream* lores_stream{nullptr};
  libcamera::StreamConfiguration lores_stream_config;
  unsigned int lores_width{0U};
  unsigned int lores_height{0U};
  bool ai_uses_lores{false};
  std::vector<std::unique_ptr<libcamera::Request>> requests;
  std::unordered_map<const libcamera::FrameBuffer*, MappedBuffer> mapped_buffers;
  std::shared_ptr<RequeueContext> requeue_context;
  X264Encoder encoder;
  config::CameraConfig configured_camera;
  FrameRateEstimator capture_rate;
  FrameRateEstimator encoded_rate;
  std::uint64_t next_pts{0};
  std::uint64_t captured_frames{0U};
  std::uint64_t encoded_frames{0U};
  std::uint64_t capture_error_count{0U};
  std::uint64_t encode_error_count{0U};
  SnapshotTap::SourceEpoch source_epoch{0U};
  unsigned int output_width{configured_camera.video.width};
  unsigned int output_height{configured_camera.video.height};
  std::string camera_id{"imx708-main"};
  std::string state{"stopped"};
  bool running{false};
  bool camera_started{false};
};

CameraPipeline::CameraPipeline(SnapshotTap& snapshot_tap,
                               ai::AiFrameTap& ai_frame_tap,
                               EncodedRing& encoded_ring)
    : impl_(std::make_unique<Impl>(snapshot_tap, ai_frame_tap, encoded_ring)) {}

CameraPipeline::~CameraPipeline() = default;

Result<void> CameraPipeline::ValidateConfigOnly(const config::AppConfig& config) {
  return impl_->ValidateConfigOnly(config);
}

Result<void> CameraPipeline::Start(const config::AppConfig& config) {
  return impl_->Start(config);
}

void CameraPipeline::Stop() { impl_->Stop(); }

std::vector<CameraPipelineStatus> CameraPipeline::Status() const {
  return impl_->Status();
}

std::vector<CameraPipelineStatus> CameraPipeline::Status(
    std::chrono::milliseconds maximum_snapshot_age) const {
  return impl_->Status(maximum_snapshot_age);
}

}  // namespace camera_firmware::media
