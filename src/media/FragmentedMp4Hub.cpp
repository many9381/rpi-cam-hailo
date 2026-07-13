#include "camera_firmware/media/FragmentedMp4Hub.hpp"

#include <gst/app/gstappsink.h>
#include <gst/app/gstappsrc.h>
#include <gst/gst.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>

#include "camera_firmware/common/Logger.hpp"

namespace camera_firmware::media {
namespace {

using camera_firmware::common::Logger;
using camera_firmware::common::Result;

void EnsureGStreamerInitialized() {
  static std::once_flag initialized;
  std::call_once(initialized, [] { gst_init(nullptr, nullptr); });
}

Result<void> ValidateConfig(const FragmentedMp4HubConfig& config) {
  if (config.width == 0U || config.height == 0U || config.fps == 0U ||
      config.fragment_duration_ms == 0U ||
      config.stale_timeout_ms < config.fragment_duration_ms * 2ULL ||
      config.width > static_cast<unsigned int>(std::numeric_limits<int>::max()) ||
      config.height > static_cast<unsigned int>(std::numeric_limits<int>::max()) ||
      config.fps > static_cast<unsigned int>(std::numeric_limits<int>::max()) ||
      config.ring_limits.max_fragments == 0U ||
      config.ring_limits.max_bytes == 0U ||
      config.ring_limits.max_readers == 0U ||
      config.assembler_limits.max_buffer_bytes < 8U ||
      config.assembler_limits.max_box_bytes < 8U ||
      config.assembler_limits.max_init_segment_bytes < 16U ||
      config.assembler_limits.max_media_fragment_bytes < 16U) {
    return Result<void>::Err(
        {"E_FMP4_CONFIG", "fragmented MP4 configuration is invalid"});
  }
  return Result<void>::Ok();
}

}  // namespace

struct FragmentedMp4Hub::Impl {
  explicit Impl(EncodedRing& encoded) : encoded_ring(encoded) {}

  ~Impl() { Stop(); }

  Result<void> Start(const FragmentedMp4HubConfig& requested_config) {
    const auto validation = ValidateConfig(requested_config);
    if (!validation.ok()) {
      return validation;
    }

    {
      std::lock_guard lock(mutex);
      if (state == "starting" || state == "running" || state == "stopping" ||
          pipeline != nullptr || worker.joinable()) {
        return Result<void>::Err(
            {"E_FMP4_ALREADY_RUNNING", "fragmented MP4 hub is already running"});
      }
      state = "starting";
      config = requested_config;
      input_access_units = 0U;
      pushed_access_units = 0U;
      dropped_until_keyframe = 0U;
      input_error_count = 0U;
      published_fragments = 0U;
      current_generation = 0U;
      last_error_code.clear();
      last_error_message.clear();
    }

    EnsureGStreamerInitialized();
    auto next_ring =
        std::make_shared<FragmentRing>(requested_config.ring_limits);
    auto next_assembler = std::make_unique<IsoBmffAssembler>(
        requested_config.assembler_limits);
    {
      std::lock_guard lock(mutex);
      ring = std::move(next_ring);
    }
    {
      std::lock_guard output_lock(output_mutex);
      assembler = std::move(next_assembler);
    }

    const auto pipeline_result = CreatePipeline();
    if (!pipeline_result.ok()) {
      CleanupFailedStart(pipeline_result.error().code,
                         pipeline_result.error().message);
      return pipeline_result;
    }

    stop_requested.store(false, std::memory_order_release);
    accept_output.store(true, std::memory_order_release);
    const GstStateChangeReturn state_change =
        gst_element_set_state(pipeline, GST_STATE_PLAYING);
    if (state_change == GST_STATE_CHANGE_FAILURE) {
      const auto error = Result<void>::Err(
          {"E_FMP4_PIPELINE", "failed to start fragmented MP4 pipeline"});
      CleanupFailedStart(error.error().code, error.error().message);
      return error;
    }

    auto input_reader = encoded_ring.NewReader();
    {
      std::lock_guard lock(mutex);
      state = "running";
    }
    worker = std::thread(
        [this, input_reader = std::move(input_reader)]() mutable {
          WorkerMain(std::move(input_reader));
        });
    return Result<void>::Ok();
  }

  void Stop() noexcept {
    std::shared_ptr<FragmentRing> ring_to_invalidate;
    {
      std::lock_guard lock(mutex);
      if (state == "stopped" && pipeline == nullptr && !worker.joinable()) {
        return;
      }
      state = "stopping";
      stop_requested.store(true, std::memory_order_release);
      accept_output.store(false, std::memory_order_release);
      ring_to_invalidate = ring;
    }
    if (ring_to_invalidate) {
      ring_to_invalidate->Invalidate();
    }
    if (appsrc != nullptr) {
      (void)gst_app_src_end_of_stream(GST_APP_SRC(appsrc));
    }
    if (worker.joinable()) {
      worker.join();
    }
    if (pipeline != nullptr) {
      (void)gst_element_set_state(pipeline, GST_STATE_NULL);
    }
    if (appsink != nullptr) {
      GstAppSinkCallbacks callbacks{};
      gst_app_sink_set_callbacks(GST_APP_SINK(appsink), &callbacks, nullptr,
                                 nullptr);
    }
    if (pipeline != nullptr) {
      gst_object_unref(pipeline);
    }
    pipeline = nullptr;
    appsrc = nullptr;
    appsink = nullptr;
    {
      std::lock_guard output_lock(output_mutex);
      assembler.reset();
    }
    {
      std::lock_guard lock(mutex);
      ring.reset();
      state = "stopped";
    }
  }

  Result<FragmentRing::Reader> OpenReader() {
    std::shared_ptr<FragmentRing> current_ring;
    unsigned int stale_timeout_ms = 0U;
    {
      std::lock_guard lock(mutex);
      current_ring = ring;
      stale_timeout_ms = config.stale_timeout_ms;
    }
    if (!current_ring) {
      return Result<FragmentRing::Reader>::Err(
          {"E_LIVE_UNAVAILABLE", "live stream is unavailable"});
    }
    return current_ring->OpenReader(
        std::chrono::milliseconds(stale_timeout_ms));
  }

  FragmentedMp4HubStatus Status() const {
    FragmentedMp4HubStatus status;
    std::shared_ptr<FragmentRing> current_ring;
    {
      std::lock_guard lock(mutex);
      status.state = state;
      status.input_access_units = input_access_units;
      status.pushed_access_units = pushed_access_units;
      status.dropped_until_keyframe = dropped_until_keyframe;
      status.input_error_count = input_error_count;
      status.published_fragments = published_fragments;
      status.generation = current_generation;
      status.last_error_code = last_error_code;
      status.last_error_message = last_error_message;
      current_ring = ring;
    }
    if (current_ring) {
      status.ring_overrun_total = current_ring->overrun_total();
      status.retained_bytes = current_ring->retained_bytes();
      status.active_readers = current_ring->active_readers();
    }
    return status;
  }

  Result<void> CreatePipeline() {
    GstElement* next_pipeline = gst_pipeline_new("camera-firmware-fmp4");
    GstElement* source = gst_element_factory_make("appsrc", "h264-source");
    GstElement* parser = gst_element_factory_make("h264parse", "h264-parser");
    GstElement* caps_filter = gst_element_factory_make("capsfilter", "avc-caps");
    GstElement* muxer = gst_element_factory_make("mp4mux", "fragmented-muxer");
    GstElement* sink = gst_element_factory_make("appsink", "fragment-sink");
    if (next_pipeline == nullptr || source == nullptr || parser == nullptr ||
        caps_filter == nullptr || muxer == nullptr || sink == nullptr) {
      for (GstElement* element : {source, parser, caps_filter, muxer, sink}) {
        if (element != nullptr) {
          gst_object_unref(element);
        }
      }
      if (next_pipeline != nullptr) {
        gst_object_unref(next_pipeline);
      }
      return Result<void>::Err(
          {"E_FMP4_PLUGIN", "required fragmented MP4 plugin is unavailable"});
    }
    pipeline = next_pipeline;
    appsrc = source;
    appsink = sink;

    GstCaps* input_caps = gst_caps_new_simple(
        "video/x-h264", "stream-format", G_TYPE_STRING, "byte-stream",
        "alignment", G_TYPE_STRING, "au", "width", G_TYPE_INT,
        static_cast<int>(config.width), "height", G_TYPE_INT,
        static_cast<int>(config.height), "framerate", GST_TYPE_FRACTION,
        static_cast<int>(config.fps), 1, nullptr);
    GstCaps* output_caps = gst_caps_new_simple(
        "video/x-h264", "stream-format", G_TYPE_STRING, "avc", "alignment",
        G_TYPE_STRING, "au", nullptr);
    g_object_set(appsrc, "caps", input_caps, "is-live", TRUE, "format",
                 GST_FORMAT_TIME, "block", FALSE, "max-bytes",
                 static_cast<guint64>(4U * 1024U * 1024U), nullptr);
    g_object_set(parser, "config-interval", -1, "disable-passthrough", TRUE,
                 nullptr);
    g_object_set(caps_filter, "caps", output_caps, nullptr);
    g_object_set(muxer, "fragment-duration", config.fragment_duration_ms,
                 "streamable", TRUE, nullptr);
    g_object_set(appsink, "emit-signals", FALSE, "sync", FALSE,
                 "max-buffers", 16U, "drop", FALSE, "wait-on-eos", FALSE,
                 "enable-last-sample", FALSE, nullptr);
    gst_caps_unref(input_caps);
    gst_caps_unref(output_caps);

    GstAppSinkCallbacks callbacks{};
    callbacks.new_sample = &Impl::OnNewSample;
    gst_app_sink_set_callbacks(GST_APP_SINK(appsink), &callbacks, this,
                               nullptr);

    gst_bin_add_many(GST_BIN(pipeline), appsrc, parser, caps_filter, muxer,
                     appsink, nullptr);
    if (!gst_element_link_many(appsrc, parser, caps_filter, muxer, appsink,
                               nullptr)) {
      return Result<void>::Err(
          {"E_FMP4_PIPELINE", "failed to link fragmented MP4 pipeline"});
    }
    return Result<void>::Ok();
  }

  void CleanupFailedStart(std::string code, std::string message) noexcept {
    accept_output.store(false, std::memory_order_release);
    stop_requested.store(true, std::memory_order_release);
    if (pipeline != nullptr) {
      (void)gst_element_set_state(pipeline, GST_STATE_NULL);
    }
    if (appsink != nullptr) {
      GstAppSinkCallbacks callbacks{};
      gst_app_sink_set_callbacks(GST_APP_SINK(appsink), &callbacks, nullptr,
                                 nullptr);
    }
    if (pipeline != nullptr) {
      gst_object_unref(pipeline);
    }
    pipeline = nullptr;
    appsrc = nullptr;
    appsink = nullptr;
    std::shared_ptr<FragmentRing> current_ring;
    {
      std::lock_guard lock(mutex);
      state = "error";
      last_error_code = std::move(code);
      last_error_message = std::move(message);
      current_ring = ring;
    }
    if (current_ring) {
      current_ring->Invalidate();
    }
  }

  void WorkerMain(EncodedRing::Reader input_reader) {
    GstBus* bus = pipeline == nullptr ? nullptr : gst_element_get_bus(pipeline);
    std::optional<std::chrono::nanoseconds> base_timestamp;
    std::optional<GstClockTime> last_pts;
    const GstClockTime frame_duration = GST_SECOND / config.fps;
    bool seen_keyframe = false;

    while (!stop_requested.load(std::memory_order_acquire)) {
      if (bus != nullptr) {
        GstMessage* message = gst_bus_pop_filtered(
            bus, static_cast<GstMessageType>(GST_MESSAGE_ERROR |
                                             GST_MESSAGE_EOS));
        if (message != nullptr) {
          const GstMessageType type = GST_MESSAGE_TYPE(message);
          gst_message_unref(message);
          if (type == GST_MESSAGE_ERROR) {
            Fail("E_FMP4_PIPELINE", "fragmented MP4 pipeline failed");
          } else if (!stop_requested.load(std::memory_order_acquire)) {
            Fail("E_FMP4_PIPELINE", "fragmented MP4 pipeline ended unexpectedly");
          }
          break;
        }
      }

      auto next = input_reader.WaitNext(std::chrono::milliseconds(20));
      if (!next.has_value()) {
        continue;
      }
      EncodedAccessUnit access_unit = std::move(*next);
      {
        std::lock_guard lock(mutex);
        ++input_access_units;
      }
      if (access_unit.bytes.empty()) {
        std::lock_guard lock(mutex);
        ++input_error_count;
        continue;
      }
      if (!seen_keyframe) {
        if (!access_unit.is_key_frame) {
          std::lock_guard lock(mutex);
          ++dropped_until_keyframe;
          continue;
        }
        seen_keyframe = true;
        base_timestamp = access_unit.timestamp;
      }

      GstClockTime pts = 0U;
      const auto relative = access_unit.timestamp - *base_timestamp;
      if (relative.count() > 0) {
        pts = static_cast<GstClockTime>(relative.count());
      }
      if (last_pts.has_value() && pts <= *last_pts) {
        pts = *last_pts + frame_duration;
      }
      last_pts = pts;

      GstBuffer* buffer = gst_buffer_new_allocate(nullptr,
                                                  access_unit.bytes.size(),
                                                  nullptr);
      if (buffer == nullptr ||
          gst_buffer_fill(buffer, 0U, access_unit.bytes.data(),
                          access_unit.bytes.size()) !=
              access_unit.bytes.size()) {
        if (buffer != nullptr) {
          gst_buffer_unref(buffer);
        }
        Fail("E_FMP4_BUFFER", "failed to allocate fragmented MP4 input");
        break;
      }
      GST_BUFFER_PTS(buffer) = pts;
      GST_BUFFER_DTS(buffer) = pts;
      GST_BUFFER_DURATION(buffer) = frame_duration;
      GST_BUFFER_OFFSET(buffer) = access_unit.sequence;
      GST_BUFFER_FLAG_SET(buffer, GST_BUFFER_FLAG_MARKER);
      if (!access_unit.is_key_frame) {
        GST_BUFFER_FLAG_SET(buffer, GST_BUFFER_FLAG_DELTA_UNIT);
      }

      const GstFlowReturn flow =
          gst_app_src_push_buffer(GST_APP_SRC(appsrc), buffer);
      if (flow != GST_FLOW_OK) {
        if (!stop_requested.load(std::memory_order_acquire)) {
          Fail("E_FMP4_PIPELINE", "fragmented MP4 input was rejected");
        }
        break;
      }
      std::lock_guard lock(mutex);
      ++pushed_access_units;
    }

    if (bus != nullptr) {
      gst_object_unref(bus);
    }
  }

  static GstFlowReturn OnNewSample(GstAppSink* sink, gpointer user_data) {
    auto* self = static_cast<Impl*>(user_data);
    return self == nullptr ? GST_FLOW_ERROR : self->HandleNewSample(sink);
  }

  GstFlowReturn HandleNewSample(GstAppSink* sink) {
    GstSample* sample = gst_app_sink_pull_sample(sink);
    if (sample == nullptr) {
      return GST_FLOW_EOS;
    }
    GstBuffer* buffer = gst_sample_get_buffer(sample);
    GstMapInfo mapping{};
    if (buffer == nullptr || !gst_buffer_map(buffer, &mapping, GST_MAP_READ)) {
      gst_sample_unref(sample);
      Fail("E_FMP4_BUFFER", "failed to read fragmented MP4 output");
      return GST_FLOW_ERROR;
    }

    GstFlowReturn flow = GST_FLOW_OK;
    if (accept_output.load(std::memory_order_acquire)) {
      std::lock_guard output_lock(output_mutex);
      if (assembler != nullptr) {
        const auto assembled = assembler->Push(
            std::span<const std::uint8_t>(mapping.data, mapping.size));
        if (!assembled.ok()) {
          Fail(assembled.error().code, assembled.error().message);
          flow = GST_FLOW_ERROR;
        } else {
          for (auto segment : assembled.value()) {
            if (!PublishSegment(std::move(segment))) {
              flow = GST_FLOW_ERROR;
              break;
            }
          }
        }
      }
    }

    gst_buffer_unmap(buffer, &mapping);
    gst_sample_unref(sample);
    return flow;
  }

  bool PublishSegment(IsoBmffSegment segment) {
    std::shared_ptr<FragmentRing> current_ring;
    {
      std::lock_guard lock(mutex);
      current_ring = ring;
    }
    if (!current_ring) {
      return false;
    }

    if (segment.kind == IsoBmffSegmentKind::kInitialization) {
      const auto generation =
          current_ring->BeginGeneration(std::move(segment.bytes));
      if (!generation.ok()) {
        Fail(generation.error().code, generation.error().message);
        return false;
      }
      std::lock_guard lock(mutex);
      current_generation = generation.value();
      return true;
    }

    const auto published =
        current_ring->Publish(std::move(segment.bytes), true);
    if (!published.ok()) {
      Fail(published.error().code, published.error().message);
      return false;
    }
    std::lock_guard lock(mutex);
    ++published_fragments;
    return true;
  }

  void Fail(std::string code, std::string message) noexcept {
    std::shared_ptr<FragmentRing> current_ring;
    {
      std::lock_guard lock(mutex);
      if (state == "stopping" || state == "stopped") {
        return;
      }
      state = "error";
      last_error_code = std::move(code);
      last_error_message = std::move(message);
      stop_requested.store(true, std::memory_order_release);
      accept_output.store(false, std::memory_order_release);
      current_ring = ring;
    }
    if (current_ring) {
      current_ring->Invalidate();
    }
    Logger::instance().log(Logger::Level::kError,
                           "fragmented MP4 hub entered error state");
  }

  EncodedRing& encoded_ring;
  mutable std::mutex mutex;
  std::mutex output_mutex;
  FragmentedMp4HubConfig config;
  std::shared_ptr<FragmentRing> ring;
  std::unique_ptr<IsoBmffAssembler> assembler;
  std::thread worker;
  std::atomic<bool> stop_requested{false};
  std::atomic<bool> accept_output{false};
  GstElement* pipeline{nullptr};
  GstElement* appsrc{nullptr};
  GstElement* appsink{nullptr};
  std::string state{"stopped"};
  std::uint64_t input_access_units{0U};
  std::uint64_t pushed_access_units{0U};
  std::uint64_t dropped_until_keyframe{0U};
  std::uint64_t input_error_count{0U};
  std::uint64_t published_fragments{0U};
  std::uint64_t current_generation{0U};
  std::string last_error_code;
  std::string last_error_message;
};

FragmentedMp4Hub::FragmentedMp4Hub(EncodedRing& encoded_ring)
    : impl_(std::make_unique<Impl>(encoded_ring)) {}

FragmentedMp4Hub::~FragmentedMp4Hub() = default;

Result<void> FragmentedMp4Hub::Start(const FragmentedMp4HubConfig& config) {
  return impl_->Start(config);
}

void FragmentedMp4Hub::Stop() noexcept { impl_->Stop(); }

Result<FragmentRing::Reader> FragmentedMp4Hub::OpenReader() {
  return impl_->OpenReader();
}

FragmentedMp4HubStatus FragmentedMp4Hub::Status() const {
  return impl_->Status();
}

}  // namespace camera_firmware::media
