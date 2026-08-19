#include "camera_firmware/ai/Nv12RgbPreprocessor.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include <libavutil/pixfmt.h>
#include <libswscale/swscale.h>
}

#include "camera_firmware/config/AppConfig.hpp"

namespace camera_firmware::ai {
namespace {

constexpr std::size_t kRgbChannels = 3U;

common::Error PreprocessError(std::string message) {
  return {"E_AI_PREPROCESS", std::move(message)};
}

struct ModelInputGeometry {
  std::uint32_t scaled_width{0};
  std::uint32_t scaled_height{0};
  std::uint32_t x_offset{0};
  std::uint32_t y_offset{0};
};

bool MultiplicationOverflows(std::size_t left, std::size_t right) {
  return left != 0U && right > std::numeric_limits<std::size_t>::max() / left;
}

common::Result<std::size_t> Rgb8ByteCount(std::uint32_t width,
                                           std::uint32_t height) {
  if (width == 0U || height == 0U ||
      MultiplicationOverflows(width, height) ||
      MultiplicationOverflows(static_cast<std::size_t>(width) * height,
                              kRgbChannels)) {
    return common::Result<std::size_t>::Err(
        PreprocessError("AI model input dimensions are invalid"));
  }
  const auto bytes = static_cast<std::size_t>(width) * height * kRgbChannels;
  if (bytes > config::kMaximumAiModelInputBytes) {
    return common::Result<std::size_t>::Err(
        PreprocessError("AI model input exceeds the RGB8 memory limit"));
  }
  return common::Result<std::size_t>::Ok(bytes);
}

common::Result<std::size_t> RequiredPlaneBytes(std::uint32_t stride,
                                                std::uint32_t rows) {
  if (stride == 0U || rows == 0U || MultiplicationOverflows(stride, rows)) {
    return common::Result<std::size_t>::Err(
        PreprocessError("NV12 plane dimensions are invalid"));
  }
  return common::Result<std::size_t>::Ok(
      static_cast<std::size_t>(stride) * rows);
}

// Page-alignment bookkeeping for mmap()'ing a (possibly unaligned) dmabuf
// plane range. `mapping_offset` is the page-aligned mmap() offset,
// `data_offset` is how far the plane's actual first byte sits past that
// (i.e. the amount to add back to the mapped base to reach `plane.offset`),
// and `mapping_size` is the number of bytes to pass to mmap()/munmap().
struct PlaneMappingParams {
  std::size_t mapping_offset{0};
  std::size_t data_offset{0};
  std::size_t mapping_size{0};
};

common::Result<PlaneMappingParams> ComputePlaneMappingParams(
    const media::FramePlane& plane) {
  if (plane.dmabuf_fd < 0 || plane.length == 0U ||
      plane.offset > std::numeric_limits<std::size_t>::max() - plane.length) {
    return common::Result<PlaneMappingParams>::Err(
        PreprocessError("NV12 plane descriptor is invalid"));
  }

  const long page_size_long = ::sysconf(_SC_PAGESIZE);
  if (page_size_long <= 0) {
    return common::Result<PlaneMappingParams>::Err(
        PreprocessError("cannot determine system page size"));
  }
  const auto page_size = static_cast<std::size_t>(page_size_long);
  const std::size_t mapping_offset = plane.offset - (plane.offset % page_size);
  const std::size_t data_offset = plane.offset - mapping_offset;
  if (data_offset > std::numeric_limits<std::size_t>::max() - plane.length ||
      mapping_offset >
          static_cast<std::size_t>(std::numeric_limits<off_t>::max())) {
    return common::Result<PlaneMappingParams>::Err(
        PreprocessError("NV12 plane mapping range is invalid"));
  }
  return common::Result<PlaneMappingParams>::Ok(
      PlaneMappingParams{mapping_offset, data_offset, data_offset + plane.length});
}

common::Result<ModelInputGeometry> BuildModelInputGeometry(
    std::uint32_t source_width,
    std::uint32_t source_height,
    std::uint32_t target_width,
    std::uint32_t target_height,
    bool letterbox) {
  if (source_width == 0U || source_height == 0U || target_width == 0U ||
      target_height == 0U) {
    return common::Result<ModelInputGeometry>::Err(
        PreprocessError("NV12 source or model input dimensions are invalid"));
  }

  ModelInputGeometry geometry{target_width, target_height, 0U, 0U};
  if (!letterbox) {
    return common::Result<ModelInputGeometry>::Ok(geometry);
  }

  const double scale = std::min(
      static_cast<double>(target_width) / source_width,
      static_cast<double>(target_height) / source_height);
  geometry.scaled_width = std::min(
      target_width,
      std::max(1U, static_cast<std::uint32_t>(source_width * scale)));
  geometry.scaled_height = std::min(
      target_height,
      std::max(1U, static_cast<std::uint32_t>(source_height * scale)));
  geometry.x_offset = (target_width - geometry.scaled_width) / 2U;
  geometry.y_offset = (target_height - geometry.scaled_height) / 2U;
  return common::Result<ModelInputGeometry>::Ok(geometry);
}

}  // namespace

struct Nv12RgbPreprocessor::Impl {
  Impl(std::uint32_t width,
       std::uint32_t height,
       bool use_letterbox,
       std::uint8_t fill)
      : target_width(width),
        target_height(height),
        letterbox(use_letterbox),
        padding(fill) {}

  ~Impl() {
    sws_freeContext(sws);
    for (auto& entry : mapped_planes) {
      if (entry.address != nullptr && entry.address != MAP_FAILED) {
        (void)::munmap(entry.address, entry.mapping_size);
      }
    }
  }

  std::uint32_t target_width;
  std::uint32_t target_height;
  bool letterbox;
  std::uint8_t padding;
  SwsContext* sws{nullptr};

  // dmabuf plane mmap cache, keyed by (fd, mapping_offset, mapping_size) --
  // i.e. the exact mmap() call this plane would otherwise repeat every
  // frame. A single Nv12RgbPreprocessor is owned by one AiModelRunner worker
  // and Convert() is only ever called from that worker's single dedicated
  // thread (see AiModelRunner::Run()/ProcessFrame() in AiModelRunner.cpp),
  // so this cache needs no locking.
  //
  // Staleness defense: an (fd, mapping_offset, mapping_size) key match is
  // only a *candidate* hit. dmabuf fd numbers are recycled by the OS once
  // closed (e.g. after a camera buffer-pool rebuild), and a recycled fd can
  // legitimately land back at the same offset/size for a *different*,
  // unrelated underlying buffer -- a bare key match cannot tell the two
  // apart and would silently serve the old, dead mapping's pixel data. So
  // every candidate hit pays one fstat() to compare the fd's current
  // (st_dev, st_ino) against what was captured when the mapping was
  // inserted; on a mismatch (or if fstat() itself fails) the entry is
  // treated as stale, unmapped, and replaced by a fresh mmap(). This is the
  // sole defense against fd recycling and is why a "hit" still costs one
  // syscall (~2/frame for a Y+UV pair) rather than zero -- down from the
  // original ~8 (fcntl + fstat + mmap per plane, munmap x2).
  //
  // Note on eviction: production NV12 frames commonly map the Y and UV
  // planes onto the *same* dmabuf fd at different offsets/lengths (see
  // CameraPipeline.cpp BuildFrameHandle, single-plane-buffer path), so two
  // simultaneously-live entries sharing an fd is the *normal* case for a
  // Y/UV pair, not a sign of staleness -- staleness is only decided by the
  // fstat identity check above, never by fd alone. This cache is simply
  // bounded: it holds at most kMaxMappedPlanes entries (comfortably above
  // the <=8-buffer camera pool x 2 planes it needs to hold steady-state)
  // and evicts the oldest entry, FIFO, only when an insert would exceed
  // that cap -- which self-heals unbounded growth from fd recycling across
  // many restarts without ever touching an entry the current Convert() call
  // still needs (at most 2 entries are ever live within one call). Because
  // entries are unmapped only in ~Impl() or on eviction, up to
  // kMaxMappedPlanes dmabuf-backed (CMA) mappings stay pinned for the
  // lifetime of this object -- acceptable given the camera buffer pool
  // itself is bounded to the same order of magnitude.
  struct MappedPlane {
    int fd{-1};
    std::size_t mapping_offset{0};
    std::size_t mapping_size{0};
    void* address{nullptr};
    dev_t backing_dev{};
    ino_t backing_ino{};
  };
  static constexpr std::size_t kMaxMappedPlanes = 16;
  std::vector<MappedPlane> mapped_planes;

  void UnmapEntry(const MappedPlane& entry) {
    if (entry.address != nullptr && entry.address != MAP_FAILED) {
      (void)::munmap(entry.address, entry.mapping_size);
    }
  }

  common::Result<const std::uint8_t*> MapPlaneCached(
      const media::FramePlane& plane) {
    const auto params = ComputePlaneMappingParams(plane);
    if (!params.ok()) {
      return common::Result<const std::uint8_t*>::Err(params.error());
    }
    const auto& mapping_params = params.value();

    for (auto it = mapped_planes.begin(); it != mapped_planes.end(); ++it) {
      if (it->fd != plane.dmabuf_fd ||
          it->mapping_offset != mapping_params.mapping_offset ||
          it->mapping_size != mapping_params.mapping_size) {
        continue;
      }
      struct stat backing {};
      if (::fstat(plane.dmabuf_fd, &backing) == 0 &&
          backing.st_dev == it->backing_dev && backing.st_ino == it->backing_ino) {
        return common::Result<const std::uint8_t*>::Ok(
            static_cast<const std::uint8_t*>(it->address) +
            mapping_params.data_offset);
      }
      // Key matched but the fd's identity didn't (fd recycled to a
      // different underlying buffer) or fstat() failed outright -- this
      // entry is stale. Drop it and fall through to remap fresh below.
      UnmapEntry(*it);
      mapped_planes.erase(it);
      break;
    }

    if (::fcntl(plane.dmabuf_fd, F_GETFD) == -1) {
      return common::Result<const std::uint8_t*>::Err(
          PreprocessError("NV12 plane descriptor cannot be used"));
    }
    struct stat backing {};
    const bool have_backing_stat = ::fstat(plane.dmabuf_fd, &backing) == 0;
    if (have_backing_stat && S_ISREG(backing.st_mode) &&
        static_cast<std::uintmax_t>(plane.offset) + plane.length >
            static_cast<std::uintmax_t>(backing.st_size)) {
      return common::Result<const std::uint8_t*>::Err(
          PreprocessError("NV12 plane range exceeds its backing file"));
    }

    void* mapping = ::mmap(nullptr,
                           mapping_params.mapping_size,
                           PROT_READ,
                           MAP_SHARED,
                           plane.dmabuf_fd,
                           static_cast<off_t>(mapping_params.mapping_offset));
    if (mapping == MAP_FAILED) {
      return common::Result<const std::uint8_t*>::Err(
          PreprocessError("failed to map NV12 plane"));
    }

    if (have_backing_stat) {
      // Only cache entries we can later re-validate by identity; without a
      // successful fstat() here there is nothing safe to compare against on
      // a future lookup, so this mapping is used for this call only.
      if (mapped_planes.size() >= kMaxMappedPlanes) {
        UnmapEntry(mapped_planes.front());
        mapped_planes.erase(mapped_planes.begin());
      }
      MappedPlane entry;
      entry.fd = plane.dmabuf_fd;
      entry.mapping_offset = mapping_params.mapping_offset;
      entry.mapping_size = mapping_params.mapping_size;
      entry.address = mapping;
      entry.backing_dev = backing.st_dev;
      entry.backing_ino = backing.st_ino;
      mapped_planes.push_back(entry);
    }
    return common::Result<const std::uint8_t*>::Ok(
        static_cast<const std::uint8_t*>(mapping) + mapping_params.data_offset);
  }
};

Nv12RgbPreprocessor::Nv12RgbPreprocessor(std::uint32_t target_width,
                                         std::uint32_t target_height,
                                         bool letterbox,
                                         std::uint8_t padding)
    : impl_(std::make_unique<Impl>(target_width,
                                   target_height,
                                   letterbox,
                                   padding)) {}

Nv12RgbPreprocessor::~Nv12RgbPreprocessor() = default;

common::Result<std::vector<std::uint8_t>> Nv12RgbPreprocessor::Convert(
    const media::FrameLease& frame) {
  if (!frame.valid()) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("AI frame lease is invalid"));
  }

  const auto& source = frame.handle();
  if (source.format != "NV12" || source.width == 0U || source.height == 0U ||
      source.plane_count < 2U || (source.width % 2U) != 0U ||
      (source.height % 2U) != 0U) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("AI processor expected an even-dimension NV12 frame"));
  }
  if (source.planes[0].stride < source.width ||
      source.planes[1].stride < source.width) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("NV12 plane stride is smaller than the source width"));
  }

  const auto y_required = RequiredPlaneBytes(source.planes[0].stride,
                                             source.height);
  const auto uv_required = RequiredPlaneBytes(source.planes[1].stride,
                                              source.height / 2U);
  if (!y_required.ok() || !uv_required.ok() ||
      source.planes[0].length < y_required.value() ||
      source.planes[1].length < uv_required.value()) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("AI processor received inconsistent NV12 planes"));
  }

  const auto geometry = BuildModelInputGeometry(source.width,
                                                source.height,
                                                impl_->target_width,
                                                impl_->target_height,
                                                impl_->letterbox);
  const auto target_bytes = Rgb8ByteCount(impl_->target_width,
                                          impl_->target_height);
  if (!geometry.ok()) {
    return common::Result<std::vector<std::uint8_t>>::Err(geometry.error());
  }
  if (!target_bytes.ok()) {
    return common::Result<std::vector<std::uint8_t>>::Err(target_bytes.error());
  }
  if (source.width > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      source.height > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      source.planes[0].stride >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      source.planes[1].stride >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      geometry.value().scaled_width >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      geometry.value().scaled_height >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      impl_->target_width >
          static_cast<std::uint32_t>(std::numeric_limits<int>::max() / 3)) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("NV12 dimensions exceed libswscale limits"));
  }

  auto mapped_y = impl_->MapPlaneCached(source.planes[0]);
  if (!mapped_y.ok()) {
    return common::Result<std::vector<std::uint8_t>>::Err(mapped_y.error());
  }
  auto mapped_uv = impl_->MapPlaneCached(source.planes[1]);
  if (!mapped_uv.ok()) {
    return common::Result<std::vector<std::uint8_t>>::Err(mapped_uv.error());
  }

  impl_->sws = sws_getCachedContext(
      impl_->sws,
      static_cast<int>(source.width),
      static_cast<int>(source.height),
      AV_PIX_FMT_NV12,
      static_cast<int>(geometry.value().scaled_width),
      static_cast<int>(geometry.value().scaled_height),
      AV_PIX_FMT_RGB24,
      SWS_BILINEAR,
      nullptr,
      nullptr,
      nullptr);
  if (impl_->sws == nullptr) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("failed to create NV12 conversion context"));
  }

  // A per-call scratch buffer (rather than a persistent, reused one) was
  // tried and measured net *slower* on-device: the reuse still had to copy
  // the whole canvas out to satisfy Convert()'s move-out contract (see
  // AiModelProcessor.cpp -- the caller keeps the buffer alive through async
  // inference submission, so the scratch can't be moved out and reused
  // directly), and that copy cost more than the memset it was meant to
  // avoid. Reverted to the plain per-call allocation; only the dmabuf mmap
  // cache above is kept, which measured a real win on its own.
  std::vector<std::uint8_t> rgb;
  try {
    rgb.assign(target_bytes.value(), impl_->padding);
  } catch (const std::bad_alloc&) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("failed to allocate AI model input buffer"));
  } catch (const std::length_error&) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("AI model input buffer size is invalid"));
  }
  const std::uint8_t* source_planes[2] = {mapped_y.value(), mapped_uv.value()};
  int source_strides[2] = {static_cast<int>(source.planes[0].stride),
                           static_cast<int>(source.planes[1].stride)};
  std::uint8_t* target_planes[1] = {
      rgb.data() + ((static_cast<std::size_t>(geometry.value().y_offset) *
                         impl_->target_width +
                     geometry.value().x_offset) *
                    kRgbChannels)};
  int target_strides[1] = {static_cast<int>(impl_->target_width * kRgbChannels)};

  const int scaled_rows = sws_scale(impl_->sws,
                                    source_planes,
                                    source_strides,
                                    0,
                                    static_cast<int>(source.height),
                                    target_planes,
                                    target_strides);
  if (scaled_rows != static_cast<int>(geometry.value().scaled_height)) {
    return common::Result<std::vector<std::uint8_t>>::Err(
        PreprocessError("failed to scale NV12 frame to model input"));
  }
  return common::Result<std::vector<std::uint8_t>>::Ok(std::move(rgb));
}

}  // namespace camera_firmware::ai
