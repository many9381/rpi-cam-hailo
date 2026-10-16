# MOV fragment growth follow-up and firmware impact — 2026-10-15

Status: **additional implementation deferred; excluded from current required
firmware work by user agreement on 2026-10-15**. The growth-request issue is
reproduced; no additional production correction is applied.
CVE-2026-107678 remains **partially mitigated/open**. The accepted image
`20261015T185424Z-e664cb9647e7`, layer and operating Pi are unchanged.

## Agreed disposition

- Retain the verified cleanup and incremental-append patches, including safe
  invalidation at MOV parsing boundaries.
- Do not implement the proposed common libavutil allocator redesign for the
  current camera workflow. This is not a pending approval request or a required
  item for the next image.
- Keep the residual security record and reproduction evidence. Exclusion from
  required product work does not mean that the advisory is fixed or that every
  use of the installed FFmpeg tools is unaffected.
- Reassess when external MOV/MP4 upload, playback, conversion or thumbnail
  processing is added, when operational ffmpeg/ffprobe use accepts untrusted
  files, or when new evidence identifies a reachable input path. A compatible
  upstream fix can be reviewed separately without committing to this redesign.

The earlier priority recommendation came from the residual advisory list before
checking the application's actual input paths. That was a prioritization error.
Future required-work recommendations must consider reachable inputs, product
impact and the risk of the proposed change, rather than residual status alone.

## Investigation context

This follows the [continuous-append correction](ffmpeg-mov-append-2026-10-15.md).
The official PR was fetched again on October 15: it remains open/unmerged at
`df40e69194187f8ab0db3558bf2a154d32fd0040`. Its public discussion also identifies
the allocation-lifetime problem. Primary records:
[FFmpeg PR 24593](https://code.ffmpeg.org/FFmpeg/FFmpeg/pulls/24593) and
[CVE CNA record](https://cveawg.mitre.org/api/cve/CVE-2026-107678).

## Reproduction

New reusable fixture generator:
`tests/integration/make_ffmpeg_fragment_fixtures.py` in the parent repository.
It takes the ordinary PCM `base.mov` from `make_ffmpeg_mov_fixtures.py` and
produces monotonic fragments containing one PSSH record and one packet each.
The existing real-demuxer test verifies all packets and exact expected PSSH
bytes, with optional `TRACE_PSSH_GROWTH` instrumentation separating appender
allocation requests from other demuxer work.

| Fragments | PSSH growth requests | Requested PSSH bytes | Relocated logical prefix bytes on this host |
|---:|---:|---:|---:|
| 1,024 | 1,024 | 19,411,461 | 280,109 |
| 2,048 | 2,048 | 77,620,230 | 526,069 |
| 4,096 | 4,096 | 310,429,696 | 950,385 |

The first two small cases pass; all three large cases fail the existing bounded
growth gate while retaining their media and PSSH bytes. Eight previous normal,
copy-back, discovery, insertion-failure and continuous-growth controls pass.
The reusable generator reproduces the measured fixture hashes exactly.

These figures demonstrate quadratic growth-request volume, **not quadratic
actual copying or target CPU exhaustion**. The tested host allocator often
extends the buffer in place. A moving-allocation regression remains necessary
before claiming a bound on worst-case copying. No target exploit was run.

## Current firmware exposure

The current rootfs executable hash matches accepted WIC evidence. Its direct
dependencies include libswscale and exclude libavformat; libswscale depends
on libavutil. Product sources contain no calls to `avformat_open_input`,
`avformat_find_stream_info` or `av_read_frame`. The app produces camera video
and feeds GStreamer output pipelines rather than accepting external MOV files.
No direct trigger for this MOV-reader issue was identified in those application
paths. Installed ffmpeg and ffprobe do link libavformat, so image-level
exposure when such tools process external files remains separately relevant.
This is not a blanket exclusion for dynamic plugins or future features.

Video downscaling (`Nv12Downscaler`) and CPU AI preprocessing
(`Nv12RgbPreprocessor`) use libswscale/libavutil. A common libavutil allocator
redesign therefore has a broader performance and failure impact than the MOV
reader. It offers no expected frame-rate or image-quality improvement for
ordinary current camera/Hailo operation.

## Design boundary and deferred implementation

Independent read-only review found that MOV-private capacity or pointer equality
cannot detect all public replacement/free operations or same-address reuse.
Removing root invalidation would risk writes beyond a smaller replacement.
Copying a private accumulator into public side data every packet retains the
cumulative-copy problem. Extra public padding changes the serialized bytes.

A possible compatible route is opt-in lifetime tracking in libavutil's common
allocator, with invalidation on free/realloc and reserved metadata before
fallible ownership changes. That is a broader design, not an approved local
MOV optimization. It requires failure, concurrency, same-address reuse,
sanitizer, overhead, ABI and independent-review gates before layer integration.
The current root invalidation is retained.

The deferred proposal is in the parent repository's
`docs/superpowers/specs/2026-10-15-ffmpeg-mov-fragment-lifetime-design.md`.
After reviewing the firmware impact, the user agreed to retain the accepted
patches, track the residual issue and exclude additional implementation from
current required work. The allocator redesign is not approved for implementation.

Review additionally identified a possible discovery-time PSSH overwrite and
repeated codec-context-copy costs. Those are source findings requiring dedicated
reproductions; they are not presented as newly fixed or target-reproduced bugs.
No ledger disposition changes, image build, SSD write, reboot, QEMU or prolonged
device test was performed. Working evidence and fetched primary-source hashes:
`.state/ffmpeg-mov-fragments-2026-10-15/`.
