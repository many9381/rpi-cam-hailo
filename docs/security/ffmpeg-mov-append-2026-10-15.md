# FFmpeg MOV PSSH append follow-up — 2026-10-15

The repeated reconstruction of previously collected MOV encryption-init records
is replaced with incremental serialization. The change is integrated in Hailo image
**`20261015T121728Z-e664cb9647e7`**, with build and exact-image verification **PASS**.
Hardware acceptance was **NOT_RUN** at build completion. The subsequent
[device validation found a camera capture failure](camera-capture-failure-2026-10-15.md);
subsequent [recovery validation](ffmpeg-mov-deployment-validation-2026-10-15.md)
passed capture-progress checks, three new reboots and user-confirmed video/Hailo.
Current hardware acceptance is **PASS after recovery**.
This follows the already deployed
[iterative cleanup corrections](security-residual-followup-2026-10-15.md).

## Change and provenance

`meta-rpi5-cam/recipes-multimedia/rpidistro-ffmpeg/files/0005-encryption-init-append-serialized-records.patch`
is included by `rpidistro-ffmpeg_7.1.13.bbappend`, whose actual pinned version
remains FFmpeg **7.1.5**, source `2fe08f3bd52c6e795df8353d29deb89596b5099d`.

The patch backports the proposed
[libavutil appender](https://code.ffmpeg.org/FFmpeg/FFmpeg/commit/abbd3cd2866dd5cc3491d99b19aa79f9287daf72)
and [MOV integration](https://code.ffmpeg.org/FFmpeg/FFmpeg/commit/df40e69194187f8ab0db3558bf2a154d32fd0040).
The [official pull request](https://code.ffmpeg.org/FFmpeg/FFmpeg/pulls/24593)
was open and unmerged when fetched on October 15. Retrieved responses and
hashes are retained; this is a downstream backport of a proposal, not an
upstream released fix.

Each append writes only the new records into a geometrically grown buffer.
Serialization stays in libavutil. Existing record bytes/order, stream
association, ownership and cleanup are preserved. A failed first side-data
insertion now returns ENOMEM instead of silently succeeding. Before a later
root parsing pass, the cached allocation identity is invalidated: stream
discovery can replace side data with an exact-sized copy, including a copy at
the same address. Reusing its previous spare capacity would be unsafe.

The existing iterative destructor and missing-key-array guard remain intact.
The backport adds `av_encryption_init_info_append_side_data`; it changes no
existing public function signature or public structure layout. The distro
retains the existing library version and SONAME rather than advertising the
upstream proposal's 61.x version. Allocation/ownership documentation and a
comment explaining root invalidation are the local adaptations.

## Regression evidence

Tests use native builds of the actual patched production source, including the
real MOV demuxer, codec-parameter copying and allocation routines. Synthetic
MOV files contain a short generated PCM tone; a separate Python encoder builds
the expected encryption-info bytes independently of FFmpeg's serializer.

| Continuous records | Before: allocation calls | After: allocation calls | After: requested growth bytes |
|---:|---:|---:|---:|
| 2,048 | 9,444,738 | 11,308 | 1,458,335 |
| 4,096 | Not run | 22,571 | 2,910,190 |
| 32,768 | Not run | 180,268 | 24,929,122 |

These are intercepted production allocation calls and growth-request sizes,
not a measurement of physical bytes copied by the allocator. The real demuxer
fails the bounded work check before the patch and passes after it. Growth
requests are measured at `av_fast_realloc`, because wrapping `av_realloc`
alone misses calls within the same allocator translation unit.

**54 native checks pass:** ten MOV cases in both plain and ASan/UBSan/LSan
builds, sixteen cleanup/appender cases in both builds, and the upstream
`fate-encryption-info` test in both builds. Coverage includes:

- Zero, one, small and large record sets; version 0 and version 1 records,
  zero/multiple key IDs, empty payloads, exact byte/order checks and two streams.
- Actual `avformat_find_stream_info`, followed by codec-parameter copies and
  later fragment reads: 17 records after discovery, 26 at final EOF, with
  all expected records and four media packets retained.
- Side-data insertion failure injected at the insertion API: baseline loses
  the error; patched code reports ENOMEM and releases the failed-open context.
- Real configured-allocation-limit failure, preserved pointer/size/data,
  successful retry, writable copies with unknown capacity, empty lists,
  arithmetic rejection before writing, and 20,000 continuous API appends.
- The previous long-list cleanup and NULL key-array regression fixtures.

The existing host suite passes **365 tests**. Its first sandboxed run stalled
at a local-listener test; the task-owned process tree was stopped and the full
suite passed with local binding available. These tests use process doubles;
no QEMU image was built and no QEMU VM was started. Sanitizer configure also
encountered the sandbox's ptrace/LeakSanitizer limitation; final sanitizer
tests ran with leak detection enabled outside that restriction.

Independent source review found no introduced production defect and replayed
the layer patch with zero fuzz to the exact candidate hashes. Forced
same-address allocation reuse is source-reviewed, not dynamically forced.
The API failure test uses `av_max_alloc`, not an allocator-returned failure.
This is not full FATE, arbitrary invalid caller-list testing, or target runtime
acceptance. The public zero-length/NULL-copy edge cases predating this change
are not claimed fixed.

Reusable fixtures are `tests/integration/ffmpeg-mov-pssh.c`,
`ffmpeg-encryption-append.c` and `make_ffmpeg_mov_fixtures.py` in the same
directory. The generator takes an output directory and uses host FFmpeg only
to create the ordinary PCM MOV containers. The test runner and exact compile
commands are retained with the evidence.

## Remaining scope and security classification

The improvement is amortized linear work for continuous appends retaining
capacity. Safety requires invalidating that capacity across parsing passes;
many separately parsed fragments can still cause repeated buffer growth or
copying. This change therefore does **not** establish a universal linear bound
for every fragmented MOV layout. Removing that remaining cost needs a separate
ownership/lifetime design and compatible public side-data publication.

CVE-2026-107678 remains **partially mitigated/open**. No complete-fix CVE
metadata, filename-based closure or broad exclusion is added. The other 545
associations in the 546-entry source ledger are outside this change. The
existing count remains **200 fixed, 331 not affected, 11 open, three partial,
one unassessed**; no new complete advisory closure is claimed.

## Image and evidence

Build profile: `rpi5-camera-hailo`; build **`20261015T121728Z-e664cb9647e7`**. All 7,884 BitBake
tasks succeeded. WIC SHA-256:
`bc72d65e53f7fdeabb3de4f063d239b0f24541cfe30af95354737e43e57a32ab`.
SPDX SHA-256:
`30e2369785e0b7fc5acc85748678392c5aaea6f2b780e783e436e856e1e60952`.

- Actual final source matches the four reviewed files. Reversing/reapplying the
  patch with zero fuzz reproduces the exact before/after hashes.
- All 187 shared-library paths and SONAMEs match the baseline. All prior
  exports remain, with exactly one reviewed addition in libavutil. No other
  library's export set changes. This checks exported interfaces, not every
  possible C ABI or runtime behavior.
- The actual WIC matches 378 protected file hashes, all 27 kernel modules,
  four boot files and 16 privileged ownership/mode records. Camera and Wi-Fi
  rootfs, provenance and camera public-identity checks pass. All 460 package
  names/versions are unchanged. Any rpicam-app generated timestamp/build-ID/
  debug-CRC difference is checked separately from code and unrelated data.
- Packaged libavutil and libavformat match the rootfs and actual WIC. Known
  pristine-image authentication/configuration/private-key paths remain absent;
  no authentication file was read or archived by this verification.
- The same October 14 offline database yields the same 24,395 installed
  scanner rows: 23,965 fixed, 400 affected and 30 not affected. The raw FFmpeg
  advisory remains affected. This comparison is not a fresh whole-database
  update or clearance of bundled/vendor dependencies.
- The reconciled ledger preserves all 545 other association rows and the
  separate BusyBox cp exclusion. No complete advisory is newly closed.
- Read-only installer selection chooses this completed image by default. It
  does not discover, mount or write an SSD.

Curated evidence:
`artifacts/20261015T121728Z-e664cb9647e7/rpi5-camera-hailo/security/ffmpeg-mov-append-2026-10-15/`.
The archive contains public sources, fixtures, hashes, test/build/image/scan
records and this report, with verified checksums. Credentials, private keys,
whole databases and native build trees are excluded; scripts may require the
retained workspace toolchain.

Working evidence: `.state/ffmpeg-mov-append-2026-10-15/`.
The initial image verifier used `libavformat.so.61.7.100`; both the frozen
baseline and actual package identify `61.7.103`. That exact filename was
corrected, with the first failure and verifier retained. No product or expected
interface/hash check was changed to accommodate the error.
No SSD write, device configuration change or Pi reboot is part of this work.
The prior successful hardware acceptance belongs to
[image 20261015T110905Z-e664cb9647e7](security-residual-deployment-validation-2026-10-15.md).
