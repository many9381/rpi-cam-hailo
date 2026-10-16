# FFmpeg remaining-candidate follow-up — 2026-10-12

This record follows the five unresolved FFmpeg candidates in
[the previous platform remediation](platform-security-remediation-2026-10-12.md).
The user approved security follow-up and excluded long-duration operation tests.
The Raspberry Pi FFmpeg integration remains on 7.1.5 with its existing shared
library SONAMEs and hardware/media support.

## Layer changes

Four patches are added to
`meta-rpi5-cam/recipes-multimedia/rpidistro-ffmpeg/rpidistro-ffmpeg_7.1.13.bbappend`.
All four affected components are enabled in this image.

| Candidate | Change and upstream evidence |
| --- | --- |
| CVE-2026-107696 | Limit RTSP redirects to eight, preserving stream and connection cleanup. [Upstream fix](https://github.com/FFmpeg/FFmpeg/commit/f5d4fd186c68913240c4f6e9cda98443e1518b34). |
| CVE-2026-58049 | Check row boundaries before each of four 32-bit RASC DLTA access sites. [Upstream fix](https://github.com/FFmpeg/FFmpeg/commit/11ff18a6c80187405fc492f9bb07ba9f2f663f76). |
| CVE-2026-65705 | Size the floodfill allocation for the current frame. Includes the [prerequisite change](https://github.com/FFmpeg/FFmpeg/commit/24c322fdb232d0a3f3790d544dcb64e5c2138e79) and [fix](https://github.com/FFmpeg/FFmpeg/commit/f186c50cf53aec20e9a29059cb22ca3f2d59201c). |
| CVE-2026-66036 | Reconfigure hqdn3d buffers when dimensions change, retain parameter validation and correct frame ownership on errors. Includes the [prerequisite](https://github.com/FFmpeg/FFmpeg/commit/f0f634b6585fdc7bbb43ab3ae461499bfca9ad2e) and [fix](https://github.com/FFmpeg/FFmpeg/commit/5d7112c60e6f0f0742ce47d448e6da0718a70f4c), adapted to the 7.1 filter API. |

The hqdn3d backport changes its implementation/header and the narrow existing
filter-reconfiguration assertion; it does not import the newer FFFilter API.
Patch application and reverse checks pass without fuzz. Independent review
found no unresolved critical or important issue in these four backports.

## Regression evidence and limits

The bounded fixtures extract the actual changed source functions or blocks and
compile them with AddressSanitizer and UndefinedBehaviorSanitizer. Before the
patches all four fixtures fail; afterwards all four pass. They cover:

- Floodfill frame growth, shrinkage, repeated dimensions and oversized coordinates.
- hqdn3d growth/shrinkage, direct/copied frame paths, disabled operation and
  rejection of an incompatible format.
- All four RASC 32-bit access sites, short PAL8/RGB555 rows, BGR0 and exact-fit controls.
- RTSP redirect counts zero, one and eight, rejection of the ninth redirect,
  and the corresponding cleanup behavior.

These fixtures use simplified graph delivery and sequential worker execution.
They do not establish full filter-graph, allocation-failure, concurrency or
FFmpeg FATE coverage. Separate ordinary target-media and final-image checks
passed for image `20261012T080118Z-e664cb9647e7`. Actual BitBake sources contain
all four patches; the FFmpeg CLI and libraries tested on Pi match the WIC.
H.264/MP4 and JPEG encode/decode passed. Floodfill (PGM/gray) and hqdn3d (MJPEG)
each processed four alternating 32×24/64×48 frames with filter reinitialization
disabled and two filter workers; before/after dimensions were checked.
Temporary files were removed and the production service stayed running.
See the [integrated record](security-followup-2026-10-12.md) for checks and
limits. Subsequent [deployment validation](security-deployment-validation-2026-10-12.md)
also passed these ordinary media checks using the installed system binaries.

Private evidence is in `.state/security-followup-2026-10-12/ffmpeg/`, including
the exact upstream downloads, patch hashes, application checks, `regression.py`,
red/green results, assessment and independent review. The final integrated
archive contains a curated copy; credentials, copied executables and complete
source trees are excluded.

## Remaining MOV candidate

**CVE-2026-107678 remains open.** The installed MOV demuxer is enabled and its
encryption-initialization list handling remains relevant. As reviewed on
2026-10-12, [upstream proposal 24593](https://code.ffmpeg.org/FFmpeg/FFmpeg/pulls/24593)
is unmerged and changes public append APIs and MOV side-data ownership. It is
not a self-contained backport to this integration. The fact that the camera
application usually produces media does not make the installed CLI and library
unaffected. Track upstream resolution and repeat source/regression review before
closing this candidate.
