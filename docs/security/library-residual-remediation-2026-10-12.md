# Remaining library remediation — 2026-10-12

The selected library follow-up adds source corrections for **24 candidate
associations**, two configuration exclusions, and further Avahi/libevent
mitigations. **Fourteen candidates remain open and two remain partial.**
These are package/advisory associations, not confirmed exploit counts.

Built image: `20261012T140609Z-e664cb9647e7` (`rpi5-camera-hailo`). Previous deployed image:
`20261012T080118Z-e664cb9647e7`. The new image has **not been installed**;
its complete boot, camera and Hailo acceptance is still pending. No QEMU or
minimal image, long-duration run or SSD write was performed.

## Applied layer changes

| Library | Newly corrected associations | CVEs |
|---|---:|---|
| alsa-lib | 2 | CVE-2026-56109, CVE-2026-90781 |
| glib-2.0 | 5 | CVE-2026-58011, CVE-2026-58012, CVE-2026-58013, CVE-2026-58014, CVE-2026-58015 |
| glibc | 10 | CVE-2026-18374, CVE-2026-19499, CVE-2026-19542, CVE-2026-5435, CVE-2026-5450, CVE-2026-5928, CVE-2026-6238, CVE-2026-6791, CVE-2026-86805, CVE-2026-95818 |
| gnutls | 2 | CVE-2026-3832, CVE-2026-3833 |
| libpng | 1 | CVE-2026-34757 |
| libx11 | 4 | CVE-2026-88806, CVE-2026-94283, CVE-2026-94284, CVE-2026-94285 |

The exact ordered patches and hashes are in `frozen-layer-inputs.json` and
`source-verification.json`. Fifteen official glibc stable patches include
required DNS and loader prerequisites; the public ABI is preserved at the
source level. GLib changes are backported from official 2.88.1 files with
required internal authentication companions. GnuTLS takes the selected OCSP
response index and ASCII-case-insensitive DNS/domain comparison corrections.
ALSA, PNG and X11 use official maintenance changes, including PNG's ownership
follow-up and all three XIM/locale changes.

Avahi now disables listener polling for one second after descriptor/resource
exhaustion or a full client pool. A non-renewing five-second deadline reclaims
connections that have not supplied a complete initial command. Existing valid
long-lived browser clients remain supported; such clients can still hold all
50 slots. This is additional mitigation, **not complete remediation** of
CVE-2025-59529. [Upstream advisory](https://github.com/avahi/avahi/security/advisories/GHSA-73wf-3xmj-x82q).

Libevent rejects percent-encoded NUL in an HTTP request target before routing
and rejects embedded decoded NUL in query string helpers, clearing partial
results. The documented binary percent-decoding API remains unchanged.
Applications that treat its output as a C-string path still need their own
length-aware validation; CVE-2026-63385 remains **partial**.
[Upstream advisory](https://github.com/libevent/libevent/security/advisories/GHSA-jcwh-pvf2-73p2).

The actual AArch64 BFD build excludes XCOFF/rs6000 target vectors and symbols.
The final WIC libbfd bytes were checked. This excludes CVE-2026-3441 and
CVE-2026-3442 for this configuration; it does not exclude the independent ELF
`readelf` candidates.

## Verification and its limits

- Host project suite: **365 tests passed**.
- Avahi: actual simple-protocol code and source event loop, real Unix sockets,
  bounded injected descriptor errors, full pool/recovery, initial deadline,
  ordinary HELP and shutdown controls passed with ASan/UBSan. Accept attempts
  fell from more than 120,000 to one per 120 ms in the injected-error check.
  Valid browser-state preservation was simulated; actual mDNS browser behavior
  and every allocation-failure branch were not covered.
- Libevent: nine HTTP cases, query-string and binary-decoder controls passed;
  five selected upstream URI/query tests passed. This is not the full HTTP suite.
- glibc: normal tree and path controls passed with ASan/UBSan. Ordinary fopen,
  UTF-8, scanf, monetary formatting, wide streams, wordexp and tree operations
  passed on the Pi with both the deployed libc and the new WIC-matched libc and
  loader in an unprivileged temporary directory. Files were removed; the
  production boot, camera PID and restart count stayed unchanged. No privileged
  loader attack test or full glibc suite was run.
- ALSA: four valid configuration cases and 43 valid control identifiers passed.
  PNG: six upstream metadata get/set roundtrips passed with ASan; the ownership
  failure observed before the patch was absent after it.
- GLib: three ordinary API checks passed; datetime/authentication source and
  compile checks have narrower behavioral coverage. GnuTLS DNS comparison
  controls passed; complete certificate-chain and OCSP runtime validation was
  not performed. X11 changed translation units compiled; no X server/XIM
  protocol acceptance is claimed.
- The integrated Hailo build passed. 34 local patches across eight
  changed recipes reversed/reapplied on copies of actual BitBake sources with
  zero fuzz and identical final file hashes (including existing patches).
- **182 shared-library SONAME/export comparisons** passed; 13 library
  files changed. This checks symbol compatibility, not full ABI or runtime
  equivalence. The actual WIC supplied 34 selected files matching rootfs
  hashes, kernel/modules and camera/RTSP source checks, SSH/service policy,
  camera auto-detection and two valid IPA signatures. Altered IPA signatures
  were rejected. Absence of Codex authentication files, the provisioned app
  configuration and device TLS key was checked directly in the WIC too.

The first integrated attempt stopped on a missing GLib internal authentication
prerequisite. That failure is retained in `build-attempt-1/`; companion changes
were added before the successful build. Some automated component investigations
were interrupted, so this record deliberately limits security validation to
source review and the checks actually recorded. No dynamic coverage is inferred
from successful compilation or a CVE tag.

## Remaining candidates

The libxml2 candidate was **not retained**: the official callback-context patch
passed basic checks but changed a valid bounded XSD entity value `42` into
`4242`. A compatible fix is required. Existing XML/Expat fixes remain present.

| Library | CVE | Status | Evidence / reason |
|---|---|---|---|
| acl | CVE-2026-54369 | open | Both CNA-listed commits reviewed:3589787c only version bump;24a227d0 only CVE records. Upstream history adds new _at APIs/flags, directory descriptor walking and openat2, requiring callers to opt in. Legacy pathname API semantics cannot be safely changed globally here; source remains open. No privilege traversal test performed. [Primary source](https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/?id=3589787cd589b34bdd9265936e17190b6d3f17d1). |
| alsa-lib | CVE-2026-96675 | open | PR527 patch4 reviewed. It validates indices only after allocating multi/slaves/channels and returns directly without cleanup; adopting it verbatim leaks allocations. It is not the narrow supported maintenance fix accepted here. Source assertions and potential sparse binding indices remain; dynamic security validation deferred. [Primary source](https://github.com/alsa-project/alsa-lib/pull/527). |
| avahi | CVE-2025-59529 | partially_mitigated_open | Added one-second accept backoff for EMFILE/ENFILE/ENOBUFS/ENOMEM and full pool, plus non-renewing five-second initial-request deadline. Real Unix sockets and full production simple-protocol/source simple-watch event loop pass recovery/idle/normalHELP/capacity/shutdown checks under ASan/UBSan. Active valid long-lived browsers may still monopolize all50slots; no total availability guarantee. [Primary source](https://github.com/avahi/avahi/security/advisories/GHSA-73wf-3xmj-x82q). |
| binutils | CVE-2026-6844 | open | Installed ELF readelf path remains enabled. Primary description groups resource exhaustion and NULL dereference; no exact correcting commit or function established. No unrelated XCOFF change is used as evidence; remains open. [Primary source](https://access.redhat.com/security/cve/CVE-2026-6844). |
| binutils | CVE-2026-6845 | open | Installed ELF readelf path remains enabled. Distinct RedHat2460012 reference has no resolved precise fix in this review; cannot infer remediation from6844/6846. Remains open. [Primary source](https://access.redhat.com/security/cve/CVE-2026-6845). |
| busybox | CVE-2026-38752 | open | Primary092351 is an AWK function recursion depth proposal. No supported adoption or introduction ancestry established; installed CONFIG_AWK path stays open. No new attack input generated or executed. [Primary source](https://lists.busybox.net/pipermail/busybox/2026-June/092351.html). |
| busybox | CVE-2026-38753 | open | Primary092352 snapshots substitution replacement before as_regex and frees the snapshot at return; ownership rationale reviewed. Exact pinned ancestry, supported upstream acceptance and ordinary unit verification remain prerequisites; not adopted. [Primary source](https://lists.busybox.net/pipermail/busybox/2026-June/092352.html). |
| busybox | CVE-2026-38754 | open | Primary092360 v3 supersedes earlier bounds patch with dash-style ifsfree cleanup at expansion-error handlers. Directly adopting v1 would miss the stated root cause. Source ancestry and ordinary shell regression verification remain open; not adopted. [Primary source](https://lists.busybox.net/pipermail/busybox/2026-June/092360.html). |
| busybox | CVE-2026-38755 | open | Primary092354 describes evalfun recursion depth/stack exhaustion, whereas CNA/baseline alleges evalcommand heap overflow. This discrepancy prevents exact finding/fix linkage. No recursion proposal is falsely counted as heap-overflow remediation. [Primary source](https://lists.busybox.net/pipermail/busybox/2026-June/092354.html). |
| expat | CVE-2025-66382 | open | Primary upstream issues1076 and1160 remain open; no supported complete fix or public reproducer from1076. Existing2.8.5+2backports retained; unrelated limits cannot be claimed to fix an undisclosed condition. [Primary source](https://github.com/libexpat/libexpat/issues/1076). |
| glibc | CVE-2010-4756 | open | glibc glob recursive/path enumeration code is present. The primary report needs an application passing attacker-controlled glob expressions, historically an FTP STAT command; an FTP listener has not been established in this image. [Primary source](http://securityreason.com/achievement_securityalert/89). |
| glibc | CVE-2011-0536 | open | Old advisory concerns modified downstream loader behavior. The baseline WIC has sixteen privileged executables; no complete source-equivalence or dependency-path exclusion established for this old candidate. The distinct 2026 loader backports are verified in the new built image, which does not by itself resolve this older association. [Primary source](http://www.securityfocus.com/archive/1/520102/100/0/threaded). |
| glibc | CVE-2025-0577 | open | Installed libc exports randomness APIs. Candidate requires fork concurrent with random calls and inherited/reused state; ordinary getrandom use alone is insufficient to assess this race. [Primary source](https://access.redhat.com/security/cve/CVE-2025-0577). |
| gnutls | CVE-2026-33845 | open | Exact3.8.13 buffers.c replaces end_offset arithmetic with frag_length throughout parse/reassembly and requires related gnutls_int.h changes. Baseline3.8.12 has companion earlier reassembly patches but not this complete zero-length correction. Not applied; ordinary upstream DTLS tests pending. [Primary source](https://access.redhat.com/security/cve/CVE-2026-33845). |
| libevent | CVE-2026-63385 | partially_mitigated_open | HTTP server rejects encoded NUL before routing; query helpers reject decoded NUL and clear partial results. Existing2.1.13 header fix retained. Binary percent-decoder deliberately retains documented behavior; applications directly using it as C-string path need their own length-aware validation. Nine HTTP cases, query/API controls and five upstream URI tests pass. [Primary source](https://github.com/libevent/libevent/security/advisories/GHSA-jcwh-pvf2-73p2). |
| libxml2 | CVE-2026-6732 | open | Official226b560 parser callback patch removes the observed failure but breaks valid bounded XSD entity content:42 becomes4242. Candidate removed from layer pending compatible entity callback semantics; existing8patches retained. [Primary source](https://github.com/GNOME/libxml2/commit/226b560837b90dea9b14431eca6e6fda8fb01ab4). |

Among the original 99 library associations the updated source/configuration
assessment is **64 fixed, 19 excluded, 14 open and two partial**. Across the
original 539 whole-image associations it is **111 fixed, 210 excluded, 123 open,
two partial and 93 unassessed**. Kernel/FFmpeg work was not expanded in this
library task, and the existing BusyBox `cp` cross-component follow-up remains
unassessed.

## Scanner and reproducible evidence

Unresolved raw installed-package associations changed from **483 to 459**. The scanner
was rerun against the new generated SPDX document and package manifest using
the same **2026-10-11 database snapshots**; this is not a newly downloaded
2026-10-12 database. Primary-source review was performed on 2026-10-12. Raw
reports stay separate from source/configuration dispositions; backport tags
and configuration exclusions do not imply a clean whole-image security result.

Evidence is retained under
`artifacts/20261012T140609Z-e664cb9647e7/rpi5-camera-hailo/security/`, including the immutable raw scan,
scanner metadata, configuration evidence, and the curated
`library-residual-2026-10-12/` directory with `SHA256SUMS`. Its per-CVE JSON/CSV
records retain source URLs and links to unchanged baseline evidence. It excludes
credentials, vendor package payloads, full copied source trees and executables.

Install this image through `scripts/install-ssd.sh` when the target SSD is
connected. Full-image boot, video and Hailo acceptance must be recorded after
installation; the isolated libc check does not replace it.

## Subsequent installed-device validation

The image in this report was subsequently installed and checked on the Pi.
Installed files, three Wi-Fi reboots, automatic 1080p capture and user-observed
Hailo inference passed. See [deployment validation](library-deployment-validation-2026-10-12.md).
The earlier hardware-pending statements above describe the build-time boundary.
The deployment report separately records the unresolved initial setup session/clock
follow-up; the library security assessment counts remain unchanged.
