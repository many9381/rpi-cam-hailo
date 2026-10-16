# Residual security consumer review — 2026-10-16

The caller review for accepted Hailo image
**`20261016T111625Z-e664cb9647e7`** is complete. No additional production patch
is justified by the paths examined. Keep the existing layer corrections and
accepted image; this review requires no rebuild or SSD installation.

This follows the [October 15 residual assessment](security-residual-followup-2026-10-15.md).
The user selected follow-up of actual input paths, particularly libevent URI
decoding and glibc `glob`. Long-duration operation and additional MOV/common
allocator redesign remain [excluded](README.md#agreed-work-exclusions).

## Product work status

**Completed — no current implementation action.** Remove the reviewed libevent
camera/`cam` paths and the HailoRT fixed-pattern `glob` call from active
remaining-work lists. Continue using the accepted image. No patch, rebuild or
SSD reinstall is assigned for these reviewed paths.

Keep their underlying library advisory records and this evidence. Reopen the
product task only if the relevant feature/input path, package or configuration
changes, or new upstream evidence changes its applicability. An unchanged
advisory count alone does not reopen it. This closes the caller-review task;
it does not mark the library CVEs fixed or resolve every other glob consumer.
Other residual records retain their individual dispositions and prerequisites.

## Image and source verification

- The accepted compressed WIC SHA-256 is
  `49417cfdc898f1cb0ab9aae7a2f78de92d19f45666a0e4c0a5f2d4276f7a9c12`.
- All **867 inventoried ELF paths**, three packaged sudoers includes and the
  build ID match the actual WIC: **871 file hashes PASS**. The temporary sparse
  filesystem extraction was removed. This inventory covers non-symlink
  executable/shared-library ELF files in the documented system directories;
  it is not an assertion that arbitrary static or dynamically constructed
  loading paths are absent.
- All **170 reviewed product C/C++ files** match both the compiled source tree
  and packaged development checkout. The direct-call search found no
  `evhttp_*`, `glob` or `glob64` call in those product files.
- Twenty library/caller source and configuration files match the prior review,
  including glibc, libevent, systemd, sudo, libcamera and the other recorded
  glob consumers. Their earlier behavioral tests remain historical evidence;
  they are not counted as newly executed tests here.

## libevent: HTTP decoding is not used by the identified consumer

The image's dynamic import inventory contains **no `evhttp_*` importer**.
The single executable directly dependent on libevent is `/usr/bin/cam`, the
libcamera command-line tool. Its imports and actual `event_loop.cpp` use
event scheduling, file-descriptor events and timers. The camera firmware
executable has no direct libevent dependency; its web service uses Drogon.

The [official advisory](https://github.com/libevent/libevent/security/advisories/GHSA-jcwh-pvf2-73p2)
still describes decoder and HTTP-header risks. Existing layer fixes for URI
string inputs and duplicate Content-Length remain in place. The public
length-returning decoding API also supports binary results; changing it to
reject every decoded NUL would change that contract. The prior bounded
consumer test demonstrated the necessary returned-length check, but no
installed unsafe direct caller was identified to patch.

Disposition remains **partially mitigated/open** at library level. For the
identified camera application and `cam` paths, there is no newly established
HTTP decoding input requiring another fix. Reopen caller implementation work
when a new HTTP/URI decoder consumer is introduced, an unsafe existing path is
identified, or a compatible upstream correction changes the assessment.
Computed symbol loading and every possible static consumer are not excluded.

## glibc: the HailoRT uncertainty is narrowed by the actual binary

Twenty installed ELF paths import `glob` or `glob64`. Import presence alone
does not show that a remote caller controls the expansion pattern.

The shipped vendor `libhailort.so.4.24.0` has SHA-256
`5fb8e54bb9945a3566930701af8dfc600edb5a15a7aca328b59cc18ce8d5a12c`.
Its disassembly contains one direct `glob@plt` call and one `glob` dynamic
relocation. Decoding the actual AArch64 ADRP/ADD argument instructions at
`0x20669c`/`0x2066a0` resolves the call's pattern to read-only address
`0x8e79d0`: **`/sys/class/hwmon/hwmon*/name`**. The call at `0x2066bc` supplies
flags `0x1000` (`GLOB_TILDE`). The pattern is a fixed hardware-monitor lookup,
not a pattern assembled from the web request or AI model name at that call.
This improves on the prior import-only vendor-library evidence. It is not an
exhaustive proof of every indirect control flow in the proprietary binary.

Other callers retain distinct input boundaries:

| Caller group | Established boundary / remaining condition |
|---|---|
| libv4l2, Avahi service scan, `ip`, `lsclocks` | Recorded calls use fixed plugin/device/process/service patterns; arbitrary pattern text is not supplied there. Filesystem-size costs are not universally bounded. |
| Packaged `rpiadmin` sudo rules | Nine allowed command entries use literal executable paths. The reviewed sudo command matcher selects `glob` only for sudoers command patterns containing metacharacters. User arguments do not become that command-path pattern. This is not a claim about every sudo configuration. |
| systemd/NSS/udev helpers | Configuration, condition and command-line patterns still need their own trust boundary. A function named `safe_glob` is not a general resource limit. |
| FFmpeg image-sequence CLI, make, linker, nftables, procps | Developer or administrator command/configuration patterns remain supported. No new remote camera input feeding those patterns was established. |

The [glibc maintainer discussion](https://bugzilla.redhat.com/show_bug.cgi?id=681681)
and the [current glob source](https://github.com/bminor/glibc/blob/master/posix/glob.c)
do not establish a compatible general workload limit for every caller. The
review therefore retains **open** at library/image level. No arbitrary global
limit or vendor-binary patch is introduced. Further implementation needs an
identified untrusted-pattern entry point or a compatible upstream strategy.

## Primary-record refresh and remaining work

The **14 non-MOV residual CVE records** were fetched at CVEList revision
`88c7335ba41ef6558f3785078e9d0830b2dda6b2`. Each full record, including its CNA
and other containers, is unchanged from October 15. The selected libevent
advisory/source/history, glibc source/history and Avahi PR 975 are unchanged.
The Red Hat response wrapper differs, but all eleven actual comments match.
This is a selected primary-record refresh, not a complete vulnerability
database scan or a fresh upstream source audit of all fourteen components.

The existing ledger stays **11 open, three partially mitigated/open and one
unassessed**, including the separately deferred MOV item. No finding is closed
by successful camera operation or by lack of one direct symbol import.

| Follow-up group | Trigger for additional implementation or review |
|---|---|
| libevent / glibc | New or demonstrated untrusted consumer path, changed packaged binary/configuration, or compatible upstream fix |
| libxml2 / ACL | Compatible callback/caller correction preserving the previously tested valid behavior |
| Expat / BusyBox ash / binutils / historical Sun-Brocade kernel record | Matching trigger, affected-code evidence or verified correction resolving the documented evidence gap |
| BusyBox awk | Compatible resource handling and failure unwinding, with normal recursion preserved |
| Avahi | Compatible capacity/lifetime correction addressing the retained starvation behavior; unchanged draft PR alone is insufficient |
| Three policy-mitigated kernel records | Changed exposure/policy or a compatible source correction; retain the already verified policies |

Unchanged historical findings are not automatically new implementation tasks.
The accepted development image remains usable within its recorded acceptance
scope. Source-quality warning cleanup and release preparation are separate work.

## Evidence and operational scope

Public summary: [verification.json](scan-2026-10-16-consumer-review/verification.json),
[caller-boundaries.json](scan-2026-10-16-consumer-review/caller-boundaries.json),
and [primary-refresh.json](scan-2026-10-16-consumer-review/primary-refresh.json).
Private source/binary excerpts, all image hashes, public-source downloads and
inspection scripts are retained in Git-ignored
`.state/security-consumer-review-2026-10-16/`, with an independently checksummed
copy under the accepted image's `security/consumer-review-2026-10-16/` artifact
directory. The large temporary full disassembly is removed after retaining
its call excerpt and hash; it can be regenerated from the verified binary.

No production source, recipe, package, account, TLS material, Pi service or SSD
was changed. No BitBake/QEMU build, device restart, exploit/resource-exhaustion
trial, long-duration test or new hardware acceptance was performed.
