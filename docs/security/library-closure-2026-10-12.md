# Common-library follow-up — 2026-10-12

This pass reviews the **14 open and two partial** library associations left
by the [previous remediation](library-residual-remediation-2026-10-12.md).
Four have corrections verified in the built image, two old glibc findings have precise
source-based exclusions, and **eight remain open plus two partial**.
These are package/advisory associations, not confirmed exploit counts.

Accepted device baseline: `20261012T162756Z-e664cb9647e7`. New Hailo image:
`20261012T172633Z-e664cb9647e7`. **Build and final-image verification passed.**
At completion of this build pass, the new image had not been installed or
hardware-accepted. The running Pi was not changed; no SSD write, QEMU/minimal
image build or long-duration test was performed during this pass.
**Subsequent deployment acceptance passed on 2026-10-13**: installed-file checks,
three Wi-Fi reboots and user-confirmed video/Hailo inference are recorded in the
[separate deployment report](library-closure-deployment-validation-2026-10-13.md).

## Applied layer changes

| Component | Association | Change and provenance |
|---|---|---|
| BusyBox | CVE-2026-38754 | Restore IFS state on all three continuing expansion-error paths. Accepted upstream ash correction, including v3 ownership handling. |
| BusyBox | CVE-2026-38753 | Copy AWK replacement text before regex evaluation can invalidate its storage; free it at the shared return. Exact official proposal, **not yet merged upstream**. |
| ALSA | CVE-2026-96675 | Reject missing, negative and out-of-range multi-PCM bindings before allocation or ownership transfer. Locally adapted from an **unmerged** proposal to avoid its allocation leaks. |
| GnuTLS | CVE-2026-33845 | Complete DTLS fragment-length reassembly correction, private structure update, bounds and sequence/type prerequisites, and official security tests. Production `buffers.c` matches 3.8.13. |
| libevent | Additional framing correction; CVE-2026-63385 remains partial | Evaluate duplicate Content-Length even when Transfer-Encoding is absent. Local correction, **not submitted upstream**; no additional CVE identifier or complete decoder fix is claimed. |

Primary references: [BusyBox ash commit](https://github.com/vda-linux/busybox_mirror/commit/a448b6d5b21e5b21249391389b6f0551d9bea136),
[AWK proposal](https://lists.busybox.net/pipermail/busybox/2026-June/092352.html),
[ALSA PR527](https://github.com/alsa-project/alsa-lib/pull/527),
[GnuTLS reassembly commit](https://github.com/gnutls/gnutls/commit/e5b72c53c7d789d19d1d1cd10b275e87d0415413),
[libevent advisory](https://github.com/libevent/libevent/security/advisories/GHSA-jcwh-pvf2-73p2).

Nine layer files changed: five new patches and four appends. The complete
affected local series comprises 14 frozen inputs, including existing patches.
No broad CVE-status override, public API removal or feature disabling was used.

## New exclusions

- **glibc CVE-2011-0536:** the faulty historical downstream token-count guard
  is absent. Current secure-mode token recognition and substitution expand or
  reject the expression correctly in ten exact-source controls. The accepted
  image's 16 privileged executables have no ORIGIN RPATH/RUNPATH; the full ELF
  inventory finds only the nonprivileged `hailortcli` using ORIGIN. This excludes
  that particular downstream regression, not other loader vulnerabilities.
  [Original downstream report](https://bugzilla.redhat.com/show_bug.cgi?id=667974).
- **glibc CVE-2025-0577:** the vendor limits this to prerelease vDSO backports;
  no released upstream glibc was affected. The complete official ordering and
  state-ownership fix is already present in 2.43 and reverses with zero fuzz.
  Three deterministic source tests fail before the fix and pass now. The
  AArch64 vDSO implementation is enabled; exclusion does not assume it is absent.
  [Vendor report](https://bugzilla.redhat.com/show_bug.cgi?id=2338871),
  [official fix](https://github.com/bminor/glibc/commit/abeae3c0061c0599ac2f012b270d6b4c8f59c82f).

No glibc source or layer file was changed. Final-image libc/loader bytes match
the accepted baseline. The host adapters are not
complete privileged-loader or concurrent-fork target tests.

## Tests and limitations

- Project host suite: **365 passed**.
- BusyBox: 14 focused controls pass under ASan, including failing-before IFS
  and AWK substitution cases. Official AWK tests: **73 passed**; ash:
  **326 passed, three preexisting failures with identical before/after output**:
  `heredoc_backslash1`, `heredoc_bkslash_newline2`, `bkslash_in_varexp`.
  The separately tracked unbounded recursion condition still reproduces.
- ALSA: six grouped cases pass; five invalid index/ownership cases each run
  200 times under ASan/LSan. Valid null/multi PCM setup, 32-frame writes and
  closing controls pass. Physical audio hardware is not required or tested.
- GnuTLS: official isolated underflow reproducer changes from SIGSEGV to pass;
  fragment suite plus six DTLS compatibility programs and the isolated test
  pass. `dtls-rehandshake-cert` times out after 60 seconds both before and after;
  `mini-dtls-large` skips with heartbeat disabled; `dtls-sliding-window` could
  not compile without cmocka. This is **not a full GnuTLS suite pass**.
- libevent: five duplicate-length cases change from HTTP 200 to 400; all
  11 framing controls, nine URI cases and query/binary API controls pass.
  Official HTTP suite: **61 passed, 12 skipped**. An exploratory test incorrectly
  expected incoming obsolete folding to be rejected; it is intentionally
  normalized, as verified by `http/multi_line_header` and permitted by
  [RFC 9112 section 5.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-5.2).
  That initial result and the corrected test selection are retained.
- Avahi: fresh ASan/UBSan tests exercise actual simple-protocol/event-loop code,
  resource backoff, capacity recovery and a real core DNS-browser object. All
  real network interfaces are excluded from the fixture. Host core/common
  libraries are used; complete target mDNS behavior is not established.
- ACL: actual 2.3.2 source confirms substituted intermediate path components
  affect all four named pathname APIs; an already-open descriptor retains its
  original inode. Seven behavior cases pass. Official suite: nine passed,
  four root-only skips, two NFS expected failures. No privilege escalation was
  attempted on the host or Pi.

An independent review checked all frozen inputs, upstream GnuTLS byte
equivalence, patch/source correspondence and ownership paths, and reran the
GnuTLS reproducer and ALSA controls without sanitizer errors. It found no
blocking defect. Target compilation, installed-image checks and hardware
acceptance are separate from this source review.

## Remaining candidates

| Component | CVE | Remaining condition |
|---|---|---|
| ACL | CVE-2026-54369 | New `_at` APIs require caller adoption. Legacy pathname wrappers still use flags zero; globally rejecting symlinks would break actual systemd procfd uses. Privileged callers need compatible descriptor-based integration. |
| binutils | CVE-2026-6844, CVE-2026-6845 | ELF readelf remains installed. Public vendor trackers still lack disclosed reproducer/fix details; unrelated XCOFF exclusions cannot close these findings. |
| BusyBox | CVE-2026-38752 | Unbounded AWK recursion still exhausts the stack. An unmerged arbitrary depth cap is not adopted as a compatibility-preserving fix. |
| BusyBox | CVE-2026-38755 | CNA describes evalcommand heap overflow but links an evalfun recursion proposal. Exact matching trigger and correction remain unresolved. |
| Expat | CVE-2025-66382 | Official issue 1076 remains confidential and unfixed; issue 1160 still lists it as incomplete. |
| glibc | CVE-2010-4756 | Attacker-controlled glob complexity must be bounded at callers; no supported global bound or complete input-boundary exclusion was established. |
| libxml2 | CVE-2026-6732 | Official callback correction prevents the crash but duplicates valid bounded schema values (`42` becomes `4242`). Matching parser functions in current master and 2.15.4 still have that behavior. Candidate not applied. |
| Avahi | CVE-2025-59529 — partial | Valid long-lived browsers can monopolize the bounded client pool. PR808 was closed unmerged on 2026-09-07; existing resource controls remain. |
| libevent | CVE-2026-63385 — partial | Binary decoder users must check returned length before treating output as a C-string path. No dynamic evhttp import was found in the current image, but static/dlopen/future developer uses are not excluded. |

Primary residual evidence: [ACL implementation](https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/?id=5906d2868ec8d3b08be556153696e6b1122eeeda),
[binutils 6844 tracker](https://bugzilla.redhat.com/show_bug.cgi?id=2460505),
[binutils 6845 tracker](https://bugzilla.redhat.com/show_bug.cgi?id=2460511),
[AWK recursion proposal](https://lists.busybox.net/pipermail/busybox/2026-June/092351.html),
[ash recursion proposal](https://lists.busybox.net/pipermail/busybox/2026-June/092354.html),
[Expat tracking](https://github.com/libexpat/libexpat/issues/1160),
[glob vendor discussion](https://bugzilla.redhat.com/show_bug.cgi?id=681681),
[libxml2 candidate](https://github.com/GNOME/libxml2/commit/226b560837b90dea9b14431eca6e6fda8fb01ab4),
[Avahi PR808](https://github.com/avahi/avahi/pull/808).

Kernel, FFmpeg MOV and the separate BusyBox `cp` follow-up are outside this
selected library pass. No new runtime acceptance is inferred from earlier
successful video and Hailo checks.

## Integration status and evidence

The integrated Hailo build completed successfully: 7,786 tasks, with 6,796
reused. Ten local patches across the four affected recipes reverse and reapply
to copies of the actual build sources with zero fuzz and identical final
bytes. All 14 frozen inputs still match the independent review.

All **182 SONAME/export comparisons passed**; five shared-library files changed
(ALSA, GnuTLS, libevent, libcamera and librpicam_app). This is symbol
compatibility evidence, not a complete ABI/runtime proof. The actual WIC
supplied **58 matching selected files**, seven kernel modules, 16 preserved
privileged-file modes/owners and two valid IPA signatures; altered IPA
signatures were rejected. The initial-setup web assets and application files
match the previously accepted image. Camera auto-detection, Wi-Fi/service
configuration, the development checkout and absence of provisioned credentials
were checked. In particular, libc and loader bytes remain unchanged, supporting
the scoped glibc exclusions.

Among the original **99 library associations**, the result is **68 corrected,
21 excluded, eight open and two partial**. Across the original **539 whole-image
associations**, it is **115 corrected, 212 excluded, 117 open, two partial and
93 unassessed**. Unresolved raw matches fell from **459 to 455**, with no new
association in the same snapshot. The scanner uses the existing **2026-10-11
database snapshots**; primary-source review above is dated **2026-10-12**.
No fresh database download or clean whole-image security claim is implied.

Working evidence is in `.state/library-closure-2026-10-12/`. Selected text
evidence and checksums are retained under
`artifacts/20261012T172633Z-e664cb9647e7/rpi5-camera-hailo/security/library-closure-2026-10-12/`.
Credentials, vendor payloads, full copied source trees and executables are
excluded from that archive.

The user subsequently installed this image with the normal SSD workflow.
Its own boot, automatic-startup, video and Hailo acceptance is now recorded in
the [2026-10-13 deployment report](library-closure-deployment-validation-2026-10-13.md).
The build-only evidence above remains unchanged; prior-image acceptance was
not reused to validate these binaries.
