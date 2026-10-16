# Remaining installed library candidates — 2026-10-12

The later [remaining-library remediation](library-residual-remediation-2026-10-12.md)
records 24 additional source corrections, two configuration exclusions and
additional partial mitigations in image `20261012T140609Z-e664cb9647e7`.
The historical assessment below is preserved; the later image has not yet
been installed for full hardware acceptance.

The baseline is deployed image `20261012T031641Z-e664cb9647e7`, profile
`rpi5-camera-hailo`. This follow-up covers all **99 affected associations** outside
Linux and Raspberry Pi FFmpeg in its installed-findings CSV, representing 97
unique CVEs across 22 recipe associations. The two util-linux/libuuid duplicate
associations are retained and assessed against their different installed files.
Scanner version matches are not confirmed exploits. Raw reports are unchanged.

The machine-readable ledger is
`.state/security-followup-2026-10-12/libraries/assessment.json` and
`assessment.csv`. Each row preserves its recipe, CVE, baseline version and
installed packages, primary CNA record/references, disposition, rationale,
evidence files and specific remaining work. The 39 remaining source candidates
have distinct API/path/condition reviews in `open-source-path-checks.json`;
those observations do not establish complete fix equivalence or runtime
reachability. All named paths were located. They remain open.

| Disposition before the integrated rebuild | Associations |
| --- | ---: |
| Verified candidate source fixes; final build/image acceptance pending | 34 |
| Already fixed in baseline source or official release | 6 |
| Image-specific absent tool/service/module/component, architecture or source implementation | 17 |
| Remaining source candidates with specific follow-up | 39 |
| Expat upstream unfixed DoS | 1 |
| Avahi resource mitigation with residual availability/CPU risks | 1 |
| Libevent header fix with unresolved URI-NUL behavior | 1 |
| **Total** | **99** |

Final image `20261012T080118Z-e664cb9647e7` passed target compilation, actual
source/patch-series verification, installed-library SONAME/export comparisons
and actual WIC checks. The integrated ledger advances the 34 pending source
fixes to fixed-in-image: **40 fixed, 17 excluded, 40 open and two partial**.
The immutable pre-build component ledger above is retained as historical
evidence. Subsequent [deployment validation](security-deployment-validation-2026-10-12.md)
passed installed-file, system-media, boot and camera/Hailo checks. It does not
establish coverage of all library APIs.

## Layer changes and primary sources

The existing OE recipe versions remain the append match points. Expat advances
to 2.8.5; libevent advances to stable 2.1.13. Glibc, libxml2, util-linux and
Avahi keep their existing versions and receive narrowly scoped source patches.
This record covers library source evidence and bounded host checks. Integrated
build, WIC checks and deployment status are recorded in the image security
follow-up. No feature removal or blanket CVE_STATUS suppression is introduced.

| Source | Change |
| --- | --- |
| [Expat 2.8.5 release](https://github.com/libexpat/libexpat/releases/tag/R_2_8_5) | Take 2.8 security fixes with the existing libexpat.so.1 ABI; retain pre-2.9 optional API compatibility. Remove nine inherited patches already incorporated in this release. Both license files compare byte-for-byte. |
| [Expat allocator fix](https://github.com/libexpat/libexpat/commit/209801d7fbaf07ab74bae8cb32dd2ab9e5846118), [parse-buffer fix](https://github.com/libexpat/libexpat/commit/13c5f63a7f1c52c2feee3b16a1134d4fb68e9ea0) | Backport CVE-2026-102633 and CVE-2026-77214. Downloaded merge-commit patch streams contain authored commits 69edbec0 and 4d9b1c49 respectively; this distinction is preserved in original patch headers. |
| [libevent 2.1.13 stable](https://github.com/libevent/libevent/releases/tag/release-2.1.13-stable) | Same 2.1 SONAME family and byte-identical license. All five inherited OE patches apply with zero fuzz. This fixes seven candidate associations; the WebSocket implementation is absent on 2.1 and CVE-2026-63385 remains partial. |
| [glibc resolver fix 506ea570](https://sourceware.org/git/?p=glibc.git;a=commit;h=506ea57086bfb9ce3daff1c14246a1cb532aba0a) | Correct search-list truncation matching and oversized first-domain handling for CVE-2026-8674; preserve the OE 2.43 source pin. |
| [libxml2 2.15.3…2.15.4 changes](https://github.com/GNOME/libxml2/compare/v2.15.3...v2.15.4) | Eight exact CVE-2026-86137…86144 patches preserve recipe version 2.15.2. The regexp length-field prerequisite precedes its allocation-failure correction. CVE-2026-6732 is separate and remains open. |
| [util-linux a15c00a9](https://github.com/util-linux/util-linux/commit/a15c00a9e545aa8b9cf6ec0f888ff6c7b3eaeedc) | Skip privileged post hooks after failed helper/syscall status, preserve a legitimate no-op mount stage for bind/move, and include loop-device cleanup when its post hook is skipped. Version stays 2.41.3. |
| [Avahi proposal 808](https://github.com/avahi/avahi/pull/808), [official advisory](https://github.com/avahi/avahi/security/advisories/GHSA-73wf-3xmj-x82q) | Proposal 808 is closed and unmerged. A local partial mitigation enforces the source's existing CLIENTS_MAX=50 and suppresses EMFILE/ENFILE error-log flooding without the proposal's credential/rlimit refactor. Version stays 0.8. |

Downloaded release tarball SHA256 values are:

- Expat 2.8.5 tar.bz2: `952c03c33a6b337f12dae7a9b0f9dee86f867550d35c994d6bdaaddd37dc8454`.
- libevent 2.1.13 stable tar.gz: `f7e9383b8c0baa81b687e5b5eecc01beefaf1b19b64151d95ed61647fe7a315c`.

These match the official GitHub release asset digests. No detached-signature
verification is claimed. Exact local file hashes for all 19 layer inputs and
expected package versions are in `frozen-layer-inputs.json`. Primary downloads,
source files, generated configuration and installed-file hashes are retained
separately from binary build acceptance.

## Bounded checks and their limits

Expat's new upstream XML_ParseBuffer capacity regression fails against
unpatched 2.8.5 and passes after the two fixes. The candidate passes **4,944
upstream checks**. The allocator overflow test also passes in the candidate;
this host run does not demonstrate the architecture-specific 32-bit exploit.

Libevent passes nine selected evtag/HTTP/evbuffer tests, including empty-chain
multicast, malformed headers, chunk parsing and multiline headers. These are
short host regressions rather than full application/proxy/DNS integration.

The glibc fixture executes the exact production `resolv_conf_matches()`
function. An oversized first search domain rejects the valid truncated state
before the fix; the fixed function accepts it and passes normal/mismatch
controls. Nameserver and sort lists are empty; actual DHCP propagation and
resolver I/O are outside this fixture.

Both baseline and candidate host libxml2 builds succeed. The upstream
XInclude issue1120 regression executes four cases: baseline reports three
errors, candidate reports none. A separate exact `xmlSnprintfElements()`
fixture detects a capacity canary overwrite before its fix and passes after
it, including normal output. Its size-one buffer is synthetic; the current
private production callsites use 5,000-byte buffers. It is a direct helper
bounds check, not independent proof of an end-to-end exploit. Other huge-size,
OOM and parser conditions in the eight-patch series are source-reviewed, not
individually reproduced. Host builds disable optional iconv/compression/Python
components; target recipe configuration is preserved.

The util-linux fixture executes the exact production post-hook predicates and
`is_mount_stage_failed()` using status accessors. Failed helper and failed
syscall states improperly enable hooks before the fix; all five failed,
successful and no-op states pass after it. No real mount, idmap, namespace or
loop-device operation is performed. Independent review checked the loop-device
cleanup ownership and preservation of the bind/move no-op case.

Avahi's fixture executes the exact production accept callback with real Unix
sockets. Before the fix six checks fail; afterward it admits 50 clients,
closes the rejected 51st descriptor, admits a replacement when a slot is freed,
suppresses resource-exhaustion error logging, retains other error logging and
ignores non-input events. Client allocation and logging are fixture stubs.
The whole daemon poll/mDNS path is not run.

Independent review found no unresolved important code issue in the 19 layer
inputs. Actual integrated BitBake source, SONAME/export and image checks have
passed. These checks do not establish deployed-image operation or full ABI
equivalence.

## Explicit exclusions and unresolved work

`installed-package-files.json` records 162 associated installed packages and
978 owned files. Image-specific exclusions distinguish full utilities from
other implementations: the installed getfattr is a BusyBox symlink; login
resolves to shadow. Attr's utilities, ACL utilities and xmlwf are absent.
libuuid contains only UUID code, so its login/libmount associations remain
separate from util-linux. ALSA topology is built into separate libatopology;
the image contains no such library and libasound exports no snd_tplg API.
The Win32 experimental Theora AVI example and libevent's 2.2 WebSocket code
are absent from the deployed implementation.

The glibc nscd service and SHIFT_JISX0213/EUC_JISX0213 gconv modules are absent.
Actual libc is ELF64 AArch64, excluding the Power8 strncasecmp implementation.
Sudo's generated target configuration does not define HAVE_PTRACE_INTERCEPT,
and installed policy does not enable intercept/log_subcmds. OpenSSL 3.5.9 has
no old Red Hat 1.0.1e ssleay_rand_bytes PRNG implementation.

Rootfs host permission bits are managed under pseudo. A host scan finding no
setuid/setgid files does **not** establish an AT_SECURE loader exclusion;
CVE-2026-86805 and CVE-2026-95818 remain open pending actual image metadata and
source review. The exclusion checker `verify-final-exclusions.py ROOTFS
BUILD_ID --output JSON` passed against both baseline and the final rebuild.
It rechecks utility/module/library absence, the two
alternative implementations, ELF architecture and unchanged sudo config/policy.

The six existing fixes are the zlib gzwrite change (the scanner's 76844 and
existing patch's 85091 cite the same df84af25 fix), GnuTLS's older RSA exchange
issue, libarchive's complete RAR window/copy/filter guards, and all three
GStreamer candidates. The two H.264/H.266 changes reverse-check exactly against
actual plugins-bad 1.28.8. The official MOV advisory fixes versions before
1.28.2; coordinated 1.28.8 is already installed.

The remaining source candidates are ACL pathname-library traversal; three
ALSA parser/PCM cases; four BFD/readelf cases; four enabled BusyBox AWK/ASH
cases; five GLib cases; thirteen glibc cases; three GnuTLS cases; PNG setter
aliasing; four X11 cases; and libxml2 schema/entity type confusion. Their
ledger entries identify the relevant API, prerequisite and exact remaining
source or regression work. This is not a claim that those candidates are all
confirmed exploitable, fixed, or fully understood.

[Expat issue 1076](https://github.com/libexpat/libexpat/issues/1076) explicitly
remains open for all releases. [Libevent's HTTP advisory](https://github.com/libevent/libevent/security/advisories/GHSA-jcwh-pvf2-73p2)
fixes header handling but the CNA does not establish complete remediation of
URI `%00` truncation. Avahi still permits an attacker to hold all 50 slots and
deny new simple clients; repeated EMFILE/ENFILE listener readiness can still
consume CPU because no backoff is added. Its patch filename and header
intentionally omit recognized CVE-fix tags. The actual OE detector test returns
no fixed CVE for the new patch and detects the old filename/header controls.
Therefore the partial mitigation must not create a false scanner PASS.
