# Kernel network and coredump policies — 2026-10-14

The camera image now includes an explicit network/coredump policy package.
Build `20261014T152325Z-e664cb9647e7` and final-image verification passed.
**New-image hardware acceptance has not run.** The previously accepted image is
`20261014T125728Z-e664cb9647e7`; its acceptance does not cover this change.

## Changes

| Policy | Applied behavior | Boundary |
|---|---|---|
| ICMP timestamp | nftables drops inbound IPv4 timestamp requests (type 13) and outbound timestamp replies (type 14). Ordinary echo/ping, TCP and UDP retain accept policy. | A network policy, not removal of the kernel timestamp implementation. |
| IPv6 L2 mismatch | Set `drop_unicast_in_l2_multicast=1` for all/default/current interfaces; systemd/udev applies the interface prefix to new interfaces. | Drops IPv6 unicast carried by an Ethernet multicast/broadcast frame. Does not block legitimate IPv6 multicast or close the advisory's separate multicast-destination/error variant. |
| Coredumps | Persist `kernel.core_pattern=|/bin/false`, `kernel.core_pipe_limit=1`, `fs.suid_dumpable=0`. | Discards dumps and bounds helper concurrency. Does not fix the kernel dumpability transition itself. The old device already discarded cores, but that setting was not explicit in this layer. |

`meta-rpi5-cam/recipes-core/rpi5-security-policy/` owns the recipe, rules,
sysctls, module loading, service and fixed read-only status helper. The package
is included in camera/Hailo images. `kas/rpi5-camera.yml` enables the already
pinned `meta-networking` layer for nftables. QEMU/minimal profiles are unchanged.

The policy runs after module loading and sysctl initialization, before network
configuration. `systemd-networkd` requires its successful startup. A bad policy
therefore prevents normal network configuration; the installed valid rules and
failure/recovery behavior were tested in an isolated native systemd container.
Rules replace only `table ip rpi5_security` in an atomic transaction. They remain
installed on service stop. Other nftables tables are preserved.

`rpiadmin` receives only `sudo /usr/libexec/rpi5-security-status`, with no arguments.
It lists this one table as JSON and cannot change network policy. The rule file
is root-owned 0440; the helper is root-owned 0755, and `/etc/sudoers.d` is 0750.
These target ownership/mode values were checked in the actual WIC filesystem.

## Newly installed kernel dependency

Installing nftables requires `nf_tables` and `nfnetlink`. The old image excluded
[CVE-2026-90061](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/90xxx/CVE-2026-90061.json)
solely because `nf_tables.ko` was absent. That exclusion expires with this image.

- `0420-nftables-borrow-default-set-expressions.patch` backports the exact
  [official ownership fix](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=43559058d21e0493aa220ac167e0279334dea5f9): borrow set defaults, clone them only for the element, and free only owned overrides.
- `0421-nft-dynset-mark-serialized-expression-lists.patch` is a local correction
  found during review. Multi-expression dumps require `NFT_DYNSET_F_EXPR` for
  initialization to accept the emitted list. The flag is set exactly when a list
  is emitted, retaining inversion and single/default expression behavior.

Linux stays at `6.18.55-v8-16k`, pin
`4103a989a46196239b830bd07693277e42b8f992`, with the accepted feature configuration.
The preceding 66 patches are retained.

## Validation and evidence limits

- Eleven native packet tests: six fail against the former policy and all pass
  against the new policy. Includes real IPv6 UDP frames in mismatched multicast
  and broadcast Ethernet frames, valid unicast/multicast, late/dotted interfaces,
  timestamp counters, ordinary ping/TCP/UDP, atomic replacement and failed reload.
- Native systemd checks: policy startup, no-argument status, argument rejection,
  retained rules on stop, networkd startup failure and recovery.
- Eleven extracted-source ownership/serialization groups with ASan/UBSan.
  Ownership controls fail the old source; the new serialization group fails
  the official-only patch and passes the additional flag correction.
- Both complete modified C translation units compile with the actual Yocto
  ARM64 compiler/options and `-Werror`.
- Independent review found no remaining important or critical issue after the
  serialization correction and build-input integration fixes.

The packet/service container used the host's Linux 6.8 kernel with native tools;
it was isolated without a LAN interface and removed after testing. Host core
sysctls and the running Pi were not changed. These are bounded behavior tests,
not Pi runtime or exploit-resistance claims. The fixed-source fixtures do not
execute the full kernel initialization path or stress concurrency.

## Completed image validation

- Full host suite: **365 passed** for the frozen layer/build inputs.
- All **68** kernel patches reverse to the pinned upstream tree and reapply
  without fuzz. Final modified sources match the reviewed candidate; all eleven
  extracted-source groups also pass against the actual completed build source.
- All **27** installed modules have matching vermagic and **2,452** imported
  symbol CRCs; **54** negative controls reject mismatches. Exported symbols do
  not change. Both new modules bind to the compiled objects after the same
  packaging strip operations; code-mutation controls are rejected.
- The former **25** modules, **225** protected userspace files and **182** shared
  library comparisons are byte-identical to the accepted image. Existing
  privileged ownership/modes remain correct for **16** checked files.
- The actual compressed WIC was opened and **264** files matched, including
  policy content, executable dependencies, module inventory and protected files.
  Service enablement, exact symlink targets, policy owner/modes, boot kernel,
  board DTB, camera overlay and boot configuration passed. Camera/Wi-Fi rootfs,
  source provenance, artifact checksums and forbidden credential-path checks pass.
- Installed policy units and sudoers syntax pass validation. Effective sysctl
  file precedence and the systemd interface hotplug rule were checked. The core
  discard executable and dependency closure exist; **native coredump behavior
  and Pi runtime remain NOT_RUN**.
- Default `install-ssd.sh` image selection resolves to this completed build;
  this check did not access or write an SSD.

The manifest grows from **453 to 460 packages**, with all previous versions
retained. The seven additions are:

| Package | Version |
|---|---|
| `rpi5-security-policy` | `1.0` |
| `nftables` | `1.1.6` |
| `libnftnl11` | `1.3.1` |
| `libjansson4` | `2.15.0` |
| `libreadline8` | `8.3` |
| `kernel-module-nf-tables-6.18.55-v8-16k` | `6.18.55+git0+6d012fbc35_4103a989a4` |
| `kernel-module-nfnetlink-6.18.55-v8-16k` | `6.18.55+git0+6d012fbc35_4103a989a4` |

Readline reuses the already installed `libtinfo5 6.6`; it is not a new package.
The kernel feature configuration and boot kernel bytes remain unchanged because
these source corrections affect the newly installed loadable `nf_tables` module.

| Identity | Value |
|---|---|
| Build | `20261014T152325Z-e664cb9647e7` |
| WIC bz2 SHA-256 | `60c48862a4df7a085961907128d33050ad9f5a35fcd71646d49bb5b4d68774b6` |
| Boot kernel SHA-256 | `61457fcafe4578b940ba8573fcafab34c6c7676f791a37f86d6cb53775b309e4` |
| Kernel config SHA-256 | `751ecdb597addf24fb7e2eb954cc28e4fc523983665e294c032dd11cd0ca8250` |
| Patched source HEAD | `7055acd80eb1dcec2a72e8754b9a76da64a13bff` |

## Security assessment boundaries

The policy associations remain source-open until separately assessed:
[CVE-1999-0524](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/1999/0xxx/CVE-1999-0524.json),
[CVE-2010-4563](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2010/4xxx/CVE-2010-4563.json), and
[CVE-2021-3864](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/3xxx/CVE-2021-3864.json).
Policy installation and native tests are recorded separately from source fixes
and installed-device effectiveness. The IPv6 advisory also includes an
[originally described multicast-destination/error-header variant](https://seclists.org/fulldisclosure/2011/Apr/254), which this unicast policy does not address.

The retained vulnerability ledger uses the 2026-10-11 database snapshot.
Selected primary records were reviewed on 2026-10-14; this is not a fresh
whole-image scan. New userspace packages are listed as a package delta and are
not silently added to the original 539-association denominator. Unrelated open,
partially mitigated and Sun/Brocade-unassessed findings are unchanged.

| Ledger | Fixed | Not affected | Source open | Partially mitigated/open | Unassessed | Total |
|---|---:|---:|---:|---:|---:|---:|
| Kernel | 108 | 291 | 3 | 0 | 1 | 403 |
| Original whole-image associations | 197 | 327 | 12 | 2 | 1 | 539 |

Only CVE-2026-90061 moves from absence-based exclusion to a verified source fix.
The three policy associations retain source-open status, with build/native/device
policy evidence recorded separately. These counts are not a claim that the
whole image or every variant of those advisories is resolved.

See [systemd sysctl ordering and hotplug rules](https://raw.githubusercontent.com/systemd/systemd/v259/man/sysctl.d.xml),
[kernel IP sysctl documentation](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html),
and [nftables transaction/type documentation](https://netfilter.org/projects/nftables/manpage.html).

Working evidence: `.state/kernel-policy-2026-10-14/`. Curated evidence and its
`SHA256SUMS` are stored under
`artifacts/20261014T152325Z-e664cb9647e7/rpi5-camera-hailo/security/kernel-policy-evidence/`.
No credentials or vendor package payloads are included in that evidence.

## Deployment remaining

Connect the target SSD to the build PC and run `./scripts/install-ssd.sh` from
this project to install the completed image. SSD installation and Pi acceptance
have not been performed for this build. After boot, verify policy startup and
actual timestamp blocking, interface/core sysctls, Wi-Fi/SSH/web connectivity,
camera video and Hailo inference across reboots. The previous image's acceptance
does not substitute for these checks. No QEMU/minimal image was built in this task.
