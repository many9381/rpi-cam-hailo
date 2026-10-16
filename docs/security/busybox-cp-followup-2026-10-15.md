# BusyBox cp applicability follow-up — 2026-10-15

Image: `20261014T170636Z-e664cb9647e7` / `rpi5-camera-hailo`.

## Finding and conclusion

The separate BusyBox `cp` follow-up for **CVE-2007-4998** is **not affected in
this verified image configuration**. The existing upstream-layer setting
`CONFIG_FEATURE_NON_POSIX_CP=y` already enables the relevant protection.
No new source patch, layer configuration change, image rebuild or SSD
installation is required for this finding.

This closes the userspace question recorded separately from the historical
kernel association. It does not declare all BusyBox versions/configurations
unaffected, close the other BusyBox advisories, or establish safety against
arbitrary concurrent ancestor-directory replacement.

## Primary condition and actual implementation

The [CNA record](https://www.cve.org/CVERecord?id=CVE-2007-4998) and
[Red Hat report](https://bugzilla.redhat.com/show_bug.cgi?id=356471) describe a
copy invocation preserving source symlinks: a source symlink is copied first,
then a later ordinary source with the same basename is copied into the same
destination. An affected implementation follows the newly created destination
link and writes the later source data to a different file writable by the
copying user. This is a local, user-assisted scenario, not a remote camera API.

BusyBox documents its safe-copy configuration in upstream commits
[2d7b5bfa9bd0](https://lists.busybox.net/pipermail/busybox-cvs/2009-July/029569.html)
and [6f58be07485f](https://lists.busybox.net/pipermail/busybox-cvs/2009-July/029570.html).
The actual 1.37.0 `libbb/copy_file.c` uses `O_CREAT|O_EXCL` in this configuration.
If the destination already exists, it unlinks that entry and retries exclusive
creation. Thus a destination symlink is replaced by a regular file; its referent
is not opened for truncation. The original source symlink is retained.

This pre-existing behavior also replaces an ordinary destination inode and
does not implement POSIX-style copying through destination symlinks or special
nodes. The investigation does not introduce a new compatibility change.

## Source, configuration and binary binding

- The pinned OpenEmbedded `meta/recipes-core/busybox/busybox/defconfig` already
  sets `CONFIG_FEATURE_NON_POSIX_CP=y`. The final `.config`, `.config.orig`
  and generated autoconf retain it. The `cp` applet is selected in the nonsuid
  split; the shared non-applet configuration survives the recipe's split.
- Relevant installed copy settings are `CP`, `LONG_OPTS`,
  `FEATURE_CP_LONG_OPTIONS`, `FEATURE_NON_POSIX_CP`, `FEATURE_VERBOSE` enabled;
  SELinux, reflink, hardlink preservation and verbose-error extension disabled.
- The compiled binary differs from the installed one by packaging debug data.
  Normalizing private copies with the target strip tool, removing only
  non-runtime symbols/debug data, `.comment` and `.gnu_debuglink`, produces
  identical bytes; code/data, relocations and build ID remain compared.
- Packaged, assembled rootfs, previously verified actual WIC and live Pi
  `busybox.nosuid` SHA-256 all match:
  `6051d7cbda76f205c3959418d9003035d8ff5dfc450bce830ee0367a717d6538`.
  On the Pi, `/usr/bin/cp` resolves to this binary. It is root-owned mode
  `0755`; the tests run as the ordinary UID 1000 account.

## Behavioral evidence

The reusable suite is
`tests/integration/check-busybox-cp-symlinks.sh` in the parent Yocto repository.
Run it without root:

```sh
sh tests/integration/check-busybox-cp-symlinks.sh /absolute/path/to/busybox
```

Its 26 finding-specific cases cover `-a`, `-R`, `-RP`, `-d`, `-P`, relative
and absolute links, existing and absent referents, and recursive merging of
same-name source directories. They assert that the referent is unchanged or
absent, the resulting destination is an ordinary file with the later source
content, and the original source link is preserved where checked.

Eleven additional cases check ordinary creation/overwrite/recursive copying,
source-link and dangling-source-link preservation, explicit source dereference,
no-clobber including a destination link, interactive refusal/acceptance and
the existing remove-destination invocation.

| Execution | Result |
|---|---|
| Same-source native cp with installed copy settings | **37/37 pass** |
| Same-source native control with only NON_POSIX_CP disabled | All **26 finding-specific cases fail**; ten ordinary controls pass |
| Additional remove-destination case on that unsafe control | Fails too; this option is not accepted as substitute mitigation |
| Inert no-copy executable | Suite rejects it: 34/37 cases fail |
| Actual Pi `/usr/bin/busybox.nosuid cp` | **37/37 pass** |
| Actual Pi `/usr/bin/cp` entry | **37/37 pass** |

Native builds use the real cp/copy helper source and match the listed target
copy options; they are minimal x86_64 test builds, not target binaries.
An initial minimal build omitted verbose-copy support; that configuration and
its results are retained separately. Final results use the matching option.
The initial runner expected all eleven ordinary cases to pass in the unsafe
control; inspecting real behavior corrected that expectation for
`--remove-destination`. No product source was changed to satisfy a test.

Every referent and payload is a disposable file under a newly created private
directory. The Pi's real system files, account policy and configuration are
not used as targets. Successful and deliberately failing native suites clean
up their fixtures; no matching temporary directories remain after either Pi
run. The device retains the same boot and camera-service PID, zero application
restarts, unchanged BusyBox bytes and HTTPS 200. No reboot or service stop is
part of this check.

## Assessment and evidence boundary

The separate follow-up moves from **unassessed** to **notaffected**, based on
this source/configuration/binary/behavior combination. The original
546-association ledger remains **200 fixed, 331 not affected, 12 open, two
partially mitigated/open and one unassessed**; BusyBox `cp` was outside that
denominator. In particular, the unresolved BusyBox awk/ash entries and the
unassessed Sun/Brocade kernel entry are unchanged. This is not a new full-image
scan; the image scan database remains the October 14 snapshot.

Changing the copy configuration, cp provider, source, binary or relevant
calling behavior requires reassessment. These bounded tests do not cover
setuid transitions, privileged user behavior or general filesystem races.
The version number alone is not the basis for exclusion.

Independent review passed with no findings. The reviewer reproduced the
native positive and negative controls and normalized target-binary equality,
and verified the recorded source/configuration hashes, device-test evidence
and unchanged original ledger. The review did not repeat device access.

Working evidence: `.state/busybox-cp-followup-2026-10-15/`.
Curated evidence, primary records and checked `SHA256SUMS`:
`artifacts/20261014T170636Z-e664cb9647e7/rpi5-camera-hailo/security/busybox-cp-followup-2026-10-15/`.
The archive excludes private keys, credentials, raw device journals and native
build trees. Original scan/build/deployment evidence is preserved.
