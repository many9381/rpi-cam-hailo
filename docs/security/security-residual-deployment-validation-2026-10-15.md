# Residual-security image deployment validation — 2026-10-15

Image **`20261015T110905Z-e664cb9647e7`**, profile `rpi5-camera-hailo`: **PASS**.
Installed-image checks, ten installed FFmpeg tests and three controlled Wi-Fi
reboots passed. After reboot three, the user confirmed web video, `hailo / ready`,
increasing inference frames, and object labels with confidence values.

This is the hardware acceptance record for the
[residual-security follow-up](security-residual-followup-2026-10-15.md).
The user installed and booted the new image before testing. No image rebuild,
SSD write, package installation, credentials/settings change, or QEMU work was
performed. Small unprivileged test programs and SFTP payloads were removed.

## Image identity and installed content

- The install receipt and running build/profile/registered board/USB root
  identity match. WIC SHA-256:
  `d885c45a7f0173c492723b88580158164bcfc9114ebfc63234acf445a18630bb`.
- The user confirmed the current Pi address after SSH reported a changed host
  key. A separate new pin preserves the old record; a public TLS certificate
  was retrieved through pinned SSH from the loopback service. Both pins and
  the root UUID remain unchanged throughout this run.
- **376 readable files** match the actual-WIC build evidence, including
  **187 shared-library files**, **27 kernel modules**, and selected application,
  camera, Codex, mount and security-policy files. Corrected libavutil and the
  rebuilt librpicam_app match exactly. The latter's timestamp/build-ID/debug-CRC
  changes are explained in the build report.
- All **27 modules and four boot files** match before and after the reboots.
  Module version magic is correct and no extra kernel release tree is present.
  This run does not add a separate byte-hash claim for builtin module metadata.
- **16 privileged ownership/mode checks** pass. Execute-only `/usr/bin/sudo`
  and the root-only security sudoers rule cannot be hashed by `rpiadmin`;
  their WIC evidence is retained, and permitted/denied helper behavior is
  checked without changing permissions.

## Installed FFmpeg checks

Three small ARM64 fixtures were cross-compiled with the existing toolchain.
They import the installed `libavutil.so.59` functions; production encryption
implementation code is not compiled into the test executables. Dynamic loader
output, library SHA-256 and transferred fixture SHA-256 bind the test to the
shipped library. No private replacement library or image rebuild is involved.

All **10 tests pass**: NULL/empty/small inputs, 20,000-node free and serialization
roundtrip, truncated-final-record cleanup, key-array allocation failure,
zero key size/count, and the upstream encryption-info unit test. The allocator
failure test uses a process-local `av_max_alloc` bound: the structure fits,
the larger key array does not, and restoring the bound permits normal allocation.

Each test has a 256 KiB stack, five CPU seconds, ten-second wall alarm,
256 MiB address-space limit and disabled core dumps. The installed Perl alarm
was separately checked across `exec`; no additional timeout package was needed.
Two initial test-harness failures are retained: a missing `timeout` executable
prevented the first case from starting, then an overstrict test incorrectly
required a NULL pointer for a zero-count allocation. The source permits a
freeable non-NULL zero-size result; the corrected test checks count/key-size
and safe cleanup. No production change was needed for either harness issue.

The camera service PID remains unchanged with zero restarts through these
tests. Target sanitizers, complete allocator-failure injection and the
unresolved quadratic MOV append condition are outside this run; the prior
native sanitizer/failure-site evidence remains in the build record.

## Three reboots and automatic recovery

Recovery is host elapsed time until Wi-Fi SSH, healthy services and pinned HTTPS
return. Camera start uses monotonic time after kernel boot. Each cycle includes
at least twenty seconds of stable operation.

| Cycle | Wi-Fi/web recovery | Camera service start | App restarts | Result |
|---|---:|---:|---:|---|
| 1 | 73.424 s | 6.261 s | 0 | PASS |
| 2 | 40.935 s | 6.357 s | 0 | PASS |
| 3 | 26.720 s | 6.241 s | 0 | PASS |

Four distinct boot IDs were observed. IMX708 NV12 1920×1080 starts automatically
on each boot. Setup remains complete; the default route is through Wi-Fi,
Ethernet is disconnected, and wired wait-online remains inactive. Selected
kernel panic/oops/BUG, symbol/version mismatch and sensor-probe error counts
are zero; no application TLS-identity error was observed.

## Hardware, access and persistence

- HAILO8 firmware **4.24.0**, camera/autofocus/CFE/PiSP, fan and Wi-Fi modules
  operate with Linux **6.18.55-v8-16k**, 16 KiB pages. Final temperature is
  **58.4 °C**, fan **2/4**,
  approximately **5,317 RPM**. This is an operating-point
  observation, not a thermal stress test.
- Codex **0.162.1** reports the restored ChatGPT login, and bundled ripgrep
  **15.2.0** runs. No model request or authentication-file read was performed.
- NTP is synchronized and UTC is within five seconds of the host request
  window. Development repository revision/ownership and normal BusyBox shell
  and AWK controls pass.
- SSH remains key-only; root/non-key login attempts fail. A 128 KiB SFTP
  roundtrip matches. HTTPS assets return 200; unauthenticated AI access returns
  401. Sixteen TLS/unauthenticated RTSPS checks and five OPTIONS selector checks
  pass before and after reboots. No authenticated RTSPS credentials were read.
- Existing firewall, IPv6-interface and core-discard policy persists, with
  policy setup completing before networkd. Restricted helper calls behave
  correctly. Packet injection, core dumps and interface-hotplug are not repeated.
- Root and boot mounts are active/read-write on all four boots. Unprivileged
  `findmnt --verify` remains **LIMITED**: zero parse errors, one error and two
  warnings because stock `/dev/root` has no device node and the account cannot
  read raw block devices. No on-disk filesystem or privileged mount-race
  validation is claimed.

## Security scope and evidence

The build-stage ledger remains **200 fixed, 331 not affected, 11 open, three
partially mitigated/open and one unassessed**, among 546 associations. FFmpeg
remains partial; the separate BusyBox cp configuration exclusion is preserved.
No new vulnerability scan or complete-advisory closure is claimed. This is
Wi-Fi integration acceptance, distinct from a wired/minimal release gate and
long-duration endurance testing.

Working evidence: `.state/security-residual-deployment-2026-10-15/`.
Curated archive with verified `SHA256SUMS`:
`artifacts/20261015T110905Z-e664cb9647e7/rpi5-camera-hailo/security/security-residual-deployment-2026-10-15/`.
Keys, certificates, credentials, cookies, signed app configuration, raw journals,
target executable payloads and SFTP payloads are excluded. Device identifiers
remain in ignored evidence. Original build-stage acceptance status is preserved
in its archived records; this document records subsequent hardware acceptance.
