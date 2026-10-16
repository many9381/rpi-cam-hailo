# Raspberry Pi kernel security follow-up — 2026-10-13

This pass reassesses the **108 open and 93 inconclusive kernel associations**
left by the [previous kernel review](kernel-followup-2026-10-12.md).
The accepted device baseline is `20261012T172633Z-e664cb9647e7`, whose
[deployment acceptance](library-closure-deployment-validation-2026-10-13.md)
is separate evidence. The new Hailo image is
`20261013T124642Z-e664cb9647e7`.

**Integrated build and actual-WIC verification passed. Hardware acceptance of this new image has not been performed.**

| Kernel disposition | Before | After |
|---|---:|---:|
| Source-fixed | 26 | 55 |
| Specific source/configuration/image exclusions | 176 | 285 |
| Identified unresolved condition | 108 | 45 |
| Applicability or source equivalence unresolved | 93 | 18 |
| **Original associations** | **403** | **403** |

These are advisory associations, not confirmed exploits. A source correction takes precedence in the table when an optional module is also absent; the underlying record retains both facts.

## Layer changes

The kernel stays at Raspberry Pi Linux **6.18.55**, source pin
`4103a989a46196239b830bd07693277e42b8f992`, release `6.18.55-v8-16k`.
Thirteen additional patches are registered in
`meta-rpi5-cam/recipes-kernel/linux/linux-raspberrypi_6.18.bbappend` alongside
the existing thirteen. No feature disablement or blanket recipe-level
`CVE_STATUS` suppression is used.

| CVE | Correction and primary upstream source |
|---|---|
| CVE-2026-80580 | [Bound fbdev mode sysfs formatting](https://git.kernel.org/stable/c/d15d51fb26e830af58f3f21964f1c09c239077ea), including all callers and remaining page capacity. |
| CVE-2026-98376 | [Check per-CPU inner-map dimensions](https://git.kernel.org/stable/c/593980175389a05793f6060aa20e626330960395), retaining the upstream BPF selftest. |
| CVE-2026-80634 | [Prevent bridge VLAN untag count underflow](https://git.kernel.org/stable/c/e052f920773b73be49eb4d8702a9f85de7464363). The module was already absent from the accepted image; this additionally corrects its source. |
| CVE-2026-23374 | [Record blktrace command names after reservation](https://git.kernel.org/stable/c/e5584932ac1dacc182c430d09e2b5490d1d4372b), when the successful ring-buffer reservation holds preemption disabled. |
| CVE-2026-98147 | [Handle expected printk thread-creation errors without WARN](https://git.kernel.org/stable/c/72dd0ec09e7cc98ed58ddeac26575e5d1ab8a93d), preserving failure logging and cleanup. |
| CVE-2026-80579 | [Clear a deleted fbdev mode pointer](https://git.kernel.org/stable/c/95e647d2a5304a8fd11f1ba3c8502de700650131), preserving refused and unrelated-mode behavior. |
| CVE-2026-80738 | [Check socket state before full-socket protocol fields](https://git.kernel.org/stable/c/31a420a822ff92e2090bd5d65efe8e34e2d6d9b8), in both BPF syncookie helpers. |
| CVE-2026-90217 | [Compare iterator register types during verifier pruning](https://git.kernel.org/linus/83608e303b95d07afba1c15da0b5d9e513c2f15a). |
| CVE-2026-98085 | [Backtrack implicit subprogram exits](https://git.kernel.org/linus/387b1baefbb776e3f48dc2261e77a49213f470f7) for legacy ABS/IND loads. |
| CVE-2026-93125 | [Bound kfunc return-buffer size before narrowing](https://git.kernel.org/linus/2aaf67f0516fde29620d0edfc29c01b9ea7ad430). |
| CVE-2026-90177 | [Record every atomic destination pointer type](https://git.kernel.org/linus/4bc49ae344d65cfcef738f281ac575cf73ca2fc5), retaining ordinary pointer-transition compatibility. |
| CVE-2026-98049 | [Recognize arena compare/exchange for zero extension](https://git.kernel.org/linus/4814ed6406f3493bd554ad046da5f7fc04833571). The existing ARM64 W-register CASAL/LDXR implementation already zero-extends; this source correction does not establish a Pi exploit. |
| CVE-2026-74336 | [Bound S1G TIM reads by payload length](https://git.kernel.org/linus/b224d18b1e5d1cddfc67f63f41d80023b2ec8889), excluding the adjacent element's bytes. |

The BPF verifier pieces and S1G helper were mapped from newer split files to
their exact 6.18 implementations. Existing diagnostic/register APIs were
preserved. Patch manifests record every adaptation and hash; the remaining
seven patches retain their complete upstream diffs.

## Corrected image-exposure assessment

`CONFIG_FEATURE=m` does not establish that the module is installed. The accepted
WIC has **25 modules**. Each new module exclusion connects the affected source
to its complete Kbuild/configuration gates, retained compiled-object membership
where available, WIC inventory and builtin-module metadata. Unobserved runtime loading alone is
not evidence of absence. Optional sources and separately produced module
packages retain their own unresolved status before future use.

For example, **CVE-2026-93047 (V3D BO lifetime)** remains **open in the kernel
source**, while this exact image excludes the path because V3D is neither an
installed module nor builtin. No V3D patch or configuration change was applied.
The draft moved BO ownership/dependencies toward the consuming jobs, but
testing exposed incomplete indirect-CPU allocation/unwind handling. The baseline
ran 117 bounded cases with 33 failures; the draft ran 121 with 29 failures.
Normal-path improvements did not justify integrating a failing candidate.
Future V3D enablement requires ownership/PM/fence/reservation cleanup repair,
passing failure-injection controls, compilation and actual GPU validation.

Other specific exclusions include the absent introducing kernfs xattr-cache
behavior (with SELinux also disabled), disabled conntrack BPF integration, and
the absent NFSD provider for the affected builtin lockd path. These conclusions
are narrower than excluding whole source subsystems.

All **201 selected records** were individually reassessed against current primary records and frozen source evidence. The other **202 previously resolved records** retain their prior conclusions, bound to unchanged source/configuration evidence. This pass also established **16 existing source corrections** among the previously inconclusive records; these are not new layer patches.

Independent review required an ext4 group-0 initialization claim (CVE-2018-10876) to remain inconclusive because full replacement-path equivalence was not established. Historical commit ancestry by itself is not proof that a current implementation retains a complete fix. Every unresolved record retains its concrete missing evidence or next action in the CSV/JSON ledger.

For the **539 original whole-image associations**, current totals are: 144 fixed, 321 specifically excluded, 54 open, 2 partially mitigated/open, 18 inconclusive. Non-kernel assessments were carried forward without new closure claims.

Raw scanner affected/under-investigation associations changed **455 → 442**. Raw version/patch metadata output is separate from this source-and-image ledger. There are 0 additional unresolved raw associations outside the original 539-record comparison.

## Verification and limits

The project host suite passed **365 tests**. All **13 focused regression groups**
reproduce their expected failures on the pre-fix source and pass with the
combined corrections. Full fbdev, flowtable, blktrace, printk and syncookie
functions are exercised with bounded kernel adapters; other verifier checks
exercise exact decision paths. Seven groups use UBSan. The S1G parser tests
include valid single/block/OLB controls and adjacent-element truncation.

Independent review compared primary upstream changes, complete caller context,
patch hashes and combined source hashes. Regression runners propagate failure
through their exit status. Verification tooling also rejects stale PASS records,
wrong build IDs and GNU patch's implicit direction reversal. These checks are
not complete kernel selftests, concurrency proofs or target exploit tests.
The upstream per-CPU BPF syscall selftest is retained but was not run on Pi.

The final kernel is byte-bound to its compiled and deployed Image. All **26 local patches** reverse and reapply without fuzz or automatic direction switching; all **11 changed source paths** match the combined reviewed candidate, and **545 other assessed source files** retain their baseline identities. The final-source regression groups pass again against the actual BitBake source.

Kernel configuration and all **19,428 Module.symvers rows** are byte-identical to the baseline. This verifies recorded export CRC/signature compatibility, not every possible ABI or runtime interaction. The actual WIC contains exactly the expected kernel release tree and **25 modules**, with matching module hashes/vermagic and preserved builtin metadata.

Actual-WIC checks verified **76 files**, including the **51 protected userspace files**, camera/web/Codex executables and all installed modules. The **16 privileged executable modes/owners** are preserved; no ORIGIN RPATH/RUNPATH was introduced. All **182 installed shared libraries** retain their SONAME/export compatibility; **0 library files changed**. Libcamera and both IPA modules/signatures remain byte-identical to the accepted image.

Boot configuration is unchanged, camera auto-detection is retained, and the WIC IMX708 overlay matches the deployed build. Package versions/set, camera/Wi-Fi rootfs rules, time-service ordering, source provenance, signing identity and artifact checksums pass. Image credentials, generated application configuration, device TLS private key and provisioned timesync clock remain absent.

| Artifact | SHA-256 |
|---|---|
| Compressed WIC | `b1409682781aabbab917f9340d781aea8223d527ff353e87743bb599fd86014f` |
| Kernel Image | `5db06314fc343ed828b9e95243468440ac5bcda27ff03e5f838871ff6b8fc93a` |
| Kernel configuration | `751ecdb597addf24fb7e2eb954cc28e4fc523983665e294c032dd11cd0ca8250` |

No Pi or SSD was modified in this pass. The accepted running image's previous
video/Hailo confirmation does not validate this newly compiled kernel. Install
the new image with `scripts/install-ssd.sh` and perform separate boot,
Wi-Fi/clock/Codex, camera and Hailo acceptance. QEMU/minimal builds and the
user-excluded long-duration tests were not performed.

## Reproducible evidence

The working evidence is Git-excluded under
`.state/kernel-followup-2026-10-13/`. Historical ledgers and accepted artifacts
are preserved. Main records are `kernel-assessment.json/.csv` (403 rows),
`integrated-assessment.json/.csv` (539 original associations), individual
primary records/source snapshots, patch manifests, independent reviews,
regression results and build/image verification.

Curated evidence is archived with per-file `SHA256SUMS` at
`artifacts/20261013T124642Z-e664cb9647e7/rpi5-camera-hailo/security/kernel-followup-evidence/`.
The original scanner output and its exact database-snapshot metadata are retained in the sibling `cve-scan/` and `scanner-evidence/` directories. Source excerpts, rejected V3D draft evidence and focused test adapters are retained for reproducibility; rejected drafts are not part of the layer.

The full-image raw scanner uses the retained **2026-10-11 database snapshot**;
the 201 selected kernel primary records were refreshed on **2026-10-13**.
No fresh whole-database scan or whole-image security PASS is claimed.
Library, FFmpeg MOV and separate BusyBox `cp` follow-ups remain outside this
kernel pass. Candidate associations are not counts of confirmed exploits.
