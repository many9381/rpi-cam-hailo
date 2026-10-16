# Initial setup session recovery — 2026-10-12

## Scope and incident boundary

This change addresses the setup-session and error-reporting follow-up from
[the library-image deployment check](library-deployment-validation-2026-10-12.md).
The original failed HTTP response was not captured. A roughly 19-minute forward
clock correction was observed on that boot, and the server uses a 600-second
wall-clock session deadline. This can explain an expired session but does **not**
establish the cause of that particular user failure.

Two independently reproducible UI defects are fixed: a rejected setup session
previously left the operator in the wizard, and unrelated failures all displayed
an instruction to check credentials.

## Applied changes

- After setup initialization returns HTTP 401, unmount the wizard, discard the
  entered passwords, fetch current setup state and initial credentials, and
  explain that the operator needs to sign in again.
- Refresh failure or a five-second timeout offers a retry instead of presenting
  stale initial credentials or leaving the failed wizard active.
- Honor a device that has already progressed to runtime recovery or operational
  mode, including when the response to a successful request was lost. Do not
  automatically resubmit administrator creation.
- Display allowlisted Korean/English guidance for account/password/IP input,
  changed peer address, rejected request origin, rate limiting, and server
  failure. Unknown or network failures use a neutral connection/result message.
  Raw server messages and transport details are never rendered.
- Retain non-secret wizard entries on ordinary validation failures; clear
  passwords after submission. Reauthentication starts a fresh wizard and the
  notice explicitly tells the operator to re-enter administrator details.

The server's session lifetime, password policy, peer binding, Origin checks,
database format, and account/IP authorization behavior are unchanged. No live
device clock, account, configuration, or installation was changed for this work.

## Firmware and layer integration

Firmware changes are in `web/src/App.tsx`, `pages/LoginPage.tsx`, the setup wizard,
its public-error mapper, and both message dictionaries. Regression tests use the
real API client with simulated HTTP responses. A C++ characterization test uses
the existing fake clock and real authentication service/store to reproduce
initial-account session expiry and successful relogin after 600 or 1,140 seconds.

Layer patch:
`meta-rpi-cam-hailo/recipes-camera/camera-firmware/files/0007-setup-session-recovery-and-error-messages.patch`.
It is applied to `camera-firmware-web` and to the optional editable
`/home/rpiadmin/rpi-cam-hailo` development checkout. The backend production source
is unchanged; the C++ addition is a test only.

Both recipe patch sequences were applied to pinned upstream commit
`ba503a1fbc4ed68c1fd29aace7214a5c330d7021` with whitespace errors rejected, then all
nine affected source files were compared byte-for-byte with the tested checkout.

## Validation

| Check | Result |
|---|---|
| Before-fix UI reproduction | 12 of 13 cases failed; the completed-setup control passed |
| Final web suite (`npm test`) | 768 tests / 56 files passed, including 14 new setup cases |
| TypeScript and production web build | Passed |
| Host authentication/security/configuration harness | 484 tests passed |
| Yocto host suite | 365 tests passed |
| Independent code review | No blocking findings |
| Web/devrepo patch application and source comparison | Passed |
| Hailo image build | Passed; 7,786 tasks, 64 rerun, no warnings/errors |
| Actual WIC checks | Passed; 15 files compared with the assembled rootfs |
| New image installation and physical first-boot validation | Passed in the subsequent deployment check linked below |

The initial C++ characterization run had one incorrect expected internal error
code (`E_AUTHENTICATION_REQUIRED` instead of the existing
`E_AUTHENTICATION_FAILED`). The expectation was corrected without changing the
server. Both codes map to HTTP 401 and are covered by the web regression tests.

The three web assets inside the image match the locally tested production
build. The nine affected development-source files match the tested checkout.
The backend executable is byte-identical to the previously validated image.
Image checksums, source provenance, camera/Wi-Fi rootfs checks and the public
configuration-signing identity passed. Codex login credentials and device-private
TLS/configuration files are absent from the image; installation provisions them
separately as before.

Working evidence is in `.state/setup-session-recovery-2026-10-12/` in the parent
Yocto checkout. A curated copy with its own `SHA256SUMS` is under
`artifacts/20261012T162756Z-e664cb9647e7/rpi5-camera-hailo/security/setup-session-recovery-2026-10-12/`.
This is a setup reliability correction, not a new CVE audit or a claim that
remaining library/kernel findings are closed.

## Deployment boundary

Target build: `20261012T162756Z-e664cb9647e7`, profile `rpi5-camera-hailo`.
The currently running, previously validated Pi image is not modified by building
this replacement. After installation, confirm initial setup and normal
video/Hailo operation on the new image; existing-device reboot evidence does not
replace that check. Simulated expiry is automated and does not require changing
the live Pi's clock.

The completed image is selected by the existing `scripts/install-ssd.sh` installer
after the registered SSD is connected to the build host. Only the Hailo profile
was built; no QEMU build or run was required.

## Subsequent deployment validation

The new image was subsequently installed and verified on the Pi. Initial setup
completed without errors, installed files matched, three Wi-Fi reboots passed,
and the user confirmed normal video and Hailo inference after the final reboot.
See [the deployment validation record](setup-session-deployment-validation-2026-10-12.md).
The original build-time archive remains unchanged; live forced expiry was not
performed on the configured device.
