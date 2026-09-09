# Security evidence (TTA 10.x)

This directory holds the artifacts that back the certification items on known
vulnerabilities (TTA 10.2) and source weaknesses (TTA 10.1). Everything here is
regenerated from the repository plus the development device; nothing is
hand-typed except the assessment prose.

| File | What it is |
|---|---|
| `dependency-inventory.md` | Human-readable inventory: firmware runtime packages, vendored sources, platform, web packages, toolchain |
| `sbom/firmware.cdx.json`, `sbom/web.cdx.json` | CycloneDX 1.5 SBOMs (`tools/security/generate_sbom.py`) |
| `vulnerability-scan-<date>.md` | The known-vulnerability scan record for that date: sources, findings with CVE/GHSA ids, status, and the remediation taken |
| `scan-<date>/` | Raw scan outputs the record was written from |
| `static-analysis-<date>.md` | TTA 10.1 record: clang-tidy/clang-format configuration, baseline counts, fixes |

## Regenerating the SBOMs

```bash
python3 tools/security/generate_sbom.py \
  --firmware-binary build-current/livetest/apps/camera-firmware/camera-firmware \
  --out-dir docs/security/sbom
```

Offline. Uses `ldd` + `dpkg` for the runtime libraries, `cmake/Dependencies.cmake`
and `vendor/` for the vendored sources, and `web/package-lock.json` for the web.

## Running the vulnerability scan

1. **Debian packages** — download the public tracker dump and match it offline:
   ```bash
   curl -fsSL -o /tmp/debian-security-tracker.json https://security-tracker.debian.org/tracker/data/json
   date -u +%FT%TZ > docs/security/scan-<date>/debian-tracker-snapshot-time.txt
   ldd build-current/livetest/apps/camera-firmware/camera-firmware | awk '/=>/{print $3}' \
     | xargs -r realpath | sort -u | xargs -r dpkg -S | cut -d: -f1 | sort -u > /tmp/pkgs.txt
   python3 tools/security/scan_debian.py --tracker /tmp/debian-security-tracker.json \
     --packages /tmp/pkgs.txt --release trixie \
     --markdown docs/security/scan-<date>/debian-tracker-open-cves.md \
     --json docs/security/scan-<date>/debian-tracker-findings.json
   ```
   `VULNERABLE` = the installed version is older than Debian's fix (apply the update);
   `OPEN` = Debian has no fix yet (assess exposure); `NOT-IN-TRACKER` = a Raspberry Pi /
   vendor package that Debian does not track (check upstream).
2. **Web packages** — `cd web && npm audit --json` (queries the npm advisory database).
   Fix with `npm audit fix`, or upgrade the direct dependency when the advisory spans a
   whole major line; re-run the web test suite and `npm run build`.
3. **Vendored C++ sources and vendor packages** — query NVD by keyword
   (`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<name>`) and OSV by
   commit (`POST https://api.osv.dev/v1/query {"commit": "<sha>"}`) for Drogon, Trantor,
   stb, libcamera, HailoRT. Record every hit with its affected range and our verdict.
4. Write `vulnerability-scan-<date>.md` from the outputs: one row per finding with
   component, version, id, severity, status (`fixed` / `not affected` + reason /
   `mitigated` / `open`), and the commit that closed it.

Only public package names, versions and commit ids leave the device during a scan.
