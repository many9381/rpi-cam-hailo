#!/usr/bin/env python3
"""Match the firmware's installed Debian packages against the Debian security tracker.

Usage:
  scan_debian.py --tracker debian-security-tracker.json --packages pkgs.txt \
      [--release trixie] [--markdown out.md] [--json out.json]

`pkgs.txt` holds one binary package name per line (e.g. from `ldd` of the firmware
binary resolved through `dpkg -S`). The tracker JSON is the public dump from
https://security-tracker.debian.org/tracker/data/json (record its download time
in the scan report). For every CVE the tracker lists for a package's SOURCE
package, the script reports whether the installed version already carries the
fix (resolved), is older than the fixing version (VULNERABLE), or whether the
release has no fix yet (OPEN). Versions are compared with `dpkg --compare-versions`.
No network access is needed once the tracker dump is on disk.
"""
import argparse
import json
import subprocess
import sys
from collections import defaultdict


def installed(packages):
    out = subprocess.check_output(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\n"] + packages,
        text=True)
    rows = []
    for line in out.splitlines():
        name, version, source = line.split("\t")
        rows.append((name, version, source or name))
    return rows


def dpkg_lt(left, right):
    return subprocess.call(["dpkg", "--compare-versions", left, "lt", right]) == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tracker", required=True)
    ap.add_argument("--packages", required=True)
    ap.add_argument("--release", default="trixie")
    ap.add_argument("--markdown")
    ap.add_argument("--json")
    args = ap.parse_args()

    tracker = json.load(open(args.tracker))
    packages = [p.strip() for p in open(args.packages) if p.strip()]
    findings = []
    covered = 0
    for name, version, source in installed(packages):
        entries = tracker.get(source)
        if entries is None:
            findings.append({"package": name, "source": source, "installed": version,
                             "cve": None, "status": "NOT-IN-TRACKER"})
            continue
        covered += 1
        for cve, info in entries.items():
            rel = info.get("releases", {}).get(args.release)
            if rel is None:
                continue
            status = rel.get("status")
            fixed = rel.get("fixed_version")
            urgency = rel.get("urgency", "")
            if status == "resolved" and fixed:
                verdict = "VULNERABLE" if dpkg_lt(version, fixed) else "resolved"
            elif status == "resolved":
                verdict = "resolved"
            elif status == "open":
                verdict = "OPEN"
            else:
                verdict = status or "undetermined"
            if verdict in ("VULNERABLE", "OPEN"):
                findings.append({"package": name, "source": source, "installed": version,
                                 "cve": cve, "status": verdict, "fixed_version": fixed,
                                 "urgency": urgency, "description": info.get("description", "")})
    findings.sort(key=lambda f: (f["status"], f["package"], f["cve"] or ""))
    summary = defaultdict(int)
    for f in findings:
        summary[f["status"]] += 1
    print(f"packages checked: {len(packages)}, in tracker: {covered}; findings: {dict(summary)}")
    if args.json:
        json.dump({"release": args.release, "summary": dict(summary), "findings": findings},
                  open(args.json, "w"), indent=1)
    if args.markdown:
        with open(args.markdown, "w") as out:
            out.write("| Package | Installed | Source | CVE | Status | Fixed in | Urgency | Description |\n")
            out.write("|---|---|---|---|---|---|---|---|\n")
            for f in findings:
                if f["cve"] is None:
                    out.write(f"| {f['package']} | {f['installed']} | {f['source']} | — | not in Debian tracker (RPi/vendor package) | — | — | — |\n")
                else:
                    out.write(f"| {f['package']} | {f['installed']} | {f['source']} | {f['cve']} | {f['status']} | {f.get('fixed_version') or '—'} | {f.get('urgency','')} | {f.get('description','')[:120]} |\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
