#!/usr/bin/env python3
"""Generate CycloneDX 1.5 SBOMs for the camera firmware, offline.

  generate_sbom.py --firmware-binary build-current/livetest/apps/camera-firmware/camera-firmware \
      --out-dir docs/security/sbom

Produces:
  firmware.cdx.json  runtime shared libraries of the firmware binary (ldd → dpkg),
                     the vendored sources pinned by cmake/Dependencies.cmake and
                     vendor/, the platform kernel, and the build toolchain
  web.cdx.json       every package resolved in web/package-lock.json

Everything comes from local state (dpkg database, package-lock.json, git); the
only inputs that change between runs are the installed package versions and
the lockfile, so diffs of these files show exactly what changed.
"""
import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import subprocess
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run(cmd, **kw):
    return subprocess.check_output(cmd, text=True, **kw).strip()


def dpkg_packages_for(binary):
    libs = sorted({line.split("=>")[1].split()[0] for line in run(["ldd", binary]).splitlines()
                   if "=>" in line and "/" in line.split("=>")[1]})
    real = sorted({os.path.realpath(l) for l in libs})
    owners = run(["dpkg", "-S"] + real).splitlines()
    names = sorted({o.split(":")[0] for o in owners})
    rows = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\t${Architecture}\t${Homepage}\n"] + names).splitlines()
    comps = []
    for row in rows:
        pkg, ver, src, arch, home = row.split("\t")
        vendor = "raspberrypi" if "rpt" in ver or pkg in ("hailort", "libpisp1") else "debian"
        comp = {"type": "library", "name": pkg, "version": ver,
                "purl": f"pkg:deb/{vendor}/{pkg}@{ver}?arch={arch}",
                "properties": [{"name": "debian:source", "value": src or pkg},
                               {"name": "firmware:linkage", "value": "shared-library (ldd)"}]}
        if home:
            comp["externalReferences"] = [{"type": "website", "url": home}]
        comps.append(comp)
    return comps


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def vendored_components():
    deps = open(os.path.join(ROOT, "cmake", "Dependencies.cmake")).read()
    drogon = re.search(r'_cf_drogon_expected_commit\s+"([0-9a-f]+)"', deps).group(1)
    trantor = re.search(r'_cf_trantor_expected_commit\s+"([0-9a-f]+)"', deps).group(1)
    stb_path = os.path.join(ROOT, "vendor", "stb", "stb_truetype.h")
    stb_version = re.search(r"stb_truetype\.h - v([0-9.]+)", open(stb_path, errors="replace").read()).group(1)
    font_path = os.path.join(ROOT, "vendor", "fonts", "NanumGothicBold.ttf")
    patches = sorted(os.listdir(os.path.join(ROOT, "patches")))
    return [
        {"type": "library", "name": "drogon", "version": "1.9.0",
         "purl": f"pkg:github/drogonframework/drogon@{drogon}",
         "properties": [{"name": "firmware:linkage", "value": "vendored source, static"},
                        {"name": "firmware:patches", "value": ", ".join(p for p in patches if "drogon" in p)}]},
        {"type": "library", "name": "trantor", "version": "1.5.20",
         "purl": f"pkg:github/an-tao/trantor@{trantor}",
         "properties": [{"name": "firmware:linkage", "value": "vendored source, static"},
                        {"name": "firmware:patches", "value": ", ".join(p for p in patches if "trantor" in p)}]},
        {"type": "library", "name": "stb_truetype.h", "version": stb_version,
         "purl": f"pkg:github/nothings/stb@master#stb_truetype.h",
         "hashes": [{"alg": "SHA-256", "content": sha256(stb_path)}],
         "properties": [{"name": "firmware:linkage", "value": "vendored header, compiled into camera_firmware_media"},
                        {"name": "firmware:input-trust", "value": "parses only the embedded NanumGothicBold font (build-time asset)"}]},
        {"type": "data", "name": "NanumGothicBold.ttf", "version": "fonts-nanum 20200506-1",
         "purl": "pkg:deb/debian/fonts-nanum@20200506-1",
         "hashes": [{"alg": "SHA-256", "content": sha256(font_path)}],
         "licenses": [{"license": {"id": "OFL-1.1"}}],
         "properties": [{"name": "firmware:linkage", "value": "embedded in .rodata (.incbin)"}]},
    ]


def platform_components():
    kernel = run(["uname", "-r"])
    gcc = run(["gcc", "-dumpfullversion"])
    cmake = run(["cmake", "--version"]).splitlines()[0].split()[-1]
    node = run(["node", "--version"]).lstrip("v")
    npm = run(["npm", "--version"])
    return [
        {"type": "operating-system", "name": "linux-rpi", "version": kernel,
         "purl": f"pkg:generic/raspberrypi/linux@{kernel}",
         "properties": [{"name": "firmware:role", "value": "kernel image covered by the integrity manifest"}]},
        {"type": "application", "name": "gcc", "version": gcc, "purl": f"pkg:deb/debian/gcc-14@{gcc}",
         "properties": [{"name": "firmware:role", "value": "build toolchain"}]},
        {"type": "application", "name": "cmake", "version": cmake, "purl": f"pkg:deb/debian/cmake@{cmake}",
         "properties": [{"name": "firmware:role", "value": "build toolchain"}]},
        {"type": "application", "name": "node", "version": node, "purl": f"pkg:generic/nodejs@{node}",
         "properties": [{"name": "firmware:role", "value": "web build toolchain"}]},
        {"type": "application", "name": "npm", "version": npm, "purl": f"pkg:npm/npm@{npm}",
         "properties": [{"name": "firmware:role", "value": "web build toolchain"}]},
    ]


def integrity_hashes(integrity):
    """Convert npm SRI base64 digests to validated CycloneDX hex digests."""
    lengths = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
    if not isinstance(integrity, str) or not integrity.split():
        raise ValueError("invalid npm integrity value")
    hashes = []
    for value in integrity.split():
        algorithm, _, encoded = value.partition("-")
        if algorithm not in lengths:
            raise ValueError(f"unsupported npm integrity algorithm: {algorithm}")
        try:
            digest = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError(f"invalid {algorithm} integrity encoding") from error
        if len(digest) != lengths[algorithm]:
            raise ValueError(f"invalid {algorithm} integrity length")
        hashes.append({"alg": algorithm.upper().replace("SHA", "SHA-"),
                       "content": digest.hex()})
    return hashes


def web_components():
    with open(os.path.join(ROOT, "web", "package-lock.json"), encoding="utf-8") as source:
        lock = json.load(source)
    direct = set(lock["packages"][""].get("dependencies", {})) | set(lock["packages"][""].get("devDependencies", {}))
    comps = []
    for path, meta in lock["packages"].items():
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        comp = {"type": "library", "name": name, "version": meta.get("version", ""),
                "purl": f"pkg:npm/{name}@{meta.get('version', '')}",
                "scope": "excluded" if meta.get("dev") else "required",
                "properties": [{"name": "web:dependency-kind", "value": ("direct" if name in direct else "transitive") + (", dev" if meta.get("dev") else "")}]}
        if meta.get("integrity"):
            comp["hashes"] = integrity_hashes(meta["integrity"])
        if meta.get("license") and isinstance(meta["license"], str):
            comp["licenses"] = [{"license": {"id": meta["license"]}}]
        comps.append(comp)
    comps.sort(key=lambda c: c["name"])
    return comps


def bom(name, version, description, components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
            "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                         "tools": [{"name": "generate_sbom.py", "version": "1"}],
                         "component": {"type": "application", "name": name, "version": version, "description": description}},
            "components": components}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--firmware-binary", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    version = run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"])
    os.makedirs(args.out_dir, exist_ok=True)
    fw = bom("camera-firmware", version, "Raspberry Pi 5 + Hailo camera firmware (native binary)",
             dpkg_packages_for(args.firmware_binary) + vendored_components() + platform_components())
    web = bom("camera-firmware-web", version, "Management web UI served by the firmware (web/dist)", web_components())
    for fname, doc in (("firmware.cdx.json", fw), ("web.cdx.json", web)):
        with open(os.path.join(args.out_dir, fname), "w") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
            f.write("\n")
        print(f"{fname}: {len(doc['components'])} components")


if __name__ == "__main__":
    main()
