#!/usr/bin/env python3
"""Pull verified NAS export manifests and ZIPs, then import all discovered sources.

Run as ai-monitor on Debian. Uses existing SMB auth files and importer. No AI,
email, or scheduling. Unavailable sources remain visible in the source registry.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

import runpy
_settings_module = runpy.run_path(str(Path(__file__).with_name('settings.py')))
SETTINGS = _settings_module['load']()


spec = importlib.util.spec_from_file_location("synology_import", Path(__file__).with_name("import_synology.py"))
importer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(importer)
NAS = {"home": SETTINGS["home_nas"], "work": SETTINGS["work_nas"]}
RUN = re.compile(r"^(home|work)-\d{8}T\d{6}Z-[a-f0-9]{8}$")


def digest(path):
    sha = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def save_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix=".registry-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def get_smb(site, remote, local, auth_dir):
    if not (remote == site + "-manifest.json" or re.fullmatch(
            re.escape(site) + r"-\d{8}T\d{6}Z-[a-f0-9]{8}/asset-[a-f0-9]{32}\.zip", remote)):
        raise ValueError("Unsafe remote export path")
    if any(char in str(local) for char in ('"', '\n', '\r', '\\')):
        raise ValueError("Unsafe local SMB destination path")
    command = ["smbclient", "//" + NAS[site] + "/Logs", "-p", "445", "-t", "60",
               "--option=client min protocol=SMB2", "-A", str(Path(auth_dir) / (site + ".smb")),
               "-D", "AI-Monitor-Exports", "-c", 'get "' + remote + '" "' + str(local) + '"']
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=180, text=True, errors="replace")
    if result.returncode or not local.is_file():
        raise RuntimeError("SMB download failed: " + result.stdout[-1200:])


def mounted_getter(root):
    """Read finalized exports from ro bind mounts; never open live NAS databases."""
    root = Path(root).resolve(strict=True)
    def get(site, remote, local, auth_dir):
        if site not in NAS or not (remote == site + '-manifest.json' or re.fullmatch(
                re.escape(site) + r'-\d{8}T\d{6}Z-[a-f0-9]{8}/asset-[a-f0-9]{32}\.zip', remote)):
            raise ValueError('Unsafe mounted export path')
        share = root / site
        if share.is_symlink():
            raise ValueError('Share mount must not be a symbolic link')
        if os.name == 'posix' and not os.statvfs(share).f_flag & os.ST_RDONLY:
            raise ValueError('NAS export mount must be read-only: ' + site)
        source = share / 'AI-Monitor-Exports' / remote
        for candidate in (source, *source.parents):
            if candidate == root:
                break
            if candidate.is_symlink():
                raise ValueError('Symbolic links are not accepted in mounted exports')
        resolved = source.resolve(strict=True)
        resolved.relative_to(share.resolve(strict=True))
        limit = 2*1024**2 if remote.endswith('.json') else 128*1024**2
        if not resolved.is_file() or resolved.stat().st_size > limit:
            raise ValueError('Mounted export is missing or exceeds the size limit')
        with resolved.open('rb') as incoming, Path(local).open('wb') as outgoing:
            total = 0
            while chunk := incoming.read(1024*1024):
                total += len(chunk)
                if total > limit:
                    raise ValueError('Mounted export grew beyond its size limit')
                outgoing.write(chunk)
    return get


def validate_manifest(value, site):
    if value.get("producer") != "ai-monitor-site-export-v1" or value.get("format_version") != 1 or value.get("site") != site:
        raise ValueError("Manifest producer, version, or site mismatch")
    run_id = value.get("run_id", "")
    if not RUN.fullmatch(run_id) or not run_id.startswith(site + "-"):
        raise ValueError("Invalid export run ID")
    if value.get("status") not in ("complete", "partial") or not isinstance(value.get("sources"), dict):
        raise ValueError("Invalid manifest status or source list")
    assets = value.get("assets")
    if not isinstance(assets, list) or len(assets) > 2000 or not isinstance(value.get("errors"), list):
        raise ValueError("Invalid or excessive manifest assets")
    seen = set()
    for source in value["sources"]:
        if not isinstance(source, str) or not source or len(source) > 256 or any(ord(char) < 32 for char in source):
            raise ValueError("Invalid source label")
    for asset in assets:
        remote = asset.get("file", "")
        if not re.fullmatch(re.escape(run_id) + r"/asset-[a-f0-9]{32}\.zip", remote) or remote in seen:
            raise ValueError("Invalid or repeated asset filename")
        seen.add(remote)
        if asset.get("source") not in value["sources"] or asset.get("kind") not in ("live", "archive"):
            raise ValueError("Invalid asset source or kind")
        if not re.fullmatch(r"[a-f0-9]{64}", asset.get("sha256", "")):
            raise ValueError("Invalid asset checksum")
        if type(asset.get("bytes")) is not int or not 1 <= asset["bytes"] <= 128 * 1024 ** 2:
            raise ValueError("Asset exceeds size limits")
        if type(asset.get("rows_exported")) is not int or asset["rows_exported"] < 0:
            raise ValueError("Invalid asset row count")
        if type(asset.get("invalid_utf8_rows", 0)) is not int or not 0 <= asset.get("invalid_utf8_rows", 0) <= asset["rows_exported"]:
            raise ValueError("Invalid asset text-decoding row count")
    return value


def timestamp(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Export timestamp lacks a timezone")
    return int(parsed.timestamp())


def collect(base, sites=("home", "work"), auth_dir=Path("/etc/ai-monitor"), getter=get_smb):
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    history = base / "events.sqlite"
    registry_path = base / "site-registry.json"
    registry = json.loads(registry_path.read_text()) if registry_path.exists() else {"format_version": 1, "sites": {}}
    results = {}
    for site in sites:
        previous = registry["sites"].get(site, {})
        cache = base / "cache" / site
        cache.mkdir(parents=True, exist_ok=True)
        try:
            with tempfile.TemporaryDirectory(prefix=".fetch-", dir=str(cache)) as temporary:
                manifest_path = Path(temporary) / "manifest.json"
                getter(site, site + "-manifest.json", manifest_path, auth_dir)
                if manifest_path.stat().st_size > 2 * 1024 ** 2:
                    raise ValueError("Manifest exceeds 2 MiB")
                manifest = validate_manifest(json.loads(manifest_path.read_text(encoding="utf-8")), site)
            finished = timestamp(manifest["finished_utc"])
            warnings = [error["input"] + ": " + error["error"] for error in manifest["errors"]]
            if time.time() - finished > 7200:
                warnings.append("NAS export is over two hours old; rerun its export task.")
            if finished > time.time() + 300:
                warnings.append("NAS export timestamp is in the future; check clocks.")
            if manifest["status"] == "partial" and not warnings:
                warnings.append("NAS marked this export as partial.")
            entry = {"nas_name": manifest["nas_name"], "run_id": manifest["run_id"],
                     "exported_utc": finished, "collected_utc": int(time.time()),
                     "lookback_hours": manifest["lookback_hours"], "warnings": warnings,
                     "empty_folders": manifest["empty_folders"], "sources": {}}
            for source, info in manifest["sources"].items():
                entry["sources"][source] = {"file": manifest["run_id"], "exported_utc": None,
                    "warnings": [], "has_live_database": bool(info.get("has_live_database")),
                    "assets_imported": 0, "rows_in_export": 0}
                if not info.get("has_live_database"):
                    entry["sources"][source]["warnings"].append("Archive-only source: no live database was found.")
            stats = {"assets_imported": 0, "rows_read": 0, "new_rows": 0, "duplicate_rows": 0}
            for asset in manifest["assets"]:
                info = entry["sources"][asset["source"]]
                path = cache / asset["file"]
                path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    if not path.is_file() or path.stat().st_size != asset["bytes"] or digest(path) != asset["sha256"]:
                        temporary = path.with_suffix(".part")
                        try:
                            getter(site, asset["file"], temporary, auth_dir)
                            if temporary.stat().st_size != asset["bytes"] or digest(temporary) != asset["sha256"]:
                                raise ValueError("Downloaded ZIP does not match the NAS manifest")
                            os.replace(str(temporary), str(path))
                        finally:
                            if temporary.exists():
                                temporary.unlink()
                    print(site + ": importing " + json.dumps(asset["source"]) + " (" + asset["kind"] + ")", file=sys.stderr, flush=True)
                    result = importer.import_archive(path, history, site, asset["source"])
                    if result["rows_read"] != asset["rows_exported"]:
                        raise ValueError("Imported row count differs from the NAS manifest")
                    stats["assets_imported"] += 1
                    for key in ("rows_read", "new_rows", "duplicate_rows"):
                        stats[key] += result[key]
                    info["assets_imported"] += 1
                    info["rows_in_export"] += result["rows_read"]
                    exported = timestamp(asset["exported_at_utc"])
                    info["exported_utc"] = max(info["exported_utc"] or 0, exported)
                    if asset.get("untimed_rows") and "Records with missing timestamps are present." not in info["warnings"]:
                        info["warnings"].append("Records with missing timestamps are present.")
                    if asset.get("future_timestamp_rows"):
                        info["warnings"].append("An export includes a future timestamp; inspect source clocks.")
                    if asset.get("invalid_utf8_rows"):
                        info["warnings"].append(asset["input"] + ": " + str(asset["invalid_utf8_rows"]) +
                            " exported rows contain invalid UTF-8 text. Readable previews remain; original bytes are retained on the NAS and in restricted export caches, and omitted from sanitized records.")
                except Exception as error:
                    warning = asset["input"] + ": " + str(error)
                    info["warnings"].append(warning)
                    entry["warnings"].append(warning)
            for source, info in entry["sources"].items():
                if not info["assets_imported"]:
                    info["warnings"].append("No export asset was successfully imported for this source.")
                    entry["warnings"].append(source + ": no successfully imported asset.")
            for source, info in previous.get("sources", {}).items():
                if source not in entry["sources"]:
                    retained = dict(info)
                    retained["warnings"] = ["Missing from latest discovery; only previously imported history is available."]
                    entry["sources"][source] = retained
                    entry["warnings"].append(source + ": absent from the latest NAS discovery.")
            if not entry["sources"]:
                entry["warnings"].append("No sources discovered; log coverage is unavailable.")
            entry["status"] = "partial" if entry["warnings"] else "complete"
            registry["sites"][site] = entry
            results[site] = dict(stats, status=entry["status"], sources=len(entry["sources"]), warnings=entry["warnings"])
            save_json(cache / "last-manifest.json", manifest)
            # Keep current and one previous tool-generated cache run only.
            runs = sorted((p for p in cache.iterdir() if p.is_dir() and not p.is_symlink() and RUN.fullmatch(p.name)),
                          key=lambda p: p.stat().st_mtime_ns)
            old = [p for p in runs if p.name != manifest["run_id"]]
            for directory in old[:max(0, len(runs) - 2)]:
                if directory.resolve().parent != cache.resolve():
                    raise ValueError("Cache cleanup escaped its expected directory")
                shutil.rmtree(str(directory))
        except Exception as error:
            entry = dict(previous)
            entry.update({"status": "unavailable", "warnings": ["Collection failed: " + str(error)],
                          "sources": previous.get("sources", {}), "attempted_utc": int(time.time())})
            registry["sites"][site] = entry
            results[site] = {"status": "unavailable", "warnings": entry["warnings"]}
        save_json(registry_path, registry)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("/var/lib/ai-monitor"))
    parser.add_argument("--auth-dir", type=Path, default=Path("/etc/ai-monitor"))
    parser.add_argument("--sites", nargs="+", choices=("home", "work"), default=["home", "work"])
    parser.add_argument('--mount-root', type=Path, default=os.environ.get('AI_MONITOR_MOUNT_ROOT'),
                        help='Optional parent of read-only home/ and work/ NAS bind mounts')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        result = collect(args.data_dir, args.sites, args.auth_dir,
                         getter=mounted_getter(args.mount_root) if args.mount_root else get_smb)
        print(json.dumps(result, indent=2))
        return 2 if any(item["status"] != "complete" for item in result.values()) else 0
    except Exception as error:
        print("Collection failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
