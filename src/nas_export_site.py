#!/usr/bin/env python3
"""NAS-side discovery, recent archive catch-up, and atomic export publication.

Python 3.8+, standard library. Install beside nas_export_recent.py. Reads only
Log Center databases/archives; retention removes only this tool's own run folders.
"""
import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import sys
import tempfile
import time
import uuid
import zipfile

spec = importlib.util.spec_from_file_location("nas_recent", Path(__file__).with_name("nas_export_recent.py"))
recent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recent)
DATE_NAME = re.compile(r"^(\d{4}-\d{2}-\d{2})_(\d{4}-\d{2}-\d{2})", re.I)
RUN_NAME = re.compile(r"^(home|work)-\d{8}T\d{6}Z-[a-f0-9]{8}$")
MAX_EXPANSION = 4 * 1024 ** 3
MAX_RUN_BYTES = 1024 ** 3


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_json(path, value):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".manifest-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def lock(path):
    with Path(path).open("a+b") as stream:
        if os.name == "posix":
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def discover(root):
    folders = [root] + sorted(path for path in root.iterdir()
        if path.is_dir() and not path.is_symlink() and not path.name.startswith(("@", "#", "."))
        and path.name != "AI-Monitor-Exports")
    live, archives, empty = [], [], []
    for folder in folders:
        found = False
        for path in sorted(folder.iterdir()):
            if not path.is_file() or path.is_symlink():
                continue
            name = path.name.lower()
            if name.endswith(("-wal", "-shm", "-journal")):
                continue
            if name.startswith("synosyslogdb"):
                live.append(path)
                found = True
            elif DATE_NAME.match(name):
                archives.append(path)
                found = True
        if not found and folder != root:
            empty.append(folder.name)
    return live, archives, empty


def recent_archive(path, now, hours):
    # Date labels and mtime are hints, not proof of coverage. Use either, with
    # a two-day buffer for timezone labels, late rotation, or recently moved files.
    cutoff = now - (hours + 48) * 3600
    if path.stat().st_mtime >= cutoff:
        return True
    match = DATE_NAME.match(path.name)
    if match:
        try:
            return datetime.strptime(match.group(2), "%Y-%m-%d").date() >= datetime.fromtimestamp(cutoff, timezone.utc).date()
        except ValueError:
            return True
    return False


def source_name(root, original, table):
    if table != "logs":
        return {"general_log": "NAS/system", "connection_log": "NAS/connections",
                "transfer_log": "NAS/transfers"}[table]
    folder = original.parent.relative_to(root).as_posix()
    if folder == "." or (folder == "local" and "_LOCAL" in original.name.upper()):
        return "NAS/syslog" if "_LOCAL" in original.name.upper() else "root/received"
    return folder


def file_signature(path):
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, stat.st_ino


def prune_runs(output, site, keep, current):
    runs = sorted((path for path in output.iterdir() if path.is_dir() and not path.is_symlink()
                  and RUN_NAME.fullmatch(path.name) and path.name.startswith(site + "-")),
                  key=lambda path: path.stat().st_mtime_ns)
    eligible = [path for path in runs if path.name != current]
    for path in eligible[:max(0, len(runs) - keep)]:
        if path.resolve().parent != output.resolve():
            raise ValueError("Retention target escaped the export directory")
        marker = path / "manifest.json"
        if marker.is_file() and not marker.is_symlink():
            info = json.loads(marker.read_text(encoding="utf-8"))
            if info.get("producer") == "ai-monitor-site-export-v1" and info.get("run_id") == path.name:
                shutil.rmtree(str(path))


def export_site(root, site, hours=72, keep=3, now=None):
    root = Path(root).resolve()
    if site not in ("home", "work") or not 1 <= hours <= 168 or keep < 2:
        raise ValueError("Use home/work, 1-168 hours, and at least two retained runs")
    if not root.is_dir():
        raise ValueError("Log Center root does not exist")
    output = root / "AI-Monitor-Exports"
    if output.is_symlink():
        raise ValueError("Output directory must not be a symbolic link")
    output.mkdir(mode=0o755, exist_ok=True)
    os.chmod(str(output), 0o755)
    moment = int(time.time() if now is None else now)
    run_id = site + "-" + datetime.fromtimestamp(moment, timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    manifest = {"format_version": 1, "producer": "ai-monitor-site-export-v1", "site": site,
                "nas_name": socket.gethostname(), "run_id": run_id, "started_utc": recent.iso(moment),
                "lookback_hours": hours, "sources": {}, "assets": [], "errors": [],
                "skipped_old_archives": 0, "empty_folders": [],
                "coverage_note": "Discovered Log Center databases and recent archives under this root and its immediate device folders. "
                                 "Empty folders, quiet sources, and timestamps do not prove device health. "
                                 "Older archives outside the buffered catch-up window are not backfilled."}
    with lock(output / ("." + site + "-export.lock")):
        stage = Path(tempfile.mkdtemp(prefix=".pending-" + site + "-", dir=str(output)))
        os.chmod(str(stage), 0o755)
        published = False
        total_bytes = 0

        def issue(path, error):
            manifest["errors"].append({"input": str(path.relative_to(root)), "error": str(error)})

        def export_database(database, original, kind, member=""):
            nonlocal total_bytes
            tables = recent.supported_tables(database)
            if not tables:
                raise ValueError("No supported Synology log table; source is not silently skipped")
            with closing(sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True)) as check:
                unknown = [row[0] for row in check.execute("SELECT name FROM sqlite_master WHERE type='table'")
                           if row[0] not in recent.TABLE_FIELDS and not row[0].startswith("sqlite_")]
            if unknown:
                issue(original, "Additional unhandled tables: " + ", ".join(unknown))
            for table in tables:
                source = source_name(root, original, table)
                info = manifest["sources"].setdefault(source, {"has_live_database": False, "assets": []})
                info["has_live_database"] |= kind == "live"
                key = json.dumps([str(original.relative_to(root)), member, table], ensure_ascii=True).encode()
                filename = "asset-" + hashlib.sha256(key).hexdigest()[:32] + ".zip"
                target = stage / filename
                print(site + ": exporting " + str(original.relative_to(root)) + " [" + table + "]", file=sys.stderr, flush=True)
                summary = recent.export_recent(database, target, hours=hours, now=now, table=table)
                size = target.stat().st_size
                total_bytes += size
                if total_bytes > MAX_RUN_BYTES:
                    target.unlink()
                    raise ValueError("Generated ZIPs exceed the 1 GiB run limit")
                asset = {"source": source, "kind": kind, "input": str(original.relative_to(root)),
                         "member": member, "table": table, "file": run_id + "/" + filename,
                         "sha256": sha256(target), "bytes": size, "rows_exported": summary["rows_exported"],
                         "exported_at_utc": summary["exported_at_utc"],
                         "untimed_rows": summary["rows_without_valid_timestamps"],
                         "invalid_utf8_rows": summary.get("rows_with_invalid_utf8", 0),
                         "future_timestamp_rows": summary["rows_with_future_timestamp"]}
                info["assets"].append(len(manifest["assets"]))
                manifest["assets"].append(asset)

        try:
            live, first_archives, empty = discover(root)
            manifest["empty_folders"] = empty
            for path in live:
                try:
                    export_database(path, path, "live")
                except Exception as error:
                    issue(path, error)
            # Scan again after live reads to include archives created by rotation
            # during those reads. Re-importing overlap is handled by event hashes.
            _, second_archives, _ = discover(root)
            for path in sorted(set(first_archives + second_archives)):
                try:
                    if not recent_archive(path, moment, hours):
                        manifest["skipped_old_archives"] += 1
                        continue
                    before = file_signature(path)
                    if path.suffix.lower() == ".zip":
                        if path.stat().st_size > 1024 ** 3:
                            raise ValueError("Recent ZIP exceeds the 1 GiB input limit")
                        with zipfile.ZipFile(path) as zipped, tempfile.TemporaryDirectory(prefix=".archive-", dir=str(stage)) as temporary:
                            members = [member for member in zipped.infolist() if not member.is_dir()]
                            if len(members) > 256 or any(m.filename.lower().endswith(("-wal", "-shm", "-journal")) for m in members):
                                raise ValueError("Archive has too many members or live database sidecars")
                            found = 0
                            for number, member in enumerate(members):
                                with zipped.open(member) as incoming:
                                    header = incoming.read(16)
                                    if header != b"SQLite format 3\x00":
                                        if member.filename.lower().endswith(".db"):
                                            raise ValueError("Archive .DB member is not SQLite")
                                        continue
                                    if member.file_size > MAX_EXPANSION or shutil.disk_usage(stage).free < member.file_size + 256 * 1024 ** 2:
                                        raise ValueError("Archive member exceeds expansion limit or available scratch space")
                                    sample = Path(temporary) / (str(number) + ".db")
                                    with sample.open("wb") as destination:
                                        destination.write(header)
                                        copied = len(header)
                                        while True:
                                            chunk = incoming.read(1024 * 1024)
                                            if not chunk:
                                                break
                                            copied += len(chunk)
                                            if copied > member.file_size or copied > MAX_EXPANSION:
                                                raise ValueError("Archive member exceeds its declared size")
                                            destination.write(chunk)
                                export_database(sample, path, "archive", str(number) + ":" + member.filename)
                                sample.unlink()
                                found += 1
                            if not found:
                                raise ValueError("No SQLite database in recent ZIP")
                    else:
                        with path.open("rb") as stream:
                            if stream.read(16) != b"SQLite format 3\x00":
                                raise ValueError("Dated archive is neither a ZIP nor a SQLite database")
                        export_database(path, path, "archive")
                    if file_signature(path) != before:
                        raise ValueError("Archive changed during export; this run has incomplete coverage")
                except Exception as error:
                    issue(path, error)
            manifest["finished_utc"] = recent.iso(int(time.time()))
            manifest["status"] = "partial" if manifest["errors"] else "complete"
            manifest["zip_bytes"] = total_bytes
            save_json(stage / "manifest.json", manifest)
            os.replace(str(stage), str(output / run_id))
            published = True
            save_json(output / (site + "-manifest.json"), manifest)
            prune_runs(output, site, keep, run_id)
        finally:
            if not published and stage.exists():
                if stage.resolve().parent != output.resolve() or not stage.name.startswith(".pending-" + site + "-"):
                    raise ValueError("Unsafe temporary cleanup target")
                shutil.rmtree(str(stage))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/volume1/Logs"))
    parser.add_argument("--site", required=True, choices=("home", "work"))
    parser.add_argument("--hours", type=int, default=72)
    parser.add_argument("--keep-runs", type=int, default=3)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        result = export_site(args.root, args.site, args.hours, args.keep_runs)
        print(json.dumps({"site": args.site, "status": result["status"], "run_id": result["run_id"],
                          "sources": len(result["sources"]), "assets": len(result["assets"]),
                          "rows_exported_before_deduplication": sum(a["rows_exported"] for a in result["assets"]),
                          "invalid_utf8_rows_before_deduplication": sum(a.get("invalid_utf8_rows", 0) for a in result["assets"]),
                          "skipped_old_archives": result["skipped_old_archives"], "errors": result["errors"]}, indent=2))
        return 2 if result["errors"] else 0
    except Exception as error:
        print("Site export failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
