#!/usr/bin/env python3
"""Import completed Synology ZIP archives into a local SQLite event history.

Run as ai-monitor. This reads archive copies, never active NAS databases.
Uses only the Python standard library. No AI calls, mail, or scheduling.
"""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import zipfile

_spec = importlib.util.spec_from_file_location('import_privacy', Path(__file__).with_name('sanitize_logs.py'))
privacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(privacy)

FIELDS = (
    "id", "host", "ip", "fac", "prio", "llevel", "tag", "utcsec",
    "r_utcsec", "tzoffset", "ldate", "ltime", "prog", "msg",
)
MAX_EXPANDED = 256 * 1024 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024


def epoch(value):
    """Treat the two utcsec fields as seconds; preserve originals in raw_json."""
    try:
        number = int(value)
        if isinstance(value, float) and value != number:
            return None
        if 0 < number < 253402300800:
            return number
    except (TypeError, ValueError, OverflowError):
        pass
    return None


def utc(value):
    return (datetime.fromtimestamp(value, timezone.utc).isoformat()
            if value is not None else None)


def record_value(value):
    # Preserve a BLOB if a database has one despite its declared text affinity.
    return {"sqlite_blob_hex": value.hex()} if isinstance(value, bytes) else value


def inspect_db(db_file, destination, site, source, now, summary):
    uri = db_file.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as database:
        database.execute("PRAGMA query_only=ON")
        database.execute("PRAGMA trusted_schema=OFF")
        integrity = database.execute("PRAGMA quick_check").fetchall()
        if integrity != [("ok",)]:
            raise ValueError("Archived database failed SQLite quick_check")
        kind = database.execute(
            "SELECT type FROM sqlite_master WHERE name='logs'"
        ).fetchone()
        if kind != ("table",):
            raise ValueError("Expected a logs table")
        actual = {row[1] for row in database.execute("PRAGMA table_info(logs)")}
        missing = set(FIELDS) - actual
        if missing:
            raise ValueError("Missing columns: " + ", ".join(sorted(missing)))
        for values in database.execute("SELECT " + ",".join(FIELDS) + " FROM logs"):
            raw = dict(zip(FIELDS, map(record_value, values)))
            identity = json.dumps([site, source, raw], sort_keys=True,
                                  ensure_ascii=True, separators=(",", ":"),
                                  allow_nan=False).encode("utf-8")
            fingerprint = hashlib.sha256(identity).hexdigest()
            sanitized = privacy.record(raw)
            summary['redacted_rows'] += int(sanitized != raw)
            raw_json = json.dumps(sanitized, sort_keys=True, ensure_ascii=True,
                                  separators=(",", ":"), allow_nan=False)
            event_time = epoch(raw["utcsec"])
            receive_time = epoch(raw["r_utcsec"])
            change = destination.execute(
                "INSERT OR IGNORE INTO events "
                "(fingerprint,site,source,utcsec,r_utcsec,first_seen_utc,raw_json) "
                "VALUES (?,?,?,?,?,?,?)",
                (fingerprint, site, source, event_time, receive_time, now, raw_json),
            ).rowcount
            summary["rows_read"] += 1
            summary["new_rows"] += change
            for field, stamp in (("utcsec", event_time), ("r_utcsec", receive_time)):
                if stamp is None:
                    summary[field + "_missing_or_invalid"] += 1
                    continue
                first, last = field + "_min", field + "_max"
                summary[first] = stamp if summary[first] is None else min(summary[first], stamp)
                summary[last] = stamp if summary[last] is None else max(summary[last], stamp)


def import_archive(archive, history, site, source):
    archive, history = Path(archive), Path(history)
    if not site.strip() or not source.strip():
        raise ValueError("Site and source must be nonempty")
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("Archive exceeds this importer's 128 MiB input limit")
    if archive.resolve() == history.resolve():
        raise ValueError("Input archive and history must be different files")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    now = int(time.time())
    summary = dict(site=site, source=source, archive=archive.name,
                   archive_sha256=digest, rows_read=0, new_rows=0,
                   databases_read=0, non_database_members=0,
                   sanitization=privacy.VERSION, redacted_rows=0)
    for field in ("utcsec", "r_utcsec"):
        summary.update({field + "_min": None, field + "_max": None,
                        field + "_missing_or_invalid": 0})

    history.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(history, timeout=30)) as destination:
        destination.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                fingerprint TEXT PRIMARY KEY, site TEXT NOT NULL,
                source TEXT NOT NULL, utcsec INTEGER, r_utcsec INTEGER,
                first_seen_utc INTEGER NOT NULL, raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_site_time ON events(site,utcsec);
            CREATE INDEX IF NOT EXISTS events_received ON events(site,r_utcsec);
            CREATE TABLE IF NOT EXISTS imports (
                site TEXT NOT NULL, source TEXT NOT NULL,
                archive_sha256 TEXT NOT NULL, imported_utc INTEGER NOT NULL,
                summary_json TEXT NOT NULL,
                PRIMARY KEY(site,source,archive_sha256)
            );
        """)
        # One transaction per archive: an invalid member rolls back its entire import.
        with destination, zipfile.ZipFile(archive) as zipped, tempfile.TemporaryDirectory() as folder:
            members = [member for member in zipped.infolist() if not member.is_dir()]
            if len(members) > 256 or sum(m.file_size for m in members) > MAX_EXPANDED:
                raise ValueError("Archive exceeds the member or expanded-size limit")
            if any(m.filename.lower().endswith(("-wal", "-shm")) for m in members):
                raise ValueError("Archive includes WAL sidecars; use a consistent database snapshot")
            for index, member in enumerate(members):
                # Ignore archive paths: write only generated names in a private temp folder.
                sample = Path(folder) / (str(index) + ".db")
                size = 0
                with zipped.open(member) as incoming, sample.open("wb") as outgoing:
                    while chunk := incoming.read(1024 * 1024):
                        size += len(chunk)
                        if size > member.file_size or size > MAX_EXPANDED:
                            raise ValueError("Archive member exceeds its declared size")
                        outgoing.write(chunk)
                with sample.open("rb") as stream:
                    signature = stream.read(16)
                if signature != b"SQLite format 3\x00":
                    if member.filename.lower().endswith(".db"):
                        raise ValueError("A .DB member is not a valid SQLite database")
                    summary["non_database_members"] += 1
                    continue
                inspect_db(sample, destination, site, source, now, summary)
                summary["databases_read"] += 1
            if not summary["databases_read"]:
                raise ValueError("No SQLite logs database found in the archive")
            summary["duplicate_rows"] = summary["rows_read"] - summary["new_rows"]
            summary["time_ranges_assume_unix_seconds"] = True
            for field in ("utcsec", "r_utcsec"):
                summary[field + "_first_utc"] = utc(summary[field + "_min"])
                summary[field + "_last_utc"] = utc(summary[field + "_max"])
            summary["coverage_note"] = (
                "These are the time ranges of this archive only; "
                "they do not establish complete daily coverage or device health."
            )
            destination.execute(
                "INSERT OR REPLACE INTO imports VALUES (?,?,?,?,?)",
                (site, source, digest, now, json.dumps(summary, sort_keys=True)),
            )
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", required=True, choices=("home", "work"))
    parser.add_argument("--source", required=True, help="Stable source name; preserve it across runs")
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--history", type=Path,
                        default=Path("/var/lib/ai-monitor/events.sqlite"))
    arguments = parser.parse_args()
    os.umask(0o077)
    try:
        result = import_archive(arguments.archive, arguments.history,
                                arguments.site, arguments.source)
    except Exception as error:
        print("Import failed: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
