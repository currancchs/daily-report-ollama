#!/usr/bin/env python3
"""Export recent Synology logs on the NAS itself (Python 3.8+, stdlib only).

The source is opened read-only through SQLite, never copied as a live file.
A completed ZIP replaces the previous output atomically. A failed run leaves
the old ZIP in place; consumers MUST check export.json for its actual freshness.
This is a single-database export, not a claim of full-site log coverage.
"""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import zipfile

FIELDS = (
    "id", "host", "ip", "fac", "prio", "llevel", "tag", "utcsec",
    "r_utcsec", "tzoffset", "ldate", "ltime", "prog", "msg",
)
SCHEMA = """CREATE TABLE logs (
    id INTEGER PRIMARY KEY, host TEXT, ip TEXT, fac TEXT, prio TEXT,
    llevel TEXT, tag TEXT, utcsec INT, r_utcsec INT, tzoffset TEXT,
    ldate DATE, ltime TIME, prog TEXT, msg TEXT
)"""
MAX_DATABASE_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
TABLE_FIELDS = {
    "logs": FIELDS,
    "connection_log": tuple("id host llevel prog utcsec ldate ltime luser msg".split()),
    "general_log": tuple("id host llevel prog utcsec ldate ltime luser msg".split()),
    "transfer_log": tuple("id host prog utcsec ldate ltime ip luser event isdir fsize fname".split()),
}


class InvalidUTF8(bytes):
    """Distinguish malformed SQLite TEXT from an intentional SQLite BLOB."""


def decode_text(value):
    try:
        return value.decode('utf-8')
    except UnicodeDecodeError:
        return InvalidUTF8(value)


def preserve_invalid_text(fields, values, summary):
    result = []
    affected = False
    for field, value in zip(fields, values):
        if isinstance(value, InvalidUTF8):
            affected = True
            counts = summary['invalid_utf8_fields']
            counts[field] = counts.get(field, 0) + 1
            # Keep the exact bytes alongside a readable approximation. No bytes
            # are dropped or guessed as another encoding; valid text is unchanged.
            value = json.dumps({'synology_invalid_utf8': True,
                                'text_preview': value.decode('utf-8', errors='backslashreplace'),
                                'original_bytes_hex': value.hex()},
                               sort_keys=True, ensure_ascii=True, separators=(',', ':'))
        result.append(value)
    if affected:
        summary['rows_with_invalid_utf8'] += 1
    return tuple(result)


def supported_tables(database):
    with closing(sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return [name for name in TABLE_FIELDS if name in names]


def normalized_values(table, values):
    if table == "logs":
        return values
    original = dict(zip(TABLE_FIELDS[table], values))
    row = {key: original.get(key) for key in FIELDS}
    row["tag"] = table
    extra = {key: value for key, value in original.items()
             if key not in FIELDS or key == "msg"}
    extra["synology_table"] = table
    extra = {key: {"sqlite_blob_hex": value.hex()} if isinstance(value, bytes) else value
             for key, value in extra.items()}
    row["msg"] = json.dumps(extra, sort_keys=True, ensure_ascii=True,
                            separators=(",", ":"), allow_nan=False)
    # Missing receive time, timezone, and severity remain missing, never invented.
    return tuple(row[key] for key in FIELDS)


def iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def epoch(value):
    # Numeric seconds match the INT columns in the observed Synology schema.
    if isinstance(value, (int, float)) and 0 < value < 253402300800:
        integer = int(value)
        if integer == value:
            return integer
    return None


def time_expression(column):
    return (
        "CASE WHEN typeof({0}) IN ('integer','real') "
        "AND {0} = CAST({0} AS INTEGER) "
        "AND {0} > 0 AND {0} < 253402300800 "
        "THEN CAST({0} AS INTEGER) ELSE NULL END"
    ).format(column)


def find_database(folder):
    folder = Path(folder)
    if not folder.is_dir():
        raise ValueError("Device folder not found: " + str(folder))
    candidates = [path for path in folder.iterdir()
                  if path.is_file() and not path.is_symlink()
                  and path.name.upper().startswith("SYNOSYSLOGDB")
                  and path.name.upper().endswith(".DB")]
    if len(candidates) != 1:
        raise ValueError("Expected one live SYNOSYSLOGDB*.DB in " + str(folder) +
                         "; found " + str(len(candidates)))
    return candidates[0]


def export_recent(database, output, hours=48, max_rows=250000,
                  timeout=90, now=None, table=None):
    database, output = Path(database), Path(output)
    if not database.is_file():
        raise ValueError("Source database not found: " + str(database))
    if output.suffix.lower() != ".zip":
        raise ValueError("Output filename must end in .zip")
    if output.is_symlink():
        raise ValueError("Refusing a symbolic-link output file")
    if not 1 <= hours <= 168 or max_rows < 1 or timeout < 1:
        raise ValueError("Use 1-168 hours, a positive row limit and timeout")
    # The extra second includes events stamped in the current second.
    end = int(time.time() if now is None else now) + 1
    start = end - hours * 3600
    output.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "format_version": 1,
        "status": "complete",
        "source_database": str(database.resolve()),
        "window_start_utc": iso(start),
        "window_end_utc_exclusive": iso(end),
        "lookback_hours": hours,
        "selection": "Either utcsec or r_utcsec falls within the window; "
                     "also retain rows where both timestamps are invalid.",
        "rows_exported": 0,
        "rows_without_valid_timestamps": 0,
        "rows_with_future_timestamp": 0,
        "rows_with_invalid_utf8": 0,
        "invalid_utf8_fields": {},
        "text_encoding_policy": "Valid UTF-8 text is unchanged. Malformed TEXT values are JSON-wrapped with a readable preview and exact original_bytes_hex. SQLite BLOB values remain BLOBs.",
        "timestamp_value_types": {},
        "timestamp_samples": [],
        "coverage_note": "One input database table only. Other "
                         "databases are not included. Row counts do not establish "
                         "complete device coverage or device health.",
    }
    # Keep temporary output on the same filesystem for atomic publication.
    with tempfile.TemporaryDirectory(prefix=".ai-export-", dir=str(output.parent)) as temp:
        temp = Path(temp)
        snapshot = temp / "recent.DB"
        archive = temp / "result.zip"
        deadline = time.monotonic() + timeout

        def check_deadline():
            if time.monotonic() >= deadline:
                raise TimeoutError("Read/export time limit exceeded; no new ZIP published")

        uri = database.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=min(5, timeout))) as source:
            source.execute("PRAGMA query_only=ON")
            source.execute("PRAGMA trusted_schema=OFF")
            source.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10000)
            source.execute("BEGIN")
            if table is None:
                names = {r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                candidates = [name for name in TABLE_FIELDS if name in names]
                if len(candidates) != 1:
                    raise ValueError("Expected exactly one known Synology log table")
                table = candidates[0]
            if table not in TABLE_FIELDS:
                raise ValueError("Unsupported table name")
            kind = source.execute(
                "SELECT type FROM sqlite_master WHERE name=?", (table,)
            ).fetchone()
            if kind != ("table",):
                raise ValueError("Expected a real log table")
            fields = TABLE_FIELDS[table]
            actual = {row[0] for row in source.execute("SELECT name FROM pragma_table_info(?)", (table,))}
            if set(fields) - actual:
                raise ValueError("Unsupported log schema; missing: " +
                                 ", ".join(sorted(set(fields) - actual)))
            summary["input_table"] = table
            summary["normalization"] = "unchanged" if table == "logs" else "NAS extra fields retained as JSON in msg; absent fields are NULL"
            event = time_expression("utcsec")
            received = time_expression("r_utcsec") if "r_utcsec" in fields else "NULL"
            query = (
                "SELECT " + ",".join(fields) + " FROM " + table + " WHERE "
                "(({0}) >= ? AND ({0}) < ?) OR "
                "(({1}) >= ? AND ({1}) < ?) OR "
                "(({0}) IS NULL AND ({1}) IS NULL)"
            ).format(event, received)
            # Apply only to row data, after strict schema/table validation above.
            source.text_factory = decode_text
            cursor = source.execute(query, (start, end, start, end))
            with closing(sqlite3.connect(str(snapshot))) as destination, destination:
                destination.execute("PRAGMA page_size=4096")
                destination.execute("PRAGMA journal_mode=DELETE")
                destination.execute("PRAGMA max_page_count=" + str(MAX_DATABASE_BYTES // 4096))
                destination.execute(SCHEMA)
                while True:
                    check_deadline()
                    batch = cursor.fetchmany(500)
                    if not batch:
                        break
                    batch = [normalized_values(table, preserve_invalid_text(fields, values, summary))
                             for values in batch]
                    if summary["rows_exported"] + len(batch) > max_rows:
                        raise ValueError("Row limit exceeded; no partial ZIP published. "
                                         "This source needs a larger or partitioned export.")
                    destination.executemany(
                        "INSERT INTO logs VALUES (" + ",".join("?" for _ in FIELDS) + ")",
                        batch,
                    )
                    summary["rows_exported"] += len(batch)
                    for values in batch:
                        raw = dict(zip(FIELDS, values))
                        stamps = (epoch(raw["utcsec"]), epoch(raw["r_utcsec"]))
                        if all(stamp is None for stamp in stamps):
                            summary["rows_without_valid_timestamps"] += 1
                        if any(stamp is not None and stamp >= end for stamp in stamps):
                            summary["rows_with_future_timestamp"] += 1
                        for field in ("utcsec", "r_utcsec"):
                            key = field + ":" + type(raw[field]).__name__
                            counts = summary["timestamp_value_types"]
                            counts[key] = counts.get(key, 0) + 1
                        if len(summary["timestamp_samples"]) < 2:
                            sample = {}
                            for field in ("utcsec", "r_utcsec", "tzoffset", "ldate", "ltime"):
                                value = raw[field]
                                sample[field] = "[BLOB]" if isinstance(value, bytes) else value
                            summary["timestamp_samples"].append(sample)
                check_deadline()
            # Closing the source ends the read transaction before compression.
        with closing(sqlite3.connect(snapshot.resolve().as_uri() + "?mode=ro", uri=True)) as check:
            if check.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ValueError("Exported database failed quick_check")
        if summary["rows_with_invalid_utf8"]:
            summary["normalization"] += "; invalid UTF-8 TEXT is JSON-wrapped with readable preview and exact original bytes"
        summary["database_bytes"] = snapshot.stat().st_size
        summary["exported_at_utc"] = iso(int(time.time()))
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zipped:
            zipped.write(snapshot, "recent.DB")
            zipped.writestr("export.json", json.dumps(summary, indent=2, allow_nan=False))
        if archive.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("ZIP exceeds the importer's 128 MiB limit")
        with archive.open("r+b") as stream:
            os.fsync(stream.fileno())
        os.chmod(str(archive), 0o644)
        os.replace(str(archive), str(output))
    result = dict(summary)
    result["output"] = str(output)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--database")
    source.add_argument("--source-dir", help="Device folder containing exactly one live database")
    parser.add_argument("--output", required=True)
    parser.add_argument("--hours", type=int, default=48)
    parser.add_argument("--table", choices=tuple(TABLE_FIELDS))
    parser.add_argument("--max-rows", type=int, default=250000)
    parser.add_argument("--timeout", type=int, default=90,
                        help="Maximum seconds holding the source read transaction")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        database = find_database(args.source_dir) if args.source_dir else args.database
        result = export_recent(database, args.output, args.hours,
                               args.max_rows, args.timeout, table=args.table)
    except Exception as error:
        print(json.dumps({"status": "failed", "error": str(error),
                          "output": args.output,
                          "note": "An existing ZIP, if any, is from an older run."}),
              file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
