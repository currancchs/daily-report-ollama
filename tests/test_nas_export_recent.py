import ast
from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


exporter = module("exporter", ROOT / "src/nas_export_recent.py")
importer = module("importer", ROOT / "src/import_synology.py")
ast.parse((ROOT / "src/nas_export_recent.py").read_text(), feature_version=(3, 8))
NOW = 1793320000
with tempfile.TemporaryDirectory(dir=ROOT / "work") as directory:
    root = Path(directory)
    source = root / "live.DB"
    archive = root / "published/recent.zip"
    history = root / "history.sqlite"
    with closing(sqlite3.connect(source)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(exporter.SCHEMA)
        writer.executemany(
            "INSERT INTO logs(id,host,utcsec,r_utcsec,msg) VALUES(?,?,?,?,?)",
            [
                (1, "test", NOW-100, NOW-99, "recent WAL record"),
                (2, "test", NOW-200000, NOW-199999, "old record"),
                (3, "test", NOW-200000, NOW-10, "late-arriving old event"),
                (4, "test", NOW+10000, NOW-5, "device clock ahead"),
                (5, "test", None, 0, "unknown timestamps"),
                (6, "test", NOW-100, NOW-99, "recent WAL record"),
                (7, "test", NOW+1, NOW+1, "outside upper bound"),
                (8, "test", NOW+1-48*3600, None, "inclusive lower bound"),
                (9, "test", NOW-48*3600, None, "outside lower bound"),
            ],
        )
        writer.commit()
        assert Path(str(source) + "-wal").stat().st_size > 0
        writer.execute(
            "INSERT INTO logs(id,utcsec,msg) VALUES(100,?, 'uncommitted')", (NOW,)
        )
        first = exporter.export_recent(source, archive, now=NOW)
        assert first["rows_exported"] == 6, first
        assert first["rows_without_valid_timestamps"] == 1
        assert first["rows_with_future_timestamp"] == 1
        assert first["timestamp_value_types"]["utcsec:int"] == 5
        writer.rollback()
        with zipfile.ZipFile(archive) as zipped:
            assert set(zipped.namelist()) == {"recent.DB", "export.json"}
            metadata = json.loads(zipped.read("export.json"))
            assert metadata["status"] == "complete"
            local_copy = root / "copy.db"
            local_copy.write_bytes(zipped.read("recent.DB"))
        with closing(sqlite3.connect(local_copy)) as copy:
            ids = {row[0] for row in copy.execute("SELECT id FROM logs")}
            assert ids == {1, 3, 4, 5, 6, 8}, ids
            assert copy.execute("PRAGMA quick_check").fetchall() == [("ok",)]
        imported = importer.import_archive(archive, history, "home", "test")
        assert imported["new_rows"] == 6 and imported["non_database_members"] == 1
        again = importer.import_archive(archive, history, "home", "test")
        assert again["new_rows"] == 0 and again["duplicate_rows"] == 6
        original_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        try:
            exporter.export_recent(source, archive, now=NOW, max_rows=2)
            raise AssertionError("Row limit failed to stop export")
        except ValueError as error:
            assert "Row limit" in str(error), error
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == original_digest
        assert not list(archive.parent.glob(".ai-export-*"))
        assert writer.execute("SELECT count(*) FROM logs").fetchone()[0] == 9
        writer.execute("INSERT INTO logs(id,utcsec,msg) VALUES(10,?,'next committed event')", (NOW,))
        writer.commit()
        exporter.export_recent(source, archive, now=NOW)
        changed = importer.import_archive(archive, history, "home", "test")
        assert changed["new_rows"] == 1 and changed["duplicate_rows"] == 6
    bad = root / "wrong.db"
    with closing(sqlite3.connect(bad)) as invalid, invalid:
        invalid.execute("CREATE TABLE logs (id INTEGER)")
    previous = archive.read_bytes()
    try:
        exporter.export_recent(bad, archive, now=NOW)
        raise AssertionError("Wrong schema accepted")
    except ValueError as error:
        assert "schema" in str(error), error
    assert archive.read_bytes() == previous
    try:
        exporter.export_recent(root / "missing.db", archive, now=NOW)
        raise AssertionError("Missing input accepted")
    except ValueError:
        pass
    assert not (root / "missing.db").exists()
    empty = root / "empty.db"
    with closing(sqlite3.connect(empty)) as db, db:
        db.execute(exporter.SCHEMA)
    exported_empty = exporter.export_recent(empty, root / "empty.zip", now=NOW)
    assert exported_empty["rows_exported"] == 0
    assert importer.import_archive(root / "empty.zip", history, "work", "empty")["new_rows"] == 0
    device = root / "device"
    device.mkdir()
    selected = device / "SYNOSYSLOGDB_device.DB"
    selected.write_bytes(empty.read_bytes())
    (device / "SYNOSYSLOGDB_device.DB-wal").write_bytes(b"sidecar")
    (device / "2026-10-29.DB").write_bytes(empty.read_bytes())
    assert exporter.find_database(device) == selected
    (device / "SYNOSYSLOGDB_second.DB").write_bytes(empty.read_bytes())
    try:
        exporter.find_database(device)
        raise AssertionError("Ambiguous database selection accepted")
    except ValueError:
        pass
print("PASS: Python 3.8 syntax, committed WAL reads, uncommitted exclusion, window boundaries, late arrivals, clock skew, unknown timestamps, schema validation, empty source, source unchanged, atomic failure and importer compatibility/deduplication")
