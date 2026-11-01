import importlib.util
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import zipfile

workspace = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("importer", workspace / "src/import_synology.py")
importer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(importer)
schema = """CREATE TABLE logs (id integer primary key, host text default NULL,
ip text default NULL, fac text default NULL, prio text default NULL,
llevel text default NULL, tag text default NULL, utcsec int default NULL,
r_utcsec int default NULL, tzoffset text default NULL,
ldate date default CURRENT_DATE, ltime time default CURRENT_TIME,
prog text default NULL, msg text default NULL)"""

with tempfile.TemporaryDirectory(dir=workspace / "work") as temp:
    root = Path(temp)
    database = root / "input.db"
    history = root / "events.sqlite"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(schema)
        connection.executemany(
            "INSERT INTO logs(id,host,utcsec,r_utcsec,prog,msg) VALUES(?,?,?,?,?,?)",
            [(1, "test-host", 1793300000, 1793300001, "test", "Repeated message"),
             (2, "test-host", 1793300000, 1793300001, "test", "Repeated message"),
             (3, "test-host", 0, None, "test", "Missing timestamps")],
        )
    archive = root / "input.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
        zipped.write(database, "../../escape.db")
    first = importer.import_archive(archive, history, "home", "test-host")
    assert first["new_rows"] == 3 and first["utcsec_missing_or_invalid"] == 1
    assert first["utcsec_last_utc"] == "2026-10-29T18:53:20+00:00", first
    assert not (workspace / "work/escape.db").exists()
    second = importer.import_archive(archive, history, "home", "test-host")
    assert second["new_rows"] == 0 and second["duplicate_rows"] == 3
    remote = importer.import_archive(archive, history, "work", "test-host")
    assert remote["new_rows"] == 3
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("INSERT INTO logs(id,utcsec,msg) VALUES (4,1793300100,'Added later')")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
        zipped.write(database, "archive.db")
    changed = importer.import_archive(archive, history, "home", "test-host")
    assert changed["new_rows"] == 1 and changed["duplicate_rows"] == 3
    bad = root / "bad.zip"
    with zipfile.ZipFile(bad, "w", zipfile.ZIP_DEFLATED) as zipped:
        zipped.write(database, "valid.db")
        zipped.writestr("invalid.db", b"not SQLite")
    try:
        importer.import_archive(bad, history, "home", "rollback-test")
        raise AssertionError("Bad archive accepted")
    except ValueError:
        pass
    with closing(sqlite3.connect(history)) as connection:
        assert connection.execute("SELECT count(*) FROM events WHERE source='rollback-test'").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 7
        raw = json.loads(connection.execute("SELECT raw_json FROM events LIMIT 1").fetchone()[0])
        assert raw["msg"] == "Repeated message" and raw["id"] == 1
    with zipfile.ZipFile(bad, "w") as zipped:
        zipped.write(database, "archive.db")
        zipped.writestr("archive.db-wal", b"pending")
    try:
        importer.import_archive(bad, history, "home", "wal-test")
        raise AssertionError("WAL-sidecar archive accepted")
    except ValueError:
        pass
    print("PASS: schema import, distinct repeated events, timestamp coverage, repeat imports, site isolation, changed archives, atomic failure, WAL rejection, and archive path isolation")
