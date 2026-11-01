from contextlib import closing
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "src" / filename)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


preview = load("preview", "preview_report.py")
exporter = load("exporter", "nas_export_recent.py")
importer = load("importer", "import_synology.py")
NOW = int(datetime(2026, 10, 30, 1, 40, tzinfo=timezone.utc).timestamp())


def answer(batch):
    return [{"id": group["id"], "classification": "issue", "severity": "warning",
             "summary": "Observed a test warning.", "suggested_check": "Inspect the source service logs."}
            for group in batch]


with tempfile.TemporaryDirectory(dir=ROOT / "work") as temporary:
    root = Path(temporary)
    history = root / "events.sqlite"
    all_rows = 0
    for site, sources in preview.SOURCES.items():
        (root / site).mkdir()
        for source in sources:
            source_db = root / site / (source + ".db")
            with closing(sqlite3.connect(source_db)) as db, db:
                db.execute(exporter.SCHEMA)
                rows = [
                    (1, source, NOW-200, NOW-199, "warning", "Repeated warning"),
                    (2, source, NOW-100, NOW-99, "warning", "Repeated warning"),
                    (3, source, NOW-300, NOW-299, "info", "Started normally"),
                    (4, source, NOW-90000, NOW-89999, "info", "Outside report window"),
                    (5, source, NOW-95000, NOW-60, "error", "Late arriving event"),
                ]
                db.executemany("INSERT INTO logs(id,host,utcsec,r_utcsec,llevel,msg) VALUES(?,?,?,?,?,?)", rows)
            archive = root / site / (source + "-recent.zip")
            with patch.object(exporter.time, "time", return_value=NOW):
                exporter.export_recent(source_db, archive, now=NOW)
            imported = importer.import_archive(archive, history, site, source)
            all_rows += imported["new_rows"]
    assert all_rows == 20
    report = preview.collect(history, root, 24, 20, 2, now=NOW)
    for site, data in report["sites"].items():
        assert data["rows_in_window"] == 8
        assert data["rows_scanned"] == 8
        assert data["groups_total"] == 6
        assert sorted(group["count"] for group in data["groups"]) == [1, 1, 1, 1, 2, 2]
        assert all(not check["warnings"] for check in data["sources"].values())
        assert all(group["id"].startswith(site + "-") for group in data["groups"])
        assert all(preview.fits(batch) and len(batch) <= 4 for batch in preview.batches(data["groups"]))
    seen = []

    def mock_model(url, model, batch, timeout):
        seen.extend(group["id"] for group in batch)
        return answer(batch)

    preview.analyze(report, "http://localhost:11434", "test-model", 1, caller=mock_model)
    assert report["status"] == "preview_complete"
    assert len(seen) == len(set(seen)) == 12
    text = preview.render(report, timezone.utc)
    assert "HOME" in text and "WORK" in text and "TRIAL" in text and "read-only" not in text
    assert "archive catch-up is not configured" in text
    assert "2 matching records" in text
    assert "Outside report window" not in text
    output = root / "preview.txt"
    preview.save_atomic(output, text)
    assert output.read_text() == text

    bounded = preview.collect(history, root, 24, 1, 2, now=NOW)
    assert all(data["omitted_groups"] == 5 and data["warnings"] for data in bounded["sites"].values())
    complete = preview.collect(history, root, 24, 0, 2, now=NOW)
    assert all(data["omitted_groups"] == 0 and len(data["groups"]) == 6 for data in complete["sites"].values())
    preview.analyze(complete, "http://localhost", "test-model", 1, caller=mock_model, max_runtime=0)
    assert complete["status"] == "preview_with_ai_errors"
    assert all(not data["assessments"] and "time limit" in data["ai_errors"][0] for data in complete["sites"].values())
    stale = preview.collect(history, root, 24, 20, 2, now=NOW+8000)
    assert all(any("older" in warning for warning in check["warnings"])
               for data in stale["sites"].values() for check in data["sources"].values())

    batch = report["sites"]["home"]["groups"][:2]
    invalid = answer(batch)
    invalid[0]["id"] = "invented-evidence"
    try:
        preview.validate({"assessments": invalid}, batch)
        raise AssertionError("Invented evidence accepted")
    except ValueError:
        pass
    try:
        preview.validate({"assessments": answer(batch)[:1]}, batch)
        raise AssertionError("Incomplete assessments accepted")
    except ValueError:
        pass

    captured = {}

    class FakeOpener:
        def open(self, request, timeout):
            captured.update(json.loads(request.data))
            return io.BytesIO(json.dumps({"done": True, "done_reason": "stop", "message": {
                "content": json.dumps({"assessments": answer(batch)})}}).encode())

    with patch.object(preview.urllib.request, "build_opener", return_value=FakeOpener()):
        assert len(preview.call_ollama("http://localhost:11434", "test-model", batch, 2)) == 2
    assert captured["stream"] is False and captured["think"] is False
    assert "tools" not in captured and captured["options"]["num_ctx"] == 8192
    assert "untrusted" in captured["messages"][0]["content"]
    assert json.loads(captured["messages"][1]["content"])["log_groups"][0]["id"] == batch[0]["id"]

    failed = preview.collect(history, root, 24, 20, 2, now=NOW)

    def unavailable(*args):
        raise TimeoutError("synthetic timeout")

    preview.analyze(failed, "http://localhost", "test-model", 1, caller=unavailable)
    assert failed["status"] == "preview_with_ai_errors"
    assert all(data["batches_attempted"] == 1 and data["ai_errors"] and not data["assessments"]
               for data in failed["sites"].values())
    assert "AI ERROR" in preview.render(failed, timezone.utc)

    (root / "home/ProxmoxVE-recent.zip").unlink()
    missing = preview.collect(history, root, 24, 20, 2, now=NOW)
    assert missing["sites"]["home"]["sources"]["ProxmoxVE"]["warnings"]
    with closing(sqlite3.connect(history)) as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == all_rows

print("PASS: end-to-end export/import/report grouping, site isolation, receive-time windows, freshness, omission reporting, evidence validation, mocked Ollama contract, unavailable-model handling, atomic report writing and unchanged history")
