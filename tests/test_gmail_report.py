from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import ssl
import tempfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("gmail", ROOT / "src/gmail_report.py")
gmail = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gmail)
NOW = 1793325000
GENERATED = datetime.fromtimestamp(NOW, timezone.utc).isoformat()
config = {"username": "sender@example.com", "recipient": "recipient@example.com", "app_password": "abcdefghijklmnop"}


class FakeSMTP:
    sends = []
    uncertain = False
    bad_auth = False

    def __init__(self, host, port, timeout, context):
        assert (host, port) == ("smtp.gmail.com", 465)
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname

    def login(self, username, password):
        assert username == config["username"] and password == config["app_password"]
        if self.bad_auth:
            raise RuntimeError("Authentication rejected")

    def send_message(self, message, from_addr, to_addrs):
        assert from_addr == config["username"] and to_addrs == [config["recipient"]]
        self.sends.append(message)
        if self.uncertain:
            raise TimeoutError("reply lost")
        return {}

    def quit(self):
        raise OSError("QUIT reply lost after accepted DATA")

    def close(self):
        pass


with tempfile.TemporaryDirectory(dir=ROOT / "work") as temporary:
    root = Path(temporary)
    report = root / "preview.txt"
    report.write_text("HOME + WORK LOG REPORT - MANUAL PREVIEW\nGenerated: " + GENERATED + "\nTRIAL: partial data\n", encoding="utf-8")
    report.with_suffix(".json").write_text(json.dumps({"status": "preview_complete", "generated_utc": GENERATED}), encoding="utf-8")
    result = gmail.send_report(config, report, root / "state", smtp_factory=FakeSMTP, now=NOW)
    assert result["status"] == "accepted_by_smtp"
    assert "PREVIEW" in result["subject"]
    assert FakeSMTP.sends[0].get_content_type() == "multipart/alternative"
    assert [part.get_content_type() for part in FakeSMTP.sends[0].iter_parts()] == ['text/plain', 'text/html']
    assert config["app_password"] not in FakeSMTP.sends[0].as_string()
    assert gmail.send_report(config, report, root / "state", smtp_factory=FakeSMTP, now=NOW)["status"] == "already_sent"
    assert len(FakeSMTP.sends) == 1
    try:
        gmail.send_report(config, report, root / "state2", smtp_factory=FakeSMTP, now=NOW+8000)
        raise AssertionError("Stale report sent")
    except ValueError as error:
        assert "stale" in str(error)
    FakeSMTP.uncertain = True
    try:
        gmail.send_report(config, report, root / "uncertain", smtp_factory=FakeSMTP, now=NOW)
        raise AssertionError("Unconfirmed delivery marked accepted")
    except RuntimeError:
        pass
    sends = len(FakeSMTP.sends)
    try:
        gmail.send_report(config, report, root / "uncertain", smtp_factory=FakeSMTP, now=NOW)
        raise AssertionError("Unconfirmed delivery retried automatically")
    except RuntimeError:
        pass
    assert len(FakeSMTP.sends) == sends
    FakeSMTP.uncertain = False
    assert gmail.send_report(config, report, root / "uncertain", smtp_factory=FakeSMTP, now=NOW, retry=True)["status"] == "accepted_by_smtp"
    FakeSMTP.bad_auth = True
    try:
        gmail.send_report(config, report, root / "bad-auth", smtp_factory=FakeSMTP, now=NOW)
        raise AssertionError("Bad authentication accepted")
    except RuntimeError:
        pass
    assert not list((root / "bad-auth").glob("*.json"))
    FakeSMTP.bad_auth = False
    report.with_suffix(".json").write_text(json.dumps({"status": "preview_complete", "generated_utc": "2026-10-29T00:00:00+00:00"}), encoding="utf-8")
    try:
        gmail.load_report(report, now=NOW)
        raise AssertionError("Mismatched companion accepted")
    except ValueError:
        pass
    # Daily reports deduplicate by report date, including regenerated bodies.
    daily_metadata = {"report_kind": "daily", "report_date": "2026-10-29",
                      "status": "daily_complete", "generated_utc": GENERATED,
                      "review_limited": True}
    report.with_suffix(".json").write_text(json.dumps(daily_metadata), encoding="utf-8")
    result = gmail.send_report(config, report, root / "daily", smtp_factory=FakeSMTP, now=NOW)
    assert "DAILY - LIMITED REVIEW" in result["subject"]
    count = len(FakeSMTP.sends)
    report.write_text(report.read_text(encoding="utf-8") + "Updated findings.\n", encoding="utf-8")
    result = gmail.send_report(config, report, root / "daily", smtp_factory=FakeSMTP, now=NOW)
    assert result["status"] == "already_sent" and "for this date" in result["note"]
    assert len(FakeSMTP.sends) == count
    for status, label in (("daily_partial", "PIPELINE ISSUE"), ("daily_failed", "REPORT FAILED")):
        daily_metadata["status"] = status
        report.with_suffix(".json").write_text(json.dumps(daily_metadata), encoding="utf-8")
        result = gmail.send_report(config, report, root / status, smtp_factory=FakeSMTP, now=NOW)
        assert label in result["subject"]
    daily_metadata["report_date"] = "not-a-date"
    report.with_suffix(".json").write_text(json.dumps(daily_metadata), encoding="utf-8")
    try:
        gmail.load_report(report, now=NOW)
        raise AssertionError("Invalid daily report date accepted")
    except ValueError:
        pass
    try:
        gmail.email_address("sender@example.com\r\nBcc: hidden@example.com")
        raise AssertionError("Header injection accepted")
    except ValueError:
        pass
print("PASS: certificate-verified Gmail TLS contract, single-recipient addressing, plain-text preview labeling, secret exclusion, SMTP acceptance vs delivery, duplicate suppression, uncertain-delivery retry guard, authentication failure, freshness, paired-report validation and header injection rejection (mock SMTP; no email sent)")
