#!/usr/bin/env python3
"""Configure Gmail locally and explicitly email an existing report preview.

configure: run as root interactively; secrets are never command-line arguments.
send: run as ai-monitor. Uses certificate-verified TLS to smtp.gmail.com:465.
No scheduling. SMTP acceptance is recorded to avoid accidental duplicate sends.
"""
import argparse
from contextlib import contextmanager
from datetime import date, datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import smtplib
import ssl
import sys
import tempfile
import time
from zoneinfo import ZoneInfo

import runpy
_settings_module = runpy.run_path(str(Path(__file__).with_name('settings.py')))
SETTINGS = _settings_module['load']()


_html_spec = importlib.util.spec_from_file_location('mail_html', Path(__file__).with_name('html_report.py'))
html_report = importlib.util.module_from_spec(_html_spec)
_html_spec.loader.exec_module(html_report)


def email_address(value):
    value = value.strip()
    if not re.fullmatch(r"[^\s<>@,;]+@[^\s<>@,;]+\.[^\s<>@,;]+", value):
        raise ValueError("Enter one plain email address, without a display name")
    return value


def save_json(path, value, gid=None):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".mail-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if gid is not None:
            os.chown(temporary, 0, gid)
            os.chmod(temporary, 0o640)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def configure(path):
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise PermissionError("Run configure as root inside the Debian container")
    import grp
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("Configuration path must not be a symbolic link")
    username = email_address(input("Gmail sending address: "))
    recipient = input("Recipient address [press Enter for the same address]: ").strip()
    recipient = email_address(recipient or username)
    password = "".join(getpass.getpass("Google app password (hidden): ").split())
    if not re.fullmatch(r"[A-Za-z0-9]{16}", password):
        raise ValueError("Expected the 16-character Google app password; spaces are allowed")
    gid = grp.getgrnam("ai-monitor").gr_gid
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(path.parent, 0, gid)
    os.chmod(path.parent, 0o750)
    save_json(path, {"username": username, "recipient": recipient,
                     "app_password": password}, gid=gid)
    return {"status": "configured", "file": str(path),
            "note": "Secret saved locally with root:ai-monitor ownership and mode 0640."}


def load_config(path):
    path = Path(path)
    if path.stat().st_size > 16384:
        raise ValueError("Configuration file is unexpectedly large")
    if os.name == "posix" and path.stat().st_mode & 0o007:
        raise PermissionError("Configuration must not be accessible to other users; use mode 0640")
    config = json.loads(path.read_text(encoding="utf-8"))
    config["username"] = email_address(config["username"])
    config["recipient"] = email_address(config["recipient"])
    if not isinstance(config.get("app_password"), str) or not config["app_password"]:
        raise ValueError("Missing app password; rerun configure")
    return config


def load_report(path, max_age_hours=2, now=None):
    path = Path(path)
    metadata_path = path.with_suffix(".json")
    if path.stat().st_size > 1024 * 1024 or metadata_path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("Report is too large for this preview sender")
    body = path.read_text(encoding="utf-8")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    daily = metadata.get('report_kind') == 'daily'
    allowed = ('daily_complete', 'daily_partial', 'daily_failed') if daily else ('preview_complete', 'preview_with_ai_errors')
    if metadata.get("status") not in allowed:
        raise ValueError("Report does not have a completed status")
    if daily:
        if date.fromisoformat(metadata['report_date']).isoformat() != metadata['report_date']:
            raise ValueError('Invalid daily report date')
    generated = datetime.fromisoformat(metadata["generated_utc"])
    if generated.tzinfo is None or ("Generated: " + metadata["generated_utc"]) not in body.splitlines()[:5]:
        raise ValueError("Text and JSON reports do not identify the same generation")
    age = (time.time() if now is None else now) - generated.timestamp()
    if age < -300 or age > max_age_hours * 3600:
        raise ValueError("Report is stale or dated in the future; generate a current report before sending")
    return body, metadata, generated


@contextmanager
def send_lock(path):
    with Path(path).open("a+b") as stream:
        if os.name == "posix":
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "posix":
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def send_report(config, report_path, state_dir, max_age_hours=2, retry=False,
                smtp_factory=smtplib.SMTP_SSL, now=None):
    body, metadata, generated = load_report(report_path, max_age_hours, now)
    username = email_address(config["username"])
    recipient = email_address(config["recipient"])
    daily = metadata.get('report_kind') == 'daily'
    identity = [username, recipient, 'daily', metadata['report_date']] if daily else [username, recipient, body]
    key = hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()
    state_dir = Path(state_dir)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_path = state_dir / (key + ".json")
    with send_lock(state_dir / ".send.lock"):
        if state_path.exists() and not retry:
            previous = json.loads(state_path.read_text(encoding="utf-8"))
            if previous.get("status") == "accepted_by_smtp":
                return {"status": "already_sent", "message_id": previous["message_id"],
                        "note": ("A daily report for this date was already accepted by Gmail." if daily
                                 else "This exact report was already accepted by Gmail.")}
            raise RuntimeError("Previous delivery was not confirmed. Check your inbox/Sent mail before using --retry.")
        message = EmailMessage()
        report_date = metadata['report_date'] if daily else generated.astimezone(ZoneInfo(SETTINGS['timezone'])).strftime("%Y-%m-%d")
        label = "PREVIEW - AI ERRORS" if metadata["status"] == "preview_with_ai_errors" else "PREVIEW"
        if daily:
            label = {'daily_complete': 'DAILY', 'daily_partial': 'DAILY - PIPELINE ISSUE',
                     'daily_failed': 'DAILY - REPORT FAILED'}[metadata['status']]
            if metadata['status'] == 'daily_complete' and metadata.get('review_limited'):
                label = 'DAILY - LIMITED REVIEW'
        message["Subject"] = "[AI Logs][" + label + "] Home + Work - " + report_date
        message["From"] = username
        message["To"] = recipient
        message["Date"] = format_datetime(datetime.now(timezone.utc))
        message["Message-ID"] = make_msgid(domain="ai-monitor.local")
        preamble = 'Scheduled daily digest. Coverage and review limits are listed below.' if daily else 'Manual delivery test. Coverage limitations are listed in the report below.'
        message.set_content(preamble + '\n\n' + html_report.privacy.text(body))
        message.add_alternative(html_report.render(metadata, fallback_text=body), subtype='html')
        receipt = {"status": "pending", "message_id": message["Message-ID"],
                   "recipient": recipient, "report": str(report_path),
                   "attempted_utc": datetime.now(timezone.utc).isoformat()}
        server = smtp_factory("smtp.gmail.com", 465, timeout=30, context=ssl.create_default_context())
        try:
            server.login(username, config["app_password"])
            save_json(state_path, receipt)
            try:
                refused = server.send_message(message, from_addr=username, to_addrs=[recipient])
                if refused:
                    raise RuntimeError("SMTP refused the configured recipient")
                receipt["status"] = "accepted_by_smtp"
                save_json(state_path, receipt)
            except Exception:
                receipt["status"] = "delivery_unknown"
                save_json(state_path, receipt)
                raise RuntimeError("SMTP delivery was not confirmed. Check your inbox/Sent mail before retrying.") from None
        finally:
            try:
                server.quit()
            except Exception:
                server.close()
        return {"status": receipt["status"], "recipient": recipient,
                "message_id": message["Message-ID"], "subject": message["Subject"],
                "note": "Gmail accepted the message; check your inbox to confirm receipt."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/ai-monitor/gmail.json"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("configure")
    send = commands.add_parser("send")
    send.add_argument("--report", type=Path, default=Path("/var/lib/ai-monitor/reports/preview.txt"))
    send.add_argument("--state-dir", type=Path, default=Path("/var/lib/ai-monitor/reports/email-state"))
    send.add_argument("--max-age-hours", type=int, default=2)
    send.add_argument("--retry", action="store_true", help="Explicitly resend after checking prior delivery")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "configure":
            result = configure(args.config)
        else:
            if args.max_age_hours < 1:
                raise ValueError("max-age-hours must be positive")
            result = send_report(load_config(args.config), args.report, args.state_dir,
                                 args.max_age_hours, args.retry)
    except Exception as error:
        print("Email setup/send failed: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
