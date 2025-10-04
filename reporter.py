#!/usr/bin/env python3
"""
triage_crashes.py

Scan a directory for fuzz 'crashes' files, run them through a triager
executable (reads crash on stdin), filter uninteresting crashes (e.g.
ASAN "unknown address" SEGVs), retry transient segfaults, and email
interesting ones.

Usage example:
  ./triage_crashes.py \
    --scan-dir ~/finalfuzz/out_newest_shitfuck \
    --triager /home/user/pdftriage/pdf_fuzzer \
    --email me@example.com \
    --max-retries 12

Notes:
 - If no SMTP details are provided the script will try to use the local
   sendmail binary. If neither is available, interesting reports are
   written to ~/.fuzz_triage_outbox/ for manual inspection.
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import re
import shlex
import shutil
import smtplib
import subprocess
import sys
import time
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional, Tuple

# ----------------------------
# Configuration / defaults
# ----------------------------
DEFAULT_DB = Path.home() / ".fuzz_triage_db.json"
DEFAULT_LOG = Path.home() / ".fuzz_triage.log"
DEFAULT_OUTBOX = Path.home() / ".fuzz_triage_outbox"
SENDMAIL_PATHS = ["/usr/sbin/sendmail", "/usr/bin/sendmail", "/usr/sbin/mail"]

# ASAN-interesting error types (regex)
ASAN_INTERESTING_RE = re.compile(
    r"(heap-buffer-overflow|stack-buffer-overflow|heap-use-after-free|"
    r"global-buffer-overflow|double-free|use-after-poison|assert|"
    r"allocator-|(malloc|free).*corrupt|stack-use-after-return)",
    re.IGNORECASE,
)

# Patterns that indicate an ASAN SEGV at unknown address (ignore these)
ASAN_UNKNOWN_ADDR_RE = re.compile(r"SEGV on unknown address|unknown address", re.IGNORECASE)

# Detect AddressSanitizer presence
ASAN_PRESENT_RE = re.compile(r"AddressSanitizer:", re.IGNORECASE)

# ----------------------------
# Helpers
# ----------------------------
def load_db(path: Path) -> dict:
    if path.exists():
        try:
            with path.open("r") as f:
                return json.load(f)
        except Exception:
            logging.exception("Failed to load DB; starting fresh")
    return {}

def save_db(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as f:
        json.dump(data, f)
    tmp.replace(path)

def find_crash_files(root: Path) -> list[Path]:
    """Walks root and returns files that live in a 'crashes' directory."""
    out = []
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        # quick filter to skip huge irrelevant directories
        if "crashes" not in Path(dirpath).parts:
            continue
        for fn in files:
            p = Path(dirpath) / fn
            # skip weird special files
            if p.is_file():
                out.append(p)
    # sort by mtime ascending (oldest first)
    out.sort(key=lambda p: p.stat().st_mtime)
    return out

def run_triager(triager_cmd: str, crash_file: Path, timeout: int = 30) -> Tuple[int, str, str]:
    """
    Run triager_cmd with crash_file piped into stdin.
    Returns (returncode, stdout, stderr).
    """
    # triager_cmd may be a path or a shell command
    if isinstance(triager_cmd, str):
        cmd = shlex.split(triager_cmd)
    else:
        cmd = triager_cmd

    with crash_file.open("rb") as fin:
        try:
            proc = subprocess.run(
                cmd,
                stdin=fin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            return proc.returncode, stdout, stderr
        except subprocess.TimeoutExpired as e:
            logging.warning("triager timed out for %s", crash_file)
            return -999, "", f"TIMEOUT: {e}"
        except Exception as e:
            logging.exception("Failed to run triager")
            return -998, "", f"EXN: {e}"

def classify_output(stdout: str, stderr: str) -> Tuple[bool, str]:
    """
    Classify the triager output.
    Returns (interesting_bool, reason_string). If interesting_bool is True,
    reason_string will describe why it is interesting.
    """
    combined = stdout + "\n" + stderr
    if ASAN_PRESENT_RE.search(combined):
        # If ASAN present but unknown address mention -> not interesting
        if ASAN_UNKNOWN_ADDR_RE.search(combined):
            return False, "ASAN SEGV at unknown address -> ignore"
        # If ASAN-specific interesting signatures exist -> interesting
        if ASAN_INTERESTING_RE.search(combined):
            return True, "ASAN interesting signature"
        # ASAN present but no known interesting signature -> treat as uninteresting
        return False, "ASAN present but no interesting signature"
    # No ASAN output: if process crashed (non-zero) it's transient; caller
    # will decide to retry. If exit code==0 then nothing to do.
    return False, "No ASAN output"

def send_via_sendmail(sendmail_path: str, to_addr: str, subject: str, body: str) -> bool:
    if not Path(sendmail_path).exists():
        logging.debug("sendmail not found at %s", sendmail_path)
        return False
    headers = f"To: {to_addr}\nSubject: {subject}\n\n"
    try:
        p = subprocess.run([sendmail_path, "-t"], input=(headers + body), text=True)
        return p.returncode == 0
    except Exception:
        logging.exception("sendmail failed")
        return False

def send_via_smtp(smtp_host: str, smtp_port: int, smtp_user: Optional[str], smtp_pass: Optional[str],
                  from_addr: str, to_addr: str, subject: str, body: str, use_tls: bool) -> bool:
    try:
        msg = MIMEText(body)
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg["Subject"] = subject
        if use_tls:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.starttls()
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        if smtp_user:
            server.login(smtp_user, smtp_pass or "")
        server.sendmail(from_addr, [to_addr], msg.as_string())
        server.quit()
        return True
    except Exception:
        logging.exception("SMTP send failed")
        return False

def email_interesting(recipient: str, subject: str, body: str, smtp_cfg: dict, outbox_dir: Path) -> None:
    # Try SMTP if config provided, otherwise try sendmail, otherwise save to outbox.
    if smtp_cfg and smtp_cfg.get("host"):
        ok = send_via_smtp(
            smtp_host=smtp_cfg["host"],
            smtp_port=int(smtp_cfg.get("port", 25)),
            smtp_user=smtp_cfg.get("user"),
            smtp_pass=smtp_cfg.get("pass"),
            from_addr=smtp_cfg.get("from", smtp_cfg.get("user", "fuzz-triage@localhost")),
            to_addr=recipient,
            subject=subject,
            body=body,
            use_tls=bool(smtp_cfg.get("tls", False)),
        )
        if ok:
            logging.info("Sent email via SMTP to %s", recipient)
            return

    for sm_path in SENDMAIL_PATHS:
        if send_via_sendmail(sm_path, recipient, subject, body):
            logging.info("Sent email via sendmail (%s) to %s", sm_path, recipient)
            return

    # Fallback: save to outbox directory
    outbox_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    fname = outbox_dir / f"interesting_{ts}.txt"
    with fname.open("w") as f:
        f.write(f"Subject: {subject}\n\n")
        f.write(body)
    logging.warning("Email failed; saved report to %s", fname)

# ----------------------------
# Main processing
# ----------------------------
def process_one_file(crash_file: Path, triager_cmd: str, max_retries: int, smtp_cfg: dict, recipient: str,
                     db: dict, outbox_dir: Path, triage_timeout: int) -> None:
    key = str(crash_file.resolve())
    if key in db:
        logging.debug("Already processed %s -> skipping", crash_file)
        return

    logging.info("Processing %s", crash_file)
    attempt = 0
    final_stdout = ""
    final_stderr = ""
    final_ret = 0
    interesting = False
    reason = None

    while attempt < max_retries:
        attempt += 1
        logging.debug("Triager attempt %d/%d for %s", attempt, max_retries, crash_file)
        ret, out, err = run_triager(triager_cmd, crash_file, timeout=triage_timeout)
        final_stdout, final_stderr, final_ret = out, err, ret

        # If triager wrote ASAN output, classify it.
        is_interesting, why = classify_output(out, err)
        logging.debug("Classification: %s (%s); ret=%s", is_interesting, why, ret)

        if is_interesting:
            interesting = True
            reason = why
            break

        # if ASAN present but uninteresting, do not retry further
        if ASAN_PRESENT_RE.search(out + "\n" + err):
            logging.info("ASAN present but not interesting (%s) -> stop retries", why)
            reason = why
            break

        # If triager didn't print ASAN but crashed (non-zero) -> retry
        if ret != 0:
            # On POSIX negative returncode indicates signal; we treat that as transient
            logging.debug("Triager returned non-zero (%s) with no ASAN -> retrying", ret)
            time.sleep(0.5)  # small backoff
            continue

        # ret == 0 and no ASAN -> nothing happened; mark uninteresting and stop
        logging.info("Triager returned 0 and no ASAN output -> not interesting")
        reason = "triager returned 0 and no ASAN"
        break

    # Record in DB whether we treated it / ignored it / emailed it
    db_entry = {
        "path": key,
        "mtime": crash_file.stat().st_mtime,
        "processed_at": int(time.time()),
        "attempts": attempt,
        "triager_ret": final_ret,
        "interesting": bool(interesting),
        "reason": reason or "",
    }
    db[key] = db_entry
    # Persist DB outside caller
    # If interesting -> send email with ASAN log + filename
    if interesting:
        subject = f"Fuzzer: interesting crash - {crash_file.name}"
        body = f"Crash file: {key}\n\nTriage attempts: {attempt}\nReason: {reason}\n\n=== TRIAGER STDOUT ===\n\n{final_stdout}\n\n=== TRIAGER STDERR ===\n\n{final_stderr}\n"
        email_interesting(recipient, subject, body, smtp_cfg, outbox_dir)
        logging.info("Emailed interesting crash %s", crash_file)
    else:
        logging.info("No interesting issue for %s (%s)", crash_file, reason or "no reason")

def main() -> int:
    p = argparse.ArgumentParser(description="Scan and triage fuzz crash files")
    p.add_argument("--scan-dir", required=True, help="Root directory to scan for crashes")
    p.add_argument("--triager", required=True, help="Path to triager executable (reads crash on stdin)")
    p.add_argument("--db", default=str(DEFAULT_DB), help="JSON DB path to store processed file records")
    p.add_argument("--outbox", default=str(DEFAULT_OUTBOX), help="Fallback dir to save interesting reports")
    p.add_argument("--email", required=True, help="Recipient email address for interesting crashes")
    p.add_argument("--max-retries", type=int, default=10, help="Retries when triager segfaults without ASAN")
    p.add_argument("--timeout", type=int, default=30, help="Per-triage timeout (seconds)")
    p.add_argument("--smtp-host", help="Optional SMTP host to send mail (if not set, use sendmail)")
    p.add_argument("--smtp-port", type=int, default=587, help="SMTP port")
    p.add_argument("--smtp-user", help="SMTP user")
    p.add_argument("--smtp-pass", help="SMTP password")
    p.add_argument("--smtp-from", help="From address for SMTP")
    p.add_argument("--smtp-tls", action="store_true", help="Use STARTTLS for SMTP")
    p.add_argument("--logfile", default=str(DEFAULT_LOG), help="Log file path")
    args = p.parse_args()

    # Setup logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.StreamHandler(sys.stdout),
                                  logging.FileHandler(args.logfile)])

    scan_root = Path(args.scan_dir).expanduser().resolve()
    if not scan_root.exists():
        logging.error("Scan directory does not exist: %s", scan_root)
        return 2

    db_path = Path(args.db).expanduser().resolve()
    outbox_dir = Path(args.outbox).expanduser().resolve()

    smtp_cfg = {}
    if args.smtp_host:
        smtp_cfg["host"] = args.smtp_host
        smtp_cfg["port"] = args.smtp_port
        smtp_cfg["user"] = args.smtp_user
        smtp_cfg["pass"] = args.smtp_pass
        smtp_cfg["from"] = args.smtp_from
        smtp_cfg["tls"] = bool(args.smtp_tls)

    db = load_db(db_path)

    # find crash files under any 'crashes' subdir
    crash_files = find_crash_files(scan_root)
    logging.info("Found %d candidate files under 'crashes' directories", len(crash_files))

    for cfile in crash_files:
        try:
            process_one_file(cfile, args.triager, args.max_retries, smtp_cfg, args.email, db, outbox_dir, args.timeout)
            # persist DB after each file for safety
            save_db(db_path, db)
        except Exception:
            logging.exception("Error processing file %s", cfile)

    # done
    save_db(db_path, db)
    logging.info("Done scan")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
