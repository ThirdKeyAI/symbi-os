"""Write one bounded launcher-preparation failure report before guest poweroff."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


CHANNEL = Path("/dev/virtio-ports/org.symbi.update")
LAUNCHER_UNIT = "b.service"
STATUS_PROPERTIES = (
    "Result,ExecMainCode,ExecMainStatus,ActiveState,SubState"
)
JOURNAL_COMMAND = [
    "/usr/bin/journalctl", "--unit=b.service", "--boot=0", "--no-pager",
    "--output=short-monotonic", "--lines=24",
]
JOURNAL_MAX_BYTES = 8 * 1024
JOURNAL_MAX_LINES = 24
JOURNAL_MAX_LINE_BYTES = 512
COMMAND_STDOUT_MAX_BYTES = 64 * 1024
COMMAND_STDERR_MAX_BYTES = 8 * 1024
REPORT_MAX_BYTES = 128 * 1024
SCOPE = "Bounded launcher-preparation diagnostics; no update action ran"
_SENSITIVE_COMPONENT = (
    r"(?:(?:api|private)[_.-]key|authorization|authentication|auth|cookie|"
    r"credential|password|passwd|passphrase|secret|token|jwt|pat|key)"
)
_SENSITIVE_IDENTIFIER = (
    r"(?:[A-Za-z0-9]+[_.-])*" + _SENSITIVE_COMPONENT
    + r"(?:[_.-][A-Za-z0-9]+)*"
)
_SENSITIVE_KEY = (
    r"(?:[\"']" + _SENSITIVE_IDENTIFIER + r"[\"']"
    + r"|-{1,2}" + _SENSITIVE_IDENTIFIER
    + r"|" + _SENSITIVE_IDENTIFIER + r")"
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(" + _SENSITIVE_KEY
    + r")(\s*[:=]\s*|\s+)(.*)$"
)
_BEARER_VALUE = re.compile(r"(?i)\bbearer\s+[^ ]+")
_LONG_VALUE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{48,}(?![A-Za-z0-9])")


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def service_properties(raw):
    """Parse exactly the five fixed systemd failure fields."""
    if (not isinstance(raw, str) or not raw.endswith("\n")
            or not 0 < len(raw.encode()) <= 4096):
        raise ValueError("invalid launcher service property output")
    allowed = set(STATUS_PROPERTIES.split(","))
    properties = {}
    for line in raw.splitlines():
        if "=" not in line:
            raise ValueError("malformed launcher service property output")
        key, value = line.split("=", 1)
        if (key not in allowed or key in properties or not value
                or len(value.encode()) > 128):
            raise ValueError("ambiguous launcher service property output")
        properties[key] = value
    if set(properties) != allowed:
        raise ValueError("incomplete launcher service property output")
    if (properties["Result"] == "success"
            or properties["ActiveState"] != "failed"
            or properties["SubState"] != "failed"
            or re.fullmatch(r"[0-9]{1,3}", properties["ExecMainCode"]) is None
            or re.fullmatch(r"[0-9]{1,3}", properties["ExecMainStatus"]) is None
            or properties["ExecMainStatus"] == "0"):
        raise ValueError("launcher service did not fail closed")
    return properties


def _sanitize_line(line):
    line = "".join(character if " " <= character <= "~" else "?"
                   for character in line)
    line = _SENSITIVE_ASSIGNMENT.sub(lambda match: match.group(1)
                                     + match.group(2) + "<redacted>", line)
    line = _BEARER_VALUE.sub("Bearer <redacted>", line)
    return _LONG_VALUE.sub("<redacted>", line)


def bounded_journal_excerpt(raw):
    """Return a printable, redacted journal excerpt under fixed byte limits."""
    if not isinstance(raw, str):
        raise ValueError("invalid launcher journal output")
    encoded = raw.encode("utf-8", errors="strict")
    truncated = len(encoded) > JOURNAL_MAX_BYTES
    prefix = encoded[:JOURNAL_MAX_BYTES].decode("utf-8", errors="ignore")
    source_lines = prefix.splitlines()
    if len(source_lines) > JOURNAL_MAX_LINES:
        truncated = True
        source_lines = source_lines[:JOURNAL_MAX_LINES]
    excerpt = []
    used = 0
    for source_line in source_lines:
        line = _sanitize_line(source_line)
        if len(line.encode("ascii")) > JOURNAL_MAX_LINE_BYTES:
            line = line[:JOURNAL_MAX_LINE_BYTES - 3] + "..."
            truncated = True
        remaining = JOURNAL_MAX_BYTES - used
        if remaining <= 1:
            truncated = True
            break
        if len(line.encode("ascii")) + 1 > remaining:
            if remaining <= 4:
                truncated = True
                break
            line = line[:remaining - 4] + "..."
            truncated = True
        excerpt.append(line)
        used += len(line.encode("ascii")) + 1
        if used >= JOURNAL_MAX_BYTES:
            break
    payload = ("\n".join(excerpt) + ("\n" if excerpt else "")).encode("ascii")
    if len(payload) > JOURNAL_MAX_BYTES:
        raise ValueError("bounded launcher journal exceeded its limit")
    return {
        "unit": LAUNCHER_UNIT,
        "command": JOURNAL_COMMAND,
        "line_count": len(excerpt),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "truncated": truncated,
        "excerpt": excerpt,
    }


def fixed_command(command, *, timeout, stdout_max):
    if (not isinstance(command, list) or not command
            or any(not isinstance(value, str) or not value for value in command)
            or type(timeout) is not int or not 1 <= timeout <= 30
            or type(stdout_max) is not int or not 1 <= stdout_max <= COMMAND_STDOUT_MAX_BYTES):
        raise ValueError("invalid launcher diagnostic command")
    result = subprocess.run(
        command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=timeout,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if (len(result.stdout.encode()) > stdout_max
            or len(result.stderr.encode()) > COMMAND_STDERR_MAX_BYTES):
        raise ValueError("launcher diagnostic command output exceeded its bound")
    result.check_returncode()
    return result.stdout


def write_report(report, channel=CHANNEL):
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if not 0 < len(raw) <= REPORT_MAX_BYTES:
        raise ValueError("launcher diagnostic report exceeded its bound")
    deadline = time.monotonic() + 15
    while not Path(channel).exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    with Path(channel).open("wb", buffering=0) as output:
        output.write(raw)


def main():
    product = Path("/sys/class/dmi/id/product_name").read_text().strip()
    if (os.geteuid() != 0 or product != "Symbi-Hosted-Update-Probe"
            or Path("/run/.containerenv").exists() or len(sys.argv) != 1):
        raise SystemExit("Use only the disposable hosted update guest")
    properties = service_properties(fixed_command([
        "/usr/bin/systemctl", "show", LAUNCHER_UNIT,
        "--property=" + STATUS_PROPERTIES,
    ], timeout=10, stdout_max=4096))
    journal = bounded_journal_excerpt(fixed_command(
        JOURNAL_COMMAND, timeout=10, stdout_max=COMMAND_STDOUT_MAX_BYTES))
    report = {
        "schema": 1,
        "passed": False,
        "guest_booted": True,
        "release_qualified": False,
        "product": product,
        "diagnostic": "launcher-preparation-failure",
        "unit": LAUNCHER_UNIT,
        "runner_sha256": sha256(Path(__file__)),
        "service": properties,
        "journal": journal,
        "scope": SCOPE,
    }
    write_report(report)


if __name__ == "__main__":
    main()
