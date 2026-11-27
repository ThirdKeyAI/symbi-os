"""Write one bounded explicit-transition failure report before guest poweroff."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time


CHANNEL = Path("/dev/virtio-ports/org.symbi.update")
COLLECTOR_CHANNEL = Path("/dev/virtio-ports/org.symbi.update.diagnostic")
LAUNCHER_UNIT = "b.service"
SOURCE_CAPTURE_COMMAND = ["/usr/bin/cat", "/proc/self/attr/current"]
BOOTC_CONTEXT = "system_u:system_r:install_t:s0"
BOOTC_PROBE_COMMAND = [
    "/usr/bin/runcon", BOOTC_CONTEXT, "/usr/bin/bootc", "--version",
]
STATUS_PROPERTIES = (
    "Result,ExecMainCode,ExecMainStatus,ActiveState,SubState,InvocationID,"
    "ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic"
)
JOURNAL_COMMAND = [
    "/usr/bin/journalctl", "--unit=b.service", "--boot=0", "--no-pager",
    "--output=short-monotonic", "--lines=24",
]
JOURNAL_MAX_BYTES = 8 * 1024
JOURNAL_MAX_LINES = 24
JOURNAL_MAX_LINE_BYTES = 512
SOURCE_JOURNAL_COMMAND = [
    "/usr/bin/journalctl", "--unit=b.service", "--boot=0", "--no-pager",
    "--quiet", "--output=json",
    "--output-fields=MESSAGE,__CURSOR,__MONOTONIC_TIMESTAMP,_COMM,_PID,"
    "_TRANSPORT,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID", "--lines=25",
]
AVC_JOURNAL_COMMAND = [
    "/usr/bin/journalctl", "--boot=0", "--no-pager", "--quiet",
    "--output=json",
    "--output-fields=MESSAGE,__CURSOR,__MONOTONIC_TIMESTAMP,_TRANSPORT",
    "--lines=33",
    "--grep=avc:[[:space:]]+denied.*comm=\"runcon\".*(?:path|name)=\"/usr/bin/bootc\"",
    "_TRANSPORT=audit", "+", "_TRANSPORT=kernel",
]
STRUCTURED_JOURNAL_MAX_BYTES = 64 * 1024
STRUCTURED_JOURNAL_MAX_LINE_BYTES = 8192
SOURCE_JOURNAL_MAX_RECORDS = 24
AVC_MAX_RECORDS = 32
JOURNAL_CORRELATION_MARGIN_USEC = 120 * 1_000_000
COMMAND_STDOUT_MAX_BYTES = 64 * 1024
COMMAND_STDERR_MAX_BYTES = 8 * 1024
AVC_STDERR_MAX_BYTES = 0
REPORT_MAX_BYTES = 128 * 1024
SCOPE = "Bounded explicit-transition diagnostics; no update action ran"
COLLECTOR_SCOPE = "Bounded collector progress; no transition or update claim"
COLLECTOR_MAX_EVENT_BYTES = 1024
COLLECTOR_STAGES = (
    "service-properties", "source-journal", "monitor", "identity-correlation",
    "avc-journal", "bounded-journal", "report-build", "primary-report-write",
)
AVC_FAILURE_REASONS = frozenset({
    "command-timeout", "spawn-permission", "spawn-os-error",
    "command-result-invalid", "stdout-truncated", "stderr-truncated",
    "stderr-nonempty", "unexpected-exit", "no-match-output-nonempty",
    "records-output-empty", "stdout-invalid-utf8", "source-invalid",
    "journal-output-invalid", "journal-output-empty-or-truncated",
    "journal-record-oversized", "journal-record-invalid-json",
    "journal-record-duplicate-key", "journal-record-incomplete",
    "denial-malformed", "permissions-invalid", "field-ambiguous",
    "probe-binding-mismatch", "process-correlation-mismatch",
    "source-correlation-mismatch", "records-duplicated", "records-invalid",
})
AVC_COMMAND_SHA256 = hashlib.sha256(json.dumps(
    AVC_JOURNAL_COMMAND, separators=(",", ":")).encode()).hexdigest()
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
_SELINUX_CONTEXT = re.compile(
    r"[A-Za-z0-9_.-]{1,64}:[A-Za-z0-9_.-]{1,64}:"
    r"[A-Za-z0-9_.-]{1,128}:[A-Za-z0-9_.:,-]{1,192}"
)
_JOURNAL_CURSOR = re.compile(r"[A-Za-z0-9_.:;=-]{32,2048}")
_INVOCATION_ID = re.compile(r"[a-f0-9]{32}")


class AvcEvidenceError(ValueError):
    """Carry one fixed content-free AVC rejection observation."""

    def __init__(self, reason, observation, failure_kind="invalid-evidence"):
        if not isinstance(reason, str) or reason not in AVC_FAILURE_REASONS:
            raise ValueError("invalid AVC failure reason")
        self.reason = reason
        self.observation = observation
        self.failure_kind = failure_kind
        super().__init__("AVC evidence rejected: " + reason)


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _unique_json(raw, description):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate " + description + " key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError(description + " must be an object")
    return value


def _structured_journal_lines(raw, maximum):
    if (not isinstance(raw, str)
            or not 0 < len(raw.encode()) <= STRUCTURED_JOURNAL_MAX_BYTES):
        raise ValueError("invalid structured transition journal output")
    lines = raw.splitlines()
    if not 1 <= len(lines) <= maximum:
        raise ValueError("structured transition journal is empty or truncated")
    result = []
    for line in lines:
        if not 0 < len(line.encode()) <= STRUCTURED_JOURNAL_MAX_LINE_BYTES:
            raise ValueError("structured transition journal record exceeded its limit")
        try:
            result.append(_unique_json(line, "structured transition journal record"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("invalid structured transition journal record") from error
    return result


def parse_source_capture(raw, invocation_id):
    """Bind the fixed pre-probe cat output to this service invocation."""
    if (not isinstance(invocation_id, str)
            or _INVOCATION_ID.fullmatch(invocation_id) is None):
        raise ValueError("invalid transition-probe invocation identity")
    matches = []
    for item in _structured_journal_lines(raw, SOURCE_JOURNAL_MAX_RECORDS):
        if (item.get("_COMM") != "cat" or item.get("_TRANSPORT") != "stdout"
                or item.get("_SYSTEMD_UNIT") != LAUNCHER_UNIT
                or item.get("_SYSTEMD_INVOCATION_ID") != invocation_id):
            continue
        context = item.get("MESSAGE")
        cursor = item.get("__CURSOR")
        monotonic = item.get("__MONOTONIC_TIMESTAMP")
        pid_text = item.get("_PID")
        if (not isinstance(context, str) or _SELINUX_CONTEXT.fullmatch(context) is None
                or not isinstance(cursor, str)
                or _JOURNAL_CURSOR.fullmatch(cursor) is None
                or not isinstance(monotonic, str)
                or re.fullmatch(r"[0-9]{1,20}", monotonic) is None
                or not isinstance(pid_text, str)
                or re.fullmatch(r"[0-9]{1,10}", pid_text) is None
                or not 0 < int(pid_text) <= 2**31 - 1):
            raise ValueError("invalid transition source-context observation")
        matches.append({
            "command": SOURCE_CAPTURE_COMMAND,
            "journal_command": SOURCE_JOURNAL_COMMAND,
            "source_context": context,
            "requested_context": BOOTC_CONTEXT,
            "probe_command": BOOTC_PROBE_COMMAND,
            "invocation_id": invocation_id,
            "pid": int(pid_text),
            "transport": "stdout",
            "receipt_monotonic_usec": int(monotonic),
            "cursor_sha256": hashlib.sha256(cursor.encode()).hexdigest(),
        })
    if len(matches) != 1:
        raise ValueError("transition source context is absent or ambiguous")
    return matches[0]


def service_properties(raw):
    """Parse the fixed systemd failure fields and invocation identity."""
    if (not isinstance(raw, str) or not raw.endswith("\n")
            or not 0 < len(raw.encode()) <= 4096):
        raise ValueError("invalid transition-probe service property output")
    allowed = set(STATUS_PROPERTIES.split(","))
    properties = {}
    for line in raw.splitlines():
        if "=" not in line:
            raise ValueError("malformed transition-probe service property output")
        key, value = line.split("=", 1)
        if (key not in allowed or key in properties or not value
                or len(value.encode()) > 128):
            raise ValueError("ambiguous transition-probe service property output")
        properties[key] = value
    if set(properties) != allowed:
        raise ValueError("incomplete transition-probe service property output")
    main_pid = properties.get("ExecMainPID", "")
    started = properties.get("ExecMainStartTimestampMonotonic", "")
    exited = properties.get("ExecMainExitTimestampMonotonic", "")
    if (properties["Result"] == "success"
            or properties["ActiveState"] != "failed"
            or properties["SubState"] != "failed"
            or re.fullmatch(r"[0-9]{1,3}", properties["ExecMainCode"]) is None
            or re.fullmatch(r"[0-9]{1,3}", properties["ExecMainStatus"]) is None
            or properties["ExecMainStatus"] == "0"
            or _INVOCATION_ID.fullmatch(properties["InvocationID"]) is None
            or re.fullmatch(r"[0-9]{1,10}", main_pid) is None
            or not 0 < int(main_pid) <= 2**31 - 1
            or re.fullmatch(r"[0-9]{1,20}", started) is None
            or re.fullmatch(r"[0-9]{1,20}", exited) is None
            or not 0 < int(started) <= int(exited) <= 2**63 - 1):
        raise ValueError("transition-probe service did not fail closed")
    return properties


def monitor_properties(environment=None):
    """Bind the OnFailure activation to the exact failed b.service invocation."""
    environment = os.environ if environment is None else environment
    monitor = {
        "unit": environment.get("MONITOR_UNIT", ""),
        "invocation_id": environment.get("MONITOR_INVOCATION_ID", ""),
        "service_result": environment.get("MONITOR_SERVICE_RESULT", ""),
        "exit_code": environment.get("MONITOR_EXIT_CODE", ""),
        "exit_status": environment.get("MONITOR_EXIT_STATUS", ""),
    }
    if (monitor["unit"] != LAUNCHER_UNIT
            or _INVOCATION_ID.fullmatch(monitor["invocation_id"]) is None
            or monitor["service_result"] == "success"
            or monitor["exit_code"] != "exited"
            or re.fullmatch(r"[0-9]{1,3}", monitor["exit_status"]) is None
            or monitor["exit_status"] == "0"):
        raise ValueError("invalid transition-probe OnFailure activation")
    return monitor


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
        raise ValueError("invalid transition-probe journal output")
    encoded = raw.encode("utf-8", errors="strict")
    truncated = len(encoded) > JOURNAL_MAX_BYTES
    source_lines = raw.splitlines()
    if len(source_lines) > JOURNAL_MAX_LINES:
        truncated = True
        source_lines = source_lines[:JOURNAL_MAX_LINES]
    excerpt = []
    used = 0
    for source_line in source_lines:
        line = _sanitize_line(source_line)
        if len(line.encode("ascii")) > JOURNAL_MAX_LINE_BYTES:
            line = "<line omitted: over 512-byte limit>"
            truncated = True
        remaining = JOURNAL_MAX_BYTES - used
        if remaining <= 1:
            truncated = True
            break
        if len(line.encode("ascii")) + 1 > remaining:
            truncated = True
            marker = "<remaining lines omitted: output limit>"
            if len(marker.encode("ascii")) + 1 <= remaining:
                excerpt.append(marker)
                used += len(marker.encode("ascii")) + 1
            break
        excerpt.append(line)
        used += len(line.encode("ascii")) + 1
        if used >= JOURNAL_MAX_BYTES:
            break
    payload = ("\n".join(excerpt) + ("\n" if excerpt else "")).encode("ascii")
    if len(payload) > JOURNAL_MAX_BYTES:
        raise ValueError("bounded transition-probe journal exceeded its limit")
    return {
        "unit": LAUNCHER_UNIT,
        "command": JOURNAL_COMMAND,
        "line_count": len(excerpt),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "truncated": truncated,
        "excerpt": excerpt,
    }


def _avc_field(message, name, *, quoted=False):
    pattern = (r'(?:^| )' + re.escape(name) + r'="([^"\x00]+)"'
               if quoted else
               r'(?:^| )' + re.escape(name) + r'=([^ \x00]+)')
    matches = re.findall(pattern, message)
    if len(matches) != 1:
        raise ValueError("ambiguous transition AVC " + name)
    return matches[0]


def parse_avc_evidence(raw, source, service=None):
    """Retain only allowlisted fields from enforcing AVCs for this exact probe."""
    source_context = (source.get("source_context")
                      if isinstance(source, dict) else None)
    if (not isinstance(source_context, str)
            or _SELINUX_CONTEXT.fullmatch(source_context) is None
            or source.get("requested_context") != BOOTC_CONTEXT):
        raise ValueError("invalid transition source observation")
    items = _structured_journal_lines(raw, AVC_MAX_RECORDS)
    records = []
    for item in items:
        message = item.get("MESSAGE")
        cursor = item.get("__CURSOR")
        monotonic = item.get("__MONOTONIC_TIMESTAMP")
        transport = item.get("_TRANSPORT")
        if (not isinstance(message, str) or not 0 < len(message.encode()) <= 4096
                or any(not " " <= character <= "~" for character in message)
                or not isinstance(cursor, str)
                or _JOURNAL_CURSOR.fullmatch(cursor) is None
                or not isinstance(monotonic, str)
                or re.fullmatch(r"[0-9]{1,20}", monotonic) is None
                or not isinstance(transport, str)
                or transport not in {"audit", "kernel"}):
            raise ValueError("incomplete transition AVC journal record")
        denial = re.search(
            r"avc:[ ]+denied[ ]+\{[ ]*([a-z0-9_ ]+?)[ ]*\}[ ]+for\b", message)
        serial = re.search(r"audit\([0-9]+(?:\.[0-9]+)?:([0-9]{1,20})\)", message)
        if denial is None or serial is None:
            raise ValueError("malformed transition AVC denial")
        permissions = denial.group(1).split()
        if (not 1 <= len(permissions) <= 16 or len(set(permissions)) != len(permissions)
                or any(re.fullmatch(r"[a-z0-9_]{1,64}", value) is None
                       for value in permissions)):
            raise ValueError("invalid transition AVC permissions")
        path_matches = []
        for field in ("path", "name"):
            found = re.findall(r'(?:^| )' + field + r'="([^"\x00]+)"', message)
            path_matches.extend((field, value) for value in found)
        source_context = _avc_field(message, "scontext")
        target_context = _avc_field(message, "tcontext")
        target_class = _avc_field(message, "tclass")
        permissive = _avc_field(message, "permissive")
        pid_text = _avc_field(message, "pid")
        timestamp = int(monotonic)
        pid = int(pid_text) if re.fullmatch(r"[0-9]{1,10}", pid_text) else 0
        audit_serial = int(serial.group(1))
        if (len(path_matches) != 1 or path_matches[0][1] != "/usr/bin/bootc"
                or _avc_field(message, "comm", quoted=True) != "runcon"
                or _SELINUX_CONTEXT.fullmatch(source_context) is None
                or _SELINUX_CONTEXT.fullmatch(target_context) is None
                or re.fullmatch(r"[a-z0-9_]{1,64}", target_class) is None
                or permissive != "0" or not 0 < pid <= 2**31 - 1
                or not 0 < audit_serial <= 2**63 - 1
                ):
            raise ValueError("transition AVC does not bind the enforcing probe")
        if (service is not None
                and (pid != int(service["ExecMainPID"])
                     or not max(0, int(service["ExecMainStartTimestampMonotonic"])
                                - JOURNAL_CORRELATION_MARGIN_USEC)
                     <= timestamp
                     <= int(service["ExecMainExitTimestampMonotonic"])
                        + JOURNAL_CORRELATION_MARGIN_USEC)):
            raise ValueError("transition AVC falls outside the main process")
        records.append({
            "audit_serial": audit_serial,
            "transport": transport,
            "receipt_monotonic_usec": timestamp,
            "pid": pid,
            "comm": "runcon",
            "path_field": path_matches[0][0],
            "path": "/usr/bin/bootc",
            "source_context": source_context,
            "target_context": target_context,
            "class": target_class,
            "permissions": permissions,
            "permissive": False,
            "cursor_sha256": hashlib.sha256(cursor.encode()).hexdigest(),
        })
    allowed_sources = {source["source_context"], source["requested_context"]}
    if any(item["source_context"] not in allowed_sources for item in records):
        raise ValueError("transition AVC source does not bind the requested transition")
    if (len({item["audit_serial"] for item in records}) != len(records)
            or len({item["cursor_sha256"] for item in records}) != len(records)):
        raise ValueError("transition AVC records are duplicated")
    return {
        "command": AVC_JOURNAL_COMMAND,
        "query_result": "records",
        "raw_bytes": len(raw.encode()),
        "raw_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "line_count": len(items),
        "truncated": False,
        "records": records,
    }


def _kill_and_reap(process):
    """Kill one owned live child, then wait without a deadline until it is reaped."""
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    returncode = process.wait()
    if type(returncode) is not int:
        raise RuntimeError("bounded diagnostic child was not reaped")
    return returncode


def bounded_command_result(command, *, timeout, stdout_max, stderr_max):
    """Run one fixed command and retain bounded bytes plus exact process status."""
    if (not isinstance(command, list) or not command
            or any(not isinstance(value, str) or not value for value in command)
            or type(timeout) is not int or not 1 <= timeout <= 30
            or type(stdout_max) is not int or not 1 <= stdout_max <= COMMAND_STDOUT_MAX_BYTES
            or type(stderr_max) is not int
            or not 0 <= stderr_max <= COMMAND_STDERR_MAX_BYTES):
        raise ValueError("invalid bounded diagnostic command")
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    cleanup_attempted = False
    selector = None
    try:
        deadline = time.monotonic() + timeout
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        maxima = {"stdout": stdout_max, "stderr": stderr_max}
        truncated = {"stdout": False, "stderr": False}
        timed_out = False
        returncode = None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        stop = False
        while selector.get_map() and not stop:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(remaining)
            if not events:
                timed_out = True
                break
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                name = key.data
                maximum = maxima[name]
                room = max(0, maximum + 1 - len(buffers[name]))
                buffers[name].extend(chunk[:room])
                if len(chunk) > room or len(buffers[name]) > maximum:
                    truncated[name] = True
                    stop = True
                    break
        if timed_out or any(truncated.values()):
            cleanup_attempted = True
            returncode = _kill_and_reap(process)
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                cleanup_attempted = True
                returncode = _kill_and_reap(process)
            else:
                try:
                    returncode = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    cleanup_attempted = True
                    returncode = _kill_and_reap(process)
        if type(returncode) is not int:
            raise RuntimeError("bounded diagnostic child was not reaped")
    except BaseException:
        if not cleanup_attempted:
            cleanup_attempted = True
            _kill_and_reap(process)
        raise
    finally:
        if selector is not None:
            selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    return {
        "command": list(command),
        "exit_code": returncode,
        "timed_out": timed_out,
        "stdout": bytes(buffers["stdout"]),
        "stderr": bytes(buffers["stderr"]),
        "stdout_truncated": truncated["stdout"],
        "stderr_truncated": truncated["stderr"],
    }


def _empty_avc_observation(*, timed_out=False):
    empty_hash = hashlib.sha256(b"").hexdigest()
    return {
        "command_sha256": AVC_COMMAND_SHA256,
        "exit_code": None,
        "timed_out": timed_out,
        "stdout_bytes": 0,
        "stdout_sha256": empty_hash,
        "stdout_truncated": False,
        "stderr_bytes": 0,
        "stderr_sha256": empty_hash,
        "stderr_truncated": False,
    }


def _avc_command_observation(result):
    required = {
        "command", "exit_code", "timed_out", "stdout", "stderr",
        "stdout_truncated", "stderr_truncated",
    }
    if (not isinstance(result, dict) or set(result) != required
            or result.get("command") != AVC_JOURNAL_COMMAND
            or type(result.get("exit_code")) is not int
            or not -2**31 <= result["exit_code"] <= 255
            or type(result.get("timed_out")) is not bool
            or not isinstance(result.get("stdout"), bytes)
            or not isinstance(result.get("stderr"), bytes)
            or type(result.get("stdout_truncated")) is not bool
            or type(result.get("stderr_truncated")) is not bool
            or len(result["stdout"]) > STRUCTURED_JOURNAL_MAX_BYTES + 1
            or len(result["stderr"]) > AVC_STDERR_MAX_BYTES + 1
            or (result["stdout_truncated"]
                != (len(result["stdout"]) == STRUCTURED_JOURNAL_MAX_BYTES + 1))
            or (result["stderr_truncated"]
                != (len(result["stderr"]) == AVC_STDERR_MAX_BYTES + 1))):
        raise ValueError("invalid bounded AVC command result")
    return {
        "command_sha256": AVC_COMMAND_SHA256,
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "stdout_bytes": len(result["stdout"]),
        "stdout_sha256": hashlib.sha256(result["stdout"]).hexdigest(),
        "stdout_truncated": result["stdout_truncated"],
        "stderr_bytes": len(result["stderr"]),
        "stderr_sha256": hashlib.sha256(result["stderr"]).hexdigest(),
        "stderr_truncated": result["stderr_truncated"],
    }


def _avc_parse_reason(error):
    message = str(error)
    exact = {
        "invalid transition source observation": "source-invalid",
        "invalid structured transition journal output": "journal-output-invalid",
        "structured transition journal is empty or truncated":
            "journal-output-empty-or-truncated",
        "structured transition journal record exceeded its limit":
            "journal-record-oversized",
        "invalid structured transition journal record": "journal-record-invalid-json",
        "incomplete transition AVC journal record": "journal-record-incomplete",
        "malformed transition AVC denial": "denial-malformed",
        "invalid transition AVC permissions": "permissions-invalid",
        "transition AVC does not bind the enforcing probe": "probe-binding-mismatch",
        "transition AVC falls outside the main process":
            "process-correlation-mismatch",
        "transition AVC source does not bind the requested transition":
            "source-correlation-mismatch",
        "transition AVC records are duplicated": "records-duplicated",
    }
    if message in exact:
        return exact[message]
    if message.startswith("ambiguous transition AVC "):
        return "field-ambiguous"
    if message == "duplicate structured transition journal record key":
        return "journal-record-duplicate-key"
    return "records-invalid"


def _raise_avc(reason, observation, failure_kind="invalid-evidence"):
    raise AvcEvidenceError(reason, observation, failure_kind)


def bounded_avc_evidence(source, service, run=None):
    """Query only runcon/bootc AVC denials from the current boot."""
    run = bounded_command_result if run is None else run
    try:
        result = run(
            AVC_JOURNAL_COMMAND, timeout=5,
            stdout_max=STRUCTURED_JOURNAL_MAX_BYTES,
            stderr_max=AVC_STDERR_MAX_BYTES)
    except subprocess.TimeoutExpired:
        _raise_avc("command-timeout", _empty_avc_observation(timed_out=True),
                   "timeout")
    except PermissionError:
        _raise_avc("spawn-permission", _empty_avc_observation(), "permission")
    except OSError:
        _raise_avc("spawn-os-error", _empty_avc_observation(), "os-error")
    try:
        observation = _avc_command_observation(result)
    except (TypeError, ValueError):
        _raise_avc("command-result-invalid", _empty_avc_observation())
    if observation["timed_out"]:
        _raise_avc("command-timeout", observation, "timeout")
    if observation["stdout_truncated"]:
        _raise_avc("stdout-truncated", observation)
    if observation["stderr_truncated"]:
        _raise_avc("stderr-truncated", observation)
    if observation["stderr_bytes"]:
        _raise_avc("stderr-nonempty", observation)
    stdout = result["stdout"]
    if observation["exit_code"] == 1:
        if stdout:
            _raise_avc("no-match-output-nonempty", observation)
        return {
            "command": AVC_JOURNAL_COMMAND,
            "command_observation": observation,
            "query_result": "no-match",
            "raw_bytes": 0,
            "raw_sha256": hashlib.sha256(b"").hexdigest(),
            "line_count": 0,
            "truncated": False,
            "records": [],
        }
    if observation["exit_code"] != 0:
        _raise_avc("unexpected-exit", observation, "command-exit")
    if not stdout:
        _raise_avc("records-output-empty", observation)
    try:
        raw = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _raise_avc("stdout-invalid-utf8", observation)
    try:
        parsed = parse_avc_evidence(raw, source, service)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        _raise_avc(_avc_parse_reason(error), observation)
    parsed["command_observation"] = observation
    return parsed


def fixed_command(command, *, timeout, stdout_max,
                  stderr_max=COMMAND_STDERR_MAX_BYTES):
    if (not isinstance(command, list) or not command
            or any(not isinstance(value, str) or not value for value in command)
            or type(timeout) is not int or not 1 <= timeout <= 30
            or type(stdout_max) is not int or not 1 <= stdout_max <= COMMAND_STDOUT_MAX_BYTES
            or type(stderr_max) is not int
            or not 0 <= stderr_max <= COMMAND_STDERR_MAX_BYTES):
        raise ValueError("invalid transition-probe diagnostic command")
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    deadline = time.monotonic() + timeout
    stdout = bytearray()
    stderr_bytes = 0
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(command, timeout)
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.data == "stdout":
                    stdout.extend(chunk)
                    exceeded = len(stdout) > stdout_max
                else:
                    stderr_bytes += len(chunk)
                    exceeded = stderr_bytes > stderr_max
                if exceeded:
                    raise ValueError(
                        "transition-probe diagnostic command output exceeded its bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        returncode = process.wait(timeout=remaining)
    except BaseException:
        process.kill()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    if returncode != 0:
        raise subprocess.CalledProcessError(returncode, command)
    try:
        return stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("transition-probe diagnostic output is not UTF-8") from error


def write_report(report, channel=CHANNEL):
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if not 0 < len(raw) <= REPORT_MAX_BYTES:
        raise ValueError("transition-probe diagnostic report exceeded its bound")
    deadline = time.monotonic() + 15
    channel = Path(channel)
    while not channel.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    with channel.open("wb", buffering=0) as output:
        _write_all(output, raw, "transition report channel")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _write_all(output, raw, description):
    offset = 0
    while offset < len(raw):
        written = output.write(raw[offset:])
        if type(written) is not int or not 0 < written <= len(raw) - offset:
            raise RuntimeError(description + " stopped accepting data")
        offset += written


def open_collector_channel(channel=COLLECTOR_CHANNEL):
    """Open the auxiliary port without waiting; absence cannot block the report."""
    descriptor = None
    try:
        channel = Path(channel)
        flags = os.O_WRONLY | os.O_CLOEXEC | os.O_NONBLOCK
        descriptor = os.open(channel, flags)
        if not stat.S_ISCHR(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            return None
        return descriptor
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException:
                pass
        return None


def collector_failure_kind(error):
    """Reduce an exception to a fixed, content-free diagnostic class."""
    if isinstance(error, AvcEvidenceError):
        return error.failure_kind
    if isinstance(error, subprocess.TimeoutExpired):
        return "timeout"
    if isinstance(error, subprocess.CalledProcessError):
        return "command-exit"
    if isinstance(error, PermissionError):
        return "permission"
    if isinstance(error, OSError):
        return "os-error"
    if isinstance(error, (UnicodeError, json.JSONDecodeError, ValueError)):
        return "invalid-evidence"
    if isinstance(error, RuntimeError):
        return "transport"
    return "unexpected"


def _valid_avc_command_observation(observation):
    fields = {
        "command_sha256", "exit_code", "timed_out", "stdout_bytes",
        "stdout_sha256", "stdout_truncated", "stderr_bytes", "stderr_sha256",
        "stderr_truncated",
    }
    if (not isinstance(observation, dict) or set(observation) != fields
            or not isinstance(observation.get("command_sha256"), str)
            or observation["command_sha256"] != AVC_COMMAND_SHA256
            or (observation.get("exit_code") is not None
                and (type(observation["exit_code"]) is not int
                     or not -2**31 <= observation["exit_code"] <= 255))
            or type(observation.get("timed_out")) is not bool
            or type(observation.get("stdout_bytes")) is not int
            or not 0 <= observation["stdout_bytes"] <= STRUCTURED_JOURNAL_MAX_BYTES + 1
            or not isinstance(observation.get("stdout_sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}",
                            observation["stdout_sha256"]) is None
            or type(observation.get("stdout_truncated")) is not bool
            or type(observation.get("stderr_bytes")) is not int
            or not 0 <= observation["stderr_bytes"] <= AVC_STDERR_MAX_BYTES + 1
            or not isinstance(observation.get("stderr_sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}",
                            observation["stderr_sha256"]) is None
            or type(observation.get("stderr_truncated")) is not bool
            or observation["stdout_truncated"]
               != (observation["stdout_bytes"] == STRUCTURED_JOURNAL_MAX_BYTES + 1)
            or observation["stderr_truncated"]
               != (observation["stderr_bytes"] == AVC_STDERR_MAX_BYTES + 1)):
        return False
    empty_hash = hashlib.sha256(b"").hexdigest()
    if ((observation["stdout_bytes"] == 0)
            != (observation["stdout_sha256"] == empty_hash)
            or (observation["stderr_bytes"] == 0)
               != (observation["stderr_sha256"] == empty_hash)):
        return False
    return True


def _valid_avc_failure_detail(detail):
    if (not isinstance(detail, dict) or set(detail) != {"reason", "command"}
            or not isinstance(detail.get("reason"), str)
            or detail["reason"] not in AVC_FAILURE_REASONS
            or not _valid_avc_command_observation(detail.get("command"))):
        return False
    reason = detail["reason"]
    observation = detail["command"]
    parser_reasons = AVC_FAILURE_REASONS - {
        "command-timeout", "spawn-permission", "spawn-os-error",
        "command-result-invalid", "stdout-truncated", "stderr-truncated",
        "stderr-nonempty", "unexpected-exit", "no-match-output-nonempty",
        "records-output-empty", "stdout-invalid-utf8",
    }
    if observation["exit_code"] is None:
        if observation["timed_out"]:
            return (reason == "command-timeout"
                    and observation["stdout_bytes"] == 0
                    and observation["stderr_bytes"] == 0
                    and not observation["stdout_truncated"]
                    and not observation["stderr_truncated"])
        return (reason in {
            "spawn-permission", "spawn-os-error", "command-result-invalid",
        } and observation["stdout_bytes"] == 0
                and observation["stderr_bytes"] == 0
                and not observation["stdout_truncated"]
                and not observation["stderr_truncated"])
    if observation["timed_out"]:
        return reason == "command-timeout"
    if observation["stdout_truncated"]:
        return reason == "stdout-truncated"
    if observation["stderr_truncated"]:
        return reason == "stderr-truncated"
    if observation["stderr_bytes"]:
        return reason == "stderr-nonempty"
    if observation["exit_code"] == 1:
        return (observation["stdout_bytes"] > 0
                and reason == "no-match-output-nonempty")
    if observation["exit_code"] != 0:
        return reason == "unexpected-exit"
    if observation["stdout_bytes"] == 0:
        return reason == "records-output-empty"
    return reason == "stdout-invalid-utf8" or reason in parser_reasons


def _avc_failure_kind(reason):
    return {
        "command-timeout": "timeout",
        "spawn-permission": "permission",
        "spawn-os-error": "os-error",
        "unexpected-exit": "command-exit",
    }.get(reason, "invalid-evidence")


def collector_failure_detail(error):
    """Return only the fixed AVC reason and content-free command observation."""
    if not isinstance(error, AvcEvidenceError):
        return None
    detail = {"reason": error.reason, "command": error.observation}
    if not _valid_avc_failure_detail(detail):
        return None
    return detail


def write_collector_event(output, event, runner_hash, *, sequence, stage=None,
                          failure_kind=None, failure_detail=None,
                          report_observation=None):
    """Write one canonical, allowlisted progress event without raw failure text."""
    if (not isinstance(event, str)
            or event not in {"collector-started", "collector-stage",
                             "collector-failed", "collector-completed"}
            or not isinstance(runner_hash, str)
            or re.fullmatch(r"[a-f0-9]{64}", runner_hash) is None
            or type(sequence) is not int or not 0 <= sequence <= 9):
        raise ValueError("invalid collector progress event")
    record = {
        "schema": 1,
        "passed": False,
        "release_qualified": False,
        "diagnostic": "transition-evidence-collector",
        "event": event,
        "seq": sequence,
        "unit": LAUNCHER_UNIT,
        "runner_sha256": runner_hash,
        "scope": COLLECTOR_SCOPE,
    }
    if event in {"collector-stage", "collector-failed", "collector-completed"}:
        if not isinstance(stage, str) or stage not in COLLECTOR_STAGES:
            raise ValueError("invalid collector progress stage")
        record["stage"] = stage
    elif stage is not None:
        raise ValueError("collector start cannot name a stage")
    if event == "collector-failed":
        if not isinstance(failure_kind, str) or failure_kind not in {
                "timeout", "command-exit", "permission", "os-error",
                "invalid-evidence", "transport", "unexpected"}:
            raise ValueError("invalid collector failure kind")
        record["failure_kind"] = failure_kind
        if failure_detail is not None:
            if (stage != "avc-journal"
                    or not _valid_avc_failure_detail(failure_detail)
                    or failure_kind != _avc_failure_kind(failure_detail["reason"])):
                raise ValueError("invalid AVC collector failure detail")
            record["failure_detail"] = failure_detail
    elif failure_kind is not None:
        raise ValueError("non-failure collector event named a failure")
    elif failure_detail is not None:
        raise ValueError("non-failure collector event named AVC failure detail")
    if event == "collector-completed":
        if (not isinstance(report_observation, dict)
                or set(report_observation) != {"bytes", "sha256"}
                or type(report_observation.get("bytes")) is not int
                or not 0 < report_observation["bytes"] <= REPORT_MAX_BYTES
                or not isinstance(report_observation.get("sha256"), str)
                or re.fullmatch(r"[a-f0-9]{64}",
                                report_observation["sha256"]) is None):
            raise ValueError("invalid completed primary-report observation")
        record["report"] = report_observation
    elif report_observation is not None:
        raise ValueError("non-completion collector event named a report")
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":"),
                      allow_nan=False) + "\n").encode()
    if not 0 < len(raw) <= COLLECTOR_MAX_EVENT_BYTES:
        raise ValueError("collector progress event exceeded its bound")
    written = (os.write(output, raw) if type(output) is int else output.write(raw))
    if type(written) is not int or written != len(raw):
        raise RuntimeError("collector progress channel did not accept one event")


def _close_collector_output(output):
    if type(output) is int:
        os.close(output)
    else:
        output.close()


def safe_collector_event(state, event, runner_hash, **fields):
    """Disable auxiliary diagnostics after any failure without masking evidence."""
    output = state.get("output")
    if output is None:
        return False
    try:
        write_collector_event(
            output, event, runner_hash, sequence=state["sequence"], **fields)
    except BaseException:
        try:
            _close_collector_output(output)
        except BaseException:
            pass
        state["output"] = None
        return False
    state["sequence"] += 1
    return True


def close_collector(state):
    output = state.get("output")
    state["output"] = None
    if output is not None:
        try:
            _close_collector_output(output)
        except BaseException:
            pass


def main():
    product = Path("/sys/class/dmi/id/product_name").read_text().strip()
    if (os.geteuid() != 0 or product != "Symbi-Hosted-Update-Probe"
            or Path("/run/.containerenv").exists() or len(sys.argv) != 1):
        raise SystemExit("Use only the disposable hosted update guest")
    runner_hash = sha256(Path(__file__))
    collector = {"output": open_collector_channel(), "sequence": 0}
    stage = None
    try:
        safe_collector_event(collector, "collector-started", runner_hash)

        stage = "service-properties"
        safe_collector_event(
            collector, "collector-stage", runner_hash, stage=stage)
        properties = service_properties(fixed_command([
            "/usr/bin/systemctl", "show", LAUNCHER_UNIT,
            "--property=" + STATUS_PROPERTIES,
        ], timeout=10, stdout_max=4096))

        stage = "source-journal"
        safe_collector_event(
            collector, "collector-stage", runner_hash, stage=stage)
        source = parse_source_capture(fixed_command(
            SOURCE_JOURNAL_COMMAND, timeout=5,
            stdout_max=STRUCTURED_JOURNAL_MAX_BYTES), properties["InvocationID"])

        stage = "monitor"
        safe_collector_event(
            collector, "collector-stage", runner_hash, stage=stage)
        monitor = monitor_properties()
        stage = "identity-correlation"
        safe_collector_event(
            collector, "collector-stage", runner_hash, stage=stage)
        if (monitor["invocation_id"] != properties["InvocationID"]
                or monitor["service_result"] != properties["Result"]
                or monitor["exit_status"] != properties["ExecMainStatus"]
                or source["invocation_id"] != properties["InvocationID"]
                or abs(source["receipt_monotonic_usec"]
                       - int(properties["ExecMainStartTimestampMonotonic"]))
                   > JOURNAL_CORRELATION_MARGIN_USEC):
            raise ValueError("transition diagnostic identities differ")

        stage = "avc-journal"
        safe_collector_event(
            collector, "collector-stage", runner_hash, stage=stage)
        avc = bounded_avc_evidence(source, properties)

        stage = "bounded-journal"
        safe_collector_event(
            collector, "collector-stage", runner_hash, stage=stage)
        journal = bounded_journal_excerpt(fixed_command(
            JOURNAL_COMMAND, timeout=10, stdout_max=COMMAND_STDOUT_MAX_BYTES))
        stage = "report-build"
        safe_collector_event(
            collector, "collector-stage", runner_hash, stage=stage)
        report = {
            "schema": 1,
            "passed": False,
            "guest_booted": True,
            "release_qualified": False,
            "product": product,
            "diagnostic": "bootc-transition-probe-failure",
            "unit": LAUNCHER_UNIT,
            "runner_sha256": runner_hash,
            "service": properties,
            "monitor": monitor,
            "probe": source,
            "avc": avc,
            "journal": journal,
            "diagnostic_stages": list(COLLECTOR_STAGES[:-1]),
            "scope": SCOPE,
        }

        stage = "primary-report-write"
        safe_collector_event(
            collector, "collector-stage", runner_hash, stage=stage)
        report_observation = write_report(report)
        safe_collector_event(
            collector, "collector-completed", runner_hash, stage=stage,
            report_observation=report_observation)
    except BaseException as error:
        if stage is not None:
            try:
                safe_collector_event(
                    collector, "collector-failed", runner_hash, stage=stage,
                    failure_kind=collector_failure_kind(error),
                    failure_detail=collector_failure_detail(error))
            except BaseException:
                pass
        raise
    finally:
        close_collector(collector)


if __name__ == "__main__":
    main()
