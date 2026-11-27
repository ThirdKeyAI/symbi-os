"""Coordinate disposable signature controls and persistent update recovery."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time


MAX_REPORT = 128 * 1024
MAX_COLLECTOR_DIAGNOSTIC = 16 * 1024
MAX_QEMU_LOG = 1024 * 1024
MAX_SERIAL_LOG = 2 * 1024 * 1024
TRANSITION_COLLECTOR_MAX_EVENT_BYTES = 1280
TRANSITION_COLLECTOR_EMERGENCY_MAGIC = (
    b"SYMBI-TRANSITION-COLLECTOR-EMERGENCY-V1"
)
DISPOSABLE_PHASE_TIMEOUT_SECONDS = 1800
NEGATIVE_CASES = ("unsigned", "wrong-key", "wrong-reference", "altered-signature")
NEGATIVE_UPDATE_SOURCE = "/run/symbi-update-negative/source"
POSITIVE_OVERLAY_CASE = "valid-signature"
TRANSITION_FAILURE_SCOPE = "Bounded explicit-transition diagnostics; no update action ran"
TRANSITION_COLLECTOR_SCOPE = "Bounded collector progress; no transition or update claim"
TRANSITION_COLLECTOR_STAGES = (
    "service-properties", "source-journal", "monitor", "identity-correlation",
    "avc-journal", "bounded-journal", "report-build", "primary-report-write",
)
TRANSITION_STATUS_PROPERTIES = (
    "Result,ExecMainCode,ExecMainStatus,ActiveState,SubState,InvocationID,"
    "ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic"
)
TRANSITION_SERVICE_PROPERTIES_COMMAND = [
    "/usr/bin/systemctl", "show", "b.service",
    "--property=" + TRANSITION_STATUS_PROPERTIES,
]
TRANSITION_COLLECTOR_FAILURE_KINDS = {
    "timeout", "command-exit", "permission", "os-error", "invalid-evidence",
    "transport", "unexpected",
}
TRANSITION_FAILURE_JOURNAL_COMMAND = [
    "/usr/bin/journalctl", "--unit=b.service", "--boot=0", "--no-pager",
    "--output=short-monotonic", "--lines=24",
]
TRANSITION_FAILURE_JOURNAL_MAX_BYTES = 8 * 1024
TRANSITION_FAILURE_JOURNAL_MAX_LINES = 24
TRANSITION_FAILURE_JOURNAL_MAX_LINE_BYTES = 512
TRANSITION_SOURCE_CAPTURE_COMMAND = ["/usr/bin/cat", "/proc/self/attr/current"]
TRANSITION_PROBE_COMMAND = [
    "/usr/bin/runcon", "system_u:system_r:install_t:s0",
    "/usr/bin/bootc", "--version",
]
TRANSITION_SOURCE_JOURNAL_COMMAND = [
    "/usr/bin/journalctl", "--unit=b.service", "--boot=0", "--no-pager",
    "--quiet", "--output=json",
    "--output-fields=MESSAGE,__CURSOR,__MONOTONIC_TIMESTAMP,_COMM,_PID,"
    "_TRANSPORT,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID", "--lines=25",
]
TRANSITION_AVC_JOURNAL_COMMAND = [
    "/usr/bin/journalctl", "--boot=0", "--no-pager", "--quiet",
    "--output=json",
    "--output-fields=MESSAGE,__CURSOR,__MONOTONIC_TIMESTAMP,_TRANSPORT,"
    "_AUDIT_ID",
    "--lines=33",
    "--grep=avc:[[:space:]]+denied.*comm=\"runcon\".*(?:path|name)=\"/usr/bin/bootc\"",
    "_TRANSPORT=audit", "+", "_TRANSPORT=kernel",
]
TRANSITION_AVC_MAX_BYTES = 64 * 1024
TRANSITION_AVC_STDERR_MAX_BYTES = 0
TRANSITION_AVC_MAX_RECORDS = 32
TRANSITION_JOURNAL_CORRELATION_MARGIN_USEC = 120 * 1_000_000
TRANSITION_AVC_COMMAND_SHA256 = hashlib.sha256(json.dumps(
    TRANSITION_AVC_JOURNAL_COMMAND, separators=(",", ":")).encode()).hexdigest()
TRANSITION_COLLECTOR_STAGE_OPERATIONS = {
    "service-properties": TRANSITION_SERVICE_PROPERTIES_COMMAND,
    "source-journal": TRANSITION_SOURCE_JOURNAL_COMMAND,
    "monitor": ["builtin", "monitor-properties"],
    "identity-correlation": ["builtin", "identity-correlation"],
    "avc-journal": TRANSITION_AVC_JOURNAL_COMMAND,
    "bounded-journal": TRANSITION_FAILURE_JOURNAL_COMMAND,
    "report-build": ["builtin", "report-build"],
    "primary-report-write": [
        "builtin", "primary-report-write", "/dev/virtio-ports/org.symbi.update",
    ],
}
TRANSITION_COLLECTOR_COMMAND_STAGES = frozenset({
    "service-properties", "source-journal", "avc-journal", "bounded-journal",
})
TRANSITION_COLLECTOR_STAGE_OPERATION_SHA256 = {
    stage: hashlib.sha256(json.dumps(
        command, separators=(",", ":")).encode()).hexdigest()
    for stage, command in TRANSITION_COLLECTOR_STAGE_OPERATIONS.items()
}
TRANSITION_COLLECTOR_COMMAND_FAILURE_REASONS = frozenset({
    "command-timeout", "spawn-permission", "spawn-os-error",
    "command-result-invalid", "stdout-truncated", "stderr-truncated",
    "stderr-nonempty", "unexpected-exit", "stdout-invalid-utf8",
    "command-cleanup-failed",
})
TRANSITION_COLLECTOR_STAGE_REJECTION_REASON = {
    "service-properties": "service-properties-rejected",
    "source-journal": "source-journal-rejected",
    "monitor": "monitor-rejected",
    "identity-correlation": "identity-correlation-rejected",
    "avc-journal": "avc-journal-rejected",
    "bounded-journal": "bounded-journal-rejected",
    "report-build": "report-build-rejected",
    "primary-report-write": "primary-report-write-rejected",
}
TRANSITION_COLLECTOR_TERMINATION_REASONS = frozenset({
    "service-timeout", "service-signal", "service-exit",
    "service-resource", "service-protocol", "transport-loss",
})
TRANSITION_AVC_FAILURE_REASONS = frozenset({
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
_SELINUX_CONTEXT = re.compile(
    r"[A-Za-z0-9_.-]{1,64}:[A-Za-z0-9_.-]{1,64}:"
    r"[A-Za-z0-9_.-]{1,128}:[A-Za-z0-9_.:,-]{1,192}"
)
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


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _phase_report_observation(path, name, maximum=MAX_REPORT):
    """Describe the exact report endpoint after one QEMU process exits."""
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"name": name, "state": "absent", "bytes": 0, "sha256": None}
    if (path.is_symlink() or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1):
        return {"name": name, "state": "unsafe", "bytes": info.st_size,
                "sha256": None}
    if info.st_size == 0:
        return {"name": name, "state": "empty", "bytes": 0,
                "sha256": hashlib.sha256(b"").hexdigest()}
    if info.st_size > maximum:
        return {"name": name, "state": "oversized", "bytes": info.st_size,
                "sha256": None}
    return {"name": name, "state": "ready", "bytes": info.st_size,
            "sha256": sha256(path)}


def unique_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate update report key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("update report must be an object")
    return value


def _valid_transition_avc_command_observation(observation):
    fields = {
        "command_sha256", "exit_code", "timed_out", "stdout_bytes",
        "stdout_sha256", "stdout_truncated", "stderr_bytes", "stderr_sha256",
        "stderr_truncated",
    }
    if (not isinstance(observation, dict) or set(observation) != fields
            or not isinstance(observation.get("command_sha256"), str)
            or observation["command_sha256"] != TRANSITION_AVC_COMMAND_SHA256
            or (observation.get("exit_code") is not None
                and (type(observation["exit_code"]) is not int
                     or not -2**31 <= observation["exit_code"] <= 255))
            or type(observation.get("timed_out")) is not bool
            or type(observation.get("stdout_bytes")) is not int
            or not 0 <= observation["stdout_bytes"] <= TRANSITION_AVC_MAX_BYTES + 1
            or not isinstance(observation.get("stdout_sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}",
                            observation["stdout_sha256"]) is None
            or type(observation.get("stdout_truncated")) is not bool
            or type(observation.get("stderr_bytes")) is not int
            or not 0 <= observation["stderr_bytes"] <= TRANSITION_AVC_STDERR_MAX_BYTES + 1
            or not isinstance(observation.get("stderr_sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}",
                            observation["stderr_sha256"]) is None
            or type(observation.get("stderr_truncated")) is not bool
            or observation["stdout_truncated"]
               != (observation["stdout_bytes"] == TRANSITION_AVC_MAX_BYTES + 1)
            or observation["stderr_truncated"]
               != (observation["stderr_bytes"]
                   == TRANSITION_AVC_STDERR_MAX_BYTES + 1)
            or sum((observation["timed_out"],
                    observation["stdout_truncated"],
                    observation["stderr_truncated"])) > 1):
        return False
    empty_hash = hashlib.sha256(b"").hexdigest()
    return not (((observation["stdout_bytes"] == 0)
                 != (observation["stdout_sha256"] == empty_hash))
                or ((observation["stderr_bytes"] == 0)
                    != (observation["stderr_sha256"] == empty_hash)))


def _valid_transition_avc_parser_predicates(value):
    """Validate one bounded, content-free malformed-denial observation."""
    fields = {
        "schema", "record_index", "record_count",
        "transport", "serial_source", "denial_pattern_matched",
        "authenticated_serial_matched",
    }
    return (isinstance(value, dict) and set(value) == fields
            and type(value.get("schema")) is int and value["schema"] == 1
            and type(value.get("record_index")) is int
            and type(value.get("record_count")) is int
            and 1 <= value["record_count"] <= TRANSITION_AVC_MAX_RECORDS
            and 0 <= value["record_index"] < value["record_count"]
            and isinstance(value.get("transport"), str)
            and value.get("transport") in {"audit", "kernel"}
            and isinstance(value.get("serial_source"), str)
            and value.get("serial_source") in {
                "journal-audit-id", "message-audit-header",
            }
            and value["serial_source"] == (
                "journal-audit-id" if value["transport"] == "audit"
                else "message-audit-header")
            and type(value.get("denial_pattern_matched")) is bool
            and type(value.get("authenticated_serial_matched")) is bool
            and not (value["denial_pattern_matched"]
                     and value["authenticated_serial_matched"]))


def _valid_transition_avc_failure_detail(detail):
    if (not isinstance(detail, dict)
            or not isinstance(detail.get("reason"), str)
            or detail["reason"] not in TRANSITION_AVC_FAILURE_REASONS):
        return False
    reason = detail["reason"]
    fields = {"reason", "command"}
    if reason == "denial-malformed":
        fields.add("parser_predicates")
    if (set(detail) != fields
            or not _valid_transition_avc_command_observation(
                detail.get("command"))
            or (reason == "denial-malformed"
                and not _valid_transition_avc_parser_predicates(
                    detail.get("parser_predicates")))):
        return False
    observation = detail["command"]
    parser_reasons = TRANSITION_AVC_FAILURE_REASONS - {
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


def _transition_avc_failure_kind(reason):
    return {
        "command-timeout": "timeout",
        "spawn-permission": "permission",
        "spawn-os-error": "os-error",
        "unexpected-exit": "command-exit",
    }.get(reason, "invalid-evidence")


def _transition_command_limits(stage):
    return {
        "service-properties": (4096, 8 * 1024),
        "source-journal": (64 * 1024, 8 * 1024),
        "avc-journal": (TRANSITION_AVC_MAX_BYTES,
                        TRANSITION_AVC_STDERR_MAX_BYTES),
        "bounded-journal": (64 * 1024, 8 * 1024),
    }.get(stage)


def _valid_transition_command_observation(observation, stage):
    limits = _transition_command_limits(stage)
    if limits is None:
        return observation is None
    stdout_max, stderr_max = limits
    if (not isinstance(observation, dict)
            or set(observation) != {
                "exit_code", "timed_out", "stdout_bytes", "stdout_truncated",
                "stderr_bytes", "stderr_truncated",
            }
            or type(observation.get("exit_code")) is not int
            or not -2**31 <= observation["exit_code"] <= 255
            or type(observation.get("timed_out")) is not bool
            or type(observation.get("stdout_bytes")) is not int
            or not 0 <= observation["stdout_bytes"] <= stdout_max + 1
            or type(observation.get("stdout_truncated")) is not bool
            or observation["stdout_truncated"]
               != (observation["stdout_bytes"] == stdout_max + 1)
            or type(observation.get("stderr_bytes")) is not int
            or not 0 <= observation["stderr_bytes"] <= stderr_max + 1
            or type(observation.get("stderr_truncated")) is not bool
            or observation["stderr_truncated"]
               != (observation["stderr_bytes"] == stderr_max + 1)
            or sum((observation["timed_out"],
                    observation["stdout_truncated"],
                    observation["stderr_truncated"])) > 1):
        return False
    return True


def _transition_observation_from_avc(observation):
    if not _valid_transition_avc_command_observation(observation):
        return None
    if type(observation["exit_code"]) is not int:
        return None
    return {
        "exit_code": observation["exit_code"],
        "timed_out": observation["timed_out"],
        "stdout_bytes": observation["stdout_bytes"],
        "stdout_truncated": observation["stdout_truncated"],
        "stderr_bytes": observation["stderr_bytes"],
        "stderr_truncated": observation["stderr_truncated"],
    }


def _valid_transition_stage_receipt(stage, reason, observation, *, accepted=False,
                                    terminated=False):
    if stage not in TRANSITION_COLLECTOR_STAGES or not isinstance(reason, str):
        return False
    if accepted:
        if reason != "accepted":
            return False
        if stage in TRANSITION_COLLECTOR_COMMAND_STAGES:
            if not _valid_transition_command_observation(observation, stage):
                return False
            allowed = {0, 1} if stage == "avc-journal" else {0}
            return (not observation["timed_out"]
                    and not observation["stdout_truncated"]
                    and not observation["stderr_truncated"]
                    and observation["stderr_bytes"] == 0
                    and observation["exit_code"] in allowed)
        return observation is None
    if terminated:
        return (reason in TRANSITION_COLLECTOR_TERMINATION_REASONS
                and (observation is None
                     or _valid_transition_command_observation(observation, stage)))
    allowed = {TRANSITION_COLLECTOR_STAGE_REJECTION_REASON[stage]}
    if stage in TRANSITION_COLLECTOR_COMMAND_STAGES:
        allowed |= set(TRANSITION_COLLECTOR_COMMAND_FAILURE_REASONS)
    if stage == "avc-journal":
        allowed |= set(TRANSITION_AVC_FAILURE_REASONS)
    if reason not in allowed:
        return False
    if observation is None:
        return (reason in {
            "spawn-permission", "spawn-os-error", "command-result-invalid",
            "command-cleanup-failed",
        } or (stage not in TRANSITION_COLLECTOR_COMMAND_STAGES
              and reason
                  == TRANSITION_COLLECTOR_STAGE_REJECTION_REASON[stage]))
    if not _valid_transition_command_observation(observation, stage):
        return False
    if reason == "command-timeout":
        return observation["timed_out"]
    if observation["timed_out"]:
        return False
    if reason == "stdout-truncated":
        return observation["stdout_truncated"]
    if observation["stdout_truncated"]:
        return False
    if reason == "stderr-truncated":
        return observation["stderr_truncated"]
    if observation["stderr_truncated"]:
        return False
    if reason == "stderr-nonempty":
        return observation["stderr_bytes"] > 0
    if observation["stderr_bytes"]:
        return False
    if reason == "unexpected-exit":
        return observation["exit_code"] not in (
            {0, 1} if stage == "avc-journal" else {0})
    if observation["exit_code"] not in (
            {0, 1} if stage == "avc-journal" else {0}):
        return False
    if reason in {
            "spawn-permission", "spawn-os-error", "command-result-invalid",
            "command-cleanup-failed",
            }:
        return False
    if stage == "avc-journal":
        if observation["exit_code"] == 1:
            return (reason == "no-match-output-nonempty"
                    and observation["stdout_bytes"] > 0)
        if observation["stdout_bytes"] == 0:
            return reason == "records-output-empty"
        if reason in {"no-match-output-nonempty", "records-output-empty"}:
            return False
    if reason == "stdout-invalid-utf8":
        return observation["stdout_bytes"] > 0
    if reason == TRANSITION_COLLECTOR_STAGE_REJECTION_REASON[stage]:
        return True
    if stage != "avc-journal":
        return False
    return reason in TRANSITION_AVC_FAILURE_REASONS


def _transition_receipt_failure_kind(reason):
    return {
        "command-timeout": "timeout",
        "spawn-permission": "permission",
        "spawn-os-error": "os-error",
        "unexpected-exit": "command-exit",
        "command-cleanup-failed": "transport",
    }.get(reason, "invalid-evidence")


def _transition_termination_failure_kind(reason):
    return {
        "service-timeout": "timeout",
        "service-signal": "unexpected",
        "service-exit": "command-exit",
        "service-resource": "unexpected",
        "service-protocol": "invalid-evidence",
        "transport-loss": "transport",
    }.get(reason)


def _validate_transition_emergency(line_raw, runner_hash):
    """Validate one independently framed stop-post recovery receipt."""
    if (not isinstance(line_raw, bytes)
            or not 0 < len(line_raw) + 1
               <= TRANSITION_COLLECTOR_MAX_EVENT_BYTES):
        raise ValueError("invalid transition collector emergency receipt")

    def reject_constant(_value):
        raise ValueError("non-finite collector emergency number")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate collector emergency key")
            value[key] = item
        return value

    record = json.loads(
        line_raw.decode("utf-8", errors="strict"),
        object_pairs_hook=unique, parse_constant=reject_constant)
    canonical = json.dumps(
        record, sort_keys=True, separators=(",", ":"),
        allow_nan=False).encode()
    required = {
        "schema", "passed", "release_qualified", "diagnostic", "event",
        "unit", "runner_sha256", "scope", "stage", "command_sha256",
        "prepared_sequence", "failure_kind", "reason", "command_result",
        "service_exit_code",
    }
    if (canonical != line_raw or not isinstance(record, dict)
            or set(record) != required
            or type(record.get("schema")) is not int
            or record["schema"] != 1
            or record.get("passed") is not False
            or record.get("release_qualified") is not False
            or record.get("diagnostic")
               != "transition-evidence-collector-emergency"
            or record.get("event") != "collector-emergency"
            or record.get("unit") != "b.service"
            or record.get("runner_sha256") != runner_hash
            or record.get("scope") != TRANSITION_COLLECTOR_SCOPE
            or type(record.get("prepared_sequence")) is not int
            or not 0 <= record["prepared_sequence"] <= 18
            or record.get("reason") not in TRANSITION_COLLECTOR_TERMINATION_REASONS
            or record.get("failure_kind")
               != _transition_termination_failure_kind(record.get("reason"))
            or (record.get("service_exit_code") is not None
                and (type(record["service_exit_code"]) is not int
                     or not 0 <= record["service_exit_code"] <= 255))):
        raise ValueError("invalid transition collector emergency receipt")
    stage = record["stage"]
    if stage is None:
        if (record["command_sha256"] is not None
                or record["command_result"] is not None):
            raise ValueError("startup emergency receipt named a command")
    elif (stage not in TRANSITION_COLLECTOR_STAGES
          or record["command_sha256"]
             != TRANSITION_COLLECTOR_STAGE_OPERATION_SHA256[stage]
          or not _valid_transition_stage_receipt(
              stage, record["reason"], record["command_result"],
              terminated=True)):
        raise ValueError("invalid transition collector emergency stage")
    return record


def validate_collector_diagnostic(raw, runner_hash):
    """Validate and normalize the isolated transition-collector event stream."""
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_COLLECTOR_DIAGNOSTIC
            or not isinstance(runner_hash, str)
            or re.fullmatch(r"[a-f0-9]{64}", runner_hash) is None):
        raise ValueError("invalid transition collector stream")
    common = {
        "schema": 1,
        "passed": False,
        "release_qualified": False,
        "diagnostic": "transition-evidence-collector",
        "unit": "b.service",
        "runner_sha256": runner_hash,
        "scope": TRANSITION_COLLECTOR_SCOPE,
    }
    emergency = None
    stream_raw = raw
    marker = b"\n" + TRANSITION_COLLECTOR_EMERGENCY_MAGIC + b"\n"
    marker_offset = raw.rfind(marker)
    if marker_offset >= 0:
        emergency_raw = raw[marker_offset + len(marker):]
        if (not emergency_raw.endswith(b"\n")
                or b"\n" in emergency_raw[:-1]):
            raise ValueError("invalid transition collector emergency frame")
        emergency = _validate_transition_emergency(
            emergency_raw[:-1], runner_hash)
        stream_raw = raw[:marker_offset]
    events = []
    event_offsets = []
    offset = 0
    suffix = None
    maximum_events = len(TRANSITION_COLLECTOR_STAGES) * 2 + 2
    while offset < len(stream_raw):
        end = stream_raw.find(b"\n", offset)
        if end < 0:
            remaining = stream_raw[offset:]
            suffix = {"state": "truncated", "bytes": len(remaining),
                      "sha256": hashlib.sha256(remaining).hexdigest()}
            break
        line_raw = stream_raw[offset:end]
        next_offset = end + 1
        try:
            if (not 0 < len(line_raw) + 1
                    <= TRANSITION_COLLECTOR_MAX_EVENT_BYTES
                    or len(events) >= maximum_events):
                raise ValueError("transition collector event exceeded its bound")

            def reject_constant(_value):
                raise ValueError("non-finite collector number")

            def unique(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError("duplicate transition collector key")
                    value[key] = item
                return value

            event = json.loads(
                line_raw.decode("utf-8", errors="strict"),
                object_pairs_hook=unique, parse_constant=reject_constant)
            canonical = json.dumps(
                event, sort_keys=True, separators=(",", ":"),
                allow_nan=False).encode()
            if canonical != line_raw or not isinstance(event, dict):
                raise ValueError("noncanonical transition collector event")
            event_name = event.get("event")
            required = set(common) | {"event", "seq"}
            stage_events = {
                "collector-stage", "collector-stage-result", "collector-failed",
                "collector-terminated", "collector-completed",
            }
            if event_name in stage_events:
                required.update({"stage", "command_sha256"})
            if event_name == "collector-stage-result":
                required.update({"reason", "command_result"})
            elif event_name == "collector-failed":
                required.update({
                    "failure_kind", "reason", "command_result",
                })
                if "failure_detail" in event:
                    required.add("failure_detail")
            elif event_name == "collector-terminated":
                required.update({
                    "failure_kind", "reason", "command_result",
                    "service_exit_code",
                })
            elif event_name == "collector-completed":
                required.add("report")
            if (set(event) != required
                    or type(event.get("schema")) is not int
                    or event.get("schema") != 1
                    or event.get("passed") is not False
                    or event.get("release_qualified") is not False
                    or type(event.get("seq")) is not int
                    or event.get("seq") != len(events)
                    or any(event.get(key) != value
                           for key, value in common.items())
                    or (event_name in stage_events
                        and (event.get("stage") not in TRANSITION_COLLECTOR_STAGES
                             or event.get("command_sha256")
                                != TRANSITION_COLLECTOR_STAGE_OPERATION_SHA256[
                                    event["stage"]]))):
                raise ValueError("invalid transition collector event")
        except (UnicodeError, ValueError, TypeError, RecursionError,
                json.JSONDecodeError):
            remaining = stream_raw[offset:]
            suffix = {"state": "invalid", "bytes": len(remaining),
                      "sha256": hashlib.sha256(remaining).hexdigest()}
            break
        event_offsets.append(offset)
        events.append(event)
        offset = next_offset
    if events and events[0]["event"] != "collector-started":
        if emergency is None:
            raise ValueError("transition collector receipt is absent")
        suffix = {"state": "invalid", "bytes": len(stream_raw),
                  "sha256": hashlib.sha256(stream_raw).hexdigest()}
        events = []
        event_offsets = []
    if not events and emergency is None:
        raise ValueError("transition collector receipt is absent")

    def invalid_suffix(index):
        start = event_offsets[index]
        return {"state": "invalid", "bytes": len(stream_raw) - start,
                "sha256": hashlib.sha256(stream_raw[start:]).hexdigest()}

    stages = []
    completed_stages = []
    pending = None
    terminal = None
    for index, event in enumerate(events[1:], 1):
        event_name = event["event"]
        valid = terminal is None
        if valid and event_name == "collector-stage":
            valid = (pending is None
                     and len(stages) < len(TRANSITION_COLLECTOR_STAGES)
                     and event["stage"] == TRANSITION_COLLECTOR_STAGES[len(stages)])
            if valid:
                pending = event["stage"]
                stages.append(pending)
        elif valid and event_name == "collector-stage-result":
            valid = (pending == event["stage"]
                     and _valid_transition_stage_receipt(
                         event["stage"], event.get("reason"),
                         event.get("command_result"), accepted=True))
            if valid:
                completed_stages.append(pending)
                pending = None
        elif valid and event_name == "collector-failed":
            detail = event.get("failure_detail")
            detail_present = "failure_detail" in event
            valid = (pending == event["stage"]
                     and isinstance(event.get("failure_kind"), str)
                     and event["failure_kind"]
                        == _transition_receipt_failure_kind(
                            event.get("reason"))
                     and _valid_transition_stage_receipt(
                         event["stage"], event.get("reason"),
                         event.get("command_result"))
                     and (event.get("reason") != "denial-malformed"
                          or detail_present)
                     and (not detail_present
                          or (event["stage"] == "avc-journal"
                              and detail is not None
                              and _valid_transition_avc_failure_detail(detail)
                              and detail["reason"] == event["reason"]
                              and event["failure_kind"]
                                 == _transition_avc_failure_kind(detail["reason"])
                              and event["command_result"]
                                 == _transition_observation_from_avc(
                                     detail["command"]))))
            if valid:
                terminal = {
                    "event": event_name, "stage": event["stage"],
                    "failure_kind": event["failure_kind"],
                    "reason": event["reason"],
                    "command_result": event["command_result"],
                }
                if detail is not None:
                    terminal["failure_detail"] = detail
        elif valid and event_name == "collector-terminated":
            service_exit = event.get("service_exit_code")
            expected_kind = _transition_termination_failure_kind(
                event.get("reason"))
            valid = (pending == event["stage"]
                     and event.get("failure_kind") == expected_kind
                     and (service_exit is None
                          or (type(service_exit) is int
                              and 0 <= service_exit <= 255))
                     and _valid_transition_stage_receipt(
                         event["stage"], event.get("reason"),
                         event.get("command_result"), terminated=True))
            if valid:
                terminal = {
                    "event": event_name, "stage": event["stage"],
                    "failure_kind": event["failure_kind"],
                    "reason": event["reason"],
                    "command_result": event["command_result"],
                    "service_exit_code": service_exit,
                }
        elif valid and event_name == "collector-completed":
            report = event.get("report")
            valid = (pending is None
                     and stages == list(TRANSITION_COLLECTOR_STAGES)
                     and completed_stages == list(TRANSITION_COLLECTOR_STAGES)
                     and event["stage"] == TRANSITION_COLLECTOR_STAGES[-1]
                     and isinstance(report, dict)
                     and set(report) == {"bytes", "sha256"}
                     and type(report.get("bytes")) is int
                     and 0 < report["bytes"] <= MAX_REPORT
                     and isinstance(report.get("sha256"), str)
                     and re.fullmatch(r"[a-f0-9]{64}", report["sha256"])
                        is not None)
            if valid:
                terminal = {"event": event_name, "stage": event["stage"],
                            "report": report}
        else:
            valid = False
        if not valid:
            suffix = invalid_suffix(index)
            break
    emergency_terminal = None
    if emergency is not None:
        prepared = emergency["prepared_sequence"]
        stage = emergency["stage"]
        sequence_compatible = prepared in {
            len(events), max(0, len(events) - 1),
        }
        stage_compatible = False
        if stage is None:
            stage_compatible = not stages and pending is None
        elif pending == stage:
            stage_compatible = True
        elif terminal is not None and terminal.get("stage") == stage:
            stage_compatible = True
        elif completed_stages and completed_stages[-1] == stage:
            stage_compatible = True
        elif (pending is None and len(stages) < len(TRANSITION_COLLECTOR_STAGES)
              and stage == TRANSITION_COLLECTOR_STAGES[len(stages)]):
            stage_compatible = True
        if not sequence_compatible or not stage_compatible:
            raise ValueError("collector emergency state does not bind its prefix")
        emergency_terminal = {
            "event": emergency["event"],
            "stage": stage,
            "failure_kind": emergency["failure_kind"],
            "reason": emergency["reason"],
            "command_result": emergency["command_result"],
            "service_exit_code": emergency["service_exit_code"],
            "prepared_sequence": prepared,
        }
        if terminal is None:
            terminal = emergency_terminal
    return {
        "schema": 1,
        "passed": False,
        "release_qualified": False,
        "diagnostic": "transition-evidence-collector",
        "runner_sha256": runner_hash,
        "scope": TRANSITION_COLLECTOR_SCOPE,
        "receipt": True,
        "stages": stages,
        "completed_stages": completed_stages,
        "terminal": terminal,
        "emergency": emergency_terminal,
        "suffix": suffix,
    }


def validate_transition_failure_report(report, runner_hash):
    """Accept only the hash-bound, bounded explicit-transition diagnostic."""
    required = {
        "schema", "passed", "guest_booted", "release_qualified", "product",
        "diagnostic", "unit", "runner_sha256", "service", "monitor", "probe",
        "avc", "journal", "diagnostic_stages", "scope",
    }
    if (not isinstance(report, dict) or set(report) != required
            or type(report.get("schema")) is not int
            or report["schema"] != 1 or report.get("passed") is not False
            or report.get("guest_booted") is not True
            or report.get("release_qualified") is not False
            or report.get("product") != "Symbi-Hosted-Update-Probe"
            or report.get("diagnostic") != "bootc-transition-probe-failure"
            or report.get("unit") != "b.service"
            or report.get("runner_sha256") != runner_hash
            or not isinstance(runner_hash, str)
            or re.fullmatch(r"[a-f0-9]{64}", runner_hash) is None
            or type(report.get("diagnostic_stages")) is not list
            or report["diagnostic_stages"]
               != list(TRANSITION_COLLECTOR_STAGES[:-1])
            or report.get("scope") != TRANSITION_FAILURE_SCOPE):
        raise ValueError("unbound transition-probe failure report")
    service = report.get("service")
    service_fields = {
        "Result", "ExecMainCode", "ExecMainStatus", "ActiveState", "SubState",
        "InvocationID", "ExecMainPID", "ExecMainStartTimestampMonotonic",
        "ExecMainExitTimestampMonotonic",
    }
    main_pid = service.get("ExecMainPID", "") if isinstance(service, dict) else ""
    main_started = (service.get("ExecMainStartTimestampMonotonic", "")
                    if isinstance(service, dict) else "")
    main_exited = (service.get("ExecMainExitTimestampMonotonic", "")
                   if isinstance(service, dict) else "")
    if (not isinstance(service, dict) or set(service) != service_fields
            or any(not isinstance(value, str) for value in service.values())
            or service.get("Result") == "success"
            or service.get("ActiveState") != "failed"
            or service.get("SubState") != "failed"
            or re.fullmatch(r"[0-9]{1,3}", service.get("ExecMainCode", "")) is None
            or re.fullmatch(r"[0-9]{1,3}", service.get("ExecMainStatus", "")) is None
            or service.get("ExecMainStatus") == "0"
            or re.fullmatch(r"[a-f0-9]{32}", service.get("InvocationID", "")) is None
            or re.fullmatch(r"[0-9]{1,10}", main_pid) is None
            or not 0 < int(main_pid) <= 2**31 - 1
            or re.fullmatch(r"[0-9]{1,20}", main_started) is None
            or re.fullmatch(r"[0-9]{1,20}", main_exited) is None
            or not 0 < int(main_started) <= int(main_exited) <= 2**63 - 1
            or any(not value or len(value.encode()) > 128
                   for value in service.values())):
        raise ValueError("transition-probe service failure is incomplete")
    monitor = report.get("monitor")
    if (not isinstance(monitor, dict)
            or set(monitor) != {"unit", "invocation_id", "service_result",
                                "exit_code", "exit_status"}
            or monitor.get("unit") != "b.service"
            or monitor.get("invocation_id") != service["InvocationID"]
            or monitor.get("service_result") != service["Result"]
            or monitor.get("exit_code") != "exited"
            or monitor.get("exit_status") != service["ExecMainStatus"]):
        raise ValueError("transition-probe OnFailure activation is incomplete")
    probe = report.get("probe")
    probe_fields = {
        "command", "journal_command", "source_context", "requested_context",
        "probe_command", "invocation_id", "pid", "transport",
        "receipt_monotonic_usec", "cursor_sha256",
    }
    if (not isinstance(probe, dict) or set(probe) != probe_fields
            or probe.get("command") != TRANSITION_SOURCE_CAPTURE_COMMAND
            or probe.get("journal_command") != TRANSITION_SOURCE_JOURNAL_COMMAND
            or not isinstance(probe.get("source_context"), str)
            or _SELINUX_CONTEXT.fullmatch(probe["source_context"]) is None
            or probe.get("requested_context") != "system_u:system_r:install_t:s0"
            or probe.get("probe_command") != TRANSITION_PROBE_COMMAND
            or probe.get("invocation_id") != service["InvocationID"]
            or type(probe.get("pid")) is not int
            or not 0 < probe["pid"] <= 2**31 - 1
            or probe.get("transport") != "stdout"
            or type(probe.get("receipt_monotonic_usec")) is not int
            or probe["receipt_monotonic_usec"] <= 0
            or abs(probe["receipt_monotonic_usec"] - int(main_started))
               > TRANSITION_JOURNAL_CORRELATION_MARGIN_USEC
            or not isinstance(probe.get("cursor_sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}", probe["cursor_sha256"]) is None):
        raise ValueError("transition source-context observation is incomplete")
    avc = report.get("avc")
    query_result = avc.get("query_result") if isinstance(avc, dict) else None
    raw_sha256 = avc.get("raw_sha256") if isinstance(avc, dict) else None
    avc_fields = {
        "command", "command_observation", "query_result", "raw_bytes",
        "raw_sha256", "line_count", "truncated", "records",
    }
    command_observation = (avc.get("command_observation")
                           if isinstance(avc, dict) else None)
    if (not isinstance(avc, dict) or set(avc) != avc_fields
            or avc.get("command") != TRANSITION_AVC_JOURNAL_COMMAND
            or not _valid_transition_avc_command_observation(command_observation)
            or command_observation["timed_out"]
            or command_observation["stdout_truncated"]
            or command_observation["stderr_truncated"]
            or command_observation["stderr_bytes"] != 0
            or not isinstance(query_result, str)
            or query_result not in {"no-match", "records"}
            or type(avc.get("raw_bytes")) is not int
            or not isinstance(raw_sha256, str)
            or re.fullmatch(r"[a-f0-9]{64}", raw_sha256) is None
            or type(avc.get("line_count")) is not int
            or avc.get("truncated") is not False
            or not isinstance(avc.get("records"), list)
            or len(avc["records"]) != avc["line_count"]):
        raise ValueError("transition AVC evidence is incomplete")
    if avc["query_result"] == "no-match":
        if (command_observation["exit_code"] != 1
                or command_observation["stdout_bytes"] != 0
                or avc["raw_bytes"] != 0
                or avc["raw_sha256"] != hashlib.sha256(b"").hexdigest()
                or avc["line_count"] != 0
                or avc["records"] != []):
            raise ValueError("transition AVC no-match evidence is inconsistent")
    elif (not 0 < avc["raw_bytes"] <= TRANSITION_AVC_MAX_BYTES
          or not 1 <= avc["line_count"] <= TRANSITION_AVC_MAX_RECORDS
          or command_observation["exit_code"] != 0
          or command_observation["stdout_bytes"] != avc["raw_bytes"]
          or command_observation["stdout_sha256"] != avc["raw_sha256"]):
        raise ValueError("transition AVC record evidence is incomplete")
    avc_record_fields = {
        "audit_serial", "audit_serial_source", "transport",
        "receipt_monotonic_usec", "pid", "comm", "path_field", "path",
        "source_context", "target_context", "class", "permissions",
        "permissive", "cursor_sha256",
    }
    for record in avc["records"]:
        permissions = record.get("permissions") if isinstance(record, dict) else None
        if (not isinstance(record, dict) or set(record) != avc_record_fields
                or type(record.get("audit_serial")) is not int
                or not 0 < record["audit_serial"] <= 2**63 - 1
                or not isinstance(record.get("transport"), str)
                or record["transport"] not in {"audit", "kernel"}
                or record.get("audit_serial_source") != (
                    "journal-audit-id" if record.get("transport") == "audit"
                    else "message-audit-header")
                or type(record.get("receipt_monotonic_usec")) is not int
                or not max(0, int(main_started)
                           - TRANSITION_JOURNAL_CORRELATION_MARGIN_USEC)
                <= record["receipt_monotonic_usec"]
                <= int(main_exited) + TRANSITION_JOURNAL_CORRELATION_MARGIN_USEC
                or type(record.get("pid")) is not int
                or record["pid"] != int(main_pid)
                or record.get("comm") != "runcon"
                or not isinstance(record.get("path_field"), str)
                or record["path_field"] not in {"path", "name"}
                or record.get("path") != "/usr/bin/bootc"
                or not isinstance(record.get("source_context"), str)
                or _SELINUX_CONTEXT.fullmatch(record["source_context"]) is None
                or not isinstance(record.get("target_context"), str)
                or _SELINUX_CONTEXT.fullmatch(record["target_context"]) is None
                or not isinstance(record.get("class"), str)
                or re.fullmatch(r"[a-z0-9_]{1,64}", record["class"]) is None
                or not isinstance(permissions, list) or not 1 <= len(permissions) <= 16
                or any(not isinstance(value, str) for value in permissions)
                or len(set(permissions)) != len(permissions)
                or any(re.fullmatch(r"[a-z0-9_]{1,64}", value) is None
                       for value in permissions)
                or record.get("permissive") is not False
                or not isinstance(record.get("cursor_sha256"), str)
                or re.fullmatch(r"[a-f0-9]{64}", record["cursor_sha256"]) is None):
            raise ValueError("transition AVC record is incomplete")
    allowed_sources = {probe["source_context"], probe["requested_context"]}
    if any(record["source_context"] not in allowed_sources
           for record in avc["records"]):
        raise ValueError("transition AVC source does not bind the requested transition")
    if (len({record["audit_serial"] for record in avc["records"]})
            != len(avc["records"])
            or len({record["cursor_sha256"] for record in avc["records"]})
            != len(avc["records"])):
        raise ValueError("transition AVC records are duplicated")
    journal = report.get("journal")
    journal_fields = {
        "unit", "command", "line_count", "bytes", "sha256", "truncated", "excerpt",
    }
    if (not isinstance(journal, dict) or set(journal) != journal_fields
            or journal.get("unit") != "b.service"
            or journal.get("command") != TRANSITION_FAILURE_JOURNAL_COMMAND
            or type(journal.get("line_count")) is not int
            or not 0 <= journal["line_count"] <= TRANSITION_FAILURE_JOURNAL_MAX_LINES
            or type(journal.get("bytes")) is not int
            or not 0 <= journal["bytes"] <= TRANSITION_FAILURE_JOURNAL_MAX_BYTES
            or type(journal.get("truncated")) is not bool
            or not isinstance(journal.get("sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}", journal["sha256"]) is None
            or not isinstance(journal.get("excerpt"), list)
            or len(journal["excerpt"]) != journal["line_count"]):
        raise ValueError("transition-probe journal metadata is incomplete")
    for line in journal["excerpt"]:
        sensitive_assignment = (_SENSITIVE_ASSIGNMENT.search(line)
                                if isinstance(line, str) else None)
        if (not isinstance(line, str)
                or len(line.encode("ascii", errors="ignore")) != len(line)
                or len(line.encode("ascii")) > TRANSITION_FAILURE_JOURNAL_MAX_LINE_BYTES
                or any(not " " <= character <= "~" for character in line)
                or (sensitive_assignment is not None
                    and sensitive_assignment.group(3) != "<redacted>")
                or re.search(r"(?i)\bbearer\s+(?!<redacted>)[^ ]+", line)
                or re.search(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{48,}(?![A-Za-z0-9])",
                             line)):
            raise ValueError("transition-probe journal excerpt is unsafe")
    payload = ("\n".join(journal["excerpt"])
               + ("\n" if journal["excerpt"] else "")).encode("ascii")
    if (len(payload) != journal["bytes"]
            or hashlib.sha256(payload).hexdigest() != journal["sha256"]):
        raise ValueError("transition-probe journal digest differs")
    return report


def stop_child(child):
    """Best-effort QEMU cleanup that never masks the primary gate failure."""
    result = {"attempted": False, "terminated": False, "killed": False, "errors": []}
    if child is None or child.poll() is not None:
        return result
    result["attempted"] = True
    try:
        child.terminate()
        result["terminated"] = True
    except OSError as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    else:
        try:
            child.wait(timeout=10)
            return result
        except subprocess.TimeoutExpired:
            pass
    try:
        child.kill()
        result["killed"] = True
    except OSError as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    else:
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired as error:
            result["errors"].append(type(error).__name__ + ": " + str(error))
    return result


def firmware_arguments(directory=Path("/inputs"), expected_filename="expected.json"):
    allowed = {"expected.json", "expected-positive.json",
               *("expected-" + case + ".json" for case in NEGATIVE_CASES)}
    if directory != Path("/inputs") or expected_filename not in allowed:
        raise ValueError("fixed update firmware input required")
    files = [
        ("systemd.extra-unit.o.service", "update-o.service"),
        ("systemd.extra-unit.s.service", "s.service"),
        ("systemd.extra-unit.b.service", "update-b.service"),
        ("systemd.extra-unit.f.service", "update-f.service"),
        ("symbi-update.py", "update_guest.py"),
        ("symbi-update-failure.py", "update_boot_failure.py"),
        ("symbi-update-expected.json", expected_filename),
        ("symbi-update-policy.json", "update-policy.json"),
    ]
    result = []
    for name, filename in files:
        name = "opt/io.systemd.credentials/" + name
        if len(name.encode("ascii")) >= 56:
            raise ValueError("QEMU update firmware name is too long")
        result += ["-fw_cfg", "name=" + name + ",file=" + str(directory / filename)]
    return result


def _qemu_command(overlay, report, serial, expected_filename, collector=None,
                  directory=Path("/inputs"), output=Path("/output")):
    if (directory != Path("/inputs") or output != Path("/output")
            or any(not isinstance(value, str) or not value.startswith("/output/")
                   for value in (overlay, report, serial))
            or (collector is not None
                and (not isinstance(collector, str)
                     or not collector.startswith("/output/")))):
        raise ValueError("fixed update QEMU paths and mounts required")
    command = [
        "/usr/bin/qemu-system-x86_64", "-machine", "q35,dump-guest-core=off",
        "-accel", "tcg,thread=single", "-cpu", "max", "-m", "2048M", "-smp", "1",
        "-nodefaults", "-no-user-config", "-no-reboot", "-net", "none",
        "-smbios", "type=1,manufacturer=Symbi-Test,product=Symbi-Hosted-Update-Probe",
        "-drive", "file=" + overlay + ",format=qcow2,if=none,id=symbi-boot-disk",
        "-device", "virtio-blk-pci,drive=symbi-boot-disk,bootindex=1",
        "-drive", "file=/inputs/update.raw,format=raw,if=none,"
                  "id=symbi-update-source,readonly=on",
        "-device", "virtio-blk-pci,drive=symbi-update-source,serial=SYMBIUPDATE",
        "-boot", "strict=on",
        "-device", "virtio-rng-pci", "-device", "virtio-serial-pci",
        "-chardev", "file,id=report,path=" + report,
        "-device", "virtserialport,chardev=report,name=org.symbi.update",
    ]
    if collector is not None:
        command += [
            "-chardev", "file,id=collector,path=" + collector,
            "-device", "virtserialport,chardev=collector,"
                       "name=org.symbi.update.diagnostic",
        ]
    return command + [
        "-serial", "file:" + serial, "-monitor", "none", "-display", "none",
        *firmware_arguments(directory, expected_filename),
    ]


def qemu_command(index, directory=Path("/inputs"), output=Path("/output")):
    if type(index) is not int or not 0 <= index <= 2:
        raise ValueError("fixed update QEMU phase required")
    return _qemu_command("/output/guest.qcow2", f"/output/phase-{index}.json",
                         f"/output/serial-{index}.log", "expected.json",
                         directory=directory, output=output)


def negative_qemu_command(case, directory=Path("/inputs"), output=Path("/output")):
    if case not in NEGATIVE_CASES:
        raise ValueError("fixed update rejection case required")
    return _qemu_command(f"/output/negative-{case}.qcow2",
                         f"/output/negative-{case}.json",
                         f"/output/negative-{case}-serial.log",
                         f"expected-{case}.json", directory=directory, output=output)


def positive_qemu_command(directory=Path("/inputs"), output=Path("/output")):
    return _qemu_command("/output/same-path-positive.qcow2",
                         "/output/same-path-positive.json",
                         "/output/same-path-positive-serial.log",
                         "expected-positive.json",
                         "/output/same-path-positive-collector.jsonl",
                         directory, output)


def validate_source_device(report, expected):
    """Bind guest block evidence to the authenticated source-disk identity."""
    try:
        observed = report["source_device"]
        source = expected["source_disk"]
    except (KeyError, TypeError) as error:
        raise ValueError("update source-device evidence is missing") from error
    required = {"path", "serial", "TYPE", "LABEL", "UUID"}
    if (not isinstance(observed, dict) or set(observed) != required
            or re.fullmatch(r"/dev/vd[a-z]{1,3}", observed.get("path", "")) is None
            or observed.get("serial") != "SYMBIUPDATE"
            or source.get("serial") != "SYMBIUPDATE"
            or observed.get("TYPE") != source.get("filesystem")
            or observed.get("LABEL") != source.get("label")
            or observed.get("UUID") != source.get("uuid")):
        raise ValueError("update source-device evidence is unbound")


def validate_status_observations(report, expected_count):
    """Require every deployment snapshot to come from the fixed direct unit."""
    expected_service = {
        "Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0",
        "ActiveState": "active", "SubState": "exited",
    }
    observations = report.get("status_observations")
    commands = report.get("commands")
    if (type(expected_count) is not int or expected_count < 1
            or not isinstance(observations, list)
            or len(observations) != expected_count
            or not isinstance(commands, list)):
        raise ValueError("fixed bootc status observations are incomplete")
    for sequence, observation in enumerate(observations, 1):
        if (not isinstance(observation, dict)
                or set(observation) != {
                    "sequence", "unit", "service", "bytes", "sha256"
                }
                or observation.get("sequence") != sequence
                or observation.get("unit") != "s.service"
                or observation.get("service") != expected_service
                or type(observation.get("bytes")) is not int
                or not 0 < observation["bytes"] <= MAX_REPORT
                or re.fullmatch(r"[a-f0-9]{64}",
                                observation.get("sha256", "")) is None):
            raise ValueError("fixed bootc status observation is unbound")
    starts = [item for item in commands if item.get("command") ==
              ["/usr/bin/systemctl", "restart", "s.service"]]
    shows = [item for item in commands if item.get("command") == [
        "/usr/bin/systemctl", "show", "s.service",
        "--property=Result,ExecMainCode,ExecMainStatus,ActiveState,SubState",
    ]]
    if (len(starts) != expected_count or len(shows) != expected_count
            or any(item.get("exit_code") != 0 for item in starts + shows)
            or any(item.get("command", [None])[0:1] == ["/usr/bin/bootc"]
                   for item in commands)):
        raise ValueError("status bypassed the fixed direct bootc unit")


def validate_transition(report):
    """Require the fixed transition probe and stable labeled executables."""
    transition = report.get("bootc_transition")
    service = {
        "Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0",
        "ActiveState": "active", "SubState": "exited",
    }
    commands = report.get("commands")
    show_command = [
        "/usr/bin/systemctl", "show", "b.service",
        "--property=Result,ExecMainCode,ExecMainStatus,ActiveState,SubState",
    ]
    probe_command = [
        "/usr/bin/runcon", "system_u:system_r:install_t:s0",
        "/usr/bin/bootc", "--version",
    ]
    if (not isinstance(transition, dict)
            or set(transition) != {
                "unit", "service", "context", "probe_command", "scope",
                "runcon", "runcon_sha256", "runcon_selinux_label",
                "source", "source_sha256",
                "label_reference", "label_reference_sha256", "selinux_label", "mode",
            }
            or transition.get("unit") != "b.service"
            or transition.get("service") != service
            or transition.get("context") != "system_u:system_r:install_t:s0"
            or transition.get("probe_command") != probe_command
            or transition.get("scope")
               != "Explicit transition availability only; no update qualification"
            or transition.get("runcon") != "/usr/bin/runcon"
            or transition.get("runcon_selinux_label")
               != "system_u:object_r:bin_t:s0"
            or transition.get("source") != "/usr/bin/bootc"
            or transition.get("label_reference") != "/usr/bin/ostree"
            or any(re.fullmatch(r"[a-f0-9]{64}", transition.get(key, "")) is None
                   for key in ("runcon_sha256", "source_sha256",
                               "label_reference_sha256"))
            or not isinstance(transition.get("selinux_label"), str)
            or re.fullmatch(r"[^:\x00]+:object_r:install_exec_t:[^\x00]+",
                            transition["selinux_label"]) is None
            or transition.get("mode") != "0755"
            or not isinstance(commands, list)
            or len([item for item in commands
                    if item.get("command") == show_command
                    and item.get("exit_code") == 0]) != 1):
        raise ValueError("fixed SELinux bootc transition is unbound")
    return transition


def validate_operation_observation(report, operation, expected_success):
    """Bind one exact mutation to runcon and the validated labeled bootc."""
    paths = {
        "negative": ["switch", "--transport", "dir",
                     "--enforce-container-sigpolicy", NEGATIVE_UPDATE_SOURCE],
        "positive": ["switch", "--transport", "dir",
                     "--enforce-container-sigpolicy", "/run/symbi-update/source"],
        "rollback": ["rollback"],
    }
    observation = report.get("bootc_operation")
    commands = report.get("commands")
    expected_command = [
        "/usr/bin/runcon", "system_u:system_r:install_t:s0", "/usr/bin/bootc",
        *paths.get(operation, []),
    ]
    validate_transition(report)
    if (operation not in paths or type(expected_success) is not bool
            or not isinstance(observation, dict)
            or set(observation) != {
                "name", "command", "exit_code", "stderr", "stderr_sha256"
            }
            or observation.get("name") != operation
            or observation.get("command") != expected_command
            or type(observation.get("exit_code")) is not int
            or not isinstance(observation.get("stderr"), str)
            or len(observation["stderr"].encode()) > 128 * 1024
            or hashlib.sha256(observation["stderr"].encode()).hexdigest()
               != observation.get("stderr_sha256")
            or not isinstance(commands, list)):
        raise ValueError("fixed bootc operation observation is unbound")
    if expected_success:
        if observation["exit_code"] != 0:
            raise ValueError("fixed bootc operation did not succeed")
    elif (observation["exit_code"] == 0
          or "signature" not in observation["stderr"].lower()):
        raise ValueError("native bootc signature rejection reason is incomplete")
    matches = [item for item in commands if item.get("command") == expected_command]
    other_bootc = [item for item in commands
                   if item.get("command", [None])[0:1]
                   in (["/usr/bin/bootc"], ["/usr/bin/runcon"])
                   and item.get("command") != expected_command]
    if (len(matches) != 1
            or matches[0].get("exit_code") != observation["exit_code"]
            or matches[0].get("stderr") != observation["stderr"]
            or other_bootc):
        raise ValueError("mutation bypassed the fixed runcon bootc command")


def validate_phase_report(report, expected, expected_hash, runner_hash, phase):
    required = {"schema": 1, "passed": True, "guest_booted": True,
                "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
                "nonce": expected["nonce"], "expected_sha256": expected_hash,
                "runner_sha256": runner_hash, "source_mounted_readonly": True,
                "phase": phase}
    if any(report.get(key) != value for key, value in required.items()) or "failure" in report:
        raise ValueError("unbound or incomplete update guest phase")
    validate_source_device(report, expected)
    name = phase.get("name")
    validate_status_observations(report, 1 if name == "rolled-back" else 2)
    if name == "installed":
        validate_operation_observation(report, "positive", True)
    elif name == "updated":
        validate_operation_observation(report, "rollback", True)
    elif name == "rolled-back":
        if "bootc_operation" in report:
            raise ValueError("rollback verification unexpectedly mutated the deployment")
        validate_transition(report)
    else:
        raise ValueError("unknown update phase report")
    commands = report.get("commands")
    if (not isinstance(commands, list) or not commands
            or any(item.get("exit_code") != 0 for item in commands)):
        raise ValueError("update guest command evidence is incomplete")


def validate_positive_report(report, expected, expected_hash, runner_hash):
    required = {"schema": 1, "passed": True, "guest_booted": True,
                "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
                "nonce": expected["nonce"], "expected_sha256": expected_hash,
                "runner_sha256": runner_hash, "source_mounted_readonly": True}
    if any(report.get(key) != value for key, value in required.items()) or "failure" in report:
        raise ValueError("unbound or incomplete same-path positive update report")
    validate_source_device(report, expected)
    validate_status_observations(report, 2)
    validate_operation_observation(report, "negative", True)
    control = report.get("same_path_positive_control")
    if (not isinstance(control, dict) or control.get("case") != POSITIVE_OVERLAY_CASE
            or control.get("switch_accepted") is not True
            or control.get("switch_exit_code") != 0
            or control.get("booted_unchanged") is not True
            or control.get("deployment_staged") is not True
            or control.get("default_changed") is not True
            or control.get("staged_digest") != expected["new_digest"]
            or control.get("source") != NEGATIVE_UPDATE_SOURCE
            or control.get("source_readonly") is not True):
        raise ValueError("same-path valid signature did not stage the expected update")
    hashes = (control.get("state_before_sha256"), control.get("state_after_sha256"))
    if (hashes[0] == hashes[1]
            or any(not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None
                   for value in hashes)):
        raise ValueError("same-path positive control did not bind its state transition")
    commands = report.get("commands")
    if (not isinstance(commands, list) or not commands
            or any(item.get("exit_code") != 0 for item in commands)):
        raise ValueError("real enforced same-path bootc switch acceptance is incomplete")


def validate_negative_report(report, expected, expected_hash, runner_hash, case):
    if case not in NEGATIVE_CASES:
        raise ValueError("unknown update rejection case")
    required = {"schema": 1, "passed": True, "guest_booted": True,
                "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
                "nonce": expected["nonce"], "expected_sha256": expected_hash,
                "runner_sha256": runner_hash, "source_mounted_readonly": True}
    if any(report.get(key) != value for key, value in required.items()) or "failure" in report:
        raise ValueError("unbound or incomplete negative update guest report")
    validate_source_device(report, expected)
    validate_status_observations(report, 2)
    validate_operation_observation(report, "negative", False)
    control = report.get("negative_control")
    if (not isinstance(control, dict) or control.get("case") != case
            or control.get("switch_rejected") is not True
            or type(control.get("switch_exit_code")) is not int
            or control["switch_exit_code"] == 0
            or control["switch_exit_code"] != report["bootc_operation"]["exit_code"]
            or control.get("deployment_unchanged") is not True
            or control.get("default_unchanged") is not True
            or control.get("source") != NEGATIVE_UPDATE_SOURCE
            or control.get("source_readonly") is not True
            or not isinstance(control.get("state_sha256"), str)
            or len(control["state_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in control["state_sha256"])):
        raise ValueError("native bootc rejection did not preserve the deployment state")
    commands = report.get("commands")
    failed_switches = [item for item in commands if item.get("command") ==
                       report["bootc_operation"]["command"]]
    if (len(failed_switches) != 1 or failed_switches[0].get("exit_code") == 0
            or any(item.get("exit_code") != 0 for item in commands
                   if item is not failed_switches[0])):
        raise ValueError("real enforced bootc switch rejection evidence is incomplete")


def validate_shared_baseline(positive_report, negative_report):
    try:
        accepted = positive_report["same_path_positive_control"]["state_before_sha256"]
        rejected = negative_report["negative_control"]["state_sha256"]
    except (KeyError, TypeError) as error:
        raise ValueError("disposable signature control baseline is missing") from error
    if (accepted != rejected or not isinstance(accepted, str)
            or re.fullmatch(r"[a-f0-9]{64}", accepted) is None):
        raise ValueError("negative control did not start from the positive baseline")
    return accepted


def main():
    if os.geteuid() != 10001 or not Path("/run/.containerenv").exists():
        raise SystemExit("Use the unprivileged disposable hosted update VM container")
    group = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    process = {key: value.strip() for key, value in
               (line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)}
    inputs, output = Path("/inputs"), Path("/output")
    if (limits != {"memory.max": "3221225472", "memory.swap.max": "0",
                   "cpu.max": "200000 100000", "pids.max": "64"}
            or process.get("CapEff") != "0000000000000000" or process.get("NoNewPrivs") != "1"
            or not os.statvfs("/").f_flag & os.ST_RDONLY
            or not os.statvfs(inputs / "atomic.raw").f_flag & os.ST_RDONLY
            or not os.statvfs(inputs / "update.raw").f_flag & os.ST_RDONLY
            or sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]):
        raise ValueError("update QEMU container isolation changed")
    expected_raw = (inputs / "expected.json").read_bytes()
    if len(expected_raw) > 128 * 1024:
        raise ValueError("oversized update expectation")
    expected = unique_json(expected_raw)
    source = expected.get("source_disk", {})
    if (source.get("serial") != "SYMBIUPDATE"
            or (inputs / "update.raw").stat().st_size != source.get("bytes")
            or sha256(inputs / "update.raw") != source.get("sha256")):
        raise ValueError("authenticated update source disk changed")
    names = ["update_boot.py", "update_guest.py", "update_boot_failure.py", "expected.json",
             "update-policy.json", "update-o.service", "s.service",
             "update-b.service", "update-f.service"]
    positive_name = "expected-positive.json"
    positive_raw = (inputs / positive_name).read_bytes()
    if len(positive_raw) > 128 * 1024:
        raise ValueError("oversized same-path positive update expectation")
    positive_candidate = unique_json(positive_raw)
    positive_control = positive_candidate.pop("same_path_positive_control", None)
    if (positive_candidate != expected or positive_control != {
            "case": POSITIVE_OVERLAY_CASE, "source": NEGATIVE_UPDATE_SOURCE}):
        raise ValueError("same-path positive expectation differs from the accepted input")
    positive_expected = unique_json(positive_raw)
    names.append(positive_name)
    negative_expected = {}
    for case in NEGATIVE_CASES:
        name = "expected-" + case + ".json"
        raw = (inputs / name).read_bytes()
        if len(raw) > 128 * 1024:
            raise ValueError("oversized negative update expectation")
        candidate = unique_json(raw)
        control = candidate.pop("negative_control", None)
        signature = control.get("signature") if isinstance(control, dict) else "invalid"
        if (candidate != expected or not isinstance(control, dict)
                or set(control) != {"case", "source", "signature"}
                or control.get("case") != case
                or control.get("source") != NEGATIVE_UPDATE_SOURCE
                or (case == "unsigned" and signature is not None)
                or (case != "unsigned"
                    and (not isinstance(signature, dict)
                         or set(signature) != {"base64", "sha256"}))):
            raise ValueError("negative update expectation differs from the accepted input")
        negative_expected[case] = unique_json(raw)
        names.append(name)
    hashes = {name: sha256(inputs / name) for name in names}
    phases = [
        {"name": "installed", "booted_digest": expected["old_digest"],
         "operation": "signed-update-staged", "staged_digest": expected["new_digest"]},
        {"name": "updated", "booted_digest": expected["new_digest"],
         "operation": "rollback-queued", "rollback_digest": expected["old_digest"]},
        {"name": "rolled-back", "booted_digest": expected["old_digest"],
         "rollback_from_digest": expected["new_digest"]},
    ]
    record = {"schema": 1, "passed": False, "guest_booted": False,
              "release_qualified": False, "limits": limits, "inputs": hashes,
              "source_disk": source, "negative_reports": [], "phase_reports": [],
              "scope": "One valid-signature same-path disposable control, four rejection "
                       "overlays, then signed update and rollback on a persistent overlay"}
    child = None
    try:
        def create_overlay(name):
            path = output / name
            with (output / ("prepare-" + name + ".log")).open("x") as log:
                subprocess.run(["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "raw",
                                "-b", "/inputs/atomic.raw", str(path)],
                               stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                               check=True, timeout=30)
            return path, (path.stat().st_dev, path.stat().st_ino)

        def run_qemu(command, label, report_name, serial_name, timeout,
                     collector_name=None):
            nonlocal child
            record["active_phase"] = label
            record["commands"] = record.get("commands", []) + [command]
            (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
            started = time.monotonic()
            log_name = "qemu-" + label + ".log"
            with (output / log_name).open("x") as log:
                child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                         stderr=subprocess.STDOUT,
                                         env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                              "HOME": "/output", "TMPDIR": "/output"})
                while child.poll() is None:
                    bounded_outputs = [
                        (serial_name, MAX_SERIAL_LOG),
                        (log_name, MAX_QEMU_LOG),
                        (report_name, MAX_REPORT),
                    ]
                    if collector_name is not None:
                        bounded_outputs.append(
                            (collector_name, MAX_COLLECTOR_DIAGNOSTIC))
                    for name, maximum in bounded_outputs:
                        path = output / name
                        if path.exists() and path.stat().st_size > maximum:
                            raise ValueError("update guest output exceeded its bound: " + name)
                    if time.monotonic() - started >= timeout:
                        raise TimeoutError("update guest phase exceeded its bound")
                    time.sleep(0.5)
            phase_process = {
                "label": label,
                "command_sha256": hashlib.sha256(json.dumps(
                    command, separators=(",", ":")).encode()).hexdigest(),
                "exit_code": child.returncode,
                "log_name": log_name,
                "serial_name": serial_name,
                "log": _phase_report_observation(
                    output / log_name, log_name, MAX_QEMU_LOG),
                "serial": _phase_report_observation(
                    output / serial_name, serial_name, MAX_SERIAL_LOG),
                "report": _phase_report_observation(output / report_name, report_name),
            }
            if collector_name is not None:
                phase_process["collector"] = _phase_report_observation(
                    output / collector_name, collector_name,
                    MAX_COLLECTOR_DIAGNOSTIC)
            if child.returncode != 0:
                record["phase_failure"] = phase_process
                raise RuntimeError("update QEMU phase failed; inspect original logs")
            child = None
            path = output / report_name
            if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_REPORT:
                record["phase_failure"] = phase_process
                raise ValueError("missing bounded update phase report")
            return path, time.monotonic() - started

        positive_overlay, positive_identity = create_overlay("same-path-positive.qcow2")
        path, elapsed = run_qemu(
            positive_qemu_command(), "same-path-positive", "same-path-positive.json",
            "same-path-positive-serial.log", DISPOSABLE_PHASE_TIMEOUT_SECONDS,
            "same-path-positive-collector.jsonl")
        positive_report = unique_json(path.read_bytes())
        if positive_report.get("diagnostic") == "bootc-transition-probe-failure":
            record["transition_failure"] = validate_transition_failure_report(
                positive_report, hashes["update_boot_failure.py"])
            raise RuntimeError("bootc transition probe failed; inspect bounded report")
        validate_positive_report(positive_report, positive_expected,
                                 hashes[positive_name], hashes["update_guest.py"])
        baseline_hash = positive_report["same_path_positive_control"]["state_before_sha256"]
        staged_hash = positive_report["same_path_positive_control"]["state_after_sha256"]
        if ((positive_overlay.stat().st_dev, positive_overlay.stat().st_ino)
                != positive_identity or sha256(inputs / "update.raw") != source["sha256"]):
            raise ValueError("same-path positive overlay or update source identity changed")
        positive_overlay.unlink()
        if positive_overlay.exists() or positive_overlay.is_symlink():
            raise ValueError("same-path positive overlay was not discarded")
        positive_summary = {
            "passed": True, "overlay_discarded": True,
            "negative_baselines_clean": False,
            "source": NEGATIVE_UPDATE_SOURCE, "elapsed_seconds": elapsed,
            "report_sha256": sha256(path), "state_before_sha256": baseline_hash,
            "state_after_sha256": staged_hash,
        }
        record["same_path_positive_control"] = positive_summary

        controls = {}
        for case in NEGATIVE_CASES:
            overlay, identity = create_overlay("negative-" + case + ".qcow2")
            path, elapsed = run_qemu(
                negative_qemu_command(case), "negative-" + case,
                "negative-" + case + ".json", "negative-" + case + "-serial.log",
                DISPOSABLE_PHASE_TIMEOUT_SECONDS)
            report = unique_json(path.read_bytes())
            validate_negative_report(report, negative_expected[case],
                                     hashes["expected-" + case + ".json"],
                                     hashes["update_guest.py"], case)
            if validate_shared_baseline(positive_report, report) != baseline_hash:
                raise ValueError("positive baseline identity changed between controls")
            if ((overlay.stat().st_dev, overlay.stat().st_ino) != identity
                    or sha256(inputs / "update.raw") != source["sha256"]):
                raise ValueError("negative overlay or read-only update source identity changed")
            overlay.unlink()
            if overlay.exists() or overlay.is_symlink():
                raise ValueError("negative update overlay was not discarded")
            controls[case] = True
            record["negative_reports"].append({
                "case": case, "elapsed_seconds": elapsed,
                "report_sha256": sha256(path), "overlay_discarded": True,
                "state_sha256": report["negative_control"]["state_sha256"],
            })
        positive_summary["negative_baselines_clean"] = True

        overlay, overlay_identity = create_overlay("guest.qcow2")
        for index, phase in enumerate(phases):
            command = qemu_command(index)
            path, elapsed = run_qemu(command, str(index), f"phase-{index}.json",
                                     f"serial-{index}.log", 1800)
            report = unique_json(path.read_bytes())
            validate_phase_report(report, expected, hashes["expected.json"],
                                  hashes["update_guest.py"], phase)
            record["phase_reports"].append({"index": index, "elapsed_seconds": elapsed,
                                            "phase": report["phase"], "report_sha256": sha256(path)})
            if ((overlay.stat().st_dev, overlay.stat().st_ino) != overlay_identity
                    or sha256(inputs / "update.raw") != source["sha256"]):
                raise ValueError("persistent overlay or read-only update source identity changed")
        record.update(passed=True, guest_booted=True, phases=phases,
                      same_path_positive_control=positive_summary,
                      bootc_negative_controls=controls,
                      negative_overlays_discarded=True,
                      source_disk_unchanged=True, persistent_overlay=True)
        record.pop("active_phase", None)
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        cleanup = stop_child(child)
        record["child_cleanup"] = cleanup
        if cleanup["attempted"]:
            record["passed"] = False
        record["cgroup_final"] = {name: (group / name).read_text().strip()
                                   for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        events = dict(line.split() for line in record["cgroup_final"]["memory.events"].splitlines())
        if any(events.get(name) != "0" for name in ("oom", "oom_kill", "oom_group_kill")):
            record["passed"] = False
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    if not record["passed"]:
        raise RuntimeError("hosted update resource controls failed")


if __name__ == "__main__":
    main()
