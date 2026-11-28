"""Contracts for the signed installed-image update and booted rollback gate."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from image.atomic.update_contract import (NEGATIVE_UPDATE_SOURCE, POSITIVE_OVERLAY_CASE,
                                          update_policy,
                                          update_command, rollback_command,
                                          negative_signature_payloads,
                                          validate_report, require_update_base,
                                          validate_artifact_metadata,
                                          validate_controller_identity)
from image.atomic.update_boot import (DISPOSABLE_PHASE_TIMEOUT_SECONDS,
                                      TRANSITION_COLLECTOR_STAGES,
                                      TRANSITION_COLLECTOR_STAGE_OPERATION_SHA256,
                                      _SENSITIVE_ASSIGNMENT as VALIDATOR_SENSITIVE,
                                      _validate_controller_identity as
                                      validate_boot_controller_identity,
                                      qemu_command, negative_qemu_command,
                                      positive_qemu_command,
                                      firmware_arguments,
                                      stop_child,
                                      validate_collector_diagnostic,
                                      validate_transition_failure_report,
                                      validate_phase_report,
                                      validate_negative_report,
                                      validate_positive_report,
                                      validate_shared_baseline)
from image.atomic.update_boot_failure import (JOURNAL_MAX_BYTES,
                                              JOURNAL_MAX_LINES,
                                              JOURNAL_MAX_LINE_BYTES,
                                              AVC_JOURNAL_COMMAND,
                                              SOURCE_CAPTURE_COMMAND,
                                              SOURCE_JOURNAL_COMMAND,
                                              COLLECTOR_STAGES,
                                              COLLECTOR_STAGE_OPERATION_SHA256,
                                              SERVICE_PROPERTIES_COMMAND,
                                              AVC_COMMAND_SHA256,
                                              AVC_FAILURE_REASONS,
                                              AvcEvidenceError,
                                              AvcParserPredicateError,
                                              CollectorCommandError,
                                              _SENSITIVE_ASSIGNMENT as PRODUCER_SENSITIVE,
                                              _kill_and_reap,
                                              bounded_command_result,
                                              collector_event,
                                              collector_stage_command,
                                              bounded_avc_evidence,
                                              collector_failure_detail,
                                              collector_failure_reason,
                                              fixed_command as fixed_failure_command,
                                              parse_avc_evidence,
                                              parse_source_capture,
                                              monitor_properties,
                                              bounded_journal_excerpt,
                                              close_collector,
                                              emit_stop_post_receipt,
                                              load_collector_state,
                                              open_collector_channel,
                                              persist_collector_state,
                                              safe_collector_event,
                                              service_properties,
                                              write_collector_event,
                                              write_report as write_failure_report)
from image.atomic import update_boot_failure as failure_collector
from image.atomic.update_process import TIMEOUT_SECONDS, validate_update_controller_command
from image.atomic.update_guest import (UPDATE_COMMAND_TIMEOUT_SECONDS,
                                       BOOTC_LABEL_REFERENCE, BOOTC_SOURCE,
                                       BOOTC_TRANSITION_BRIDGE,
                                       BOOTC_TRANSITION_BRIDGE_CONTEXT,
                                       CONTROLLER_CONTEXT,
                                       CONTROLLER_ENTRYPOINT,
                                       CONTROLLER_ENTRYPOINT_CONTEXT,
                                       CONTROLLER_MANIFEST,
                                       CONTROLLER_PATH,
                                       FDINFO_MAX_BYTES,
                                       INSTALL_CONTEXT,
                                       MOUNTINFO_MAX_BYTES,
                                       SOURCE, STATE, SOURCE_SERIAL,
                                       SOURCE_DEVICE_TIMEOUT_SECONDS,
                                       phase_status, deployment_snapshot,
                                       staged_deployment_snapshot,
                                       validate_source_identity,
                                       discover_source_device,
                                       wait_for_source_device,
                                       mount_observation,
                                       parse_visible_mount_id,
                                       read_visible_mount_id,
                                       source_mount_observation,
                                       observe_visible_source_mount,
                                       validate_source_mount,
                                       validate_mounted_device,
                                       _bootc_file_observation,
                                       _bootc_subprocess,
                                       _transition_receipt,
                                       controller_observation,
                                       fixed_bootc_transition,
                                       fixed_bootc_operation,
                                       fixed_bootc_status,
                                       write_channel)
from image.atomic.update_hosted import (_lifecycle_observation,
                                        retain_controller_output, run_update)
from image.atomic.hosted import (RETAINED_REPORT_MAX_BYTES,
                                 validate_retained_preflight)
from image.boot.inputs import require_desktop_image
from image.boot.preflight import expected_inputs


class AtomicUpdateTests(unittest.TestCase):
    class ShortWriter:
        def __init__(self, maximum):
            self.maximum = maximum
            self.raw = bytearray()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def write(self, raw):
            count = min(self.maximum, len(raw))
            self.raw.extend(raw[:count])
            return count

    @staticmethod
    def avc_command_result(*, exit_code=0, stdout=b"record", stderr=b"",
                           timed_out=False, stdout_truncated=False,
                           stderr_truncated=False):
        return {
            "command": AVC_JOURNAL_COMMAND,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }

    @staticmethod
    def avc_command_observation(*, exit_code=0, stdout=b"record", stderr=b"",
                                timed_out=False, stdout_truncated=False,
                                stderr_truncated=False):
        return {
            "command_sha256": AVC_COMMAND_SHA256,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout_bytes": len(stdout),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stdout_truncated": stdout_truncated,
            "stderr_bytes": len(stderr),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "stderr_truncated": stderr_truncated,
        }

    @staticmethod
    def avc_parser_predicates(*, record_index=0, record_count=1,
                              transport="kernel",
                              serial_source="message-audit-header",
                              denial_pattern_matched=False,
                              authenticated_serial_matched=True):
        return {
            "schema": 1,
            "record_index": record_index,
            "record_count": record_count,
            "transport": transport,
            "serial_source": serial_source,
            "denial_pattern_matched": denial_pattern_matched,
            "authenticated_serial_matched": authenticated_serial_matched,
        }

    @staticmethod
    def avc_journal_raw(**changes):
        source_context = "system_u:system_r:init_t:s0"
        message = (
            "audit: type=1400 audit(100.200:42): avc: denied { transition } for "
            "pid=654 comm=\"(sd-exec)\" "
            "path=\"/usr/libexec/symbi-atomic-update\" "
            "scontext=" + source_context + " "
            "tcontext=system_u:system_r:symbi_atomic_update_t:s0 "
            "tclass=process permissive=0"
        )
        record = {
            "MESSAGE": message,
            "__CURSOR": "s=" + "2" * 64,
            "__MONOTONIC_TIMESTAMP": "1002",
            "_TRANSPORT": "kernel",
        }
        record.update(changes)
        return (json.dumps(record) + "\n").encode()

    def collector_stream(self, stage="avc-journal", failure_kind="command-exit",
                         failure_detail=None, reason=None,
                         command_observation=None, terminated=False,
                         service_exit_code=None):
        writer = self.ShortWriter(4096)
        runner_hash = "a" * 64
        sequence = 0
        write_collector_event(
            writer, "collector-started", runner_hash, sequence=sequence)
        sequence += 1
        for current in COLLECTOR_STAGES:
            write_collector_event(
                writer, "collector-stage", runner_hash, sequence=sequence,
                stage=current)
            sequence += 1
            if current == stage:
                if failure_detail is not None:
                    detail_observation = failure_detail["command"]
                    command_observation = (
                        None if detail_observation["exit_code"] is None else {
                            "exit_code": detail_observation["exit_code"],
                            "timed_out": detail_observation["timed_out"],
                            "stdout_bytes": detail_observation["stdout_bytes"],
                            "stdout_truncated": detail_observation["stdout_truncated"],
                            "stderr_bytes": detail_observation["stderr_bytes"],
                            "stderr_truncated": detail_observation["stderr_truncated"],
                        })
                    reason = failure_detail["reason"]
                if reason is None:
                    if current == "avc-journal" and failure_kind == "command-exit":
                        reason = "unexpected-exit"
                        command_observation = self.stage_command_observation(
                            current, exit_code=2)
                    else:
                        reason = current + "-rejected"
                write_collector_event(
                    writer, ("collector-terminated" if terminated
                             else "collector-failed"), runner_hash,
                    sequence=sequence,
                    stage=current,
                    failure_kind=failure_kind, failure_detail=failure_detail,
                    reason=reason, command_observation=command_observation,
                    service_exit_code=service_exit_code)
                break
            observation = (self.stage_command_observation(current)
                           if current in {
                               "service-properties", "source-journal",
                               "avc-journal", "bounded-journal",
                           } else None)
            write_collector_event(
                writer, "collector-stage-result", runner_hash,
                sequence=sequence, stage=current, reason="accepted",
                command_observation=observation)
            sequence += 1
        return bytes(writer.raw)

    @staticmethod
    def stage_command_observation(stage, *, exit_code=0, timed_out=False,
                                  stdout_bytes=1, stdout_truncated=False,
                                  stderr_bytes=0, stderr_truncated=False):
        if stage == "avc-journal" and exit_code == 1:
            stdout_bytes = 0
        return {
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout_bytes": stdout_bytes,
            "stdout_truncated": stdout_truncated,
            "stderr_bytes": stderr_bytes,
            "stderr_truncated": stderr_truncated,
        }

    @staticmethod
    def stage_command_result(stage, *, exit_code=0, stdout=b"record", stderr=b"",
                             timed_out=False, stdout_truncated=False,
                             stderr_truncated=False):
        return {
            "command": {
                "service-properties": SERVICE_PROPERTIES_COMMAND,
                "source-journal": SOURCE_JOURNAL_COMMAND,
                "avc-journal": AVC_JOURNAL_COMMAND,
                "bounded-journal": failure_collector.JOURNAL_COMMAND,
            }[stage],
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }

    def completed_collector_stream(self, report_raw):
        writer = self.ShortWriter(4096)
        runner_hash = "a" * 64
        sequence = 0
        write_collector_event(
            writer, "collector-started", runner_hash, sequence=sequence)
        sequence += 1
        for stage in COLLECTOR_STAGES:
            write_collector_event(
                writer, "collector-stage", runner_hash, sequence=sequence,
                stage=stage)
            sequence += 1
            observation = (self.stage_command_observation(stage)
                           if stage in {
                               "service-properties", "source-journal",
                               "avc-journal", "bounded-journal",
                           } else None)
            write_collector_event(
                writer, "collector-stage-result", runner_hash,
                sequence=sequence, stage=stage, reason="accepted",
                command_observation=observation)
            sequence += 1
        write_collector_event(
            writer, "collector-completed", runner_hash, sequence=sequence,
            stage=COLLECTOR_STAGES[-1], report_observation={
                "bytes": len(report_raw),
                "sha256": hashlib.sha256(report_raw).hexdigest(),
            })
        return bytes(writer.raw)

    def test_virtio_report_writers_complete_short_writes_and_reject_zero(self):
        payload = b'{"passed":false}\n'
        guest = self.ShortWriter(3)
        with patch.object(Path, "exists", return_value=True), \
                patch.object(Path, "open", return_value=guest):
            write_channel(payload, Path("/unused-channel"))
        self.assertEqual(bytes(guest.raw), payload)

        failure = self.ShortWriter(5)
        with patch.object(Path, "exists", return_value=True), \
                patch.object(Path, "open", return_value=failure):
            write_failure_report({"passed": False}, Path("/unused-channel"))
        self.assertEqual(json.loads(bytes(failure.raw)), {"passed": False})

        for writer in (write_channel,
                       lambda raw, channel: write_failure_report(
                           {"passed": False}, channel)):
            with self.subTest(writer=writer), \
                    patch.object(Path, "exists", return_value=True), \
                    patch.object(Path, "open", return_value=self.ShortWriter(0)), \
                    self.assertRaises(RuntimeError):
                writer(payload, Path("/unused-channel"))

        collector = self.ShortWriter(4096)
        write_collector_event(
            collector, "collector-started", "a" * 64, sequence=0)
        self.assertEqual(
            json.loads(bytes(collector.raw)),
            {"schema": 1, "passed": False, "release_qualified": False,
             "diagnostic": "transition-evidence-collector",
             "event": "collector-started", "seq": 0, "unit": "b.service",
             "runner_sha256": "a" * 64,
             "scope": "Bounded collector progress; no transition or update claim"},
        )
        with self.assertRaises(RuntimeError):
            write_collector_event(
                self.ShortWriter(0), "collector-started", "a" * 64,
                sequence=0)
        with self.assertRaises(RuntimeError):
            write_collector_event(
                self.ShortWriter(4), "collector-started", "a" * 64,
                sequence=0)

    def test_collector_stream_binds_receipt_order_stage_and_failure(self):
        self.assertEqual(COLLECTOR_STAGES, TRANSITION_COLLECTOR_STAGES)
        raw = self.collector_stream()
        observed = validate_collector_diagnostic(raw, "a" * 64)
        self.assertTrue(observed["receipt"])
        self.assertEqual(observed["stages"], [
            "service-properties", "source-journal", "monitor",
            "identity-correlation", "avc-journal",
        ])
        self.assertEqual(observed["terminal"], {
            "event": "collector-failed", "stage": "avc-journal",
            "failure_kind": "command-exit",
            "reason": "unexpected-exit",
            "command_result": self.stage_command_observation(
                "avc-journal", exit_code=2),
        })
        self.assertEqual(observed["completed_stages"], [
            "service-properties", "source-journal", "monitor",
            "identity-correlation",
        ])
        self.assertIsNone(observed["suffix"])
        self.assertFalse(observed["passed"])
        self.assertFalse(observed["release_qualified"])

        receipt = raw.splitlines(keepends=True)[0]
        partial = validate_collector_diagnostic(receipt, "a" * 64)
        self.assertTrue(partial["receipt"])
        self.assertEqual(partial["stages"], [])
        self.assertEqual(partial["completed_stages"], [])
        self.assertIsNone(partial["terminal"])

        writer = self.ShortWriter(4096)
        sequence = 0
        write_collector_event(
            writer, "collector-started", "a" * 64, sequence=sequence)
        sequence += 1
        for stage in COLLECTOR_STAGES:
            write_collector_event(
                writer, "collector-stage", "a" * 64, sequence=sequence,
                stage=stage)
            sequence += 1
            observation = (self.stage_command_observation(stage)
                           if stage in {
                               "service-properties", "source-journal",
                               "avc-journal", "bounded-journal",
                           } else None)
            write_collector_event(
                writer, "collector-stage-result", "a" * 64,
                sequence=sequence, stage=stage, reason="accepted",
                command_observation=observation)
            sequence += 1
        report = {"bytes": 321, "sha256": "b" * 64}
        write_collector_event(
            writer, "collector-completed", "a" * 64, sequence=sequence,
            stage=COLLECTOR_STAGES[-1], report_observation=report)
        completed = validate_collector_diagnostic(bytes(writer.raw), "a" * 64)
        self.assertEqual(completed["terminal"], {
            "event": "collector-completed",
            "stage": "primary-report-write",
            "report": report,
        })
        self.assertEqual(completed["completed_stages"], list(COLLECTOR_STAGES))
        self.assertEqual(COLLECTOR_STAGE_OPERATION_SHA256,
                         TRANSITION_COLLECTOR_STAGE_OPERATION_SHA256)

    def test_collector_field_type_mutations_fail_closed(self):
        invalid_json_values = ([], {}, True, None)
        for value in invalid_json_values:
            for label, arguments in (
                    ("event", (value, "a" * 64, 0, None, None, None)),
                    ("runner-hash", ("collector-started", value, 0,
                                     None, None, None)),
                    ("sequence", ("collector-started", "a" * 64, value,
                                  None, None, None)),
                    ("stage", ("collector-stage", "a" * 64, 1,
                               value, None, None)),
                    ("failure-kind", ("collector-failed", "a" * 64, 6,
                                      "avc-journal", value, None))):
                event, runner_hash, sequence, stage, failure_kind, detail = arguments
                with self.subTest(producer=label, value=value), \
                        self.assertRaises(ValueError):
                    write_collector_event(
                        self.ShortWriter(4096), event, runner_hash,
                        sequence=sequence, stage=stage,
                        failure_kind=failure_kind, failure_detail=detail)

            for key in ("bytes", "sha256"):
                report = {"bytes": 321, "sha256": "b" * 64}
                report[key] = value
                with self.subTest(producer_report=key, value=value), \
                        self.assertRaises(ValueError):
                    write_collector_event(
                        self.ShortWriter(4096), "collector-completed", "a" * 64,
                        sequence=9, stage=COLLECTOR_STAGES[-1],
                        report_observation=report)

            with self.subTest(host_runner_hash=value), self.assertRaises(ValueError):
                validate_collector_diagnostic(
                    self.collector_stream(), value)

        receipt = json.loads(self.collector_stream().splitlines()[0])
        for key in receipt:
            for value in invalid_json_values:
                changed = copy.deepcopy(receipt)
                changed[key] = value
                raw = (json.dumps(
                    changed, sort_keys=True, separators=(",", ":")) + "\n").encode()
                with self.subTest(receipt=key, value=value), \
                        self.assertRaises(ValueError):
                    validate_collector_diagnostic(raw, "a" * 64)

        report_raw = b'{"passed":false}\n'
        completed_raw = self.completed_collector_stream(report_raw)
        lines = completed_raw.splitlines()
        terminal = json.loads(lines[-1])
        prefix = b"\n".join(lines[:-1]) + b"\n"
        for key in ("bytes", "sha256"):
            for value in invalid_json_values:
                changed = copy.deepcopy(terminal)
                changed["report"][key] = value
                raw = prefix + (json.dumps(
                    changed, sort_keys=True, separators=(",", ":")) + "\n").encode()
                observed = validate_collector_diagnostic(raw, "a" * 64)
                with self.subTest(host_report=key, value=value):
                    self.assertIsNone(observed["terminal"])
                    self.assertEqual(observed["suffix"]["state"], "invalid")

    def test_avc_failure_receipt_is_content_free_and_exactly_bound(self):
        private_stderr = b"API_TOKEN=must-not-be-retained"
        stderr = private_stderr[:1]
        observation = self.avc_command_observation(
            exit_code=1, stdout=b"", stderr=stderr, stderr_truncated=True)
        error = AvcEvidenceError("stderr-truncated", observation)
        detail = collector_failure_detail(error)
        self.assertEqual(detail, {
            "reason": "stderr-truncated", "command": observation,
        })
        self.assertNotIn("API_TOKEN", json.dumps(detail, sort_keys=True))
        self.assertNotIn("must-not-be-retained", json.dumps(detail, sort_keys=True))
        raw = self.collector_stream(
            failure_kind="invalid-evidence", failure_detail=detail)
        self.assertLessEqual(max(map(len, raw.splitlines())), 1280)
        observed = validate_collector_diagnostic(raw, "a" * 64)
        self.assertEqual(observed["terminal"], {
            "event": "collector-failed", "stage": "avc-journal",
            "failure_kind": "invalid-evidence", "failure_detail": detail,
            "reason": "stderr-truncated",
            "command_result": {
                "exit_code": 1, "timed_out": False,
                "stdout_bytes": 0, "stdout_truncated": False,
                "stderr_bytes": 1, "stderr_truncated": True,
            },
        })

        terminal = json.loads(raw.splitlines()[-1])
        mutations = []
        for key, value in (
                ("reason", "unreviewed-reason"),
                ("reason", "records-output-empty")):
            changed = copy.deepcopy(terminal)
            changed["failure_detail"][key] = value
            mutations.append((key, changed))
        for key, value in (
                ("command_sha256", "b" * 64),
                ("stderr_bytes", 0),
                ("stderr_truncated", False)):
            changed = copy.deepcopy(terminal)
            changed["failure_detail"]["command"][key] = value
            mutations.append((key, changed))
        changed = copy.deepcopy(terminal)
        changed["failure_kind"] = "command-exit"
        mutations.append(("failure_kind-binding", changed))
        invalid_json_values = ([], {}, True, None)
        for value in invalid_json_values:
            changed = copy.deepcopy(terminal)
            changed["failure_detail"] = value
            mutations.append(("failure_detail", changed))
            changed = copy.deepcopy(terminal)
            changed["failure_detail"]["reason"] = value
            mutations.append(("reason", changed))
            changed = copy.deepcopy(terminal)
            changed["failure_detail"]["command"] = value
            mutations.append(("command", changed))
        for key in observation:
            for value in invalid_json_values:
                if (type(value) is type(observation[key])
                        and value == observation[key]):
                    continue
                changed = copy.deepcopy(terminal)
                changed["failure_detail"]["command"][key] = value
                mutations.append((key, changed))
        for value in invalid_json_values:
            changed = copy.deepcopy(terminal)
            changed["failure_kind"] = value
            mutations.append(("failure_kind", changed))
        prefix = b"\n".join(raw.splitlines()[:-1]) + b"\n"
        for label, changed in mutations:
            candidate = prefix + (json.dumps(
                changed, sort_keys=True, separators=(",", ":")) + "\n").encode()
            with self.subTest(label=label, changed=changed):
                rejected = validate_collector_diagnostic(candidate, "a" * 64)
                self.assertIsNone(rejected["terminal"])
                self.assertEqual(rejected["suffix"]["state"], "invalid")

        for label, changed in mutations:
            if label == "failure_detail" and changed.get("failure_detail") is None:
                continue
            with self.subTest(producer_label=label), self.assertRaises(ValueError):
                write_collector_event(
                    self.ShortWriter(4096), "collector-failed", "a" * 64,
                    sequence=6, stage="avc-journal",
                    failure_kind=changed.get("failure_kind"),
                    failure_detail=changed.get("failure_detail"),
                    reason=changed.get("reason"),
                    command_observation=changed.get("command_result"))

        with self.assertRaises(ValueError):
            write_collector_event(
                self.ShortWriter(4096), "collector-failed", "a" * 64,
                sequence=2, stage="source-journal",
                failure_kind="invalid-evidence", failure_detail=detail,
                reason="source-journal-rejected", command_observation=None)

    def test_malformed_avc_retains_only_exact_parser_predicates(self):
        source = {
            "source_context": "system_u:system_r:init_t:s0",
            "requested_context": CONTROLLER_CONTEXT,
        }
        record = json.loads(self.avc_journal_raw())
        message = record["MESSAGE"]
        messages = (
            (message.replace("avc: denied", "avc: rejected"),
             self.avc_parser_predicates()),
            (message.replace("audit(100.200:42):", "audit:"),
             self.avc_parser_predicates(
                 denial_pattern_matched=True,
                 authenticated_serial_matched=False)),
            (message.replace("audit(100.200:42):", "audit:")
                    .replace("avc: denied", "avc: rejected"),
             self.avc_parser_predicates(
                 authenticated_serial_matched=False)),
        )
        for malformed, predicates in messages:
            changed = copy.deepcopy(record)
            changed["MESSAGE"] = malformed + " API_TOKEN=must-not-be-retained"
            raw = (json.dumps(changed) + "\n").encode()
            result = self.avc_command_result(exit_code=0, stdout=raw)
            with self.subTest(predicates=predicates), \
                    self.assertRaises(AvcEvidenceError) as caught:
                bounded_avc_evidence(source, None, Mock(return_value=result))
            self.assertEqual(caught.exception.reason, "denial-malformed")
            self.assertEqual(caught.exception.parser_predicates, predicates)
            detail = collector_failure_detail(caught.exception)
            self.assertEqual(detail, {
                "reason": "denial-malformed",
                "command": self.avc_command_observation(
                    exit_code=0, stdout=raw),
                "parser_predicates": predicates,
            })
            encoded = json.dumps(detail, sort_keys=True)
            self.assertNotIn("API_TOKEN", encoded)
            self.assertNotIn("must-not-be-retained", encoded)
            stream = self.collector_stream(
                failure_kind="invalid-evidence", failure_detail=detail)
            observed = validate_collector_diagnostic(stream, "a" * 64)
            self.assertEqual(
                observed["terminal"]["failure_detail"], detail)

        first = self.avc_journal_raw()
        second = copy.deepcopy(record)
        second["MESSAGE"] = message.replace("avc: denied", "avc: rejected")
        second["__CURSOR"] = "s=" + "3" * 64
        raw = first + (json.dumps(second) + "\n").encode()
        with self.assertRaises(AvcEvidenceError) as caught:
            bounded_avc_evidence(
                source, None, Mock(return_value=self.avc_command_result(
                    exit_code=0, stdout=raw)))
        self.assertEqual(caught.exception.parser_predicates,
                         self.avc_parser_predicates(
                             record_index=1, record_count=2))

    def test_avc_parser_predicate_receipt_rejects_every_schema_mutation(self):
        observation = self.avc_command_observation()
        predicates = self.avc_parser_predicates()
        error = AvcEvidenceError(
            "denial-malformed", observation,
            parser_predicates=predicates)
        detail = collector_failure_detail(error)
        raw = self.collector_stream(
            failure_kind="invalid-evidence", failure_detail=detail)
        terminal = json.loads(raw.splitlines()[-1])
        prefix = b"\n".join(raw.splitlines()[:-1]) + b"\n"
        mutations = []
        invalid_values = (None, [], {}, "1", True, 1.0)
        for key in predicates:
            for value in invalid_values:
                if type(value) is type(predicates[key]) and value == predicates[key]:
                    continue
                changed = copy.deepcopy(terminal)
                changed["failure_detail"]["parser_predicates"][key] = value
                mutations.append((key, value, changed))
        for key, value in (
                ("record_count", 0), ("record_count", 33),
                ("record_index", -1), ("record_index", 1),
                ("denial_pattern_matched", True),
                ("transport", "audit"),
                ("serial_source", "journal-audit-id")):
            changed = copy.deepcopy(terminal)
            changed["failure_detail"]["parser_predicates"][key] = value
            mutations.append((key, value, changed))
        for label in ("missing", "extra"):
            changed = copy.deepcopy(terminal)
            if label == "missing":
                del changed["failure_detail"]["parser_predicates"]["schema"]
            else:
                changed["failure_detail"]["parser_predicates"]["raw"] = "forbidden"
            mutations.append((label, None, changed))
        changed = copy.deepcopy(terminal)
        del changed["failure_detail"]["parser_predicates"]
        mutations.append(("predicates-absent", None, changed))
        changed = copy.deepcopy(terminal)
        del changed["failure_detail"]
        mutations.append(("detail-absent", None, changed))
        changed = copy.deepcopy(terminal)
        changed["reason"] = "permissions-invalid"
        mutations.append(("detail-reason-mismatch", None, changed))

        for label, value, changed in mutations:
            candidate = prefix + (json.dumps(
                changed, sort_keys=True, separators=(",", ":")) + "\n").encode()
            with self.subTest(host=label, value=value):
                rejected = validate_collector_diagnostic(candidate, "a" * 64)
                self.assertIsNone(rejected["terminal"])
                self.assertEqual(rejected["suffix"]["state"], "invalid")
            with self.subTest(producer=label, value=value), \
                    self.assertRaises(ValueError):
                write_collector_event(
                    self.ShortWriter(4096), "collector-failed", "a" * 64,
                    sequence=6, stage="avc-journal",
                    failure_kind=changed["failure_kind"],
                    failure_detail=changed.get("failure_detail"),
                    reason=changed["reason"],
                    command_observation=changed["command_result"])

        with self.assertRaises(ValueError):
            AvcEvidenceError("denial-malformed", observation)
        with self.assertRaises(ValueError):
            AvcEvidenceError(
                "stderr-truncated", observation,
                parser_predicates=predicates)

        with self.assertRaises(ValueError):
            write_collector_event(
                self.ShortWriter(4096), "collector-failed", "a" * 64,
                sequence=6, stage="avc-journal",
                failure_kind="invalid-evidence", failure_detail=None,
                reason="denial-malformed",
                command_observation=self.stage_command_observation(
                    "avc-journal", stdout_bytes=1))

    def test_avc_receipt_without_detail_binds_exit_and_output_precedence(self):
        exit_zero_nonempty = self.stage_command_observation("avc-journal")
        exit_one_nonempty = self.stage_command_observation(
            "avc-journal", exit_code=1)
        exit_one_nonempty["stdout_bytes"] = 10
        exit_zero_empty = self.stage_command_observation(
            "avc-journal", stdout_bytes=0)
        cases = (
            (exit_zero_nonempty, "stdout-invalid-utf8", (
                "records-output-empty", "no-match-output-nonempty")),
            (exit_one_nonempty, "no-match-output-nonempty", (
                "stdout-invalid-utf8", "avc-journal-rejected",
                "records-output-empty")),
            (exit_zero_empty, "records-output-empty", (
                "stdout-invalid-utf8", "avc-journal-rejected",
                "no-match-output-nonempty")),
        )
        for observation, valid_reason, invalid_reasons in cases:
            raw = self.collector_stream(
                stage="avc-journal", failure_kind="invalid-evidence",
                failure_detail=None, reason=valid_reason,
                command_observation=observation)
            accepted = validate_collector_diagnostic(raw, "a" * 64)
            with self.subTest(valid_reason=valid_reason):
                self.assertEqual(accepted["terminal"]["reason"], valid_reason)
                self.assertNotIn("failure_detail", accepted["terminal"])

            prefix = b"\n".join(raw.splitlines()[:-1]) + b"\n"
            terminal = json.loads(raw.splitlines()[-1])
            for invalid_reason in invalid_reasons:
                with self.subTest(observation=observation,
                                  invalid_reason=invalid_reason), \
                        self.assertRaises(ValueError):
                    write_collector_event(
                        self.ShortWriter(4096), "collector-failed", "a" * 64,
                        sequence=6, stage="avc-journal",
                        failure_kind="invalid-evidence", failure_detail=None,
                        reason=invalid_reason,
                        command_observation=observation)

                changed = copy.deepcopy(terminal)
                changed["reason"] = invalid_reason
                candidate = prefix + (json.dumps(
                    changed, sort_keys=True, separators=(",", ":"))
                    + "\n").encode()
                rejected = validate_collector_diagnostic(candidate, "a" * 64)
                self.assertIsNone(rejected["terminal"])
                self.assertEqual(rejected["suffix"]["state"], "invalid")

    def test_avc_command_status_predicates_reject_every_ambiguous_result(self):
        source = {
            "source_context": "system_u:system_r:init_t:s0",
            "requested_context": CONTROLLER_CONTEXT,
        }
        cases = (
            ("records-output-empty", self.avc_command_result(
                exit_code=0, stdout=b"")),
            ("no-match-output-nonempty", self.avc_command_result(
                exit_code=1, stdout=b"unexpected")),
            ("unexpected-exit", self.avc_command_result(
                exit_code=2, stdout=b"")),
            ("command-result-invalid", self.avc_command_result(
                exit_code=1, stdout=b"", stderr=b"x")),
            ("stdout-truncated", self.avc_command_result(
                exit_code=0, stdout=b"x" * (64 * 1024 + 1),
                stdout_truncated=True)),
            ("stderr-truncated", self.avc_command_result(
                exit_code=1, stdout=b"", stderr=b"x",
                stderr_truncated=True)),
            ("command-timeout", self.avc_command_result(
                exit_code=-9, stdout=b"", timed_out=True)),
            ("stdout-invalid-utf8", self.avc_command_result(
                exit_code=0, stdout=b"\xff")),
            ("journal-record-invalid-json", self.avc_command_result(
                exit_code=0, stdout=b"not-json\n")),
            ("command-result-invalid", "not-a-command-result"),
        )
        for reason, result in cases:
            runner = Mock(return_value=result)
            with self.subTest(reason=reason), \
                    self.assertRaises(AvcEvidenceError) as caught:
                bounded_avc_evidence(source, None, runner)
            self.assertEqual(caught.exception.reason, reason)
            detail = collector_failure_detail(caught.exception)
            self.assertIsNotNone(detail)
            self.assertEqual(detail["reason"], reason)
            self.assertEqual(set(detail), {"reason", "command"})
            runner.assert_called_once_with(
                AVC_JOURNAL_COMMAND, timeout=5, stdout_max=64 * 1024,
                stderr_max=0)

        wrong_command = self.avc_command_result(exit_code=1, stdout=b"")
        wrong_command["command"] = ["/usr/bin/true"]
        with self.assertRaises(AvcEvidenceError) as caught:
            bounded_avc_evidence(
                source, None, Mock(return_value=wrong_command))
        self.assertEqual(caught.exception.reason, "command-result-invalid")

    def test_returned_null_exit_status_becomes_bound_invalid_evidence(self):
        source = {
            "source_context": "system_u:system_r:init_t:s0",
            "requested_context": CONTROLLER_CONTEXT,
        }
        for exit_code, timed_out in (
                (None, False), (None, True), (True, False), (1.0, False),
                (-2**31 - 1, False), (256, False)):
            result = self.avc_command_result(
                exit_code=exit_code, stdout=b"", timed_out=timed_out)
            with self.subTest(exit_code=exit_code, timed_out=timed_out), \
                    self.assertRaises(AvcEvidenceError) as caught:
                bounded_avc_evidence(source, None, Mock(return_value=result))
            self.assertEqual(caught.exception.reason, "command-result-invalid")
            detail = collector_failure_detail(caught.exception)
            self.assertEqual(detail["reason"], "command-result-invalid")
            self.assertEqual(detail["command"]["exit_code"], None)
            self.assertFalse(detail["command"]["timed_out"])
            raw = self.collector_stream(
                failure_kind="invalid-evidence", failure_detail=detail)
            observed = validate_collector_diagnostic(raw, "a" * 64)
            self.assertEqual(observed["terminal"]["failure_detail"], detail)

        timeout = subprocess.TimeoutExpired(AVC_JOURNAL_COMMAND, 5)
        with self.assertRaises(AvcEvidenceError) as caught:
            bounded_avc_evidence(source, None, Mock(side_effect=timeout))
        self.assertEqual(caught.exception.reason, "command-timeout")
        detail = collector_failure_detail(caught.exception)
        self.assertIsNotNone(detail)
        self.assertEqual(detail["command"]["exit_code"], None)
        self.assertTrue(detail["command"]["timed_out"])

    def test_collector_stage_command_binds_fixed_identity_and_status(self):
        valid = self.stage_command_result(
            "service-properties", stdout=b"Result=exit-code\n")
        runner = Mock(return_value=valid)
        raw, observation = collector_stage_command(
            "service-properties", SERVICE_PROPERTIES_COMMAND,
            timeout=10, stdout_max=4096, run=runner)
        self.assertEqual(raw, "Result=exit-code\n")
        self.assertEqual(observation, self.stage_command_observation(
            "service-properties", stdout_bytes=len(valid["stdout"])))
        runner.assert_called_once_with(
            SERVICE_PROPERTIES_COMMAND, timeout=10, stdout_max=4096,
            stderr_max=8 * 1024)

        for stage, command, timeout, stdout_max, stderr_max in (
                ("service-properties", SERVICE_PROPERTIES_COMMAND, 9, 4096,
                 8 * 1024),
                ("service-properties", SERVICE_PROPERTIES_COMMAND, 10, 4095,
                 8 * 1024),
                ("service-properties", ["/usr/bin/true"], 10, 4096,
                 8 * 1024),
                ("source-journal", SERVICE_PROPERTIES_COMMAND, 5, 64 * 1024,
                 8 * 1024)):
            with self.subTest(identity=(stage, timeout, stdout_max)), \
                    self.assertRaisesRegex(ValueError, "identity differs"):
                collector_stage_command(
                    stage, command, timeout=timeout, stdout_max=stdout_max,
                    stderr_max=stderr_max, run=Mock())

        invalid_statuses = (None, True, 1.0, -2**31 - 1, 256)
        for exit_code in invalid_statuses:
            result = self.stage_command_result(
                "service-properties", exit_code=exit_code, stdout=b"")
            with self.subTest(exit_code=exit_code), \
                    self.assertRaises(CollectorCommandError) as caught:
                collector_stage_command(
                    "service-properties", SERVICE_PROPERTIES_COMMAND,
                    timeout=10, stdout_max=4096,
                    run=Mock(return_value=result))
            self.assertEqual(caught.exception.reason, "command-result-invalid")
            self.assertIsNone(caught.exception.observation)

        cases = (
            ("command-timeout", self.stage_command_result(
                "service-properties", exit_code=-9, stdout=b"",
                timed_out=True)),
            ("stdout-truncated", self.stage_command_result(
                "service-properties", stdout=b"x" * 4097,
                stdout_truncated=True)),
            ("stderr-truncated", self.stage_command_result(
                "service-properties", stdout=b"", stderr=b"x" * 8193,
                stderr_truncated=True)),
            ("stderr-nonempty", self.stage_command_result(
                "service-properties", stdout=b"", stderr=b"x")),
            ("unexpected-exit", self.stage_command_result(
                "service-properties", exit_code=2, stdout=b"")),
            ("stdout-invalid-utf8", self.stage_command_result(
                "service-properties", stdout=b"\xff")),
        )
        for reason, result in cases:
            with self.subTest(reason=reason), \
                    self.assertRaises(CollectorCommandError) as caught:
                collector_stage_command(
                    "service-properties", SERVICE_PROPERTIES_COMMAND,
                    timeout=10, stdout_max=4096,
                    run=Mock(return_value=result))
            self.assertEqual(caught.exception.reason, reason)
            self.assertIsNotNone(caught.exception.observation)

        for reason, error in (
                ("command-timeout", subprocess.TimeoutExpired(
                    SERVICE_PROPERTIES_COMMAND, 10)),
                ("spawn-permission", PermissionError("denied")),
                ("spawn-os-error", OSError("failed")),
                ("command-cleanup-failed", RuntimeError("unreaped"))):
            with self.subTest(exception=reason), \
                    self.assertRaises(CollectorCommandError) as caught:
                collector_stage_command(
                    "service-properties", SERVICE_PROPERTIES_COMMAND,
                    timeout=10, stdout_max=4096,
                    run=Mock(side_effect=error))
            self.assertEqual(caught.exception.reason, reason)
            self.assertIsNone(caught.exception.observation)

    def test_service_properties_parser_rejection_emits_exact_stage_receipt(self):
        writer = self.ShortWriter(4096)
        observation = self.stage_command_observation(
            "service-properties", stdout_bytes=len(b"malformed\n"))
        with patch.object(Path, "read_text",
                          return_value="Symbi-Hosted-Update-Probe"), \
                patch.object(Path, "exists", return_value=False), \
                patch.object(sys, "argv", ["symbi-update-failure.py"]), \
                patch("image.atomic.update_boot_failure.os.geteuid",
                      return_value=0), \
                patch("image.atomic.update_boot_failure.sha256",
                      return_value="a" * 64), \
                patch("image.atomic.update_boot_failure.open_collector_channel",
                      return_value=writer), \
                patch("image.atomic.update_boot_failure.persist_collector_state"), \
                patch("image.atomic.update_boot_failure.collector_stage_command",
                      return_value=("malformed\n", observation)), \
                self.assertRaises(ValueError):
            failure_collector.main()
        normalized = validate_collector_diagnostic(bytes(writer.raw), "a" * 64)
        self.assertEqual(normalized["completed_stages"], [])
        self.assertEqual(normalized["terminal"], {
            "event": "collector-failed",
            "stage": "service-properties",
            "failure_kind": "invalid-evidence",
            "reason": "service-properties-rejected",
            "command_result": observation,
        })
        self.assertNotIn("malformed", bytes(writer.raw).decode())

    def test_avc_journal_malformed_types_nesting_and_surrogates_are_normalized(self):
        source = {
            "source_context": "system_u:system_r:init_t:s0",
            "requested_context": CONTROLLER_CONTEXT,
        }
        cases = []
        invalid_json_values = ([], {}, True, None)
        for field in (
                "MESSAGE", "__CURSOR", "__MONOTONIC_TIMESTAMP", "_TRANSPORT"):
            for value in invalid_json_values:
                cases.append((field + "-type", self.avc_journal_raw(**{field: value})))
        cases.extend((
            ("cursor-malformed", self.avc_journal_raw(__CURSOR="short")),
            ("message-surrogate", self.avc_journal_raw(MESSAGE="\ud800")),
            ("cursor-surrogate", self.avc_journal_raw(__CURSOR="\ud800")),
            ("transport-surrogate", self.avc_journal_raw(_TRANSPORT="\ud800")),
            ("duplicate-key", b'{"MESSAGE":"one","MESSAGE":"two"}\n'),
            ("deep-nesting", (
                '{"nested":' + '[' * 1500 + '0' + ']' * 1500 + '}\n').encode()),
        ))
        for name, raw in cases:
            result = self.avc_command_result(exit_code=0, stdout=raw)
            with self.subTest(name=name), \
                    self.assertRaises(AvcEvidenceError) as caught:
                bounded_avc_evidence(source, None, Mock(return_value=result))
            self.assertIn(caught.exception.reason, AVC_FAILURE_REASONS)
            detail = collector_failure_detail(caught.exception)
            self.assertIsNotNone(detail)
            self.assertEqual(
                detail["command"],
                self.avc_command_observation(exit_code=0, stdout=raw))

    def test_bounded_command_result_observes_real_status_and_hard_caps(self):
        exit_one = bounded_command_result(
            [sys.executable, "-c", "raise SystemExit(1)"], timeout=2,
            stdout_max=16, stderr_max=16)
        self.assertEqual(exit_one["exit_code"], 1)
        self.assertEqual(exit_one["stdout"], b"")
        self.assertEqual(exit_one["stderr"], b"")
        self.assertFalse(exit_one["timed_out"])
        self.assertFalse(exit_one["stdout_truncated"])
        self.assertFalse(exit_one["stderr_truncated"])

        stdout = bounded_command_result(
            [sys.executable, "-c", "import sys;sys.stdout.write('x'*17)"],
            timeout=2, stdout_max=16, stderr_max=16)
        self.assertTrue(stdout["stdout_truncated"])
        self.assertEqual(len(stdout["stdout"]), 17)
        stderr = bounded_command_result(
            [sys.executable, "-c", "import sys;sys.stderr.write('x'*17)"],
            timeout=2, stdout_max=16, stderr_max=16)
        self.assertTrue(stderr["stderr_truncated"])
        self.assertEqual(len(stderr["stderr"]), 17)

        zero_stderr = bounded_command_result(
            [sys.executable, "-c", "import sys;sys.stderr.write('x')"],
            timeout=2, stdout_max=16, stderr_max=0)
        self.assertEqual(zero_stderr["stderr"], b"x")
        self.assertTrue(zero_stderr["stderr_truncated"])

        timed = bounded_command_result(
            [sys.executable, "-c",
             "import os,time;print(os.getpid(),flush=True);time.sleep(5)"],
            timeout=1, stdout_max=16, stderr_max=16)
        self.assertTrue(timed["timed_out"])
        self.assertIsInstance(timed["exit_code"], int)
        self.assertNotEqual(timed["exit_code"], 0)
        child_pid = int(timed["stdout"].strip())
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_bounded_command_cleanup_reaps_or_fails_closed(self):
        live = Mock()
        live.poll.return_value = None
        live.wait.return_value = -9
        self.assertEqual(_kill_and_reap(live), -9)
        live.kill.assert_called_once_with()
        live.wait.assert_called_once_with()

        raced = Mock()
        raced.poll.return_value = None
        raced.kill.side_effect = ProcessLookupError
        raced.wait.return_value = 0
        self.assertEqual(_kill_and_reap(raced), 0)
        raced.wait.assert_called_once_with()

        unreaped = Mock()
        unreaped.poll.return_value = None
        unreaped.wait.return_value = None
        with self.assertRaisesRegex(RuntimeError, "was not reaped"):
            _kill_and_reap(unreaped)
        unreaped.wait.assert_called_once_with()

        def mocked_process(*, kill_error=None, wait_error=None):
            process = Mock()
            process.stdout = SimpleNamespace(closed=True)
            process.stderr = SimpleNamespace(closed=True)
            process.poll.return_value = None
            process.kill.side_effect = kill_error
            process.wait.side_effect = wait_error
            if wait_error is None:
                process.wait.return_value = -9
            return process

        selector = Mock()
        selector.register.side_effect = RuntimeError("original selector failure")
        process = mocked_process()
        with patch("image.atomic.update_boot_failure.subprocess.Popen",
                   return_value=process), \
                patch("image.atomic.update_boot_failure.selectors.DefaultSelector",
                      return_value=selector), \
                self.assertRaisesRegex(RuntimeError, "original selector failure"):
            bounded_command_result(
                ["/usr/bin/true"], timeout=1, stdout_max=1, stderr_max=0)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with()

        with patch("image.atomic.update_boot_failure.subprocess.Popen",
                   return_value=mocked_process()) as opener, \
                patch(
                    "image.atomic.update_boot_failure.selectors.DefaultSelector",
                    side_effect=RuntimeError("selector construction failed")), \
                self.assertRaisesRegex(
                    RuntimeError, "selector construction failed"):
            bounded_command_result(
                ["/usr/bin/true"], timeout=1, stdout_max=1, stderr_max=0)
        constructed = opener.return_value
        constructed.kill.assert_called_once_with()
        constructed.wait.assert_called_once_with()

        for cleanup_error in (
                PermissionError("kill denied"), OSError("reap failed"),
                subprocess.TimeoutExpired(["/usr/bin/true"], 1)):
            if isinstance(cleanup_error, PermissionError):
                process = mocked_process(kill_error=cleanup_error)
            else:
                process = mocked_process(wait_error=cleanup_error)
            selector = Mock()
            selector.register.side_effect = RuntimeError(
                "original selector failure")
            with self.subTest(cleanup_error=type(cleanup_error).__name__), \
                    patch("image.atomic.update_boot_failure.subprocess.Popen",
                          return_value=process), \
                    patch(
                        "image.atomic.update_boot_failure.selectors.DefaultSelector",
                        return_value=selector), \
                    self.assertRaises(type(cleanup_error)) as caught:
                bounded_command_result(
                    ["/usr/bin/true"], timeout=1, stdout_max=1, stderr_max=0)
            self.assertIs(caught.exception, cleanup_error)
            if isinstance(cleanup_error, PermissionError):
                process.wait.assert_not_called()
            else:
                process.wait.assert_called_once_with()

    def test_auxiliary_collector_failures_never_block_the_primary_report(self):
        with patch("image.atomic.update_boot_failure.os.open",
                   side_effect=FileNotFoundError):
            self.assertIsNone(open_collector_channel(Path("/missing")))
        with patch("image.atomic.update_boot_failure.os.open", return_value=17) as opener, \
                patch("image.atomic.update_boot_failure.os.fstat",
                      return_value=SimpleNamespace(st_mode=stat.S_IFCHR)):
            self.assertEqual(open_collector_channel(Path("/collector")), 17)
            flags = opener.call_args.args[1]
            self.assertTrue(flags & os.O_WRONLY)
            self.assertTrue(flags & os.O_CLOEXEC)
            self.assertTrue(flags & os.O_NONBLOCK)
            self.assertFalse(flags & getattr(os, "O_NOFOLLOW", 0))

        with patch("image.atomic.update_boot_failure.os.open", return_value=29), \
                patch("image.atomic.update_boot_failure.os.fstat",
                      return_value=SimpleNamespace(st_mode=stat.S_IFREG)), \
                patch("image.atomic.update_boot_failure.os.close") as closer:
            self.assertIsNone(open_collector_channel(Path("/not-a-device")))
            closer.assert_called_once_with(29)

        with tempfile.TemporaryDirectory() as temporary:
            link = Path(temporary) / "collector"
            link.symlink_to("/dev/null")
            descriptor = open_collector_channel(link)
            self.assertIsInstance(descriptor, int)
            os.close(descriptor)

        state = {"output": self.ShortWriter(0), "sequence": 0}
        self.assertFalse(safe_collector_event(
            state, "collector-started", "a" * 64))
        self.assertIsNone(state["output"])

        state = {"output": 19, "sequence": 0}
        with patch("image.atomic.update_boot_failure.os.write", return_value=1), \
                patch("image.atomic.update_boot_failure.os.close") as closer:
            self.assertFalse(safe_collector_event(
                state, "collector-started", "a" * 64))
            closer.assert_called_once_with(19)
        self.assertIsNone(state["output"])

        state = {"output": 23, "sequence": 0}
        with patch("image.atomic.update_boot_failure.os.write",
                   side_effect=BlockingIOError), \
                patch("image.atomic.update_boot_failure.os.close"):
            self.assertFalse(safe_collector_event(
                state, "collector-started", "a" * 64))
        self.assertIsNone(state["output"])

        class BrokenClose(self.ShortWriter):
            def close(self):
                raise OSError("close failed")

        state = {"output": BrokenClose(16), "sequence": 0}
        close_collector(state)
        self.assertIsNone(state["output"])

        primary = self.ShortWriter(5)
        with patch.object(Path, "exists", return_value=True), \
                patch.object(Path, "open", return_value=primary):
            observation = write_failure_report(
                {"passed": False}, Path("/primary-report"))
        self.assertEqual(json.loads(bytes(primary.raw)), {"passed": False})
        self.assertEqual(observation["bytes"], len(bytes(primary.raw)))
        self.assertEqual(
            observation["sha256"], hashlib.sha256(bytes(primary.raw)).hexdigest())

    def test_stop_post_receipts_bind_timeout_signal_exit_and_transport(self):
        runner_hash = "a" * 64
        observation = self.stage_command_observation(
            "service-properties", stdout_bytes=128)
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "collector-state.json"
            cases = (
                ("timeout", False,
                 {"SERVICE_RESULT": "timeout", "EXIT_CODE": "killed",
                  "EXIT_STATUS": "TERM"},
                 "service-timeout", "timeout", None),
                ("signal", False,
                 {"SERVICE_RESULT": "signal", "EXIT_CODE": "killed",
                  "EXIT_STATUS": "ABRT"},
                 "service-signal", "unexpected", None),
                ("exit", False,
                 {"SERVICE_RESULT": "exit-code", "EXIT_CODE": "exited",
                  "EXIT_STATUS": "7"},
                 "service-exit", "command-exit", 7),
                ("transport", True,
                 {"SERVICE_RESULT": "signal", "EXIT_CODE": "killed",
                  "EXIT_STATUS": "KILL"},
                 "transport-loss", "transport", None),
            )
            for (label, transport_lost, environment, reason, failure_kind,
                 service_exit) in cases:
                state = {
                    "sequence": 2,
                    "stage": "service-properties",
                    "command_result": observation,
                    "terminal": False,
                    "transport_lost": transport_lost,
                }
                persist_collector_state(state, runner_hash, state_path)
                terminal_writer = self.ShortWriter(4096)
                with self.subTest(case=label), \
                        patch("image.atomic.update_boot_failure."
                              "open_collector_channel",
                              return_value=terminal_writer):
                    self.assertTrue(emit_stop_post_receipt(
                        runner_hash, state_path=state_path,
                        channel=Path("/unused"), environment=environment))
                prefix = self.ShortWriter(4096)
                write_collector_event(
                    prefix, "collector-started", runner_hash, sequence=0)
                write_collector_event(
                    prefix, "collector-stage", runner_hash, sequence=1,
                    stage="service-properties")
                normalized = validate_collector_diagnostic(
                    bytes(prefix.raw) + bytes(terminal_writer.raw), runner_hash)
                self.assertEqual(normalized["terminal"], {
                    "event": "collector-emergency",
                    "stage": "service-properties",
                    "failure_kind": failure_kind,
                    "reason": reason,
                    "command_result": observation,
                    "service_exit_code": service_exit,
                    "prepared_sequence": 2,
                })
                self.assertEqual(normalized["emergency"], normalized["terminal"])
                self.assertIsNone(normalized["suffix"])

            persist_collector_state({
                "sequence": 2,
                "stage": "service-properties",
                "command_result": observation,
                "terminal": False,
                "transport_lost": False,
            }, runner_hash, state_path)
            malformed_writer = self.ShortWriter(4096)
            with patch("image.atomic.update_boot_failure.open_collector_channel",
                       return_value=malformed_writer):
                self.assertFalse(emit_stop_post_receipt(
                    runner_hash, state_path=state_path,
                    environment={"SERVICE_RESULT": []}))
            self.assertEqual(bytes(malformed_writer.raw), b"")

            unknown_status_writer = self.ShortWriter(4096)
            with patch("image.atomic.update_boot_failure.open_collector_channel",
                       return_value=unknown_status_writer):
                self.assertTrue(emit_stop_post_receipt(
                    runner_hash, state_path=state_path,
                    environment={"SERVICE_RESULT": "exit-code",
                                 "EXIT_CODE": "exited", "EXIT_STATUS": []}))
            self.assertIsNone(
                json.loads(bytes(unknown_status_writer.raw).splitlines()[-1])[
                    "service_exit_code"])

        for invalid in (-1, 256, True, 1.0, [], {}):
            with self.subTest(service_exit=invalid), self.assertRaises(ValueError):
                write_collector_event(
                    self.ShortWriter(4096), "collector-terminated",
                    runner_hash, sequence=2, stage="service-properties",
                    failure_kind="command-exit", reason="service-exit",
                    command_observation=observation,
                    service_exit_code=invalid)

    def test_stop_post_retains_clean_incomplete_source_journal_receipt(self):
        runner_hash = "a" * 64
        service_observation = self.stage_command_observation(
            "service-properties", stdout_bytes=128)
        journal_observation = self.stage_command_observation(
            "source-journal", stdout_bytes=512)
        prefix = self.ShortWriter(4096)
        write_collector_event(
            prefix, "collector-started", runner_hash, sequence=0)
        write_collector_event(
            prefix, "collector-stage", runner_hash, sequence=1,
            stage="service-properties")
        write_collector_event(
            prefix, "collector-stage-result", runner_hash, sequence=2,
            stage="service-properties", reason="accepted",
            command_observation=service_observation)
        write_collector_event(
            prefix, "collector-stage", runner_hash, sequence=3,
            stage="source-journal")

        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "collector-state.json"
            persist_collector_state({
                "sequence": 4,
                "stage": "source-journal",
                "command_result": journal_observation,
                "terminal": False,
                "transport_lost": False,
            }, runner_hash, state_path)
            emergency = self.ShortWriter(4096)
            with patch("image.atomic.update_boot_failure."
                       "open_collector_channel", return_value=emergency):
                self.assertTrue(emit_stop_post_receipt(
                    runner_hash, state_path=state_path,
                    environment={"SERVICE_RESULT": "success",
                                 "EXIT_CODE": "exited", "EXIT_STATUS": "0"}))

            repeated = self.ShortWriter(4096)
            with patch("image.atomic.update_boot_failure."
                       "open_collector_channel", return_value=repeated):
                self.assertFalse(emit_stop_post_receipt(
                    runner_hash, state_path=state_path,
                    environment={"SERVICE_RESULT": "success",
                                 "EXIT_CODE": "exited", "EXIT_STATUS": "0"}))
            self.assertEqual(bytes(repeated.raw), b"")

        normalized = validate_collector_diagnostic(
            bytes(prefix.raw) + bytes(emergency.raw), runner_hash)
        self.assertEqual(normalized["terminal"], {
            "event": "collector-emergency",
            "stage": "source-journal",
            "failure_kind": "command-exit",
            "reason": "service-exit",
            "command_result": journal_observation,
            "service_exit_code": 0,
            "prepared_sequence": 4,
        })
        self.assertEqual(normalized["emergency"], normalized["terminal"])
        self.assertEqual(normalized["completed_stages"], ["service-properties"])
        self.assertIsNone(normalized["suffix"])

    def test_stop_post_marks_inconsistent_success_metadata_as_protocol_failure(self):
        runner_hash = "a" * 64
        observation = self.stage_command_observation(
            "source-journal", stdout_bytes=512)
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "collector-state.json"
            for label, environment, expected_exit in (
                    ("nonzero", {"SERVICE_RESULT": "success",
                                 "EXIT_CODE": "exited", "EXIT_STATUS": "7"}, 7),
                    ("missing", {"SERVICE_RESULT": "success"}, None)):
                persist_collector_state({
                    "sequence": 4,
                    "stage": "source-journal",
                    "command_result": observation,
                    "terminal": False,
                    "transport_lost": False,
                }, runner_hash, state_path)
                emergency = self.ShortWriter(4096)
                with self.subTest(case=label), patch(
                        "image.atomic.update_boot_failure.open_collector_channel",
                        return_value=emergency):
                    self.assertTrue(emit_stop_post_receipt(
                        runner_hash, state_path=state_path,
                        environment=environment))
                receipt = json.loads(bytes(emergency.raw).splitlines()[-1])
                self.assertEqual(receipt["reason"], "service-protocol")
                self.assertEqual(receipt["failure_kind"], "invalid-evidence")
                self.assertEqual(receipt["command_result"], observation)
                self.assertEqual(receipt["service_exit_code"], expected_exit)

    def test_collector_state_rejects_special_links_and_recovers_write_loss(self):
        runner_hash = "a" * 64
        observation = self.stage_command_observation(
            "service-properties", stdout_bytes=128)
        state = {
            "output": self.ShortWriter(0),
            "sequence": 2,
            "stage": "service-properties",
            "command_result": observation,
            "terminal": False,
            "transport_lost": False,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "collector-state.json"

            def persist_in_test(current, current_hash):
                return persist_collector_state(
                    current, current_hash, state_path)

            with patch("image.atomic.update_boot_failure.persist_collector_state",
                       side_effect=persist_in_test):
                self.assertFalse(collector_event(
                    state, "collector-stage-result", runner_hash,
                    stage="service-properties", reason="accepted",
                    command_observation=observation))
            retained = load_collector_state(state_path)
            self.assertTrue(retained["transport_lost"])
            self.assertEqual(retained["sequence"], 2)
            self.assertIsNone(state["output"])

            writer = self.ShortWriter(4096)
            with patch("image.atomic.update_boot_failure.open_collector_channel",
                       return_value=writer):
                self.assertTrue(emit_stop_post_receipt(
                    runner_hash, state_path=state_path,
                    environment={"SERVICE_RESULT": "timeout"}))
            terminal = json.loads(bytes(writer.raw).splitlines()[-1])
            self.assertEqual(terminal["reason"], "transport-loss")
            self.assertEqual(terminal["command_result"], observation)
            self.assertNotIn("stdout", terminal["command_result"])

            safe_target = root / "safe-target"
            safe_target.write_text("safe")
            safe_target.chmod(0o600)
            special_cases = []
            symlink = root / "state-symlink"
            symlink.symlink_to(safe_target)
            special_cases.append(symlink)
            hardlink = root / "state-hardlink"
            os.link(safe_target, hardlink)
            special_cases.append(hardlink)
            fifo = root / "state-fifo"
            os.mkfifo(fifo)
            special_cases.append(fifo)
            socket_path = root / "state-socket"
            listener = socket.socket(socket.AF_UNIX)
            try:
                listener.bind(str(socket_path))
                special_cases.append(socket_path)
                for path in special_cases:
                    with self.subTest(path=path.name), \
                            self.assertRaises(ValueError):
                        load_collector_state(path)
                    with self.subTest(persist=path.name), \
                            self.assertRaises(ValueError):
                        persist_collector_state(state, runner_hash, path)
            finally:
                listener.close()

            interrupted = root / "interrupted.json"
            with patch("image.atomic.update_boot_failure._write_all",
                       side_effect=RuntimeError("short write")), \
                    self.assertRaisesRegex(RuntimeError, "short write"):
                persist_collector_state(state, runner_hash, interrupted)
            self.assertFalse(interrupted.exists())
            self.assertEqual(
                list(root.glob("." + interrupted.name + ".*")), [])

            race_path = root / "race-state.json"
            safe_state = {
                "sequence": 2, "stage": "service-properties",
                "command_result": observation, "terminal": False,
                "transport_lost": False,
            }
            real_read = os.read

            def replace_name(descriptor, maximum):
                raw = real_read(descriptor, maximum)
                old = race_path.with_name(race_path.name + ".old")
                race_path.rename(old)
                race_path.write_bytes(raw)
                race_path.chmod(0o600)
                return raw

            persist_collector_state(safe_state, runner_hash, race_path)
            with patch("image.atomic.update_boot_failure.os.read",
                       side_effect=replace_name), self.assertRaisesRegex(
                           ValueError, "name changed"):
                load_collector_state(race_path)

            race_path.unlink()
            persist_collector_state(safe_state, runner_hash, race_path)

            def change_mode(descriptor, maximum):
                raw = real_read(descriptor, maximum)
                race_path.chmod(0o644)
                return raw

            with patch("image.atomic.update_boot_failure.os.read",
                       side_effect=change_mode), self.assertRaisesRegex(
                           ValueError, "name changed"):
                load_collector_state(race_path)

            race_path.chmod(0o600)
            link_after_open = root / "race-state-link"

            def add_link(descriptor, maximum):
                raw = real_read(descriptor, maximum)
                os.link(race_path, link_after_open)
                return raw

            with patch("image.atomic.update_boot_failure.os.read",
                       side_effect=add_link), self.assertRaisesRegex(
                           ValueError, "name changed"):
                load_collector_state(race_path)

    def test_emergency_frame_recovers_each_write_boundary(self):
        runner_hash = "a" * 64
        observation = self.stage_command_observation(
            "service-properties", stdout_bytes=128)

        def started_prefix():
            writer = self.ShortWriter(4096)
            write_collector_event(
                writer, "collector-started", runner_hash, sequence=0)
            return bytes(writer.raw)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            startup_state = root / "startup.json"
            persist_collector_state({
                "sequence": 0, "stage": None, "command_result": None,
                "terminal": False, "transport_lost": True,
            }, runner_hash, startup_state)
            startup_writer = self.ShortWriter(4096)
            with patch("image.atomic.update_boot_failure.open_collector_channel",
                       return_value=startup_writer):
                self.assertTrue(emit_stop_post_receipt(
                    runner_hash, state_path=startup_state,
                    environment={"SERVICE_RESULT": "timeout"}))
            startup = validate_collector_diagnostic(
                bytes(startup_writer.raw), runner_hash)
            self.assertEqual(startup["terminal"]["stage"], None)
            self.assertEqual(startup["terminal"]["reason"], "transport-loss")
            self.assertEqual(startup["terminal"]["prepared_sequence"], 0)
            self.assertEqual(startup["stages"], [])

            zero_state_path = root / "zero.json"
            zero_state = {
                "output": self.ShortWriter(0), "sequence": 1,
                "stage": None, "command_result": None, "terminal": False,
                "transport_lost": False,
            }

            def persist_zero(current, current_hash):
                persist_collector_state(current, current_hash, zero_state_path)

            with patch("image.atomic.update_boot_failure.persist_collector_state",
                       side_effect=persist_zero):
                self.assertFalse(collector_event(
                    zero_state, "collector-stage", runner_hash,
                    stage="service-properties"))
            zero_emergency = self.ShortWriter(4096)
            with patch("image.atomic.update_boot_failure.open_collector_channel",
                       return_value=zero_emergency):
                self.assertTrue(emit_stop_post_receipt(
                    runner_hash, state_path=zero_state_path,
                    environment={"SERVICE_RESULT": "timeout"}))
            zero = validate_collector_diagnostic(
                started_prefix() + bytes(zero_emergency.raw), runner_hash)
            self.assertEqual(zero["stages"], [])
            self.assertEqual(zero["terminal"]["stage"], "service-properties")
            self.assertEqual(zero["terminal"]["reason"], "transport-loss")
            self.assertIsNone(zero["suffix"])

            partial_state_path = root / "partial.json"
            partial_writer = self.ShortWriter(19)
            partial_state = {
                "output": partial_writer, "sequence": 1, "stage": None,
                "command_result": None, "terminal": False,
                "transport_lost": False,
            }

            def persist_partial(current, current_hash):
                persist_collector_state(
                    current, current_hash, partial_state_path)

            with patch("image.atomic.update_boot_failure.persist_collector_state",
                       side_effect=persist_partial):
                self.assertFalse(collector_event(
                    partial_state, "collector-stage", runner_hash,
                    stage="service-properties"))
            partial_emergency = self.ShortWriter(4096)
            with patch("image.atomic.update_boot_failure.open_collector_channel",
                       return_value=partial_emergency):
                self.assertTrue(emit_stop_post_receipt(
                    runner_hash, state_path=partial_state_path,
                    environment={"SERVICE_RESULT": "signal"}))
            partial = validate_collector_diagnostic(
                started_prefix() + bytes(partial_writer.raw)
                + bytes(partial_emergency.raw), runner_hash)
            self.assertEqual(partial["terminal"]["reason"], "transport-loss")
            self.assertEqual(partial["suffix"]["state"], "truncated")

            full_state_path = root / "full.json"
            full_writer = self.ShortWriter(4096)
            full_state = {
                "output": full_writer, "sequence": 1, "stage": None,
                "command_result": None, "terminal": False,
                "transport_lost": False,
            }
            persist_calls = 0

            def fail_after_full_write(current, current_hash):
                nonlocal persist_calls
                persist_calls += 1
                if persist_calls == 1:
                    persist_collector_state(
                        current, current_hash, full_state_path)
                    return
                raise OSError("state commit interrupted")

            with patch("image.atomic.update_boot_failure.persist_collector_state",
                       side_effect=fail_after_full_write):
                self.assertTrue(collector_event(
                    full_state, "collector-stage", runner_hash,
                    stage="service-properties"))
            full_emergency = self.ShortWriter(4096)
            with patch("image.atomic.update_boot_failure.open_collector_channel",
                       return_value=full_emergency):
                self.assertTrue(emit_stop_post_receipt(
                    runner_hash, state_path=full_state_path,
                    environment={"SERVICE_RESULT": "signal"}))
            full = validate_collector_diagnostic(
                started_prefix() + bytes(full_writer.raw)
                + bytes(full_emergency.raw), runner_hash)
            self.assertEqual(full["stages"], ["service-properties"])
            self.assertEqual(full["terminal"]["reason"], "service-signal")
            self.assertEqual(full["terminal"]["prepared_sequence"], 1)
            self.assertIsNone(full["suffix"])

            repeated = self.ShortWriter(4096)
            with patch("image.atomic.update_boot_failure.open_collector_channel",
                       return_value=repeated):
                self.assertFalse(emit_stop_post_receipt(
                    runner_hash, state_path=full_state_path,
                    environment={"SERVICE_RESULT": "signal"}))
            self.assertEqual(bytes(repeated.raw), b"")

    def test_collector_stream_rejects_unordered_or_unreviewed_content(self):
        raw = self.collector_stream()
        lines = raw.splitlines()
        receipt_mutations = [
            b"\n".join(lines[1:]) + b"\n",
            raw.replace(b'"runner_sha256":"' + b"a" * 64,
                        b'"runner_sha256":"' + b"b" * 64, 1),
            lines[0].replace(b'"schema":1', b'"schema":1.0') + b"\n",
            lines[0].replace(b'"passed":false', b'"passed":0') + b"\n",
            lines[0].replace(b'"seq":0', b'"seq":false') + b"\n",
            lines[0].replace(b'"schema":1', b'"schema":NaN') + b"\n",
        ]
        for mutation in receipt_mutations:
            with self.subTest(mutation=mutation[:80]), self.assertRaises(ValueError):
                validate_collector_diagnostic(mutation, "a" * 64)

        for mutation, state in (
            (b"\n".join([lines[0], lines[2], lines[1], *lines[3:]]) + b"\n",
             "invalid"),
            (raw + b'{"API_TOKEN":"must-not-pass"}\n', "invalid"),
            (raw + b'{"partial_secret":"must-not-pass"', "truncated"),
        ):
            with self.subTest(state=state):
                observed = validate_collector_diagnostic(mutation, "a" * 64)
                self.assertTrue(observed["receipt"])
                self.assertEqual(observed["suffix"]["state"], state)
                self.assertNotIn("must-not-pass", json.dumps(observed))

        observation = self.stage_command_observation(
            "service-properties", stdout_bytes=128)
        terminated = self.collector_stream(
            stage="service-properties", failure_kind="command-exit",
            reason="service-exit", command_observation=observation,
            terminated=True, service_exit_code=7)
        lines = terminated.splitlines(keepends=True)
        terminal = json.loads(lines[-1])
        mutations = []
        for value in (-1, 256, True, 1.0, [], {}):
            changed = copy.deepcopy(terminal)
            changed["service_exit_code"] = value
            mutations.append(("service-exit", value, changed))
        for key, value in (
                ("reason", "service-timeout"),
                ("failure_kind", "permission"),
                ("command_sha256", "b" * 64)):
            changed = copy.deepcopy(terminal)
            changed[key] = value
            mutations.append((key, value, changed))
        for key, value in (
                ("stdout_bytes", 4097),
                ("stdout_truncated", True),
                ("timed_out", [])):
            changed = copy.deepcopy(terminal)
            changed["command_result"][key] = value
            mutations.append(("command-result-" + key, value, changed))
        prefix = b"".join(lines[:-1])
        for label, value, changed in mutations:
            candidate = prefix + (json.dumps(
                changed, sort_keys=True, separators=(",", ":")) + "\n").encode()
            with self.subTest(termination=label, value=value):
                observed = validate_collector_diagnostic(candidate, "a" * 64)
                self.assertIsNone(observed["terminal"])
                self.assertEqual(observed["suffix"]["state"], "invalid")

    def test_collector_failure_cross_bindings_match_runtime_precedence(self):
        timeout = self.stage_command_observation(
            "service-properties", exit_code=-9, timed_out=True,
            stdout_bytes=0)
        valid = self.collector_stream(
            stage="service-properties", failure_kind="timeout",
            reason="command-timeout", command_observation=timeout)
        lines = valid.splitlines(keepends=True)
        terminal = json.loads(lines[-1])
        cases = []

        changed = copy.deepcopy(terminal)
        changed["reason"] = "service-properties-rejected"
        changed["failure_kind"] = "invalid-evidence"
        cases.append(("parser-rejection-with-timeout", changed))

        changed = copy.deepcopy(terminal)
        changed["failure_kind"] = "permission"
        cases.append(("timeout-kind", changed))

        changed = copy.deepcopy(terminal)
        changed["reason"] = "command-result-invalid"
        changed["failure_kind"] = "invalid-evidence"
        changed["command_result"] = self.stage_command_observation(
            "service-properties")
        cases.append(("invalid-result-with-valid-observation", changed))

        changed = copy.deepcopy(terminal)
        changed["reason"] = "stdout-invalid-utf8"
        changed["failure_kind"] = "invalid-evidence"
        changed["command_result"] = self.stage_command_observation(
            "service-properties", stdout_bytes=0)
        cases.append(("utf8-without-output", changed))

        changed = copy.deepcopy(terminal)
        changed["command_result"] = self.stage_command_observation(
            "service-properties", exit_code=-9, timed_out=True,
            stdout_bytes=4097, stdout_truncated=True)
        cases.append(("simultaneous-flags", changed))

        prefix = b"".join(lines[:-1])
        for label, changed in cases:
            arguments = {
                "failure_kind": changed["failure_kind"],
                "reason": changed["reason"],
                "command_observation": changed["command_result"],
            }
            with self.subTest(producer=label), self.assertRaises(ValueError):
                write_collector_event(
                    self.ShortWriter(4096), "collector-failed", "a" * 64,
                    sequence=2, stage="service-properties", **arguments)
            candidate = prefix + (json.dumps(
                changed, sort_keys=True, separators=(",", ":")) + "\n").encode()
            with self.subTest(host=label):
                observed = validate_collector_diagnostic(candidate, "a" * 64)
                self.assertIsNone(observed["terminal"])
                self.assertEqual(observed["suffix"]["state"], "invalid")

    def test_collector_parser_stays_within_a_48_mib_address_space(self):
        receipt = self.collector_stream().splitlines(keepends=True)[0]
        script = (
            "from image.atomic.update_boot import validate_collector_diagnostic;"
            "import sys;"
            "assert validate_collector_diagnostic(sys.stdin.buffer.read(),"
            "'a'*64)['receipt'] is True"
        )

        def limit_address_space():
            resource.setrlimit(resource.RLIMIT_AS, (48 * 1024**2, 48 * 1024**2))

        completed = subprocess.run(
            [sys.executable, "-c", script], input=receipt,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                 "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"},
            preexec_fn=limit_address_space,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_disposable_vm_deadline_exceeds_the_longest_guest_command(self):
        self.assertEqual(UPDATE_COMMAND_TIMEOUT_SECONDS, 1200)
        self.assertEqual(DISPOSABLE_PHASE_TIMEOUT_SECONDS, 1800)
        self.assertGreater(DISPOSABLE_PHASE_TIMEOUT_SECONDS,
                           UPDATE_COMMAND_TIMEOUT_SECONDS)

    def test_update_qemu_cleanup_does_not_mask_a_primary_failure(self):
        child = Mock()
        child.poll.return_value = None
        child.terminate.side_effect = PermissionError(13, "denied")
        child.kill.side_effect = PermissionError(13, "denied")
        result = stop_child(child)
        self.assertTrue(result["attempted"])
        self.assertFalse(result["terminated"])
        self.assertFalse(result["killed"])
        self.assertEqual(len(result["errors"]), 2)
        self.assertTrue(all("PermissionError" in error for error in result["errors"]))

    def test_exited_update_qemu_receives_no_cleanup_signal(self):
        child = Mock()
        child.poll.return_value = 1
        result = stop_child(child)
        self.assertFalse(result["attempted"])
        child.terminate.assert_not_called()
        child.kill.assert_not_called()

    def test_update_qemu_cleanup_escalates_after_terminate_timeout(self):
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [
            subprocess.TimeoutExpired(["qemu-system-x86_64"], 10), None,
        ]
        result = stop_child(child)
        self.assertTrue(result["attempted"])
        self.assertTrue(result["terminated"])
        self.assertTrue(result["killed"])
        self.assertEqual(result["errors"], [])
        child.terminate.assert_called_once_with()
        child.kill.assert_called_once_with()

    def test_failed_update_retains_only_bounded_direct_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            (output / "result.json").write_text('{"passed": false}\n')
            (output / "same-path-positive-serial.log").write_text("guest stalled\n")
            (output / "same-path-positive.qcow2").write_bytes(b"private disk")
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained,
                             ["controller-result.json", "same-path-positive-serial.log"])
            self.assertEqual((evidence / "controller-result.json").read_text(),
                             '{"passed": false}\n')
            self.assertFalse((evidence / "same-path-positive.qcow2").exists())

    @staticmethod
    def missing_report_controller(collector_raw=None, serial_raw=None, qemu_raw=None):
        command = positive_qemu_command()
        command_hash = hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest()
        names = {
            "update_boot.py", "update_boot_failure.py",
            "expected.json", "update-policy.json", "update-o.service", "s.service",
            "update-b.service", "update-f.service", "expected-positive.json",
            *("expected-" + case + ".json" for case in (
                "unsigned", "wrong-key", "wrong-reference", "altered-signature")),
        }
        limits = {"memory.max": "3221225472", "memory.swap.max": "0",
                  "cpu.max": "200000 100000", "pids.max": "64"}
        collector = (
            {"name": "same-path-positive-collector.jsonl", "state": "absent",
             "bytes": 0, "sha256": None}
            if collector_raw is None else
            {"name": "same-path-positive-collector.jsonl",
             "state": "empty" if collector_raw == b"" else "ready",
             "bytes": len(collector_raw),
             "sha256": hashlib.sha256(collector_raw).hexdigest()}
        )
        def observation(name, raw):
            return ({"name": name, "state": "absent", "bytes": 0,
                     "sha256": None}
                    if raw is None else
                    {"name": name, "state": "empty" if raw == b"" else "ready",
                     "bytes": len(raw),
                     "sha256": hashlib.sha256(raw).hexdigest()})
        return {
            "schema": 1, "passed": False, "guest_booted": False,
            "release_qualified": False, "active_phase": "same-path-positive",
            "failure": "ValueError: missing bounded update phase report",
            "negative_reports": [], "phase_reports": [],
            "commands": [command], "inputs": {name: "a" * 64 for name in names},
            "phase_failure": {
                "label": "same-path-positive", "command_sha256": command_hash,
                "exit_code": 0, "log_name": "qemu-same-path-positive.log",
                "serial_name": "same-path-positive-serial.log",
                "log": observation("qemu-same-path-positive.log", qemu_raw),
                "serial": observation("same-path-positive-serial.log", serial_raw),
                "report": {"name": "same-path-positive.json", "state": "empty",
                           "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
                "collector": collector,
            },
            "child_cleanup": {"attempted": False, "terminated": False,
                              "killed": False, "errors": []},
            "limits": limits,
            "cgroup_final": {**limits, "memory.peak": "2147483648",
                             "memory.events": ("low 0\nhigh 0\nmax 17\noom 0\n"
                                               "oom_kill 0\noom_group_kill 0\n"
                                               "sock_throttled 0\n"),
                             "cpu.stat": "usage_usec 1\n"},
        }

    def test_missing_report_retains_only_content_free_bound_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            collector_raw = self.collector_stream()
            serial_raw = b"".join((
                b"API_TOKEN=must-not-be-retained\n",
                b"console: SYMBI_UPDATE_LIFECYCLE=b-enter\n",
                b"console: SYMBI_UPDATE_LIFECYCLE=f-enter\n",
                b"console: SYMBI_UPDATE_LIFECYCLE=f-stop\n",
            ))
            qemu_raw = b"PRIVATE_KEY=must-not-be-retained\n"
            controller = self.missing_report_controller(
                collector_raw, serial_raw, qemu_raw)
            (output / "result.json").write_text(json.dumps(controller) + "\n")
            (output / "same-path-positive.json").write_bytes(b"")
            (output / "same-path-positive-collector.jsonl").write_bytes(
                collector_raw)
            (output / "same-path-positive-serial.log").write_bytes(serial_raw)
            (output / "qemu-same-path-positive.log").write_bytes(qemu_raw)
            (output / "same-path-positive.qcow2").write_bytes(b"private disk")
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained, ["controller-result.json",
                                        "same-path-positive-diagnostic.json"])
            summary = json.loads((evidence / "controller-result.json").read_bytes())
            self.assertTrue(summary["phase_diagnostic_validated"])
            self.assertTrue(summary["collector_prefix_validated"])
            self.assertTrue(summary["collector_stream_validated"])
            self.assertFalse(summary["transition_failure_validated"])
            diagnostic = json.loads(
                (evidence / "same-path-positive-diagnostic.json").read_bytes())
            self.assertEqual(diagnostic["diagnostic"], "missing-update-phase-report")
            self.assertEqual(diagnostic["process"]["exit_code"], 0)
            self.assertEqual(diagnostic["report"]["state"], "empty")
            self.assertEqual(diagnostic["outputs"]["qemu"], {
                "name": "qemu-same-path-positive.log", "state": "ready",
                "bytes": len(qemu_raw),
                "sha256": hashlib.sha256(qemu_raw).hexdigest(),
            })
            self.assertEqual(diagnostic["outputs"]["serial"], {
                "name": "same-path-positive-serial.log", "state": "ready",
                "bytes": len(serial_raw),
                "sha256": hashlib.sha256(serial_raw).hexdigest(),
            })
            self.assertEqual(diagnostic["outputs"]["lifecycle"], {
                "state": "valid", "events": ["b-enter", "f-enter", "f-stop"],
                "last_event": "f-stop", "boundary": "f-stopped",
                "marker_count": 3,
            })
            self.assertTrue(diagnostic["collector"]["prefix_validated"])
            self.assertTrue(diagnostic["collector"]["stream_validated"])
            self.assertEqual(
                diagnostic["collector"]["events"]["terminal"],
                {"event": "collector-failed", "stage": "avc-journal",
                 "failure_kind": "command-exit",
                 "reason": "unexpected-exit",
                 "command_result": self.stage_command_observation(
                     "avc-journal", exit_code=2)})
            self.assertEqual(
                diagnostic["collector"]["observation"]["sha256"],
                hashlib.sha256(collector_raw).hexdigest())
            self.assertEqual(diagnostic["resources"]["cpu.max"], "200000 100000")
            self.assertEqual(diagnostic["resources"]["pids.max"], "64")
            self.assertEqual(diagnostic["resources"]["memory.events"], {
                "max": "17", "oom": "0", "oom_group_kill": "0", "oom_kill": "0"})
            retained_raw = b"".join(path.read_bytes() for path in evidence.iterdir())
            self.assertNotIn(b"API_TOKEN", retained_raw)
            self.assertNotIn(b"PRIVATE_KEY", retained_raw)
            self.assertFalse((evidence / "same-path-positive-serial.log").exists())
            self.assertFalse((evidence / "qemu-same-path-positive.log").exists())
            self.assertFalse(
                (evidence / "same-path-positive-collector.jsonl").exists())
            self.assertFalse((evidence / "same-path-positive.qcow2").exists())

    def test_missing_report_diagnostic_rejects_identity_and_type_mutations(self):
        cases = (
            "command", "exit", "exit-false", "exit-float", "report",
            "report-bytes-false", "log", "log-bytes-false", "log-name-list",
            "log-state-null", "log-sha-list", "serial", "serial-extra",
            "input", "cleanup", "cleanup-int",
            "schema-true", "resource", "cpu-max", "pids-max",
            "duplicate-events", "integer-peak", "integer-events",
            "malformed-counter", "extra-counter",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output, evidence = root / "output", root / "evidence"
                output.mkdir()
                evidence.mkdir()
                serial_raw = b"API_TOKEN=must-not-be-retained\n"
                controller = self.missing_report_controller(
                    serial_raw=serial_raw)
                if case == "command":
                    controller["commands"][0][-1] = "--help"
                elif case == "exit":
                    controller["phase_failure"]["exit_code"] = 1
                elif case == "exit-false":
                    controller["phase_failure"]["exit_code"] = False
                elif case == "exit-float":
                    controller["phase_failure"]["exit_code"] = 0.0
                elif case == "report":
                    controller["phase_failure"]["report"]["sha256"] = "b" * 64
                elif case == "report-bytes-false":
                    controller["phase_failure"]["report"]["bytes"] = False
                elif case == "log":
                    controller["phase_failure"]["log"]["sha256"] = "b" * 64
                elif case == "log-bytes-false":
                    controller["phase_failure"]["log"]["bytes"] = False
                elif case == "log-name-list":
                    controller["phase_failure"]["log"]["name"] = []
                elif case == "log-state-null":
                    controller["phase_failure"]["log"]["state"] = None
                elif case == "log-sha-list":
                    controller["phase_failure"]["log"]["sha256"] = []
                elif case == "serial":
                    controller["phase_failure"]["serial"]["bytes"] = False
                elif case == "serial-extra":
                    controller["phase_failure"]["serial"]["extra"] = False
                elif case == "input":
                    controller["inputs"]["update_boot.py"] = "not-a-hash"
                elif case == "cleanup":
                    controller["child_cleanup"]["attempted"] = True
                elif case == "cleanup-int":
                    controller["child_cleanup"]["attempted"] = 0
                elif case == "schema-true":
                    controller["schema"] = True
                elif case == "resource":
                    controller["cgroup_final"]["memory.peak"] = "not-a-number"
                elif case == "cpu-max":
                    controller["cgroup_final"]["cpu.max"] = "max 100000"
                elif case == "pids-max":
                    controller["cgroup_final"]["pids.max"] = "max"
                elif case == "duplicate-events":
                    controller["cgroup_final"]["memory.events"] += "max 17\n"
                elif case == "integer-peak":
                    controller["cgroup_final"]["memory.peak"] = 2147483648
                elif case == "integer-events":
                    controller["cgroup_final"]["memory.events"] = 0
                elif case == "malformed-counter":
                    controller["cgroup_final"]["memory.events"] = "max 17 extra\n"
                elif case == "extra-counter":
                    controller["cgroup_final"]["memory.events"] += "unexpected 0\n"
                (output / "result.json").write_text(json.dumps(controller) + "\n")
                (output / "same-path-positive.json").write_bytes(b"")
                (output / "same-path-positive-serial.log").write_bytes(serial_raw)
                retained = retain_controller_output(output, evidence)
                self.assertEqual(retained, ["controller-result.json"])
                summary = json.loads(
                    (evidence / "controller-result.json").read_bytes())
                self.assertFalse(summary["transition_failure_validated"])
                self.assertNotIn("phase_diagnostic_validated", summary)
                self.assertEqual([path.name for path in evidence.iterdir()],
                                 ["controller-result.json"])

    def test_missing_report_binds_empty_outputs_and_absent_lifecycle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            controller = self.missing_report_controller(b"", b"", b"")
            (output / "result.json").write_text(json.dumps(controller) + "\n")
            (output / "same-path-positive.json").write_bytes(b"")
            (output / "same-path-positive-collector.jsonl").write_bytes(b"")
            (output / "same-path-positive-serial.log").write_bytes(b"")
            (output / "qemu-same-path-positive.log").write_bytes(b"")
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained, ["controller-result.json",
                                        "same-path-positive-diagnostic.json"])
            summary = json.loads((evidence / "controller-result.json").read_bytes())
            self.assertFalse(summary["passed"])
            self.assertFalse(summary["guest_booted"])
            self.assertFalse(summary["release_qualified"])
            self.assertFalse(summary["transition_failure_validated"])
            diagnostic = json.loads(
                (evidence / "same-path-positive-diagnostic.json").read_bytes())
            self.assertEqual(diagnostic["collector"]["observation"]["state"], "empty")
            self.assertEqual(diagnostic["outputs"]["qemu"]["state"], "empty")
            self.assertEqual(diagnostic["outputs"]["serial"]["state"], "empty")
            self.assertEqual(diagnostic["outputs"]["lifecycle"], {
                "state": "absent", "events": [], "last_event": None,
                "boundary": "unobserved", "marker_count": 0,
            })

    def test_missing_report_normalizes_invalid_lifecycle_without_raw_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            serial_raw = (b"SYMBI_UPDATE_LIFECYCLE=b-enter\n"
                          b"SYMBI_UPDATE_LIFECYCLE=API_TOKEN=not-retained\n")
            controller = self.missing_report_controller(
                b"", serial_raw=serial_raw)
            (output / "result.json").write_text(json.dumps(controller) + "\n")
            (output / "same-path-positive.json").write_bytes(b"")
            (output / "same-path-positive-collector.jsonl").write_bytes(b"")
            (output / "same-path-positive-serial.log").write_bytes(serial_raw)
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained, ["controller-result.json",
                                        "same-path-positive-diagnostic.json"])
            raw = (evidence / "same-path-positive-diagnostic.json").read_bytes()
            self.assertNotIn(b"API_TOKEN", raw)
            self.assertNotIn(b"not-retained", raw)
            lifecycle = json.loads(raw)["outputs"]["lifecycle"]
            self.assertEqual(lifecycle, {
                "state": "invalid", "events": [], "last_event": None,
                "boundary": "invalid", "marker_count": 2,
            })

    def test_missing_report_normalizes_a_secret_bearing_truncated_suffix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            valid = self.collector_stream()
            secret_suffix = b'{"API_TOKEN":"must-not-be-retained"'
            raw = valid + secret_suffix
            controller = self.missing_report_controller(raw)
            (output / "result.json").write_text(json.dumps(controller) + "\n")
            (output / "same-path-positive.json").write_bytes(b"")
            (output / "same-path-positive-collector.jsonl").write_bytes(raw)
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained, ["controller-result.json",
                                        "same-path-positive-diagnostic.json"])
            diagnostic_raw = (
                evidence / "same-path-positive-diagnostic.json").read_bytes()
            self.assertNotIn(b"API_TOKEN", diagnostic_raw)
            self.assertNotIn(b"must-not-be-retained", diagnostic_raw)
            diagnostic = json.loads(diagnostic_raw)
            self.assertTrue(diagnostic["collector"]["prefix_validated"])
            self.assertFalse(diagnostic["collector"]["stream_validated"])
            suffix = diagnostic["collector"]["events"]["suffix"]
            self.assertEqual(suffix["state"], "truncated")
            self.assertEqual(suffix["bytes"], len(secret_suffix))
            self.assertEqual(
                suffix["sha256"], hashlib.sha256(secret_suffix).hexdigest())
            self.assertFalse(
                (evidence / "same-path-positive-collector.jsonl").exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            raw = b'{"API_TOKEN":"malformed-first-event"}\n'
            controller = self.missing_report_controller(raw)
            (output / "result.json").write_text(json.dumps(controller) + "\n")
            (output / "same-path-positive.json").write_bytes(b"")
            (output / "same-path-positive-collector.jsonl").write_bytes(raw)
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained, ["controller-result.json",
                                        "same-path-positive-diagnostic.json"])
            retained_raw = b"".join(
                path.read_bytes() for path in evidence.iterdir())
            self.assertNotIn(b"API_TOKEN", retained_raw)
            self.assertNotIn(b"malformed-first-event", retained_raw)
            diagnostic = json.loads(
                (evidence / "same-path-positive-diagnostic.json").read_bytes())
            self.assertFalse(diagnostic["collector"]["prefix_validated"])
            self.assertFalse(diagnostic["collector"]["stream_validated"])
            self.assertIsNone(diagnostic["collector"]["events"])
            self.assertEqual(
                diagnostic["collector"]["observation"]["sha256"],
                hashlib.sha256(raw).hexdigest())

    def test_transition_failure_report_is_retained_without_private_overlay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            report = self.transition_failure_report()
            report["avc"] = {
                "command": AVC_JOURNAL_COMMAND,
                "command_observation": self.avc_command_observation(
                    exit_code=1, stdout=b""),
                "query_result": "no-match",
                "raw_bytes": 0,
                "raw_sha256": hashlib.sha256(b"").hexdigest(),
                "line_count": 0,
                "truncated": False,
                "records": [],
            }
            controller = self.transition_failure_controller(report)
            controller["unreviewed"] = "API_TOKEN=short"
            controller_raw = (json.dumps(controller, sort_keys=True) + "\n").encode()
            (output / "result.json").write_bytes(controller_raw)
            raw = (json.dumps(report, sort_keys=True) + "\n").encode()
            (output / "same-path-positive.json").write_bytes(raw)
            (output / "same-path-positive-serial.log").write_text(
                "b.service: API_TOKEN=short\n")
            (output / "qemu-same-path-positive.log").write_text(
                "guest console API_TOKEN=short\n")
            (output / "same-path-positive-collector.jsonl").write_bytes(
                self.completed_collector_stream(raw))
            (output / "same-path-positive.qcow2").write_bytes(b"private disk")
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained,
                             ["controller-result.json", "same-path-positive.json"])
            retained_controller = json.loads(
                (evidence / "controller-result.json").read_bytes())
            self.assertEqual(set(retained_controller), {
                "schema", "passed", "guest_booted", "release_qualified",
                "active_phase", "failure", "negative_reports", "phase_reports",
                "inputs", "transition_failure_validated", "diagnostic_evidence",
            })
            self.assertTrue(retained_controller["transition_failure_validated"])
            self.assertEqual(retained_controller["inputs"],
                             {"update_boot_failure.py": "a" * 64})
            self.assertEqual(
                retained_controller["failure"],
                "same-path-positive failed; bounded transition report validated")
            self.assertEqual((evidence / "same-path-positive.json").read_bytes(), raw)
            diagnostic = retained_controller["diagnostic_evidence"]
            self.assertEqual(
                diagnostic["report_declared_stages"],
                list(TRANSITION_COLLECTOR_STAGES[:-1]))
            self.assertEqual(
                diagnostic["collector_observed_stages"],
                list(TRANSITION_COLLECTOR_STAGES))
            self.assertEqual(diagnostic["report"], {
                "name": "same-path-positive.json", "state": "ready",
                "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            })
            self.assertEqual(diagnostic["collector_terminal"], {
                "event": "collector-completed",
                "stage": TRANSITION_COLLECTOR_STAGES[-1],
                "report": {"bytes": len(raw),
                           "sha256": hashlib.sha256(raw).hexdigest()},
            })
            retained_report = json.loads(
                (evidence / "same-path-positive.json").read_bytes())
            self.assertEqual(
                retained_report["probe"]["source_context"],
                "system_u:system_r:init_t:s0")
            self.assertEqual(retained_report["monitor"]["invocation_id"],
                             retained_report["service"]["InvocationID"])
            self.assertEqual(retained_report["avc"]["query_result"], "no-match")
            self.assertEqual(retained_report["avc"]["records"], [])
            self.assertIn("permission denied", retained_report["journal"]["excerpt"][0])
            self.assertFalse((evidence / "same-path-positive.qcow2").exists())
            self.assertFalse(
                (evidence / "same-path-positive-collector.jsonl").exists())
            retained_raw = b"".join(path.read_bytes() for path in evidence.iterdir())
            self.assertNotIn(b"API_TOKEN", retained_raw)
            self.assertNotIn(b"API_TOKEN=short", retained_raw)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            report = self.transition_failure_report()
            unredacted = "b.service: API_TOKEN=short"
            payload = (unredacted + "\n").encode("ascii")
            report["journal"].update(
                excerpt=[unredacted], line_count=1, bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest())
            controller = self.transition_failure_controller(
                failure="ValueError: transition-probe journal excerpt is unsafe")
            controller["unreviewed"] = "API_TOKEN=short"
            (output / "result.json").write_text(
                json.dumps(controller, sort_keys=True) + "\n")
            (output / "same-path-positive.json").write_text(
                json.dumps(report, sort_keys=True) + "\n")
            (output / "same-path-positive-serial.log").write_text(
                unredacted + "\n")
            (output / "qemu-same-path-positive.log").write_text(
                unredacted + "\n")
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained, ["controller-result.json"])
            retained_raw = (evidence / "controller-result.json").read_bytes()
            self.assertNotIn(b"API_TOKEN", retained_raw)
            retained_controller = json.loads(retained_raw)
            self.assertFalse(retained_controller["transition_failure_validated"])
            self.assertEqual(
                retained_controller["failure"],
                "same-path-positive failed; bounded transition report unavailable or rejected")
            self.assertFalse((evidence / "same-path-positive.json").exists())
            self.assertFalse((evidence / "same-path-positive-serial.log").exists())
            self.assertFalse((evidence / "qemu-same-path-positive.log").exists())

        for case, report_raw in (
            ("malformed", b'{"diagnostic":'),
            ("missing-diagnostic", b'{"API_TOKEN":"short","schema":1}\n'),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output, evidence = root / "output", root / "evidence"
                output.mkdir()
                evidence.mkdir()
                controller = self.transition_failure_controller(
                    failure="ValueError: rejected same-path-positive report")
                controller["unreviewed"] = "API_TOKEN=short"
                (output / "result.json").write_text(
                    json.dumps(controller, sort_keys=True) + "\n")
                (output / "same-path-positive.json").write_bytes(report_raw)
                (output / "same-path-positive-serial.log").write_text(
                    "API_TOKEN=short\n")
                (output / "qemu-same-path-positive.log").write_text(
                    "API_TOKEN=short\n")
                retained = retain_controller_output(output, evidence)
                self.assertEqual(retained, ["controller-result.json"])
                retained_raw = (evidence / "controller-result.json").read_bytes()
                self.assertNotIn(b"API_TOKEN", retained_raw)
                self.assertFalse(json.loads(retained_raw)["transition_failure_validated"])
                self.assertEqual([path.name for path in evidence.iterdir()],
                                 ["controller-result.json"])

    def test_transition_report_requires_exact_completed_collector_binding(self):
        report = self.transition_failure_report()
        raw = (json.dumps(report, sort_keys=True) + "\n").encode()
        valid_collector = self.completed_collector_stream(raw)
        stage_mutation = valid_collector.replace(
            b'"stage":"service-properties"',
            b'"stage":"source-journal"', 1)
        collector_lines = valid_collector.splitlines(keepends=True)
        invalid_event = json.loads(collector_lines[0])
        invalid_event["event"] = []
        collector_lines[0] = (json.dumps(
            invalid_event, sort_keys=True, separators=(",", ":")) + "\n").encode()
        cases = {
            "missing": None,
            "report-hash": self.completed_collector_stream(raw + b"different"),
            "stage": stage_mutation,
            "terminal": self.collector_stream(
                stage="primary-report-write", failure_kind="invalid-evidence"),
            "event-type": b"".join(collector_lines),
            "invalid-suffix": valid_collector
                              + b'{"API_TOKEN":"must-not-survive"}\n',
        }
        for case, collector in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output, evidence = root / "output", root / "evidence"
                output.mkdir()
                evidence.mkdir()
                controller = self.transition_failure_controller(report)
                (output / "result.json").write_text(
                    json.dumps(controller, sort_keys=True) + "\n")
                (output / "same-path-positive.json").write_bytes(raw)
                if collector is not None:
                    (output / "same-path-positive-collector.jsonl").write_bytes(
                        collector)
                retained = retain_controller_output(output, evidence)
                self.assertEqual(retained, ["controller-result.json"])
                retained_raw = (evidence / "controller-result.json").read_bytes()
                self.assertFalse(
                    json.loads(retained_raw)["transition_failure_validated"])
                self.assertNotIn(b"diagnostic_evidence", retained_raw)
                self.assertNotIn(b"API_TOKEN", retained_raw)
                self.assertFalse((evidence / "same-path-positive.json").exists())
                self.assertFalse(
                    (evidence / "same-path-positive-collector.jsonl").exists())

    def test_failed_update_refuses_unsafe_diagnostic_entries(self):
        for case in ("unexpected", "symlink", "hardlink", "fifo", "socket",
                     "directory", "oversized"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output, evidence = root / "output", root / "evidence"
                output.mkdir()
                evidence.mkdir()
                (output / "result.json").write_text('{"passed": false}\n')
                path = output / "same-path-positive-serial.log"
                if case == "unexpected":
                    (output / "unreviewed.txt").write_text("x")
                elif case == "symlink":
                    target = root / "target"
                    target.write_text("x")
                    path.symlink_to(target)
                elif case == "hardlink":
                    target = root / "target"
                    target.write_text("x")
                    os.link(target, path)
                elif case == "fifo":
                    os.mkfifo(path)
                elif case == "socket":
                    with socket.socket(socket.AF_UNIX) as server:
                        server.bind(str(path))
                        with self.assertRaises((OSError, ValueError)):
                            retain_controller_output(output, evidence)
                    continue
                elif case == "directory":
                    path.mkdir()
                else:
                    with path.open("wb") as stream:
                        stream.truncate(2 * 1024**2 + 1)
                with self.assertRaises((OSError, ValueError)):
                    retain_controller_output(output, evidence)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            (output / "result.json").write_text('{"passed":false}\n')
            with (output / "same-path-positive-collector.jsonl").open("wb") as stream:
                stream.truncate(16 * 1024 + 1)
            with self.assertRaisesRegex(ValueError, "unsafe or oversized"):
                retain_controller_output(output, evidence)

    def test_failed_update_refuses_existing_evidence_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            (output / "result.json").write_text('{"passed": false}\n')
            (evidence / "controller-result.json").write_text("preexisting\n")
            with self.assertRaises(FileExistsError):
                retain_controller_output(output, evidence)
            self.assertEqual((evidence / "controller-result.json").read_text(),
                             "preexisting\n")

    def test_failed_update_detects_same_size_in_place_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            (output / "result.json").write_text('{"passed": false}\n')
            path = output / "same-path-positive-serial.log"
            path.write_bytes(b"a" * 4096)
            initial = path.stat()
            original_read = os.read
            changed = False

            def changing_read(descriptor, count):
                nonlocal changed
                raw = original_read(descriptor, count)
                if not changed and os.fstat(descriptor).st_ino == initial.st_ino:
                    changed = True
                    path.write_bytes(b"b" * 4096)
                    os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns))
                return raw

            with patch("image.atomic.update_hosted.os.read", side_effect=changing_read):
                with self.assertRaisesRegex(ValueError, "changed while retained"):
                    retain_controller_output(output, evidence)

    def retained_preflight_context(self):
        root = Path(__file__).resolve().parents[2]
        lock = json.loads((root / "image/desktop-images.lock.json").read_text())
        pins = json.loads((root / "image/base-images.json").read_text())
        selected = lock["images"]["generic"]
        manifest = require_desktop_image(lock, pins, "generic")
        expected = expected_inputs(root, lock, pins, "generic")
        readiness = json.loads((root / "image/atomic/preflight.lock.json").read_text())
        return root, selected, manifest, expected, readiness

    def retained_preflight_fixture(self, destination):
        source, selected, manifest, expected, readiness = self.retained_preflight_context()
        root = Path(destination)
        (root / "image").mkdir()
        shutil.copyfile(source / "image/desktop-images.lock.json",
                        root / "image/desktop-images.lock.json")
        for relative in ("image/boot/probe.py", "image/desktop/verify.py",
                         "image/fonts/verify.py"):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative, target)
        evidence = (root / "docs/security/reports/P0-03-atomic-preflight"
                    / str(readiness["preflight_run"]))
        evidence.mkdir(parents=True)
        source_evidence = (source / "docs/security/reports/P0-03-atomic-preflight"
                           / str(readiness["preflight_run"]))
        for name in ("inspect.json", "prepare.json", "independent-check.json"):
            shutil.copyfile(source_evidence / name, evidence / name)

        # The checked-in retained preflight predates the dedicated controller
        # and must remain invalid.  Unit tests use a private synthetic copy so
        # mutation coverage can exercise every later predicate without
        # fabricating a repository-trusted predecessor identity.
        inspect_path = evidence / "inspect.json"
        inspect = json.loads(inspect_path.read_text())
        inspect["installed_files"]["atomic_update_controller"] = \
            self.controller_identity()
        inspect["probe_hashes"]["verify.py"] = hashlib.sha256(
            (root / "image/desktop/verify.py").read_bytes()).hexdigest()
        inspect_raw = (json.dumps(inspect, indent=2) + "\n").encode()
        inspect_path.write_bytes(inspect_raw)
        readiness = copy.deepcopy(readiness)
        readiness["inspect_sha256"] = hashlib.sha256(inspect_raw).hexdigest()

        check_path = evidence / "independent-check.json"
        check = json.loads(check_path.read_text())
        check["retained_reports"]["inspect.json"] = readiness["inspect_sha256"]
        check_raw = (json.dumps(check, indent=2) + "\n").encode()
        check_path.write_bytes(check_raw)
        readiness["independent_check_sha256"] = hashlib.sha256(
            check_raw).hexdigest()
        validate_retained_preflight(root, readiness, selected, manifest, expected)
        return root, selected, manifest, expected, copy.deepcopy(readiness), evidence

    def replace_retained_report(self, evidence, readiness, phase, item):
        raw = (json.dumps(item, indent=2) + "\n").encode()
        (evidence / (phase + ".json")).write_bytes(raw)
        report_sha256 = hashlib.sha256(raw).hexdigest()
        readiness[phase + "_sha256"] = report_sha256
        check_path = evidence / "independent-check.json"
        check = json.loads(check_path.read_text())
        check["retained_reports"][phase + ".json"] = report_sha256
        check_raw = (json.dumps(check, indent=2) + "\n").encode()
        check_path.write_bytes(check_raw)
        readiness["independent_check_sha256"] = hashlib.sha256(check_raw).hexdigest()

    def test_hosted_controller_imports(self):
        self.assertTrue(callable(run_update))

    def test_retained_preflight_matches_the_complete_current_image_lock(self):
        root, selected, manifest, expected, readiness = self.retained_preflight_context()
        with self.assertRaisesRegex(ValueError, "preflight is incomplete"):
            validate_retained_preflight(
                root, readiness, selected, manifest, expected)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.retained_preflight_fixture(temporary)
            fixture_root, fixture_selected, fixture_manifest, fixture_expected, \
                fixture_readiness, evidence = fixture
            reports = validate_retained_preflight(
                fixture_root, fixture_readiness, fixture_selected,
                fixture_manifest, fixture_expected)
            current_lock_sha256 = hashlib.sha256(
                (fixture_root / "image/desktop-images.lock.json").read_bytes()
            ).hexdigest()
            self.assertEqual(reports["prepare"]["lock_sha256"],
                             current_lock_sha256)

            stale = {**fixture_readiness, "source_commit": "0" * 40}
            with self.assertRaisesRegex(ValueError, "Exact saved-image preflight"):
                validate_retained_preflight(
                    fixture_root, stale, fixture_selected, fixture_manifest,
                    fixture_expected)

            mismatched_report = {
                **fixture_readiness, "inspect_sha256": "0" * 64}
            with self.assertRaisesRegex(ValueError, "evidence bytes changed"):
                validate_retained_preflight(
                    fixture_root, mismatched_report, fixture_selected,
                    fixture_manifest, fixture_expected)

            item = json.loads((evidence / "inspect.json").read_text())
            item["cgroup_final"]["cpu.stat"] += "\n"
            (evidence / "inspect.json").write_text(json.dumps(item) + "\n")
            with self.assertRaisesRegex(ValueError, "evidence bytes changed"):
                validate_retained_preflight(
                    fixture_root, fixture_readiness, fixture_selected,
                    fixture_manifest, fixture_expected)

        boolean_schema = {**readiness, "schema": True}
        with self.assertRaisesRegex(ValueError, "Unknown preflight readiness"):
            validate_retained_preflight(
                root, boolean_schema, selected, manifest, expected)
        for field, value in (("preflight_run", -1),
                             ("preflight_run", "../../45910498271"),
                             ("repository_id", True),
                             ("evidence_artifact_id", True),
                             ("evidence_artifact_bytes", -1),
                             ("evidence_artifact_sha256", 1),
                             ("inspect_sha256", 1),
                             ("kernel_observation_sha256", True),
                             ("manifest_digest", True)):
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, "Unknown preflight readiness"):
                validate_retained_preflight(
                    root, {**readiness, field: value}, selected, manifest, expected)

    def test_retained_preflight_rejects_envelope_and_resource_mutations(self):
        mutations = (
            ("boolean schema", "inspect", lambda item: item.__setitem__("schema", True)),
            ("wrong phase", "prepare", lambda item: item.__setitem__("phase", "inspect")),
            ("wrong base", "inspect", lambda item: item.__setitem__("base", "wrong")),
            ("wrong limits", "prepare", lambda item: item["limits"].__setitem__(
                "memory.max", "1")),
            ("wrong final limits", "inspect", lambda item: item["cgroup_final"].__setitem__(
                "pids.max", "1")),
            ("oom event", "inspect", lambda item: item["cgroup_final"].__setitem__(
                "memory.events", item["cgroup_final"]["memory.events"].replace(
                    "oom 0", "oom 1", 1))),
            ("missing oom event", "inspect", lambda item: item[
                "cgroup_final"].__setitem__("memory.events", item["cgroup_final"][
                    "memory.events"].replace("oom 0\n", "", 1))),
            ("duplicate oom event", "inspect", lambda item: item[
                "cgroup_final"].__setitem__("memory.events", item["cgroup_final"][
                    "memory.events"].replace("oom 0\n", "oom 0\noom 0\n", 1))),
            ("empty cpu stat", "prepare", lambda item: item[
                "cgroup_final"].__setitem__("cpu.stat", "")),
            ("boot input oom event", "inspect", lambda item: item["boot_inputs"][
                "cgroup_final"].__setitem__("memory.events", item["boot_inputs"][
                    "cgroup_final"]["memory.events"].replace("oom 0", "oom 1", 1))),
            ("changed command result", "inspect", lambda item: item["commands"][0].__setitem__(
                "exit_code", 1)),
            ("qualification scope", "inspect", lambda item: item.__setitem__(
                "scope", "Release qualified")),
            ("qualification field", "inspect", lambda item: item.__setitem__(
                "release_qualified", True)),
            ("nonstandard JSON number", "inspect", lambda item: item.__setitem__(
                "disk_free_before_load", float("nan"))),
        )
        for name, phase, mutate in mutations:
            with self.subTest(name), tempfile.TemporaryDirectory() as temporary:
                root, selected, manifest, expected, readiness, evidence = \
                    self.retained_preflight_fixture(temporary)
                item = json.loads((evidence / (phase + ".json")).read_text())
                mutate(item)
                self.replace_retained_report(evidence, readiness, phase, item)
                with self.assertRaises(ValueError):
                    validate_retained_preflight(
                        root, readiness, selected, manifest, expected)

    def test_retained_preflight_rejects_artifact_archive_and_boot_input_mutations(self):
        mutations = (
            ("artifact", "prepare", lambda item: item["artifact"].__setitem__(
                "id", item["artifact"]["id"] + 1)),
            ("artifact workflow", "prepare", lambda item: item["artifact"][
                "workflow_run"].__setitem__("head_sha", "0" * 40)),
            ("artifact repository", "prepare", lambda item: item["artifact"][
                "workflow_run"].__setitem__("repository_id", 1)),
            ("verified archive", "prepare", lambda item: item[
                "verified_archive"].__setitem__("image_id", "sha256:" + "0" * 64)),
            ("boot inputs", "inspect", lambda item: item["boot_inputs"][
                "os"].__setitem__("ID", "fedora")),
            ("boot command", "inspect", lambda item: item["boot_inputs"][
                "commands"][0].__setitem__("exit_code", 77)),
            ("boot backend", "inspect", lambda item: item["boot_inputs"].__setitem__(
                "backend_files", {})),
            ("boot tools", "inspect", lambda item: item["boot_inputs"][
                "tools"]["bootc"].__setitem__("present", False)),
            ("boot install configuration", "inspect", lambda item: item[
                "boot_inputs"]["install_configuration"].__setitem__("filesystem", "xfs")),
            ("boot memory peak", "inspect", lambda item: item["boot_inputs"][
                "cgroup_final"].__setitem__("memory.peak", "999999999999")),
        )
        for name, phase, mutate in mutations:
            with self.subTest(name), tempfile.TemporaryDirectory() as temporary:
                root, selected, manifest, expected, readiness, evidence = \
                    self.retained_preflight_fixture(temporary)
                item = json.loads((evidence / (phase + ".json")).read_text())
                mutate(item)
                self.replace_retained_report(evidence, readiness, phase, item)
                with self.assertRaises(ValueError):
                    validate_retained_preflight(
                        root, readiness, selected, manifest, expected)

    def test_retained_preflight_run_is_bound_to_independent_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, selected, manifest, expected, readiness, evidence = \
                self.retained_preflight_fixture(temporary)
            relabeled = evidence.parent / "1"
            shutil.copytree(evidence, relabeled)
            readiness["preflight_run"] = 1
            with self.assertRaisesRegex(ValueError, "Independent preflight reconciliation"):
                validate_retained_preflight(
                    root, readiness, selected, manifest, expected)

        with tempfile.TemporaryDirectory() as temporary:
            root, selected, manifest, expected, readiness, evidence = \
                self.retained_preflight_fixture(temporary)
            path = evidence / "independent-check.json"
            check = json.loads(path.read_text())
            check["evidence_artifact"].update({
                "id": 1, "bytes": 1, "sha256": "0" * 64})
            raw = (json.dumps(check, indent=2) + "\n").encode()
            path.write_bytes(raw)
            readiness["independent_check_sha256"] = hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(ValueError, "Independent preflight reconciliation"):
                validate_retained_preflight(
                    root, readiness, selected, manifest, expected)

    def test_retained_preflight_rejects_loaded_image_mutations(self):
        mutations = {
            "Id": "0" * 64,
            "Digest": "sha256:" + "0" * 64,
            "Architecture": "arm64",
            "Os": "windows",
        }
        for field, value in mutations.items():
            with self.subTest(field), tempfile.TemporaryDirectory() as temporary:
                root, selected, manifest, expected, readiness, evidence = \
                    self.retained_preflight_fixture(temporary)
                item = json.loads((evidence / "inspect.json").read_text())
                item["loaded_image"][field] = value
                self.replace_retained_report(evidence, readiness, "inspect", item)
                with self.assertRaises(ValueError):
                    validate_retained_preflight(
                        root, readiness, selected, manifest, expected)

    def test_retained_preflight_rejects_incomplete_payload_kernel_and_cleanup(self):
        def forge_both_kernel_observations(item):
            forged = "0" * 64
            item["boot_inputs"]["kernel"]["vmlinuz"]["sha256"] = forged
            item["kernel_copy"]["kernel"]["vmlinuz"]["sha256"] = forged
            observation = hashlib.sha256((json.dumps(
                item["boot_inputs"]["kernel"], sort_keys=True) + "\n").encode()).hexdigest()
            item["boot_inputs"]["kernel_source_sha256"] = observation
            item["kernel_copy"]["observation_sha256"] = observation

        mutations = (
            ("installed files", lambda item: item["installed_files"].__setitem__(
                "installed_files_checked", 211)),
            ("package identities", lambda item: item["installed_files"].__setitem__(
                "all_package_identities_preserved_after_build", False)),
            ("font verification", lambda item: item["installed_files"].__setitem__(
                "fonts", {"checked": False, "scanned_fonts": 0, "families": []})),
            ("kernel observation", lambda item: item["kernel_copy"].__setitem__(
                "observation_sha256", "0" * 64)),
            ("dual kernel observation", forge_both_kernel_observations),
            ("container cleanup", lambda item: item["cleanup"][
                "symbi-atomic-boot-inputs"].__setitem__("absent", False)),
            ("image cleanup", lambda item: item.__setitem__("image_removed", False)),
        )
        for name, mutate in mutations:
            with self.subTest(name), tempfile.TemporaryDirectory() as temporary:
                root, selected, manifest, expected, readiness, evidence = \
                    self.retained_preflight_fixture(temporary)
                item = json.loads((evidence / "inspect.json").read_text())
                mutate(item)
                self.replace_retained_report(evidence, readiness, "inspect", item)
                with self.assertRaises(ValueError):
                    validate_retained_preflight(
                        root, readiness, selected, manifest, expected)

    def test_retained_preflight_rejects_unsafe_report_files(self):
        for case in ("symlink", "hardlink", "fifo", "oversize", "parent-symlink"):
            with self.subTest(case), tempfile.TemporaryDirectory() as temporary:
                root, selected, manifest, expected, readiness, evidence = \
                    self.retained_preflight_fixture(temporary)
                path = evidence / "inspect.json"
                if case == "symlink":
                    target = evidence / "inspect-target.json"
                    path.rename(target)
                    path.symlink_to(target.name)
                elif case == "hardlink":
                    os.link(path, evidence / "inspect-hardlink.json")
                elif case == "fifo":
                    path.unlink()
                    os.mkfifo(path)
                elif case == "oversize":
                    item = json.loads(path.read_text())
                    item["cgroup_final"]["cpu.stat"] = "x" * RETAINED_REPORT_MAX_BYTES
                    raw = (json.dumps(item) + "\n").encode()
                    path.write_bytes(raw)
                    readiness["inspect_sha256"] = hashlib.sha256(raw).hexdigest()
                else:
                    target = evidence.with_name(evidence.name + "-target")
                    evidence.rename(target)
                    evidence.symlink_to(target.name, target_is_directory=True)
                messages = {"symlink": "direct regular file",
                            "hardlink": "bounded regular file",
                            "fifo": "bounded regular file",
                            "oversize": "bounded regular file",
                            "parent-symlink": "Linked preflight evidence"}
                previous_handler = signal.getsignal(signal.SIGALRM)
                if case == "fifo":
                    signal.signal(signal.SIGALRM,
                                  lambda *_: (_ for _ in ()).throw(TimeoutError()))
                    signal.setitimer(signal.ITIMER_REAL, 1)
                try:
                    with self.assertRaisesRegex(ValueError, messages[case]):
                        validate_retained_preflight(
                            root, readiness, selected, manifest, expected)
                finally:
                    if case == "fifo":
                        signal.setitimer(signal.ITIMER_REAL, 0)
                        signal.signal(signal.SIGALRM, previous_handler)

    def test_retained_preflight_rejects_duplicate_report_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, selected, manifest, expected, readiness, evidence = \
                self.retained_preflight_fixture(temporary)
            item = json.loads((evidence / "inspect.json").read_text())
            needle = '"Digest": ' + json.dumps(item["loaded_image"]["Digest"])
            text = (evidence / "inspect.json").read_text()
            raw = text.replace(needle, needle + ",\n    " + needle, 1).encode()
            (evidence / "inspect.json").write_bytes(raw)
            readiness["inspect_sha256"] = hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
                validate_retained_preflight(
                    root, readiness, selected, manifest, expected)

    old = "sha256:" + "1" * 64
    new = "sha256:" + "2" * 64
    source_uuid = "88888888-8888-4888-8888-888888888888"

    def entry(self, digest, transport="registry"):
        return {"incompatible": False, "image": {
            "image": {"image": "fixture", "transport": transport,
                      "signature": "containerPolicy"},
            "imageDigest": digest, "architecture": "amd64"}}

    def status(self, booted, staged=None, rollback=None, queued=False,
               default=None, default_transport="registry"):
        return {"apiVersion": "org.containers.bootc/v1", "kind": "BootcHost",
                "spec": {"image": self.entry(
                    default or booted, default_transport)["image"]["image"]},
                "status": {"type": "bootcHost", "booted": self.entry(booted),
                           "staged": self.entry(staged, "dir") if staged else None,
                           "rollback": self.entry(rollback) if rollback else None,
                           "rollbackQueued": queued}}

    def test_retained_update_base_is_exact_and_precedes_current_image(self):
        root = Path(__file__).resolve().parents[2]
        config = json.loads((root / "image/atomic/update-base.lock.json").read_text())
        pins = json.loads((root / "image/base-images.json").read_text())
        current = json.loads((root / "image/desktop-images.lock.json").read_text())
        with self.assertRaisesRegex(
                ValueError, "invalid retained predecessor preflight identity"):
            require_update_base(config, pins, current)
        config = copy.deepcopy(config)
        config["preflight"]["controller"] = self.controller_identity()
        selected = require_update_base(config, pins, current)
        self.assertEqual(selected["run_id"], 45792057599)
        self.assertEqual(config["manifest_digest"],
                         "sha256:9b6e8fdd9f6f98631895ccdfaaed6ffd88febd3ea6238d543935a524b572faf3")
        self.assertLess(selected["run_id"], current["images"]["generic"]["run_id"])
        evidence_path = root / current["images"]["generic"]["evidence"]
        evidence = json.loads(evidence_path.read_text())
        self.assertEqual(evidence["source_commit"], current["images"]["generic"]["tested_commit"])
        self.assertEqual(evidence["image_manifest_sha256"],
                         current["images"]["generic"]["manifest_sha256"])
        self.assertEqual(evidence["hosted_image_artifact"]["id"],
                         current["images"]["generic"]["artifact"]["id"])

        changed = copy.deepcopy(config)
        changed["image"]["tested_commit"] = current["images"]["generic"]["tested_commit"]
        with self.assertRaises(ValueError):
            require_update_base(changed, pins, current)

        for field, value in (
                ("entrypoint_sha256", True),
                ("controller_context", "system_u:system_r:install_t:s0"),
                ("expanded_policy", {})):
            changed = copy.deepcopy(config)
            changed["preflight"]["controller"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                require_update_base(changed, pins, current)

    def test_hosted_artifact_metadata_must_match_predecessor_lock(self):
        root = Path(__file__).resolve().parents[2]
        config = json.loads((root / "image/atomic/update-base.lock.json").read_text())
        selected = config["image"]
        metadata = {
            "id": selected["artifact"]["id"],
            "name": selected["artifact"]["name"],
            "size_in_bytes": selected["artifact"]["bytes"],
            "digest": "sha256:" + selected["artifact"]["sha256"],
            "expired": False,
            "workflow_run": {
                "id": selected["run_id"],
                "head_sha": selected["tested_commit"],
            },
        }
        validate_artifact_metadata(config, metadata)
        for field in ("id", "digest", "expired"):
            with self.subTest(field=field):
                changed = copy.deepcopy(metadata)
                changed[field] = True if field == "expired" else "changed"
                with self.assertRaises(ValueError):
                    validate_artifact_metadata(config, changed)

    def policy(self):
        return {
            "default": [{"type": "reject"}],
            "transports": {"docker": {"ghcr.io/thirdkeyai/symbiont-os": [{
                "type": "sigstoreSigned", "keyData": "release-public",
                "signedIdentity": {"type": "exactRepository",
                                   "dockerRepository": "ghcr.io/thirdkeyai/symbiont-os"},
            }]}},
        }

    def test_update_policy_preserves_release_rules_and_scopes_fixture_key(self):
        original = self.policy()
        result = update_policy(original, b"fixture public key", self.new)
        self.assertEqual(original, self.policy())
        self.assertEqual(result["default"], [{"type": "reject"}])
        self.assertEqual(result["transports"]["docker"], original["transports"]["docker"])
        self.assertEqual(set(result["transports"]["dir"]),
                         {"/run/symbi-update/source", NEGATIVE_UPDATE_SOURCE})
        rule = result["transports"]["dir"]["/run/symbi-update/source"][0]
        self.assertEqual(rule["type"], "signedBy")
        self.assertEqual(rule["signedIdentity"]["dockerReference"],
                         "localhost/symbi-ci/development@" + self.new)
        self.assertNotIn("insecureAcceptAnything", json.dumps(result))

    def test_real_source_negative_signatures_are_hash_bound_and_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authentication = {"negative_source_signatures": {"unsigned": None}}
            for case in ("wrong-key", "wrong-reference", "altered-signature"):
                payload = ("fixture-" + case).encode()
                (root / ("negative-" + case + "-signature-1")).write_bytes(payload)
                authentication["negative_source_signatures"][case] = hashlib.sha256(
                    payload).hexdigest()
            controls = negative_signature_payloads(root, authentication)
            self.assertIsNone(controls["unsigned"])
            self.assertEqual(set(controls), {
                "unsigned", "wrong-key", "wrong-reference", "altered-signature"})
            authentication["negative_source_signatures"]["wrong-key"] = "0" * 64
            with self.assertRaises(ValueError):
                negative_signature_payloads(root, authentication)

    def test_update_and_rollback_commands_keep_signature_enforcement(self):
        switch = update_command()
        prefix = ["/usr/bin/bootc"]
        self.assertEqual(switch[:3], [*prefix, "switch", "--transport"])
        self.assertIn("--enforce-container-sigpolicy", switch)
        self.assertEqual(switch[-1], "/run/symbi-update/source")
        self.assertEqual(rollback_command(), [*prefix, "rollback"])
        forbidden = {"--target-no-signature-verification", "--disable-selinux",
                     "--allow-missing-verity"}
        self.assertFalse(forbidden.intersection(switch))

        negative = update_command(NEGATIVE_UPDATE_SOURCE)
        self.assertIn("--enforce-container-sigpolicy", negative)
        self.assertEqual(negative[-1], NEGATIVE_UPDATE_SOURCE)
        with self.assertRaises(ValueError):
            update_command("/tmp/caller-selected-source")

    def test_three_boot_vm_uses_one_persistent_overlay_and_read_only_source(self):
        command = qemu_command(1)
        joined = " ".join(command)
        self.assertIn(
            "file=/output/guest.qcow2,format=qcow2,if=none,id=symbi-boot-disk",
            joined)
        self.assertIn(
            "virtio-blk-pci,drive=symbi-boot-disk,bootindex=1", joined)
        self.assertNotIn("snapshot=on", joined)
        self.assertIn(
            "file=/inputs/update.raw,format=raw,if=none,id=symbi-update-source,readonly=on",
            joined)
        self.assertIn(
            "virtio-blk-pci,drive=symbi-update-source,serial=SYMBIUPDATE", joined)
        self.assertNotIn("file=/inputs/update.raw,format=raw,if=virtio", joined)
        self.assertIn("-net none", joined)
        self.assertIn("phase-1.json", joined)
        self.assertNotIn("org.symbi.update.diagnostic", joined)
        firmware = firmware_arguments()
        self.assertIn("systemd.extra-unit.o.service", " ".join(firmware))
        self.assertIn("systemd.extra-unit.s.service", " ".join(firmware))
        self.assertIn("systemd.extra-unit.b.service", " ".join(firmware))
        self.assertIn("systemd.extra-unit.f.service", " ".join(firmware))
        self.assertIn("symbi-update-failure.py", " ".join(firmware))
        self.assertNotIn("fstab.extra", " ".join(firmware))

    def transition_failure_report(self):
        excerpt = bounded_journal_excerpt(
            "b.service: /usr/libexec/symbi-atomic-update: "
            "permission denied while starting the fixed probe: "
            "Permission denied\n")
        source = "system_u:system_r:init_t:s0"
        requested = CONTROLLER_CONTEXT
        invocation = "b" * 32
        return {
            "schema": 1,
            "passed": False,
            "guest_booted": True,
            "release_qualified": False,
            "product": "Symbi-Hosted-Update-Probe",
            "diagnostic": "bootc-transition-probe-failure",
            "unit": "b.service",
            "runner_sha256": "a" * 64,
            "service": {
                "Result": "exit-code", "ExecMainCode": "1",
                "ExecMainStatus": "229", "ActiveState": "failed",
                "SubState": "failed", "InvocationID": invocation,
                "ExecMainPID": "654",
                "ExecMainStartTimestampMonotonic": "1001",
                "ExecMainExitTimestampMonotonic": "1003",
            },
            "monitor": {
                "unit": "b.service", "invocation_id": invocation,
                "service_result": "exit-code", "exit_code": "exited",
                "exit_status": "229",
            },
            "probe": {
                "command": SOURCE_CAPTURE_COMMAND,
                "journal_command": SOURCE_JOURNAL_COMMAND,
                "source_context": source,
                "requested_context": requested,
                "probe_command": [str(CONTROLLER_ENTRYPOINT), "--probe"],
                "invocation_id": invocation,
                "pid": 653,
                "transport": "stdout",
                "receipt_monotonic_usec": 1000,
                "cursor_sha256": "c" * 64,
            },
            "avc": {
                "command": AVC_JOURNAL_COMMAND,
                "command_observation": {
                    "command_sha256": AVC_COMMAND_SHA256,
                    "exit_code": 0,
                    "timed_out": False,
                    "stdout_bytes": 512,
                    "stdout_sha256": "d" * 64,
                    "stdout_truncated": False,
                    "stderr_bytes": 0,
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                    "stderr_truncated": False,
                },
                "query_result": "records",
                "raw_bytes": 512,
                "raw_sha256": "d" * 64,
                "line_count": 1,
                "truncated": False,
                "records": [{
                    "audit_serial": 42,
                    "audit_serial_source": "message-audit-header",
                    "transport": "kernel",
                    "receipt_monotonic_usec": 1002,
                    "pid": 654,
                    "comm": "(sd-exec)",
                    "path_field": "path",
                    "path": str(CONTROLLER_ENTRYPOINT),
                    "source_context": source,
                    "target_context": requested,
                    "class": "process",
                    "permissions": ["transition"],
                    "permissive": False,
                    "cursor_sha256": "e" * 64,
                }],
            },
            "journal": excerpt,
            "diagnostic_stages": list(TRANSITION_COLLECTOR_STAGES[:-1]),
            "scope": "Bounded explicit-transition diagnostics; no update action ran",
        }

    @staticmethod
    def transition_failure_controller(report=None, failure=None):
        result = {
            "schema": 1,
            "passed": False,
            "guest_booted": False,
            "release_qualified": False,
            "active_phase": "same-path-positive",
            "failure": (failure or
                        "RuntimeError: bootc transition probe failed; inspect bounded report"),
            "negative_reports": [],
            "phase_reports": [],
            "inputs": {"update_boot_failure.py": "a" * 64},
        }
        if report is not None:
            result["transition_failure"] = report
        return result

    def test_transition_failure_report_binds_exact_fields_and_bounds(self):
        report = self.transition_failure_report()
        self.assertEqual(validate_transition_failure_report(report, "a" * 64), report)
        mutations = []
        for schema in (True, 1.0):
            changed = copy.deepcopy(report)
            changed["schema"] = schema
            mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["extra"] = True
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["service"]["ActiveState"] = "active"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["service"]["ExecMainStatus"] = "not-a-number"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["service"]["ExecMainStatus"] = "0"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["monitor"]["invocation_id"] = "c" * 32
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["monitor"]["exit_code"] = "killed"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["probe"]["probe_command"][-1] = "status"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["probe"]["receipt_monotonic_usec"] = 120001002
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["diagnostic_stages"] = list(TRANSITION_COLLECTOR_STAGES[:-2])
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["diagnostic_stages"] = tuple(TRANSITION_COLLECTOR_STAGES[:-1])
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["avc"]["records"][0]["pid"] = 655
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["avc"]["records"][0]["source_context"] = (
            "system_u:system_r:unrelated_t:s0")
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["avc"]["records"][0]["permissive"] = True
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["avc"]["records"].append(copy.deepcopy(changed["avc"]["records"][0]))
        changed["avc"]["line_count"] = 2
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["journal"]["excerpt"][0] = "x" * (JOURNAL_MAX_LINE_BYTES + 1)
        changed["journal"]["bytes"] = len(changed["journal"]["excerpt"][0]) + 1
        changed["journal"]["sha256"] = hashlib.sha256(
            (changed["journal"]["excerpt"][0] + "\n").encode()).hexdigest()
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["journal"]["sha256"] = "b" * 64
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["journal"]["excerpt"][0] += "\x00"
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_transition_failure_report(changed, "a" * 64)
        with self.assertRaises(ValueError):
            validate_transition_failure_report(report, "b" * 64)
        properties = ("Result=exit-code\nExecMainCode=1\nExecMainStatus=229\n"
                      "ActiveState=failed\nSubState=failed\n"
                      "InvocationID=" + "b" * 32 + "\nExecMainPID=654\n"
                      "ExecMainStartTimestampMonotonic=1001\n"
                      "ExecMainExitTimestampMonotonic=1003\n")
        self.assertEqual(service_properties(properties), report["service"])
        monitor_environment = {
            "MONITOR_UNIT": "b.service",
            "MONITOR_INVOCATION_ID": "b" * 32,
            "MONITOR_SERVICE_RESULT": "exit-code",
            "MONITOR_EXIT_CODE": "exited",
            "MONITOR_EXIT_STATUS": "229",
        }
        self.assertEqual(monitor_properties(monitor_environment), report["monitor"])
        with self.assertRaisesRegex(ValueError, "did not fail closed"):
            service_properties(properties.replace("ExecMainStatus=229",
                                                  "ExecMainStatus=0"))

    def test_transition_avc_no_match_is_exact_and_fail_closed(self):
        report = self.transition_failure_report()
        no_match = {
            "command": AVC_JOURNAL_COMMAND,
            "command_observation": self.avc_command_observation(
                exit_code=1, stdout=b""),
            "query_result": "no-match",
            "raw_bytes": 0,
            "raw_sha256": hashlib.sha256(b"").hexdigest(),
            "line_count": 0,
            "truncated": False,
            "records": [],
        }
        report["avc"] = no_match
        self.assertEqual(validate_transition_failure_report(report, "a" * 64), report)
        mutations = []
        for key, value in (
                ("query_result", "records"),
                ("query_result", []),
                ("raw_bytes", 1),
                ("raw_sha256", "d" * 64),
                ("raw_sha256", []),
                ("line_count", 1),
                ("truncated", True),
                ("records", [copy.deepcopy(
                    self.transition_failure_report()["avc"]["records"][0])])):
            changed = copy.deepcopy(report)
            changed["avc"][key] = value
            mutations.append(changed)
        for observation in (
                self.avc_command_observation(exit_code=0, stdout=b""),
                self.avc_command_observation(exit_code=1, stdout=b"unexpected"),
                self.avc_command_observation(
                    exit_code=1, stdout=b"", stderr=b"diagnostic"),
                self.avc_command_observation(
                    exit_code=-9, stdout=b"", timed_out=True),
                self.avc_command_observation(
                    exit_code=-9, stdout=b"x" * (64 * 1024 + 1),
                    stdout_truncated=True)):
            changed = copy.deepcopy(report)
            changed["avc"]["command_observation"] = observation
            mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["avc"]["command_observation"]["command_sha256"] = "d" * 64
        mutations.append(changed)
        invalid_json_values = ([], {}, True, None)
        for key in no_match["command_observation"]:
            for value in invalid_json_values:
                changed = copy.deepcopy(report)
                changed["avc"]["command_observation"][key] = value
                mutations.append(changed)
        for key in no_match:
            if key == "command_observation":
                continue
            for value in invalid_json_values:
                if type(value) is type(no_match[key]) and value == no_match[key]:
                    continue
                changed = copy.deepcopy(report)
                changed["avc"][key] = value
                mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed["avc"]), self.assertRaises(ValueError):
                validate_transition_failure_report(changed, "a" * 64)

    def test_transition_avc_record_type_mutations_fail_as_value_errors(self):
        report = self.transition_failure_report()
        record = report["avc"]["records"][0]
        invalid_json_values = ([], {}, True, None)
        for key in record:
            for value in invalid_json_values:
                changed = copy.deepcopy(report)
                changed["avc"]["records"][0][key] = value
                with self.subTest(key=key, value=value), \
                        self.assertRaises(ValueError):
                    validate_transition_failure_report(changed, "a" * 64)
        changed = copy.deepcopy(report)
        changed["avc"]["records"][0]["permissions"] = [["transition"]]
        with self.assertRaises(ValueError):
            validate_transition_failure_report(changed, "a" * 64)

    def test_transition_failure_journal_is_bounded_and_redacts_secret_shapes(self):
        secret = "s" * 64
        long_value = "a" * 64
        raw = ("token=" + secret + "\n" + long_value + "\n"
               + "Authorization: Bearer bearer-value\n"
               + ("z!" * (JOURNAL_MAX_LINE_BYTES + 100)) + "\n"
               + "control\x00value\n"
               + (("q!" * (JOURNAL_MAX_LINE_BYTES // 2) + "\n")
                  * JOURNAL_MAX_LINES))
        observed = bounded_journal_excerpt(raw)
        rendered = "\n".join(observed["excerpt"])
        self.assertNotIn(secret, rendered)
        self.assertNotIn(long_value, rendered)
        self.assertNotIn("bearer-value", rendered)
        self.assertIn("<redacted>", rendered)
        self.assertTrue(observed["truncated"])
        self.assertLessEqual(observed["bytes"], JOURNAL_MAX_BYTES)
        self.assertLessEqual(observed["line_count"], JOURNAL_MAX_LINES)
        self.assertTrue(all(len(line.encode("ascii")) <= JOURNAL_MAX_LINE_BYTES
                            for line in observed["excerpt"]))
        self.assertNotIn("\x00", rendered)
        payload = ("\n".join(observed["excerpt"]) + "\n").encode("ascii")
        self.assertEqual(len(payload), observed["bytes"])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), observed["sha256"])

        sensitive_keys = (
            ("API_TOKEN", "=", "x"),
            ("GH_TOKEN", "=", "gh"),
            ("client-secret", "=", "s"),
            ("client_secret", "=", "tiny"),
            ("client.secret", "=", "dot"),
            ("Authorization", ": ", "short"),
            ("--token", "=", "short"),
            ('"token"', ": ", '"short"'),
            ("X-API-Key", ": ", "short"),
            ("API_KEY", "=", "short"),
            ("OPENAI_API_KEY", "=", "short"),
            ("DB_KEY", "=", "short"),
            ("AWS_ACCESS_KEY_ID", "=", "short"),
            ("PRIVATE_KEY", "=", "short"),
            ("GITHUB_PAT", "=", "short"),
            ("AUTH", "=", "short"),
            ("AUTH_TOKEN", "=", "short"),
            ("Authentication", ": ", "short"),
            ("JWT", "=", "short"),
            ("JWT_SECRET", "=", "short"),
            ("PASSWD", "=", "short"),
            ("PASSPHRASE", "=", "short"),
            ("--password", " ", "short"),
        )
        self.assertEqual(PRODUCER_SENSITIVE.pattern,
                         VALIDATOR_SENSITIVE.pattern)
        for key, separator, value in sensitive_keys:
            with self.subTest(key=key):
                prefix = "b.service: "
                sanitized = bounded_journal_excerpt(
                    prefix + key + separator + value + "\n")
                self.assertEqual(
                    sanitized["excerpt"],
                    [prefix + key + separator + "<redacted>"],
                )
                report = self.transition_failure_report()
                report["journal"] = sanitized
                self.assertEqual(
                    validate_transition_failure_report(report, "a" * 64), report)

                changed = copy.deepcopy(report)
                unredacted = prefix + key + separator + value
                changed["journal"]["excerpt"] = [unredacted]
                changed["journal"]["line_count"] = 1
                raw_unredacted = (unredacted + "\n").encode("ascii")
                changed["journal"]["bytes"] = len(raw_unredacted)
                changed["journal"]["sha256"] = hashlib.sha256(
                    raw_unredacted).hexdigest()
                with self.assertRaisesRegex(ValueError, "excerpt is unsafe"):
                    validate_transition_failure_report(changed, "a" * 64)

    def test_transition_source_and_avc_are_correlated_and_field_allowlisted(self):
        invocation = "b" * 32
        cursor = "s=" + "1" * 64
        source_context = "system_u:system_r:init_t:s0"
        source_raw = json.dumps({
            "MESSAGE": source_context,
            "__CURSOR": cursor,
            "__MONOTONIC_TIMESTAMP": "1000",
            "_COMM": "cat",
            "_PID": "653",
            "_TRANSPORT": "stdout",
            "_SYSTEMD_UNIT": "b.service",
            "_SYSTEMD_INVOCATION_ID": invocation,
        }) + "\n"
        source = parse_source_capture(source_raw, invocation)
        self.assertEqual(source["source_context"], source_context)
        self.assertEqual(source["pid"], 653)
        self.assertEqual(source["command"], SOURCE_CAPTURE_COMMAND)
        service = self.transition_failure_report()["service"]
        no_match_runner = Mock(return_value=self.avc_command_result(
            exit_code=1, stdout=b""))
        no_match = bounded_avc_evidence(source, service, no_match_runner)
        self.assertEqual(no_match, {
            "command": AVC_JOURNAL_COMMAND,
            "command_observation": self.avc_command_observation(
                exit_code=1, stdout=b""),
            "query_result": "no-match",
            "raw_bytes": 0,
            "raw_sha256": hashlib.sha256(b"").hexdigest(),
            "line_count": 0,
            "truncated": False,
            "records": [],
        })
        no_match_runner.assert_called_once_with(
            AVC_JOURNAL_COMMAND, timeout=5, stdout_max=64 * 1024,
            stderr_max=0)
        message = (
            "audit: type=1400 audit(100.200:42): avc: denied { transition } for "
            "pid=654 comm=\"(sd-exec)\" "
            "path=\"/usr/libexec/symbi-atomic-update\" dev=\"vda3\" "
            "scontext=" + source_context + " "
            "tcontext=" + CONTROLLER_CONTEXT + " tclass=process permissive=0"
        )
        raw = json.dumps({
            "MESSAGE": message,
            "__CURSOR": "s=" + "2" * 64,
            "__MONOTONIC_TIMESTAMP": "1002",
            "_TRANSPORT": "kernel",
        }) + "\n"
        observed = parse_avc_evidence(raw, source, service)
        self.assertEqual(observed["command"], AVC_JOURNAL_COMMAND)
        self.assertEqual(observed["records"][0]["permissions"], ["transition"])
        self.assertEqual(observed["records"][0]["source_context"], source_context)
        self.assertEqual(observed["records"][0]["target_context"],
                         CONTROLLER_CONTEXT)
        retained = json.dumps(observed, sort_keys=True)
        self.assertNotIn("vda3", retained)
        self.assertNotIn("audit: type=1400", retained)
        self.assertEqual(set(observed["records"][0]), {
            "audit_serial", "audit_serial_source", "transport",
            "receipt_monotonic_usec", "pid", "comm", "path_field", "path",
            "source_context", "target_context", "class", "permissions",
            "permissive", "cursor_sha256",
        })
        runner = Mock(return_value=self.avc_command_result(
            exit_code=0, stdout=raw.encode()))
        bounded = bounded_avc_evidence(source, service, runner)
        runner.assert_called_once_with(
            AVC_JOURNAL_COMMAND, timeout=5, stdout_max=64 * 1024,
            stderr_max=0)
        self.assertEqual(bounded["command"], AVC_JOURNAL_COMMAND)
        self.assertEqual(
            bounded["command_observation"],
            self.avc_command_observation(exit_code=0, stdout=raw.encode()))
        self.assertNotIn(cursor, json.dumps(bounded, sort_keys=True))

        entrypoint = raw.replace(
            "scontext=" + source_context,
            "scontext=" + CONTROLLER_CONTEXT).replace(
                "tcontext=" + CONTROLLER_CONTEXT + " tclass=process",
                "tcontext=system_u:object_r:symbi_atomic_update_exec_t:s0 "
                "tclass=file")
        self.assertEqual(
            parse_avc_evidence(entrypoint, source, service)["records"][0]["class"],
            "file",
        )
        reordered = raw.replace('"1002"', '"999"')
        self.assertEqual(
            parse_avc_evidence(reordered, source, service)["records"][0]
            ["receipt_monotonic_usec"],
            999,
        )

        reordered_report = self.transition_failure_report()
        reordered_report["probe"]["receipt_monotonic_usec"] = 1002
        reordered_report["avc"]["records"][0]["receipt_monotonic_usec"] = 999
        self.assertEqual(
            validate_transition_failure_report(reordered_report, "a" * 64),
            reordered_report,
        )

        for changed in (
                raw.replace("permissive=0", "permissive=1"),
                raw.replace("pid=654", "pid=655"),
                raw.replace(source_context,
                            "system_u:system_r:another_service_t:s0"),
                raw.replace('"1002"', '"120001004"')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                parse_avc_evidence(changed, source, service)
        with self.assertRaisesRegex(ValueError, "empty or truncated"):
            parse_avc_evidence(raw * 33, source, service)
        with self.assertRaisesRegex(ValueError, "duplicated"):
            parse_avc_evidence(raw * 2, source, service)
        for malformed in ("\n", "{}\n", b""):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                parse_avc_evidence(malformed, source, service)
        for field in ("source_context", "requested_context"):
            for invalid in (None, 7, [], {}):
                changed = copy.deepcopy(source)
                changed[field] = invalid
                with self.subTest(field=field, invalid=invalid), \
                        self.assertRaises(ValueError):
                    parse_avc_evidence("", changed, service)
        ambiguous = source_raw.replace(
            '"MESSAGE":', '"MESSAGE":"duplicate","MESSAGE":', 1)
        with self.assertRaises(ValueError):
            parse_source_capture(ambiguous, invocation)

    def test_audit_transport_binds_trusted_structured_serial_to_exact_record(self):
        source_context = "system_u:system_r:init_t:s0"
        source = {
            "source_context": source_context,
            "requested_context": CONTROLLER_CONTEXT,
        }
        service = self.transition_failure_report()["service"]
        kernel_record = json.loads(self.avc_journal_raw())
        audit_record = copy.deepcopy(kernel_record)
        audit_record["MESSAGE"] = re.sub(
            r"^.*audit\([0-9]+\.[0-9]+:[0-9]+\):[ ]+", "AVC ",
            audit_record["MESSAGE"], count=1)
        audit_record["_TRANSPORT"] = "audit"
        audit_record["_AUDIT_ID"] = "42"
        self.assertIn("_AUDIT_ID", AVC_JOURNAL_COMMAND[5])
        raw = json.dumps(audit_record) + "\n"
        parsed = parse_avc_evidence(raw, source, service)
        self.assertEqual(parsed["records"][0]["audit_serial"], 42)
        self.assertEqual(
            parsed["records"][0]["audit_serial_source"], "journal-audit-id")
        self.assertEqual(parsed["records"][0]["transport"], "audit")

        second = copy.deepcopy(audit_record)
        second["_AUDIT_ID"] = "43"
        second["__CURSOR"] = "s=" + "3" * 64
        paired = parse_avc_evidence(
            raw + json.dumps(second) + "\n", source, service)
        self.assertEqual(
            [(record["audit_serial"], record["audit_serial_source"])
             for record in paired["records"]],
            [(42, "journal-audit-id"), (43, "journal-audit-id")],
        )
        duplicate = copy.deepcopy(second)
        duplicate["_AUDIT_ID"] = "42"
        with self.assertRaisesRegex(ValueError, "duplicated"):
            parse_avc_evidence(
                raw + json.dumps(duplicate) + "\n", source, service)

        invalid_ids = (
            None, True, 42, [], {}, "", "0", "00", "-1", "+1", "1.0",
            "9223372036854775808", "18446744073709551615",
        )
        for invalid in invalid_ids:
            changed = copy.deepcopy(audit_record)
            changed["_AUDIT_ID"] = invalid
            with self.subTest(invalid=invalid), \
                    self.assertRaises(AvcParserPredicateError) as caught:
                parse_avc_evidence(json.dumps(changed) + "\n", source, service)
            self.assertEqual(caught.exception.predicates,
                             self.avc_parser_predicates(
                                 transport="audit",
                                 serial_source="journal-audit-id",
                                 denial_pattern_matched=True,
                                 authenticated_serial_matched=False))
        missing = copy.deepcopy(audit_record)
        del missing["_AUDIT_ID"]
        with self.assertRaises(AvcParserPredicateError) as caught:
            parse_avc_evidence(json.dumps(missing) + "\n", source, service)
        self.assertEqual(caught.exception.predicates,
                         self.avc_parser_predicates(
                             transport="audit",
                             serial_source="journal-audit-id",
                             denial_pattern_matched=True,
                             authenticated_serial_matched=False))
        malformed_denial = copy.deepcopy(audit_record)
        malformed_denial["MESSAGE"] = malformed_denial["MESSAGE"].replace(
            "avc: denied", "avc: rejected")
        with self.assertRaises(AvcParserPredicateError) as caught:
            parse_avc_evidence(
                json.dumps(malformed_denial) + "\n", source, service)
        self.assertEqual(caught.exception.predicates,
                         self.avc_parser_predicates(
                             transport="audit",
                             serial_source="journal-audit-id"))

        ambiguous_audit = copy.deepcopy(audit_record)
        ambiguous_audit["MESSAGE"] = (
            "audit(100.200:42): " + ambiguous_audit["MESSAGE"])
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            parse_avc_evidence(
                json.dumps(ambiguous_audit) + "\n", source, service)
        ambiguous_kernel = copy.deepcopy(kernel_record)
        ambiguous_kernel["_AUDIT_ID"] = "42"
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            parse_avc_evidence(
                json.dumps(ambiguous_kernel) + "\n", source, service)

        missing_message_serial = copy.deepcopy(kernel_record)
        missing_message_serial["MESSAGE"] = missing_message_serial["MESSAGE"].replace(
            "audit(100.200:42):", "audit:")
        with self.assertRaises(AvcParserPredicateError) as caught:
            parse_avc_evidence(
                json.dumps(missing_message_serial) + "\n", source, service)
        self.assertEqual(caught.exception.predicates,
                         self.avc_parser_predicates(
                             denial_pattern_matched=True,
                             authenticated_serial_matched=False))

        report = self.transition_failure_report()
        report["avc"]["records"][0] = parsed["records"][0]
        report["avc"]["raw_bytes"] = len(raw.encode())
        report["avc"]["raw_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
        report["avc"]["command_observation"] = self.avc_command_observation(
            exit_code=0, stdout=raw.encode())
        self.assertEqual(
            validate_transition_failure_report(report, "a" * 64), report)
        for transport, serial_source in (
                ("audit", "message-audit-header"),
                ("kernel", "journal-audit-id")):
            changed = copy.deepcopy(report)
            changed["avc"]["records"][0]["transport"] = transport
            changed["avc"]["records"][0]["audit_serial_source"] = serial_source
            with self.subTest(transport=transport, source=serial_source), \
                    self.assertRaises(ValueError):
                validate_transition_failure_report(changed, "a" * 64)

    def test_transition_diagnostic_command_hard_caps_pipes(self):
        self.assertEqual(
            fixed_failure_command(["/usr/bin/printf", "bounded"],
                                  timeout=2, stdout_max=16),
            "bounded",
        )
        with self.assertRaisesRegex(ValueError, "exceeded its bound"):
            fixed_failure_command(
                ["/usr/bin/python3", "-c", "import sys;sys.stdout.write('x'*8192)"],
                timeout=2, stdout_max=4096,
            )
        with self.assertRaisesRegex(ValueError, "exceeded its bound"):
            fixed_failure_command(
                ["/usr/bin/python3", "-c", "import sys;sys.stderr.write('x'*16384)"],
                timeout=2, stdout_max=4096,
            )
        with self.assertRaisesRegex(ValueError, "exceeded its bound"):
            fixed_failure_command(
                ["/usr/bin/python3", "-c", "import sys;sys.stderr.write('x')"],
                timeout=2, stdout_max=4096, stderr_max=0,
            )
        with self.assertRaises(subprocess.CalledProcessError):
            fixed_failure_command(
                ["/usr/bin/python3", "-c", "raise SystemExit(1)"],
                timeout=2, stdout_max=4096, stderr_max=0,
            )

    def test_journal_boundary_never_retains_a_partial_secret(self):
        secret = "A" * 64
        raw = (("x!" * 177 + "\n") * 23) + secret + "\n"
        observed = bounded_journal_excerpt(raw)
        rendered = "\n".join(observed["excerpt"])
        self.assertTrue(observed["truncated"])
        self.assertNotIn("A" * 8, rendered)
        report = self.transition_failure_report()
        report["journal"] = observed
        self.assertEqual(validate_transition_failure_report(report, "a" * 64), report)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            controller = self.transition_failure_controller(report)
            (output / "result.json").write_text(json.dumps(controller) + "\n")
            (output / "same-path-positive.json").write_text(json.dumps(report) + "\n")
            retain_controller_output(output, evidence)
            retained = b"".join(path.read_bytes() for path in evidence.iterdir())
            self.assertNotIn(b"A" * 8, retained)

    def test_each_bootc_rejection_uses_a_distinct_disposable_overlay(self):
        commands = {case: negative_qemu_command(case) for case in (
            "unsigned", "wrong-key", "wrong-reference", "altered-signature")}
        for case, command in commands.items():
            joined = " ".join(command)
            self.assertIn(
                f"file=/output/negative-{case}.qcow2,format=qcow2,"
                "if=none,id=symbi-boot-disk", joined)
            self.assertIn(f"path=/output/negative-{case}.json", joined)
            self.assertIn(f"file=/inputs/expected-{case}.json", joined)
            self.assertIn(
                "file=/inputs/update.raw,format=raw,if=none,id=symbi-update-source,readonly=on",
                joined)
            self.assertIn(
                "virtio-blk-pci,drive=symbi-update-source,serial=SYMBIUPDATE", joined)
            self.assertNotIn("file=/output/guest.qcow2", joined)
            self.assertNotIn("org.symbi.update.diagnostic", joined)
        self.assertEqual(len({tuple(command) for command in commands.values()}), 4)
        positive = " ".join(positive_qemu_command())
        self.assertIn(
            "file=/output/same-path-positive.qcow2,format=qcow2,"
            "if=none,id=symbi-boot-disk", positive)
        self.assertIn("path=/output/same-path-positive.json", positive)
        self.assertIn(
            "file,id=collector,path=/output/same-path-positive-collector.jsonl",
            positive)
        self.assertIn(
            "virtserialport,chardev=collector,name=org.symbi.update.diagnostic",
            positive)
        self.assertIn("file=/inputs/expected-positive.json", positive)
        self.assertNotIn("file=/output/guest.qcow2", positive)
        self.assertNotIn("file=/output/negative-", positive)
        with self.assertRaises(ValueError):
            negative_qemu_command("caller-selected")

    def test_all_update_vms_boot_only_the_explicit_overlay(self):
        commands = [
            positive_qemu_command(),
            *(negative_qemu_command(case) for case in (
                "unsigned", "wrong-key", "wrong-reference", "altered-signature")),
            *(qemu_command(index) for index in range(3)),
        ]
        self.assertIn("org.symbi.update.diagnostic", " ".join(commands[0]))
        for command in commands[1:]:
            self.assertNotIn("org.symbi.update.diagnostic", " ".join(command))
        for command in commands:
            with self.subTest(report=command[command.index("-chardev") + 1]):
                drives = [command[index + 1] for index, value in enumerate(command)
                          if value == "-drive"]
                devices = [command[index + 1] for index, value in enumerate(command)
                           if value == "-device"]
                self.assertEqual(len(drives), 2)
                self.assertEqual(len(set(drives)), 2)
                self.assertTrue(any(
                    value.endswith("if=none,id=symbi-boot-disk") for value in drives))
                self.assertIn(
                    "file=/inputs/update.raw,format=raw,if=none,"
                    "id=symbi-update-source,readonly=on", drives)
                self.assertEqual(
                    [value for value in devices if "bootindex=" in value],
                    ["virtio-blk-pci,drive=symbi-boot-disk,bootindex=1"])
                self.assertIn(
                    "virtio-blk-pci,drive=symbi-update-source,serial=SYMBIUPDATE",
                    devices)
                self.assertEqual(command.count("-boot"), 1)
                self.assertEqual(command[command.index("-boot") + 1], "strict=on")
                self.assertFalse(any("if=virtio" in value for value in command))

    def test_guest_status_requires_exact_signed_slots_and_rollback_queue(self):
        phase_status(self.status(self.old), self.old)
        phase_status(self.status(self.old, staged=self.new), self.old, staged=self.new)
        phase_status(self.status(self.new, rollback=self.old, queued=True), self.new,
                     rollback=self.old, rollback_queued=True)
        cases = [
            self.status(self.new),
            self.status(self.old, staged=self.old),
            self.status(self.new, rollback=self.old, queued=False),
            self.status(self.old),
        ]
        cases[-1]["status"]["booted"]["image"]["image"]["signature"] = "insecure"
        expected = [(self.old, {}), (self.old, {"staged": self.new}),
                    (self.new, {"rollback": self.old, "rollback_queued": True}),
                    (self.old, {})]
        for status, (booted, options) in zip(cases, expected):
            with self.assertRaises(ValueError):
                phase_status(status, booted, **options)

    def test_negative_switch_snapshot_binds_default_and_all_deployments(self):
        original = self.status(self.old)
        snapshot = deployment_snapshot(original, self.old)
        self.assertEqual(snapshot["default"], original["spec"]["image"])
        self.assertEqual(snapshot["booted"], original["status"]["booted"])
        changes = []
        changed = copy.deepcopy(original)
        changed["spec"]["image"]["image"] = "changed"
        changes.append((changed, True))
        changed = copy.deepcopy(original)
        changed["status"]["booted"]["ostree"] = {"checksum": "0" * 64}
        changes.append((changed, False))
        changed = copy.deepcopy(original)
        changed["status"]["staged"] = self.entry(self.new, "dir")
        changes.append((changed, True))
        for changed, rejected in changes:
            with self.subTest(changed=changed):
                if rejected:
                    with self.assertRaises(ValueError):
                        deployment_snapshot(changed, self.old)
                else:
                    self.assertNotEqual(deployment_snapshot(changed, self.old), snapshot)
        staged = staged_deployment_snapshot(
            self.status(self.old, staged=self.new, default=self.new,
                        default_transport="dir"), self.old, self.new)
        self.assertEqual(staged["default"], staged["staged"]["image"]["image"])
        self.assertEqual(staged["booted"], snapshot["booted"])
        invalid = self.status(self.old, staged=self.new, default=self.new)
        with self.assertRaises(ValueError):
            staged_deployment_snapshot(invalid, self.old, self.new)

    @staticmethod
    def controller_identity():
        return {
            "schema": 1,
            "policy": "symbi_atomic_update",
            "entrypoint": "/usr/libexec/symbi-atomic-update",
            "entrypoint_sha256": "1" * 64,
            "entrypoint_selinux_label":
                "system_u:object_r:symbi_atomic_update_exec_t:s0",
            "bridge": "/usr/libexec/symbi-bootc-transition",
            "bridge_sha256": "7" * 64,
            "bridge_selinux_label":
                "system_u:object_r:symbi_bootc_transition_exec_t:s0",
            "controller": "/usr/libexec/symbi-atomic-update-controller.py",
            "controller_sha256": "6" * 64,
            "manifest":
                "/usr/share/symbi-os/selinux/symbi-atomic-update.json",
            "manifest_sha256": "2" * 64,
            "controller_context":
                "system_u:system_r:symbi_atomic_update_t:s0",
            "install_context": "system_u:system_r:install_t:s0",
            "policy_sources": {
                "te_sha256": "3" * 64,
                "fc_sha256": "4" * 64,
                "launcher_sha256": "5" * 64,
                "bridge_sha256": "8" * 64,
            },
            "expanded_policy": {
                "schema": 2, "policy": "symbi_atomic_update",
                "install_transition_inventory": {
                    "schema": 1,
                    "source": "symbi_atomic_update_t",
                    "class": "process",
                    "destination": "install_t",
                    "rules": [
                        "type_transition symbi_atomic_update_t "
                        "symbi_bootc_transition_exec_t:process install_t;",
                    ],
                },
                "required": {
                    "init_entrypoint": True, "init_transition": True,
                    "bridge_entrypoint": True,
                    "bridge_transition": True,
                    "bridge_type_transition": True,
                    "install_sigchld": True,
                },
                "forbidden": {
                    "shared_install_type_transition": False,
                    "generic_install_transition": False,
                    "controller_forbidden_process_permissions": False,
                    "controller_policy_load": False,
                    "controller_enforcing_change": False,
                },
            },
        }

    def test_controller_identity_schema_matches_both_host_validators(self):
        identity = self.controller_identity()
        self.assertEqual(validate_controller_identity(identity), identity)
        self.assertEqual(validate_boot_controller_identity(identity), identity)
        for name, mutate in (
                ("bridge", lambda item: item.pop("bridge")),
                ("bridge-hash", lambda item: item.__setitem__(
                    "bridge_sha256", "0" * 63)),
                ("bridge-label", lambda item: item.__setitem__(
                    "bridge_selinux_label", "system_u:object_r:bin_t:s0")),
                ("bridge-source", lambda item: item["policy_sources"].pop(
                    "bridge_sha256")),
                ("transition-missing", lambda item: item["expanded_policy"].pop(
                    "install_transition_inventory")),
                ("transition-schema-bool", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"].__setitem__("schema", True)),
                ("transition-extra-field", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"].__setitem__("extra", False)),
                ("transition-other-exec", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"]["rules"].append(
                        "type_transition symbi_atomic_update_t "
                        "other_exec_t:process install_t;")),
                ("transition-shared-exec", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"]["rules"].append(
                        "type_transition symbi_atomic_update_t "
                        "install_exec_t:process install_t;"))):
            changed = copy.deepcopy(identity)
            mutate(changed)
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    validate_controller_identity(changed)
                with self.assertRaises(ValueError):
                    validate_boot_controller_identity(changed)

    @classmethod
    def transition_report(cls):
        return {
            "unit": "b.service",
            "service": {"Result": "success", "ExecMainCode": "1",
                        "ExecMainStatus": "0", "ActiveState": "active",
                        "SubState": "exited"},
            "controller": cls.controller_identity(),
            "controller_probe_command": [
                "/usr/libexec/symbi-atomic-update", "--probe"],
            "bootc_probe_command": ["/usr/bin/bootc", "--version"],
            "install_context": "system_u:system_r:install_t:s0",
            "scope": ("Dedicated-domain transition availability only; "
                      "no update qualification"),
            "bootc": {
                "source": "/usr/bin/bootc",
                "label_reference": "/usr/bin/ostree",
                "source_sha256": "8" * 64,
                "label_reference_sha256": "9" * 64,
                "selinux_label": "system_u:object_r:install_exec_t:s0",
                "mode": "0755",
            },
        }

    @staticmethod
    def status_evidence(count):
        service = {"Result": "success", "ExecMainCode": "1",
                   "ExecMainStatus": "0", "ActiveState": "active",
                   "SubState": "exited"}
        observations = [
            {"sequence": sequence, "unit": "s.service", "service": service,
             "bytes": 1024, "sha256": f"{sequence}" * 64}
            for sequence in range(1, count + 1)
        ]
        commands = [{
            "command": ["/usr/bin/systemctl", "show", "b.service",
                        "--property=Result,ExecMainCode,ExecMainStatus,ActiveState,SubState"],
            "exit_code": 0,
        }]
        for _sequence in range(count):
            commands.extend([
                {"command": ["/usr/bin/systemctl", "restart", "s.service"],
                 "exit_code": 0},
                {"command": ["/usr/bin/systemctl", "show", "s.service",
                             "--property=Result,ExecMainCode,ExecMainStatus,ActiveState,SubState"],
                 "exit_code": 0},
            ])
        return observations, commands

    def operation_report(self, name, exit_code=0, stderr=""):
        arguments = {
            "negative": ["switch", "--transport", "dir",
                         "--enforce-container-sigpolicy", NEGATIVE_UPDATE_SOURCE],
            "positive": ["switch", "--transport", "dir",
                         "--enforce-container-sigpolicy", "/run/symbi-update/source"],
            "rollback": ["rollback"],
        }[name]
        command = ["/usr/bin/bootc", *arguments]
        digest = self.old if name == "rollback" else self.new
        return {
            "name": name, "command": command, "exit_code": exit_code,
            "child_context": {
                "pid": 1234, "pidfd_opened": True,
                "selinux_context": "system_u:system_r:install_t:s0",
            },
            "transition_receipt": {
                "schema": 1,
                "bridge": "/usr/libexec/symbi-bootc-transition",
                "operation": name,
                "digest": digest,
                "selinux_context": "system_u:system_r:install_t:s0",
                "close_on_exec": True,
            },
            "stderr": stderr,
            "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
        }

    def positive_report(self):
        observations, commands = self.status_evidence(2)
        operation = self.operation_report("negative")
        commands.insert(3, {"command": operation["command"], "exit_code": 0,
                            "child_context": operation["child_context"],
                            "transition_receipt": operation["transition_receipt"],
                            "stderr": operation["stderr"]})
        return {
            "schema": 1, "passed": True, "guest_booted": True,
            "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
            "nonce": "4" * 32, "expected_sha256": "5" * 64,
            "runner_sha256": "6" * 64, "source_mounted_readonly": True,
            "source_device": {"path": "/dev/vdb", "serial": "SYMBIUPDATE",
                              "TYPE": "ext4",
                              "LABEL": "SYMBIUPDATE", "UUID": self.source_uuid},
            "status_observations": observations,
            "bootc_transition": self.transition_report(),
            "bootc_operation": operation,
            "same_path_positive_control": {
                "case": POSITIVE_OVERLAY_CASE, "switch_accepted": True,
                "switch_exit_code": 0, "booted_unchanged": True,
                "deployment_staged": True, "default_changed": True,
                "staged_digest": self.new, "state_before_sha256": "3" * 64,
                "state_after_sha256": "7" * 64,
                "source": NEGATIVE_UPDATE_SOURCE, "source_readonly": True,
            },
            "commands": commands,
        }

    def test_same_path_positive_report_binds_success_and_controlled_state(self):
        expected = {"nonce": "4" * 32, "new_digest": self.new,
                    "controller": self.controller_identity(),
                    "source_disk": {"filesystem": "ext4", "label": "SYMBIUPDATE",
                                    "serial": "SYMBIUPDATE",
                                    "uuid": self.source_uuid}}
        report = self.positive_report()
        validate_positive_report(report, expected, "5" * 64, "6" * 64)
        validate_shared_baseline(report, self.negative_report())
        mutations = []
        changed = copy.deepcopy(report)
        changed["commands"][3]["exit_code"] = 1
        changed["bootc_operation"]["exit_code"] = 1
        changed["same_path_positive_control"]["switch_exit_code"] = 1
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["same_path_positive_control"]["state_after_sha256"] = "3" * 64
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["same_path_positive_control"]["source"] = "/tmp/other"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["source_device"]["UUID"] = "9" * 32
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_positive_report(changed, expected, "5" * 64, "6" * 64)
        negative = self.negative_report()
        negative["negative_control"]["state_sha256"] = "9" * 64
        with self.assertRaises(ValueError):
            validate_shared_baseline(report, negative)

    def test_controller_rejects_transition_input_and_command_substitution(self):
        expected = {"nonce": "4" * 32, "new_digest": self.new,
                    "controller": self.controller_identity(),
                    "source_disk": {"filesystem": "ext4", "label": "SYMBIUPDATE",
                                    "serial": "SYMBIUPDATE",
                                    "uuid": self.source_uuid}}
        report = self.positive_report()
        mutations = []
        for field, value in (
                ("install_context",
                 "system_u:system_r:unconfined_service_t:s0"),
                ("controller_probe_command", ["/usr/bin/bootc", "--version"]),
                ("bootc_probe_command", ["/usr/bin/bootc", "status"]),
                ("scope", "Update qualified")):
            changed = copy.deepcopy(report)
            changed["bootc_transition"][field] = value
            mutations.append(changed)
        for field, value in (
                ("source", "/tmp/bootc"),
                ("source_sha256", "0" * 63),
                ("label_reference", "/tmp/ostree"),
                ("label_reference_sha256", "0" * 63),
                ("selinux_label", "system_u:object_r:bin_t:s0"),
                ("mode", "0700")):
            changed = copy.deepcopy(report)
            changed["bootc_transition"]["bootc"][field] = value
            mutations.append(changed)
        changed = copy.deepcopy(report)
        del changed["bootc_transition"]["bootc"]["selinux_label"]
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["bootc_transition"]["controller"]["entrypoint_sha256"] = "0" * 64
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["bootc_operation"]["child_context"]["selinux_context"] = (
            "system_u:system_r:unconfined_service_t:s0")
        changed["commands"][3]["child_context"] = copy.deepcopy(
            changed["bootc_operation"]["child_context"])
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["bootc_operation"]["transition_receipt"]["digest"] = self.old
        changed["commands"][3]["transition_receipt"] = copy.deepcopy(
            changed["bootc_operation"]["transition_receipt"])
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["bootc_operation"]["command"][0] = "/tmp/bootc"
        changed["commands"][3]["command"][0] = "/tmp/bootc"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["commands"].append({
            "command": ["/usr/bin/bootc", "rollback"], "exit_code": 0,
        })
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_positive_report(changed, expected, "5" * 64, "6" * 64)

    def negative_report(self, case="unsigned"):
        state_hash = "3" * 64
        observations, commands = self.status_evidence(2)
        operation = self.operation_report(
            "negative", exit_code=1, stderr="signature verification failed\n")
        commands.insert(3, {"command": operation["command"], "exit_code": 1,
                            "child_context": operation["child_context"],
                            "transition_receipt": operation["transition_receipt"],
                            "stderr": operation["stderr"]})
        return {
            "schema": 1, "passed": True, "guest_booted": True,
            "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
            "nonce": "4" * 32, "expected_sha256": "5" * 64,
            "runner_sha256": "6" * 64, "source_mounted_readonly": True,
            "source_device": {"path": "/dev/vdb", "serial": "SYMBIUPDATE",
                              "TYPE": "ext4",
                              "LABEL": "SYMBIUPDATE", "UUID": self.source_uuid},
            "status_observations": observations,
            "bootc_transition": self.transition_report(),
            "bootc_operation": operation,
            "negative_control": {
                "case": case, "switch_rejected": True, "switch_exit_code": 1,
                "deployment_unchanged": True, "default_unchanged": True,
                "state_sha256": state_hash, "source": NEGATIVE_UPDATE_SOURCE,
                "source_readonly": True,
            },
            "commands": commands,
        }

    def test_negative_report_requires_failed_real_switch_and_unchanged_state(self):
        report = self.negative_report()
        expected = {"nonce": "4" * 32, "new_digest": self.new,
                    "controller": self.controller_identity(),
                    "source_disk": {"filesystem": "ext4", "label": "SYMBIUPDATE",
                                    "serial": "SYMBIUPDATE",
                                    "uuid": self.source_uuid}}
        validate_negative_report(report, expected, "5" * 64, "6" * 64, "unsigned")
        mutations = []
        changed = copy.deepcopy(report)
        changed["commands"][3]["exit_code"] = 0
        changed["bootc_operation"]["exit_code"] = 0
        changed["negative_control"]["switch_exit_code"] = 0
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["negative_control"]["deployment_unchanged"] = False
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["commands"][3]["command"][-1] = "/tmp/other"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["source_device"]["LABEL"] = "OTHER"
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_negative_report(changed, expected, "5" * 64,
                                         "6" * 64, "unsigned")

    def test_phase_report_binds_the_exact_source_device(self):
        expected = {"nonce": "4" * 32, "old_digest": self.old,
                    "new_digest": self.new,
                    "controller": self.controller_identity(),
                    "source_disk": {"filesystem": "ext4", "label": "SYMBIUPDATE",
                                    "serial": "SYMBIUPDATE",
                                    "uuid": self.source_uuid}}
        phase = {"name": "installed", "booted_digest": self.old,
                 "operation": "signed-update-staged", "staged_digest": self.new}
        observations, commands = self.status_evidence(2)
        operation = self.operation_report("positive")
        commands.insert(3, {"command": operation["command"], "exit_code": 0,
                            "child_context": operation["child_context"],
                            "transition_receipt": operation["transition_receipt"],
                            "stderr": operation["stderr"]})
        report = {
            "schema": 1, "passed": True, "guest_booted": True,
            "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
            "nonce": "4" * 32, "expected_sha256": "5" * 64,
            "runner_sha256": "6" * 64, "source_mounted_readonly": True,
            "source_device": {"path": "/dev/vdb", "serial": "SYMBIUPDATE",
                              "TYPE": "ext4",
                              "LABEL": "SYMBIUPDATE", "UUID": self.source_uuid},
            "phase": phase,
            "status_observations": observations,
            "bootc_transition": self.transition_report(),
            "bootc_operation": operation,
            "commands": commands,
        }
        validate_phase_report(report, expected, "5" * 64, "6" * 64, phase)
        for field in ("path", "serial", "TYPE", "LABEL", "UUID"):
            changed = copy.deepcopy(report)
            changed["source_device"].pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_phase_report(changed, expected, "5" * 64, "6" * 64, phase)
        changed = copy.deepcopy(report)
        changed["source_device"]["serial"] = "OTHER"
        with self.assertRaises(ValueError):
            validate_phase_report(changed, expected, "5" * 64, "6" * 64, phase)
        changed_expected = copy.deepcopy(expected)
        changed_expected["source_disk"]["serial"] = "OTHER"
        with self.assertRaises(ValueError):
            validate_phase_report(report, changed_expected, "5" * 64,
                                  "6" * 64, phase)

    def test_update_service_and_mount_are_bounded_and_offline(self):
        root = Path(__file__).resolve().parents[2]
        settings = dict(line.split("=", 1) for line in
                        (root / "image/atomic/update-o.service").read_text().splitlines()
                        if "=" in line and not line.startswith("#"))
        self.assertNotIn("RequiresMountsFor", settings)
        self.assertEqual(settings["Requires"], "b.service")
        self.assertNotIn("Wants", settings)
        self.assertEqual(settings["After"], "local-fs.target b.service")
        self.assertNotIn("s.service", settings.get("Requires", ""))
        self.assertNotIn("s.service", settings.get("After", ""))
        self.assertNotIn("OnFailure", settings)

        status_settings = dict(line.split("=", 1) for line in
                               (root / "image/atomic/s.service").read_text().splitlines()
                               if "=" in line and not line.startswith("#"))
        self.assertNotIn("o.service", status_settings.get("Before", ""))
        self.assertNotIn("o.service", status_settings.get("After", ""))
        self.assertEqual(settings["RuntimeDirectory"], "symbi-update")
        self.assertEqual(settings["RuntimeDirectoryMode"], "0700")
        self.assertEqual(settings["StateDirectory"], "symbi-update-test")
        self.assertEqual(settings["PrivateMounts"], "yes")
        self.assertEqual(settings["MemorySwapMax"], "0")
        self.assertEqual(settings["TasksMax"], "128")
        self.assertFalse((root / "image/atomic/update-fstab.extra").exists())
        self.assertNotIn("udev", (root / "image/atomic/update-o.service").read_text())

        transition = dict(line.split("=", 1) for line in
                          (root / "image/atomic/update-b.service").read_text().splitlines()
                          if "=" in line and not line.startswith("#"))
        self.assertEqual(transition["User"], "root")
        self.assertEqual(transition["Group"], "root")
        self.assertEqual(transition["CapabilityBoundingSet"], "")
        self.assertEqual(transition["MemorySwapMax"], "0")
        self.assertEqual(transition["TasksMax"], "16")
        self.assertEqual(transition["OnFailure"], "f.service")
        self.assertEqual(transition["PrivateTmp"], "yes")
        self.assertEqual(transition["ProtectSystem"], "strict")
        self.assertEqual(transition["ProtectKernelTunables"], "yes")
        self.assertEqual(transition["ProtectKernelModules"], "yes")
        self.assertEqual(transition["ProtectKernelLogs"], "yes")
        self.assertEqual(transition["ProtectControlGroups"], "yes")
        self.assertEqual(
            transition["ExecStart"],
            "/usr/libexec/symbi-atomic-update --probe")
        self.assertEqual(transition["ExecStartPre"],
                         "/usr/bin/cat /proc/self/attr/current")
        text = (root / "image/atomic/update-b.service").read_text()
        self.assertNotIn("SELinuxContext=", text)
        self.assertNotIn("ExecStopPost=", text)
        self.assertNotIn("NoNewPrivileges=", text)
        self.assertNotIn("/usr/bin/install", text)
        self.assertNotIn("/usr/bin/chcon", text)
        self.assertNotIn("/usr/bin/mv", text)
        self.assertNotIn("/usr/bin/rm", text)
        self.assertNotIn("/run/symbi-update-bootc", text)
        self.assertNotIn("PrivateMounts=", text)
        self.assertNotIn("/bin/sh", text)
        self.assertNotIn("/usr/bin/python3", text)
        self.assertNotIn("ImportCredential=", text)
        self.assertNotIn("ExecStartPre=+", text)
        conditions = [line for line in text.splitlines()
                      if line.startswith("ConditionPathExists=")]
        self.assertEqual(conditions, ["ConditionPathExists=!/etc/initrd-release"])

        failure = dict(line.split("=", 1) for line in
                       (root / "image/atomic/update-f.service").read_text().splitlines()
                       if "=" in line and not line.startswith("#"))
        self.assertEqual(failure["After"], "b.service")
        self.assertEqual(failure["OnFailure"], "poweroff.target")
        self.assertEqual(failure["ImportCredential"], "symbi-update-failure.py")
        self.assertEqual(failure["ExecStartPre"],
                         "/usr/bin/systemctl --quiet is-failed b.service")
        self.assertNotIn("ExecCondition", failure)
        self.assertEqual(failure["ExecStart"],
                         "/usr/bin/python3 %d/symbi-update-failure.py")
        self.assertEqual(failure["ExecStopPost"],
                         "/usr/bin/systemctl --no-block poweroff")
        self.assertEqual([
            line for line in
            (root / "image/atomic/update-f.service").read_text().splitlines()
            if line.startswith("ExecStopPost=")
        ], [
            "ExecStopPost=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=f-stop",
            "ExecStopPost=-/usr/bin/python3 %d/symbi-update-failure.py --stop-post",
            "ExecStopPost=/usr/bin/systemctl --no-block poweroff",
        ])
        self.assertEqual(failure["NoNewPrivileges"], "yes")
        self.assertEqual(failure["CapabilityBoundingSet"], "")
        self.assertEqual(failure["PrivateMounts"], "yes")
        self.assertEqual(failure["MemorySwapMax"], "0")
        self.assertEqual(failure["TasksMax"], "16")
        self.assertEqual(failure["TimeoutStartSec"], "30")
        self.assertNotIn("SELinuxContext", failure)
        failure_text = (root / "image/atomic/update-f.service").read_text()
        self.assertNotIn("[Install]", failure_text)
        self.assertNotIn("f.service", (root / "image/atomic/contract.py").read_text())

        skipped = ("Result=success\nExecMainCode=0\nExecMainStatus=0\n"
                   "ActiveState=inactive\nSubState=dead\n")
        with self.assertRaisesRegex(ValueError, "transition probe did not complete"):
            fixed_bootc_transition(
                Mock(return_value=skipped), self.controller_identity())

    def test_update_service_lifecycle_markers_are_best_effort_and_ordered(self):
        root = Path(__file__).resolve().parents[2]
        expected = {
            "update-b.service": [
                "ExecStartPre=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=b-enter",
                "ExecStartPost=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=b-success",
            ],
            "update-f.service": [
                "ExecStartPre=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=f-enter",
                "ExecStartPost=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=f-success",
                "ExecStopPost=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=f-stop",
            ],
            "update-o.service": [
                "ExecStartPre=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=o-enter",
                "ExecStartPost=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=o-success",
                "ExecStopPost=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=o-stop",
            ],
        }
        for name, markers in expected.items():
            with self.subTest(name=name):
                lines = (root / "image/atomic" / name).read_text().splitlines()
                positions = [lines.index(marker) for marker in markers]
                self.assertEqual(positions, sorted(positions))
                self.assertTrue(all(lines.count(marker) == 1 for marker in markers))
                self.assertTrue(all(marker.startswith(("ExecStartPre=-", "ExecStartPost=-",
                                                       "ExecStopPost=-"))
                                    for marker in markers))
                self.assertTrue(all("/bin/sh" not in marker and "%" not in marker
                                    for marker in markers))
        transition_lines = (root / "image/atomic/update-b.service").read_text().splitlines()
        self.assertLess(
            transition_lines.index(
                "ExecStartPre=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=b-enter"),
            transition_lines.index("ExecStartPre=/usr/bin/cat /proc/self/attr/current"))
        self.assertLess(
            transition_lines.index(
                "ExecStart=/usr/libexec/symbi-atomic-update --probe"),
            transition_lines.index(
                "ExecStartPost=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=b-success"))
        failure_lines = (root / "image/atomic/update-f.service").read_text().splitlines()
        self.assertLess(
            failure_lines.index("ExecStartPre=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=f-enter"),
            failure_lines.index(
                "ExecStartPre=/usr/bin/systemctl --quiet is-failed b.service"))
        self.assertLess(
            failure_lines.index("ExecStart=/usr/bin/python3 %d/symbi-update-failure.py"),
            failure_lines.index(
                "ExecStartPost=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=f-success"))
        self.assertLess(
            failure_lines.index("ExecStopPost=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=f-stop"),
            failure_lines.index(
                "ExecStopPost=-/usr/bin/python3 %d/symbi-update-failure.py --stop-post"))
        success_lines = (root / "image/atomic/update-o.service").read_text().splitlines()
        self.assertLess(
            success_lines.index("ExecStartPre=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=o-enter"),
            success_lines.index(
                "ExecStart=/usr/libexec/symbi-atomic-update --advance "
                "%d/symbi-update-expected.json %d/symbi-update-policy.json"))
        self.assertLess(
            success_lines.index(
                "ExecStart=/usr/libexec/symbi-atomic-update --advance "
                "%d/symbi-update-expected.json %d/symbi-update-policy.json"),
            success_lines.index(
                "ExecStartPost=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=o-success"))
        self.assertLess(
            success_lines.index("ExecStopPost=-/usr/bin/echo SYMBI_UPDATE_LIFECYCLE=o-stop"),
            success_lines.index("ExecStopPost=/usr/bin/systemctl --no-block poweroff"))

    def test_lifecycle_observation_normalizes_only_fixed_marker_sequences(self):
        failure_raw = b"".join((
            b"private API_TOKEN=not-retained\n",
            b"console: SYMBI_UPDATE_LIFECYCLE=b-enter\n",
            b"console: SYMBI_UPDATE_LIFECYCLE=f-enter\n",
            b"console: SYMBI_UPDATE_LIFECYCLE=f-success\n",
            b"console: SYMBI_UPDATE_LIFECYCLE=f-stop\r\n",
        ))
        self.assertEqual(_lifecycle_observation(failure_raw), {
            "state": "valid",
            "events": ["b-enter", "f-enter", "f-success", "f-stop"],
            "last_event": "f-stop",
            "boundary": "f-stopped",
            "marker_count": 4,
        })
        success_raw = b"".join(
            b"SYMBI_UPDATE_LIFECYCLE=" + event + b"\n"
            for event in (b"b-enter", b"b-success", b"o-enter",
                          b"o-success", b"o-stop"))
        self.assertEqual(_lifecycle_observation(success_raw), {
            "state": "valid",
            "events": ["b-enter", "b-success", "o-enter", "o-success", "o-stop"],
            "last_event": "o-stop",
            "boundary": "o-stopped",
            "marker_count": 5,
        })
        self.assertEqual(_lifecycle_observation(b"unreviewed secret bytes\n"), {
            "state": "absent", "events": [], "last_event": None,
            "boundary": "unobserved", "marker_count": 0,
        })
        for case, raw in {
            "duplicate": (b"SYMBI_UPDATE_LIFECYCLE=b-enter\n" * 2),
            "reordered": (b"SYMBI_UPDATE_LIFECYCLE=o-enter\n"
                          b"SYMBI_UPDATE_LIFECYCLE=b-enter\n"),
            "unknown": b"SYMBI_UPDATE_LIFECYCLE=private-value\n",
            "non-ascii": b"SYMBI_UPDATE_LIFECYCLE=b-enter\xff\n",
            "trailing": b"SYMBI_UPDATE_LIFECYCLE=b-enter private-value\n",
            "multiple": (b"SYMBI_UPDATE_LIFECYCLE=b-enter "
                         b"SYMBI_UPDATE_LIFECYCLE=b-success\n"),
        }.items():
            with self.subTest(case=case):
                normalized = _lifecycle_observation(raw)
                self.assertEqual(normalized["state"], "invalid")
                self.assertEqual(normalized["events"], [])
                self.assertIsNone(normalized["last_event"])
                self.assertEqual(normalized["boundary"], "invalid")
                self.assertNotIn(b"private-value", json.dumps(normalized).encode())
        for raw in (None, "SYMBI_UPDATE_LIFECYCLE=b-enter", bytearray()):
            with self.subTest(raw_type=type(raw).__name__), self.assertRaises(ValueError):
                _lifecycle_observation(raw)

    @staticmethod
    def root_file_stat(real_fstat, changed_gid_path=None):
        def reader(descriptor):
            observed = real_fstat(descriptor)
            path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
            return SimpleNamespace(
                st_mode=observed.st_mode, st_uid=0,
                st_gid=1 if changed_gid_path == path else 0,
                st_size=observed.st_size, st_nlink=observed.st_nlink,
                st_dev=observed.st_dev, st_ino=observed.st_ino,
                st_mtime_ns=observed.st_mtime_ns,
                st_ctime_ns=observed.st_ctime_ns,
            )
        return reader

    def bootc_fixture(self, root):
        source, reference = root / "bootc", root / "ostree"
        source.write_bytes(b"fixed bootc bytes")
        reference.write_bytes(b"label reference")
        source.chmod(0o755)
        reference.chmod(0o755)
        return source, reference

    def test_fixed_transition_binds_bootc_owner_mode_bytes_and_label(self):
        real_fstat = os.fstat
        label = b"system_u:object_r:install_exec_t:s0\0"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, reference = self.bootc_fixture(root)
            root_stat = self.root_file_stat(real_fstat)
            with patch("image.atomic.update_guest.os.fstat", side_effect=root_stat), \
                    patch("image.atomic.update_guest.os.getxattr",
                          return_value=label):
                observation = _bootc_file_observation(source, reference)
            self.assertEqual(observation["source_sha256"],
                             hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(observation["label_reference_sha256"],
                             hashlib.sha256(reference.read_bytes()).hexdigest())
            self.assertEqual(observation["mode"], "0755")
            self.assertEqual(observation["selinux_label"], label[:-1].decode())
            self.assertNotEqual(
                observation["selinux_label"], BOOTC_TRANSITION_BRIDGE_CONTEXT)

            mutations = (
                "source-gid", "reference-gid", "source-mode",
                "reference-mode", "label", "malformed-label",
                "source-symlink", "reference-symlink",
            )
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    source, reference = self.bootc_fixture(root)
                    changed_gid = {
                        "source-gid": source,
                        "reference-gid": reference,
                    }.get(mutation)
                    getxattr = Mock(return_value=label)
                    original = None
                    if mutation == "source-mode":
                        source.chmod(0o775)
                    elif mutation == "reference-mode":
                        reference.chmod(0o775)
                    elif mutation == "label":
                        def labels(descriptor, _name):
                            target = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                            return (b"system_u:object_r:bin_t:s0\0"
                                    if target == source else label)
                        getxattr.side_effect = labels
                    elif mutation == "malformed-label":
                        getxattr.return_value = label + b"junk"
                    elif mutation.endswith("-symlink"):
                        target = {"source-symlink": source,
                                  "reference-symlink": reference}[mutation]
                        original = target.with_name(target.name + ".real")
                        target.rename(original)
                        target.symlink_to(original)
                    stat_reader = self.root_file_stat(real_fstat, changed_gid)
                    with patch("image.atomic.update_guest.os.fstat",
                               side_effect=stat_reader), \
                            patch("image.atomic.update_guest.os.getxattr", getxattr):
                        with self.assertRaises((OSError, ValueError)):
                            _bootc_file_observation(source, reference)
                    if original is not None:
                        target = {"source-symlink": source,
                                  "reference-symlink": reference}[mutation]
                        target.unlink()
                        original.rename(target)

    def test_fixed_status_replaces_stale_output_and_binds_service_freshness(self):
        real_fstat = os.fstat
        properties = ("Result=success\nExecMainCode=1\nExecMainStatus=0\n"
                      "ActiveState=active\nSubState=exited\n")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "status.json"
            output.write_bytes(b'{"stale":true}\n')
            output.chmod(0o600)
            fresh = b'{"fresh":true}\n'
            commands = []

            def run(command, **_options):
                commands.append(command)
                if command[1] == "restart":
                    output.write_bytes(fresh)
                    output.chmod(0o600)
                    return ""
                return properties

            observations = []
            with patch("image.atomic.update_guest.os.fstat",
                       side_effect=self.root_file_stat(real_fstat)):
                self.assertEqual(fixed_bootc_status(run, observations, output),
                                 {"fresh": True})
            self.assertEqual(len(observations), 1)
            self.assertEqual(observations[0]["bytes"], len(fresh))
            self.assertEqual(observations[0]["sha256"],
                             hashlib.sha256(fresh).hexdigest())
            self.assertEqual(commands[0],
                             ["/usr/bin/systemctl", "restart", "s.service"])

            output.write_bytes(b'{"stale":true}\n')
            output.chmod(0o600)
            with patch("image.atomic.update_guest.os.fstat",
                       side_effect=self.root_file_stat(real_fstat)):
                with self.assertRaises(FileNotFoundError):
                    fixed_bootc_status(
                        lambda command, **_options: properties,
                        [], output)
            self.assertFalse(output.exists())

    def test_fixed_bootc_operation_revalidates_before_and_after_execution(self):
        transition = self.transition_report()
        record = {"bootc_transition": transition}
        current = transition["bootc"]
        child_context = {
            "pid": 1234, "pidfd_opened": True,
            "selinux_context": INSTALL_CONTEXT,
        }
        transition_receipt = self.operation_report(
            "positive")["transition_receipt"]
        result = SimpleNamespace(returncode=0, stderr="",
                                 child_context=child_context,
                                 transition_receipt=transition_receipt)
        runner = Mock(return_value=result)
        with patch("image.atomic.update_guest._bootc_file_observation",
                   side_effect=[current, current]):
            observed = fixed_bootc_operation(
                runner, record, "positive", self.new,
                expected_success=True, timeout=120)
        self.assertEqual(observed["command"], [
            "/usr/bin/bootc", "switch", "--transport", "dir",
            "--enforce-container-sigpolicy", "/run/symbi-update/source",
        ])
        runner.assert_called_once_with(observed["command"], timeout=120,
                                       check=False, return_result=True,
                                       observe_bootc=True,
                                       bootc_operation="positive",
                                       bootc_digest=self.new)

        changed = dict(current, source_sha256="0" * 64)
        before_runner = Mock(return_value=result)
        with patch("image.atomic.update_guest._bootc_file_observation",
                   return_value=changed), self.assertRaisesRegex(
                       ValueError, "changed before use"):
            fixed_bootc_operation(before_runner, record, "positive", self.new,
                                  expected_success=True, timeout=120)
        before_runner.assert_not_called()

        after_runner = Mock(return_value=result)
        with patch("image.atomic.update_guest._bootc_file_observation",
                   side_effect=[current, changed]), self.assertRaisesRegex(
                       ValueError, "changed during use"):
            fixed_bootc_operation(after_runner, record, "positive", self.new,
                                  expected_success=True, timeout=120)
        after_runner.assert_called_once()

    def test_bootc_bridge_receipt_binds_dispatch_and_pipe_eof(self):
        command = [
            "/usr/bin/bootc", "switch", "--transport", "dir",
            "--enforce-container-sigpolicy", "/run/symbi-update/source",
        ]
        calls = []

        class Child:
            pid = 4321
            returncode = None

            def poll(self):
                return self.returncode

            def communicate(self, timeout=None):
                if timeout is None or timeout <= 0:
                    raise AssertionError("missing bounded communicate timeout")
                self.returncode = 0
                return "bootc output", ""

            def kill(self):
                self.returncode = -9

            def wait(self):
                return self.returncode

        def popen(arguments, **options):
            calls.append((arguments, options))
            receipt_fd, = options["pass_fds"]
            os.write(receipt_fd, (
                "SYMBI_BOOTC_RECEIPT_V1|positive|" + self.new + "|"
                + INSTALL_CONTEXT + "\n").encode())
            return Child()

        result = _bootc_subprocess(
            command, 30, operation="positive", digest=self.new, popen=popen,
            pidfd_open=lambda _pid, _flags: os.open("/dev/null", os.O_RDONLY))
        self.assertEqual(result.args, command)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.child_context, {
            "pid": 4321, "pidfd_opened": True,
            "selinux_context": INSTALL_CONTEXT,
        })
        self.assertEqual(result.transition_receipt, {
            "schema": 1, "bridge": str(BOOTC_TRANSITION_BRIDGE),
            "operation": "positive", "digest": self.new,
            "selinux_context": INSTALL_CONTEXT, "close_on_exec": True,
        })
        bridge_command, options = calls[0]
        self.assertEqual(bridge_command[0:2], [
            str(BOOTC_TRANSITION_BRIDGE), "--receipt-fd"])
        self.assertEqual(bridge_command[3:], ["positive", self.new])
        self.assertEqual(options["pass_fds"], (int(bridge_command[2]),))

    def test_bootc_bridge_receipt_rejects_operation_digest_and_framing_changes(self):
        valid = ("SYMBI_BOOTC_RECEIPT_V1|rollback|" + self.old + "|"
                 + INSTALL_CONTEXT + "\n").encode()
        self.assertEqual(
            _transition_receipt(valid, "rollback", self.old)["digest"],
            self.old)
        for raw, operation, digest in (
                (valid, "positive", self.old),
                (valid, "rollback", self.new),
                (valid[:-1], "rollback", self.old),
                (valid + b"extra", "rollback", self.old),
                (b"SYMBI_BOOTC_RECEIPT_V1|probe|-|wrong\n", "probe", "-")):
            with self.subTest(raw=raw, operation=operation, digest=digest), \
                    self.assertRaises(ValueError):
                _transition_receipt(raw, operation, digest)

    def test_transition_command_and_inputs_are_fixed(self):
        self.assertEqual(BOOTC_SOURCE, Path("/usr/bin/bootc"))
        self.assertEqual(BOOTC_LABEL_REFERENCE, Path("/usr/bin/ostree"))
        self.assertEqual(CONTROLLER_ENTRYPOINT,
                         Path("/usr/libexec/symbi-atomic-update"))
        self.assertEqual(CONTROLLER_PATH,
                         Path("/usr/libexec/symbi-atomic-update-controller.py"))
        self.assertEqual(INSTALL_CONTEXT,
                         "system_u:system_r:install_t:s0")

    def test_update_device_readiness_wait_is_fixed_and_bounded(self):
        self.assertEqual(SOURCE_SERIAL, "SYMBIUPDATE")
        self.assertEqual(SOURCE_DEVICE_TIMEOUT_SECONDS, 30)
        source = Path("/dev/vdb")
        scan = Mock(side_effect=[(None, ["vda"]),
                                 (source, ["vda", "vdb"])])
        clock = Mock(side_effect=[0.0, 0.0, 0.1])
        sleeper = Mock()
        self.assertEqual(wait_for_source_device(scan=scan, clock=clock,
                                                sleeper=sleeper),
                         (source, ["vda", "vdb"]))
        sleeper.assert_called_once_with(0.25)

        scan = Mock(return_value=(None, ["vda"]))
        with self.assertRaisesRegex(ValueError, "virtio serial is absent"):
            wait_for_source_device(scan=scan,
                                   clock=Mock(side_effect=[0.0, 0.0, 30.0]),
                                   sleeper=Mock())
        self.assertEqual(scan.call_count, 1)

    def test_source_device_discovery_binds_exact_serial_and_device_number(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sys_block, dev_root = root / "sys", root / "dev"
            sys_block.mkdir()
            dev_root.mkdir()
            numbers = {"vda": (252, 0), "vdb": (252, 16)}

            def add(name, serial_value, number):
                entry = sys_block / name
                entry.mkdir()
                (entry / "dev").write_text(f"{number[0]}:{number[1]}\n")
                if serial_value is not None:
                    (entry / "serial").write_bytes(serial_value)

            add("vda", b"", numbers["vda"])
            add("vda1", b"SYMBIUPDATE", (252, 1))
            add("vdb", b"SYMBIUPDATE", numbers["vdb"])
            (sys_block / "zram0").mkdir()

            def block_lstat(path):
                major, minor = numbers[Path(path).name]
                return Mock(st_mode=stat.S_IFBLK | 0o600,
                            st_rdev=os.makedev(major, minor))

            source, inventory = discover_source_device(sys_block, dev_root,
                                                        block_lstat)
            self.assertEqual(source, dev_root / "vdb")
            self.assertEqual(inventory, ["vda", "vda1", "vdb", "zram0"])

            (sys_block / "vdb" / "serial").write_bytes(b"symbiupdate")
            self.assertIsNone(discover_source_device(sys_block, dev_root,
                                                     block_lstat)[0])
            (sys_block / "vdb" / "serial").write_bytes(b"SYMBIUPDATE\n")
            self.assertIsNone(discover_source_device(sys_block, dev_root,
                                                     block_lstat)[0])
            (sys_block / "vdb" / "serial").write_bytes(b"SYMBIUPDATE-X")
            self.assertIsNone(discover_source_device(sys_block, dev_root,
                                                     block_lstat)[0])

    def test_source_device_discovery_rejects_ambiguity_and_node_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sys_block, dev_root = root / "sys", root / "dev"
            sys_block.mkdir()
            dev_root.mkdir()

            def add(name, number):
                entry = sys_block / name
                entry.mkdir()
                (entry / "serial").write_bytes(b"SYMBIUPDATE")
                (entry / "dev").write_text(f"{number[0]}:{number[1]}\n")

            add("vdb", (252, 16))
            self.assertIsNone(discover_source_device(sys_block, dev_root)[0])
            (dev_root / "vdb").write_text("not a device")
            with self.assertRaisesRegex(ValueError, "device node differs"):
                discover_source_device(sys_block, dev_root)
            (dev_root / "vdb").unlink()
            target = dev_root / "target"
            target.write_text("not a device")
            (dev_root / "vdb").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "device node differs"):
                discover_source_device(sys_block, dev_root)

            mismatch = Mock(st_mode=stat.S_IFBLK | 0o600,
                            st_rdev=os.makedev(252, 17))
            with self.assertRaisesRegex(ValueError, "device node differs"):
                discover_source_device(sys_block, dev_root,
                                       lambda _path: mismatch)

            add("vdc", (252, 32))
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                discover_source_device(sys_block, dev_root,
                                       lambda _path: mismatch)

    def test_source_device_discovery_rejects_unbounded_or_unsafe_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            sys_block = Path(temporary)
            (sys_block / "bad name").mkdir()
            with self.assertRaisesRegex(ValueError, "invalid block-device inventory"):
                discover_source_device(sys_block, sys_block)
        with tempfile.TemporaryDirectory() as temporary:
            sys_block = Path(temporary)
            for index in range(65):
                (sys_block / f"loop{index}").mkdir()
            with self.assertRaisesRegex(ValueError, "invalid block-device inventory"):
                discover_source_device(sys_block, sys_block)

    def test_source_mount_is_boot_ephemeral_while_phase_state_persists(self):
        self.assertEqual(SOURCE, Path("/run/symbi-update/source"))
        self.assertEqual(STATE, Path("/var/lib/symbi-update-test/phase"))
        self.assertNotEqual(SOURCE.parent, STATE.parent)

    def test_update_source_identity_is_exact_and_rejects_ambiguity(self):
        expected = {"filesystem": "ext4", "label": "SYMBIUPDATE",
                    "uuid": "1d3a0ad0-0fdb-4338-a56d-12061df7b091"}
        raw = ("DEVNAME=/dev/vdb\nLABEL=SYMBIUPDATE\n"
               "UUID=1d3a0ad0-0fdb-4338-a56d-12061df7b091\nTYPE=ext4\n")
        self.assertEqual(validate_source_identity(raw, expected), {
            "TYPE": "ext4", "LABEL": "SYMBIUPDATE",
            "UUID": "1d3a0ad0-0fdb-4338-a56d-12061df7b091"})
        mutations = [
            raw.replace("TYPE=ext4", "TYPE=xfs"),
            raw.replace("LABEL=SYMBIUPDATE", "LABEL=OTHER"),
            raw.replace(expected["uuid"], "2d3a0ad0-0fdb-4338-a56d-12061df7b091"),
            raw + "TYPE=ext4\n",
            raw + "malformed\n",
        ]
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_source_identity(changed, expected)

    def test_source_mount_observation_binds_kernel_mountinfo_to_the_device(self):
        raw = (r"46 23 0:1 /cache\040root /run/other\040mount ro - tmpfs "
               "tmpfs\\134name rw\n"
               "99 23 0:44 / /run/symbi-update "
               "rw,nosuid,nodev,noexec - tmpfs runtime rw\n"
               "47 23 252:16 / /run/symbi-update "
               "ro,nosuid,nodev,noexec,relatime - ext4 /dev/vdb ro,seclabel\n")
        observation = source_mount_observation(raw, 47)
        self.assertEqual(observation, {
            "mountinfo_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "path_match_count": 2,
            "selected_match_count": 1,
            "visible_mount_id": 47,
            "selected_mount_id": 47,
            "mountpoint": "/run/symbi-update",
            "root": "/",
            "fstype": "ext4",
            "source": "/dev/vdb",
            "major_minor": "252:16",
            "options": ["ro", "nosuid", "nodev", "noexec", "relatime"],
            "super_options": ["ro", "seclabel"],
        })
        self.assertEqual(validate_source_mount(
            observation, Path("/dev/vdb"), (252, 16)), observation)

    def test_source_mount_validation_rejects_changed_controls(self):
        valid = ("47 23 252:16 / /run/symbi-update "
                 "ro,nosuid,nodev,noexec,relatime - ext4 /dev/vdb ro,seclabel\n")
        mutations = {
            "device number": valid.replace("252:16", "252:17"),
            "filesystem root": valid.replace("252:16 / /run", "252:16 /subtree /run"),
            "mountpoint": valid.replace("/run/symbi-update", "/run/other"),
            "source": valid.replace("/dev/vdb", "/dev/vdc"),
            "filesystem": valid.replace(" ext4 ", " xfs "),
            "read only": valid.replace("ro,nosuid", "rw,nosuid"),
            "nosuid": valid.replace(",nosuid", ""),
            "nodev": valid.replace(",nodev", ""),
            "noexec": valid.replace(",noexec", ""),
        }
        for name, raw in mutations.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_source_mount(
                    source_mount_observation(raw, 47), Path("/dev/vdb"), (252, 16))

    def test_source_mount_observation_rejects_ambiguous_or_unsafe_input(self):
        valid = ("47 23 252:16 / /run/symbi-update "
                 "ro,nosuid,nodev,noexec - ext4 /dev/vdb ro,seclabel\n")
        cases = {
            "duplicate selected ID": valid + valid,
            "malformed escape": valid.replace("symbi-update", r"symbi\041update"),
            "unknown escape": valid.replace("/dev/vdb", r"/dev/vd\142"),
            "nul": valid.replace("ext4", "ext4\x00"),
            "oversized": valid + ("x" * MOUNTINFO_MAX_BYTES),
        }
        for name, raw in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                observation = source_mount_observation(raw, 47)
                validate_source_mount(observation, Path("/dev/vdb"), (252, 16))

    def test_visible_mount_id_selection_fails_closed_without_guessing(self):
        visible = ("47 23 252:16 / /run/symbi-update "
                   "ro,nosuid,nodev,noexec - ext4 /dev/vdb ro,seclabel\n")
        hidden = ("99 23 0:44 / /run/symbi-update "
                  "rw,nosuid,nodev,noexec - tmpfs runtime rw\n")
        selected = source_mount_observation(visible + hidden, 47)
        self.assertEqual(selected["path_match_count"], 2)
        self.assertEqual(selected["visible_mount_id"], 47)
        self.assertEqual(selected["selected_mount_id"], 47)
        self.assertEqual(selected["source"], "/dev/vdb")
        for raw, visible_id in (
            (visible + visible, 47),
            (visible + hidden, 48),
        ):
            with self.subTest(visible_id=visible_id), self.assertRaises(ValueError):
                validate_source_mount(
                    source_mount_observation(raw, visible_id),
                    Path("/dev/vdb"), (252, 16))

    def test_fdinfo_mount_id_parser_is_bounded_and_unambiguous(self):
        raw = "pos:\t0\nflags:\t012000000\nmnt_id:\t47\nino:\t123\n"
        self.assertEqual(parse_visible_mount_id(raw), 47)
        mutations = {
            "missing": raw.replace("mnt_id:\t47\n", ""),
            "duplicate": raw + "mnt_id:\t47\n",
            "negative": raw.replace("mnt_id:\t47", "mnt_id:\t-1"),
            "leading zero": raw.replace("mnt_id:\t47", "mnt_id:\t047"),
            "non-numeric": raw.replace("mnt_id:\t47", "mnt_id:\tabc"),
            "nul": raw.replace("mnt_id", "mnt\x00_id"),
            "no newline": raw.rstrip("\n"),
            "oversized": raw + ("x" * FDINFO_MAX_BYTES),
        }
        for name, changed in mutations.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                parse_visible_mount_id(changed)

    def test_visible_mount_open_binds_fdinfo_mountinfo_and_named_path(self):
        raw = ("47 23 252:16 / /run/symbi-update "
               "ro,nosuid,nodev,noexec - ext4 /dev/vdb ro,seclabel\n")
        opened = Mock(st_mode=stat.S_IFDIR | 0o700, st_dev=11, st_ino=22)
        named = Mock(st_mode=stat.S_IFDIR | 0o700, st_dev=11, st_ino=22)
        close = Mock()
        opener = Mock(return_value=9)
        observation = observe_visible_source_mount(
            opener=opener, descriptor_stat=Mock(return_value=opened),
            path_lstat=Mock(side_effect=[named, named]), closer=close,
            fdinfo_reader=Mock(return_value=47), mountinfo_reader=Mock(return_value=raw))
        self.assertEqual(observation["selected_mount_id"], 47)
        opened_path, opened_flags = opener.call_args.args
        self.assertEqual(opened_path, SOURCE.parent)
        self.assertTrue(opened_flags & os.O_PATH)
        self.assertTrue(opened_flags & os.O_DIRECTORY)
        self.assertTrue(opened_flags & os.O_NOFOLLOW)
        close.assert_called_once_with(9)

        symlink = Mock(st_mode=stat.S_IFLNK | 0o777, st_dev=11, st_ino=22)
        changed = Mock(st_mode=stat.S_IFDIR | 0o700, st_dev=11, st_ino=23)
        for name, named_states in {
            "symlink": [symlink],
            "descriptor mismatch": [changed],
            "changed path": [named, changed],
        }.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                observe_visible_source_mount(
                    opener=Mock(return_value=9),
                    descriptor_stat=Mock(return_value=opened),
                    path_lstat=Mock(side_effect=named_states), closer=Mock(),
                    fdinfo_reader=Mock(return_value=47),
                    mountinfo_reader=Mock(return_value=raw))

    def test_real_host_fdinfo_mount_id_selects_the_visible_root_mount(self):
        descriptor = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            visible_mount_id = read_visible_mount_id(descriptor)
        finally:
            os.close(descriptor)
        observation = mount_observation(
            Path("/proc/self/mountinfo").read_text(), Path("/"), visible_mount_id)
        self.assertEqual(observation["selected_match_count"], 1)
        self.assertEqual(observation["selected_mount_id"], visible_mount_id)
        self.assertEqual(observation["mountpoint"], "/")

    def test_mounted_device_binding_requires_one_real_mount_of_the_block_node(self):
        source = Mock(st_mode=stat.S_IFBLK | 0o600,
                      st_rdev=os.makedev(252, 16))
        mounted = Mock(st_mode=stat.S_IFDIR | 0o755,
                       st_dev=os.makedev(252, 16))
        kwargs = {
            "device_lstat": Mock(return_value=source),
            "mount_stat": Mock(return_value=mounted),
            "is_mount": Mock(return_value=True),
        }
        self.assertEqual(validate_mounted_device(
            Path("/dev/vdb"), SOURCE.parent, **kwargs), (252, 16))
        for name, change in {
            "not mounted": {"is_mount": Mock(return_value=False)},
            "not block": {"device_lstat": Mock(return_value=Mock(
                st_mode=stat.S_IFREG | 0o600, st_rdev=os.makedev(252, 16)))},
            "other mounted device": {"mount_stat": Mock(return_value=Mock(
                st_mode=stat.S_IFDIR | 0o755, st_dev=os.makedev(252, 17)))},
        }.items():
            changed = dict(kwargs)
            changed.update(change)
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_mounted_device(Path("/dev/vdb"), SOURCE.parent, **changed)

    def test_existing_atomic_workflow_downloads_both_exact_artifacts(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/atomic-boot.yml").read_text()
        script = (root / "scripts/check-atomic-boot.sh").read_text()
        hosted = (root / "image/atomic/hosted.py").read_text()
        self.assertIn("SYMBI_QUALIFICATION: update", workflow)
        self.assertIn("atomic-update-artifact.json", workflow)
        self.assertIn("atomic-update-image.zip", workflow)
        self.assertIn("require_update_base(lock,pins,current)", workflow)
        self.assertIn(".cache/atomic-update-evidence", workflow)
        self.assertIn("SYMBI_QUALIFICATION=update", script)
        self.assertIn("--property=MemoryMax=5G", script)
        self.assertIn("'memory.max':'5368709120'", hosted)
        self.assertIn("qualification not in ('','update')", hosted)
        self.assertNotIn("qualification=='landlock'", hosted)
        self.assertIn("qualification=='update'", hosted)

    def test_only_the_fixed_atomic_controller_can_use_the_extended_timeout(self):
        command = [
            "podman", "--cgroup-manager=cgroupfs", "--root", "/private/root",
            "--runroot", "/run/symbi-atomic-disk-123-1", "run", "--rm",
            "--name=symbi-atomic-update-qemu", "--pull=never", "--network=none",
            "--pid=private",
            "--cgroup-parent=/system.slice/symbi-atomic-disk-123-1.service",
            "--env=LANG=C.UTF-8",
            "--env=PYTHONDONTWRITEBYTECODE=1", "--read-only", "--user=10001:10001",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=3g",
            "--memory-swap=3g", "--cpus=2", "--pids-limit=64",
            "--mount", "type=bind,src=/private/input,dst=/inputs,ro",
            "--mount", "type=bind,src=/private/old,dst=/inputs/atomic.raw,ro",
            "--mount", "type=bind,src=/private/update,dst=/inputs/update.raw,ro",
            "--mount", "type=bind,src=/private/output,dst=/output",
            "--entrypoint=/usr/bin/python3", "sha256:" + "a" * 64,
            "/inputs/update_boot.py",
        ]
        self.assertEqual(TIMEOUT_SECONDS, 5400)
        validate_update_controller_command(command)
        for mutation in ("network", "entrypoint", "script", "memory",
                         "memory-override", "read-write-override", "remote",
                         "global-manager", "global-root", "relative-root",
                         "long-runroot", "cgroup", "mount-option", "ro-false",
                         "output-ro"):
            with self.subTest(mutation=mutation):
                changed = list(command)
                if mutation == "network":
                    changed.remove("--network=none")
                elif mutation == "entrypoint":
                    changed[changed.index("--entrypoint=/usr/bin/python3")] = "--entrypoint=/bin/sh"
                elif mutation == "script":
                    changed[-1] = "/inputs/caller.py"
                elif mutation == "memory-override":
                    changed.insert(-2, "--memory=4g")
                elif mutation == "read-write-override":
                    changed.insert(-2, "--read-only=false")
                elif mutation == "remote":
                    changed.insert(1, "--remote")
                elif mutation == "global-manager":
                    changed[1] = "--cgroup-manager=systemd"
                elif mutation == "global-root":
                    changed.insert(changed.index("run"), "--root=/other")
                elif mutation == "relative-root":
                    changed[changed.index("/private/root")] = "relative/root"
                elif mutation == "long-runroot":
                    changed[changed.index("/run/symbi-atomic-disk-123-1")] = "/run/" + "x" * 51
                elif mutation == "cgroup":
                    changed[changed.index(
                        "--cgroup-parent=/system.slice/symbi-atomic-disk-123-1.service"
                    )] = "--cgroup-parent=/system.slice/symbi-atomic-disk-999-1.service"
                elif mutation == "mount-option":
                    index = changed.index("type=bind,src=/private/input,dst=/inputs,ro")
                    changed[index] += ",rw"
                elif mutation == "ro-false":
                    index = changed.index("type=bind,src=/private/input,dst=/inputs,ro")
                    changed[index] = "type=bind,src=/private/input,dst=/inputs,ro=false"
                elif mutation == "output-ro":
                    index = changed.index("type=bind,src=/private/output,dst=/output")
                    changed[index] += ",ro"
                else:
                    changed[changed.index("--memory=3g")] = "--memory=4g"
                with self.assertRaises(ValueError):
                    validate_update_controller_command(changed)

    def test_atomic_wrapper_reclaims_only_exact_evidence_directories(self):
        root = Path(__file__).resolve().parents[2]
        script = (root / "scripts/check-atomic-boot.sh").read_text()
        for name in ("atomic-image-evidence", "atomic-disk-evidence",
                     "atomic-update-evidence"):
            self.assertIn(f'"$root/.cache/{name}"', script)
        self.assertIn('find -P "$path" -xdev', script)
        self.assertIn('-type f -links 1', script)
        self.assertIn('chown --no-dereference', script)
        self.assertIn('[[ -L "$path" || ! -d "$path" ]]', script)
        self.assertNotIn(".cache/atomic-*", script)
        self.assertLess(script.index('cache="$root/.cache"'),
                        script.index('mkdir -p "$evidence"'))
        self.assertLess(script.index("before use: $path"),
                        script.index("sudo systemd-run"))

    def report(self):
        return {
            "schema": 1,
            "passed": True,
            "guest_booted": True,
            "release_qualified": False,
            "source_authentication": {
                "positive_controls": {"install": True, "update": True},
                "negative_controls": {
                    "unsigned": True, "wrong-key": True,
                    "wrong-reference": True, "altered-signature": True,
                },
            },
            "bootc_negative_controls": {
                "unsigned": True, "wrong-key": True,
                "wrong-reference": True, "altered-signature": True,
            },
            "same_path_positive_control": {
                "passed": True, "overlay_discarded": True,
                "negative_baselines_clean": True,
                "source": NEGATIVE_UPDATE_SOURCE,
                "report_sha256": "8" * 64,
                "state_before_sha256": "3" * 64,
                "state_after_sha256": "7" * 64,
            },
            "negative_overlays_discarded": True,
            "phases": [
                {"name": "installed", "booted_digest": self.old,
                 "operation": "signed-update-staged",
                 "staged_digest": self.new},
                {"name": "updated", "booted_digest": self.new,
                 "operation": "rollback-queued",
                 "rollback_digest": self.old},
                {"name": "rolled-back", "booted_digest": self.old,
                 "rollback_from_digest": self.new},
            ],
            "source_disk_unchanged": True,
            "persistent_overlay": True,
        }

    def test_complete_signed_update_and_booted_rollback_pass(self):
        result = validate_report(self.report(), self.old, self.new)
        self.assertEqual(result["updated_digest"], self.new)
        self.assertEqual(result["rolled_back_digest"], self.old)
        self.assertTrue(result["signed_update"])
        self.assertTrue(result["booted_rollback"])
        self.assertTrue(result["same_path_signature_acceptance"])

    def test_missing_phase_or_signature_control_fails(self):
        cases = []
        report = self.report()
        report["phases"].pop()
        cases.append(report)
        report = self.report()
        report["source_authentication"]["negative_controls"]["unsigned"] = False
        cases.append(report)
        report = self.report()
        report["bootc_negative_controls"]["unsigned"] = False
        cases.append(report)
        report = self.report()
        report["same_path_positive_control"]["passed"] = False
        cases.append(report)
        report = self.report()
        report["same_path_positive_control"]["negative_baselines_clean"] = False
        cases.append(report)
        report = self.report()
        report["same_path_positive_control"]["overlay_discarded"] = False
        cases.append(report)
        report = self.report()
        report["same_path_positive_control"]["state_after_sha256"] = "3" * 64
        cases.append(report)
        report = self.report()
        report["negative_overlays_discarded"] = False
        cases.append(report)
        report = self.report()
        report["phases"][1]["booted_digest"] = self.old
        cases.append(report)
        report = self.report()
        report["release_qualified"] = True
        cases.append(report)
        for report in cases:
            with self.subTest(report=report), self.assertRaises(ValueError):
                validate_report(report, self.old, self.new)


if __name__ == "__main__":
    unittest.main()
