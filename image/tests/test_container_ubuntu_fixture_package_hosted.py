"""Fail-closed tests for the manual Ubuntu package producer."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

from image.container import ubuntu_fixture_package_hosted as hosted
from image.container import ubuntu_fixture_packages as packages


ROOT = Path(__file__).resolve().parents[2]


class FakeResponse:
    status = 200

    def __init__(self, payload, url):
        self.payload = payload
        self.url = url
        self.offset = 0
        self.headers = {"Content-Length": str(len(payload))}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def geturl(self):
        return self.url

    def read(self, size=-1):
        if size < 0:
            size = len(self.payload) - self.offset
        result = self.payload[self.offset:self.offset + size]
        self.offset += len(result)
        return result


class UbuntuHostedProducerTests(unittest.TestCase):
    def setUp(self):
        self.contract, self.lock = hosted.load_contract(ROOT)

    def hosted_environment(self):
        return {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": packages.REPOSITORY["full_name"],
            "GITHUB_REPOSITORY_ID": str(packages.REPOSITORY["id"]),
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_WORKFLOW_REF": (
                packages.REPOSITORY["full_name"] + "/" + hosted.WORKFLOW
                + "@refs/heads/card/P0-05-package-producer"
            ),
        }

    def systemd_result(self, **overrides):
        rows = {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "SubState": "dead",
            "Result": "success",
            "ExecMainCode": "1",
            "ExecMainStatus": "0",
            "MemoryCurrent": "0",
            "MemoryPeak": "0",
            "MemoryMax": str(hosted.EXPECTED_LIMITS["memory_max"]),
            "MemorySwapCurrent": "0",
            "MemorySwapPeak": "0",
            "MemorySwapMax": "0",
            "CPUQuotaPerSecUSec": "1s",
            "CPUQuotaPeriodUSec": "100ms",
            "CPUUsageNSec": "1",
            "TasksCurrent": "0",
            "TasksMax": str(hosted.EXPECTED_LIMITS["pids_max"]),
            "RuntimeMaxUSec": "50min",
        }
        self.assertTrue(set(overrides).issubset(rows))
        rows.update(overrides)
        self.assertEqual(set(rows), hosted.SYSTEMD_RESULT_FIELDS)
        return "".join(f"{name}={value}\n"
                       for name, value in rows.items()).encode()

    def ready_contract(self):
        contract = copy.deepcopy(self.contract)
        contract["state"] = "ready"
        contract["scope"] = hosted.READY_SCOPE
        for sequence, pin in enumerate(contract["metadata_pins"], 1):
            pin["inrelease"] = {
                "bytes": sequence,
                "sha256": format(sequence, "064x"),
            }
            pin["packages_xz"] = {
                "bytes": sequence + 10,
                "sha256": format(sequence + 10, "064x"),
            }
        return contract

    def test_committed_contract_is_strict_pending_discovery(self):
        self.assertEqual(self.contract["schema"], 2)
        self.assertEqual(self.contract["state"], "pending-discovery")
        self.assertEqual(
            [row["mode"] for row in self.contract["freshness_policy"]],
            ["immutable-release", "rolling-date", "rolling-date"],
        )
        self.assertEqual(
            [row["suite"] for row in self.contract["metadata_pins"]],
            packages.EXPECTED_REQUEST["suites"],
        )
        self.assertTrue(all(
            row[name] == {"bytes": None, "sha256": None}
            for row in self.contract["metadata_pins"]
            for name in ("inrelease", "packages_xz")
        ))
        self.assertTrue(all(
            value is False
            for key, value in self.contract["candidate"].items()
            if key != "state"
        ))

    def test_contract_rejects_extra_fields_bool_ints_and_partial_pins(self):
        cases = []
        changed = copy.deepcopy(self.contract)
        changed["extra"] = "caller field"
        cases.append(changed)
        changed = copy.deepcopy(self.contract)
        changed["limits"]["memory_max"] = True
        cases.append(changed)
        changed = copy.deepcopy(self.contract)
        changed["metadata_pins"][0]["inrelease"] = {
            "bytes": 1, "sha256": "a" * 64,
        }
        cases.append(changed)
        changed = self.ready_contract()
        changed["metadata_pins"][0]["packages_xz"]["bytes"] = None
        cases.append(changed)
        changed = self.ready_contract()
        changed["candidate"]["producer_passed"] = True
        cases.append(changed)
        for field, value in (
                ("suite", "noble-updates"),
                ("codename", "jammy"),
                ("inrelease_url", "https://security.ubuntu.com/ubuntu/dists/noble/InRelease"),
                ("signer_fingerprint", "A" * 40),
                ("mode", "rolling-date"),
                ("maximum_age_days", 1831)):
            changed = copy.deepcopy(self.contract)
            changed["freshness_policy"][0][field] = value
            cases.append(changed)
        for field, value in (
                ("mode", "valid-until"),
                ("maximum_age_days", 15)):
            changed = copy.deepcopy(self.contract)
            changed["freshness_policy"][1][field] = value
            cases.append(changed)
        for contract in cases:
            with self.subTest(contract=contract), self.assertRaises(ValueError):
                hosted.validate_contract(ROOT, contract, self.lock)

    def test_ready_contract_accepts_only_complete_ordered_pins(self):
        contract = self.ready_contract()
        hosted.validate_contract(ROOT, contract, self.lock)
        hosted.validate_mode(contract, "produce")
        for change in ("wrong order", "duplicate", "bool size"):
            changed = copy.deepcopy(contract)
            if change == "wrong order":
                changed["metadata_pins"].reverse()
            elif change == "duplicate":
                changed["metadata_pins"][1]["suite"] = changed[
                    "metadata_pins"][0]["suite"]
            else:
                changed["metadata_pins"][0]["inrelease"]["bytes"] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                hosted.validate_contract(ROOT, changed, self.lock)
        changed = copy.deepcopy(contract)
        changed["metadata_pins"][0]["inrelease"] = {
            "bytes": None, "sha256": None,
        }
        with self.assertRaises(ValueError):
            hosted.validate_contract(ROOT, changed, self.lock)

    def test_produce_refuses_before_inputs_cgroup_commands_or_network(self):
        environment = self.hosted_environment()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in ("work", "evidence", "output"):
                (base / name).mkdir(mode=0o700)
            with mock.patch.object(
                    hosted, "validate_retained_inputs") as retained, \
                    mock.patch.object(hosted, "validate_cgroup") as cgroup, \
                    mock.patch.object(hosted, "_run_rootfs") as rootfs, \
                    mock.patch.object(hosted, "fetch_exact") as fetch, \
                    self.assertRaisesRegex(ValueError, "metadata pin state"):
                hosted.run(
                    ROOT, "produce", base / "work", base / "evidence",
                    base / "output", environment)
        retained.assert_not_called()
        cgroup.assert_not_called()
        rootfs.assert_not_called()
        fetch.assert_not_called()

    def test_environment_rejects_nonmanual_wrong_repository_and_bad_types(self):
        for name, value in (
                ("GITHUB_EVENT_NAME", "pull_request"),
                ("GITHUB_REPOSITORY_ID", str(packages.REPOSITORY["id"] + 1)),
                ("GITHUB_RUN_ATTEMPT", "true"),
                ("RUNNER_ENVIRONMENT", "self-hosted")):
            environment = self.hosted_environment()
            environment[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                hosted.validate_hosted_environment(
                    self.contract, "discover", environment)

    def test_retained_rootfs_signature_inputs_match_exact_lock(self):
        observed = hosted.validate_retained_inputs(
            ROOT, self.contract, self.lock)
        self.assertEqual(
            {name: row["name"] for name, row in observed.items()},
            {name: name for name in self.contract["retained_inputs"]},
        )
        self.assertEqual(
            observed["archive_keyring"]["sha256"],
            self.lock["rootfs"]["keyring"]["sha256"],
        )
        self.assertEqual(
            observed["checksum_signature"]["sha256"],
            self.lock["rootfs"]["checksum"]["signature_sha256"],
        )

    def test_metadata_command_uses_stable_logical_input_names(self):
        class InputsObserved(Exception):
            pass

        class Runner:
            inputs = None

            def run(self, _name, _argv, _timeout, *, inputs_=()):
                self.inputs = list(inputs_)
                raise InputsObserved

        retained = hosted.validate_retained_inputs(
            ROOT, self.contract, self.lock)
        runner = Runner()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(
                    hosted, "fetch_exact",
                    return_value={"bytes": 1, "sha256": "a" * 64}), \
                mock.patch.object(
                    hosted.build, "inrelease_verification_command",
                    return_value=["/usr/bin/gpgv"]), \
                self.assertRaises(InputsObserved):
            base = Path(directory)
            hosted._run_metadata(
                self.lock, self.contract, base, base, runner, None,
                ROOT / self.contract["retained_inputs"]["archive_keyring"],
                retained["archive_keyring"],
            )
        self.assertEqual(
            [row["name"] for row in runner.inputs],
            ["inrelease-noble", "archive_keyring"],
        )

    def test_checkout_binding_requires_exact_head_tree_and_clean_state(self):
        head = "a" * 40
        tree = "b" * 40

        class Runner:
            def __init__(self, dirty=b""):
                self.dirty = dirty
                self.calls = []

            def run(self, name, argv, timeout):
                self.calls.append((name, argv, timeout))
                output = {
                    "checkout-head": (head + "\n").encode(),
                    "checkout-tree": (tree + "\n").encode(),
                    "checkout-clean": self.dirty,
                }[name]
                return {
                    "timed_out": False,
                    "exit_status": 0,
                }, output, b""

        runner = Runner()
        self.assertEqual(
            hosted._run_checkout_binding(ROOT, head, runner, 5), tree)
        self.assertEqual(
            [call[0] for call in runner.calls],
            ["checkout-head", "checkout-tree", "checkout-clean"],
        )
        with self.assertRaisesRegex(ValueError, "GITHUB_SHA"):
            hosted._run_checkout_binding(ROOT, "c" * 40, Runner(), 5)
        with self.assertRaisesRegex(ValueError, "committed tree"):
            hosted._run_checkout_binding(
                ROOT, head, Runner(b"?? injected.py\n"), 5)

    def test_fetch_is_exact_no_redirect_bounded_and_preflighted(self):
        url = packages.EXPECTED_SOURCES[0]["metadata"]["inrelease_url"]
        payload = b"signed metadata"
        expected = {
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "InRelease"
            calls = []

            def opener(request, timeout):
                calls.append((request.full_url, timeout))
                return FakeResponse(payload, request.full_url)

            self.assertEqual(
                hosted.fetch_exact(
                    url, output, 1024, 5, expected=expected, opener=opener),
                expected,
            )
            self.assertEqual(output.read_bytes(), payload)
            self.assertEqual(len(calls), 1)

            bad = base / "redirected"
            with self.assertRaises(ValueError):
                hosted.fetch_exact(
                    url, bad, 1024, 5, expected=expected,
                    opener=lambda request, timeout: FakeResponse(
                        payload, "https://mirror.invalid/InRelease"),
                )
            preflight_calls = []
            with self.assertRaises(ValueError):
                hosted.fetch_exact(
                    url, base / "bad", 1024, 5,
                    expected={"bytes": True, "sha256": expected["sha256"]},
                    opener=lambda *args, **kwargs: preflight_calls.append(
                        (args, kwargs)),
                )
            self.assertEqual(preflight_calls, [])

    def command_fixture(self, base):
        raw = base / "raw"
        raw.mkdir(mode=0o700)
        (raw / "test.stdout").write_bytes(b"")
        (raw / "test.stderr").write_bytes(b"retained stderr")
        os.chmod(raw / "test.stdout", 0o600)
        os.chmod(raw / "test.stderr", 0o600)
        tool_path = "/usr/bin/gpgv"
        info = os.stat(tool_path)
        raw_tool = Path(tool_path).read_bytes()
        tool = {
            "path": tool_path,
            "bytes": len(raw_tool),
            "sha256": hashlib.sha256(raw_tool).hexdigest(),
            "device": info.st_dev,
            "inode": info.st_ino,
        }
        return {
            "name": "test",
            "argv": [tool_path],
            "tool": tool,
            "launcher": None,
            "network": "host",
            "timeout_seconds": 5,
            "timed_out": False,
            "exit_status": 0,
            "started_at": "2026-11-27T00:00:00Z",
            "finished_at": "2026-11-27T00:00:01Z",
            "duration_ms": 1,
            "stdout": {
                "path": "raw/test.stdout",
                "bytes": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
            },
            "stderr": {
                "path": "raw/test.stderr",
                "bytes": len(b"retained stderr"),
                "sha256": hashlib.sha256(b"retained stderr").hexdigest(),
            },
            "inputs": [{
                "name": "checksum_signature",
                "bytes": 1,
                "sha256": "2" * 64,
            }],
        }

    def ledger_command(self, evidence, name, argv, stdout=b"", stderr=b"",
                       inputs_=()):
        raw = evidence / "raw"
        raw.mkdir(mode=0o700, exist_ok=True)
        for suffix, payload in (("stdout", stdout), ("stderr", stderr)):
            path = raw / f"{name}.{suffix}"
            path.write_bytes(payload)
            path.chmod(0o600)
        descriptor = os.open(argv[0], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            tool = hosted._tool_record(argv[0], descriptor)
        finally:
            os.close(descriptor)
        return {
            "name": name,
            "argv": argv,
            "tool": tool,
            "launcher": None,
            "network": "host",
            "timeout_seconds": self.contract["timeouts"]["metadata_seconds"],
            "timed_out": False,
            "exit_status": 0,
            "started_at": "2026-11-27T00:00:00Z",
            "finished_at": "2026-11-27T00:00:01Z",
            "duration_ms": 1,
            "stdout": {
                "path": f"raw/{name}.stdout",
                "bytes": len(stdout),
                "sha256": hashlib.sha256(stdout).hexdigest(),
            },
            "stderr": {
                "path": f"raw/{name}.stderr",
                "bytes": len(stderr),
                "sha256": hashlib.sha256(stderr).hexdigest(),
            },
            "inputs": list(inputs_),
        }

    @staticmethod
    def gpg_status(fingerprint):
        return (
            "[GNUPG:] NEWSIG\n"
            f"[GNUPG:] GOODSIG {fingerprint[-16:]} Ubuntu Archive\n"
            f"[GNUPG:] VALIDSIG {fingerprint} 2026-11-27 1795780800 "
            f"0 4 0 1 10 01 {fingerprint}\n"
        ).encode()

    def ledger_fixture(self, base, *, full=True, run_id=123):
        evidence = base / "evidence"
        evidence.mkdir(mode=0o700)
        run = {
            "id": run_id,
            "attempt": 2,
            "head_sha": "a" * 40,
            "head_tree": "b" * 40,
            "workflow": hosted.WORKFLOW,
            "event": "workflow_dispatch",
        }
        checkout = []
        outputs = {
            "checkout-head": (run["head_sha"] + "\n").encode(),
            "checkout-tree": (run["head_tree"] + "\n").encode(),
            "checkout-clean": b"",
        }
        for name, argv in hosted._expected_checkout_commands(ROOT).items():
            checkout.append(self.ledger_command(
                evidence, name, argv, outputs[name]))
        ledger = hosted.PhaseLedger(
            evidence, "discover", self.contract, self.lock, run, ROOT)
        inodes = [(evidence / "phase-ledger.json").stat().st_ino]

        def append(*args, **kwargs):
            ledger.append(*args, **kwargs)
            inodes.append((evidence / "phase-ledger.json").stat().st_ino)

        append("checkout", None, commands=checkout, diagnostics={
            "head_sha": run["head_sha"],
            "head_tree": run["head_tree"],
            "clean": True,
        })
        retained = hosted.validate_retained_inputs(
            ROOT, self.contract, self.lock)
        root_fingerprint = self.lock["rootfs"]["checksum"]["signer_fingerprint"]
        root_status = self.gpg_status(root_fingerprint)
        root_command = self.ledger_command(
            evidence, "rootfs-gpgv", [
                "/usr/bin/gpgv", "--status-fd=1", "--keyring",
                str(ROOT / self.contract["retained_inputs"]["archive_keyring"]),
                str(ROOT / self.contract["retained_inputs"]["checksum_signature"]),
                str(ROOT / self.contract["retained_inputs"]["checksum"]),
            ], root_status, inputs_=[retained[name] for name in (
                "archive_keyring", "checksum_signature", "checksum")])
        append(
            "rootfs-signature", None, commands=[root_command],
            diagnostics=hosted.build.validate_gpgv_status(
                0, root_status.decode(), root_fingerprint))
        append(
            "rootfs-download", None,
            payloads=[hosted._ledger_payload(
                "rootfs", self.lock["rootfs"]["url"], {
                    "bytes": self.lock["rootfs"]["bytes"],
                    "sha256": self.lock["rootfs"]["sha256"],
                })])
        for sequence, source in enumerate(packages.EXPECTED_SOURCES, 1):
            suite = source["suite"]
            identity = {
                "bytes": 100 + sequence,
                "sha256": format(sequence, "064x"),
            }
            append(
                "inrelease-download", suite,
                payloads=[hosted._ledger_payload(
                    "inrelease-" + suite,
                    source["metadata"]["inrelease_url"], identity)])
            directory = base / ("metadata-" + suite)
            directory.mkdir(mode=0o700)
            fingerprint = source["metadata"]["signer_fingerprint"]
            status = self.gpg_status(fingerprint)
            command = self.ledger_command(
                evidence, "inrelease-" + suite, [
                    "/usr/bin/gpgv", "--status-fd=1", "--keyring",
                    str(ROOT / self.contract["retained_inputs"]["archive_keyring"]),
                    "--output", str(directory / (suite + "_Release")),
                    str(directory / (suite + "_InRelease")),
                ], status, inputs_=({
                    "name": "inrelease-" + suite, **identity,
                }, retained["archive_keyring"]))
            release = (
                "Origin: Ubuntu\nLabel: Ubuntu\n"
                f"Suite: {suite}\nCodename: noble\nDate: now\n"
                "SHA256:\n"
            ).encode()
            diagnostics = hosted.build.signed_release_diagnostics(
                release, source)
            append(
                "inrelease-signature", suite, commands=[command],
                diagnostics={
                    "signature": hosted.build.validate_gpgv_status(
                        0, status.decode(), fingerprint),
                    "release": diagnostics,
                })
            if not full and suite == "noble":
                return ledger, evidence, run, inodes, identity
            index = {
                "path": "main/binary-amd64/Packages.xz",
                "bytes": 200 + sequence,
                "sha256": format(10 + sequence, "064x"),
            }
            append(
                "release-validated", suite, diagnostics={
                    "freshness_policy": hosted.build.expected_freshness_policy(
                        source),
                    "release": {
                        "bytes": diagnostics["bytes"],
                        "sha256": diagnostics["sha256"],
                    },
                    "index": index,
                })
            append(
                "packages-download", suite,
                payloads=[hosted._ledger_payload(
                    "packages-" + suite, source["packages_url"], {
                        "bytes": index["bytes"],
                        "sha256": index["sha256"],
                    })])
        return ledger, evidence, run, inodes, None

    def discovery_result_fixture(self, base):
        ledger, evidence, run, _, _ = self.ledger_fixture(base, full=True)
        phases = ledger.value["phases"]
        commands = [
            command
            for phase in phases
            for command in phase["commands"]
        ]
        metadata = []
        for source in packages.EXPECTED_SOURCES:
            suite = source["suite"]
            inrelease = next(
                phase for phase in phases
                if phase["kind"] == "inrelease-download"
                and phase["suite"] == suite)["payloads"][0]
            index = next(
                phase for phase in phases
                if phase["kind"] == "packages-download"
                and phase["suite"] == suite)["payloads"][0]
            signature = next(
                phase for phase in phases
                if phase["kind"] == "inrelease-signature"
                and phase["suite"] == suite)["diagnostics"]["signature"]
            metadata.append({
                "suite": suite,
                "inrelease": {
                    "path": suite + "_InRelease",
                    "bytes": inrelease["bytes"],
                    "sha256": inrelease["sha256"],
                },
                "packages_xz": {
                    "path": suite + "_main_binary-amd64_Packages.xz",
                    "bytes": index["bytes"],
                    "sha256": index["sha256"],
                },
                "release": {"suite": suite},
                "signature": signature,
            })
        rootfs = self.lock["rootfs"]
        result = hosted._result(
            "discover", self.contract, self.lock, run,
            hosted.datetime(2026, 11, 27, 12, 0,
                            tzinfo=hosted.timezone.utc), {
                "archive": rootfs["archive"],
                "bytes": rootfs["bytes"],
                "sha256": rootfs["sha256"],
                "checksum_sha256": rootfs["checksum"]["sha256"],
                "checksum_signature_sha256": rootfs["checksum"][
                    "signature_sha256"],
                "keyring_sha256": rootfs["keyring"]["sha256"],
                "signing_fingerprint": rootfs["checksum"][
                    "signer_fingerprint"],
            }, metadata, commands,
            {"count": 0, "bytes": 0, "order_sha256": None},
            {
                "created": False, "manifest_sha256": None,
                "state": "candidate-unselected",
            }, ledger.receipt())
        return ledger, evidence, result

    def test_phase_ledger_atomically_accepts_every_strict_success_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger, evidence, run, inodes, _ = self.ledger_fixture(
                Path(directory), full=True)
            try:
                self.assertEqual(
                    len(ledger.value["phases"]), len(hosted.LEDGER_PHASE_ORDER))
                self.assertEqual(len(inodes), len(hosted.LEDGER_PHASE_ORDER) + 1)
                self.assertEqual(len(set(inodes)), len(inodes))
                receipt = ledger.receipt()
                self.assertEqual(receipt["phase_count"], 15)
                self.assertEqual(receipt["terminal_phase"], "packages-download")
                hosted.validate_phase_ledger_receipt(
                    receipt, "discover", self.contract, self.lock,
                    evidence, ROOT, run)
                for cutoff in range(len(ledger.value["phases"]) + 1):
                    prefix = copy.deepcopy(ledger.value)
                    prefix["phases"] = prefix["phases"][:cutoff]
                    hosted.validate_phase_ledger(
                        prefix, "discover", self.contract, self.lock,
                        evidence, ROOT, run)
                serialized = json.dumps(ledger.value)
                self.assertNotIn("Origin: Ubuntu", serialized)
                self.assertNotIn("Valid-Until:", serialized)
                self.assertLess(
                    (evidence / "phase-ledger.json").stat().st_size,
                    hosted.MAX_PHASE_LEDGER_BYTES)
            finally:
                ledger.close()

    def test_phase_ledger_accepts_only_rolling_zero_or_one_valid_until(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger, evidence, run, _, _ = self.ledger_fixture(
                Path(directory), full=True)
            try:
                hosted.validate_phase_ledger(
                    ledger.value, "discover", self.contract, self.lock,
                    evidence, ROOT, run)
                for suite in ("noble-updates", "noble-security"):
                    with_expiry = copy.deepcopy(ledger.value)
                    phase = next(
                        row for row in with_expiry["phases"]
                        if row["kind"] == "inrelease-signature"
                        and row["suite"] == suite)
                    self.assertEqual(
                        phase["diagnostics"]["release"][
                            "valid_until_fields"], 0)
                    phase["diagnostics"]["release"][
                        "valid_until_fields"] = 1
                    hosted.validate_phase_ledger(
                        with_expiry, "discover", self.contract, self.lock,
                        evidence, ROOT, run)

                    duplicate = copy.deepcopy(with_expiry)
                    duplicate_phase = next(
                        row for row in duplicate["phases"]
                        if row["kind"] == "inrelease-signature"
                        and row["suite"] == suite)
                    duplicate_phase["diagnostics"]["release"][
                        "valid_until_fields"] = 2
                    with self.assertRaises(ValueError):
                        hosted.validate_phase_ledger(
                            duplicate, "discover", self.contract, self.lock,
                            evidence, ROOT, run)

                immutable_changed = copy.deepcopy(ledger.value)
                immutable_phase = next(
                    row for row in immutable_changed["phases"]
                    if row["kind"] == "inrelease-signature"
                    and row["suite"] == "noble")
                immutable_phase["diagnostics"]["release"][
                    "valid_until_fields"] = 1
                with self.assertRaises(ValueError):
                    hosted.validate_phase_ledger(
                        immutable_changed, "discover", self.contract,
                        self.lock, evidence, ROOT, run)
            finally:
                ledger.close()

    def test_phase_ledger_receipt_rejects_different_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger, evidence, run, _, _ = self.ledger_fixture(
                Path(directory), full=True)
            try:
                receipt = ledger.receipt()
                path = evidence / "phase-ledger.json"
                path.write_bytes(path.read_bytes() + b"\n")
                path.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "receipt changed"):
                    hosted.validate_phase_ledger_receipt(
                        receipt, "discover", self.contract, self.lock,
                        evidence, ROOT, run)
            finally:
                ledger.close()

    def test_phase_ledger_receipt_rejects_same_size_name_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger, evidence, run, _, _ = self.ledger_fixture(
                Path(directory), full=True)
            try:
                receipt = ledger.receipt()
                path = evidence / "phase-ledger.json"
                raw = path.read_bytes()
                real_read = hosted.os.read
                replaced = False

                def replace_after_read(descriptor, count):
                    nonlocal replaced
                    block = real_read(descriptor, count)
                    if block and not replaced:
                        replaced = True
                        replacement = evidence / "same-size-replacement"
                        replacement.write_bytes(raw)
                        replacement.chmod(0o600)
                        os.replace(replacement, path)
                    return block

                with mock.patch.object(
                        hosted.os, "read", side_effect=replace_after_read), \
                        self.assertRaisesRegex(ValueError, "identity changed"):
                    hosted.validate_phase_ledger_receipt(
                        receipt, "discover", self.contract, self.lock,
                        evidence, ROOT, run)
                self.assertTrue(replaced)
                self.assertEqual(path.read_bytes(), raw)
            finally:
                ledger.close()

    def test_phase_ledger_receipt_cannot_mix_runs_or_ledgers(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "first").mkdir()
            (base / "second").mkdir()
            first, first_evidence, first_run, _, _ = self.ledger_fixture(
                base / "first", full=True, run_id=123)
            second, second_evidence, second_run, _, _ = self.ledger_fixture(
                base / "second", full=True, run_id=456)
            try:
                first_receipt = first.receipt()
                second_receipt = second.receipt()
                with self.assertRaises(ValueError):
                    hosted.validate_phase_ledger_receipt(
                        first_receipt, "discover", self.contract, self.lock,
                        second_evidence, ROOT, second_run)
                with self.assertRaises(ValueError):
                    hosted.validate_phase_ledger_receipt(
                        second_receipt, "discover", self.contract, self.lock,
                        second_evidence, ROOT, first_run)
                hosted.validate_phase_ledger_receipt(
                    first_receipt, "discover", self.contract, self.lock,
                    first_evidence, ROOT, first_run)
            finally:
                first.close()
                second.close()

    def test_release_validation_failure_ends_in_fixed_non_authoritative_row(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger, evidence, run, _, inrelease = self.ledger_fixture(
                Path(directory), full=False)
            try:
                with self.assertRaises(ValueError):
                    ledger.reject_release(
                        "noble", inrelease,
                        packages.EXPECTED_SOURCES[0]["metadata"][
                            "signer_fingerprint"],
                        "index-inventory-rejected")
                with self.assertRaises(ValueError):
                    ledger.reject_release(
                        "noble", inrelease,
                        packages.EXPECTED_SOURCES[0]["metadata"][
                            "signer_fingerprint"],
                        "valid-until-rejected", "sha256-size-syntax")
                with self.assertRaises(ValueError):
                    ledger.reject_release(
                        "noble", inrelease,
                        packages.EXPECTED_SOURCES[0]["metadata"][
                            "signer_fingerprint"],
                        "index-inventory-rejected", {})
                ledger.reject_release(
                    "noble", inrelease,
                    packages.EXPECTED_SOURCES[0]["metadata"][
                        "signer_fingerprint"],
                    "valid-until-rejected")
                hosted.validate_phase_ledger(
                    ledger.value, "discover", self.contract, self.lock,
                    evidence, ROOT, run)
                terminal = ledger.value["phases"][-1]
                self.assertEqual(terminal["kind"], "release-rejected")
                self.assertEqual(
                    terminal["diagnostics"]["inrelease"], inrelease)
                self.assertIsNone(terminal["diagnostics"]["predicate"])
                changed = copy.deepcopy(ledger.value)
                changed["phases"][-1]["diagnostics"].update(
                    reason="index-inventory-rejected")
                with self.assertRaises(ValueError):
                    hosted.validate_phase_ledger(
                        changed, "discover", self.contract, self.lock,
                        evidence, ROOT, run)
                changed["phases"][-1]["diagnostics"].update(
                    predicate={})
                with self.assertRaises(ValueError):
                    hosted.validate_phase_ledger(
                        changed, "discover", self.contract, self.lock,
                        evidence, ROOT, run)
                self.assertFalse(ledger.value["passed"])
                self.assertFalse((evidence / "producer-result.json").exists())
                self.assertEqual(
                    hosted.build.release_rejection_reason(ValueError(
                        "Ubuntu Release Valid-Until is missing or oversized")),
                    "valid-until-rejected")
            finally:
                ledger.close()

        with tempfile.TemporaryDirectory() as directory:
            ledger, evidence, run, _, inrelease = self.ledger_fixture(
                Path(directory), full=False)
            try:
                ledger.reject_release(
                    "noble", inrelease,
                    packages.EXPECTED_SOURCES[0]["metadata"][
                        "signer_fingerprint"],
                    "index-inventory-rejected", "sha256-size-syntax")
                hosted.validate_phase_ledger(
                    ledger.value, "discover", self.contract, self.lock,
                    evidence, ROOT, run)
                terminal = ledger.value["phases"][-1]
                self.assertEqual(
                    terminal["diagnostics"]["predicate"],
                    "sha256-size-syntax")

                legacy = copy.deepcopy(ledger.value)
                legacy["schema"] = hosted.LEGACY_PHASE_LEDGER_SCHEMA
                del legacy["phases"][-1]["diagnostics"]["predicate"]
                hosted.validate_phase_ledger(
                    legacy, "discover", self.contract, self.lock,
                    evidence, ROOT, run)
                legacy["phases"][-1]["diagnostics"]["predicate"] = \
                    "sha256-size-syntax"
                with self.assertRaises(ValueError):
                    hosted.validate_phase_ledger(
                        legacy, "discover", self.contract, self.lock,
                        evidence, ROOT, run)
            finally:
                ledger.close()

    def test_metadata_parser_persists_rejection_before_propagating_failure(self):
        source = copy.deepcopy(packages.EXPECTED_SOURCES[1])
        contract = copy.deepcopy(self.contract)
        contract["freshness_policy"] = [
            hosted.build.expected_freshness_policy(source)]
        contract["metadata_pins"] = [contract["metadata_pins"][1]]
        lock = copy.deepcopy(self.lock)
        lock["sources"] = [source]
        identity = {"bytes": 123, "sha256": "1" * 64}
        status = self.gpg_status(source["metadata"]["signer_fingerprint"])
        release = (
            "Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble-updates\n"
            "Codename: noble\nDate: Thu, 12 Nov 2026 11:00:00 GMT\n"
            "Architectures: amd64\nComponents: main\nSHA256:\n"
            f" {'2' * 64} 1 main/binary-amd64/Packages.xz\n"
        ).encode()

        class Runner:
            def run(self, *_args, **_kwargs):
                return {"timed_out": False, "exit_status": 0}, status, b""

        class Ledger:
            def __init__(self):
                self.calls = []

            def append(self, kind, suite, **kwargs):
                self.calls.append((kind, suite, kwargs))

            def reject_release(self, *args):
                self.calls.append(("reject", *args))

        ledger = Ledger()
        retained = hosted.validate_retained_inputs(
            ROOT, self.contract, self.lock)
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(hosted, "fetch_exact", return_value=identity), \
                mock.patch.object(
                    hosted.packages, "read_bounded_control_file",
                    return_value=release), \
                self.assertRaisesRegex(ValueError, "Date exceeds its age bound"):
            hosted._run_metadata(
                lock, contract, Path(directory), Path(directory), Runner(),
                hosted.datetime(2026, 11, 27, 12, 0,
                                tzinfo=hosted.timezone.utc),
                ROOT / self.contract["retained_inputs"]["archive_keyring"],
                retained["archive_keyring"], ledger)
        self.assertEqual(
            [row[0] for row in ledger.calls],
            ["inrelease-download", "inrelease-signature", "reject"],
        )
        self.assertEqual(ledger.calls[-1][1], "noble-updates")
        self.assertEqual(ledger.calls[-1][2], identity)
        self.assertEqual(
            ledger.calls[-1][-2], "freshness-rejected")
        self.assertIsNone(ledger.calls[-1][-1])

        inventory_release = release.replace(
            b"Date: Thu, 12 Nov 2026 11:00:00 GMT\n",
            b"Date: Fri, 27 Nov 2026 11:00:00 GMT\n",
        ).replace(
            b"Architectures: amd64\n",
            b"Valid-Until: Sat, 28 Nov 2026 12:00:00 GMT\n"
            b"Architectures: amd64\n",
        ).replace(
            b" 1 main/binary-amd64/Packages.xz\n",
            b" 0 main/binary-amd64/Packages.xz\n",
        )
        inventory_ledger = Ledger()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(hosted, "fetch_exact", return_value=identity), \
                mock.patch.object(
                    hosted.packages, "read_bounded_control_file",
                    return_value=inventory_release), \
                self.assertRaisesRegex(
                    hosted.build.ReleaseInventoryRejection,
                    "index size exceeds its bound"):
            hosted._run_metadata(
                lock, contract, Path(directory), Path(directory), Runner(),
                hosted.datetime(2026, 11, 27, 12, 0,
                                tzinfo=hosted.timezone.utc),
                ROOT / self.contract["retained_inputs"]["archive_keyring"],
                retained["archive_keyring"], inventory_ledger)
        self.assertEqual(
            [row[0] for row in inventory_ledger.calls],
            ["inrelease-download", "inrelease-signature", "reject"],
        )
        self.assertEqual(
            inventory_ledger.calls[-1][-2], "index-inventory-rejected")
        self.assertEqual(
            inventory_ledger.calls[-1][-1], "target-index-byte-bound")

    def test_phase_ledger_rejects_mutation_order_duplicates_and_cross_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger, evidence, run, _, _ = self.ledger_fixture(
                Path(directory), full=True)
            try:
                cases = []
                changed = copy.deepcopy(ledger.value)
                changed["phases"][3], changed["phases"][4] = (
                    changed["phases"][4], changed["phases"][3])
                cases.append(changed)
                changed = copy.deepcopy(ledger.value)
                changed["phases"].insert(
                    5, copy.deepcopy(changed["phases"][4]))
                cases.append(changed)
                changed = copy.deepcopy(ledger.value)
                changed["run"]["head_sha"] = "c" * 40
                cases.append(changed)
                changed = copy.deepcopy(ledger.value)
                changed["phases"][4]["commands"][0]["inputs"][0][
                    "sha256"] = "f" * 64
                cases.append(changed)
                changed = copy.deepcopy(ledger.value)
                changed["phases"][3]["payloads"][0]["url"] = (
                    "https://security.ubuntu.com/ubuntu/dists/noble/InRelease")
                cases.append(changed)
                changed = copy.deepcopy(ledger.value)
                changed["phases"][5]["diagnostics"]["freshness_policy"][
                    "signer_fingerprint"] = "A" * 40
                cases.append(changed)
                changed = copy.deepcopy(ledger.value)
                changed["phases"][4]["diagnostics"]["release"][
                    "origin_matches"] = False
                cases.append(changed)
                changed = copy.deepcopy(ledger.value)
                changed["phases"][1]["commands"][0]["timeout_seconds"] += 1
                cases.append(changed)
                for changed in cases:
                    with self.subTest(changed=changed), self.assertRaises(ValueError):
                        hosted.validate_phase_ledger(
                            changed, "discover", self.contract, self.lock,
                            evidence, ROOT, run)
            finally:
                ledger.close()

    def test_ledger_and_result_reject_every_false_authority_claim(self):
        claims = (
            "passed", "authoritative", "selected", "qualified",
            "container_qualified", "signature_qualified", "os_qualified",
            "release_qualified",
        )
        with tempfile.TemporaryDirectory() as directory:
            ledger, evidence, result = self.discovery_result_fixture(
                Path(directory))
            try:
                hosted.validate_result(
                    result, "discover", self.contract, self.lock,
                    evidence, ROOT)
                for claim in claims:
                    changed_ledger = copy.deepcopy(ledger.value)
                    changed_ledger[claim] = True
                    with self.subTest(target="ledger", claim=claim), \
                            self.assertRaises(ValueError):
                        hosted.validate_phase_ledger(
                            changed_ledger, "discover", self.contract,
                            self.lock, evidence, ROOT, result["run"])

                    changed_result = copy.deepcopy(result)
                    changed_result[claim] = True
                    with self.subTest(target="result", claim=claim), \
                            self.assertRaises(ValueError):
                        hosted.validate_result(
                            changed_result, "discover", self.contract,
                            self.lock, evidence, ROOT)
            finally:
                ledger.close()

    def test_phase_ledger_rejects_truncation_unsafe_names_and_publication_race(self):
        run = {
            "id": 123, "attempt": 2, "head_sha": "a" * 40,
            "head_tree": "b" * 40, "workflow": hosted.WORKFLOW,
            "event": "workflow_dispatch",
        }
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            evidence.mkdir(mode=0o700)
            ledger = hosted.PhaseLedger(
                evidence, "discover", self.contract, self.lock, run, ROOT)
            ledger.close()
            (evidence / "phase-ledger.json").write_bytes(b'{"schema":')
            (evidence / "phase-ledger.json").chmod(0o600)
            with self.assertRaises(ValueError):
                hosted.load_phase_ledger(evidence / "phase-ledger.json")
            (evidence / "phase-ledger.json").write_bytes(
                b'{"schema": 1, "schema": 1}')
            with self.assertRaises(ValueError):
                hosted.load_phase_ledger(evidence / "phase-ledger.json")
            os.truncate(
                evidence / "phase-ledger.json",
                hosted.MAX_PHASE_LEDGER_BYTES + 1)
            with self.assertRaises(ValueError):
                hosted.load_phase_ledger(evidence / "phase-ledger.json")

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            evidence.mkdir(mode=0o700)
            temporary = evidence / "phase-ledger.new"
            temporary.write_bytes(b"occupied")
            temporary.chmod(0o600)
            with self.assertRaises(ValueError):
                hosted.PhaseLedger(
                    evidence, "discover", self.contract, self.lock, run, ROOT)
            self.assertEqual(temporary.read_bytes(), b"occupied")

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            evidence.mkdir(mode=0o700)
            final = evidence / "phase-ledger.json"
            final.write_bytes(b"occupied")
            final.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "unexpected state"):
                hosted.PhaseLedger(
                    evidence, "discover", self.contract, self.lock, run, ROOT)
            self.assertEqual(final.read_bytes(), b"occupied")

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            evidence.mkdir(mode=0o700)
            target = evidence / "target"
            target.write_bytes(b"target")
            target.chmod(0o600)
            (evidence / "phase-ledger.json").symlink_to(target)
            with self.assertRaises(ValueError):
                hosted.PhaseLedger(
                    evidence, "discover", self.contract, self.lock, run, ROOT)
            self.assertTrue((evidence / "phase-ledger.json").is_symlink())

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            evidence.mkdir(mode=0o700)
            ledger = hosted.PhaseLedger(
                evidence, "discover", self.contract, self.lock, run, ROOT)
            real_rename = hosted._renameat2
            raced = False

            def race(source_fd, source_name, destination_fd,
                     destination_name, flags):
                nonlocal raced
                if flags == hosted._RENAME_EXCHANGE and not raced:
                    raced = True
                    replacement = evidence / "replacement"
                    replacement.write_bytes(b"raced\n")
                    replacement.chmod(0o600)
                    os.replace(replacement, evidence / "phase-ledger.json")
                return real_rename(
                    source_fd, source_name, destination_fd,
                    destination_name, flags)

            try:
                with mock.patch.object(hosted, "_renameat2", side_effect=race), \
                        self.assertRaisesRegex(ValueError, "raced publication"):
                    ledger._persist()
            finally:
                ledger.close()

    def test_phase_ledger_nonblocking_reader_rejects_unsafe_node_types(self):
        run = {
            "id": 123, "attempt": 2, "head_sha": "a" * 40,
            "head_tree": "b" * 40, "workflow": hosted.WORKFLOW,
            "event": "workflow_dispatch",
        }

        def make_node(evidence, name, kind):
            path = evidence / name
            handle = None
            if kind == "fifo":
                os.mkfifo(path, 0o600)
            elif kind == "socket":
                handle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    handle.bind(str(path))
                except BaseException:
                    handle.close()
                    raise
            else:
                target = evidence / (name + "-target")
                target.write_bytes(b"retained")
                target.chmod(0o600)
                if kind == "hardlink":
                    os.link(target, path)
                else:
                    path.symlink_to(target.name)
            return path, handle

        def assert_rejected(operation, *, bounded):
            previous = None

            def blocked(*_):
                raise TimeoutError("unsafe FIFO open blocked")

            if bounded:
                previous = signal.signal(signal.SIGALRM, blocked)
                signal.setitimer(signal.ITIMER_REAL, 1.0)
            try:
                with self.assertRaises(ValueError):
                    operation()
            finally:
                if bounded:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    signal.signal(signal.SIGALRM, previous)

        for name, operation_name in (
                ("phase-ledger.json", "final"),
                ("phase-ledger.new", "temporary")):
            for kind in ("fifo", "hardlink", "symlink", "socket"):
                with self.subTest(path=operation_name, kind=kind), \
                        tempfile.TemporaryDirectory() as directory:
                    evidence = Path(directory) / "evidence"
                    evidence.mkdir(mode=0o700)
                    node, handle = make_node(evidence, name, kind)

                    def construct():
                        ledger = hosted.PhaseLedger(
                            evidence, "discover", self.contract, self.lock,
                            run, ROOT)
                        ledger.close()

                    try:
                        assert_rejected(construct, bounded=kind == "fifo")
                        self.assertTrue(node.exists() or node.is_symlink())
                    finally:
                        if handle is not None:
                            handle.close()

        for kind in ("fifo", "hardlink", "symlink", "socket"):
            with self.subTest(load=kind), \
                    tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory) / "evidence"
                evidence.mkdir(mode=0o700)
                node, handle = make_node(
                    evidence, "phase-ledger.json", kind)
                try:
                    assert_rejected(
                        lambda: hosted.load_phase_ledger(node),
                        bounded=kind == "fifo")
                finally:
                    if handle is not None:
                        handle.close()

        for name, operation in (
                ("phase-ledger.json", "final"),
                ("phase-ledger.new", "temporary"),
                ("phase-ledger.json", "load")):
            with self.subTest(device=operation), \
                    tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory) / "evidence"
                evidence.mkdir(mode=0o700)
                path = evidence / name
                path.write_bytes(b"device-shaped")
                path.chmod(0o600)
                real_fstat = hosted.os.fstat

                def device_fstat(descriptor):
                    info = real_fstat(descriptor)
                    if hosted.stat.S_ISREG(info.st_mode):
                        return mock.Mock(st_mode=hosted.stat.S_IFCHR | 0o600)
                    return info

                with mock.patch.object(
                        hosted.os, "fstat", side_effect=device_fstat), \
                        self.assertRaises(ValueError):
                    if operation == "load":
                        hosted.load_phase_ledger(path)
                    else:
                        hosted.PhaseLedger(
                            evidence, "discover", self.contract, self.lock,
                            run, ROOT)

    def test_phase_ledger_publication_interruptions_remain_fail_closed(self):
        for interruption in (
                "partial-write", "file-fsync", "rename", "directory-fsync"):
            with self.subTest(interruption=interruption), \
                    tempfile.TemporaryDirectory() as directory:
                ledger, evidence, run, _, _ = self.ledger_fixture(
                    Path(directory), full=False)
                before_value = copy.deepcopy(ledger.value)
                source = packages.EXPECTED_SOURCES[0]
                release = (
                    "Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble\n"
                    "Codename: noble\nDate: now\nSHA256:\n"
                ).encode()
                release_diagnostics = hosted.build.signed_release_diagnostics(
                    release, source)
                next_diagnostics = {
                    "freshness_policy": hosted.build.expected_freshness_policy(
                        source),
                    "release": {
                        "bytes": release_diagnostics["bytes"],
                        "sha256": release_diagnostics["sha256"],
                    },
                    "index": {
                        "path": "main/binary-amd64/Packages.xz",
                        "bytes": 201,
                        "sha256": format(11, "064x"),
                    },
                }
                real_fsync = hosted.os.fsync
                real_write = hosted.os.write
                write_calls = 0

                def interrupted_write(descriptor, value):
                    nonlocal write_calls
                    write_calls += 1
                    if write_calls == 1:
                        count = max(1, len(value) // 2)
                        return real_write(descriptor, value[:count])
                    raise OSError("injected partial write interruption")

                def interrupted_fsync(descriptor):
                    if (interruption == "file-fsync"
                            and descriptor != ledger.fd):
                        raise OSError("injected file fsync interruption")
                    if (interruption == "directory-fsync"
                            and descriptor == ledger.fd):
                        raise OSError("injected directory fsync interruption")
                    return real_fsync(descriptor)

                try:
                    if interruption == "partial-write":
                        context = mock.patch.object(
                            hosted.os, "write",
                            side_effect=interrupted_write)
                    elif interruption == "rename":
                        context = mock.patch.object(
                            hosted, "_renameat2",
                            side_effect=OSError("injected rename interruption"))
                    else:
                        context = mock.patch.object(
                            hosted.os, "fsync", side_effect=interrupted_fsync)
                    with context, self.assertRaises(OSError):
                        ledger.append(
                            "release-validated", "noble",
                            diagnostics=next_diagnostics)
                    after_value = copy.deepcopy(ledger.value)
                    self.assertEqual(
                        after_value["phases"][:-1], before_value["phases"])
                    self.assertEqual(
                        after_value["phases"][-1]["kind"],
                        "release-validated")
                    hosted.validate_phase_ledger(
                        before_value, "discover", self.contract, self.lock,
                        evidence, ROOT, run)
                    hosted.validate_phase_ledger(
                        after_value, "discover", self.contract, self.lock,
                        evidence, ROOT, run)
                    expected = after_value if interruption == "directory-fsync" \
                        else before_value
                    observed = hosted.load_phase_ledger(
                        evidence / "phase-ledger.json")
                    self.assertEqual(observed, expected)
                    expected_raw = (
                        json.dumps(expected, indent=2, sort_keys=True) + "\n"
                    ).encode()
                    self.assertEqual(
                        (evidence / "phase-ledger.json").read_bytes(),
                        expected_raw)
                    self.assertFalse((evidence / "phase-ledger.new").exists())
                    self.assertFalse((evidence / "producer-result.json").exists())
                    self.assertFalse((evidence / "discovery.json").exists())
                finally:
                    ledger.close()

    def test_command_evidence_reopens_tools_and_raw_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            row = self.command_fixture(base)
            with mock.patch.object(
                    hosted, "_tool_record", return_value=row["tool"]):
                hosted.validate_command_result(base, row)
            cases = []
            changed = copy.deepcopy(row)
            changed["extra"] = "caller field"
            cases.append(changed)
            changed = copy.deepcopy(row)
            changed["timed_out"] = 0
            cases.append(changed)
            changed = copy.deepcopy(row)
            changed["tool"]["sha256"] = "0" * 64
            cases.append(changed)
            changed = copy.deepcopy(row)
            changed["stderr"]["sha256"] = "1" * 64
            cases.append(changed)
            changed = copy.deepcopy(row)
            changed["inputs"] = [{
                "name": "input", "bytes": True, "sha256": "2" * 64,
            }]
            cases.append(changed)
            for unsafe_name in (
                    "SHA256SUMS.gpg", "../checksum", "checksum/signature",
                    "checksum signature"):
                changed = copy.deepcopy(row)
                changed["inputs"][0]["name"] = unsafe_name
                cases.append(changed)
            changed = copy.deepcopy(row)
            changed["inputs"].append(copy.deepcopy(changed["inputs"][0]))
            cases.append(changed)
            for changed in cases:
                with self.subTest(changed=changed), \
                        mock.patch.object(
                            hosted, "_tool_record", return_value=row["tool"]), \
                    self.assertRaises(ValueError):
                    hosted.validate_command_result(base, changed)

    def test_production_result_binds_phase_hashes_and_download_totals(self):
        def phase(stdout, stderr):
            return {
                "stdout": {"sha256": hashlib.sha256(stdout).hexdigest()},
                "stderr": {"sha256": hashlib.sha256(stderr).hexdigest()},
            }

        commands = {
            "apt-update": phase(b"update", b""),
            "apt-uris": phase(b"uris", b"warnings"),
            "apt-simulate": phase(b"simulation", b""),
            "dpkg-no-act": phase(b"dpkg", b""),
        }
        order = ["1" * 64, "2" * 64]
        manifest = {
            "package_count": 2,
            "package_bytes": 123,
            "download_order": order,
            "command_hashes": {
                "apt_update": hosted._phase_hash(commands["apt-update"]),
                "apt_uri_plan": hosted._phase_hash(commands["apt-uris"]),
                "apt_simulation": hosted._phase_hash(commands["apt-simulate"]),
                "dpkg_plan": hosted._phase_hash(commands["dpkg-no-act"]),
            },
        }
        download = {
            "count": 2,
            "bytes": 123,
            "order_sha256": hashlib.sha256(
                ("\n".join(order) + "\n").encode()).hexdigest(),
        }
        hosted._validate_production_bindings(manifest, commands, download)
        cases = []
        changed = copy.deepcopy(manifest)
        changed["command_hashes"]["apt_update"] = "0" * 64
        cases.append((changed, commands, download))
        changed_download = copy.deepcopy(download)
        changed_download["bytes"] += 1
        cases.append((manifest, commands, changed_download))
        changed = copy.deepcopy(manifest)
        changed["download_order"].reverse()
        cases.append((changed, commands, download))
        changed_commands = copy.deepcopy(commands)
        changed_commands["dpkg-no-act"]["stderr"]["sha256"] = "3" * 64
        cases.append((manifest, changed_commands, download))
        for candidate, rows, observed in cases:
            with self.subTest(candidate=candidate, observed=observed), \
                    self.assertRaises(ValueError):
                hosted._validate_production_bindings(
                    candidate, rows, observed)

    def test_systemd_fallback_always_records_swap_and_oom_state(self):
        oom = self.systemd_result(
            Result="oom-kill", ExecMainCode="2", ExecMainStatus="9")
        result = hosted.systemd_fallback_record(oom)
        self.assertEqual(set(result), hosted.SYSTEMD_FALLBACK_FIELDS)
        self.assertEqual(result["schema"], hosted.SYSTEMD_FALLBACK_SCHEMA)
        self.assertFalse(result["authoritative"])
        self.assertTrue(result["measurement_available"])
        self.assertTrue(result["zero_swap"])
        self.assertTrue(result["oom_observed"])
        self.assertTrue(result["oom_auditable"])
        self.assertIsNone(result["error"])

        not_found = hosted.systemd_fallback_record(self.systemd_result(
            LoadState="not-found", Result="success", ExecMainCode="0",
            MemoryCurrent="[not set]", MemoryPeak="[not set]",
            MemoryMax="infinity", MemorySwapCurrent="[not set]",
            MemorySwapPeak="[not set]", MemorySwapMax="infinity",
            CPUQuotaPerSecUSec="infinity", CPUQuotaPeriodUSec="infinity",
            CPUUsageNSec="[not set]", TasksCurrent="[not set]",
            TasksMax="16666", RuntimeMaxUSec="infinity"))
        self.assertFalse(not_found["measurement_available"])
        self.assertFalse(not_found["zero_swap"])
        self.assertFalse(not_found["oom_observed"])
        self.assertFalse(not_found["oom_auditable"])
        self.assertIn("measurement is unavailable", not_found["error"])

        unknown = hosted.systemd_fallback_record(
            b"systemctl show failed with status 1\n")
        self.assertFalse(unknown["measurement_available"])
        self.assertFalse(unknown["zero_swap"])
        self.assertFalse(unknown["oom_observed"])
        self.assertFalse(unknown["oom_auditable"])
        self.assertIn("systemctl show failed", unknown["error"])
        for malformed in (
                oom + b"Result=success\n",
                b"bad key=value\n",
                b"Result=\xff\n"):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                hosted.systemd_fallback_record(malformed)

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            systemd = base / "systemd-result.txt"
            primary = base / "cgroup-final.json"
            fallback = base / "systemd-fallback.json"
            systemd.write_bytes(oom)
            primary.write_bytes(b"{")
            os.chmod(systemd, 0o600)
            os.chmod(primary, 0o600)
            hosted.write_systemd_fallback(systemd, fallback)
            self.assertEqual(primary.read_bytes(), b"{")
            self.assertTrue(json.loads(fallback.read_text())["oom_observed"])

    def test_post_unit_records_use_primary_swap_authority(self):
        cgroup = {
            "schema": 1,
            "limits": copy.deepcopy(hosted.EXPECTED_LIMITS),
            "counters": {
                "memory.max": str(hosted.EXPECTED_LIMITS["memory_max"]),
                "memory.swap.max": "0",
                "memory.current": "1",
                "memory.peak": "1",
                "memory.swap.current": "0",
                "memory.swap.peak": "0",
                "memory.events": (
                    "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"
                    "oom_group_kill 0"
                ),
                "cpu.max": hosted.EXPECTED_LIMITS["cpu_max"],
                "cpu.stat": "usage_usec 1",
                "pids.max": str(hosted.EXPECTED_LIMITS["pids_max"]),
                "pids.current": "1",
                "pids.peak": "1",
            },
            "zero_swap": True,
            "error": None,
        }
        fallback = hosted.systemd_fallback_record(self.systemd_result(
            LoadState="not-found", Result="success", ExecMainCode="0",
            MemoryCurrent="[not set]", MemoryPeak="[not set]",
            MemoryMax="infinity", MemorySwapCurrent="[not set]",
            MemorySwapPeak="[not set]", MemorySwapMax="infinity",
            CPUQuotaPerSecUSec="infinity", CPUQuotaPeriodUSec="infinity",
            CPUUsageNSec="[not set]", TasksCurrent="[not set]",
            TasksMax="16666", RuntimeMaxUSec="infinity"))
        cleanup = {
            "schema": 1,
            "mode": "discover",
            "producer_exit_status": 0,
            "private_work_retained": True,
            "recursive_path_cleanup_performed": False,
            "candidate_present": False,
            "post_unit_candidate_validated": False,
            "selected": False,
            "qualified": False,
        }
        self.assertFalse(fallback["measurement_available"])
        self.assertFalse(fallback["oom_auditable"])
        self.assertFalse(fallback["zero_swap"])
        self.assertTrue(hosted.validate_post_unit_records(
            cgroup, fallback, cleanup))

        failed_cleanup = copy.deepcopy(cleanup)
        failed_cleanup["producer_exit_status"] = 1
        with self.assertRaises(ValueError):
            hosted.validate_post_unit_records(
                cgroup, fallback, failed_cleanup)

        for field, value in (
                ("measurement_available", True),
                ("oom_auditable", True),
                ("oom_observed", True),
                ("error", "caller supplied")):
            changed = copy.deepcopy(fallback)
            changed[field] = value
            with self.subTest(inconsistent_claim=field), \
                    self.assertRaises(ValueError):
                hosted.validate_post_unit_records(cgroup, changed, cleanup)

        loaded = hosted.systemd_fallback_record(self.systemd_result())
        self.assertTrue(loaded["measurement_available"])
        self.assertTrue(loaded["oom_auditable"])
        self.assertTrue(hosted.validate_post_unit_records(
            cgroup, loaded, cleanup))
        changed = copy.deepcopy(loaded)
        changed["oom_auditable"] = False
        with self.assertRaises(ValueError):
            hosted.validate_post_unit_records(cgroup, changed, cleanup)

        for field, value in (
                ("memory.swap.max", "1"),
                ("memory.swap.current", "1"),
                ("memory.swap.peak", "1")):
            changed = copy.deepcopy(cgroup)
            changed["counters"][field] = value
            changed["zero_swap"] = False
            with self.subTest(field=field), self.assertRaises(ValueError):
                hosted.validate_post_unit_records(changed, fallback, cleanup)
        for field in (
                "memory.swap.max", "memory.swap.current", "memory.swap.peak"):
            changed = copy.deepcopy(cgroup)
            del changed["counters"][field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                hosted.validate_post_unit_records(changed, fallback, cleanup)

        oom = hosted.systemd_fallback_record(self.systemd_result(
            Result="oom-kill", ExecMainCode="2", ExecMainStatus="9"))
        with self.assertRaises(ValueError):
            hosted.validate_post_unit_records(cgroup, oom, cleanup)

        for field in (
                "MemorySwapMax", "MemorySwapCurrent", "MemorySwapPeak"):
            swap = {
                "MemorySwapMax": "0",
                "MemorySwapCurrent": "0",
                "MemorySwapPeak": "0",
            }
            swap[field] = "1"
            nonzero = hosted.systemd_fallback_record(
                self.systemd_result(**swap))
            with self.subTest(fallback_nonzero=field), \
                    self.assertRaises(ValueError):
                hosted.validate_post_unit_records(cgroup, nonzero, cleanup)

    def test_retention_rejects_same_uid_directory_replacement_without_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            paths = {}
            identities = {}
            for name in ("evidence", "output", "work"):
                path = base / name
                path.mkdir(mode=0o700)
                paths[name] = path
                info = path.stat()
                identities[name] = f"{info.st_dev}:{info.st_ino}"
            result = hosted.write_retention_record(
                paths["evidence"], identities["evidence"],
                paths["output"], identities["output"],
                paths["work"], identities["work"],
                "discover", 1, False)
            self.assertTrue(result["private_work_retained"])
            self.assertFalse(result["recursive_path_cleanup_performed"])
            self.assertTrue(paths["work"].is_dir())

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            paths = {}
            identities = {}
            for name in ("evidence", "output", "work"):
                path = base / name
                path.mkdir(mode=0o700)
                paths[name] = path
                info = path.stat()
                identities[name] = f"{info.st_dev}:{info.st_ino}"
            original = base / "original-work"
            paths["work"].rename(original)
            paths["work"].mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "identity changed"):
                hosted.write_retention_record(
                    paths["evidence"], identities["evidence"],
                    paths["output"], identities["output"],
                    paths["work"], identities["work"],
                    "discover", 1, False)
            self.assertTrue(original.is_dir())
            self.assertTrue(paths["work"].is_dir())
            self.assertFalse((paths["evidence"] / "cleanup.json").exists())

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            paths = {}
            identities = {}
            for name in ("evidence", "output", "work"):
                path = base / name
                path.mkdir(mode=0o700)
                paths[name] = path
                info = path.stat()
                identities[name] = f"{info.st_dev}:{info.st_ino}"
            retained_evidence = base / "retained-evidence"
            original_open = hosted._open_exact_private_directory

            def swap_after_open(path, identity, description):
                descriptor = original_open(path, identity, description)
                if description == "Ubuntu producer evidence directory":
                    paths["evidence"].rename(retained_evidence)
                    paths["evidence"].mkdir(mode=0o700)
                return descriptor

            with mock.patch.object(
                    hosted, "_open_exact_private_directory",
                    side_effect=swap_after_open):
                hosted.write_retention_record(
                    paths["evidence"], identities["evidence"],
                    paths["output"], identities["output"],
                    paths["work"], identities["work"],
                    "discover", 1, False)
            self.assertTrue((retained_evidence / "cleanup.json").is_file())
            self.assertEqual(list(paths["evidence"].iterdir()), [])
            self.assertTrue(paths["evidence"].is_dir())

    def test_workflow_is_manual_and_candidate_upload_is_production_only(self):
        path = ROOT / ".github/workflows/ubuntu-fixture-packages.yml"
        document = yaml.safe_load(path.read_text())
        self.assertEqual(set(document[True]), {"workflow_dispatch"})
        self.assertEqual(document["permissions"], {"contents": "read"})
        self.assertEqual(document["jobs"]["packages"]["runs-on"], "ubuntu-24.04")
        steps = document["jobs"]["packages"]["steps"]
        candidate = next(
            step for step in steps
            if step.get("name") == "Retain the validated unselected package candidate")
        self.assertEqual(
            candidate["if"], "${{ success() && inputs.mode == 'produce' }}")
        self.assertEqual(
            candidate["with"]["name"], packages.ARTIFACT_NAME)
        evidence = next(
            step for step in steps
            if step.get("name", "").startswith("Retain raw authenticated"))
        self.assertEqual(evidence["if"], "always()")

    def test_wrapper_has_exact_limits_zero_swap_and_no_network_phases(self):
        path = ROOT / "scripts/check-container-ubuntu-package-producer.sh"
        subprocess.run(["bash", "-n", str(path)], check=True)
        text = path.read_text()
        for value in (
                "--property=MemoryMax=2147483648",
                "--property=MemorySwapMax=0",
                "--property=CPUQuota=100%",
                "--property=CPUQuotaPeriodSec=100ms",
                "--property=TasksMax=128",
                "--property=RuntimeMaxSec=3000",
                "--property=TimeoutStopSec=30s",
                "--property=KillMode=control-group",
                "--property=OOMPolicy=kill",
                "--property=PrivateTmp=yes",
                "--property=ProtectSystem=strict",
                "--property=ProtectHome=read-only",
                "--property=RestrictNamespaces=yes",
                "--property=CapabilityBoundingSet=",
                "--property=AmbientCapabilities=",
                "--property=RestrictNamespaces=net",
                "--property=CapabilityBoundingSet=CAP_SYS_ADMIN",
                "--property=AmbientCapabilities=CAP_SYS_ADMIN",
                "--property=ReadWritePaths=$cache",
                "validate_post_unit_records(cgroup, fallback, cleanup)"):
            self.assertIn(value, text)
        self.assertNotIn('fallback["zero_swap"] is True', text)
        self.assertNotIn(" +  ", text)
        self.assertNotIn("rm -rf", text)
        self.assertNotIn("chown -R", text)
        self.assertNotIn('if [[ ! -e "$evidence/cgroup-final.json"', text)
        self.assertIn('if [[ "$mode" == discover ]]', text)
        self.assertIn("systemd-fallback.json", text)
        self.assertIn(
            'sudo systemd-run "${systemd_args[@]}" /usr/bin/env -i '
            '"${clean_env[@]}" "${producer_argv[@]}"', text)
        self.assertIn(
            'env -i "PATH=/usr/bin:/bin" "HOME=$HOME" "LANG=C.UTF-8" '
            '"LC_ALL=C.UTF-8" "PYTHONDONTWRITEBYTECODE=1" '
            '"${validation_argv[@]}"', text)
        self.assertIn('verify_direct_directory "$work" "$cache"', text)
        self.assertIn("resource-fallback --systemd", text)
        module = (
            ROOT / "image/container/ubuntu_fixture_package_hosted.py"
        ).read_text()
        self.assertIn('launcher_path = "/usr/bin/unshare"', module)
        self.assertIn('"--net", "--", executable', module)
        self.assertIn("download_package_plan", module)
        self.assertIn("offline_dpkg_command", module)
        self.assertIn(
            'cleanup.get("post_unit_candidate_validated") is production',
            module)
        self.assertIn(
            'cleanup.get("recursive_path_cleanup_performed") is False',
            module)


if __name__ == "__main__":
    unittest.main()
