"""Fail-closed tests for the manual Ubuntu package producer."""
import copy
import hashlib
import json
import os
from pathlib import Path
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
        self.assertEqual(self.contract["state"], "pending-discovery")
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
        oom = (
            b"Result=oom-kill\nMemorySwapMax=0\nMemorySwapCurrent=0\n"
            b"MemorySwapPeak=0\nExecMainStatus=137\n"
        )
        result = hosted.systemd_fallback_record(oom)
        self.assertEqual(set(result), hosted.SYSTEMD_FALLBACK_FIELDS)
        self.assertTrue(result["zero_swap"])
        self.assertTrue(result["oom_observed"])
        self.assertTrue(result["oom_auditable"])

        unknown = hosted.systemd_fallback_record(
            b"systemctl show failed with status 1\n")
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
                "post_unit_candidate_validated",
                'cgroup["zero_swap"] is True'):
            self.assertIn(value, text)
        self.assertNotIn(" +  ", text)
        self.assertNotIn("rm -rf", text)
        self.assertNotIn("chown -R", text)
        self.assertNotIn('if [[ ! -e "$evidence/cgroup-final.json"', text)
        self.assertIn('if [[ "$mode" == discover ]]', text)
        self.assertIn("systemd-fallback.json", text)
        self.assertIn("recursive_path_cleanup_performed", text)
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


if __name__ == "__main__":
    unittest.main()
