"""Offline configuration/inspection checks, not container execution evidence."""
import copy
import importlib.util
import hashlib
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "image/qualification"))


class ContainerEvidence(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("containers", ROOT / "image/qualification/containers.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.info = {"CgroupVersion": "2", "CgroupDriver": "systemd", "LiveRestoreEnabled": False,
                     "Runtimes": {"runc": {}, "runsc": {"path": "/usr/bin/runsc"}},
                     "DefaultRuntime": "runc", "SecurityOptions": ["name=selinux", "name=seccomp,profile=builtin"]}
        self.container = {"Image": "sha256:" + "a" * 64, "Config": {"User": "65534:65534"},
                          "HostConfig": {"Runtime": "runsc", "NetworkMode": "none", "Privileged": False,
                                         "ReadonlyRootfs": True, "CapDrop": ["ALL"], "CapAdd": [],
                                         "SecurityOpt": ["no-new-privileges=true"], "Memory": 268435456,
                                         "MemorySwap": 268435456, "NanoCpus": 500000000, "PidsLimit": 32,
                                         "IpcMode": "private", "CgroupnsMode": "private",
                                         "PidMode": "", "UTSMode": "",
                                         "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16777216"},
                                         "Binds": [], "LogConfig": {"Type": "none"}}, "Mounts": []}

    def fixture_report(self, driver="test-filesystem-grants.py", backend="runc"):
        expected_runtime = {"runc": "runc", "runsc": "runsc"}[backend]
        expected_backend = {"runc": "docker", "runsc": "gvisor"}[backend]
        cases = []
        for index, name in enumerate(self.module.SUPPORTED_CASES[driver]):
            workers = [] if index else [{"runtime": expected_runtime}]
            cases.append({"name": name, "passed": True, "workers": workers})
        result = {
            "passed": True,
            "backend": expected_backend,
            "binary_sha256": "b" * 64,
            "driver_sha256": "d" * 64,
            "image": "sha256:" + "c" * 64,
            "cases": cases,
            "remaining_workers": [],
            "remaining_leases": [],
            "provider_errors": [],
        }
        if backend == "runsc":
            result["runsc"] = {
                "path": "/usr/bin/runsc",
                "registered_path": "/usr/bin/runsc",
                "sha256": "e" * 64,
                "mode": 0o755,
            }
        return result

    def escape_payload(self):
        return {
            "passed": True,
            "uid": 65534,
            "gid": 65534,
            "docker_socket_visible": False,
            "cases": [
                {"name": name, "passed": True} for name in self.module.ESCAPE_CASES
            ],
        }

    def test_complete_synthetic_inspection_passes(self):
        self.module.validate_daemon(self.info)
        self.module.validate_container(self.container, "runsc", self.container["Image"])

    def test_daemon_cannot_drop_required_controls(self):
        for field, value in [("CgroupVersion", "1"), ("LiveRestoreEnabled", True),
                             ("SecurityOptions", []), ("Runtimes", {"runc": {}}),
                             ("DefaultRuntime", "runsc")]:
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.info)
                candidate[field] = value
                with self.assertRaises(ValueError):
                    self.module.validate_daemon(candidate)

    def test_container_cannot_weaken_inspected_boundary(self):
        for field, value in [("Runtime", "runc"), ("NetworkMode", "bridge"), ("Privileged", True),
                             ("ReadonlyRootfs", False), ("Memory", 0), ("MemorySwap", -1),
                             ("NanoCpus", 0), ("PidsLimit", 0), ("CapAdd", ["SYS_ADMIN"]),
                             ("SecurityOpt", []), ("SecurityOpt", ["no-new-privileges=true", "seccomp=unconfined"]),
                             ("IpcMode", "host"), ("CgroupnsMode", "host"), ("PidMode", "host"),
                             ("UTSMode", "host"), ("Tmpfs", {})]:
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.container)
                candidate["HostConfig"][field] = value
                with self.assertRaises(ValueError):
                    self.module.validate_container(candidate, "runsc", self.container["Image"])

    def test_wrong_image_root_user_and_host_mount_fail(self):
        for field, value in [("Image", "sha256:" + "b" * 64), ("Config", {"User": "0:0"}),
                             ("Mounts", [{"Type": "bind", "Source": "/", "Destination": "/host"}])]:
            candidate = copy.deepcopy(self.container)
            candidate[field] = value
            with self.assertRaises(ValueError):
                self.module.validate_container(candidate, "runsc", self.container["Image"])

    def test_selected_daemon_configuration_is_deterministic(self):
        import json
        config = json.loads((ROOT / "image/container/daemon.json").read_text())
        self.assertIs(config["live-restore"], False)
        self.assertIs(config["selinux-enabled"], True)
        self.assertIs(config["no-new-privileges"], True)
        self.assertEqual(config["runtimes"]["runsc"]["path"], "/usr/bin/runsc")
        self.assertNotIn("hosts", config)

    def test_retained_daemon_metadata_excludes_proxy_credentials(self):
        self.info["HTTPProxy"] = "http://user:synthetic-secret@example.invalid"
        retained = self.module.retained_daemon_info(self.info)
        self.assertNotIn("HTTPProxy", retained)
        self.assertEqual(retained["CgroupVersion"], "2")

    def test_boot_status_uses_the_fixed_output_only_socket(self):
        source = (ROOT / "image/qualification/containers.py").read_text()
        self.assertIn('parser.add_argument("--bootc-status-socket", type=Path)', source)
        self.assertIn("validate_status_socket(args.bootc_status_socket)", source)
        self.assertEqual(source.count("read_bootc_status(args.bootc_status_socket)"), 2)
        self.assertNotIn('command_output(["bootc", "status", "--json"])', source)

    def test_runtime_and_reviewed_fixture_sources_are_separate_exact_inputs(self):
        source = (ROOT / "image/qualification/containers.py").read_text()
        self.assertIn('parser.add_argument("--fixture-source", type=Path)', source)
        self.assertIn('image/container/native-fixture.lock.json', source)
        self.assertIn('validate_source(fixture_source, fixture_revision)', source)
        self.assertIn('fixture_plan(fixture_source, binary, args.fixture_ref, output)', source)

    def test_exact_six_driver_backend_runs_are_planned(self):
        plan = self.module.fixture_plan(Path("/source"), Path("/usr/bin/symbi"),
                                        "registry.invalid/fixture@sha256:" + "f" * 64,
                                        Path("/evidence"))
        self.assertEqual(
            [(item["backend"], item["driver"]) for item in plan],
            [(backend, driver) for backend in ("runc", "runsc")
             for driver in self.module.FIXTURE_DRIVERS],
        )
        self.assertEqual(len(plan), 6)
        for item in plan[:3]:
            self.assertNotIn("--gvisor", item["command"])
        for item in plan[3:]:
            self.assertIn("--gvisor", item["command"])
            self.assertEqual(item["command"][-2:], ["--runsc-binary", "/usr/bin/runsc"])

    def test_supported_case_inventory_is_exact(self):
        self.assertEqual(self.module.SUPPORTED_CASES, {
            "test-filesystem-grants.py": (
                "granted", "undeclared", "parser", "oversize", "existing", "symlink",
                "nested", "descendant", "substitution",
            ),
            "test-source-broker.py": (
                "read", "list", "grep", "traversal", "symlink", "hardlink",
                "no_ceiling", "denied", "scratch",
            ),
            "test-git-source.py": (
                "log", "staged", "diff", "status", "sha256", "snapshot", "denied",
                "alternates", "pointer", "oversize", "extension", "capacity",
                "prepare_crash", "crash",
            ),
        })

    def test_controller_escape_negative_inventory_is_exact(self):
        self.assertEqual(self.module.ESCAPE_CASES, (
            "direct_network", "dns_tunnel", "abstract_unix", "external_signal",
            "proc_ptrace", "uinput", "pipewire_capture", "ssh_read",
        ))
        effects = {"tcp": False, "udp": False, "abstract": False,
                   "pipewire": False}
        self.module.validate_escape_payload(self.escape_payload(), "runsc", effects)

    def test_controller_escape_negatives_reject_changed_case_effect_or_identity(self):
        effects = {"tcp": False, "udp": False, "abstract": False,
                   "pipewire": False}
        variants = []
        changed = self.escape_payload()
        changed["cases"] = changed["cases"][:-1]
        variants.append((changed, effects))
        changed = self.escape_payload()
        changed["cases"][0]["name"] = "changed"
        variants.append((changed, effects))
        changed = self.escape_payload()
        changed["cases"][2]["passed"] = False
        variants.append((changed, effects))
        changed = self.escape_payload()
        changed["uid"] = 0
        variants.append((changed, effects))
        changed = self.escape_payload()
        changed["docker_socket_visible"] = True
        variants.append((changed, effects))
        changed_effects = dict(effects, udp=True)
        variants.append((self.escape_payload(), changed_effects))
        for payload, observed in variants:
            with self.subTest(payload=payload, effects=observed), self.assertRaises(ValueError):
                self.module.validate_escape_payload(payload, "runsc", observed)

    def test_controller_observer_private_paths_are_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            stack, controls = self.module._listener_controls(output)
            pipewire = Path(controls["pipewire_path"])
            private = Path(controls["ssh_canary"]).parents[1]
            self.assertTrue(pipewire.exists())
            self.assertTrue(Path(controls["ssh_canary"]).is_file())
            stack.close()
            self.assertFalse(pipewire.exists())
            self.assertFalse(private.exists())

    def test_compact_evidence_never_promotes_narrow_negatives_to_qualification(self):
        runs = []
        for backend in ("runc", "runsc"):
            for driver in self.module.FIXTURE_DRIVERS:
                runs.append({
                    "backend": backend, "driver": driver, "passed": True,
                    "cleanup_confirmed": True, "driver_sha256": "1" * 64,
                    "report_sha256": "2" * 64,
                    "observed_runtimes": [self.module.BACKENDS[backend]["runtime"]],
                    "cases": list(self.module.SUPPORTED_CASES[driver]),
                })
        report = {
            "passed": True, "native_fixture_matrix_passed": True,
            "controller_escape_negatives_passed": True,
            "runtime_revision": "3" * 40, "source_tree": "4" * 40,
            "binary_sha256": "5" * 64, "fixture_source_revision": "6" * 40,
            "fixture_source_tree": "7" * 40, "fixture_source_lock_sha256": "8" * 64,
            "fixture_ref": "example.invalid/fixture@sha256:" + "9" * 64,
            "fixture_id": "sha256:" + "a" * 64, "runsc_sha256": "b" * 64,
            "image_ref": "example.invalid/os@sha256:" + "c" * 64,
            "deployment_sha256": "d" * 64, "bootc_before_sha256": "e" * 64,
            "bootc_after_sha256": "f" * 64, "runs": runs,
            "escape_negatives": {
                backend: {"passed": True, "cleanup_confirmed": True,
                          "positive_controls": True,
                          "observer_effects": {"tcp": False, "udp": False,
                                               "abstract": False, "pipewire": False},
                          "cases": list(self.module.ESCAPE_CASES),
                          "report_sha256": "0" * 64}
                for backend in ("runc", "runsc")
            },
        }
        evidence = self.module.compact_evidence(report)
        self.assertTrue(evidence["passed"])
        self.assertTrue(evidence["native_fixture_matrix_passed"])
        self.assertTrue(evidence["controller_escape_negatives_passed"])
        self.assertFalse(evidence["managed_route_qualified"])
        self.assertFalse(evidence["escape_suite_qualified"])
        self.assertFalse(evidence["signature_qualified"])
        self.assertFalse(evidence["review_complete"])
        self.assertFalse(evidence["qualified"])
        self.assertEqual(evidence["remaining_blockers"], [
            "managed-route-evidence", "escape-suite-evidence", "required-review",
        ])

    def test_probe_cleanup_uses_owned_names_even_when_create_is_uncertain(self):
        source = (ROOT / "image/qualification/containers.py").read_text()
        self.assertIn('removed = docker_call(env, "rm", "--force", name, check=False)', source)
        self.assertEqual(source.count('"name=^/" + name + "$"'), 2)
        self.assertNotIn('"--pid=private"', source)

    def test_complete_fixture_report_binds_cases_runtime_and_hashes(self):
        report = self.fixture_report()
        observed = self.module.validate_fixture_result(
            report, "test-filesystem-grants.py", "runc", "b" * 64,
            "d" * 64, "sha256:" + "c" * 64, "e" * 64,
        )
        self.assertEqual(observed, ["runc"])

        report = self.fixture_report(backend="runsc")
        observed = self.module.validate_fixture_result(
            report, "test-filesystem-grants.py", "runsc", "b" * 64,
            "d" * 64, "sha256:" + "c" * 64, "e" * 64,
        )
        self.assertEqual(observed, ["runsc"])

    def test_fixture_report_rejects_short_extra_or_duplicate_case_sets(self):
        original = self.fixture_report()
        variants = []
        candidate = copy.deepcopy(original)
        candidate["cases"].pop()
        variants.append(candidate)
        candidate = copy.deepcopy(original)
        candidate["cases"].append({"name": "unsupported", "passed": True, "workers": []})
        variants.append(candidate)
        candidate = copy.deepcopy(original)
        candidate["cases"][-1]["name"] = candidate["cases"][0]["name"]
        variants.append(candidate)
        for candidate in variants:
            with self.subTest(names=[case["name"] for case in candidate["cases"]]):
                with self.assertRaises(ValueError):
                    self.module.validate_fixture_result(
                        candidate, "test-filesystem-grants.py", "runc", "b" * 64,
                        "d" * 64, "sha256:" + "c" * 64, "e" * 64,
                    )

    def test_fixture_report_rejects_wrong_or_missing_runtime_observation(self):
        for runtime in ("runsc", None):
            candidate = self.fixture_report()
            candidate["cases"][0]["workers"] = ([] if runtime is None else [{"runtime": runtime}])
            with self.subTest(runtime=runtime), self.assertRaises(ValueError):
                self.module.validate_fixture_result(
                    candidate, "test-filesystem-grants.py", "runc", "b" * 64,
                    "d" * 64, "sha256:" + "c" * 64, "e" * 64,
                )

    def test_fixture_report_rejects_remaining_or_failed_state(self):
        changes = [
            ("remaining_workers", ["worker"]),
            ("remaining_leases", ["lease"]),
            ("provider_errors", ["error"]),
            ("passed", False),
        ]
        for field, value in changes:
            candidate = self.fixture_report()
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.module.validate_fixture_result(
                    candidate, "test-filesystem-grants.py", "runc", "b" * 64,
                    "d" * 64, "sha256:" + "c" * 64, "e" * 64,
                )

    def test_fixture_report_rejects_changed_bindings_and_runsc_registration(self):
        changes = [
            ("binary_sha256", "0" * 64),
            ("driver_sha256", "0" * 64),
            ("image", "sha256:" + "0" * 64),
            ("backend", "gvisor"),
        ]
        for field, value in changes:
            candidate = self.fixture_report()
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.module.validate_fixture_result(
                    candidate, "test-filesystem-grants.py", "runc", "b" * 64,
                    "d" * 64, "sha256:" + "c" * 64, "e" * 64,
                )
        for field, value in (("sha256", "0" * 64), ("registered_path", "/tmp/runsc"),
                             ("mode", 0o777)):
            candidate = self.fixture_report(backend="runsc")
            candidate["runsc"][field] = value
            with self.subTest(runsc_field=field), self.assertRaises(ValueError):
                self.module.validate_fixture_result(
                    candidate, "test-filesystem-grants.py", "runsc", "b" * 64,
                    "d" * 64, "sha256:" + "c" * 64, "e" * 64,
                )

    def test_run_record_requires_empty_container_state_and_exact_report_hash(self):
        report = self.fixture_report()
        raw = (self.module.json.dumps(report, sort_keys=True) + "\n").encode()
        expected = hashlib.sha256(raw).hexdigest()
        record = {"passed": True, "cleanup_confirmed": True,
                  "remaining_containers": [], "report_sha256": expected,
                  "observed_runtimes": ["runc"]}
        self.module.validate_run_record(record, raw, "runc")
        for field, value in (("passed", False), ("cleanup_confirmed", False),
                             ("remaining_containers", ["a" * 64]),
                             ("report_sha256", "0" * 64),
                             ("observed_runtimes", ["runsc"])):
            candidate = copy.deepcopy(record)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.module.validate_run_record(candidate, raw, "runc")

    def test_fixture_report_reader_rejects_duplicate_keys_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"passed":true,"passed":true}\n')
            with self.assertRaises(ValueError):
                self.module.read_fixture_result(duplicate)
            regular = root / "regular.json"
            regular.write_text('{"passed":true}\n')
            linked = root / "linked.json"
            linked.symlink_to(regular.name)
            with self.assertRaises((ValueError, OSError)):
                self.module.read_fixture_result(linked)


if __name__ == "__main__":
    unittest.main()
