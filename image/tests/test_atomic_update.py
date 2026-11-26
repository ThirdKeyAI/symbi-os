"""Contracts for the signed installed-image update and booted rollback gate."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from image.atomic.update_contract import (NEGATIVE_UPDATE_SOURCE, POSITIVE_OVERLAY_CASE,
                                          update_policy,
                                          update_command, rollback_command,
                                          negative_signature_payloads,
                                          validate_report, require_update_base,
                                          validate_artifact_metadata)
from image.atomic.update_boot import (qemu_command, negative_qemu_command,
                                      positive_qemu_command,
                                      firmware_arguments,
                                      validate_negative_report,
                                      validate_positive_report,
                                      validate_shared_baseline)
from image.atomic.update_process import TIMEOUT_SECONDS, validate_update_controller_command
from image.atomic.update_guest import (phase_status, deployment_snapshot,
                                       staged_deployment_snapshot)
from image.atomic.update_hosted import run_update


class AtomicUpdateTests(unittest.TestCase):
    def test_hosted_controller_imports(self):
        self.assertTrue(callable(run_update))

    old = "sha256:" + "1" * 64
    new = "sha256:" + "2" * 64

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
                         {"/var/lib/symbi-update/source", NEGATIVE_UPDATE_SOURCE})
        rule = result["transports"]["dir"]["/var/lib/symbi-update/source"][0]
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
        self.assertEqual(switch[:3], ["/usr/bin/bootc", "switch", "--transport"])
        self.assertIn("--enforce-container-sigpolicy", switch)
        self.assertEqual(switch[-1], "/var/lib/symbi-update/source")
        self.assertEqual(rollback_command(), ["/usr/bin/bootc", "rollback"])
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
        self.assertIn("file=/output/guest.qcow2,format=qcow2,if=virtio", joined)
        self.assertNotIn("snapshot=on", joined)
        self.assertIn("file=/inputs/update.raw,format=raw,if=virtio,readonly=on", joined)
        self.assertIn("-net none", joined)
        self.assertIn("phase-1.json", joined)
        firmware = firmware_arguments()
        self.assertIn("systemd.extra-unit.o.service", " ".join(firmware))
        self.assertIn("fstab.extra", " ".join(firmware))

    def test_each_bootc_rejection_uses_a_distinct_disposable_overlay(self):
        commands = {case: negative_qemu_command(case) for case in (
            "unsigned", "wrong-key", "wrong-reference", "altered-signature")}
        for case, command in commands.items():
            joined = " ".join(command)
            self.assertIn(f"file=/output/negative-{case}.qcow2,format=qcow2,if=virtio", joined)
            self.assertIn(f"path=/output/negative-{case}.json", joined)
            self.assertIn(f"file=/inputs/expected-{case}.json", joined)
            self.assertIn("file=/inputs/update.raw,format=raw,if=virtio,readonly=on", joined)
            self.assertNotIn("file=/output/guest.qcow2", joined)
        self.assertEqual(len({tuple(command) for command in commands.values()}), 4)
        positive = " ".join(positive_qemu_command())
        self.assertIn("file=/output/same-path-positive.qcow2,format=qcow2,if=virtio", positive)
        self.assertIn("path=/output/same-path-positive.json", positive)
        self.assertIn("file=/inputs/expected-positive.json", positive)
        self.assertNotIn("file=/output/guest.qcow2", positive)
        self.assertNotIn("file=/output/negative-", positive)
        with self.assertRaises(ValueError):
            negative_qemu_command("caller-selected")

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

    def positive_report(self):
        switch = update_command(NEGATIVE_UPDATE_SOURCE)
        return {
            "schema": 1, "passed": True, "guest_booted": True,
            "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
            "nonce": "4" * 32, "expected_sha256": "5" * 64,
            "runner_sha256": "6" * 64, "source_mounted_readonly": True,
            "same_path_positive_control": {
                "case": POSITIVE_OVERLAY_CASE, "switch_accepted": True,
                "switch_exit_code": 0, "booted_unchanged": True,
                "deployment_staged": True, "default_changed": True,
                "staged_digest": self.new, "state_before_sha256": "3" * 64,
                "state_after_sha256": "7" * 64,
                "source": NEGATIVE_UPDATE_SOURCE, "source_readonly": True,
            },
            "commands": [
                {"command": ["/usr/bin/bootc", "status", "--json"], "exit_code": 0},
                {"command": switch, "exit_code": 0},
                {"command": ["/usr/bin/bootc", "status", "--json"], "exit_code": 0},
            ],
        }

    def test_same_path_positive_report_binds_success_and_controlled_state(self):
        expected = {"nonce": "4" * 32, "new_digest": self.new}
        report = self.positive_report()
        validate_positive_report(report, expected, "5" * 64, "6" * 64)
        validate_shared_baseline(report, self.negative_report())
        mutations = []
        changed = copy.deepcopy(report)
        changed["commands"][1]["exit_code"] = 1
        changed["same_path_positive_control"]["switch_exit_code"] = 1
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["same_path_positive_control"]["state_after_sha256"] = "3" * 64
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["same_path_positive_control"]["source"] = "/tmp/other"
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_positive_report(changed, expected, "5" * 64, "6" * 64)
        negative = self.negative_report()
        negative["negative_control"]["state_sha256"] = "9" * 64
        with self.assertRaises(ValueError):
            validate_shared_baseline(report, negative)

    def negative_report(self, case="unsigned"):
        switch = update_command(NEGATIVE_UPDATE_SOURCE)
        state_hash = "3" * 64
        return {
            "schema": 1, "passed": True, "guest_booted": True,
            "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
            "nonce": "4" * 32, "expected_sha256": "5" * 64,
            "runner_sha256": "6" * 64, "source_mounted_readonly": True,
            "negative_control": {
                "case": case, "switch_rejected": True, "switch_exit_code": 1,
                "deployment_unchanged": True, "default_unchanged": True,
                "state_sha256": state_hash, "source": NEGATIVE_UPDATE_SOURCE,
                "source_readonly": True,
            },
            "commands": [
                {"command": ["/usr/bin/bootc", "status", "--json"], "exit_code": 0},
                {"command": switch, "exit_code": 1},
                {"command": ["/usr/bin/bootc", "status", "--json"], "exit_code": 0},
            ],
        }

    def test_negative_report_requires_failed_real_switch_and_unchanged_state(self):
        report = self.negative_report()
        validate_negative_report(report, {"nonce": "4" * 32}, "5" * 64,
                                 "6" * 64, "unsigned")
        mutations = []
        changed = copy.deepcopy(report)
        changed["commands"][1]["exit_code"] = 0
        changed["negative_control"]["switch_exit_code"] = 0
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["negative_control"]["deployment_unchanged"] = False
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["commands"][1]["command"][-1] = "/tmp/other"
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_negative_report(changed, {"nonce": "4" * 32},
                                         "5" * 64, "6" * 64, "unsigned")

    def test_update_service_and_mount_are_bounded_and_offline(self):
        root = Path(__file__).resolve().parents[2]
        settings = dict(line.split("=", 1) for line in
                        (root / "image/atomic/update-o.service").read_text().splitlines()
                        if "=" in line and not line.startswith("#"))
        self.assertEqual(settings["RequiresMountsFor"], "/var/lib/symbi-update/source")
        self.assertEqual(settings["StateDirectory"], "symbi-update-test")
        self.assertEqual(settings["PrivateMounts"], "yes")
        self.assertEqual(settings["MemorySwapMax"], "0")
        self.assertEqual(settings["TasksMax"], "128")
        mount = (root / "image/atomic/update-fstab.extra").read_text().split()
        self.assertEqual(mount[:3], ["LABEL=SYMBIUPDATE", "/var/lib/symbi-update", "ext4"])
        self.assertEqual(set(mount[3].split(",")), {"ro", "nosuid", "nodev", "noexec"})

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
