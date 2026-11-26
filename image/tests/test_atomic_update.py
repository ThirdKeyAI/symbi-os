"""Contracts for the signed installed-image update and booted rollback gate."""
import copy
import json
from pathlib import Path
import unittest

from image.atomic.update_contract import (update_policy, update_command,
                                          rollback_command, validate_report,
                                          require_update_base,
                                          validate_artifact_metadata)
from image.atomic.update_boot import qemu_command, firmware_arguments
from image.atomic.update_guest import phase_status
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

    def status(self, booted, staged=None, rollback=None, queued=False):
        return {"apiVersion": "org.containers.bootc/v1", "kind": "BootcHost",
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
                         {"/var/lib/symbi-update/source"})
        rule = result["transports"]["dir"]["/var/lib/symbi-update/source"][0]
        self.assertEqual(rule["type"], "signedBy")
        self.assertEqual(rule["signedIdentity"]["dockerReference"],
                         "localhost/symbi-ci/development@" + self.new)
        self.assertNotIn("insecureAcceptAnything", json.dumps(result))

    def test_update_and_rollback_commands_keep_signature_enforcement(self):
        switch = update_command()
        self.assertEqual(switch[:3], ["/usr/bin/bootc", "switch", "--transport"])
        self.assertIn("--enforce-container-sigpolicy", switch)
        self.assertEqual(switch[-1], "/var/lib/symbi-update/source")
        self.assertEqual(rollback_command(), ["/usr/bin/bootc", "rollback"])
        forbidden = {"--target-no-signature-verification", "--disable-selinux",
                     "--allow-missing-verity"}
        self.assertFalse(forbidden.intersection(switch))

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
        self.assertIn("qualification=='landlock'", hosted)
        self.assertIn("qualification=='update'", hosted)

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

    def test_missing_phase_or_signature_control_fails(self):
        cases = []
        report = self.report()
        report["phases"].pop()
        cases.append(report)
        report = self.report()
        report["source_authentication"]["negative_controls"]["unsigned"] = False
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
