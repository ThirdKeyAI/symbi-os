"""Offline acceptance tests for P0-05 Moby and gVisor image inputs."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


class ContainerRuntimeInputs(unittest.TestCase):
    @classmethod
    def module(cls):
        spec = importlib.util.spec_from_file_location(
            "container_runtime_inputs", ROOT / "image/container/runtime_inputs.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def make_archive(self, path, entries):
        rows = {}
        with tarfile.open(path, "w") as archive:
            for name, kind, body, mode in entries:
                item = tarfile.TarInfo(name)
                item.type = kind
                item.mode = mode
                item.uid = item.gid = 0
                item.mtime = 946684800
                if kind == tarfile.REGTYPE:
                    item.size = len(body)
                    archive.addfile(item, io.BytesIO(body))
                    rows.setdefault(name, {
                        "kind": "regular", "bytes": len(body), "mode": mode,
                        "uid": 0, "gid": 0, "mtime": 946684800,
                        "sha256": hashlib.sha256(body).hexdigest(),
                    })
                elif kind == tarfile.DIRTYPE:
                    archive.addfile(item)
                    rows.setdefault(name, {
                        "kind": "directory", "mode": mode,
                        "uid": 0, "gid": 0, "mtime": 946684800,
                    })
                else:
                    item.linkname = body.decode()
                    archive.addfile(item)
        return {
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "sha512": hashlib.sha512(path.read_bytes()).hexdigest(),
            "members": rows,
        }

    def test_real_release_is_exact_complete_and_unselected(self):
        mod = self.module()
        pins = mod.load_pins()
        self.assertEqual(pins["release"]["tag"], "release-20261123.1")
        self.assertEqual(
            pins["release"]["commit"],
            "81f68cb7d4661a9313d891a1758a765abe8eb27e",
        )
        self.assertEqual(
            pins["release"]["tag_object"],
            "c04644c3a80cda69a57070e14f2e9f71445f36e4",
        )
        self.assertIs(pins["release"]["tag_signed"], False)
        self.assertIs(pins["release"]["github_attestation_found"], False)
        self.assertIs(pins["selected"], False)
        self.assertIs(pins["security_qualified"], False)
        self.assertIs(pins["os_qualified"], False)
        self.assertEqual(pins["archive"]["bytes"], 84944091)
        self.assertEqual(
            pins["archive"]["sha256"],
            "95c23cd8eda66eab351717e5ee2b1a5703f848bb73ac855a7b281e1c6cd178e8",
        )
        self.assertEqual(len(pins["archive"]["members"]), 10)
        self.assertEqual(
            pins["archive"]["members"]["runsc"]["sha256"],
            "540c5824b3df0786a7a12ce06c9c9b0e05447a4543bcd859dd6b34bf67b218fb",
        )
        self.assertIn("gvisor-bin/gvisor_sentry", pins["archive"]["members"])

    def test_exact_archive_is_inventoried_and_extracted_without_execution(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = base / "gvisor.tar"
            entries = [
                ("gvisor-bin", tarfile.DIRTYPE, b"", 0o755),
                ("runsc", tarfile.REGTYPE, b"runsc fixture\n", 0o755),
                ("gvisor-bin/gvisor_sentry", tarfile.REGTYPE, b"sentry fixture\n", 0o755),
            ]
            pins = {"archive": self.make_archive(archive, entries)}
            observed = mod.inspect_archive(archive, pins)
            self.assertEqual(observed, pins["archive"]["members"])
            destination = base / "payload"
            extracted = mod.extract_archive(archive, pins, destination)
            self.assertEqual(extracted, observed)
            self.assertEqual((destination / "runsc").read_bytes(), b"runsc fixture\n")
            self.assertEqual((destination / "runsc").stat().st_mode & 0o777, 0o755)
            self.assertEqual(
                (destination / "gvisor-bin/gvisor_sentry").read_bytes(),
                b"sentry fixture\n",
            )
            with self.assertRaises(ValueError):
                mod.extract_archive(archive, pins, destination)

    def test_archive_rejects_aliases_links_special_files_modes_and_changed_bytes(self):
        mod = self.module()
        faults = [
            [("../runsc", tarfile.REGTYPE, b"x", 0o755)],
            [("gvisor-bin//runsc", tarfile.REGTYPE, b"x", 0o755)],
            [("runsc", tarfile.SYMTYPE, b"gvisor-bin/gvisor_sentry", 0o755)],
            [("runsc", tarfile.LNKTYPE, b"gvisor-bin/gvisor_sentry", 0o755)],
            [("runsc", tarfile.FIFOTYPE, b"", 0o755)],
            [("runsc", tarfile.REGTYPE, b"x", 0o4755)],
            [
                ("runsc", tarfile.REGTYPE, b"first", 0o755),
                ("runsc", tarfile.REGTYPE, b"second", 0o755),
            ],
        ]
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "gvisor.tar"
            for entries in faults:
                pins = {"archive": self.make_archive(archive, entries)}
                with self.subTest(entries=entries), self.assertRaises(ValueError):
                    mod.inspect_archive(archive, pins)
            valid = [("runsc", tarfile.REGTYPE, b"one", 0o755)]
            pins = {"archive": self.make_archive(archive, valid)}
            self.make_archive(archive, [("runsc", tarfile.REGTYPE, b"two", 0o755)])
            with self.assertRaises(ValueError):
                mod.inspect_archive(archive, pins)

    def test_checksum_list_is_exact_and_duplicate_safe(self):
        mod = self.module()
        values = {
            "gvisor-aarch64.tar.bz2": "1" * 128,
            "gvisor-aarch64.tar.zstd": "2" * 128,
            "gvisor-x86_64.tar.bz2": "3" * 128,
            "gvisor-x86_64.tar.zstd": "4" * 128,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SHA512SUMS"
            path.write_text("".join(f"{value}  {name}\n" for name, value in values.items()))
            pins = {
                "checksums": {
                    "bytes": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "entries": values,
                }
            }
            self.assertEqual(mod.inspect_checksums(path, pins), values)
            path.write_text(path.read_text() + f"{'4' * 128}  gvisor-x86_64.tar.zstd\n")
            pins["checksums"]["bytes"] = path.stat().st_size
            pins["checksums"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):
                mod.inspect_checksums(path, pins)

    def test_fedora_runtime_profile_is_separate_and_heavy_jobs_are_manual_or_main(self):
        requirements = json.loads(
            (ROOT / "image/container/runtime-requirements.json").read_text())
        self.assertEqual(requirements["profile"], "container-runtime")
        self.assertEqual(
            requirements["source_inputs"], "image/container/gvisor-inputs.json")
        self.assertIn("moby-engine", requirements["packages"])
        self.assertIn("docker-cli", requirements["packages"])
        self.assertIn("container-selinux", requirements["packages"])
        spec = importlib.util.spec_from_file_location(
            "package_inventory", ROOT / "image/hyprland/package_inventory.py")
        inventory = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inventory)
        self.assertEqual(
            inventory.requirements_input(ROOT, "container-runtime"),
            "image/container/runtime-requirements.json",
        )
        wrapper = (ROOT / "scripts/check-fedora-packages.sh").read_text()
        self.assertIn("container-runtime", wrapper)
        self.assertFalse((ROOT / ".github/workflows/container-packages.yml").exists())
        workflow_path = ROOT / ".github/workflows/fedora-packages.yml"
        workflow = workflow_path.read_text()
        document = yaml.safe_load(workflow)
        triggers = document[True]
        profile = triggers["workflow_dispatch"]["inputs"]["profile"]
        self.assertEqual(profile["type"], "choice")
        self.assertEqual(profile["default"], "hyprland")
        self.assertEqual(profile["options"], ["hyprland", "container-runtime"])
        self.assertEqual(triggers["push"]["branches"], ["main"])
        job = document["jobs"]["packages"]
        selected = job["env"]["SYMBI_FEDORA_PACKAGE_PROFILE"]
        self.assertEqual(
            selected,
            "${{ github.event_name == 'workflow_dispatch' && inputs.profile || 'hyprland' }}",
        )
        self.assertIn("inputs.profile == 'container-runtime'", document["concurrency"]["group"])
        command = next(step["run"] for step in job["steps"]
                       if step["name"] == "Authenticate and resolve Fedora build inputs without installation")
        self.assertIn('case "$SYMBI_FEDORA_PACKAGE_PROFILE" in', command)
        self.assertIn("hyprland|container-runtime", command)
        self.assertIn('bash scripts/check-fedora-packages.sh "$SYMBI_FEDORA_PACKAGE_PROFILE"', command)
        self.assertNotIn("${{ inputs.profile }}", command)
        artifact_names = [step["with"]["name"] for step in job["steps"]
                          if step.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertTrue(all("inputs.profile == 'container-runtime'" in name
                            for name in artifact_names))
        self.assertIn("contents: read", workflow)

        intake_workflow = (ROOT / ".github/workflows/gvisor-intake.yml").read_text()
        self.assertIn("branches: [main]", intake_workflow)
        self.assertIn("workflow_dispatch:", intake_workflow)
        self.assertNotIn('branches: ["**"]', intake_workflow)
        self.assertNotIn("pull_request:", intake_workflow)
        self.assertIn("contents: read", intake_workflow)

        intake_wrapper = (ROOT / "scripts/check-gvisor-intake.sh").read_text()
        for required in (
                '--uid="$(id -u)"', "MemoryMax=512M", "MemorySwapMax=0",
                "CPUQuota=100%", "TasksMax=32", "NoNewPrivileges=yes",
                "CapabilityBoundingSet=", "ProtectSystem=strict", "PrivateTmp=yes",
                'pipeline_status=("${PIPESTATUS[@]}")'):
            self.assertIn(required, intake_wrapper)
        intake = (ROOT / "image/container/intake.py").read_text()
        self.assertNotIn("extract_archive(", intake)
        self.assertIn('"archive_extracted": False', intake)
        self.assertIn('"candidate_executed": False', intake)

    def test_daemon_uses_fixed_explicit_runsc_without_runtime_installer(self):
        daemon = json.loads((ROOT / "image/container/daemon.json").read_text())
        self.assertEqual(daemon["default-runtime"], "runc")
        self.assertEqual(daemon["runtimes"]["runsc"]["path"], "/usr/bin/runsc")
        self.assertIs(daemon["no-new-privileges"], True)
        self.assertIs(daemon["selinux-enabled"], True)
        self.assertNotIn("hosts", daemon)
        combined = "\n".join(
            path.read_text()
            for path in (
                ROOT / "image/container/runtime_inputs.py",
                ROOT / "image/container/intake.py",
                ROOT / "scripts/check-gvisor-intake.sh",
            )
        )
        self.assertNotIn("runsc install", combined)
        self.assertNotIn("release/latest", combined)

    def test_package_wrapper_rejects_profile_injection_before_hosted_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "injected"
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/check-fedora-packages.sh"),
                 "container-runtime; touch " + str(marker)],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr.strip(), "Unknown package discovery profile.")
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
