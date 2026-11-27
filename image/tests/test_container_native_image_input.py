"""Offline mutation tests for the derived Fedora container image consumer."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from image.container import native_image_inputs as inputs


ROOT = Path(__file__).resolve().parents[2]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class ContainerNativeImageInput(unittest.TestCase):
    def setUp(self):
        self.pending = json.loads(
            (ROOT / "image/container/fedora-runtime-image.lock.json").read_text())
        images = json.loads((ROOT / "image/desktop-images.lock.json").read_text())
        pins = json.loads((ROOT / "image/base-images.json").read_text())
        from image.boot.inputs import require_desktop_image
        source_manifest = require_desktop_image(images, pins, "generic")
        self.source_commit = images["images"]["generic"]["tested_commit"]
        self.source_image_id = source_manifest["archive"]["image_id"]
        self.hosted_environment = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REPOSITORY": "ThirdKeyAI/symbi-os",
            "GITHUB_SHA": "6" * 40,
            "GITHUB_RUN_ID": "900",
            "GITHUB_RUN_ATTEMPT": "2",
        }

    def ready_fixture(self, directory):
        directory = Path(directory)
        contract_raw = json.dumps({"schema": 1, "packages": []}, sort_keys=True).encode() + b"\n"
        archive_raw = b"small inert OCI fixture"
        archive = {
            "name": "symbi-container-runtime-generic.oci.tar.gz",
            "bytes": len(archive_raw),
            "sha256": digest(archive_raw),
            "image_id": "sha256:" + "1" * 64,
            "manifest_digest": "sha256:" + "2" * 64,
        }
        selection = copy.deepcopy(self.pending)
        selection.update(state="selected", selected=True)
        selection["workflow"]["id"] = 123
        selection["producer"].update(
            run_id=456,
            run_attempt=1,
            head_sha="3" * 40,
            head_branch="card/P0-05-installed-image",
            status="completed",
            conclusion="success",
        )
        manifest = {
            "schema": 1,
            "built": True,
            "installed": True,
            "qualified": False,
            "os_qualified": False,
            "release_qualified": False,
            "signature_qualified": False,
            "variant": "generic",
            "source_commit": selection["producer"]["head_sha"],
            "source_image_commit": self.source_commit,
            "source_image_id": self.source_image_id,
            "archive": archive,
            "contract_sha256": digest(contract_raw),
            "scope": inputs.MANIFEST_SCOPE,
        }
        manifest_raw = json.dumps(manifest, indent=2).encode() + b"\n"
        selection["manifest"] = {
            "sha256": digest(manifest_raw),
            "contract_sha256": digest(contract_raw),
            "archive": archive,
        }
        bundle = directory / "candidate.zip"
        with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_STORED) as output:
            for name, raw in (
                ("manifest.json", manifest_raw),
                ("fedora-runtime.lock.json", contract_raw),
                (archive["name"], archive_raw),
            ):
                row = zipfile.ZipInfo(name)
                row.external_attr = (stat.S_IFREG | 0o600) << 16
                output.writestr(row, raw)
        selection["artifact"].update(
            id=789, bytes=bundle.stat().st_size, sha256=inputs.sha256(bundle))
        run = {
            "id": 456,
            "run_attempt": 1,
            "event": "workflow_dispatch",
            "path": inputs.PRODUCER_WORKFLOW,
            "workflow_id": 123,
            "head_sha": "3" * 40,
            "head_branch": "card/P0-05-installed-image",
            "status": "completed",
            "conclusion": "success",
            "repository": inputs.REPOSITORY,
            "head_repository": inputs.REPOSITORY,
        }
        metadata = {
            "id": 789,
            "name": inputs.ARTIFACT_NAME,
            "size_in_bytes": bundle.stat().st_size,
            "digest": "sha256:" + inputs.sha256(bundle),
            "expired": False,
            "workflow_run": {
                "id": 456,
                "head_sha": "3" * 40,
                "repository_id": inputs.REPOSITORY["id"],
                "head_repository_id": inputs.REPOSITORY["id"],
            },
        }
        return selection, run, metadata, bundle, manifest

    def test_committed_slot_is_pending_and_cannot_select_unavailable_output(self):
        status = inputs.validate_candidate_selection(self.pending)
        self.assertFalse(status["ready"])
        self.assertEqual(status["blocker"], "pending-container-runtime-image")
        self.assertFalse(self.pending["selected"])
        self.assertFalse(self.pending["signature_qualified"])
        self.assertIsNone(self.pending["producer"]["run_id"])
        self.assertIsNone(self.pending["artifact"]["id"])
        self.assertIsNone(self.pending["manifest"]["sha256"])

    def test_exact_run_artifact_bundle_contract_and_generic_variant_are_consumed(self):
        with tempfile.TemporaryDirectory() as directory:
            selection, run, metadata, bundle, manifest = self.ready_fixture(directory)
            proposed = inputs.propose_candidate_selection(
                self.pending, run, metadata, bundle,
                validate_contract=lambda contract, source_commit, source_image_id: None,
            )
            self.assertEqual(proposed, selection)
            destination = Path(directory) / "output"
            calls = []
            observed = inputs.consume_candidate_bundle(
                bundle, selection, run, metadata, destination,
                validate_contract=lambda contract, source_commit, source_image_id: calls.append(
                    (contract, source_commit, source_image_id)),
            )
            self.assertEqual(observed["manifest"], manifest)
            self.assertEqual(
                observed["selection_canonical_sha256"],
                inputs.canonical_sha256(selection),
            )
            self.assertEqual(calls, [(
                {"schema": 1, "packages": []}, self.source_commit,
                self.source_image_id,
            )])
            self.assertEqual(
                inputs.sha256(destination / manifest["archive"]["name"]),
                manifest["archive"]["sha256"],
            )
            self.assertEqual(
                inputs.sha256(destination / "fedora-runtime.lock.json"),
                manifest["contract_sha256"],
            )

    def test_wrong_run_head_artifact_hash_signature_or_variant_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            selection, run, metadata, bundle, _ = self.ready_fixture(directory)
            mutations = []
            changed = copy.deepcopy(run); changed["id"] += 1
            mutations.append(("run", changed, metadata, selection, bundle))
            changed = copy.deepcopy(run); changed["head_sha"] = "0" * 40
            mutations.append(("head", changed, metadata, selection, bundle))
            changed = copy.deepcopy(metadata); changed["id"] += 1
            mutations.append(("artifact", run, changed, selection, bundle))
            changed = copy.deepcopy(metadata); changed["digest"] = "sha256:" + "0" * 64
            mutations.append(("metadata-hash", run, changed, selection, bundle))
            changed = copy.deepcopy(selection); changed["signature_qualified"] = True
            mutations.append(("signature", run, metadata, changed, bundle))
            changed = copy.deepcopy(selection); changed["variant"] = "nvidia"
            mutations.append(("variant", run, metadata, changed, bundle))
            for label, candidate_run, candidate_metadata, candidate_selection, candidate_bundle in mutations:
                with self.subTest(label=label), self.assertRaises(ValueError):
                    inputs.consume_candidate_bundle(
                        candidate_bundle, candidate_selection, candidate_run,
                        candidate_metadata, Path(directory) / ("output-" + label),
                        validate_contract=lambda contract, source_commit, source_image_id: None,
                    )
            tampered = Path(directory) / "tampered.zip"
            tampered.write_bytes(bundle.read_bytes() + b"tamper")
            with self.assertRaises(ValueError):
                inputs.consume_candidate_bundle(
                    tampered, selection, run, metadata,
                    Path(directory) / "output-zip-hash",
                    validate_contract=lambda contract, source_commit, source_image_id: None,
                )

    def test_generated_manifest_cannot_claim_signature_or_change_variant(self):
        with tempfile.TemporaryDirectory() as directory:
            selection, _, _, _, manifest = self.ready_fixture(directory)
            contract_raw = json.dumps(
                {"schema": 1, "packages": []}, sort_keys=True).encode() + b"\n"
            for field, value in (("signature_qualified", True), ("variant", "nvidia")):
                with self.subTest(field=field):
                    changed = copy.deepcopy(manifest)
                    changed[field] = value
                    manifest_raw = json.dumps(changed, indent=2).encode() + b"\n"
                    changed_selection = copy.deepcopy(selection)
                    changed_selection["manifest"]["sha256"] = digest(manifest_raw)
                    with self.assertRaises(ValueError):
                        inputs.validate_generated_manifest(
                            changed, manifest_raw, contract_raw, changed_selection)

    def test_caller_paths_remain_lexical_and_links_or_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cache = root / ".cache"
            cache.mkdir()
            expected = {
                "bundle": cache / "container-runtime-development-image.zip",
                "run_metadata": cache / "container-runtime-image-run.json",
                "artifact_metadata": cache / "container-runtime-image-artifact.json",
                "destination": cache / "container-runtime-native-inputs",
                "evidence": cache / "container-runtime-native-evidence",
            }
            for name in ("bundle", "run_metadata", "artifact_metadata"):
                expected[name].write_bytes(b"fixture")
            expected["evidence"].mkdir()
            actual = inputs.validate_consumer_paths(root, **expected)
            self.assertEqual(actual, expected)
            linked = root / "linked.zip"
            linked.symlink_to(expected["bundle"])
            self.assertEqual(inputs.absolute_without_dereference(linked), linked)
            with self.assertRaises(ValueError):
                inputs.validate_consumer_paths(root, **{**expected, "bundle": linked})
            linked_parent = root / "linked-cache"
            linked_parent.symlink_to(cache, target_is_directory=True)
            with self.assertRaises(ValueError):
                inputs.validate_consumer_paths(
                    root, **{**expected, "destination": linked_parent / "new"})
            with self.assertRaises(ValueError):
                inputs.validate_consumer_paths(
                    root, **{**expected, "destination": cache / ".." / "outside"})

    def test_hosted_context_refuses_local_wrong_unit_limits_or_identity(self):
        unit = "symbi-container-input-900-2.service"
        context = inputs.validate_hosted_context(
            self.hosted_environment, 1000, unit, inputs.HOSTED_LIMITS)
        self.assertEqual(context["run_id"], 900)
        self.assertEqual(context["run_attempt"], 2)
        faults = [
            ({**self.hosted_environment, "GITHUB_ACTIONS": "false"}, 1000, unit,
             inputs.HOSTED_LIMITS),
            (self.hosted_environment, 0, unit, inputs.HOSTED_LIMITS),
            (self.hosted_environment, 1000, "user.slice", inputs.HOSTED_LIMITS),
            (self.hosted_environment, 1000, unit,
             {**inputs.HOSTED_LIMITS, "memory.max": "unlimited"}),
        ]
        for environment, euid, group, limits in faults:
            with self.subTest(group=group, euid=euid), self.assertRaises(ValueError):
                inputs.validate_hosted_context(environment, euid, group, limits)

    def test_pretransfer_retains_pending_disk_and_transfer_failure_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "image/container").mkdir(parents=True)
            (root / "image/container/fedora-runtime-image.lock.json").write_text(
                json.dumps(self.pending) + "\n")
            (root / ".cache").mkdir()
            with self.assertRaises(ValueError):
                inputs.prepare_transfer(
                    root, self.hosted_environment,
                    available_bytes=inputs.PRE_TRANSFER_REQUIRED_BYTES + 1)
            record_path = root / ".cache/container-runtime-native-evidence/pre-transfer.json"
            record = json.loads(record_path.read_text())
            self.assertFalse(record["passed"])
            self.assertEqual(record["blocker"], "pending-container-runtime-image")
            self.assertEqual(record["disk"]["required_bytes"],
                             inputs.PRE_TRANSFER_REQUIRED_BYTES)
            inputs.record_transfer_failure(
                root, self.hosted_environment, "run-metadata", 22)
            failed = json.loads(record_path.read_text())
            self.assertEqual(failed["transfer"]["stage"], "run-metadata")
            self.assertEqual(failed["transfer"]["exit_code"], 22)
            self.assertFalse(failed["transfer"]["download_complete"])

    def test_pretransfer_refuses_insufficient_space_before_download(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "image/container").mkdir(parents=True)
            selection, _, _, _, _ = self.ready_fixture(root)
            (root / "image/container/fedora-runtime-image.lock.json").write_text(
                json.dumps(selection) + "\n")
            (root / ".cache").mkdir()
            with self.assertRaises(ValueError):
                inputs.prepare_transfer(
                    root, self.hosted_environment,
                    available_bytes=inputs.PRE_TRANSFER_REQUIRED_BYTES - 1)
            record = json.loads((root / ".cache/container-runtime-native-evidence/"
                                 "pre-transfer.json").read_text())
            self.assertEqual(record["blocker"], "insufficient-container-runtime-disk")
            self.assertFalse(record["passed"])

    def test_downloaded_zip_refuses_insufficient_extraction_space(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cache = root / ".cache"
            (root / "image/container").mkdir(parents=True)
            cache.mkdir()
            selection, run, metadata, bundle, _ = self.ready_fixture(root)
            (root / "image/container/fedora-runtime-image.lock.json").write_text(
                json.dumps(selection) + "\n")
            (cache / "container-runtime-image-run.json").write_text(
                json.dumps(run) + "\n")
            (cache / "container-runtime-image-artifact.json").write_text(
                json.dumps(metadata) + "\n")
            bundle.replace(cache / "container-runtime-development-image.zip")
            inputs.prepare_transfer(
                root, self.hosted_environment,
                available_bytes=inputs.PRE_TRANSFER_REQUIRED_BYTES)
            inputs.record_transfer_metadata(root, self.hosted_environment)
            with self.assertRaises(ValueError):
                inputs.record_transfer_complete(
                    root, self.hosted_environment,
                    available_bytes=inputs.PRE_TRANSFER_MARGIN_BYTES - 1)
            record = json.loads((cache / "container-runtime-native-evidence/"
                                 "pre-transfer.json").read_text())
            self.assertEqual(record["transfer"]["stage"], "download-validation")
            self.assertFalse(record["transfer"]["download_complete"])
            self.assertIn("insufficient-container-runtime-extraction-disk",
                          record["failure"])

    def test_duplicate_unsafe_or_link_bundle_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selection, run, metadata, bundle, _ = self.ready_fixture(root)
            with zipfile.ZipFile(bundle) as source:
                members = [(row.filename, source.read(row)) for row in source.infolist()]
            for case in ("duplicate", "traversal", "link"):
                changed_bundle = root / (case + ".zip")
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(changed_bundle, "w") as output:
                        for name, raw in members:
                            row = zipfile.ZipInfo(name)
                            row.external_attr = (stat.S_IFREG | 0o600) << 16
                            if case == "link" and name == "manifest.json":
                                row.external_attr = (stat.S_IFLNK | 0o777) << 16
                            output.writestr(row, raw)
                        if case == "duplicate":
                            output.writestr("manifest.json", members[0][1])
                        elif case == "traversal":
                            output.writestr("../outside", b"extra")
                changed_selection = copy.deepcopy(selection)
                changed_metadata = copy.deepcopy(metadata)
                changed_selection["artifact"]["bytes"] = changed_bundle.stat().st_size
                changed_selection["artifact"]["sha256"] = inputs.sha256(changed_bundle)
                changed_metadata["size_in_bytes"] = changed_bundle.stat().st_size
                changed_metadata["digest"] = "sha256:" + inputs.sha256(changed_bundle)
                with self.subTest(case=case), self.assertRaises(ValueError):
                    inputs.consume_candidate_bundle(
                        changed_bundle, changed_selection, run, changed_metadata,
                        root / ("output-" + case),
                        validate_contract=lambda contract, source_commit, source_image_id: None,
                    )

    def test_selected_bundle_is_consumed_then_fully_revalidated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cache = root / ".cache"
            (root / "image/container").mkdir(parents=True)
            cache.mkdir()
            selection, run, metadata, bundle, manifest = self.ready_fixture(root)
            (root / "image/container/fedora-runtime-image.lock.json").write_text(
                json.dumps(selection, indent=2) + "\n")
            shutil.copy(ROOT / "image/desktop-images.lock.json",
                        root / "image/desktop-images.lock.json")
            shutil.copy(ROOT / "image/base-images.json", root / "image/base-images.json")
            run_path = cache / "container-runtime-image-run.json"
            artifact_path = cache / "container-runtime-image-artifact.json"
            bundle_path = cache / "container-runtime-development-image.zip"
            run_path.write_text(json.dumps(run) + "\n")
            artifact_path.write_text(json.dumps(metadata) + "\n")
            bundle.replace(bundle_path)
            inputs.prepare_transfer(
                root, self.hosted_environment,
                available_bytes=inputs.PRE_TRANSFER_REQUIRED_BYTES + 1)
            inputs.record_transfer_metadata(root, self.hosted_environment)
            inputs.record_transfer_complete(
                root, self.hosted_environment,
                available_bytes=inputs.PRE_TRANSFER_MARGIN_BYTES + 1024)
            context = inputs.validate_hosted_context(
                self.hosted_environment, 1000,
                "symbi-container-input-900-2.service", inputs.HOSTED_LIMITS)
            final = {
                **inputs.HOSTED_LIMITS,
                "memory.peak": "1048576",
                "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
                "cpu.stat": "usage_usec 1\n",
            }
            with mock.patch.object(inputs, "load_hosted_context", return_value=(context, Path("/cg"))), \
                    mock.patch.object(inputs, "read_cgroup_final", return_value=final), \
                    mock.patch.object(inputs, "_real_contract_validator",
                                      return_value=lambda contract, commit, image_id: None):
                inputs.consume(
                    root, bundle_path, run_path, artifact_path,
                    cache / "container-runtime-native-inputs",
                    cache / "container-runtime-native-evidence")
            unit_result = cache / "container-runtime-native-evidence/systemd-result.txt"
            systemd_values = {
                "LoadState": "loaded",
                "Result": "success",
                "MemoryPeak": "1048576",
                "MemorySwapPeak": "0",
                "ExecMainCode": "1",
                "ExecMainStatus": "0",
                "ControlGroup": context["control_group"],
                "ActiveState": "active",
                "SubState": "exited",
            }
            unit_result.write_text("".join(
                key + "=" + value + "\n" for key, value in systemd_values.items()))
            result = inputs.validate_consumed_candidate(
                root, self.hosted_environment["GITHUB_SHA"], self.hosted_environment)
            self.assertTrue(result["ready"])
            self.assertEqual(result["manifest"], manifest)
            wrong_run = {**self.hosted_environment, "GITHUB_RUN_ATTEMPT": "3"}
            with self.assertRaises(ValueError):
                inputs.validate_consumed_candidate(
                    root, self.hosted_environment["GITHUB_SHA"], wrong_run)
            prepare_path = cache / "container-runtime-native-evidence/prepare.json"
            changed = json.loads(prepare_path.read_text())
            changed["hosted"]["source_commit"] = "0" * 40
            prepare_path.write_text(json.dumps(changed) + "\n")
            with self.assertRaises(ValueError):
                inputs.validate_consumed_candidate(
                    root, self.hosted_environment["GITHUB_SHA"], self.hosted_environment)
            changed["hosted"]["source_commit"] = self.hosted_environment["GITHUB_SHA"]
            clean_events = changed["cgroup_final"]["memory.events"]
            changed["cgroup_final"]["memory.events"] = clean_events.replace(
                "oom_kill 0", "oom_kill 1")
            prepare_path.write_text(json.dumps(changed) + "\n")
            with self.assertRaises(ValueError):
                inputs.validate_consumed_candidate(
                    root, self.hosted_environment["GITHUB_SHA"], self.hosted_environment)
            changed["cgroup_final"]["memory.events"] = clean_events
            prepare_path.write_text(json.dumps(changed) + "\n")
            systemd_values["Result"] = "exit-code"
            unit_result.write_text("".join(
                key + "=" + value + "\n" for key, value in systemd_values.items()))
            with self.assertRaises(ValueError):
                inputs.validate_consumed_candidate(
                    root, self.hosted_environment["GITHUB_SHA"], self.hosted_environment)

    def test_producer_manifest_keeps_signature_and_variant_claims_false_and_exact(self):
        builder = (ROOT / "image/container/runtime_image_build.py").read_text()
        self.assertIn('"signature_qualified": False', builder)
        self.assertIn('"variant": "generic"', builder)
        workflow = (ROOT / ".github/workflows/landlock-qualification.yml").read_text()
        transfer = (ROOT / "scripts/check-container-runtime-native-transfer.sh").read_text()
        self.assertIn("container-runtime-image-run.json", transfer)
        self.assertIn("container-runtime-image-artifact.json", transfer)
        self.assertIn("check-container-runtime-native-input.sh", workflow)
        self.assertIn("check-container-runtime-native-transfer.sh", workflow)
        self.assertIn('actions/runs/${values[0]}/attempts/${values[1]}',
                      transfer)
        self.assertIn(".cache/container-runtime-native-evidence", workflow)
        documentation = (ROOT / "image/container/README.md").read_text()
        self.assertIn("artifact metadata does not expose the run attempt", documentation)
        self.assertLess(
            workflow.index("Validate and download the exact retained container-runtime image"),
            workflow.index("Authenticate and stream the exact retained container-runtime image"),
        )


if __name__ == "__main__":
    unittest.main()
