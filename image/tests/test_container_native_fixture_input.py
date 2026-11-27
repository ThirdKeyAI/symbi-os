"""Offline mutation tests for the authenticated native fixture OCI intake."""
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
import zipfile

from image.container import native_fixture_inputs as inputs


ROOT = Path(__file__).resolve().parents[2]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class NativeFixtureInput(unittest.TestCase):
    def setUp(self):
        self.pending = json.loads(
            (ROOT / "image/container/native-fixture-image.lock.json").read_text())
        self.source = inputs.load_fixture_pin(ROOT)
        self.consumer = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REPOSITORY": "ThirdKeyAI/symbi-os",
            "GITHUB_SHA": "6" * 40,
            "GITHUB_RUN_ID": "900",
            "GITHUB_RUN_ATTEMPT": "2",
        }

    @staticmethod
    def _tar_member(output, name, raw):
        row = tarfile.TarInfo(name)
        row.size = len(raw)
        row.mode = 0o600
        row.mtime = 0
        output.addfile(row, io.BytesIO(raw))

    def oci_archive(self, path):
        config_raw = json.dumps(
            {"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        layer_raw = b"small inert fixture layer"
        config = digest(config_raw)
        layer = digest(layer_raw)
        manifest_raw = json.dumps({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:" + config,
                "size": len(config_raw),
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": "sha256:" + layer,
                "size": len(layer_raw),
            }],
        }, sort_keys=True, separators=(",", ":")).encode()
        manifest = digest(manifest_raw)
        index_raw = json.dumps({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:" + manifest,
                "size": len(manifest_raw),
            }],
        }, sort_keys=True, separators=(",", ":")).encode()
        with tarfile.open(path, "w:gz") as output:
            for directory in ("blobs", "blobs/sha256"):
                row = tarfile.TarInfo(directory)
                row.type = tarfile.DIRTYPE
                row.mode = 0o700
                row.mtime = 0
                output.addfile(row)
            for name, raw in (
                ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
                ("index.json", index_raw),
                ("blobs/sha256/" + config, config_raw),
                ("blobs/sha256/" + manifest, manifest_raw),
                ("blobs/sha256/" + layer, layer_raw),
            ):
                self._tar_member(output, name, raw)
        return "sha256:" + config, "sha256:" + manifest

    @staticmethod
    def write_bundle(path, manifest_raw, archive, extra=None):
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as output:
            for name, raw in (
                ("manifest.json", manifest_raw),
                (inputs.ARCHIVE_NAME, archive.read_bytes()),
            ):
                row = zipfile.ZipInfo(name)
                row.external_attr = (stat.S_IFREG | 0o600) << 16
                output.writestr(row, raw)
            if extra is not None:
                output.writestr("extra", extra)

    @staticmethod
    def bind_outer(selection, metadata, bundle):
        checksum = inputs.sha256(bundle)
        selection["artifact"].update(bytes=bundle.stat().st_size, sha256=checksum)
        metadata.update(
            size_in_bytes=bundle.stat().st_size,
            digest="sha256:" + checksum,
        )

    def ready_fixture(self, directory):
        directory = Path(directory)
        archive = directory / inputs.ARCHIVE_NAME
        image_id, manifest_digest = self.oci_archive(archive)
        selection = copy.deepcopy(self.pending)
        selection.update(state="selected", selected=True)
        selection["workflow"]["id"] = 123
        selection["producer"].update(
            run_id=456, run_attempt=1, head_sha="3" * 40,
            head_branch="card/P0-05-fixture-image", status="completed",
            conclusion="success",
        )
        archive_binding = {
            "name": inputs.ARCHIVE_NAME,
            "bytes": archive.stat().st_size,
            "sha256": inputs.sha256(archive),
        }
        manifest = {
            "schema": 1,
            "built": True,
            "qualified": False,
            "container_qualified": False,
            "os_qualified": False,
            "release_qualified": False,
            "signature_qualified": False,
            "source_commit": selection["producer"]["head_sha"],
            "producer": {
                "run_id": selection["producer"]["run_id"],
                "run_attempt": selection["producer"]["run_attempt"],
                "workflow_id": selection["workflow"]["id"],
            },
            "fixture_source": self.source,
            "archive": archive_binding,
            "tested_image": {
                "descriptor": "sha256:" + "7" * 64,
                "config_digest": image_id,
            },
            "image": {
                "repository": inputs.IMAGE_REPOSITORY,
                "image_id": image_id,
                "manifest_digest": manifest_digest,
                "repo_digest": inputs.IMAGE_REPOSITORY + "@" + manifest_digest,
            },
            "scope": inputs.MANIFEST_SCOPE,
        }
        manifest_raw = (json.dumps(manifest, indent=2) + "\n").encode()
        selection["manifest"] = {
            "sha256": digest(manifest_raw),
            "archive": archive_binding,
        }
        bundle = directory / "fixture.zip"
        self.write_bundle(bundle, manifest_raw, archive)
        selection["artifact"].update(
            id=789, bytes=bundle.stat().st_size, sha256=inputs.sha256(bundle))
        run = {
            "id": 456,
            "run_attempt": 1,
            "event": "workflow_dispatch",
            "path": inputs.PRODUCER_WORKFLOW,
            "workflow_id": 123,
            "head_sha": "3" * 40,
            "head_branch": "card/P0-05-fixture-image",
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
        return selection, run, metadata, bundle, archive, manifest

    def write_root(self, root, selection, run, metadata, bundle):
        (root / "image/container").mkdir(parents=True)
        (root / "upstream").mkdir()
        shutil.copyfile(
            ROOT / "image/container/native-fixture.lock.json",
            root / "image/container/native-fixture.lock.json")
        shutil.copyfile(
            ROOT / "upstream/symbiont.toml", root / "upstream/symbiont.toml")
        (root / "image/container/native-fixture-image.lock.json").write_text(
            json.dumps(selection) + "\n")
        cache = root / ".cache"
        cache.mkdir()
        (cache / "container-native-fixture-run.json").write_text(json.dumps(run))
        (cache / "container-native-fixture-artifact.json").write_text(json.dumps(metadata))
        shutil.copyfile(bundle, cache / "container-native-fixture-image.zip")
        return cache

    def test_pending_slot_has_no_producer_artifact_manifest_or_image_identity(self):
        status = inputs.validate_selection(self.pending, self.source)
        self.assertFalse(status["ready"])
        self.assertEqual(status["blocker"], "pending-native-fixture-image")
        self.assertFalse(self.pending["qualified"])
        self.assertFalse(self.pending["container_qualified"])
        self.assertFalse(self.pending["os_qualified"])
        self.assertFalse(self.pending["release_qualified"])
        self.assertFalse(self.pending["signature_qualified"])
        self.assertIsNone(self.pending["producer"]["head_sha"])
        self.assertIsNone(self.pending["artifact"]["sha256"])
        self.assertIsNone(self.pending["manifest"]["sha256"])
        self.assertNotIn("image", self.pending["manifest"])

    def test_producer_and_consumer_commits_are_independent_exact_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            selection, run, metadata, _, _, _ = self.ready_fixture(directory)
            self.assertTrue(inputs.validate_selection(selection, self.source)["ready"])
            inputs.validate_producer_metadata(run, selection)
            inputs.validate_artifact_metadata(metadata, selection)
            consumer = inputs._workflow_identity(self.consumer)
            self.assertEqual(selection["producer"]["head_sha"], "3" * 40)
            self.assertEqual(consumer["source_commit"], "6" * 40)
            self.assertNotEqual(selection["producer"]["head_sha"],
                                consumer["source_commit"])

    def test_exact_outer_members_inner_archive_and_oci_identity_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            selection, run, metadata, bundle, _, manifest = self.ready_fixture(directory)
            destination = Path(directory) / "prepared"
            observed = inputs.consume_fixture_bundle(
                bundle, selection, run, metadata, destination, self.source)
            self.assertEqual(observed["manifest"], manifest)
            self.assertEqual(observed["image"], manifest["image"])
            self.assertFalse(observed["artifact_metadata"]["expired"])
            self.assertEqual(observed["artifact_metadata"]["repository_id"],
                             inputs.REPOSITORY["id"])
            self.assertEqual(observed["producer_metadata"]["repository_full_name"],
                             inputs.REPOSITORY["full_name"])
            self.assertEqual(observed["oci"]["manifest_digest"],
                             manifest["image"]["manifest_digest"])
            self.assertEqual({path.name for path in destination.iterdir()},
                             {"manifest.json", inputs.ARCHIVE_NAME})

    def test_manifest_identity_is_checked_against_the_oci_not_selector_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            selection, run, metadata, bundle, archive, manifest = self.ready_fixture(directory)
            changed = copy.deepcopy(manifest)
            changed["image"]["image_id"] = "sha256:" + "9" * 64
            raw = (json.dumps(changed, indent=2) + "\n").encode()
            selection["manifest"]["sha256"] = digest(raw)
            self.write_bundle(bundle, raw, archive)
            self.bind_outer(selection, metadata, bundle)
            with self.assertRaises(ValueError):
                inputs.consume_fixture_bundle(
                    bundle, selection, run, metadata, Path(directory) / "prepared",
                    self.source)

            selection, run, metadata, bundle, archive, manifest = self.ready_fixture(directory)
            changed = copy.deepcopy(manifest)
            changed["tested_image"]["descriptor"] = changed["image"]["image_id"]
            raw = (json.dumps(changed, indent=2) + "\n").encode()
            selection["manifest"]["sha256"] = digest(raw)
            self.write_bundle(bundle, raw, archive)
            self.bind_outer(selection, metadata, bundle)
            with self.assertRaises(ValueError):
                inputs.consume_fixture_bundle(
                    bundle, selection, run, metadata,
                    Path(directory) / "same-descriptor", self.source)

            selection, run, metadata, bundle, archive, manifest = self.ready_fixture(directory)
            changed = copy.deepcopy(manifest)
            changed["producer"]["run_attempt"] += 1
            raw = (json.dumps(changed, indent=2) + "\n").encode()
            selection["manifest"]["sha256"] = digest(raw)
            self.write_bundle(bundle, raw, archive)
            self.bind_outer(selection, metadata, bundle)
            with self.assertRaises(ValueError):
                inputs.consume_fixture_bundle(
                    bundle, selection, run, metadata,
                    Path(directory) / "wrong-attempt", self.source)

    def test_tampered_outer_archive_and_unexpected_member_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            selection, run, metadata, bundle, archive, manifest = self.ready_fixture(directory)
            tampered = Path(directory) / "outer.zip"
            tampered.write_bytes(bundle.read_bytes() + b"tamper")
            with self.assertRaises(ValueError):
                inputs.consume_fixture_bundle(
                    tampered, selection, run, metadata, Path(directory) / "outer-output",
                    self.source)

            extra = Path(directory) / "extra.zip"
            raw = (json.dumps(manifest, indent=2) + "\n").encode()
            self.write_bundle(extra, raw, archive, extra=b"unexpected")
            changed_selection = copy.deepcopy(selection)
            changed_metadata = copy.deepcopy(metadata)
            self.bind_outer(changed_selection, changed_metadata, extra)
            with self.assertRaises(ValueError):
                inputs.consume_fixture_bundle(
                    extra, changed_selection, run, changed_metadata,
                    Path(directory) / "extra-output", self.source)

            changed_archive = Path(directory) / inputs.ARCHIVE_NAME
            changed_raw = bytearray(archive.read_bytes())
            changed_raw[-1] ^= 1
            changed_archive.write_bytes(changed_raw)
            inner = Path(directory) / "inner.zip"
            self.write_bundle(inner, raw, changed_archive)
            changed_selection = copy.deepcopy(selection)
            changed_metadata = copy.deepcopy(metadata)
            self.bind_outer(changed_selection, changed_metadata, inner)
            inner_output = Path(directory) / "inner-output"
            with self.assertRaises(ValueError):
                inputs.consume_fixture_bundle(
                    inner, changed_selection, run, changed_metadata,
                    inner_output, self.source)
            self.assertFalse(inner_output.exists())

    def test_wrong_run_repository_expiry_or_artifact_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            selection, run, metadata, _, _, _ = self.ready_fixture(directory)
            mutations = []
            changed = copy.deepcopy(run)
            changed["head_sha"] = "0" * 40
            mutations.append((changed, metadata))
            changed = copy.deepcopy(run)
            changed["repository"]["id"] += 1
            mutations.append((changed, metadata))
            changed_metadata = copy.deepcopy(metadata)
            changed_metadata["expired"] = True
            mutations.append((run, changed_metadata))
            changed_metadata = copy.deepcopy(metadata)
            changed_metadata["digest"] = "sha256:" + "0" * 64
            mutations.append((run, changed_metadata))
            for candidate_run, candidate_metadata in mutations:
                with self.subTest(run=candidate_run, metadata=candidate_metadata), \
                        self.assertRaises(ValueError):
                    inputs.validate_producer_metadata(candidate_run, selection)
                    inputs.validate_artifact_metadata(candidate_metadata, selection)

    def test_pending_pretransfer_fails_closed_with_consumer_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "image/container").mkdir(parents=True)
            (root / "upstream").mkdir()
            shutil.copyfile(
                ROOT / "image/container/native-fixture.lock.json",
                root / "image/container/native-fixture.lock.json")
            shutil.copyfile(
                ROOT / "upstream/symbiont.toml", root / "upstream/symbiont.toml")
            (root / "image/container/native-fixture-image.lock.json").write_text(
                json.dumps(self.pending))
            (root / ".cache").mkdir()
            with self.assertRaises(ValueError):
                inputs.prepare_transfer(
                    root, self.consumer,
                    available_bytes=inputs.PRE_TRANSFER_REQUIRED_BYTES + 1)
            record = json.loads((
                root / ".cache/container-fixture-native-evidence/pre-transfer.json"
            ).read_text())
            self.assertEqual(record["blocker"], "pending-native-fixture-image")
            self.assertEqual(record["hosted"]["source_commit"], "6" * 40)
            self.assertFalse(record["passed"])

    def test_disk_gates_fail_closed_before_transfer_and_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source_directory = root / "source"
            source_directory.mkdir()
            selection, run, metadata, bundle, _, _ = self.ready_fixture(source_directory)
            cache = self.write_root(root, selection, run, metadata, bundle)
            with self.assertRaisesRegex(
                    ValueError, "insufficient-native-fixture-disk"):
                inputs.prepare_transfer(
                    root, self.consumer,
                    available_bytes=inputs.PRE_TRANSFER_REQUIRED_BYTES - 1)
            record = json.loads((
                cache / "container-fixture-native-evidence/pre-transfer.json"
            ).read_text())
            self.assertFalse(record["passed"])
            self.assertEqual(record["blocker"], "insufficient-native-fixture-disk")
            self.assertEqual(record["transfer"]["stage"], "selection")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source_directory = root / "source"
            source_directory.mkdir()
            selection, run, metadata, bundle, _, _ = self.ready_fixture(source_directory)
            cache = self.write_root(root, selection, run, metadata, bundle)
            inputs.prepare_transfer(
                root, self.consumer,
                available_bytes=inputs.PRE_TRANSFER_REQUIRED_BYTES + 1)
            inputs.record_transfer_metadata(root, self.consumer)
            required = (selection["manifest"]["archive"]["bytes"]
                        + inputs.MAX_OCI_BYTES + inputs.PRE_TRANSFER_MARGIN_BYTES)
            with self.assertRaisesRegex(
                    ValueError, "insufficient-native-fixture-extraction-disk"):
                inputs.record_transfer_complete(
                    root, self.consumer, available_bytes=required - 1)
            record = json.loads((
                cache / "container-fixture-native-evidence/pre-transfer.json"
            ).read_text())
            self.assertFalse(record["passed"])
            self.assertEqual(
                record["blocker"], "insufficient-native-fixture-extraction-disk")
            self.assertEqual(record["transfer"]["stage"], "download-validation")
            self.assertFalse(record["transfer"]["download_complete"])
            self.assertEqual(record["disk"]["available_before_extraction"],
                             required - 1)

    def test_transfer_and_preflight_recheck_exact_prepared_bytes_and_consumer_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source_directory = root / "source"
            source_directory.mkdir()
            selection, run, metadata, bundle, _, manifest = self.ready_fixture(source_directory)
            cache = self.write_root(root, selection, run, metadata, bundle)
            values = inputs.prepare_transfer(
                root, self.consumer,
                available_bytes=inputs.PRE_TRANSFER_REQUIRED_BYTES + 1)
            self.assertEqual(values, (456, 1, 789))
            inputs.record_transfer_metadata(root, self.consumer)
            inputs.record_transfer_complete(
                root, self.consumer,
                available_bytes=(selection["manifest"]["archive"]["bytes"]
                                 + inputs.MAX_OCI_BYTES
                                 + inputs.PRE_TRANSFER_MARGIN_BYTES + 1))
            observed = inputs.consume_fixture_bundle(
                cache / "container-native-fixture-image.zip", selection, run,
                metadata, cache / "container-native-fixture-inputs", self.source)
            hosted = inputs.validate_hosted_context(
                self.consumer, 1000, "symbi-fixture-input-900-2.service",
                inputs.HOSTED_LIMITS,
                "/system.slice/symbi-fixture-input-900-2.service")
            transfer = inputs.validate_transfer_record(root, selection, hosted)
            cgroup = {
                **inputs.HOSTED_LIMITS,
                "memory.peak": "4096",
                "memory.events": "oom 0\noom_kill 0\noom_group_kill 0\n",
                "cpu.stat": "usage_usec 1\n",
            }
            prepare = {
                "schema": 1, "passed": True, "qualified": False,
                "container_qualified": False, "os_qualified": False,
                "release_qualified": False, "signature_qualified": False,
                "selection_sha256": inputs.sha256(
                    root / "image/container/native-fixture-image.lock.json"),
                "pre_transfer_sha256": inputs.sha256(
                    cache / "container-fixture-native-evidence/pre-transfer.json"),
                "hosted": hosted, "limits": inputs.HOSTED_LIMITS,
                "transfer": transfer,
                "scope": "Exact fixture OCI intake; native containment qualification remains open",
                **observed, "cgroup_final": cgroup,
            }
            (cache / "container-fixture-native-evidence/prepare.json").write_text(
                json.dumps(prepare))
            systemd = {
                "LoadState": "loaded", "Result": "success", "MemoryPeak": "4096",
                "MemorySwapPeak": "0", "ExecMainCode": "1", "ExecMainStatus": "0",
                "ControlGroup": hosted["control_group"], "ActiveState": "active",
                "SubState": "exited",
            }
            (cache / "container-fixture-native-evidence/systemd-result.txt").write_text(
                "".join(key + "=" + value + "\n" for key, value in systemd.items()))
            ready = inputs.validate_consumed_fixture(
                root, "6" * 40, self.source, self.consumer)
            self.assertTrue(ready["ready"])
            self.assertEqual(ready["image"], manifest["image"])
            changed_consumer = dict(self.consumer, GITHUB_RUN_ID="901")
            with self.assertRaises(ValueError):
                inputs.validate_consumed_fixture(
                    root, "6" * 40, self.source, changed_consumer)
            for field, value in (("expired", True),
                                 ("repository_id", inputs.REPOSITORY["id"] + 1)):
                tampered = copy.deepcopy(prepare)
                tampered["artifact_metadata"][field] = value
                (cache / "container-fixture-native-evidence/prepare.json").write_text(
                    json.dumps(tampered))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    inputs.validate_consumed_fixture(
                        root, "6" * 40, self.source, self.consumer)
            for field, value in (("bytes", 0), ("unexpected", True)):
                tampered = copy.deepcopy(prepare)
                tampered["oci"][field] = value
                (cache / "container-fixture-native-evidence/prepare.json").write_text(
                    json.dumps(tampered))
                with self.subTest(oci_field=field), self.assertRaises(ValueError):
                    inputs.validate_consumed_fixture(
                        root, "6" * 40, self.source, self.consumer)
            (cache / "container-fixture-native-evidence/prepare.json").write_text(
                json.dumps(prepare))

    def test_workflow_fetches_and_authenticates_fixture_before_preflight(self):
        workflow = (ROOT / ".github/workflows/landlock-qualification.yml").read_text()
        transfer = (ROOT / "scripts/check-container-fixture-native-transfer.sh").read_text()
        self.assertIn("container-native-fixture-run.json", transfer)
        self.assertIn("container-native-fixture-artifact.json", transfer)
        self.assertIn("check-container-fixture-native-transfer.sh", workflow)
        self.assertIn("check-container-fixture-native-input.sh", workflow)
        self.assertIn(".cache/container-fixture-native-evidence", workflow)
        self.assertLess(
            workflow.index("Validate and download the exact retained native fixture image"),
            workflow.index("Validate the generated Fedora runtime contract"))
        self.assertLess(
            workflow.index("Authenticate and inspect the exact retained native fixture image"),
            workflow.index("Validate the generated Fedora runtime contract"))


if __name__ == "__main__":
    unittest.main()
