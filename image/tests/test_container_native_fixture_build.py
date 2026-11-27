"""Offline tests for the bounded native fixture OCI producer."""
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

from image.atomic.contract import unpack_oci
from image.container import native_fixture_build as build
from image.container import native_fixture_inputs as inputs


ROOT = Path(__file__).resolve().parents[2]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class NativeFixtureBuild(unittest.TestCase):
    def setUp(self):
        self.environment = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "ThirdKeyAI/symbi-os",
            "GITHUB_SHA": "4" * 40,
            "GITHUB_RUN_ID": "812",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_REF_NAME": "card/P0-05-fixture-producer",
        }
        self.metadata = {
            "id": 812,
            "run_attempt": 2,
            "event": "workflow_dispatch",
            "path": inputs.PRODUCER_WORKFLOW,
            "workflow_id": 77,
            "head_sha": "4" * 40,
            "head_branch": "card/P0-05-fixture-producer",
            "status": "in_progress",
            "conclusion": None,
            "repository": inputs.REPOSITORY,
            "head_repository": inputs.REPOSITORY,
        }

    @staticmethod
    def _row(output, name, raw, kind=tarfile.REGTYPE):
        row = tarfile.TarInfo(name)
        row.size = len(raw)
        row.mode = 0o600
        row.mtime = 0
        row.type = kind
        output.addfile(row, io.BytesIO(raw))

    def docker_archive(self, path, *, tested_descriptor=None, diff_id=None,
                       duplicate=False, unsafe=False, repeat_layer=False):
        layer_raw = b"bounded fixture image layer"
        layer_digest = "sha256:" + digest(layer_raw)
        layer_names = (
            ["layer/one.tar", "layer/two.tar"]
            if repeat_layer else ["layer/layer.tar"])
        diff_ids = [
            layer_digest if diff_id is None else diff_id
            for _ in layer_names
        ]
        config_raw = build.canonical({
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": diff_ids,
            },
        })
        tested_descriptor = (
            "sha256:" + digest(b"tested Docker manifest descriptor")
            if tested_descriptor is None else tested_descriptor)
        manifest_raw = json.dumps([{
            "Config": "config.json",
            "RepoTags": None,
            "Layers": layer_names,
        }], sort_keys=True, separators=(",", ":")).encode()
        with tarfile.open(path, "w") as output:
            self._row(output, "manifest.json", manifest_raw)
            self._row(output, "config.json", config_raw)
            for name in layer_names:
                self._row(output, name, layer_raw)
            if duplicate:
                self._row(output, "manifest.json", manifest_raw)
            if unsafe:
                self._row(output, "unsafe", b"", tarfile.SYMTYPE)
        inspection = {
            "Id": tested_descriptor,
            "Descriptor": {"digest": tested_descriptor},
            "Architecture": "amd64",
            "Os": "linux",
            "RepoDigests": [],
            "RootFS": {"Type": "layers", "Layers": [layer_digest] * len(layer_names)},
        }
        path.with_name("fixture-image-inspect.json").write_text(
            json.dumps([inspection]) + "\n")
        return tested_descriptor

    def root(self, directory):
        root = Path(directory)
        (root / "image/container").mkdir(parents=True)
        (root / "upstream").mkdir()
        shutil.copyfile(
            ROOT / "image/container/native-fixture.lock.json",
            root / "image/container/native-fixture.lock.json")
        shutil.copyfile(
            ROOT / "image/container/native-fixture-build.lock.json",
            root / "image/container/native-fixture-build.lock.json")
        shutil.copyfile(
            ROOT / "upstream/symbiont.toml",
            root / "upstream/symbiont.toml")
        work = root / ".cache/container-fixture-work"
        work.mkdir(parents=True)
        (root / ".cache/container-fixture-producer-run.json").write_text(
            json.dumps(self.metadata) + "\n")
        archive = work / build.DOCKER_ARCHIVE_NAME
        image_id = self.docker_archive(archive)
        return root, archive, image_id

    def test_builds_exact_two_file_false_claim_oci_from_current_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, tested_descriptor = self.root(directory)
            record = build._export_fixture_output(
                root, tested_descriptor, self.environment,
                available_bytes=build.MIN_FREE_AFTER_SAVE)
            output = root / ".cache/container-native-fixture-output"
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {"manifest.json", inputs.ARCHIVE_NAME})
            manifest_raw = (output / "manifest.json").read_bytes()
            manifest = json.loads(manifest_raw)
            self.assertTrue(record["built"])
            for claim in (
                    "qualified", "container_qualified", "os_qualified",
                    "release_qualified", "signature_qualified"):
                self.assertFalse(record[claim])
                self.assertFalse(manifest[claim])
            self.assertEqual(manifest["source_commit"],
                             self.environment["GITHUB_SHA"])
            self.assertEqual(manifest["producer"], {
                "run_id": 812, "run_attempt": 2, "workflow_id": 77,
            })
            self.assertEqual(
                manifest["fixture_source"], inputs.load_fixture_pin(ROOT))
            self.assertEqual(manifest["archive"]["name"], inputs.ARCHIVE_NAME)
            self.assertEqual(
                manifest["archive"]["sha256"],
                inputs.sha256(output / inputs.ARCHIVE_NAME))
            self.assertEqual(
                manifest["image"]["repo_digest"],
                inputs.IMAGE_REPOSITORY + "@"
                + manifest["image"]["manifest_digest"])
            self.assertEqual(
                manifest["tested_image"]["descriptor"], tested_descriptor)
            self.assertEqual(
                manifest["tested_image"]["config_digest"],
                manifest["image"]["image_id"])
            self.assertNotEqual(
                manifest["image"]["manifest_digest"],
                manifest["image"]["image_id"])
            self.assertNotEqual(
                manifest["image"]["image_id"], tested_descriptor)
            self.assertNotEqual(
                manifest["image"]["manifest_digest"], tested_descriptor)
            verify = root / ".cache/verify-produced-oci"
            observed = unpack_oci(
                output / inputs.ARCHIVE_NAME, verify,
                manifest["image"]["manifest_digest"],
                manifest["image"]["image_id"],
                max_bytes=build.MAX_PRODUCED_OCI_BYTES)
            self.assertEqual(
                observed["config_digest"], manifest["image"]["image_id"])
            self.assertFalse(observed["root_filesystem_extracted"])

    def test_rejects_wrong_run_repository_event_attempt_branch_or_status(self):
        mutations = (
            ("id", 813),
            ("run_attempt", 1),
            ("event", "pull_request"),
            ("head_sha", "5" * 40),
            ("head_branch", "other"),
            ("status", "completed"),
            ("conclusion", "success"),
            ("repository", {"id": 1, "full_name": "ThirdKeyAI/symbi-os"}),
            ("head_repository", {"id": 1, "full_name": "ThirdKeyAI/symbi-os"}),
        )
        for field, value in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root, _, image_id = self.root(directory)
                changed = copy.deepcopy(self.metadata)
                changed[field] = value
                (root / ".cache/container-fixture-producer-run.json").write_text(
                    json.dumps(changed) + "\n")
                with self.assertRaises(ValueError):
                    build._export_fixture_output(
                        root, image_id, self.environment,
                        available_bytes=build.MIN_FREE_AFTER_SAVE)
                self.assertFalse(
                    (root / ".cache/container-native-fixture-output").exists())

    def test_rejects_inspect_descriptor_or_layer_diff_id_and_cleans_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root, archive, tested_descriptor = self.root(directory)
            inspection = json.loads(
                archive.with_name("fixture-image-inspect.json").read_text())
            inspection[0]["Id"] = "sha256:" + "9" * 64
            archive.with_name("fixture-image-inspect.json").write_text(
                json.dumps(inspection) + "\n")
            with self.assertRaises(ValueError):
                build._export_fixture_output(
                    root, tested_descriptor, self.environment,
                    available_bytes=build.MIN_FREE_AFTER_SAVE)
            self.assertFalse(
                (root / ".cache/container-native-fixture-output").exists())
        with tempfile.TemporaryDirectory() as directory:
            root, archive, _ = self.root(directory)
            tested_descriptor = self.docker_archive(
                archive, diff_id="sha256:" + "8" * 64)
            with self.assertRaises(ValueError):
                build._export_fixture_output(
                    root, tested_descriptor, self.environment,
                    available_bytes=build.MIN_FREE_AFTER_SAVE)
            self.assertFalse(
                (root / ".cache/container-native-fixture-output").exists())

    def test_rejects_duplicate_or_special_docker_archive_member(self):
        for option in ("duplicate", "unsafe"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as directory:
                root, archive, _ = self.root(directory)
                image_id = self.docker_archive(
                    archive, **{option: True})
                with self.assertRaises(ValueError):
                    build._export_fixture_output(
                        root, image_id, self.environment,
                        available_bytes=build.MIN_FREE_AFTER_SAVE)
                self.assertFalse(
                    (root / ".cache/container-native-fixture-output").exists())

    def test_disk_gate_precedes_archive_inspection_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root, archive, image_id = self.root(directory)
            archive.write_bytes(b"not a tar")
            with self.assertRaisesRegex(ValueError, "space"):
                build._export_fixture_output(
                    root, image_id, self.environment,
                    available_bytes=build.MIN_FREE_AFTER_SAVE - 1)
            self.assertFalse(
                (root / ".cache/container-native-fixture-output").exists())

    def test_repeated_layer_blob_is_emitted_once_but_described_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            root, archive, _ = self.root(directory)
            tested_descriptor = self.docker_archive(
                archive, repeat_layer=True)
            record = build._export_fixture_output(
                root, tested_descriptor, self.environment,
                available_bytes=build.MIN_FREE_AFTER_SAVE)
            output = root / ".cache/container-native-fixture-output"
            verify = root / ".cache/verify-repeated-layer"
            observed = unpack_oci(
                output / inputs.ARCHIVE_NAME, verify,
                record["image"]["manifest_digest"],
                record["image"]["image_id"],
                max_bytes=build.MAX_PRODUCED_OCI_BYTES)
            self.assertEqual(observed["layers"], 2)
            self.assertEqual(observed["blobs"], 3)

    def test_compressed_writer_and_aggregate_bounds_stop_before_overflow(self):
        output = io.BytesIO()
        bounded = build._BoundedWriter(output, 3)
        self.assertEqual(bounded.write(b"abc"), 3)
        with self.assertRaisesRegex(ValueError, "compressed bound"):
            bounded.write(b"d")
        with tempfile.TemporaryDirectory() as directory:
            root, archive, tested_descriptor = self.root(directory)
            inspected = build.inspect_docker_archive(
                archive, tested_descriptor,
                build.load_image_inspect(
                    archive.with_name("fixture-image-inspect.json")))
            inspected["layers"][0]["size"] = build.MAX_PRODUCED_OCI_BYTES
            target = root / ".cache/oversized.oci.tar.gz"
            with self.assertRaisesRegex(ValueError, "expanded"):
                build.write_oci_archive(archive, target, inspected)
            self.assertFalse(target.exists())

    def test_committed_prerequisite_slot_blocks_public_producer(self):
        with tempfile.TemporaryDirectory() as directory:
            root, archive, image_id = self.root(directory)
            archive.unlink()
            archive.with_name("fixture-image-inspect.json").unlink()
            (root / ".cache/container-fixture-producer-run.json").unlink()
            with self.assertRaisesRegex(
                    ValueError, "offline-ubuntu-package-closure"):
                build.build_fixture_output(
                    root, image_id, self.environment,
                    available_bytes=build.MIN_FREE_AFTER_SAVE)
            self.assertFalse(
                (root / ".cache/container-native-fixture-output").exists())

    def test_hosted_producer_and_upload_remain_unwired(self):
        check = (ROOT / "image/container/hosted/check.py").read_text()
        wrapper = (ROOT / "scripts/check-container-fixtures.sh").read_text()
        workflow = (ROOT / ".github/workflows/container-fixtures.yml").read_text()
        self.assertNotIn("native_fixture_build", check)
        self.assertNotIn("PRODUCE_NATIVE_FIXTURE=", wrapper)
        self.assertNotIn(inputs.ARTIFACT_NAME, workflow)


if __name__ == "__main__":
    unittest.main()
