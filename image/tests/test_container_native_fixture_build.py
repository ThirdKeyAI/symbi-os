"""Offline tests for the bounded native fixture OCI producer."""
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import shlex
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from image.atomic.contract import unpack_oci
from image.container import native_fixture_build as build
from image.container import native_fixture_inputs as inputs
from image.container.hosted import check as hosted


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

    def docker_archive(self, path, *, inspect_target=None, diff_id=None,
                       duplicate=False, unsafe=False, repeat_layer=False,
                       compressed=False, extra_blob=False,
                       layer_size_delta=0):
        layer_uncompressed = b"bounded fixture image layer"
        layer_raw = (gzip.compress(layer_uncompressed, mtime=0)
                     if compressed else layer_uncompressed)
        layer_digest = "sha256:" + digest(layer_raw)
        layer_diff_id = "sha256:" + digest(layer_uncompressed)
        layer_descriptors = [{
            "mediaType": (
                "application/vnd.oci.image.layer.v1.tar+gzip"
                if compressed else "application/vnd.oci.image.layer.v1.tar"),
            "digest": layer_digest,
            "size": len(layer_raw) + layer_size_delta,
            "annotations": {"org.symbi-os.test.layer": "preserved"},
        } for _ in range(2 if repeat_layer else 1)]
        diff_ids = [(layer_diff_id if diff_id is None else diff_id)
                    for _ in layer_descriptors]
        config_raw = build.canonical({
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": diff_ids,
            },
        })
        config_digest = "sha256:" + digest(config_raw)
        config_descriptor = {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": len(config_raw),
            "annotations": {"org.symbi-os.test.config": "preserved"},
        }
        manifest_raw = build.canonical({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config_descriptor,
            "layers": layer_descriptors,
            "annotations": {"org.symbi-os.test.manifest": "preserved"},
        })
        initial_target_digest = "sha256:" + digest(manifest_raw)
        inspected_target = (initial_target_digest
                            if inspect_target is None else inspect_target)
        index_raw = build.canonical({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": initial_target_digest,
                "size": len(manifest_raw),
                "annotations": {
                    "org.opencontainers.image.ref.name": "qualification",
                },
                "platform": {"architecture": "amd64", "os": "linux"},
            }],
        })
        with tarfile.open(path, "w") as output:
            for name in ("blobs/", "blobs/sha256/"):
                self._row(output, name, b"", tarfile.DIRTYPE)
            self._row(output, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
            self._row(output, "index.json", index_raw)
            self._row(output, "manifest.json", b"[]")
            self._row(output, "repositories", b"{}")
            self._row(
                output, build._blob_name(initial_target_digest), manifest_raw)
            self._row(output, build._blob_name(config_digest), config_raw)
            self._row(output, build._blob_name(layer_digest), layer_raw)
            if extra_blob:
                self._row(output, "blobs/sha256/" + "f" * 64, b"extra")
            if duplicate:
                self._row(output, "index.json", index_raw)
            if unsafe:
                self._row(output, "unsafe", b"", tarfile.SYMTYPE)
        inspection = {
            "Id": inspected_target,
            "Descriptor": {
                "digest": inspected_target,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "size": len(manifest_raw),
            },
            "Architecture": "amd64",
            "Os": "linux",
            "RepoDigests": [],
            "RootFS": {"Type": "layers", "Layers": diff_ids},
        }
        path.with_name("fixture-image-inspect.json").write_text(
            json.dumps([inspection]) + "\n")
        return inspected_target

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
            ROOT / "image/container/ubuntu-fixture-packages.lock.json",
            root / "image/container/ubuntu-fixture-packages.lock.json")
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
            root, _, initial_target_digest = self.root(directory)
            record = build._export_fixture_output(
                root, initial_target_digest, self.environment,
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
                + manifest["image"]["generated_target_digest"])
            self.assertEqual(
                manifest["tested_image"]["initial_target_digest"],
                initial_target_digest)
            self.assertEqual(len({
                manifest["tested_image"]["initial_target_digest"],
                manifest["tested_image"]["config_digest"],
                manifest["image"]["generated_target_digest"],
            }), 3)
            self.assertEqual(
                manifest["tested_image"]["initial_target_media_type"],
                build.OCI_MANIFEST_MEDIA_TYPE)
            self.assertEqual(
                manifest["tested_image"]["config_media_type"],
                build.OCI_CONFIG_MEDIA_TYPE)
            self.assertEqual(
                manifest["image"]["generated_target_media_type"],
                build.OCI_MANIFEST_MEDIA_TYPE)
            with tarfile.open(output / inputs.ARCHIVE_NAME, "r:gz") as generated:
                target = generated.extractfile(build._blob_name(
                    manifest["image"]["generated_target_digest"])).read()
            generated_manifest = json.loads(target)
            self.assertEqual(
                generated_manifest["annotations"][
                    build.SOURCE_TARGET_ANNOTATION], initial_target_digest)
            self.assertEqual(
                generated_manifest["annotations"]["org.symbi-os.test.manifest"],
                "preserved")
            self.assertEqual(
                generated_manifest["config"]["annotations"],
                {"org.symbi-os.test.config": "preserved"})
            self.assertEqual(
                generated_manifest["layers"][0]["annotations"],
                {"org.symbi-os.test.layer": "preserved"})
            verify = root / ".cache/verify-produced-oci"
            observed = unpack_oci(
                output / inputs.ARCHIVE_NAME, verify,
                manifest["image"]["generated_target_digest"],
                manifest["tested_image"]["config_digest"],
                max_bytes=build.MAX_PRODUCED_OCI_BYTES)
            self.assertEqual(
                observed["config_digest"],
                manifest["tested_image"]["config_digest"])
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
            root, archive, initial_target_digest = self.root(directory)
            inspection = json.loads(
                archive.with_name("fixture-image-inspect.json").read_text())
            inspection[0]["Id"] = "sha256:" + "9" * 64
            archive.with_name("fixture-image-inspect.json").write_text(
                json.dumps(inspection) + "\n")
            with self.assertRaises(ValueError):
                build._export_fixture_output(
                    root, initial_target_digest, self.environment,
                    available_bytes=build.MIN_FREE_AFTER_SAVE)
            self.assertFalse(
                (root / ".cache/container-native-fixture-output").exists())
        with tempfile.TemporaryDirectory() as directory:
            root, archive, initial_target_digest = self.root(directory)
            inspection = json.loads(
                archive.with_name("fixture-image-inspect.json").read_text())
            inspection[0]["Descriptor"]["digest"] = "sha256:" + "7" * 64
            archive.with_name("fixture-image-inspect.json").write_text(
                json.dumps(inspection) + "\n")
            with self.assertRaises(ValueError):
                build._export_fixture_output(
                    root, initial_target_digest, self.environment,
                    available_bytes=build.MIN_FREE_AFTER_SAVE)
            self.assertFalse(
                (root / ".cache/container-native-fixture-output").exists())
        with tempfile.TemporaryDirectory() as directory:
            root, archive, _ = self.root(directory)
            initial_target_digest = self.docker_archive(
                archive, inspect_target="sha256:" + "6" * 64)
            with self.assertRaisesRegex(ValueError, "index target"):
                build._export_fixture_output(
                    root, initial_target_digest, self.environment,
                    available_bytes=build.MIN_FREE_AFTER_SAVE)
            self.assertFalse(
                (root / ".cache/container-native-fixture-output").exists())
        with tempfile.TemporaryDirectory() as directory:
            root, archive, _ = self.root(directory)
            initial_target_digest = self.docker_archive(
                archive, diff_id="sha256:" + "8" * 64)
            with self.assertRaises(ValueError):
                build._export_fixture_output(
                    root, initial_target_digest, self.environment,
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
                record["image"]["generated_target_digest"],
                record["tested_image"]["config_digest"],
                max_bytes=build.MAX_PRODUCED_OCI_BYTES)
            self.assertEqual(observed["layers"], 2)
            self.assertEqual(observed["blobs"], 3)

    def test_gzip_layer_is_bounded_by_uncompressed_diff_id_and_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root, archive, _ = self.root(directory)
            initial_target_digest = self.docker_archive(
                archive, compressed=True)
            inspected = build.inspect_docker_archive(
                archive, initial_target_digest,
                build.load_image_inspect(
                    archive.with_name("fixture-image-inspect.json")))
            self.assertEqual(
                inspected["layers"][0]["descriptor"]["mediaType"],
                "application/vnd.oci.image.layer.v1.tar+gzip")
            record = build._export_fixture_output(
                root, initial_target_digest, self.environment,
                available_bytes=build.MIN_FREE_AFTER_SAVE)
            output = root / ".cache/container-native-fixture-output"
            with tarfile.open(output / inputs.ARCHIVE_NAME, "r:gz") as generated:
                raw = generated.extractfile(build._blob_name(
                    record["image"]["generated_target_digest"])).read()
            generated_manifest = json.loads(raw)
            self.assertEqual(
                generated_manifest["layers"],
                [inspected["layers"][0]["descriptor"]])

    def test_rejects_unreferenced_blob_and_wrong_descriptor_size(self):
        for options in ({"extra_blob": True}, {"layer_size_delta": 1}):
            with self.subTest(options=options), \
                    tempfile.TemporaryDirectory() as directory:
                root, archive, _ = self.root(directory)
                initial_target_digest = self.docker_archive(archive, **options)
                with self.assertRaises(ValueError):
                    build._export_fixture_output(
                        root, initial_target_digest, self.environment,
                        available_bytes=build.MIN_FREE_AFTER_SAVE)
                self.assertFalse(
                    (root / ".cache/container-native-fixture-output").exists())

    def test_compressed_writer_and_aggregate_bounds_stop_before_overflow(self):
        output = io.BytesIO()
        bounded = build._BoundedWriter(output, 3)
        self.assertEqual(bounded.write(b"abc"), 3)
        with self.assertRaisesRegex(ValueError, "compressed bound"):
            bounded.write(b"d")
        with tempfile.TemporaryDirectory() as directory:
            root, archive, initial_target_digest = self.root(directory)
            inspected = build.inspect_docker_archive(
                archive, initial_target_digest,
                build.load_image_inspect(
                    archive.with_name("fixture-image-inspect.json")))
            inspected["layers"][0]["descriptor"]["size"] = (
                build.MAX_PRODUCED_OCI_BYTES)
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
                    ValueError, "offline-ubuntu-package-selection"):
                build.build_fixture_output(
                    root, image_id, self.environment,
                    available_bytes=build.MIN_FREE_AFTER_SAVE)
            self.assertFalse(
                (root / ".cache/container-native-fixture-output").exists())

    def test_hosted_producer_preflight_and_cold_load_are_wired_without_upload(self):
        check = (ROOT / "image/container/hosted/check.py").read_text()
        wrapper = (ROOT / "scripts/check-container-fixtures.sh").read_text()
        workflow = (ROOT / ".github/workflows/container-fixtures.yml").read_text()
        self.assertIn("native_fixture_build.build_fixture_output", check)
        self.assertIn("cold-load-fixture-image", check)
        self.assertIn("cold-prove-fixture-image-absent", check)
        self.assertLess(
            check.index("cold-prove-fixture-image-absent"),
            check.index("cold-load-fixture-image"),
        )
        self.assertNotIn("PRODUCE_NATIVE_FIXTURE=", wrapper)
        self.assertIn("native_fixture_build --root . preflight", workflow)
        self.assertNotIn(inputs.ARTIFACT_NAME, workflow)

    def test_hosted_daemon_uses_attempt_namespaces_and_containerd_store(self):
        environment = {
            "GITHUB_RUN_ID": "812",
            "GITHUB_RUN_ATTEMPT": "2",
        }
        namespaces = hosted.docker_namespaces(environment)
        self.assertEqual(namespaces, (
            "symbi-fixtures-run-812-attempt-2",
            "plugins.symbi-fixtures-run-812-attempt-2",
        ))
        configuration = hosted.docker_daemon_configuration(
            Path("/bounded/work"), Path("/bounded/runsc"),
            Path("/sys/fs/cgroup/symbi-container-fixtures-812.service"),
            environment)
        self.assertEqual(
            configuration["features"], {"containerd-snapshotter": True})
        self.assertEqual(configuration["containerd-namespace"], namespaces[0])
        self.assertEqual(
            configuration["containerd-plugins-namespace"], namespaces[1])
        self.assertNotEqual(namespaces[0], namespaces[1])
        self.assertNotIn("moby", namespaces)
        for field, value in (
                ("GITHUB_RUN_ID", "0"),
                ("GITHUB_RUN_ID", "0812"),
                ("GITHUB_RUN_ATTEMPT", "2.0"),
                ("GITHUB_RUN_ATTEMPT", 2)):
            changed = dict(environment)
            changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(
                    ValueError):
                hosted.docker_namespaces(changed)

    def test_hosted_daemon_requires_exact_snapshotter_driver_row(self):
        namespaces = (
            "symbi-fixtures-run-812-attempt-2",
            "plugins.symbi-fixtures-run-812-attempt-2",
        )
        valid = {
            "Driver": "overlayfs",
            "DriverStatus": [
                ["driver-type", hosted.CONTAINERD_SNAPSHOTTER_DRIVER],
                ["Backing Filesystem", "extfs"],
            ],
            "Containerd": {"Namespaces": {
                "Containers": namespaces[0],
                "Plugins": namespaces[1],
            }},
        }
        self.assertEqual(
            hosted.require_containerd_snapshotter(
                json.dumps(valid), namespaces), valid)
        failures = (
            ({}, namespaces),
            ({**valid, "DriverStatus": []}, namespaces),
            ({**valid, "DriverStatus": [
                ["driver-type", "io.containerd.snapshotter.v2"],
            ]}, namespaces),
            ({**valid, "DriverStatus": [
                ["driver-type", hosted.CONTAINERD_SNAPSHOTTER_DRIVER],
                ["driver-type", hosted.CONTAINERD_SNAPSHOTTER_DRIVER],
            ]}, namespaces),
            ({**valid, "DriverStatus": [["driver-type"]]}, namespaces),
            ({key: value for key, value in valid.items()
              if key != "Containerd"}, namespaces),
            ({**valid, "Containerd": {"Namespaces": {
                "Containers": "moby", "Plugins": "plugins.moby",
            }}}, namespaces),
            ({**valid, "Containerd": {"Namespaces": {
                "Containers": namespaces[0], "Plugins": "wrong.plugins",
            }}}, namespaces),
            ({**valid, "Containerd": {"Namespaces": []}}, namespaces),
            (valid, (namespaces[0], namespaces[0])),
        )
        for info, expected in failures:
            with self.subTest(info=info, expected=expected), self.assertRaises(
                    ValueError):
                hosted.require_containerd_snapshotter(
                    json.dumps(info), expected)

    def test_hosted_save_space_gate_precedes_and_blocks_docker_save(self):
        calls = []

        def fake_run(*args, **kwargs):
            calls.append((args, kwargs))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            work = root / ".cache/container-fixture-work"
            work.mkdir(parents=True)
            target = "sha256:" + "1" * 64
            environment = {"DOCKER_HOST": "unix:///var/run/docker.sock"}
            with self.assertRaisesRegex(ValueError, "pre-save working space"):
                hosted.save_native_fixture_image(
                    fake_run, root, work, target, environment,
                    available_bytes=build.MIN_FREE_BEFORE_SAVE - 1)
            self.assertEqual(calls, [])
            archive = hosted.save_native_fixture_image(
                fake_run, root, work, target, environment,
                available_bytes=build.MIN_FREE_BEFORE_SAVE)
            self.assertEqual(
                archive, work / build.DOCKER_ARCHIVE_NAME)
            self.assertEqual(calls, [(('fixture-image-save', [
                'docker', 'image', 'save', '--output', str(archive), target,
            ], 900), {'env': environment})])

    def test_clean_wrapper_forwards_exact_exporter_identity_and_rejects_omissions(self):
        wrapper = (ROOT / "scripts/check-container-fixtures.sh").read_text()
        start = wrapper.index("/usr/bin/env -i")
        end = wrapper.index("PYTHONDONTWRITEBYTECODE=1", start)
        tokens = shlex.split(wrapper[start:end].replace("\\\n", " "))
        self.assertEqual(tokens[:2], ["/usr/bin/env", "-i"])
        pairs = [token.split("=", 1) for token in tokens[2:]]
        assignments = dict(pairs)
        self.assertEqual(len(assignments), len(pairs))
        forwarded = {
            key: value for key, value in assignments.items()
            if key.startswith("GITHUB_") or key == "RUNNER_ENVIRONMENT"
        }
        expected = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_EVENT_NAME": "$GITHUB_EVENT_NAME",
            "GITHUB_REPOSITORY": "$GITHUB_REPOSITORY",
            "GITHUB_SHA": "$GITHUB_SHA",
            "GITHUB_RUN_ID": "$GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT": "$GITHUB_RUN_ATTEMPT",
            "GITHUB_REF_NAME": "$GITHUB_REF_NAME",
        }
        self.assertEqual(forwarded, expected)
        clean_environment = {
            key: (self.environment[value[1:]] if value.startswith("$") else value)
            for key, value in forwarded.items()
        }
        self.assertEqual(
            build.validate_producer_identity(clean_environment, self.metadata),
            {
                "source_commit": self.environment["GITHUB_SHA"],
                "run_id": 812, "run_attempt": 2, "workflow_id": 77,
            })
        for field in sorted(expected):
            missing = dict(clean_environment)
            missing.pop(field)
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, "exact manual hosted identity"):
                build.validate_producer_identity(missing, self.metadata)

        alias_environment = dict(clean_environment)
        alias_environment["GITHUB_RUN_ATTEMPT"] = "1"
        alias_metadata = copy.deepcopy(self.metadata)
        alias_metadata["run_attempt"] = True
        with self.assertRaisesRegex(ValueError, "producer metadata changed"):
            build.validate_producer_identity(
                alias_environment, alias_metadata)

    def test_fixture_account_creation_cleans_post_useradd_validation_failure(self):
        calls = []

        def run(command, **arguments):
            calls.append((command, arguments))
            return SimpleNamespace(returncode=0)

        with mock.patch.object(
                hosted.pwd, "getpwnam",
                side_effect=[KeyError(), SimpleNamespace(pw_uid=0)]), \
                mock.patch.object(hosted.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(ValueError, "not unprivileged"):
                hosted.create_fixture_account(self.environment)
        self.assertEqual(calls[0][0][0], "/usr/sbin/useradd")
        self.assertEqual(calls[1][0][0], "/usr/sbin/userdel")
        self.assertEqual(calls[1][0][-1], calls[0][0][-1])
        self.assertEqual(calls[1][1], {"check": False, "timeout": 30})


if __name__ == "__main__":
    unittest.main()
