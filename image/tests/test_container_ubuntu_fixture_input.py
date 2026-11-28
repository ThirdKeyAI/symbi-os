"""Static and adversarial tests for selected offline Ubuntu fixture inputs."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from image.container import ubuntu_fixture_inputs as inputs
from image.container import ubuntu_fixture_package_build as build
from image.container import ubuntu_fixture_package_hosted as hosted
from image.container import ubuntu_fixture_packages as packages


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
FALSE_CLAIMS = (
    "verified", "qualified", "container_qualified", "signature_qualified",
    "os_qualified", "release_qualified",
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def release_bytes(source, index_raw):
    return (
        "Origin: Ubuntu\n"
        "Label: Ubuntu\n"
        f"Suite: {source['suite']}\n"
        f"Codename: {build.EXPECTED_CODENAMES[source['suite']]}\n"
        f"Date: {build.format_release_time(NOW - timedelta(hours=1))}\n"
        "Architectures: amd64 arm64\n"
        "Components: main restricted universe multiverse\n"
        "SHA256:\n"
        f" {digest(index_raw)} {len(index_raw)} main/binary-amd64/Packages.xz\n"
    ).encode()


def identity(name, raw):
    return {"path": name, "bytes": len(raw), "sha256": digest(raw)}


def write_zip(path, members):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w") as bundle:
            for name, raw, mode, compression in members:
                row = zipfile.ZipInfo(name)
                row.create_system = 3
                row.external_attr = mode << 16
                row.compress_type = compression
                bundle.writestr(row, raw)


class UbuntuFixtureInputContract(unittest.TestCase):
    def setUp(self):
        self.pending = packages.unique_json(
            ROOT, "image/container/ubuntu-fixture-packages.lock.json",
            inputs.MAX_SELECTION_BYTES)

    @staticmethod
    def _root(directory):
        root = Path(directory).resolve()
        (root / "image/container").mkdir(parents=True)
        (root / "upstream").mkdir()
        shutil.copyfile(
            ROOT / "image/container/native-fixture.lock.json",
            root / "image/container/native-fixture.lock.json")
        shutil.copyfile(
            ROOT / "upstream/symbiont.toml",
            root / "upstream/symbiont.toml")
        return root

    @staticmethod
    def _run_metadata(lock):
        return {
            "id": lock["run"]["id"],
            "run_attempt": lock["run"]["attempt"],
            "event": lock["workflow"]["event"],
            "path": lock["workflow"]["path"],
            "workflow_id": lock["workflow"]["id"],
            "head_sha": lock["run"]["head_sha"],
            "head_branch": lock["run"]["head_branch"],
            "status": lock["run"]["status"],
            "conclusion": lock["run"]["conclusion"],
            "repository": lock["run"]["repository"],
            "head_repository": lock["run"]["head_repository"],
        }

    @staticmethod
    def _bind_zip(lock, kind, path):
        raw = path.read_bytes()
        binding = {"bytes": len(raw), "sha256": digest(raw)}
        lock["artifacts"][kind]["zip"] = binding
        lock["artifacts"][kind]["api"]["size_in_bytes"] = binding["bytes"]
        lock["artifacts"][kind]["api"]["digest"] = (
            "sha256:" + binding["sha256"])

    @staticmethod
    def _write_lock(root, lock):
        (root / "image/container/ubuntu-fixture-packages.lock.json").write_text(
            json.dumps(lock, indent=2) + "\n")

    def fixture(self, directory):
        root = self._root(directory)
        pending = copy.deepcopy(self.pending)
        payloads = {
            "ca-certificates": b"ca package payload",
            "git": b"git package payload",
            "python3": b"python package payload",
        }
        versions = {
            "ca-certificates": "20240203",
            "git": "1:2.43.0-1ubuntu7.1",
            "python3": "3.12.3-0ubuntu2",
        }
        filenames = {
            "ca-certificates": (
                "pool/main/c/ca-certificates/"
                "ca-certificates_20240203_all.deb"),
            "git": "pool/main/g/git/git_1:2.43.0-1ubuntu7.1_amd64.deb",
            "python3": (
                "pool/main/p/python3/python3_3.12.3-0ubuntu2_amd64.deb"),
        }
        releases, indexes, metadata, index_hashes = [], [], {}, {}
        for sequence, source in enumerate(packages.EXPECTED_SOURCES):
            index_raw = (source["suite"] + " exact Packages.xz").encode()
            release_raw = release_bytes(source, index_raw)
            signed = build.validate_signed_release(
                release_raw, source, NOW,
                build.expected_freshness_policy(source))
            release = build.release_record(
                source, signed,
                {"bytes": len(release_raw), "sha256": digest(release_raw)},
                {
                    "signing_fingerprint": packages.ARCHIVE_SIGNER_FINGERPRINT,
                    "status_sha256": format(sequence + 1, "064x"),
                })
            index = build.index_record(source, signed["index"])
            releases.append(release)
            indexes.append(index)
            metadata["metadata/" + release["inrelease"]["filename"]] = release_raw
            metadata["metadata/" + index["filename"]] = index_raw
            index_hashes[source["suite"]] = index["sha256"]

        package_rows, package_members = [], {}
        source = packages.EXPECTED_SOURCES[0]
        for name in sorted(payloads):
            raw, filename = payloads[name], filenames[name]
            package_rows.append({
                "package": name,
                "version": versions[name],
                "architecture": "all" if name == "ca-certificates" else "amd64",
                "filename": filename,
                "url": source["base_url"] + "/" + filename,
                "bytes": len(raw),
                "sha256": digest(raw),
                "source": {
                    "suite": "noble", "component": "main",
                    "index_architecture": "amd64",
                    "index_sha256": index_hashes["noble"],
                },
            })
            package_members["packages/" + Path(filename).name] = raw
        package_rows.sort(key=packages.package_identity)
        manifest = build.candidate_manifest(
            pending, releases, indexes, package_rows, verified_at=NOW,
            base_status={"bytes": 100, "sha256": "a" * 64},
            tools={
                "apt_get": {"version": "apt 2.8.3", "sha256": "b" * 64},
                "dpkg": {"version": "dpkg 1.22.6", "sha256": "c" * 64},
                "gpgv": {"version": "gpgv 2.4.4", "sha256": "d" * 64},
            },
            command_hashes={name: marker * 64 for name, marker in (
                ("apt_update", "1"), ("apt_uri_plan", "2"),
                ("apt_simulation", "3"), ("dpkg_plan", "4"),
            )},
            download_order=[row["sha256"] for row in package_rows],
            metadata_provenance={
                "producer_run_id": 123,
                "producer_run_attempt": 1,
                "producer_head_sha": "e" * 40,
                "producer_head_tree": "d" * 40,
                "producer_branch": "card/P0-05-retained-metadata",
                "artifact_id": 456,
                "artifact_name": "container-ubuntu-fixture-metadata",
                "artifact_bytes": 789,
                "artifact_api_sha256": "f" * 64,
                "artifact_zip_sha256": "f" * 64,
                "manifest_sha256": "0" * 64,
                "discovery_contract_sha256": "1" * 64,
                "selection_contract_sha256": "3" * 64,
                "metadata_lock_sha256": "2" * 64,
            },
        )
        manifest_raw = (json.dumps(manifest, indent=2) + "\n").encode()

        lock = copy.deepcopy(pending)
        lock.update(state="selected", selected=True, scope=inputs.SELECTED_SCOPE)
        lock["workflow"]["id"] = 91
        lock["run"] = {
            "id": 812, "attempt": 2, "head_sha": "4" * 40,
            "head_branch": "card/P0-05-fixture-producer",
            "status": "completed", "conclusion": "success",
            "repository": packages.REPOSITORY,
            "head_repository": packages.REPOSITORY,
        }
        workflow_run = {
            "id": 812, "head_sha": "4" * 40,
            "repository_id": packages.REPOSITORY["id"],
            "head_repository_id": packages.REPOSITORY["id"],
        }
        for kind, artifact_id, name in (
                ("candidate", 301, packages.ARTIFACT_NAME),
                ("evidence", 302, inputs.EVIDENCE_ARTIFACT_NAME)):
            lock["artifacts"][kind]["api"] = {
                "id": artifact_id, "name": name, "size_in_bytes": 1,
                "digest": "sha256:" + "0" * 64, "expired": False,
                "workflow_run": workflow_run,
            }
        lock["candidate"] = {
            "manifest": identity("manifest.json", manifest_raw),
            "producer_contract_sha256": inputs._canonical_sha256(
                inputs.producer_contract(lock)),
            "release_metadata": releases,
            "package_indexes": indexes,
            "package_count": len(package_rows),
            "package_bytes": sum(row["bytes"] for row in package_rows),
            "packages": package_rows,
        }
        producer_result = {
            "schema": 1, "mode": "produce", "state": "candidate-unselected",
            "passed": True, "authoritative": False, "selected": False,
            "qualified": False, "container_qualified": False,
            "signature_qualified": False, "os_qualified": False,
            "release_qualified": False, "repository": packages.REPOSITORY,
            "contract_sha256": "6" * 64, "lock_sha256": "7" * 64,
            "verified_at": "2026-11-27T12:00:00Z",
            "rootfs": {}, "metadata": [], "commands": [], "download": {},
            "run": {
                "id": 812, "attempt": 2, "head_sha": "4" * 40,
                "head_tree": "5" * 40, "workflow": inputs.WORKFLOW_PATH,
                "event": inputs.WORKFLOW_EVENT,
            },
            "candidate": {
                "created": True, "manifest_sha256": digest(manifest_raw),
                "state": "candidate-unselected",
            },
            "phase_ledger": {}, "scope": hosted.RESULT_SCOPE,
        }
        producer_raw = (json.dumps(producer_result, indent=2) + "\n").encode()
        evidence_payloads = {
            "logs/empty.stderr": b"",
            "logs/phase.txt": b"bounded retained evidence\n",
            "producer-result.json": producer_raw,
        }
        lock["evidence"] = {
            "producer_result": identity("producer-result.json", producer_raw),
            "members": [
                identity(name, raw)
                for name, raw in sorted(evidence_payloads.items())
            ],
        }

        candidate_payloads = {
            "manifest.json": manifest_raw, **metadata, **package_members,
        }
        candidate_members = [
            (name, raw, stat.S_IFREG | 0o600, zipfile.ZIP_STORED)
            for name, raw in candidate_payloads.items()
        ]
        evidence_members = [
            (name, raw, stat.S_IFREG | 0o600, zipfile.ZIP_DEFLATED)
            for name, raw in evidence_payloads.items()
        ]
        candidate_zip, evidence_zip = root / "candidate.zip", root / "evidence.zip"
        write_zip(candidate_zip, candidate_members)
        write_zip(evidence_zip, evidence_members)
        self._bind_zip(lock, "candidate", candidate_zip)
        self._bind_zip(lock, "evidence", evidence_zip)
        self._write_lock(root, lock)
        return {
            "root": root, "lock": lock, "candidate_zip": candidate_zip,
            "evidence_zip": evidence_zip,
            "candidate_members": candidate_members,
            "evidence_members": evidence_members,
        }

    def consume(self, fixture, destination, candidate_zip=None, evidence_zip=None):
        lock = fixture["lock"]
        return inputs.consume_selected_inputs(
            fixture["root"], self._run_metadata(lock),
            lock["artifacts"]["candidate"]["api"],
            lock["artifacts"]["evidence"]["api"],
            fixture["candidate_zip"] if candidate_zip is None else candidate_zip,
            fixture["evidence_zip"] if evidence_zip is None else evidence_zip,
            destination, available_bytes=16 * 1024**3)

    def test_committed_schema_two_slot_is_exactly_pending_and_all_false(self):
        self.assertEqual(inputs.validate_pending_lock(
            ROOT, copy.deepcopy(self.pending)), {
                "ready": False, "status": "pending",
                "blocker": "offline-ubuntu-package-selection",
            })
        self.assertEqual(self.pending["schema"], 2)
        self.assertIs(self.pending["selected"], False)
        for field in FALSE_CLAIMS:
            self.assertIs(self.pending[field], False)
        self.assertIsNone(self.pending["run"]["id"])
        for artifact in self.pending["artifacts"].values():
            self.assertIsNone(artifact["api"]["id"])
            self.assertIsNone(artifact["zip"]["sha256"])
        self.assertEqual(self.pending["candidate"]["packages"], [])
        self.assertEqual(self.pending["evidence"]["members"], [])

    def test_pending_mutations_cannot_invent_run_artifacts_rows_or_claims(self):
        mutations = []
        for field in ("selected", *FALSE_CLAIMS):
            changed = copy.deepcopy(self.pending)
            changed[field] = True
            mutations.append(changed)
        for path, value in (
                (("workflow", "id"), 9), (("run", "id"), 8),
                (("artifacts", "candidate", "api", "id"), 7),
                (("artifacts", "evidence", "zip", "sha256"), "a" * 64),
                (("candidate", "package_count"), 1)):
            changed = copy.deepcopy(self.pending)
            target = changed
            for name in path[:-1]:
                target = target[name]
            target[path[-1]] = value
            mutations.append(changed)
        changed = copy.deepcopy(self.pending)
        changed["repository"]["id"] = 1
        mutations.append(changed)
        changed = copy.deepcopy(self.pending)
        changed["unexpected"] = True
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                inputs.validate_pending_lock(ROOT, changed)

    def test_selected_contract_consumes_only_exact_run_artifacts_and_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            lock = fixture["lock"]
            self.assertTrue(inputs.validate_selected_lock(
                fixture["root"], lock)["ready"])
            destination = fixture["root"] / "materialized"
            result = self.consume(fixture, destination)
            self.assertTrue(result["ready"])
            self.assertTrue(result["selected"])
            for field in FALSE_CLAIMS:
                self.assertIs(result[field], False)
            candidate = inputs.validate_materialized_candidate(
                fixture["root"], destination / "candidate")
            self.assertEqual(candidate["manifest"]["packages"],
                             lock["candidate"]["packages"])
            actual = {
                path.relative_to(destination / "candidate").as_posix()
                for path in (destination / "candidate").rglob("*")
                if path.is_file()
            }
            self.assertEqual(actual, {
                name for name, *_ in fixture["candidate_members"]
            })
            empty_evidence = destination / "evidence/logs/empty.stderr"
            self.assertTrue(empty_evidence.is_file())
            self.assertEqual(empty_evidence.read_bytes(), b"")

    def test_selected_metadata_and_every_exact_binding_mutation_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            base, mutations = fixture["lock"], []
            for path, value in (
                    (("run", "id"), 813),
                    (("run", "head_sha"), "6" * 40),
                    (("artifacts", "candidate", "api", "id"), 302),
                    (("artifacts", "candidate", "zip", "sha256"), "f" * 64),
                    (("candidate", "producer_contract_sha256"), "d" * 64),
                    (("candidate", "package_count"), 4),
                    (("candidate", "package_bytes"), 1),
                    (("evidence", "producer_result", "sha256"), "c" * 64)):
                changed = copy.deepcopy(base)
                target = changed
                for name in path[:-1]:
                    target = target[name]
                target[path[-1]] = value
                mutations.append(changed)
            changed = copy.deepcopy(base)
            changed["candidate"]["package_indexes"].reverse()
            mutations.append(changed)
            changed = copy.deepcopy(base)
            changed["evidence"]["members"].reverse()
            mutations.append(changed)
            for changed in mutations:
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    inputs.validate_selected_lock(fixture["root"], changed)

    def test_selected_artifact_limits_match_each_transfer_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            for kind, maximum in (
                    ("candidate", packages.MAX_ARTIFACT_BYTES),
                    ("evidence", inputs.MAX_EVIDENCE_ARTIFACT_BYTES)):
                changed = copy.deepcopy(fixture["lock"])
                changed["artifacts"][kind]["api"]["size_in_bytes"] = maximum + 1
                changed["artifacts"][kind]["zip"]["bytes"] = maximum + 1
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    inputs.validate_selected_lock(fixture["root"], changed)

    def test_install_plan_preserves_order_and_preconfigures_exact_predepends(self):
        def package(name, marker):
            return {
                "package": name,
                "filename": "pool/main/x/" + name + "/" + name + "_1_amd64.deb",
                "sha256": marker * 64,
            }

        rows = [
            package("base", "1"),
            package("python3.12-minimal", "2"),
            package("python3-minimal", "3"),
            package("python3", "4"),
        ]
        manifest = {
            "packages": rows,
            "download_order": [row["sha256"] for row in rows],
        }
        plan = inputs.install_plan(manifest)
        self.assertEqual(
            [row["package"] for row in plan],
            ["base", "python3.12-minimal", "python3-minimal", "python3"],
        )
        self.assertEqual(
            [row["preconfigure_before"] for row in plan],
            [False, False, True, True],
        )
        self.assertEqual(
            [row["target"] for row in plan],
            [
                "0000-install-base.deb",
                "0001-install-python3.12-minimal.deb",
                "0002-preconfigure-python3-minimal.deb",
                "0003-preconfigure-python3.deb",
            ],
        )

        mutations = []
        changed = copy.deepcopy(manifest)
        changed["download_order"][1:3] = reversed(changed["download_order"][1:3])
        mutations.append(changed)
        changed = copy.deepcopy(manifest)
        changed["packages"][1]["package"] = "renamed-target"
        mutations.append(changed)
        changed = copy.deepcopy(manifest)
        changed["download_order"][0] = changed["download_order"][1]
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                inputs.install_plan(changed)

    def test_install_staging_is_exact_and_rejects_source_links_or_changes(self):
        def package(name, marker, raw):
            return {
                "package": name,
                "filename": "pool/main/x/" + name + "/" + name + "_1_amd64.deb",
                "bytes": len(raw),
                "sha256": digest(raw),
            }

        payloads = {
            "base": b"base package",
            "python3.12-minimal": b"python 3.12 minimal package",
            "python3-minimal": b"python 3 minimal package",
            "python3": b"python package",
        }
        rows = [package(name, str(index), raw) for index, (name, raw) in
                enumerate(payloads.items(), start=1)]
        manifest = {
            "packages": rows,
            "download_order": [row["sha256"] for row in rows],
        }

        def prepare(directory):
            candidate = Path(directory).resolve() / "candidate"
            packages_dir = candidate / "packages"
            packages_dir.mkdir(parents=True)
            for row in rows:
                (packages_dir / Path(row["filename"]).name).write_bytes(
                    payloads[row["package"]])
            return candidate

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            candidate = prepare(directory)
            destination = root / "staged"
            with mock.patch.object(
                    inputs, "validate_materialized_candidate",
                    return_value={"manifest": manifest, "root": candidate}):
                plan = inputs.stage_install_packages(
                    root, candidate, destination)
            self.assertEqual(
                sorted(path.name for path in destination.iterdir()),
                [row["target"] for row in plan],
            )
            for row in plan:
                self.assertEqual(
                    (destination / row["target"]).read_bytes(),
                    payloads[row["package"]],
                )

        for mutation in (
                "symlink", "fifo", "hardlink", "bytes", "destination"):
            with self.subTest(mutation=mutation), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                candidate = prepare(directory)
                source = candidate / "packages" / Path(rows[0]["filename"]).name
                destination = root / "staged"
                if mutation == "symlink":
                    original = source.with_name("original.deb")
                    source.rename(original)
                    source.symlink_to(original.name)
                elif mutation == "fifo":
                    source.unlink()
                    os.mkfifo(source)
                elif mutation == "hardlink":
                    os.link(source, source.with_name("alias.deb"))
                elif mutation == "bytes":
                    source.write_bytes(b"changed")
                else:
                    destination.mkdir()
                with mock.patch.object(
                        inputs, "validate_materialized_candidate",
                        return_value={"manifest": manifest, "root": candidate}), \
                        self.assertRaises((OSError, ValueError)):
                    inputs.stage_install_packages(
                        root, candidate, destination)

    def test_downloaded_metadata_manifest_and_row_bindings_fail_on_use(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            lock = fixture["lock"]
            run = self._run_metadata(lock)
            run["workflow_id"] += 1
            with self.assertRaises(ValueError):
                inputs.consume_selected_inputs(
                    fixture["root"], run,
                    lock["artifacts"]["candidate"]["api"],
                    lock["artifacts"]["evidence"]["api"],
                    fixture["candidate_zip"], fixture["evidence_zip"],
                    fixture["root"] / "wrong-run")
            artifact = copy.deepcopy(lock["artifacts"]["candidate"]["api"])
            artifact["id"] += 1
            with self.assertRaises(ValueError):
                inputs.consume_selected_inputs(
                    fixture["root"], self._run_metadata(lock), artifact,
                    lock["artifacts"]["evidence"]["api"],
                    fixture["candidate_zip"], fixture["evidence_zip"],
                    fixture["root"] / "wrong-artifact")

            for label, mutate in (
                    ("manifest", lambda value: value["candidate"]["manifest"].__setitem__(
                        "sha256", "e" * 64)),
                    ("package-row", lambda value: value["candidate"]["packages"][0].__setitem__(
                        "sha256", "b" * 64))):
                changed = copy.deepcopy(lock)
                mutate(changed)
                self._write_lock(fixture["root"], changed)
                fixture["lock"] = changed
                with self.subTest(label=label), self.assertRaises(ValueError):
                    self.consume(fixture, fixture["root"] / ("wrong-" + label))
            fixture["lock"] = lock
            self._write_lock(fixture["root"], lock)

    def test_complete_candidate_staging_descriptor_copies_exact_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            candidate = root / "candidate"
            metadata_dir = candidate / "metadata"
            packages_dir = candidate / "packages"
            metadata_dir.mkdir(parents=True)
            packages_dir.mkdir()
            manifest_raw = b'{"candidate":"selected"}\n'
            (candidate / "manifest.json").write_bytes(manifest_raw)

            metadata = {}
            releases = []
            indexes = []
            for index, suite in enumerate(
                    ("noble", "noble-updates", "noble-security"), start=1):
                release_name = suite + "_InRelease"
                release_raw = (suite + " release\n").encode()
                index_name = suite + "_Packages.xz"
                index_raw = (suite + " packages\n").encode()
                metadata[release_name] = release_raw
                metadata[index_name] = index_raw
                releases.append({"inrelease": {
                    **identity(release_name, release_raw),
                    "filename": release_name,
                }})
                indexes.append({**identity(index_name, index_raw),
                                "filename": index_name})
            for name, raw in metadata.items():
                (metadata_dir / name).write_bytes(raw)

            package_payloads = {
                "base": b"base package",
                "python3.12-minimal": b"python 3.12 minimal package",
                "python3-minimal": b"python 3 minimal package",
                "python3": b"python package",
            }
            package_rows = []
            for name, raw in package_payloads.items():
                filename = name + "_1_amd64.deb"
                (packages_dir / filename).write_bytes(raw)
                package_rows.append({
                    "package": name, "version": "1",
                    "architecture": "amd64", "filename": filename,
                    "bytes": len(raw), "sha256": digest(raw),
                })
            manifest = {
                "packages": package_rows,
                "download_order": [row["sha256"] for row in package_rows],
            }
            lock = {"candidate": {
                "manifest": identity("manifest.json", manifest_raw),
                "release_metadata": releases,
                "package_indexes": indexes,
                "packages": package_rows,
            }}
            context = root / "context"
            context.mkdir()
            with mock.patch.object(inputs, "load_lock", return_value=lock), \
                    mock.patch.object(inputs, "validate_selected_lock"), \
                    mock.patch.object(
                        inputs, "validate_candidate_manifest",
                        return_value=manifest):
                staged = inputs.stage_install_candidate(
                    root, candidate, context)
            self.assertEqual(
                digest((context / "manifest.json").read_bytes()),
                staged["manifest_sha256"])
            self.assertEqual(
                {path.name for path in (context / "metadata").iterdir()},
                set(metadata))
            self.assertEqual(
                {path.name for path in (context / "packages").iterdir()},
                {row["target"] for row in staged["plan"]})

    def test_selected_expansion_reserves_snapshot_and_context_space(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            lock = fixture["lock"]
            candidate_bytes = sum(
                row["bytes"] for row in inputs._candidate_bindings(lock).values())
            evidence_bytes = sum(
                row["bytes"] for row in lock["evidence"]["members"])
            required = (
                3 * candidate_bytes + evidence_bytes
                + inputs.MATERIALIZATION_FREE_RESERVE)
            destination = fixture["root"] / "space-rejected"
            with self.assertRaisesRegex(ValueError, "bounded staging space"):
                inputs.consume_selected_inputs(
                    fixture["root"], self._run_metadata(lock),
                    lock["artifacts"]["candidate"]["api"],
                    lock["artifacts"]["evidence"]["api"],
                    fixture["candidate_zip"], fixture["evidence_zip"],
                    destination, available_bytes=required - 1)
            self.assertFalse(destination.exists())

    def _reject_candidate_members(self, fixture, members):
        changed_zip = fixture["root"] / "changed-candidate.zip"
        write_zip(changed_zip, members)
        self._bind_zip(fixture["lock"], "candidate", changed_zip)
        self._write_lock(fixture["root"], fixture["lock"])
        destination = fixture["root"] / "rejected"
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            self.consume(fixture, destination, candidate_zip=changed_zip)
        self.assertFalse(destination.exists())

    def test_candidate_zip_rejects_missing_extra_duplicate_and_traversal(self):
        for mutation in ("missing", "extra", "duplicate", "traversal"):
            with self.subTest(mutation=mutation), \
                    tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                members = list(fixture["candidate_members"])
                if mutation == "missing":
                    members.pop()
                elif mutation == "extra":
                    members.append((
                        "unexpected", b"x", stat.S_IFREG | 0o600,
                        zipfile.ZIP_STORED))
                elif mutation == "duplicate":
                    members.append(members[0])
                else:
                    members.append((
                        "../escape", b"x", stat.S_IFREG | 0o600,
                        zipfile.ZIP_STORED))
                self._reject_candidate_members(fixture, members)

    def test_candidate_zip_rejects_symlink_special_size_and_compression(self):
        for mutation, mode, compression, suffix in (
                ("symlink", stat.S_IFLNK | 0o777, zipfile.ZIP_STORED, b""),
                ("fifo", stat.S_IFIFO | 0o600, zipfile.ZIP_STORED, b""),
                ("size", stat.S_IFREG | 0o600, zipfile.ZIP_STORED, b"extra"),
                ("compression", stat.S_IFREG | 0o600, zipfile.ZIP_BZIP2, b"")):
            with self.subTest(mutation=mutation), \
                    tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                members = list(fixture["candidate_members"])
                index = next(i for i, row in enumerate(members)
                             if row[0].startswith("packages/"))
                name, raw, _, _ = members[index]
                members[index] = (name, raw + suffix, mode, compression)
                self._reject_candidate_members(fixture, members)

    def test_candidate_zip_rejects_crc_corruption_after_outer_hash_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            changed = fixture["root"] / "crc-candidate.zip"
            shutil.copyfile(fixture["candidate_zip"], changed)
            with zipfile.ZipFile(changed) as bundle:
                row = next(row for row in bundle.infolist()
                           if row.filename.startswith("packages/"))
                with changed.open("r+b") as stream:
                    stream.seek(row.header_offset)
                    header = stream.read(30)
                    name_bytes = int.from_bytes(header[26:28], "little")
                    extra_bytes = int.from_bytes(header[28:30], "little")
                    stream.seek(row.header_offset + 30 + name_bytes + extra_bytes)
                    original = stream.read(1)
                    stream.seek(-1, os.SEEK_CUR)
                    stream.write(bytes([original[0] ^ 1]))
            self._bind_zip(fixture["lock"], "candidate", changed)
            self._write_lock(fixture["root"], fixture["lock"])
            destination = fixture["root"] / "crc-rejected"
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                self.consume(fixture, destination, candidate_zip=changed)
            self.assertFalse(destination.exists())

    def test_zip_directory_is_bounded_before_zipfile_materializes_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "hostile.zip"
            archive.write_bytes(struct.pack(
                "<4s4H2LH", b"PK\x05\x06", 0, 0, 65534, 65534,
                65534 * 46, 0, 0))
            destination = root / "output"
            destination.mkdir()
            expected = {"expected": {
                "path": "expected", "bytes": 1, "sha256": digest(b"x")}}
            with mock.patch.object(
                    zipfile, "ZipFile",
                    side_effect=AssertionError("ZipFile must not be reached")):
                with self.assertRaisesRegex(ValueError, "member count"):
                    inputs._extract_bundle(
                        archive, expected, destination, 1, "hostile artifact")

    def test_zip_preflight_rejects_last_fake_eocd_inside_comment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "comment-hostile.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("expected", b"x")
                bundle.comment = (
                    b"comment-prefix"
                    + struct.pack(
                        "<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1,
                        0x7fffffff, 0, 0))
            destination = root / "output"
            destination.mkdir()
            expected = {"expected": {
                "path": "expected", "bytes": 1, "sha256": digest(b"x")}}
            with mock.patch.object(
                    zipfile, "ZipFile",
                    side_effect=AssertionError("ZipFile must not be reached")):
                with self.assertRaisesRegex(
                        ValueError, "central directory is oversized"):
                    inputs._extract_bundle(
                        archive, expected, destination, 1, "hostile artifact")

    def test_zip_preflight_honors_zip64_locator_without_legacy_sentinels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "zip64-hostile.zip"
            zip64 = struct.pack(
                "<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1,
                inputs.MAX_ZIP_CENTRAL_DIRECTORY_BYTES + 1, 0)
            locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, 0, 1)
            legacy = struct.pack(
                "<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, 46, 10, 0)
            archive.write_bytes(zip64 + locator + legacy)
            destination = root / "output"
            destination.mkdir()
            expected = {"expected": {
                "path": "expected", "bytes": 1, "sha256": digest(b"x")}}
            with mock.patch.object(
                    zipfile, "ZipFile",
                    side_effect=AssertionError("ZipFile must not be reached")):
                with self.assertRaisesRegex(
                        ValueError, "central directory is oversized"):
                    inputs._extract_bundle(
                        archive, expected, destination, 1, "hostile artifact")

    def test_zip_preflight_rejects_records_hidden_by_understated_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "hidden-record.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("expected", b"x")
                bundle.writestr("hidden", b"y")
            raw = bytearray(archive.read_bytes())
            end = raw.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(end, 0)
            struct.pack_into("<HH", raw, end + 8, 1, 1)
            archive.write_bytes(raw)
            destination = root / "output"
            destination.mkdir()
            expected = {"expected": {
                "path": "expected", "bytes": 1, "sha256": digest(b"x")}}
            with mock.patch.object(
                    zipfile, "ZipFile",
                    side_effect=AssertionError("ZipFile must not be reached")):
                with self.assertRaisesRegex(ValueError, "hidden records"):
                    inputs._extract_bundle(
                        archive, expected, destination, 1, "hostile artifact")

    def test_zip_preflight_rejects_malformed_central_record_lengths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "malformed-record.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("expected", b"x")
            raw = bytearray(archive.read_bytes())
            central = raw.find(b"PK\x01\x02")
            self.assertGreaterEqual(central, 0)
            struct.pack_into("<H", raw, central + 28, 0xffff)
            archive.write_bytes(raw)
            destination = root / "output"
            destination.mkdir()
            expected = {"expected": {
                "path": "expected", "bytes": 1, "sha256": digest(b"x")}}
            with mock.patch.object(
                    zipfile, "ZipFile",
                    side_effect=AssertionError("ZipFile must not be reached")):
                with self.assertRaisesRegex(ValueError, "record is invalid"):
                    inputs._extract_bundle(
                        archive, expected, destination, 1, "hostile artifact")

    def test_api_and_producer_result_integer_fields_reject_bool_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            lock = fixture["lock"]
            strict_lock = copy.deepcopy(lock)
            strict_lock["run"]["attempt"] = 1
            run = self._run_metadata(strict_lock)
            run["run_attempt"] = True
            with self.assertRaises(ValueError):
                inputs.validate_run_metadata_unchecked(run, strict_lock)

            metadata = copy.deepcopy(lock["artifacts"]["candidate"]["api"])
            metadata["expired"] = 0
            with self.assertRaises(ValueError):
                inputs.validate_artifact_metadata(metadata, lock, "candidate")

            producer_row = next(
                row for row in fixture["evidence_members"]
                if row[0] == "producer-result.json")
            result = json.loads(producer_row[1])
            result["run"]["attempt"] = True
            strict_lock["evidence"]["producer_result"] = identity(
                "producer-result.json",
                (json.dumps(result, indent=2) + "\n").encode())
            raw = (json.dumps(result, indent=2) + "\n").encode()
            with self.assertRaises(ValueError):
                inputs.validate_producer_result(strict_lock, raw)

    def test_evidence_zip_and_result_false_claims_are_enforced(self):
        mutations = {
            "true claim": lambda result: result.update(
                signature_qualified=True),
            "invented verified claim": lambda result: result.update(
                verified=True),
            "unknown claim": lambda result: result.update(
                third_party_qualified=False),
            "misleading scope": lambda result: result.update(
                scope="Qualified package evidence"),
        }
        for description, mutate in mutations.items():
            with self.subTest(description=description), \
                    tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                members = list(fixture["evidence_members"])
                index = next(i for i, row in enumerate(members)
                             if row[0] == "producer-result.json")
                name, raw, mode, compression = members[index]
                result = json.loads(raw)
                mutate(result)
                changed_raw = (json.dumps(result, indent=2) + "\n").encode()
                members[index] = (name, changed_raw, mode, compression)
                changed = fixture["root"] / "changed-evidence.zip"
                write_zip(changed, members)
                fixture["lock"]["evidence"]["producer_result"] = identity(
                    name, changed_raw)
                fixture["lock"]["evidence"]["members"] = [
                    identity(member_name, member_raw)
                    for member_name, member_raw, *_ in sorted(members)
                ]
                self._bind_zip(fixture["lock"], "evidence", changed)
                self._write_lock(fixture["root"], fixture["lock"])
                destination = fixture["root"] / "evidence-rejected"
                with self.assertRaises(ValueError):
                    self.consume(fixture, destination, evidence_zip=changed)
                self.assertFalse(destination.exists())

    def test_outer_zip_and_destination_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            alias = fixture["root"] / "candidate-alias.zip"
            alias.symlink_to(fixture["candidate_zip"].name)
            with self.assertRaises(ValueError):
                self.consume(fixture, fixture["root"] / "link-rejected",
                             candidate_zip=alias)
            destination = fixture["root"] / "existing"
            destination.mkdir()
            with self.assertRaises(ValueError):
                self.consume(fixture, destination)

    def test_stream_receiver_bounds_bytes_hash_space_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cache = root / ".cache"
            cache.mkdir()
            raw = b"selected artifact bytes"
            target = cache / "selected.zip"
            received = inputs.receive_stream(
                root, io.BytesIO(raw), target, len(raw), len(raw), digest(raw),
                available_bytes=len(raw) + inputs.TRANSFER_FREE_RESERVE)
            self.assertEqual(received, {
                "bytes": len(raw), "sha256": digest(raw)})
            self.assertEqual(target.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

            oversized = cache / "oversized.zip"
            with self.assertRaises(ValueError):
                inputs.receive_stream(
                    root, io.BytesIO(raw + b"x"), oversized, len(raw),
                    available_bytes=len(raw) + inputs.TRANSFER_FREE_RESERVE)
            self.assertFalse(oversized.exists())

            changed = cache / "changed.zip"
            with self.assertRaises(ValueError):
                inputs.receive_stream(
                    root, io.BytesIO(raw), changed, len(raw), len(raw), "0" * 64,
                    available_bytes=len(raw) + inputs.TRANSFER_FREE_RESERVE)
            self.assertFalse(changed.exists())

            no_space = cache / "no-space.zip"
            with self.assertRaises(ValueError):
                inputs.receive_stream(
                    root, io.BytesIO(raw), no_space, len(raw),
                    available_bytes=(
                        len(raw) + inputs.TRANSFER_FREE_RESERVE - 1))
            self.assertFalse(no_space.exists())

    def test_public_check_and_transfer_order_fail_closed_while_pending(self):
        script = ROOT / "scripts/check-container-ubuntu-packages.sh"
        checked = subprocess.run(
            ["bash", str(script), "check"], cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn('"ready": false', checked.stdout)
        blocked = subprocess.run(
            ["bash", str(script), "consume"], cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False)
        self.assertEqual(blocked.returncode, 2)
        transfer = (ROOT / "scripts/check-container-ubuntu-package-input.sh").read_text()
        self.assertLess(transfer.index("pre-transfer"), transfer.index("gh api"))
        self.assertLess(transfer.index(" metadata "), transfer.index("/zip\""))
        self.assertIn("${#selected[@]} == 8", transfer)
        self.assertIn("ubuntu_fixture_inputs --root \"$root\" receive", transfer)
        self.assertNotIn('gh api "$endpoint" >', transfer)
        self.assertNotIn("readarray -t selected < <(", transfer)
        self.assertIn("selection=$(\n", transfer)
        self.assertIn("unset SYMBI_GITHUB_TOKEN GH_TOKEN GITHUB_TOKEN", transfer)
        self.assertIn('env GH_TOKEN="$github_token" gh api', transfer)
        self.assertIn('"$evidence_zip" 553648128', transfer)

        fixture_check = (ROOT / "scripts/check-container-fixtures.sh").read_text()
        workflow = (ROOT / ".github/workflows/container-fixtures.yml").read_text()
        transfer_seconds = sum(
            int(value) for value in re.findall(r"^download (\d+) ", transfer,
                                               flags=re.MULTILINE))
        runtime_minutes = int(re.search(
            r"RuntimeMaxSec=(\d+)min", fixture_check).group(1))
        job_minutes = int(re.search(
            r"timeout-minutes: (\d+)", workflow).group(1))
        self.assertEqual(transfer_seconds, 990)
        self.assertEqual(runtime_minutes, 75)
        self.assertIn("--kill-after=5s 300s", transfer)
        explicit_seconds = (
            transfer_seconds + 300 + 30 + 600 + runtime_minutes * 60)
        self.assertGreaterEqual(job_minutes * 60 - explicit_seconds, 600)
        self.assertIn("SYMBI_GITHUB_TOKEN: ${{ github.token }}", workflow)
        self.assertIn('mkdir -m 0700 -- "$staging"', fixture_check)
        self.assertIn('entries=("$staging"/*)', fixture_check)
        self.assertIn('Container fixture evidence paths must be new.',
                      fixture_check)
        self.assertIn('if (( status == 0 )); then', fixture_check)
        self.assertIn('public_seen == 1', fixture_check)
        self.assertIn('mv --no-clobber -- "$staging" "$evidence"',
                      fixture_check)
        self.assertIn("printf 'evidence_ready=true\\n'", fixture_check)
        self.assertIn(
            "steps.fixture_run.outputs.evidence_ready == 'true'", workflow)
        self.assertNotIn('if: always()\n', workflow)
        self.assertNotIn(
            'mkdir -p "$root/.cache/container-fixture-evidence"',
            fixture_check)

    def test_docker_workflow_and_native_export_route_are_static_and_offline(self):
        dockerfile = (
            ROOT / "image/container/hosted/fixture/Dockerfile").read_text()
        check = (ROOT / "image/container/hosted/check.py").read_text()
        workflow = (ROOT / ".github/workflows/container-fixtures.yml").read_text()
        native = (ROOT / "image/container/native_fixture_build.py").read_text()
        self.assertNotIn("apt-get", dockerfile)
        self.assertIn("DEBIAN_FRONTEND=noninteractive", dockerfile)
        self.assertIn(
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            dockerfile,
        )
        self.assertIn("COPY packages/", dockerfile)
        self.assertIn('for archive in "$@"; do', dockerfile)
        self.assertIn("????-preconfigure-*.deb", dockerfile)
        self.assertNotIn("????-python3-minimal_", dockerfile)
        self.assertNotIn("????-python3_", dockerfile)
        self.assertLess(
            dockerfile.index("dpkg --configure -a"),
            dockerfile.index('dpkg --unpack "$archive"'),
        )
        self.assertIn("dpkg --configure -a", dockerfile)
        self.assertIn("ubuntu_fixture_inputs.stage_install_candidate", check)
        self.assertIn("expected_public_files = {'result.json'}", check)
        self.assertIn("bindings, expected_public_files", check)
        self.assertIn("validate_fixture_output(fixture_output, setup)", check)
        self.assertLess(
            check.index("quiesce_fixture_account(account, require_clean=True)"),
            check.index("validate_fixture_output(fixture_output, setup)"))
        self.assertLess(
            check.index("validate_fixture_output(fixture_output, setup)"),
            check.index("collect_public(\n            fixture_output"))
        self.assertIn("create_fixture_account(os.environ)", check)
        self.assertNotIn("FIXTURE_USER", check)
        self.assertIn("'--network=none'", check)
        self.assertIn("cold-load-fixture-image", check)
        self.assertIn("native_fixture_build.build_fixture_output", check)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertLess(
            workflow.index("native_fixture_build --root . preflight"),
            workflow.index("check-container-ubuntu-package-input.sh"))
        self.assertNotIn("container-native-fixture-output", workflow)
        self.assertIn("def preflight_fixture_output", native)
        prerequisites = json.loads((
            ROOT / "image/container/native-fixture-build.lock.json").read_text())
        self.assertEqual(prerequisites["state"], "pending")
        self.assertIs(prerequisites["cold_load"]["verified"], False)
        for claim in (
                "selected", "built", "qualified", "container_qualified",
                "signature_qualified", "os_qualified", "release_qualified"):
            self.assertIs(prerequisites[claim], False)


if __name__ == "__main__":
    unittest.main()
