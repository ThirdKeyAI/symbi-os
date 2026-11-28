"""Fail-closed tests for retained Ubuntu repository metadata."""
import copy
from contextlib import redirect_stdout
from datetime import datetime, timezone
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError
import warnings
import zipfile

from image.container import ubuntu_fixture_metadata as metadata
from image.container import ubuntu_fixture_package_hosted as hosted
from image.container import ubuntu_fixture_packages as packages


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 28, 6, 0, tzinfo=timezone.utc)


def write_private(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


class Response(io.BytesIO):
    status = 200

    def __init__(self, payload, url, *, length=None):
        super().__init__(payload)
        self.url = url
        self.headers = {
            "Content-Length": str(len(payload) if length is None else length),
        }

    def geturl(self):
        return self.url


class RetainedUbuntuMetadataTests(unittest.TestCase):
    def setUp(self):
        self.committed, self.lock = hosted.load_contract(ROOT)
        self.assertEqual(self.committed["state"], "ready")
        self.pending = copy.deepcopy(self.committed)
        self.pending["state"] = "pending-discovery"
        self.pending["scope"] = hosted.PENDING_SCOPE
        for pin in self.pending["metadata_pins"]:
            pin["inrelease"] = {"bytes": None, "sha256": None}
            pin["packages_xz"] = {"bytes": None, "sha256": None}
        self.pending["metadata_source"] = {
            "state": "pending",
            "producer": {
                "run_id": None,
                "run_attempt": None,
                "head_sha": None,
                "head_tree": None,
                "branch": None,
            },
            "artifact": {
                "id": None,
                "name": metadata.ARTIFACT_NAME,
                "bytes": None,
                "api_sha256": None,
                "zip_sha256": None,
            },
            "manifest_sha256": None,
            "discovery_contract_sha256": None,
            "lock_sha256": None,
        }
        hosted.validate_contract(ROOT, self.pending, self.lock)

    @staticmethod
    def _write_zip(path, rows):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(
                    path, "w", compression=zipfile.ZIP_STORED,
                    allowZip64=True) as archive:
                for name, raw, mode in rows:
                    info = zipfile.ZipInfo(name)
                    info.compress_type = zipfile.ZIP_STORED
                    info.external_attr = mode << 16
                    archive.writestr(info, raw)
        path.chmod(0o600)

    def fixture(self, base):
        source_root = base / "source"
        output_root = base / "output"
        source_root.mkdir(mode=0o700)
        output_root.mkdir(mode=0o700)
        inputs = {}
        results = []
        for sequence, source in enumerate(packages.EXPECTED_SOURCES, 1):
            suite = source["suite"]
            inrelease_raw = ("signed InRelease " + suite).encode()
            index_raw = ("signed Packages.xz " + suite).encode()
            inrelease = source_root / (suite + "_InRelease")
            index = source_root / (
                suite + "_main_binary-amd64_Packages.xz")
            write_private(inrelease, inrelease_raw)
            write_private(index, index_raw)
            inputs[inrelease.name] = inrelease
            inputs[index.name] = index
            results.append({
                "suite": suite,
                "inrelease": {
                    "path": inrelease.name,
                    "bytes": len(inrelease_raw),
                    "sha256": hashlib.sha256(inrelease_raw).hexdigest(),
                },
                "packages_xz": {
                    "path": index.name,
                    "bytes": len(index_raw),
                    "sha256": hashlib.sha256(index_raw).hexdigest(),
                },
                "release": {"sequence": sequence},
                "signature": {"sequence": sequence},
            })
        run = {
            "id": 123,
            "attempt": 2,
            "head_sha": "a" * 40,
            "head_tree": "b" * 40,
            "workflow": hosted.WORKFLOW,
            "event": "workflow_dispatch",
        }
        branch = "card/P0-05-retained-metadata"
        artifact_directory = output_root / "metadata"
        manifest = metadata.write_discovery_artifact(
            artifact_directory, self.pending, self.lock, run, branch, NOW,
            results, inputs)
        rows = [
            (name, (artifact_directory / name).read_bytes(),
             stat.S_IFREG | 0o600)
            for name in sorted(metadata.expected_names())
        ]
        archive = base / "metadata.zip"
        self._write_zip(archive, rows)
        archive_raw = archive.read_bytes()
        archive_sha256 = hashlib.sha256(archive_raw).hexdigest()
        manifest_raw = (artifact_directory / metadata.MANIFEST_NAME).read_bytes()
        ready = copy.deepcopy(self.pending)
        ready["state"] = "ready"
        ready["scope"] = hosted.READY_SCOPE
        for pin, row in zip(
                ready["metadata_pins"], manifest["metadata"], strict=True):
            pin["inrelease"] = {
                key: row["inrelease"][key] for key in ("bytes", "sha256")
            }
            pin["packages_xz"] = {
                key: row["packages_xz"][key]
                for key in ("bytes", "sha256")
            }
        ready["metadata_source"] = {
            "state": "ready",
            "producer": {
                "run_id": run["id"],
                "run_attempt": run["attempt"],
                "head_sha": run["head_sha"],
                "head_tree": run["head_tree"],
                "branch": branch,
            },
            "artifact": {
                "id": 456,
                "name": metadata.ARTIFACT_NAME,
                "bytes": len(archive_raw),
                "api_sha256": archive_sha256,
                "zip_sha256": archive_sha256,
            },
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "discovery_contract_sha256": metadata.canonical_sha256(
                self.pending),
            "lock_sha256": metadata.canonical_sha256(self.lock),
        }
        hosted.validate_contract(ROOT, ready, self.lock)
        return {
            "source_root": source_root,
            "output_root": output_root,
            "inputs": inputs,
            "results": results,
            "run": run,
            "branch": branch,
            "artifact_directory": artifact_directory,
            "manifest": manifest,
            "manifest_raw": manifest_raw,
            "archive": archive,
            "rows": rows,
            "ready": ready,
        }

    def test_discovery_emits_exactly_seven_flat_private_false_claim_members(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = self.fixture(base)
            artifact = fixture["artifact_directory"]
            self.assertEqual(set(os.listdir(artifact)), metadata.expected_names())
            self.assertEqual(len(metadata.expected_names()), 7)
            for name in metadata.expected_names():
                path = artifact / name
                info = os.lstat(path)
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                self.assertEqual(Path(name).parts, (name,))
            provenance = metadata.provenance(fixture["ready"])
            self.assertEqual(
                provenance["selection_contract_sha256"],
                metadata.canonical_sha256(fixture["ready"]))
            self.assertEqual(
                provenance["metadata_lock_sha256"],
                metadata.canonical_sha256(self.lock))
            manifest = fixture["manifest"]
            for field in metadata.FALSE_CLAIMS:
                self.assertIs(manifest[field], False)
                changed = copy.deepcopy(manifest)
                changed[field] = True
                with self.subTest(claim=field), self.assertRaises(ValueError):
                    metadata.validate_manifest(
                        changed, workflow=self.pending["workflow"],
                        expected_contract_sha256=metadata.canonical_sha256(
                            self.pending),
                        expected_lock_sha256=metadata.canonical_sha256(
                            self.lock),
                        policies=self.pending["freshness_policy"])
            partial_parent = base / "partial-output"
            partial_parent.mkdir(mode=0o700)
            original_write = os.write

            def partial_write(descriptor, value):
                return original_write(descriptor, value[:5])

            with mock.patch.object(
                    metadata.os, "write", side_effect=partial_write):
                partial_manifest = metadata.write_discovery_artifact(
                    partial_parent / "metadata", self.pending, self.lock,
                    fixture["run"], fixture["branch"], NOW,
                    fixture["results"], fixture["inputs"])
            self.assertEqual(partial_manifest, fixture["manifest"])
            self.assertEqual(
                set(os.listdir(partial_parent / "metadata")),
                metadata.expected_names())

    def test_ready_selection_rejects_every_identity_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fixture(Path(directory))["ready"]["metadata_source"]
            cases = []
            for group, field, value in (
                    ("producer", "run_id", True),
                    ("producer", "run_attempt", 0),
                    ("producer", "head_sha", "a" * 39),
                    ("producer", "head_tree", "B" * 40),
                    ("producer", "branch", "../main"),
                    ("artifact", "id", True),
                    ("artifact", "name", "different"),
                    ("artifact", "bytes", 0),
                    ("artifact", "api_sha256", "0" * 64),
                    ("artifact", "zip_sha256", "1" * 64)):
                changed = copy.deepcopy(source)
                changed[group][field] = value
                cases.append((group + "." + field, changed))
            for field, value in (
                    ("manifest_sha256", "x" * 64),
                    ("discovery_contract_sha256", None),
                    ("lock_sha256", True)):
                changed = copy.deepcopy(source)
                changed[field] = value
                cases.append((field, changed))
            extra = copy.deepcopy(source)
            extra["caller"] = "authority"
            cases.append(("extra", extra))
            for name, changed in cases:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    metadata.validate_source_selection(changed, pending=False)

    def test_api_run_and_artifact_records_are_exactly_cross_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = self.fixture(Path(directory))["ready"]
            selected = ready["metadata_source"]
            producer = selected["producer"]
            artifact_selection = selected["artifact"]
            run = {
                "id": producer["run_id"],
                "run_attempt": producer["run_attempt"],
                "head_sha": producer["head_sha"],
                "head_branch": producer["branch"],
                "event": "workflow_dispatch",
                "path": ready["workflow"],
                "status": "completed",
                "conclusion": "success",
                "repository": {"id": packages.REPOSITORY["id"]},
                "head_repository": {"id": packages.REPOSITORY["id"]},
                "head_commit": {"tree_id": producer["head_tree"]},
            }
            artifact = {
                "id": artifact_selection["id"],
                "name": artifact_selection["name"],
                "size_in_bytes": artifact_selection["bytes"],
                "digest": "sha256:" + artifact_selection["api_sha256"],
                "expired": False,
                "workflow_run": {
                    "id": producer["run_id"],
                    "head_sha": producer["head_sha"],
                    "repository_id": packages.REPOSITORY["id"],
                    "head_repository_id": packages.REPOSITORY["id"],
                },
            }
            self.assertTrue(metadata.validate_github_records(
                run, artifact, ready))
            cases = []
            for field, value in (
                    ("id", producer["run_id"] + 1),
                    ("run_attempt", producer["run_attempt"] + 1),
                    ("head_sha", "0" * 40),
                    ("head_branch", "main"),
                    ("event", "push"),
                    ("path", "different.yml"),
                    ("status", "in_progress"),
                    ("conclusion", "failure")):
                changed = copy.deepcopy(run)
                changed[field] = value
                cases.append(("run." + field, changed, artifact))
            for group, field in (
                    ("repository", "id"),
                    ("head_repository", "id"),
                    ("head_commit", "tree_id")):
                changed = copy.deepcopy(run)
                changed[group][field] = 0 if field == "id" else "0" * 40
                cases.append(("run." + group, changed, artifact))
            for field, value in (
                    ("id", artifact_selection["id"] + 1),
                    ("name", "different"),
                    ("size_in_bytes", artifact_selection["bytes"] + 1),
                    ("digest", "sha256:" + "0" * 64),
                    ("expired", True)):
                changed = copy.deepcopy(artifact)
                changed[field] = value
                cases.append(("artifact." + field, run, changed))
            for field, value in (
                    ("id", producer["run_id"] + 1),
                    ("head_sha", "0" * 40),
                    ("repository_id", 0),
                    ("head_repository_id", 0)):
                changed = copy.deepcopy(artifact)
                changed["workflow_run"][field] = value
                cases.append(("artifact.workflow_run." + field, run, changed))
            for name, changed_run, changed_artifact in cases:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    metadata.validate_github_records(
                        changed_run, changed_artifact, ready)

    def test_zip_rejects_extra_nested_duplicate_link_and_changed_members(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = self.fixture(base)
            regular = stat.S_IFREG | 0o600
            rows = fixture["rows"]
            cases = []
            cases.append(("extra", rows + [("extra", b"x", regular)]))
            nested = copy.deepcopy(rows)
            nested[0] = ("nested/" + nested[0][0], nested[0][1], regular)
            cases.append(("nested", nested))
            cases.append(("duplicate", rows + [rows[0]]))
            linked = copy.deepcopy(rows)
            linked[0] = (linked[0][0], b"target", stat.S_IFLNK | 0o777)
            cases.append(("link", linked))
            changed = copy.deepcopy(rows)
            changed[0] = (changed[0][0], changed[0][1] + b"changed", regular)
            cases.append(("changed", changed))
            for name, archive_rows in cases:
                archive = base / (name + ".zip")
                self._write_zip(archive, archive_rows)
                contract = copy.deepcopy(fixture["ready"])
                raw = archive.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                contract["metadata_source"]["artifact"].update({
                    "bytes": len(raw),
                    "api_sha256": digest,
                    "zip_sha256": digest,
                })
                parent = base / (name + "-output")
                parent.mkdir(mode=0o700)
                with self.subTest(name=name), self.assertRaises(
                        (ValueError, zipfile.BadZipFile)):
                    metadata.extract_selected_zip(
                        archive, parent / "metadata", contract, self.lock)
            forged = bytearray(fixture["archive"].read_bytes())
            end = forged.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(end, 0)
            forged[end + 10:end + 12] = (8).to_bytes(2, "little")
            archive = base / "forged-directory.zip"
            write_private(archive, bytes(forged))
            contract = copy.deepcopy(fixture["ready"])
            digest = hashlib.sha256(forged).hexdigest()
            contract["metadata_source"]["artifact"].update({
                "bytes": len(forged),
                "api_sha256": digest,
                "zip_sha256": digest,
            })
            parent = base / "forged-directory-output"
            parent.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "directory is not bounded"):
                metadata.extract_selected_zip(
                    archive, parent / "metadata", contract, self.lock)
            unsupported = base / "unsupported-compression.zip"
            with zipfile.ZipFile(
                    unsupported, "w", compression=zipfile.ZIP_BZIP2) as archive:
                for member_name, raw, mode in rows:
                    info = zipfile.ZipInfo(member_name)
                    info.compress_type = zipfile.ZIP_BZIP2
                    info.external_attr = mode << 16
                    archive.writestr(info, raw)
            unsupported.chmod(0o600)
            raw = unsupported.read_bytes()
            contract = copy.deepcopy(fixture["ready"])
            digest = hashlib.sha256(raw).hexdigest()
            contract["metadata_source"]["artifact"].update({
                "bytes": len(raw),
                "api_sha256": digest,
                "zip_sha256": digest,
            })
            parent = base / "unsupported-compression-output"
            parent.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "unsafe member"):
                metadata.extract_selected_zip(
                    unsupported, parent / "metadata", contract, self.lock)

    def test_transfer_uses_api_token_only_before_signed_redirect_and_full_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = self.fixture(base)
            ready = fixture["ready"]
            selection = ready["metadata_source"]
            producer = selection["producer"]
            artifact_selection = selection["artifact"]
            run = {
                "id": producer["run_id"],
                "run_attempt": producer["run_attempt"],
                "head_sha": producer["head_sha"],
                "head_branch": producer["branch"],
                "event": "workflow_dispatch",
                "path": ready["workflow"],
                "status": "completed",
                "conclusion": "success",
                "repository": {"id": packages.REPOSITORY["id"]},
                "head_repository": {"id": packages.REPOSITORY["id"]},
                "head_commit": {"tree_id": producer["head_tree"]},
            }
            artifact = {
                "id": artifact_selection["id"],
                "name": artifact_selection["name"],
                "size_in_bytes": artifact_selection["bytes"],
                "digest": "sha256:" + artifact_selection["api_sha256"],
                "expired": False,
                "workflow_run": {
                    "id": producer["run_id"],
                    "head_sha": producer["head_sha"],
                    "repository_id": packages.REPOSITORY["id"],
                    "head_repository_id": packages.REPOSITORY["id"],
                },
            }
            redirect = (
                "https://results.blob.core.windows.net/actions-results/"
                "retained.zip?signature=public-test")

            class ApiOpener:
                requests = []

                def open(self, request, timeout):
                    self.requests.append((request, timeout))
                    test.assertEqual(
                        request.get_header("Authorization"), "Bearer secret")
                    url = request.full_url
                    if url.endswith("/zip"):
                        headers = Message()
                        headers["Location"] = redirect
                        raise HTTPError(
                            url, 302, "Found", headers, io.BytesIO())
                    value = artifact if "/artifacts/" in url else run
                    raw = json.dumps(value, separators=(",", ":")).encode()
                    return Response(raw, url)

            class DownloadOpener:
                requests = []

                def open(self, request, timeout):
                    self.requests.append((request, timeout))
                    test.assertIsNone(request.get_header("Authorization"))
                    test.assertEqual(request.full_url, redirect)
                    return Response(
                        fixture["archive"].read_bytes(), redirect)

            test = self
            api_opener = ApiOpener()
            download_opener = DownloadOpener()
            destination_parent = base / "transfer"
            destination_parent.mkdir(mode=0o700)
            original_write = os.write

            def partial_write(descriptor, value):
                return original_write(descriptor, value[:7])

            with mock.patch.object(
                    hosted, "load_contract", return_value=(ready, self.lock)), \
                    mock.patch.object(metadata.os, "write",
                                      side_effect=partial_write):
                manifest = metadata.fetch_selected(
                    ROOT, destination_parent / "metadata", "secret",
                    api_opener=api_opener,
                    download_opener=download_opener)
            self.assertEqual(manifest, fixture["manifest"])
            self.assertEqual(len(api_opener.requests), 3)
            self.assertEqual(len(download_opener.requests), 1)
            retained_zip = destination_parent / "metadata.zip"
            self.assertTrue(retained_zip.is_file())
            self.assertEqual(stat.S_IMODE(retained_zip.stat().st_mode), 0o600)
            self.assertEqual(
                hashlib.sha256(retained_zip.read_bytes()).hexdigest(),
                selection["artifact"]["zip_sha256"])
            loaded, paths = metadata.load_selected_directory(
                destination_parent / "metadata", ready, self.lock)
            self.assertEqual(loaded, fixture["manifest"])
            self.assertEqual(len(paths), 6)

    def test_real_private_parent_and_member_modes_are_mandatory(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = self.fixture(base)
            unsafe = base / "unsafe"
            unsafe.mkdir(mode=0o700)
            unsafe.chmod(0o755)
            try:
                with self.assertRaises(ValueError):
                    metadata.write_discovery_artifact(
                        unsafe / "metadata", self.pending, self.lock,
                        fixture["run"], fixture["branch"], NOW,
                        fixture["results"], fixture["inputs"])
            finally:
                unsafe.chmod(0o700)

            real = base / "real"
            real.mkdir(mode=0o700)
            linked = base / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                metadata.write_discovery_artifact(
                    linked / "metadata", self.pending, self.lock,
                    fixture["run"], fixture["branch"], NOW,
                    fixture["results"], fixture["inputs"])

            manifest_path = fixture["artifact_directory"] / "manifest.json"
            manifest_path.chmod(0o644)
            try:
                with self.assertRaises(ValueError):
                    metadata.load_selected_directory(
                        fixture["artifact_directory"], fixture["ready"],
                        self.lock)
            finally:
                manifest_path.chmod(0o600)

            fixture["archive"].chmod(0o644)
            parent = base / "bad-zip-output"
            parent.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                metadata.extract_selected_zip(
                    fixture["archive"], parent / "metadata",
                    fixture["ready"], self.lock)

            changed_lock = copy.deepcopy(self.lock)
            changed_lock["package_request"]["roots"].reverse()
            with self.assertRaisesRegex(ValueError, "current lock"):
                metadata.load_selected_directory(
                    fixture["artifact_directory"], fixture["ready"],
                    changed_lock)

    def test_api_json_rejects_duplicate_keys_length_mismatch_and_redirects(self):
        url = "https://api.github.com/repos/ThirdKeyAI/symbi-os/actions/runs/1"

        class Opener:
            def __init__(self, response):
                self.response = response

            def open(self, _request, timeout):
                self.test_timeout = timeout
                return self.response

        duplicate = b'{"id":1,"id":2}'
        with self.assertRaises(ValueError):
            metadata._api_json(
                url, "token", Opener(Response(duplicate, url)))
        with self.assertRaises(ValueError):
            metadata._api_json(
                url, "token", Opener(Response(b'{"id":1}', url, length=99)))
        with self.assertRaises(ValueError):
            metadata._api_json(
                url, "token", Opener(Response(b'{"id":1}', url + "/moved")))

    def test_artifact_redirect_rejects_untrusted_hosts_credentials_and_ports(self):
        url = (
            "https://api.github.com/repos/ThirdKeyAI/symbi-os/"
            "actions/artifacts/456/zip")

        class RedirectOpener:
            def __init__(self, location):
                self.location = location

            def open(self, _request, timeout):
                headers = Message()
                headers["Location"] = self.location
                raise HTTPError(
                    url, 302, "Found", headers, io.BytesIO())

        accepted = (
            "https://results.blob.core.windows.net/actions-results/"
            "metadata.zip?signature=test")
        self.assertEqual(
            metadata._download_redirect(
                url, "token", RedirectOpener(accepted)),
            accepted)
        for location in (
                "http://results.blob.core.windows.net/file",
                "https://user@results.blob.core.windows.net/file",
                "https://results.blob.core.windows.net:444/file",
                "https://results.blob.core.windows.net.attacker.example/file",
                "https://githubusercontent.com.attacker.example/file",
                "https://results.blob.core.windows.net/file#fragment"):
            with self.subTest(location=location), self.assertRaises(ValueError):
                metadata._download_redirect(
                    url, "token", RedirectOpener(location))

    def test_transfer_entrypoint_pops_token_and_emits_only_false_claims(self):
        manifest = {
            "state": "retained-metadata-unselected",
        }
        output = io.StringIO()
        environment = {"GITHUB_TOKEN": "secret"}
        with mock.patch.object(metadata, "fetch_selected", return_value=manifest), \
                mock.patch.dict(os.environ, environment, clear=True), \
                redirect_stdout(output):
            self.assertEqual(metadata.main([
                "--root", str(ROOT),
                "--destination", str(ROOT / ".cache-test-metadata"),
            ]), 0)
            self.assertNotIn("GITHUB_TOKEN", os.environ)
        record = json.loads(output.getvalue())
        self.assertEqual(record["state"], manifest["state"])
        self.assertIs(record["selected"], False)
        self.assertIs(record["qualified"], False)
        self.assertNotIn("secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()
