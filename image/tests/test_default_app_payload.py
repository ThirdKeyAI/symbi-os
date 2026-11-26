"""Acceptance and fault checks for the offline default-application payload."""
import copy
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

from image.default_apps.glum_release import load_release_inputs as load_glum_release_inputs
from image.default_apps.payload import (
    load_payload_contract,
    unpack_payload,
    verify_payload_tree,
)
from image.desktop.files import copy_regular as real_copy_regular


ROOT = Path(__file__).resolve().parents[2]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class DefaultApplicationPayload(unittest.TestCase):
    def test_real_contract_is_exact_unselected_and_has_no_download_helpers(self):
        contract = load_payload_contract()
        self.assertFalse(contract["selected_for_release"])
        self.assertFalse(contract["security_qualified"])
        self.assertFalse(contract["os_qualified"])
        self.assertEqual(set(contract["applications"]), {"yazi", "glum", "tootles"})
        expected = {
            "yazi": {
                "usr/bin/yazi",
                "usr/share/applications/yazi.desktop",
                "usr/share/licenses/yazi/LICENSE",
                "usr/share/licenses/yazi/LICENSE-ICONS",
            },
            "glum": {
                "usr/bin/glum",
                "usr/share/bash-completion/completions/glum",
                "usr/share/fish/vendor_completions.d/glum.fish",
                "usr/share/licenses/glum/LICENSE",
                "usr/share/licenses/glum/NOTICE",
                "usr/share/man/man1/glum.1",
                "usr/share/zsh/site-functions/_glum",
            },
            "tootles": {
                "usr/bin/tootles",
                "usr/share/applications/tootles.desktop",
                "usr/share/licenses/tootles/LICENSE",
                "usr/share/man/man1/tootles.1",
            },
        }
        for name, app in contract["applications"].items():
            with self.subTest(name=name):
                self.assertEqual({row["destination"] for row in app["files"]}, expected[name])
                self.assertEqual(sum(row["kind"] == "binary" for row in app["files"]), 1)
        forbidden = set(contract["forbidden_destinations"])
        self.assertIn("usr/bin/ya", forbidden)
        self.assertTrue(any("plugin" in path for path in forbidden))
        self.assertTrue(any("updater" in path for path in forbidden))

    def fixture(self, root):
        source_path = root / "source-inputs.json"
        release_path = root / "glum-release-inputs.json"
        sources = json.loads((ROOT / "image/default_apps/source-inputs.json").read_text())
        release = copy.deepcopy(load_glum_release_inputs())
        contract = json.loads((ROOT / "image/default_apps/payload-contract.json").read_text())
        contents = {}
        for name, app in contract["applications"].items():
            source = sources["applications"][name]
            for row in app["files"]:
                if row["kind"] == "binary":
                    raw = b"\x7fELFfixture:" + row["bundle"].encode() + b"\n"
                elif row["kind"] == "desktop":
                    raw = (
                        "[Desktop Entry]\nType=Application\nName="
                        + name.title()
                        + "\nExec="
                        + name
                        + "\nTerminal=true\n"
                    ).encode()
                else:
                    raw = ("fixture:" + row["bundle"] + "\n").encode()
                contents[row["bundle"]] = raw
                source_file = row.get("source_file")
                release_file = row.get("release_file")
                if source_file is not None:
                    expected = source["source"]["required_files"][source_file]
                    expected.update(bytes=len(raw), sha256=sha(raw))
                if release_file is not None:
                    expected = release["asset"]["files"][release_file]
                    expected.update(bytes=len(raw), sha256=sha(raw))
        source_path.write_text(json.dumps(sources, sort_keys=True) + "\n")
        release["asset"]["expanded_bytes"] = sum(
            row["bytes"] for row in release["asset"]["files"].values()
        )
        release_path.write_text(json.dumps(release, sort_keys=True) + "\n")
        contract["source_inputs_sha256"] = sha(source_path.read_bytes())
        contract["glum_release_inputs_sha256"] = sha(release_path.read_bytes())
        contract_path = root / "payload-contract.json"
        contract_path.write_text(json.dumps(contract, sort_keys=True) + "\n")
        with mock.patch(
            "image.default_apps.payload.load_release_inputs", return_value=release
        ):
            loaded = load_payload_contract(contract_path, source_path, release_path)
        applications = {}
        for name, app in loaded["applications"].items():
            source = sources["applications"][name]
            files = []
            for row in app["files"]:
                raw = contents[row["bundle"]]
                files.append({**row, "bytes": len(raw), "sha256": sha(raw)})
            application = {
                "version": source["version"],
                "revision": source["revision"],
                "source_archive_sha256": source["source"]["sha256"],
                "files": files,
            }
            if name == "glum":
                application["release_asset_sha256"] = release["asset"]["sha256"]
            applications[name] = application
        manifest = {
            "schema": 1,
            "compiled": True,
            "os_qualified": False,
            "source_commit": "a" * 40,
            "source_inputs_sha256": sha(source_path.read_bytes()),
            "glum_release_inputs_sha256": sha(release_path.read_bytes()),
            "plugins_included": False,
            "updaters_included": False,
            "applications": applications,
        }
        raw_manifest = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        archive = root / "default-apps-development-payload.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            manifest_info = zipfile.ZipInfo("manifest.json")
            manifest_info.external_attr = (stat.S_IFREG | 0o644) << 16
            bundle.writestr(manifest_info, raw_manifest)
            for member, raw in contents.items():
                info = zipfile.ZipInfo(member)
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                bundle.writestr(info, raw)
        lock = {
            "schema": 1,
            "development_included": True,
            "selected_for_release": False,
            "security_qualified": False,
            "os_qualified": False,
            "native_tests_passed": False,
            "tested_commit": "a" * 40,
            "run_id": 123,
            "source_inputs_sha256": sha(source_path.read_bytes()),
            "glum_release_inputs_sha256": sha(release_path.read_bytes()),
            "contract_sha256": sha(contract_path.read_bytes()),
            "manifest_sha256": sha(raw_manifest),
            "manifest": manifest,
            "artifact": {
                "id": 456,
                "name": archive.name,
                "bytes": archive.stat().st_size,
                "sha256": sha(archive.read_bytes()),
            },
            "attestation": {
                "verified": True,
                "issuer": "https://token.actions.githubusercontent.com",
                "repository": "ThirdKeyAI/symbi-os",
                "workflow": ".github/workflows/default-app-payload.yml",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "subject_sha256": sha(archive.read_bytes()),
                "bundle_sha256": "1" * 64,
            },
            "scope": "Fixture development payload; native desktop qualification remains open",
        }
        return (
            archive,
            lock,
            contract_path,
            source_path,
            release_path,
            release,
            contents,
        )

    def test_exact_payload_is_staged_offline_with_modes_and_source_assets_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive, lock, contract, sources, release_path, release, contents = self.fixture(
                root
            )
            destination = root / "payload"
            destination.mkdir()
            with mock.patch(
                "image.default_apps.payload.load_release_inputs", return_value=release
            ):
                manifest = unpack_payload(
                    archive,
                    lock,
                    contract,
                    sources,
                    destination,
                    "a" * 40,
                    release_path,
                )
            self.assertEqual(set(manifest["applications"]), {"yazi", "glum", "tootles"})
            for app in manifest["applications"].values():
                for row in app["files"]:
                    target = destination / row["destination"]
                    self.assertEqual(target.read_bytes(), contents[row["bundle"]])
                    self.assertEqual(target.stat().st_mode & 0o777, row["mode"])
            with mock.patch(
                "image.default_apps.payload.load_release_inputs", return_value=release
            ):
                report = verify_payload_tree(
                    destination, manifest, contract, sources, release_path
                )
            self.assertTrue(report["passed"])
            self.assertFalse(report["os_qualified"])
            self.assertFalse(report["native_desktop_qualified"])
            self.assertFalse(report["real_accounts_qualified"])

    def test_archive_manifest_source_and_qualification_mutations_are_refused(self):
        mutations = (
            "archive",
            "manifest",
            "revision",
            "source",
            "release",
            "qualified",
            "attestation",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                (
                    archive,
                    lock,
                    contract,
                    sources,
                    release_path,
                    release,
                    _,
                ) = self.fixture(root)
                if mutation == "archive":
                    archive.write_bytes(archive.read_bytes() + b"changed")
                elif mutation == "manifest":
                    lock["manifest_sha256"] = "0" * 64
                elif mutation == "revision":
                    lock["manifest"]["applications"]["yazi"]["revision"] = "b" * 40
                elif mutation == "source":
                    lock["manifest"]["applications"]["glum"]["source_archive_sha256"] = "0" * 64
                elif mutation == "release":
                    lock["selected_for_release"] = True
                elif mutation == "qualified":
                    lock["os_qualified"] = True
                else:
                    lock["attestation"]["verified"] = False
                destination = root / "payload"
                destination.mkdir()
                with mock.patch(
                    "image.default_apps.payload.load_release_inputs", return_value=release
                ), self.assertRaises(ValueError):
                    unpack_payload(
                        archive,
                        lock,
                        contract,
                        sources,
                        destination,
                        "a" * 40,
                        release_path,
                    )
                self.assertEqual(list(destination.iterdir()), [])

    def test_extra_members_source_asset_changes_and_unsafe_destinations_are_refused(self):
        for mutation in ("extra", "asset", "destination"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                (
                    archive,
                    lock,
                    contract_path,
                    source_path,
                    release_path,
                    release,
                    contents,
                ) = self.fixture(root)
                if mutation == "extra":
                    with zipfile.ZipFile(archive, "a") as bundle:
                        bundle.writestr("yazi/ya", b"runtime package manager")
                    lock["artifact"]["bytes"] = archive.stat().st_size
                    lock["artifact"]["sha256"] = sha(archive.read_bytes())
                    lock["attestation"]["subject_sha256"] = lock["artifact"]["sha256"]
                elif mutation == "asset":
                    sources = json.loads(source_path.read_text())
                    sources["applications"]["tootles"]["source"]["required_files"][
                        "packaging/tootles.desktop"
                    ]["sha256"] = "0" * 64
                    source_path.write_text(json.dumps(sources, sort_keys=True) + "\n")
                    contract = json.loads(contract_path.read_text())
                    contract["source_inputs_sha256"] = sha(source_path.read_bytes())
                    contract_path.write_text(json.dumps(contract, sort_keys=True) + "\n")
                    lock["source_inputs_sha256"] = sha(source_path.read_bytes())
                    lock["contract_sha256"] = sha(contract_path.read_bytes())
                    lock["manifest"]["source_inputs_sha256"] = sha(source_path.read_bytes())
                    raw = (json.dumps(lock["manifest"], sort_keys=True) + "\n").encode()
                    lock["manifest_sha256"] = sha(raw)
                    with zipfile.ZipFile(archive, "w") as bundle:
                        bundle.writestr("manifest.json", raw)
                        for member, body in contents.items():
                            bundle.writestr(member, body)
                    lock["artifact"]["bytes"] = archive.stat().st_size
                    lock["artifact"]["sha256"] = sha(archive.read_bytes())
                    lock["attestation"]["subject_sha256"] = lock["artifact"]["sha256"]
                else:
                    contract = json.loads(contract_path.read_text())
                    contract["applications"]["glum"]["files"][0]["destination"] = "../bin/glum"
                    contract_path.write_text(json.dumps(contract, sort_keys=True) + "\n")
                    lock["contract_sha256"] = sha(contract_path.read_bytes())
                destination = root / "payload"
                destination.mkdir()
                with mock.patch(
                    "image.default_apps.payload.load_release_inputs", return_value=release
                ), self.assertRaises(ValueError):
                    unpack_payload(
                        archive,
                        lock,
                        contract_path,
                        source_path,
                        destination,
                        "a" * 40,
                        release_path,
                    )

    def test_overwrite_or_linked_parent_is_refused_without_partial_install(self):
        for mutation in ("overwrite", "linked-parent"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                (
                    archive,
                    lock,
                    contract,
                    sources,
                    release_path,
                    release,
                    _,
                ) = self.fixture(root)
                destination = root / "payload"
                destination.mkdir()
                if mutation == "overwrite":
                    target = destination / "usr/bin/tootles"
                    target.parent.mkdir(parents=True)
                    target.write_text("keep\n")
                else:
                    (root / "outside").mkdir()
                    (destination / "usr").symlink_to(root / "outside", target_is_directory=True)
                before = sorted(str(path.relative_to(destination)) for path in destination.rglob("*"))
                with mock.patch(
                    "image.default_apps.payload.load_release_inputs", return_value=release
                ), self.assertRaises(ValueError):
                    unpack_payload(
                        archive,
                        lock,
                        contract,
                        sources,
                        destination,
                        "a" * 40,
                        release_path,
                    )
                after = sorted(str(path.relative_to(destination)) for path in destination.rglob("*"))
                self.assertEqual(after, before)

    def test_failed_copy_removes_files_and_directories_from_that_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (
                archive,
                lock,
                contract,
                sources,
                release_path,
                release,
                _,
            ) = self.fixture(root)
            destination = root / "payload"
            destination.mkdir()
            calls = 0

            def fail_second(source, target, executable=False):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return real_copy_regular(source, target, executable)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"partial")
                raise OSError("injected copy failure")

            with mock.patch(
                "image.default_apps.payload.load_release_inputs", return_value=release
            ), mock.patch(
                "image.default_apps.payload.copy_regular", side_effect=fail_second
            ):
                with self.assertRaises(OSError):
                    unpack_payload(
                        archive,
                        lock,
                        contract,
                        sources,
                        destination,
                        "a" * 40,
                        release_path,
                    )
            self.assertEqual(list(destination.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
