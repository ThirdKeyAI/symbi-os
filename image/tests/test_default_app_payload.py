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
    _check_payload_tree_files,
    load_payload_contract,
    unpack_payload,
    verify_payload_tree,
)


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

    def test_self_reported_provenance_cannot_stage_or_touch_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive, lock, contract, sources, release_path, release, _ = self.fixture(root)
            destination = root / "payload"
            destination.mkdir()
            sentinel = destination / "keep"
            sentinel.write_bytes(b"keep\n")
            before = (sentinel.stat().st_ino, sentinel.read_bytes())
            with mock.patch(
                "image.default_apps.payload.load_release_inputs", return_value=release
            ), self.assertRaisesRegex(ValueError, "staging is disabled"):
                unpack_payload(
                    archive,
                    lock,
                    contract,
                    sources,
                    destination,
                    "a" * 40,
                    release_path,
                )
            self.assertEqual((sentinel.stat().st_ino, sentinel.read_bytes()), before)
            self.assertEqual(list(destination.iterdir()), [sentinel])

    def test_lock_manifest_source_and_claim_mutations_are_refused(self):
        mutations = ("lock-commit", "manifest-commit", "source", "claim")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                archive, lock, contract, sources, release_path, release, _ = self.fixture(root)
                if mutation == "lock-commit":
                    lock["tested_commit"] = "b" * 40
                elif mutation == "manifest-commit":
                    lock["manifest"]["source_commit"] = "b" * 40
                elif mutation == "source":
                    lock["manifest"]["applications"]["yazi"][
                        "source_archive_sha256"
                    ] = "0" * 64
                else:
                    lock["attestation"]["subject_sha256"] = "0" * 64
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

    def test_tree_verification_requires_lock_commit_and_real_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _, lock, contract, sources, release_path, release, _ = self.fixture(root)
            destination = root / "payload"
            destination.mkdir()
            with self.assertRaisesRegex(ValueError, "source commit and payload lock"):
                verify_payload_tree(
                    destination, lock, contract, sources, release_path
                )
            with mock.patch(
                "image.default_apps.payload.load_release_inputs", return_value=release
            ):
                with self.assertRaisesRegex(ValueError, "unexpected.*payload lock"):
                    verify_payload_tree(
                        destination,
                        lock["manifest"],
                        contract,
                        sources,
                        release_path,
                        "a" * 40,
                    )
                with self.assertRaisesRegex(ValueError, "staging is disabled"):
                    verify_payload_tree(
                        destination,
                        lock,
                        contract,
                        sources,
                        release_path,
                        "a" * 40,
                    )

    def populate_tree(self, destination, manifest, contents):
        for app in manifest["applications"].values():
            for row in app["files"]:
                target = destination / row["destination"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(contents[row["bundle"]])
                target.chmod(row["mode"])

    def test_static_tree_check_refuses_suid_sgid_and_sticky_modes(self):
        for special in (0o4000, 0o2000, 0o1000):
            with self.subTest(special=oct(special)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                _, lock, contract_path, _, _, _, contents = self.fixture(root)
                destination = root / "payload"
                destination.mkdir()
                self.populate_tree(destination, lock["manifest"], contents)
                target = destination / "usr/bin/yazi"
                target.chmod(0o755 | special)
                contract = json.loads(contract_path.read_text())
                with self.assertRaisesRegex(
                    ValueError, "staged default-application file changed"
                ):
                    _check_payload_tree_files(destination, lock["manifest"], contract)

    def test_refused_staging_never_unlinks_a_racing_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive, lock, contract, sources, release_path, release, _ = self.fixture(root)
            destination = root / "payload"
            target = destination / "usr/bin/yazi"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"created by another process\n")
            target.chmod(0o600)
            before = (
                target.stat().st_dev,
                target.stat().st_ino,
                target.stat().st_mode,
                target.read_bytes(),
            )
            with mock.patch(
                "image.default_apps.payload.load_release_inputs", return_value=release
            ), mock.patch("pathlib.Path.unlink") as unlink, self.assertRaisesRegex(
                ValueError, "staging is disabled"
            ):
                unpack_payload(
                    archive,
                    lock,
                    contract,
                    sources,
                    destination,
                    "a" * 40,
                    release_path,
                )
            unlink.assert_not_called()
            self.assertEqual(
                (
                    target.stat().st_dev,
                    target.stat().st_ino,
                    target.stat().st_mode,
                    target.read_bytes(),
                ),
                before,
            )


if __name__ == "__main__":
    unittest.main()
