"""Fault checks for the exact Glum v0.4.1 Linux release candidate."""
import copy
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from image.default_apps.glum_release import inspect_release_archive, load_release_inputs


ROOT = Path(__file__).resolve().parents[2]


class GlumReleaseInputs(unittest.TestCase):
    def test_real_input_binds_official_release_tag_commit_assets_and_payload(self):
        pins = load_release_inputs()
        self.assertEqual(pins["version"], "v0.4.1")
        self.assertEqual(pins["revision"], "9cc45ced6ee0fc0bb5c6d90db65b453e6c2e650b")
        self.assertEqual(pins["release"]["id"], 405365169)
        self.assertEqual(pins["release"]["published_at"], "2026-10-07T04:02:46Z")
        self.assertEqual(pins["tag"], {
            "kind": "annotated",
            "object": "0277948bf54c594fec39597fb3eca272fae75b5f",
            "signed": False,
        })
        asset = pins["asset"]
        self.assertEqual(asset["id"], 617523321)
        self.assertEqual(asset["sha256"], "640e94aa3d9aa5a5dcd8431ee4ac35119b51f976d2bbc952d2a34c2768566594")
        installed = {name for name, row in asset["files"].items() if row["install"]}
        self.assertEqual(installed, {
            "glum", "LICENSE", "NOTICE", "share/man/man1/glum.1",
            "share/bash-completion/completions/glum",
            "share/fish/vendor_completions.d/glum.fish",
            "share/zsh/site-functions/_glum",
        })
        self.assertTrue(pins["signature"]["payload_signature_verified"])
        self.assertFalse(pins["signature"]["fulcio_chain_verified"])
        self.assertFalse(pins["signature"]["transparency_log_verified"])
        self.assertFalse(pins["selected"])
        self.assertFalse(pins["security_qualified"])
        self.assertFalse(pins["os_qualified"])

    def test_substituted_asset_member_and_signature_metadata_are_refused(self):
        for mutation in (
            "asset-hash",
            "member-hash",
            "signature-asset-hash",
            "signature-asset-size",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                pins = json.loads(
                    (ROOT / "image/default_apps/glum-release-inputs.json").read_text()
                )
                if mutation == "asset-hash":
                    pins["asset"]["sha256"] = "0" * 64
                    pins["signature"]["asset_sha256"] = "0" * 64
                elif mutation == "member-hash":
                    pins["asset"]["files"]["glum"]["sha256"] = "0" * 64
                elif mutation == "signature-asset-hash":
                    pins["signature"]["signature_asset"]["sha256"] = "0" * 64
                else:
                    pins["signature"]["signature_asset"]["bytes"] += 1
                path = Path(directory).resolve() / "release.json"
                path.write_text(json.dumps(pins, sort_keys=True) + "\n")
                with self.assertRaises(ValueError):
                    load_release_inputs(path)

    def structural_archive(self, path, first_name, first_type, first_mode=0o644):
        pins = load_release_inputs()
        expected = [*pins["asset"]["directories"], *pins["asset"]["files"]]
        remaining = [name for name in expected if name != first_name][:17]
        with tarfile.open(path, "w:gz") as archive:
            first = tarfile.TarInfo(first_name)
            first.mode = first_mode
            if first_type == "link":
                first.type = tarfile.SYMTYPE
                first.linkname = "/etc/passwd"
            elif first_type == "directory":
                first.type = tarfile.DIRTYPE
            archive.addfile(first)
            for name in remaining:
                item = tarfile.TarInfo(name)
                if name in pins["asset"]["directories"]:
                    item.type = tarfile.DIRTYPE
                    item.mode = 0o755
                else:
                    item.mode = pins["asset"]["files"][name]["mode"]
                archive.addfile(item)
        return pins

    def test_inspector_revalidates_canonical_inputs_before_archive_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "candidate.tar.gz"
            path.write_bytes(b"not an archive")
            changed = copy.deepcopy(load_release_inputs())
            changed["asset"]["sha256"] = "0" * 64
            with mock.patch(
                "image.default_apps.glum_release._require_archive_identity"
            ) as identity:
                with self.assertRaisesRegex(ValueError, "canonical hard-pinned"):
                    inspect_release_archive(path, changed)
            identity.assert_not_called()
            with self.assertRaisesRegex(ValueError, "archive bytes changed"):
                inspect_release_archive(path, load_release_inputs())

    def test_extra_link_and_special_mode_cases_reach_structural_checks(self):
        cases = (
            ("unexpected", "file", 0o644, "unexpected or duplicate"),
            ("glum", "link", 0o777, "link or special"),
            ("glum", "file", 0o4755, "file metadata changed"),
            ("share", "directory", 0o1755, "directory metadata changed"),
        )
        for name, kind, mode, message in cases:
            with self.subTest(kind=kind, mode=oct(mode)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory).resolve() / "candidate.tar.gz"
                pins = self.structural_archive(path, name, kind, mode)
                with mock.patch(
                    "image.default_apps.glum_release._require_archive_identity"
                ), self.assertRaisesRegex(ValueError, message):
                    inspect_release_archive(path, pins)


if __name__ == "__main__":
    unittest.main()
