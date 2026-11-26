"""Fault checks for the exact Glum v0.4.1 Linux release candidate."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from image.default_apps.glum_release import inspect_release_archive, load_release_inputs


ROOT = Path(__file__).resolve().parents[2]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


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

    def fixture(self, root):
        pins = copy.deepcopy(load_release_inputs())
        bodies = {}
        for name, row in pins["asset"]["files"].items():
            body = (b"\x7fELF" if name == "glum" else b"") + ("fixture:" + name + "\n").encode()
            bodies[name] = body
            row.update(bytes=len(body), sha256=sha(body))
        archive = root / pins["asset"]["name"]
        with tarfile.open(archive, "w:gz") as bundle:
            for name in pins["asset"]["directories"]:
                item = tarfile.TarInfo(name)
                item.type = tarfile.DIRTYPE
                item.mode = 0o755
                bundle.addfile(item)
            for name, row in pins["asset"]["files"].items():
                item = tarfile.TarInfo(name)
                item.size = len(bodies[name])
                item.mode = row["mode"]
                bundle.addfile(item, io.BytesIO(bodies[name]))
        pins["asset"]["bytes"] = archive.stat().st_size
        pins["asset"]["sha256"] = sha(archive.read_bytes())
        pins["asset"]["expanded_bytes"] = sum(len(body) for body in bodies.values())
        pins["signature"]["asset_sha256"] = pins["asset"]["sha256"]
        return archive, pins, bodies

    def test_exact_archive_inventory_is_passively_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive, pins, bodies = self.fixture(root)
            result = inspect_release_archive(archive, pins)
            self.assertEqual(result["files"], len(bodies))
            self.assertEqual(list(root.iterdir()), [archive])

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

    def test_changed_bytes_extra_member_link_and_premature_qualification_fail(self):
        for mutation in ("bytes", "extra", "link", "qualified"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                archive, pins, _ = self.fixture(root)
                if mutation == "bytes":
                    archive.write_bytes(archive.read_bytes() + b"changed")
                elif mutation in ("extra", "link"):
                    changed = root / "changed.tar.gz"
                    with tarfile.open(archive, "r:gz") as source, tarfile.open(changed, "w:gz") as target:
                        for member in source.getmembers():
                            data = source.extractfile(member) if member.isfile() else None
                            target.addfile(member, data)
                        item = tarfile.TarInfo("extra" if mutation == "extra" else "linked")
                        if mutation == "link":
                            item.type = tarfile.SYMTYPE
                            item.linkname = "/etc/passwd"
                        else:
                            item.size = 1
                            data = io.BytesIO(b"x")
                        target.addfile(item, data if mutation == "extra" else None)
                    archive = changed
                    pins = copy.deepcopy(pins)
                    pins["asset"]["bytes"] = archive.stat().st_size
                    pins["asset"]["sha256"] = sha(archive.read_bytes())
                else:
                    pins = copy.deepcopy(pins)
                    pins["security_qualified"] = True
                with self.assertRaises(ValueError):
                    inspect_release_archive(archive, pins)


if __name__ == "__main__":
    unittest.main()
