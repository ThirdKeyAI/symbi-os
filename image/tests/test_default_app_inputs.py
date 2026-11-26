"""Fault checks for pinned Yazi, Glum and Tootles source intake."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from image.default_apps.inputs import inspect_archive, load_inputs


ROOT = Path(__file__).resolve().parents[2]


class DefaultApplicationInputs(unittest.TestCase):
    def test_real_inputs_bind_exact_unselected_sources_and_build_boundaries(self):
        pins = load_inputs()
        self.assertEqual(set(pins["applications"]), {"yazi", "glum", "tootles"})
        expected = {
            "yazi": ("v26.9.1", "8dd895c695a5950330c2623eb43debf323b60654", "yazi"),
            "glum": ("v0.2.2", "7608edc56e5b48c6c398e1f36a3c64c49e4261f8", "glum"),
            "tootles": ("v0.2.0", "40d7a63c5ec0e08cb3eb8241b50a2af6cf76c98a", "tootles"),
        }
        for name, (version, revision, binary) in expected.items():
            with self.subTest(name=name):
                app = pins["applications"][name]
                self.assertEqual((app["version"], app["revision"]), (version, revision))
                self.assertEqual(app["build"]["installed_binaries"], [binary])
                self.assertIn("Cargo.lock", app["source"]["required_files"])
                self.assertFalse(app["tag"]["signed"])
        self.assertEqual(pins["applications"]["yazi"]["build"]["excluded_binaries"], ["ya"])
        self.assertFalse(pins["selected"])
        self.assertFalse(pins["security_qualified"])
        self.assertFalse(pins["os_qualified"])

    def make_archive(self, path, *, link_target="Cargo.toml", extra=None):
        root = "demo-" + "1" * 40
        cargo = (b'[package]\nname="demo"\nversion="1.0.0"\nlicense="MIT"\n'
                 b'rust-version="1.75"\n[[bin]]\nname="demo"\npath="src/main.rs"\n')
        lock = b'version = 3\n\n[[package]]\nname = "demo"\nversion = "1.0.0"\n'
        files = {"Cargo.toml": cargo, "Cargo.lock": lock, "LICENSE": b"MIT\n",
                 "src/main.rs": b"fn main() {}\n"}
        with tarfile.open(path, "w:gz") as archive:
            directory = tarfile.TarInfo(root + "/")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            for relative, body in files.items():
                item = tarfile.TarInfo(root + "/" + relative)
                item.size = len(body)
                item.mode = 0o644
                archive.addfile(item, io.BytesIO(body))
            link = tarfile.TarInfo(root + "/CURRENT")
            link.type = tarfile.SYMTYPE
            link.linkname = link_target
            archive.addfile(link)
            if extra:
                archive.addfile(extra)
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
        source = {
            "url": "https://github.com/example/demo/archive/" + "1" * 40 + ".tar.gz",
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "root": root,
            "members": len(members),
            "regular_files": 4,
            "directories": 1,
            "symlinks": 1,
            "hardlinks": 0,
            "expanded_bytes": sum(len(value) for value in files.values()),
            "links": {"CURRENT": "Cargo.toml"},
            "required_files": {name: {"bytes": len(body),
                                      "sha256": hashlib.sha256(body).hexdigest()}
                               for name, body in files.items() if name != "src/main.rs"},
        }
        return {
            "repository": "https://github.com/example/demo",
            "version": "v1.0.0", "revision": "1" * 40, "license": "MIT",
            "tag": {"kind": "lightweight", "object": "1" * 40, "signed": False},
            "source": source,
            "cargo_lock": {"version": 3, "packages": 1,
                           "sources": ["local"], "git_packages": []},
            "build": {"rust_version": "1.75", "package": "demo",
                      "installed_binaries": ["demo"], "excluded_binaries": []},
        }

    def test_archive_is_passively_inspected_without_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "source.tar.gz"
            app = self.make_archive(archive)
            result = inspect_archive(archive, app)
            self.assertEqual(result["cargo_lock"]["packages"], 1)
            self.assertEqual(result["links"], {"CURRENT": "Cargo.toml"})
            self.assertEqual(list(Path(directory).iterdir()), [archive])

    def test_changed_bytes_links_paths_and_special_members_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = base / "source.tar.gz"
            app = self.make_archive(archive)
            changed = copy.deepcopy(app)
            changed["source"]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                inspect_archive(archive, changed)
            wrong = base / "wrong.tar.gz"
            wrong_app = self.make_archive(wrong, link_target="../outside")
            with self.assertRaises(ValueError):
                inspect_archive(wrong, wrong_app)
            special = tarfile.TarInfo("demo-" + "1" * 40 + "/pipe")
            special.type = tarfile.FIFOTYPE
            unsafe = base / "unsafe.tar.gz"
            unsafe_app = self.make_archive(unsafe, extra=special)
            with self.assertRaises(ValueError):
                inspect_archive(unsafe, unsafe_app)

    def test_registry_entries_need_checksums_and_git_sources_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "source.tar.gz"
            app = self.make_archive(archive)
            with tarfile.open(archive, "r:gz") as source:
                self.assertIsNotNone(source.getmember(app["source"]["root"] + "/Cargo.lock"))
            changed = copy.deepcopy(app)
            changed["cargo_lock"]["packages"] = 2
            with self.assertRaises(ValueError):
                inspect_archive(archive, changed)

    def test_intake_is_bounded_and_consolidated_with_existing_source_workflow(self):
        wrapper = (ROOT / "scripts/check-default-app-intake.sh").read_text()
        for value in ("MemoryMax=512M", "MemorySwapMax=0", "CPUQuota=100%",
                      "TasksMax=32", "NoNewPrivileges=yes", "ProtectSystem=strict"):
            self.assertIn(value, wrapper)
        workflow = (ROOT / ".github/workflows/desktop-source-intake.yml").read_text()
        self.assertIn("check-tolaria-intake.sh", workflow)
        self.assertIn("check-default-app-intake.sh", workflow)
        self.assertIn("branches: [main]", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertFalse((ROOT / ".github/workflows/tolaria-intake.yml").exists())
        self.assertNotIn("pull_request:", workflow)


if __name__ == "__main__":
    unittest.main()
