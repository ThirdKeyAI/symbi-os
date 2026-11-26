"""Offline faults for the pinned Tolaria source and managed integration patch."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class TolariaInputs(unittest.TestCase):
    @classmethod
    def module(cls):
        spec = importlib.util.spec_from_file_location(
            "tolaria_inputs", ROOT / "image/tolaria/inputs.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def source_archive(self, path, root, members):
        with tarfile.open(path, "w:gz") as archive:
            root_item = tarfile.TarInfo(root)
            root_item.type = tarfile.DIRTYPE
            root_item.mode = 0o755
            archive.addfile(root_item)
            for name, kind, body in members:
                item = tarfile.TarInfo(name)
                item.type = kind
                item.mode = 0o644
                if kind == tarfile.REGTYPE:
                    item.size = len(body)
                    archive.addfile(item, io.BytesIO(body))
                else:
                    item.linkname = body.decode()
                    archive.addfile(item)

    def source_pins(self, path, root, required):
        mod = self.module()
        with tarfile.open(path, "r:gz") as archive:
            rows = archive.getmembers()
        return {
            "source": {
                "bytes": path.stat().st_size,
                "sha256": mod.digest(path),
                "root": root,
                "members": len(rows),
                "regular_files": sum(item.isfile() for item in rows),
                "directories": sum(item.isdir() for item in rows),
                "expanded_bytes": sum(item.size for item in rows),
            },
            "required_files": {
                name: {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                for name, body in required.items()
            },
        }

    def test_real_pin_document_and_patch_are_exact_and_unselected(self):
        mod = self.module()
        pins = mod.load_pins()
        self.assertEqual(pins["release"]["source_commit"],
                         "a87d074c0f35acd6475b6e37145ccbfd6fbecffd")
        self.assertIs(pins["release"]["tag_signed"], False)
        self.assertIs(pins["release"]["github_attestation_found"], False)
        self.assertIs(pins["selected"], False)
        self.assertIs(pins["os_qualified"], False)
        result = mod.require_patch(pins)
        self.assertEqual(result["sha256"],
                         "f3a2d1bddd4323831ec28c83516766a7cebfbcaebe4f6264d7217f202e0cb687")
        self.assertEqual(result["paths"], pins["downstream_patch"]["paths"])

    def test_desktop_entry_uses_fixed_managed_binary(self):
        rows = {}
        for line in (ROOT / "image/tolaria/Tolaria.desktop").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                rows[key] = value
        self.assertEqual(rows["TryExec"], "/usr/bin/tolaria")
        self.assertEqual(rows["Exec"], "/usr/bin/tolaria")
        self.assertNotIn("%", rows["Exec"])
        self.assertNotIn("http", rows["Exec"])
        self.assertEqual(rows["Terminal"], "false")
        self.assertEqual(rows["Categories"], "Utility;TextEditor;")

    def test_fedora_build_profile_is_separate_and_does_not_queue_branch_pushes(self):
        requirements = json.loads(
            (ROOT / "image/tolaria/build-requirements.json").read_text())
        self.assertEqual(requirements["source_inputs"], "image/tolaria/source.json")
        self.assertEqual(requirements["source_revision"],
                         "a87d074c0f35acd6475b6e37145ccbfd6fbecffd")
        self.assertIn("pkgconfig(webkit2gtk-4.1)", requirements["packages"])
        self.assertIn("rust >= 1.100.0", requirements["packages"])
        spec = importlib.util.spec_from_file_location(
            "package_inventory", ROOT / "image/hyprland/package_inventory.py")
        inventory = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inventory)
        self.assertEqual(inventory.requirements_input(ROOT, "tolaria-build"),
                         "image/tolaria/build-requirements.json")
        wrapper = (ROOT / "scripts/check-fedora-packages.sh").read_text()
        self.assertIn("tolaria-build", wrapper)
        workflow = (ROOT / ".github/workflows/tolaria-packages.yml").read_text()
        self.assertIn("branches: [main]", workflow)
        self.assertNotIn('branches: ["**"]', workflow)
        self.assertNotIn("pull_request:", workflow)

    def test_source_intake_is_bounded_unprivileged_and_main_or_manual_only(self):
        wrapper = (ROOT / "scripts/check-tolaria-intake.sh").read_text()
        for required in (
                "--uid=\"$(id -u)\"", "MemoryMax=512M", "MemorySwapMax=0",
                "CPUQuota=100%", "TasksMax=32", "NoNewPrivileges=yes",
                "CapabilityBoundingSet=", "ProtectSystem=strict", "PrivateTmp=yes",
                'pipeline_status=("${PIPESTATUS[@]}")'):
            self.assertIn(required, wrapper)
        self.assertLess(wrapper.index("systemd-run"),
                        wrapper.index('mv -- "$hosted_log" "$evidence/hosted-intake.log"'))
        workflow = (ROOT / ".github/workflows/tolaria-intake.yml").read_text()
        self.assertIn("branches: [main]", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn('branches: ["**"]', workflow)
        self.assertNotIn("pull_request:", workflow)

    def test_source_is_streamed_and_required_files_are_hashed_without_extraction(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = base / "source.tar.gz"
            root = "tolaria-test"
            body = b"AGPL test notice\n"
            self.source_archive(archive, root, [
                (root + "/LICENSE", tarfile.REGTYPE, body),
                (root + "/src", tarfile.DIRTYPE, b""),
                (root + "/src/main.rs", tarfile.REGTYPE, b"fn main() {}\n"),
            ])
            pins = self.source_pins(archive, root, {"LICENSE": body})
            result = mod.inspect_source(archive, pins)
            self.assertEqual(result["regular_files"], 2)
            self.assertEqual(result["required_files"]["LICENSE"]["bytes"], len(body))
            self.assertEqual(list(base.iterdir()), [archive])

    def test_source_rejects_paths_links_special_files_duplicates_and_changed_bytes(self):
        mod = self.module()
        faults = [
            ("../escape", tarfile.REGTYPE, b"x"),
            ("/absolute", tarfile.REGTYPE, b"x"),
            ("tolaria-test/link", tarfile.SYMTYPE, b"LICENSE"),
            ("tolaria-test/hard", tarfile.LNKTYPE, b"tolaria-test/LICENSE"),
            ("tolaria-test/pipe", tarfile.FIFOTYPE, b""),
            ("tolaria-test/\ncontrol", tarfile.REGTYPE, b"x"),
            ("tolaria-test//LICENSE", tarfile.REGTYPE, b"license"),
            ("tolaria-test/./LICENSE", tarfile.REGTYPE, b"license"),
            ("tolaria-test/LICENSE", tarfile.REGTYPE, b"second"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "source.tar.gz"
            for fault in faults:
                self.source_archive(archive, "tolaria-test", [
                    ("tolaria-test/LICENSE", tarfile.REGTYPE, b"license"), fault])
                pins = self.source_pins(archive, "tolaria-test", {"LICENSE": b"license"})
                with self.subTest(fault=fault[0]), self.assertRaises(ValueError):
                    mod.inspect_source(archive, pins)
            self.source_archive(archive, "tolaria-test", [
                ("tolaria-test/LICENSE", tarfile.REGTYPE, b"license")])
            pins = self.source_pins(archive, "tolaria-test", {"LICENSE": b"license"})
            pins["source"]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                mod.inspect_source(archive, pins)

    def test_pnpm_archive_requires_regular_single_root_payload_and_fixed_inventory(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "pnpm.tgz"
            required = {
                "package/package.json": b'{"version":"test"}\n',
                "package/bin/pnpm.cjs": b"main\n",
                "package/bin/pnpx.cjs": b"shim\n",
            }
            with tarfile.open(archive, "w:gz") as output:
                for name, body in required.items():
                    item = tarfile.TarInfo(name)
                    item.size = len(body)
                    item.mode = 0o644
                    output.addfile(item, io.BytesIO(body))
            pin = {
                "bytes": archive.stat().st_size,
                "sha256": mod.digest(archive),
                "members": 3,
                "expanded_bytes": sum(map(len, required.values())),
                "required_files": {name: hashlib.sha256(body).hexdigest()
                                   for name, body in required.items()},
            }
            result = mod.inspect_pnpm(archive, {"pnpm": pin})
            self.assertEqual(result["members"], 3)
            pin["members"] = 4
            with self.assertRaises(ValueError):
                mod.inspect_pnpm(archive, {"pnpm": pin})

    def test_patch_parser_rejects_create_delete_rename_escape_and_binary_changes(self):
        mod = self.module()
        valid = "--- a/src/file\n+++ b/src/file\n@@ -1 +1 @@\n-old\n+new\n"
        self.assertEqual(mod.patch_paths(valid), ["src/file"])
        invalid = [
            "--- /dev/null\n+++ b/new\n",
            "--- a/old\n+++ /dev/null\n",
            "--- a/old\n+++ b/new\n",
            "--- a/../escape\n+++ b/../escape\n",
            "--- a/only\n",
        ]
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ValueError):
                mod.patch_paths(text)

    def test_patched_tree_is_hash_bound_and_forbidden_routes_stay_absent(self):
        mod = self.module()
        paths = [
            "src-tauri/Cargo.toml", "src-tauri/tauri.conf.json",
            "src-tauri/capabilities/default.json", "src-tauri/src/lib.rs",
            "src-tauri/src/pi_config/package_args.rs",
        ]
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            expected = {}
            for relative in paths:
                path = tree / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("managed\n")
                expected[relative] = mod.digest(path)
            pins = {"downstream_patch": {"result_sha256": expected}}
            self.assertEqual(mod.require_patched_tree(tree, pins), expected)
            cargo = tree / "src-tauri/Cargo.toml"
            cargo.write_text("tauri-plugin-updater = \"2\"\n")
            expected["src-tauri/Cargo.toml"] = mod.digest(cargo)
            with self.assertRaisesRegex(ValueError, "forbidden"):
                mod.require_patched_tree(tree, pins)

    def test_duplicate_json_keys_are_refused_at_any_depth(self):
        mod = self.module()
        for raw in (b'{"schema":1,"schema":2}', b'{"source":{"bytes":1,"bytes":2}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                mod.unique_json(raw)


if __name__ == "__main__":
    unittest.main()
