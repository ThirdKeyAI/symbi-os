"""Offline faults for the pinned Nerd Font candidate intake."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class FontInputs(unittest.TestCase):
    def test_release_assets_and_notices_are_exact_and_unselected(self):
        pins = json.loads((ROOT / "image/fonts/inputs.json").read_text())
        self.assertEqual(pins["schema"], 1)
        self.assertEqual(pins["tag"], "v3.5.1")
        self.assertEqual(pins["revision"], "b894ea7803af6aade63d60a4381e006098ec9c4d")
        self.assertIs(pins["selected"], False)
        self.assertIs(pins["os_qualified"], False)
        expected = {
            "JetBrainsMono.tar.xz": (523475208, 7284244,
                "04d5e8f903693f9dd13e16f867e994834e681eb3c72c0d337a770dcda09010cf"),
            "NerdFontsSymbolsOnly.tar.xz": (523461571, 2362384,
                "01172f37db8543edb102e5cb5c64101c9f4686630804d49b419aa07b23a69996"),
            "SHA-256.txt": (523593027, 11898,
                "e03d7ad54547d83f1620719cbc89b5684bc0c6fb028160640aa322b5035a63fb"),
        }
        self.assertEqual([row["name"] for row in pins["assets"]], list(expected))
        for row in pins["assets"]:
            self.assertEqual((row["asset_id"], row["bytes"], row["sha256"]), expected[row["name"]])
            self.assertEqual(row["url"],
                "https://github.com/ryanoasis/nerd-fonts/releases/download/v3.5.1/" + row["name"])
        for row in pins["notices"]:
            path = ROOT / row["path"]
            self.assertEqual(path.stat().st_size, row["bytes"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), row["sha256"])


class PassiveFontArchive(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location("font_intake", ROOT / "image/fonts/intake.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def make_tar(self, path, profile="jetbrains", extras=(), omit=()):
        members = ([
            ("JetBrainsMonoNerdFont-Regular.ttf", tarfile.REGTYPE, b"\x00\x01\x00\x00font"),
            ("JetBrainsMonoNerdFontMono-Regular.ttf", tarfile.REGTYPE, b"OTTOfont"),
            ("OFL.txt", tarfile.REGTYPE, b"license"),
            ("README.md", tarfile.REGTYPE, b"readme"),
        ] if profile == "jetbrains" else [
            ("SymbolsNerdFont-Regular.ttf", tarfile.REGTYPE, b"\x00\x01\x00\x00font"),
            ("SymbolsNerdFontMono-Regular.ttf", tarfile.REGTYPE, b"OTTOfont"),
            ("LICENSE", tarfile.REGTYPE, b"license"),
            ("README.md", tarfile.REGTYPE, b"readme"),
            ("10-nerd-font-symbols.conf", tarfile.REGTYPE, b"<fontconfig/>")
        ])
        members.extend(extras)
        with tarfile.open(path, "w:xz") as archive:
            for name, kind, data in members:
                if name in omit:
                    continue
                item = tarfile.TarInfo(name)
                item.type = kind
                item.mode = 0o644
                if kind == tarfile.REGTYPE:
                    item.size = len(data)
                    archive.addfile(item, io.BytesIO(data))
                else:
                    item.linkname = data.decode()
                    archive.addfile(item)

    def test_hashes_flat_fonts_and_notices_without_extracting(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jetbrains = root / "JetBrainsMono.tar.xz"
            symbols = root / "NerdFontsSymbolsOnly.tar.xz"
            self.make_tar(jetbrains)
            self.make_tar(symbols, "symbols")
            first = mod.inspect_archive(jetbrains, "jetbrains")
            second = mod.inspect_archive(symbols, "symbols")
            self.assertEqual(first["JetBrainsMonoNerdFont-Regular.ttf"]["magic"], "00010000")
            self.assertEqual(second["SymbolsNerdFontMono-Regular.ttf"]["magic"], "4f54544f")
            self.assertEqual(set(root.iterdir()), {jetbrains, symbols})

    def test_rejects_paths_duplicates_links_special_files_and_unknown_payloads(self):
        mod = self.module()
        faults = [
            ("../escape.ttf", tarfile.REGTYPE, b"\x00\x01\x00\x00x"),
            ("/absolute.ttf", tarfile.REGTYPE, b"\x00\x01\x00\x00x"),
            ("nested/font.ttf", tarfile.REGTYPE, b"\x00\x01\x00\x00x"),
            ("JetBrainsMonoNerdFont-Regular.ttf", tarfile.REGTYPE, b"\x00\x01\x00\x00x"),
            ("link.ttf", tarfile.SYMTYPE, b"JetBrainsMonoNerdFont-Regular.ttf"),
            ("pipe", tarfile.FIFOTYPE, b""),
            ("program.sh", tarfile.REGTYPE, b"#!/bin/sh"),
            ("control\n.ttf", tarfile.REGTYPE, b"\x00\x01\x00\x00x"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.tar.xz"
            for fault in faults:
                self.make_tar(path, extras=[fault])
                with self.subTest(fault=fault[0]), self.assertRaises(ValueError):
                    mod.inspect_archive(path, "jetbrains")

    def test_rejects_bad_font_magic_missing_notices_and_limits(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.tar.xz"
            self.make_tar(path, extras=[("Bad.ttf", tarfile.REGTYPE, b"bad-font")])
            with self.assertRaises(ValueError):
                mod.inspect_archive(path, "jetbrains")
            self.make_tar(path, omit={"OFL.txt"})
            with self.assertRaises(ValueError):
                mod.inspect_archive(path, "jetbrains")
            self.make_tar(path)
            with self.assertRaises(ValueError):
                mod.inspect_archive(path, "jetbrains", max_members=2)
            with self.assertRaises(ValueError):
                mod.inspect_archive(path, "jetbrains", max_bytes=4)

    def test_release_checksum_index_must_agree_without_duplicate_names(self):
        mod = self.module()
        assets = [
            {"name": "JetBrainsMono.tar.xz", "sha256": "a" * 64},
            {"name": "NerdFontsSymbolsOnly.tar.xz", "sha256": "b" * 64},
            {"name": "SHA-256.txt", "sha256": "c" * 64},
        ]
        text = f"{'a' * 64}  JetBrainsMono.tar.xz\n{'b' * 64} *NerdFontsSymbolsOnly.tar.xz\n"
        rows = mod.require_checksum_index(text, assets)
        self.assertEqual(rows["JetBrainsMono.tar.xz"], "a" * 64)
        for invalid in (text.replace("a" * 64, "d" * 64),
                        text.splitlines()[0] + "\n",
                        text + text.splitlines()[0] + "\n"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                mod.require_checksum_index(invalid, assets)

    def test_pin_json_rejects_duplicate_keys_at_any_depth(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pins.json"
            for content in (
                    '{"schema": 1, "schema": 2}',
                    '{"asset": {"bytes": 1, "bytes": 2}}'):
                path.write_text(content)
                with self.subTest(content=content), self.assertRaises(ValueError):
                    mod.load_json(path)


if __name__ == "__main__":
    unittest.main()
