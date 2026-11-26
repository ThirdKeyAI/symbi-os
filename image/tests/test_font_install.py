"""Development-image integration boundaries for the pinned Nerd Font payload."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FontPayload(unittest.TestCase):
    commit = "a" * 40

    def make_tar(self, path, profile, config=None):
        if profile == "jetbrains":
            rows = [
                ("JetBrainsMonoNerdFont-Regular.ttf", b"\x00\x01\x00\x00regular"),
                ("JetBrainsMonoNerdFontMono-Regular.ttf", b"OTTOmono"),
                ("OFL.txt", b"fixture license"),
                ("README.md", b"fixture readme"),
            ]
        else:
            config = config or (b'<?xml version="1.0"?>\n<!DOCTYPE fontconfig SYSTEM "fonts.dtd">\n'
                                b'<fontconfig><alias><family>monospace</family><prefer>'
                                b'<family>Symbols Nerd Font</family></prefer></alias></fontconfig>\n')
            rows = [
                ("SymbolsNerdFont-Regular.ttf", b"\x00\x01\x00\x00symbols"),
                ("SymbolsNerdFontMono-Regular.ttf", b"OTTOsymbols-mono"),
                ("LICENSE", b"fixture symbols license"),
                ("README.md", b"fixture symbols readme"),
                ("10-nerd-font-symbols.conf", config),
            ]
        with tarfile.open(path, "w:xz") as archive:
            for name, data in rows:
                item = tarfile.TarInfo(name)
                item.mode = 0o644
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))

    def fixture(self, root, config=None):
        from image.fonts.intake import inspect_archive

        candidate = root / "candidate"
        candidate.mkdir()
        pins = json.loads((ROOT / "image/fonts/inputs.json").read_text())
        profiles = {
            "JetBrainsMono.tar.xz": "jetbrains",
            "NerdFontsSymbolsOnly.tar.xz": "symbols",
        }
        inventories = {}
        for asset in pins["assets"][:2]:
            path = candidate / asset["name"]
            self.make_tar(path, profiles[asset["name"]], config)
            asset["bytes"] = path.stat().st_size
            asset["sha256"] = sha(path)
            rows = inspect_archive(path, profiles[asset["name"]])
            inventories[asset["name"]] = {
                "members": len(rows),
                "fonts": sum(name.lower().endswith((".ttf", ".otf")) for name in rows),
                "expanded_bytes": sum(row["bytes"] for row in rows.values()),
                "inventory_sha256": hashlib.sha256((json.dumps(rows, indent=2) + "\n").encode()).hexdigest(),
            }
        pins_path = root / "inputs.json"
        pins_path.write_text(json.dumps(pins, indent=2) + "\n")
        manifest = {
            "schema": 1,
            "source_commit": self.commit,
            "inputs_sha256": sha(pins_path),
            "selected": False,
            "archives": inventories,
        }
        (candidate / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return candidate, pins_path

    def test_extracts_only_fonts_config_and_reviewed_notices(self):
        from image.fonts.install import prepare_font_payload

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, pins = self.fixture(root)
            payload = root / "payload"
            payload.mkdir()
            record = prepare_font_payload(candidate, pins, ROOT, payload, self.commit)
            fonts = payload / "usr/share/fonts/symbi-nerd-fonts"
            expected = {
                "JetBrainsMono/JetBrainsMonoNerdFont-Regular.ttf",
                "JetBrainsMono/JetBrainsMonoNerdFontMono-Regular.ttf",
                "Symbols/SymbolsNerdFont-Regular.ttf",
                "Symbols/SymbolsNerdFontMono-Regular.ttf",
            }
            self.assertEqual({path.relative_to(fonts).as_posix() for path in fonts.rglob("*") if path.is_file()}, expected)
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o644 for path in fonts.rglob("*.ttf")))
            self.assertEqual(record["font_count"], 4)
            self.assertTrue(record["development_included"])
            self.assertFalse(record["selected_for_release"])
            config = payload / "etc/fonts/conf.d/10-nerd-font-symbols.conf"
            self.assertEqual(ET.fromstring(config.read_bytes()).tag, "fontconfig")
            licenses = payload / "usr/share/licenses/symbi-nerd-fonts"
            self.assertEqual({path.name for path in licenses.iterdir()},
                             {Path(row["path"]).name for row in json.loads(pins.read_text())["notices"]})

    def test_rejects_changed_inputs_wrong_commit_unsafe_config_and_linked_target_without_partial_files(self):
        from image.fonts.install import prepare_font_payload

        malicious = b'<fontconfig><include>/tmp/untrusted</include></fontconfig>\n'
        external = (b'<?xml version="1.0"?>\n<!DOCTYPE fontconfig SYSTEM "file:///etc/passwd">\n'
                    b'<fontconfig><alias><family>monospace</family><prefer>'
                    b'<family>Symbols Nerd Font</family></prefer></alias></fontconfig>\n')
        for fault in ("archive", "commit", "config", "external-doctype", "target-link"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = malicious if fault == "config" else external if fault == "external-doctype" else None
                candidate, pins = self.fixture(root, config)
                payload = root / "payload"
                payload.mkdir()
                commit = self.commit
                if fault == "archive":
                    with (candidate / "JetBrainsMono.tar.xz").open("ab") as output:
                        output.write(b"changed")
                elif fault == "commit":
                    commit = "b" * 40
                elif fault == "target-link":
                    outside = root / "outside"
                    outside.mkdir()
                    target = payload / "usr/share/fonts"
                    target.parent.mkdir(parents=True)
                    target.symlink_to(outside, target_is_directory=True)
                with self.assertRaises((ValueError, OSError)):
                    prepare_font_payload(candidate, pins, ROOT, payload, commit)
                self.assertFalse(any(path.is_file() for path in payload.rglob("*")))


class FontDefaults(unittest.TestCase):
    def test_every_retained_image_requires_native_font_scan(self):
        from image.desktop.verify import verify_font_payload

        lock = json.loads((ROOT / "image/desktop-images.lock.json").read_text())
        sources = set()
        for variant, selected in lock["images"].items():
            with self.subTest(variant=variant):
                self.assertEqual(selected["manifest"]["source_commit"], selected["tested_commit"])
                sources.add(selected["tested_commit"])
                with self.assertRaises(ValueError):
                    verify_font_payload({"source_commit": selected["tested_commit"]})
        self.assertEqual(sources, {"d436c6ee8a7ed159afa59db9bd82377ae8ea2389"})
        with self.assertRaises(ValueError):
            verify_font_payload({"source_commit": "0" * 40})
        hosted = (ROOT / "image/boot/hosted.py").read_text()
        self.assertIn("(root/'image/fonts/verify.py','font_verify.py')", hosted)
        self.assertIn("'font_verify.py'", hosted[hosted.index("record['probe_hashes']"):])

    def test_system_defaults_match_the_observed_ombuntu_font_profile(self):
        path = ROOT / "image/overlay/etc/fonts/conf.d/49-symbi-fonts.conf"
        root = ET.fromstring(path.read_bytes())
        assigned = {(node.findtext("test/string"), node.findtext("edit/string"))
                    for node in root.findall("match")}
        self.assertIn(("monospace", "JetBrainsMono Nerd Font"), assigned)
        self.assertIn(("sans-serif", "Liberation Sans"), assigned)
        self.assertIn(("serif", "Liberation Serif"), assigned)
        kitty = (ROOT / "image/overlay/usr/share/symbiont/defaults/kitty/kitty.conf").read_text()
        self.assertIn("font_family JetBrainsMono Nerd Font\n", kitty)
        self.assertIn("font_size 9.0\n", kitty)
        self.assertNotIn("allow_remote_control yes", kitty)

    def test_native_font_scan_requires_every_file_and_the_default_family(self):
        from image.fonts.verify import validate_native_output

        paths = [
            "/usr/share/fonts/symbi-nerd-fonts/JetBrainsMono/JetBrainsMonoNerdFont-Regular.ttf",
            "/usr/share/fonts/symbi-nerd-fonts/Symbols/SymbolsNerdFont-Regular.ttf",
        ]
        scan = (paths[0] + "\tJetBrainsMono Nerd Font,JetBrainsMono NF\tRegular\n"
                + paths[1] + "\tSymbols Nerd Font\tRegular\n")
        match = "JetBrainsMono Nerd Font,JetBrainsMono NF\t" + paths[0] + "\n"
        result = validate_native_output(scan, match, paths)
        self.assertEqual(result["scanned_fonts"], 2)
        self.assertEqual(result["monospace_family"], "JetBrainsMono Nerd Font")
        for changed in (scan.splitlines()[0] + "\n", scan + scan.splitlines()[0] + "\n",
                        scan.replace("Symbols Nerd Font", "Unknown")):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_native_output(changed, match, paths)
        with self.assertRaises(ValueError):
            validate_native_output(scan, "DejaVu Sans Mono\t/usr/share/fonts/dejavu.ttf\n", paths)

    def test_desktop_job_prepares_fonts_before_the_image_context(self):
        workflow = (ROOT / ".github/workflows/desktop-image.yml").read_text()
        intake = workflow.index("bash scripts/check-font-intake.sh")
        prepare = workflow.index("bash scripts/check-desktop-image.sh prepare")
        self.assertLess(intake, prepare)
        source = (ROOT / "image/desktop/prepare.py").read_text()
        self.assertIn("prepare_font_payload", source)
        self.assertIn(".cache/font-candidate", source)
        self.assertLess(source.index("intake = unique_json"),
                        source.index("record['fonts'] = prepare_font_payload"))


if __name__ == "__main__":
    unittest.main()
