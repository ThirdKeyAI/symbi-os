"""Focused tests for the static desktop shortcut coverage ledger."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from image.desktop.shortcut_coverage import validate


ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "docs/desktop-reference/ombuntu-keybindings.json"
OVERLAY = ROOT / "image/overlay/usr/share/symbiont/defaults/hypr/bindings.lua"
LEDGER = ROOT / "image/desktop/shortcut-coverage.json"


class ShortcutCoverageTests(unittest.TestCase):
    def validate_mutation(self, *, reference=None, overlay=None, ledger=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference_path = root / "reference.json"
            overlay_path = root / "bindings.lua"
            ledger_path = root / "ledger.json"
            if reference is None:
                reference_path.write_bytes(REFERENCE.read_bytes())
            else:
                reference_path.write_text(json.dumps(reference, indent=2) + "\n")
            overlay_path.write_text(OVERLAY.read_text() if overlay is None else overlay)
            if ledger is None:
                ledger_path.write_bytes(LEDGER.read_bytes())
            else:
                ledger_path.write_text(json.dumps(ledger, indent=2) + "\n")
            return validate(reference_path, overlay_path, ledger_path)

    def test_current_ledger_accounts_for_every_reference_and_overlay_binding(self):
        result = validate()
        self.assertIs(result["passed"], True)
        self.assertEqual(result["reference_bindings"], 190)
        self.assertEqual(result["shipped_bindings"], 70)
        self.assertEqual(result["status_counts"], {
            "implemented": 56,
            "reserved": 14,
            "blocked": 120,
        })
        self.assertIs(result["runtime_tested"], False)
        self.assertIs(result["os_qualified"], False)
        self.assertIs(result["security_qualified"], False)

    def test_reference_rows_and_order_cannot_drift(self):
        reference = json.loads(REFERENCE.read_text())
        reference["bindings"][0]["description"] = "Changed without ledger review"
        with self.assertRaisesRegex(ValueError, "Reference identity|Coverage reference"):
            self.validate_mutation(reference=reference)

        ledger = json.loads(LEDGER.read_text())
        ledger["entries"] = ledger["entries"][:-1]
        with self.assertRaisesRegex(ValueError, "entry count"):
            self.validate_mutation(ledger=ledger)

    def test_duplicate_or_reused_overlay_chord_is_rejected(self):
        line = next(line for line in OVERLAY.read_text().splitlines()
                    if line.startswith('hl.bind("SUPER + SPACE"'))
        duplicate = OVERLAY.read_text() + line + "\n"
        with self.assertRaisesRegex(ValueError, "reuses a literal chord"):
            self.validate_mutation(overlay=duplicate)

    def test_spacing_and_nested_calls_cannot_escape_binding_accounting(self):
        source = OVERLAY.read_text()
        separated = source.replace('hl.bind("SUPER + SPACE"',
                                   'hl.bind ("SUPER + SPACE"', 1)
        indented = source.replace('hl.bind("SUPER + SPACE"',
                                  '  hl.bind("SUPER + SPACE"', 1)
        line = next(row for row in source.splitlines()
                    if row.startswith('hl.bind("SUPER + SPACE"'))
        nested = source.replace(line, "wrapper(" + line + ")", 1)
        for name, changed in (("separated", separated), ("indented", indented),
                              ("nested", nested)):
            with self.subTest(name=name), self.assertRaisesRegex(
                    ValueError, "Unsupported Lua syntax"):
                self.validate_mutation(overlay=changed)

    def test_block_comments_cannot_hide_accounted_bindings(self):
        source = OVERLAY.read_text()
        variants = {
            "ordinary-long-comment": "--[[\n" + source + "]]\n",
            "level-long-comment": "--[=[\n" + source + "]=]\n",
            "inline-long-comment": source + "--[[ hidden executable source ]]\n",
        }
        for name, changed in variants.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                    ValueError, "Unsupported Lua syntax"):
                self.validate_mutation(overlay=changed)

    def test_control_flow_and_other_executable_lua_are_rejected(self):
        source = OVERLAY.read_text()
        variants = {
            "conditional": "if false then\n" + source + "end\n",
            "do-block": "do\n" + source + "end\n",
            "early-return": "return\n" + source,
            "assignment": "local disabled = true\n" + source,
            "function": "function hidden()\n" + source + "end\n",
            "executable": 'os.execute("false")\n' + source,
        }
        for name, changed in variants.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                    ValueError, "Unsupported Lua syntax"):
                self.validate_mutation(overlay=changed)

    def test_nested_or_commented_handler_expressions_are_rejected(self):
        source = OVERLAY.read_text()
        original = 'hl.dsp.exec_cmd("/usr/bin/walker")'
        variants = {
            "nested-call": 'hl.dsp.exec_cmd(os.getenv("SHELL"))',
            "wrapped-handler": 'wrapper(hl.dsp.exec_cmd("/usr/bin/walker"))',
            "inline-function": '(function() return hl.dsp.no_op() end)()',
            "commented-handler": 'hl.dsp.no_op() --[[ hidden ]]',
        }
        for name, handler in variants.items():
            changed = source.replace(original, handler, 1)
            with self.subTest(name=name), self.assertRaisesRegex(
                    ValueError, "Unsupported binding handler"):
                self.validate_mutation(overlay=changed)

    def test_entire_overlay_source_is_bound_to_the_ledger(self):
        changed = OVERLAY.read_text().replace(
            "-- First working tranche of the owner's recorded Ombuntu bindings.",
            "-- Unreviewed source-only change.", 1)
        with self.assertRaisesRegex(ValueError, "overlay source"):
            self.validate_mutation(overlay=changed)

    def test_silent_handler_or_description_change_is_rejected(self):
        changed = OVERLAY.read_text().replace(
            'hl.dsp.exec_cmd("/usr/bin/walker")',
            'hl.dsp.exec_cmd("/usr/bin/foot")', 1)
        with self.assertRaisesRegex(ValueError, "overlay source|Shipped action"):
            self.validate_mutation(overlay=changed)

        changed = OVERLAY.read_text().replace(
            'description = "Application launcher"',
            'description = "Unreviewed action"', 1)
        with self.assertRaisesRegex(ValueError, "overlay source|Shipped action"):
            self.validate_mutation(overlay=changed)

    def test_unaccounted_new_chord_and_status_reuse_are_rejected(self):
        extra = (OVERLAY.read_text()
                 + 'hl.bind("SUPER + Q", hl.dsp.no_op(), { description = "Unreviewed" })\n')
        with self.assertRaisesRegex(ValueError, "overlay source|unaccounted"):
            self.validate_mutation(overlay=extra)

        ledger = json.loads(LEDGER.read_text())
        mapped = [entry for entry in ledger["entries"] if entry["shipped"] is not None]
        mapped[1]["shipped"] = copy.deepcopy(mapped[0]["shipped"])
        with self.assertRaisesRegex(ValueError, "Shipped action changed|reused"):
            self.validate_mutation(ledger=ledger)

    def test_known_reference_multi_bindings_require_explicit_declarations(self):
        ledger = json.loads(LEDGER.read_text())
        self.assertEqual([row["indices"] for row in ledger["reference_multi_bindings"]],
                         [[84, 86], [85, 87], [162, 163]])
        ledger["reference_multi_bindings"].pop()
        with self.assertRaisesRegex(ValueError, "physical-chord reuse"):
            self.validate_mutation(ledger=ledger)

    def test_static_ledger_cannot_claim_runtime_or_qualification(self):
        ledger = json.loads(LEDGER.read_text())
        ledger["qualification"]["runtime_tested"] = True
        with self.assertRaisesRegex(ValueError, "may not claim"):
            self.validate_mutation(ledger=ledger)


if __name__ == "__main__":
    unittest.main()
