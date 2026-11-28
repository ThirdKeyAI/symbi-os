"""Focused static checks for terminal and menu command dispatch."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import unittest

from image.desktop.shortcut_coverage import validate


ROOT = Path(__file__).resolve().parents[2]
COMMANDS = ROOT / "image/overlay/usr/libexec/symbi-desktop-commands.py"
BINDINGS = ROOT / "image/overlay/usr/share/symbiont/defaults/hypr/bindings.lua"
DEFAULTS = ROOT / "image/overlay/usr/share/symbiont/defaults"
LEDGER = ROOT / "image/desktop/shortcut-coverage.json"

SPEC = importlib.util.spec_from_file_location("desktop_commands", COMMANDS)
assert SPEC and SPEC.loader
desktop_commands = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(desktop_commands)


class DesktopCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binding_lines = {}
        for line in BINDINGS.read_text().splitlines():
            match = re.match(r'^hl\.bind\("([^"]+)"', line)
            if match:
                cls.binding_lines[match.group(1)] = line

    def test_terminal_prefers_kitty_and_falls_back_to_foot(self):
        present = {"/usr/bin/kitty", "/usr/bin/foot"}
        self.assertEqual(desktop_commands.terminal_command(present.__contains__),
                         ("/usr/bin/kitty",))
        present.remove("/usr/bin/kitty")
        self.assertEqual(desktop_commands.terminal_command(present.__contains__),
                         ("/usr/bin/foot",))
        with self.assertRaisesRegex(RuntimeError, "no supported terminal"):
            desktop_commands.terminal_command(set().__contains__)

        terminals = [line for line in (DEFAULTS / "xdg-terminals.list").read_text().splitlines()
                     if line and not line.startswith("#")]
        self.assertEqual(terminals, ["kitty.desktop", "foot.desktop"])

    def test_menu_routes_only_to_fixed_installed_helpers(self):
        choose = lambda expected: (lambda _title, _options: expected)
        self.assertEqual(desktop_commands.resolve("menu", choose("Applications")),
                         ("/usr/bin/walker",))
        self.assertEqual(desktop_commands.resolve(
            "menu", choose("Terminal"), lambda path: path == "/usr/bin/foot"),
            ("/usr/bin/foot",))
        expected_system = {
            "Suspend": ("/usr/bin/systemctl", "suspend"),
            "Restart": ("/usr/bin/systemctl", "reboot"),
            "Power off": ("/usr/bin/systemctl", "poweroff"),
        }
        self.assertEqual(desktop_commands.SYSTEM_COMMANDS, expected_system)
        for choice, command in expected_system.items():
            with self.subTest(choice=choice):
                self.assertEqual(desktop_commands.resolve("system", choose(choice)), command)
        source = COMMANDS.read_text()
        self.assertNotRegex(source, r"shell\s*=\s*True|/bin/(?:ba)?sh|os\.system|Popen")

    def test_active_shortcuts_keep_reference_chords_and_help_meanings(self):
        result = validate()
        self.assertEqual(result["status_counts"], {
            "implemented": 59, "reserved": 11, "blocked": 120,
        })
        helper = "/usr/bin/python3 /usr/libexec/symbi-desktop-commands.py"
        expected = {
            "SUPER + ALT + SPACE": helper + " menu",
            "SUPER + Return": helper + " terminal",
            "SUPER + Escape": helper + " system",
            "SUPER + K": helper + " keybindings",
        }
        for chord, command in expected.items():
            with self.subTest(chord=chord):
                self.assertIn(f'hl.dsp.exec_cmd("{command}")', self.binding_lines[chord])

        ledger = json.loads(LEDGER.read_text())
        by_chord = {row["shipped"]["chord"]: row for row in ledger["entries"]
                    if row["shipped"] is not None}
        for chord, description in desktop_commands.HELP_ROWS:
            with self.subTest(help_chord=chord):
                self.assertIn(chord, self.binding_lines)
                self.assertIn(f'description = "{description}"', self.binding_lines[chord])
                self.assertEqual(by_chord[chord]["status"], "implemented")

    def test_unavailable_application_shortcuts_remain_reserved(self):
        for chord in ("SUPER + ALT + Return", "SUPER + SHIFT + F", "SUPER + SHIFT + O"):
            with self.subTest(chord=chord):
                self.assertIn("hl.dsp.no_op()", self.binding_lines[chord])
        self.assertNotRegex(COMMANDS.read_text().casefold(), r"\b(?:tolaria|yazi|glum|tootles)\b")

    def test_waybar_and_fallback_terminal_keep_the_static_defaults(self):
        waybar = json.loads((DEFAULTS / "waybar/config.jsonc").read_text())
        menu = waybar["custom/menu"]
        helper = "/usr/bin/python3 /usr/libexec/symbi-desktop-commands.py"
        self.assertEqual(waybar["modules-left"][0], "custom/menu")
        self.assertEqual(menu["on-click"], helper + " menu")
        self.assertEqual(menu["on-click-right"], helper + " terminal")

        foot = (DEFAULTS / "foot/foot.ini").read_text()
        kitty = (DEFAULTS / "kitty/kitty.conf").read_text()
        for color in ("a9b1d6", "1a1b26", "7aa2f7"):
            with self.subTest(color=color):
                self.assertIn(color, foot)
                self.assertIn("#" + color, kitty)
        for binding in ("Control+Insert", "Shift+Insert", r"\x1b[13;2u", r"\x1b[13;4u"):
            self.assertIn(binding, foot)


if __name__ == "__main__":
    unittest.main()
