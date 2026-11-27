"""Offline acceptance for the first Ombuntu-compatible desktop-default tranche.

The real pinned Hyprland parser remains the hosted syntax/ABI gate.  These
checks bind the reviewable defaults to the owner's recorded shortcut meanings
and to a single local Tokyo Night palette.
"""
import json
from pathlib import Path
import re
import tomllib
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
DEFAULTS = ROOT / "image/overlay/usr/share/symbiont/defaults"
SESSION = ROOT / "image/desktop/session/usr/share/symbiont/defaults/hypr/hyprland.lua"
TOKYO = {
    "background": "#1a1b26",
    "foreground": "#a9b1d6",
    "accent": "#7aa2f7",
    "inactive": "#414868",
    "urgent": "#f7768e",
}


class TokyoNightDefaults(unittest.TestCase):
    def test_compositor_bar_and_launcher_share_local_palette(self):
        appearance = (DEFAULTS / "hypr/appearance.lua").read_text()
        waybar = (DEFAULTS / "waybar/style.css").read_text()
        walker = (DEFAULTS / "walker/themes/symbi-tokyo-night/style.css").read_text()
        for name, color in TOKYO.items():
            with self.subTest(surface="walker", token=name):
                self.assertIn(color, walker)
        for color in (TOKYO["background"], TOKYO["foreground"], TOKYO["accent"]):
            with self.subTest(surface="waybar", color=color):
                self.assertIn(color, waybar)
        for color in (TOKYO["accent"][1:], TOKYO["inactive"][1:]):
            with self.subTest(surface="hyprland", color=color):
                self.assertIn(color, appearance)
        self.assertIn("JetBrainsMono Nerd Font", waybar)
        self.assertIn("JetBrainsMono Nerd Font", walker)
        self.assertNotIn("@import", walker)
        self.assertNotRegex(walker, r"https?://|/home/|~/.local/share")

    def test_walker_selects_only_the_shipped_local_theme_and_provider(self):
        config = tomllib.loads((DEFAULTS / "walker/config.toml").read_text())
        self.assertEqual(config["theme"], "symbi-tokyo-night")
        self.assertEqual(config["additional_theme_location"], "~/.config/walker/themes/")
        self.assertEqual(config["providers"]["default"], ["desktopapplications"])
        self.assertEqual(config["keybinds"]["quick_activate"], [])
        layout = ET.parse(DEFAULTS / "walker/themes/symbi-tokyo-night/layout.xml")
        ids = {node.attrib["id"] for node in layout.iter() if "id" in node.attrib}
        self.assertTrue({"Window", "Input", "List", "Placeholder", "Error"} <= ids)

    def test_inactive_kitty_profile_preserves_terminal_look_and_keys_without_remote_control(self):
        kitty = (DEFAULTS / "kitty/kitty.conf").read_text()
        expected = [
            "font_family JetBrainsMono Nerd Font",
            "font_size 9.0",
            "window_padding_width 14",
            "map ctrl+insert copy_to_clipboard",
            "map shift+insert paste_from_clipboard",
            r"map shift+enter send_text all \e[13;2u",
            r"map alt+shift+enter send_text all \e[13;4u",
            "cursor_shape block",
            "cursor_blink_interval 0",
            "enable_audio_bell no",
            "tab_bar_edge bottom",
            "tab_bar_style powerline",
            "foreground #a9b1d6",
            "background #1a1b26",
            "selection_background #7aa2f7",
        ]
        for line in expected:
            self.assertIn(line, kitty)
        self.assertNotRegex(kitty, r"(?m)^\s*(include|allow_remote_control|listen_on|shell)\b")

    def test_inactive_tmux_profile_preserves_keys_without_shell_hooks(self):
        tmux = (DEFAULTS / "tmux/tmux.conf").read_text()
        expected = [
            "set -g prefix C-Space",
            "set -g prefix2 C-b",
            "bind -n M-Enter split-window -v",
            "bind -n M-S-Enter split-window -h",
            "bind -n M-Escape kill-pane",
            "bind -n C-M-Left select-pane -L",
            "bind -n C-M-S-Right resize-pane -R 5",
            "bind -n M-1 select-window -t 1",
            "set -g extended-keys on",
            "set -g extended-keys-format csi-u",
            'set -ag terminal-features "xterm-kitty:extkeys"',
        ]
        for line in expected:
            self.assertIn(line, tmux)
        self.assertNotRegex(tmux, r"(?m)^\s*(run-shell|if-shell|pipe-pane)\b")


class ShortcutCompatibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bindings_path = DEFAULTS / "hypr/bindings.lua"
        cls.text = cls.bindings_path.read_text()
        cls.lines = [line.strip() for line in cls.text.splitlines() if line.strip().startswith("hl.bind(")]
        cls.by_chord = {}
        for line in cls.lines:
            match = re.match(r'^hl\.bind\("([^"]+)"', line)
            if not match:
                raise AssertionError("binding must use a literal reviewable chord: " + line)
            chord = match.group(1)
            if chord in cls.by_chord:
                raise AssertionError("duplicate chord: " + chord)
            cls.by_chord[chord] = line

    def test_entrypoints_load_one_shared_binding_file(self):
        for path in (DEFAULTS / "hypr/hyprland.lua", SESSION):
            text = path.read_text()
            self.assertIn('dofile(config_dir .. "bindings.lua")', text)
            self.assertNotIn("hl.bind(", text)

    def test_review_is_bound_to_the_selected_compositor_revision(self):
        review = json.loads((ROOT / "image/desktop/hyprland-bindings-review.json").read_text())
        self.assertEqual(review["source_revision"], "11cbc6c577b84ffb1edf4df3fc5b6128c3ae6947")
        self.assertIs(review["qualified"], False)
        self.assertEqual(len(review["files"]), 5)
        for path, blob in review["files"].items():
            self.assertFalse(path.startswith("/"))
            self.assertRegex(blob, r"^[0-9a-f]{40}$")
        self.assertIn("code:<number> is parsed as a physical keycode", review["reviewed_properties"])

    def test_workspaces_match_the_recorded_physical_keycodes(self):
        reference = json.loads((ROOT / "docs/desktop-reference/ombuntu-keybindings.json").read_text())
        rows = [row for row in reference["bindings"]
                if row["keycode"] and row["description"].startswith("Switch to workspace ")]
        self.assertEqual(len(rows), 10)
        for workspace, row in enumerate(rows, start=1):
            key = row["keycode"]
            expected = {
                f"SUPER + code:{key}": f"workspace = {workspace}",
                f"SUPER + SHIFT + code:{key}": f"workspace = {workspace}",
                f"SUPER + SHIFT + ALT + code:{key}": f"workspace = {workspace}, follow = false",
            }
            for chord, handler in expected.items():
                with self.subTest(chord=chord):
                    self.assertIn(chord, self.by_chord)
                    self.assertIn(handler, self.by_chord[chord])

    def test_working_core_and_reserved_menu_chords_keep_their_meanings(self):
        expected = {
            "SUPER + SPACE": '/usr/bin/walker',
            "SUPER + ALT + SPACE": "hl.dsp.no_op()",
            "SUPER + Return": "/usr/bin/foot",
            "SUPER + W": "hl.dsp.window.close()",
            "SUPER + T": "hl.dsp.window.float",
            "SUPER + F": "hl.dsp.window.fullscreen",
            "SUPER + left": 'direction = "left"',
            "SUPER + right": 'direction = "right"',
            "SUPER + up": 'direction = "up"',
            "SUPER + down": 'direction = "down"',
            "SUPER + SHIFT + left": 'direction = "left"',
            "SUPER + SHIFT + right": 'direction = "right"',
            "SUPER + SHIFT + up": 'direction = "up"',
            "SUPER + SHIFT + down": 'direction = "down"',
            "SUPER + TAB": 'workspace = "e+1"',
            "SUPER + SHIFT + TAB": 'workspace = "e-1"',
            "SUPER + CTRL + TAB": 'workspace = "previous"',
            "SUPER + SHIFT + O": "hl.dsp.no_op()",
        }
        for chord, handler in expected.items():
            with self.subTest(chord=chord):
                self.assertIn(chord, self.by_chord)
                self.assertIn(handler, self.by_chord[chord])
        for chord in ("SUPER + ALT + Return", "SUPER + Escape", "SUPER + K",
                      "SUPER + SHIFT + K", "SUPER + CTRL + V", "Print", "ALT + Print"):
            with self.subTest(reserved=chord):
                self.assertIn("hl.dsp.no_op()", self.by_chord[chord])

    def test_media_actions_are_constant_packaged_commands(self):
        expected = {
            "XF86AudioRaiseVolume": "/usr/bin/wpctl set-volume",
            "XF86AudioLowerVolume": "/usr/bin/wpctl set-volume",
            "XF86AudioMute": "/usr/bin/wpctl set-mute",
            "XF86AudioMicMute": "/usr/bin/wpctl set-mute",
            "XF86MonBrightnessUp": "/usr/bin/brightnessctl",
            "XF86MonBrightnessDown": "/usr/bin/brightnessctl",
            "XF86AudioNext": "/usr/bin/playerctl next",
            "XF86AudioPlay": "/usr/bin/playerctl play-pause",
            "XF86AudioPrev": "/usr/bin/playerctl previous",
        }
        for chord, command in expected.items():
            with self.subTest(chord=chord):
                self.assertIn(command, self.by_chord[chord])
        self.assertNotRegex(self.text, r"bash\s+-c|sh\s+-c|curl\s|wget\s|hyprpm|exec_raw")

    def test_every_binding_is_named_for_future_help_and_runtime_accounting(self):
        self.assertGreaterEqual(len(self.lines), 60)
        for line in self.lines:
            self.assertIn("description = ", line)


if __name__ == "__main__":
    unittest.main()
