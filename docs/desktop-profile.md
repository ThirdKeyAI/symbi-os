# Desktop defaults and Ombuntu compatibility

Owner decision: Symbi OS should keep the owner's Ombuntu desktop habits:
MPlayer, familiar menus, Tokyo Night by default, Kitty as the default terminal,
Nerd Fonts, terminal customizations, and the same keyboard shortcuts. This is
part of P0-03 desktop integration. The requirements below are pending; the
already-built generic and NVIDIA images do not yet contain this full profile.

## Local reference and intended defaults

The owner's Ubuntu 26.04.1 desktop was inspected without changing its settings.
The running Hyprland session returned 190 binding entries. The installed
Omarchy checkout is at `8fcc9d6048af4cb0e3af8512c78049857a3b53dd`, matching
the existing OS source pin; the local Ombuntu installation marker says `0.1.3`.
The separate local Ombuntu source checkout is at
`3017e46d610bb7bddf25c7af887c1c0935588c65`. That checkout is reference material,
not proof of which revision produced every installed file, and does not change
the OS's existing Ombuntu input pin.

| Area | Observed locally | Required Symbi OS behavior |
| --- | --- | --- |
| Theme | Active `tokyo-night`, background `#1a1b26`, foreground `#a9b1d6`, accent `#7aa2f7` | Tokyo Night selected on first login, coordinated across Kitty, bar, launcher and desktop controls; preserve later user choices |
| Terminal | Kitty 0.45.0 is installed and configured; `xdg-terminals.list` still selects Alacritty | Kitty is the default for the terminal shortcut, terminal desktop entries and menu actions; keep the existing shortcut and working-directory behavior |
| Fonts | JetBrainsMono Nerd Font, its Mono/Propo variants, Symbols Nerd Font and Omarchy icons | Package licensed, pinned font assets; use JetBrainsMono Nerd Font in Kitty and suitable Nerd Font glyphs in menus/bar |
| Media | Both MPlayer and mpv are installed | Include the explicitly requested MPlayer; retain mpv compatibility for the Ombuntu media profile and qualify real audio/video playback |
| Menus | Walker application launcher, Omarchy menu, capture/toggle/hardware/system/theme/background menus, keybinding help, bar menu entry | Port the familiar menu structure and shortcuts to working Fedora actions; retain the planned Agents section for the cards that implement it |
| Shell | Bash imports Omarchy defaults; Starship, mise, zoxide, fzf, eza, bat, fd and ripgrep are available | Port interactive prompt, navigation, completion, history, aliases and file previews using packaged tools and Fedora paths |
| Terminal tools | tmux, Neovim, btop, fastfetch and lazygit are installed | Include and configure the matching terminal workflow; record exact authenticated Fedora/source inputs before assembly |

These are observed local versions and settings, not Fedora dependency pins.
MPlayer is explicit: it must not be silently replaced by mpv. The local system
already has both. The pinned upstream [Ombuntu package list](https://github.com/Ombuntu/Ombuntu/blob/8f2085cb73520fc3558f1248dadd1fca5e69cfcc/install/packages.list)
lists mpv; the owner's MPlayer requirement adds to that baseline.

The pinned [Ombuntu theme setup](https://github.com/Ombuntu/Ombuntu/blob/8f2085cb73520fc3558f1248dadd1fca5e69cfcc/install/50-theme.sh)
selects Tokyo Night. Its [font setup](https://github.com/Ombuntu/Ombuntu/blob/8f2085cb73520fc3558f1248dadd1fca5e69cfcc/install/25-fonts.sh)
selects JetBrainsMono Nerd Font and Omarchy icons. Reuse reviewed data and
licenses through the image pipeline; do not execute the Ubuntu installers.
See [third-party provenance](../image/THIRD_PARTY.md).

## Preserve shortcuts

The [190-entry reference](desktop-reference/ombuntu-keybindings.json) records the
running session's keys, physical keycodes, modifiers, action labels, dispatchers
and flags in order. It includes press/release distinctions, repeat behavior,
mouse bindings and paired actions such as Alt+Tab. Execution arguments, personal
paths and shell contents are omitted. It is reference data, not a configuration
loader or a claim that these actions work in Symbi OS.

Preserve every existing chord and its intended action while translating from
the installed compositor's configuration to the pinned maintained compositor's
Lua API. Keep user overrides. Do not reuse a currently occupied shortcut for a
new Symbi action. A later or optional feature keeps its shortcut reserved until
the corresponding implementation is available; account for each such case
explicitly in the acceptance report.

| Shortcut | Action to preserve |
| --- | --- |
| Super+Enter | Terminal; Kitty becomes the default |
| Super+Alt+Enter | Attach/create tmux in the terminal |
| Super+Space | Application launcher |
| Super+Alt+Space | Main desktop menu |
| Super+Escape | System menu |
| Super+K / Super+Shift+K | Keybinding help / beginner cheatsheet |
| Super+W / Super+F / Super+T | Close / fullscreen / floating |
| Super+arrows / Super+Shift+arrows | Focus / swap windows |
| Super+1..0 | Workspaces 1 through 10, using the existing physical keycodes |
| Super+Shift+1..0 / Super+Alt+Shift+1..0 | Move window / move silently to workspace |
| Super+Tab / Super+Shift+Tab / Super+Ctrl+Tab | Next / previous / former workspace |
| Super+C / V / X | Universal copy / paste / cut in ordinary applications |
| Super+Ctrl+V | Clipboard menu |
| Print / Alt+Print | Screenshot / recording menu |
| Super+Ctrl+L | Lock screen |
| Super+Shift+Enter or B / Super+Shift+F / Super+Shift+N | Browser / file manager / editor |
| Volume, brightness and playback keys | Existing media actions and modifier variants |

The table is a summary; the full reference also covers grouping, scratchpads,
monitor moves, menus, notifications, zoom, app shortcuts and optional dictation.
The current minimal OS overlay is not this profile: it has only a few shortcuts
and four workspaces. Replacing that subset requires actual compositor tests.

## Terminal details to carry over

- Kitty: JetBrainsMono Nerd Font at the local 9-point default, 14-pixel padding,
  block cursor without blinking, disabled audio bell and bottom powerline tabs.
  Preserve Ctrl+Insert copy, Shift+Insert paste, and CSI-u encodings for
  Shift+Enter and Alt+Shift+Enter so terminal applications distinguish them.
- tmux: Ctrl+Space prefix with Ctrl+B fallback; Alt+Enter vertical split,
  Alt+Shift+Enter horizontal split, Alt+Escape close pane; Ctrl+Alt+arrows move
  between panes and Shift variants resize; Alt+1..9 selects windows.
  Preserve the remaining local tmux bindings, vi copy mode and Kitty extended
  key support when packaging the terminal configuration.
- Bash: history search on Up/Down, Tab/Shift+Tab completion cycling, case-insensitive
  completion, appended history, directory/file aliases and zoxide navigation.
  Include fzf previews with Kitty image rendering, bat text previews and shell
  completion. Carry over the short Starship directory/Git prompt; the local
  5-second command timeout is a host-specific HDD setting to keep configurable.
- Input: Caps Lock as Compose, repeat rate 40, repeat delay 250 ms and Num Lock
  enabled, matching the inspected local configuration.

Source inspection does not approve every upstream shell helper or security
setting. The local Kitty file enables unrestricted remote control and some shell
aliases disable agent safeguards. Port presentation, navigation and shortcuts
without importing those authority changes; review the specific terminal
permissions needed by previews and tmux. No raw home-directory configuration,
credential, history or personal environment file enters the public image.

Menus and synthetic copy/paste remain ordinary desktop actions; they cannot
approve grants or feed trusted input surfaces (INV-2, INV-4). The local dictation
shortcuts remain reserved for the optional voice cards (INV-14). Package/helper
changes must retain source pins, signatures, licenses and existing image policy
(INV-12). The plan's restrictions on menu extensions and remote themes still
apply to the curated menu/theme port.

## Acceptance still to implement

- [ ] Resolve and review the added packages/fonts and exact source inputs;
  include license notices and SBOM entries in both image variants.
- [ ] Fresh-login defaults select Tokyo Night, Kitty and the intended font;
  existing user configuration and later theme/font choices survive upgrades.
- [ ] Query bindings in a booted Symbi OS session and account for all 190
  reference entries, preserving modifiers, keycodes, flags, order and intended
  actions. Test actual window/workspace/menu operations, including all ten
  workspaces and multi-monitor behavior; a parser check is insufficient.
- [ ] Exercise Kitty/tmux key delivery, clipboard and file/image previews,
  interactive/noninteractive shell startup and representative file names with
  spaces and metacharacters. Launchers preserve arguments without shell injection.
- [ ] Exercise each shipped menu action, unavailable optional-app handling,
  font/icon rendering, both media players and audio/video output in the actual
  image. No shortcut is silently remapped or claimed complete because it parses.
- [ ] Keep CPU/RAM bounded; perform image builds and VM checks on hosted runners.
  Installed font files and menu entries require no always-running extra service.


## Candidate package preparation

The [hosted package discovery](../image/desktop_packages/README.md) prepares
signed candidates for MPlayer, mpv, Kitty and the requested terminal/media tools.
It uses isolated pinned Fedora/RPM Fusion Free keys and stable repositories,
records exact package/source/license/hash identities, tests missing/wrong keys
and altered package bytes, and requires an unchanged installed base. This is a
separate hosted download-only step; no candidate is installed or selected here.

Kitty security requirements are bound to the retained cve.bz assessment, with
fixed-package verification still false. Exact source/backport proof, remaining
advisories, both-base additive compatibility, font/theme/menu/keybinding work
and actual desktop acceptance remain required. Local verification uses only
small inert fixtures; large candidates and native RPM tests stay hosted.
