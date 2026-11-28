# Desktop defaults and Ombuntu compatibility

Owner decision: Symbi OS should keep the owner's Ombuntu desktop habits:
MPlayer, familiar menus, Tokyo Night by default, Kitty as the default terminal,
Nerd Fonts, terminal customizations, Tolaria as the default second brain, Yazi,
Glum, Tootles, and the same keyboard shortcuts. This is part of P0-03 desktop
integration. The
requirements below are pending; the already-built generic and NVIDIA images do
not yet contain this full profile.

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
| Notes | The recorded session maps Super+Shift+O to Obsidian | Ship the patched Tolaria desktop app, expose it through Walker and keep Super+Shift+O as the note/second-brain shortcut |
| Terminal file manager | Yazi was not part of the captured installed package baseline | Ship Yazi in Kitty from menus and the existing file-manager chord while preserving graphical portal file selection |
| Markdown reader | Glum was not part of the captured installed package baseline | Ship Glum with its man page and completions; expose an explicit Read in Glum action without silently changing user MIME choices |
| Social client | Tootles was not part of the captured installed package baseline | Ship the Tootles Mastodon and Bluesky TUI in Kitty with Tokyo Night selected, mpv media integration and human-controlled account setup |
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

Tolaria vaults remain ordinary user-selected Git repositories containing
Markdown and YAML frontmatter. First launch must not silently create a vault in
the user's home. The desktop app may edit and commit in the active human session;
its updater, writable loopback bridge, direct model-provider routes, runtime
package downloads and durable agent-configuration writes are disabled in the OS
build. Governed agent reads and isolated-branch writes belong to P1-13. An agent
write is presented as a diff and cannot merge or push without a separate human
decision.

Yazi ships with no downloaded theme or third-party Lua plugin. Its `ya pkg`
network install and update route must be unavailable in the immutable OS build;
reviewed extensions, if any, enter through the signed image recipe. File
previews run under the user session with bounded resources and must not turn
untrusted file names into shell input. Yazi's integrated plugin system, remote
filesystems and package manager require this work before it can satisfy INV-12.

Glum is a local Markdown reader. The image uses a pinned authenticated source or
release artifact rather than its convenience installer. Clipboard, editor and
link-opening actions remain explicit human gestures. Tootles is a networked
human application: account creation is interactive, agent routes do not receive
its tokens, and the image must qualify secret storage, user-selected server
egress, media cache, browser handoff and mpv subprocesses before enabling real
accounts. Its Tokyo Night theme is the initial default.

## Preserve shortcuts

The [190-entry reference](desktop-reference/ombuntu-keybindings.json) records the
running session's keys, physical keycodes, modifiers, action labels, dispatchers
and flags in order. It includes press/release distinctions, repeat behavior,
mouse bindings and paired actions such as Alt+Tab. Execution arguments, personal
paths and shell contents are omitted. It is reference data, not a configuration
loader or a claim that these actions work in Symbi OS.

The static [coverage ledger](../image/desktop/shortcut-coverage.json) accounts
for every reference entry against the current source overlay: 56 have a
non-no-op handler, 14 keep their chord as an explicit no-op reservation, and
120 remain blocked because the overlay has no corresponding binding. Here,
`implemented` means only that source code contains a reviewed handler. The
validator makes no claim about compositor parsing, installed commands, desktop
interaction, boot, OS qualification or security qualification. Any reference
count or order change, unaccounted overlay chord, reused chord, or handler,
description and option change requires an explicit ledger update. The checker
also rejects block comments, control-flow wrappers and executable Lua outside
the exact one-line binding form so source text cannot hide an accounted chord.

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
| Super+Shift+O | Tolaria second brain, preserving the existing note-app chord |
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
- [ ] Launch Tolaria from Walker and Super+Shift+O on both image variants; open
  an existing Git vault, edit and commit a Markdown note, and verify that update,
  loopback bridge, direct-provider and durable config-write routes stay disabled.
- [ ] Launch Yazi in Kitty from Walker and the preserved file-manager chord;
  exercise file operations, previews, unusual names, cancellation and resource
  bounds, and prove runtime package and theme downloads are unavailable.
- [ ] Launch Glum on local Markdown with links, images and metacharacters; verify
  its pinned bytes, man page, completions and explicit external-application
  handoffs. Launch Tootles in offline demo and with test Mastodon and Bluesky
  accounts; verify Tokyo Night, private credentials, bounded media, mpv and
  revocation without exposing account material to governed sessions.
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

## Retained signed candidates and Kitty selection blocker

[Discovery 45818341284](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45818341284)
passed at `30d4ab7`. All 218 original small evidence files are retained and
independently reconciled: 39 RPMs totaling 46,606,537 bytes, 37 verified against
the Fedora key and two against RPM Fusion Free. Both signers' missing-key,
wrong-key and modified-RPM controls failed as required (six native controls).
The installed base inventory stayed byte-identical; container/image/private
storage cleanup passed. The parent had 60,246 memory-limit events with no OOM,
kill or swap; the discovery container peaked at 412,282,880 bytes with zero
memory-limit/OOM/kill events. The large candidate archive remains hosted.

Candidates include MPlayer `1.5.1-0.26.r38531.20260727.f401198.fc45`, mpv
`0.41.0-10.fc45`, and Kitty `0.48.2-1.fc45`. The separately queried gum version
was `2.0.2-1.fc45`; the stable repositories returned no Starship or mise rows.
These are discovered inputs, not installed additions or release pins. The
MPlayer spec reviewed earlier was release 0.27 and is not source proof for the
actual 0.26 candidate; that exact source review remains required.

The [exact Kitty source review](security/reports/P0-03-cve-bz/2026-11-26/desktop-profile/fedora-kitty/README.md)
rejects the candidate for integration: seven reviewed cve.bz fixes are absent
from the checksum-bound source and are not backported by its three Fedora
patches. Kitty remains absent from the built image. Select an authenticated
maintained fixed package/source, assess the remaining advisories and run native
tests before enabling it as the default. No blanket audit exemption, security
clearance or claim about the owner's current workstation is made.

Both-base additive installation, remaining dependency/security/license review,
fonts, Tokyo Night, menus, all 190 shortcuts and actual desktop acceptance are
still pending. No production dependency or trust selection changes in this
evidence-only follow-up; INV-12 remains a release requirement.

Authenticated Kitty 0.51.0 source contains the corresponding reviewed fixes;
[source authentication and all sixteen scoped assessments](security/reports/P0-03-cve-bz/2026-11-26/desktop-profile/kitty-source-followup/README.md)
are retained. It remains unselected pending native build, dependency and desktop
qualification. The requested Kitty default and all reference shortcuts remain
requirements; the built images still have their minimal Foot profile.

## First implementation tranche

The image defaults now include a shared, reviewable Lua binding file with 69
named chords. It implements 56 compositor, ten-workspace and media bindings and
keeps 13 unavailable menu/application chords reserved with `no_op`. The existing
Super+Space launcher and Super+Alt+Space main-menu meanings are preserved. This
is the first working subset of the 190-entry reference; every omitted or
reserved entry still needs explicit booted-session accounting.

Tokyo Night is selected from shipped local Hyprland, Waybar and Walker data.
Kitty and tmux profiles carry the selected presentation and terminal-key
behavior without copying Kitty remote control or tmux shell hooks. Foot remains
the active terminal until Kitty 0.51.0 and its bundled dependency closure pass
native review. The profiles do not claim that Kitty or tmux is installed.

A separate Nerd Fonts v3.5.1 intake pins JetBrains Mono and Symbols Only release
assets and notices. Exact cached assets passed passive bounded inventory without
extraction or font parser execution. The hosted intake, native font rendering,
package integration, menu implementations, application tests and complete
190-binding session inventory remain acceptance gates. Local fail-first and
passing evidence is retained under
`security/reports/P0-03-desktop-profile/local-defaults-2026-11-26/`.

## Development font integration

The desktop preparation path now turns a successful current-job Nerd Fonts
intake into the exact development-image payload. It installs all 96 pinned
JetBrains Mono Nerd Font faces, both Symbols Nerd Font faces, the reviewed
Symbols aliases and five notices. The system aliases reproduce the inspected
Ombuntu defaults: Liberation Sans, Liberation Serif, JetBrainsMono Nerd Font,
Symbols Nerd Font and Noto Color Emoji. Kitty's staged 9-point profile therefore
names the same monospace family as the local reference.

The installer binds the input pins, source commit, intake manifest, archive
sizes and hashes and complete member inventories. It rejects links, traversal,
special files, unsafe fontconfig XML, existing or linked output paths and any
copy failure without leaving a partial payload. It rechecks all input hashes
after extraction. The installed-image probe uses native `fc-scan` for every
expected path and `fc-match monospace` for the default family.

The exact v3.5.1 assets passed a local extraction and native fontconfig check:
98 unique faces, 248,325,788 font bytes and 398 Symbols aliases, in 1.62 seconds
at 97,832 KiB peak RSS with zero swap. All 277 image tests then passed in 2.08
seconds at 54,540 KiB peak RSS with zero swap. This result establishes bounded
payload construction against local parser libraries. The complete serial
repository gate passed in 4.17 seconds at 68,280 KiB peak RSS with one Cargo
job and zero swap. A hosted intake and real generic/NVIDIA image runs must still
prove the selected secureblue bases contain
the required tools and accept the exact payload. Booted Kitty, Walker, Waybar
and glyph rendering remain open. The record therefore says development-included
and leaves release, security and OS qualification false.
