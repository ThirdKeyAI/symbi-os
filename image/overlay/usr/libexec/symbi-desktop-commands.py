#!/usr/bin/python3
"""Resolve the small set of commands exposed by the default desktop."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from typing import Callable, Sequence


WALKER_COMMAND = ("/usr/bin/walker",)
TERMINAL_CANDIDATES = ("/usr/bin/kitty", "/usr/bin/foot")
MAIN_ACTIONS = ("Applications", "Terminal", "Keybindings", "System")
SYSTEM_COMMANDS = {
    "Suspend": ("/usr/bin/systemctl", "suspend"),
    "Restart": ("/usr/bin/systemctl", "reboot"),
    "Power off": ("/usr/bin/systemctl", "poweroff"),
}
HELP_ROWS = (
    ("SUPER + SPACE", "Application launcher"),
    ("SUPER + ALT + SPACE", "Main desktop menu"),
    ("SUPER + Return", "Terminal (Kitty, Foot fallback)"),
    ("SUPER + Escape", "System menu"),
    ("SUPER + K", "Keybinding help"),
    ("SUPER + W", "Close window"),
    ("SUPER + T", "Toggle window floating"),
    ("SUPER + F", "Full screen"),
    ("SUPER + TAB", "Next workspace"),
    ("SUPER + SHIFT + TAB", "Previous workspace"),
    ("SUPER + CTRL + TAB", "Former workspace"),
)
HELP_OPTIONS = tuple(f"{chord}  {description}" for chord, description in HELP_ROWS)


def is_executable(path: str) -> bool:
    candidate = Path(path)
    return candidate.is_file() and os.access(candidate, os.X_OK)


def terminal_command(executable: Callable[[str], bool] = is_executable) -> tuple[str, ...]:
    for candidate in TERMINAL_CANDIDATES:
        if executable(candidate):
            return (candidate,)
    raise RuntimeError("no supported terminal is installed")


def select(title: str, options: Sequence[str]) -> str | None:
    completed = subprocess.run(
        [*WALKER_COMMAND, "--dmenu", "--width", "420", "--minheight", "1",
         "--maxheight", "420", "-p", title],
        input="\n".join(options) + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    choice = completed.stdout.rstrip("\n")
    return choice if choice in options else None


def resolve(
    action: str,
    chooser: Callable[[str, Sequence[str]], str | None] = select,
    executable: Callable[[str], bool] = is_executable,
) -> tuple[str, ...] | None:
    if action == "terminal":
        return terminal_command(executable)
    if action == "menu":
        choice = chooser("Menu", MAIN_ACTIONS)
        if choice == "Applications":
            return WALKER_COMMAND
        if choice == "Terminal":
            return terminal_command(executable)
        if choice == "Keybindings":
            action = "keybindings"
        elif choice == "System":
            action = "system"
        else:
            return None
    if action == "keybindings":
        chooser("Keybindings", HELP_OPTIONS)
        return None
    if action == "system":
        return SYSTEM_COMMANDS.get(chooser("System", tuple(SYSTEM_COMMANDS)))
    raise ValueError("unknown desktop command")


def main(arguments: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if arguments is None else arguments)
    if len(arguments) != 1 or arguments[0] not in {"terminal", "menu", "system", "keybindings"}:
        print("usage: symbi-desktop-commands.py terminal|menu|system|keybindings", file=sys.stderr)
        return 2
    try:
        command = resolve(arguments[0])
        if command is not None:
            os.execv(command[0], list(command))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"desktop command failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
