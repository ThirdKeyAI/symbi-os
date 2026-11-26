"""Native fontconfig/FreeType checks for the installed development image."""
import os
from pathlib import Path
import subprocess


PREFIX = "/usr/share/fonts/symbi-nerd-fonts/"


def validate_native_output(scan, match, expected_paths):
    if (not expected_paths or len(expected_paths) != len(set(expected_paths))
            or any(not path.startswith(PREFIX) for path in expected_paths)):
        raise ValueError("Unexpected native font path set")
    rows = {}
    families = set()
    for line in scan.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or parts[0] in rows or not parts[1] or not parts[2]:
            raise ValueError("Malformed or duplicate fc-scan output")
        rows[parts[0]] = {"families": parts[1], "styles": parts[2]}
        families.update(name.strip() for name in parts[1].split(","))
    if set(rows) != set(expected_paths) or not {"JetBrainsMono Nerd Font", "Symbols Nerd Font"} <= families:
        raise ValueError("Native font scan did not cover the selected families")
    matched = match.strip().split("\t")
    if (len(matched) != 2 or matched[0].split(",")[0].strip() != "JetBrainsMono Nerd Font"
            or matched[1] not in expected_paths or "/JetBrainsMono/" not in matched[1]):
        raise ValueError("Installed monospace default is not JetBrainsMono Nerd Font")
    return {"scanned_fonts": len(rows), "families": sorted(families),
            "monospace_family": "JetBrainsMono Nerd Font", "monospace_file": matched[1]}


def verify_installed_fonts(record):
    paths = record.get("font_paths", [])
    if (record.get("development_included") is not True or record.get("selected_for_release") is not False
            or record.get("os_qualified") is not False or record.get("font_count") != len(paths)
            or len(paths) > 128):
        raise ValueError("Unexpected development font record")
    for name in paths:
        path = Path(name)
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o022:
            raise ValueError("Installed font shape or permissions changed")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": os.environ.get("HOME", "/tmp"),
                   "XDG_CACHE_HOME": os.environ.get("XDG_CACHE_HOME", "/tmp")}
    scan = subprocess.run(["/usr/bin/fc-scan", "--format=%{file}\t%{family}\t%{style}\n", *paths],
                          capture_output=True, text=True, check=True, timeout=120, env=environment)
    match = subprocess.run(["/usr/bin/fc-match", "--format=%{family}\t%{file}\n", "monospace"],
                           capture_output=True, text=True, check=True, timeout=60, env=environment)
    if len(scan.stdout.encode()) > 128 * 1024 or scan.stderr or len(match.stdout.encode()) > 4096 or match.stderr:
        raise ValueError("Native font tool output exceeded its boundary")
    return validate_native_output(scan.stdout, match.stdout, paths)
