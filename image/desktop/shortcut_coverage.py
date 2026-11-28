#!/usr/bin/env python3
"""Validate static coverage of the recorded desktop shortcut reference.

The ledger accounts for source configuration only.  It does not execute the
compositor, prove that command dependencies are installed, or qualify a booted
session.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
REFERENCE_PATH = Path("docs/desktop-reference/ombuntu-keybindings.json")
OVERLAY_PATH = Path("image/overlay/usr/share/symbiont/defaults/hypr/bindings.lua")
LEDGER_PATH = Path("image/desktop/shortcut-coverage.json")
SCOPE = (
    "Static source accounting only; no compositor parsing, command execution, "
    "package availability, desktop interaction, boot, OS or security qualification"
)
STATUS_MEANINGS = {
    "implemented": "A non-no-op handler is present in the shipped source overlay; runtime behavior is untested",
    "reserved": "The recorded chord is present as an explicit no-op so later work cannot silently reuse it",
    "blocked": "No binding for the recorded chord is present in the shipped source overlay",
}
MODIFIERS = {"SHIFT": 1, "CTRL": 4, "ALT": 8, "SUPER": 64}
DISPLAY_MODIFIERS = ((64, "SUPER"), (1, "SHIFT"), (4, "CTRL"), (8, "ALT"))
BINDING = re.compile(
    r'^hl\.bind\("(?P<chord>[^"\\]+)", (?P<handler>.+), '
    r'\{ description = "(?P<description>[^"\\]+)"'
    r'(?P<options>(?:, [a-z_]+ = (?:true|false))*) \}\)$'
)
OPTION = re.compile(r", ([a-z_]+) = (true|false)")
LINE_COMMENT = re.compile(r"-- [ -~]*")
LUA_STRING = r'"[^"\\\r\n]*"'
LUA_SCALAR = rf"(?:{LUA_STRING}|true|false|[1-9][0-9]*)"
HANDLER = re.compile(
    rf"^hl\.dsp(?:\.[a-z_][a-z0-9_]*)+\("
    rf"(?:{LUA_STRING}|\{{ [a-z_][a-z0-9_]* = {LUA_SCALAR}"
    rf"(?:, [a-z_][a-z0-9_]* = {LUA_SCALAR})* \}})?"
    rf"\)$"
)


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_json(value) -> str:
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    return digest_bytes(raw)


def load_json(path: Path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_bytes(), object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"Malformed JSON in {path}") from error


def reference_identity(row: dict) -> tuple[int, str, int]:
    if set(row) != {"modmask", "key", "keycode", "description", "dispatcher", "flags"}:
        raise ValueError("Reference binding shape changed")
    if (not isinstance(row["modmask"], int) or row["modmask"] < 0
            or not isinstance(row["key"], str)
            or not isinstance(row["keycode"], int) or row["keycode"] < 0
            or not isinstance(row["description"], str)
            or not isinstance(row["dispatcher"], str) or not row["dispatcher"]
            or not isinstance(row["flags"], list)
            or not all(isinstance(flag, str) and flag for flag in row["flags"])
            or len(row["flags"]) != len(set(row["flags"]))):
        raise ValueError("Invalid reference binding")
    if bool(row["key"]) == bool(row["keycode"]):
        raise ValueError("Reference binding must select exactly one key form")
    return row["modmask"], row["key"].casefold(), row["keycode"]


def chord_identity(chord: str) -> tuple[int, str, int]:
    parts = [part.strip() for part in chord.split("+")]
    if not parts or any(not part for part in parts):
        raise ValueError(f"Malformed shipped chord: {chord!r}")
    modifiers = parts[:-1]
    if len(modifiers) != len(set(modifiers)) or any(name not in MODIFIERS for name in modifiers):
        raise ValueError(f"Unknown or duplicate modifier in shipped chord: {chord!r}")
    mask = sum(MODIFIERS[name] for name in modifiers)
    key = parts[-1]
    if key.lower().startswith("code:"):
        value = key.split(":", 1)[1]
        if not value.isdecimal() or int(value) <= 0:
            raise ValueError(f"Invalid physical keycode in shipped chord: {chord!r}")
        return mask, "", int(value)
    return mask, key.casefold(), 0


def reference_chord(row: dict) -> str:
    mask, key, keycode = reference_identity(row)
    known_mask = sum(bit for bit, _ in DISPLAY_MODIFIERS)
    if mask & ~known_mask:
        raise ValueError("Reference binding uses an unknown modifier bit")
    parts = [name for bit, name in DISPLAY_MODIFIERS if mask & bit]
    parts.append(f"code:{keycode}" if keycode else row["key"])
    return " + ".join(parts)


def parse_overlay(path: Path) -> list[dict]:
    rows = []
    for line_number, raw in enumerate(path.read_text().splitlines(), start=1):
        if raw == "":
            continue
        if LINE_COMMENT.fullmatch(raw):
            continue
        match = BINDING.fullmatch(raw)
        if not match:
            raise ValueError(f"Unsupported Lua syntax at {path}:{line_number}")
        if not HANDLER.fullmatch(match.group("handler")):
            raise ValueError(f"Unsupported binding handler at {path}:{line_number}")
        option_pairs = OPTION.findall(match.group("options"))
        options = {}
        for name, value in option_pairs:
            if name in options:
                raise ValueError(f"Duplicate binding option at {path}:{line_number}")
            options[name] = value == "true"
        row = {
            "chord": match.group("chord"),
            "handler": match.group("handler"),
            "description": match.group("description"),
            "options": options,
            "line_sha256": digest_bytes((raw + "\n").encode()),
            "line": raw,
            "line_number": line_number,
        }
        row["identity"] = chord_identity(row["chord"])
        rows.append(row)
    if not rows:
        raise ValueError("Shipped overlay contains no bindings")
    chords = [row["chord"] for row in rows]
    identities = [row["identity"] for row in rows]
    if len(chords) != len(set(chords)):
        raise ValueError("Shipped overlay reuses a literal chord")
    if len(identities) != len(set(identities)):
        raise ValueError("Shipped overlay reuses a physical chord")
    return rows


def shipped_record(row: dict) -> dict:
    return {name: row[name] for name in (
        "chord", "handler", "description", "options")}


def binding_set_digest(rows: list[dict]) -> str:
    return digest_bytes("".join(row["line"] + "\n" for row in rows).encode())


def validate(reference_path: Path = ROOT / REFERENCE_PATH,
             overlay_path: Path = ROOT / OVERLAY_PATH,
             ledger_path: Path = ROOT / LEDGER_PATH) -> dict:
    reference_raw = reference_path.read_bytes()
    reference = load_json(reference_path)
    overlay = parse_overlay(overlay_path)
    ledger = load_json(ledger_path)

    reference_rows = reference.get("bindings") if isinstance(reference, dict) else None
    if (not isinstance(reference_rows, list)
            or reference.get("binding_count") != len(reference_rows)):
        raise ValueError("Reference binding count or shape changed")
    reference_identities = [reference_identity(row) for row in reference_rows]
    # Rebuild the physical-identity groups without accepting an implicit duplicate.
    grouped = defaultdict(list)
    for index, identity in enumerate(reference_identities):
        grouped[identity].append(index)
    duplicate_groups = sorted(sorted(indices) for indices in grouped.values() if len(indices) > 1)

    expected_top = {
        "schema", "scope", "reference", "overlay", "status_meanings",
        "status_counts", "reference_multi_bindings", "qualification", "entries",
    }
    if not isinstance(ledger, dict) or set(ledger) != expected_top or ledger.get("schema") != 1:
        raise ValueError("Shortcut coverage ledger shape changed")
    if ledger["scope"] != SCOPE or ledger["status_meanings"] != STATUS_MEANINGS:
        raise ValueError("Shortcut coverage status or scope changed")
    if ledger["qualification"] != {
            "runtime_tested": False, "os_qualified": False, "security_qualified": False}:
        raise ValueError("Static ledger may not claim runtime or qualification evidence")
    if ledger["reference"] != {
            "path": REFERENCE_PATH.as_posix(),
            "sha256": digest_bytes(reference_raw),
            "binding_count": len(reference_rows),
    }:
        raise ValueError("Reference identity or count drifted")
    if ledger["overlay"] != {
            "path": OVERLAY_PATH.as_posix(),
            "sha256": digest_bytes(overlay_path.read_bytes()),
            "binding_count": len(overlay),
            "bindings_sha256": binding_set_digest(overlay),
    }:
        raise ValueError("Shipped overlay source, binding set or count drifted")

    declared_groups = ledger["reference_multi_bindings"]
    if (not isinstance(declared_groups, list)
            or any(not isinstance(item, dict) or set(item) != {"indices", "reason"}
                   or not isinstance(item["reason"], str) or not item["reason"]
                   for item in declared_groups)):
        raise ValueError("Reference multi-binding declarations are malformed")
    declared_indices = [item["indices"] for item in declared_groups]
    if declared_indices != duplicate_groups or len(declared_indices) != len({tuple(x) for x in declared_indices}):
        raise ValueError("Reference physical-chord reuse changed without explicit review")

    by_identity = {row["identity"]: row for row in overlay}
    entries = ledger["entries"]
    if not isinstance(entries, list) or len(entries) != len(reference_rows):
        raise ValueError("Coverage entry count drifted")
    used_chords = set()
    counts = Counter()
    for index, (entry, source, identity) in enumerate(zip(entries, reference_rows, reference_identities)):
        if (not isinstance(entry, dict)
                or set(entry) != {"reference_index", "reference_sha256", "reference_chord",
                                  "reference_intent", "status", "shipped"}
                or entry["reference_index"] != index
                or entry["reference_sha256"] != digest_json(source)
                or entry["reference_chord"] != reference_chord(source)
                or entry["reference_intent"] != source["description"]):
            raise ValueError(f"Coverage reference binding changed at index {index}")
        status = entry["status"]
        if status not in STATUS_MEANINGS:
            raise ValueError(f"Unknown or inconsistent status at index {index}")
        shipped = by_identity.get(identity)
        if status == "blocked":
            if entry["shipped"] is not None or shipped is not None:
                raise ValueError(f"Blocked reference now owns a shipped chord at index {index}")
        else:
            if shipped is None or entry["shipped"] != shipped_record(shipped):
                raise ValueError(f"Shipped action changed at reference index {index}")
            if shipped["chord"] in used_chords:
                raise ValueError(f"Shipped chord reused in coverage ledger: {shipped['chord']}")
            used_chords.add(shipped["chord"])
            reserved = shipped["handler"] == "hl.dsp.no_op()"
            if status != ("reserved" if reserved else "implemented"):
                raise ValueError(f"Handler status changed at reference index {index}")
        counts[status] += 1

    if used_chords != {row["chord"] for row in overlay}:
        raise ValueError("Shipped overlay contains an unaccounted binding")
    calculated_counts = {name: counts[name] for name in STATUS_MEANINGS}
    if ledger["status_counts"] != calculated_counts or sum(calculated_counts.values()) != len(reference_rows):
        raise ValueError("Shortcut coverage status counts drifted")
    return {
        "schema": 1,
        "passed": True,
        "reference_bindings": len(reference_rows),
        "shipped_bindings": len(overlay),
        "status_counts": calculated_counts,
        "runtime_tested": False,
        "os_qualified": False,
        "security_qualified": False,
        "scope": SCOPE,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, default=ROOT / REFERENCE_PATH)
    parser.add_argument("--overlay", type=Path, default=ROOT / OVERLAY_PATH)
    parser.add_argument("--ledger", type=Path, default=ROOT / LEDGER_PATH)
    args = parser.parse_args()
    try:
        result = validate(args.reference, args.overlay, args.ledger)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Shortcut coverage refused: {error}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
