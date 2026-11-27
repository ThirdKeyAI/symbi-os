#!/usr/bin/env python3
"""Validate the fixed Tolaria source, tool and downstream integration inputs."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


ROOT = Path(__file__).resolve().parents[2]
HEX64 = re.compile(r"[0-9a-f]{64}")
PATCH_MARKERS = {
    "symbi-os-image-updates-only",
    "symbi-os-transient-mcp-only",
    "symbi-os-governed-agent-route-only",
    "symbi-os-model-broker-only",
}


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def unique_json(raw):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key: " + key)
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=object_pairs)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ValueError("Malformed JSON input") from error


def load_pins(path=ROOT / "image/tolaria/source.json"):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 128 * 1024:
        raise ValueError("Invalid Tolaria pin document")
    pins = unique_json(path.read_bytes())
    required_top = {
        "schema", "status", "repository", "license", "release", "source",
        "required_files", "downstream_patch", "pnpm", "selected",
        "security_qualified", "os_qualified",
    }
    if set(pins) != required_top or pins["schema"] != 1:
        raise ValueError("Unexpected Tolaria pin schema")
    if (pins["repository"] != "https://github.com/refactoringhq/tolaria"
            or pins["license"] != "AGPL-3.0-or-later"
            or pins["status"] != "candidate-awaiting-bounded-fedora-build-and-os-qualification"
            or any(pins[name] is not False for name in ("selected", "security_qualified", "os_qualified"))):
        raise ValueError("Unexpected Tolaria selection or qualification state")
    release = pins["release"]
    if (set(release) != {"tag", "published_at", "tag_object", "tag_signed",
                         "source_commit", "github_attestation_found"}
            or release["tag"] != "v2026-11-18"
            or release["published_at"] != "2026-11-18T22:20:21Z"
            or release["tag_object"] != "7145103d8183cb243ab831969fd200e431eab560"
            or release["source_commit"] != "a87d074c0f35acd6475b6e37145ccbfd6fbecffd"
            or release["tag_signed"] is not False
            or release["github_attestation_found"] is not False):
        raise ValueError("Unexpected Tolaria release identity or authentication claim")
    source = pins["source"]
    root_name = "tolaria-" + release["source_commit"]
    expected_url = f"{pins['repository']}/archive/{release['source_commit']}.tar.gz"
    if (set(source) != {"url", "bytes", "sha256", "root", "members",
                        "regular_files", "directories", "expanded_bytes"}
            or source["url"] != expected_url or source["root"] != root_name
            or not isinstance(source["bytes"], int) or not 0 < source["bytes"] <= 64 * 1024**2
            or not HEX64.fullmatch(source["sha256"])
            or source["members"] != source["regular_files"] + source["directories"]
            or not 0 < source["members"] <= 8192
            or not 0 < source["expanded_bytes"] <= 128 * 1024**2):
        raise ValueError("Unexpected Tolaria source archive pin")
    required = pins["required_files"]
    required_names = {
        "LICENSE", "package.json", "pnpm-lock.yaml", "mcp-server/package.json",
        "mcp-server/package-lock.json", "src-tauri/Cargo.toml",
        "src-tauri/Cargo.lock", "src-tauri/tauri.conf.json",
        "src-tauri/capabilities/default.json",
    }
    if set(required) != required_names:
        raise ValueError("Unexpected required Tolaria source-file set")
    for name, row in required.items():
        require_relative(name)
        if (set(row) != {"bytes", "sha256"} or not isinstance(row["bytes"], int)
                or not 0 < row["bytes"] <= 2 * 1024**2 or not HEX64.fullmatch(row["sha256"])):
            raise ValueError("Invalid required Tolaria file pin: " + name)
    require_patch(pins, ROOT)
    require_pnpm_pin(pins["pnpm"])
    return pins


def require_relative(name):
    if not isinstance(name, str) or not name or len(name.encode()) > 2048 or "\\" in name:
        raise ValueError("Invalid archive path")
    path = PurePosixPath(name)
    if (path.is_absolute() or path.as_posix() != name
            or any(part in ("", ".", "..") for part in path.parts)):
        raise ValueError("Unsafe archive path: " + repr(name))
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("Control character in archive path")
    return path


def read_regular_member(archive, item, limit):
    if item.size < 0 or item.size > limit:
        raise ValueError("Archive member exceeds its size bound")
    source = archive.extractfile(item)
    if source is None:
        raise ValueError("Regular archive member has no readable bytes")
    size = 0
    hasher = hashlib.sha256()
    with source:
        while block := source.read(65536):
            size += len(block)
            if size > item.size:
                raise ValueError("Archive member exceeded its declared size")
            hasher.update(block)
    if size != item.size:
        raise ValueError("Truncated archive member")
    return size, hasher.hexdigest()


def inspect_source(path, pins=None):
    pins = pins or load_pins()
    path = Path(path)
    source_pin = pins["source"]
    if (path.is_symlink() or not path.is_file() or path.stat().st_size != source_pin["bytes"]
            or digest(path) != source_pin["sha256"]):
        raise ValueError("Tolaria source archive bytes changed")
    root_name = source_pin["root"]
    required = pins["required_files"]
    found = {}
    seen = set()
    members = regular = directories = expanded = 0
    try:
        with tarfile.open(path, "r|gz") as archive:
            for item in archive:
                members += 1
                if members > 8192:
                    raise ValueError("Source archive member limit exceeded")
                name = item.name.removeprefix("./")
                archive_path = require_relative(name)
                if name in seen:
                    raise ValueError("Duplicate source archive member: " + name)
                seen.add(name)
                if archive_path.parts[0] != root_name:
                    raise ValueError("Source archive has an unexpected root")
                if item.mode & 0o7000 or item.issparse():
                    raise ValueError("Unsafe source archive mode or sparse member")
                expanded += item.size
                if expanded > 128 * 1024**2:
                    raise ValueError("Source archive expanded-byte limit exceeded")
                if item.isdir():
                    if item.size != 0:
                        raise ValueError("Source directory has a nonzero body")
                    directories += 1
                    continue
                if not item.isfile():
                    raise ValueError("Source archive contains a link or special member")
                regular += 1
                size, sha256 = read_regular_member(archive, item, 16 * 1024**2)
                relative = "/".join(archive_path.parts[1:])
                if relative in required:
                    expected = required[relative]
                    if size != expected["bytes"] or sha256 != expected["sha256"]:
                        raise ValueError("Required source file changed: " + relative)
                    found[relative] = {"bytes": size, "sha256": sha256}
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ValueError("Unreadable Tolaria source archive") from error
    observed = {
        "members": members, "regular_files": regular,
        "directories": directories, "expanded_bytes": expanded,
    }
    expected_counts = {key: source_pin[key] for key in observed}
    if observed != expected_counts or set(found) != set(required):
        raise ValueError("Tolaria source inventory changed")
    return {**observed, "required_files": found}


def patch_paths(text):
    old = []
    new = []
    for line in text.splitlines():
        if line.startswith("--- "):
            old.append(line[4:].split("\t", 1)[0])
        elif line.startswith("+++ "):
            new.append(line[4:].split("\t", 1)[0])
    if len(old) != len(new) or not old:
        raise ValueError("Patch file headers are incomplete")
    paths = []
    for before, after in zip(old, new):
        if not before.startswith("a/") or not after.startswith("b/") or before[2:] != after[2:]:
            raise ValueError("Patch creates, deletes, renames or escapes a file")
        require_relative(before[2:])
        paths.append(before[2:])
    return paths


def require_patch(pins, root=ROOT):
    patch_pin = pins["downstream_patch"]
    required_keys = {"path", "bytes", "sha256", "paths", "result_sha256"}
    if set(patch_pin) != required_keys:
        raise ValueError("Unexpected downstream patch schema")
    relative = require_relative(patch_pin["path"])
    if relative.parts[:2] != ("image", "tolaria") or relative.parts[-1] != "0001-managed-os-integration.patch":
        raise ValueError("Downstream patch path is outside the Tolaria input directory")
    patch = Path(root) / relative
    if (patch.is_symlink() or not patch.is_file() or patch.stat().st_size != patch_pin["bytes"]
            or not HEX64.fullmatch(patch_pin["sha256"]) or digest(patch) != patch_pin["sha256"]):
        raise ValueError("Downstream patch bytes changed")
    try:
        text = patch.read_text(encoding="utf-8")
    except UnicodeError as error:
        raise ValueError("Downstream patch is not UTF-8") from error
    if "GIT binary patch" in text or "Binary files " in text or "\x00" in text:
        raise ValueError("Downstream patch contains a binary change")
    paths = patch_paths(text)
    if paths != patch_pin["paths"] or set(patch_pin["result_sha256"]) != set(paths):
        raise ValueError("Downstream patch path set or order changed")
    if any(not HEX64.fullmatch(value) for value in patch_pin["result_sha256"].values()):
        raise ValueError("Invalid patched-file digest")
    if not PATCH_MARKERS.issubset(text.split('"')):
        raise ValueError("Downstream fail-closed marker is missing")
    return {"bytes": patch.stat().st_size, "sha256": digest(patch), "paths": paths}


def require_pnpm_pin(pin):
    keys = {"version", "url", "bytes", "sha256", "npm_integrity",
            "npm_signing_key_id", "members", "expanded_bytes", "required_files"}
    if (set(pin) != keys or pin["version"] != "10.34.9"
            or pin["url"] != "https://registry.npmjs.org/pnpm/-/pnpm-10.34.9.tgz"
            or not isinstance(pin["bytes"], int) or not 0 < pin["bytes"] <= 16 * 1024**2
            or not HEX64.fullmatch(pin["sha256"])
            or pin["npm_integrity"] != "sha512-9JtajqD97bRLs8DB1ldQkqU8KVDZW3rRXfEfF5dId6LeOgHAfpNOmyjOcW5RwJqUlixzBtCb4uHksYqMh2L9Mg=="
            or pin["npm_signing_key_id"] != "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U"
            or not 0 < pin["members"] <= 2048
            or not 0 < pin["expanded_bytes"] <= 32 * 1024**2
            or set(pin["required_files"]) != {"package/package.json", "package/bin/pnpm.cjs", "package/bin/pnpx.cjs"}
            or any(not HEX64.fullmatch(value) for value in pin["required_files"].values())):
        raise ValueError("Unexpected pnpm tool pin")


def inspect_pnpm(path, pins=None):
    pins = pins or load_pins()
    pin = pins["pnpm"]
    path = Path(path)
    if (path.is_symlink() or not path.is_file() or path.stat().st_size != pin["bytes"]
            or digest(path) != pin["sha256"]):
        raise ValueError("pnpm archive bytes changed")
    seen = set()
    found = {}
    members = expanded = 0
    try:
        with tarfile.open(path, "r|gz") as archive:
            for item in archive:
                members += 1
                if members > 2048:
                    raise ValueError("pnpm member limit exceeded")
                name = item.name.removeprefix("./")
                archive_path = require_relative(name)
                if archive_path.parts[0] != "package" or name in seen:
                    raise ValueError("Unexpected or duplicate pnpm archive path")
                seen.add(name)
                if not item.isfile() or item.mode & 0o6000 or item.issparse():
                    raise ValueError("pnpm archive contains a link, special file or unsafe mode")
                expanded += item.size
                if expanded > 32 * 1024**2:
                    raise ValueError("pnpm expanded-byte limit exceeded")
                _, sha256 = read_regular_member(archive, item, 16 * 1024**2)
                if name in pin["required_files"]:
                    if sha256 != pin["required_files"][name]:
                        raise ValueError("Required pnpm file changed: " + name)
                    found[name] = sha256
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ValueError("Unreadable pnpm archive") from error
    if (members != pin["members"] or expanded != pin["expanded_bytes"]
            or set(found) != set(pin["required_files"])):
        raise ValueError("pnpm archive inventory changed")
    return {"members": members, "expanded_bytes": expanded, "required_files": found}


def require_patched_tree(tree, pins=None):
    pins = pins or load_pins()
    tree = Path(tree)
    if tree.is_symlink() or not tree.is_dir():
        raise ValueError("Patched source tree is absent")
    expected = pins["downstream_patch"]["result_sha256"]
    observed = {}
    for relative, sha256 in expected.items():
        path = tree / relative
        if (path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(tree.resolve())
                or digest(path) != sha256):
            raise ValueError("Patched source result changed: " + relative)
        observed[relative] = sha256
    cargo = (tree / "src-tauri/Cargo.toml").read_text()
    config = (tree / "src-tauri/tauri.conf.json").read_text()
    capability = (tree / "src-tauri/capabilities/default.json").read_text()
    library = (tree / "src-tauri/src/lib.rs").read_text()
    package_args = (tree / "src-tauri/src/pi_config/package_args.rs").read_text()
    combined = "\n".join((cargo, config, capability, library, package_args))
    forbidden = ("tauri-plugin-updater", "tauri_plugin_updater::Builder",
                 "spawn_initial_ws_bridge_sync", "npm:pi-mcp-adapter",
                 "desktop_runtime::spawn_startup_tasks()")
    if any(token in combined for token in forbidden):
        raise ValueError("Patched source retains a forbidden update, bridge or runtime-download path")
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pins", type=Path, default=ROOT / "image/tolaria/source.json")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--pnpm", type=Path)
    parser.add_argument("--patched-tree", type=Path)
    args = parser.parse_args()
    try:
        pins = load_pins(args.pins)
        record = {"schema": 1, "pins_sha256": digest(args.pins),
                  "patch": require_patch(pins, ROOT)}
        if args.source:
            record["source"] = inspect_source(args.source, pins)
        if args.pnpm:
            record["pnpm"] = inspect_pnpm(args.pnpm, pins)
        if args.patched_tree:
            record["patched_tree"] = require_patched_tree(args.patched_tree, pins)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Tolaria input validation refused: {error}\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
