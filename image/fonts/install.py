"""Build a bounded desktop-image payload from the authenticated font candidate."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import xml.etree.ElementTree as ET

from image.desktop.files import copy_regular
from image.fonts.intake import digest, inspect_archive, load_json


ARCHIVES = {
    "JetBrainsMono.tar.xz": ("jetbrains", "JetBrainsMono"),
    "NerdFontsSymbolsOnly.tar.xz": ("symbols", "Symbols"),
}
FONTCONFIG_DOCTYPE = b'<!DOCTYPE fontconfig SYSTEM "fonts.dtd">'


def validate_fontconfig(raw):
    upper = raw.upper()
    if (not 0 < len(raw) <= 64 * 1024 or b"<!ENTITY" in upper
            or raw.count(FONTCONFIG_DOCTYPE) != 1 or upper.count(b"<!DOCTYPE") != 1):
        raise ValueError("Unsafe Nerd Font fontconfig input")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, UnicodeError) as error:
        raise ValueError("Malformed Nerd Font fontconfig input") from error
    if root.tag != "fontconfig" or root.attrib or not 1 <= len(root) <= 512:
        raise ValueError("Unexpected Nerd Font fontconfig root")
    families = []
    for alias in root:
        if alias.tag != "alias" or alias.attrib or [child.tag for child in alias] != ["family", "prefer"]:
            raise ValueError("Nerd Font configuration may contain aliases only")
        family, prefer = alias
        if (family.attrib or prefer.attrib or list(family)
                or [child.tag for child in prefer] != ["family"] or prefer[0].attrib or list(prefer[0])
                or not family.text or len(family.text) > 128 or prefer[0].text != "Symbols Nerd Font"):
            raise ValueError("Unexpected Nerd Font alias")
        families.append(family.text)
    if not families or families[0] != "monospace" or len(families) != len(set(families)):
        raise ValueError("Nerd Font aliases must begin with a unique monospace rule")
    return {"aliases": len(families), "sha256": hashlib.sha256(raw).hexdigest()}


def _summary(rows):
    raw = (json.dumps(rows, indent=2) + "\n").encode()
    return {
        "members": len(rows),
        "fonts": sum(name.lower().endswith((".ttf", ".otf")) for name in rows),
        "expanded_bytes": sum(row["bytes"] for row in rows.values()),
        "inventory_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _require_candidate(candidate, pins_path, current_commit):
    if (candidate.is_symlink() or not candidate.is_dir() or candidate.resolve() != candidate
            or not re.fullmatch(r"[0-9a-f]{40}", current_commit)):
        raise ValueError("Invalid font candidate directory or source commit")
    if {path.name for path in candidate.iterdir()} != {*ARCHIVES, "manifest.json"}:
        raise ValueError("Unexpected font candidate artifact members")
    pins = load_json(pins_path)
    assets = pins.get("assets", [])
    if (pins.get("schema") != 1 or pins.get("selected") is not False
            or pins.get("security_qualified") is not False or pins.get("os_qualified") is not False
            or [row.get("name") for row in assets[:2]] != list(ARCHIVES)
            or len(assets) != 3):
        raise ValueError("Font candidate pin state changed")
    manifest = load_json(candidate / "manifest.json")
    if (set(manifest) != {"schema", "source_commit", "inputs_sha256", "selected", "archives"}
            or manifest.get("schema") != 1 or manifest.get("source_commit") != current_commit
            or manifest.get("inputs_sha256") != digest(pins_path) or manifest.get("selected") is not False
            or set(manifest.get("archives", {})) != set(ARCHIVES)):
        raise ValueError("Font candidate manifest is not bound to this image build")
    inventories = {}
    for asset in assets[:2]:
        if set(asset) != {"name", "asset_id", "bytes", "sha256", "url"}:
            raise ValueError("Unexpected font archive pin")
        path = candidate / asset["name"]
        if (path.is_symlink() or not path.is_file() or path.resolve() != path
                or path.stat().st_size != asset["bytes"] or digest(path) != asset["sha256"]):
            raise ValueError("Authenticated font archive changed")
        rows = inspect_archive(path, ARCHIVES[asset["name"]][0])
        if manifest["archives"][asset["name"]] != _summary(rows):
            raise ValueError("Font archive inventory changed")
        inventories[asset["name"]] = rows
    return pins, manifest, inventories


def _extract_archive(archive_path, rows, folder, stage):
    extracted = []
    config = None
    with tarfile.open(archive_path, "r:xz") as archive:
        for item in archive:
            name = item.name.removeprefix("./")
            if name not in rows:
                raise ValueError("Font member differs from the reviewed inventory")
            if name == "10-nerd-font-symbols.conf":
                source = archive.extractfile(item)
                if source is None:
                    raise ValueError("Missing fontconfig bytes")
                config = source.read(64 * 1024 + 1)
                if len(config) != item.size or hashlib.sha256(config).hexdigest() != rows[name]["sha256"]:
                    raise ValueError("Fontconfig bytes changed")
                continue
            if not name.lower().endswith((".ttf", ".otf")):
                continue
            target = stage / "usr/share/fonts/symbi-nerd-fonts" / folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(item)
            if source is None:
                raise ValueError("Missing font bytes")
            size = 0
            hasher = hashlib.sha256()
            with source, target.open("xb") as output:
                while block := source.read(1024 * 1024):
                    size += len(block)
                    if size > item.size:
                        raise ValueError("Font exceeded its reviewed size")
                    hasher.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
                os.posix_fadvise(output.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            if size != rows[name]["bytes"] or hasher.hexdigest() != rows[name]["sha256"]:
                raise ValueError("Extracted font differs from the reviewed member")
            target.chmod(0o644)
            extracted.append(target)
    expected = {name for name in rows if name.lower().endswith((".ttf", ".otf"))}
    if {path.name for path in extracted} != expected:
        raise ValueError("Font extraction omitted a reviewed face")
    return extracted, config


def _safe_targets(payload, files):
    for relative in files:
        target = payload / relative
        current = payload
        for part in relative.parts[:-1]:
            current /= part
            if current.is_symlink() or (current.exists() and not current.is_dir()):
                raise ValueError("Linked or non-directory font payload parent")
        if target.exists() or target.is_symlink():
            raise ValueError("Font payload would overwrite an existing path")


def prepare_font_payload(candidate, pins_path, repository, payload, current_commit):
    """Validate, stage and copy the full locally observed Ombuntu font set."""
    candidate = Path(candidate)
    pins_path = Path(pins_path)
    repository = Path(repository)
    payload = Path(payload)
    if (candidate.is_symlink() or pins_path.is_symlink() or repository.is_symlink()
            or candidate.resolve() != candidate or pins_path.resolve() != pins_path
            or repository.resolve() != repository):
        raise ValueError("Font integration inputs must be direct absolute paths")
    if payload.is_symlink() or not payload.is_dir() or payload.resolve() != payload:
        raise ValueError("Invalid desktop payload root")
    pins, manifest, inventories = _require_candidate(candidate, pins_path, current_commit)
    manifest_sha256 = digest(candidate / "manifest.json")
    archive_bindings = {row["name"]: (row["bytes"], row["sha256"]) for row in pins["assets"][:2]}
    stage = Path(tempfile.mkdtemp(prefix="symbi-font-stage-", dir=payload.parent))
    try:
        fonts = []
        config = None
        for name, (_, folder) in ARCHIVES.items():
            rows = inventories[name]
            extracted, discovered_config = _extract_archive(candidate / name, rows, folder, stage)
            fonts.extend(extracted)
            if discovered_config is not None:
                if config is not None:
                    raise ValueError("Duplicate fontconfig payload")
                config = discovered_config
        if config is None:
            raise ValueError("Missing reviewed Nerd Font fontconfig payload")
        config_review = validate_fontconfig(config)
        config_target = stage / "etc/fonts/conf.d/10-nerd-font-symbols.conf"
        config_target.parent.mkdir(parents=True, exist_ok=True)
        config_target.write_bytes(config)
        config_target.chmod(0o644)
        notices = []
        for row in pins.get("notices", []):
            source = repository / row.get("path", "")
            expected_parent = repository / "image/fonts/licenses"
            if (set(row) != {"path", "bytes", "sha256"} or source.parent != expected_parent
                    or source.is_symlink() or not source.is_file() or source.resolve() != source
                    or source.stat().st_size != row["bytes"] or digest(source) != row["sha256"]):
                raise ValueError("Reviewed font notice changed")
            target = stage / "usr/share/licenses/symbi-nerd-fonts" / source.name
            copy_regular(source, target)
            notices.append(target)
        if (digest(pins_path) != manifest["inputs_sha256"]
                or digest(candidate / "manifest.json") != manifest_sha256
                or {path.name for path in candidate.iterdir()} != {*ARCHIVES, "manifest.json"}):
            raise ValueError("Font candidate metadata changed during preparation")
        for name, (size, expected_hash) in archive_bindings.items():
            path = candidate / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size != size or digest(path) != expected_hash:
                raise ValueError("Font archive changed during preparation")
        staged = [path for path in stage.rglob("*") if path.is_file()]
        relatives = [path.relative_to(stage) for path in staged]
        _safe_targets(payload, relatives)
        created = []
        try:
            for source, relative in zip(staged, relatives, strict=True):
                target = payload / relative
                copy_regular(source, target)
                created.append(target)
        except Exception:
            for path in reversed(created):
                path.unlink(missing_ok=True)
            raise
        paths = sorted("/" + path.relative_to(stage).as_posix() for path in fonts)
        return {
            "schema": 1,
            "development_included": True,
            "selected_for_release": False,
            "security_qualified": False,
            "os_qualified": False,
            "source_commit": current_commit,
            "inputs_sha256": manifest["inputs_sha256"],
            "candidate_manifest_sha256": manifest_sha256,
            "archives": manifest["archives"],
            "font_count": len(fonts),
            "font_bytes": sum(path.stat().st_size for path in fonts),
            "font_paths": paths,
            "fontconfig": config_review,
            "notice_count": len(notices),
            "scope": "Development-image font payload; native parsing and booted desktop acceptance remain separate gates",
        }
    finally:
        shutil.rmtree(stage)
        if stage.exists():
            raise RuntimeError("Temporary font staging was not removed")
