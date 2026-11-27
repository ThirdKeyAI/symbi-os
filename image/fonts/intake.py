"""Passively authenticate and inventory pinned Nerd Font release candidates."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import time
import urllib.parse
import urllib.request


FONT_MAGIC = {b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"}
PLAIN_MEMBERS = {"OFL.txt", "LICENSE", "README.md", "10-nerd-font-symbols.conf"}
NOTICE_PATHS = [
    "image/fonts/licenses/Nerd-Fonts-MIT",
    "image/fonts/licenses/JetBrains-Mono-OFL-1.1",
    "image/fonts/licenses/Nerd-Fonts-Symbols-MIT",
    "image/fonts/licenses/Font-Logos-Unlicense",
    "image/fonts/licenses/upstream-license-audit.md",
]


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def load_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise ValueError("Invalid font pin document")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate key in font pin document: " + key)
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ValueError("Malformed font pin document") from error


def inspect_archive(path, profile, max_bytes=512 * 1024**2, max_members=256):
    if profile not in ("jetbrains", "symbols"):
        raise ValueError("Unknown font archive profile")
    rows = {}
    expanded = 0
    try:
        with tarfile.open(path, "r|*") as archive:
            for item in archive:
                name = item.name.removeprefix("./")
                if (not name or name in rows or name.startswith("/") or "/" in name
                        or name in (".", "..") or any(ord(char) < 32 or ord(char) == 127 for char in name)
                        or not item.isfile() or item.mode & 0o7000 or item.issparse()):
                    raise ValueError("Unsafe, duplicate or non-regular font archive member: " + repr(name))
                if len(rows) >= max_members or item.size < 0 or item.size > 8 * 1024**2:
                    raise ValueError("Font archive member limit exceeded")
                expanded += item.size
                if expanded > max_bytes:
                    raise ValueError("Font archive expanded-byte limit exceeded")
                is_font = name.lower().endswith((".ttf", ".otf"))
                if not is_font and name not in PLAIN_MEMBERS:
                    raise ValueError("Unexpected font archive payload: " + name)
                source = archive.extractfile(item)
                if source is None:
                    raise ValueError("Missing regular member bytes")
                hasher = hashlib.sha256()
                size = 0
                magic = b""
                with source:
                    while block := source.read(65536):
                        if not magic:
                            magic = block[:4]
                        size += len(block)
                        if size > item.size:
                            raise ValueError("Font member exceeded its declared size")
                        hasher.update(block)
                if size != item.size:
                    raise ValueError("Truncated font archive member")
                if is_font and magic not in FONT_MAGIC:
                    raise ValueError("Font member has an unsupported header: " + name)
                rows[name] = {"bytes": size, "sha256": hasher.hexdigest(),
                              "magic": magic.hex(), "mode": item.mode}
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ValueError("Unreadable font archive") from error
    required = ({"JetBrainsMonoNerdFont-Regular.ttf", "JetBrainsMonoNerdFontMono-Regular.ttf", "OFL.txt", "README.md"}
                if profile == "jetbrains" else
                {"SymbolsNerdFont-Regular.ttf", "SymbolsNerdFontMono-Regular.ttf", "LICENSE", "README.md",
                 "10-nerd-font-symbols.conf"})
    if not required <= rows.keys():
        raise ValueError("Font archive lacks required fonts or notices")
    return dict(sorted(rows.items()))


def require_checksum_index(text, assets):
    rows = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})\s+\*?([^/\s]+)", line.strip())
        if match:
            if match.group(2) in rows:
                raise ValueError("Duplicate checksum-index name")
            rows[match.group(2)] = match.group(1)
    for asset in assets:
        if asset["name"] == "SHA-256.txt":
            continue
        if rows.get(asset["name"]) != asset["sha256"]:
            raise ValueError("Release checksum index disagrees with pinned asset")
    return rows


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.geteuid() == 0):
        raise SystemExit("Use the unprivileged disposable hosted font-intake unit")
    root = Path.cwd().resolve()
    group = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip() for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    expected_limits = {"memory.max": "536870912", "memory.swap.max": "0", "cpu.max": "100000 100000", "pids.max": "32"}
    if not group.name.startswith("symbi-font-intake-") or limits != expected_limits:
        raise ValueError("Unexpected font-intake resource group")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if any(status[name].strip() != "0000000000000000" for name in ("CapEff", "CapPrm", "CapBnd")) or status["NoNewPrivs"].strip() != "1":
        raise ValueError("Font inspector must have no capabilities and no new privileges")
    evidence = root / ".cache/font-intake-evidence"
    candidate = root / ".cache/font-candidate"
    private = root / ".cache/font-intake-private"
    evidence.mkdir()
    candidate.mkdir()
    private.mkdir(mode=0o700)
    pins_path = root / "image/fonts/inputs.json"
    record = {"schema": 1, "passed": False, "selected": False, "font_parser_executed": False,
              "archive_extracted": False, "os_qualified": False, "limits": limits,
              "source_commit": os.environ["GITHUB_SHA"], "scope": "Hash and passive archive inventory only"}

    def save():
        (evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n")

    try:
        pins = load_json(pins_path)
        if (pins.get("schema") != 1 or pins.get("tag") != "v3.5.1"
                or pins.get("revision") != "b894ea7803af6aade63d60a4381e006098ec9c4d"
                or pins.get("published_at") != "2026-08-21T15:21:46Z"
                or pins.get("repository") != "https://github.com/ryanoasis/nerd-fonts"
                or pins.get("selected") is not False or pins.get("security_qualified") is not False
                or pins.get("os_qualified") is not False):
            raise ValueError("Unexpected font candidate selection or revision")
        if [notice.get("path") for notice in pins.get("notices", [])] != NOTICE_PATHS:
            raise ValueError("Unexpected font notice set or order")
        for notice in pins["notices"]:
            path = root / notice["path"]
            if (set(notice) != {"path", "bytes", "sha256"}
                    or path.parent != root / "image/fonts/licenses"
                    or path.resolve() != path or path.stat().st_size != notice["bytes"]
                    or not 0 < notice["bytes"] <= 64 * 1024
                    or not re.fullmatch(r"[0-9a-f]{64}", notice["sha256"])
                    or digest(path) != notice["sha256"]):
                raise ValueError("Reviewed font notice changed")
        record["inputs_sha256"] = digest(pins_path)
        record["downloads"] = []
        assets = pins.get("assets", [])
        expected_names = ["JetBrainsMono.tar.xz", "NerdFontsSymbolsOnly.tar.xz", "SHA-256.txt"]
        if [asset.get("name") for asset in assets] != expected_names:
            raise ValueError("Unexpected font asset set or order")
        for asset in assets:
            if (set(asset) != {"name", "asset_id", "bytes", "sha256", "url"}
                    or not isinstance(asset["asset_id"], int) or asset["asset_id"] <= 0
                    or asset["url"] != f"https://github.com/ryanoasis/nerd-fonts/releases/download/v3.5.1/{asset['name']}"
                    or not re.fullmatch(r"[0-9a-f]{64}", asset["sha256"])
                    or not 0 < asset["bytes"] <= 16 * 1024**2):
                raise ValueError("Unexpected font asset pin")
            target = private / asset["name"]
            request = urllib.request.Request(asset["url"], headers={
                "User-Agent": "SymbiOS-P0-font-intake/1", "Accept-Encoding": "identity"})
            start = time.monotonic()
            size = 0
            hasher = hashlib.sha256()
            with urllib.request.urlopen(request, timeout=30) as response, target.open("xb") as output:
                final_url = urllib.parse.urlsplit(response.url)
                if (response.status != 200 or final_url.scheme != "https"
                        or final_url.username is not None or final_url.password is not None
                        or final_url.port not in (None, 443)
                        or not (final_url.hostname == "github.com"
                                or (final_url.hostname or "").endswith(".githubusercontent.com"))):
                    raise ValueError("Unexpected font asset response")
                while block := response.read(65536):
                    size += len(block)
                    if size > asset["bytes"] or time.monotonic() - start > 180:
                        raise ValueError("Font asset exceeded its size/time bound")
                    hasher.update(block)
                    output.write(block)
            if size != asset["bytes"] or hasher.hexdigest() != asset["sha256"]:
                raise ValueError("Font asset bytes changed")
            record["downloads"].append(asset)
            save()
        checksum = (private / "SHA-256.txt").read_text(encoding="utf-8")
        record["checksum_entries"] = len(require_checksum_index(checksum, pins["assets"]))
        inventories = {}
        expected = {"JetBrainsMono.tar.xz": ("jetbrains", 98, 96),
                    "NerdFontsSymbolsOnly.tar.xz": ("symbols", 5, 2)}
        for name, (profile, member_count, font_count) in expected.items():
            rows = inspect_archive(private / name, profile)
            fonts = sum(member.lower().endswith((".ttf", ".otf")) for member in rows)
            if len(rows) != member_count or fonts != font_count:
                raise ValueError("Unexpected font release inventory count")
            raw = (json.dumps(rows, indent=2) + "\n").encode()
            (evidence / (name + ".inventory.json")).write_bytes(raw)
            inventories[name] = {"members": len(rows), "fonts": fonts,
                                 "expanded_bytes": sum(row["bytes"] for row in rows.values()),
                                 "inventory_sha256": hashlib.sha256(raw).hexdigest()}
            shutil.copyfile(private / name, candidate / name)
        manifest = {"schema": 1, "source_commit": os.environ["GITHUB_SHA"], "inputs_sha256": record["inputs_sha256"],
                    "selected": False, "archives": inventories}
        (candidate / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        record.update(passed=True, inventories=inventories)
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        shutil.rmtree(private)
        record["private_downloads_removed"] = not private.exists()
        record["cgroup_final"] = {name: (group / name).read_text().strip()
                                  for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        if not record["private_downloads_removed"]:
            record["passed"] = False
        save()


if __name__ == "__main__":
    main()
