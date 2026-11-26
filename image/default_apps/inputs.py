"""Validate exact source archives for the requested terminal applications."""
import hashlib
import json
from pathlib import Path
import re
import tarfile
import tomllib


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
EXPECTED = {
    "yazi": ("https://github.com/sxyazi/yazi", "MIT", ["yazi"], ["ya"]),
    "glum": ("https://github.com/jaschadub/glum", "Apache-2.0", ["glum"], []),
    "tootles": ("https://github.com/tootles-dev/tootles", "MIT", ["tootles"], []),
}


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate source-input key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("source inputs must be an object")
    return value


def exact_hash(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{%d}" % length, value)


def _source_shape(name, app):
    repository, license_name, installed, excluded = EXPECTED[name]
    if (set(app) != {"repository", "version", "revision", "license", "tag", "source",
                     "cargo_lock", "build"}
            or app["repository"] != repository or app["license"] != license_name
            or not re.fullmatch(r"v[0-9]+(?:\.[0-9]+)+", app["version"])
            or not exact_hash(app["revision"], 40)):
        raise ValueError("unexpected application source identity: " + name)
    tag = app["tag"]
    if (set(tag) != {"kind", "object", "signed"}
            or tag["kind"] not in ("lightweight", "annotated")
            or not exact_hash(tag["object"], 40) or tag["signed"] is not False
            or (tag["kind"] == "lightweight" and tag["object"] != app["revision"])):
        raise ValueError("unbound or prematurely trusted tag: " + name)
    source = app["source"]
    required_source = {"url", "bytes", "sha256", "root", "members", "regular_files",
                       "directories", "symlinks", "hardlinks", "expanded_bytes", "links",
                       "required_files"}
    if (set(source) != required_source
            or source["url"] != repository + "/archive/" + app["revision"] + ".tar.gz"
            or source["root"] != repository.rsplit("/", 1)[1] + "-" + app["revision"]
            or type(source["bytes"]) is not int or not 0 < source["bytes"] <= 32 * 1024**2
            or not exact_hash(source["sha256"])
            or any(type(source[key]) is not int or source[key] < 0 for key in
                   ("members", "regular_files", "directories", "symlinks", "hardlinks",
                    "expanded_bytes"))
            or not 1 <= source["members"] <= 10000
            or source["expanded_bytes"] > 256 * 1024**2
            or source["hardlinks"] != 0
            or not isinstance(source["links"], dict)
            or not isinstance(source["required_files"], dict)
            or not {"Cargo.toml", "Cargo.lock", "LICENSE"}.issubset(source["required_files"])):
        raise ValueError("unexpected application archive contract: " + name)
    for relative, target in source["links"].items():
        if (not re.fullmatch(r"[A-Za-z0-9_.-]+", relative)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", target)):
            raise ValueError("unsafe pinned source link")
    for relative, item in source["required_files"].items():
        if (not _safe_relative(relative) or set(item) != {"bytes", "sha256"}
                or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= 4 * 1024**2
                or not exact_hash(item["sha256"])):
            raise ValueError("invalid required source file: " + relative)
    lock = app["cargo_lock"]
    if (set(lock) != {"version", "packages", "sources", "git_packages"}
            or lock["version"] not in (3, 4) or type(lock["packages"]) is not int
            or not 1 <= lock["packages"] <= 2000 or not isinstance(lock["sources"], list)
            or not lock["sources"] or len(set(lock["sources"])) != len(lock["sources"])
            or any(value != "local" and value != REGISTRY and not value.startswith("git+https://")
                   for value in lock["sources"])
            or not isinstance(lock["git_packages"], list)
            or any(set(row) != {"name", "version", "source"}
                   or not isinstance(row["name"], str) or not isinstance(row["version"], str)
                   or row["source"] not in lock["sources"] or not row["source"].startswith("git+")
                   for row in lock["git_packages"])):
        raise ValueError("invalid Cargo lock contract: " + name)
    build = app["build"]
    if (set(build) != {"rust_version", "package", "installed_binaries", "excluded_binaries"}
            or not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", build["rust_version"])
            or not re.fullmatch(r"[a-z][a-z0-9-]*", build["package"])
            or build["installed_binaries"] != installed
            or build["excluded_binaries"] != excluded
            or set(installed).intersection(excluded)):
        raise ValueError("unexpected installed application boundary: " + name)


def load_inputs(path=ROOT / "image/default_apps/source-inputs.json"):
    value = unique_json(Path(path).read_bytes())
    if (set(value) != {"schema", "status", "applications", "selected",
                      "security_qualified", "os_qualified", "scope"}
            or value["schema"] != 1 or value["status"] != "candidate-source-intake-only"
            or value["selected"] is not False or value["security_qualified"] is not False
            or value["os_qualified"] is not False
            or set(value["applications"]) != set(EXPECTED)
            or not isinstance(value["scope"], str) or not value["scope"]):
        raise ValueError("unexpected default application source input document")
    for name, app in value["applications"].items():
        _source_shape(name, app)
    return value


def _safe_relative(value):
    if (not isinstance(value, str) or not value or value.startswith("/") or "\\" in value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        return False
    return all(part not in ("", ".", "..") for part in value.split("/"))


def _member_relative(name, root):
    trimmed = name[:-1] if name.endswith("/") else name
    if not _safe_relative(trimmed) or not trimmed.startswith(root + "/"):
        if trimmed == root:
            return ""
        raise ValueError("unsafe source archive path")
    return trimmed[len(root) + 1:]


def _read_member(archive, member, maximum=4 * 1024**2):
    if not member.isfile() or not 0 <= member.size <= maximum:
        raise ValueError("required source member is not a bounded regular file")
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError("required source member is unreadable")
    data = stream.read(maximum + 1)
    if len(data) != member.size or len(data) > maximum:
        raise ValueError("required source member size changed")
    return data


def _cargo_inventory(cargo_raw, lock_raw, app):
    try:
        manifest = tomllib.loads(cargo_raw.decode("utf-8"))
        lock = tomllib.loads(lock_raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("unreadable Cargo source metadata") from error
    package = manifest.get("workspace", {}).get("package", manifest.get("package", {}))
    build = app["build"]
    if (package.get("version") != app["version"].removeprefix("v")
            or package.get("license") != app["license"]
            or package.get("rust-version") != build["rust_version"]):
        raise ValueError("Cargo manifest identity differs from source pin")
    packages = lock.get("package")
    if not isinstance(packages, list) or lock.get("version") != app["cargo_lock"]["version"]:
        raise ValueError("Cargo lock format changed")
    seen = set()
    sources = set()
    git_packages = []
    for row in packages:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not isinstance(row.get("version"), str):
            raise ValueError("malformed Cargo package entry")
        source = row.get("source", "local")
        identity = (row["name"], row["version"], source)
        if identity in seen:
            raise ValueError("duplicate Cargo package identity")
        seen.add(identity)
        sources.add(source)
        if source == REGISTRY:
            if not exact_hash(row.get("checksum")):
                raise ValueError("registry package lacks an exact checksum")
        elif source.startswith("git+"):
            git_packages.append({"name": row["name"], "version": row["version"], "source": source})
        elif source != "local":
            raise ValueError("Cargo lock uses an unreviewed dependency source")
    actual = {"version": lock["version"], "packages": len(packages),
              "sources": sorted(sources), "git_packages": git_packages}
    if actual != app["cargo_lock"]:
        raise ValueError("Cargo dependency inventory differs from source pin")
    return actual


def inspect_archive(path, app):
    path = Path(path)
    source = app["source"]
    if (path.is_symlink() or not path.is_file() or path.stat().st_size != source["bytes"]
            or digest(path) != source["sha256"]):
        raise ValueError("application source archive bytes changed")
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) != source["members"]:
                raise ValueError("application source member count changed")
            names = set()
            files = {}
            counts = {"regular_files": 0, "directories": 0, "symlinks": 0,
                      "hardlinks": 0, "expanded_bytes": 0}
            links = {}
            for member in members:
                relative = _member_relative(member.name, source["root"])
                if member.name in names:
                    raise ValueError("duplicate application source member")
                names.add(member.name)
                if relative == "" and not member.isdir():
                    raise ValueError("application source root is not a directory")
                if member.isfile():
                    counts["regular_files"] += 1
                    counts["expanded_bytes"] += member.size
                    if counts["expanded_bytes"] > 256 * 1024**2:
                        raise ValueError("expanded application source exceeds its bound")
                    if relative in source["required_files"]:
                        files[relative] = _read_member(archive, member)
                elif member.isdir():
                    counts["directories"] += 1
                elif member.issym():
                    counts["symlinks"] += 1
                    expected = source["links"].get(relative)
                    if expected is None or member.linkname != expected or not re.fullmatch(
                            r"[A-Za-z0-9_.-]+", member.linkname):
                        raise ValueError("unreviewed application source link")
                    links[relative] = member.linkname
                elif member.islnk():
                    counts["hardlinks"] += 1
                    raise ValueError("application source hard links are refused")
                else:
                    raise ValueError("application source contains a special member")
            expected_counts = {key: source[key] for key in counts}
            if counts != expected_counts or links != source["links"]:
                raise ValueError("application source inventory changed")
            if set(files) != set(source["required_files"]):
                raise ValueError("required application source file is absent")
            for relative, expected in source["required_files"].items():
                if len(files[relative]) != expected["bytes"] or hashlib.sha256(
                        files[relative]).hexdigest() != expected["sha256"]:
                    raise ValueError("required application source file changed: " + relative)
            cargo = _cargo_inventory(files["Cargo.toml"], files["Cargo.lock"], app)
            return {**counts, "members": len(members), "links": links,
                    "required_files": source["required_files"], "cargo_lock": cargo}
    except (tarfile.TarError, OSError) as error:
        raise ValueError("unreadable application source archive") from error
