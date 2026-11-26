"""Validate the exact, signed Glum Linux release candidate without extracting it."""
import hashlib
import json
from pathlib import Path
import re
import tarfile


ROOT = Path(__file__).resolve().parents[2]
INPUTS = ROOT / "image/default_apps/glum-release-inputs.json"
MAX_ARCHIVE = 32 * 1024**2
MAX_FILE = 16 * 1024**2
IDENTITY = (
    "https://github.com/jaschadub/glum",
    "v0.4.1",
    "9cc45ced6ee0fc0bb5c6d90db65b453e6c2e650b",
)
TAG = {
    "kind": "annotated",
    "object": "0277948bf54c594fec39597fb3eca272fae75b5f",
    "signed": False,
}
RELEASE = {
    "id": 405365169,
    "published_at": "2026-10-07T04:02:46Z",
    "target_commitish": "main",
    "draft": False,
    "prerelease": False,
}
SOURCE = {
    "url": IDENTITY[0] + "/archive/" + IDENTITY[2] + ".tar.gz",
    "bytes": 4823054,
    "sha256": "01c0d6d97c58bdb48061eb7d5220f3ba2bad220800ff1f909e11b38f55b527f0",
}
ASSET_ID = 617523321
ASSET_NAME = "glum-v0.4.1-x86_64-unknown-linux-gnu.tar.gz"
ASSET_URL = IDENTITY[0] + "/releases/download/v0.4.1/" + ASSET_NAME
DIRECTORIES = [
    "share",
    "share/zsh",
    "share/zsh/site-functions",
    "share/bash-completion",
    "share/bash-completion/completions",
    "share/fish",
    "share/fish/vendor_completions.d",
    "share/man",
    "share/man/man1",
]
FILES = {
    "CHANGELOG.md": (0o644, False, "release-notes"),
    "LICENSE": (0o644, True, "license"),
    "NOTICE": (0o644, True, "notice"),
    "README.md": (0o644, False, "documentation"),
    "glum": (0o755, True, "binary"),
    "share/zsh/site-functions/_glum": (0o644, True, "zsh-completion"),
    "share/bash-completion/completions/glum": (0o644, True, "bash-completion"),
    "share/fish/vendor_completions.d/glum.fish": (0o644, True, "fish-completion"),
    "share/man/man1/glum.1": (0o644, True, "manpage"),
}


def _unique_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate Glum release-input key")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("unreadable Glum release inputs") from error
    if not isinstance(value, dict):
        raise ValueError("Glum release inputs must be an object")
    return value


def _hash(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{%d}" % length, value)


def _safe_relative(value):
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return False
    return all(part not in ("", ".", "..") for part in value.split("/"))


def _asset_record(value, expected_id, expected_name):
    expected_url = IDENTITY[0] + "/releases/download/v0.4.1/" + expected_name
    return (
        isinstance(value, dict)
        and set(value) == {"id", "name", "url", "bytes", "sha256"}
        and value["id"] == expected_id
        and value["name"] == expected_name
        and value["url"] == expected_url
        and type(value["bytes"]) is int
        and 0 < value["bytes"] <= MAX_ARCHIVE
        and _hash(value["sha256"])
    )


def load_release_inputs(path=INPUTS):
    """Load the fixed release identity, inventory and still-open trust flags."""
    path = Path(path)
    if (
        path.is_symlink()
        or not path.is_file()
        or path.resolve() != path
        or not 0 < path.stat().st_size <= 256 * 1024
    ):
        raise ValueError("expected bounded regular Glum release inputs")
    value = _unique_json(path.read_bytes())
    required = {
        "schema",
        "status",
        "repository",
        "version",
        "revision",
        "release",
        "tag",
        "source",
        "asset",
        "signature",
        "selected",
        "security_qualified",
        "os_qualified",
        "scope",
    }
    if (
        set(value) != required
        or value["schema"] != 1
        or value["status"] != "official-release-candidate"
        or (value["repository"], value["version"], value["revision"]) != IDENTITY
        or value["release"] != RELEASE
        or value["tag"] != TAG
        or value["source"] != SOURCE
        or value["selected"] is not False
        or value["security_qualified"] is not False
        or value["os_qualified"] is not False
        or not isinstance(value["scope"], str)
        or not value["scope"]
    ):
        raise ValueError("unexpected Glum release identity or qualification")
    asset = value["asset"]
    if (
        not isinstance(asset, dict)
        or set(asset)
        != {
            "id",
            "name",
            "url",
            "bytes",
            "sha256",
            "members",
            "regular_files",
            "directories",
            "symlinks",
            "hardlinks",
            "expanded_bytes",
            "files",
        }
        or asset["id"] != ASSET_ID
        or asset["name"] != ASSET_NAME
        or asset["url"] != ASSET_URL
        or type(asset["bytes"]) is not int
        or not 0 < asset["bytes"] <= MAX_ARCHIVE
        or not _hash(asset["sha256"])
        or asset["members"] != len(DIRECTORIES) + len(FILES)
        or asset["regular_files"] != len(FILES)
        or asset["directories"] != DIRECTORIES
        or asset["symlinks"] != 0
        or asset["hardlinks"] != 0
        or type(asset["expanded_bytes"]) is not int
        or not 0 < asset["expanded_bytes"] <= MAX_ARCHIVE
        or not isinstance(asset["files"], dict)
        or set(asset["files"]) != set(FILES)
    ):
        raise ValueError("unexpected Glum release asset inventory")
    expanded = 0
    for name, expected in FILES.items():
        row = asset["files"][name]
        if (
            not _safe_relative(name)
            or not isinstance(row, dict)
            or set(row) != {"bytes", "sha256", "mode", "install", "role"}
            or type(row["bytes"]) is not int
            or not 0 < row["bytes"] <= MAX_FILE
            or not _hash(row["sha256"])
            or (row["mode"], row["install"], row["role"]) != expected
        ):
            raise ValueError("unexpected Glum release file: " + name)
        expanded += row["bytes"]
    if expanded != asset["expanded_bytes"]:
        raise ValueError("Glum release expanded size differs from its file inventory")
    signature = value["signature"]
    if not isinstance(signature, dict) or set(signature) != {
        "certificate_asset",
        "signature_asset",
        "checksums_asset",
        "decoded_certificate",
        "decoded_signature",
        "asset_sha256",
        "payload_signature_verified",
        "fulcio_chain_verified",
        "transparency_log_verified",
    }:
        raise ValueError("unexpected Glum release signature record")
    if (
        not _asset_record(
            signature["certificate_asset"],
            617523310,
            ASSET_NAME + ".pem",
        )
        or not _asset_record(
            signature["signature_asset"],
            617523312,
            ASSET_NAME + ".sig",
        )
        or not _asset_record(signature["checksums_asset"], 617523342, "checksums.txt")
        or signature["asset_sha256"] != asset["sha256"]
        or signature["payload_signature_verified"] is not True
        or signature["fulcio_chain_verified"] is not False
        or signature["transparency_log_verified"] is not False
    ):
        raise ValueError("unbound or prematurely trusted Glum release signature")
    certificate = signature["decoded_certificate"]
    expected_certificate = {
        "bytes": 2439,
        "sha256": "dbd7b39d181ab34f55393423679f9946b0961e2989a30b61aaa0b40100229cef",
        "issuer": "O=sigstore.dev, CN=sigstore-intermediate",
        "serial": "3E0669387576A98A5DD6CAD491133EC9EA332BAD",
        "not_before": "2026-10-07T04:10:04Z",
        "not_after": "2026-10-07T04:20:04Z",
        "san": "https://github.com/jaschadub/glum/.github/workflows/release-binaries.yml@refs/tags/v0.4.1",
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "repository": "jaschadub/glum",
        "commit": IDENTITY[2],
        "ref": "refs/tags/v0.4.1",
        "workflow": "Release Binaries",
        "workflow_run_url": "https://github.com/jaschadub/glum/actions/runs/37569571310/attempts/1",
    }
    if certificate != expected_certificate or signature["decoded_signature"] != {
        "bytes": 70,
        "sha256": "985b6320ce050d93f65465d076e12aa0ddef4c6ab2902ed31479c4c74879b88b",
    }:
        raise ValueError("Glum release certificate identity differs from the reviewed input")
    return value


def inspect_release_archive(path, inputs):
    """Passively verify every member of an exact Glum release archive."""
    path = Path(path)
    if (
        inputs.get("selected") is not False
        or inputs.get("security_qualified") is not False
        or inputs.get("os_qualified") is not False
    ):
        raise ValueError("Glum release candidate is prematurely selected or qualified")
    asset = inputs["asset"]
    if (
        path.is_symlink()
        or not path.is_file()
        or path.resolve() != path
        or path.stat().st_size != asset["bytes"]
        or hashlib.sha256(path.read_bytes()).hexdigest() != asset["sha256"]
    ):
        raise ValueError("Glum release archive bytes changed")
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) != asset["members"]:
                raise ValueError("Glum release archive member count changed")
            expected_names = {*asset["directories"], *asset["files"]}
            seen = set()
            files = 0
            directories = 0
            expanded = 0
            for member in members:
                name = member.name
                if name in seen or name not in expected_names or not _safe_relative(name):
                    raise ValueError("unexpected or duplicate Glum release member")
                seen.add(name)
                if member.isfile():
                    if name not in asset["files"]:
                        raise ValueError("Glum release member type changed")
                    expected = asset["files"][name]
                    if member.mode & 0o777 != expected["mode"] or member.size != expected["bytes"]:
                        raise ValueError("Glum release file metadata changed")
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValueError("Glum release file is unreadable")
                    raw = stream.read(MAX_FILE + 1)
                    if (
                        len(raw) != expected["bytes"]
                        or hashlib.sha256(raw).hexdigest() != expected["sha256"]
                    ):
                        raise ValueError("Glum release file bytes changed")
                    files += 1
                    expanded += len(raw)
                elif member.isdir():
                    if name not in asset["directories"] or member.mode & 0o777 != 0o755:
                        raise ValueError("Glum release directory metadata changed")
                    directories += 1
                else:
                    raise ValueError("Glum release contains a link or special member")
            if (
                seen != expected_names
                or files != asset["regular_files"]
                or directories != len(asset["directories"])
                or expanded != asset["expanded_bytes"]
            ):
                raise ValueError("Glum release archive inventory changed")
            return {
                "members": len(members),
                "files": files,
                "directories": directories,
                "expanded_bytes": expanded,
                "installed_files": sum(
                    row["install"] is True for row in asset["files"].values()
                ),
            }
    except (tarfile.TarError, OSError) as error:
        raise ValueError("unreadable Glum release archive") from error
