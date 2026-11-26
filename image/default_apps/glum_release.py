"""Validate the exact Glum Linux release candidate without extracting it."""
import hashlib
import json
from pathlib import Path
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
ASSET_NAME = "glum-v0.4.1-x86_64-unknown-linux-gnu.tar.gz"
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
    "CHANGELOG.md": {
        "bytes": 16082,
        "sha256": "35258dd8e392d184232784b8dbf5f14cee9cb3b7c74213cdcb07a6216df94d42",
        "mode": 0o644,
        "install": False,
        "role": "release-notes",
    },
    "LICENSE": {
        "bytes": 11305,
        "sha256": "7b3c40ac89912496e3a3d10ba8a6714d4022d9f8b60f89797169606f86797258",
        "mode": 0o644,
        "install": True,
        "role": "license",
    },
    "NOTICE": {
        "bytes": 236,
        "sha256": "04f7943c9982a2695534add74015be58fbaa501dc5ad86385a274108c2317d15",
        "mode": 0o644,
        "install": True,
        "role": "notice",
    },
    "README.md": {
        "bytes": 13259,
        "sha256": "6ee5d9b0db7d068724b2850e97c3046e4ce2ba351265200c7f18e49a1d33d9fe",
        "mode": 0o644,
        "install": False,
        "role": "documentation",
    },
    "glum": {
        "bytes": 4727920,
        "sha256": "381cc4d764a44bab6180f16e5d44642c4d7e6f8404c1ddb6736eef19a4d62260",
        "mode": 0o755,
        "install": True,
        "role": "binary",
    },
    "share/zsh/site-functions/_glum": {
        "bytes": 5384,
        "sha256": "e58cf71d14da76c13d1ed2dbfef772c6bd19c15abd3d6d7eacaa00409e54ae4b",
        "mode": 0o644,
        "install": True,
        "role": "zsh-completion",
    },
    "share/bash-completion/completions/glum": {
        "bytes": 2671,
        "sha256": "107d60fc17f322756e5a1516c0bb97258afd20708da1c8a540eb3bb627c784fa",
        "mode": 0o644,
        "install": True,
        "role": "bash-completion",
    },
    "share/fish/vendor_completions.d/glum.fish": {
        "bytes": 4202,
        "sha256": "4e578542e7a284c08bab7c7fb83bd6a9307013c90d44865f2ad42770421307c7",
        "mode": 0o644,
        "install": True,
        "role": "fish-completion",
    },
    "share/man/man1/glum.1": {
        "bytes": 5392,
        "sha256": "7143b6d65bcd3bfa5d8247b08929b5110814e86a4ad946ba94c232f934b56d71",
        "mode": 0o644,
        "install": True,
        "role": "manpage",
    },
}
ASSET = {
    "id": 617523321,
    "name": ASSET_NAME,
    "url": IDENTITY[0] + "/releases/download/v0.4.1/" + ASSET_NAME,
    "bytes": 1986149,
    "sha256": "640e94aa3d9aa5a5dcd8431ee4ac35119b51f976d2bbc952d2a34c2768566594",
    "members": 18,
    "regular_files": 9,
    "directories": DIRECTORIES,
    "symlinks": 0,
    "hardlinks": 0,
    "expanded_bytes": 4786451,
}
SIGNATURE_ASSETS = {
    "certificate_asset": {
        "id": 617523310,
        "name": ASSET_NAME + ".pem",
        "url": IDENTITY[0] + "/releases/download/v0.4.1/" + ASSET_NAME + ".pem",
        "bytes": 3252,
        "sha256": "a54bf5b0fc81866cc0a0ef89d1b2c02eee7e8fd9f7734b5eb249c5b3c6b1668c",
    },
    "signature_asset": {
        "id": 617523312,
        "name": ASSET_NAME + ".sig",
        "url": IDENTITY[0] + "/releases/download/v0.4.1/" + ASSET_NAME + ".sig",
        "bytes": 96,
        "sha256": "9b51cf19b471132a8513213b62bbde49b9294f6f96667c5490a151c1947bfcfb",
    },
    "checksums_asset": {
        "id": 617523342,
        "name": "checksums.txt",
        "url": IDENTITY[0] + "/releases/download/v0.4.1/checksums.txt",
        "bytes": 896,
        "sha256": "7746def6d7e782b63bb2a4fe6e21da70114f53e20966af75f09c02fb156d1f0a",
    },
}
DECODED_CERTIFICATE = {
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
DECODED_SIGNATURE = {
    "bytes": 70,
    "sha256": "985b6320ce050d93f65465d076e12aa0ddef4c6ab2902ed31479c4c74879b88b",
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


def _exact(value, expected):
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(value) == set(expected) and all(
            _exact(value[key], item) for key, item in expected.items()
        )
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            _exact(actual, item) for actual, item in zip(value, expected, strict=True)
        )
    return value == expected


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
        or not _exact(value["release"], RELEASE)
        or not _exact(value["tag"], TAG)
        or not _exact(value["source"], SOURCE)
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
        or not _exact({key: asset[key] for key in ASSET}, ASSET)
        or not isinstance(asset["files"], dict)
        or set(asset["files"]) != set(FILES)
    ):
        raise ValueError("unexpected Glum release asset inventory")
    for name, expected in FILES.items():
        row = asset["files"][name]
        if (
            not _safe_relative(name)
            or not isinstance(row, dict)
            or not _exact(row, expected)
        ):
            raise ValueError("unexpected Glum release file: " + name)
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
        any(
            not _exact(signature[name], expected)
            for name, expected in SIGNATURE_ASSETS.items()
        )
        or signature["asset_sha256"] != ASSET["sha256"]
        or signature["payload_signature_verified"] is not True
        or signature["fulcio_chain_verified"] is not False
        or signature["transparency_log_verified"] is not False
    ):
        raise ValueError("unbound or prematurely trusted Glum release signature")
    if (
        not _exact(signature["decoded_certificate"], DECODED_CERTIFICATE)
        or not _exact(signature["decoded_signature"], DECODED_SIGNATURE)
    ):
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
