"""Describe a closed offline Yazi, Glum and Tootles payload.

Staging remains fail-closed until an offline verifier authenticates provenance
bytes rather than trusting claims embedded in a payload lock.
"""
import hashlib
import json
import os
from pathlib import Path
import stat

from image.default_apps.inputs import digest, exact_hash, load_inputs
from image.default_apps.glum_release import load_release_inputs


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "image/default_apps/payload-contract.json"
SOURCE_INPUTS = ROOT / "image/default_apps/source-inputs.json"
GLUM_RELEASE_INPUTS = ROOT / "image/default_apps/glum-release-inputs.json"
MAX_ARCHIVE = 768 * 1024**2
MAX_FILE = 256 * 1024**2
EXPECTED_IDENTITIES = {
    "yazi": (
        "https://github.com/sxyazi/yazi",
        "v26.9.1",
        "8dd895c695a5950330c2623eb43debf323b60654",
    ),
    "glum": (
        "https://github.com/jaschadub/glum",
        "v0.4.1",
        "9cc45ced6ee0fc0bb5c6d90db65b453e6c2e650b",
    ),
    "tootles": (
        "https://github.com/tootles-dev/tootles",
        "v0.2.0",
        "40d7a63c5ec0e08cb3eb8241b50a2af6cf76c98a",
    ),
}
EXPECTED_FILES = {
    "yazi": [
        ("yazi/bin/yazi", "usr/bin/yazi", 0o755, "binary", None, None),
        (
            "yazi/assets/yazi.desktop",
            "usr/share/applications/yazi.desktop",
            0o644,
            "desktop",
            "assets/yazi.desktop",
            None,
        ),
        (
            "yazi/licenses/LICENSE",
            "usr/share/licenses/yazi/LICENSE",
            0o644,
            "license",
            "LICENSE",
            None,
        ),
        (
            "yazi/licenses/LICENSE-ICONS",
            "usr/share/licenses/yazi/LICENSE-ICONS",
            0o644,
            "license",
            "LICENSE-ICONS",
            None,
        ),
    ],
    "glum": [
        ("glum/bin/glum", "usr/bin/glum", 0o755, "binary", None, "glum"),
        (
            "glum/licenses/LICENSE",
            "usr/share/licenses/glum/LICENSE",
            0o644,
            "license",
            "LICENSE",
            "LICENSE",
        ),
        (
            "glum/licenses/NOTICE",
            "usr/share/licenses/glum/NOTICE",
            0o644,
            "notice",
            "NOTICE",
            "NOTICE",
        ),
        (
            "glum/man/glum.1",
            "usr/share/man/man1/glum.1",
            0o644,
            "manpage",
            None,
            "share/man/man1/glum.1",
        ),
        (
            "glum/completions/bash/glum",
            "usr/share/bash-completion/completions/glum",
            0o644,
            "bash-completion",
            None,
            "share/bash-completion/completions/glum",
        ),
        (
            "glum/completions/fish/glum.fish",
            "usr/share/fish/vendor_completions.d/glum.fish",
            0o644,
            "fish-completion",
            None,
            "share/fish/vendor_completions.d/glum.fish",
        ),
        (
            "glum/completions/zsh/_glum",
            "usr/share/zsh/site-functions/_glum",
            0o644,
            "zsh-completion",
            None,
            "share/zsh/site-functions/_glum",
        ),
    ],
    "tootles": [
        ("tootles/bin/tootles", "usr/bin/tootles", 0o755, "binary", None, None),
        (
            "tootles/assets/tootles.desktop",
            "usr/share/applications/tootles.desktop",
            0o644,
            "desktop",
            "packaging/tootles.desktop",
            None,
        ),
        (
            "tootles/licenses/LICENSE",
            "usr/share/licenses/tootles/LICENSE",
            0o644,
            "license",
            "LICENSE",
            None,
        ),
        (
            "tootles/man/tootles.1",
            "usr/share/man/man1/tootles.1",
            0o644,
            "manpage",
            "packaging/tootles.1",
            None,
        ),
    ],
}
EXPECTED_FORBIDDEN = [
    "usr/bin/ya",
    "usr/lib/yazi/plugins",
    "usr/libexec/glum-updater",
    "usr/libexec/tootles-updater",
    "usr/libexec/yazi-updater",
    "usr/share/applications/ya.desktop",
    "usr/share/yazi/flavors",
    "usr/share/yazi/plugins",
]


def _unique_json(raw, label):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate " + label + " key")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("unreadable " + label) from error
    if not isinstance(value, dict):
        raise ValueError(label + " must be an object")
    return value


def _regular(path, maximum):
    path = Path(path)
    if (
        path.is_symlink()
        or not path.is_file()
        or path.resolve() != path
        or not 0 < path.stat().st_size <= maximum
    ):
        raise ValueError("expected a bounded regular payload input")


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


def _expected_rows(name):
    rows = []
    for bundle, destination, mode, kind, source_file, release_file in EXPECTED_FILES[name]:
        row = {
            "bundle": bundle,
            "destination": destination,
            "mode": mode,
            "kind": kind,
        }
        if source_file is not None:
            row["source_file"] = source_file
        if release_file is not None:
            row["release_file"] = release_file
        rows.append(row)
    return rows


def load_payload_contract(
    path=CONTRACT,
    source_inputs_path=SOURCE_INPUTS,
    glum_release_inputs_path=GLUM_RELEASE_INPUTS,
):
    """Load the immutable destination allowlist and bind it to source inputs."""
    path = Path(path)
    source_inputs_path = Path(source_inputs_path)
    glum_release_inputs_path = Path(glum_release_inputs_path)
    _regular(path, 256 * 1024)
    _regular(source_inputs_path, 2 * 1024**2)
    contract = _unique_json(path.read_bytes(), "default-application payload contract")
    sources = load_inputs(source_inputs_path)
    glum_release = load_release_inputs(glum_release_inputs_path)
    required = {
        "schema",
        "status",
        "source_inputs_sha256",
        "glum_release_inputs_sha256",
        "selected_for_release",
        "security_qualified",
        "os_qualified",
        "applications",
        "forbidden_destinations",
        "scope",
    }
    if (
        set(contract) != required
        or contract["schema"] != 1
        or contract["status"] != "offline-payload-contract-only"
        or contract["source_inputs_sha256"] != digest(source_inputs_path)
        or contract["glum_release_inputs_sha256"] != digest(glum_release_inputs_path)
        or contract["selected_for_release"] is not False
        or contract["security_qualified"] is not False
        or contract["os_qualified"] is not False
        or set(contract["applications"]) != set(EXPECTED_IDENTITIES)
        or contract["forbidden_destinations"] != EXPECTED_FORBIDDEN
        or not isinstance(contract["scope"], str)
        or not contract["scope"]
    ):
        raise ValueError("unexpected default-application payload contract")
    destinations = set()
    bundles = set()
    for name, identity in EXPECTED_IDENTITIES.items():
        app = contract["applications"][name]
        source = sources["applications"][name]
        repository, version, revision = identity
        if (
            set(app) != {"repository", "version", "revision", "files"}
            or (app["repository"], app["version"], app["revision"]) != identity
            or (source["repository"], source["version"], source["revision"]) != identity
            or app["files"] != _expected_rows(name)
        ):
            raise ValueError("application payload identity or allowlist changed: " + name)
        for row in app["files"]:
            if (
                not _safe_relative(row["bundle"])
                or not _safe_relative(row["destination"])
                or row["bundle"] in bundles
                or row["destination"] in destinations
            ):
                raise ValueError("unsafe or duplicate application payload path")
            bundles.add(row["bundle"])
            destinations.add(row["destination"])
            source_file = row.get("source_file")
            release_file = row.get("release_file")
            if source_file is not None:
                if source_file not in source["source"]["required_files"]:
                    raise ValueError("payload asset is not bound to the exact source archive")
            if release_file is not None:
                release = glum_release["asset"]["files"].get(release_file)
                if name != "glum" or release is None or release["install"] is not True:
                    raise ValueError("payload asset is not bound to the exact Glum release")
    if destinations.intersection(EXPECTED_FORBIDDEN):
        raise ValueError("an installed path is also forbidden")
    return contract


def _require_attestation(value, artifact):
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "verified",
            "issuer",
            "repository",
            "workflow",
            "predicate_type",
            "subject_sha256",
            "bundle_sha256",
        }
        or value["verified"] is not True
        or value["issuer"] != "https://token.actions.githubusercontent.com"
        or value["repository"] != "ThirdKeyAI/symbi-os"
        or value["workflow"] != ".github/workflows/default-app-payload.yml"
        or value["predicate_type"] != "https://slsa.dev/provenance/v1"
        or value["subject_sha256"] != artifact["sha256"]
        or not exact_hash(value["bundle_sha256"])
        or value["bundle_sha256"] == "0" * 64
    ):
        raise ValueError("default-application payload lacks a bounded provenance claim")
    raise ValueError(
        "default-application staging is disabled until offline provenance "
        "signature and bundle verification is implemented"
    )


def _require_manifest(manifest, contract, sources, glum_release, expected_commit):
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "schema",
            "compiled",
            "os_qualified",
            "source_commit",
            "source_inputs_sha256",
            "glum_release_inputs_sha256",
            "plugins_included",
            "updaters_included",
            "applications",
        }
        or manifest["schema"] != 1
        or manifest["compiled"] is not True
        or manifest["os_qualified"] is not False
        or manifest["source_commit"] != expected_commit
        or not exact_hash(expected_commit, 40)
        or manifest["source_inputs_sha256"] != contract["source_inputs_sha256"]
        or manifest["glum_release_inputs_sha256"]
        != contract["glum_release_inputs_sha256"]
        or manifest["plugins_included"] is not False
        or manifest["updaters_included"] is not False
        or set(manifest["applications"]) != set(EXPECTED_IDENTITIES)
    ):
        raise ValueError("unexpected default-application payload manifest")
    total = 0
    for name in EXPECTED_IDENTITIES:
        app = manifest["applications"][name]
        source = sources["applications"][name]
        app_keys = {"version", "revision", "source_archive_sha256", "files"}
        if name == "glum":
            app_keys.add("release_asset_sha256")
        if (
            not isinstance(app, dict)
            or set(app) != app_keys
            or app["version"] != source["version"]
            or app["revision"] != source["revision"]
            or app["source_archive_sha256"] != source["source"]["sha256"]
            or (
                name == "glum"
                and app["release_asset_sha256"] != glum_release["asset"]["sha256"]
            )
            or not isinstance(app["files"], list)
            or len(app["files"]) != len(contract["applications"][name]["files"])
        ):
            raise ValueError("default-application build is not bound to its source: " + name)
        for actual, expected in zip(
            app["files"], contract["applications"][name]["files"], strict=True
        ):
            if (
                not isinstance(actual, dict)
                or set(actual) != set(expected) | {"bytes", "sha256"}
                or any(actual[key] != value for key, value in expected.items())
                or type(actual["bytes"]) is not int
                or not 0 < actual["bytes"] <= MAX_FILE
                or not exact_hash(actual["sha256"])
            ):
                raise ValueError("unexpected default-application payload file")
            total += actual["bytes"]
            source_file = actual.get("source_file")
            release_file = actual.get("release_file")
            if source_file is not None:
                pinned = source["source"]["required_files"][source_file]
                if (actual["bytes"], actual["sha256"]) != (
                    pinned["bytes"],
                    pinned["sha256"],
                ):
                    raise ValueError("source-backed application asset bytes changed")
            if release_file is not None:
                pinned = glum_release["asset"]["files"][release_file]
                if (actual["bytes"], actual["sha256"]) != (
                    pinned["bytes"],
                    pinned["sha256"],
                ):
                    raise ValueError("release-backed Glum asset bytes changed")
    if total > MAX_ARCHIVE:
        raise ValueError("expanded default-application payload exceeds its bound")
    return manifest


def _require_lock(
    lock,
    contract_path,
    source_inputs_path,
    glum_release_inputs_path,
    expected_commit,
):
    contract = load_payload_contract(
        contract_path, source_inputs_path, glum_release_inputs_path
    )
    sources = load_inputs(source_inputs_path)
    glum_release = load_release_inputs(glum_release_inputs_path)
    required = {
        "schema",
        "development_included",
        "selected_for_release",
        "security_qualified",
        "os_qualified",
        "native_tests_passed",
        "tested_commit",
        "run_id",
        "source_inputs_sha256",
        "glum_release_inputs_sha256",
        "contract_sha256",
        "manifest_sha256",
        "manifest",
        "artifact",
        "attestation",
        "scope",
    }
    artifact = lock.get("artifact") if isinstance(lock, dict) else None
    if (
        not isinstance(lock, dict)
        or set(lock) != required
        or lock["schema"] != 1
        or lock["development_included"] is not True
        or lock["selected_for_release"] is not False
        or lock["security_qualified"] is not False
        or lock["os_qualified"] is not False
        or lock["native_tests_passed"] is not False
        or lock["tested_commit"] != expected_commit
        or type(lock["run_id"]) is not int
        or lock["run_id"] <= 0
        or lock["source_inputs_sha256"] != digest(source_inputs_path)
        or lock["glum_release_inputs_sha256"] != digest(glum_release_inputs_path)
        or lock["contract_sha256"] != digest(contract_path)
        or not exact_hash(lock["manifest_sha256"])
        or not isinstance(artifact, dict)
        or set(artifact) != {"id", "name", "bytes", "sha256"}
        or type(artifact["id"]) is not int
        or artifact["id"] <= 0
        or artifact["name"] != "default-apps-development-payload.zip"
        or type(artifact["bytes"]) is not int
        or not 0 < artifact["bytes"] <= MAX_ARCHIVE
        or not exact_hash(artifact["sha256"])
        or not isinstance(lock["scope"], str)
        or not lock["scope"]
    ):
        raise ValueError("unexpected default-application payload lock")
    _require_manifest(
        lock["manifest"], contract, sources, glum_release, expected_commit
    )
    _require_attestation(lock["attestation"], artifact)
    return contract, sources, glum_release



def _check_payload_tree_files(payload, manifest, contract):
    """Check untrusted staged bytes without granting installation status."""
    payload = Path(payload)
    if payload.is_symlink() or not payload.is_dir() or payload.resolve() != payload:
        raise ValueError("invalid default-application payload tree")
    count = 0
    total = 0
    for name in EXPECTED_IDENTITIES:
        for row in manifest["applications"][name]["files"]:
            path = payload / row["destination"]
            try:
                descriptor = os.open(
                    path,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                )
            except OSError as error:
                raise ValueError("staged default-application file changed") from error
            try:
                before = os.fstat(descriptor)
                with os.fdopen(os.dup(descriptor), "rb") as stream:
                    actual_hash = hashlib.file_digest(stream, "sha256").hexdigest()
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != row["mode"]
                or before.st_size != row["bytes"]
                or actual_hash != row["sha256"]
                or (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_nlink,
                    before.st_size,
                    before.st_mtime_ns,
                )
                != (
                    after.st_dev,
                    after.st_ino,
                    after.st_mode,
                    after.st_nlink,
                    after.st_size,
                    after.st_mtime_ns,
                )
            ):
                raise ValueError("staged default-application file changed")
            count += 1
            total += row["bytes"]
    for relative in contract["forbidden_destinations"]:
        path = payload / relative
        if path.exists() or path.is_symlink():
            raise ValueError("a forbidden package, updater, plugin or theme path is present")
    return count, total


def unpack_payload(
    archive,
    lock,
    contract_path=CONTRACT,
    source_inputs_path=SOURCE_INPUTS,
    destination=None,
    expected_commit=None,
    glum_release_inputs_path=GLUM_RELEASE_INPUTS,
):
    """Refuse staging until provenance bytes have a real offline verifier.

    This function deliberately performs no archive extraction, destination
    creation, copying or cleanup.  A self-reported lock can never authorize a
    filesystem mutation.
    """
    del archive
    if destination is None or expected_commit is None:
        raise ValueError("payload destination and authenticated source commit are required")
    _require_lock(
        lock,
        Path(contract_path),
        Path(source_inputs_path),
        Path(glum_release_inputs_path),
        expected_commit,
    )
    raise AssertionError("unreachable without an implemented provenance verifier")


def verify_payload_tree(
    payload,
    lock,
    contract_path=CONTRACT,
    source_inputs_path=SOURCE_INPUTS,
    glum_release_inputs_path=GLUM_RELEASE_INPUTS,
    expected_commit=None,
):
    """Require an authenticated lock before checking any installed tree.

    The current provenance gate always refuses, so this function cannot return
    a passing report until real offline signature and bundle verification is
    implemented.
    """
    if expected_commit is None:
        raise ValueError("an authenticated source commit and payload lock are required")
    contract, _, _ = _require_lock(
        lock,
        Path(contract_path),
        Path(source_inputs_path),
        Path(glum_release_inputs_path),
        expected_commit,
    )
    count, total = _check_payload_tree_files(payload, lock["manifest"], contract)
    return {
        "schema": 1,
        "passed": True,
        "payload_files_verified": True,
        "development_included": True,
        "selected_for_release": False,
        "security_qualified": False,
        "os_qualified": False,
        "native_desktop_qualified": False,
        "real_accounts_qualified": False,
        "applications": list(EXPECTED_IDENTITIES),
        "files": count,
        "bytes": total,
        "source_inputs_sha256": contract["source_inputs_sha256"],
        "glum_release_inputs_sha256": contract["glum_release_inputs_sha256"],
        "scope": "Offline payload bytes only; provenance and native acceptance remain open",
    }
