"""Admit and stage an exact offline Yazi, Glum and Tootles payload.

This module has no downloader or build route.  A separate hosted build must
produce an attested archive and a retained lock before desktop preparation can
call :func:`unpack_payload`.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import zipfile

from image.default_apps.inputs import digest, exact_hash, load_inputs
from image.default_apps.glum_release import load_release_inputs
from image.desktop.files import copy_regular


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "image/default_apps/payload-contract.json"
SOURCE_INPUTS = ROOT / "image/default_apps/source-inputs.json"
GLUM_RELEASE_INPUTS = ROOT / "image/default_apps/glum-release-inputs.json"
MAX_ARCHIVE = 768 * 1024**2
MAX_FILE = 256 * 1024**2
MAX_MANIFEST = 1024**2
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
        raise ValueError("default-application payload lacks its exact build attestation")


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
    _require_attestation(lock["attestation"], artifact)
    _require_manifest(
        lock["manifest"], contract, sources, glum_release, expected_commit
    )
    return contract, sources, glum_release


def _validate_desktop(raw, name):
    if len(raw) > 64 * 1024 or b"\0" in raw:
        raise ValueError("unsafe application desktop entry")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("application desktop entry is not UTF-8") from error
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    if not lines or lines[0] != "[Desktop Entry]":
        raise ValueError("application desktop entry lacks its fixed group")
    exec_rows = [line.split("=", 1)[1] for line in lines if line.startswith("Exec=")]
    terminal_rows = [line.split("=", 1)[1].lower() for line in lines if line.startswith("Terminal=")]
    if (
        len(exec_rows) != 1
        or len(terminal_rows) != 1
        or terminal_rows[0] != "true"
        or not re.fullmatch(r"(?:/usr/bin/)?" + re.escape(name) + r"(?:\s+%[fFuU])?", exec_rows[0])
    ):
        raise ValueError("application desktop entry may only launch its terminal binary")
    lowered = text.lower()
    if any(value in lowered for value in ("http://", "https://", "curl ", "wget ", "updater", "plugin")):
        raise ValueError("application desktop entry exposes a download or extension route")


def _copy_zip_member(bundle, info, target, expected):
    target.parent.mkdir(parents=True, exist_ok=True)
    size = 0
    hasher = hashlib.sha256()
    with bundle.open(info) as source, target.open("xb") as output:
        while block := source.read(1024**2):
            size += len(block)
            if size > expected["bytes"]:
                raise ValueError("application payload member exceeded its exact size")
            hasher.update(block)
            output.write(block)
        output.flush()
        os.fsync(output.fileno())
        os.posix_fadvise(output.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
    if size != expected["bytes"] or hasher.hexdigest() != expected["sha256"]:
        raise ValueError("application payload member bytes changed")
    target.chmod(expected["mode"])


def _preflight_targets(payload, rows, forbidden):
    for relative in [*(row["destination"] for row in rows), *forbidden]:
        if not _safe_relative(relative):
            raise ValueError("unsafe application install destination")
        target = payload / relative
        current = payload
        for part in Path(relative).parts[:-1]:
            current /= part
            if current.is_symlink() or (current.exists() and not current.is_dir()):
                raise ValueError("linked or non-directory application payload parent")
        if target.exists() or target.is_symlink():
            raise ValueError("application payload would overwrite or retain a forbidden path")


def unpack_payload(
    archive,
    lock,
    contract_path=CONTRACT,
    source_inputs_path=SOURCE_INPUTS,
    destination=None,
    expected_commit=None,
    glum_release_inputs_path=GLUM_RELEASE_INPUTS,
):
    """Authenticate and copy only the fixed application payload allowlist."""
    archive = Path(archive)
    contract_path, source_inputs_path = Path(contract_path), Path(source_inputs_path)
    glum_release_inputs_path = Path(glum_release_inputs_path)
    destination = Path(destination) if destination is not None else None
    if destination is None or expected_commit is None:
        raise ValueError("payload destination and source commit are required")
    contract, _, _ = _require_lock(
        lock,
        contract_path,
        source_inputs_path,
        glum_release_inputs_path,
        expected_commit,
    )
    _regular(archive, MAX_ARCHIVE)
    if (
        archive.name != lock["artifact"]["name"]
        or archive.stat().st_size != lock["artifact"]["bytes"]
        or digest(archive) != lock["artifact"]["sha256"]
    ):
        raise ValueError("default-application payload archive changed")
    if (
        destination.is_symlink()
        or not destination.is_dir()
        or destination.resolve() != destination
        or not destination.parent.is_dir()
        or destination.parent.resolve() != destination.parent
    ):
        raise ValueError("use a regular existing application payload root")
    rows = [
        row
        for name in EXPECTED_IDENTITIES
        for row in lock["manifest"]["applications"][name]["files"]
    ]
    expected = {row["bundle"]: row for row in rows}
    stage = Path(tempfile.mkdtemp(prefix="symbi-default-apps-", dir=destination.parent))
    created = []
    created_directories = set()
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            names = [row.filename for row in entries]
            if len(names) != len(expected) + 1 or set(names) != {*expected, "manifest.json"}:
                raise ValueError("unexpected, missing or duplicate application payload member")
            for info in entries:
                mode = stat.S_IFMT(info.external_attr >> 16)
                maximum = MAX_MANIFEST if info.filename == "manifest.json" else expected[info.filename]["bytes"]
                if (
                    info.flag_bits & 1
                    or mode not in (0, stat.S_IFREG)
                    or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or not 0 < info.file_size <= maximum
                ):
                    raise ValueError("unsafe application payload archive member")
            raw_manifest = bundle.read("manifest.json")
            if (
                hashlib.sha256(raw_manifest).hexdigest() != lock["manifest_sha256"]
                or _unique_json(raw_manifest, "application payload manifest") != lock["manifest"]
            ):
                raise ValueError("application payload manifest differs from retained bytes")
            for member, row in expected.items():
                info = bundle.getinfo(member)
                if info.file_size != row["bytes"]:
                    raise ValueError("application payload member size changed")
                target = stage / member
                _copy_zip_member(bundle, info, target, row)
                if row["kind"] == "binary":
                    with target.open("rb") as stream:
                        if stream.read(4) != b"\x7fELF":
                            raise ValueError("application executable is not an ELF binary")
                if row["kind"] == "desktop":
                    _validate_desktop(target.read_bytes(), member.split("/", 1)[0])
        _preflight_targets(destination, rows, contract["forbidden_destinations"])
        for row in rows:
            target = destination / row["destination"]
            missing = []
            current = destination
            for part in Path(row["destination"]).parts[:-1]:
                current /= part
                if not current.exists():
                    missing.append(current)
            created.append(target)
            created_directories.update(missing)
            copy_regular(stage / row["bundle"], target, row["mode"] == 0o755)
        verify_payload_tree(
            destination,
            lock["manifest"],
            contract_path,
            source_inputs_path,
            glum_release_inputs_path,
        )
        return lock["manifest"]
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        for path in sorted(created_directories, key=lambda item: len(item.parts), reverse=True):
            try:
                path.rmdir()
            except (FileNotFoundError, OSError):
                pass
        raise
    finally:
        shutil.rmtree(stage)
        if stage.exists():
            raise RuntimeError("temporary application payload staging was not removed")


def verify_payload_tree(
    payload,
    manifest,
    contract_path=CONTRACT,
    source_inputs_path=SOURCE_INPUTS,
    glum_release_inputs_path=GLUM_RELEASE_INPUTS,
):
    """Verify exact staged bytes while preserving all native-test blockers."""
    payload = Path(payload)
    contract = load_payload_contract(
        contract_path, source_inputs_path, glum_release_inputs_path
    )
    sources = load_inputs(source_inputs_path)
    glum_release = load_release_inputs(glum_release_inputs_path)
    if payload.is_symlink() or not payload.is_dir() or payload.resolve() != payload:
        raise ValueError("invalid default-application payload tree")
    commit = manifest.get("source_commit") if isinstance(manifest, dict) else None
    _require_manifest(manifest, contract, sources, glum_release, commit)
    count = 0
    total = 0
    for name in EXPECTED_IDENTITIES:
        for row in manifest["applications"][name]["files"]:
            path = payload / row["destination"]
            if (
                path.is_symlink()
                or not path.is_file()
                or path.resolve() != path
                or path.stat().st_size != row["bytes"]
                or digest(path) != row["sha256"]
                or path.stat().st_mode & 0o777 != row["mode"]
            ):
                raise ValueError("staged default-application file changed")
            count += 1
            total += row["bytes"]
    for relative in contract["forbidden_destinations"]:
        path = payload / relative
        if path.exists() or path.is_symlink():
            raise ValueError("a forbidden package, updater, plugin or theme path is present")
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
        "scope": "Offline payload bytes only; native launch, UI, file-operation, egress, secret-storage and real-account acceptance remain open",
    }
