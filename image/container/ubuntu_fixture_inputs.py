"""Select and materialize one exact offline fixture package candidate.

The committed schema-2 slot is deliberately pending.  A later reviewed change
must bind one successful producer run, both artifact API identities, both ZIP
files, the candidate manifest, the producer result and every retained package
row.  No value accepted here is a qualification or release claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import sys
import tomllib
import zipfile
import zlib

from image.container import ubuntu_fixture_packages as packages


LOCK_NAME = "ubuntu-fixture-packages.lock.json"
WORKFLOW_PATH = ".github/workflows/ubuntu-fixture-packages.yml"
WORKFLOW_EVENT = "workflow_dispatch"
EVIDENCE_ARTIFACT_NAME = "container-ubuntu-fixture-package-evidence"
PENDING_SCOPE = (
    "Pending offline fixture package selection; no artifact, verification, "
    "build, container, OS or release claim"
)
SELECTED_SCOPE = (
    "Selected offline fixture package bytes; all verification, build, "
    "container, OS and release claims remain false"
)
FALSE_CLAIM_FIELDS = (
    "verified", "qualified", "container_qualified", "signature_qualified",
    "os_qualified", "release_qualified",
)
LOCK_FIELDS = {
    "schema", "state", "selected", *FALSE_CLAIM_FIELDS, "repository",
    "workflow", "run", "artifacts", "rootfs", "package_request", "sources",
    "fixture_source", "candidate", "evidence", "scope",
}
WORKFLOW_FIELDS = {"id", "path", "event"}
RUN_FIELDS = {
    "id", "attempt", "head_sha", "head_branch", "status", "conclusion",
    "repository", "head_repository",
}
ARTIFACT_SET_FIELDS = {"candidate", "evidence"}
ARTIFACT_BINDING_FIELDS = {"api", "zip"}
ARTIFACT_API_FIELDS = {
    "id", "name", "size_in_bytes", "digest", "expired", "workflow_run",
}
ARTIFACT_RUN_FIELDS = {
    "id", "head_sha", "repository_id", "head_repository_id",
}
ZIP_FIELDS = {"bytes", "sha256"}
CANDIDATE_FIELDS = {
    "manifest", "producer_contract_sha256", "release_metadata",
    "package_indexes", "package_count", "package_bytes", "packages",
}
IDENTITY_FIELDS = {"path", "bytes", "sha256"}
EVIDENCE_FIELDS = {"producer_result", "members"}
FIXTURE_SOURCE_FIELDS = {
    "runtime_source_revision", "fixture_revision", "fixture_tree", "drivers",
}
NATIVE_FIXTURE_FIELDS = {
    "schema", "repository", "revision", "tree", "runtime_source_revision",
    "pull_request", "reviewed_head", "drivers", "qualified", "scope",
}
NATIVE_FIXTURE_REPOSITORY = "https://github.com/ThirdKeyAI/Symbiont"
NATIVE_FIXTURE_PULL_REQUEST = 25
NATIVE_FIXTURE_REVIEWED_HEAD = "b98b3f172f2875ccc5dadd6d3e86a4b6abc0c992"
NATIVE_FIXTURE_SCOPE = (
    "PR 24 reviewed fixture drivers plus PR 25 serialized lifecycle CI; "
    "installed runtime and Fedora qualification remain separate bindings"
)
EXPECTED_FIXTURE_SOURCE = {
    "runtime_source_revision": "deddb9e997244d2289c217ad76b8fde0e9b0339b",
    "fixture_revision": "cd4b34282ade880c8ac3d5136d31ff80cde92794",
    "fixture_tree": "2b2379d0de4eaaf4a57cf52c96355015bb3dc25d",
    "drivers": {
        "test-filesystem-grants.py": (
            "c5dc5d798c285f99e8db72b64d55749f127aa4139645425b7bd69d48dd7e9ded"
        ),
        "test-source-broker.py": (
            "ae2b6490cca43924e0f14aa84e71943c4684f298103db72b62eef534a16d1d2e"
        ),
        "test-git-source.py": (
            "82a02079c1a13799d03295e33ea4bc6f6120af7b8c4d25a840dcf023b4e0a075"
        ),
    },
}
MAX_SELECTION_BYTES = 4 * 1024**2
MAX_MANIFEST_BYTES = packages.MAX_METADATA_BYTES
MAX_EVIDENCE_EXPANDED_BYTES = 512 * 1024**2
MAX_EVIDENCE_MEMBERS = 4096
MAX_ZIP_MEMBERS = max(
    MAX_EVIDENCE_MEMBERS,
    packages.MAX_PACKAGE_COUNT + 1 + 2 * len(packages.EXPECTED_SOURCES))
MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 8 * 1024**2
MAX_ZIP_END_RECORD_BYTES = 4096
MAX_EVIDENCE_ARTIFACT_BYTES = (
    MAX_EVIDENCE_EXPANDED_BYTES + 2 * MAX_ZIP_CENTRAL_DIRECTORY_BYTES)
COPY_CHUNK_BYTES = 64 * 1024
TRANSFER_FREE_RESERVE = 1024**3
MATERIALIZATION_FREE_RESERVE = 5 * 1024**3
INSTALL_PRE_DEPENDENCIES = (
    ("python3-minimal", "python3.12-minimal"),
    ("python3", "python3-minimal"),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _exact_record(actual, expected):
    """Compare contract data without Python's bool/int equality aliases."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return (set(actual) == set(expected)
                and all(_exact_record(actual[key], value)
                        for key, value in expected.items()))
    if isinstance(expected, list):
        return (len(actual) == len(expected)
                and all(_exact_record(left, right)
                        for left, right in zip(actual, expected, strict=True)))
    return actual == expected


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _canonical_sha256(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _safe_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (not path.is_absolute() and str(path) == value
            and all(part not in ("", ".", "..") for part in path.parts))


def _identity(value, *, pending=False, expected_path=None, maximum=None,
              allow_empty=False):
    require(isinstance(value, dict) and set(value) == IDENTITY_FIELDS
            and (expected_path is None or value.get("path") == expected_path),
            "offline fixture identity fields changed")
    if pending:
        require(value["bytes"] is None and value["sha256"] is None,
                "pending offline fixture identity contains invented bytes")
    else:
        require(_safe_path(value["path"])
                and type(value["bytes"]) is int
                and (value["bytes"] >= 0 if allow_empty else value["bytes"] > 0)
                and (maximum is None or value["bytes"] <= maximum)
                and packages.exact_hash(value["sha256"]),
                "offline fixture identity is malformed or oversized")
    return value


def _validate_native_fixture_pin(source, fixture):
    require(isinstance(fixture, dict) and set(fixture) == NATIVE_FIXTURE_FIELDS
            and type(fixture.get("schema")) is int and fixture["schema"] == 1
            and fixture.get("repository") == NATIVE_FIXTURE_REPOSITORY
            and fixture.get("revision") == source["fixture_revision"]
            and fixture.get("tree") == source["fixture_tree"]
            and fixture.get("runtime_source_revision")
            == source["runtime_source_revision"]
            and type(fixture.get("pull_request")) is int
            and fixture["pull_request"] == NATIVE_FIXTURE_PULL_REQUEST
            and fixture.get("reviewed_head") == NATIVE_FIXTURE_REVIEWED_HEAD
            and packages.exact_hash(fixture["reviewed_head"], 40)
            and _exact_record(fixture.get("drivers"), source["drivers"])
            and fixture.get("qualified") is False
            and fixture.get("scope") == NATIVE_FIXTURE_SCOPE,
            "reviewed native fixture source pin changed or made a claim")
    return fixture


def _validate_fixture_source(root, source):
    require(isinstance(source, dict) and set(source) == FIXTURE_SOURCE_FIELDS
            and _exact_record(source, EXPECTED_FIXTURE_SOURCE),
            "offline fixture runtime or reviewed driver source changed")
    runtime_raw = packages.read_bounded_control_file(
        root, "upstream/symbiont.toml", "runtime pin")
    runtime = tomllib.loads(runtime_raw.decode("utf-8"))
    fixture = packages.unique_json(
        root, "image/container/native-fixture.lock.json")
    _validate_native_fixture_pin(source, fixture)
    require(runtime.get("revision") == source["runtime_source_revision"]
            and source["runtime_source_revision"] != source["fixture_revision"],
            "offline fixture source does not match the reviewed repository pins")
    return source


def producer_contract(lock):
    """Recreate the exact schema-1 empty contract used by the producer."""
    return {
        "schema": 1,
        "status": "pending",
        "selected": False,
        "qualified": False,
        "container_qualified": False,
        "signature_qualified": False,
        "os_qualified": False,
        "release_qualified": False,
        "rootfs": lock.get("rootfs"),
        "package_request": lock.get("package_request"),
        "sources": lock.get("sources"),
        "fixture_source": lock.get("fixture_source"),
        "producer": {
            "workflow": None, "run_id": None, "run_attempt": None,
            "head_sha": None,
        },
        "artifact": {
            "id": None, "name": packages.ARTIFACT_NAME,
            "bytes": None, "sha256": None,
        },
        "release_metadata": [],
        "package_indexes": [],
        "package_count": 0,
        "package_bytes": 0,
        "packages": [],
        "scope": (
            "Pending signed Ubuntu fixture package closure; no metadata payload, "
            "artifact, build, container, OS or release qualification"
        ),
    }


def _validate_common(root, lock):
    require(isinstance(lock, dict) and set(lock) == LOCK_FIELDS
            and type(lock.get("schema")) is int and lock["schema"] == 2
            and _exact_record(lock.get("repository"), packages.REPOSITORY)
            and all(lock.get(field) is False for field in FALSE_CLAIM_FIELDS),
            "offline fixture selection fields or claims changed")
    packages.validate_rootfs(lock.get("rootfs"))
    packages.validate_request(lock.get("package_request"))
    packages.validate_sources(lock.get("sources"))
    _validate_fixture_source(root, lock.get("fixture_source"))
    require(isinstance(lock.get("workflow"), dict)
            and set(lock["workflow"]) == WORKFLOW_FIELDS
            and lock["workflow"].get("path") == WORKFLOW_PATH
            and lock["workflow"].get("event") == WORKFLOW_EVENT
            and isinstance(lock.get("run"), dict)
            and set(lock["run"]) == RUN_FIELDS
            and isinstance(lock.get("artifacts"), dict)
            and set(lock["artifacts"]) == ARTIFACT_SET_FIELDS
            and isinstance(lock.get("candidate"), dict)
            and set(lock["candidate"]) == CANDIDATE_FIELDS
            and isinstance(lock.get("evidence"), dict)
            and set(lock["evidence"]) == EVIDENCE_FIELDS,
            "offline fixture selection nested fields changed")
    return lock


def _pending_artifact(value, name):
    require(isinstance(value, dict) and set(value) == ARTIFACT_BINDING_FIELDS
            and _exact_record(value.get("api"), {
                "id": None, "name": name, "size_in_bytes": None,
                "digest": None, "expired": None, "workflow_run": None,
            })
            and _exact_record(
                value.get("zip"), {"bytes": None, "sha256": None}),
            "pending artifact binding contains invented values")


def validate_pending_lock(root, lock):
    root = Path(root).resolve()
    _validate_common(root, lock)
    require(lock.get("state") == "pending" and lock.get("selected") is False
            and lock["workflow"]["id"] is None
            and _exact_record(lock["run"], {
                "id": None, "attempt": None, "head_sha": None,
                "head_branch": None, "status": "pending", "conclusion": None,
                "repository": packages.REPOSITORY,
                "head_repository": packages.REPOSITORY,
            }), "pending offline fixture lock contains a run selection")
    _pending_artifact(lock["artifacts"]["candidate"], packages.ARTIFACT_NAME)
    _pending_artifact(lock["artifacts"]["evidence"], EVIDENCE_ARTIFACT_NAME)
    candidate = lock["candidate"]
    evidence = lock["evidence"]
    _identity(candidate.get("manifest"), pending=True, expected_path="manifest.json")
    _identity(evidence.get("producer_result"), pending=True,
              expected_path="producer-result.json")
    require(candidate.get("producer_contract_sha256") is None
            and candidate.get("release_metadata") == []
            and candidate.get("package_indexes") == []
            and candidate.get("packages") == []
            and type(candidate.get("package_count")) is int
            and candidate["package_count"] == 0
            and type(candidate.get("package_bytes")) is int
            and candidate["package_bytes"] == 0
            and evidence.get("members") == []
            and lock.get("scope") == PENDING_SCOPE,
            "pending offline fixture lock contains unaudited producer output")
    return {"ready": False, "status": "pending",
            "blocker": "offline-ubuntu-package-selection"}


def _selected_artifact(value, name, run, maximum):
    require(isinstance(value, dict) and set(value) == ARTIFACT_BINDING_FIELDS
            and isinstance(value.get("api"), dict)
            and set(value["api"]) == ARTIFACT_API_FIELDS
            and isinstance(value.get("zip"), dict)
            and set(value["zip"]) == ZIP_FIELDS,
            "selected artifact binding fields changed")
    api = value["api"]
    workflow_run = api.get("workflow_run")
    archive = value["zip"]
    require(type(api.get("id")) is int and api["id"] > 0
            and api.get("name") == name
            and type(api.get("size_in_bytes")) is int
            and 0 < api["size_in_bytes"] <= maximum
            and isinstance(api.get("digest"), str)
            and api["digest"].startswith("sha256:")
            and packages.exact_hash(api["digest"][7:])
            and api.get("expired") is False
            and isinstance(workflow_run, dict)
            and set(workflow_run) == ARTIFACT_RUN_FIELDS
            and _exact_record(workflow_run, {
                "id": run["id"], "head_sha": run["head_sha"],
                "repository_id": packages.REPOSITORY["id"],
                "head_repository_id": packages.REPOSITORY["id"],
            })
            and type(archive.get("bytes")) is int
            and archive["bytes"] == api["size_in_bytes"]
            and packages.exact_hash(archive.get("sha256"))
            and archive["sha256"] == api["digest"][7:],
            "selected artifact API and ZIP identities differ")
    return value


def _validate_selected_candidate_rows(lock):
    from image.container import ubuntu_fixture_package_build as build

    candidate = lock["candidate"]
    releases = candidate["release_metadata"]
    indexes = candidate["package_indexes"]
    base_releases = []
    for source, row in zip(lock["sources"], releases, strict=True):
        signed = row.get("signed") if isinstance(row, dict) else None
        verification = row.get("verification") if isinstance(row, dict) else None
        require(isinstance(row, dict)
                and set(row) == build.CANDIDATE_RELEASE_FIELDS
                and isinstance(signed, dict)
                and set(signed) == build.SIGNED_RELEASE_FIELDS
                and isinstance(verification, dict)
                and set(verification) == build.SIGNATURE_RECORD_FIELDS
                and verification.get("signing_fingerprint")
                == source["metadata"]["signer_fingerprint"]
                and packages.exact_hash(verification.get("status_sha256")),
                "selected candidate Release evidence rows changed")
        base_releases.append({key: row[key] for key in packages.RELEASE_FIELDS})
    packages._validate_retained_package_shape(
        candidate["packages"], base_releases, indexes, lock["sources"],
        candidate["package_count"], candidate["package_bytes"])
    require(candidate["producer_contract_sha256"]
            == _canonical_sha256(producer_contract(lock)),
            "selected candidate producer contract identity changed")


def validate_selected_lock(root, lock):
    root = Path(root).resolve()
    _validate_common(root, lock)
    run = lock["run"]
    require(lock.get("state") == "selected" and lock.get("selected") is True
            and type(lock["workflow"].get("id")) is int
            and lock["workflow"]["id"] > 0
            and type(run.get("id")) is int and run["id"] > 0
            and type(run.get("attempt")) is int and run["attempt"] > 0
            and packages.exact_hash(run.get("head_sha"), 40)
            and isinstance(run.get("head_branch"), str) and run["head_branch"]
            and not any(character.isspace() for character in run["head_branch"])
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and _exact_record(run.get("repository"), packages.REPOSITORY)
            and _exact_record(
                run.get("head_repository"), packages.REPOSITORY),
            "selected producer run is not one exact repository success")
    _selected_artifact(
        lock["artifacts"]["candidate"], packages.ARTIFACT_NAME, run,
        packages.MAX_ARTIFACT_BYTES)
    _selected_artifact(
        lock["artifacts"]["evidence"], EVIDENCE_ARTIFACT_NAME, run,
        MAX_EVIDENCE_ARTIFACT_BYTES)
    require(lock["artifacts"]["candidate"]["api"]["id"]
            != lock["artifacts"]["evidence"]["api"]["id"],
            "selected candidate and evidence artifact identities overlap")
    candidate = lock["candidate"]
    _identity(candidate.get("manifest"), expected_path="manifest.json",
              maximum=MAX_MANIFEST_BYTES)
    require(packages.exact_hash(candidate.get("producer_contract_sha256"))
            and isinstance(candidate.get("release_metadata"), list)
            and len(candidate["release_metadata"]) == len(lock["sources"])
            and isinstance(candidate.get("package_indexes"), list)
            and len(candidate["package_indexes"]) == len(lock["sources"])
            and isinstance(candidate.get("packages"), list)
            and type(candidate.get("package_count")) is int
            and 0 < candidate["package_count"] <= packages.MAX_PACKAGE_COUNT
            and len(candidate["packages"]) == candidate["package_count"]
            and type(candidate.get("package_bytes")) is int
            and 0 < candidate["package_bytes"] <= packages.MAX_CLOSURE_BYTES
            and sum(row.get("bytes", 0) for row in candidate["packages"]
                    if isinstance(row, dict)) == candidate["package_bytes"],
            "selected candidate rows or totals are incomplete")
    _validate_selected_candidate_rows(lock)
    evidence = lock["evidence"]
    result = _identity(
        evidence.get("producer_result"), expected_path="producer-result.json",
        maximum=packages.MAX_METADATA_BYTES)
    members = evidence.get("members")
    require(isinstance(members, list) and 0 < len(members) <= MAX_EVIDENCE_MEMBERS,
            "selected producer evidence inventory is empty or excessive")
    paths = []
    for row in members:
        _identity(row, maximum=packages.MAX_ARTIFACT_BYTES, allow_empty=True)
        paths.append(row["path"])
    require(paths == sorted(paths) and len(paths) == len(set(paths))
            and any(row == result for row in members)
            and sum(row["bytes"] for row in members)
            <= MAX_EVIDENCE_EXPANDED_BYTES
            and lock.get("scope") == SELECTED_SCOPE,
            "selected producer evidence inventory is not exact and canonical")
    return {"ready": True, "status": "selected", "blocker": None}


def validate_lock(root, lock):
    if isinstance(lock, dict) and lock.get("state") == "pending":
        return validate_pending_lock(root, lock)
    return validate_selected_lock(root, lock)


def load_lock(root):
    root = Path(root).resolve()
    lock = packages.unique_json(
        root, "image/container/" + LOCK_NAME, MAX_SELECTION_BYTES)
    validate_lock(root, lock)
    return lock


def load_pending_lock(root):
    lock = load_lock(root)
    validate_pending_lock(root, lock)
    return lock


def _normalized_run(metadata):
    repository = metadata.get("repository") if isinstance(metadata, dict) else None
    head_repository = (
        metadata.get("head_repository") if isinstance(metadata, dict) else None)
    return {
        "id": metadata.get("id") if isinstance(metadata, dict) else None,
        "attempt": metadata.get("run_attempt") if isinstance(metadata, dict) else None,
        "head_sha": metadata.get("head_sha") if isinstance(metadata, dict) else None,
        "head_branch": metadata.get("head_branch") if isinstance(metadata, dict) else None,
        "status": metadata.get("status") if isinstance(metadata, dict) else None,
        "conclusion": metadata.get("conclusion") if isinstance(metadata, dict) else None,
        "repository": ({"id": repository.get("id"),
                         "full_name": repository.get("full_name")}
                        if isinstance(repository, dict) else None),
        "head_repository": ({"id": head_repository.get("id"),
                              "full_name": head_repository.get("full_name")}
                             if isinstance(head_repository, dict) else None),
    }


def validate_run_metadata(metadata, lock):
    return validate_run_metadata_unchecked(metadata, lock)


def _normalize_artifact(metadata):
    workflow = metadata.get("workflow_run") if isinstance(metadata, dict) else None
    return {
        "id": metadata.get("id") if isinstance(metadata, dict) else None,
        "name": metadata.get("name") if isinstance(metadata, dict) else None,
        "size_in_bytes": metadata.get("size_in_bytes") if isinstance(metadata, dict) else None,
        "digest": metadata.get("digest") if isinstance(metadata, dict) else None,
        "expired": metadata.get("expired") if isinstance(metadata, dict) else None,
        "workflow_run": ({
            "id": workflow.get("id"), "head_sha": workflow.get("head_sha"),
            "repository_id": workflow.get("repository_id"),
            "head_repository_id": workflow.get("head_repository_id"),
        } if isinstance(workflow, dict) else None),
    }


def validate_artifact_metadata(metadata, lock, kind):
    require(kind in ARTIFACT_SET_FIELDS
            and _exact_record(
                _normalize_artifact(metadata),
                lock["artifacts"][kind]["api"]),
            kind + " artifact API record differs from the selected record")
    return metadata


def _regular_archive(path, binding, maximum, description):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not path.is_symlink() and path.resolve() == path
            and 0 < info.st_size <= maximum
            and info.st_size == binding["bytes"]
            and sha256(path) == binding["sha256"],
            description + " ZIP differs from the selected bytes")
    return path


def _preflight_zip_directory(stream, expected_entries, description):
    """Bound the ZIP directory before zipfile materializes every ZipInfo."""
    require(type(expected_entries) is int
            and 0 < expected_entries <= MAX_ZIP_MEMBERS,
            description + " ZIP expected member count is invalid")
    size = os.fstat(stream.fileno()).st_size
    maximum_tail = 22 + 65535
    require(size >= 22, description + " ZIP end record is absent")
    tail_size = min(size, maximum_tail)
    stream.seek(size - tail_size)
    tail = stream.read(tail_size)
    require(len(tail) == tail_size,
            description + " ZIP end record could not be read")

    signature = b"PK\x05\x06"
    # CPython zipfile selects the last signature in this tail.  Select the
    # same record and reject it if malformed; never skip backward to a record
    # that zipfile itself would not use.
    position = tail.rfind(signature)
    require(position >= 0 and position + 22 <= len(tail),
            description + " ZIP end record is invalid")
    fields = struct.unpack_from("<4s4H2LH", tail, position)
    require(position + 22 + fields[-1] == len(tail),
            description + " ZIP end record is invalid")
    (_, disk, directory_disk, disk_entries, entries,
     directory_bytes, directory_offset, _) = fields
    end_offset = size - tail_size + position
    require(disk == 0 and directory_disk == 0,
            description + " ZIP spans multiple disks")

    directory_end = end_offset
    legacy_requires_zip64 = (
        entries == 0xffff or disk_entries == 0xffff
        or directory_bytes == 0xffffffff
        or directory_offset == 0xffffffff)
    locator_offset = end_offset - 20
    locator = b""
    if locator_offset >= 0:
        stream.seek(locator_offset)
        locator = stream.read(20)
    has_zip64_locator = (
        len(locator) == 20 and locator[:4] == b"PK\x06\x07")
    require(not legacy_requires_zip64 or has_zip64_locator,
            description + " ZIP64 locator is absent")
    if has_zip64_locator:
        require(len(locator) == 20,
                description + " ZIP64 locator is truncated")
        locator_signature, locator_disk, zip64_offset, total_disks = (
            struct.unpack("<4sLQL", locator))
        require(locator_signature == b"PK\x06\x07"
                and locator_disk == 0 and total_disks == 1
                and zip64_offset < locator_offset,
                description + " ZIP64 locator is invalid")
        stream.seek(zip64_offset)
        zip64_header = stream.read(56)
        require(len(zip64_header) == 56,
                description + " ZIP64 end record is truncated")
        zip64 = struct.unpack("<4sQ2H2L4Q", zip64_header)
        (zip64_signature, record_bytes, _, _, zip64_disk,
         zip64_directory_disk, zip64_disk_entries, zip64_entries,
         zip64_directory_bytes, zip64_directory_offset) = zip64
        require(zip64_signature == b"PK\x06\x06"
                and 44 <= record_bytes <= MAX_ZIP_END_RECORD_BYTES - 12
                and zip64_offset + 12 + record_bytes == locator_offset
                and zip64_disk == 0 and zip64_directory_disk == 0
                and zip64_disk_entries == zip64_entries,
                description + " ZIP64 end record is invalid")
        entries = zip64_entries
        disk_entries = zip64_disk_entries
        directory_bytes = zip64_directory_bytes
        directory_offset = zip64_directory_offset
        directory_end = zip64_offset

    require(entries == disk_entries == expected_entries,
            description + " ZIP directory member count changed")
    require(46 * entries <= directory_bytes
            <= MAX_ZIP_CENTRAL_DIRECTORY_BYTES,
            description + " ZIP central directory is oversized")
    require(directory_offset + directory_bytes == directory_end,
            description + " ZIP central directory bounds are invalid")
    stream.seek(directory_offset)
    # Parse the entire selected directory as a bounded stream.  The EOCD count
    # alone is not authoritative: zipfile reads records until directory_bytes
    # is exhausted, so a forged smaller count must not hide extra records from
    # this pre-materialization bound.
    consumed = 0
    records = 0
    header_format = "<4s6H3L5H2L"
    header_bytes = struct.calcsize(header_format)
    while consumed < directory_bytes:
        remaining = directory_bytes - consumed
        require(remaining >= header_bytes,
                description + " ZIP central directory record is truncated")
        header = stream.read(header_bytes)
        require(len(header) == header_bytes,
                description + " ZIP central directory record is truncated")
        fields = struct.unpack(header_format, header)
        require(fields[0] == b"PK\x01\x02",
                description + " ZIP central directory signature is invalid")
        name_bytes, extra_bytes, comment_bytes = fields[10:13]
        variable_bytes = name_bytes + extra_bytes + comment_bytes
        require(name_bytes > 0
                and header_bytes + variable_bytes <= remaining,
                description + " ZIP central directory record is invalid")
        unread = variable_bytes
        while unread:
            block = stream.read(min(COPY_CHUNK_BYTES, unread))
            require(block,
                    description + " ZIP central directory record is truncated")
            unread -= len(block)
        consumed += header_bytes + variable_bytes
        records += 1
        require(records <= expected_entries,
                description + " ZIP central directory has hidden records")
    require(consumed == directory_bytes and records == expected_entries,
            description + " ZIP central directory record count changed")
    stream.seek(0)


def _zip_members(bundle, expected, maximum_total, description, *,
                 allow_empty=False):
    rows = bundle.infolist()
    require(0 < len(rows) == len(expected)
            and len(rows) == len({row.filename for row in rows})
            and {row.filename for row in rows} == set(expected),
            description + " ZIP has unexpected, duplicate or missing members")
    total = 0
    result = {}
    for row in rows:
        path = PurePosixPath(row.filename)
        file_type = stat.S_IFMT(row.external_attr >> 16)
        binding = expected[row.filename]
        require(_safe_path(row.filename) and not row.is_dir()
                and path.parts[0] not in ("", ".", "..")
                and not row.flag_bits & 1
                and file_type in (0, stat.S_IFREG)
                and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and type(row.file_size) is int and row.file_size == binding["bytes"]
                and (row.file_size >= 0 if allow_empty else row.file_size > 0)
                and row.compress_size >= 0,
                description + " ZIP contains an unsafe, special or oversized member")
        total += row.file_size
        require(total <= maximum_total,
                description + " ZIP expanded bytes exceed the selected bound")
        result[row.filename] = row
    return result


def _read_member(bundle, row, binding, output=None):
    digest = hashlib.sha256()
    crc = 0
    count = 0
    with bundle.open(row) as source:
        while block := source.read(COPY_CHUNK_BYTES):
            count += len(block)
            require(count <= binding["bytes"], "ZIP member exceeded its selected size")
            digest.update(block)
            crc = zlib.crc32(block, crc)
            if output is not None:
                written = output.write(block)
                require(written == len(block), "offline package extraction was truncated")
    require(count == binding["bytes"] == row.file_size
            and digest.hexdigest() == binding["sha256"]
            and (crc & 0xffffffff) == row.CRC,
            "ZIP member failed size, SHA-256 or CRC validation")
    return digest.hexdigest()


def _candidate_bindings(lock):
    expected = {"manifest.json": lock["candidate"]["manifest"]}
    for release, index in zip(
            lock["candidate"]["release_metadata"],
            lock["candidate"]["package_indexes"], strict=True):
        for row in (release["inrelease"], index):
            name = "metadata/" + row["filename"]
            require(name not in expected, "candidate metadata paths collide")
            expected[name] = {"path": name, "bytes": row["bytes"],
                              "sha256": row["sha256"]}
    for row in lock["candidate"]["packages"]:
        name = "packages/" + PurePosixPath(row["filename"]).name
        require(name not in expected, "candidate package basenames collide")
        expected[name] = {"path": name, "bytes": row["bytes"],
                          "sha256": row["sha256"]}
    return expected


def validate_producer_result(lock, raw):
    """Keep the selected producer result unselected and non-authoritative."""
    binding = lock["evidence"]["producer_result"]
    require(len(raw) == binding["bytes"]
            and hashlib.sha256(raw).hexdigest() == binding["sha256"],
            "producer result differs from its selected identity")
    result = packages.unique_json_bytes(raw, packages.MAX_METADATA_BYTES)
    from image.container import ubuntu_fixture_package_hosted as hosted
    run = result.get("run") if isinstance(result, dict) else None
    candidate = result.get("candidate") if isinstance(result, dict) else None
    require(type(result) is dict and set(result) == hosted.RESULT_FIELDS
            and type(result.get("schema")) is int and result["schema"] == 1
            and result.get("mode") == "produce"
            and result.get("state") == "candidate-unselected"
            and result.get("passed") is True
            and result.get("authoritative") is False
            and all(result.get(field) is False for field in (
                "selected", "qualified", "container_qualified",
                "signature_qualified", "os_qualified", "release_qualified"))
            and _exact_record(result.get("repository"), packages.REPOSITORY)
            and type(run) is dict and set(run) == hosted.RUN_FIELDS
            and _exact_record(run.get("id"), lock["run"]["id"])
            and _exact_record(run.get("attempt"), lock["run"]["attempt"])
            and run.get("head_sha") == lock["run"]["head_sha"]
            and packages.exact_hash(run.get("head_tree"), 40)
            and run.get("workflow") == lock["workflow"]["path"]
            and run.get("event") == lock["workflow"]["event"]
            and type(candidate) is dict
            and set(candidate) == hosted.RESULT_CANDIDATE_FIELDS
            and candidate.get("created") is True
            and candidate.get("state") == "candidate-unselected"
            and candidate.get("manifest_sha256")
            == lock["candidate"]["manifest"]["sha256"]
            and result.get("scope") == hosted.RESULT_SCOPE,
            "selected producer result identity, state or false claims changed")
    return result


def validate_candidate_manifest(lock, raw):
    binding = lock["candidate"]["manifest"]
    require(len(raw) == binding["bytes"]
            and hashlib.sha256(raw).hexdigest() == binding["sha256"],
            "candidate manifest differs from its selected identity")
    manifest = packages.unique_json_bytes(raw, MAX_MANIFEST_BYTES)
    from image.container import ubuntu_fixture_package_build as build
    contract = producer_contract(lock)
    build.validate_candidate_manifest(contract, manifest)
    candidate = lock["candidate"]
    require(manifest["contract_sha256"] == _canonical_sha256(contract)
            == candidate["producer_contract_sha256"]
            and _exact_record(
                manifest["release_metadata"], candidate["release_metadata"])
            and _exact_record(
                manifest["package_indexes"], candidate["package_indexes"])
            and _exact_record(
                manifest["package_count"], candidate["package_count"])
            and _exact_record(
                manifest["package_bytes"], candidate["package_bytes"])
            and _exact_record(manifest["packages"], candidate["packages"])
            and manifest.get("selected") is False
            and manifest.get("signature_qualified") is False
            and manifest.get("container_qualified") is False
            and manifest.get("os_qualified") is False
            and manifest.get("release_qualified") is False
            and manifest.get("qualified") is False
            and all(value is False for value in manifest["verification"].values()),
            "candidate manifest differs from the selected rows or made a claim")
    return manifest


def validate_materialized_candidate(root, candidate_root):
    """Recheck the exact extracted tree before it enters an image context."""
    root = Path(root).resolve()
    lock = load_lock(root)
    validate_selected_lock(root, lock)
    candidate_root = Path(candidate_root)
    info = candidate_root.lstat()
    require(stat.S_ISDIR(info.st_mode) and not candidate_root.is_symlink()
            and candidate_root.resolve() == candidate_root,
            "materialized candidate root is not one direct directory")
    manifest_path = candidate_root / "manifest.json"
    manifest_info = manifest_path.lstat()
    binding = lock["candidate"]["manifest"]
    require(stat.S_ISREG(manifest_info.st_mode) and manifest_info.st_nlink == 1
            and not manifest_path.is_symlink()
            and manifest_info.st_size == binding["bytes"],
            "materialized candidate manifest is not exact")
    manifest_raw = manifest_path.read_bytes()
    manifest = validate_candidate_manifest(lock, manifest_raw)
    expected = _candidate_bindings(lock)
    actual = {}
    directories = set()
    for path in candidate_root.rglob("*"):
        relative = path.relative_to(candidate_root).as_posix()
        row = path.lstat()
        require(not path.is_symlink(), "materialized candidate contains a link")
        if stat.S_ISDIR(row.st_mode):
            directories.add(relative)
        else:
            require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1,
                    "materialized candidate contains a special or linked file")
            actual[relative] = path
    require(directories == {"metadata", "packages"}
            and set(actual) == set(expected),
            "materialized candidate members changed")
    for name, path in actual.items():
        row = path.stat()
        binding = expected[name]
        require(row.st_size == binding["bytes"] and sha256(path) == binding["sha256"],
                "materialized candidate bytes changed")
    return {"manifest": manifest, "root": candidate_root}


def install_plan(manifest):
    """Bind the image install order and its two exact Pre-Depends barriers."""
    rows = manifest.get("packages") if isinstance(manifest, dict) else None
    order = manifest.get("download_order") if isinstance(manifest, dict) else None
    require(isinstance(rows, list) and rows
            and isinstance(order, list) and len(order) == len(rows),
            "offline fixture install plan is incomplete")
    by_hash = {}
    by_package = {}
    for row in rows:
        require(isinstance(row, dict)
                and re.fullmatch(
                    r"[a-z0-9][a-z0-9+.-]*", row.get("package", ""))
                is not None
                and packages._safe_filename(row.get("filename"), ".deb")
                and packages.exact_hash(row.get("sha256"))
                and row["sha256"] not in by_hash
                and row["package"] not in by_package,
                "offline fixture package identity is ambiguous")
        by_hash[row["sha256"]] = row
        by_package[row["package"]] = row
    require(len(order) == len(set(order)) and set(order) == set(by_hash),
            "offline fixture download order changed")
    ordered = [by_hash[digest] for digest in order]
    positions = {row["package"]: index for index, row in enumerate(ordered)}
    for package, target in INSTALL_PRE_DEPENDENCIES:
        require(package in positions and target in positions
                and positions[target] < positions[package],
                "offline fixture Pre-Depends install order changed")
    barriers = {package for package, _ in INSTALL_PRE_DEPENDENCIES}
    return [
        {
            "sequence": sequence,
            "package": row["package"],
            "source": PurePosixPath(row["filename"]).name,
            "target": (
                f"{sequence:04d}-"
                + ("preconfigure-" if row["package"] in barriers else "install-")
                + row["package"] + ".deb"
            ),
            "bytes": row.get("bytes"),
            "sha256": row["sha256"],
            "preconfigure_before": row["package"] in barriers,
        }
        for sequence, row in enumerate(ordered)
    ]


def stage_install_packages(root, candidate_root, destination):
    """Copy exact candidate packages into sequence-prefixed install order."""
    candidate_root = Path(candidate_root)
    validated = validate_materialized_candidate(root, candidate_root)
    plan = install_plan(validated["manifest"])
    destination = Path(destination)
    require(destination.is_absolute() and destination.resolve() == destination
            and not destination.exists() and not destination.is_symlink()
            and destination.parent.is_dir()
            and not destination.parent.is_symlink()
            and destination.parent.resolve() == destination.parent,
            "offline fixture install directory must be a new direct path")
    destination.mkdir(mode=0o700)
    source_fd = os.open(
        candidate_root / "packages",
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    destination_fd = os.open(
        destination,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        for row in plan:
            source = os.open(
                row["source"], os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                dir_fd=source_fd)
            output = None
            try:
                info = os.fstat(source)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and type(row["bytes"]) is int
                        and info.st_size == row["bytes"],
                        "offline fixture install source changed")
                output = os.open(
                    row["target"],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    0o600, dir_fd=destination_fd)
                digest = hashlib.sha256()
                count = 0
                while block := os.read(source, COPY_CHUNK_BYTES):
                    count += len(block)
                    require(count <= row["bytes"],
                            "offline fixture install source grew")
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(output, view)
                        require(written > 0,
                                "offline fixture install copy stalled")
                        view = view[written:]
                os.fsync(output)
                require(count == row["bytes"]
                        and digest.hexdigest() == row["sha256"],
                        "offline fixture install source bytes changed")
            finally:
                if output is not None:
                    os.close(output)
                os.close(source)
        require(set(os.listdir(destination_fd))
                == {row["target"] for row in plan},
                "offline fixture staged package set changed")
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)
    return plan


def stage_install_candidate(root, candidate_root, context):
    """Descriptor-copy the complete selected candidate into one exact context."""
    root = Path(root).resolve()
    candidate_root = Path(candidate_root)
    context = Path(context)
    require(candidate_root.is_absolute() and candidate_root.is_dir()
            and not candidate_root.is_symlink()
            and candidate_root.resolve() == candidate_root
            and context.is_absolute() and context.is_dir()
            and not context.is_symlink() and context.resolve() == context,
            "offline fixture candidate and context must be direct directories")
    lock = load_lock(root)
    validate_selected_lock(root, lock)
    bindings = _candidate_bindings(lock)
    metadata_names = {
        name.removeprefix("metadata/")
        for name in bindings if name.startswith("metadata/")
    }
    package_names = {
        PurePosixPath(row["filename"]).name
        for row in lock["candidate"]["packages"]
    }
    require(not (context / "manifest.json").exists()
            and not (context / "metadata").exists()
            and not (context / "packages").exists(),
            "offline fixture context already contains candidate inputs")

    source_root_fd = source_metadata_fd = source_packages_fd = None
    context_fd = output_metadata_fd = output_packages_fd = None

    def copy_bound(source_fd, source_name, output_fd, output_name, binding):
        descriptor = output = None
        checksum = hashlib.sha256()
        count = 0
        try:
            descriptor = os.open(
                source_name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
                | os.O_NOFOLLOW, dir_fd=source_fd)
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_size == binding["bytes"],
                    "offline fixture candidate member changed")
            output = os.open(
                output_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                | os.O_NOFOLLOW, 0o600, dir_fd=output_fd)
            while block := os.read(descriptor, COPY_CHUNK_BYTES):
                count += len(block)
                require(count <= binding["bytes"],
                        "offline fixture candidate member grew")
                checksum.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(output, view)
                    require(written > 0,
                            "offline fixture candidate copy stalled")
                    view = view[written:]
            os.fsync(output)
            final = os.fstat(descriptor)
            require(count == binding["bytes"]
                    and checksum.hexdigest() == binding["sha256"]
                    and (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                         info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                    == (final.st_dev, final.st_ino, final.st_mode,
                        final.st_nlink, final.st_size, final.st_mtime_ns,
                        final.st_ctime_ns),
                    "offline fixture candidate member bytes changed")
        finally:
            if output is not None:
                os.close(output)
            if descriptor is not None:
                os.close(descriptor)

    try:
        source_root_fd = os.open(
            candidate_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        source_metadata_fd = os.open(
            "metadata", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            | os.O_NOFOLLOW, dir_fd=source_root_fd)
        source_packages_fd = os.open(
            "packages", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            | os.O_NOFOLLOW, dir_fd=source_root_fd)
        require(set(os.listdir(source_root_fd))
                == {"manifest.json", "metadata", "packages"}
                and set(os.listdir(source_metadata_fd)) == metadata_names
                and set(os.listdir(source_packages_fd)) == package_names,
                "offline fixture candidate inventory changed")

        context_fd = os.open(
            context,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        os.mkdir("metadata", mode=0o700, dir_fd=context_fd)
        os.mkdir("packages", mode=0o700, dir_fd=context_fd)
        output_metadata_fd = os.open(
            "metadata", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            | os.O_NOFOLLOW, dir_fd=context_fd)
        output_packages_fd = os.open(
            "packages", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            | os.O_NOFOLLOW, dir_fd=context_fd)

        copy_bound(source_root_fd, "manifest.json", context_fd,
                   "manifest.json", bindings["manifest.json"])
        manifest = validate_candidate_manifest(
            lock, (context / "manifest.json").read_bytes())
        plan = install_plan(manifest)
        for name in sorted(metadata_names):
            copy_bound(source_metadata_fd, name, output_metadata_fd, name,
                       bindings["metadata/" + name])
        for row in plan:
            copy_bound(source_packages_fd, row["source"], output_packages_fd,
                       row["target"], row)
        require(set(os.listdir(source_root_fd))
                == {"manifest.json", "metadata", "packages"}
                and set(os.listdir(source_metadata_fd)) == metadata_names
                and set(os.listdir(source_packages_fd)) == package_names
                and set(os.listdir(output_metadata_fd)) == metadata_names
                and set(os.listdir(output_packages_fd))
                == {row["target"] for row in plan},
                "offline fixture candidate changed during staging")
        os.fsync(output_metadata_fd)
        os.fsync(output_packages_fd)
        os.fsync(context_fd)
        return {
            "manifest": manifest,
            "manifest_sha256": bindings["manifest.json"]["sha256"],
            "plan": plan,
        }
    finally:
        for descriptor in (
                output_packages_fd, output_metadata_fd, context_fd,
                source_packages_fd, source_metadata_fd, source_root_fd):
            if descriptor is not None:
                os.close(descriptor)


def _extract_bundle(path, expected, destination, maximum_total, description,
                    callbacks=None, *, allow_empty=False):
    with Path(path).open("rb") as archive:
        _preflight_zip_directory(archive, len(expected), description)
        with zipfile.ZipFile(archive, "r") as bundle:
            rows = _zip_members(
                bundle, expected, maximum_total, description,
                allow_empty=allow_empty)
            for name, callback in (callbacks or {}).items():
                require(name in expected,
                        description + " callback member is absent")
                binding = expected[name]
                with bundle.open(rows[name]) as stream:
                    raw = stream.read(binding["bytes"] + 1)
                callback(raw)
            for name in sorted(expected):
                target = destination / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                descriptor = os.open(
                    target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(descriptor, "wb") as output:
                        descriptor = -1
                        _read_member(
                            bundle, rows[name], expected[name], output)
                        output.flush()
                        os.fsync(output.fileno())
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)


def consume_selected_inputs(root, run_metadata, candidate_metadata,
                            evidence_metadata, candidate_zip, evidence_zip,
                            destination, available_bytes=None):
    root = Path(root).resolve()
    lock = load_lock(root)
    validate_selected_lock(root, lock)
    validate_run_metadata_unchecked(run_metadata, lock)
    validate_artifact_metadata(candidate_metadata, lock, "candidate")
    validate_artifact_metadata(evidence_metadata, lock, "evidence")
    candidate_zip = _regular_archive(
        candidate_zip, lock["artifacts"]["candidate"]["zip"],
        packages.MAX_ARTIFACT_BYTES, "candidate artifact")
    evidence_zip = _regular_archive(
        evidence_zip, lock["artifacts"]["evidence"]["zip"],
        MAX_EVIDENCE_ARTIFACT_BYTES, "producer evidence artifact")
    destination = Path(destination)
    require(destination.is_absolute() and destination.resolve() == destination
            and not destination.exists() and not destination.is_symlink()
            and destination.parent.is_dir() and not destination.parent.is_symlink()
            and destination.parent.resolve() == destination.parent,
            "offline package destination must be a new direct directory")
    candidate_bindings = _candidate_bindings(lock)
    candidate_expanded = sum(row["bytes"] for row in candidate_bindings.values())
    evidence_expanded = sum(
        row["bytes"] for row in lock["evidence"]["members"])
    required_free = (
        3 * candidate_expanded + evidence_expanded
        + MATERIALIZATION_FREE_RESERVE)
    free = (shutil.disk_usage(destination.parent).free
            if available_bytes is None else available_bytes)
    require(type(free) is int and free >= required_free,
            "offline package extraction lacks bounded staging space")
    destination.mkdir(mode=0o700)
    try:
        candidate_output = destination / "candidate"
        evidence_output = destination / "evidence"
        candidate_output.mkdir(mode=0o700)
        evidence_output.mkdir(mode=0o700)
        validated_manifest = {}
        _extract_bundle(
            candidate_zip, candidate_bindings, candidate_output,
            sum(row["bytes"] for row in candidate_bindings.values()),
            "candidate artifact", {
                "manifest.json": lambda raw: validated_manifest.setdefault(
                    "value", validate_candidate_manifest(lock, raw)),
            })
        evidence_bindings = {row["path"]: row for row in lock["evidence"]["members"]}
        _extract_bundle(
            evidence_zip, evidence_bindings, evidence_output,
            MAX_EVIDENCE_EXPANDED_BYTES, "producer evidence artifact", {
                "producer-result.json": lambda raw: validate_producer_result(
                    lock, raw),
            }, allow_empty=True)
        require("value" in validated_manifest,
                "candidate manifest was not validated")
        return {"ready": True, "selected": True, "verified": False,
                "qualified": False, "container_qualified": False,
                "signature_qualified": False, "os_qualified": False,
                "release_qualified": False,
                "candidate": str(candidate_output), "evidence": str(evidence_output)}
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def validate_run_metadata_unchecked(metadata, lock):
    require(isinstance(metadata, dict)
            and _exact_record(_normalized_run(metadata), lock["run"])
            and metadata.get("event") == lock["workflow"]["event"]
            and metadata.get("path") == lock["workflow"]["path"]
            and _exact_record(
                metadata.get("workflow_id"), lock["workflow"]["id"]),
            "producer run API record differs from the selected run")
    return metadata


def validate_artifact_for_use(root, lock, candidate, metadata):
    if lock.get("state") == "pending":
        validate_pending_lock(root, lock)
        raise ValueError("pending offline fixture package selection cannot use an artifact")
    validate_selected_lock(root, lock)
    return validate_artifact_metadata(metadata, lock, "candidate")


def require_mode(root, lock, mode):
    require(mode in {"check", "consume", "build", "materialize"},
            "unknown offline fixture package validator mode")
    result = validate_lock(root, lock)
    if mode != "check" and result["ready"] is not True:
        raise ValueError("pending offline fixture package selection cannot " + mode)
    return result


def _json_path(path, maximum=4 * 1024**2):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not path.is_symlink() and 0 < info.st_size <= maximum,
            "downloaded API record is not a bounded direct regular file")
    return packages.unique_json_bytes(path.read_bytes(), maximum)


def receive_stream(root, stream, output, maximum, expected_bytes=None,
                   expected_sha256=None, available_bytes=None):
    """Bound one authenticated API response before it reaches the filesystem."""
    root = Path(root).resolve()
    cache = root / ".cache"
    output = Path(output)
    require(cache.is_dir() and not cache.is_symlink() and cache.resolve() == cache
            and output.is_absolute() and output.parent == cache
            and output.resolve(strict=False) == output
            and not output.exists() and not output.is_symlink(),
            "offline fixture transfer target is not a new direct cache path")
    require(type(maximum) is int and 0 < maximum <= packages.MAX_ARTIFACT_BYTES,
            "offline fixture transfer maximum is invalid")
    if expected_bytes is None:
        require(expected_sha256 is None,
                "offline fixture transfer hash lacks an exact byte count")
        hard_limit = maximum
    else:
        require(type(expected_bytes) is int and 0 < expected_bytes <= maximum
                and packages.exact_hash(expected_sha256),
                "offline fixture transfer identity is invalid")
        hard_limit = expected_bytes
    free = (shutil.disk_usage(cache).free
            if available_bytes is None else available_bytes)
    require(type(free) is int
            and free >= hard_limit + TRANSFER_FREE_RESERVE,
            "offline fixture transfer lacks bounded cache space")

    descriptor = None
    count = 0
    digest = hashlib.sha256()
    try:
        descriptor = os.open(
            output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            | os.O_NOFOLLOW, 0o600)
        while block := stream.read(min(COPY_CHUNK_BYTES, hard_limit + 1 - count)):
            require(isinstance(block, bytes),
                    "offline fixture transfer stream is not binary")
            count += len(block)
            require(count <= hard_limit,
                    "offline fixture transfer exceeded its byte bound")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(descriptor, view)
                require(written > 0, "offline fixture transfer write stalled")
                view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        actual = digest.hexdigest()
        if expected_bytes is not None:
            require(count == expected_bytes and actual == expected_sha256,
                    "offline fixture transfer bytes changed")
        info = output.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_size == count and not output.is_symlink(),
                "offline fixture transfer output is not a direct regular file")
        return {"bytes": count, "sha256": actual}
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        output.unlink(missing_ok=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate or consume the selected offline fixture packages")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    subparsers = parser.add_subparsers(dest="mode", required=True)
    subparsers.add_parser("check")
    subparsers.add_parser("pre-transfer")
    receive = subparsers.add_parser("receive")
    receive.add_argument("--output", type=Path, required=True)
    receive.add_argument("--maximum", type=int, required=True)
    receive.add_argument("--expected-bytes", type=int)
    receive.add_argument("--expected-sha256")
    metadata = subparsers.add_parser("metadata")
    consume = subparsers.add_parser("consume")
    for target in (metadata, consume):
        target.add_argument("--run-metadata", type=Path, required=True)
        target.add_argument("--candidate-metadata", type=Path, required=True)
        target.add_argument("--evidence-metadata", type=Path, required=True)
    consume.add_argument("--candidate-zip", type=Path, required=True)
    consume.add_argument("--evidence-zip", type=Path, required=True)
    consume.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        lock = load_lock(args.root)
        if args.mode == "check":
            result = validate_lock(args.root, lock)
            print(json.dumps(result, sort_keys=True))
        elif args.mode == "pre-transfer":
            result = validate_selected_lock(args.root, lock)
            require(result["ready"] is True, "offline fixture package selection is pending")
            print(lock["run"]["id"])
            print(lock["run"]["attempt"])
            print(lock["artifacts"]["candidate"]["api"]["id"])
            print(lock["artifacts"]["evidence"]["api"]["id"])
            print(lock["artifacts"]["candidate"]["zip"]["bytes"])
            print(lock["artifacts"]["candidate"]["zip"]["sha256"])
            print(lock["artifacts"]["evidence"]["zip"]["bytes"])
            print(lock["artifacts"]["evidence"]["zip"]["sha256"])
        elif args.mode == "receive":
            validate_selected_lock(args.root, lock)
            result = receive_stream(
                args.root, sys.stdin.buffer, args.output, args.maximum,
                args.expected_bytes, args.expected_sha256)
            print(json.dumps(result, sort_keys=True))
        else:
            run = _json_path(args.run_metadata)
            candidate_metadata = _json_path(args.candidate_metadata)
            evidence_metadata = _json_path(args.evidence_metadata)
            validate_selected_lock(args.root, lock)
            validate_run_metadata_unchecked(run, lock)
            validate_artifact_metadata(candidate_metadata, lock, "candidate")
            validate_artifact_metadata(evidence_metadata, lock, "evidence")
            if args.mode == "metadata":
                print(json.dumps({"metadata": "selected", "verified": False},
                                 sort_keys=True))
            else:
                result = consume_selected_inputs(
                    args.root, run, candidate_metadata, evidence_metadata,
                    args.candidate_zip, args.evidence_zip, args.destination)
                print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError,
            zipfile.BadZipFile, zlib.error) as error:
        parser.exit(1, "Offline fixture package input rejected: " + str(error) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
