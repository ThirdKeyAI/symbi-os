"""Retain and consume authenticated Ubuntu repository metadata.

Discovery creates a seven-file, non-authoritative artifact.  Production accepts
only the artifact selected by the reviewed producer contract, verifies GitHub's
run and artifact records before transfer, and then reauthenticates the retained
InRelease files.  Repository code receives GITHUB_TOKEN only in the
pre-transfer command; it is never part of the producer environment.
"""
from datetime import datetime
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request
import zipfile

from image.container import ubuntu_fixture_packages as packages


ARTIFACT_NAME = "container-ubuntu-fixture-metadata"
MANIFEST_NAME = "manifest.json"
SCOPE = (
    "Retained authenticated Ubuntu metadata candidate; no artifact selection, "
    "package candidate, image use or qualification"
)
MANIFEST_FIELDS = {
    "schema", "state", "authoritative", "selected", "qualified",
    "container_qualified", "signature_qualified", "os_qualified",
    "release_qualified", "repository", "workflow", "event", "run",
    "branch", "contract_sha256", "lock_sha256", "verified_at", "metadata",
    "scope",
}
RUN_FIELDS = {"id", "attempt", "head_sha", "head_tree"}
METADATA_FIELDS = {
    "suite", "inrelease_url", "packages_url", "signer_fingerprint",
    "freshness_policy", "inrelease", "packages_xz",
}
PAYLOAD_FIELDS = {"name", "bytes", "sha256"}
FALSE_CLAIMS = (
    "authoritative", "selected", "qualified", "container_qualified",
    "signature_qualified", "os_qualified", "release_qualified",
)
SOURCE_FIELDS = {
    "state", "producer", "artifact", "manifest_sha256",
    "discovery_contract_sha256", "lock_sha256",
}
PRODUCER_FIELDS = {
    "run_id", "run_attempt", "head_sha", "head_tree", "branch",
}
ARTIFACT_FIELDS = {
    "id", "name", "bytes", "api_sha256", "zip_sha256",
}
MAX_API_BYTES = 2 * 1024**2
MAX_MANIFEST_BYTES = packages.MAX_CONTROL_FILE_BYTES
MAX_ZIP_MEMBERS = 7
MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024
MAX_EXPANDED_BYTES = (
    3 * packages.MAX_METADATA_BYTES + 3 * packages.MAX_INDEX_BYTES
    + MAX_MANIFEST_BYTES
)
TRANSFER_SCOPE = (
    "Reviewed retained metadata transfer only; no package, image, selection "
    "or qualification claim"
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_sha256(value):
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _exact_hash(value, length=64):
    return (isinstance(value, str)
            and re.fullmatch(r"[a-f0-9]{" + str(length) + r"}", value)
            is not None)


def _positive_int(value, maximum=None):
    return (type(value) is int and value > 0
            and (maximum is None or value <= maximum))


def _branch(value):
    return (isinstance(value, str) and 0 < len(value.encode()) <= 255
            and not value.startswith("/") and not value.endswith("/")
            and ".." not in value and "//" not in value
            and re.fullmatch(r"[A-Za-z0-9._/-]+", value) is not None)


def _trusted_artifact_redirect(value):
    if (not isinstance(value, str) or not value
            or "\\" in value
            or any(character.isspace() or ord(character) < 33
                   for character in value)):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    host = parsed.hostname or ""
    return (parsed.scheme == "https" and parsed.username is None
            and parsed.password is None and parsed.fragment == ""
            and port in (None, 443) and parsed.path.startswith("/")
            and host.endswith((
                ".blob.core.windows.net", ".githubusercontent.com")))


def artifact_filename(suite, kind):
    require(any(source["suite"] == suite
                for source in packages.EXPECTED_SOURCES),
            "Ubuntu metadata suite is unknown")
    require(kind in {"InRelease", "Packages.xz"},
            "Ubuntu metadata artifact kind is unknown")
    return suite + "." + kind


def expected_names():
    names = {MANIFEST_NAME}
    for source in packages.EXPECTED_SOURCES:
        names.add(artifact_filename(source["suite"], "InRelease"))
        names.add(artifact_filename(source["suite"], "Packages.xz"))
    return names


def _require_real_directory(path, description):
    path = Path(path)
    require(path.is_absolute(), description + " is not absolute")
    info = os.lstat(path)
    require(stat.S_ISDIR(info.st_mode) and not path.is_symlink()
            and path.resolve(strict=True) == path
            and info.st_uid == os.geteuid()
            and info.st_gid == os.getegid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            description + " is not a real canonical directory")
    return path


def validate_source_selection(source, *, pending):
    require(type(source) is dict and set(source) == SOURCE_FIELDS
            and source.get("state") == ("pending" if pending else "ready"),
            "Ubuntu retained metadata selection fields changed")
    producer = source.get("producer")
    artifact = source.get("artifact")
    require(type(producer) is dict and set(producer) == PRODUCER_FIELDS
            and type(artifact) is dict and set(artifact) == ARTIFACT_FIELDS
            and artifact.get("name") == ARTIFACT_NAME,
            "Ubuntu retained metadata producer or artifact fields changed")
    nullable = {
        "run_id": None, "run_attempt": None, "head_sha": None,
        "head_tree": None, "branch": None,
    }
    null_artifact = {
        "id": None, "name": ARTIFACT_NAME, "bytes": None,
        "api_sha256": None, "zip_sha256": None,
    }
    if pending:
        require(producer == nullable and artifact == null_artifact
                and source.get("manifest_sha256") is None
                and source.get("discovery_contract_sha256") is None
                and source.get("lock_sha256") is None,
                "pending Ubuntu metadata selection contains authority")
    else:
        require(_positive_int(producer.get("run_id"))
                and _positive_int(producer.get("run_attempt"))
                and _exact_hash(producer.get("head_sha"), 40)
                and _exact_hash(producer.get("head_tree"), 40)
                and _branch(producer.get("branch"))
                and _positive_int(artifact.get("id"))
                and _positive_int(artifact.get("bytes"),
                                  packages.MAX_ARTIFACT_BYTES)
                and _exact_hash(artifact.get("api_sha256"))
                and _exact_hash(artifact.get("zip_sha256"))
                and artifact["api_sha256"] == artifact["zip_sha256"]
                and _exact_hash(source.get("manifest_sha256"))
                and _exact_hash(source.get("discovery_contract_sha256"))
                and _exact_hash(source.get("lock_sha256")),
                "ready Ubuntu metadata selection is incomplete")
    return source


def _validate_payload(value, name, maximum):
    require(type(value) is dict and set(value) == PAYLOAD_FIELDS
            and value.get("name") == name
            and _positive_int(value.get("bytes"), maximum)
            and _exact_hash(value.get("sha256")),
            "Ubuntu retained metadata payload binding changed")
    return value


def validate_manifest(manifest, *, workflow, expected_contract_sha256,
                      expected_lock_sha256, policies, pins=None,
                      selection=None):
    require(type(manifest) is dict and set(manifest) == MANIFEST_FIELDS
            and type(manifest.get("schema")) is int
            and manifest["schema"] == 1
            and manifest.get("state") == "retained-metadata-unselected"
            and all(manifest.get(field) is False for field in FALSE_CLAIMS)
            and manifest.get("repository") == packages.REPOSITORY
            and manifest.get("workflow") == workflow
            and manifest.get("event") == "workflow_dispatch"
            and _branch(manifest.get("branch"))
            and manifest.get("contract_sha256")
            == expected_contract_sha256
            and manifest.get("lock_sha256") == expected_lock_sha256
            and isinstance(manifest.get("verified_at"), str)
            and manifest.get("scope") == SCOPE,
            "Ubuntu retained metadata manifest identity or claims changed")
    run = manifest.get("run")
    require(type(run) is dict and set(run) == RUN_FIELDS
            and _positive_int(run.get("id"))
            and _positive_int(run.get("attempt"))
            and _exact_hash(run.get("head_sha"), 40)
            and _exact_hash(run.get("head_tree"), 40),
            "Ubuntu retained metadata run identity changed")
    try:
        verified = datetime.fromisoformat(
            manifest["verified_at"].replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise ValueError("Ubuntu retained metadata verification time is invalid") from error
    require(verified.tzinfo is not None,
            "Ubuntu retained metadata verification time lacks a zone")
    rows = manifest.get("metadata")
    require(type(rows) is list
            and len(rows) == len(packages.EXPECTED_SOURCES),
            "Ubuntu retained metadata manifest row count changed")
    pin_rows = None if pins is None else {
        row["suite"]: row for row in pins
    }
    require(type(policies) is list
            and len(policies) == len(packages.EXPECTED_SOURCES),
            "Ubuntu retained metadata freshness policy count changed")
    for row, source, policy in zip(
            rows, packages.EXPECTED_SOURCES, policies, strict=True):
        suite = source["suite"]
        require(type(row) is dict and set(row) == METADATA_FIELDS
                and row.get("suite") == suite
                and row.get("inrelease_url")
                == source["metadata"]["inrelease_url"]
                and row.get("packages_url") == source["packages_url"]
                and row.get("signer_fingerprint")
                == source["metadata"]["signer_fingerprint"]
                and row.get("freshness_policy") == policy,
                "Ubuntu retained metadata source binding changed")
        inrelease = _validate_payload(
            row.get("inrelease"), artifact_filename(suite, "InRelease"),
            packages.MAX_METADATA_BYTES)
        index = _validate_payload(
            row.get("packages_xz"), artifact_filename(suite, "Packages.xz"),
            packages.MAX_INDEX_BYTES)
        if pin_rows is not None:
            require(suite in pin_rows
                    and {key: inrelease[key] for key in ("bytes", "sha256")}
                    == pin_rows[suite]["inrelease"]
                    and {key: index[key] for key in ("bytes", "sha256")}
                    == pin_rows[suite]["packages_xz"],
                    "Ubuntu retained metadata differs from reviewed pins")
    if selection is not None:
        producer = selection["producer"]
        require(run == {
                    "id": producer["run_id"],
                    "attempt": producer["run_attempt"],
                    "head_sha": producer["head_sha"],
                    "head_tree": producer["head_tree"],
                }
                and manifest["branch"] == producer["branch"],
                "Ubuntu retained metadata manifest differs from its selection")
    return manifest


def discovery_manifest(contract, lock, run, branch, verified_at,
                       metadata_result):
    require(type(run) is dict
            and set(run) >= {"id", "attempt", "head_sha", "head_tree"}
            and _branch(branch)
            and isinstance(verified_at, datetime)
            and verified_at.tzinfo is not None,
            "Ubuntu retained metadata discovery identity is invalid")
    rows = []
    for result, source, policy in zip(
            metadata_result, packages.EXPECTED_SOURCES,
            contract["freshness_policy"], strict=True):
        suite = source["suite"]
        require(result.get("suite") == suite,
                "Ubuntu retained metadata result order changed")
        rows.append({
            "suite": suite,
            "inrelease_url": source["metadata"]["inrelease_url"],
            "packages_url": source["packages_url"],
            "signer_fingerprint": source["metadata"]["signer_fingerprint"],
            "freshness_policy": policy,
            "inrelease": {
                "name": artifact_filename(suite, "InRelease"),
                "bytes": result["inrelease"]["bytes"],
                "sha256": result["inrelease"]["sha256"],
            },
            "packages_xz": {
                "name": artifact_filename(suite, "Packages.xz"),
                "bytes": result["packages_xz"]["bytes"],
                "sha256": result["packages_xz"]["sha256"],
            },
        })
    value = {
        "schema": 1,
        "state": "retained-metadata-unselected",
        **{field: False for field in FALSE_CLAIMS},
        "repository": packages.REPOSITORY,
        "workflow": contract["workflow"],
        "event": "workflow_dispatch",
        "run": {key: run[key] for key in RUN_FIELDS},
        "branch": branch,
        "contract_sha256": canonical_sha256(contract),
        "lock_sha256": canonical_sha256(lock),
        "verified_at": verified_at.isoformat().replace("+00:00", "Z"),
        "metadata": rows,
        "scope": SCOPE,
    }
    return validate_manifest(
        value, workflow=contract["workflow"],
        expected_contract_sha256=canonical_sha256(contract),
        expected_lock_sha256=canonical_sha256(lock),
        policies=contract["freshness_policy"])


def _copy_exact(source, destination, expected):
    source = Path(source)
    destination = Path(destination)
    require(source.is_absolute() and destination.is_absolute(),
            "Ubuntu retained metadata copy paths are not absolute")
    _require_real_directory(
        source.parent, "Ubuntu retained metadata source parent")
    _require_real_directory(
        destination.parent, "Ubuntu retained metadata destination parent")
    source_info = os.lstat(source)
    require(stat.S_ISREG(source_info.st_mode) and not source.is_symlink()
            and source.resolve(strict=True) == source
            and source_info.st_uid == os.geteuid()
            and source_info.st_gid == os.getegid()
            and stat.S_IMODE(source_info.st_mode) == 0o600
            and source_info.st_nlink == 1 and not destination.exists(),
            "Ubuntu retained metadata source or destination is unsafe")
    digest = hashlib.sha256()
    total = 0
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    target_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600)
    try:
        before = os.fstat(source_fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.geteuid()
                and before.st_gid == os.getegid()
                and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_size == expected["bytes"],
                "Ubuntu retained metadata source identity changed")
        while True:
            block = os.read(source_fd, 64 * 1024)
            if not block:
                break
            total += len(block)
            digest.update(block)
            view = memoryview(block)
            while view:
                count = os.write(target_fd, view)
                require(count > 0, "Ubuntu retained metadata write stalled")
                view = view[count:]
        os.fsync(target_fd)
        after = os.fstat(source_fd)
        require(total == expected["bytes"]
                and digest.hexdigest() == expected["sha256"]
                and (before.st_dev, before.st_ino, before.st_mode,
                     before.st_uid, before.st_gid, before.st_nlink,
                     before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_mode,
                    after.st_uid, after.st_gid, after.st_nlink,
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "Ubuntu retained metadata source changed while copying")
    finally:
        os.close(source_fd)
        os.close(target_fd)


def write_discovery_artifact(destination, contract, lock, run, branch,
                             verified_at, metadata_result, metadata_inputs):
    destination = Path(destination)
    require(destination.is_absolute()
            and not destination.exists(),
            "Ubuntu retained metadata artifact destination is unsafe")
    _require_real_directory(
        destination.parent, "Ubuntu retained metadata artifact parent")
    destination.mkdir(mode=0o700)
    manifest = discovery_manifest(
        contract, lock, run, branch, verified_at, metadata_result)
    by_suite = {row["suite"]: row for row in manifest["metadata"]}
    for source in packages.EXPECTED_SOURCES:
        suite = source["suite"]
        row = by_suite[suite]
        source_names = {
            "inrelease": suite + "_InRelease",
            "packages_xz": suite + "_main_binary-amd64_Packages.xz",
        }
        for kind in ("inrelease", "packages_xz"):
            require(source_names[kind] in metadata_inputs,
                    "Ubuntu retained metadata source file is missing")
            _copy_exact(
                metadata_inputs[source_names[kind]],
                destination / row[kind]["name"], row[kind])
    raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    require(len(raw) <= MAX_MANIFEST_BYTES,
            "Ubuntu retained metadata manifest exceeds its bound")
    descriptor = os.open(
        destination / MANIFEST_NAME,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            require(count > 0, "Ubuntu retained metadata manifest write stalled")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require(set(os.listdir(destination)) == expected_names(),
            "Ubuntu retained metadata artifact members changed")
    return manifest


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers,
                         new_url):
        return None


def _api_json(url, token, opener=None):
    require(isinstance(token, str) and token
            and packages._canonical_https(url),
            "Ubuntu metadata GitHub API request is malformed")
    opener = build_opener(_NoRedirect) if opener is None else opener
    request = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Accept-Encoding": "identity",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SymbiOS-retained-metadata/1",
    })
    with opener.open(request, timeout=30) as response:
        length = response.headers.get("Content-Length")
        require(response.status == 200 and response.geturl() == url
                and isinstance(length, str) and length.isdigit()
                and 0 < int(length) <= MAX_API_BYTES,
                "Ubuntu metadata GitHub API redirected")
        raw = response.read(MAX_API_BYTES + 1)
    require(0 < len(raw) <= MAX_API_BYTES and len(raw) == int(length),
            "Ubuntu metadata GitHub API response exceeds its bound")
    return packages.unique_json_bytes(raw, MAX_API_BYTES)


def _download_redirect(url, token, opener=None):
    opener = build_opener(_NoRedirect) if opener is None else opener
    request = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Accept-Encoding": "identity",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SymbiOS-retained-metadata/1",
    })
    try:
        opener.open(request, timeout=30)
    except HTTPError as error:
        try:
            require(error.code in {302, 307}
                    and isinstance(error.headers.get("Location"), str),
                    "Ubuntu metadata artifact endpoint did not return a redirect")
            location = error.headers["Location"]
        finally:
            error.close()
    else:
        raise ValueError(
            "Ubuntu metadata artifact endpoint bypassed its signed redirect")
    require(_trusted_artifact_redirect(location),
            "Ubuntu metadata artifact redirect host is not trusted")
    return location


def _download_zip(url, destination, selection, opener=None):
    require(_trusted_artifact_redirect(url),
            "Ubuntu metadata artifact download URL is not trusted")
    opener = build_opener(_NoRedirect) if opener is None else opener
    request = Request(url, headers={
        "Accept-Encoding": "identity",
        "User-Agent": "SymbiOS-retained-metadata/1",
    })
    destination = Path(destination)
    require(destination.is_absolute(),
            "Ubuntu metadata ZIP transfer destination is not absolute")
    _require_real_directory(
        destination.parent, "Ubuntu metadata ZIP transfer parent")
    require(not destination.exists(),
            "Ubuntu metadata ZIP transfer destination exists")
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600)
    digest = hashlib.sha256()
    total = 0
    try:
        with opener.open(request, timeout=120) as response:
            length = response.headers.get("Content-Length")
            require(response.status == 200 and response.geturl() == url
                    and isinstance(length, str) and length.isdigit()
                    and int(length) == selection["artifact"]["bytes"],
                    "Ubuntu metadata artifact transfer identity changed")
            while True:
                block = response.read(64 * 1024)
                if not block:
                    break
                total += len(block)
                require(total <= int(length),
                        "Ubuntu metadata artifact transfer exceeded its bound")
                digest.update(block)
                view = memoryview(block)
                while view:
                    count = os.write(descriptor, view)
                    require(count > 0,
                            "Ubuntu metadata artifact transfer stalled")
                    view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require(total == selection["artifact"]["bytes"]
            and digest.hexdigest() == selection["artifact"]["zip_sha256"],
            "Ubuntu metadata artifact ZIP differs from its selection")


def validate_github_records(run, artifact, contract):
    selection = contract["metadata_source"]
    producer = selection["producer"]
    selected = selection["artifact"]
    require(type(run) is dict
            and run.get("id") == producer["run_id"]
            and run.get("run_attempt") == producer["run_attempt"]
            and run.get("head_sha") == producer["head_sha"]
            and run.get("head_branch") == producer["branch"]
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == contract["workflow"]
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and type(run.get("repository")) is dict
            and run["repository"].get("id") == packages.REPOSITORY["id"]
            and type(run.get("head_repository")) is dict
            and run["head_repository"].get("id") == packages.REPOSITORY["id"]
            and type(run.get("head_commit")) is dict
            and run["head_commit"].get("tree_id") == producer["head_tree"],
            "Ubuntu metadata producer run differs from its selection")
    require(type(artifact) is dict
            and artifact.get("id") == selected["id"]
            and artifact.get("name") == selected["name"]
            and artifact.get("size_in_bytes") == selected["bytes"]
            and artifact.get("digest")
            == "sha256:" + selected["api_sha256"]
            and artifact.get("expired") is False
            and type(artifact.get("workflow_run")) is dict
            and artifact["workflow_run"].get("id") == producer["run_id"]
            and artifact["workflow_run"].get("head_sha")
            == producer["head_sha"]
            and artifact["workflow_run"].get("repository_id")
            == packages.REPOSITORY["id"]
            and artifact["workflow_run"].get("head_repository_id")
            == packages.REPOSITORY["id"],
            "Ubuntu metadata artifact record differs from its selection")
    return True


def _manifest_from_zip(archive, selection, contract, lock):
    infos = archive.infolist()
    names = [info.filename for info in infos]
    require(len(infos) == MAX_ZIP_MEMBERS
            and len(set(names)) == len(names)
            and set(names) == expected_names(),
            "Ubuntu metadata artifact ZIP members changed")
    total = 0
    compressed_total = 0
    for info in infos:
        path = PurePosixPath(info.filename)
        mode = info.external_attr >> 16
        require(not info.is_dir() and not info.flag_bits & 1
                and not path.is_absolute() and str(path) == info.filename
                and len(path.parts) == 1 and path.name not in ("", ".", "..")
                and (mode == 0 or stat.S_ISREG(mode))
                and info.compress_type in {
                    zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                and info.file_size > 0
                and info.file_size <= packages.MAX_INDEX_BYTES
                and info.compress_size > 0,
                "Ubuntu metadata artifact ZIP contains an unsafe member")
        total += info.file_size
        compressed_total += info.compress_size
    require(total <= MAX_EXPANDED_BYTES,
            "Ubuntu metadata artifact ZIP expansion exceeds its bound")
    require(compressed_total <= selection["artifact"]["bytes"],
            "Ubuntu metadata artifact compressed size exceeds its bound")
    info = archive.getinfo(MANIFEST_NAME)
    require(info.file_size <= MAX_MANIFEST_BYTES,
            "Ubuntu metadata artifact manifest exceeds its bound")
    with archive.open(info, "r") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    require(len(raw) == info.file_size
            and sha256_bytes(raw) == selection["manifest_sha256"],
            "Ubuntu metadata artifact manifest differs from its selection")
    manifest = packages.unique_json_bytes(raw, MAX_MANIFEST_BYTES)
    return validate_manifest(
        manifest, workflow=contract["workflow"],
        expected_contract_sha256=selection["discovery_contract_sha256"],
        expected_lock_sha256=selection["lock_sha256"],
        policies=contract["freshness_policy"],
        pins=contract["metadata_pins"], selection=selection)


def _stable_selected_zip(zip_path, selection):
    zip_path = Path(zip_path)
    require(zip_path.is_absolute(),
            "Ubuntu metadata artifact ZIP path is not absolute")
    _require_real_directory(zip_path.parent, "Ubuntu metadata ZIP parent")
    info = os.lstat(zip_path)
    require(stat.S_ISREG(info.st_mode) and not zip_path.is_symlink()
            and zip_path.resolve(strict=True) == zip_path
            and info.st_uid == os.geteuid() and info.st_gid == os.getegid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
            and info.st_size == selection["artifact"]["bytes"],
            "Ubuntu metadata artifact ZIP identity changed")
    descriptor = os.open(
        zip_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    before = os.fstat(descriptor)
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            total += len(block)
            require(total <= selection["artifact"]["bytes"],
                    "Ubuntu metadata artifact ZIP exceeded its bound")
            digest.update(block)
        after = os.fstat(descriptor)
        require(total == selection["artifact"]["bytes"]
                and digest.hexdigest()
                == selection["artifact"]["zip_sha256"]
                and (before.st_dev, before.st_ino, before.st_mode,
                     before.st_uid, before.st_gid, before.st_nlink,
                     before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_mode,
                    after.st_uid, after.st_gid, after.st_nlink,
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "Ubuntu metadata artifact ZIP bytes changed")
        tail_size = min(before.st_size, 65_557)
        require(tail_size >= 22,
                "Ubuntu metadata artifact ZIP is truncated")
        os.lseek(descriptor, before.st_size - tail_size, os.SEEK_SET)
        chunks = []
        remaining = tail_size
        while remaining:
            block = os.read(descriptor, remaining)
            require(block, "Ubuntu metadata artifact ZIP tail is truncated")
            chunks.append(block)
            remaining -= len(block)
        tail = b"".join(chunks)
        relative = tail.rfind(b"PK\x05\x06")
        require(relative >= 0 and len(tail) - relative >= 22,
                "Ubuntu metadata artifact ZIP end record is missing")
        fields = struct.unpack("<4s4H2LH", tail[relative:relative + 22])
        (_, disk, central_disk, disk_entries, total_entries,
         central_bytes, central_offset, comment_bytes) = fields
        end_offset = before.st_size - tail_size + relative
        require(disk == 0 and central_disk == 0
                and disk_entries == total_entries == MAX_ZIP_MEMBERS
                and 0 < central_bytes <= MAX_CENTRAL_DIRECTORY_BYTES
                and central_offset + central_bytes == end_offset
                and relative + 22 + comment_bytes == len(tail),
                "Ubuntu metadata artifact ZIP directory is not bounded")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, before
    except Exception:
        os.close(descriptor)
        raise


def extract_selected_zip(zip_path, destination, contract, lock):
    selection = contract["metadata_source"]
    validate_source_selection(selection, pending=False)
    require(selection["lock_sha256"] == canonical_sha256(lock),
            "Ubuntu metadata selection differs from the current lock")
    destination = Path(destination)
    require(destination.is_absolute()
            and not destination.exists(),
            "Ubuntu metadata transfer destination is unsafe")
    _require_real_directory(
        destination.parent, "Ubuntu metadata transfer parent")
    zip_descriptor, zip_identity = _stable_selected_zip(zip_path, selection)
    try:
        with os.fdopen(os.dup(zip_descriptor), "rb") as zip_stream, \
                zipfile.ZipFile(zip_stream, "r", allowZip64=False) as archive:
            manifest = _manifest_from_zip(archive, selection, contract, lock)
            by_name = {row[kind]["name"]: row[kind]
                       for row in manifest["metadata"]
                       for kind in ("inrelease", "packages_xz")}
            destination.mkdir(mode=0o700)
            for info in archive.infolist():
                maximum = (MAX_MANIFEST_BYTES
                           if info.filename == MANIFEST_NAME
                           else by_name[info.filename]["bytes"])
                if info.filename != MANIFEST_NAME:
                    require(info.file_size == maximum,
                            "Ubuntu metadata artifact member size changed")
                target = destination / info.filename
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                    | os.O_NOFOLLOW, 0o600)
                digest = hashlib.sha256()
                total = 0
                try:
                    with archive.open(info, "r") as stream:
                        while True:
                            block = stream.read(64 * 1024)
                            if not block:
                                break
                            total += len(block)
                            require(total <= maximum,
                                    "Ubuntu metadata artifact member expanded past its bound")
                            digest.update(block)
                            view = memoryview(block)
                            while view:
                                count = os.write(descriptor, view)
                                require(count > 0,
                                        "Ubuntu metadata artifact extraction stalled")
                                view = view[count:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                if info.filename == MANIFEST_NAME:
                    expected = selection["manifest_sha256"]
                else:
                    expected = by_name[info.filename]["sha256"]
                require(total == info.file_size
                        and digest.hexdigest() == expected,
                        "Ubuntu metadata artifact member digest changed")
            after = os.fstat(zip_descriptor)
            require((zip_identity.st_dev, zip_identity.st_ino,
                     zip_identity.st_mode, zip_identity.st_uid,
                     zip_identity.st_gid, zip_identity.st_nlink,
                     zip_identity.st_size, zip_identity.st_mtime_ns,
                     zip_identity.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_mode,
                        after.st_uid, after.st_gid, after.st_nlink,
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    "Ubuntu metadata artifact ZIP changed during extraction")
    finally:
        os.close(zip_descriptor)
    require(set(os.listdir(destination)) == expected_names(),
            "Ubuntu metadata transfer contains extra members")
    return manifest


def fetch_selected(root, destination, token, *, api_opener=None,
                   download_opener=None):
    # Local import avoids a module cycle: the hosted producer imports this
    # module for discovery and retained production.
    from image.container import ubuntu_fixture_package_hosted as hosted

    root = Path(root).resolve(strict=True)
    contract, lock = hosted.load_contract(root)
    require(contract["state"] == "ready", "Ubuntu metadata source is pending")
    selection = validate_source_selection(
        contract["metadata_source"], pending=False)
    repository = packages.REPOSITORY["full_name"]
    api = "https://api.github.com/repos/" + repository
    run = _api_json(
        api + "/actions/runs/" + str(selection["producer"]["run_id"]),
        token, api_opener)
    artifact = _api_json(
        api + "/actions/artifacts/" + str(selection["artifact"]["id"]),
        token, api_opener)
    validate_github_records(run, artifact, contract)
    redirect = _download_redirect(
        api + "/actions/artifacts/" + str(selection["artifact"]["id"])
        + "/zip", token, api_opener)
    destination = Path(destination)
    require(destination.is_absolute(),
            "Ubuntu metadata transfer destination is not absolute")
    _require_real_directory(
        destination.parent, "Ubuntu metadata transfer parent")
    zip_path = destination.parent / (destination.name + ".zip")
    require(not zip_path.exists(), "Ubuntu metadata transfer ZIP already exists")
    # Retain the exact private ZIP for disposal with the ephemeral runner.
    # Unlinking a pathname after transfer would reopen a same-UID substitution
    # race; production consumes only the separately validated extraction.
    _download_zip(redirect, zip_path, selection, download_opener)
    return extract_selected_zip(zip_path, destination, contract, lock)


def load_selected_directory(directory, contract, lock):
    selection = validate_source_selection(
        contract["metadata_source"], pending=False)
    require(selection["lock_sha256"] == canonical_sha256(lock),
            "Ubuntu metadata selection differs from the current lock")
    directory = Path(directory)
    require(directory.is_absolute(),
            "Ubuntu retained metadata directory is not absolute")
    directory = _require_real_directory(
        directory,
        "Ubuntu retained metadata directory")
    require(set(os.listdir(directory)) == expected_names(),
            "Ubuntu retained metadata directory members changed")
    manifest_info = os.lstat(directory / MANIFEST_NAME)
    require(stat.S_ISREG(manifest_info.st_mode)
            and not (directory / MANIFEST_NAME).is_symlink()
            and manifest_info.st_uid == os.geteuid()
            and manifest_info.st_gid == os.getegid()
            and stat.S_IMODE(manifest_info.st_mode) == 0o600
            and manifest_info.st_nlink == 1,
            "Ubuntu retained metadata manifest identity changed")
    raw = packages.read_bounded_control_file(
        directory, MANIFEST_NAME, "Ubuntu retained metadata manifest",
        MAX_MANIFEST_BYTES)
    require(sha256_bytes(raw) == selection["manifest_sha256"],
            "Ubuntu retained metadata manifest hash changed")
    manifest = validate_manifest(
        packages.unique_json_bytes(raw, MAX_MANIFEST_BYTES),
        workflow=contract["workflow"],
        expected_contract_sha256=selection["discovery_contract_sha256"],
        expected_lock_sha256=selection["lock_sha256"],
        policies=contract["freshness_policy"],
        pins=contract["metadata_pins"], selection=selection)
    paths = {}
    for row in manifest["metadata"]:
        for kind in ("inrelease", "packages_xz"):
            payload = row[kind]
            path = directory / payload["name"]
            info = os.lstat(path)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == os.geteuid()
                    and info.st_gid == os.getegid()
                    and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_size == payload["bytes"],
                    "Ubuntu retained metadata file identity changed")
            descriptor = os.open(
                path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            digest = hashlib.sha256()
            total = 0
            try:
                before = os.fstat(descriptor)
                while True:
                    block = os.read(descriptor, 64 * 1024)
                    if not block:
                        break
                    total += len(block)
                    require(total <= payload["bytes"],
                            "Ubuntu retained metadata file exceeded its bound")
                    digest.update(block)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            require(total == payload["bytes"]
                    and digest.hexdigest() == payload["sha256"]
                    and (before.st_dev, before.st_ino, before.st_mode,
                         before.st_nlink, before.st_size, before.st_mtime_ns,
                         before.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_mode,
                        after.st_nlink, after.st_size, after.st_mtime_ns,
                        after.st_ctime_ns),
                    "Ubuntu retained metadata file digest changed")
            paths[(row["suite"], kind)] = path
    return manifest, paths


def provenance(contract):
    source = validate_source_selection(
        contract["metadata_source"], pending=False)
    return {
        "producer_run_id": source["producer"]["run_id"],
        "producer_run_attempt": source["producer"]["run_attempt"],
        "producer_head_sha": source["producer"]["head_sha"],
        "producer_head_tree": source["producer"]["head_tree"],
        "producer_branch": source["producer"]["branch"],
        "artifact_id": source["artifact"]["id"],
        "artifact_name": source["artifact"]["name"],
        "artifact_bytes": source["artifact"]["bytes"],
        "artifact_api_sha256": source["artifact"]["api_sha256"],
        "artifact_zip_sha256": source["artifact"]["zip_sha256"],
        "manifest_sha256": source["manifest_sha256"],
        "discovery_contract_sha256": source["discovery_contract_sha256"],
        "selection_contract_sha256": canonical_sha256(contract),
        "metadata_lock_sha256": source["lock_sha256"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Transfer the reviewed retained Ubuntu metadata artifact")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    token = os.environ.pop("GITHUB_TOKEN", None)
    try:
        require(isinstance(token, str) and token,
                "repository code requires GITHUB_TOKEN only for retained "
                "metadata transfer")
        manifest = fetch_selected(args.root, args.destination, token)
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError,
            zipfile.BadZipFile) as error:
        parser.exit(1, "Ubuntu retained metadata rejected: " + str(error) + "\n")
    print(json.dumps({
        "state": manifest["state"],
        "selected": False,
        "qualified": False,
        "scope": TRANSFER_SCOPE,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
