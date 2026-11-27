"""Pending anchors and dormant shapes for an Ubuntu fixture package closure.

This module performs no discovery, download, extraction, package installation or
image build.  Only the immutable rootfs, request and source anchors participate
in the pending public check.  The private metadata, package and artifact helpers
are non-authoritative shape checks: they do not verify signatures, freshness,
index membership, solver output, workflow identity or artifact bytes and must
never authorize selection, consumption or a build.
"""
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from urllib.parse import urlsplit


REPOSITORY = {"id": 1472078858, "full_name": "ThirdKeyAI/symbi-os"}
ARTIFACT_NAME = "container-ubuntu-fixture-packages"
ROOTFS_ARCHIVE = "ubuntu-base-24.04.5-base-amd64.tar.gz"
ROOTFS_URL = (
    "https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/"
    + ROOTFS_ARCHIVE
)
ROOTFS_BYTES = 30028293
ROOTFS_SHA256 = "e77b6f10c2590cef872b33ee9f635a0e3fd1f57fb074c0e52b5c7f56147a0c86"
ROOTFS_SIGNER_FINGERPRINT = "843938DF228D22F7B3742BC0D94AA3F0EFE21092"
KEYRING_SHA256 = "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31"
CHECKSUM_SHA256 = "30f23cec3a46679bcf21dbe0c0a0ab51440e9b2f5ac69b3ae1d4a7a71c0ffc69"
CHECKSUM_SIGNATURE_SHA256 = (
    "5164e25bab9ff0467fc83415c8f759bb79cbd4e0264b9a11f49ff1e6a10a4c1f"
)
ARCHIVE_SIGNER_FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
MAX_METADATA_BYTES = 16 * 1024**2
MAX_INDEX_BYTES = 512 * 1024**2
MAX_PACKAGE_BYTES = 1024**3
MAX_PACKAGE_COUNT = 4096
MAX_CLOSURE_BYTES = 4 * 1024**3
MAX_ARTIFACT_BYTES = 2 * 1024**3
MAX_CONTROL_FILE_BYTES = 64 * 1024

ROOTFS_FIELDS = {"archive", "url", "bytes", "sha256", "checksum", "keyring"}
CHECKSUM_FIELDS = {
    "filename", "url", "sha256", "signature_filename", "signature_url",
    "signature_sha256", "signer_fingerprint",
}
KEYRING_FIELDS = {"filename", "sha256"}
REQUEST_FIELDS = {
    "architecture", "component", "suites", "roots", "install_recommends",
}
SOURCE_FIELDS = {
    "base_url", "suite", "component", "architecture", "metadata",
    "packages_url",
}
SOURCE_METADATA_FIELDS = {
    "mode", "inrelease_url", "release_url", "signature_url",
    "signer_fingerprint",
}
RELEASE_FIELDS = {
    "suite", "mode", "inrelease", "release", "signature",
    "signer_fingerprint", "index",
}
PAYLOAD_FIELDS = {"filename", "url", "bytes", "sha256"}
RELEASE_INDEX_FIELDS = {"path", "bytes", "sha256"}
INDEX_FIELDS = {
    "suite", "component", "architecture", "filename", "url", "bytes",
    "sha256",
}
PACKAGE_FIELDS = {
    "package", "version", "architecture", "filename", "url", "bytes",
    "sha256", "source",
}
PACKAGE_SOURCE_FIELDS = {
    "suite", "component", "index_architecture", "index_sha256",
}
CANDIDATE_ARTIFACT_FIELDS = {
    "selected", "id", "name", "bytes", "sha256", "run",
}
CANDIDATE_RUN_FIELDS = {"id", "attempt", "head_sha"}
ARTIFACT_METADATA_FIELDS = {
    "id", "name", "size_in_bytes", "digest", "expired", "workflow_run",
}
ARTIFACT_WORKFLOW_FIELDS = {
    "id", "head_sha", "repository_id", "head_repository_id",
}

EXPECTED_ROOTFS = {
    "archive": ROOTFS_ARCHIVE,
    "url": ROOTFS_URL,
    "bytes": ROOTFS_BYTES,
    "sha256": ROOTFS_SHA256,
    "checksum": {
        "filename": "SHA256SUMS",
        "url": (
            "https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/"
            "SHA256SUMS"
        ),
        "sha256": CHECKSUM_SHA256,
        "signature_filename": "SHA256SUMS.gpg",
        "signature_url": (
            "https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/"
            "SHA256SUMS.gpg"
        ),
        "signature_sha256": CHECKSUM_SIGNATURE_SHA256,
        "signer_fingerprint": ROOTFS_SIGNER_FINGERPRINT,
    },
    "keyring": {
        "filename": "ubuntu-archive-keyring.gpg",
        "sha256": KEYRING_SHA256,
    },
}

EXPECTED_REQUEST = {
    "architecture": "amd64",
    "component": "main",
    "suites": ["noble", "noble-updates", "noble-security"],
    "roots": ["python3", "git", "ca-certificates"],
    "install_recommends": False,
}


def _source(base_url, suite):
    prefix = base_url + "/dists/" + suite
    return {
        "base_url": base_url,
        "suite": suite,
        "component": "main",
        "architecture": "amd64",
        "metadata": {
            "mode": "inrelease",
            "inrelease_url": prefix + "/InRelease",
            "release_url": None,
            "signature_url": None,
            "signer_fingerprint": ARCHIVE_SIGNER_FINGERPRINT,
        },
        "packages_url": prefix + "/main/binary-amd64/Packages.xz",
    }


EXPECTED_SOURCES = [
    _source("https://archive.ubuntu.com/ubuntu", "noble"),
    _source("https://archive.ubuntu.com/ubuntu", "noble-updates"),
    _source("https://security.ubuntu.com/ubuntu", "noble-security"),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_hash(value, length=64):
    return (isinstance(value, str)
            and re.fullmatch(r"[a-f0-9]{" + str(length) + r"}", value)
            is not None)


def full_fingerprint(value):
    return (isinstance(value, str)
            and re.fullmatch(r"[A-F0-9]{40}", value) is not None)


def unique_json_bytes(raw, maximum=MAX_CONTROL_FILE_BYTES):
    require(type(maximum) is int and maximum > 0
            and isinstance(raw, bytes) and 0 < len(raw) <= maximum,
            "Ubuntu fixture JSON is empty or exceeds its byte bound")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate Ubuntu fixture JSON key")
            result[key] = value
        return result

    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=unique,
        parse_float=lambda item: (_ for _ in ()).throw(
            ValueError("noncanonical Ubuntu fixture JSON float")),
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError("noncanonical Ubuntu fixture JSON number")),
    )
    require(isinstance(value, dict), "Ubuntu fixture JSON must be an object")
    return value


def read_bounded_control_file(root, relative_path, description,
                              maximum=MAX_CONTROL_FILE_BYTES):
    """Read from an anchored root fd with O_NOFOLLOW on every path component.

    Descriptor-relative traversal keeps every lookup below the opened root even
    if names are concurrently renamed.  The final file must be a bounded,
    single-link regular file and remain the same inode and size for the read.
    """
    require(type(maximum) is int and maximum > 0
            and isinstance(description, str) and description,
            "Ubuntu fixture control-file bound is invalid")
    name = str(relative_path)
    path = PurePosixPath(name)
    require(name and "\\" not in name and not path.is_absolute()
            and str(path) == name
            and all(part not in ("", ".", "..") for part in path.parts),
            description + " path is unsafe or aliased")
    root_path = Path(root).resolve(strict=True)
    directory_flags = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_fd = os.open(root_path, directory_flags)
    file_fd = None
    try:
        for part in path.parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(path.parts[-1], file_flags, dir_fd=directory_fd)
        stream = os.fdopen(file_fd, "rb")
        file_fd = None
        with stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and 0 < before.st_size <= maximum,
                    description
                    + " must be one bounded direct regular file")
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size == after.st_size
                and before.st_dev == after.st_dev
                and before.st_ino == after.st_ino
                and before.st_mode == after.st_mode
                and before.st_nlink == after.st_nlink == 1
                and before.st_mtime_ns == after.st_mtime_ns
                and before.st_ctime_ns == after.st_ctime_ns,
                description + " changed while reading")
        return raw
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


def unique_json(root, relative_path, maximum=MAX_CONTROL_FILE_BYTES):
    raw = read_bounded_control_file(
        root, relative_path, "Ubuntu fixture JSON", maximum)
    return unique_json_bytes(raw, maximum)


def _safe_filename(value, suffix=None):
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value:
        return False
    if any(part in ("", ".", "..") for part in path.parts):
        return False
    if any(character.isspace() or ord(character) < 33 for character in value):
        return False
    return suffix is None or value.endswith(suffix)


def _canonical_https(value):
    if not isinstance(value, str) or "\\" in value or "%" in value:
        return False
    parsed = urlsplit(value)
    return (parsed.scheme == "https" and parsed.hostname is not None
            and parsed.username is None and parsed.password is None
            and parsed.port is None and not parsed.query and not parsed.fragment
            and parsed.path.startswith("/") and "//" not in parsed.path
            and all(part not in (".", "..") for part in parsed.path.split("/")))


def validate_rootfs(rootfs):
    require(isinstance(rootfs, dict) and set(rootfs) == ROOTFS_FIELDS,
            "Ubuntu Base binding fields changed")
    checksum = rootfs.get("checksum")
    keyring = rootfs.get("keyring")
    require(isinstance(checksum, dict) and set(checksum) == CHECKSUM_FIELDS
            and isinstance(keyring, dict) and set(keyring) == KEYRING_FIELDS,
            "Ubuntu Base signature binding fields changed")
    require(rootfs == EXPECTED_ROOTFS
            and _safe_filename(rootfs["archive"], ".tar.gz")
            and _canonical_https(rootfs["url"])
            and type(rootfs["bytes"]) is int and rootfs["bytes"] > 0
            and exact_hash(rootfs["sha256"])
            and _safe_filename(checksum["filename"])
            and _safe_filename(checksum["signature_filename"])
            and _canonical_https(checksum["url"])
            and _canonical_https(checksum["signature_url"])
            and exact_hash(checksum["sha256"])
            and exact_hash(checksum["signature_sha256"])
            and full_fingerprint(checksum["signer_fingerprint"])
            and _safe_filename(keyring["filename"], ".gpg")
            and exact_hash(keyring["sha256"]),
            "Ubuntu Base immutable anchor changed")
    return rootfs


def validate_request(request):
    require(isinstance(request, dict) and set(request) == REQUEST_FIELDS
            and request == EXPECTED_REQUEST
            and request.get("install_recommends") is False,
            "Ubuntu package request, root order or no-recommends policy changed")
    return request


def validate_sources(sources):
    require(isinstance(sources, list) and len(sources) == len(EXPECTED_SOURCES),
            "Ubuntu package source count changed")
    for source, expected in zip(sources, EXPECTED_SOURCES, strict=True):
        metadata = source.get("metadata") if isinstance(source, dict) else None
        require(isinstance(source, dict) and set(source) == SOURCE_FIELDS
                and isinstance(metadata, dict)
                and set(metadata) == SOURCE_METADATA_FIELDS,
                "Ubuntu package source fields changed")
        require(source == expected
                and _canonical_https(source["base_url"])
                and _canonical_https(source["packages_url"])
                and metadata["mode"] == "inrelease"
                and _canonical_https(metadata["inrelease_url"])
                and metadata["release_url"] is None
                and metadata["signature_url"] is None
                and full_fingerprint(metadata["signer_fingerprint"]),
                "Ubuntu package source, order or metadata mode changed")
    return sources


def _validate_payload(row, expected_filename, expected_url, maximum, description):
    require(isinstance(row, dict) and set(row) == PAYLOAD_FIELDS
            and row.get("filename") == expected_filename
            and _safe_filename(row["filename"])
            and row.get("url") == expected_url and _canonical_https(row["url"])
            and type(row.get("bytes")) is int and 0 < row["bytes"] <= maximum
            and exact_hash(row.get("sha256")),
            description + " is malformed or changed")


def _validate_retained_metadata_shape(releases, indexes, sources):
    """Check a dormant retained shape; do not infer signature or freshness."""
    validate_sources(sources)
    require(isinstance(releases, list) and isinstance(indexes, list)
            and len(releases) == len(sources) == len(indexes),
            "Ubuntu retained metadata count changed")
    index_hashes = {}
    for source, release, index in zip(sources, releases, indexes, strict=True):
        require(isinstance(release, dict) and set(release) == RELEASE_FIELDS,
                "Ubuntu retained release fields changed")
        require(release.get("suite") == source["suite"]
                and release.get("mode") == "inrelease"
                and release.get("release") is None
                and release.get("signature") is None
                and release.get("signer_fingerprint")
                == source["metadata"]["signer_fingerprint"]
                and full_fingerprint(release["signer_fingerprint"]),
                "Ubuntu retained metadata mode or signer field is invalid")
        _validate_payload(
            release.get("inrelease"), source["suite"] + "_InRelease",
            source["metadata"]["inrelease_url"], MAX_METADATA_BYTES,
            "Ubuntu InRelease payload",
        )
        release_index = release.get("index")
        require(isinstance(release_index, dict)
                and set(release_index) == RELEASE_INDEX_FIELDS
                and release_index.get("path")
                == "main/binary-amd64/Packages.xz"
                and type(release_index.get("bytes")) is int
                and 0 < release_index["bytes"] <= MAX_INDEX_BYTES
                and exact_hash(release_index.get("sha256")),
                "Ubuntu retained release has no exact amd64 index reference")
        require(isinstance(index, dict) and set(index) == INDEX_FIELDS
                and index.get("suite") == source["suite"]
                and index.get("component") == "main"
                and index.get("architecture") == "amd64"
                and index.get("filename")
                == source["suite"] + "_main_binary-amd64_Packages.xz"
                and _safe_filename(index["filename"], "_Packages.xz")
                and index.get("url") == source["packages_url"]
                and _canonical_https(index["url"])
                and type(index.get("bytes")) is int
                and 0 < index["bytes"] <= MAX_INDEX_BYTES
                and exact_hash(index.get("sha256"))
                and index["bytes"] == release_index["bytes"]
                and index["sha256"] == release_index["sha256"],
                "Ubuntu amd64 package index is malformed or changed")
        require(index["sha256"] not in index_hashes.values(),
                "Ubuntu package indexes have duplicate identities")
        index_hashes[source["suite"]] = index["sha256"]
    return index_hashes


def package_identity(row):
    if not isinstance(row, dict):
        return ("", "", "", "")
    return (
        row.get("package", ""), row.get("architecture", ""),
        row.get("version", ""), row.get("filename", ""),
    )


def _validate_retained_package_shape(packages, releases, indexes, sources,
                                     expected_count, expected_bytes):
    """Check dormant row consistency, not index membership or solver output."""
    index_hashes = _validate_retained_metadata_shape(
        releases, indexes, sources)
    require(type(expected_count) is int
            and 0 < expected_count <= MAX_PACKAGE_COUNT
            and type(expected_bytes) is int
            and 0 < expected_bytes <= MAX_CLOSURE_BYTES
            and isinstance(packages, list) and len(packages) == expected_count,
            "Ubuntu package closure count or byte bound is invalid")
    require(packages == sorted(packages, key=package_identity),
            "Ubuntu package rows are not in canonical identity order")
    source_by_suite = {source["suite"]: source for source in sources}
    identities, package_names, filenames, urls = set(), set(), set(), set()
    total = 0
    for row in packages:
        source = row.get("source") if isinstance(row, dict) else None
        require(isinstance(row, dict) and set(row) == PACKAGE_FIELDS
                and isinstance(source, dict)
                and set(source) == PACKAGE_SOURCE_FIELDS,
                "Ubuntu package row fields changed")
        name = row.get("package")
        version = row.get("version")
        architecture = row.get("architecture")
        filename = row.get("filename")
        suite = source.get("suite")
        selected_source = source_by_suite.get(suite)
        require(isinstance(name, str)
                and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) is not None
                and isinstance(version, str) and version
                and re.fullmatch(r"[A-Za-z0-9.+:~\-]+", version) is not None
                and architecture in ("amd64", "all")
                and _safe_filename(filename, ".deb")
                and filename.startswith("pool/main/")
                and selected_source is not None
                and row.get("url") == selected_source["base_url"] + "/" + filename
                and _canonical_https(row["url"])
                and type(row.get("bytes")) is int
                and 0 < row["bytes"] <= MAX_PACKAGE_BYTES
                and exact_hash(row.get("sha256"))
                and source.get("component") == "main"
                and source.get("index_architecture") == "amd64"
                and source.get("index_sha256") == index_hashes.get(suite),
                "Ubuntu package row is unsafe or has an invalid index reference")
        identity = (name, version, architecture)
        # This amd64-only shape retains no Debian Multi-Arch declaration, so a
        # package name can resolve to only one all-or-amd64 row.
        require(identity not in identities and name not in package_names
                and filename not in filenames
                and row["url"] not in urls,
                "Ubuntu package closure has a duplicate package identity")
        identities.add(identity)
        package_names.add(name)
        filenames.add(filename)
        urls.add(row["url"])
        total += row["bytes"]
        require(total <= MAX_CLOSURE_BYTES,
                "Ubuntu package closure exceeds its byte bound")
    require(total == expected_bytes,
            "Ubuntu package closure byte total changed")
    require(set(EXPECTED_REQUEST["roots"]).issubset(
                {identity[0] for identity in identities}),
            "Ubuntu package closure omits a requested root")
    return len(packages), total


def _validate_candidate_artifact_shape(candidate):
    """Check a dormant unselected candidate shape; never select it."""
    run = candidate.get("run") if isinstance(candidate, dict) else None
    require(isinstance(candidate, dict)
            and set(candidate) == CANDIDATE_ARTIFACT_FIELDS
            and candidate.get("selected") is False
            and type(candidate.get("id")) is int and candidate["id"] > 0
            and candidate.get("name") == ARTIFACT_NAME
            and type(candidate.get("bytes")) is int
            and 0 < candidate["bytes"] <= MAX_ARTIFACT_BYTES
            and exact_hash(candidate.get("sha256"))
            and isinstance(run, dict) and set(run) == CANDIDATE_RUN_FIELDS
            and type(run.get("id")) is int and run["id"] > 0
            and type(run.get("attempt")) is int and run["attempt"] > 0
            and exact_hash(run.get("head_sha"), 40),
            "Ubuntu package artifact candidate is invalid or selected")
    return candidate


def _validate_artifact_metadata_shape(metadata, candidate):
    """Correlate dormant shapes without authenticating a run or artifact."""
    _validate_candidate_artifact_shape(candidate)
    workflow = metadata.get("workflow_run") if isinstance(metadata, dict) else None
    run = candidate["run"]
    require(isinstance(metadata, dict)
            and set(metadata) == ARTIFACT_METADATA_FIELDS
            and isinstance(workflow, dict)
            and set(workflow) == ARTIFACT_WORKFLOW_FIELDS
            and type(metadata.get("id")) is int and metadata["id"] > 0
            and metadata.get("id") == candidate["id"]
            and metadata.get("name") == candidate["name"]
            and type(metadata.get("size_in_bytes")) is int
            and metadata["size_in_bytes"] > 0
            and metadata.get("size_in_bytes") == candidate["bytes"]
            and metadata.get("digest") == "sha256:" + candidate["sha256"]
            and metadata.get("expired") is False
            and type(workflow.get("id")) is int and workflow["id"] > 0
            and workflow.get("id") == run["id"]
            and workflow.get("head_sha") == run["head_sha"]
            and type(workflow.get("repository_id")) is int
            and type(workflow.get("head_repository_id")) is int
            and workflow.get("repository_id") == REPOSITORY["id"]
            and workflow.get("head_repository_id") == REPOSITORY["id"],
            "Ubuntu package artifact metadata differs from the candidate")
    return metadata
