"""Pure validators for a future signed Ubuntu fixture package closure.

This module performs no discovery, download, extraction, package installation or
image build.  It validates retained metadata objects supplied by a separate,
reviewed producer.  The committed input lock remains pending and cannot select
or consume an artifact.
"""
import json
from pathlib import PurePosixPath
import re
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
    "signature_verified", "signer_fingerprint", "index",
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


def unique_json_bytes(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate Ubuntu fixture JSON key")
            result[key] = value
        return result

    value = json.loads(
        raw, object_pairs_hook=unique,
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError("noncanonical Ubuntu fixture JSON number")),
    )
    require(isinstance(value, dict), "Ubuntu fixture JSON must be an object")
    return value


def unique_json(path):
    return unique_json_bytes(path.read_bytes())


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
            and request == EXPECTED_REQUEST,
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


def validate_metadata(releases, indexes, sources):
    """Validate signed InRelease records and their exact amd64 package indexes."""
    validate_sources(sources)
    require(isinstance(releases, list) and isinstance(indexes, list)
            and len(releases) == len(sources) == len(indexes),
            "Ubuntu retained metadata count changed")
    index_hashes = {}
    for source, release, index in zip(sources, releases, indexes, strict=True):
        require(isinstance(release, dict) and set(release) == RELEASE_FIELDS,
                "Ubuntu signed-release fields changed")
        require(release.get("suite") == source["suite"]
                and release.get("mode") == "inrelease"
                and release.get("release") is None
                and release.get("signature") is None
                and release.get("signature_verified") is True
                and release.get("signer_fingerprint")
                == source["metadata"]["signer_fingerprint"]
                and full_fingerprint(release["signer_fingerprint"]),
                "Ubuntu metadata signature mode or signer is invalid")
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
                "Ubuntu signed release has no exact amd64 index binding")
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


def validate_packages(packages, releases, indexes, sources, expected_count,
                      expected_bytes):
    """Bind exact package rows to the authenticated binary-amd64 indexes."""
    index_hashes = validate_metadata(releases, indexes, sources)
    require(type(expected_count) is int
            and 0 < expected_count <= MAX_PACKAGE_COUNT
            and type(expected_bytes) is int
            and 0 < expected_bytes <= MAX_CLOSURE_BYTES
            and isinstance(packages, list) and len(packages) == expected_count,
            "Ubuntu package closure count or byte bound is invalid")
    require(packages == sorted(packages, key=package_identity),
            "Ubuntu package rows are not in canonical identity order")
    source_by_suite = {source["suite"]: source for source in sources}
    identities, package_slots, filenames, urls = set(), set(), set(), set()
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
                "Ubuntu package row is unsafe or not from a signed amd64 index")
        identity = (name, version, architecture)
        package_slot = (name, architecture)
        require(identity not in identities and package_slot not in package_slots
                and filename not in filenames
                and row["url"] not in urls,
                "Ubuntu package closure has a duplicate package identity")
        identities.add(identity)
        package_slots.add(package_slot)
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


def validate_candidate_artifact(candidate):
    """Validate an observed artifact candidate without selecting it."""
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


def validate_artifact_metadata(metadata, candidate):
    """Match a retained API subset to an unselected artifact candidate."""
    validate_candidate_artifact(candidate)
    workflow = metadata.get("workflow_run") if isinstance(metadata, dict) else None
    run = candidate["run"]
    require(isinstance(metadata, dict)
            and set(metadata) == ARTIFACT_METADATA_FIELDS
            and isinstance(workflow, dict)
            and set(workflow) == ARTIFACT_WORKFLOW_FIELDS
            and metadata.get("id") == candidate["id"]
            and metadata.get("name") == candidate["name"]
            and metadata.get("size_in_bytes") == candidate["bytes"]
            and metadata.get("digest") == "sha256:" + candidate["sha256"]
            and metadata.get("expired") is False
            and workflow.get("id") == run["id"]
            and workflow.get("head_sha") == run["head_sha"]
            and workflow.get("repository_id") == REPOSITORY["id"]
            and workflow.get("head_repository_id") == REPOSITORY["id"],
            "Ubuntu package artifact metadata differs from the candidate")
    return metadata
