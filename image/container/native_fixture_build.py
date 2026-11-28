#!/usr/bin/env python3
"""Build the bounded OCI artifact consumed by native fixture qualification.

The hosted fixture job has already authenticated and exercised the image before
this module runs.  This exporter accepts only one Linux/amd64 image from the
local Docker archive.  It preserves exact config and stored layer descriptors
and blobs, verifies each uncompressed layer diff ID, and records provenance
without a qualification claim.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile

from image.atomic.contract import unpack_oci
from image.container.native_fixture_inputs import (
    ARCHIVE_NAME,
    IMAGE_REPOSITORY,
    MANIFEST_SCOPE,
    MAX_MANIFEST_BYTES,
    PRODUCER_WORKFLOW,
    REPOSITORY,
    load_fixture_pin,
    validate_generated_manifest,
)


DOCKER_ARCHIVE_NAME = "fixture-image.docker.tar"
MAX_DOCKER_ARCHIVE_BYTES = 1024**3
MAX_PRODUCED_ARCHIVE_BYTES = 512 * 1024**2
MAX_PRODUCED_OCI_BYTES = 1024**3
MAX_DOCKER_MEMBERS = 1024
MAX_LAYERS = 128
MAX_CONFIG_BYTES = 1024**2
MAX_DOCKER_MANIFEST_BYTES = 1024**2
MAX_INSPECT_BYTES = 4 * 1024**2
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar": False,
    "application/vnd.oci.image.layer.v1.tar+gzip": True,
}
SOURCE_TARGET_ANNOTATION = "org.symbi-os.fixture.source-target.digest"
QUALIFICATION_REFERENCE = IMAGE_REPOSITORY + ":qualification"
MIN_FREE_BEFORE_SAVE = (
    MAX_DOCKER_ARCHIVE_BYTES + MAX_PRODUCED_ARCHIVE_BYTES
    + MAX_PRODUCED_OCI_BYTES + 2 * 1024**3
)
MIN_FREE_AFTER_SAVE = (
    MAX_PRODUCED_ARCHIVE_BYTES + MAX_PRODUCED_OCI_BYTES + 2 * 1024**3
)
PREREQUISITE_FIELDS = {
    "schema", "state", "selected", "built", "qualified",
    "container_qualified", "os_qualified", "release_qualified",
    "signature_qualified", "fixture_source", "limits", "cold_load", "blockers",
    "scope",
}
PREREQUISITE_LIMITS = {
    "compressed_oci_bytes": MAX_PRODUCED_ARCHIVE_BYTES,
    "expanded_oci_bytes": MAX_PRODUCED_OCI_BYTES,
    "manifest_bytes": MAX_MANIFEST_BYTES,
    "producer_cpu": 1,
}
PREREQUISITE_BLOCKERS = [
    "offline-ubuntu-package-selection",
    "fixture-source-alignment",
    "cold-load-by-manifest-digest",
    "artifact-upload-approval",
]
COLD_LOAD_POLICY = {
    "required": True,
    "network": "none",
    "reference": "manifest-digest",
    "repository": IMAGE_REPOSITORY,
    "verified": False,
}
PREREQUISITE_SCOPE = (
    "Native fixture producer remains disabled until authenticated offline "
    "packages, exact source alignment, cold load and upload approval exist"
)
OUTPUT_SCOPE = (
    "Hosted development fixture OCI; native container, OS and release "
    "qualification remain open"
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_hash(value, length=64):
    return (isinstance(value, str)
            and re.fullmatch(r"[a-f0-9]{" + str(length) + r"}", value) is not None)


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def unique_json_bytes(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate producer JSON key")
            result[key] = value
        return result

    return json.loads(
        raw, object_pairs_hook=unique,
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError("noncanonical producer JSON number")),
    )


def _regular(path, maximum, description):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not path.is_symlink() and path.resolve() == path
            and 0 < info.st_size <= maximum,
            description + " must be one bounded direct regular file")
    return info


def _safe_name(name):
    if not isinstance(name, str) or not name:
        return False
    value = PurePosixPath(name)
    return ("\\" not in name and not value.is_absolute() and str(value) == name
            and all(part not in ("", ".", "..") for part in value.parts))


def validate_producer_identity(environment, metadata):
    """Bind output to the active manual hosted run and its repository."""
    require(environment.get("GITHUB_ACTIONS") == "true"
            and environment.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and environment.get("GITHUB_REPOSITORY") == REPOSITORY["full_name"]
            and exact_hash(environment.get("GITHUB_SHA"), 40)
            and re.fullmatch(r"[1-9][0-9]*",
                             environment.get("GITHUB_RUN_ID", "")) is not None
            and re.fullmatch(r"[1-9][0-9]*",
                             environment.get("GITHUB_RUN_ATTEMPT", "")) is not None
            and isinstance(environment.get("GITHUB_REF_NAME"), str)
            and environment["GITHUB_REF_NAME"]
            and not any(character.isspace()
                        for character in environment["GITHUB_REF_NAME"]),
            "native fixture output requires an exact manual hosted identity")
    repository = metadata.get("repository") if isinstance(metadata, dict) else None
    head_repository = (
        metadata.get("head_repository") if isinstance(metadata, dict) else None)
    require(isinstance(repository, dict) and isinstance(head_repository, dict)
            and type(metadata.get("id")) is int
            and metadata["id"] == int(environment["GITHUB_RUN_ID"])
            and type(metadata.get("run_attempt")) is int
            and metadata["run_attempt"]
            == int(environment["GITHUB_RUN_ATTEMPT"])
            and metadata.get("event") == environment["GITHUB_EVENT_NAME"]
            and metadata.get("path") == PRODUCER_WORKFLOW
            and type(metadata.get("workflow_id")) is int
            and metadata["workflow_id"] > 0
            and metadata.get("head_sha") == environment["GITHUB_SHA"]
            and metadata.get("head_branch") == environment["GITHUB_REF_NAME"]
            and metadata.get("status") == "in_progress"
            and metadata.get("conclusion") is None
            and type(repository.get("id")) is int
            and repository["id"] == REPOSITORY["id"]
            and repository.get("full_name") == REPOSITORY["full_name"]
            and type(head_repository.get("id")) is int
            and head_repository["id"] == REPOSITORY["id"]
            and head_repository.get("full_name") == REPOSITORY["full_name"],
            "current native fixture producer metadata changed")
    return {
        "source_commit": environment["GITHUB_SHA"],
        "run_id": int(environment["GITHUB_RUN_ID"]),
        "run_attempt": int(environment["GITHUB_RUN_ATTEMPT"]),
        "workflow_id": metadata["workflow_id"],
    }


def load_producer_metadata(path):
    info = _regular(path, 4 * 1024**2, "producer run metadata")
    raw = Path(path).read_bytes()
    require(len(raw) == info.st_size, "producer run metadata changed while reading")
    value = unique_json_bytes(raw)
    require(isinstance(value, dict), "producer run metadata must be an object")
    return value


def load_image_inspect(path):
    info = _regular(path, MAX_INSPECT_BYTES, "tested image inspection")
    raw = Path(path).read_bytes()
    require(len(raw) == info.st_size,
            "tested image inspection changed while reading")
    value = unique_json_bytes(raw)
    require(isinstance(value, list) and len(value) == 1
            and isinstance(value[0], dict),
            "tested image inspection must contain exactly one image")
    return value[0]


def load_prerequisites(root, fixture_source):
    """Validate the committed fail-closed producer slot."""
    path = Path(root) / "image/container/native-fixture-build.lock.json"
    info = _regular(path, MAX_MANIFEST_BYTES, "native fixture build prerequisite")
    raw = path.read_bytes()
    require(len(raw) == info.st_size,
            "native fixture build prerequisite changed while reading")
    value = unique_json_bytes(raw)
    require(isinstance(value, dict) and set(value) == PREREQUISITE_FIELDS
            and type(value.get("schema")) is int and value["schema"] == 1
            and value.get("state") == "pending"
            and value.get("selected") is False
            and value.get("built") is False
            and value.get("qualified") is False
            and value.get("container_qualified") is False
            and value.get("os_qualified") is False
            and value.get("release_qualified") is False
            and value.get("signature_qualified") is False
            and value.get("fixture_source") == fixture_source
            and value.get("limits") == PREREQUISITE_LIMITS
            and value.get("cold_load") == COLD_LOAD_POLICY
            and value.get("blockers") == PREREQUISITE_BLOCKERS
            and value.get("scope") == PREREQUISITE_SCOPE,
            "native fixture build prerequisite slot changed or made a claim")
    return {"ready": False, "blockers": list(value["blockers"])}


def preflight_fixture_output(root):
    """Fail before image work until package selection and export gates are ready."""
    from image.container import ubuntu_fixture_inputs as package_inputs

    root = Path(root).resolve()
    package_lock = package_inputs.load_lock(root)
    package_status = package_inputs.validate_lock(root, package_lock)
    fixture_source = load_fixture_pin(root)
    prerequisites = load_prerequisites(root, fixture_source)
    blockers = []
    if package_status["ready"] is not True:
        blockers.append(package_status["blocker"])
    if prerequisites["ready"] is not True:
        blockers.extend(prerequisites["blockers"])
    blockers = list(dict.fromkeys(blockers))
    require(not blockers,
            "native fixture producer is blocked: " + ",".join(blockers))
    return {"ready": True, "cold_load": dict(COLD_LOAD_POLICY)}


def _tar_members(stream):
    members = {}
    for row in stream:
        name = (row.name[:-1]
                if row.isdir() and row.name.endswith("/") else row.name)
        require(len(members) < MAX_DOCKER_MEMBERS and name not in members
                and _safe_name(name)
                and not row.pax_headers and not getattr(row, "sparse", None)
                and (row.isfile() or row.isdir()),
                "Docker archive contains an unsafe, duplicate or excessive member")
        row.name = name
        members[name] = row
    return members


def _read_member(stream, row, maximum):
    require(row.isfile() and 0 < row.size <= maximum,
            "Docker archive JSON member is missing or oversized")
    with stream.extractfile(row) as source:
        raw = source.read(maximum + 1)
    require(len(raw) == row.size, "Docker archive member changed while reading")
    return raw


def _member_digest(stream, row):
    require(row.isfile() and 0 < row.size <= MAX_DOCKER_ARCHIVE_BYTES,
            "Docker image layer is missing or oversized")
    checksum = hashlib.sha256()
    count = 0
    with stream.extractfile(row) as source:
        while block := source.read(1024**2):
            count += len(block)
            require(count <= row.size, "Docker image layer grew while reading")
            checksum.update(block)
    require(count == row.size, "Docker image layer was truncated")
    return checksum.hexdigest()


def _descriptor(value, media_types, description, allow_platform=False):
    """Validate one local SHA-256 OCI descriptor without remote transports."""
    require(isinstance(value, dict)
            and {"mediaType", "digest", "size"}.issubset(value)
            and set(value) <= ({"mediaType", "digest", "size", "annotations"}
                               | ({"platform"} if allow_platform else set()))
            and value.get("mediaType") in media_types
            and isinstance(value.get("digest"), str)
            and value["digest"].startswith("sha256:")
            and exact_hash(value["digest"].removeprefix("sha256:"))
            and type(value.get("size")) is int and 0 < value["size"]
            <= MAX_DOCKER_ARCHIVE_BYTES,
            description + " descriptor is malformed or unsupported")
    annotations = value.get("annotations")
    require(annotations is None or (
        isinstance(annotations, dict)
        and all(isinstance(key, str) and key
                and isinstance(item, str)
                for key, item in annotations.items())),
        description + " descriptor annotations are malformed")
    return dict(value)


def _blob_name(value):
    return "blobs/sha256/" + value.removeprefix("sha256:")


def _verified_blob(stream, members, descriptor, maximum, description):
    name = _blob_name(descriptor["digest"])
    row = members.get(name)
    require(row is not None and row.isfile()
            and row.size == descriptor["size"] and row.size <= maximum,
            description + " blob path or size differs from its descriptor")
    require(_member_digest(stream, row) == descriptor["digest"].removeprefix("sha256:"),
            description + " blob differs from its descriptor digest")
    return name, row


def _layer_diff_id(stream, row, compressed, maximum):
    """Hash one bounded layer's uncompressed tar stream without retaining it."""
    checksum = hashlib.sha256()
    count = 0
    try:
        with stream.extractfile(row) as source:
            content = gzip.GzipFile(fileobj=source, mode="rb") if compressed else source
            while block := content.read(1024**2):
                count += len(block)
                require(count <= maximum,
                        "uncompressed Docker layer exceeded its aggregate bound")
                checksum.update(block)
            if compressed:
                content.close()
    except (EOFError, OSError) as error:
        raise ValueError("Docker gzip layer is malformed") from error
    require(count > 0, "Docker layer expanded to an empty payload")
    return "sha256:" + checksum.hexdigest(), count


def inspect_docker_archive(path, initial_target_digest, image_inspect):
    """Validate the exact OCI graph exported by Docker's containerd image store."""
    require(isinstance(initial_target_digest, str)
            and initial_target_digest.startswith("sha256:")
            and exact_hash(initial_target_digest.removeprefix("sha256:")),
            "tested fixture initial target digest is invalid")
    inspected_descriptor = (
        image_inspect.get("Descriptor") if isinstance(image_inspect, dict)
        else None)
    inspected_rootfs = (
        image_inspect.get("RootFS") if isinstance(image_inspect, dict)
        else None)
    require(isinstance(inspected_descriptor, dict)
            and inspected_descriptor.get("digest") == initial_target_digest
            and inspected_descriptor.get("mediaType") == OCI_MANIFEST_MEDIA_TYPE
            and type(inspected_descriptor.get("size")) is int
            and inspected_descriptor["size"] > 0
            and image_inspect.get("Id") == initial_target_digest
            and image_inspect.get("Architecture") == "amd64"
            and image_inspect.get("Os") == "linux"
            and image_inspect.get("RepoDigests") == []
            and isinstance(inspected_rootfs, dict)
            and inspected_rootfs.get("Type") == "layers"
            and isinstance(inspected_rootfs.get("Layers"), list),
            "pre-save fixture inspection differs from the initial OCI target")
    info = _regular(path, MAX_DOCKER_ARCHIVE_BYTES, "Docker image archive")
    initial = (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
               info.st_size, info.st_mtime_ns)
    with tarfile.open(path, "r:") as stream:
        members = _tar_members(stream)
        require("oci-layout" in members and "index.json" in members,
                "Docker archive omitted its OCI layout or index")
        layout = unique_json_bytes(
            _read_member(stream, members["oci-layout"], MAX_DOCKER_MANIFEST_BYTES))
        require(layout == {"imageLayoutVersion": "1.0.0"},
                "Docker archive uses an unsupported OCI layout")
        index = unique_json_bytes(
            _read_member(stream, members["index.json"], MAX_DOCKER_MANIFEST_BYTES))
        require(set(index) in ({"schemaVersion", "manifests"},
                               {"schemaVersion", "mediaType", "manifests"})
                and index.get("schemaVersion") == 2
                and index.get("mediaType", "application/vnd.oci.image.index.v1+json")
                == "application/vnd.oci.image.index.v1+json"
                and isinstance(index.get("manifests"), list)
                and len(index["manifests"]) == 1,
                "Docker archive must select exactly one OCI image manifest")
        initial_descriptor = _descriptor(
            index["manifests"][0], {OCI_MANIFEST_MEDIA_TYPE}, "initial target",
            allow_platform=True)
        platform = initial_descriptor.pop("platform", None)
        require(platform is None or platform == {"architecture": "amd64", "os": "linux"},
                "initial target platform is not Linux/amd64")
        require(initial_descriptor["digest"] == initial_target_digest
                and initial_descriptor["size"] == inspected_descriptor["size"],
                "Docker index target differs from the tested initial target")
        target_name, target_row = _verified_blob(
            stream, members, initial_descriptor,
            MAX_DOCKER_MANIFEST_BYTES, "initial target")
        manifest_raw = _read_member(stream, target_row, MAX_DOCKER_MANIFEST_BYTES)
        manifest = unique_json_bytes(manifest_raw)
        require(set(manifest) in (
            {"schemaVersion", "mediaType", "config", "layers"},
            {"schemaVersion", "mediaType", "config", "layers", "annotations"})
            and manifest.get("schemaVersion") == 2
            and manifest.get("mediaType") == OCI_MANIFEST_MEDIA_TYPE
            and isinstance(manifest.get("layers"), list)
            and 0 < len(manifest["layers"]) <= MAX_LAYERS,
            "initial target is not one supported OCI image manifest")
        annotations = manifest.get("annotations", {})
        require(isinstance(annotations, dict)
                and SOURCE_TARGET_ANNOTATION not in annotations
                and all(isinstance(key, str) and key
                        and isinstance(value, str)
                        for key, value in annotations.items()),
                "initial target annotations are malformed or reserve the source binding")
        config_descriptor = _descriptor(
            manifest.get("config"), {OCI_CONFIG_MEDIA_TYPE}, "config")
        config_name, config_row = _verified_blob(
            stream, members, config_descriptor, MAX_CONFIG_BYTES, "config")
        config_raw = _read_member(stream, config_row, MAX_CONFIG_BYTES)
        config = unique_json_bytes(config_raw)
        rootfs = config.get("rootfs") if isinstance(config, dict) else None
        require(config.get("architecture") == "amd64"
                and config.get("os") == "linux"
                and isinstance(rootfs, dict)
                and set(rootfs) >= {"type", "diff_ids"}
                and rootfs.get("type") == "layers"
                and isinstance(rootfs.get("diff_ids"), list)
                and len(rootfs["diff_ids"]) == len(manifest["layers"])
                and rootfs["diff_ids"] == inspected_rootfs["Layers"]
                and all(isinstance(value, str)
                        and value.startswith("sha256:")
                        and exact_hash(value.removeprefix("sha256:"))
                        for value in rootfs["diff_ids"]),
                "Docker config is not the inspected Linux/amd64 layered image")
        layer_records = []
        uncompressed_total = 0
        for descriptor, expected_diff_id in zip(
                manifest["layers"], rootfs["diff_ids"], strict=True):
            layer_descriptor = _descriptor(
                descriptor, set(OCI_LAYER_MEDIA_TYPES), "layer")
            layer_name, layer_row = _verified_blob(
                stream, members, layer_descriptor,
                MAX_DOCKER_ARCHIVE_BYTES, "layer")
            diff_id, uncompressed_bytes = _layer_diff_id(
                stream, layer_row,
                OCI_LAYER_MEDIA_TYPES[layer_descriptor["mediaType"]],
                MAX_PRODUCED_OCI_BYTES - uncompressed_total)
            require(diff_id == expected_diff_id,
                    "Docker layer differs from its config diff ID")
            uncompressed_total += uncompressed_bytes
            layer_records.append({
                "descriptor": layer_descriptor,
                "source": layer_name,
                "diff_id": diff_id,
                "uncompressed_bytes": uncompressed_bytes,
            })
        identities = {
            initial_target_digest, config_descriptor["digest"],
            *(row["descriptor"]["digest"] for row in layer_records),
        }
        require(initial_target_digest != config_descriptor["digest"],
                "initial target and config identities overlap")
        require(config_descriptor["digest"] not in {
            row["descriptor"]["digest"] for row in layer_records
        }, "config and layer identities overlap")
        referenced = {target_name, config_name}
        referenced.update(row["source"] for row in layer_records)
        blob_members = {
            name for name, row in members.items()
            if row.isfile() and name.startswith("blobs/")
        }
        require(blob_members == referenced,
                "Docker archive contains an unreferenced or missing OCI blob")
        allowed_files = referenced | {
            "oci-layout", "index.json", "manifest.json", "repositories",
        }
        allowed_directories = {"blobs", "blobs/sha256"}
        require(all((row.isfile() and name in allowed_files)
                    or (row.isdir() and name in allowed_directories)
                    for name, row in members.items()),
                "Docker archive contains an unexpected OCI member")
        for name in ("manifest.json", "repositories"):
            if name in members:
                _read_member(stream, members[name], MAX_DOCKER_MANIFEST_BYTES)
        unique_descriptors = {}
        for descriptor in [config_descriptor] + [
                row["descriptor"] for row in layer_records]:
            prior = unique_descriptors.setdefault(
                descriptor["digest"], descriptor)
            require(prior == descriptor,
                    "repeated OCI blob digest changed its descriptor")
        expanded = (
            sum(value["size"] for value in unique_descriptors.values())
            + 2 * MAX_MANIFEST_BYTES + 1024)
        require(expanded <= MAX_PRODUCED_OCI_BYTES,
                "referenced OCI bytes exceed the expanded producer bound")
    final = Path(path).stat()
    require(initial == (
        final.st_dev, final.st_ino, final.st_mode, final.st_nlink,
        final.st_size, final.st_mtime_ns),
        "Docker image archive changed while it was inspected")
    return {
        "initial_target_digest": initial_target_digest,
        "initial_target_media_type": initial_descriptor["mediaType"],
        "config_descriptor": config_descriptor,
        "config_source": config_name,
        "manifest_annotations": dict(annotations),
        "layers": layer_records,
        "expanded_bytes_upper_bound": expanded,
        "identities": identities,
    }


class _BoundedWriter:
    """Stop gzip output before it can exceed the retained compressed bound."""

    def __init__(self, output, maximum):
        self.output = output
        self.maximum = maximum
        self.count = 0

    def write(self, raw):
        require(self.count + len(raw) <= self.maximum,
                "generated OCI archive exceeded its compressed bound")
        written = self.output.write(raw)
        require(written == len(raw), "generated OCI archive write was truncated")
        self.count += written
        return written

    def flush(self):
        return self.output.flush()

    def tell(self):
        return self.count


def _tar_row(name, size=0, directory=False):
    row = tarfile.TarInfo(name)
    row.size = size
    row.mode = 0o700 if directory else 0o600
    row.mtime = 0
    row.uid = row.gid = 0
    row.uname = row.gname = ""
    if directory:
        row.type = tarfile.DIRTYPE
    return row


def _add_bytes(output, name, raw):
    output.addfile(_tar_row(name, len(raw)), io.BytesIO(raw))


def _generated_graph(inspected):
    """Describe the deterministic OCI graph derived from the tested source target."""
    annotations = dict(inspected["manifest_annotations"])
    annotations[SOURCE_TARGET_ANNOTATION] = inspected["initial_target_digest"]
    manifest_raw = canonical({
        "schemaVersion": 2,
        "mediaType": inspected["initial_target_media_type"],
        "config": dict(inspected["config_descriptor"]),
        "layers": [dict(row["descriptor"]) for row in inspected["layers"]],
        "annotations": annotations,
    })
    generated_target_digest = "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
    require(generated_target_digest not in inspected["identities"],
            "initial target, config, layers and generated target identities overlap")
    index_raw = canonical({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": inspected["initial_target_media_type"],
            "digest": generated_target_digest,
            "size": len(manifest_raw),
            "annotations": {
                "org.opencontainers.image.ref.name": QUALIFICATION_REFERENCE,
            },
        }],
    })
    selected = {
        _blob_name(inspected["config_descriptor"]["digest"]):
        inspected["config_source"],
    }
    selected_sizes = {
        _blob_name(inspected["config_descriptor"]["digest"]):
        inspected["config_descriptor"]["size"],
    }
    for row in inspected["layers"]:
        descriptor = row["descriptor"]
        target_name = _blob_name(descriptor["digest"])
        if target_name in selected:
            require(selected_sizes[target_name] == descriptor["size"],
                    "repeated OCI blob identity changed size")
            continue
        selected[target_name] = row["source"]
        selected_sizes[target_name] = descriptor["size"]
    return {
        "layout_raw": b'{"imageLayoutVersion":"1.0.0"}',
        "index_raw": index_raw,
        "manifest_raw": manifest_raw,
        "generated_target_digest": generated_target_digest,
        "selected": selected,
        "selected_sizes": selected_sizes,
    }


def verify_generated_oci(path, inspected, exported):
    """Recheck every generated descriptor, blob and source-target binding."""
    expected = _generated_graph(inspected)
    require(exported == {
        "initial_target_digest": inspected["initial_target_digest"],
        "initial_target_media_type": inspected["initial_target_media_type"],
        "config_digest": inspected["config_descriptor"]["digest"],
        "config_media_type": inspected["config_descriptor"]["mediaType"],
        "generated_target_digest": expected["generated_target_digest"],
        "generated_target_media_type": inspected["initial_target_media_type"],
        "repo_digest": IMAGE_REPOSITORY + "@" + expected["generated_target_digest"],
    }, "generated OCI identity record differs from its exact graph")
    with tarfile.open(path, "r:gz") as stream:
        members = _tar_members(stream)
        generated_name = _blob_name(expected["generated_target_digest"])
        expected_files = {
            "oci-layout", "index.json", generated_name,
            *expected["selected"],
        }
        require(set(members) == expected_files | {"blobs", "blobs/sha256"}
                and members["blobs"].isdir()
                and members["blobs/sha256"].isdir()
                and all(members[name].isfile() for name in expected_files),
                "generated OCI contains an unexpected, missing or mistyped member")
        require(_read_member(
            stream, members["oci-layout"], MAX_DOCKER_MANIFEST_BYTES)
            == expected["layout_raw"]
            and _read_member(
                stream, members["index.json"], MAX_DOCKER_MANIFEST_BYTES)
            == expected["index_raw"]
            and _read_member(
                stream, members[generated_name], MAX_DOCKER_MANIFEST_BYTES)
            == expected["manifest_raw"],
            "generated OCI metadata differs from the deterministic graph")
        require(_member_digest(stream, members[generated_name])
                == expected["generated_target_digest"].removeprefix("sha256:"),
                "generated OCI target digest differs from its blob")
        for target_name, size in expected["selected_sizes"].items():
            row = members[target_name]
            require(row.size == size
                    and _member_digest(stream, row) == target_name.rsplit("/", 1)[1],
                    "generated OCI retained blob differs from its descriptor")
    return {
        "generated_target_digest": expected["generated_target_digest"],
        "config_digest": inspected["config_descriptor"]["digest"],
        "layers": len(inspected["layers"]),
        "blobs": len(expected["selected"]) + 1,
    }


def write_oci_archive(docker_archive, target, inspected):
    """Stream exact source config/layer blobs into one bounded OCI archive."""
    target = Path(target)
    require(not target.exists() and not target.is_symlink()
            and target.parent.is_dir() and target.parent.resolve() == target.parent,
            "OCI destination must be new under a canonical directory")
    graph = _generated_graph(inspected)
    require(
        len(graph["layout_raw"]) + len(graph["index_raw"])
        + len(graph["manifest_raw"]) + sum(graph["selected_sizes"].values())
        <= MAX_PRODUCED_OCI_BYTES,
        "exact referenced OCI bytes exceed the expanded producer bound")
    exported = {
        "initial_target_digest": inspected["initial_target_digest"],
        "initial_target_media_type": inspected["initial_target_media_type"],
        "config_digest": inspected["config_descriptor"]["digest"],
        "config_media_type": inspected["config_descriptor"]["mediaType"],
        "generated_target_digest": graph["generated_target_digest"],
        "generated_target_media_type": inspected["initial_target_media_type"],
        "repo_digest": IMAGE_REPOSITORY + "@" + graph["generated_target_digest"],
    }
    try:
        with tarfile.open(docker_archive, "r:") as source:
            members = _tar_members(source)
            with target.open("xb") as raw_output:
                bounded_output = _BoundedWriter(
                    raw_output, MAX_PRODUCED_ARCHIVE_BYTES)
                with gzip.GzipFile(
                        filename="", mode="wb", compresslevel=1,
                        fileobj=bounded_output, mtime=0) as compressed:
                    with tarfile.open(
                            fileobj=compressed, mode="w|",
                            format=tarfile.USTAR_FORMAT) as output:
                        output.addfile(_tar_row("blobs", directory=True))
                        output.addfile(_tar_row("blobs/sha256", directory=True))
                        _add_bytes(output, "oci-layout", graph["layout_raw"])
                        _add_bytes(output, "index.json", graph["index_raw"])
                        _add_bytes(
                            output, _blob_name(graph["generated_target_digest"]),
                            graph["manifest_raw"])
                        for target_name, source_name in graph["selected"].items():
                            row = members.get(source_name)
                            require(row is not None and row.isfile()
                                    and row.size == graph["selected_sizes"][target_name],
                                    "Docker archive changed before OCI export")
                            with source.extractfile(row) as content:
                                output.addfile(_tar_row(target_name, row.size), content)
        info = _regular(
            target, MAX_PRODUCED_ARCHIVE_BYTES, "generated OCI archive")
        require(info.st_size <= MAX_PRODUCED_ARCHIVE_BYTES,
                "generated OCI archive exceeds its retained bound")
        verify_generated_oci(target, inspected, exported)
        return exported
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def _export_fixture_output(
        root, initial_target_digest, environment=None, available_bytes=None,
        authority_root=None):
    """Create exact upload members after separately reviewed prerequisites."""
    root = Path(root).resolve()
    authority_root = Path(
        root if authority_root is None else authority_root).resolve()
    environment = dict(os.environ if environment is None else environment)
    cache = root / ".cache"
    docker_archive = cache / "container-fixture-work" / DOCKER_ARCHIVE_NAME
    inspect_path = cache / "container-fixture-work/fixture-image-inspect.json"
    metadata_path = (
        authority_root / ".cache/container-fixture-producer-run.json")
    output = cache / "container-native-fixture-output"
    require(cache.is_dir() and not cache.is_symlink() and cache.resolve() == cache,
            "native fixture producer cache is not canonical")
    require(not output.exists() and not output.is_symlink(),
            "native fixture output destination already exists")
    free = shutil.disk_usage(cache).free if available_bytes is None else available_bytes
    require(type(free) is int and free >= MIN_FREE_AFTER_SAVE,
            "native fixture producer lacks bounded output and verification space")
    identity = validate_producer_identity(
        environment, load_producer_metadata(metadata_path))
    fixture_source = load_fixture_pin(authority_root)
    inspected = inspect_docker_archive(
        docker_archive, initial_target_digest, load_image_inspect(inspect_path))
    output.mkdir(mode=0o755)
    archive = output / ARCHIVE_NAME
    verify = output / "verified-oci"
    try:
        exported = write_oci_archive(docker_archive, archive, inspected)
        tested_image = {
            key: exported[key] for key in (
                "initial_target_digest", "initial_target_media_type",
                "config_digest", "config_media_type",
            )
        }
        image = {
            "repository": IMAGE_REPOSITORY,
            **{key: exported[key] for key in (
                "generated_target_digest", "generated_target_media_type",
                "repo_digest",
            )},
        }
        archive_binding = {
            "name": ARCHIVE_NAME,
            "bytes": archive.stat().st_size,
            "sha256": sha256(archive),
        }
        manifest = {
            "schema": 1,
            "built": True,
            "qualified": False,
            "container_qualified": False,
            "os_qualified": False,
            "release_qualified": False,
            "signature_qualified": False,
            "source_commit": identity["source_commit"],
            "producer": {
                "run_id": identity["run_id"],
                "run_attempt": identity["run_attempt"],
                "workflow_id": identity["workflow_id"],
            },
            "fixture_source": fixture_source,
            "archive": archive_binding,
            "tested_image": tested_image,
            "image": image,
            "scope": MANIFEST_SCOPE,
        }
        manifest_raw = (json.dumps(manifest, indent=2) + "\n").encode()
        require(len(manifest_raw) <= MAX_MANIFEST_BYTES,
                "generated fixture manifest is oversized")
        selection = {
            "producer": {
                "run_id": identity["run_id"],
                "run_attempt": identity["run_attempt"],
                "head_sha": identity["source_commit"],
            },
            "workflow": {"id": identity["workflow_id"]},
            "fixture_source": fixture_source,
            "manifest": {
                "sha256": hashlib.sha256(manifest_raw).hexdigest(),
                "archive": archive_binding,
            },
        }
        validate_generated_manifest(manifest, manifest_raw, selection)
        (output / "manifest.json").write_bytes(manifest_raw)
        (output / "manifest.json").chmod(0o644)
        archive.chmod(0o644)
        verified = unpack_oci(
            archive, verify, image["generated_target_digest"],
            tested_image["config_digest"],
            max_bytes=MAX_PRODUCED_OCI_BYTES)
        require(verified.get("root_filesystem_extracted") is False
                and verified.get("config_digest") == tested_image["config_digest"]
                and verified.get("manifest_digest")
                == image["generated_target_digest"],
                "generated OCI failed its independent bounded verification")
        shutil.rmtree(verify)
        require({path.name for path in output.iterdir()}
                == {"manifest.json", ARCHIVE_NAME},
                "native fixture output contains unexpected members")
        return {
            "schema": 1,
            "built": True,
            "qualified": False,
            "container_qualified": False,
            "os_qualified": False,
            "release_qualified": False,
            "signature_qualified": False,
            "source_commit": identity["source_commit"],
            "producer": manifest["producer"],
            "archive": archive_binding,
            "tested_image": manifest["tested_image"],
            "image": manifest["image"],
            "scope": OUTPUT_SCOPE,
        }
    except BaseException:
        shutil.rmtree(output)
        raise


def build_fixture_output(
        root, initial_target_digest, environment=None, available_bytes=None,
        authority_root=None):
    """Fail closed until every committed native producer prerequisite is ready."""
    root = Path(root).resolve()
    authority_root = Path(
        root if authority_root is None else authority_root).resolve()
    preflight_fixture_output(authority_root)
    return _export_fixture_output(
        root, initial_target_digest, environment=environment,
        available_bytes=available_bytes, authority_root=authority_root)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    subparsers.add_parser("preflight")
    export = subparsers.add_parser("export")
    export.add_argument("--initial-target-digest", required=True)
    args = parser.parse_args(argv)
    record = (preflight_fixture_output(args.root) if args.mode == "preflight"
              else build_fixture_output(args.root, args.initial_target_digest))
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
