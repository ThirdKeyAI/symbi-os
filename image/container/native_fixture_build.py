#!/usr/bin/env python3
"""Build the bounded OCI artifact consumed by native fixture qualification.

The hosted fixture job has already authenticated and exercised the image before
this module runs.  This exporter accepts only one Linux/amd64 image from the
local Docker archive, converts its exact config and uncompressed layers to OCI,
and records build provenance without making any qualification claim.
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
    "signature_qualified", "fixture_source", "limits", "blockers", "scope",
}
PREREQUISITE_LIMITS = {
    "compressed_oci_bytes": MAX_PRODUCED_ARCHIVE_BYTES,
    "expanded_oci_bytes": MAX_PRODUCED_OCI_BYTES,
    "manifest_bytes": MAX_MANIFEST_BYTES,
    "producer_cpu": 1,
}
PREREQUISITE_BLOCKERS = [
    "offline-ubuntu-package-closure",
    "fixture-source-alignment",
    "cold-load-by-manifest-digest",
    "artifact-upload-approval",
]
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
            and metadata.get("id") == int(environment["GITHUB_RUN_ID"])
            and metadata.get("run_attempt")
            == int(environment["GITHUB_RUN_ATTEMPT"])
            and metadata.get("event") == environment["GITHUB_EVENT_NAME"]
            and metadata.get("path") == PRODUCER_WORKFLOW
            and type(metadata.get("workflow_id")) is int
            and metadata["workflow_id"] > 0
            and metadata.get("head_sha") == environment["GITHUB_SHA"]
            and metadata.get("head_branch") == environment["GITHUB_REF_NAME"]
            and metadata.get("status") == "in_progress"
            and metadata.get("conclusion") is None
            and repository.get("id") == REPOSITORY["id"]
            and repository.get("full_name") == REPOSITORY["full_name"]
            and head_repository.get("id") == REPOSITORY["id"]
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
            and value.get("blockers") == PREREQUISITE_BLOCKERS
            and value.get("scope") == PREREQUISITE_SCOPE,
            "native fixture build prerequisite slot changed or made a claim")
    return {"ready": False, "blockers": list(value["blockers"])}


def _tar_members(stream):
    members = {}
    for row in stream:
        require(len(members) < MAX_DOCKER_MEMBERS and row.name not in members
                and _safe_name(row.name)
                and not row.pax_headers and not getattr(row, "sparse", None)
                and (row.isfile() or row.isdir()),
                "Docker archive contains an unsafe, duplicate or excessive member")
        members[row.name] = row
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


def inspect_docker_archive(path, tested_descriptor, image_inspect):
    """Return exact config and layer descriptors for one Docker image archive."""
    require(isinstance(tested_descriptor, str)
            and tested_descriptor.startswith("sha256:")
            and exact_hash(tested_descriptor.removeprefix("sha256:")),
            "tested fixture descriptor is invalid")
    descriptor = (
        image_inspect.get("Descriptor") if isinstance(image_inspect, dict)
        else None)
    inspected_rootfs = (
        image_inspect.get("RootFS") if isinstance(image_inspect, dict)
        else None)
    require(isinstance(descriptor, dict)
            and descriptor.get("digest") == tested_descriptor
            and image_inspect.get("Id") == tested_descriptor
            and image_inspect.get("Architecture") == "amd64"
            and image_inspect.get("Os") == "linux"
            and image_inspect.get("RepoDigests") == []
            and isinstance(inspected_rootfs, dict)
            and inspected_rootfs.get("Type") == "layers"
            and isinstance(inspected_rootfs.get("Layers"), list),
            "pre-save fixture inspection differs from the tested descriptor")
    info = _regular(path, MAX_DOCKER_ARCHIVE_BYTES, "Docker image archive")
    initial = (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
               info.st_size, info.st_mtime_ns)
    with tarfile.open(path, "r:") as stream:
        members = _tar_members(stream)
        require("manifest.json" in members, "Docker archive omitted manifest.json")
        manifest_raw = _read_member(
            stream, members["manifest.json"], MAX_DOCKER_MANIFEST_BYTES)
        manifest = unique_json_bytes(manifest_raw)
        require(isinstance(manifest, list) and len(manifest) == 1
                and isinstance(manifest[0], dict)
                and set(manifest[0]) == {"Config", "RepoTags", "Layers"},
                "Docker archive must contain exactly one conventional image")
        item = manifest[0]
        config_name = item.get("Config")
        layers = item.get("Layers")
        tags = item.get("RepoTags")
        require(_safe_name(config_name)
                and isinstance(layers, list) and 0 < len(layers) <= MAX_LAYERS
                and len(set(layers)) == len(layers)
                and all(_safe_name(name) for name in layers)
                and (tags is None or (
                    isinstance(tags, list) and len(tags) <= 8
                    and all(isinstance(tag, str) and 0 < len(tag) <= 256
                            for tag in tags))),
                "Docker image manifest fields are malformed")
        require(config_name in members
                and all(name in members for name in layers),
                "Docker archive omits a referenced image member")
        config_raw = _read_member(stream, members[config_name], MAX_CONFIG_BYTES)
        config_digest = "sha256:" + hashlib.sha256(config_raw).hexdigest()
        require(config_digest != tested_descriptor,
                "tested Docker descriptor was confused with the config digest")
        config = unique_json_bytes(config_raw)
        rootfs = config.get("rootfs") if isinstance(config, dict) else None
        require(config.get("architecture") == "amd64"
                and config.get("os") == "linux"
                and isinstance(rootfs, dict)
                and set(rootfs) >= {"type", "diff_ids"}
                and rootfs.get("type") == "layers"
                and isinstance(rootfs.get("diff_ids"), list)
                and len(rootfs["diff_ids"]) == len(layers)
                and rootfs["diff_ids"] == inspected_rootfs["Layers"],
                "Docker config is not one Linux/amd64 layered image")
        layer_records = []
        for name, expected in zip(layers, rootfs["diff_ids"], strict=True):
            digest = _member_digest(stream, members[name])
            require(expected == "sha256:" + digest,
                    "Docker layer differs from its config diff ID")
            layer_records.append({
                "source": name,
                "digest": "sha256:" + digest,
                "size": members[name].size,
            })
        require(config_digest not in {row["digest"] for row in layer_records},
                "Docker config identity aliases an image layer")
        unique_layers = {}
        for row in layer_records:
            previous = unique_layers.setdefault(
                row["digest"], {"size": row["size"], "source": row["source"]})
            require(previous["size"] == row["size"],
                    "repeated Docker layer digest changed size")
        expanded = (
            len(config_raw) + sum(row["size"] for row in unique_layers.values())
            + 2 * MAX_MANIFEST_BYTES + 1024)
        require(expanded <= MAX_PRODUCED_OCI_BYTES,
                "referenced OCI bytes exceed the expanded producer bound")
    final = Path(path).stat()
    require(initial == (
        final.st_dev, final.st_ino, final.st_mode, final.st_nlink,
        final.st_size, final.st_mtime_ns),
        "Docker image archive changed while it was inspected")
    return {
        "tested_descriptor": tested_descriptor,
        "image_id": config_digest,
        "config_name": config_name,
        "config_raw": config_raw,
        "layers": layer_records,
        "expanded_bytes_upper_bound": expanded,
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


def write_oci_archive(docker_archive, target, inspected):
    """Stream exact Docker config/layers into one bounded OCI archive."""
    target = Path(target)
    require(not target.exists() and not target.is_symlink()
            and target.parent.is_dir() and target.parent.resolve() == target.parent,
            "OCI destination must be new under a canonical directory")
    config_raw = inspected["config_raw"]
    layers = [{
        "mediaType": "application/vnd.oci.image.layer.v1.tar",
        "digest": row["digest"],
        "size": row["size"],
    } for row in inspected["layers"]]
    manifest_raw = canonical({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": inspected["image_id"],
            "size": len(config_raw),
        },
        "layers": layers,
    })
    manifest_digest = "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
    require(manifest_digest not in {
        inspected["tested_descriptor"], inspected["image_id"]},
        "tested descriptor, config and generated manifest identities overlap")
    index_raw = canonical({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": manifest_digest,
            "size": len(manifest_raw),
            "annotations": {
                "org.opencontainers.image.ref.name":
                IMAGE_REPOSITORY + ":qualification",
            },
        }],
    })
    selected = {
        "blobs/sha256/" + inspected["image_id"].removeprefix("sha256:"):
        inspected["config_name"],
    }
    selected_sizes = {
        "blobs/sha256/" + inspected["image_id"].removeprefix("sha256:"):
        len(config_raw),
    }
    for row in inspected["layers"]:
        target_name = "blobs/sha256/" + row["digest"].removeprefix("sha256:")
        if target_name in selected:
            require(selected_sizes[target_name] == row["size"],
                    "repeated OCI blob identity changed size")
            continue
        selected[target_name] = row["source"]
        selected_sizes[target_name] = row["size"]
    layout_raw = b'{"imageLayoutVersion":"1.0.0"}'
    require(
        len(layout_raw) + len(index_raw) + len(manifest_raw)
        + sum(selected_sizes.values()) <= MAX_PRODUCED_OCI_BYTES,
        "exact referenced OCI bytes exceed the expanded producer bound")
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
                        _add_bytes(output, "oci-layout", layout_raw)
                        _add_bytes(output, "index.json", index_raw)
                        _add_bytes(
                            output,
                            "blobs/sha256/"
                            + manifest_digest.removeprefix("sha256:"),
                            manifest_raw)
                        for target_name, source_name in selected.items():
                            row = members.get(source_name)
                            require(row is not None and row.isfile(),
                                    "Docker archive changed before OCI export")
                            with source.extractfile(row) as content:
                                output.addfile(_tar_row(target_name, row.size), content)
        info = _regular(
            target, MAX_PRODUCED_ARCHIVE_BYTES, "generated OCI archive")
        require(info.st_size <= MAX_PRODUCED_ARCHIVE_BYTES,
                "generated OCI archive exceeds its retained bound")
        return {
            "tested_descriptor": inspected["tested_descriptor"],
            "image_id": inspected["image_id"],
            "manifest_digest": manifest_digest,
            "repo_digest": IMAGE_REPOSITORY + "@" + manifest_digest,
        }
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def _export_fixture_output(root, image_id, environment=None, available_bytes=None):
    """Create exact upload members after separately reviewed prerequisites."""
    root = Path(root).resolve()
    environment = dict(os.environ if environment is None else environment)
    cache = root / ".cache"
    docker_archive = cache / "container-fixture-work" / DOCKER_ARCHIVE_NAME
    inspect_path = cache / "container-fixture-work/fixture-image-inspect.json"
    metadata_path = cache / "container-fixture-producer-run.json"
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
    fixture_source = load_fixture_pin(root)
    inspected = inspect_docker_archive(
        docker_archive, image_id, load_image_inspect(inspect_path))
    output.mkdir(mode=0o755)
    archive = output / ARCHIVE_NAME
    verify = output / "verified-oci"
    try:
        exported = write_oci_archive(docker_archive, archive, inspected)
        tested_image = {
            "descriptor": exported.pop("tested_descriptor"),
            "config_digest": exported["image_id"],
        }
        image = exported
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
            "image": {
                "repository": IMAGE_REPOSITORY,
                **image,
            },
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
            archive, verify, image["manifest_digest"], image["image_id"],
            max_bytes=MAX_PRODUCED_OCI_BYTES)
        require(verified.get("root_filesystem_extracted") is False
                and verified.get("config_digest") == image["image_id"]
                and verified.get("manifest_digest") == image["manifest_digest"],
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


def build_fixture_output(root, image_id, environment=None, available_bytes=None):
    """Fail closed until every committed native producer prerequisite is ready."""
    root = Path(root).resolve()
    fixture_source = load_fixture_pin(root)
    prerequisites = load_prerequisites(root, fixture_source)
    require(prerequisites["ready"] is True,
            "native fixture producer is blocked: "
            + ",".join(prerequisites["blockers"]))
    return _export_fixture_output(
        root, image_id, environment=environment,
        available_bytes=available_bytes)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    record = build_fixture_output(args.root, args.image_id)
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
