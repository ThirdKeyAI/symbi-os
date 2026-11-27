"""Authenticate the offline fixture OCI used by native container qualification.

The producer and consumer are deliberately different hosted runs.  A committed
selection binds a producer run and artifact; the current qualification run is
recorded separately while it downloads, validates, and prepares those bytes.
No result from this module is an OS or containment qualification claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tomllib
import zipfile

from image.atomic.contract import unpack_oci


REPOSITORY = {"id": 1472078858, "full_name": "ThirdKeyAI/symbi-os"}
PRODUCER_WORKFLOW = ".github/workflows/container-fixtures.yml"
ARTIFACT_NAME = "container-native-fixture-image"
ARCHIVE_NAME = "symbi-native-fixture.oci.tar.gz"
IMAGE_REPOSITORY = "localhost/symbi-ci/native-fixture"
SELECTION_SCOPE = (
    "Offline native fixture selection; unavailable producer output cannot enter "
    "container qualification"
)
MANIFEST_SCOPE = (
    "Offline fixture image for native matrix execution; container, OS and release "
    "qualification remain open"
)
SELECTOR_FIELDS = {
    "schema", "state", "selected", "qualified", "container_qualified",
    "os_qualified", "release_qualified", "signature_qualified", "repository",
    "workflow", "producer", "artifact", "fixture_source", "manifest", "scope",
}
PRODUCER_FIELDS = {
    "run_id", "run_attempt", "event", "head_sha", "head_branch", "status",
    "conclusion",
}
ARTIFACT_FIELDS = {"id", "name", "bytes", "sha256"}
ARCHIVE_FIELDS = {"name", "bytes", "sha256"}
MANIFEST_BINDING_FIELDS = {"sha256", "archive"}
IMAGE_FIELDS = {"repository", "image_id", "manifest_digest", "repo_digest"}
TESTED_IMAGE_FIELDS = {"descriptor", "config_digest"}
GENERATED_MANIFEST_FIELDS = {
    "schema", "built", "qualified", "container_qualified", "os_qualified",
    "release_qualified", "signature_qualified", "source_commit",
    "producer", "fixture_source", "archive", "tested_image", "image", "scope",
}
MANIFEST_PRODUCER_FIELDS = {"run_id", "run_attempt", "workflow_id"}
FIXTURE_DRIVERS = {
    "test-filesystem-grants.py", "test-source-broker.py", "test-git-source.py",
}
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024**2 + MAX_MANIFEST_BYTES + 1024**2
MAX_ARCHIVE_BYTES = 512 * 1024**2
MAX_OCI_BYTES = 1024**3
MAX_TRANSFER_RECORD_BYTES = 64 * 1024
MAX_PREPARE_RECORD_BYTES = 256 * 1024
PRE_TRANSFER_MARGIN_BYTES = 2 * 1024**3
PRE_TRANSFER_REQUIRED_BYTES = (
    MAX_ARTIFACT_BYTES + MAX_ARCHIVE_BYTES + MAX_OCI_BYTES
    + PRE_TRANSFER_MARGIN_BYTES
)
HOSTED_LIMITS = {
    "memory.max": "1073741824",
    "memory.swap.max": "0",
    "cpu.max": "100000 100000",
    "pids.max": "64",
}
SYSTEMD_RESULT_FIELDS = {
    "LoadState", "Result", "MemoryPeak", "MemorySwapPeak", "ExecMainCode",
    "ExecMainStatus", "ControlGroup", "ActiveState", "SubState",
}
TRANSFER_SCOPE = (
    "Hosted fixture selector and disk gate before exact artifact transfer; no "
    "native containment qualification"
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


def canonical_sha256(value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return hashlib.sha256(raw).hexdigest()


def unique_json_bytes(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate fixture input JSON key")
            result[key] = value
        return result

    value = json.loads(
        raw, object_pairs_hook=unique,
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError("noncanonical fixture input JSON number")),
    )
    require(isinstance(value, dict), "fixture input JSON must be an object")
    return value


def unique_json(path):
    return unique_json_bytes(Path(path).read_bytes())


def absolute_without_dereference(path):
    return Path(os.path.abspath(os.fspath(path)))


def load_fixture_pin(root):
    root = Path(root)
    pin = unique_json(root / "image/container/native-fixture.lock.json")
    runtime = tomllib.loads((root / "upstream/symbiont.toml").read_text())["revision"]
    require(type(pin.get("schema")) is int and pin["schema"] == 1
            and pin.get("qualified") is False
            and pin.get("repository") == "https://github.com/ThirdKeyAI/Symbiont"
            and exact_hash(pin.get("revision"), 40)
            and exact_hash(pin.get("tree"), 40)
            and pin.get("runtime_source_revision") == runtime
            and isinstance(pin.get("drivers"), dict)
            and set(pin["drivers"]) == FIXTURE_DRIVERS
            and all(exact_hash(value) for value in pin["drivers"].values()),
            "reviewed fixture source pin is incomplete")
    return {key: pin[key] for key in ("revision", "tree", "drivers")}


def validate_selection(selection, fixture_source):
    """Validate the exact pending or selected producer slot."""
    require(isinstance(selection, dict) and set(selection) == SELECTOR_FIELDS
            and type(selection.get("schema")) is int and selection["schema"] == 1
            and selection.get("qualified") is False
            and selection.get("container_qualified") is False
            and selection.get("os_qualified") is False
            and selection.get("release_qualified") is False
            and selection.get("signature_qualified") is False
            and selection.get("repository") == REPOSITORY
            and selection.get("fixture_source") == fixture_source
            and selection.get("scope") == SELECTION_SCOPE,
            "native fixture selection fields or claims changed")
    workflow = selection.get("workflow")
    producer = selection.get("producer")
    artifact = selection.get("artifact")
    manifest = selection.get("manifest")
    require(isinstance(workflow, dict) and set(workflow) == {"id", "path"}
            and workflow.get("path") == PRODUCER_WORKFLOW
            and isinstance(producer, dict) and set(producer) == PRODUCER_FIELDS
            and isinstance(artifact, dict) and set(artifact) == ARTIFACT_FIELDS
            and isinstance(manifest, dict) and set(manifest) == MANIFEST_BINDING_FIELDS
            and isinstance(manifest.get("archive"), dict)
            and set(manifest["archive"]) == ARCHIVE_FIELDS,
            "native fixture producer binding fields changed")
    if selection.get("state") == "pending":
        require(selection.get("selected") is False
                and workflow.get("id") is None
                and producer == {
                    "run_id": None, "run_attempt": None,
                    "event": "workflow_dispatch", "head_sha": None,
                    "head_branch": None, "status": "pending", "conclusion": None,
                }
                and artifact == {
                    "id": None, "name": ARTIFACT_NAME,
                    "bytes": None, "sha256": None,
                }
                and manifest == {
                    "sha256": None,
                    "archive": {
                        "name": ARCHIVE_NAME, "bytes": None, "sha256": None,
                    },
                },
                "pending native fixture selection contains invented output")
        return {"ready": False, "blocker": "pending-native-fixture-image"}
    require(selection.get("state") == "selected" and selection.get("selected") is True
            and type(workflow.get("id")) is int and workflow["id"] > 0
            and type(producer.get("run_id")) is int and producer["run_id"] > 0
            and type(producer.get("run_attempt")) is int and producer["run_attempt"] > 0
            and producer.get("event") == "workflow_dispatch"
            and exact_hash(producer.get("head_sha"), 40)
            and isinstance(producer.get("head_branch"), str)
            and producer["head_branch"] and not any(
                character.isspace() for character in producer["head_branch"])
            and producer.get("status") == "completed"
            and producer.get("conclusion") == "success",
            "native fixture producer identity is not an exact success")
    require(type(artifact.get("id")) is int and artifact["id"] > 0
            and artifact.get("name") == ARTIFACT_NAME
            and type(artifact.get("bytes")) is int
            and 0 < artifact["bytes"] <= MAX_ARTIFACT_BYTES
            and exact_hash(artifact.get("sha256")),
            "native fixture artifact identity is invalid")
    archive = manifest["archive"]
    require(exact_hash(manifest.get("sha256"))
            and archive.get("name") == ARCHIVE_NAME
            and type(archive.get("bytes")) is int
            and 0 < archive["bytes"] <= MAX_ARCHIVE_BYTES
            and exact_hash(archive.get("sha256")),
            "native fixture manifest binding is invalid")
    return {"ready": True, "blocker": None}


def validate_producer_metadata(run, selection):
    producer = selection["producer"]
    repository = run.get("repository") if isinstance(run, dict) else None
    head_repository = run.get("head_repository") if isinstance(run, dict) else None
    require(isinstance(repository, dict) and isinstance(head_repository, dict)
            and run.get("id") == producer["run_id"]
            and run.get("run_attempt") == producer["run_attempt"]
            and run.get("event") == producer["event"]
            and run.get("path") == selection["workflow"]["path"]
            and run.get("workflow_id") == selection["workflow"]["id"]
            and run.get("head_sha") == producer["head_sha"]
            and run.get("head_branch") == producer["head_branch"]
            and run.get("status") == producer["status"]
            and run.get("conclusion") == producer["conclusion"]
            and repository.get("id") == REPOSITORY["id"]
            and repository.get("full_name") == REPOSITORY["full_name"]
            and head_repository.get("id") == REPOSITORY["id"]
            and head_repository.get("full_name") == REPOSITORY["full_name"],
            "native fixture producer metadata differs from the selected run")


def validate_artifact_metadata(metadata, selection):
    artifact = selection["artifact"]
    producer = selection["producer"]
    workflow = metadata.get("workflow_run") if isinstance(metadata, dict) else None
    require(isinstance(workflow, dict)
            and metadata.get("id") == artifact["id"]
            and metadata.get("name") == artifact["name"]
            and metadata.get("size_in_bytes") == artifact["bytes"]
            and metadata.get("digest") == "sha256:" + artifact["sha256"]
            and metadata.get("expired") is False
            and workflow.get("id") == producer["run_id"]
            and workflow.get("head_sha") == producer["head_sha"]
            and workflow.get("repository_id") == REPOSITORY["id"]
            and workflow.get("head_repository_id") == REPOSITORY["id"],
            "native fixture artifact metadata differs from the selected bytes")


def retained_producer_metadata(run):
    """Return the exact, compact producer identity kept with intake evidence."""
    return {
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "event": run["event"],
        "workflow_path": run["path"],
        "workflow_id": run["workflow_id"],
        "head_sha": run["head_sha"],
        "head_branch": run["head_branch"],
        "status": run["status"],
        "conclusion": run["conclusion"],
        "repository_id": run["repository"]["id"],
        "repository_full_name": run["repository"]["full_name"],
        "head_repository_id": run["head_repository"]["id"],
        "head_repository_full_name": run["head_repository"]["full_name"],
    }


def retained_artifact_metadata(metadata):
    """Return artifact availability and repository binding retained by the gate."""
    workflow = metadata["workflow_run"]
    return {
        "artifact_id": metadata["id"],
        "name": metadata["name"],
        "bytes": metadata["size_in_bytes"],
        "digest": metadata["digest"],
        "expired": metadata["expired"],
        "workflow_run_id": workflow["id"],
        "head_sha": workflow["head_sha"],
        "repository_id": workflow["repository_id"],
        "head_repository_id": workflow["head_repository_id"],
    }


def _bundle_rows(bundle):
    rows = bundle.infolist()
    expected = {"manifest.json", ARCHIVE_NAME}
    require(len(rows) == 2 and {row.filename for row in rows} == expected,
            "native fixture artifact has unexpected, duplicate or missing members")
    result = {}
    for row in rows:
        path = PurePosixPath(row.filename)
        mode = stat.S_IFMT(row.external_attr >> 16)
        maximum = MAX_MANIFEST_BYTES if row.filename == "manifest.json" else MAX_ARCHIVE_BYTES
        require(not row.flag_bits & 1 and not path.is_absolute()
                and len(path.parts) == 1 and path.parts[0] not in ("", ".", "..")
                and "\\" not in row.filename and not row.is_dir()
                and mode in (0, stat.S_IFREG)
                and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and 0 < row.file_size <= maximum,
                "native fixture artifact contains an unsafe or oversized member")
        result[row.filename] = row
    return result


def _read_member(bundle, row, maximum):
    with bundle.open(row) as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) == row.file_size,
            "native fixture artifact member length changed")
    return raw


def validate_generated_manifest(manifest, manifest_raw, selection):
    archive = manifest.get("archive") if isinstance(manifest, dict) else None
    image = manifest.get("image") if isinstance(manifest, dict) else None
    tested_image = (
        manifest.get("tested_image") if isinstance(manifest, dict) else None)
    producer = manifest.get("producer") if isinstance(manifest, dict) else None
    require(set(manifest) == GENERATED_MANIFEST_FIELDS
            and len(manifest_raw) <= MAX_MANIFEST_BYTES
            and hashlib.sha256(manifest_raw).hexdigest() == selection["manifest"]["sha256"]
            and type(manifest.get("schema")) is int and manifest["schema"] == 1
            and manifest.get("built") is True
            and manifest.get("qualified") is False
            and manifest.get("container_qualified") is False
            and manifest.get("os_qualified") is False
            and manifest.get("release_qualified") is False
            and manifest.get("signature_qualified") is False
            and manifest.get("source_commit") == selection["producer"]["head_sha"]
            and isinstance(producer, dict)
            and set(producer) == MANIFEST_PRODUCER_FIELDS
            and producer == {
                "run_id": selection["producer"]["run_id"],
                "run_attempt": selection["producer"]["run_attempt"],
                "workflow_id": selection["workflow"]["id"],
            }
            and manifest.get("fixture_source") == selection["fixture_source"]
            and isinstance(archive, dict) and set(archive) == ARCHIVE_FIELDS
            and archive == selection["manifest"]["archive"]
            and isinstance(image, dict) and set(image) == IMAGE_FIELDS
            and isinstance(tested_image, dict)
            and set(tested_image) == TESTED_IMAGE_FIELDS
            and isinstance(tested_image.get("descriptor"), str)
            and tested_image["descriptor"].startswith("sha256:")
            and exact_hash(
                tested_image["descriptor"].removeprefix("sha256:"))
            and tested_image.get("config_digest") == image.get("image_id")
            and image.get("repository") == IMAGE_REPOSITORY
            and isinstance(image.get("image_id"), str)
            and image["image_id"].startswith("sha256:")
            and exact_hash(image["image_id"].removeprefix("sha256:"))
            and isinstance(image.get("manifest_digest"), str)
            and image["manifest_digest"].startswith("sha256:")
            and exact_hash(image["manifest_digest"].removeprefix("sha256:"))
            and image.get("repo_digest")
            == IMAGE_REPOSITORY + "@" + image["manifest_digest"]
            and len({
                tested_image["descriptor"],
                image["image_id"],
                image["manifest_digest"],
            }) == 3
            and manifest.get("scope") == MANIFEST_SCOPE,
            "native fixture manifest differs from the selected producer output")
    return image


def _workflow_identity(environment):
    require(environment.get("GITHUB_ACTIONS") == "true"
            and environment.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and environment.get("GITHUB_REPOSITORY") == REPOSITORY["full_name"]
            and exact_hash(environment.get("GITHUB_SHA"), 40)
            and re.fullmatch(r"[1-9][0-9]*", environment.get("GITHUB_RUN_ID", ""))
            and re.fullmatch(r"[1-9][0-9]*", environment.get("GITHUB_RUN_ATTEMPT", "")),
            "native fixture intake requires exact hosted workflow identity")
    return {
        "repository": environment["GITHUB_REPOSITORY"],
        "source_commit": environment["GITHUB_SHA"],
        "run_id": int(environment["GITHUB_RUN_ID"]),
        "run_attempt": int(environment["GITHUB_RUN_ATTEMPT"]),
    }


def validate_hosted_context(environment, euid, group_name, limits, control_group=None):
    identity = _workflow_identity(environment)
    unit = "symbi-fixture-input-%d-%d.service" % (
        identity["run_id"], identity["run_attempt"])
    require(euid != 0 and group_name == unit and limits == HOSTED_LIMITS,
            "unexpected native fixture intake unit or limits")
    identity.update(
        unit=unit,
        control_group=control_group if control_group is not None else "/" + unit,
    )
    return identity


def load_hosted_context():
    relative = Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]
    ).relative_to("/")
    group = Path("/sys/fs/cgroup") / relative
    limits = {name: (group / name).read_text().strip() for name in HOSTED_LIMITS}
    return (validate_hosted_context(
        os.environ, os.geteuid(), group.name, limits, "/" + str(relative)), group)


def _memory_events(raw):
    events = {}
    for line in raw.splitlines() if isinstance(raw, str) else ():
        fields = line.split()
        require(len(fields) == 2 and fields[0] not in events and fields[1].isdigit(),
                "native fixture memory events are malformed")
        events[fields[0]] = fields[1]
    require({"oom", "oom_kill", "oom_group_kill"}.issubset(events)
            and all(events[name] == "0"
                    for name in ("oom", "oom_kill", "oom_group_kill")),
            "native fixture intake observed an OOM event")
    return events


def read_cgroup_final(group):
    return {name: (Path(group) / name).read_text().strip()
            for name in (*HOSTED_LIMITS, "memory.peak", "memory.events", "cpu.stat")}


def validate_cgroup_final(final):
    expected = set(HOSTED_LIMITS) | {"memory.peak", "memory.events", "cpu.stat"}
    require(isinstance(final, dict) and set(final) == expected
            and all(final.get(name) == value for name, value in HOSTED_LIMITS.items())
            and isinstance(final.get("memory.peak"), str)
            and final["memory.peak"].isdigit()
            and int(final["memory.peak"]) <= int(HOSTED_LIMITS["memory.max"]) + 4096
            and isinstance(final.get("cpu.stat"), str) and final["cpu.stat"].strip(),
            "native fixture intake cgroup record changed")
    _memory_events(final["memory.events"])


def validate_systemd_result(path, hosted):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not path.is_symlink() and 0 < info.st_size <= 16384,
            "native fixture systemd result is not a bounded regular file")
    values = {}
    for line in path.read_text().splitlines():
        key, separator, value = line.partition("=")
        require(separator and key in SYSTEMD_RESULT_FIELDS and key not in values,
                "native fixture systemd result is malformed")
        values[key] = value
    require(set(values) == SYSTEMD_RESULT_FIELDS
            and values["LoadState"] == "loaded"
            and values["ActiveState"] == "active" and values["SubState"] == "exited"
            and values["Result"] == "success" and values["ExecMainCode"] == "1"
            and values["ExecMainStatus"] == "0"
            and values["ControlGroup"] == hosted["control_group"]
            and values["MemoryPeak"].isdigit()
            and int(values["MemoryPeak"]) <= int(HOSTED_LIMITS["memory.max"]) + 4096
            and values["MemorySwapPeak"] == "0",
            "native fixture intake unit did not finish cleanly without swap")
    return values


def _evidence_directory(root):
    cache = Path(root) / ".cache"
    require(cache.is_dir() and not cache.is_symlink() and cache.resolve() == cache,
            "native fixture cache must be a direct directory")
    evidence = cache / "container-fixture-native-evidence"
    if evidence.exists() or evidence.is_symlink():
        require(evidence.is_dir() and not evidence.is_symlink()
                and evidence.resolve() == evidence,
                "native fixture evidence path is not a direct directory")
    else:
        evidence.mkdir(mode=0o700)
    return evidence


def _write_record(path, record, maximum=MAX_TRANSFER_RECORD_BYTES):
    raw = (json.dumps(record, indent=2) + "\n").encode()
    require(type(maximum) is int and 0 < len(raw) <= maximum,
            "native fixture evidence exceeded its bound")
    Path(path).write_bytes(raw)


def _fixed_evidence_file(root, name, maximum):
    evidence = Path(root).resolve() / ".cache/container-fixture-native-evidence"
    require(evidence.is_dir() and not evidence.is_symlink()
            and evidence.resolve() == evidence,
            "native fixture evidence path is not a direct directory")
    path = evidence / name
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not path.is_symlink() and path.resolve() == path
            and 0 < info.st_size <= maximum,
            "native fixture evidence is not a bounded direct regular file")
    return path


def prepare_transfer(root, environment=os.environ, available_bytes=None):
    root = Path(root).resolve()
    identity = _workflow_identity(environment)
    evidence = _evidence_directory(root)
    path = evidence / "pre-transfer.json"
    require(not path.exists() and not path.is_symlink(),
            "native fixture pre-transfer evidence already exists")
    selector_path = root / "image/container/native-fixture-image.lock.json"
    available = (shutil.disk_usage(root / ".cache").free
                 if available_bytes is None else available_bytes)
    record = {
        "schema": 1, "phase": "pre-transfer", "passed": False,
        "selected": False, "qualified": False, "container_qualified": False,
        "os_qualified": False, "release_qualified": False,
        "signature_qualified": False, "hosted": identity,
        "selection_sha256": None,
        "disk": {
            "max_artifact_bytes": MAX_ARTIFACT_BYTES,
            "max_archive_bytes": MAX_ARCHIVE_BYTES,
            "max_oci_bytes": MAX_OCI_BYTES,
            "margin_bytes": PRE_TRANSFER_MARGIN_BYTES,
            "required_bytes": PRE_TRANSFER_REQUIRED_BYTES,
            "available_before_transfer": available,
        },
        "transfer": {
            "stage": "selection", "metadata_validated": False,
            "download_complete": False, "exit_code": None,
        },
        "scope": TRANSFER_SCOPE,
    }
    try:
        require(type(available) is int and available >= 0,
                "native fixture available disk record is invalid")
        selection = unique_json(selector_path)
        record["selection_sha256"] = sha256(selector_path)
        status = validate_selection(selection, load_fixture_pin(root))
        if status["ready"] is not True:
            record["blocker"] = status["blocker"]
            raise ValueError(status["blocker"])
        record["selected"] = True
        if available < PRE_TRANSFER_REQUIRED_BYTES:
            record["blocker"] = "insufficient-native-fixture-disk"
            raise ValueError("insufficient-native-fixture-disk")
        record["producer"] = {
            "run_id": selection["producer"]["run_id"],
            "run_attempt": selection["producer"]["run_attempt"],
            "head_sha": selection["producer"]["head_sha"],
            "artifact_id": selection["artifact"]["id"],
        }
        record["passed"] = True
        return (selection["producer"]["run_id"],
                selection["producer"]["run_attempt"], selection["artifact"]["id"])
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        _write_record(path, record)


def _load_transfer_record(root, environment):
    identity = _workflow_identity(environment)
    path = _fixed_evidence_file(root, "pre-transfer.json", MAX_TRANSFER_RECORD_BYTES)
    record = unique_json(path)
    require(type(record.get("schema")) is int and record["schema"] == 1
            and record.get("phase") == "pre-transfer"
            and record.get("hosted") == identity
            and record.get("qualified") is False
            and record.get("container_qualified") is False
            and record.get("os_qualified") is False
            and record.get("release_qualified") is False
            and record.get("signature_qualified") is False,
            "native fixture pre-transfer evidence changed")
    return path, record, identity


def record_transfer_failure(root, environment, stage, exit_code):
    allowed = {
        "selection-output", "run-metadata", "artifact-metadata",
        "metadata-validation", "artifact-download", "download-validation",
    }
    require(stage in allowed and type(exit_code) is int and 0 < exit_code <= 255,
            "native fixture transfer failure record is invalid")
    path, record, _ = _load_transfer_record(root, environment)
    metadata_validated = (record.get("transfer", {}).get("metadata_validated") is True
                          and stage in {"artifact-download", "download-validation"})
    record["passed"] = False
    record["transfer"].update(
        stage=stage, metadata_validated=metadata_validated,
        download_complete=False, exit_code=exit_code)
    record["failure"] = "transfer-failure: " + stage
    _write_record(path, record)


def _fixed_regular_file(root, name, maximum=4 * 1024**2):
    cache = Path(root).resolve() / ".cache"
    require(cache.is_dir() and not cache.is_symlink() and cache.resolve() == cache,
            "native fixture cache must be a direct directory")
    path = cache / name
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not path.is_symlink() and path.resolve() == path
            and 0 < info.st_size <= maximum,
            "native fixture downloaded input is not a direct regular file")
    return path, info


def record_transfer_metadata(root, environment=os.environ):
    root = Path(root).resolve()
    path, record, _ = _load_transfer_record(root, environment)
    selection = unique_json(root / "image/container/native-fixture-image.lock.json")
    try:
        require(record.get("passed") is True and record.get("selected") is True
                and record.get("selection_sha256")
                == sha256(root / "image/container/native-fixture-image.lock.json"),
                "native fixture pre-transfer selection is not ready")
        run_path, _ = _fixed_regular_file(root, "container-native-fixture-run.json")
        artifact_path, _ = _fixed_regular_file(
            root, "container-native-fixture-artifact.json")
        validate_producer_metadata(unique_json(run_path), selection)
        validate_artifact_metadata(unique_json(artifact_path), selection)
        record["transfer"].update(
            stage="metadata-validated", metadata_validated=True,
            download_complete=False, exit_code=None)
        record.pop("failure", None)
    except Exception as error:
        record["passed"] = False
        record["transfer"].update(
            stage="metadata-validation", metadata_validated=False,
            download_complete=False, exit_code=1)
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        _write_record(path, record)


def record_transfer_complete(root, environment=os.environ, available_bytes=None):
    root = Path(root).resolve()
    path, record, _ = _load_transfer_record(root, environment)
    selection = unique_json(root / "image/container/native-fixture-image.lock.json")
    try:
        require(record.get("passed") is True
                and record.get("transfer", {}).get("metadata_validated") is True,
                "native fixture metadata did not pass before artifact download")
        bundle, info = _fixed_regular_file(
            root, "container-native-fixture-image.zip", MAX_ARTIFACT_BYTES)
        require(info.st_size == selection["artifact"]["bytes"]
                and sha256(bundle) == selection["artifact"]["sha256"],
                "native fixture artifact download differs from the selected bytes")
        available = (shutil.disk_usage(root / ".cache").free
                     if available_bytes is None else available_bytes)
        required = (selection["manifest"]["archive"]["bytes"]
                    + MAX_OCI_BYTES + PRE_TRANSFER_MARGIN_BYTES)
        record["disk"].update(
            available_before_extraction=available,
            required_before_extraction=required)
        if type(available) is not int or available < required:
            record["blocker"] = "insufficient-native-fixture-extraction-disk"
            raise ValueError("insufficient-native-fixture-extraction-disk")
        record["transfer"].update(
            stage="artifact-downloaded", metadata_validated=True,
            download_complete=True, exit_code=None)
        record.pop("blocker", None)
        record.pop("failure", None)
    except Exception as error:
        record["passed"] = False
        record["transfer"].update(
            stage="download-validation", download_complete=False, exit_code=1)
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        _write_record(path, record)


def validate_transfer_record(root, selection, hosted):
    root = Path(root)
    record = unique_json(_fixed_evidence_file(
        root, "pre-transfer.json", MAX_TRANSFER_RECORD_BYTES))
    disk = record.get("disk") if isinstance(record, dict) else None
    transfer = record.get("transfer") if isinstance(record, dict) else None
    producer = record.get("producer") if isinstance(record, dict) else None
    expected_fields = {
        "schema", "phase", "passed", "selected", "qualified",
        "container_qualified", "os_qualified", "release_qualified",
        "signature_qualified", "hosted", "selection_sha256", "disk",
        "transfer", "scope", "producer",
    }
    expected_disk = {
        "max_artifact_bytes", "max_archive_bytes", "max_oci_bytes",
        "margin_bytes", "required_bytes", "available_before_transfer",
        "available_before_extraction", "required_before_extraction",
    }
    require(set(record) == expected_fields
            and type(record.get("schema")) is int and record["schema"] == 1
            and record.get("phase") == "pre-transfer"
            and record.get("passed") is True and record.get("selected") is True
            and record.get("qualified") is False
            and record.get("container_qualified") is False
            and record.get("os_qualified") is False
            and record.get("release_qualified") is False
            and record.get("signature_qualified") is False
            and record.get("hosted") == {key: hosted[key] for key in
                                         ("repository", "source_commit", "run_id", "run_attempt")}
            and record.get("selection_sha256")
            == sha256(root / "image/container/native-fixture-image.lock.json")
            and producer == {
                "run_id": selection["producer"]["run_id"],
                "run_attempt": selection["producer"]["run_attempt"],
                "head_sha": selection["producer"]["head_sha"],
                "artifact_id": selection["artifact"]["id"],
            }
            and isinstance(disk, dict) and set(disk) == expected_disk
            and disk.get("max_artifact_bytes") == MAX_ARTIFACT_BYTES
            and disk.get("max_archive_bytes") == MAX_ARCHIVE_BYTES
            and disk.get("max_oci_bytes") == MAX_OCI_BYTES
            and disk.get("margin_bytes") == PRE_TRANSFER_MARGIN_BYTES
            and disk.get("required_bytes") == PRE_TRANSFER_REQUIRED_BYTES
            and type(disk.get("available_before_transfer")) is int
            and disk["available_before_transfer"] >= PRE_TRANSFER_REQUIRED_BYTES
            and disk.get("required_before_extraction")
            == selection["manifest"]["archive"]["bytes"]
            + MAX_OCI_BYTES + PRE_TRANSFER_MARGIN_BYTES
            and type(disk.get("available_before_extraction")) is int
            and disk["available_before_extraction"] >= disk["required_before_extraction"]
            and transfer == {
                "stage": "artifact-downloaded", "metadata_validated": True,
                "download_complete": True, "exit_code": None,
            }
            and record.get("scope") == TRANSFER_SCOPE,
            "native fixture transfer evidence is incomplete or changed")
    return record


def validate_consumer_paths(root, bundle, run_metadata, artifact_metadata,
                            destination, evidence):
    root = Path(root).resolve()
    cache = root / ".cache"
    require(cache.is_dir() and not cache.is_symlink() and cache.resolve() == cache,
            "native fixture cache must be a direct directory")
    expected = {
        "bundle": cache / "container-native-fixture-image.zip",
        "run_metadata": cache / "container-native-fixture-run.json",
        "artifact_metadata": cache / "container-native-fixture-artifact.json",
        "destination": cache / "container-native-fixture-inputs",
        "evidence": cache / "container-fixture-native-evidence",
    }
    supplied = {name: absolute_without_dereference(path) for name, path in {
        "bundle": bundle, "run_metadata": run_metadata,
        "artifact_metadata": artifact_metadata, "destination": destination,
        "evidence": evidence,
    }.items()}
    require(supplied == expected,
            "native fixture consumer paths escaped their fixed cache locations")
    for name in ("bundle", "run_metadata", "artifact_metadata"):
        info = supplied[name].lstat()
        maximum = MAX_ARTIFACT_BYTES if name == "bundle" else 4 * 1024**2
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and not supplied[name].is_symlink()
                and supplied[name].resolve() == supplied[name]
                and 0 < info.st_size <= maximum,
                "native fixture downloaded input is not a direct regular file")
    require(not supplied["destination"].exists()
            and not supplied["destination"].is_symlink(),
            "native fixture destination already exists or is linked")
    require(supplied["evidence"].is_dir()
            and not supplied["evidence"].is_symlink()
            and supplied["evidence"].resolve() == supplied["evidence"],
            "native fixture evidence path is not a direct directory")
    return supplied


def consume_fixture_bundle(bundle_path, selection, run, metadata, destination,
                           fixture_source):
    """Validate and prepare the exact fixture OCI without trusting selector identity."""
    require(validate_selection(selection, fixture_source)["ready"] is True,
            "native fixture image selection is still pending")
    validate_producer_metadata(run, selection)
    validate_artifact_metadata(metadata, selection)
    bundle_path = absolute_without_dereference(bundle_path)
    destination = absolute_without_dereference(destination)
    info = bundle_path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not bundle_path.is_symlink() and bundle_path.resolve() == bundle_path
            and info.st_size == selection["artifact"]["bytes"]
            and sha256(bundle_path) == selection["artifact"]["sha256"],
            "native fixture artifact ZIP differs from the selected digest")
    require(not destination.exists() and not destination.is_symlink()
            and destination.parent.is_dir() and destination.parent.resolve() == destination.parent,
            "use a new regular native fixture input directory")
    initial = bundle_path.stat()
    created = False
    try:
        with zipfile.ZipFile(bundle_path) as bundle:
            rows = _bundle_rows(bundle)
            manifest_raw = _read_member(
                bundle, rows["manifest.json"], MAX_MANIFEST_BYTES)
            manifest = unique_json_bytes(manifest_raw)
            image = validate_generated_manifest(manifest, manifest_raw, selection)
            archive = manifest["archive"]
            require(rows[ARCHIVE_NAME].file_size == archive["bytes"],
                    "native fixture OCI archive length changed")
            destination.mkdir(mode=0o700)
            created = True
            archive_path = destination / ARCHIVE_NAME
            checksum = hashlib.sha256()
            total = pending = 0
            with bundle.open(rows[ARCHIVE_NAME]) as incoming, archive_path.open("xb") as outgoing:
                while chunk := incoming.read(64 * 1024):
                    total += len(chunk)
                    pending += len(chunk)
                    require(total <= archive["bytes"],
                            "native fixture OCI stream exceeded its selected size")
                    checksum.update(chunk)
                    outgoing.write(chunk)
                    if pending >= 16 * 1024**2:
                        outgoing.flush()
                        os.fsync(outgoing.fileno())
                        os.posix_fadvise(outgoing.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                        pending = 0
                outgoing.flush()
                os.fsync(outgoing.fileno())
            require(total == archive["bytes"] and checksum.hexdigest() == archive["sha256"],
                    "native fixture OCI archive content changed")
            archive_path.chmod(0o644)
            (destination / "manifest.json").write_bytes(manifest_raw)
            (destination / "manifest.json").chmod(0o644)
        verify = destination / "verified-oci"
        oci = unpack_oci(
            archive_path, verify, image["manifest_digest"], image["image_id"],
            max_bytes=MAX_OCI_BYTES)
        shutil.rmtree(verify)
        final = bundle_path.stat()
        require((initial.st_dev, initial.st_ino, initial.st_mode, initial.st_nlink,
                 initial.st_size, initial.st_mtime_ns)
                == (final.st_dev, final.st_ino, final.st_mode, final.st_nlink,
                    final.st_size, final.st_mtime_ns),
                "native fixture artifact changed while it was consumed")
        return {
            "manifest": manifest,
            "image": image,
            "oci": oci,
            "producer_metadata": retained_producer_metadata(run),
            "artifact_metadata": retained_artifact_metadata(metadata),
            "selection_canonical_sha256": canonical_sha256(selection),
            "artifact_sha256": selection["artifact"]["sha256"],
            "archive_sha256": archive["sha256"],
        }
    except BaseException:
        if created:
            shutil.rmtree(destination)
        raise


def consume(root, bundle, run_metadata, artifact_metadata, destination, evidence):
    root = Path(root).resolve()
    paths = validate_consumer_paths(
        root, bundle, run_metadata, artifact_metadata, destination, evidence)
    hosted, group = load_hosted_context()
    selector_path = root / "image/container/native-fixture-image.lock.json"
    selection = unique_json(selector_path)
    validate_selection(selection, load_fixture_pin(root))
    transfer = validate_transfer_record(root, selection, hosted)
    record = {
        "schema": 1, "passed": False, "qualified": False,
        "container_qualified": False, "os_qualified": False,
        "release_qualified": False, "signature_qualified": False,
        "selection_sha256": sha256(selector_path),
        "pre_transfer_sha256": sha256(
            root / ".cache/container-fixture-native-evidence/pre-transfer.json"),
        "hosted": hosted, "limits": HOSTED_LIMITS, "transfer": transfer,
        "scope": "Exact fixture OCI intake; native containment qualification remains open",
    }
    prepare_path = paths["evidence"] / "prepare.json"
    require(not prepare_path.exists() and not prepare_path.is_symlink(),
            "native fixture prepare evidence already exists")
    try:
        observed = consume_fixture_bundle(
            paths["bundle"], selection, unique_json(paths["run_metadata"]),
            unique_json(paths["artifact_metadata"]), paths["destination"],
            load_fixture_pin(root))
        require(observed["selection_canonical_sha256"] == canonical_sha256(selection),
                "native fixture selection changed during intake")
        record.update(observed)
        record["cgroup_final"] = read_cgroup_final(group)
        validate_cgroup_final(record["cgroup_final"])
        record["passed"] = True
        return record
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if "cgroup_final" not in record:
            try:
                record["cgroup_final"] = read_cgroup_final(group)
            except Exception as error:
                record["cgroup_failure"] = type(error).__name__ + ": " + str(error)
        _write_record(prepare_path, record, MAX_PREPARE_RECORD_BYTES)


def validate_recorded_hosted(hosted, source_commit):
    fields = {"repository", "source_commit", "run_id", "run_attempt", "unit", "control_group"}
    require(isinstance(hosted, dict) and set(hosted) == fields
            and hosted.get("repository") == REPOSITORY["full_name"]
            and hosted.get("source_commit") == source_commit
            and type(hosted.get("run_id")) is int and hosted["run_id"] > 0
            and type(hosted.get("run_attempt")) is int and hosted["run_attempt"] > 0,
            "prepared native fixture hosted identity changed")
    unit = "symbi-fixture-input-%d-%d.service" % (
        hosted["run_id"], hosted["run_attempt"])
    control = PurePosixPath(hosted.get("control_group", ""))
    require(hosted.get("unit") == unit and control.is_absolute()
            and ".." not in control.parts and control.name == unit,
            "prepared native fixture unit identity changed")


def validate_consumed_fixture(root, source_commit, fixture_source=None,
                              environment=os.environ):
    """Recheck prepared fixture inputs while keeping producer and consumer distinct."""
    root = Path(root).resolve()
    selector_path = root / "image/container/native-fixture-image.lock.json"
    selection = unique_json(selector_path)
    expected_source = load_fixture_pin(root) if fixture_source is None else fixture_source
    status = validate_selection(selection, expected_source)
    selector_hash = sha256(selector_path)
    if status["ready"] is not True:
        return {"ready": False, "blocker": status["blocker"],
                "selector_sha256": selector_hash}
    require(exact_hash(source_commit, 40),
            "prepared native fixture input needs the exact OS source commit")
    current = _workflow_identity(environment)
    require(current["source_commit"] == source_commit,
            "native fixture preflight uses a different consumer source commit")
    run_path, _ = _fixed_regular_file(root, "container-native-fixture-run.json")
    metadata_path, _ = _fixed_regular_file(root, "container-native-fixture-artifact.json")
    run_metadata = unique_json(run_path)
    artifact_metadata = unique_json(metadata_path)
    validate_producer_metadata(run_metadata, selection)
    validate_artifact_metadata(artifact_metadata, selection)
    expected_producer_metadata = retained_producer_metadata(run_metadata)
    expected_artifact_metadata = retained_artifact_metadata(artifact_metadata)
    outer, outer_info = _fixed_regular_file(
        root, "container-native-fixture-image.zip", MAX_ARTIFACT_BYTES)
    require(outer_info.st_size == selection["artifact"]["bytes"]
            and sha256(outer) == selection["artifact"]["sha256"],
            "prepared native fixture artifact ZIP changed")
    destination = root / ".cache/container-native-fixture-inputs"
    require(destination.is_dir() and not destination.is_symlink()
            and destination.resolve() == destination
            and {path.name for path in destination.iterdir()}
            == {"manifest.json", ARCHIVE_NAME},
            "prepared native fixture input directory changed")
    manifest_path = destination / "manifest.json"
    archive_path = destination / ARCHIVE_NAME
    for path, maximum in ((manifest_path, MAX_MANIFEST_BYTES),
                          (archive_path, selection["manifest"]["archive"]["bytes"])):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and not path.is_symlink() and 0 < info.st_size <= maximum,
                "prepared native fixture input is not a bounded direct regular file")
    manifest_raw = manifest_path.read_bytes()
    manifest = unique_json_bytes(manifest_raw)
    image = validate_generated_manifest(manifest, manifest_raw, selection)
    require(sha256(manifest_path) == selection["manifest"]["sha256"]
            and archive_path.stat().st_size == selection["manifest"]["archive"]["bytes"]
            and sha256(archive_path) == selection["manifest"]["archive"]["sha256"],
            "prepared native fixture manifest or OCI changed")
    record = unique_json(_fixed_evidence_file(
        root, "prepare.json", MAX_PREPARE_RECORD_BYTES))
    hosted = record.get("hosted") if isinstance(record, dict) else None
    validate_recorded_hosted(hosted, source_commit)
    require({key: hosted[key] for key in current} == current,
            "prepared native fixture input uses a different consumer run")
    transfer = validate_transfer_record(root, selection, hosted)
    validate_cgroup_final(record.get("cgroup_final"))
    validate_systemd_result(
        root / ".cache/container-fixture-native-evidence/systemd-result.txt", hosted)
    oci = record.get("oci") if isinstance(record, dict) else None
    expected_record_fields = {
        "schema", "passed", "qualified", "container_qualified", "os_qualified",
        "release_qualified", "signature_qualified", "selection_sha256",
        "pre_transfer_sha256", "hosted", "limits", "transfer", "scope",
        "manifest", "image", "oci", "producer_metadata", "artifact_metadata",
        "selection_canonical_sha256", "artifact_sha256", "archive_sha256",
        "cgroup_final",
    }
    require(set(record) == expected_record_fields
            and type(record.get("schema")) is int and record["schema"] == 1
            and record.get("passed") is True
            and record.get("qualified") is False
            and record.get("container_qualified") is False
            and record.get("os_qualified") is False
            and record.get("release_qualified") is False
            and record.get("signature_qualified") is False
            and record.get("selection_sha256") == selector_hash
            and record.get("pre_transfer_sha256")
            == sha256(root / ".cache/container-fixture-native-evidence/pre-transfer.json")
            and record.get("limits") == HOSTED_LIMITS
            and record.get("transfer") == transfer
            and record.get("scope")
            == "Exact fixture OCI intake; native containment qualification remains open"
            and record.get("producer_metadata") == expected_producer_metadata
            and record.get("artifact_metadata") == expected_artifact_metadata
            and record.get("selection_canonical_sha256") == canonical_sha256(selection)
            and record.get("artifact_sha256") == selection["artifact"]["sha256"]
            and record.get("archive_sha256") == selection["manifest"]["archive"]["sha256"]
            and record.get("manifest") == manifest and record.get("image") == image
            and isinstance(oci, dict)
            and set(oci) == {
                "manifest_digest", "config_digest", "blobs", "layers", "bytes",
                "root_filesystem_extracted",
            }
            and oci.get("manifest_digest") == image["manifest_digest"]
            and oci.get("config_digest") == image["image_id"]
            and type(oci.get("blobs")) is int and 3 <= oci["blobs"] <= 4096
            and type(oci.get("layers")) is int and 1 <= oci["layers"] <= 4096
            and type(oci.get("bytes")) is int and 0 < oci["bytes"] <= MAX_OCI_BYTES
            and oci.get("root_filesystem_extracted") is False,
            "prepared native fixture intake record changed")
    return {
        "ready": True, "blocker": None, "selector": selection,
        "selector_sha256": selector_hash, "manifest": manifest,
        "archive_path": archive_path, "image": image,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("pre-transfer")
    subparsers.add_parser("record-transfer-metadata")
    subparsers.add_parser("record-transfer-complete")
    failure = subparsers.add_parser("record-transfer-failure")
    failure.add_argument("--stage", required=True)
    failure.add_argument("--exit-code", type=int, required=True)
    unit = subparsers.add_parser("validate-unit-result")
    unit.add_argument("--result", type=Path, required=True)
    consume_parser = subparsers.add_parser("consume")
    consume_parser.add_argument("--bundle", type=Path, required=True)
    consume_parser.add_argument("--run-metadata", type=Path, required=True)
    consume_parser.add_argument("--artifact-metadata", type=Path, required=True)
    consume_parser.add_argument("--destination", type=Path, required=True)
    consume_parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if arguments.command == "pre-transfer":
        for value in prepare_transfer(root):
            print(value)
        return
    if arguments.command == "record-transfer-failure":
        record_transfer_failure(root, os.environ, arguments.stage, arguments.exit_code)
        return
    if arguments.command == "record-transfer-metadata":
        record_transfer_metadata(root)
        return
    if arguments.command == "record-transfer-complete":
        record_transfer_complete(root)
        return
    if arguments.command == "validate-unit-result":
        record = unique_json(root / ".cache/container-fixture-native-evidence/prepare.json")
        validate_systemd_result(arguments.result, record.get("hosted"))
        return
    consume(
        root, arguments.bundle, arguments.run_metadata, arguments.artifact_metadata,
        arguments.destination, arguments.evidence)


if __name__ == "__main__":
    main()
