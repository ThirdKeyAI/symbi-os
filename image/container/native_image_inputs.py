"""Authenticate one derived Fedora container-runtime image for native testing.

The committed selection starts as an explicit pending slot.  A successful
hosted producer can be recorded only with its real run, artifact metadata and
generated bundle.  Native qualification consumes that exact selection; it does
not infer identities from a branch name or a self-authored success flag.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import zipfile


REPOSITORY = {"id": 1472078858, "full_name": "ThirdKeyAI/symbi-os"}
PRODUCER_WORKFLOW = ".github/workflows/container-runtime-image.yml"
ARTIFACT_NAME = "container-runtime-development-image"
ARCHIVE_NAME = "symbi-container-runtime-generic.oci.tar.gz"
MANIFEST_SCOPE = (
    "Derived development image with an offline container runtime; "
    "native containment qualification remains open"
)
SELECTION_SCOPE = (
    "Derived development image selection; unavailable hosted output "
    "cannot enter native qualification"
)
SELECTION_FIELDS = {
    "schema", "state", "selected", "qualified", "os_qualified",
    "release_qualified", "signature_qualified", "variant", "repository",
    "workflow", "producer", "artifact", "manifest", "scope",
}
PRODUCER_FIELDS = {
    "run_id", "run_attempt", "event", "head_sha", "head_branch", "status",
    "conclusion",
}
ARTIFACT_FIELDS = {"id", "name", "bytes", "sha256"}
ARCHIVE_FIELDS = {"name", "bytes", "sha256", "image_id", "manifest_digest"}
MANIFEST_FIELDS = {"sha256", "contract_sha256", "archive"}
GENERATED_MANIFEST_FIELDS = {
    "schema", "built", "installed", "qualified", "os_qualified",
    "release_qualified", "signature_qualified", "variant", "source_commit",
    "source_image_commit", "source_image_id", "archive", "contract_sha256",
    "scope",
}
MAX_ARTIFACT_BYTES = 13 * 1024**3
MAX_ARCHIVE_BYTES = 12 * 1024**3
MAX_CONTRACT_BYTES = 4 * 1024**2
PRE_TRANSFER_MARGIN_BYTES = 5 * 1024**3
PRE_TRANSFER_REQUIRED_BYTES = (
    MAX_ARTIFACT_BYTES + MAX_ARCHIVE_BYTES + PRE_TRANSFER_MARGIN_BYTES
)
HOSTED_LIMITS = {
    "memory.max": "1073741824",
    "memory.swap.max": "0",
    "cpu.max": "100000 100000",
    "pids.max": "64",
}
SYSTEMD_RESULT_FIELDS = {
    "LoadState", "Result", "MemoryPeak", "MemorySwapPeak",
    "ExecMainCode", "ExecMainStatus", "ControlGroup", "ActiveState", "SubState",
}
TRANSFER_SCOPE = (
    "Hosted selector and disk gate before exact derived image transfer; "
    "no native containment qualification"
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def absolute_without_dereference(path):
    """Normalize a caller path lexically without following any symlink."""
    return Path(os.path.abspath(os.fspath(path)))


def validate_consumer_paths(root, bundle, run_metadata, artifact_metadata,
                            destination, evidence):
    """Require the fixed cache paths while preserving the paths the caller supplied."""
    root = Path(root).resolve()
    cache = root / ".cache"
    require(cache.is_dir() and not cache.is_symlink() and cache.resolve() == cache,
            "container-runtime cache must be a direct directory")
    expected = {
        "bundle": cache / "container-runtime-development-image.zip",
        "run_metadata": cache / "container-runtime-image-run.json",
        "artifact_metadata": cache / "container-runtime-image-artifact.json",
        "destination": cache / "container-runtime-native-inputs",
        "evidence": cache / "container-runtime-native-evidence",
    }
    supplied = {
        "bundle": absolute_without_dereference(bundle),
        "run_metadata": absolute_without_dereference(run_metadata),
        "artifact_metadata": absolute_without_dereference(artifact_metadata),
        "destination": absolute_without_dereference(destination),
        "evidence": absolute_without_dereference(evidence),
    }
    require(supplied == expected,
            "container-runtime consumer paths escaped their fixed cache locations")
    for name in ("bundle", "run_metadata", "artifact_metadata"):
        path = supplied[name]
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and not path.is_symlink() and path.resolve() == path,
                "container-runtime downloaded input is not a direct regular file")
    require(not supplied["destination"].exists()
            and not supplied["destination"].is_symlink(),
            "container-runtime destination already exists or is linked")
    require(supplied["evidence"].is_dir()
            and not supplied["evidence"].is_symlink()
            and supplied["evidence"].resolve() == supplied["evidence"],
            "container-runtime evidence path is not a direct directory")
    return supplied


def _workflow_identity(environment):
    require(environment.get("GITHUB_ACTIONS") == "true"
            and environment.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and environment.get("GITHUB_REPOSITORY") == REPOSITORY["full_name"]
            and exact_hash(environment.get("GITHUB_SHA"), 40)
            and re.fullmatch(r"[1-9][0-9]*", environment.get("GITHUB_RUN_ID", ""))
            and re.fullmatch(r"[1-9][0-9]*", environment.get("GITHUB_RUN_ATTEMPT", "")),
            "container-runtime intake requires exact hosted workflow identity")
    return {
        "repository": environment["GITHUB_REPOSITORY"],
        "source_commit": environment["GITHUB_SHA"],
        "run_id": int(environment["GITHUB_RUN_ID"]),
        "run_attempt": int(environment["GITHUB_RUN_ATTEMPT"]),
    }


def validate_hosted_context(environment, euid, group_name, limits, control_group=None):
    identity = _workflow_identity(environment)
    unit = "symbi-container-input-%d-%d.service" % (
        identity["run_id"], identity["run_attempt"])
    require(euid != 0 and group_name == unit and limits == HOSTED_LIMITS,
            "unexpected hosted container-runtime intake unit or limits")
    identity.update(
        unit=unit,
        control_group=control_group if control_group is not None else "/" + unit,
    )
    return identity


def validate_recorded_hosted(hosted, source_commit):
    fields = {
        "repository", "source_commit", "run_id", "run_attempt", "unit",
        "control_group",
    }
    require(isinstance(hosted, dict) and set(hosted) == fields
            and hosted.get("repository") == REPOSITORY["full_name"]
            and hosted.get("source_commit") == source_commit
            and type(hosted.get("run_id")) is int and hosted["run_id"] > 0
            and type(hosted.get("run_attempt")) is int and hosted["run_attempt"] > 0,
            "prepared container-runtime hosted identity changed")
    unit = "symbi-container-input-%d-%d.service" % (
        hosted["run_id"], hosted["run_attempt"])
    control = PurePosixPath(hosted.get("control_group", ""))
    require(hosted.get("unit") == unit and control.is_absolute()
            and ".." not in control.parts and control.name == unit,
            "prepared container-runtime unit identity changed")


def load_hosted_context():
    relative = Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]
    ).relative_to("/")
    group = Path("/sys/fs/cgroup") / relative
    limits = {name: (group / name).read_text().strip() for name in HOSTED_LIMITS}
    identity = validate_hosted_context(
        os.environ, os.geteuid(), group.name, limits, "/" + str(relative))
    return identity, group


def _memory_events(raw):
    events = {}
    require(isinstance(raw, str), "container-runtime memory events are missing")
    for line in raw.splitlines():
        fields = line.split()
        require(len(fields) == 2 and fields[0] not in events and fields[1].isdigit(),
                "container-runtime memory events are malformed")
        events[fields[0]] = fields[1]
    require({"oom", "oom_kill", "oom_group_kill"}.issubset(events)
            and all(events[name] == "0"
                    for name in ("oom", "oom_kill", "oom_group_kill")),
            "container-runtime intake observed an OOM event")
    return events


def read_cgroup_final(group):
    return {
        name: (Path(group) / name).read_text().strip()
        for name in (*HOSTED_LIMITS, "memory.peak", "memory.events", "cpu.stat")
    }


def validate_cgroup_final(final):
    expected = set(HOSTED_LIMITS) | {"memory.peak", "memory.events", "cpu.stat"}
    require(isinstance(final, dict) and set(final) == expected
            and all(final.get(name) == value for name, value in HOSTED_LIMITS.items())
            and isinstance(final.get("memory.peak"), str)
            and final["memory.peak"].isdigit()
            and int(final["memory.peak"]) <= int(HOSTED_LIMITS["memory.max"]) + 4096
            and isinstance(final.get("cpu.stat"), str) and final["cpu.stat"].strip(),
            "container-runtime intake cgroup record changed")
    _memory_events(final["memory.events"])


def validate_systemd_result(path, hosted):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not path.is_symlink() and 0 < info.st_size <= 16384,
            "container-runtime systemd result is not a bounded regular file")
    values = {}
    for line in path.read_text().splitlines():
        key, separator, value = line.partition("=")
        require(separator and key in SYSTEMD_RESULT_FIELDS and key not in values,
                "container-runtime systemd result is malformed")
        values[key] = value
    require(set(values) == SYSTEMD_RESULT_FIELDS
            and values["LoadState"] == "loaded"
            and values["ActiveState"] == "active"
            and values["SubState"] == "exited"
            and values["Result"] == "success"
            and values["ExecMainCode"] == "1"
            and values["ExecMainStatus"] == "0"
            and values["ControlGroup"] == hosted["control_group"]
            and values["MemoryPeak"].isdigit()
            and int(values["MemoryPeak"]) <= int(HOSTED_LIMITS["memory.max"]) + 4096
            and values["MemorySwapPeak"] == "0",
            "container-runtime hosted unit did not finish cleanly without swap")
    return values


def _evidence_directory(root):
    cache = Path(root) / ".cache"
    require(cache.is_dir() and not cache.is_symlink() and cache.resolve() == cache,
            "container-runtime cache must be a direct directory")
    evidence = cache / "container-runtime-native-evidence"
    if evidence.exists() or evidence.is_symlink():
        require(evidence.is_dir() and not evidence.is_symlink()
                and evidence.resolve() == evidence,
                "container-runtime evidence path is not a direct directory")
    else:
        evidence.mkdir(mode=0o700)
    return evidence


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
            require(key not in result, "duplicate candidate image JSON key")
            result[key] = value
        return result

    value = json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError("noncanonical candidate image JSON number")),
    )
    require(isinstance(value, dict), "candidate image JSON must be an object")
    return value


def unique_json(path):
    return unique_json_bytes(Path(path).read_bytes())


def _write_transfer_record(path, record):
    raw = (json.dumps(record, indent=2) + "\n").encode()
    require(len(raw) <= 65536, "container-runtime transfer evidence exceeded its bound")
    Path(path).write_bytes(raw)


def _load_transfer_record(root, environment):
    identity = _workflow_identity(environment)
    path = _evidence_directory(root) / "pre-transfer.json"
    require(path.is_file() and not path.is_symlink()
            and 0 < path.stat().st_size <= 65536,
            "container-runtime pre-transfer evidence is not bounded")
    record = unique_json(path)
    hosted = record.get("hosted") if isinstance(record, dict) else None
    require(isinstance(hosted, dict)
            and hosted == identity
            and record.get("schema") == 1
            and record.get("phase") == "pre-transfer"
            and record.get("qualified") is False
            and record.get("os_qualified") is False
            and record.get("release_qualified") is False
            and record.get("signature_qualified") is False,
            "container-runtime pre-transfer evidence changed")
    return path, record, identity


def prepare_transfer(root, environment=os.environ, available_bytes=None):
    """Validate the selector and disk budget before any metadata or artifact transfer."""
    root = Path(root).resolve()
    identity = _workflow_identity(environment)
    evidence = _evidence_directory(root)
    path = evidence / "pre-transfer.json"
    require(not path.exists() and not path.is_symlink(),
            "container-runtime pre-transfer evidence already exists")
    selection_path = root / "image/container/fedora-runtime-image.lock.json"
    available = (shutil.disk_usage(root / ".cache").free
                 if available_bytes is None else available_bytes)
    record = {
        "schema": 1,
        "phase": "pre-transfer",
        "passed": False,
        "selected": False,
        "qualified": False,
        "os_qualified": False,
        "release_qualified": False,
        "signature_qualified": False,
        "variant": "generic",
        "hosted": identity,
        "selection_sha256": None,
        "disk": {
            "max_artifact_bytes": MAX_ARTIFACT_BYTES,
            "max_archive_bytes": MAX_ARCHIVE_BYTES,
            "margin_bytes": PRE_TRANSFER_MARGIN_BYTES,
            "required_bytes": PRE_TRANSFER_REQUIRED_BYTES,
            "available_before_transfer": available,
        },
        "transfer": {
            "stage": "selection",
            "metadata_validated": False,
            "download_complete": False,
            "exit_code": None,
        },
        "scope": TRANSFER_SCOPE,
    }
    try:
        require(type(available) is int and available >= 0,
                "container-runtime available disk record is invalid")
        selection = unique_json(selection_path)
        record["selection_sha256"] = sha256(selection_path)
        status = validate_candidate_selection(selection)
        if status["ready"] is not True:
            record["blocker"] = status["blocker"]
            raise ValueError(status["blocker"])
        record["selected"] = True
        if available < PRE_TRANSFER_REQUIRED_BYTES:
            record["blocker"] = "insufficient-container-runtime-disk"
            raise ValueError("insufficient-container-runtime-disk")
        record["producer"] = {
            "run_id": selection["producer"]["run_id"],
            "run_attempt": selection["producer"]["run_attempt"],
            "head_sha": selection["producer"]["head_sha"],
            "artifact_id": selection["artifact"]["id"],
        }
        record["passed"] = True
        return (
            selection["producer"]["run_id"],
            selection["producer"]["run_attempt"],
            selection["artifact"]["id"],
        )
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        _write_transfer_record(path, record)


def record_transfer_failure(root, environment, stage, exit_code):
    allowed = {
        "selection-output", "run-metadata", "artifact-metadata",
        "metadata-validation", "artifact-download", "download-validation",
    }
    require(stage in allowed and type(exit_code) is int and 0 < exit_code <= 255,
            "container-runtime transfer failure record is invalid")
    path, record, _ = _load_transfer_record(root, environment)
    metadata_validated = (
        record.get("transfer", {}).get("metadata_validated") is True
        and stage in {"artifact-download", "download-validation"}
    )
    record["passed"] = False
    record["transfer"].update(
        stage=stage, metadata_validated=metadata_validated,
        download_complete=False, exit_code=exit_code)
    record["failure"] = "transfer-failure: " + stage
    _write_transfer_record(path, record)


def record_transfer_metadata(root, environment=os.environ):
    root = Path(root).resolve()
    path, record, _ = _load_transfer_record(root, environment)
    selection = unique_json(root / "image/container/fedora-runtime-image.lock.json")
    try:
        require(record.get("passed") is True and record.get("selected") is True
                and record.get("selection_sha256")
                == sha256(root / "image/container/fedora-runtime-image.lock.json"),
                "container-runtime pre-transfer selection is not ready")
        validate_producer_metadata(
            unique_json(root / ".cache/container-runtime-image-run.json"), selection)
        validate_artifact_metadata(
            unique_json(root / ".cache/container-runtime-image-artifact.json"), selection)
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
        _write_transfer_record(path, record)


def record_transfer_complete(root, environment=os.environ, available_bytes=None):
    root = Path(root).resolve()
    path, record, _ = _load_transfer_record(root, environment)
    selection = unique_json(root / "image/container/fedora-runtime-image.lock.json")
    bundle = root / ".cache/container-runtime-development-image.zip"
    try:
        require(record.get("passed") is True
                and record.get("transfer", {}).get("metadata_validated") is True,
                "container-runtime metadata did not pass before artifact download")
        info = bundle.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and not bundle.is_symlink() and bundle.resolve() == bundle
                and info.st_size == selection["artifact"]["bytes"],
                "container-runtime artifact download has the wrong size or path")
        available = (shutil.disk_usage(root / ".cache").free
                     if available_bytes is None else available_bytes)
        required = selection["manifest"]["archive"]["bytes"] + PRE_TRANSFER_MARGIN_BYTES
        record["disk"].update(
            available_before_extraction=available,
            required_before_extraction=required)
        require(type(available) is int and available >= required,
                "insufficient-container-runtime-extraction-disk")
        record["transfer"].update(
            stage="artifact-downloaded", metadata_validated=True,
            download_complete=True, exit_code=None)
        record.pop("failure", None)
    except Exception as error:
        record["passed"] = False
        record["transfer"].update(
            stage="download-validation", download_complete=False, exit_code=1)
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        _write_transfer_record(path, record)


def validate_transfer_record(root, selection, hosted):
    root = Path(root)
    path = root / ".cache/container-runtime-native-evidence/pre-transfer.json"
    require(path.is_file() and not path.is_symlink()
            and 0 < path.stat().st_size <= 65536,
            "container-runtime pre-transfer evidence is not bounded")
    record = unique_json(path)
    disk = record.get("disk") if isinstance(record, dict) else None
    transfer = record.get("transfer") if isinstance(record, dict) else None
    producer = record.get("producer") if isinstance(record, dict) else None
    expected_fields = {
        "schema", "phase", "passed", "selected", "qualified", "os_qualified",
        "release_qualified", "signature_qualified", "variant", "hosted",
        "selection_sha256", "disk", "transfer", "scope", "producer",
    }
    require(set(record) == expected_fields
            and record.get("schema") == 1 and record.get("phase") == "pre-transfer"
            and record.get("passed") is True and record.get("selected") is True
            and record.get("qualified") is False and record.get("os_qualified") is False
            and record.get("release_qualified") is False
            and record.get("signature_qualified") is False
            and record.get("variant") == "generic"
            and record.get("hosted") == {key: hosted[key] for key in
                                         ("repository", "source_commit", "run_id", "run_attempt")}
            and record.get("selection_sha256")
            == sha256(root / "image/container/fedora-runtime-image.lock.json")
            and producer == {
                "run_id": selection["producer"]["run_id"],
                "run_attempt": selection["producer"]["run_attempt"],
                "head_sha": selection["producer"]["head_sha"],
                "artifact_id": selection["artifact"]["id"],
            }
            and isinstance(disk, dict)
            and disk.get("max_artifact_bytes") == MAX_ARTIFACT_BYTES
            and disk.get("max_archive_bytes") == MAX_ARCHIVE_BYTES
            and disk.get("margin_bytes") == PRE_TRANSFER_MARGIN_BYTES
            and disk.get("required_bytes") == PRE_TRANSFER_REQUIRED_BYTES
            and type(disk.get("available_before_transfer")) is int
            and disk["available_before_transfer"] >= PRE_TRANSFER_REQUIRED_BYTES
            and disk.get("required_before_extraction")
            == selection["manifest"]["archive"]["bytes"] + PRE_TRANSFER_MARGIN_BYTES
            and type(disk.get("available_before_extraction")) is int
            and disk["available_before_extraction"] >= disk["required_before_extraction"]
            and transfer == {
                "stage": "artifact-downloaded", "metadata_validated": True,
                "download_complete": True, "exit_code": None,
            }
            and record.get("scope") == TRANSFER_SCOPE,
            "container-runtime pre-transfer evidence is incomplete or changed")
    return record


def _pending_fields(selection):
    archive = selection["manifest"]["archive"]
    return (
        selection["workflow"]["id"] is None
        and selection["producer"] == {
            "run_id": None,
            "run_attempt": None,
            "event": "workflow_dispatch",
            "head_sha": None,
            "head_branch": None,
            "status": "pending",
            "conclusion": None,
        }
        and selection["artifact"] == {
            "id": None,
            "name": ARTIFACT_NAME,
            "bytes": None,
            "sha256": None,
        }
        and selection["manifest"] == {
            "sha256": None,
            "contract_sha256": None,
            "archive": {
                "name": ARCHIVE_NAME,
                "bytes": None,
                "sha256": None,
                "image_id": None,
                "manifest_digest": None,
            },
        }
        and archive["name"] == ARCHIVE_NAME
    )


def validate_candidate_selection(selection):
    """Validate the committed pending or exact selected producer slot."""
    require(isinstance(selection, dict) and set(selection) == SELECTION_FIELDS,
            "container-runtime image selection fields changed")
    require(type(selection.get("schema")) is int and selection["schema"] == 1
            and selection.get("qualified") is False
            and selection.get("os_qualified") is False
            and selection.get("release_qualified") is False
            and selection.get("signature_qualified") is False
            and selection.get("variant") == "generic"
            and selection.get("repository") == REPOSITORY
            and selection.get("scope") == SELECTION_SCOPE,
            "container-runtime image selection claims changed")
    workflow = selection.get("workflow")
    producer = selection.get("producer")
    artifact = selection.get("artifact")
    manifest = selection.get("manifest")
    require(isinstance(workflow, dict) and set(workflow) == {"id", "path"}
            and workflow.get("path") == PRODUCER_WORKFLOW
            and isinstance(producer, dict) and set(producer) == PRODUCER_FIELDS
            and isinstance(artifact, dict) and set(artifact) == ARTIFACT_FIELDS
            and isinstance(manifest, dict) and set(manifest) == MANIFEST_FIELDS
            and isinstance(manifest.get("archive"), dict)
            and set(manifest["archive"]) == ARCHIVE_FIELDS,
            "container-runtime image producer binding fields changed")
    if selection.get("state") == "pending":
        require(selection.get("selected") is False and _pending_fields(selection),
                "pending container-runtime image slot contains invented output")
        return {"ready": False, "blocker": "pending-container-runtime-image"}
    require(selection.get("state") == "selected" and selection.get("selected") is True,
            "container-runtime image selection state is invalid")
    require(type(workflow.get("id")) is int and workflow["id"] > 0
            and type(producer.get("run_id")) is int and producer["run_id"] > 0
            and type(producer.get("run_attempt")) is int and producer["run_attempt"] > 0
            and producer.get("event") == "workflow_dispatch"
            and exact_hash(producer.get("head_sha"), 40)
            and isinstance(producer.get("head_branch"), str)
            and producer["head_branch"] and not any(ch.isspace() for ch in producer["head_branch"])
            and producer.get("status") == "completed"
            and producer.get("conclusion") == "success",
            "container-runtime image producer identity is not an exact success")
    require(type(artifact.get("id")) is int and artifact["id"] > 0
            and artifact.get("name") == ARTIFACT_NAME
            and type(artifact.get("bytes")) is int
            and 0 < artifact["bytes"] <= MAX_ARTIFACT_BYTES
            and exact_hash(artifact.get("sha256")),
            "container-runtime image artifact identity is invalid")
    archive = manifest["archive"]
    require(exact_hash(manifest.get("sha256"))
            and exact_hash(manifest.get("contract_sha256"))
            and archive.get("name") == ARCHIVE_NAME
            and type(archive.get("bytes")) is int
            and 0 < archive["bytes"] <= MAX_ARCHIVE_BYTES
            and exact_hash(archive.get("sha256"))
            and isinstance(archive.get("image_id"), str)
            and archive["image_id"].startswith("sha256:")
            and exact_hash(archive["image_id"].removeprefix("sha256:"))
            and isinstance(archive.get("manifest_digest"), str)
            and archive["manifest_digest"].startswith("sha256:")
            and exact_hash(archive["manifest_digest"].removeprefix("sha256:")),
            "container-runtime generated manifest selection is invalid")
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
            "container-runtime producer metadata differs from the selected run")


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
            "container-runtime artifact metadata differs from the selected bytes")


def _bundle_rows(bundle):
    rows = bundle.infolist()
    expected = {"manifest.json", "fedora-runtime.lock.json", ARCHIVE_NAME}
    require(len(rows) == 3 and {row.filename for row in rows} == expected,
            "container-runtime artifact has unexpected, duplicate or missing members")
    result = {}
    for row in rows:
        path = PurePosixPath(row.filename)
        mode = stat.S_IFMT(row.external_attr >> 16)
        maximum = (65536 if row.filename == "manifest.json" else
                   MAX_CONTRACT_BYTES if row.filename == "fedora-runtime.lock.json" else
                   MAX_ARCHIVE_BYTES)
        require(not row.flag_bits & 1 and not path.is_absolute()
                and len(path.parts) == 1 and path.parts[0] not in ("", ".", "..")
                and "\\" not in row.filename and not row.is_dir()
                and mode in (0, stat.S_IFREG)
                and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and 0 < row.file_size <= maximum,
                "container-runtime artifact contains an unsafe or oversized member")
        result[row.filename] = row
    return result


def _read_member(bundle, row, maximum):
    with bundle.open(row) as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) == row.file_size, "container-runtime artifact member length changed")
    return raw


def _hash_member(bundle, row):
    checksum = hashlib.sha256()
    total = 0
    with bundle.open(row) as stream:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            require(total <= row.file_size,
                    "container-runtime artifact member exceeded its recorded size")
            checksum.update(chunk)
    require(total == row.file_size,
            "container-runtime artifact member length changed")
    return checksum.hexdigest()


def validate_generated_manifest(manifest, manifest_raw, contract_raw, selection):
    archive = manifest.get("archive") if isinstance(manifest, dict) else None
    require(set(manifest) == GENERATED_MANIFEST_FIELDS
            and type(manifest.get("schema")) is int and manifest["schema"] == 1
            and manifest.get("built") is True and manifest.get("installed") is True
            and manifest.get("qualified") is False
            and manifest.get("os_qualified") is False
            and manifest.get("release_qualified") is False
            and manifest.get("signature_qualified") is False
            and manifest.get("variant") == selection["variant"] == "generic"
            and manifest.get("source_commit") == selection["producer"]["head_sha"]
            and exact_hash(manifest.get("source_image_commit"), 40)
            and isinstance(manifest.get("source_image_id"), str)
            and manifest["source_image_id"].startswith("sha256:")
            and exact_hash(manifest["source_image_id"].removeprefix("sha256:"))
            and manifest.get("contract_sha256") == hashlib.sha256(contract_raw).hexdigest()
            and manifest.get("scope") == MANIFEST_SCOPE
            and isinstance(archive, dict) and set(archive) == ARCHIVE_FIELDS
            and archive == selection["manifest"]["archive"]
            and hashlib.sha256(manifest_raw).hexdigest() == selection["manifest"]["sha256"]
            and manifest["contract_sha256"] == selection["manifest"]["contract_sha256"],
            "generated container-runtime manifest differs from the selected producer output")


def propose_candidate_selection(pending, run, metadata, bundle_path, validate_contract):
    """Create a reviewable selection from real successful producer records."""
    require(validate_candidate_selection(pending)["ready"] is False,
            "recording requires the unchanged pending selection slot")
    repository = run.get("repository") if isinstance(run, dict) else None
    head_repository = run.get("head_repository") if isinstance(run, dict) else None
    require(isinstance(repository, dict) and isinstance(head_repository, dict)
            and type(run.get("id")) is int and run["id"] > 0
            and type(run.get("run_attempt")) is int and run["run_attempt"] > 0
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == PRODUCER_WORKFLOW
            and type(run.get("workflow_id")) is int and run["workflow_id"] > 0
            and exact_hash(run.get("head_sha"), 40)
            and isinstance(run.get("head_branch"), str) and run["head_branch"]
            and run.get("status") == "completed" and run.get("conclusion") == "success"
            and repository.get("id") == REPOSITORY["id"]
            and repository.get("full_name") == REPOSITORY["full_name"]
            and head_repository.get("id") == REPOSITORY["id"]
            and head_repository.get("full_name") == REPOSITORY["full_name"],
            "cannot record a different or unsuccessful container-runtime producer")
    workflow = metadata.get("workflow_run") if isinstance(metadata, dict) else None
    digest_value = metadata.get("digest") if isinstance(metadata, dict) else None
    require(isinstance(workflow, dict)
            and type(metadata.get("id")) is int and metadata["id"] > 0
            and metadata.get("name") == ARTIFACT_NAME
            and type(metadata.get("size_in_bytes")) is int
            and 0 < metadata["size_in_bytes"] <= MAX_ARTIFACT_BYTES
            and isinstance(digest_value, str) and digest_value.startswith("sha256:")
            and exact_hash(digest_value.removeprefix("sha256:"))
            and metadata.get("expired") is False
            and workflow.get("id") == run["id"]
            and workflow.get("head_sha") == run["head_sha"]
            and workflow.get("repository_id") == REPOSITORY["id"]
            and workflow.get("head_repository_id") == REPOSITORY["id"],
            "cannot record a different or expired container-runtime artifact")
    bundle_path = absolute_without_dereference(bundle_path)
    bundle_info = bundle_path.lstat()
    require(stat.S_ISREG(bundle_info.st_mode) and bundle_info.st_nlink == 1
            and not bundle_path.is_symlink() and bundle_path.is_file()
            and bundle_path.resolve() == bundle_path
            and bundle_path.stat().st_size == metadata["size_in_bytes"]
            and sha256(bundle_path) == digest_value.removeprefix("sha256:"),
            "producer artifact bytes differ from authenticated metadata")
    with zipfile.ZipFile(bundle_path) as bundle:
        rows = _bundle_rows(bundle)
        manifest_raw = _read_member(bundle, rows["manifest.json"], 65536)
        contract_raw = _read_member(
            bundle, rows["fedora-runtime.lock.json"], MAX_CONTRACT_BYTES)
        manifest = unique_json_bytes(manifest_raw)
        contract = unique_json_bytes(contract_raw)
        archive = manifest.get("archive") if isinstance(manifest, dict) else None
        require(set(manifest) == GENERATED_MANIFEST_FIELDS
                and manifest.get("schema") == 1
                and manifest.get("built") is True and manifest.get("installed") is True
                and manifest.get("qualified") is False
                and manifest.get("os_qualified") is False
                and manifest.get("release_qualified") is False
                and manifest.get("signature_qualified") is False
                and manifest.get("variant") == "generic"
                and manifest.get("source_commit") == run["head_sha"]
                and exact_hash(manifest.get("source_image_commit"), 40)
                and isinstance(manifest.get("source_image_id"), str)
                and manifest["source_image_id"].startswith("sha256:")
                and exact_hash(manifest["source_image_id"].removeprefix("sha256:"))
                and isinstance(archive, dict) and set(archive) == ARCHIVE_FIELDS
                and archive.get("name") == ARCHIVE_NAME
                and type(archive.get("bytes")) is int
                and 0 < archive["bytes"] <= MAX_ARCHIVE_BYTES
                and exact_hash(archive.get("sha256"))
                and isinstance(archive.get("image_id"), str)
                and archive["image_id"].startswith("sha256:")
                and exact_hash(archive["image_id"].removeprefix("sha256:"))
                and isinstance(archive.get("manifest_digest"), str)
                and archive["manifest_digest"].startswith("sha256:")
                and exact_hash(archive["manifest_digest"].removeprefix("sha256:"))
                and rows[ARCHIVE_NAME].file_size == archive["bytes"]
                and _hash_member(bundle, rows[ARCHIVE_NAME]) == archive["sha256"]
                and manifest.get("contract_sha256")
                == hashlib.sha256(contract_raw).hexdigest()
                and manifest.get("scope") == MANIFEST_SCOPE,
                "producer bundle cannot populate the selected generic image slot")
        validate_contract(
            contract, manifest["source_image_commit"], manifest["source_image_id"])
    selected = json.loads(json.dumps(pending))
    selected.update(state="selected", selected=True)
    selected["workflow"]["id"] = run["workflow_id"]
    selected["producer"] = {
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "event": run["event"],
        "head_sha": run["head_sha"],
        "head_branch": run["head_branch"],
        "status": run["status"],
        "conclusion": run["conclusion"],
    }
    selected["artifact"] = {
        "id": metadata["id"],
        "name": metadata["name"],
        "bytes": metadata["size_in_bytes"],
        "sha256": digest_value.removeprefix("sha256:"),
    }
    selected["manifest"] = {
        "sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "contract_sha256": hashlib.sha256(contract_raw).hexdigest(),
        "archive": archive,
    }
    require(validate_candidate_selection(selected)["ready"] is True,
            "recorded container-runtime selection is not consumable")
    validate_generated_manifest(manifest, manifest_raw, contract_raw, selected)
    return selected


def consume_candidate_bundle(bundle_path, selection, run, metadata, destination,
                             validate_contract):
    """Validate and stream one selected OCI plus its generated contract."""
    require(validate_candidate_selection(selection)["ready"] is True,
            "container-runtime image selection is still pending")
    validate_producer_metadata(run, selection)
    validate_artifact_metadata(metadata, selection)
    bundle_path = absolute_without_dereference(bundle_path)
    destination = absolute_without_dereference(destination)
    bundle_info = bundle_path.lstat()
    require(stat.S_ISREG(bundle_info.st_mode) and bundle_info.st_nlink == 1
            and not bundle_path.is_symlink() and bundle_path.is_file()
            and bundle_path.resolve() == bundle_path
            and bundle_path.stat().st_size == selection["artifact"]["bytes"]
            and sha256(bundle_path) == selection["artifact"]["sha256"],
            "container-runtime artifact ZIP bytes differ from the selected digest")
    require(not destination.exists() and not destination.is_symlink()
            and destination.parent.is_dir() and destination.parent.resolve() == destination.parent,
            "use a new regular container-runtime input directory")
    initial = bundle_path.stat()
    created = False
    try:
        with zipfile.ZipFile(bundle_path) as bundle:
            rows = _bundle_rows(bundle)
            manifest_raw = _read_member(bundle, rows["manifest.json"], 65536)
            contract_raw = _read_member(
                bundle, rows["fedora-runtime.lock.json"], MAX_CONTRACT_BYTES)
            manifest = unique_json_bytes(manifest_raw)
            contract = unique_json_bytes(contract_raw)
            validate_generated_manifest(
                manifest, manifest_raw, contract_raw, selection)
            validate_contract(
                contract, manifest["source_image_commit"], manifest["source_image_id"])
            archive = manifest["archive"]
            require(rows[ARCHIVE_NAME].file_size == archive["bytes"],
                    "container-runtime OCI archive length changed")
            destination.mkdir(mode=0o700)
            created = True
            checksum = hashlib.sha256()
            total = pending = 0
            target = destination / ARCHIVE_NAME
            with bundle.open(rows[ARCHIVE_NAME]) as incoming, target.open("xb") as outgoing:
                while chunk := incoming.read(64 * 1024):
                    total += len(chunk)
                    pending += len(chunk)
                    require(total <= archive["bytes"],
                            "container-runtime OCI stream exceeded its selected size")
                    checksum.update(chunk)
                    outgoing.write(chunk)
                    if pending >= 16 * 1024**2:
                        outgoing.flush()
                        os.fsync(outgoing.fileno())
                        os.posix_fadvise(outgoing.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                        pending = 0
                outgoing.flush()
                os.fsync(outgoing.fileno())
                os.posix_fadvise(outgoing.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            require(total == archive["bytes"] and checksum.hexdigest() == archive["sha256"],
                    "container-runtime OCI archive content changed")
            target.chmod(0o644)
            (destination / "manifest.json").write_bytes(manifest_raw)
            (destination / "fedora-runtime.lock.json").write_bytes(contract_raw)
            (destination / "manifest.json").chmod(0o644)
            (destination / "fedora-runtime.lock.json").chmod(0o644)
        final = bundle_path.stat()
        require((initial.st_dev, initial.st_ino, initial.st_mode, initial.st_nlink,
                 initial.st_size, initial.st_mtime_ns)
                == (final.st_dev, final.st_ino, final.st_mode, final.st_nlink,
                    final.st_size, final.st_mtime_ns),
                "container-runtime artifact changed while it was consumed")
        return {
            "manifest": manifest,
            "selection_canonical_sha256": canonical_sha256(selection),
            "artifact_sha256": selection["artifact"]["sha256"],
            "contract_sha256": manifest["contract_sha256"],
            "archive_sha256": manifest["archive"]["sha256"],
        }
    except BaseException:
        if created:
            shutil.rmtree(destination)
        raise


def _real_contract_validator(root):
    from image.boot.inputs import require_desktop_image
    from image.qualification.container_hosted import (
        load_authenticated_runsc, validate_fedora_contract,
    )
    images = unique_json(root / "image/desktop-images.lock.json")
    pins = unique_json(root / "image/base-images.json")
    source_manifest = require_desktop_image(images, pins, "generic")
    selected = images["images"]["generic"]
    runsc = load_authenticated_runsc(root)

    def validate(contract, source_commit, source_image_id):
        require(source_commit == selected["tested_commit"]
                and source_image_id == source_manifest["archive"]["image_id"],
                "derived container image uses a different retained source image")
        validate_fedora_contract(contract, runsc, root, source_commit)

    return validate


def consume(root, bundle, run_metadata, artifact_metadata, destination, evidence):
    root = Path(root).resolve()
    paths = validate_consumer_paths(
        root, bundle, run_metadata, artifact_metadata, destination, evidence)
    hosted, group = load_hosted_context()
    selection_path = root / "image/container/fedora-runtime-image.lock.json"
    selection = unique_json(selection_path)
    transfer = validate_transfer_record(root, selection, hosted)
    record = {
        "schema": 1,
        "passed": False,
        "qualified": False,
        "os_qualified": False,
        "release_qualified": False,
        "signature_qualified": False,
        "variant": "generic",
        "selection_sha256": sha256(selection_path),
        "pre_transfer_sha256": sha256(
            root / ".cache/container-runtime-native-evidence/pre-transfer.json"),
        "hosted": hosted,
        "limits": HOSTED_LIMITS,
        "transfer": transfer,
        "scope": "Exact derived image intake; native containment qualification remains open",
    }
    evidence = paths["evidence"]
    prepare_path = evidence / "prepare.json"
    require(not prepare_path.exists() and not prepare_path.is_symlink(),
            "container-runtime prepare evidence already exists")
    try:
        observed = consume_candidate_bundle(
            paths["bundle"], selection, unique_json(paths["run_metadata"]),
            unique_json(paths["artifact_metadata"]), paths["destination"],
            _real_contract_validator(root),
        )
        require(observed["selection_canonical_sha256"] == canonical_sha256(selection),
                "container-runtime selection changed during intake")
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
        prepare_path.write_text(json.dumps(record, indent=2) + "\n")


def validate_consumed_candidate(root, source_commit, environment=os.environ):
    """Recheck the prepared native input without trusting its success record."""
    root = Path(root).resolve()
    selection_path = root / "image/container/fedora-runtime-image.lock.json"
    selection = unique_json(selection_path)
    status = validate_candidate_selection(selection)
    if not status["ready"]:
        return {"ready": False, "blocker": status["blocker"]}
    require(exact_hash(source_commit, 40),
            "prepared container-runtime input needs the exact OS source commit")
    current_hosted = _workflow_identity(environment)
    require(current_hosted["source_commit"] == source_commit,
            "native preflight uses a different hosted source commit")
    validate_producer_metadata(
        unique_json(root / ".cache/container-runtime-image-run.json"), selection)
    validate_artifact_metadata(
        unique_json(root / ".cache/container-runtime-image-artifact.json"), selection)
    outer = root / ".cache/container-runtime-development-image.zip"
    outer_info = outer.lstat()
    require(stat.S_ISREG(outer_info.st_mode) and outer_info.st_nlink == 1
            and not outer.is_symlink() and outer.is_file()
            and outer.resolve() == outer
            and outer.stat().st_size == selection["artifact"]["bytes"]
            and sha256(outer) == selection["artifact"]["sha256"],
            "prepared container-runtime artifact ZIP changed")
    destination = root / ".cache/container-runtime-native-inputs"
    require(destination.is_dir() and not destination.is_symlink()
            and destination.resolve() == destination
            and {path.name for path in destination.iterdir()}
            == {"manifest.json", "fedora-runtime.lock.json", ARCHIVE_NAME},
            "prepared container-runtime input directory changed")
    manifest_path = destination / "manifest.json"
    contract_path = destination / "fedora-runtime.lock.json"
    archive_path = destination / ARCHIVE_NAME
    limits = {
        manifest_path: 65536,
        contract_path: MAX_CONTRACT_BYTES,
        archive_path: selection["manifest"]["archive"]["bytes"],
    }
    for path, maximum in limits.items():
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and 0 < info.st_size <= maximum,
                "prepared container-runtime input is not a bounded direct regular file")
    manifest_raw = manifest_path.read_bytes()
    contract_raw = contract_path.read_bytes()
    manifest = unique_json_bytes(manifest_raw)
    validate_generated_manifest(
        manifest, manifest_raw, contract_raw, selection)
    from image.boot.inputs import require_desktop_image
    images = unique_json(root / "image/desktop-images.lock.json")
    pins = unique_json(root / "image/base-images.json")
    source_manifest = require_desktop_image(images, pins, "generic")
    source = images["images"]["generic"]
    require(manifest["source_image_commit"] == source["tested_commit"]
            and manifest["source_image_id"] == source_manifest["archive"]["image_id"],
            "prepared derived image uses a different retained source image")
    require(sha256(manifest_path) == selection["manifest"]["sha256"]
            and sha256(contract_path) == selection["manifest"]["contract_sha256"]
            and archive_path.stat().st_size == selection["manifest"]["archive"]["bytes"]
            and sha256(archive_path) == selection["manifest"]["archive"]["sha256"],
            "prepared container-runtime manifest, contract or OCI changed")
    record = unique_json(root / ".cache/container-runtime-native-evidence/prepare.json")
    expected_keys = {
        "schema", "passed", "qualified", "os_qualified", "release_qualified",
        "signature_qualified", "variant", "selection_sha256", "scope",
        "manifest", "selection_canonical_sha256", "artifact_sha256",
        "contract_sha256", "archive_sha256", "pre_transfer_sha256",
        "hosted", "limits", "transfer", "cgroup_final",
    }
    hosted = record.get("hosted") if isinstance(record, dict) else None
    validate_recorded_hosted(hosted, source_commit)
    require({key: hosted[key] for key in current_hosted} == current_hosted,
            "prepared container-runtime input uses a different hosted run")
    transfer = validate_transfer_record(root, selection, hosted)
    validate_cgroup_final(record.get("cgroup_final"))
    validate_systemd_result(
        root / ".cache/container-runtime-native-evidence/systemd-result.txt", hosted)
    require(set(record) == expected_keys and record.get("schema") == 1
            and record.get("passed") is True
            and record.get("qualified") is False
            and record.get("os_qualified") is False
            and record.get("release_qualified") is False
            and record.get("signature_qualified") is False
            and record.get("variant") == "generic"
            and record.get("selection_sha256") == sha256(selection_path)
            and record.get("pre_transfer_sha256")
            == sha256(root / ".cache/container-runtime-native-evidence/pre-transfer.json")
            and record.get("limits") == HOSTED_LIMITS
            and record.get("transfer") == transfer
            and record.get("selection_canonical_sha256") == canonical_sha256(selection)
            and record.get("artifact_sha256") == selection["artifact"]["sha256"]
            and record.get("contract_sha256") == selection["manifest"]["contract_sha256"]
            and record.get("archive_sha256") == selection["manifest"]["archive"]["sha256"]
            and record.get("manifest") == manifest,
            "prepared container-runtime intake record changed")
    return {
        "ready": True,
        "blocker": None,
        "selection": selection,
        "manifest": manifest,
        "contract_path": contract_path,
        "archive_path": archive_path,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("selection-values")
    subparsers.add_parser("pre-transfer")
    subparsers.add_parser("record-transfer-metadata")
    subparsers.add_parser("record-transfer-complete")
    failure_parser = subparsers.add_parser("record-transfer-failure")
    failure_parser.add_argument("--stage", required=True)
    failure_parser.add_argument("--exit-code", type=int, required=True)
    unit_parser = subparsers.add_parser("validate-unit-result")
    unit_parser.add_argument("--result", type=Path, required=True)
    consume_parser = subparsers.add_parser("consume")
    consume_parser.add_argument("--bundle", type=Path, required=True)
    consume_parser.add_argument("--run-metadata", type=Path, required=True)
    consume_parser.add_argument("--artifact-metadata", type=Path, required=True)
    consume_parser.add_argument("--destination", type=Path, required=True)
    consume_parser.add_argument("--evidence", type=Path, required=True)
    record_parser = subparsers.add_parser("record-selection")
    record_parser.add_argument("--bundle", type=Path, required=True)
    record_parser.add_argument("--run-metadata", type=Path, required=True)
    record_parser.add_argument("--artifact-metadata", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if arguments.command == "selection-values":
        selection = unique_json(root / "image/container/fedora-runtime-image.lock.json")
        status = validate_candidate_selection(selection)
        require(status["ready"] is True, status["blocker"])
        print(selection["producer"]["run_id"])
        print(selection["producer"]["run_attempt"])
        print(selection["artifact"]["id"])
        return
    if arguments.command == "pre-transfer":
        for value in prepare_transfer(root):
            print(value)
        return
    if arguments.command == "record-transfer-failure":
        record_transfer_failure(
            root, os.environ, arguments.stage, arguments.exit_code)
        return
    if arguments.command == "record-transfer-metadata":
        record_transfer_metadata(root)
        return
    if arguments.command == "record-transfer-complete":
        record_transfer_complete(root)
        return
    if arguments.command == "validate-unit-result":
        record = unique_json(
            root / ".cache/container-runtime-native-evidence/prepare.json")
        validate_systemd_result(arguments.result, record.get("hosted"))
        return
    if arguments.command == "record-selection":
        pending = unique_json(root / "image/container/fedora-runtime-image.lock.json")
        selected = propose_candidate_selection(
            pending, unique_json(arguments.run_metadata),
            unique_json(arguments.artifact_metadata),
            absolute_without_dereference(arguments.bundle),
            _real_contract_validator(root),
        )
        print(json.dumps(selected, indent=2))
        return
    consume(
        root, arguments.bundle, arguments.run_metadata, arguments.artifact_metadata,
        arguments.destination, arguments.evidence,
    )


if __name__ == "__main__":
    main()
