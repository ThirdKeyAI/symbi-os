"""Authenticate the retained container-runtime inputs before offline image assembly."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import zipfile

from image.container.package_inventory import inventory_digest, parse_inventory


PACKAGE_FIELDS = {
    "filename", "bytes", "sha256", "nevra", "vendor", "license",
    "signature_verified", "key_fingerprint",
}
EXPECTED_LIMITS = {
    "memory.max": "2147483648", "memory.swap.max": "0",
    "cpu.max": "100000 100000", "pids.max": "128",
}
SUMMARY_SCOPE = "Candidate signed package closure; not installed, compiled or qualified"
GUEST_SCOPE = "Candidate RPM download and signature verification; no package install or build"
EXPECTED_SOURCE_PACKAGE_PLAN = {
    "inventory": {
        "run_id": 46107995231,
        "path": "docs/security/reports/P0-03-desktop/46107995231/install/installed-after-stdout.log",
        "bytes": 88016,
        "sha256": "4142fa70cff7227a164225f6ebff5bbbaf7816c5d5d864a4a47c454969445387",
        "canonical_sha256": "7af38020fc34399648c491a007e089982395582ad2f79448fb853a57c93effc4",
        "package_count": 2184,
    },
    "requested_root_nevras": {
        "container-selinux": "container-selinux-4:2.251.0-1.fc45.noarch",
        "docker-cli": "docker-cli-29.9.3-1.fc45.x86_64",
        "moby-engine": "moby-engine-29.9.3-1.fc45.x86_64",
    },
    "additive_nevras": [],
    "replacements_allowed": False,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json_bytes(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate retained JSON key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda value: (_ for _ in ()).throw(
                           ValueError("noncanonical retained JSON number")))
    require(isinstance(value, dict), "retained JSON must be an object")
    return value


def unique_json(path):
    return unique_json_bytes(Path(path).read_bytes())


def exact_hash(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{" + str(length) + r"}", value) is not None


def validate_selection(root, lock):
    root = Path(root)
    expected_fields = {
        "schema", "selected", "installed", "qualified", "os_qualified",
        "repository", "workflow", "profile", "run_id", "run_attempt",
        "source_commit", "package_count", "package_bytes",
        "source_package_plan", "candidate_artifact", "evidence_artifact",
        "source_image_producer", "scope",
    }
    require(isinstance(lock, dict) and set(lock) == expected_fields,
            "Fedora runtime candidate lock fields changed")
    require(lock["schema"] == 1 and lock["selected"] is True
            and lock["installed"] is False and lock["qualified"] is False
            and lock["os_qualified"] is False,
            "Fedora runtime candidates must remain selected but uninstalled and unqualified")
    require(lock["repository"] == {"id": 1472078858, "full_name": "ThirdKeyAI/symbi-os"}
            and lock["workflow"] == ".github/workflows/fedora-packages.yml"
            and lock["profile"] == "container-runtime"
            and type(lock["run_id"]) is int and lock["run_id"] > 0
            and type(lock["run_attempt"]) is int and lock["run_attempt"] > 0
            and exact_hash(lock["source_commit"], 40),
            "Fedora runtime workflow identity is invalid")
    require(lock["package_count"] == 108 and lock["package_bytes"] == 116875288,
            "Fedora runtime closure bound changed")
    require(lock["source_package_plan"] == EXPECTED_SOURCE_PACKAGE_PLAN,
            "Fedora source-image package plan changed")
    for field, name, maximum in (
        ("candidate_artifact", "container-runtime-rpm-candidates", 2 * 1024**3),
        ("evidence_artifact", "container-runtime-fedora-package-evidence", 64 * 1024**2),
    ):
        artifact = lock[field]
        require(isinstance(artifact, dict) and set(artifact) == {"id", "name", "bytes", "sha256"}
                and type(artifact["id"]) is int and artifact["id"] > 0
                and artifact["name"] == name
                and type(artifact["bytes"]) is int and 0 < artifact["bytes"] <= maximum
                and exact_hash(artifact["sha256"]),
                "Fedora runtime artifact identity is invalid")
    require(lock["source_image_producer"] == {
        "repository": {"id": 1472078858, "full_name": "ThirdKeyAI/symbi-os"},
        "head_repository": {"id": 1472078858, "full_name": "ThirdKeyAI/symbi-os"},
        "workflow": {"id": 431169773, "path": ".github/workflows/desktop-image.yml"},
        "run_id": 46107995231,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "head_sha": "c6bf3ed9eba34562d886b6b315dd9cb46340c525",
        "head_branch": "card/P0-04-hosted-fix",
        "status": "completed",
        "conclusion": "success",
    }, "desktop image producer selection changed")
    requirements = unique_json(root / "image/container/runtime-requirements.json")
    require(requirements.get("schema") == 1 and requirements.get("profile") == lock["profile"]
            and requirements.get("packages") == ["moby-engine", "docker-cli", "container-selinux"],
            "Fedora runtime requirements changed")
    return requirements


def validate_workflow_metadata(run, lock):
    repository = run.get("repository") if isinstance(run, dict) else None
    head_repository = run.get("head_repository") if isinstance(run, dict) else None
    require(isinstance(repository, dict) and isinstance(head_repository, dict)
            and run.get("id") == lock["run_id"]
            and run.get("run_attempt") == lock["run_attempt"]
            and run.get("status") == "completed" and run.get("conclusion") == "success"
            and run.get("event") == "push" and run.get("path") == lock["workflow"]
            and run.get("head_sha") == lock["source_commit"]
            and repository.get("id") == lock["repository"]["id"]
            and repository.get("full_name") == lock["repository"]["full_name"]
            and head_repository.get("id") == lock["repository"]["id"]
            and head_repository.get("full_name") == lock["repository"]["full_name"],
            "Hosted discovery workflow metadata differs from the selected success")


def validate_artifact_metadata(metadata, selected, lock):
    workflow = metadata.get("workflow_run") if isinstance(metadata, dict) else None
    require(isinstance(workflow, dict)
            and metadata.get("id") == selected["id"]
            and metadata.get("name") == selected["name"]
            and metadata.get("size_in_bytes") == selected["bytes"]
            and metadata.get("digest") == "sha256:" + selected["sha256"]
            and metadata.get("expired") is False
            and workflow.get("id") == lock["run_id"]
            and workflow.get("head_sha") == lock["source_commit"]
            and workflow.get("repository_id") == lock["repository"]["id"]
            and workflow.get("head_repository_id") == lock["repository"]["id"],
            "Hosted discovery artifact metadata differs from the selected bytes")


def validate_source_workflow_metadata(run, selected, lock):
    producer = lock["source_image_producer"]
    repository = run.get("repository") if isinstance(run, dict) else None
    head_repository = run.get("head_repository") if isinstance(run, dict) else None
    workflow = producer["workflow"]
    require(isinstance(repository, dict) and isinstance(head_repository, dict)
            and selected.get("run_id") == producer["run_id"]
            and selected.get("tested_commit") == producer["head_sha"]
            and run.get("id") == producer["run_id"]
            and run.get("run_attempt") == producer["run_attempt"]
            and run.get("event") == producer["event"]
            and run.get("path") == workflow["path"]
            and run.get("workflow_id") == workflow["id"]
            and run.get("head_sha") == producer["head_sha"]
            and run.get("head_branch") == producer["head_branch"]
            and run.get("status") == producer["status"]
            and run.get("conclusion") == producer["conclusion"]
            and repository.get("id") == producer["repository"]["id"]
            and repository.get("full_name") == producer["repository"]["full_name"]
            and head_repository.get("id") == producer["head_repository"]["id"]
            and head_repository.get("full_name") == producer["head_repository"]["full_name"],
            "desktop image workflow metadata differs from the reviewed producer")


def validate_source_artifact_metadata(metadata, selected, lock):
    producer = lock["source_image_producer"]
    artifact = selected["artifact"]
    workflow = metadata.get("workflow_run") if isinstance(metadata, dict) else None
    require(isinstance(workflow, dict)
            and metadata.get("id") == artifact["id"]
            and metadata.get("name") == artifact["name"]
            and metadata.get("size_in_bytes") == artifact["bytes"]
            and metadata.get("digest") == "sha256:" + artifact["sha256"]
            and metadata.get("expired") is False
            and workflow.get("id") == producer["run_id"]
            and workflow.get("head_sha") == producer["head_sha"]
            and workflow.get("repository_id") == producer["repository"]["id"]
            and workflow.get("head_repository_id") == producer["head_repository"]["id"],
            "desktop image artifact metadata differs from the reviewed producer")


def _safe_zip_rows(bundle, maximum_total):
    rows = bundle.infolist()
    names = [row.filename for row in rows]
    require(rows and len(names) == len(set(names)), "artifact ZIP has duplicate or no members")
    total = 0
    for row in rows:
        path = PurePosixPath(row.filename)
        mode = stat.S_IFMT(row.external_attr >> 16)
        require(not row.flag_bits & 1 and not path.is_absolute() and path.parts
                and all(part not in ("", ".", "..") for part in path.parts)
                and "\\" not in row.filename,
                "artifact ZIP has an unsafe member name")
        if row.is_dir():
            require(mode in (0, stat.S_IFDIR), "artifact ZIP directory has an unsafe type")
            continue
        require(mode in (0, stat.S_IFREG)
                and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and 0 < row.file_size <= 2 * 1024**3,
                "artifact ZIP has an unsafe member")
        total += row.file_size
        require(total <= maximum_total, "artifact ZIP expands beyond its bound")
    return {row.filename: row for row in rows if not row.is_dir()}


def _read_member(bundle, rows, name, maximum):
    row = rows.get(name)
    require(row is not None and row.file_size <= maximum, "required artifact member is missing or oversized")
    with bundle.open(row) as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) == row.file_size, "artifact member length changed")
    return raw


def _require_archive(archive, selected):
    archive = Path(archive)
    require(not archive.is_symlink() and archive.is_file() and archive.resolve() == archive
            and archive.stat().st_size == selected["bytes"] and digest(archive) == selected["sha256"],
            "hosted artifact ZIP bytes differ from the selected digest")


def validate_packages(packages, fingerprint, count, total_bytes):
    require(isinstance(packages, list) and len(packages) == count,
            "Fedora closure package count changed")
    filenames, nevras, observed_bytes = set(), set(), 0
    for row in packages:
        require(isinstance(row, dict) and set(row) == PACKAGE_FIELDS,
                "Fedora closure package fields changed")
        filename, nevra, size = row.get("filename"), row.get("nevra"), row.get("bytes")
        require(isinstance(filename, str) and filename == Path(filename).name
                and filename.endswith(".rpm") and filename not in filenames
                and isinstance(nevra, str) and nevra and not any(c.isspace() for c in nevra)
                and nevra not in nevras and type(size) is int and size > 0
                and exact_hash(row.get("sha256"))
                and isinstance(row.get("vendor"), str) and row["vendor"]
                and isinstance(row.get("license"), str) and row["license"]
                and row.get("signature_verified") is True
                and row.get("key_fingerprint") == fingerprint,
                "Fedora closure has an invalid or duplicate signed package")
        filenames.add(filename)
        nevras.add(nevra)
        observed_bytes += size
    require(observed_bytes == total_bytes, "Fedora closure byte total changed")
    return filenames, nevras


def unpack_discovery_artifacts(candidate_archive, evidence_archive, lock, destination):
    """Stream only exact signed RPMs plus the two bound discovery reports."""
    destination = Path(destination)
    require(not destination.exists() and not destination.is_symlink()
            and destination.parent.is_dir() and destination.parent.resolve() == destination.parent,
            "use a new regular discovery destination")
    _require_archive(candidate_archive, lock["candidate_artifact"])
    _require_archive(evidence_archive, lock["evidence_artifact"])
    created = False
    try:
        with zipfile.ZipFile(candidate_archive) as bundle:
            rows = _safe_zip_rows(bundle, 2 * 1024**3 + 16 * 1024**2)
            guest_raw = _read_member(bundle, rows, "evidence/result.json", 8 * 1024**2)
            guest = unique_json_bytes(guest_raw)
            packages = guest.get("packages")
            fingerprint = guest.get("key", {}).get("fingerprint") if isinstance(guest.get("key"), dict) else None
            filenames, _ = validate_packages(packages, fingerprint, lock["package_count"], lock["package_bytes"])
            expected = {"evidence/result.json"} | {"rpms/" + name for name in filenames}
            require(set(rows) == expected, "candidate artifact contains unexpected or missing members")
            destination.mkdir(mode=0o700)
            created = True
            rpm_root = destination / "rpms"
            rpm_root.mkdir(mode=0o700)
            for package in packages:
                row = rows["rpms/" + package["filename"]]
                require(row.file_size == package["bytes"], "candidate RPM length changed")
                target = rpm_root / package["filename"]
                checksum, total = hashlib.sha256(), 0
                with bundle.open(row) as source, target.open("xb") as output:
                    while chunk := source.read(1024**2):
                        total += len(chunk)
                        require(total <= package["bytes"], "candidate RPM exceeded its bound")
                        checksum.update(chunk)
                        output.write(chunk)
                require(total == package["bytes"] and checksum.hexdigest() == package["sha256"],
                        "candidate RPM bytes changed")
                target.chmod(0o600)
            (destination / "guest-result.json").write_bytes(guest_raw)
        with zipfile.ZipFile(evidence_archive) as bundle:
            rows = _safe_zip_rows(bundle, 64 * 1024**2)
            require("result.json" in rows and "input-bindings.json" in rows,
                    "discovery evidence lacks its summary or input bindings")
            summary_raw = _read_member(bundle, rows, "result.json", 1024**2)
            bindings_raw = _read_member(bundle, rows, "input-bindings.json", 1024**2)
            (destination / "summary.json").write_bytes(summary_raw)
            (destination / "input-bindings.json").write_bytes(bindings_raw)
        return unique_json_bytes(summary_raw), unique_json_bytes(bindings_raw), guest
    except BaseException:
        if created:
            shutil.rmtree(destination)
        raise


def _expected_bindings(root, requirements_path):
    root = Path(root)
    trust = unique_json(root / "image/hyprland/fedora-package-trust.json")
    paths = {
        "resolve_packages.py": "image/hyprland/resolve_packages.py",
        "guest_inventory.py": "image/hyprland/guest_inventory.py",
        "build-requirements.json": requirements_path,
        "fedora-package-trust.json": "image/hyprland/fedora-package-trust.json",
        "fedora-45-primary.asc": trust["key"]["path"],
        "dnf.conf": "image/hyprland/package-dnf.conf",
        "repos/fedora-build.repo": "image/hyprland/fedora-build.repo",
    }
    return {name: digest(root / relative) for name, relative in paths.items()}, trust


def validate_discovery_records(root, lock, summary, bindings, guest, guest_raw, bindings_raw):
    root = Path(root)
    requirements_path = "image/container/runtime-requirements.json"
    requirements = validate_selection(root, lock)
    expected_bindings, trust = _expected_bindings(root, requirements_path)
    expected_summary = {
        "passed", "base", "source_commit", "profile", "requirements_sha256",
        "repository_configuration_sha256", "input_bindings_sha256", "packages",
        "rpm_manifest_sha256", "os_qualified", "scope", "installed_root_nevras",
        "downloaded_root_nevras", "offline_closure_verified",
    }
    require(isinstance(summary, dict) and set(summary) == expected_summary
            and summary.get("passed") is True and summary.get("os_qualified") is False
            and summary.get("source_commit") == lock["source_commit"]
            and summary.get("profile") == lock["profile"]
            and summary.get("base") == trust["source"]["image"]
            and summary.get("requirements_sha256") == digest(root / requirements_path)
            and summary.get("repository_configuration_sha256")
            == expected_bindings["repos/fedora-build.repo"]
            and summary.get("input_bindings_sha256") == hashlib.sha256(bindings_raw).hexdigest()
            and summary.get("rpm_manifest_sha256") == hashlib.sha256(guest_raw).hexdigest()
            and summary.get("packages") == lock["package_count"]
            and summary.get("offline_closure_verified") is True
            and summary.get("scope") == SUMMARY_SCOPE,
            "Fedora discovery summary differs from the selected closure")
    require(set(bindings) == {"source_commit", "profile", "requirements_source", "files"}
            and bindings.get("source_commit") == lock["source_commit"]
            and bindings.get("profile") == lock["profile"]
            and bindings.get("requirements_source") == requirements_path
            and bindings.get("files") == expected_bindings,
            "Fedora discovery input bindings changed")
    expected_guest = {
        "schema", "scope", "base", "key", "requirements", "limits", "commands",
        "packages", "passed", "os_qualified", "installed_root_nevras",
        "downloaded_root_nevras", "offline_closure_verified", "closure_package_count",
        "installed_packages_unchanged", "negative_controls",
    }
    require(isinstance(guest, dict) and set(guest) == expected_guest and guest.get("schema") == 1
            and guest.get("passed") is True and guest.get("os_qualified") is False
            and guest.get("scope") == GUEST_SCOPE and guest.get("base") == trust["source"]["image"]
            and guest.get("key") == trust["key"] and guest.get("requirements") == requirements
            and guest.get("limits") == EXPECTED_LIMITS
            and guest.get("offline_closure_verified") is True
            and guest.get("closure_package_count") == lock["package_count"]
            and guest.get("installed_packages_unchanged") is True
            and guest.get("negative_controls") == {
                "missing_key_rejected": True, "tampered_package_rejected": True},
            "Fedora discovery guest evidence is incomplete")
    _, nevras = validate_packages(guest["packages"], trust["key"]["fingerprint"],
                                  lock["package_count"], lock["package_bytes"])
    roots = guest.get("installed_root_nevras")
    require(isinstance(roots, dict) and list(roots) == requirements["packages"]
            and guest.get("downloaded_root_nevras") == sorted(roots.values())
            and summary.get("installed_root_nevras") == roots
            and summary.get("downloaded_root_nevras") == sorted(roots.values())
            and all(value in nevras for value in roots.values()),
            "Fedora discovery roots are not in the exact signed closure")
    commands = guest.get("commands")
    require(isinstance(commands, list) and commands
            and all(isinstance(row, dict) and set(row) == {"name", "command", "exit_code"}
                    and isinstance(row["name"], str) and isinstance(row["command"], list)
                    and type(row["exit_code"]) is int for row in commands)
            and len({row["name"] for row in commands}) == len(commands)
            and {row["name"] for row in commands}.issuperset({
                "installed-before", "resolve-download", "offline-closure-test",
                "missing-key-control", "tampered-package-control", "installed-after"}),
            "Fedora discovery command evidence is malformed")
    return trust


def _inventory_nevra(row):
    name, epoch, version, release, architecture = row.split("\t")
    epoch_prefix = "" if epoch == "0" else epoch + ":"
    return f"{name}-{epoch_prefix}{version}-{release}.{architecture}"


def validate_source_package_plan(root, lock, signed_roots):
    """Bind the exact source inventory and accept only its reviewed empty transaction."""
    root = Path(root)
    plan = lock.get("source_package_plan")
    require(plan == EXPECTED_SOURCE_PACKAGE_PLAN and isinstance(signed_roots, dict)
            and signed_roots == plan["requested_root_nevras"],
            "signed roots differ from the reviewed source package plan")
    inventory = plan["inventory"]
    path = root / inventory["path"]
    require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root)
            and path.stat().st_size == inventory["bytes"] and digest(path) == inventory["sha256"],
            "retained source-image package inventory changed")
    raw = path.read_bytes()
    rows = parse_inventory(raw)
    require(len(rows) == inventory["package_count"]
            and inventory_digest(raw) == inventory["canonical_sha256"],
            "retained source-image package inventory is not canonicalizable as reviewed")
    requested_identities = {}
    for name, expected_nevra in plan["requested_root_nevras"].items():
        matches = [row for row in rows if row.split("\t", 1)[0] == name]
        require(len(matches) == 1 and _inventory_nevra(matches[0]) == expected_nevra,
                "selected source image lacks an exact signed runtime root")
        requested_identities[name] = matches[0]
    require(plan["additive_nevras"] == [] and plan["replacements_allowed"] is False,
            "only the reviewed empty source-aware RPM transaction is accepted")
    return {
        "source_inventory_sha256": inventory["canonical_sha256"],
        "source_package_count": inventory["package_count"],
        "requested_root_nevras": plan["requested_root_nevras"],
        "requested_root_identities": requested_identities,
        "additive_nevras": plan["additive_nevras"],
        "replacements_allowed": plan["replacements_allowed"],
    }


def validate_runsc_tree(root, inventory):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink() and root.resolve() == root,
            "runsc extraction root is unsafe")
    entries = inventory.get("entries") if isinstance(inventory, dict) else None
    require(isinstance(entries, list) and entries, "runsc inventory is empty")
    expected = {row.get("path") for row in entries if isinstance(row, dict)}
    observed = {path.relative_to(root).as_posix() for path in root.rglob("*")}
    require(None not in expected and len(expected) == len(entries) and observed == expected,
            "runsc extraction differs from the authenticated inventory")
    files = {}
    for row in entries:
        relative = row["path"]
        require(not relative.startswith("/") and ".." not in Path(relative).parts,
                "runsc inventory path escapes its root")
        path = root / relative
        info = path.lstat()
        require(not path.is_symlink() and stat.S_IMODE(info.st_mode) == row["mode"],
                "runsc extracted mode or type changed")
        if row.get("type") == "5":
            require(stat.S_ISDIR(info.st_mode), "runsc directory became another type")
        else:
            require(row.get("type") == "0" and stat.S_ISREG(info.st_mode)
                    and info.st_size == row.get("bytes") and digest(path) == row.get("sha256"),
                    "runsc file bytes changed")
            files[relative] = {"sha256": row["sha256"], "mode": row["mode"],
                               "bytes": row["bytes"]}
    return files


def input_inventory(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink() and root.resolve() == root,
            "prepared input root is unsafe")
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        require(not path.is_symlink() and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
                "prepared input contains a link or special member")
        if stat.S_ISREG(info.st_mode):
            result[relative] = {"bytes": info.st_size, "sha256": digest(path),
                                "mode": stat.S_IMODE(info.st_mode)}
    return result


def validate_install_record(record, packages, package_plan, runsc_files, daemon_sha256):
    package_nevras = sorted(row["nevra"] for row in packages)
    require(isinstance(record, dict) and record.get("passed") is True
            and record.get("installed") is True and record.get("qualified") is False
            and record.get("os_qualified") is False and record.get("release_qualified") is False
            and record.get("all_base_packages_unchanged") is True
            and record.get("rpm_transaction_empty") is True
            and record.get("source_inventory_sha256") == package_plan["source_inventory_sha256"]
            and record.get("before_inventory_sha256") == package_plan["source_inventory_sha256"]
            and record.get("after_inventory_sha256") == package_plan["source_inventory_sha256"]
            and record.get("requested_root_nevras") == package_plan["requested_root_nevras"]
            and record.get("requested_root_identities") == package_plan["requested_root_identities"]
            and record.get("additive_nevras") == package_plan["additive_nevras"] == []
            and record.get("added_nevras") == [] and record.get("added_package_names") == []
            and record.get("verified_closure_nevras") == package_nevras
            and record.get("daemon_configuration_sha256") == daemon_sha256
            and record.get("runsc_files") == runsc_files,
            "offline container-runtime installation evidence is incomplete")
    return record


def build_contract(root, lock, summary, packages, install, runsc):
    root = Path(root)
    images = unique_json(root / "image/desktop-images.lock.json")
    selected = images["images"]["generic"]
    contract = {
        "schema": 1,
        "selected": True,
        "installed": True,
        "qualified": False,
        "os_qualified": False,
        "release_qualified": False,
        "requested_packages": unique_json(
            root / "image/container/runtime-requirements.json")["packages"],
        "discovery": {
            "repository": lock["repository"],
            "workflow": lock["workflow"],
            "profile": lock["profile"],
            "run_id": lock["run_id"],
            "run_attempt": lock["run_attempt"],
            "source_commit": lock["source_commit"],
            "base": summary["base"],
            "requirements_sha256": summary["requirements_sha256"],
            "repository_configuration_sha256": summary["repository_configuration_sha256"],
            "rpm_manifest_sha256": summary["rpm_manifest_sha256"],
            "input_bindings_sha256": summary["input_bindings_sha256"],
            "package_count": len(packages),
            "artifact": {"id": lock["candidate_artifact"]["id"],
                         "name": lock["candidate_artifact"]["name"],
                         "bytes": lock["candidate_artifact"]["bytes"],
                         "sha256": lock["candidate_artifact"]["sha256"]},
        },
        "packages": packages,
        "installation": {
            "image_source_commit": selected["tested_commit"],
            "image_manifest_sha256": selected["manifest_sha256"],
            "image_producer": lock["source_image_producer"],
            "before_inventory_sha256": install["before_inventory_sha256"],
            "after_inventory_sha256": install["after_inventory_sha256"],
            "source_inventory_sha256": install["source_inventory_sha256"],
            "requested_root_nevras": install["requested_root_nevras"],
            "added_nevras": install["added_nevras"],
            "rpm_transaction_empty": install["rpm_transaction_empty"],
            "daemon_configuration_sha256": install["daemon_configuration_sha256"],
        },
        "files": {path: {"sha256": file_sha256}
                  for path, file_sha256 in sorted(runsc["package_files"].items())},
        "runsc_package_sha256": runsc["package_sha256"],
        "runsc_repository_fingerprint": runsc["signing_fingerprint"],
    }
    return contract
