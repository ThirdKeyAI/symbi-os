#!/usr/bin/env python3
"""Fail-closed input gate for native Fedora container qualification.

This controller prepares bindings for a future second offline Atomic boot. It
does not convert development fixture evidence into OS qualification: the native
six-run matrix, managed route, escape suite and review remain mandatory.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tomllib


REQUIRED_FEDORA_PACKAGES = {"moby-engine", "docker-cli", "container-selinux"}
FEDORA_REPOSITORY_FINGERPRINT = "4F50A6114CD5C6976A7F1179655A4B02F577861E"
FEDORA_PACKAGE_EVIDENCE_FIELDS = {
    "filename", "bytes", "sha256", "nevra", "vendor", "license",
    "signature_verified", "key_fingerprint",
}
FEDORA_DISCOVERY_FIELDS = {
    "repository", "workflow", "profile", "run_id", "run_attempt", "source_commit", "base",
    "requirements_sha256", "repository_configuration_sha256",
    "rpm_manifest_sha256", "input_bindings_sha256", "package_count", "artifact",
}
FEDORA_INSTALLATION_FIELDS = {
    "image_source_commit", "image_manifest_sha256", "before_inventory_sha256",
    "after_inventory_sha256", "source_inventory_sha256", "requested_root_nevras",
    "added_nevras", "rpm_transaction_empty", "daemon_configuration_sha256", "image_producer",
}
REPOSITORY_FINGERPRINT = "6F1DF85E3A71C24918E727D56FC6D554E32BD943"
SHARED_BOOT_STATUS_INPUTS = {
    "fstab.extra": "image/qualification/fstab.extra",
    "m.service": "image/qualification/m.service",
    "symbi_mountinfo.py": "image/qualification/symbi_mountinfo.py",
    "prepare.py": "image/qualification/prepare.py",
    "q.service": "image/qualification/q.service",
    "source_mount.py": "image/qualification/source_mount.py",
    "status_server.py": "image/qualification/status_server.py",
    "sysusers.conf": "image/qualification/sysusers.conf",
}
RETAINED_GVISOR_INPUTS = (
    "gvisor/Release.gpg",
    "gvisor/archive.gpg",
    "gvisor/package-inventory.json",
    "gvisor/Packages",
    "gvisor/verified-metadata.json",
    "gvisor/Release",
)
FIXTURE_DRIVERS = {"test-filesystem-grants.py", "test-source-broker.py", "test-git-source.py"}
MAX_NATIVE_ARCHIVE_BYTES = 12 * 1024**3
MAX_FIXTURE_ARCHIVE_BYTES = 4 * 1024**3


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rpm_name_from_nevra(nevra):
    """Parse the exact RPM name without accepting a requested-name prefix."""
    require(isinstance(nevra, str) and nevra and not any(ch.isspace() for ch in nevra),
            "Fedora package NEVRA is malformed")
    versioned, separator, architecture = nevra.rpartition(".")
    require(separator == "." and re.fullmatch(r"[A-Za-z0-9_]+", architecture or ""),
            "Fedora package NEVRA architecture is malformed")
    fields = versioned.rsplit("-", 2)
    require(len(fields) == 3
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.-]*", fields[0] or "")
            and fields[1] and fields[2],
            "Fedora package NEVRA name, version or release is malformed")
    return fields[0]


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate qualification input key")
            result[key] = value
        return result
    result = json.loads(Path(path).read_bytes(), object_pairs_hook=unique)
    require(isinstance(result, dict), "qualification input must be a JSON object")
    return result


def retained_input_hashes(root):
    base = Path(root) / "image/container/hosted"
    return {name: sha256(base / name) for name in RETAINED_GVISOR_INPUTS}


def _git(source, *arguments):
    return subprocess.check_output(["git", "-c", f"safe.directory={source}", *arguments], cwd=source, text=True,
                                   timeout=120).strip()


def load_fixture_pin(root):
    root = Path(root)
    pin = unique_json(root / "image/container/native-fixture.lock.json")
    runtime = tomllib.loads((root / "upstream/symbiont.toml").read_text())["revision"]
    require(pin.get("schema") == 1 and pin.get("qualified") is False
            and pin.get("repository") == "https://github.com/ThirdKeyAI/Symbiont"
            and pin.get("runtime_source_revision") == runtime,
            "reviewed fixture pin is not bound to the installed runtime source")
    require(re.fullmatch(r"[a-f0-9]{40}", pin.get("revision", ""))
            and re.fullmatch(r"[a-f0-9]{40}", pin.get("tree", "")),
            "reviewed fixture revision or tree is invalid")
    drivers = pin.get("drivers")
    require(isinstance(drivers, dict) and set(drivers) == FIXTURE_DRIVERS
            and all(re.fullmatch(r"[a-f0-9]{64}", value or "") for value in drivers.values()),
            "reviewed fixture driver hashes are incomplete")
    return pin


def validate_fixture_checkout(source, pin):
    source = Path(source).resolve(strict=True)
    require(_git(source, "rev-parse", "HEAD") == pin["revision"],
            "fixture checkout is not the reviewed merge revision")
    require(_git(source, "rev-parse", "HEAD^{tree}") == pin["tree"],
            "fixture checkout tree changed")
    require(not _git(source, "status", "--porcelain", "--untracked-files=all"),
            "fixture checkout must be clean")
    drivers = {name: sha256(source / "scripts" / name) for name in sorted(FIXTURE_DRIVERS)}
    require(drivers == pin["drivers"], "fixture checkout driver bytes changed")
    return {"revision": pin["revision"], "tree": pin["tree"], "drivers": drivers}


def load_native_fixture_image(root, source_commit, source_pin):
    """Require a reviewed, locally preserved offline fixture OCI before native work."""
    root = Path(root)
    selected = unique_json(root / "image/container/native-fixture-image.lock.json")
    require(re.fullmatch(r"[a-f0-9]{40}", source_commit or "")
            and set(selected) == {"schema", "state", "selected", "qualified",
                                  "os_qualified", "release_qualified", "repository",
                                  "workflow", "producer", "artifact", "fixture_source",
                                  "archive", "scope"}
            and selected.get("schema") == 1
            and selected.get("repository") == {
                "id": 1472078858, "full_name": "ThirdKeyAI/symbi-os"}
            and set(selected.get("workflow", {})) == {"id", "path"}
            and set(selected.get("producer", {})) == {
                "run_id", "run_attempt", "event", "head_sha", "status", "conclusion"}
            and set(selected.get("artifact", {})) == {"id", "name", "bytes", "sha256"}
            and set(selected.get("archive", {})) == {
                "name", "bytes", "sha256", "image_id", "repo_digest"}
            and selected.get("workflow", {}).get("path")
            == ".github/workflows/container-fixtures.yml"
            and selected.get("qualified") is False
            and selected.get("os_qualified") is False
            and selected.get("release_qualified") is False,
            "native fixture image selector identity or qualification claims changed")
    expected_source = {key: source_pin[key] for key in ("revision", "tree", "drivers")}
    require(selected.get("fixture_source") == expected_source,
            "native fixture image selector uses different reviewed fixture bytes")
    if selected.get("state") == "pending":
        require(selected.get("selected") is False
                and selected.get("scope")
                == "Pending offline fixture OCI; no run, artifact or image identity has been selected"
                and selected.get("workflow", {}).get("id") is None
                and selected.get("producer") == {
                    "run_id": None, "run_attempt": None, "event": "workflow_dispatch",
                    "head_sha": None, "status": "pending", "conclusion": None}
                and selected.get("artifact") == {
                    "id": None, "name": "container-native-fixture-image",
                    "bytes": None, "sha256": None}
                and selected.get("archive") == {
                    "name": "symbi-native-fixture.oci.tar", "bytes": None,
                    "sha256": None, "image_id": None, "repo_digest": None},
                "pending native fixture selector contains invented output identity")
        return {"ready": False, "blocker": "pending-native-fixture-image",
                "selector_sha256": sha256(root / "image/container/native-fixture-image.lock.json")}
    require(selected.get("state") == "selected" and selected.get("selected") is True,
            "native fixture image selector has an unsupported state")
    workflow, producer = selected.get("workflow", {}), selected.get("producer", {})
    artifact, archive = selected.get("artifact", {}), selected.get("archive", {})
    require(type(workflow.get("id")) is int and workflow["id"] > 0
            and type(producer.get("run_id")) is int and producer["run_id"] > 0
            and type(producer.get("run_attempt")) is int and producer["run_attempt"] > 0
            and producer.get("event") == "workflow_dispatch"
            and producer.get("head_sha") == source_commit
            and producer.get("status") == "completed"
            and producer.get("conclusion") == "success",
            "native fixture producer identity is incomplete or unsuccessful")
    require(type(artifact.get("id")) is int and artifact["id"] > 0
            and artifact.get("name") == "container-native-fixture-image"
            and type(artifact.get("bytes")) is int and 0 < artifact["bytes"] <= MAX_FIXTURE_ARCHIVE_BYTES
            and re.fullmatch(r"[a-f0-9]{64}", artifact.get("sha256", "")),
            "native fixture artifact identity is invalid")
    require(archive.get("name") == "symbi-native-fixture.oci.tar"
            and type(archive.get("bytes")) is int and 0 < archive["bytes"] <= MAX_FIXTURE_ARCHIVE_BYTES
            and re.fullmatch(r"[a-f0-9]{64}", archive.get("sha256", ""))
            and re.fullmatch(r"sha256:[a-f0-9]{64}", archive.get("image_id", ""))
            and re.fullmatch(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}",
                             archive.get("repo_digest", "")),
            "native fixture OCI identity is invalid")
    path = root / ".cache/container-native-fixture-inputs" / archive["name"]
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"ready": False, "blocker": "missing-native-fixture-image",
                "selector_sha256": sha256(root / "image/container/native-fixture-image.lock.json")}
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not path.is_symlink()
            and info.st_size == archive["bytes"] and sha256(path) == archive["sha256"],
            "preserved native fixture OCI differs from its reviewed selector")
    return {"ready": True, "path": path, "selector": selected,
            "selector_sha256": sha256(root / "image/container/native-fixture-image.lock.json")}


def verify_release_signature(keyring, signature, release, fingerprint):
    result = subprocess.run(
        ["/usr/bin/gpgv", "--status-fd=1", "--keyring", str(keyring),
         str(signature), str(release)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "GNUPGHOME": "/nonexistent"},
    )
    rows = [line.split() for line in result.stdout.splitlines() if line.startswith("[GNUPG:] ")]
    valid = [row[2] for row in rows if len(row) >= 3 and row[1] == "VALIDSIG"]
    bad = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY"}
    require(result.returncode == 0 and valid == [fingerprint]
            and not any(len(row) >= 2 and row[1] in bad for row in rows),
            "retained gVisor repository metadata signature is not valid")


def validate_runsc_records(lock, metadata, inventory, hashes):
    require(lock.get("schema") == 1, "unknown hosted input lock schema")
    expected_hashes = lock.get("input_sha256")
    require(isinstance(expected_hashes, dict), "hosted input lock has no retained hashes")
    for name in RETAINED_GVISOR_INPUTS:
        require(hashes.get(name) == expected_hashes.get(name),
                "retained gVisor input differs from its committed lock")
    require(metadata.get("signature_verified") is True
            and metadata.get("signing_fingerprint") == REPOSITORY_FINGERPRINT,
            "gVisor repository metadata lacks the selected publisher signature")
    require(metadata.get("package_downloaded") is True
            and metadata.get("package_sha256_verified") is True,
            "gVisor package bytes were not hash verified")
    require(metadata.get("package_index_sha256") == hashes["gvisor/Packages"],
            "gVisor package index binding changed")
    files = metadata.get("files")
    require(isinstance(files, dict), "gVisor metadata has no retained file hashes")
    for name in ("archive.gpg", "Release", "Release.gpg", "Packages"):
        require(files.get(name) == hashes["gvisor/" + name],
                "gVisor signed repository input changed")
    require(metadata.get("archive_inspection", {}).get("inventory_sha256")
            == hashes["gvisor/package-inventory.json"],
            "gVisor package inventory binding changed")
    package = metadata.get("package")
    require(isinstance(package, dict) and package.get("Package") == "runsc"
            and package.get("Version") == "20261123.0"
            and package.get("Architecture") == "amd64",
            "unexpected gVisor package identity")
    require(re.fullmatch(r"[a-f0-9]{64}", package.get("SHA256", ""))
            and int(package.get("Size", "0")) > 0,
            "invalid gVisor package digest or size")
    expected_url = "https://storage.googleapis.com/gvisor/releases/" + package["Filename"]
    require(metadata.get("package_url") == expected_url,
            "gVisor package URL differs from signed repository metadata")
    require(inventory.get("package_version") == package["Version"]
            and inventory.get("package_sha256") == package["SHA256"]
            and inventory.get("extracted") is False and inventory.get("executed") is False,
            "gVisor package inventory describes different or previously executed bytes")
    entries = inventory.get("entries")
    require(isinstance(entries, list) and entries, "gVisor package inventory is empty")
    paths = [row.get("path") if isinstance(row, dict) else None for row in entries]
    require(None not in paths and len(paths) == len(set(paths)),
            "gVisor package inventory has malformed or duplicate paths")
    package_files = {}
    executable_files = {}
    for row in entries:
        path = row["path"]
        require(not path.startswith("/") and ".." not in Path(path).parts,
                "gVisor package inventory path escapes its root")
        if row.get("type") == "0":
            digest = row.get("sha256")
            require(re.fullmatch(r"[a-f0-9]{64}", digest or ""),
                    "gVisor package file is missing its digest")
            package_files[path] = digest
            if row.get("mode") == 0o755:
                executable_files[path] = digest
    require(package_files.get("usr/bin/runsc")
            == "fcf27497492d44de3d1406d64bd72e038822bed74dea429efb338edf0b2ceeb8",
            "gVisor package contains different runsc bytes")
    require("usr/bin/containerd-shim-runsc-v1" in executable_files
            and len(executable_files) == 9,
            "gVisor executable inventory is incomplete")
    return {
        "package_version": package["Version"],
        "package_sha256": package["SHA256"],
        "package_bytes": int(package["Size"]),
        "package_url": expected_url,
        "signing_fingerprint": REPOSITORY_FINGERPRINT,
        "runsc_sha256": package_files["usr/bin/runsc"],
        "package_files": package_files,
        "executable_files": executable_files,
        "selected_for_release": False,
        "scope": "Authenticated development input; Fedora selection and native qualification remain open",
    }


def load_authenticated_runsc(root, verify=verify_release_signature):
    root = Path(root)
    base = root / "image/container/hosted"
    lock = unique_json(base / "inputs.lock.json")
    metadata = unique_json(base / "gvisor/verified-metadata.json")
    inventory = unique_json(base / "gvisor/package-inventory.json")
    hashes = retained_input_hashes(root)
    identity = validate_runsc_records(lock, metadata, inventory, hashes)
    verify(base / "gvisor/archive.gpg", base / "gvisor/Release.gpg",
           base / "gvisor/Release", identity["signing_fingerprint"])
    return identity


def validate_fedora_contract(contract, runsc, root, image_source_commit):
    require(contract.get("schema") == 1 and contract.get("selected") is True
            and contract.get("installed") is True
            and contract.get("qualified") is False
            and contract.get("os_qualified") is False
            and contract.get("release_qualified") is False,
            "Fedora container runtime contract is not selected, installed and explicitly unqualified")
    root = Path(root)
    requirements_path = root / "image/container/runtime-requirements.json"
    requirements = unique_json(requirements_path)
    requested = requirements.get("packages")
    require(isinstance(requested, list) and len(requested) == len(set(requested))
            and set(requested) == REQUIRED_FEDORA_PACKAGES
            and contract.get("requested_packages") == requested,
            "Fedora runtime requirements are not bound to the reviewed package request")
    pins = unique_json(root / "image/base-images.json")
    repository = unique_json(root / "image/hyprland/package-repository-inputs.json")
    images = unique_json(root / "image/desktop-images.lock.json")
    selected_image = images.get("images", {}).get("generic", {})
    candidate_lock = unique_json(root / "image/container/fedora-runtime-candidates.lock.json")
    from image.container.runtime_image_inputs import validate_selection, validate_source_package_plan
    validate_selection(root, candidate_lock)

    discovery = contract.get("discovery")
    require(isinstance(discovery, dict) and set(discovery) == FEDORA_DISCOVERY_FIELDS,
            "Fedora discovery binding fields are incomplete or expanded")
    require(candidate_lock.get("selected") is True
            and candidate_lock.get("installed") is False
            and candidate_lock.get("qualified") is False
            and candidate_lock.get("os_qualified") is False
            and discovery.get("repository") == candidate_lock.get("repository")
            and discovery.get("workflow") == candidate_lock.get("workflow")
            and discovery.get("profile") == candidate_lock.get("profile")
            and discovery.get("run_id") == candidate_lock.get("run_id")
            and discovery.get("run_attempt") == candidate_lock.get("run_attempt")
            and discovery.get("source_commit") == candidate_lock.get("source_commit")
            and discovery.get("base") == pins["variants"]["generic"]["image"]
            and discovery.get("requirements_sha256") == sha256(requirements_path)
            and discovery.get("repository_configuration_sha256")
            == repository["selected_configuration_sha256"]
            and re.fullmatch(r"[a-f0-9]{64}", discovery.get("rpm_manifest_sha256", ""))
            and re.fullmatch(r"[a-f0-9]{64}", discovery.get("input_bindings_sha256", "")),
            "Fedora discovery is not bound to the reviewed workflow inputs")
    artifact = discovery.get("artifact")
    require(isinstance(artifact, dict)
            and set(artifact) == {"id", "name", "bytes", "sha256"}
            and artifact == candidate_lock.get("candidate_artifact"),
            "Fedora discovery candidate artifact identity is invalid")

    packages = contract.get("packages")
    require(isinstance(packages, list) and 0 < len(packages) <= 512
            and discovery.get("package_count") == len(packages),
            "Fedora runtime package closure is empty or exceeds the discovery bound")
    filenames = set()
    nevras = set()
    package_names = set()
    package_nevras_by_name = {}
    total_bytes = 0
    for package in packages:
        require(isinstance(package, dict) and set(package) == FEDORA_PACKAGE_EVIDENCE_FIELDS,
                "Fedora package must contain only actual RPM discovery evidence fields")
        filename = package.get("filename")
        nevra = package.get("nevra")
        package_name = rpm_name_from_nevra(nevra)
        size = package.get("bytes")
        require(isinstance(filename, str) and filename.endswith(".rpm")
                and filename == Path(filename).name
                and "/" not in filename and "\\" not in filename
                and filename not in filenames
                and type(size) is int and size > 0
                and re.fullmatch(r"[a-f0-9]{64}", package.get("sha256", ""))
                and isinstance(nevra, str) and nevra and not any(ch.isspace() for ch in nevra)
                and nevra not in nevras
                and isinstance(package.get("vendor"), str) and package["vendor"]
                and isinstance(package.get("license"), str) and package["license"]
                and package.get("signature_verified") is True
                and isinstance(package.get("key_fingerprint"), str)
                and package["key_fingerprint"].upper()
                == FEDORA_REPOSITORY_FINGERPRINT
                and package_name not in package_names,
                "Fedora package closure has invalid RPM signature evidence or duplicate identity")
        filenames.add(filename)
        nevras.add(nevra)
        package_names.add(package_name)
        package_nevras_by_name[package_name] = nevra
        total_bytes += size
    require(discovery.get("package_count") == candidate_lock.get("package_count")
            and total_bytes == candidate_lock.get("package_bytes"),
            "Fedora runtime package closure differs from the selected artifact bound")
    require(set(requested).issubset(package_names),
            "Fedora runtime package closure omits a requested package")

    installation = contract.get("installation")
    source_plan = candidate_lock.get("source_package_plan")
    source_binding = validate_source_package_plan(
        root, candidate_lock, source_plan.get("requested_root_nevras")
        if isinstance(source_plan, dict) else None)
    require(isinstance(installation, dict)
            and set(installation) == FEDORA_INSTALLATION_FIELDS,
            "Fedora installation binding fields are incomplete or expanded")
    require(re.fullmatch(r"[a-f0-9]{40}", image_source_commit or "")
            and installation.get("image_source_commit") == image_source_commit
            and image_source_commit == selected_image.get("tested_commit")
            and installation.get("image_producer") == candidate_lock.get("source_image_producer")
            and installation.get("image_manifest_sha256")
            == selected_image.get("manifest_sha256")
            and re.fullmatch(r"[a-f0-9]{64}", installation.get("before_inventory_sha256", ""))
            and re.fullmatch(r"[a-f0-9]{64}", installation.get("after_inventory_sha256", ""))
            and isinstance(source_plan, dict)
            and installation.get("source_inventory_sha256")
            == source_binding.get("source_inventory_sha256")
            and installation.get("before_inventory_sha256")
            == installation.get("source_inventory_sha256")
            and installation.get("after_inventory_sha256")
            == installation.get("source_inventory_sha256")
            and installation.get("requested_root_nevras")
            == source_binding.get("requested_root_nevras")
            and installation.get("requested_root_nevras")
            == {name: package_nevras_by_name.get(name) for name in sorted(requested)}
            and installation.get("added_nevras") == source_binding.get("additive_nevras") == []
            and installation.get("rpm_transaction_empty") is True
            and source_plan.get("replacements_allowed") is False
            and installation.get("daemon_configuration_sha256")
            == sha256(root / "image/container/daemon.json"),
            "Fedora installation is not bound to the unchanged source inventory and signed roots")
    require(contract.get("runsc_package_sha256") == runsc["package_sha256"]
            and contract.get("runsc_repository_fingerprint") == runsc["signing_fingerprint"],
            "Fedora contract uses different runsc package provenance")
    files = contract.get("files")
    require(isinstance(files, dict) and set(files) == set(runsc["package_files"]),
            "Fedora contract runsc package file inventory is incomplete or expanded")
    for path, expected in runsc["package_files"].items():
        require(isinstance(files.get(path), dict)
                and files[path].get("sha256") == expected,
                "Fedora contract runsc package file digest changed")


def build_container_boot_binding(candidate, contract):
    """Bind the first native boot to the selected derived OCI and its contract."""
    selection = candidate.get("selection") if isinstance(candidate, dict) else None
    generated = candidate.get("manifest") if isinstance(candidate, dict) else None
    selected_manifest = selection.get("manifest") if isinstance(selection, dict) else None
    archive = generated.get("archive") if isinstance(generated, dict) else None
    require(isinstance(selected_manifest, dict) and isinstance(generated, dict)
            and isinstance(archive, dict)
            and archive == selected_manifest.get("archive")
            and generated.get("contract_sha256") == selected_manifest.get("contract_sha256")
            and re.fullmatch(r"[a-f0-9]{64}", selected_manifest.get("sha256", ""))
            and re.fullmatch(r"[a-f0-9]{64}", selected_manifest.get("contract_sha256", ""))
            and archive.get("name") == "symbi-container-runtime-generic.oci.tar.gz"
            and type(archive.get("bytes")) is int
            and 0 < archive["bytes"] <= MAX_NATIVE_ARCHIVE_BYTES
            and re.fullmatch(r"[a-f0-9]{64}", archive.get("sha256", ""))
            and re.fullmatch(r"sha256:[a-f0-9]{64}", archive.get("image_id", ""))
            and re.fullmatch(r"sha256:[a-f0-9]{64}", archive.get("manifest_digest", "")),
            "derived container image boot identity is incomplete or changed")
    require(isinstance(contract, dict)
            and contract.get("qualified") is False
            and contract.get("os_qualified") is False
            and contract.get("release_qualified") is False,
            "generated container contract made a qualification claim before native boot")
    files = contract.get("files")
    require(isinstance(files, dict) and 0 < len(files) <= 64,
            "generated container contract has no bounded runsc file set")
    runsc_files = {}
    for relative, item in files.items():
        path = PurePosixPath(relative) if isinstance(relative, str) else None
        require(path is not None and str(path) == relative and "\\" not in relative
                and not path.is_absolute() and ".." not in path.parts
                and path.parts and path.parts[0] in ("usr", "etc")
                and isinstance(item, dict) and set(item) == {"sha256"}
                and re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")),
                "generated container contract contains an unsafe runsc file binding")
        runsc_files[relative] = item["sha256"]
    installation = contract.get("installation")
    require(isinstance(installation, dict)
            and re.fullmatch(r"[a-f0-9]{64}",
                             installation.get("daemon_configuration_sha256", ""))
            and re.fullmatch(r"[a-f0-9]{64}",
                             installation.get("after_inventory_sha256", ""))
            and installation.get("after_inventory_sha256")
            == installation.get("source_inventory_sha256"),
            "generated container contract installation binding changed")
    return {
        "archive": dict(archive),
        "generated_manifest_sha256": selected_manifest["sha256"],
        "contract_sha256": selected_manifest["contract_sha256"],
        "runsc_files": dict(sorted(runsc_files.items())),
        "daemon_configuration_sha256": installation["daemon_configuration_sha256"],
        "inventory_sha256": installation["after_inventory_sha256"],
        "qualified": False,
        "os_qualified": False,
        "release_qualified": False,
        "remaining_blocker": "native-fedora-six-run-matrix",
    }


def build_preflight(root, source_commit, image_source_commit, verify=verify_release_signature):
    require(re.fullmatch(r"[a-f0-9]{40}", source_commit or "")
            and re.fullmatch(r"[a-f0-9]{40}", image_source_commit or ""),
            "container preflight needs exact source commits")
    root = Path(root)
    runsc = load_authenticated_runsc(root, verify=verify)
    fixture_source = load_fixture_pin(root)
    fixture_image = load_native_fixture_image(root, source_commit, fixture_source)
    result = {
        "schema": 1,
        "card": "P0-05",
        "passed": False,
        "qualified": False,
        "os_qualified": False,
        "release_qualified": False,
        "native_fixture_matrix_passed": False,
        "managed_route_qualified": False,
        "escape_suite_qualified": False,
        "source_commit": source_commit,
        "image_source_commit": image_source_commit,
        "runsc": runsc,
        "fixture_source": fixture_source,
        "fixture_source_lock_sha256": sha256(root / "image/container/native-fixture.lock.json"),
        "native_fixture_image_ready": fixture_image["ready"],
        "native_fixture_image_selector_sha256": fixture_image["selector_sha256"],
        "shared_boot_status_inputs": {
            name: sha256(root / relative) for name, relative in SHARED_BOOT_STATUS_INPUTS.items()
        },
        "blockers": ["native-fedora-six-run-matrix", "managed-route-evidence",
                     "escape-suite-evidence", "required-review"],
        "scope": "Prepared Fedora Atomic container gate; no native or release qualification",
    }
    from image.container.native_image_inputs import validate_consumed_candidate
    candidate = validate_consumed_candidate(root, source_commit)
    if fixture_image["ready"] is not True:
        result["blockers"].insert(0, fixture_image["blocker"])
    else:
        result["native_fixture_image"] = {
            "archive": fixture_image["selector"]["archive"],
            "producer": fixture_image["selector"]["producer"],
            "artifact": fixture_image["selector"]["artifact"],
        }
    if candidate.get("ready") is not True:
        result["blockers"].insert(0, candidate["blocker"])
        result["fedora_runtime_ready"] = False
    else:
        require(candidate["manifest"].get("source_image_commit") == image_source_commit,
                "derived container image uses a different retained source image")
        contract = candidate["contract_path"]
        contract_value = unique_json(contract)
        validate_fedora_contract(contract_value, runsc, root, image_source_commit)
        result["fedora_runtime_ready"] = True
        result["fedora_runtime_lock_sha256"] = sha256(contract)
        result["container_boot"] = build_container_boot_binding(candidate, contract_value)
        result["container_image_selection"] = {
            "producer_run_id": candidate["selection"]["producer"]["run_id"],
            "producer_head_sha": candidate["selection"]["producer"]["head_sha"],
            "artifact": candidate["selection"]["artifact"],
            "variant": candidate["selection"]["variant"],
            "manifest_sha256": candidate["selection"]["manifest"]["sha256"],
            "archive_sha256": candidate["selection"]["manifest"]["archive"]["sha256"],
        }
    return result


def run_container_preflight(root, source_commit, image_source_commit):
    root = Path(root)
    evidence = root / ".cache/container-qualification-evidence"
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = {"schema": 1, "card": "P0-05", "passed": False, "qualified": False,
              "blockers": ["preflight-not-completed"]}
    try:
        result = build_preflight(root, source_commit, image_source_commit)
        result["fixture_checkout"] = validate_fixture_checkout(
            root / ".cache/container-fixture-source", result["fixture_source"])
        # Passing here means only that every immutable input needed before the
        # large image transfer is present and internally consistent.  The
        # native matrix and later route gates remain explicit blockers and the
        # qualification flags stay false.
        boot = result.get("container_boot")
        result["passed"] = (
            result.get("fedora_runtime_ready") is True
            and result.get("native_fixture_image_ready") is True
            and isinstance(boot, dict)
            and boot.get("qualified") is False
            and boot.get("os_qualified") is False
            and boot.get("release_qualified") is False
            and boot.get("remaining_blocker") == "native-fedora-six-run-matrix"
        )
        return result
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
