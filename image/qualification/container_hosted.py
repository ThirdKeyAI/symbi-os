#!/usr/bin/env python3
"""Fail-closed input gate for native Fedora container qualification.

This controller prepares bindings for a future second offline Atomic boot. It
does not convert development fixture evidence into OS qualification: the native
six-run matrix, managed route, escape suite and review remain mandatory.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib


REQUIRED_FEDORA_PACKAGES = {"moby-engine", "docker-cli", "container-selinux"}
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


def require(condition, message):
    if not condition:
        raise ValueError(message)


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


def validate_fedora_contract(contract, runsc):
    require(contract.get("schema") == 1 and contract.get("selected") is True
            and contract.get("installed") is True,
            "Fedora container runtime contract is not selected and installed")
    packages = contract.get("packages")
    require(isinstance(packages, dict) and set(packages) == REQUIRED_FEDORA_PACKAGES,
            "Fedora runtime package set is incomplete or contains unreviewed packages")
    for name, package in packages.items():
        require(isinstance(package, dict) and isinstance(package.get("nevra"), str)
                and package["nevra"].startswith(name + "-")
                and re.fullmatch(r"[a-f0-9]{64}", package.get("rpm_sha256", ""))
                and package.get("signature_verified") is True
                and re.fullmatch(r"[A-Fa-f0-9]{40}", package.get("signing_fingerprint", ""))
                and re.fullmatch(r"[a-f0-9]{64}", package.get("repository_metadata_sha256", "")),
                "Fedora package lacks exact signed repository and RPM bindings")
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


def build_preflight(root, source_commit, image_source_commit, verify=verify_release_signature):
    require(re.fullmatch(r"[a-f0-9]{40}", source_commit or "")
            and re.fullmatch(r"[a-f0-9]{40}", image_source_commit or ""),
            "container preflight needs exact source commits")
    root = Path(root)
    runsc = load_authenticated_runsc(root, verify=verify)
    fixture_source = load_fixture_pin(root)
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
        "shared_boot_status_inputs": {
            name: sha256(root / relative) for name, relative in SHARED_BOOT_STATUS_INPUTS.items()
        },
        "blockers": ["native-fedora-six-run-matrix", "managed-route-evidence",
                     "escape-suite-evidence", "required-review"],
        "scope": "Prepared Fedora Atomic container gate; no native or release qualification",
    }
    contract = root / "image/container/fedora-runtime.lock.json"
    if not contract.is_file():
        result["blockers"].insert(0, "missing-fedora-runtime-lock")
        result["fedora_runtime_ready"] = False
    else:
        validate_fedora_contract(unique_json(contract), runsc)
        result["fedora_runtime_ready"] = True
        result["fedora_runtime_lock_sha256"] = sha256(contract)
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
        return result
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
