"""Verify an authenticated Fedora closure and install gVisor payload/config offline."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat

if __package__:
    from .package_inventory import parse_inventory, serialize_inventory
else:
    from package_inventory import parse_inventory, serialize_inventory


PACKAGE_FIELDS = {
    "filename", "bytes", "sha256", "nevra", "vendor", "license",
    "signature_verified", "key_fingerprint",
}
LIMITS = {"memory.max": "2147483648", "memory.swap.max": "0",
          "cpu.max": "100000 100000", "pids.max": "128"}
FORMAT = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\\n"
QUERY_FORMAT = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{NEVRA}\\n"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate install manifest key")
            result[key] = value
        return result
    value = json.loads(Path(path).read_bytes(), object_pairs_hook=unique,
                       parse_constant=lambda value: (_ for _ in ()).throw(
                           ValueError("noncanonical install manifest number")))
    require(isinstance(value, dict), "install manifest must be an object")
    return value


def select_delta(before, identities, requested_roots, requested_identities, additive_nevras):
    """Require exact installed roots and forbid every unreviewed or replacement delta."""
    serialize_inventory(before)
    require(isinstance(identities, dict) and identities
            and all(isinstance(name, str) and isinstance(value, dict)
                    and set(value) == {"identity", "nevra", "path"}
                    for name, value in identities.items()),
            "candidate package identities are malformed")
    require(isinstance(requested_roots, dict) and requested_roots
            and all(isinstance(name, str) and isinstance(nevra, str)
                    for name, nevra in requested_roots.items()),
            "requested root selection is malformed")
    require(isinstance(requested_identities, dict)
            and set(requested_identities) == set(requested_roots)
            and all(isinstance(value, str) for value in requested_identities.values()),
            "requested root inventory identities are malformed")
    require(isinstance(additive_nevras, list) and additive_nevras == sorted(additive_nevras)
            and len(additive_nevras) == len(set(additive_nevras)),
            "additive package selection is malformed")
    for name, item in identities.items():
        fields = item["identity"].split("\t")
        require(len(fields) == 5 and fields[0] == name,
                "candidate package identity name changed")
    before_set = set(before)
    before_names = {row.split("\t")[0] for row in before}
    for name, expected_nevra in requested_roots.items():
        item = identities.get(name)
        require(isinstance(item, dict) and item["nevra"] == expected_nevra
                and item["identity"] == requested_identities[name]
                and item["identity"] in before_set,
                "signed runtime root differs from the exact installed source identity")
    by_nevra = {item["nevra"]: item for item in identities.values()}
    require(len(by_nevra) == len(identities), "candidate closure repeats a NEVRA")
    delta = []
    for nevra in additive_nevras:
        item = by_nevra.get(nevra)
        require(isinstance(item, dict) and item["identity"] not in before_set
                and item["identity"].split("\t")[0] not in before_names,
                "selected additive package is missing, unknown, or would replace the base")
        delta.append(item)
    return sorted(delta, key=lambda item: item["identity"])


def require_transaction(before, after, delta, required_roots):
    before_raw, after_raw = serialize_inventory(before), serialize_inventory(after)
    added = {item["identity"] for item in delta}
    require(set(after) == set(before) | added,
            "offline installation replaced or added a package outside the reviewed delta")
    require(set(required_roots).issubset(after), "installed image omits a signed runtime root")
    return hashlib.sha256(before_raw).hexdigest(), hashlib.sha256(after_raw).hexdigest()


def _safe_parent(path):
    current = Path("/")
    for part in path.parent.relative_to("/").parts:
        current /= part
        if current.exists() or current.is_symlink():
            require(current.is_dir() and not current.is_symlink(),
                    "installed payload parent is linked or not a directory")
        else:
            current.mkdir(mode=0o755)


def install_regular(source, destination, expected):
    source, destination = Path(source), Path(destination)
    require(source.is_file() and not source.is_symlink()
            and source.stat().st_size == expected["bytes"]
            and digest(source) == expected["sha256"]
            and not destination.exists() and not destination.is_symlink(),
            "installed payload source changed or destination already exists")
    _safe_parent(destination)
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(source_fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size == expected["bytes"],
                "installed payload source is not a regular file")
        target_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                            expected["mode"])
        try:
            with os.fdopen(source_fd, "rb", closefd=False) as incoming, \
                    os.fdopen(target_fd, "wb", closefd=False) as outgoing:
                shutil.copyfileobj(incoming, outgoing, length=1024**2)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            os.fchmod(target_fd, expected["mode"])
            os.fchown(target_fd, 0, 0)
        finally:
            os.close(target_fd)
    finally:
        os.close(source_fd)
    info = destination.lstat()
    require(stat.S_ISREG(info.st_mode) and not destination.is_symlink()
            and stat.S_IMODE(info.st_mode) == expected["mode"]
            and info.st_uid == 0 and info.st_gid == 0
            and info.st_size == expected["bytes"] and digest(destination) == expected["sha256"],
            "installed payload verification failed")


def validate_manifest(manifest):
    fields = {"schema", "qualified", "os_qualified", "release_qualified", "packages",
              "source_package_plan", "key", "runsc_files", "daemon_configuration"}
    require(isinstance(manifest, dict) and set(manifest) == fields
            and manifest.get("schema") == 1 and manifest.get("qualified") is False
            and manifest.get("os_qualified") is False and manifest.get("release_qualified") is False,
            "offline installation manifest fields changed")
    key = manifest.get("key")
    require(isinstance(key, dict) and set(key) == {"fingerprint", "sha256"}
            and re.fullmatch(r"[0-9A-F]{40}", key.get("fingerprint", ""))
            and re.fullmatch(r"[a-f0-9]{64}", key.get("sha256", "")),
            "offline installation key identity is invalid")
    packages = manifest.get("packages")
    require(isinstance(packages, list) and packages and len(packages) <= 512,
            "offline installation package closure is empty or excessive")
    for row in packages:
        require(isinstance(row, dict) and set(row) == PACKAGE_FIELDS
                and row.get("signature_verified") is True
                and row.get("key_fingerprint") == key["fingerprint"],
                "offline installation package evidence changed")
    plan = manifest.get("source_package_plan")
    require(isinstance(plan, dict) and set(plan) == {
                "source_inventory_sha256", "source_package_count", "requested_root_nevras",
                "requested_root_identities", "additive_nevras", "replacements_allowed"}
            and re.fullmatch(r"[a-f0-9]{64}", plan.get("source_inventory_sha256", ""))
            and type(plan.get("source_package_count")) is int and plan["source_package_count"] > 0
            and isinstance(plan.get("requested_root_nevras"), dict)
            and set(plan["requested_root_nevras"]) == {"moby-engine", "docker-cli", "container-selinux"}
            and isinstance(plan.get("requested_root_identities"), dict)
            and set(plan["requested_root_identities"]) == set(plan["requested_root_nevras"])
            and plan.get("additive_nevras") == [] and plan.get("replacements_allowed") is False
            and set(plan["requested_root_nevras"].values())
            .issubset({row.get("nevra") for row in packages}),
            "offline source-image package plan changed")
    files = manifest.get("runsc_files")
    require(isinstance(files, dict) and files
            and all(isinstance(path, str) and not path.startswith("/") and ".." not in Path(path).parts
                    and isinstance(row, dict) and set(row) == {"bytes", "sha256", "mode"}
                    and type(row["bytes"]) is int and row["bytes"] >= 0
                    and re.fullmatch(r"[a-f0-9]{64}", row["sha256"])
                    and row["mode"] in (0o644, 0o755) for path, row in files.items()),
            "offline runsc file manifest is invalid")
    daemon = manifest.get("daemon_configuration")
    require(isinstance(daemon, dict) and set(daemon) == {"bytes", "sha256", "mode"}
            and type(daemon["bytes"]) is int and 0 < daemon["bytes"] <= 65536
            and re.fullmatch(r"[a-f0-9]{64}", daemon["sha256"])
            and daemon["mode"] == 0o644,
            "offline daemon configuration identity is invalid")
    return manifest


def main():
    inputs, output = Path("/symbi-container-inputs"), Path("/symbi-container-evidence")
    if (os.geteuid() != 0 or not (Path("/run/.containerenv").exists() or Path("/.dockerenv").exists())
            or not inputs.is_dir() or not output.is_mount()):
        raise SystemExit("Use the isolated offline container-runtime image build")
    release = platform.freedesktop_os_release()
    require(release.get("ID") in ("fedora", "secureblue")
            and "fedora" in (release.get("ID_LIKE") or "fedora").split()
            and release.get("VERSION_ID") == "45", "container runtime requires the selected Fedora 45 image")
    group = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip() for name in LIMITS}
    require(limits == LIMITS, "offline installation resource limits changed")
    require(sorted(path.name for path in Path("/sys/class/net").iterdir()) == ["lo"],
            "offline installation unexpectedly has a network interface")
    manifest = validate_manifest(unique_json(inputs / "install-manifest.json"))
    record = {"schema": 1, "passed": False, "installed": False, "qualified": False,
              "os_qualified": False, "release_qualified": False, "limits": limits,
              "commands": [], "scope": "Offline signed-root verification and gVisor file installation; native containment qualification remains open"}

    from bounded_process import run_bounded
    from resolve_packages import require_keyring, require_verified_rpm

    def save():
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")

    def run(name, command, timeout=60):
        record["active_command"] = {"name": name, "command": command}
        save()
        result = run_bounded(command, output / (name + "-stdout.log"),
                             output / (name + "-stderr.log"), timeout, 1024**2)
        record["commands"].append({"name": name, "exit_code": result.returncode})
        del record["active_command"]
        save()
        result.check_returncode()
        return result

    try:
        key = inputs / "fedora-45-primary.asc"
        require(key.is_file() and not key.is_symlink() and digest(key) == manifest["key"]["sha256"],
                "Fedora verification key changed")
        before = parse_inventory(
            run("installed-before", ["rpm", "-qa", "--qf", FORMAT]).stdout.encode())
        package_plan = manifest["source_package_plan"]
        source_inventory_hash = hashlib.sha256(serialize_inventory(before)).hexdigest()
        require(len(before) == package_plan["source_package_count"]
                and source_inventory_hash == package_plan["source_inventory_sha256"],
                "actual source-image package inventory differs from the reviewed evidence")
        for name in ("keyring", "rpmdb"):
            (output / name).mkdir(mode=0o700)
        rpmkeys = ["rpmkeys", "--define", "_keyring fs", "--define",
                   "_keyringpath " + str(output / "keyring"), "--dbpath", str(output / "rpmdb"),
                   "--define", "_pkgverify_level all"]
        run("import-key", rpmkeys + ["--import", str(key)])
        require_keyring(run("keyring", rpmkeys + ["--list"]).stdout,
                        manifest["key"]["fingerprint"])
        identities = {}
        for index, row in enumerate(manifest["packages"]):
            package = inputs / "rpms" / row["filename"]
            require(package.parent == inputs / "rpms" and package.name == row["filename"]
                    and package.is_file() and not package.is_symlink()
                    and package.stat().st_size == row["bytes"] and digest(package) == row["sha256"],
                    "signed closure RPM bytes changed")
            signature = run(f"rpm-{index:03}-signature",
                            rpmkeys + ["--checksig", "--verbose", str(package)])
            require_verified_rpm(signature.returncode, signature.stdout,
                                 manifest["key"]["fingerprint"])
            queried = run(f"rpm-{index:03}-identity",
                          ["rpm", "-qp", "--qf", QUERY_FORMAT, str(package)]).stdout.splitlines()
            require(len(queried) == 1 and len(queried[0].split("\t")) == 6,
                    "signed closure RPM has an ambiguous identity")
            name, epoch, version, release_name, arch, nevra = queried[0].split("\t")
            identity = "\t".join((name, epoch, version, release_name, arch))
            require(nevra == row["nevra"] and name not in identities,
                    "signed closure RPM identity changed or duplicates a package name")
            identities[name] = {"identity": identity, "nevra": nevra, "path": str(package)}
        delta = select_delta(before, identities, package_plan["requested_root_nevras"],
                             package_plan["requested_root_identities"],
                             package_plan["additive_nevras"])
        require(delta == [], "the reviewed source-aware RPM transaction must remain empty")
        after = parse_inventory(
            run("installed-after", ["rpm", "-qa", "--qf", FORMAT]).stdout.encode())
        observed_root_identities = {
            name: identities[name]["identity"]
            for name in package_plan["requested_root_nevras"]}
        require(observed_root_identities == package_plan["requested_root_identities"],
                "installed signed root identities differ from the reviewed source inventory")
        required_roots = [observed_root_identities[name]
                          for name in sorted(observed_root_identities)]
        before_hash, after_hash = require_transaction(before, after, delta, required_roots)
        for path, expected in sorted(manifest["runsc_files"].items()):
            install_regular(inputs / "runsc" / path, Path("/") / path, expected)
        install_regular(inputs / "daemon.json", Path("/etc/docker/daemon.json"),
                        manifest["daemon_configuration"])
        installed_files = {}
        for path, expected in sorted(manifest["runsc_files"].items()):
            target = Path("/") / path
            installed_files[path] = {"bytes": target.stat().st_size, "sha256": digest(target),
                                     "mode": stat.S_IMODE(target.stat().st_mode)}
        require(installed_files == manifest["runsc_files"], "installed runsc files changed")
        record.update(
            passed=True, installed=True, all_base_packages_unchanged=True,
            rpm_transaction_empty=True, source_inventory_sha256=source_inventory_hash,
            before_package_count=len(before), after_package_count=len(after),
            before_inventory_sha256=before_hash, after_inventory_sha256=after_hash,
            requested_root_nevras=package_plan["requested_root_nevras"],
            requested_root_identities=observed_root_identities,
            additive_nevras=package_plan["additive_nevras"],
            added_package_names=[], added_nevras=[],
            verified_closure_nevras=sorted(item["nevra"] for item in identities.values()),
            runsc_files=installed_files,
            daemon_configuration_sha256=manifest["daemon_configuration"]["sha256"],
        )
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        record["cgroup_final"] = {name: (group / name).read_text().strip()
                                  for name in (*LIMITS, "memory.peak", "memory.events", "cpu.stat")}
        save()


if __name__ == "__main__":
    main()
