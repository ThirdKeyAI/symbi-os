#!/usr/bin/env python3
"""Read public package inputs inside the authenticated base, without networking."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys


def require_fedora_family(fields):
    if fields.get("ID") == "fedora":
        return
    if fields.get("ID") == "secureblue" and "fedora" in fields.get("ID_LIKE", "").split():
        return
    raise ValueError("Expected Fedora or the selected Fedora-based secureblue family")


def require_package_inputs(files, version):
    repositories = sorted(name for name in files if name.endswith(".repo")
                          and ("/yum.repos.d/" in name or str(Path(name).parent) == "/usr/share/dnf5/repos.d"))
    keys = sorted(name for name in files if Path(name).name == f"RPM-GPG-KEY-fedora-{version}-primary")
    if not repositories or not keys:
        raise ValueError("Repository configuration and the current Fedora release key must be discovered")
    return {"repository_files": repositories, "fedora_release_key_files": keys,
            "rpm_signatures_verified": False,
            "scope": "Observed paths and bytes only; select and pin trusted keys before package use"}


def package_metadata_paths(owned, version):
    repositories = {"/etc/yum.repos.d", "/usr/etc/yum.repos.d", "/usr/share/dnf5/repos.d"}
    key_roots = {"/etc/pki/rpm-gpg", "/usr/etc/pki/rpm-gpg", "/usr/share/pki/rpm-gpg"}
    return [Path(name) for name in owned
            if (str(Path(name).parent) in repositories and Path(name).suffix == ".repo")
            or (str(Path(name).parent) in key_roots and Path(name).name == f"RPM-GPG-KEY-fedora-{version}-primary")]


def discover_tools(names, directories=(Path("/usr/bin"), Path("/usr/sbin"))):
    # An admin executable may live in sbin. Do not consult inherited PATH or
    # treat a non-executable regular file as an installed tool.
    path = os.pathsep.join(str(directory) for directory in directories)
    return {name: shutil.which(name, path=path) for name in names}


def discover_controls(roots):
    """Bounded public configuration evidence; links are recorded, not followed."""
    fixed = ("sudoers", "sddm.conf", "gdm/custom.conf", "greetd/config.toml",
             "lightdm/lightdm.conf", "sysctl.conf",
             "systemd/system/display-manager.service",
             "systemd/system/getty@.service", "systemd/system/serial-getty@.service")
    patterns = ("sudoers.d/*", "sddm.conf.d/*.conf", "lightdm/lightdm.conf.d/*.conf",
                "sysctl.d/*.conf", "polkit-1/rules.d/*.rules",
                "systemd/system/getty@*.service.d/*.conf",
                "systemd/system/serial-getty@*.service.d/*.conf")
    result = {"files": {}, "links": {}, "missing_fixed_paths": [],
              "scope": "Selected public base configuration only; not effective boot policy or a privilege test"}
    paths = {}

    def remember_link(root, path):
        relative = path.relative_to(root)
        for parent in (root, *(root.joinpath(*relative.parts[:i]) for i in range(1, len(relative.parts) + 1))):
            if parent.is_symlink():
                result["links"][str(parent)] = os.readlink(parent)
                return True
        return False

    for root in roots:
        for name in fixed:
            path = root / name
            if remember_link(root, path):
                continue
            if path.exists():
                paths[path] = root
            else:
                result["missing_fixed_paths"].append(str(path))
        for pattern in patterns:
            prefix = root
            for part in Path(pattern).parts:
                if "*" in part:
                    break
                prefix /= part
            if remember_link(root, prefix):
                continue
            for path in root.glob(pattern):
                if not remember_link(root, path):
                    paths[path] = root
    if len(paths) > 512:
        raise ValueError("Too many public control files")
    total = 0
    for path in sorted(paths):
        if remember_link(paths[path], path):
            continue
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("Non-regular public control file: " + str(path))
        with path.open("rb") as stream:
            data = stream.read(262145)
        total += len(data)
        if len(data) > 262144 or total > 2097152:
            raise ValueError("Public control evidence too large: " + str(path))
        if b"PRIVATE KEY" in data:
            raise ValueError("Unexpected private material in public controls")
        result["files"][str(path)] = {"sha256": hashlib.sha256(data).hexdigest(), "text": data.decode()}
    return result


def main():
    if not Path("/run/.containerenv").exists():
        raise SystemExit("Run inside the authenticated inventory container")
    group = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip() for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    assert limits == {"memory.max": "536870912", "memory.swap.max": "0", "cpu.max": "50000 100000", "pids.max": "64"}, limits
    release = platform.freedesktop_os_release()
    require_fedora_family(release)
    owned = subprocess.check_output(["rpm", "-ql", "fedora-repos", "fedora-gpg-keys"], text=True).splitlines()
    files = {}
    roots = [Path(name) for name in ("/etc", "/usr/etc", "/usr/share/factory/etc", "/usr/share/secureblue/etc")]
    paths = [Path("/etc/os-release")]
    for base in roots:
        paths += [base / "dnf/dnf.conf", base / "containers/policy.json"]
        paths += sorted((base / "yum.repos.d").glob("*.repo"))
        paths += sorted((base / "pki/rpm-gpg").glob("*"))
    paths += sorted(Path("/usr/share/distribution-gpg-keys/fedora").glob(f"*fedora-{release['VERSION_ID']}*"))
    paths += package_metadata_paths(owned, release["VERSION_ID"])
    for path in paths:
        if not path.is_file():
            continue
        data = path.read_bytes()
        assert len(data) <= 262144, str(path)
        assert b"PRIVATE KEY" not in data, str(path)
        files[str(path)] = {"sha256": hashlib.sha256(data).hexdigest(), "text": data.decode()}
    packages = subprocess.check_output(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"], text=True)
    keys = subprocess.run(["rpm", "-q", "gpg-pubkey", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}\n"], capture_output=True, text=True)
    tool_paths = discover_tools(("dnf", "dnf5", "rpm", "gpg", "gcc", "g++", "cmake", "ninja", "Hyprland",
                                "waybar", "walker", "elephant", "foot", "bootc", "sudo", "visudo", "run0", "pkexec"))
    tools = {name: path is not None for name, path in tool_paths.items()}
    result = {"scope": "Read-only authenticated image inventory, no package installation or Fedora boot",
              "os_release": release, "files": files, "installed_packages": sorted(packages.splitlines()),
              "configuration_roots": {str(base): base.is_dir() for base in roots},
              "rpm_key_query": {"exit_code": keys.returncode, "stdout": keys.stdout, "stderr": keys.stderr},
              "tools": tools, "tool_paths": tool_paths, "tool_search_path": "/usr/bin:/usr/sbin",
              "base_controls": discover_controls([*roots, Path("/usr/lib")]),
              "limits": limits, "os_qualified": False}
    result["package_owned_paths"] = owned
    result["tool_configuration"] = []
    for command in (["bootc", "container", "--help"], ["dnf5", "--dump-main-config"]):
        output = subprocess.run(command, capture_output=True, text=True, timeout=15)
        result["tool_configuration"].append({"command": command, "exit_code": output.returncode,
                                              "stdout": output.stdout, "stderr": output.stderr})
    try:
        result["package_inputs"] = require_package_inputs(files, release["VERSION_ID"])
        result["package_inputs_complete"] = True
    except ValueError as error:
        result["package_inputs_complete"] = False
        result["incomplete_reason"] = str(error)
    print(json.dumps(result, indent=2))
    return 0 if result["package_inputs_complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
