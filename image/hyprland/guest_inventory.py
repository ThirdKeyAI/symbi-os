#!/usr/bin/env python3
"""Read public package inputs inside the authenticated base, without networking."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess


def require_fedora_family(fields):
    if fields.get("ID") == "fedora":
        return
    if fields.get("ID") == "secureblue" and "fedora" in fields.get("ID_LIKE", "").split():
        return
    raise ValueError("Expected Fedora or the selected Fedora-based secureblue family")


def main():
    if not Path("/run/.containerenv").exists():
        raise SystemExit("Run inside the authenticated inventory container")
    group = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip() for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    assert limits == {"memory.max": "536870912", "memory.swap.max": "0", "cpu.max": "50000 100000", "pids.max": "64"}, limits
    release = platform.freedesktop_os_release()
    require_fedora_family(release)
    files = {}
    paths = [Path(name) for name in ("/etc/os-release", "/etc/dnf/dnf.conf", "/etc/containers/policy.json")]
    paths += sorted(Path("/etc/yum.repos.d").glob("*.repo"))
    paths += sorted(Path("/etc/pki/rpm-gpg").glob("*"))
    for path in paths:
        if not path.is_file():
            continue
        data = path.read_bytes()
        assert len(data) <= 262144, str(path)
        assert b"PRIVATE KEY" not in data, str(path)
        files[str(path)] = {"sha256": hashlib.sha256(data).hexdigest(), "text": data.decode()}
    packages = subprocess.check_output(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"], text=True)
    keys = subprocess.run(["rpm", "-q", "gpg-pubkey", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}\n"], capture_output=True, text=True)
    tools = {name: (Path("/usr/bin") / name).is_file() for name in
             ("dnf", "dnf5", "rpm", "gpg", "gcc", "g++", "cmake", "ninja", "Hyprland", "waybar", "walker", "foot", "bootc", "sudo", "visudo")}
    print(json.dumps({"scope": "Read-only authenticated image inventory, no package installation or Fedora boot",
                      "os_release": release, "files": files, "installed_packages": sorted(packages.splitlines()),
                      "rpm_key_query": {"exit_code": keys.returncode, "stdout": keys.stdout, "stderr": keys.stderr},
                      "tools": tools, "limits": limits, "os_qualified": False}, indent=2))


if __name__ == "__main__":
    main()
