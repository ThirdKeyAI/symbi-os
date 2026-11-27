"""Install the exact fixture-authenticated OCI into one appliance-only raw disk."""
import json
import os
from pathlib import Path
import sys

from atomic_contract import installer_policy, require_disk, sha256
from contract import installer_arguments, unique_json


def main():
    if (os.geteuid() != 0 or not Path("/run/.containerenv").exists()
            or sys.argv[1:] or sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]):
        raise SystemExit("Use only the offline disposable hosted appliance installer")
    group = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    if limits != {"memory.max": "2147483648", "memory.swap.max": "0",
                  "cpu.max": "100000 100000", "pids.max": "128"}:
        raise ValueError("Installer resource limits changed")
    config = unique_json(Path("/inputs/install.json").read_bytes())
    require_disk(Path("/output/atomic.raw"), config["disk"])
    for path in ("/inputs/signed", "/etc/containers/policy.json"):
        if not os.statvfs(path).f_flag & os.ST_RDONLY:
            raise ValueError("Authenticated source and installer policy mounts must be read-only")
    for path, expected in (
        ("/inputs/signed/manifest.json", config["manifest_digest"].removeprefix("sha256:")),
        ("/inputs/signed/signature-1", config["signature_sha256"]),
        ("/inputs/original-policy.json", config["original_policy_sha256"]),
        ("/inputs/test-public.asc", config["test_public_key_sha256"]),
        ("/etc/containers/policy.json", config["installer_policy_sha256"]),
    ):
        if sha256(Path(path)) != expected:
            raise ValueError("Authenticated source input changed: " + path)
    policy = installer_policy(unique_json(Path("/inputs/original-policy.json").read_bytes()),
                              Path("/inputs/test-public.asc").read_bytes(),
                              config["manifest_digest"])
    if unique_json(Path("/etc/containers/policy.json").read_bytes()) != policy:
        raise ValueError("Installer policy changed release trust or the exact signed local source")
    command = installer_arguments(config["manifest_digest"])
    print(json.dumps({
        "disk": config["disk"], "limits": limits, "command": command,
        "scope": "Fixture-authenticated appliance-only install; no release qualification",
    }), flush=True)
    os.execve(command[0], command, {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
                                   "HOME": "/root", "TMPDIR": "/var/tmp", "RUST_BACKTRACE": "1"})


if __name__ == "__main__":
    main()
