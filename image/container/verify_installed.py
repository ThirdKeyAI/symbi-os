"""Read-only installed-image observation for the unqualified runtime candidate."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess


LIMITS = {"memory.max": "536870912", "memory.swap.max": "0",
          "cpu.max": "100000 100000", "pids.max": "64"}
FORMAT = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\\n"


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    expected = json.loads(Path("/qualification/expected.json").read_text())
    group = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip() for name in LIMITS}
    require(os.geteuid() == 10001 and limits == LIMITS, "installed-image probe identity or limits changed")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    require(status["CapEff"].strip() == "0000000000000000"
            and status["NoNewPrivs"].strip() == "1",
            "installed-image probe gained privilege")
    require(sorted(path.name for path in Path("/sys/class/net").iterdir()) == ["lo"],
            "installed-image probe unexpectedly has a network interface")
    mount = next(line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()
                 if line.split()[4] == "/")
    require("ro" in mount[5].split(","), "installed-image probe root is writable")
    rows = sorted(subprocess.check_output(["rpm", "-qa", "--qf", FORMAT], text=True,
                                          timeout=60).splitlines())
    raw = ("\n".join(rows) + "\n").encode()
    require(len(rows) == len(set(rows))
            and hashlib.sha256(raw).hexdigest() == expected["after_inventory_sha256"]
            and expected["after_inventory_sha256"] == expected["source_inventory_sha256"],
            "installed package inventory changed")
    for row in expected["requested_root_identities"].values():
        require(row in rows, "installed image omits an exact signed runtime root")
    observed = {}
    for relative, item in expected["runsc_files"].items():
        path = Path("/") / relative
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
                and info.st_uid == 0 and info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == item["mode"]
                and info.st_size == item["bytes"] and digest(path) == item["sha256"],
                "installed runsc file changed")
        observed[relative] = item["sha256"]
    daemon = Path("/etc/docker/daemon.json")
    require(daemon.is_file() and not daemon.is_symlink()
            and digest(daemon) == expected["daemon_configuration_sha256"],
            "installed daemon configuration changed")
    tools = {name: (Path("/usr/bin") / name).is_file()
             for name in ("docker", "dockerd", "runsc", "containerd-shim-runsc-v1")}
    require(all(tools.values()), "installed container runtime executable is missing")
    print(json.dumps({
        "schema": 1, "passed": True, "installed": True, "qualified": False,
        "os_qualified": False, "release_qualified": False,
        "after_inventory_sha256": expected["after_inventory_sha256"],
        "source_inventory_sha256": expected["source_inventory_sha256"],
        "requested_root_identities": expected["requested_root_identities"],
        "package_count": len(rows), "runsc_files": observed,
        "daemon_configuration_sha256": expected["daemon_configuration_sha256"],
        "tools": tools, "limits": limits,
        "scope": "Read-only candidate image observation; daemon startup and native containment remain unqualified",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
