#!/usr/bin/env python3
"""Create one fixed disposable qualification identity inside the guest overlay."""
import grp
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys


NAME = "symbi-qual"
UID = 10001
STATE = Path("/var/lib/symbi-qualification")
HOME = STATE / "home"
EVIDENCE = STATE / "evidence"
RUNTIME = Path("/run/user/10001")
LINGER = Path("/var/lib/systemd/linger")
CONFIG = (f'u {NAME} {UID} "Disposable Symbi qualification user" '
          f'{HOME} /usr/sbin/nologin\n').encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def absent_identity(lookup, value):
    try:
        lookup(value)
    except KeyError:
        return
    raise ValueError("qualification identity already exists")


def private_directory(path):
    path.mkdir(mode=0o700)
    os.chown(path, UID, UID, follow_symlinks=False)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == UID and info.st_gid == UID
            and stat.S_IMODE(info.st_mode) == 0o700, "unsafe qualification directory")


def main():
    if (len(sys.argv) != 2 or os.geteuid() != 0 or Path("/run/.containerenv").exists()
            or Path("/sys/class/dmi/id/product_name").read_text().strip()
            != "Symbi-Hosted-Landlock-Probe"):
        raise SystemExit("Use only the disposable hosted qualification setup service")
    config = Path(sys.argv[1])
    require(config.read_bytes() == CONFIG, "qualification sysusers input changed")
    state = STATE.lstat()
    require(stat.S_ISDIR(state.st_mode) and state.st_uid == 0 and state.st_gid == 0
            and stat.S_IMODE(state.st_mode) == 0o755, "unsafe qualification state directory")
    require(not HOME.exists() and not HOME.is_symlink()
            and not EVIDENCE.exists() and not EVIDENCE.is_symlink()
            and not RUNTIME.exists() and not RUNTIME.is_symlink(),
            "qualification directories must be new")
    for lookup, value in ((pwd.getpwnam, NAME), (grp.getgrnam, NAME),
                          (pwd.getpwuid, UID), (grp.getgrgid, UID)):
        absent_identity(lookup, value)
    subprocess.run(["/usr/bin/systemd-sysusers", str(config)], stdin=subprocess.DEVNULL,
                   check=True, timeout=30, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    user = pwd.getpwnam(NAME)
    group = grp.getgrnam(NAME)
    require(user.pw_uid == UID and user.pw_gid == UID and group.gr_gid == UID
            and user.pw_name == NAME and group.gr_name == NAME and not group.gr_mem
            and user.pw_dir == str(HOME) and user.pw_shell == "/usr/sbin/nologin",
            "systemd-sysusers created a different qualification identity")
    private_directory(HOME)
    private_directory(EVIDENCE)
    if LINGER.exists() or LINGER.is_symlink():
        info = LINGER.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
                and not info.st_mode & 0o022, "unsafe systemd linger directory")
    else:
        LINGER.mkdir(mode=0o755)
    linger = LINGER / NAME
    descriptor = os.open(linger, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        os.fchown(descriptor, 0, 0)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    subprocess.run(["/usr/bin/systemctl", "start", "user-runtime-dir@10001.service",
                    "user@10001.service"], stdin=subprocess.DEVNULL, check=True, timeout=30,
                   env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    active = subprocess.run(["/usr/bin/systemctl", "is-active", "user@10001.service"],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    require(active.returncode == 0 and active.stdout.strip() == "active",
            "qualification user manager did not become active")
    runtime = RUNTIME.lstat()
    require(stat.S_ISDIR(runtime.st_mode) and runtime.st_uid == UID and runtime.st_gid == UID
            and stat.S_IMODE(runtime.st_mode) == 0o700,
            "qualification user runtime directory is unsafe")


if __name__ == "__main__":
    main()
