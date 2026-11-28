#!/usr/bin/python3
"""Build, install, query and bind the minimal Atomic update policy module."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

if __package__:
    from .policy import (BRIDGE_CONTEXT, BRIDGE_PATH, CONTROLLER_CONTEXT,
                         CONTROLLER_PATH, ENTRYPOINT_CONTEXT, ENTRYPOINT_PATH,
                         FC_SOURCE, INSTALL_CONTEXT,
                         INSTALL_TRANSITION_INVENTORY, MANIFEST_PATH, POLICY_NAME,
                         TE_SOURCE, validate_policy_sources,
                         validate_sesearch_evidence)
else:
    from policy import (BRIDGE_CONTEXT, BRIDGE_PATH, CONTROLLER_CONTEXT,
                        CONTROLLER_PATH, ENTRYPOINT_CONTEXT, ENTRYPOINT_PATH,
                        FC_SOURCE, INSTALL_CONTEXT,
                        INSTALL_TRANSITION_INVENTORY, MANIFEST_PATH, POLICY_NAME,
                        TE_SOURCE, validate_policy_sources,
                        validate_sesearch_evidence)


ROOT = Path("/tmp/symbi-atomic-update-policy")
POLICY_MAX_BYTES = 256 * 1024
QUERY_MAX_BYTES = 128 * 1024


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fixed_file(path, *, mode, maximum):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_gid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != mode
                or not 0 < before.st_size <= maximum):
            raise ValueError("image-owned Atomic update file controls differ")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            value = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode,
                                 item.st_uid, item.st_gid, item.st_nlink,
                                 item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after):
            raise ValueError("image-owned Atomic update file changed")
        return value
    finally:
        os.close(descriptor)


def run(command, *, cwd=None):
    result = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=120, check=False,
                            env={"LANG": "C.UTF-8", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    if (len(result.stdout) > QUERY_MAX_BYTES or len(result.stderr) > QUERY_MAX_BYTES
            or result.returncode != 0):
        raise ValueError("Atomic update policy build/query command failed")
    return result.stdout.decode("utf-8", "strict")


def query(policy, mode, source, target, klass, permission=None):
    command = ["/usr/bin/sesearch", mode]
    if source is not None:
        command += ["-s", source]
    if target is not None:
        command += ["-t", target]
    command += ["-c", klass]
    if permission is not None:
        command += ["-p", permission]
    command.append(str(policy))
    raw = run(command)
    if any(not " " <= character <= "~" and character != "\n" for character in raw):
        raise ValueError("Atomic update sesearch output is not bounded ASCII")
    return [" ".join(line.split()) for line in raw.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def contains_permission(lines, source, target, klass, permission):
    prefix = f"allow {source} {target}:{klass} "
    matches = 0
    for line in lines:
        if not line.startswith(prefix) or not line.endswith(";"):
            continue
        value = line[len(prefix):-1]
        if value.startswith("{ ") and value.endswith(" }"):
            permissions = value[2:-2].split()
        elif re.fullmatch(r"[a-z_]+", value) is not None:
            permissions = [value]
        else:
            continue
        matches += permission in permissions
    return matches == 1


def install_transition_inventory(lines):
    """Inventory every controller process transition whose destination is install_t."""
    if not isinstance(lines, list) or len(lines) > 4096 or any(
            not isinstance(line, str) or len(line) > 4096 for line in lines):
        raise ValueError("expanded process transition inventory is invalid")
    if len(set(lines)) != len(lines):
        raise ValueError("expanded process transition inventory is ambiguous")
    pattern = re.compile(
        r"type_transition ([A-Za-z0-9_]+) ([A-Za-z0-9_]+):"
        r"([A-Za-z0-9_]+) ([A-Za-z0-9_]+);")
    install_rules = []
    for line in lines:
        match = pattern.fullmatch(line)
        if (match is None or match.group(1) != "symbi_atomic_update_t"
                or match.group(3) != "process"):
            raise ValueError("expanded process transition rule is not canonical")
        if match.group(4) == "install_t":
            install_rules.append(line)
    return {
        "schema": 1,
        "source": "symbi_atomic_update_t",
        "class": "process",
        "destination": "install_t",
        "rules": sorted(install_rules),
    }


def expanded_evidence(policy):
    transition_inventory = install_transition_inventory(query(
        policy, "-T", "symbi_atomic_update_t", None, "process"))
    required = {
        "init_entrypoint": contains_permission(
            query(policy, "-A", "symbi_atomic_update_t",
                  "symbi_atomic_update_exec_t", "file", "entrypoint"),
            "symbi_atomic_update_t", "symbi_atomic_update_exec_t", "file",
            "entrypoint"),
        "init_transition": contains_permission(
            query(policy, "-A", "init_t", "symbi_atomic_update_t",
                  "process", "transition"),
            "init_t", "symbi_atomic_update_t", "process", "transition"),
        "bridge_entrypoint": contains_permission(
            query(policy, "-A", "install_t", "symbi_bootc_transition_exec_t",
                  "file", "entrypoint"),
            "install_t", "symbi_bootc_transition_exec_t", "file",
            "entrypoint"),
        "bridge_transition": contains_permission(
            query(policy, "-A", "symbi_atomic_update_t", "install_t",
                  "process", "transition"),
            "symbi_atomic_update_t", "install_t", "process", "transition"),
        "bridge_type_transition": (
            transition_inventory == INSTALL_TRANSITION_INVENTORY),
        "install_sigchld": contains_permission(
            query(policy, "-A", "install_t", "symbi_atomic_update_t",
                  "process", "sigchld"),
            "install_t", "symbi_atomic_update_t", "process", "sigchld"),
    }
    forbidden_permissions = (
        "noatsecure", "setexec", "setcurrent", "dyntransition",
        "siginh", "rlimitinh", "sigkill",
    )
    forbidden = {
        "shared_install_type_transition": any(
            rule == "type_transition symbi_atomic_update_t "
            "install_exec_t:process install_t;"
            for rule in transition_inventory["rules"]),
        "generic_install_transition": bool(query(
            policy, "-A", "unconfined_service_t", "install_t",
            "process", "transition")),
        "controller_forbidden_process_permissions": any(
            query(policy, "-A", "symbi_atomic_update_t", None,
                  "process", permission)
            or query(policy, "-A", None, "symbi_atomic_update_t",
                     "process", permission)
            for permission in forbidden_permissions),
        "controller_policy_load": bool(query(
            policy, "-A", "symbi_atomic_update_t", None, "security", "load_policy")),
        "controller_enforcing_change": bool(query(
            policy, "-A", "symbi_atomic_update_t", None, "security", "setenforce")),
    }
    return validate_sesearch_evidence({
        "schema": 2, "policy": POLICY_NAME,
        "install_transition_inventory": transition_inventory,
        "required": required, "forbidden": forbidden,
    })


def main():
    if os.geteuid() != 0 or not (Path("/run/.containerenv").exists()
                                  or Path("/.dockerenv").exists()):
        raise SystemExit("Use only during the image build")
    te = ROOT / (POLICY_NAME + ".te")
    fc = ROOT / (POLICY_NAME + ".fc")
    validate_policy_sources(te.read_bytes(), fc.read_bytes())
    os.chmod(CONTROLLER_PATH, 0o444, follow_symlinks=False)
    controller_hash = fixed_file(CONTROLLER_PATH, mode=0o444,
                                 maximum=POLICY_MAX_BYTES)
    compile_flags = [
        "/usr/bin/gcc", "-std=c17", "-O2", "-fPIE", "-pie", "-fno-ident",
        "-Werror", "-Wall", "-Wextra", "-Wl,-z,relro,-z,now",
        "-Wl,--build-id=none", "-o",
    ]
    run([*compile_flags, str(ENTRYPOINT_PATH),
         str(ROOT / "symbi-atomic-update.c")])
    run([*compile_flags, str(BRIDGE_PATH),
         str(ROOT / "symbi-bootc-transition.c")])
    for path in (ENTRYPOINT_PATH, BRIDGE_PATH):
        os.chmod(path, 0o755, follow_symlinks=False)
    entrypoint_hash = fixed_file(
        ENTRYPOINT_PATH, mode=0o755, maximum=POLICY_MAX_BYTES)
    bridge_hash = fixed_file(
        BRIDGE_PATH, mode=0o755, maximum=POLICY_MAX_BYTES)
    run(["/usr/bin/make", "-f", "/usr/share/selinux/devel/Makefile",
         POLICY_NAME + ".pp"], cwd=ROOT)
    module = ROOT / (POLICY_NAME + ".pp")
    fixed_file(module, mode=0o644, maximum=POLICY_MAX_BYTES)
    run(["/usr/sbin/semodule", "-n", "-X", "400", "-i", str(module)])
    run(["/usr/sbin/restorecon", "-F", str(ENTRYPOINT_PATH),
         str(BRIDGE_PATH)])
    policy_files = sorted(Path("/etc/selinux/targeted/policy").glob("policy.*"))
    if len(policy_files) != 1:
        raise ValueError("installed SELinux policy image is ambiguous")
    evidence = expanded_evidence(policy_files[0])
    label = os.getxattr(ENTRYPOINT_PATH, "security.selinux")
    if label.endswith(b"\0"):
        label = label[:-1]
    if label.decode("ascii", "strict") != ENTRYPOINT_CONTEXT:
        raise ValueError("Atomic update entrypoint label differs")
    bridge_label = os.getxattr(BRIDGE_PATH, "security.selinux")
    if bridge_label.endswith(b"\0"):
        bridge_label = bridge_label[:-1]
    if bridge_label.decode("ascii", "strict") != BRIDGE_CONTEXT:
        raise ValueError("bootc transition bridge label differs")
    manifest = {
        "schema": 1, "policy": POLICY_NAME,
        "entrypoint": {"path": str(ENTRYPOINT_PATH), "sha256": entrypoint_hash,
                       "uid": 0, "gid": 0, "mode": "0755",
                       "selinux_label": ENTRYPOINT_CONTEXT},
        "bridge": {"path": str(BRIDGE_PATH), "sha256": bridge_hash,
                   "uid": 0, "gid": 0, "mode": "0755",
                   "selinux_label": BRIDGE_CONTEXT},
        "controller": {"path": str(CONTROLLER_PATH), "sha256": controller_hash,
                       "uid": 0, "gid": 0, "mode": "0444"},
        "controller_context": CONTROLLER_CONTEXT,
        "install_context": INSTALL_CONTEXT,
        "policy_sources": {"te_sha256": hashlib.sha256(TE_SOURCE).hexdigest(),
                           "fc_sha256": hashlib.sha256(FC_SOURCE).hexdigest(),
                           "launcher_sha256": digest(
                               ROOT / "symbi-atomic-update.c"),
                           "bridge_sha256": digest(
                               ROOT / "symbi-bootc-transition.c")},
        "expanded_policy": evidence,
    }
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    descriptor = os.open(MANIFEST_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_CLOEXEC, 0o444)
    try:
        raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if os.write(descriptor, raw) != len(raw):
            raise OSError("short Atomic update manifest write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
if __name__ == "__main__":
    main()
