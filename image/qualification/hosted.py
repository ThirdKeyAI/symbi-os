#!/usr/bin/env python3
"""Prepare and run the offline hosted Landlock qualification beside Atomic boot."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tomllib
import uuid


SOURCE_DISK_BYTES = 2 * 1024**3
MAX_SOURCE_BYTES = 1024**3
MAX_SOURCE_ENTRIES = 200_000


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _git(source, *arguments):
    return subprocess.check_output(["git", *arguments], cwd=source, text=True,
                                   timeout=120).strip()


def _safe_link(path, root):
    target = os.readlink(path)
    value = PurePosixPath(target)
    if value.is_absolute():
        raise ValueError("source checkout contains an absolute symbolic link")
    depth = len(path.relative_to(root).parent.parts)
    for part in value.parts:
        if part == "..":
            depth -= 1
        elif part not in ("", "."):
            depth += 1
        if depth < 0:
            raise ValueError("source checkout symbolic link escapes its root")


def _source_inventory(source):
    entries = 0
    total = 0
    for path in source.rglob("*"):
        info = path.lstat()
        entries += 1
        if entries > MAX_SOURCE_ENTRIES:
            raise ValueError("source checkout has too many entries")
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
        elif stat.S_ISLNK(info.st_mode):
            _safe_link(path, source)
            total += len(os.readlink(path).encode())
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError("source checkout contains a special file")
        if total > MAX_SOURCE_BYTES:
            raise ValueError("source checkout exceeds its byte bound")
    return {"entries": entries, "bytes": total}


def _reject_repository_credentials(source):
    metadata = source / ".git"
    configs = list(metadata.rglob("config*"))
    if not configs or len(configs) > 256:
        raise ValueError("unexpected Git configuration inventory")
    forbidden = ("extraheader", "credential", "authorization", "password", "token",
                 "proxy", "insteadof", "sshcommand", "askpass", "cookiefile", "include.path")
    for path in configs:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024 * 1024:
            raise ValueError("unsafe Git configuration file")
        text = path.read_text(errors="strict").lower()
        if any(word in text for word in forbidden) or re.search(r"https?://[^/\s@]+@", text):
            raise ValueError("Git checkout configuration contains credentials or routing overrides")
    sensitive_names = {"credentials", ".git-credentials", ".netrc", "cookies", "alternates"}
    for path in metadata.rglob("*"):
        if path.name.lower() in sensitive_names:
            raise ValueError("Git checkout contains external credential or object routing state")


def validate_source_checkout(source, expected_revision):
    source = Path(source).resolve(strict=True)
    if (not re.fullmatch(r"[a-f0-9]{40}", expected_revision) or source.is_symlink()
            or not (source / ".git").is_dir() or not (source / "Cargo.lock").is_file()):
        raise ValueError("invalid pinned source checkout")
    if _git(source, "rev-parse", "HEAD") != expected_revision:
        raise ValueError("runtime source revision changed")
    if _git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("runtime source checkout is not clean")
    tree = _git(source, "rev-parse", "HEAD^{tree}")
    if not re.fullmatch(r"[a-f0-9]{40}", tree):
        raise ValueError("invalid source tree identity")
    submodules = []
    status = _git(source, "submodule", "status", "--recursive")
    for line in status.splitlines() if status else []:
        if not line.startswith(" "):
            raise ValueError("source submodule is missing, changed or uninitialized")
        fields = line[1:].split()
        if len(fields) < 2 or not re.fullmatch(r"[a-f0-9]{40}", fields[0]):
            raise ValueError("invalid source submodule identity")
        submodules.append({"revision": fields[0], "path": fields[1]})
    _reject_repository_credentials(source)
    inventory = _source_inventory(source)
    return {"schema": 1, "source_revision": expected_revision, "source_tree": tree,
            "cargo_lock_sha256": sha256(source / "Cargo.lock"),
            "submodules": submodules, "inventory": inventory,
            "scope": "Exact clean runtime source staged read-only for offline qualification"}


def _chown_tree(root, uid, gid):
    os.chown(root, uid, gid)
    for path in root.rglob("*"):
        os.chown(path, uid, gid, follow_symlinks=False)


def prepare_source_disk(source, expected_revision, storage, run):
    source = Path(source).resolve(strict=True)
    storage = Path(storage)
    manifest = validate_source_checkout(source, expected_revision)
    staging = storage / "landlock-source-tree"
    disk = storage / "landlock-source.raw"
    if staging.exists() or disk.exists():
        raise ValueError("qualification source staging must be new")
    staging.mkdir(mode=0o700)
    shutil.copytree(source, staging / "source", symlinks=True)
    raw = (json.dumps(manifest, sort_keys=True) + "\n").encode()
    (staging / "manifest.json").write_bytes(raw)
    _chown_tree(staging / "source", 10001, 10001)
    os.chown(staging / "manifest.json", 10001, 10001)
    descriptor = os.open(disk, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.ftruncate(descriptor, SOURCE_DISK_BYTES)
    finally:
        os.close(descriptor)
    filesystem_uuid = str(uuid.uuid4())
    try:
        run("landlock-source-filesystem",
            ["/usr/sbin/mkfs.ext4", "-q", "-F", "-m", "0", "-L", "SYMBIQUAL",
             "-U", filesystem_uuid, "-E", "lazy_itable_init=0,lazy_journal_init=0",
             "-d", str(staging), str(disk)], 600)
        probe = run("landlock-source-filesystem-identity",
                    ["/usr/sbin/blkid", "-p", "-o", "export", str(disk)], 30)
        fields = {}
        for line in probe.stdout.splitlines():
            key, value = line.split("=", 1)
            if key in fields:
                raise ValueError("duplicate source filesystem identity")
            fields[key] = value
        if (fields.get("TYPE") != "ext4" or fields.get("LABEL") != "SYMBIQUAL"
                or fields.get("UUID") != filesystem_uuid):
            raise ValueError("source filesystem identity differs from the fixed input")
        os.chmod(disk, 0o444)
        result = {"bytes": disk.stat().st_size, "sha256": sha256(disk),
                  "filesystem": "ext4", "label": "SYMBIQUAL", "uuid": filesystem_uuid,
                  "source_manifest": manifest,
                  "source_manifest_sha256": hashlib.sha256(raw).hexdigest()}
    finally:
        shutil.rmtree(staging)
    return disk, result


def _copy_bounded_output(source, destination):
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    total = 0
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            (destination / relative).mkdir(mode=0o700, exist_ok=True)
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 20 * 1024 * 1024):
            raise ValueError("unsafe hosted qualification output")
        total += info.st_size
        if total > 40 * 1024 * 1024:
            raise ValueError("hosted qualification output exceeded its retained bound")
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    return total


def run_landlock(root, group, podman, image_id, atomic_disk, storage, containers,
                 run, atomic_expected, atomic_record):
    root = Path(root)
    evidence = root / ".cache/landlock-qualification-evidence"
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    result = {"schema": 1, "passed": False, "qualified": False,
              "source_commit": os.environ["GITHUB_SHA"],
              "image_source_commit": atomic_record["image_source_commit"],
              "scope": "Offline Landlock qualification on the exact installed development image"}
    (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    output = None
    try:
        pin = tomllib.loads((root / "upstream/symbiont.toml").read_text())["revision"]
        source = root / ".cache/runtime-source"
        disk, source_disk = prepare_source_disk(source, pin, storage, run)
        runtime = json.loads((root / "image/assembly/runtime-development.lock.json").read_text())
        binary_hash = runtime["binaries"]["symbi"]["sha256"]
        payload = atomic_expected.get("payload", {}).get("usr/bin/symbi", {})
        if (runtime.get("source_revision") != pin or runtime.get("qualified") is not False
                or payload.get("sha256") != binary_hash):
            raise ValueError("installed runtime and hosted source bindings differ")
        image_ref = "ghcr.io/thirdkeyai/symbiont-os@" + atomic_expected["manifest_digest"]
        inputs = storage / "landlock-input"
        inputs.mkdir(mode=0o755)
        files = {
            "boot.py": "image/qualification/boot.py", "guest.py": "image/qualification/guest.py",
            "prepare.py": "image/qualification/prepare.py",
            "landlock.py": "image/qualification/landlock.py",
            "vertical_slice.py": "image/qualification/vertical_slice.py",
            "status_server.py": "image/qualification/status_server.py",
            "fstab.extra": "image/qualification/fstab.extra", "p.service": "image/qualification/p.service",
            "q.service": "image/qualification/q.service", "l.service": "image/qualification/l.service",
            "sysusers.conf": "image/qualification/sysusers.conf",
        }
        for name, relative in files.items():
            shutil.copyfile(root / relative, inputs / name)
            (inputs / name).chmod(0o644)
        expected = {"schema": 1, "nonce": uuid.uuid4().hex, "source_revision": pin,
                    "source_manifest_sha256": source_disk["source_manifest_sha256"],
                    "binary_sha256": binary_hash, "image_ref": image_ref,
                    "minimum_landlock_abi": 6, "source_disk": {key: source_disk[key]
                    for key in ("bytes", "sha256", "filesystem", "label", "uuid")}}
        raw = (json.dumps(expected, sort_keys=True) + "\n").encode()
        if len(raw) > 128 * 1024:
            raise ValueError("qualification expectation exceeded its bound")
        (inputs / "expected.json").write_bytes(raw)
        (inputs / "expected.json").chmod(0o644)
        output = storage / "landlock-output"
        output.mkdir(mode=0o700)
        os.chown(output, 10001, 10001)
        name = "symbi-landlock-qemu"
        containers.append(name)
        common = ["--pull=never", "--network=none", "--pid=private",
                  "--cgroup-parent=/" + str(group.relative_to("/sys/fs/cgroup")),
                  "--env=LANG=C.UTF-8", "--env=PYTHONDONTWRITEBYTECODE=1"]
        command = podman + ["run", "--rm", "--name=" + name, *common, "--read-only",
                            "--user=10001:10001", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                            "--memory=3g", "--memory-swap=3g", "--cpus=2", "--pids-limit=64",
                            "--mount", f"type=bind,src={inputs},dst=/inputs,ro",
                            "--mount", f"type=bind,src={atomic_disk},dst=/inputs/atomic.raw,ro",
                            "--mount", f"type=bind,src={disk},dst=/inputs/source.raw,ro",
                            "--mount", f"type=bind,src={output},dst=/output",
                            "--entrypoint=/usr/bin/python3", image_id, "/inputs/boot.py"]
        result.update(source_revision=pin, source_disk=source_disk,
                      binary_sha256=binary_hash, image_ref=image_ref,
                      inputs={name: sha256(inputs / name) for name in (*files, "expected.json")})
        shutil.copyfile(inputs / "expected.json", evidence / "expected.json")
        (evidence / "source-manifest.json").write_text(
            json.dumps(source_disk["source_manifest"], indent=2) + "\n")
        (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        status = run("landlock-qualification", command, 6000, check=False)
        result["container_exit_code"] = status.returncode
        if not (output / "result.json").is_file():
            raise ValueError("hosted qualification controller produced no result")
        controller = json.loads((output / "result.json").read_text())
        if (status.returncode != 0 or controller.get("passed") is not True
                or controller.get("qualification_qualified") is not True
                or controller.get("source_revision") != pin
                or controller.get("binary_sha256") != binary_hash):
            raise ValueError("hosted Landlock qualification did not pass")
        if sha256(disk) != source_disk["sha256"]:
            raise ValueError("read-only qualification source disk changed")
        if sha256(atomic_disk) != atomic_record["disk_sha256"]:
            raise ValueError("read-only installed Atomic disk changed during qualification")
        retained = _copy_bounded_output(output, evidence / "guest")
        result.update(passed=True, qualified=True, landlock_abi=controller["landlock_abi"],
                      public_reports=controller["public_reports"], retained_bytes=retained)
        return result
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if output is not None and output.is_dir() and not (evidence / "guest").exists():
            try:
                result["retained_bytes"] = _copy_bounded_output(output, evidence / "guest")
            except Exception as error:
                result["retention_failure"] = type(error).__name__ + ": " + str(error)
        (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
