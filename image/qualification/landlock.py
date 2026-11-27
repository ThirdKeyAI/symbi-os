#!/usr/bin/env python3
"""Run pinned upstream Landlock qualification inside a disposable Fedora bootc VM.

No host-policy changes, downloads, compilation, VM launch or signing are done.
P0-03 must authenticate the image/binary and provision the bounded guest first.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import stat
import subprocess
import sys

try:
    from vertical_slice import validate_vertical_slice
except ModuleNotFoundError as error:
    if error.name != "vertical_slice":
        raise
    from image.qualification.vertical_slice import validate_vertical_slice

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_CASES = ("onboarding", "files", "source", "git", "managed", "actions",
                  "broker", "lifecycle", "external-effects")
DIGEST_REF = re.compile(r"[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9_./-]+@sha256:[a-f0-9]{64}")
EXPECTED_OS_RELEASE = {"ID": "secureblue", "ID_LIKE": "fedora", "VERSION_ID": "45",
                       "VARIANT_ID": "sericea-main-hardened", "IMAGE_ID": "sericea-main-hardened"}
STATUS_SOCKET = Path("/run/symbi-qualification/status.sock")
MAX_STATUS_BYTES = 128 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate bootc status key")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(result, dict), "bootc status must be a JSON object")
    return result


def command_output(command, cwd=None):
    return subprocess.check_output(command, cwd=cwd, text=True, timeout=30).strip()


def validate_deployment(status, image_ref):
    require(DIGEST_REF.fullmatch(image_ref), "expected image must be digest-pinned")
    entry = status.get("status", {}).get("booted") or {}
    image = entry.get("image") or {}
    ref = image.get("image") or {}
    require(entry.get("incompatible") is False, "bootc deployment is incompatible")
    # composefs has had different imageDigest semantics; qualify it separately.
    require(entry.get("ostree") and not entry.get("composefs"), "expected an OSTree bootc deployment")
    require(ref.get("image") == image_ref, "booted image reference differs from expected immutable reference")
    require(image.get("imageDigest") == image_ref.split("@", 1)[1], "booted image digest mismatch")
    require(ref.get("transport") == "registry" and ref.get("signature") == "containerPolicy",
            "booted deployment does not use containers signature policy")
    # Policy mode is metadata, not cryptographic proof. P0-03 retains the actual
    # signature verification and unsigned-rebase rejection for this exact image.


def validate_os_release(release):
    """Bind qualification to the authenticated generic product base identity."""
    require(isinstance(release, dict), "OS release metadata must be a mapping")
    require(all(release.get(name) == value for name, value in EXPECTED_OS_RELEASE.items()),
            "selected secureblue Fedora 45 generic image required")


def read_bootc_status(path):
    """Read one output-only response from the fixed root status service."""
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(120)
    try:
        client.connect(str(path))
        client.shutdown(socket.SHUT_WR)
        chunks = []
        total = 0
        while chunk := client.recv(16 * 1024):
            total += len(chunk)
            if total > MAX_STATUS_BYTES:
                raise ValueError("bootc status response exceeded its bound")
            chunks.append(chunk)
    finally:
        client.close()
    if not chunks:
        raise ConnectionError("fixed bootc status service returned no report")
    return unique_json(b"".join(chunks))


def validate_status_socket(path):
    require(path == STATUS_SOCKET and path.parent.resolve(strict=True) == path.parent,
            "fixed bootc status socket required")
    parent = path.parent.stat()
    info = path.lstat()
    require(parent.st_uid == 0 and parent.st_gid == 0 and parent.st_mode & 0o777 == 0o755,
            "unsafe bootc status parent")
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o666, "unsafe bootc status socket")


def host_details():
    require(__debug__, "Python assertions must remain enabled")
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 required")
    require(os.geteuid() != 0, "qualification must run as the non-root runtime user")
    release = platform.freedesktop_os_release()
    validate_os_release(release)
    virt = command_output(["systemd-detect-virt", "--vm"])
    require(virt in ("kvm", "qemu"), "disposable QEMU/KVM guest required")
    require(subprocess.run(["systemd-detect-virt", "--container", "--quiet"],
                           timeout=10).returncode == 1, "containers are not Fedora boot qualification")
    require(os.cpu_count() == 1, "guest must expose exactly one CPU")
    mem_kib = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                       if line.startswith("MemTotal:")))
    require(mem_kib <= 2 * 1024 * 1024, "guest exceeds the 2 GiB memory ceiling")
    require(Path("/sys/fs/cgroup/cgroup.controllers").is_file(), "cgroup v2 required")
    require(command_output(["getenforce"]) == "Enforcing", "SELinux must remain enforcing")
    return {"os_release": release, "virtualization": virt, "memory_kib": mem_kib,
            "cpus": os.cpu_count(), "kernel": platform.release(), "selinux": "Enforcing"}


def validate_source(source, revision):
    require(command_output(["git", "rev-parse", "HEAD"], source) == revision, "runtime source pin mismatch")
    require(not command_output(["git", "status", "--porcelain", "--untracked-files=all"], source),
            "runtime source checkout must be clean")


def validate_results(native, release, binary_hash, revision, abi):
    for name in ("passed", "qualified", "cleanup_confirmed", "binary_unchanged", "policy_unchanged"):
        require(native.get(name) is True, f"platform {name} is not true")
    require(native.get("expected") == "usable", "a namespace refusal is not usable-platform qualification")
    require(native.get("landlock_abi") == abi and abi >= 6, "Landlock ABI mismatch")
    require(native.get("binary_sha256") == binary_hash, "platform binary hash mismatch")
    require(release.get("passed") is True and release.get("binary_unchanged") is True,
            "release driver did not pass with an unchanged binary")
    require(release.get("sha") == revision and release.get("dirty") is False, "release source mismatch or dirty tree")
    require(release.get("binary_sha256") == binary_hash, "release binary hash mismatch")
    require(release.get("profile") == "full-linux", "full Linux release profile required")
    cases = release.get("cases", [])
    require(sorted(row.get("name", "") for row in cases) == sorted(REQUIRED_CASES), "missing or duplicate release suites")
    require(all(row.get("passed") is True and row.get("exit_code") == 0 for row in cases), "a release suite failed")
    for row in cases:
        if row["name"] in ("broker", "lifecycle", "external-effects"):
            require(row.get("verification_exit_code") == 0 and row.get("integrity_exit_code") == 0,
                    "independent evidence verification or integrity check failed")


def public_reports(output):
    """An exact allowlist; never recursively publish upstream private-actions/."""
    names = ["bootc-before.json", "bootc-after.json", "platform.json", "platform.log",
             "release-driver.log", "release/qualification.json", "vertical-slice.json"]
    for name in REQUIRED_CASES:
        names += [f"release/{name}.json", f"release/{name}.log",
                  f"release/{name}-verification.json", f"release/{name}-integrity.json"]
    return [output / name for name in names if (output / name).is_file() and not (output / name).is_symlink()]


def run_driver(command, log, timeout):
    # Driver fixtures select their own synthetic credentials. Do not inherit real
    # provider keys or Python import/optimization overrides into qualification.
    keep = ("HOME", "USER", "LOGNAME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
    env = {name: os.environ[name] for name in keep if name in os.environ}
    env.update(PATH="/usr/bin:/bin", LANG="C.UTF-8", PYTHONDONTWRITEBYTECODE="1",
               CARGO_BUILD_JOBS="1", RUST_TEST_THREADS="1", RAYON_NUM_THREADS="1")
    with log.open("x") as stream:
        child = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                                 env=env, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=10)
            raise ValueError("driver deadline exceeded; retain failure evidence and discard the VM")
    require(code == 0, f"driver exited {code}; see {log.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-host", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--expected-revision")
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--image-ref")
    parser.add_argument("--expected-abi", type=int)
    parser.add_argument("--bootc-status-socket", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = {"card": "P0-04", "passed": False, "qualified": False,
              "scope": "this Fedora deployment and binary; synthetic providers only"}
    output = None
    try:
        report["host"] = host_details()
        if args.check_host:
            report["host_ready"] = True
            print(json.dumps(report, indent=2))
            return 0
        require(all((args.source, args.binary, args.expected_revision,
                     args.expected_binary_sha256, args.image_ref,
                     args.expected_abi, args.bootc_status_socket, args.output)),
                "all qualification inputs are required")
        require(re.fullmatch(r"[a-f0-9]{40}", args.expected_revision),
                "invalid runtime source revision")
        require(re.fullmatch(r"[a-f0-9]{64}", args.expected_binary_sha256), "invalid binary digest")
        require(args.expected_abi >= 6, "Landlock ABI must be at least 6")
        revision = args.expected_revision
        source = args.source.resolve(strict=True)
        binary = args.binary.resolve(strict=True)
        validate_source(source, revision)
        require(digest(binary) == args.expected_binary_sha256, "binary does not match authenticated build digest")
        candidate = args.output.resolve()
        require(not candidate.is_relative_to("/tmp"), "qualification output must be on guest disk, outside /tmp")
        require(not candidate.is_relative_to(source), "keep evidence outside the clean source checkout")
        candidate.mkdir(mode=0o700, parents=True, exist_ok=False)
        output = candidate
        validate_status_socket(args.bootc_status_socket)
        bootc = read_bootc_status(args.bootc_status_socket)
        validate_deployment(bootc, args.image_ref)
        (output / "bootc-before.json").write_text(json.dumps(bootc, indent=2) + "\n")
        report.update(runtime_revision=revision, binary_sha256=args.expected_binary_sha256,
                      image_ref=args.image_ref, drivers={name: digest(source / "scripts" / name)
                      for name in ("test-landlock-platform.py", "test-landlock-release.py")})
        run_driver([sys.executable, "-E", "-s", "-B", str(source / "scripts/test-landlock-platform.py"),
                    "--binary", str(binary), "--expected-binary-sha256", args.expected_binary_sha256,
                    "--expected-abi", str(args.expected_abi), "--expect", "usable",
                    "--report", str(output / "platform.json")], output / "platform.log", 180)
        run_driver([sys.executable, "-E", "-s", "-B", str(source / "scripts/test-landlock-release.py"),
                    "--binary", str(binary), "--source-directory", str(source), "--require-clean",
                    "--output", str(output / "release")], output / "release-driver.log", 5400)
        release = json.loads((output / "release/qualification.json").read_text())
        validate_results(json.loads((output / "platform.json").read_text()), release,
                         args.expected_binary_sha256, revision, args.expected_abi)
        scripts = source / "scripts"
        vertical_slice = validate_vertical_slice(
            release,
            json.loads((output / "release/managed.json").read_text()),
            json.loads((output / "release/external-effects-verification.json").read_text()),
            json.loads((output / "release/external-effects-integrity.json").read_text()),
            args.expected_binary_sha256,
            {
                "managed": digest(scripts / "test-landlock-managed.py"),
                "external_effects": digest(scripts / "test-external-effect-recovery.py"),
                "external_effects_verifier": digest(scripts / "verify-external-effect-recovery.py"),
                "external_effects_integrity": digest(scripts / "test-external-effect-integrity.py"),
            },
        )
        (output / "vertical-slice.json").write_text(json.dumps(vertical_slice, indent=2) + "\n")
        validate_source(source, revision)
        require(digest(binary) == args.expected_binary_sha256, "binary changed during qualification")
        after = read_bootc_status(args.bootc_status_socket)
        validate_deployment(after, args.image_ref)
        (output / "bootc-after.json").write_text(json.dumps(after, indent=2) + "\n")
        report.update(passed=True, qualified=True, vertical_slice=vertical_slice)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    finally:
        if output:
            report["public_reports"] = {str(path.relative_to(output)): digest(path) for path in public_reports(output)}
            (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
