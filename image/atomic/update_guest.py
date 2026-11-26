"""Exercise one phase of an offline signed bootc switch and rollback."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

SOURCE = Path("/var/lib/symbi-update/source")
STATE = Path("/var/lib/symbi-update-test/phase")
CHANNEL = Path("/dev/virtio-ports/org.symbi.update")


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def exact_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value)


def image_digest(entry, expected):
    """Return an exact, policy-authenticated boot entry digest."""
    if not isinstance(entry, dict) or entry.get("incompatible") is not False:
        raise ValueError("missing compatible bootc deployment")
    image = entry.get("image")
    reference = image.get("image", {}) if isinstance(image, dict) else {}
    if (image.get("imageDigest") != expected or image.get("architecture") != "amd64"
            or reference.get("signature") != "containerPolicy"
            or not isinstance(reference.get("transport"), str)
            or not isinstance(reference.get("image"), str)):
        raise ValueError("bootc deployment lost its exact digest or signature policy")
    return image["imageDigest"]


def phase_status(status, booted, *, staged=None, rollback=None, rollback_queued=False):
    try:
        if (status.get("apiVersion") != "org.containers.bootc/v1"
                or status.get("kind") != "BootcHost"
                or status["status"].get("type") != "bootcHost"
                or status["status"].get("rollbackQueued", False) is not rollback_queued):
            raise ValueError("unexpected bootc host state")
        observed = {"booted": image_digest(status["status"].get("booted"), booted)}
        for name, expected in (("staged", staged), ("rollback", rollback)):
            entry = status["status"].get(name)
            if expected is None:
                if entry is not None:
                    raise ValueError("unexpected " + name + " deployment")
            else:
                observed[name] = image_digest(entry, expected)
        return observed
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed bootc status") from error


def write_state(value):
    if value not in ("updated", "rolled-back"):
        raise ValueError("invalid update phase state")
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = STATE.with_name("phase.new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, (value + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, STATE)
    directory = os.open(STATE.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    product = Path("/sys/class/dmi/id/product_name").read_text().strip()
    if (os.geteuid() != 0 or product != "Symbi-Hosted-Update-Probe"
            or Path("/run/.containerenv").exists() or len(sys.argv) != 3):
        raise SystemExit("Use only the disposable hosted update guest")
    expected_path, policy_path = map(Path, sys.argv[1:])
    if expected_path.stat().st_size > 128 * 1024 or policy_path.stat().st_size > 128 * 1024:
        raise ValueError("oversized update credential")
    expected = json.loads(expected_path.read_bytes())
    old, new = expected["old_digest"], expected["new_digest"]
    if (not exact_digest(old) or not exact_digest(new) or old == new
            or not re.fullmatch(r"[a-f0-9]{32}", expected["nonce"])):
        raise ValueError("invalid update expectation")
    record = {"schema": 1, "passed": False, "guest_booted": True,
              "release_qualified": False, "product": product,
              "nonce": expected["nonce"], "expected_sha256": sha256(expected_path),
              "runner_sha256": sha256(Path(__file__)), "commands": [],
              "scope": "Offline ephemeral fixture-signed update and rollback only"}

    def run(command, *, timeout=120, check=True):
        if type(timeout) is not int or not 1 <= timeout <= 1200:
            raise ValueError("invalid update command timeout")
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=timeout, text=True,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
        if len(result.stdout.encode()) > 256 * 1024 or len(result.stderr.encode()) > 128 * 1024:
            raise ValueError("update command output exceeded its bound")
        record["commands"].append({"command": command, "exit_code": result.returncode,
                                   "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                                   "stderr": result.stderr})
        if check:
            result.check_returncode()
        return result.stdout

    try:
        if sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]:
            raise ValueError("update guest gained a network interface")
        if run(["/usr/sbin/getenforce"]).strip() != "Enforcing":
            raise ValueError("SELinux is not enforcing")
        if not os.statvfs(SOURCE).f_flag & os.ST_RDONLY:
            raise ValueError("update source is writable")
        mount = run(["/usr/bin/findmnt", "-n", "-o", "FSTYPE,OPTIONS", "--target", str(SOURCE)]).split()
        if len(mount) != 2 or mount[0] != "ext4" or not {"ro", "nosuid", "nodev", "noexec"}.issubset(set(mount[1].split(","))):
            raise ValueError("update source mount controls changed")
        manifest = SOURCE / "manifest.json"
        signature = SOURCE / "signature-1"
        for path in (manifest, signature):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("update source contains a linked or special control file")
        if (sha256(manifest) != new.removeprefix("sha256:")
                or sha256(signature) != expected["signature_sha256"]
                or sha256(policy_path) != expected["policy_sha256"]
                or sha256(Path("/etc/containers/policy.json")) != expected["original_policy_sha256"]):
            raise ValueError("authenticated update input changed")
        raw_status = lambda: json.loads(run(["/usr/bin/bootc", "status", "--json"]))
        state = STATE.read_text().strip() if STATE.exists() else "installed"
        if state == "installed":
            phase_status(raw_status(), old)
            run(["/usr/bin/mount", "--bind", str(policy_path), "/etc/containers/policy.json"])
            run(["/usr/bin/mount", "-o", "remount,bind,ro", "/etc/containers/policy.json"])
            if sha256(Path("/etc/containers/policy.json")) != expected["policy_sha256"]:
                raise ValueError("guest update policy bind changed")
            run(["/usr/bin/bootc", "switch", "--transport", "dir",
                 "--enforce-container-sigpolicy", str(SOURCE)], timeout=1200)
            phase_status(raw_status(), old, staged=new)
            write_state("updated")
            record["phase"] = {"name": "installed", "booted_digest": old,
                               "operation": "signed-update-staged", "staged_digest": new}
        elif state == "updated":
            phase_status(raw_status(), new, rollback=old)
            run(["/usr/bin/bootc", "rollback"], timeout=300)
            phase_status(raw_status(), new, rollback=old, rollback_queued=True)
            write_state("rolled-back")
            record["phase"] = {"name": "updated", "booted_digest": new,
                               "operation": "rollback-queued", "rollback_digest": old}
        elif state == "rolled-back":
            phase_status(raw_status(), old, rollback=new)
            record["phase"] = {"name": "rolled-back", "booted_digest": old,
                               "rollback_from_digest": new}
        else:
            raise ValueError("unknown persistent update phase")
        record["source_mounted_readonly"] = True
        record["passed"] = True
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
    raw = (json.dumps(record, sort_keys=True) + "\n").encode()
    if len(raw) > 128 * 1024:
        raise ValueError("update guest report exceeds its bound")
    deadline = time.monotonic() + 15
    while not CHANNEL.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    with CHANNEL.open("wb", buffering=0) as output:
        output.write(raw)
    if not record["passed"]:
        raise RuntimeError("update guest phase failed")


if __name__ == "__main__":
    main()
