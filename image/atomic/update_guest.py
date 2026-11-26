"""Exercise one phase of an offline signed bootc switch and rollback."""
import base64
import binascii
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
NEGATIVE_SOURCE = Path("/run/symbi-update-negative/source")
NEGATIVE_CASES = ("unsigned", "wrong-key", "wrong-reference", "altered-signature")
POSITIVE_OVERLAY_CASE = "valid-signature"
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


def deployment_snapshot(status, booted):
    """Capture the configured default and every deployment slot after validation."""
    phase_status(status, booted)
    try:
        default = status["spec"]["image"]
        active = status["status"]["booted"]
        reference = active["image"]["image"]
        if (not isinstance(default, dict) or default != reference
                or default.get("signature") != "containerPolicy"):
            raise ValueError("bootc configured default differs from the booted signed image")
        # The JSON round trip rejects non-serializable values and detaches the
        # comparison from the caller's mutable status object.
        return json.loads(json.dumps({
            "default": default,
            "booted": active,
            "staged": status["status"].get("staged"),
            "rollback": status["status"].get("rollback"),
            "rollback_queued": status["status"].get("rollbackQueued", False),
        }, sort_keys=True))
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed bootc deployment snapshot") from error


def staged_deployment_snapshot(status, booted, staged):
    """Capture an exact successful switch without accepting unrelated state."""
    phase_status(status, booted, staged=staged)
    try:
        default = status["spec"]["image"]
        active = status["status"]["booted"]
        pending = status["status"]["staged"]
        reference = pending["image"]["image"]
        if (not isinstance(default, dict) or default != reference
                or default.get("signature") != "containerPolicy"
                or default.get("transport") != "dir"):
            raise ValueError("bootc configured default differs from the staged signed image")
        return json.loads(json.dumps({
            "default": default,
            "booted": active,
            "staged": pending,
            "rollback": status["status"].get("rollback"),
            "rollback_queued": status["status"].get("rollbackQueued", False),
        }, sort_keys=True))
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed staged bootc deployment snapshot") from error


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
        positive = expected.get("same_path_positive_control")
        negative = expected.get("negative_control")
        if positive is not None or negative is not None:
            if positive is not None and negative is not None:
                raise ValueError("conflicting disposable update controls")
            is_positive = positive is not None
            control = positive if is_positive else negative
            if (not isinstance(control, dict) or STATE.exists()
                    or control.get("source") != str(NEGATIVE_SOURCE)
                    or (is_positive and (set(control) != {"case", "source"}
                                         or control.get("case") != POSITIVE_OVERLAY_CASE))
                    or (not is_positive
                        and (set(control) != {"case", "source", "signature"}
                             or control.get("case") not in NEGATIVE_CASES))):
                raise ValueError("invalid or persistent disposable update control")
            case = control["case"]
            before = deployment_snapshot(raw_status(), old)
            before_hash = hashlib.sha256(json.dumps(
                before, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            root = NEGATIVE_SOURCE.parent
            if root.exists() or root.is_symlink():
                raise ValueError("negative update overlay already exists")
            for path in (root / "upper", root / "work", NEGATIVE_SOURCE):
                path.mkdir(mode=0o700, parents=True, exist_ok=False)
            run(["/usr/bin/mount", "-t", "overlay", "overlay", "-o",
                 "lowerdir=" + str(SOURCE) + ",upperdir=" + str(root / "upper")
                 + ",workdir=" + str(root / "work") + ",nosuid,nodev,noexec",
                 str(NEGATIVE_SOURCE)])
            overlay_signature = NEGATIVE_SOURCE / "signature-1"
            signature_control = None
            if not is_positive:
                overlay_signature.unlink()
                signature_control = negative["signature"]
                if case == "unsigned":
                    if signature_control is not None:
                        raise ValueError("unsigned control unexpectedly supplies a signature")
                else:
                    if (not isinstance(signature_control, dict)
                            or set(signature_control) != {"base64", "sha256"}
                            or not re.fullmatch(r"[a-f0-9]{64}", signature_control.get("sha256", ""))):
                        raise ValueError("invalid negative source signature control")
                    try:
                        payload = base64.b64decode(signature_control["base64"], validate=True)
                    except (binascii.Error, ValueError, TypeError) as error:
                        raise ValueError("invalid negative source signature encoding") from error
                    if (not 0 < len(payload) <= 65536
                            or hashlib.sha256(payload).hexdigest() != signature_control["sha256"]
                            or signature_control["sha256"] == expected["signature_sha256"]):
                        raise ValueError("negative source signature identity changed")
                    descriptor = os.open(overlay_signature, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
                    try:
                        remaining = memoryview(payload)
                        while remaining:
                            written = os.write(descriptor, remaining)
                            if written <= 0:
                                raise OSError("short negative signature write")
                            remaining = remaining[written:]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
            run(["/usr/bin/mount", "-o", "remount,ro,nosuid,nodev,noexec",
                 str(NEGATIVE_SOURCE)])
            if (not os.statvfs(NEGATIVE_SOURCE).f_flag & os.ST_RDONLY
                    or sha256(NEGATIVE_SOURCE / "manifest.json") != new.removeprefix("sha256:")):
                raise ValueError("negative update source is writable or changed its manifest")
            if is_positive:
                if sha256(overlay_signature) != expected["signature_sha256"]:
                    raise ValueError("valid overlay signature changed after remount")
            elif case == "unsigned":
                if overlay_signature.exists() or overlay_signature.is_symlink():
                    raise ValueError("unsigned update source retained a signature")
            elif sha256(overlay_signature) != signature_control["sha256"]:
                raise ValueError("negative update signature changed after overlay remount")
            run(["/usr/bin/mount", "--bind", str(policy_path), "/etc/containers/policy.json"])
            run(["/usr/bin/mount", "-o", "remount,bind,ro", "/etc/containers/policy.json"])
            if sha256(Path("/etc/containers/policy.json")) != expected["policy_sha256"]:
                raise ValueError("guest update policy bind changed")
            switch = ["/usr/bin/bootc", "switch", "--transport", "dir",
                      "--enforce-container-sigpolicy", str(NEGATIVE_SOURCE)]
            run(switch, timeout=1200, check=False)
            switch_exit = record["commands"][-1]["exit_code"]
            if is_positive:
                after = staged_deployment_snapshot(raw_status(), old, new)
                after_hash = hashlib.sha256(json.dumps(
                    after, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                if (switch_exit != 0 or before_hash == after_hash or before == after
                        or before["booted"] != after["booted"]
                        or before["default"] == after["default"]
                        or before["staged"] is not None or after["staged"] is None):
                    raise ValueError("valid overlay switch did not stage only the signed update")
                record["same_path_positive_control"] = {
                    "case": case, "switch_accepted": True, "switch_exit_code": switch_exit,
                    "booted_unchanged": True, "deployment_staged": True,
                    "default_changed": True, "staged_digest": new,
                    "state_before_sha256": before_hash, "state_after_sha256": after_hash,
                    "source": str(NEGATIVE_SOURCE), "source_readonly": True,
                }
            else:
                after = deployment_snapshot(raw_status(), old)
                after_hash = hashlib.sha256(json.dumps(
                    after, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                if switch_exit == 0 or before != after or before_hash != after_hash:
                    raise ValueError("rejected update changed the bootc default or deployments")
                record["negative_control"] = {
                    "case": case, "switch_rejected": True, "switch_exit_code": switch_exit,
                    "deployment_unchanged": True, "default_unchanged": True,
                    "state_sha256": before_hash, "source": str(NEGATIVE_SOURCE),
                    "source_readonly": True,
                }
            record["source_mounted_readonly"] = True
            record["passed"] = True
            state = None
        else:
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
        elif state is not None:
            raise ValueError("unknown persistent update phase")
        if state is not None:
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
