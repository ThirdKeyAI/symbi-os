"""Create one locked fixture account on an appliance disk, never in the OCI image."""
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import subprocess
import sys
import stat


USERNAME = "symbi-test"
STATUS_PREFIX = "SYMBI_APPLIANCE_STATUS:"
SDDM_CONFIGURATION = """# HIGHLY EXPERIMENTAL disposable development appliance only.
# This locked account has no password or key and is not present in the product image.
[Autologin]
User=symbi-test
Session=symbi.desktop
Relogin=true
"""
PROVISION_COMMAND_TIMEOUTS = {
    "selinux-enforcement": 5,
    "create-fixture-account": 20,
    "lock-fixture-account": 10,
    "select-graphical-target": 10,
    "enable-display-manager": 15,
}
SYSTEMCTL_OFFLINE = (
    "/usr/bin/systemctl", "--root=/", "--no-reload", "--quiet",
)
SELECT_GRAPHICAL_TARGET_COMMAND = (
    *SYSTEMCTL_OFFLINE, "set-default", "graphical.target",
)
ENABLE_DISPLAY_MANAGER_COMMAND = (
    *SYSTEMCTL_OFFLINE, "enable", "--force", "sddm.service",
)
PROVISION_LOCAL_WORK_BUDGET_SECONDS = 30
PROVISION_SERVICE_TIMEOUT_SECONDS = 120
VERIFIER_SERVICE_TIMEOUT_SECONDS = 420
FIRST_BOOT_ORCHESTRATION_BUDGET_SECONDS = 180
FIRST_BOOT_CONTROLLER_MARGIN_SECONDS = 480
FIRST_BOOT_TIMEOUT_SECONDS = 1200
PROVISION_SUBPROCESS_BUDGET_SECONDS = sum(PROVISION_COMMAND_TIMEOUTS.values())
PROVISION_PHASE_BUDGET_SECONDS = (
    PROVISION_SUBPROCESS_BUDGET_SECONDS + PROVISION_LOCAL_WORK_BUDGET_SECONDS
)
PROVISION_SERVICE_MARGIN_SECONDS = (
    PROVISION_SERVICE_TIMEOUT_SECONDS - PROVISION_PHASE_BUDGET_SECONDS
)

if (PROVISION_PHASE_BUDGET_SECONDS > PROVISION_SERVICE_TIMEOUT_SECONDS
        or PROVISION_SERVICE_MARGIN_SECONDS <= 0):
    raise RuntimeError("Provisioning command budgets exceed the service deadline")
if (PROVISION_SERVICE_TIMEOUT_SECONDS + VERIFIER_SERVICE_TIMEOUT_SECONDS
        + FIRST_BOOT_ORCHESTRATION_BUDGET_SECONDS
        + FIRST_BOOT_CONTROLLER_MARGIN_SECONDS != FIRST_BOOT_TIMEOUT_SECONDS):
    raise RuntimeError("First-boot phase budgets do not close at the controller deadline")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON key: " + key)
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("Expected one JSON object")
    return value


def bound_regular(path, expected):
    if (not isinstance(expected, dict) or set(expected) != {"sha256", "bytes", "mode"}
            or not re.fullmatch(r"[0-9a-f]{64}", expected.get("sha256", ""))
            or type(expected.get("bytes")) is not int or expected["bytes"] <= 0
            or type(expected.get("mode")) is not int or not 0 <= expected["mode"] <= 0o777):
        return False
    try:
        info = path.lstat()
    except OSError:
        return False
    return (stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid == 0
            and info.st_size == expected["bytes"]
            and stat.S_IMODE(info.st_mode) == expected["mode"]
            and digest(path) == expected["sha256"])


def run(command, *, timeout):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                                  "LANG": "C.UTF-8"})
    if len(result.stdout.encode()) > 128*1024 or len(result.stderr.encode()) > 128*1024:
        raise ValueError("Provisioning command output exceeded its bound")
    result.check_returncode()
    return result.stdout


def status(name):
    """Emit one fixed public-safe lifecycle marker to the private serial log."""
    print(STATUS_PREFIX + name, flush=True)


def run_phase(name, command):
    """Run one named phase with its reviewed hard deadline."""
    status("provision-phase-start:" + name)
    try:
        result = run(command, timeout=PROVISION_COMMAND_TIMEOUTS[name])
    except subprocess.TimeoutExpired:
        status("provision-phase-timeout:" + name)
        raise
    except subprocess.CalledProcessError:
        status("provision-phase-exit:" + name)
        raise
    except Exception:
        status("provision-phase-error:" + name)
        raise
    status("provision-phase-complete:" + name)
    return result


def main():
    status("provision-start")
    product = Path("/sys/class/dmi/id/product_name").read_text().strip()
    if (os.geteuid() != 0 or product != "Symbi-Interactive-Appliance"
            or Path("/run/.containerenv").exists() or len(sys.argv) != 2):
        raise SystemExit("Use only the disposable hosted appliance guest")
    expected_path = Path(sys.argv[1])
    expected_info = expected_path.lstat()
    if (not stat.S_ISREG(expected_info.st_mode) or expected_path.is_symlink()
            or expected_info.st_uid != 0 or expected_info.st_size > 128*1024):
        raise ValueError("Oversized appliance binding")
    expected = unique_json(expected_path.read_bytes())
    if (not re.fullmatch(r"[0-9a-f]{32}", expected.get("nonce", ""))
            or expected.get("username") != USERNAME):
        raise ValueError("Invalid appliance invocation binding")
    if sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]:
        raise ValueError("Appliance fixture guest gained a network device")
    enforcement = run_phase("selinux-enforcement", ["/usr/sbin/getenforce"])
    if enforcement.strip() != "Enforcing":
        raise ValueError("SELinux is not enforcing")
    required = expected.get("production_files")
    if (not isinstance(required, dict) or set(required) != {
            "/usr/share/wayland-sessions/symbi.desktop",
            "/usr/libexec/symbi-seed-config", "/usr/libexec/symbi-desktop-session",
    }):
        raise ValueError("Missing installed desktop bindings")
    for name, binding in required.items():
        path = Path(name)
        if not path.is_absolute() or not bound_regular(path, binding):
            raise ValueError("Installed desktop input changed: " + name)
    if not Path("/usr/bin/sddm").is_file() or not Path("/usr/lib/systemd/system/sddm.service").is_file():
        raise ValueError("SDDM is not installed in the development image")
    if Path("/etc/sddm.conf.d/90-symbi-development-appliance.conf").exists():
        raise ValueError("Appliance autologin fixture already exists")
    try:
        pwd.getpwnam(USERNAME)
    except KeyError:
        pass
    else:
        raise ValueError("Disposable appliance account already exists")
    if any(entry.pw_uid == 1000 for entry in pwd.getpwall()):
        raise ValueError("UID 1000 is already allocated")

    run_phase("create-fixture-account", [
        "/usr/sbin/useradd", "--uid", "1000", "--user-group", "--create-home",
        "--shell", "/bin/bash", "--comment",
        "HIGHLY EXPERIMENTAL disposable appliance", USERNAME,
    ])
    run_phase("lock-fixture-account", ["/usr/sbin/usermod", "--lock", USERNAME])
    autologin = Path("/etc/sddm.conf.d/90-symbi-development-appliance.conf")
    autologin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with autologin.open("x") as stream:
        stream.write(SDDM_CONFIGURATION)
    autologin.chmod(0o644)
    run_phase("select-graphical-target", SELECT_GRAPHICAL_TARGET_COMMAND)
    run_phase("enable-display-manager", ENABLE_DISPLAY_MANAGER_COMMAND)
    state = {
        "schema": 1, "nonce": expected["nonce"], "source_binding": expected["source_binding"],
        "expected_sha256": digest(expected_path), "provision_sha256": digest(Path(__file__)),
        "kernel": platform.release(), "account_created": True, "password_set": False,
        "authorized_key_written": False, "production_image_modified": False,
        "autologin_sha256": digest(autologin), "transient_boot_units": True,
    }
    target = Path("/run/symbi-appliance-provision.json")
    target.write_text(json.dumps(state, sort_keys=True) + "\n")
    target.chmod(0o600)
    status("provision-complete")


if __name__ == "__main__":
    try:
        main()
    except (Exception, SystemExit):
        status("provision-failed")
        raise
