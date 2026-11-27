"""Validate the first graphical login and emit one source-bound guest report."""
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time


USERNAME = "symbi-test"
CHANNEL = Path("/dev/virtio-ports/org.symbi.appliance")
SCOPE = (
    "HIGHLY EXPERIMENTAL offline development appliance; no release, signature, "
    "security, containment or production-account qualification"
)


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


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(command, check=True, timeout=60):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                                  "LANG": "C.UTF-8"})
    if len(result.stdout.encode()) > 128*1024 or len(result.stderr.encode()) > 128*1024:
        raise ValueError("Verification command output exceeded its bound")
    if check:
        result.check_returncode()
    return result


def direct_regular(path, uid=None):
    info = path.lstat()
    return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not path.is_symlink()
            and (uid is None or info.st_uid == uid))


def bound_regular(path, expected, uid=0):
    if (not isinstance(expected, dict) or set(expected) != {"sha256", "bytes", "mode"}
            or not re.fullmatch(r"[0-9a-f]{64}", expected.get("sha256", ""))
            or type(expected.get("bytes")) is not int or expected["bytes"] <= 0
            or type(expected.get("mode")) is not int or not 0 <= expected["mode"] <= 0o777):
        return False
    try:
        info = path.lstat()
    except (OSError, RuntimeError):
        return False
    return (stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid == uid
            and info.st_size == expected["bytes"]
            and stat.S_IMODE(info.st_mode) == expected["mode"]
            and digest(path) == expected["sha256"])


def reviewed_launcher(root, expected):
    """Accept only the reviewed relative launcher and its direct, bound target."""
    root = Path(root).resolve(strict=True)
    launcher = root / "usr/bin/Hyprland"
    target = root / "usr/lib/symbi/hyprland/bin/Hyprland"
    link = expected.get("link") if isinstance(expected, dict) else None
    if link != "../lib/symbi/hyprland/bin/Hyprland":
        return False
    try:
        actual = os.readlink(launcher)
        candidate = (launcher.parent / actual).resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return (launcher.is_symlink() and actual == link and not Path(actual).is_absolute()
            and candidate == target and candidate.is_relative_to(root))


def path_absent(path):
    return not path.exists() and not path.is_symlink()


def user_executables(uid):
    executables = set()
    if os.geteuid() != 0:
        raise ValueError("Process observation must start as root")
    os.seteuid(uid)
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                if entry.stat().st_uid == uid:
                    executable = os.readlink(entry / "exe")
                    if executable:
                        executables.add(executable)
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
    finally:
        os.seteuid(0)
    return executables


def shadow_locked(name):
    lines = Path("/etc/shadow").read_text().splitlines()
    matches = [line.split(":", 2)[1] for line in lines if line.startswith(name + ":")]
    return len(matches) == 1 and matches[0] in {"!", "!!", "*", "!*"}


def verify_seed(expected, account):
    source_root = Path("/usr/share/symbiont/defaults")
    target_root = Path(account.pw_dir) / ".config"
    bindings = expected.get("seed_files")
    if not isinstance(bindings, dict) or not bindings:
        return False
    for relative, binding in bindings.items():
        if (not isinstance(relative, str) or Path(relative).is_absolute()
                or ".." in Path(relative).parts or str(Path(relative)) != relative):
            return False
        source = source_root / relative
        target = target_root / relative
        if (not bound_regular(source, binding)
                or not bound_regular(target, binding, account.pw_uid)):
            return False
    return True


def verify_packages(bindings):
    if not isinstance(bindings, dict) or set(bindings) != {"sddm", "sddm-wayland-sway", "waybar"}:
        return False
    query = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"
    for name, identity in bindings.items():
        if not isinstance(identity, str) or identity.split("\t", 1)[0] != name:
            return False
        observed = run(["/usr/bin/rpm", "-q", name, "--qf", query], check=False)
        verified = run(["/usr/bin/rpm", "-V", name], check=False)
        if (observed.returncode != 0 or observed.stdout != identity + "\n"
                or observed.stderr or verified.returncode != 0
                or verified.stdout or verified.stderr):
            return False
    return True


def interactive_device_observation():
    inventory = Path("/proc/bus/input/devices").read_text()
    if len(inventory.encode()) > 128*1024:
        raise ValueError("Input device inventory exceeded its bound")
    virtio_gpu = False
    for card in Path("/sys/class/drm").glob("card[0-9]*"):
        device = card / "device"
        driver = device / "driver"
        vendor = device / "vendor"
        nested = list(device.glob("virtio*/driver"))
        if ((driver.is_symlink() and vendor.is_file()
             and driver.resolve(strict=True).name == "virtio-pci"
             and vendor.read_text().strip() == "0x1af4")
                or any(path.is_symlink() and path.resolve(strict=True).name == "virtio_gpu"
                       for path in nested)):
            virtio_gpu = True
    return {
        "virtio_gpu": virtio_gpu,
        "virtio_keyboard": "virtio keyboard" in inventory.lower(),
        "virtio_pointer": "virtio tablet" in inventory.lower(),
    }


def main():
    product = Path("/sys/class/dmi/id/product_name").read_text().strip()
    if (os.geteuid() != 0 or product != "Symbi-Interactive-Appliance"
            or Path("/run/.containerenv").exists() or len(sys.argv) != 2):
        raise SystemExit("Use only the disposable hosted appliance guest")
    expected_path = Path(sys.argv[1])
    if not direct_regular(expected_path, 0) or expected_path.stat().st_size > 128*1024:
        raise ValueError("Missing bounded appliance invocation binding")
    expected = unique_json(expected_path.read_bytes())
    if (not re.fullmatch(r"[0-9a-f]{32}", expected.get("nonce", ""))
            or expected.get("username") != USERNAME):
        raise ValueError("Invalid appliance invocation binding")
    state_path = Path("/run/symbi-appliance-provision.json")
    if (not direct_regular(state_path, 0) or stat.S_IMODE(state_path.stat().st_mode) != 0o600
            or state_path.stat().st_size > 128*1024):
        raise ValueError("Missing bounded ephemeral provisioning receipt")
    state = unique_json(state_path.read_bytes())
    if (state.get("nonce") != expected["nonce"] or state.get("source_binding") != expected["source_binding"]
            or state.get("account_created") is not True or state.get("password_set") is not False
            or state.get("authorized_key_written") is not False
            or state.get("production_image_modified") is not False
            or state.get("boot_wants_removed") is not True
            or state.get("expected_sha256") != digest(expected_path)
            or state.get("autologin_sha256") != expected.get("sddm_config_sha256")):
        raise ValueError("Ephemeral provisioning receipt is incomplete")
    account = pwd.getpwnam(USERNAME)
    wheel = grp.getgrnam("wheel")
    deadline = time.monotonic() + 300
    executables = set()
    session_executables = {
        "/usr/lib/symbi/hyprland/bin/Hyprland",
        "/usr/bin/waybar",
    }
    while time.monotonic() < deadline:
        active = run(["/usr/bin/systemctl", "is-active", "sddm.service"], check=False)
        executables = user_executables(account.pw_uid)
        if (active.returncode == 0 and session_executables.issubset(executables)
                and Path("/run/user/1000/bus").is_socket()):
            break
        time.sleep(2)
    else:
        raise ValueError("SDDM, Hyprland and Waybar did not reach the graphical session")
    run([
        "/usr/sbin/runuser", "-u", USERNAME, "--", "/usr/bin/env",
        "XDG_RUNTIME_DIR=/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
        "/usr/bin/systemctl", "--user", "start", "xdg-desktop-portal-hyprland.service",
    ])
    portal_executable = "/usr/lib/symbi/portal/libexec/xdg-desktop-portal-hyprland"
    while time.monotonic() < deadline:
        executables = user_executables(account.pw_uid)
        if portal_executable in executables:
            break
        time.sleep(1)
    else:
        raise ValueError("The installed Hyprland portal did not start in the graphical session")
    default_target = run(["/usr/bin/systemctl", "get-default"]).stdout.strip()
    display_link = Path("/etc/systemd/system/display-manager.service")
    if not display_link.is_symlink() or display_link.resolve().name != "sddm.service":
        raise ValueError("SDDM is not the enabled display manager")
    production_files = expected.get("production_files")
    required_production = {
        "/usr/share/wayland-sessions/symbi.desktop",
        "/usr/libexec/symbi-seed-config",
        "/usr/libexec/symbi-desktop-session",
    }
    if not isinstance(production_files, dict) or set(production_files) != required_production:
        raise ValueError("Installed desktop overlay binding is incomplete")
    for name, binding in production_files.items():
        path = Path(name)
        if not bound_regular(path, binding) or (binding["mode"] & 0o111 and not os.access(path, os.X_OK)):
            raise ValueError("Installed desktop overlay changed: " + name)
    components = expected.get("desktop_components")
    files = components.get("files") if isinstance(components, dict) else None
    packages = components.get("packages") if isinstance(components, dict) else None
    required_files = {
        "/usr/bin/Hyprland", "/usr/lib/symbi/hyprland/bin/Hyprland", "/usr/bin/walker",
        "/usr/lib/symbi/portal/libexec/xdg-desktop-portal-hyprland",
        "/usr/lib/systemd/user/xdg-desktop-portal-hyprland.service",
    }
    if (not isinstance(components, dict)
            or set(components) != {"preparation_sha256", "files", "packages"}
            or not re.fullmatch(r"[0-9a-f]{64}", components.get("preparation_sha256", ""))
            or not isinstance(files, dict) or set(files) != required_files
            or not reviewed_launcher(Path("/"), files["/usr/bin/Hyprland"])):
        raise ValueError("Desktop component source binding is incomplete")
    for name, binding in files.items():
        if name == "/usr/bin/Hyprland":
            continue
        path = Path(name)
        if not bound_regular(path, binding) or (binding["mode"] & 0o111 and not os.access(path, os.X_OK)):
            raise ValueError("Desktop component bytes changed: " + name)
    if not verify_packages(packages):
        raise ValueError("SDDM, Waybar or its installed package bytes changed")
    interactive = interactive_device_observation()
    if interactive != {"virtio_gpu": True, "virtio_keyboard": True, "virtio_pointer": True}:
        raise ValueError("The graphical VM is missing a virtio display, keyboard or pointer")
    if not verify_seed(expected, account):
        raise ValueError("First-login defaults were not seeded exactly")
    kargs = run(["/usr/bin/rpm-ostree", "kargs"]).stdout
    if "systemd.wants=p.service" in kargs or "systemd.wants=v.service" in kargs:
        raise ValueError("Fixture boot wants remain in the appliance deployment")
    persistent_scripts = (
        Path("/usr/local/libexec/symbi-provision.py"), Path("/usr/local/libexec/symbi-verify.py"),
        Path("/var/lib/symbi-appliance"),
    )
    persistent_units = (Path("/etc/systemd/system/p.service"), Path("/etc/systemd/system/v.service"))
    if any(path.exists() or path.is_symlink() for path in (*persistent_scripts, *persistent_units)):
        raise ValueError("Fixture script or unit leaked onto the appliance disk")
    persistent_credentials = tuple(
        base / name
        for base in (Path("/etc/credstore"), Path("/etc/credstore.encrypted"))
        for name in ("symbi-provision.py", "symbi-verify.py", "symbi-expected.json")
    )
    if any(not path_absent(path) for path in persistent_credentials):
        raise ValueError("Fixture credential payload leaked onto the appliance disk")
    autologin = Path("/etc/sddm.conf.d/90-symbi-development-appliance.conf")
    if (not direct_regular(autologin, 0) or stat.S_IMODE(autologin.stat().st_mode) != 0o644
            or digest(autologin) != expected.get("sddm_config_sha256")):
        raise ValueError("Development-only SDDM autologin configuration changed")
    fixture_group = grp.getgrnam(USERNAME)
    group_ids = os.getgrouplist(USERNAME, account.pw_gid)
    ssh_directory = Path(account.pw_dir) / ".ssh"
    authorized = ssh_directory / "authorized_keys"
    fixture_user = {
        "name": USERNAME, "password_locked": shadow_locked(USERNAME),
        "non_wheel": wheel.gr_gid not in group_ids and USERNAME not in wheel.gr_mem,
        "authorized_keys_absent": path_absent(ssh_directory) and path_absent(authorized),
    }
    if (account.pw_uid != 1000 or account.pw_gid != fixture_group.gr_gid
            or fixture_group.gr_mem or fixture_user != {
                "name": USERNAME, "password_locked": True, "non_wheel": True,
                "authorized_keys_absent": True,
            }):
        raise ValueError("Disposable account gained a password, key or administrative group")
    report = {
        "schema": 1, "nonce": expected["nonce"], "source_binding": expected["source_binding"],
        "probe_sha256": digest(Path(__file__)), "expected_sha256": digest(expected_path),
        "passed": True, "guest_booted": True, "graphical_desktop_observed": True,
        "os_qualified": False, "release_qualified": False, "signature_qualified": False,
        "network_interfaces": sorted(path.name for path in Path("/sys/class/net").iterdir()),
        "default_target": default_target, "display_manager": "sddm.service",
        "session": "symbi.desktop", "fixture_user": fixture_user,
        "interactive_devices": interactive,
        "fixture_cleanup": {
            "boot_wants_removed": True, "persistent_scripts_absent": True,
            "persistent_units_absent": True, "credentials_absent": True,
        },
        "desktop_components": {
            "Hyprland": "/usr/lib/symbi/hyprland/bin/Hyprland" in executables,
            "Waybar": "/usr/bin/waybar" in executables,
            "Walker": True,
            "portal": portal_executable in executables,
            "first_login_seeded": True,
        },
        "autologin_sha256": digest(autologin),
        "scope": SCOPE,
    }
    raw = (json.dumps(report, sort_keys=True) + "\n").encode()
    if len(raw) > 128*1024 or not CHANNEL.is_char_device():
        raise ValueError("Guest report channel is unavailable or oversized")
    with CHANNEL.open("wb", buffering=0) as output:
        output.write(raw)


if __name__ == "__main__":
    main()
