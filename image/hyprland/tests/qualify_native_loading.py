#!/usr/bin/env python3
"""Exercise real native-loading entry points in a disposable, capped Fedora guest.

This starts a private compositor with an available DRM graphics device. It never connects to an existing
desktop, and a passing report covers native-loading refusal only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import time


REFUSAL = "Native plugins are disabled in this Symbi OS build"


def require_socket_root(runtime):
    # Pinned Compositor.cpp uses commit(40)_time(10)_random INT32_MAX(10).
    # Socket2's longer pathname must fit Linux sockaddr_un.sun_path including NUL.
    longest = runtime / 'hypr' / ('x' * 62) / '.socket2.sock'
    if len(os.fsencode(longest)) > 107:
        raise ValueError('Private compositor socket path exceeds the 107-byte limit')


def select_instance(output, pid):
    instances = json.loads(output)
    if not isinstance(instances, list) or any(not isinstance(item, dict) for item in instances):
        raise ValueError('Invalid instance query result')
    owned = [item for item in instances if item.get('pid') == pid]
    if len(owned) > 1:
        raise ValueError('Multiple instances claim the compositor child')
    if not owned:
        return None
    name = owned[0].get('instance')
    if not isinstance(name, str) or not name or '/' in name or name in ('.', '..'):
        raise ValueError('Invalid compositor instance name')
    return name


def stop_child(child):
    result = {'passed': False, 'errors': []}
    # Signal the exact child; this probe does not start external applications.
    # The enclosing container/cgroup owns descendant teardown. A denial remains
    # a failed cleanup, and must not hide the original startup/acceptance error.
    for action, timeout in ((child.terminate, 10), (child.kill, 5)):
        if child.poll() is not None:
            result.update(passed=True, returncode=child.returncode)
            return result
        try:
            action()
            child.wait(timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            result['errors'].append(type(error).__name__ + ': ' + str(error))
    result.update(passed=child.poll() is not None, returncode=child.returncode)
    return result


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hyprland", type=Path, required=True)
    parser.add_argument("--hyprctl", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise SystemExit("Run as the disposable guest's unprivileged test user")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from guest_inventory import require_fedora_family
    require_fedora_family(platform.freedesktop_os_release())
    cgroup = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {key: (cgroup / key).read_text().strip() for key in ("memory.max", "memory.swap.max", "cpu.max")}
    quota, period = limits["cpu.max"].split()
    if limits["memory.max"] == "max" or int(limits["memory.max"]) > 2 * 1024**3:
        raise SystemExit("A memory ceiling of at most 2 GiB is required")
    if limits["memory.swap.max"] != "0" or quota == "max" or int(quota) > int(period):
        raise SystemExit("At most one CPU and no swap are required")
    binary, hyprctl = args.hyprland.resolve(strict=True), args.hyprctl.resolve(strict=True)
    work = args.work_dir.absolute()
    if work.exists() or work.is_symlink() or not work.parent.is_dir() or work.parent.resolve() != work.parent:
        raise SystemExit("Use a new work directory under an existing nonsymlinked directory")
    work.mkdir(mode=0o700)
    for name in ("home", "runtime", "config"):
        (work / name).mkdir(mode=0o700)
    require_socket_root(work / 'runtime')
    report = args.report.absolute()
    if report.exists() or report.is_symlink():
        raise SystemExit("Report must not overwrite existing evidence")
    marker, ready = work / "native-loaded", work / "config-completed"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "XDG_RUNTIME_DIR": str(work / "runtime"),
           "XDG_CONFIG_HOME": str(work / "config"), "LANG": "C.UTF-8",
           "LIBGL_ALWAYS_SOFTWARE": "1", "LP_NUM_THREADS": "1", "OMP_NUM_THREADS": "1",
           "SYMBI_NATIVE_LOAD_MARKER": str(marker)}
    result = {"schema": 1, "hyprland_sha256": sha256(binary), "hyprctl_sha256": sha256(hyprctl),
              "limits": limits, "fedora_atomic_boot": Path("/run/ostree-booted").exists(),
              "scope": "Native-loading refusal in a private compositor; requires DRM allocation", "checks": [],
              "passed": False, "os_qualified": False}

    def save():
        report.write_text(json.dumps(result, indent=2) + "\n")

    def run(command, timeout=15):
        return subprocess.run(command, cwd=work, env=env, capture_output=True, text=True, timeout=timeout)

    def checked(name, passed, **details):
        result["checks"].append({"name": name, "passed": bool(passed), **details})
        save()
        if not passed:
            raise RuntimeError(name + " failed")

    devices = [str(path) for path in Path('/dev/dri').glob('*')
               if not path.is_symlink() and stat.S_ISCHR(path.stat().st_mode)]
    checked('graphics-device-available', bool(devices), devices=devices,
            requirement='Pinned Aquamarine requires a DRM allocator; software rendering alone does not supply one')
    probe = work / "symbi_probe.so"
    fixture = Path(__file__).with_name("native_probe.c").resolve(strict=True)
    compiled = run(["cc", "-shared", "-fPIC", "-O0", "-g0", str(fixture), "-o", str(probe)], timeout=30)
    checked("fixture-compiled", compiled.returncode == 0, stderr=compiled.stderr)
    control = run([sys.executable, "-c", "import ctypes,sys; ctypes.CDLL(sys.argv[1])", str(probe)])
    checked("constructor-positive-control", control.returncode == 0 and marker.is_file())
    marker.unlink()
    result["probe_sha256"] = sha256(probe)
    (work / "symbi_lua_probe.lua").write_text('return "pure Lua module loaded"\n')
    config = work / "hyprland.lua"

    def write_config(generation):
        # JSON strings are also valid Lua strings for these generated ASCII paths.
        q = json.dumps
        config.write_text(f'''hl.config({{debug = {{enable_stdout_logs = true}}}})
package.path = {q(str(work / '?.lua'))}
assert(require("symbi_lua_probe") == "pure Lua module loaded")
local direct_ok = pcall(function()
    local loader = assert(package.loadlib({q(str(probe))}, "luaopen_symbi_probe"))
    return loader()
end)
assert(not direct_ok, "native package.loadlib unexpectedly succeeded")
package.cpath = {q(str(work / '?.so'))}
local require_ok = pcall(require, "symbi_probe")
assert(not require_ok, "native require unexpectedly succeeded")
hl.permission(".*", "plugin", "allow")
local evidence = assert(io.open({q(str(ready))}, "w"))
evidence:write({q(str(generation))})
evidence:close()
''')

    def wait_for(predicate, child, timeout=30):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if child.poll() is not None:
                raise RuntimeError("Compositor exited; inspect compositor.log")
            if predicate():
                return
            time.sleep(0.1)
        raise RuntimeError("Compositor readiness timed out")

    write_config(1)
    with (work / "compositor.log").open("wb") as log:
        child = subprocess.Popen([str(binary), "--config", str(config)], cwd=work, env=env,
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            wait_for(lambda: ready.is_file() and ready.read_text() == "1", child)
            checked("config-lua-native-refused", not marker.exists(), generation=1)
            instance = None

            def ipc_ready():
                nonlocal instance
                listing = run([str(hyprctl), '-j', 'instances'])
                result['last_instance_query'] = {'exit_code': listing.returncode,
                                                 'stdout': listing.stdout[:16384], 'stderr': listing.stderr[:16384]}
                save()
                if listing.returncode != 0:
                    return False
                try:
                    instance = select_instance(listing.stdout, child.pid)
                except ValueError as error:
                    result['last_instance_query']['parse_error'] = str(error)
                    save()
                    return False
                if instance is None or not (work / 'runtime/hypr' / instance / '.socket.sock').is_socket():
                    return False
                version = run([str(hyprctl), '-i', instance, '-j', 'version'])
                result['last_version_query'] = {'exit_code': version.returncode,
                                                'stdout': version.stdout[:16384], 'stderr': version.stderr[:16384]}
                save()
                try:
                    return version.returncode == 0 and isinstance(json.loads(version.stdout), dict)
                except ValueError:
                    return False

            wait_for(ipc_ready, child)
            checked('exact-child-ipc-ready', instance is not None, instance=instance)
            for generation in (1, 2):
                if generation == 2:
                    write_config(generation)
                    reload_result = run([str(hyprctl), "-i", instance, "reload"])
                    checked("reload-request", reload_result.returncode == 0, response=reload_result.stdout)
                    wait_for(lambda: ready.read_text() == str(generation), child)
                    checked("config-lua-native-refused", not marker.exists(), generation=generation)
                ipc = run([str(hyprctl), "-i", instance, "plugin", "load", str(probe)])
                response = ipc.stdout + ipc.stderr
                checked("ipc-plugin-refused-before-constructor", REFUSAL in response and not marker.exists(),
                        generation=generation, response=response, exit_code=ipc.returncode)
                plugins = run([str(hyprctl), "-i", instance, "-j", "plugin", "list"])
                checked("no-native-plugins-loaded", plugins.returncode == 0 and json.loads(plugins.stdout) == [],
                        generation=generation)
            result["passed"] = True
            save()
        except Exception as error:
            result['failure'] = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            result['cleanup'] = stop_child(child)
            result['passed'] = result['passed'] and result['cleanup']['passed']
            save()
        if not result['cleanup']['passed']:
            raise RuntimeError('Compositor cleanup failed; inspect retained cleanup diagnostics')


if __name__ == "__main__":
    main()
