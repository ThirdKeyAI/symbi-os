#!/usr/bin/env python3
"""Bounded Moby/runsc probes and pinned Docker fixture drivers in a Fedora VM.

These probes cannot qualify the complete Symbiont gVisor route. The report always
retains qualified=false until the managed route, its escape suite and review exist.
No pull, daemon change, host build or global container cleanup is performed.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import sys
import time
import tomllib
import uuid

from landlock import (ROOT, DIGEST_REF, command_output, digest, host_details,
                      read_bootc_status, require, run_driver, validate_deployment,
                      validate_source, validate_status_socket)

FIXTURE_DRIVERS = ("test-filesystem-grants.py", "test-source-broker.py", "test-git-source.py")
SUPPORTED_CASES = {
    "test-filesystem-grants.py": (
        "granted", "undeclared", "parser", "oversize", "existing", "symlink",
        "nested", "descendant", "substitution",
    ),
    "test-source-broker.py": (
        "read", "list", "grep", "traversal", "symlink", "hardlink", "no_ceiling",
        "denied", "scratch",
    ),
    "test-git-source.py": (
        "log", "staged", "diff", "status", "sha256", "snapshot", "denied",
        "alternates", "pointer", "oversize", "extension", "capacity",
        "prepare_crash", "crash",
    ),
}
BACKENDS = {
    "runc": {"reported": "docker", "runtime": "runc", "arguments": ()},
    "runsc": {"reported": "gvisor", "runtime": "runsc",
              "arguments": ("--gvisor", "--runsc-binary", "/usr/bin/runsc")},
}
MAX_FIXTURE_REPORT_BYTES = 20 * 1024 * 1024
ESCAPE_CASES = (
    "direct_network", "dns_tunnel", "abstract_unix", "external_signal",
    "proc_ptrace", "uinput", "pipewire_capture", "ssh_read",
)
PAYLOAD = r'''
import errno,json,os,socket
assert os.getuid()==65534 and os.getgid()==65534
assert not os.path.exists('/var/run/docker.sock') and not os.path.exists('/dev/uinput')
try:
    open('/symbi-root-write-probe','w').close()
except OSError as error:
    assert error.errno in (errno.EROFS,errno.EACCES)
else:
    raise AssertionError('root filesystem is writable')
with socket.socket() as sock:
    sock.settimeout(1)
    try:
        sock.connect(('192.0.2.1',443))
    except OSError:
        pass
    else:
        raise AssertionError('unexpected external connection')
with open('/tmp/symbi-useful-work','w') as stream:
    stream.write('bounded scratch works')
print(json.dumps({'passed':True,'uid':os.getuid(),'scratch':'ok'}))
'''

ESCAPE_PAYLOAD = r'''
import ctypes,errno,json,os,socket

def refused(name, operation):
    try:
        operation()
    except OSError as error:
        return {'name':name,'passed':True,'errno':error.errno}
    return {'name':name,'passed':False,'errno':None}

tcp_port=int(os.environ['SYMBI_ESCAPE_TCP_PORT'])
udp_port=int(os.environ['SYMBI_ESCAPE_UDP_PORT'])
host_pid=int(os.environ['SYMBI_ESCAPE_HOST_PID'])
abstract='\0'+os.environ['SYMBI_ESCAPE_ABSTRACT']
pipewire=os.environ['SYMBI_ESCAPE_PIPEWIRE']
ssh_canary=os.environ['SYMBI_ESCAPE_SSH_CANARY']

def tcp():
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as value:
        value.settimeout(0.5);value.connect(('127.0.0.1',tcp_port));value.sendall(b'escape')

def abstract_socket():
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as value:
        value.settimeout(0.5);value.connect(abstract);value.sendall(b'escape')

def signal_outside(): os.kill(host_pid,0)
def open_uinput():
    descriptor=os.open('/dev/uinput',os.O_RDWR|os.O_CLOEXEC);os.close(descriptor)
def connect_pipewire():
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as value:
        value.settimeout(0.5);value.connect(pipewire)
def read_ssh():
    with open(ssh_canary,'rb') as value:value.read(1)

cases=[refused('direct_network',tcp)]
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as value:
    try:
        value.sendto(b'escape',('127.0.0.1',udp_port))
        udp_errno=None
    except OSError as error:
        udp_errno=error.errno
cases.append({'name':'dns_tunnel','passed':True,'delivery':'controller-observed','errno':udp_errno})
cases.extend((refused('abstract_unix',abstract_socket),refused('external_signal',signal_outside)))
proc_visible=os.path.exists('/proc/'+str(host_pid)+'/status')
ctypes.set_errno(0)
ptrace=ctypes.CDLL(None,use_errno=True).ptrace(16,host_pid,0,0)
ptrace_errno=ctypes.get_errno()
cases.append({'name':'proc_ptrace','passed':not proc_visible and ptrace==-1 and ptrace_errno in (errno.EPERM,errno.ESRCH),
              'proc_visible':proc_visible,'ptrace_errno':ptrace_errno})
cases.extend((refused('uinput',open_uinput),refused('pipewire_capture',connect_pipewire),
              refused('ssh_read',read_ssh)))
print(json.dumps({'passed':all(row['passed'] for row in cases),'uid':os.getuid(),'gid':os.getgid(),
                  'docker_socket_visible':os.path.exists('/var/run/docker.sock'),'cases':cases},sort_keys=True))
'''


def validate_daemon(info):
    require(info.get("CgroupVersion") == "2" and info.get("CgroupDriver") == "systemd", "systemd cgroup v2 required")
    require(info.get("LiveRestoreEnabled") is False, "live restore can outlive supervisor cleanup")
    require(info.get("DefaultRuntime") == "runc", "use explicit runsc selection, not an implicit runtime replacement")
    require(info.get("Runtimes", {}).get("runsc", {}).get("path") == "/usr/bin/runsc", "expected registered runsc path is missing")
    options = info.get("SecurityOptions", [])
    require("name=selinux" in options and any(x.startswith("name=seccomp") for x in options), "SELinux/seccomp must remain enabled")


def retained_daemon_info(info):
    # Docker info can include proxy credentials and registry configuration.
    names = ("ServerVersion", "OperatingSystem", "Driver", "CgroupVersion", "CgroupDriver",
             "LiveRestoreEnabled", "Runtimes", "DefaultRuntime", "SecurityOptions")
    return {name: info[name] for name in names if name in info}


def validate_container(container, runtime, image_id):
    host = container.get("HostConfig", {})
    require(container.get("Image") == image_id, "container image changed")
    require(container.get("Config", {}).get("User") == "65534:65534", "worker must use the non-root UID")
    expected = {"Runtime": runtime, "NetworkMode": "none", "Privileged": False,
                "ReadonlyRootfs": True, "Memory": 268435456, "MemorySwap": 268435456,
                "NanoCpus": 500000000, "PidsLimit": 32, "IpcMode": "private", "CgroupnsMode": "private",
                "PidMode": "", "UTSMode": ""}
    for key, value in expected.items():
        require(key in host and host[key] == value, f"container {key} differs from the bounded profile")
    require(host.get("CapDrop") == ["ALL"] and not host.get("CapAdd"), "capabilities must be dropped")
    require(host.get("SecurityOpt") == ["no-new-privileges=true"], "unexpected security override or missing no-new-privileges")
    require(host.get("Tmpfs") == {"/tmp": "rw,noexec,nosuid,nodev,size=16777216"}, "scratch mount is not the bounded profile")
    require(host.get("LogConfig", {}).get("Type") == "none", "daemon log storage is not allowed")
    require(not host.get("Binds"), "host bind mounts are not allowed in probes")
    require(all(m.get("Type") == "tmpfs" and m.get("Destination") == "/tmp"
                for m in container.get("Mounts", [])), "unexpected mount or anonymous image volume")


def docker_call(env, *arguments, timeout=30, check=True):
    return subprocess.run(["/usr/bin/docker", *arguments], env=env, text=True,
                          capture_output=True, timeout=timeout, check=check)


def fixture_plan(source, binary, fixture_ref, output):
    """Return the exact sequential matrix; callers must not select a subset."""
    plan = []
    for backend, details in BACKENDS.items():
        for driver in FIXTURE_DRIVERS:
            target = output / f"{backend}-{driver.removesuffix('.py')}.json"
            log = output / f"{backend}-{driver}.log"
            command = [sys.executable, "-E", "-s", "-B", str(source / "scripts" / driver),
                       "--binary", str(binary), "--image", fixture_ref,
                       "--report", str(target), *details["arguments"]]
            plan.append({"backend": backend, "driver": driver, "target": target,
                         "log": log, "command": command})
    return plan


def _unique_object(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate fixture report key")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(result, dict), "fixture report must be a JSON object")
    return result


def read_fixture_result(path):
    info = path.lstat()
    require(path.is_file() and not path.is_symlink() and info.st_nlink == 1
            and 0 < info.st_size <= MAX_FIXTURE_REPORT_BYTES,
            "missing or unsafe bounded fixture report")
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "fixture report changed while reading")
    return raw, _unique_object(raw)


def validate_fixture_result(result, driver, backend, binary_hash, driver_hash,
                            image_id, runsc_hash):
    require(driver in SUPPORTED_CASES and backend in BACKENDS, "unknown fixture matrix entry")
    expected = BACKENDS[backend]
    require(result.get("passed") is True, f"{backend}/{driver} did not pass")
    require(result.get("backend") == expected["reported"], "fixture reported the wrong backend")
    require(result.get("binary_sha256") == binary_hash, "fixture binary hash changed")
    require(result.get("driver_sha256") == driver_hash, "fixture driver hash changed")
    require(result.get("image") == image_id, "fixture image ID changed")
    require(result.get("remaining_workers") == [], "fixture left workers behind")
    require(result.get("remaining_leases") == [], "fixture left worker leases behind")
    require(result.get("provider_errors") == [], "fixture provider recorded errors")
    cases = result.get("cases")
    require(isinstance(cases, list), "fixture cases must be a list")
    names = [case.get("name") if isinstance(case, dict) else None for case in cases]
    require(len(names) == len(SUPPORTED_CASES[driver])
            and sorted(names) == sorted(SUPPORTED_CASES[driver]),
            "fixture case set is incomplete, duplicated or unsupported")
    require(all(case.get("passed") is True for case in cases), "a fixture case did not pass")
    observed = set()
    for case in cases:
        workers = case.get("workers")
        require(isinstance(workers, list), "fixture case omitted worker observations")
        for worker in workers:
            require(isinstance(worker, dict) and isinstance(worker.get("runtime"), str),
                    "fixture worker runtime observation is malformed")
            observed.add(worker["runtime"])
    require(observed == {expected["runtime"]}, "fixture did not observe only the selected runtime")
    runsc = result.get("runsc")
    if backend == "runsc":
        require(isinstance(runsc, dict), "gVisor fixture omitted runsc identity")
        require(runsc.get("path") == "/usr/bin/runsc"
                and runsc.get("registered_path") == "/usr/bin/runsc",
                "gVisor fixture used a different runsc path")
        require(runsc.get("sha256") == runsc_hash and runsc.get("mode") == 0o755,
                "gVisor fixture runsc bytes or mode changed")
    else:
        require(runsc is None, "runc fixture unexpectedly reported a runsc override")
    return sorted(observed)


def container_ids(env):
    rows = [row for row in docker_call(env, "ps", "-aq", "--no-trunc").stdout.splitlines() if row]
    require(all(re.fullmatch(r"[a-f0-9]{64}", row) for row in rows),
            "daemon returned a malformed container identity")
    return rows


def validate_run_record(record, report_raw, backend):
    require(backend in BACKENDS, "unknown fixture backend")
    require(record.get("passed") is True and record.get("cleanup_confirmed") is True,
            "fixture run did not pass with confirmed cleanup")
    require(record.get("remaining_containers") == [], "fixture run left containers behind")
    require(record.get("report_sha256") == hashlib.sha256(report_raw).hexdigest(),
            "fixture report hash changed")
    require(record.get("observed_runtimes") == [BACKENDS[backend]["runtime"]],
            "fixture run runtime observation changed")


def deployment_digest(status):
    booted = status.get("status", {}).get("booted")
    require(isinstance(booted, dict), "bootc status omitted the booted deployment")
    return hashlib.sha256(json.dumps(booted, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def probe(env, runtime, image_id, output):
    identity = None
    name = "symbi-qual-" + uuid.uuid4().hex
    report = {"runtime": runtime, "passed": False, "cleanup_confirmed": False}
    try:
        result = docker_call(env, "create", "--name", name,
                             "--pull=never", "--runtime", runtime, "--network=none", "--read-only",
                             "--user=65534:65534", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
                             "--cpus=0.5", "--memory=256m", "--memory-swap=256m", "--pids-limit=32",
                             "--ipc=private", "--cgroupns=private", "--log-driver=none",
                             "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16777216",
                             "--entrypoint=/usr/local/bin/python3", image_id, "-B", "-c", PAYLOAD)
        candidate = result.stdout.strip()
        require(re.fullmatch(r"[a-f0-9]{64}", candidate), "create returned no immutable container ID")
        identity = candidate
        inspected = json.loads(docker_call(env, "inspect", identity).stdout)[0]
        validate_container(inspected, runtime, image_id)
        report["inspection"] = {"Image": inspected["Image"], "User": inspected["Config"]["User"],
                                "HostConfig": inspected["HostConfig"], "Mounts": inspected["Mounts"]}
        attached = docker_call(env, "start", "--attach", identity)
        state = json.loads(docker_call(env, "inspect", identity).stdout)[0]["State"]
        require(state.get("Running") is False and state.get("ExitCode") == 0, "probe payload failed")
        payload = json.loads(attached.stdout)
        require(payload.get("passed") is True, "probe payload did not pass")
        report.update(passed=True, payload=payload)
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        report["error"] = str(error)
    finally:
        try:
            removed = docker_call(env, "rm", "--force", name, check=False)
            remaining = docker_call(env, "ps", "-aq", "--no-trunc", "--filter",
                                    "name=^/" + name + "$").stdout.splitlines()
            require(not remaining, "probe container remains after cleanup")
            require(identity is None or removed.returncode == 0,
                    "created probe container could not be removed")
            report["cleanup_confirmed"] = True
        except (ValueError, OSError, subprocess.SubprocessError, TypeError) as error:
            report["cleanup_error"] = str(error)
        report["passed"] = report["passed"] and report["cleanup_confirmed"]
        (output / (runtime + "-probe.json")).write_text(json.dumps(report, indent=2) + "\n")
    require(report["passed"], f"{runtime} probe failed; retain evidence and discard the guest")


def _listener_controls(output):
    """Create host-only sinks and prove the controller can observe each one."""
    stack = contextlib.ExitStack()
    try:
        tcp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        tcp.bind(("127.0.0.1", 0))
        tcp.listen(2)
        tcp.setblocking(False)
        udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp.bind(("127.0.0.1", 0))
        udp.setblocking(False)
        abstract_name = "symbi-escape-" + uuid.uuid4().hex
        abstract = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        abstract.bind("\0" + abstract_name)
        abstract.listen(2)
        abstract.setblocking(False)
        pipewire = output / ("pipewire-" + uuid.uuid4().hex)
        pipewire_listener = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        pipewire_listener.bind(str(pipewire))
        pipewire_listener.listen(2)
        pipewire_listener.setblocking(False)
        stack.callback(pipewire.unlink, missing_ok=True)
        ssh_root = output / ("host-private-" + uuid.uuid4().hex)
        ssh_root.mkdir(mode=0o700)
        stack.callback(shutil.rmtree, ssh_root, True)
        (ssh_root / ".ssh").mkdir(mode=0o700)
        ssh_canary = ssh_root / ".ssh/canary"
        ssh_canary.write_text("qualification-private-canary\n")
        ssh_canary.chmod(0o600)
        require(os.getpid() > 32, "controller PID could alias the bounded worker PID namespace")

        with socket.create_connection(tcp.getsockname(), timeout=2) as control:
            control.sendall(b"control")
        accepted, _ = tcp.accept()
        accepted.close()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
            control.sendto(b"control", udp.getsockname())
        require(udp.recv(64) == b"control", "DNS observer positive control failed")
        for listener, address in ((abstract, "\0" + abstract_name),
                                  (pipewire_listener, str(pipewire))):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
                control.settimeout(2)
                control.connect(address)
                control.sendall(b"control")
            accepted, _ = listener.accept()
            accepted.close()
        return stack, {
            "tcp": tcp, "udp": udp, "abstract": abstract, "pipewire": pipewire_listener,
            "tcp_port": tcp.getsockname()[1], "udp_port": udp.getsockname()[1],
            "abstract_name": abstract_name, "pipewire_path": str(pipewire),
            "ssh_canary": str(ssh_canary), "host_pid": os.getpid(),
        }
    except Exception:
        stack.close()
        raise


def validate_escape_payload(payload, runtime, effects):
    require(isinstance(payload, dict) and payload.get("passed") is True,
            f"{runtime} escape payload did not pass")
    require(payload.get("uid") == 65534 and payload.get("gid") == 65534
            and payload.get("docker_socket_visible") is False,
            "escape payload identity or Docker-socket isolation changed")
    cases = payload.get("cases")
    require(isinstance(cases, list) and len(cases) == len(ESCAPE_CASES),
            "escape payload case count changed")
    names = [row.get("name") if isinstance(row, dict) else None for row in cases]
    require(tuple(names) == ESCAPE_CASES and all(row.get("passed") is True for row in cases),
            "escape payload omitted, reordered or passed through a required denial")
    require(effects == {"tcp": False, "udp": False, "abstract": False,
                        "pipewire": False},
            "an escape observer received a worker effect")


def escape_probe(env, runtime, image_id, output):
    """Run narrower controller-observed negatives in one isolated worker."""
    identity = None
    name = "symbi-escape-" + uuid.uuid4().hex
    stack = None
    report = {"runtime": runtime, "passed": False, "cleanup_confirmed": False,
              "cases": list(ESCAPE_CASES)}
    try:
        stack, controls = _listener_controls(output)
        arguments = [
            "create", "--name", name,
            "--pull=never", "--runtime", runtime, "--network=none", "--read-only",
            "--user=65534:65534", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
            "--cpus=0.5", "--memory=256m", "--memory-swap=256m", "--pids-limit=32",
            "--ipc=private", "--cgroupns=private", "--log-driver=none",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16777216",
        ]
        environment = {
            "SYMBI_ESCAPE_TCP_PORT": str(controls["tcp_port"]),
            "SYMBI_ESCAPE_UDP_PORT": str(controls["udp_port"]),
            "SYMBI_ESCAPE_ABSTRACT": controls["abstract_name"],
            "SYMBI_ESCAPE_PIPEWIRE": controls["pipewire_path"],
            "SYMBI_ESCAPE_SSH_CANARY": controls["ssh_canary"],
            "SYMBI_ESCAPE_HOST_PID": str(controls["host_pid"]),
        }
        for environment_name, value in environment.items():
            arguments += ["--env", environment_name + "=" + value]
        arguments += ["--entrypoint=/usr/local/bin/python3", image_id,
                      "-B", "-c", ESCAPE_PAYLOAD]
        result = docker_call(env, *arguments)
        identity = result.stdout.strip()
        require(re.fullmatch(r"[a-f0-9]{64}", identity or ""),
                "escape create returned no immutable container ID")
        inspected = json.loads(docker_call(env, "inspect", identity).stdout)[0]
        validate_container(inspected, runtime, image_id)
        attached = docker_call(env, "start", "--attach", identity)
        state = json.loads(docker_call(env, "inspect", identity).stdout)[0]["State"]
        require(state.get("Running") is False and state.get("ExitCode") == 0,
                "escape payload failed")
        payload = _unique_object(attached.stdout)
        ready = set(select.select(
            [controls[name] for name in ("tcp", "udp", "abstract", "pipewire")],
            [], [], 0.25)[0])
        effects = {name: controls[name] in ready for name in
                   ("tcp", "udp", "abstract", "pipewire")}
        validate_escape_payload(payload, runtime, effects)
        report.update(passed=True, payload=payload, observer_effects=effects,
                      positive_controls=True)
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        try:
            removed = docker_call(env, "rm", "--force", name, check=False)
            remaining = docker_call(env, "ps", "-aq", "--no-trunc", "--filter",
                                    "name=^/" + name + "$").stdout.splitlines()
            require(not remaining, "escape container remains after cleanup")
            require(identity is None or removed.returncode == 0,
                    "created escape container could not be removed")
            report["cleanup_confirmed"] = True
        except (ValueError, OSError, subprocess.SubprocessError, TypeError) as error:
            report["cleanup_error"] = type(error).__name__ + ": " + str(error)
        if stack is not None:
            stack.close()
        report["passed"] = report["passed"] and report["cleanup_confirmed"]
        evidence = output / (runtime + "-controller-negatives.json")
        evidence.write_text(json.dumps(report, indent=2) + "\n")
    require(report["passed"], f"{runtime} controller negatives failed; retain evidence and discard the guest")
    return {
        "passed": True,
        "cleanup_confirmed": report["cleanup_confirmed"],
        "positive_controls": report["positive_controls"],
        "observer_effects": report["observer_effects"],
        "cases": list(ESCAPE_CASES),
        "report_sha256": digest(evidence),
    }


def compact_evidence(report):
    """Return the bounded public record; raw fixture logs remain in the disposable VM."""
    runs = report.get("runs", [])
    require(len(runs) == 6, "compact evidence requires the complete six-run matrix")
    compact_runs = []
    for run in runs:
        compact_runs.append({key: run[key] for key in (
            "backend", "driver", "passed", "cleanup_confirmed", "driver_sha256",
            "report_sha256", "observed_runtimes", "cases",
        )})
    escapes = report.get("escape_negatives")
    require(isinstance(escapes, dict) and set(escapes) == set(BACKENDS),
            "compact evidence requires both escape-negative backends")
    return {
        "schema": 1,
        "card": "P0-05",
        "passed": report.get("passed") is True,
        "qualified": False,
        "container_qualified": False,
        "os_qualified": False,
        "release_qualified": False,
        "signature_qualified": False,
        "native_fixture_matrix_passed": report.get("native_fixture_matrix_passed") is True,
        "controller_escape_negatives_passed": report.get("controller_escape_negatives_passed") is True,
        "managed_route_qualified": False,
        "escape_suite_qualified": False,
        "review_complete": False,
        "remaining_blockers": ["managed-route-evidence", "escape-suite-evidence", "required-review"],
        "runtime_revision": report["runtime_revision"],
        "source_tree": report["source_tree"],
        "binary_sha256": report["binary_sha256"],
        "fixture_source_revision": report["fixture_source_revision"],
        "fixture_source_tree": report["fixture_source_tree"],
        "fixture_source_lock_sha256": report["fixture_source_lock_sha256"],
        "fixture_ref": report["fixture_ref"],
        "fixture_id": report["fixture_id"],
        "runsc_sha256": report["runsc_sha256"],
        "image_ref": report["image_ref"],
        "deployment_sha256": report["deployment_sha256"],
        "bootc_before_sha256": report["bootc_before_sha256"],
        "bootc_after_sha256": report["bootc_after_sha256"],
        "runs": compact_runs,
        "escape_negatives": escapes,
        "scope": "Native fixture matrix and controller negatives; shipping managed route, escape suite and review remain open",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-host", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--fixture-source", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--expected-runsc-sha256")
    parser.add_argument("--fixture-ref")
    parser.add_argument("--image-ref")
    parser.add_argument("--bootc-status-socket", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = {
        "schema": 1, "card": "P0-05", "passed": False, "qualified": False,
        "container_qualified": False, "os_qualified": False,
        "release_qualified": False, "signature_qualified": False,
        "native_fixture_matrix_passed": False,
        "controller_escape_negatives_passed": False,
        "managed_route_qualified": False, "escape_suite_qualified": False,
        "review_complete": False,
        "remaining_blockers": ["native-fedora-six-run-matrix", "managed-route-evidence",
                               "escape-suite-evidence", "required-review"],
        "scope": "Native fixture controller; shipping managed route, escape suite and review remain open",
    }
    output = None
    try:
        report["host"] = host_details()
        if args.check_host:
            report["host_ready"] = True
            print(json.dumps(report, indent=2))
            return 0
        require(all((args.source, args.fixture_source, args.binary, args.expected_binary_sha256, args.expected_runsc_sha256,
                     args.fixture_ref, args.image_ref, args.bootc_status_socket, args.output)),
                "all qualification inputs are required")
        for value in (args.expected_binary_sha256, args.expected_runsc_sha256):
            require(re.fullmatch(r"[a-f0-9]{64}", value), "invalid authenticated binary digest")
        require(DIGEST_REF.fullmatch(args.fixture_ref), "fixture must use an authenticated immutable image reference")
        with (ROOT / "upstream/symbiont.toml").open("rb") as stream:
            revision = tomllib.load(stream)["revision"]
        fixture_lock_path = ROOT / "image/container/native-fixture.lock.json"
        fixture_lock = _unique_object(fixture_lock_path.read_bytes())
        require(fixture_lock.get("schema") == 1
                and fixture_lock.get("runtime_source_revision") == revision
                and fixture_lock.get("qualified") is False,
                "reviewed fixture source lock differs from the runtime binding")
        fixture_revision = fixture_lock.get("revision", "")
        fixture_tree = fixture_lock.get("tree", "")
        require(re.fullmatch(r"[a-f0-9]{40}", fixture_revision or "")
                and re.fullmatch(r"[a-f0-9]{40}", fixture_tree or ""),
                "reviewed fixture source identities are invalid")
        source, binary = args.source.resolve(strict=True), args.binary.resolve(strict=True)
        fixture_source = args.fixture_source.resolve(strict=True)
        require(source != fixture_source, "runtime and reviewed fixture checkouts must remain distinct")
        validate_source(source, revision)
        validate_source(fixture_source, fixture_revision)
        source_tree = command_output(["git", "rev-parse", "HEAD^{tree}"], source)
        require(re.fullmatch(r"[a-f0-9]{40}", source_tree), "runtime source tree identity is invalid")
        require(command_output(["git", "rev-parse", "HEAD^{tree}"], fixture_source) == fixture_tree,
                "reviewed fixture source tree changed")
        cargo_lock_sha256 = digest(source / "Cargo.lock")
        drivers = {name: digest(fixture_source / "scripts" / name) for name in FIXTURE_DRIVERS}
        require(drivers == fixture_lock.get("drivers"), "reviewed fixture driver hashes changed")
        require(digest(binary) == args.expected_binary_sha256, "runtime binary hash mismatch")
        require(digest("/usr/bin/runsc") == args.expected_runsc_sha256, "runsc binary hash mismatch")
        validate_status_socket(args.bootc_status_socket)
        bootc = read_bootc_status(args.bootc_status_socket)
        validate_deployment(bootc, args.image_ref)
        candidate = args.output.resolve()
        require(not candidate.is_relative_to("/tmp") and not candidate.is_relative_to(source)
                and not candidate.is_relative_to(fixture_source),
                "use guest disk outside /tmp and source checkouts")
        candidate.mkdir(mode=0o700, parents=True, exist_ok=False)
        output = candidate
        (output / "docker-client").mkdir(mode=0o700)
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "DOCKER_HOST": "unix:///var/run/docker.sock",
               "DOCKER_CONFIG": str(output / "docker-client")}
        info = json.loads(docker_call(env, "info", "--format", "{{json .}}").stdout)
        validate_daemon(info)
        inspected = json.loads(docker_call(env, "image", "inspect", args.fixture_ref).stdout)[0]
        require(args.fixture_ref in inspected.get("RepoDigests", []), "cached fixture digest mismatch")
        image_id = inspected["Id"]
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", image_id), "invalid cached fixture ID")
        report.update(runtime_revision=revision, binary_sha256=args.expected_binary_sha256,
                      source_tree=source_tree, cargo_lock_sha256=cargo_lock_sha256,
                      fixture_source_revision=fixture_revision, fixture_source_tree=fixture_tree,
                      fixture_source_lock_sha256=digest(fixture_lock_path),
                      runsc_sha256=args.expected_runsc_sha256, image_ref=args.image_ref,
                      fixture_ref=args.fixture_ref, fixture_id=image_id, daemon=retained_daemon_info(info),
                      runsc_version=command_output(["/usr/bin/runsc", "--version"]),
                      drivers=drivers,
                      runs=[], escape_negatives={})
        (output / "bootc-before.json").write_text(json.dumps(bootc, indent=2) + "\n")
        before_deployment_sha256 = deployment_digest(bootc)
        for runtime in ("runc", "runsc"):
            probe(env, runtime, image_id, output)
            require(container_ids(env) == [], "daemon has containers before controller negatives")
            report["escape_negatives"][runtime] = escape_probe(
                env, runtime, image_id, output)
            require(container_ids(env) == [], "controller negatives left containers behind")
        require(container_ids(env) == [], "daemon has containers before fixture execution")
        for item in fixture_plan(fixture_source, binary, args.fixture_ref, output):
            record = {"backend": item["backend"], "driver": item["driver"],
                      "passed": False, "cleanup_confirmed": False,
                      "remaining_containers": None,
                      "driver_sha256": report["drivers"][item["driver"]]}
            report["runs"].append(record)
            started = time.monotonic()
            report_raw = None
            try:
                require(container_ids(env) == [], "daemon has containers before a fixture run")
                run_driver(item["command"], item["log"], 900)
                report_raw, result = read_fixture_result(item["target"])
                observed = validate_fixture_result(
                    result, item["driver"], item["backend"], args.expected_binary_sha256,
                    report["drivers"][item["driver"]], image_id, args.expected_runsc_sha256,
                )
                record.update(passed=True, report_sha256=hashlib.sha256(report_raw).hexdigest(),
                              observed_runtimes=observed, elapsed_seconds=time.monotonic() - started,
                              cases=[case["name"] for case in result["cases"]])
            finally:
                remaining = container_ids(env)
                record["remaining_containers"] = remaining
                record["cleanup_confirmed"] = remaining == []
            require(report_raw is not None, "fixture produced no validated report")
            validate_run_record(record, report_raw, item["backend"])
        validate_source(source, revision)
        validate_source(fixture_source, fixture_revision)
        require(command_output(["git", "rev-parse", "HEAD^{tree}"], source) == source_tree
                and digest(source / "Cargo.lock") == cargo_lock_sha256,
                "qualification source identity changed")
        require(command_output(["git", "rev-parse", "HEAD^{tree}"], fixture_source) == fixture_tree
                and {name: digest(fixture_source / "scripts" / name) for name in FIXTURE_DRIVERS} == drivers,
                "reviewed fixture source identity changed")
        require(digest(binary) == args.expected_binary_sha256 and digest("/usr/bin/runsc") == args.expected_runsc_sha256,
                "qualification binary changed")
        after = read_bootc_status(args.bootc_status_socket)
        validate_deployment(after, args.image_ref)
        (output / "bootc-after.json").write_text(json.dumps(after, indent=2) + "\n")
        after_deployment_sha256 = deployment_digest(after)
        require(after_deployment_sha256 == before_deployment_sha256,
                "booted deployment identity changed during qualification")
        require(len(report["runs"]) == 6
                and {(run["backend"], run["driver"]) for run in report["runs"]}
                == {(backend, driver) for backend in BACKENDS for driver in FIXTURE_DRIVERS},
                "complete six-run fixture matrix was not retained")
        report.update(passed=True, native_fixture_matrix_passed=True,
                      controller_escape_negatives_passed=True,
                      remaining_blockers=["managed-route-evidence", "escape-suite-evidence",
                                          "required-review"],
                      deployment_sha256=before_deployment_sha256,
                      bootc_before_sha256=digest(output / "bootc-before.json"),
                      bootc_after_sha256=digest(output / "bootc-after.json"))
        public = output / "qualification.json"
        public.write_text(json.dumps(compact_evidence(report), indent=2) + "\n")
        report["public_reports"] = {public.name: digest(public)}
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        report["error"] = str(error)
    finally:
        if output:
            (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
