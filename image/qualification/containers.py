#!/usr/bin/env python3
"""Bounded Moby/runsc probes and pinned Docker fixture drivers in a Fedora VM.

These probes cannot qualify the complete Symbiont gVisor route. The report always
retains qualified=false until the remaining route/escape evidence is implemented.
No pull, daemon change, host build or global container cleanup is performed.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import uuid

from landlock import (ROOT, DIGEST_REF, command_output, digest, host_details, require,
                      run_driver, validate_deployment, validate_source)

FIXTURE_DRIVERS = ("test-filesystem-grants.py", "test-source-broker.py", "test-git-source.py")
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
                "NanoCpus": 500000000, "PidsLimit": 32, "IpcMode": "private", "CgroupnsMode": "private"}
    for key, value in expected.items():
        require(key in host and host[key] == value, f"container {key} differs from the bounded profile")
    require(host.get("CapDrop") == ["ALL"] and not host.get("CapAdd"), "capabilities must be dropped")
    require("no-new-privileges=true" in host.get("SecurityOpt", []), "no-new-privileges required")
    require(host.get("LogConfig", {}).get("Type") == "none", "daemon log storage is not allowed")
    require(not host.get("Binds"), "host bind mounts are not allowed in probes")
    require(all(m.get("Type") == "tmpfs" and m.get("Destination") == "/tmp"
                for m in container.get("Mounts", [])), "unexpected mount or anonymous image volume")


def docker_call(env, *arguments, timeout=30, check=True):
    return subprocess.run(["/usr/bin/docker", *arguments], env=env, text=True,
                          capture_output=True, timeout=timeout, check=check)


def probe(env, runtime, image_id, output):
    identity = None
    report = {"runtime": runtime, "passed": False, "cleanup_confirmed": False}
    try:
        result = docker_call(env, "create", "--name", "symbi-qual-" + uuid.uuid4().hex,
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
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        report["error"] = str(error)
    finally:
        if identity:
            try:
                docker_call(env, "rm", "--force", identity)
                require(not docker_call(env, "ps", "-aq", "--no-trunc", "--filter", "id=" + identity).stdout.strip(),
                        "probe container remains after cleanup")
                report["cleanup_confirmed"] = True
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                report["cleanup_error"] = str(error)
        report["passed"] = report["passed"] and report["cleanup_confirmed"]
        (output / (runtime + "-probe.json")).write_text(json.dumps(report, indent=2) + "\n")
    require(report["passed"], f"{runtime} probe failed; retain evidence and discard the guest")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-host", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--expected-runsc-sha256")
    parser.add_argument("--fixture-ref")
    parser.add_argument("--image-ref")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = {"card": "P0-05", "passed": False, "qualified": False,
              "scope": "infrastructure probes and Docker fixtures; full gVisor route evidence pending"}
    output = None
    try:
        report["host"] = host_details()
        if args.check_host:
            report["host_ready"] = True
            print(json.dumps(report, indent=2))
            return 0
        require(all((args.source, args.binary, args.expected_binary_sha256, args.expected_runsc_sha256,
                     args.fixture_ref, args.image_ref, args.output)), "all qualification inputs are required")
        for value in (args.expected_binary_sha256, args.expected_runsc_sha256):
            require(re.fullmatch(r"[a-f0-9]{64}", value), "invalid authenticated binary digest")
        require(DIGEST_REF.fullmatch(args.fixture_ref), "fixture must use an authenticated immutable image reference")
        with (ROOT / "upstream/symbiont.toml").open("rb") as stream:
            revision = tomllib.load(stream)["revision"]
        source, binary = args.source.resolve(strict=True), args.binary.resolve(strict=True)
        validate_source(source, revision)
        require(digest(binary) == args.expected_binary_sha256, "runtime binary hash mismatch")
        require(digest("/usr/bin/runsc") == args.expected_runsc_sha256, "runsc binary hash mismatch")
        bootc = json.loads(command_output(["bootc", "status", "--json"]))
        validate_deployment(bootc, args.image_ref)
        candidate = args.output.resolve()
        require(not candidate.is_relative_to("/tmp") and not candidate.is_relative_to(source), "use guest disk outside /tmp and source")
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
                      runsc_sha256=args.expected_runsc_sha256, image_ref=args.image_ref,
                      fixture_ref=args.fixture_ref, fixture_id=image_id, daemon=retained_daemon_info(info),
                      runsc_version=command_output(["/usr/bin/runsc", "--version"]),
                      drivers={name: digest(source / "scripts" / name) for name in FIXTURE_DRIVERS})
        (output / "bootc-before.json").write_text(json.dumps(bootc, indent=2) + "\n")
        for runtime in ("runc", "runsc"):
            probe(env, runtime, image_id, output)
        for driver in FIXTURE_DRIVERS:
            target = output / (driver.removesuffix(".py") + ".json")
            run_driver([sys.executable, "-E", "-s", "-B", str(source / "scripts" / driver),
                        "--binary", str(binary), "--image", args.fixture_ref, "--report", str(target)],
                       output / (driver + ".log"), 900)
            result = json.loads(target.read_text())
            require(result.get("passed") is True and result.get("binary_sha256") == args.expected_binary_sha256,
                    f"{driver} failed or reported a different binary")
        validate_source(source, revision)
        require(digest(binary) == args.expected_binary_sha256 and digest("/usr/bin/runsc") == args.expected_runsc_sha256,
                "qualification binary changed")
        validate_deployment(json.loads(command_output(["bootc", "status", "--json"])), args.image_ref)
        report["passed"] = True
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        report["error"] = str(error)
    finally:
        if output:
            (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
