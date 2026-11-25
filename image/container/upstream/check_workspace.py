#!/usr/bin/env python3
"""Validate the exact upstream baseline and fixture draft on hosted CI only."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import tomllib


RUST = "1.100.0"
PIN = "deddb9e997244d2289c217ad76b8fde0e9b0339b"
PATCH = "a4545649b1c83f0a3402781f815ebc66ea2b507128d17f61e76c4febb5017bda"
FILES = {"docs/gvisor-fixture-qualification.md", "scripts/container_fixture_profile.py",
         "scripts/file_grant_backend.py", "scripts/test-git-source.py",
         "scripts/test-source-broker.py", "scripts/test_container_fixture_profile.py"}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require_host_capacity(meminfo):
    measurements = {}
    for line in meminfo.splitlines():
        fields = line.split()
        if fields and fields[0] in {"MemTotal:", "MemAvailable:"}:
            if len(fields) != 3 or fields[2] != "kB" or fields[0][:-1] in measurements:
                raise ValueError("Unexpected hosted memory measurement")
            measurements[fields[0][:-1]] = int(fields[1]) * 1024
    if measurements.get("MemTotal", 0) < 14 * 1024**3 or measurements.get("MemAvailable", 0) < 10 * 1024**3:
        raise ValueError("Hosted builder needs at least 14 GiB total and 10 GiB available before its bounded 8 GiB compile")
    return measurements


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Refusing local runtime compilation")
    root = Path.cwd()
    source = root / ".cache/runtime-source"
    evidence = root / ".cache/runtime-workspace-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    cgroup = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    names = ("memory.max", "memory.swap.max", "cpu.max", "pids.max")
    limits = {name: (cgroup / name).read_text().strip() for name in names}
    (evidence / "cgroup-limits.json").write_text(json.dumps(limits, indent=2) + "\n")
    assert limits == {"memory.max": "8589934592", "memory.swap.max": "0", "cpu.max": "200000 100000", "pids.max": "256"}
    record = {"schema": 1, "source_revision": PIN, "rust_version": RUST, "patch_sha256": PATCH, "checks": [],
              "baseline_passed": False, "patched_workspace_passed": False,
              "os_qualified": False, "source_commit": os.environ["GITHUB_SHA"],
              "scope": "Ubuntu hosted workspace and Python fixture checks; no Fedora, container or escape qualification"}

    def save():
        (evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n")

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=source, text=True).strip()

    def run(phase, name, command, timeout):
        started = time.monotonic()
        record["active_check"] = {"phase": phase, "name": name, "command": command}
        save()  # Survives whole-unit termination, including a cgroup OOM kill.
        print(json.dumps({"phase": phase, "check": name, "state": "started"}), flush=True)
        with (evidence / f"{phase}-{name}.log").open("wb") as log:
            child = subprocess.Popen(command, cwd=source, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                child.wait(timeout=timeout)
                timed_out = False
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
        row = {"phase": phase, "name": name, "command": command, "exit_code": child.returncode,
               "timeout": timed_out, "elapsed_seconds": round(time.monotonic() - started, 3),
               "passed": not timed_out and child.returncode == 0}
        record["checks"].append(row)
        del record["active_check"]
        save()
        print(json.dumps(row), flush=True)
        if timed_out:
            raise RuntimeError("Check timed out; no later check is started")
        return row["passed"]

    def workspace(phase):
        outcomes = []
        for name, args, timeout in (("build", ["build", "--workspace", "--locked"], 3600),
                                    ("test", ["test", "--workspace", "--locked"], 1800),
                                    ("clippy", ["clippy", "--workspace", "--locked", "--", "-D", "warnings"], 1800),
                                    ("fmt", ["fmt", "--check"], 180)):
            outcomes.append(run(phase, name, ["cargo", "+" + RUST, *args], timeout))
        return all(outcomes)

    try:
        assert tomllib.loads((root / "upstream/symbiont.toml").read_text())["revision"] == PIN
        assert git("rev-parse", "HEAD") == PIN and not git("status", "--porcelain", "--untracked-files=all")
        record["source_clean_before"] = True
        lock_hash = digest(source / "Cargo.lock")
        record["cargo_lock_sha256"] = lock_hash
        record["started_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record["host_memory_bytes"] = require_host_capacity(Path("/proc/meminfo").read_text())
        save()
        subprocess.run(["rustup", "toolchain", "install", RUST, "--profile", "minimal",
                        "--component", "clippy", "--component", "rustfmt", "--no-self-update"], check=True, timeout=300)
        record["rustc"] = subprocess.check_output(["rustc", "+" + RUST, "--version", "--verbose"], text=True)
        record["protoc"] = subprocess.check_output(["protoc", "--version"], text=True).strip()
        save()
        record["baseline_passed"] = workspace("baseline")
        save()
        assert digest(source / "Cargo.lock") == lock_hash
        assert not git("status", "--porcelain", "--untracked-files=all")
        if not record["baseline_passed"]:
            raise RuntimeError("Unchanged baseline failed; fixture patch was not applied")
        patch = root / "image/container/upstream/gvisor-fixtures.patch"
        assert digest(patch) == PATCH
        subprocess.run(["git", "apply", "--check", str(patch)], cwd=source, check=True)
        subprocess.run(["git", "apply", "--index", str(patch)], cwd=source, check=True)
        assert set(git("diff", "--cached", "--name-only").splitlines()) == FILES
        assert not git("diff", "--name-only")
        record["patch_applied"] = True
        save()
        focused = run("fixture", "python", [sys.executable, "scripts/test_container_fixture_profile.py", "-v"], 120)
        gates = workspace("fixture")
        assert digest(source / "Cargo.lock") == lock_hash
        assert git("rev-parse", "HEAD") == PIN and not git("diff", "--name-only")
        assert set(git("diff", "--cached", "--name-only").splitlines()) == FILES
        record["patched_workspace_passed"] = focused and gates
        if not record["patched_workspace_passed"]:
            raise RuntimeError("Patched-source checks failed; no upstream commit is permitted")
        record["binaries"] = {}
        for name in ("symbi", "symbi-sandbox-supervisor"):
            binary = root / ".cache/runtime-target/debug" / name
            record["binaries"][name] = {"bytes": binary.stat().st_size, "sha256": digest(binary)}
        record["finished_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    except BaseException as error:
        record["failure"] = str(error)
        save()
        raise
    finally:
        final = {name: (cgroup / name).read_text().strip() for name in (*names, "memory.peak", "memory.events", "cpu.stat")}
        (evidence / "cgroup-final.json").write_text(json.dumps(final, indent=2) + "\n")
        assert all(final[name] == value for name, value in limits.items())


if __name__ == "__main__":
    main()
