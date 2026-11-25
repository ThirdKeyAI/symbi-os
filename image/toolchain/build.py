#!/usr/bin/env python3
"""Build an exact upstream CLI in the hosted resource unit, then run its tests."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Refusing local compilation")
    root = Path.cwd()
    evidence = root / ".cache/image-tool-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    config = json.loads((root / "image/toolchain/bluebuild.json").read_text())
    cgroup = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (cgroup / name).read_text().strip() for name in
              ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    (evidence / "cgroup-limits.json").write_text(json.dumps(limits, indent=2) + "\n")
    assert limits == {"memory.max": "4294967296", "memory.swap.max": "0",
                      "cpu.max": "200000 100000", "pids.max": "256"}, limits
    source = root / ".cache/bluebuild-source"

    def output(*command):
        return subprocess.check_output(command, cwd=source, text=True).strip()

    assert output("git", "rev-parse", "HEAD") == config["revision"]
    assert not output("git", "status", "--porcelain", "--untracked-files=all")
    lock = (source / "Cargo.lock").read_bytes()
    record = {"source_revision": config["revision"], "source_clean_before_build": True,
              "cargo_lock_sha256": hashlib.sha256(lock).hexdigest(), "rust": config["rust"],
              "features": config["features"], "profile": config["profile"], "build_passed": False}
    path = evidence / "source-build.json"
    path.write_text(json.dumps(record, indent=2) + "\n")
    subprocess.run(["rustup", "toolchain", "install", config["rust"], "--profile", "minimal", "--no-self-update"], check=True)
    record["rustc"] = output("rustc", "+" + config["rust"], "--version", "--verbose")
    command = ["cargo", "+" + config["rust"], "build", "--locked", "--bin", "bluebuild",
               "--no-default-features", "--features", ",".join(config["features"])]
    record["command"] = command
    path.write_text(json.dumps(record, indent=2) + "\n")
    subprocess.run(command, cwd=source, check=True)
    assert (source / "Cargo.lock").read_bytes() == lock, "Cargo.lock changed"
    record["build_passed"] = True
    path.write_text(json.dumps(record, indent=2) + "\n")
    binary = root / ".cache/bluebuild-target/debug/bluebuild"
    env = dict(os.environ, BLUEBUILD_REVISION=config["revision"])
    subprocess.run([sys.executable, "image/toolchain/qualify.py", "--binary", str(binary),
                    "--root", str(root), "--evidence", str(evidence)], env=env, check=True)


if __name__ == "__main__":
    main()
