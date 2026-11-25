#!/usr/bin/env python3
"""Build an exact upstream CLI in the hosted resource unit, then run its tests."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from bootstrap_cosign import bootstrap


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Refusing local compilation")
    root = Path.cwd()
    evidence = root / ".cache/image-tool-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    config = json.loads((root / "image/toolchain/bluebuild.json").read_text())
    assert config["schema"] == 1 and config["profile"] == "dev"
    cgroup = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (cgroup / name).read_text().strip() for name in
              ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    (evidence / "cgroup-limits.json").write_text(json.dumps(limits, indent=2) + "\n")
    assert limits == {"memory.max": "4294967296", "memory.swap.max": "0",
                      "cpu.max": "200000 100000", "pids.max": "256"}, limits
    cosign = bootstrap(root, evidence)
    os.environ["PATH"] = str(cosign.parent) + os.pathsep + os.environ["PATH"]
    source = root / ".cache/bluebuild-source"

    def output(*command):
        return subprocess.check_output(command, cwd=source, text=True).strip()

    assert output("git", "rev-parse", "HEAD") == config["revision"]
    assert not output("git", "status", "--porcelain", "--untracked-files=all")
    lock = (source / "Cargo.lock").read_bytes()
    record = {"source_revision": config["revision"], "source_clean_before_build": True,
              "cargo_lock_sha256": hashlib.sha256(lock).hexdigest(), "rust": config["rust"],
              "features": config["features"], "profile": config["profile"], "build_passed": False,
              "cli_acceptance_passed": False, "upstream_unit_tests_passed": False}
    path = evidence / "source-build.json"
    record["patches"] = []
    for patch in config.get("patches", []):
        relative = Path(patch["path"])
        assert not relative.is_absolute() and ".." not in relative.parts
        artifact = (root / relative).resolve(strict=True)
        assert artifact.is_relative_to(root / "image/toolchain/patches")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        assert digest == patch["sha256"], "Downstream patch hash mismatch"
        subprocess.run(["git", "apply", "--check", str(artifact)], cwd=source, check=True)
        subprocess.run(["git", "apply", str(artifact)], cwd=source, check=True)
        record["patches"].append({"path": patch["path"], "sha256": digest})
    subprocess.run(["git", "add", "--intent-to-add", "src/commands/validate"], cwd=source, check=True)
    subprocess.run(["git", "diff", "--check"], cwd=source, check=True)
    diff = subprocess.check_output(["git", "diff", "--binary", "--no-ext-diff"], cwd=source)
    (evidence / "applied-source.patch").write_bytes(diff)
    record["applied_diff_sha256"] = hashlib.sha256(diff).hexdigest()
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
    record["cli_acceptance_passed"] = True
    path.write_text(json.dumps(record, indent=2) + "\n")
    test_command = ["cargo", "+" + config["rust"], "test", "--workspace", "--locked",
                    "--no-default-features", "--features", ",".join(config["features"])]
    record["test_command"] = test_command
    path.write_text(json.dumps(record, indent=2) + "\n")
    test_env = dict(os.environ, CARGO_PROFILE_TEST_DEBUG="0", CARGO_PROFILE_TEST_INCREMENTAL="false",
                    CARGO_PROFILE_TEST_CODEGEN_UNITS="1")
    subprocess.run(test_command, cwd=source, env=test_env, check=True)
    assert (source / "Cargo.lock").read_bytes() == lock, "Cargo.lock changed during tests"
    record["upstream_unit_tests_passed"] = True
    path.write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
