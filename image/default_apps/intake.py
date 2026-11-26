#!/usr/bin/env python3
"""Passively authenticate fixed terminal-application sources on hosted CI."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import urllib.parse
import urllib.request

from .inputs import digest, inspect_archive, load_inputs


def download(url, target, expected_bytes, expected_sha256):
    request = urllib.request.Request(url, headers={
        "User-Agent": "SymbiOS-P0-Default-App-Intake/1", "Accept-Encoding": "identity"})
    started = time.monotonic()
    size = 0
    hasher = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=30) as response, target.open("xb") as output:
        final = urllib.parse.urlsplit(response.url)
        if (response.status != 200 or final.scheme != "https"
                or final.hostname not in {"github.com", "codeload.github.com"}
                or final.username is not None or final.password is not None
                or final.port not in (None, 443) or final.query or final.fragment):
            raise ValueError("unexpected public application source response")
        while block := response.read(65536):
            size += len(block)
            if size > expected_bytes or time.monotonic() - started > 300:
                raise ValueError("application source exceeded its size or time bound")
            hasher.update(block)
            output.write(block)
    if size != expected_bytes or hasher.hexdigest() != expected_sha256:
        raise ValueError("application source download changed")
    return {"url": url, "final_host": final.hostname, "bytes": size,
            "sha256": hasher.hexdigest()}


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.geteuid() == 0):
        raise SystemExit("use the unprivileged disposable default-application intake unit")
    root = Path.cwd().resolve()
    group = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    expected_limits = {"memory.max": "536870912", "memory.swap.max": "0",
                       "cpu.max": "100000 100000", "pids.max": "32"}
    if not group.name.startswith("symbi-default-app-intake-") or limits != expected_limits:
        raise ValueError("unexpected default-application intake resource group")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    if (any(status[name].strip() != "0000000000000000"
            for name in ("CapEff", "CapPrm", "CapBnd")) or status["NoNewPrivs"].strip() != "1"):
        raise ValueError("application source inspector has unexpected process authority")
    evidence = root / ".cache/default-app-intake-evidence"
    private = root / ".cache/default-app-intake-private"
    evidence.mkdir()
    private.mkdir(mode=0o700)
    record = {"schema": 1, "passed": False, "selected": False,
              "security_qualified": False, "os_qualified": False,
              "candidate_executed": False, "archive_extracted": False,
              "source_commit": os.environ["GITHUB_SHA"], "limits": limits,
              "inputs_sha256": digest(root / "image/default_apps/source-inputs.json"),
              "downloads": {}, "inventories": {},
              "scope": "Hash and passive source/Cargo inventory only; no extraction, execution, compilation, installation or release claim"}

    def save():
        (evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n")

    try:
        pins = load_inputs(root / "image/default_apps/source-inputs.json")
        for name, app in pins["applications"].items():
            target = private / (name + ".tar.gz")
            source = app["source"]
            record["downloads"][name] = download(
                source["url"], target, source["bytes"], source["sha256"])
            save()
            record["inventories"][name] = inspect_archive(target, app)
            save()
        record["passed"] = True
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        shutil.rmtree(private)
        record["private_downloads_removed"] = not private.exists()
        final = {name: (group / name).read_text().strip()
                 for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        record["cgroup_final"] = final
        events = dict(line.split() for line in final["memory.events"].splitlines())
        if (not record["private_downloads_removed"]
                or any(final[name] != value for name, value in limits.items())
                or any(events.get(name) != "0" for name in ("oom", "oom_kill", "oom_group_kill"))):
            record["passed"] = False
        save()
    if not record["passed"]:
        raise RuntimeError("default-application intake resource controls failed")


if __name__ == "__main__":
    main()
