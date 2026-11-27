#!/usr/bin/env python3
"""Download and passively authenticate fixed Tolaria build inputs on hosted CI."""

import json
import os
from pathlib import Path
import shutil
import time
import urllib.parse
import urllib.request

from .inputs import digest, inspect_pnpm, inspect_source, load_pins, require_patch


def download(url, target, expected_bytes, expected_sha256, allowed_hosts):
    request = urllib.request.Request(
        url, headers={"User-Agent": "SymbiOS-P0-Tolaria-intake/1", "Accept-Encoding": "identity"})
    started = time.monotonic()
    size = 0
    import hashlib
    hasher = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=30) as response, target.open("xb") as output:
        final = urllib.parse.urlsplit(response.url)
        if (response.status != 200 or final.scheme != "https" or final.hostname not in allowed_hosts
                or final.username is not None or final.password is not None or final.port not in (None, 443)
                or final.query or final.fragment):
            raise ValueError("Unexpected public input response")
        while block := response.read(65536):
            size += len(block)
            if size > expected_bytes or time.monotonic() - started > 300:
                raise ValueError("Public input exceeded its size or time bound")
            hasher.update(block)
            output.write(block)
    if size != expected_bytes or hasher.hexdigest() != expected_sha256:
        raise ValueError("Public input bytes changed")
    return {"url": url, "final_host": final.hostname, "bytes": size,
            "sha256": hasher.hexdigest()}


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.geteuid() == 0):
        raise SystemExit("Use the unprivileged disposable hosted Tolaria intake unit")
    root = Path.cwd().resolve()
    group = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    expected_limits = {"memory.max": "536870912", "memory.swap.max": "0",
                       "cpu.max": "100000 100000", "pids.max": "32"}
    if not group.name.startswith("symbi-tolaria-intake-") or limits != expected_limits:
        raise ValueError("Unexpected Tolaria intake resource group")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    if (any(status[name].strip() != "0000000000000000"
            for name in ("CapEff", "CapPrm", "CapBnd")) or status["NoNewPrivs"].strip() != "1"):
        raise ValueError("Tolaria input inspector must have no capabilities and no new privileges")
    evidence = root / ".cache/tolaria-intake-evidence"
    private = root / ".cache/tolaria-intake-private"
    evidence.mkdir()
    private.mkdir(mode=0o700)
    record = {
        "schema": 1, "passed": False, "selected": False, "security_qualified": False,
        "os_qualified": False, "candidate_executed": False, "archive_extracted": False,
        "source_commit": os.environ["GITHUB_SHA"], "limits": limits, "downloads": [],
        "scope": "Hash and passive archive inventory plus downstream patch binding; no extraction, execution, compilation, installation or release claim",
    }

    def save():
        (evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n")

    try:
        pins = load_pins(root / "image/tolaria/source.json")
        record["pins_sha256"] = digest(root / "image/tolaria/source.json")
        record["patch"] = require_patch(pins, root)
        source = private / "source.tar.gz"
        pnpm = private / "pnpm.tgz"
        record["downloads"].append(download(
            pins["source"]["url"], source, pins["source"]["bytes"],
            pins["source"]["sha256"], {"github.com", "codeload.github.com"}))
        save()
        record["downloads"].append(download(
            pins["pnpm"]["url"], pnpm, pins["pnpm"]["bytes"],
            pins["pnpm"]["sha256"], {"registry.npmjs.org"}))
        save()
        record["source_inventory"] = inspect_source(source, pins)
        record["pnpm_inventory"] = inspect_pnpm(pnpm, pins)
        record["passed"] = True
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        shutil.rmtree(private)
        record["private_downloads_removed"] = not private.exists()
        record["cgroup_final"] = {name: (group / name).read_text().strip()
                                  for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        if not record["private_downloads_removed"]:
            record["passed"] = False
        save()


if __name__ == "__main__":
    main()
