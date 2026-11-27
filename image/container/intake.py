#!/usr/bin/env python3
"""Passively authenticate fixed gVisor release inputs on hosted CI."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import urllib.parse
import urllib.request

from .runtime_inputs import digest, inspect_archive, inspect_checksums, load_pins


def download(url, target, expected_bytes, expected_sha256, allowed_hosts):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "SymbiOS-P0-gVisor-intake/1", "Accept-Encoding": "identity"},
    )
    started = time.monotonic()
    size = 0
    hasher = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=30) as response, target.open("xb") as output:
        final = urllib.parse.urlsplit(response.url)
        if (response.status != 200 or final.scheme != "https" or final.hostname not in allowed_hosts
                or final.username is not None or final.password is not None
                or final.port not in (None, 443) or final.fragment):
            raise ValueError("Unexpected public input response")
        while block := response.read(65536):
            size += len(block)
            if size > expected_bytes or time.monotonic() - started > 600:
                raise ValueError("Public input exceeded its size or time bound")
            hasher.update(block)
            output.write(block)
    if size != expected_bytes or hasher.hexdigest() != expected_sha256:
        raise ValueError("Public input bytes changed")
    return {
        "url": url, "final_host": final.hostname, "bytes": size,
        "sha256": hasher.hexdigest(),
    }


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.geteuid() == 0):
        raise SystemExit("Use the unprivileged disposable hosted gVisor intake unit")
    root = Path.cwd().resolve()
    group = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    expected_limits = {
        "memory.max": "536870912", "memory.swap.max": "0",
        "cpu.max": "100000 100000", "pids.max": "32",
    }
    if not group.name.startswith("symbi-gvisor-intake-") or limits != expected_limits:
        raise ValueError("Unexpected gVisor intake resource group")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    if (any(status[name].strip() != "0000000000000000"
            for name in ("CapEff", "CapPrm", "CapBnd")) or status["NoNewPrivs"].strip() != "1"):
        raise ValueError("gVisor input inspector must have no capabilities and no new privileges")
    evidence = root / ".cache/gvisor-intake-evidence"
    private = root / ".cache/gvisor-intake-private"
    evidence.mkdir()
    private.mkdir(mode=0o700)
    record = {
        "schema": 1, "passed": False, "selected": False, "security_qualified": False,
        "os_qualified": False, "candidate_executed": False, "archive_extracted": False,
        "source_commit": os.environ["GITHUB_SHA"], "limits": limits, "downloads": [],
        "scope": ("Hash, checksum-list and passive archive inventory only; no extraction, "
                  "execution, compilation, installation or release claim"),
    }

    def save():
        (evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n")

    try:
        pins_path = root / "image/container/gvisor-inputs.json"
        pins = load_pins(pins_path)
        record["pins_sha256"] = digest(pins_path)
        allowed_hosts = {
            "github.com", "release-assets.githubusercontent.com",
            "objects.githubusercontent.com", "raw.githubusercontent.com",
        }
        archive = private / "gvisor-x86_64.tar.bz2"
        checksums = private / "SHA512SUMS"
        license_path = private / "LICENSE"
        for name, pin, target in (
            ("archive", pins["archive"], archive),
            ("checksums", pins["checksums"], checksums),
            ("license", pins["license"], license_path),
        ):
            result = download(
                pin["url"], target, pin["bytes"], pin["sha256"], allowed_hosts)
            result["name"] = name
            record["downloads"].append(result)
            save()
        record["checksums"] = inspect_checksums(checksums, pins)
        record["archive_members"] = inspect_archive(archive, pins)
        if (license_path.stat().st_size != pins["license"]["bytes"]
                or digest(license_path) != pins["license"]["sha256"]):
            raise ValueError("gVisor license bytes changed")
        record["license"] = {
            "spdx": pins["license_spdx"], "bytes": license_path.stat().st_size,
            "sha256": digest(license_path),
        }
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
