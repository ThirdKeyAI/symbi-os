#!/usr/bin/env python3
"""Validate fixed gVisor release inputs without executing candidate bytes."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile


ROOT = Path(__file__).resolve().parents[2]
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")
MAX_ARCHIVE_BYTES = 128 * 1024**2
MAX_EXPANDED_BYTES = 256 * 1024**2
MAX_MEMBER_BYTES = 64 * 1024**2
MAX_MEMBERS = 32


def unique_json(raw):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key: " + key)
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=object_pairs)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ValueError("Malformed JSON input") from error


def digest(path, algorithm="sha256"):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, algorithm).hexdigest()


def require_relative(name):
    if (not isinstance(name, str) or not name or len(name.encode()) > 2048
            or "\\" in name or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        raise ValueError("Invalid archive path")
    path = PurePosixPath(name)
    if (path.is_absolute() or path.as_posix() != name
            or any(part in ("", ".", "..") for part in path.parts)):
        raise ValueError("Unsafe archive path: " + repr(name))
    return path


def _validate_member_pins(members):
    if not isinstance(members, dict) or not 0 < len(members) <= MAX_MEMBERS:
        raise ValueError("Invalid gVisor member inventory")
    for name, row in members.items():
        require_relative(name)
        common = {"kind", "mode", "uid", "gid", "mtime"}
        if not isinstance(row, dict) or row.get("kind") not in ("directory", "regular"):
            raise ValueError("Invalid gVisor member pin: " + name)
        expected_keys = common if row["kind"] == "directory" else common | {"bytes", "sha256"}
        if (set(row) != expected_keys or row["mode"] & 0o7000
                or row["mode"] < 0 or row["mode"] > 0o777
                or row["uid"] != 0 or row["gid"] != 0
                or not isinstance(row["mtime"], int)):
            raise ValueError("Unsafe gVisor member pin: " + name)
        if row["kind"] == "regular" and (
                not isinstance(row["bytes"], int) or not 0 <= row["bytes"] <= MAX_MEMBER_BYTES
                or not HEX64.fullmatch(row["sha256"])):
            raise ValueError("Invalid gVisor regular-file pin: " + name)


def load_pins(path=ROOT / "image/container/gvisor-inputs.json"):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 128 * 1024:
        raise ValueError("Invalid gVisor pin document")
    pins = unique_json(path.read_bytes())
    top = {
        "schema", "status", "repository", "license_spdx", "release", "archive",
        "checksums", "license", "selected", "security_qualified", "os_qualified",
    }
    if (set(pins) != top or pins["schema"] != 1
            or pins["status"] != "candidate-awaiting-fedora-build-and-os-qualification"
            or pins["repository"] != "https://github.com/google/gvisor"
            or pins["license_spdx"] != "Apache-2.0"
            or any(pins[name] is not False
                   for name in ("selected", "security_qualified", "os_qualified"))):
        raise ValueError("Unexpected gVisor pin schema or qualification state")
    release = pins["release"]
    if (set(release) != {"tag", "published_at", "tag_object", "commit", "tree",
                         "tag_signed", "commit_signed", "github_attestation_found"}
            or release["tag"] != "release-20261123.1"
            or release["published_at"] != "2026-11-26T06:25:54Z"
            or release["tag_object"] != "c04644c3a80cda69a57070e14f2e9f71445f36e4"
            or release["commit"] != "81f68cb7d4661a9313d891a1758a765abe8eb27e"
            or release["tree"] != "bc0b025cd7b81939d68e45e9aeb918cfb2875e5c"
            or any(release[name] is not False
                   for name in ("tag_signed", "commit_signed", "github_attestation_found"))):
        raise ValueError("Unexpected gVisor release identity or authentication claim")
    archive = pins["archive"]
    if (set(archive) != {"asset_id", "url", "bytes", "sha256", "sha512", "members"}
            or archive["asset_id"] != 794599557
            or archive["url"] != ("https://github.com/gvisor/gvisor/releases/download/"
                                  "release-20261123.1/gvisor-x86_64.tar.bz2")
            or archive["bytes"] != 84944091
            or archive["sha256"] != "95c23cd8eda66eab351717e5ee2b1a5703f848bb73ac855a7b281e1c6cd178e8"
            or archive["sha512"] != ("b8bcf8ebda5a0e3aa43026f26128759c3f74abc94d3f53839963fad01d152b8e"
                                         "c1c2c01cc0c84e8820aa5fb04fbc50df60332911f58884113a7984287737313a")):
        raise ValueError("Unexpected gVisor release archive pin")
    _validate_member_pins(archive["members"])
    if set(archive["members"]) != {
        "gvisor-bin", "runsc", "containerd-shim-runsc-v1", "gvisor-bin/checkpointgofer",
        "gvisor-bin/runsc-metric-server", "gvisor-bin/runsc-netgofer",
        "gvisor-bin/runsc-fd-parking", "gvisor-bin/gvisor-sentry-prewarmer",
        "gvisor-bin/gvisor-proc-umounter", "gvisor-bin/gvisor_sentry",
    }:
        raise ValueError("Unexpected gVisor archive member set")
    checksums = pins["checksums"]
    if (set(checksums) != {"asset_id", "url", "bytes", "sha256", "entries"}
            or checksums["asset_id"] != 794599562
            or checksums["url"] != ("https://github.com/gvisor/gvisor/releases/download/"
                                    "release-20261123.1/SHA512SUMS")
            or checksums["bytes"] != 612
            or checksums["sha256"] != "9c6b64e206d5a3944e0abab4d742da14b1fa5cb4ccb4f069c561922f7bf0d7fa"
            or set(checksums["entries"]) != {
                "gvisor-aarch64.tar.bz2", "gvisor-aarch64.tar.zstd",
                "gvisor-x86_64.tar.bz2", "gvisor-x86_64.tar.zstd",
            }
            or any(not HEX128.fullmatch(value) for value in checksums["entries"].values())
            or checksums["entries"]["gvisor-x86_64.tar.bz2"] != archive["sha512"]):
        raise ValueError("Unexpected gVisor checksum-list pin")
    license_pin = pins["license"]
    if (license_pin != {
            "url": ("https://raw.githubusercontent.com/google/gvisor/"
                    "81f68cb7d4661a9313d891a1758a765abe8eb27e/LICENSE"),
            "bytes": 14110,
            "sha256": "0fbab5c58efbdf6d31e8085214f2dd821659c03d73cff3ed2b08e98826ea1cd9",
    }):
        raise ValueError("Unexpected gVisor license pin")
    return pins


def _open_exact_archive(path, archive_pin):
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError("gVisor archive must be a direct regular file") from error
    stream = os.fdopen(descriptor, "rb")
    try:
        mode = os.fstat(stream.fileno())
        if not stat.S_ISREG(mode.st_mode) or not 0 < mode.st_size <= MAX_ARCHIVE_BYTES:
            raise ValueError("gVisor archive is not a bounded regular file")
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        size = 0
        while block := stream.read(1024**2):
            size += len(block)
            sha256.update(block)
            sha512.update(block)
        if (size != archive_pin["bytes"] or sha256.hexdigest() != archive_pin["sha256"]
                or sha512.hexdigest() != archive_pin["sha512"]):
            raise ValueError("gVisor archive bytes changed")
        stream.seek(0)
        return stream
    except Exception:
        stream.close()
        raise


def _read_regular(archive, item, output=None):
    if item.size < 0 or item.size > MAX_MEMBER_BYTES:
        raise ValueError("gVisor member exceeds its size bound")
    source = archive.extractfile(item)
    if source is None:
        raise ValueError("gVisor regular member has no readable bytes")
    size = 0
    hasher = hashlib.sha256()
    with source:
        while block := source.read(65536):
            size += len(block)
            if size > item.size:
                raise ValueError("gVisor member exceeded its declared size")
            hasher.update(block)
            if output is not None:
                output.write(block)
    if size != item.size:
        raise ValueError("Truncated gVisor archive member")
    return size, hasher.hexdigest()


def inspect_archive(path, pins=None):
    pins = pins or load_pins()
    expected = pins["archive"]["members"]
    _validate_member_pins(expected)
    observed = {}
    expanded = 0
    stream = _open_exact_archive(path, pins["archive"])
    try:
        with tarfile.open(fileobj=stream, mode="r|*") as archive:
            for item in archive:
                name = item.name
                require_relative(name)
                if name in observed:
                    raise ValueError("Duplicate gVisor archive member: " + name)
                if len(observed) >= MAX_MEMBERS or name not in expected:
                    raise ValueError("Unexpected gVisor archive member: " + name)
                if (item.mode & 0o7000 or item.issparse() or item.mtime is None
                        or item.mtime != int(item.mtime)):
                    raise ValueError("Unsafe gVisor archive mode, time or sparse member")
                common = {
                    "mode": item.mode, "uid": item.uid, "gid": item.gid,
                    "mtime": int(item.mtime),
                }
                if item.isdir():
                    if item.size != 0:
                        raise ValueError("gVisor directory has a nonzero body")
                    row = {"kind": "directory", **common}
                elif item.isfile():
                    size, sha256 = _read_regular(archive, item)
                    expanded += size
                    if expanded > MAX_EXPANDED_BYTES:
                        raise ValueError("gVisor archive expanded-byte limit exceeded")
                    row = {"kind": "regular", "bytes": size, **common, "sha256": sha256}
                else:
                    raise ValueError("gVisor archive contains a link or special member")
                if row != expected[name]:
                    raise ValueError("gVisor archive member changed: " + name)
                observed[name] = row
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ValueError("Unreadable gVisor release archive") from error
    finally:
        stream.close()
    if set(observed) != set(expected):
        raise ValueError("gVisor archive is missing a pinned member")
    return observed


def inspect_checksums(path, pins=None):
    pins = pins or load_pins()
    pin = pins["checksums"]
    path = Path(path)
    if (path.is_symlink() or not path.is_file() or path.stat().st_size != pin["bytes"]
            or digest(path) != pin["sha256"]):
        raise ValueError("gVisor checksum-list bytes changed")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeError as error:
        raise ValueError("gVisor checksum list is not UTF-8") from error
    observed = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{128})  ([A-Za-z0-9_.-]+)", line)
        if match is None or match.group(2) in observed:
            raise ValueError("Malformed or duplicate gVisor checksum-list entry")
        observed[match.group(2)] = match.group(1)
    if observed != pin["entries"]:
        raise ValueError("gVisor checksum-list entries changed")
    return observed


def extract_archive(path, pins, destination):
    """Extract only a fully validated archive; never execute its contents."""
    observed = inspect_archive(path, pins)
    destination = Path(destination)
    parent = destination.parent
    if destination.exists() or destination.is_symlink():
        raise ValueError("gVisor extraction destination must not exist")
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("gVisor extraction parent must be a direct directory")
    destination.mkdir(mode=0o700)
    regular_paths = []
    try:
        for name, row in sorted(observed.items(), key=lambda pair: len(PurePosixPath(pair[0]).parts)):
            if row["kind"] == "directory":
                (destination / name).mkdir(mode=0o700)
        stream = _open_exact_archive(path, pins["archive"])
        try:
            with tarfile.open(fileobj=stream, mode="r|*") as archive:
                for item in archive:
                    if not item.isfile():
                        continue
                    row = observed[item.name]
                    target = destination / item.name
                    descriptor = os.open(
                        target,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                    )
                    with os.fdopen(descriptor, "wb") as output:
                        size, sha256 = _read_regular(archive, item, output)
                    if size != row["bytes"] or sha256 != row["sha256"]:
                        raise ValueError("Extracted gVisor member changed: " + item.name)
                    regular_paths.append((target, row["mode"]))
        finally:
            stream.close()
        for target, mode in regular_paths:
            target.chmod(mode)
        for name, row in observed.items():
            if row["kind"] == "directory":
                (destination / name).chmod(row["mode"])
        return observed
    except Exception:
        shutil.rmtree(destination)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    args = parser.parse_args()
    pins = load_pins()
    result = {
        "archive": inspect_archive(args.archive, pins),
        "checksums": inspect_checksums(args.checksums, pins),
        "selected": pins["selected"],
        "security_qualified": pins["security_qualified"],
        "os_qualified": pins["os_qualified"],
        "candidate_executed": False,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
