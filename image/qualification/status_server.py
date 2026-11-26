#!/usr/bin/env python3
"""Serve two fixed, bounded bootc status observations inside the test VM."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess

SOCKET_PATH = Path("/run/symbi-qualification/status.sock")
MAX_STATUS_BYTES = 128 * 1024
MAX_ERROR_BYTES = 32 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate bootc status key")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(result, dict), "bootc status must be a JSON object")
    require(result.get("apiVersion") == "org.containers.bootc/v1"
            and result.get("kind") == "BootcHost", "unexpected bootc status schema")
    return result


def collect_status():
    result = subprocess.run(["/usr/bin/bootc", "status", "--json"],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=90,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    require(len(result.stdout) <= MAX_STATUS_BYTES and len(result.stderr) <= MAX_ERROR_BYTES,
            "bootc status output exceeded its bound")
    require(result.returncode == 0, "fixed bootc status command failed")
    unique_json(result.stdout)
    return result.stdout


def serve(path, collector, expected_requests=2, required_peer_uid=None):
    """Accept output-only clients; no request bytes can select a root command."""
    path = Path(path)
    require(type(expected_requests) is int and 1 <= expected_requests <= 2,
            "invalid status request count")
    require(path.is_absolute() and path.parent.is_dir() and not path.exists() and not path.is_symlink(),
            "status socket path must be new under an existing directory")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    identity = None
    try:
        server.bind(str(path))
        bound = path.lstat()
        identity = (bound.st_dev, bound.st_ino)
        os.chmod(path, 0o666)
        server.listen(1)
        server.settimeout(5400)
        for _ in range(expected_requests):
            connection, _ = server.accept()
            with connection:
                pid, uid, gid = struct.unpack("3i", connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                require(pid > 0 and gid >= 0, "invalid status client credentials")
                if required_peer_uid is None:
                    require(uid != 0, "root may not be the qualification client")
                else:
                    require(uid == required_peer_uid, "unexpected status client identity")
                connection.settimeout(5)
                require(connection.recv(1) == b"", "status socket accepts no request data")
                raw = collector()
                require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_STATUS_BYTES,
                        "invalid bounded status response")
                unique_json(raw)
                connection.sendall(raw)
    finally:
        server.close()
        try:
            current = path.lstat()
        except FileNotFoundError:
            current = None
        if (identity is not None and current is not None
                and (current.st_dev, current.st_ino) == identity):
            path.unlink()


def main():
    if (os.geteuid() != 0 or Path("/run/.containerenv").exists()
            or Path("/sys/class/dmi/id/product_name").read_text().strip()
            != "Symbi-Hosted-Landlock-Probe"):
        raise SystemExit("Use only the disposable hosted Landlock guest service")
    parent = SOCKET_PATH.parent
    info = parent.stat()
    require(info.st_uid == 0 and info.st_gid == 0 and info.st_mode & 0o777 == 0o755,
            "unsafe status runtime directory")
    serve(SOCKET_PATH, collect_status)


if __name__ == "__main__":
    main()
