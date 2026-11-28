"""Produce one authenticated media-only binary closure and its exact source RPMs."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
from http.client import HTTPSConnection
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, ProxyHandler

try:
    from image.desktop_packages.contract import FEDORA, FUSION, require_keyring, verified_signer
    from image.desktop_packages.media_contract import (
        MAX_MEDIA_EXPANDED_BYTES, MAX_MEDIA_MANIFEST_BYTES, MAX_MEDIA_RPM_BYTES,
        MAX_MEDIA_RPM_PAYLOAD_BYTES)
    from image.desktop_packages.media_closure_contract import (
        require_candidate_manifest, require_candidate_request, require_media_repositories)
    from image.launcher.probes.bounded_process import run_bounded
except ModuleNotFoundError:  # Copied standalone into the disposable producer container.
    from contract import FEDORA, FUSION, require_keyring, verified_signer
    from media_contract import (
        MAX_MEDIA_EXPANDED_BYTES, MAX_MEDIA_MANIFEST_BYTES, MAX_MEDIA_RPM_BYTES,
        MAX_MEDIA_RPM_PAYLOAD_BYTES)
    from media_closure_contract import (
        require_candidate_manifest, require_candidate_request, require_media_repositories)
    from bounded_process import run_bounded


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def binary_identity(row):
    return "\t".join(row[name] for name in (
        "name", "epoch", "version", "release", "arch", "nevra", "vendor", "license",
        "source_rpm"))


def _is_public_address(address):
    return (address.is_global and not address.is_private and not address.is_loopback
            and not address.is_link_local and not address.is_multicast
            and not address.is_reserved and not address.is_unspecified)


class PublicAddressResolver:
    """Resolve once, reject every non-global answer, then connect to those answers."""

    def __init__(self, getaddrinfo=socket.getaddrinfo, socket_factory=socket.socket):
        self._getaddrinfo = getaddrinfo
        self._socket_factory = socket_factory
        self._answers = {}

    def resolve(self, hostname, port):
        key = (hostname.lower(), port)
        if key in self._answers:
            return self._answers[key]
        try:
            answers = self._getaddrinfo(
                hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        except OSError as error:
            raise ValueError("Source RPM hostname could not be resolved") from error
        if not isinstance(answers, (list, tuple)) or not 1 <= len(answers) <= 32:
            raise ValueError("Source RPM hostname has no bounded public resolution")
        checked = []
        for answer in answers:
            if not isinstance(answer, tuple) or len(answer) != 5:
                raise ValueError("Source RPM hostname returned a malformed address")
            family, kind, protocol, canonical, sockaddr = answer
            sockaddr_length = 2 if family == socket.AF_INET else 4
            if (family not in (socket.AF_INET, socket.AF_INET6)
                    or kind != socket.SOCK_STREAM
                    or protocol not in (0, socket.IPPROTO_TCP)
                    or not isinstance(canonical, str)
                    or not isinstance(sockaddr, tuple) or len(sockaddr) != sockaddr_length
                    or not isinstance(sockaddr[0], str) or "%" in sockaddr[0]
                    or sockaddr[1] != port
                    or (family == socket.AF_INET6 and sockaddr[2:] != (0, 0))):
                raise ValueError("Source RPM hostname returned an unsupported address")
            try:
                address = ipaddress.ip_address(sockaddr[0])
            except ValueError as error:
                raise ValueError("Source RPM hostname returned a malformed address") from error
            if ((family == socket.AF_INET) != (address.version == 4)
                    or not _is_public_address(address)):
                raise ValueError("Source RPM hostname resolves to a non-public address")
            checked.append((family, kind, protocol, canonical, sockaddr))
        self._answers[key] = tuple(checked)
        return self._answers[key]

    def create_connection(self, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                          source_address=None):
        hostname, port = address
        last_error = None
        for family, kind, protocol, _canonical, sockaddr in self.resolve(hostname, port):
            stream = self._socket_factory(family, kind, protocol)
            try:
                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    stream.settimeout(timeout)
                if source_address:
                    stream.bind(source_address)
                stream.connect(sockaddr)
                return stream
            except OSError as error:
                last_error = error
                stream.close()
        if last_error is not None:
            raise last_error
        raise ValueError("Source RPM hostname has no usable public address")


def require_public_https(url, resolver=None):
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Source RPM location has an invalid port") from error
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or len(url) > 4096 or port not in (None, 443)
            or not re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname)
            or parsed.hostname.lower() == "localhost"
            or parsed.hostname.lower().endswith((".localhost", ".local"))):
        raise ValueError("Source RPM location is not a bounded public HTTPS URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address is not None and not _is_public_address(address):
        raise ValueError("Source RPM location uses a non-public address")
    if resolver is not None:
        resolver.resolve(parsed.hostname, port or 443)
    return parsed


class PublicHttpsRedirects(HTTPRedirectHandler):
    def __init__(self, resolver):
        super().__init__()
        self.resolver = resolver

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        require_public_https(new_url, self.resolver)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


class PinnedPublicHTTPSHandler(HTTPSHandler):
    def __init__(self, resolver):
        super().__init__()
        self.resolver = resolver

    def https_open(self, request):
        resolver = self.resolver

        def connection(host, **kwargs):
            client = HTTPSConnection(host, **kwargs)
            client._create_connection = resolver.create_connection
            return client

        return self.do_open(connection, request, context=self._context)


def download_source(url, target, resolver=None):
    resolver = resolver or PublicAddressResolver()
    require_public_https(url, resolver)
    if target.exists() or target.is_symlink():
        raise ValueError("Source RPM destination already exists")
    try:
        opener = build_opener(ProxyHandler({}), PublicHttpsRedirects(resolver),
                              PinnedPublicHTTPSHandler(resolver))
        with opener.open(url, timeout=60) as response, \
                target.open("xb") as stream:
            final = response.geturl()
            require_public_https(final, resolver)
            length = response.headers.get("Content-Length")
            if (length is not None
                    and (not length.isdigit() or not 0 < int(length) <= MAX_MEDIA_RPM_BYTES)):
                raise ValueError("Source RPM response size is invalid")
            total = 0
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_MEDIA_RPM_BYTES:
                    raise ValueError("Source RPM exceeds its byte bound")
                stream.write(block)
            if total == 0:
                raise ValueError("Source RPM response is empty")
        return final
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def main():
    if not Path("/run/.containerenv").exists() or os.geteuid() != 0:
        raise SystemExit("Use the disposable hosted media closure container")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "fedora" or release.get("VERSION_ID") != "45" \
            or platform.machine() != "x86_64":
        raise ValueError("Unexpected media closure distribution or architecture")
    group = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    if limits != {"memory.max": "2147483648", "memory.swap.max": "0",
                  "cpu.max": "100000 100000", "pids.max": "128"}:
        raise ValueError("Unexpected media closure resource limits")
    inputs, output = Path("/inputs"), Path("/output")
    request = json.loads((inputs / "request.json").read_text())
    require_candidate_request(request)
    require_media_repositories((inputs / "repos/media.repo").read_text())
    evidence = output / "evidence"
    rpms, srpms = output / "rpms", output / "srpms"
    evidence.mkdir(); rpms.mkdir(); srpms.mkdir()
    record = {
        "schema": 1,
        "passed": False,
        "packages_selected": False,
        "security_qualified": False,
        "os_qualified": False,
        "package_transaction_attempted": False,
        "request": request,
        "limits": limits,
        "commands": [],
        "scope": (
            "Authenticated media-only candidates and source RPMs; no package transaction, "
            "program execution, security clearance or OS selection"),
    }

    def save():
        (evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n")

    def run(name, command, timeout=60, check=True):
        record["active_command"] = {"name": name, "command": command}; save()
        result = run_bounded(command, evidence / (name + "-stdout.log"),
                             evidence / (name + "-stderr.log"), timeout, 1024 * 1024)
        record["commands"].append({"name": name, "exit_code": result.returncode})
        del record["active_command"]; save()
        if check:
            result.check_returncode()
        return result

    def package_row(path, index, prefix="binary"):
        checked = run(f"{prefix}-{index:03}-signature",
                      rpmkeys() + ["--checksig", "--verbose", str(path)], check=False)
        signer = verified_signer(checked.returncode, checked.stdout, [FEDORA, FUSION])
        if prefix == "binary":
            query = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{NEVRA}\t%{VENDOR}\t%{LICENSE}\t%{SOURCERPM}\n"
            names = ("name", "epoch", "version", "release", "arch", "nevra", "vendor",
                     "license", "source_rpm")
        else:
            query = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{NEVRA}\n"
            names = ("name", "epoch", "version", "release", "arch", "nevra")
        identity = run(f"{prefix}-{index:03}-identity",
                       ["rpm", "-qp", "--qf", query, str(path)]).stdout.strip().split("\t")
        if len(identity) != len(names):
            raise ValueError("Unexpected media RPM identity")
        row = dict(zip(names, identity))
        row.update(filename=path.name, bytes=path.stat().st_size, sha256=digest(path),
                   signature_verified=True, key_fingerprint=signer)
        return row

    try:
        for name in ("keyring", "empty-keyring", "fedora-keyring", "fusion-keyring", "rpmdb", "gnupg"):
            (output / name).mkdir(mode=0o700)

        def rpmkeys(ring="keyring"):
            return ["rpmkeys", "--define", "_keyring fs",
                    "--define", "_keyringpath /output/" + ring,
                    "--dbpath", "/output/rpmdb", "--define", "_pkgverify_level all"]

        for index, key in enumerate(request["trusted_keys"]):
            path = inputs / key["file"]
            if (path.is_symlink() or not path.is_file() or path.stat().st_size > 65536
                    or digest(path) != key["sha256"]):
                raise ValueError("Media public key bytes changed")
            shown = run("public-key-" + str(index), [
                "gpg", "--homedir", "/output/gnupg", "--batch", "--no-options",
                "--with-colons", "--show-keys", str(path)])
            fingerprints = [line.split(":")[9] for line in shown.stdout.splitlines()
                            if line.startswith("fpr:")]
            if fingerprints != [key["fingerprint"]]:
                raise ValueError("Media public key identity changed")
            for ring in ("keyring", "fedora-keyring" if index == 0 else "fusion-keyring"):
                run("import-" + ring + "-" + str(index),
                    rpmkeys(ring) + ["--import", str(path)])
        for ring, keys in (("keyring", [FEDORA, FUSION]), ("fedora-keyring", [FEDORA]),
                           ("fusion-keyring", [FUSION])):
            require_keyring(run("list-" + ring, rpmkeys(ring) + ["--list"]).stdout, keys)

        query = ["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"]
        before = sorted(run("installed-before", query).stdout.splitlines())
        installed = set()
        for entry in before:
            fields = entry.split("\t")
            if len(fields) != 5:
                raise ValueError("Installed package inventory is malformed")
            installed.add((fields[0], fields[4]))
        dnf = ["dnf5", "--config=/inputs/dnf.conf", "--releasever=45", "--assumeyes",
               "--disable-plugin=*"]
        run("resolve-media-closure", dnf + ["install", "--downloadonly", "--",
                                             *request["requirements"]], 1200)
        binary_paths = sorted(rpms.glob("*.rpm"))
        binary_bytes = sum(path.stat().st_size for path in binary_paths)
        if (not binary_paths or len(binary_paths) > 128
                or binary_bytes > MAX_MEDIA_RPM_PAYLOAD_BYTES):
            raise ValueError("Unexpected empty or excessive media closure")
        packages = []
        probes = {}
        for index, path in enumerate(binary_paths):
            if path.is_symlink() or not path.is_file() or path.resolve() != path:
                raise ValueError("Unsafe media RPM path")
            row = package_row(path, index)
            if row["arch"] not in ("x86_64", "noarch") or (row["name"], row["arch"]) in installed:
                raise ValueError("Media closure is not additive to the selected base")
            packages.append(row); probes.setdefault(row["key_fingerprint"], path); save()
        if set(probes) != {FEDORA, FUSION}:
            raise ValueError("Expected separately signed Fedora and RPM Fusion media packages")

        root_by_name = {row["name"]: row for row in request["root_packages"]}
        record["source_locations"] = []
        for index, name in enumerate(("mplayer", "mpv")):
            filename = root_by_name[name]["source_rpm"]
            spec = filename.removesuffix(".rpm")
            located = run(f"locate-source-{index}", dnf + [
                "repoquery", "--arch=src", "--latest-limit=1", "--location", "--", spec],
                1200).stdout.splitlines()
            locations = sorted({row.strip() for row in located if row.strip()})
            if len(locations) != 1:
                raise ValueError("Expected one exact source RPM location")
            final = download_source(locations[0], srpms / filename)
            record["source_locations"].append({"source_rpm": filename, "url": final}); save()
        source_paths = sorted(srpms.glob("*.src.rpm"))
        if ({path.name for path in source_paths}
                != {row["source_rpm"] for row in request["root_packages"]}):
            raise ValueError("Downloaded source RPMs differ from the frozen binary headers")
        source_bytes = sum(path.stat().st_size for path in source_paths)
        if (any(path.is_symlink() or not path.is_file() or path.resolve() != path
                or not 0 < path.stat().st_size <= MAX_MEDIA_RPM_BYTES for path in source_paths)
                or binary_bytes + source_bytes > MAX_MEDIA_RPM_PAYLOAD_BYTES):
            raise ValueError("Unsafe or excessive source RPM payload")
        sources = [package_row(path, index, "source") for index, path in enumerate(source_paths)]

        controls = {}
        for index, (signer, probe) in enumerate(sorted(probes.items())):
            for control, ring in (("missing-key", "empty-keyring"),
                                  ("wrong-key", "fusion-keyring" if signer == FEDORA else "fedora-keyring")):
                result = run(f"{control}-{index}",
                             rpmkeys(ring) + ["--checksig", "--verbose", str(probe)], check=False)
                if result.returncode == 0:
                    raise ValueError(control + " accepted an untrusted media package")
            changed = output / f"tampered-{index}.rpm"
            shutil.copyfile(probe, changed)
            with changed.open("r+b") as stream:
                stream.seek(changed.stat().st_size // 2)
                byte = stream.read(1); stream.seek(-1, 1); stream.write(bytes([byte[0] ^ 1]))
            invalid = run("tampered-" + str(index),
                          rpmkeys() + ["--checksig", "--verbose", str(changed)], check=False)
            if invalid.returncode == 0:
                raise ValueError("Changed media RPM bytes were accepted")
            changed.unlink()
            controls[signer] = {"missing_key_rejected": True, "wrong_key_rejected": True,
                                "tampered_package_rejected": True}

        after = sorted(run("installed-after", query).stdout.splitlines())
        if before != after:
            raise ValueError("Media closure production changed installed packages")
        manifest = {
            "schema": 1,
            "passed": True,
            "dedicated_media_closure": True,
            "package_transaction_attempted": False,
            "installed_packages_unchanged": True,
            "requirements": request["requirements"],
            "packages": packages,
            "source_packages": sources,
            "negative_controls": controls,
            "packages_selected": False,
            "security_qualified": False,
            "os_qualified": False,
            "scope": record["scope"],
        }
        require_candidate_manifest(manifest, request)
        manifest_path = output / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        if (manifest_path.stat().st_size > MAX_MEDIA_MANIFEST_BYTES
                or binary_bytes + source_bytes + manifest_path.stat().st_size
                > MAX_MEDIA_EXPANDED_BYTES):
            raise ValueError("Media closure output exceeds its retained artifact contract")
        record.update(passed=True, installed_packages_unchanged=True,
                      packages=len(packages), source_packages=len(sources),
                      manifest_sha256=digest(manifest_path))
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        final = {name: (group / name).read_text().strip()
                 for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        record["cgroup_final"] = final
        events = dict(line.split() for line in final["memory.events"].splitlines())
        if (any(final[name] != value for name, value in limits.items())
                or any(events.get(name) != "0" for name in ("oom", "oom_kill", "oom_group_kill"))):
            record["passed"] = False
        save()
    if not record["passed"]:
        raise RuntimeError("Media closure, resource or inventory checks failed")


if __name__ == "__main__":
    main()
