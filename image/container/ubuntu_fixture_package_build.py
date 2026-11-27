"""Build and validate an unselected Ubuntu fixture package candidate.

The functions in this module are producer-side only.  They authenticate signed
Release text, bind one Packages.xz per reviewed suite, bind apt's file-only URI
and simulation plans to exact package rows, and stream exact package payloads.
The resulting manifest is always an unselected candidate with every
qualification claim false.  No consumer imports this module and no workflow
currently invokes it, builds an image, or uploads an artifact.
"""
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import tarfile
import time
from urllib.parse import quote, unquote, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request

from image.container import ubuntu_fixture_packages as packages


MAX_CLOCK_SKEW = timedelta(minutes=15)
MAX_VALIDITY_WINDOW = timedelta(days=14)
MAX_RELEASE_BYTES = packages.MAX_METADATA_BYTES
MAX_RELEASE_LINE_BYTES = 64 * 1024
MAX_INDEX_TEXT_BYTES = 512 * 1024**2
MAX_STANZA_BYTES = 1024**2
MAX_PLAN_BYTES = 4 * 1024**2
MAX_STATUS_BYTES = 16 * 1024**2
DOWNLOAD_CHUNK_BYTES = 64 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 30
MAX_DOWNLOAD_SECONDS = 600
EXPECTED_CODENAMES = {
    "noble": "noble",
    "noble-updates": "noble",
    "noble-security": "noble",
}
BAD_GPG_STATUS = {
    "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY",
    "KEYEXPIRED", "SIGEXPIRED",
}
CANDIDATE_SCOPE = (
    "Authenticated Ubuntu fixture package candidate; separately reviewed "
    "selection, offline image build, cold load and qualification remain blocked"
)
CANDIDATE_CLAIMS = (
    "selected", "qualified", "container_qualified", "signature_qualified",
    "os_qualified", "release_qualified",
)
CANDIDATE_RELEASE_FIELDS = packages.RELEASE_FIELDS | {"signed", "verification"}
SIGNED_RELEASE_FIELDS = {
    "origin", "label", "suite", "codename", "date", "valid_until",
    "architectures", "components", "verified_at",
}
SIGNATURE_RECORD_FIELDS = {"signing_fingerprint", "status_sha256"}
TOOL_FIELDS = {"version", "sha256"}
TOOL_NAMES = {"apt_get", "dpkg", "gpgv"}
COMMAND_NAMES = {
    "apt_update", "apt_uri_plan", "apt_simulation", "dpkg_plan",
}
VERIFICATION_FIELDS = {
    "release_signatures", "release_freshness", "index_hashes",
    "index_membership", "offline_apt_plan", "offline_dpkg_plan",
    "sequential_package_downloads",
}
CANDIDATE_FIELDS = {
    "schema", "state", "producer_passed", *CANDIDATE_CLAIMS,
    "contract_sha256", "rootfs", "package_request", "sources",
    "verified_at", "release_metadata", "package_indexes", "package_count",
    "package_bytes", "packages", "base_status", "tools", "command_hashes",
    "download_order", "verification", "scope",
}


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers,
                         new_url):
        return None


_OPEN_EXACT_URL = build_opener(_RejectRedirects).open


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path):
    path = Path(path)
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def format_release_time(value):
    require(isinstance(value, datetime) and value.tzinfo is not None,
            "Ubuntu Release time must be timezone aware")
    value = value.astimezone(timezone.utc).replace(microsecond=0)
    return format_datetime(value, usegmt=True)


def _iso_time(value):
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def _parse_iso_time(value, description):
    require(isinstance(value, str)
            and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
                             r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is not None,
            description + " is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError(description + " is malformed") from error
    require(_iso_time(parsed) == value, description + " is not canonical UTC")
    return parsed


def _parse_release_time(value, description):
    require(isinstance(value, str) and value and len(value) <= 128,
            description + " is missing or oversized")
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(description + " is malformed") from error
    require(parsed is not None and parsed.tzinfo is not None,
            description + " is not timezone aware")
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def _control_fields(raw, description, maximum):
    require(isinstance(raw, bytes) and 0 < len(raw) <= maximum,
            description + " is empty or exceeds its byte bound")
    require(b"\x00" not in raw and b"\r" not in raw,
            description + " contains noncanonical bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(description + " is not UTF-8") from error
    result = {}
    current = None
    for line in text.splitlines():
        require(len(line.encode()) <= MAX_RELEASE_LINE_BYTES,
                description + " contains an oversized line")
        if line.startswith((" ", "\t")):
            require(current is not None, description + " starts with continuation")
            result[current] += "\n" + line[1:]
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9-]*):(?: ?(.*))", line)
        require(match is not None, description + " contains a malformed field")
        name, value = match.groups()
        folded = name.casefold()
        require(folded not in result, description + " contains a duplicate field")
        result[folded] = value
        current = folded
    require(result, description + " has no fields")
    return result


def validate_gpgv_status(returncode, status, expected_fingerprint):
    """Require one exact pinned gpgv signature and no adverse status."""
    require(type(returncode) is int and isinstance(status, str)
            and len(status.encode()) <= MAX_PLAN_BYTES
            and packages.full_fingerprint(expected_fingerprint),
            "Ubuntu InRelease signature result is malformed")
    rows = []
    for line in status.splitlines():
        if line.startswith("[GNUPG:] "):
            rows.append(line.split())
    valid = [row[2] for row in rows
             if len(row) >= 3 and row[1] == "VALIDSIG"]
    good = [row for row in rows if len(row) >= 3 and row[1] == "GOODSIG"]
    require(returncode == 0 and valid == [expected_fingerprint]
            and len(good) == 1
            and re.fullmatch(r"[A-F0-9]{16}", good[0][2]) is not None
            and expected_fingerprint.endswith(good[0][2])
            and not any(len(row) >= 2 and row[1] in BAD_GPG_STATUS
                        for row in rows),
            "Ubuntu InRelease does not have one valid pinned signature")
    return {
        "signing_fingerprint": expected_fingerprint,
        "status_sha256": sha256_bytes(status.encode()),
    }


def inrelease_verification_command(keyring, inrelease, release_output):
    """Return the exact command that verifies and extracts signed Release text."""
    keyring = Path(keyring).resolve()
    inrelease = Path(inrelease).resolve()
    release_output = Path(release_output).resolve()
    require(keyring != inrelease and inrelease != release_output
            and keyring != release_output,
            "Ubuntu InRelease verification paths overlap")
    return [
        "/usr/bin/gpgv", "--status-fd=1", "--keyring", str(keyring),
        "--output", str(release_output), str(inrelease),
    ]


def validate_signed_release(raw, source, verified_at):
    """Validate freshness, suite identity and the exact amd64 Packages.xz row."""
    packages.validate_sources(packages.EXPECTED_SOURCES)
    require(source in packages.EXPECTED_SOURCES,
            "Ubuntu Release source is not one of the reviewed sources")
    require(isinstance(verified_at, datetime) and verified_at.tzinfo is not None,
            "Ubuntu Release verification time is not timezone aware")
    now = verified_at.astimezone(timezone.utc).replace(microsecond=0)
    fields = _control_fields(raw, "Ubuntu signed Release", MAX_RELEASE_BYTES)
    suite = source["suite"]
    require(fields.get("origin") == "Ubuntu" and fields.get("label") == "Ubuntu"
            and fields.get("suite") == suite
            and fields.get("codename") == EXPECTED_CODENAMES.get(suite),
            "Ubuntu Release origin, label, suite or codename changed")
    architectures = fields.get("architectures", "").split()
    components = fields.get("components", "").split()
    require(architectures and len(architectures) == len(set(architectures))
            and "amd64" in architectures
            and components and len(components) == len(set(components))
            and "main" in components,
            "Ubuntu Release omits the reviewed architecture or component")
    released = _parse_release_time(fields.get("date"), "Ubuntu Release Date")
    valid_until = _parse_release_time(
        fields.get("valid-until"), "Ubuntu Release Valid-Until")
    require(released <= now + MAX_CLOCK_SKEW
            and released < valid_until
            and now < valid_until
            and valid_until - released <= MAX_VALIDITY_WINDOW,
            "Ubuntu Release is stale, future-dated or has an excessive validity window")
    checksum_rows = [row for row in fields.get("sha256", "").splitlines()
                     if row]
    require(checksum_rows, "Ubuntu Release has no SHA256 inventory")
    seen = set()
    selected = []
    for row in checksum_rows:
        columns = row.split()
        require(len(columns) == 3 and packages.exact_hash(columns[0])
                and re.fullmatch(r"[1-9][0-9]*", columns[1]) is not None
                and packages._safe_filename(columns[2]),
                "Ubuntu Release has a malformed SHA256 row")
        digest, size_text, path = columns
        require(path not in seen, "Ubuntu Release has a duplicate SHA256 path")
        seen.add(path)
        size = int(size_text)
        require(0 < size <= packages.MAX_INDEX_BYTES,
                "Ubuntu Release index size exceeds its bound")
        if path == "main/binary-amd64/Packages.xz":
            selected.append({"path": path, "bytes": size, "sha256": digest})
    require(len(selected) == 1,
            "Ubuntu Release lacks one exact amd64 Packages.xz membership row")
    return {
        "origin": "Ubuntu",
        "label": "Ubuntu",
        "suite": suite,
        "codename": EXPECTED_CODENAMES[suite],
        "date": _iso_time(released),
        "valid_until": _iso_time(valid_until),
        "architectures": architectures,
        "components": components,
        "verified_at": _iso_time(now),
        "index": selected[0],
    }


def _iter_control_stanzas(path):
    total = 0
    pending = bytearray()
    try:
        stream = lzma.open(path, "rb")
        with stream:
            while True:
                block = stream.read(64 * 1024)
                if not block:
                    break
                total += len(block)
                require(total <= MAX_INDEX_TEXT_BYTES,
                        "Ubuntu Packages index expands past its byte bound")
                require(b"\x00" not in block and b"\r" not in block,
                        "Ubuntu Packages index contains noncanonical bytes")
                pending.extend(block)
                while True:
                    boundary = pending.find(b"\n\n")
                    if boundary < 0:
                        break
                    stanza = bytes(pending[:boundary])
                    del pending[:boundary + 2]
                    require(0 < len(stanza) <= MAX_STANZA_BYTES,
                            "Ubuntu Packages index has an invalid stanza bound")
                    yield stanza + b"\n"
                require(len(pending) <= MAX_STANZA_BYTES,
                        "Ubuntu Packages index has an oversized stanza")
    except lzma.LZMAError as error:
        raise ValueError("Ubuntu Packages.xz is malformed") from error
    if pending:
        require(len(pending) <= MAX_STANZA_BYTES,
                "Ubuntu Packages index has an oversized final stanza")
        yield bytes(pending) + b"\n"


def _package_row(raw, source, index_sha256):
    fields = _control_fields(raw, "Ubuntu Packages stanza", MAX_STANZA_BYTES)
    name = fields.get("package")
    version = fields.get("version")
    architecture = fields.get("architecture")
    filename = fields.get("filename")
    size_text = fields.get("size")
    digest = fields.get("sha256")
    require(isinstance(name, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) is not None
            and isinstance(version, str) and version
            and re.fullmatch(r"[A-Za-z0-9.+:~\-]+", version) is not None
            and architecture in ("amd64", "all")
            and packages._safe_filename(filename, ".deb")
            and filename.startswith("pool/main/")
            and isinstance(size_text, str)
            and re.fullmatch(r"[1-9][0-9]*", size_text) is not None
            and 0 < int(size_text) <= packages.MAX_PACKAGE_BYTES
            and packages.exact_hash(digest),
            "Ubuntu Packages membership row is malformed")
    return {
        "package": name,
        "version": version,
        "architecture": architecture,
        "filename": filename,
        "url": source["base_url"] + "/" + filename,
        "bytes": int(size_text),
        "sha256": digest,
        "source": {
            "suite": source["suite"],
            "component": "main",
            "index_architecture": "amd64",
            "index_sha256": index_sha256,
        },
    }


def find_requested_packages(path, source, index_binding, requested):
    """Find every apt-selected Filename exactly once in its signed Packages.xz."""
    path = Path(path)
    mode = path.stat()
    require(not path.is_symlink() and path.resolve(strict=True) == path
            and stat.S_ISREG(mode.st_mode) and mode.st_nlink == 1
            and mode.st_size == index_binding.get("bytes")
            and sha256_file(path) == index_binding.get("sha256")
            and index_binding.get("path") == "main/binary-amd64/Packages.xz",
            "Ubuntu Packages.xz bytes differ from signed Release membership")
    require(source in packages.EXPECTED_SOURCES and isinstance(requested, dict)
            and 0 < len(requested) <= packages.MAX_PACKAGE_COUNT,
            "Ubuntu requested package membership set is invalid")
    for filename, expected in requested.items():
        require(packages._safe_filename(filename, ".deb")
                and filename.startswith("pool/main/")
                and isinstance(expected, dict)
                and set(expected) == {"bytes", "sha256"}
                and type(expected["bytes"]) is int
                and 0 < expected["bytes"] <= packages.MAX_PACKAGE_BYTES
                and packages.exact_hash(expected["sha256"]),
                "Ubuntu requested package membership row is invalid")
    found = {}
    for raw in _iter_control_stanzas(path):
        fields = _control_fields(raw, "Ubuntu Packages stanza", MAX_STANZA_BYTES)
        filename = fields.get("filename")
        if filename not in requested:
            continue
        require(filename not in found,
                "Ubuntu Packages index repeats an apt-selected filename")
        row = _package_row(raw, source, index_binding["sha256"])
        expected = requested[filename]
        require(row["bytes"] == expected["bytes"]
                and row["sha256"] == expected["sha256"],
                "apt plan bytes differ from signed Packages membership")
        found[filename] = row
    require(set(found) == set(requested),
            "apt plan contains a package absent from signed Packages metadata")
    return {filename: found[filename] for filename in requested}


def parse_apt_uri_plan(raw, repository_root, sources):
    """Parse apt --print-uris output restricted to the staged file repositories."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_PLAN_BYTES
            and b"\x00" not in raw and b"\r" not in raw,
            "offline apt URI plan is empty or oversized")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("offline apt URI plan is not UTF-8") from error
    packages.validate_sources(sources)
    repository_root = Path(repository_root).resolve(strict=True)
    suite_roots = {
        source["suite"]: (repository_root / source["suite"]).resolve()
        for source in sources
    }
    result = []
    filenames, destinations = set(), set()
    for sequence, line in enumerate(text.splitlines()):
        try:
            columns = shlex.split(line, posix=True)
        except ValueError as error:
            raise ValueError("offline apt URI plan has invalid quoting") from error
        require(len(columns) == 4,
                "offline apt URI plan contains non-package output")
        uri, destination, size_text, digest_text = columns
        parsed = urlsplit(uri)
        require(parsed.scheme == "file" and not parsed.netloc
                and not parsed.query and not parsed.fragment,
                "offline apt URI plan contains a network or aliased URI")
        decoded_path = unquote(parsed.path, errors="strict")
        require(quote(decoded_path, safe="/") == parsed.path
                and "\x00" not in decoded_path and "\\" not in decoded_path,
                "offline apt URI plan path is unsafe")
        local_path = Path(decoded_path).resolve()
        matches = []
        for suite, suite_root in suite_roots.items():
            if local_path.is_relative_to(suite_root):
                matches.append((suite, local_path.relative_to(suite_root)))
        require(len(matches) == 1,
                "offline apt URI is outside one reviewed suite repository")
        suite, relative = matches[0]
        filename = relative.as_posix()
        require(packages._safe_filename(filename, ".deb")
                and filename.startswith("pool/main/")
                and packages._safe_filename(destination, ".deb")
                and PurePosixPath(destination).name == destination
                and re.fullmatch(r"[1-9][0-9]*", size_text) is not None
                and 0 < int(size_text) <= packages.MAX_PACKAGE_BYTES
                and digest_text.startswith("SHA256:")
                and packages.exact_hash(digest_text.removeprefix("SHA256:")),
                "offline apt URI plan row is malformed or weakly hashed")
        require(filename not in filenames and destination not in destinations,
                "offline apt URI plan repeats a package or destination")
        filenames.add(filename)
        destinations.add(destination)
        result.append({
            "sequence": sequence,
            "suite": suite,
            "filename": filename,
            "destination": destination,
            "bytes": int(size_text),
            "sha256": digest_text.removeprefix("SHA256:"),
        })
    require(0 < len(result) <= packages.MAX_PACKAGE_COUNT,
            "offline apt URI plan package count is invalid")
    require(sum(row["bytes"] for row in result) <= packages.MAX_CLOSURE_BYTES,
            "offline apt URI plan exceeds the closure byte bound")
    return result


def bind_uri_plan_to_indexes(plan, index_inputs, sources):
    """Bind every ordered apt URI to one exact row in a signed suite index."""
    packages.validate_sources(sources)
    require(isinstance(plan, list) and plan
            and len(plan) <= packages.MAX_PACKAGE_COUNT
            and isinstance(index_inputs, dict),
            "offline apt URI plan or signed index inputs are invalid")
    by_suite = {}
    for sequence, row in enumerate(plan):
        require(isinstance(row, dict)
                and set(row) == {
                    "sequence", "suite", "filename", "destination", "bytes",
                    "sha256",
                }
                and row["sequence"] == sequence
                and row["suite"] in {source["suite"] for source in sources},
                "offline apt URI plan sequence or suite changed")
        by_suite.setdefault(row["suite"], {})[row["filename"]] = {
            "bytes": row["bytes"], "sha256": row["sha256"],
        }
    source_by_suite = {source["suite"]: source for source in sources}
    selected = {}
    for suite, requested in by_suite.items():
        item = index_inputs.get(suite)
        require(isinstance(item, dict) and set(item) == {"path", "binding"},
                "offline apt plan lacks one signed index input")
        rows = find_requested_packages(
            item["path"], source_by_suite[suite], item["binding"], requested)
        for filename, row in rows.items():
            selected[(suite, filename)] = row
    ordered = [selected[(row["suite"], row["filename"])] for row in plan]
    identities = [packages.package_identity(row) for row in ordered]
    names = [row["package"] for row in ordered]
    require(len(identities) == len(set(identities))
            and len(names) == len(set(names))
            and set(packages.EXPECTED_REQUEST["roots"]).issubset(names),
            "offline apt plan has duplicate identities or omits a requested root")
    return ordered


_APT_PLAN_ROW = re.compile(
    r"(Inst|Conf) ([a-z0-9][a-z0-9+.-]*)(?::([a-z0-9]+))?"
    r"(?: \[[^\]\r\n]+\])? \((\S+)(?: [^()\r\n]*)? \[([a-z0-9]+)\]\)"
)


def validate_apt_simulation(raw, package_rows):
    """Require apt's offline install/configure plan to equal the bound payload set."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_PLAN_BYTES
            and b"\x00" not in raw and b"\r" not in raw,
            "offline apt simulation is empty or oversized")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("offline apt simulation is not UTF-8") from error
    expected = {
        (row.get("package"), row.get("version"), row.get("architecture"))
        for row in package_rows if isinstance(row, dict)
    }
    require(len(expected) == len(package_rows) and expected,
            "offline apt expected package identities are invalid")
    observed = {"Inst": [], "Conf": []}
    for line in text.splitlines():
        match = _APT_PLAN_ROW.fullmatch(line)
        require(match is not None,
                "offline apt simulation contains removal or unparsed output")
        action, name, qualifier, version, architecture = match.groups()
        require(qualifier in (None, architecture),
                "offline apt simulation architecture qualifiers disagree")
        identity = (name, version, architecture)
        require(identity not in observed[action],
                "offline apt simulation repeats a package action")
        observed[action].append(identity)
    require(set(observed["Inst"]) == expected
            and set(observed["Conf"]) == expected,
            "offline apt simulation differs from the signed package plan")
    return {
        "install_count": len(observed["Inst"]),
        "configure_count": len(observed["Conf"]),
        "stdout_sha256": sha256_bytes(raw),
    }


def offline_plan_commands(apt_root, repository_root, keyring, roots,
                          package_paths):
    """Return exact local-repository apt and no-act dpkg commands."""
    apt_root = Path(apt_root).resolve()
    repository_root = Path(repository_root).resolve()
    keyring = Path(keyring).resolve()
    require(list(roots) == packages.EXPECTED_REQUEST["roots"]
            and package_paths and len(package_paths) <= packages.MAX_PACKAGE_COUNT,
            "offline Ubuntu package roots or package paths changed")
    normalized = [Path(path).resolve() for path in package_paths]
    require(len(normalized) == len(set(normalized))
            and all(path.name.endswith(".deb") for path in normalized),
            "offline dpkg package paths are invalid or duplicated")
    common = [
        "/usr/bin/apt-get",
        "-o", "Dir=" + str(apt_root),
        "-o", "Dir::Etc::sourcelist=etc/apt/sources.list",
        "-o", "Dir::Etc::sourceparts=-",
        "-o", "Dir::State::status=var/lib/dpkg/status",
        "-o", "Dir::State::lists=var/lib/apt/lists",
        "-o", "Dir::Cache::archives=var/cache/apt/archives",
        "-o", "APT::Architecture=amd64",
        "-o", "Acquire::Languages=none",
        "-o", "Acquire::Retries=0",
        "-o", "Acquire::AllowInsecureRepositories=false",
        "-o", "Acquire::Check-Valid-Until=true",
        "-o", "Dir::Etc::Trusted=" + str(keyring),
        "-o", "Dir::Etc::TrustedParts=-",
    ]
    install = ["--no-install-recommends", "install", "--", *roots]
    return {
        "sources_list": offline_sources_list(
            repository_root, keyring, packages.EXPECTED_SOURCES),
        "update": [*common, "--no-list-cleanup", "update"],
        "uris": [*common, "--quiet=2", "--print-uris", "--download-only",
                 *install],
        "simulate": [*common, "--quiet=2", "--simulate", "--no-download",
                     *install],
        "dpkg": [
            "/usr/bin/dpkg", "--root=" + str(apt_root),
            "--admindir=" + str(apt_root / "var/lib/dpkg"),
            "--no-act", "--unpack", *[str(path) for path in normalized],
        ],
    }


def offline_sources_list(repository_root, keyring, sources):
    """Render only exact signed local repositories for the offline apt phase."""
    packages.validate_sources(sources)
    repository_root = Path(repository_root).resolve()
    keyring = Path(keyring).resolve()
    require(repository_root.is_absolute() and keyring.is_absolute()
            and not any(character.isspace() for character in str(repository_root))
            and not any(character.isspace() for character in str(keyring)),
            "offline apt repository or keyring path is unsafe")
    rows = []
    for source in sources:
        suite = source["suite"]
        uri = (repository_root / suite).as_uri()
        rows.append(
            f"deb [arch=amd64 signed-by={keyring}] {uri} {suite} main"
        )
    return "\n".join(rows) + "\n"


def download_exact(url, destination, expected_bytes, expected_sha256,
                   opener=_OPEN_EXACT_URL):
    """Download one exact payload without redirects, buffering or parallelism."""
    require(packages._canonical_https(url)
            and type(expected_bytes) is int
            and 0 < expected_bytes <= packages.MAX_PACKAGE_BYTES
            and packages.exact_hash(expected_sha256),
            "Ubuntu package download binding is invalid")
    destination = Path(destination)
    parent = destination.parent.resolve(strict=True)
    require(destination.parent.resolve() == parent
            and not destination.exists() and not destination.is_symlink(),
            "Ubuntu package download destination already exists or is aliased")
    request = Request(
        url,
        headers={
            "User-Agent": "SymbiOS-P0-Ubuntu-closure-producer/1",
            "Accept-Encoding": "identity",
        },
    )
    written = 0
    digest = hashlib.sha256()
    deadline = time.monotonic() + MAX_DOWNLOAD_SECONDS
    try:
        with opener(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            length = response.headers.get("Content-Length")
            require(response.status == 200 and response.geturl() == url
                    and isinstance(length, str) and length.isdigit()
                    and int(length) == expected_bytes,
                    "Ubuntu package response redirected or changed size")
            with destination.open("xb") as output:
                while True:
                    block = response.read(DOWNLOAD_CHUNK_BYTES)
                    if not block:
                        break
                    written += len(block)
                    require(written <= expected_bytes
                            and time.monotonic() <= deadline,
                            "Ubuntu package response exceeded its signed size or time")
                    digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
        require(written == expected_bytes and digest.hexdigest() == expected_sha256,
                "Ubuntu package bytes differ from signed Packages metadata")
        destination.chmod(0o644)
        return {"bytes": written, "sha256": digest.hexdigest()}
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def download_package_plan(plan, package_rows, destination,
                          opener=_OPEN_EXACT_URL):
    """Download the signed apt plan strictly one package at a time."""
    destination = Path(destination).resolve(strict=True)
    require(destination.is_dir() and not destination.is_symlink()
            and isinstance(plan, list) and isinstance(package_rows, list)
            and len(plan) == len(package_rows)
            and 0 < len(plan) <= packages.MAX_PACKAGE_COUNT,
            "Ubuntu sequential package download plan is invalid")
    outputs = []
    try:
        for sequence, (planned, package) in enumerate(
                zip(plan, package_rows, strict=True)):
            require(planned.get("sequence") == sequence
                    and planned.get("suite")
                    == package.get("source", {}).get("suite")
                    and planned.get("filename") == package.get("filename")
                    and planned.get("bytes") == package.get("bytes")
                    and planned.get("sha256") == package.get("sha256"),
                    "Ubuntu ordered download differs from signed apt membership")
            name = f"{sequence:04d}-" + PurePosixPath(
                package["filename"]).name
            require(packages._safe_filename(name, ".deb"),
                    "Ubuntu package staging filename is unsafe")
            path = destination / name
            result = download_exact(
                package["url"], path, package["bytes"], package["sha256"],
                opener=opener,
            )
            outputs.append({
                "sequence": sequence,
                "path": path,
                "sha256": result["sha256"],
                "bytes": result["bytes"],
            })
        require(sum(row["bytes"] for row in outputs)
                <= packages.MAX_CLOSURE_BYTES,
                "Ubuntu downloaded closure exceeds its total byte bound")
        return outputs
    except BaseException:
        for row in outputs:
            row["path"].unlink(missing_ok=True)
        raise


def extract_base_dpkg_status(archive, binding):
    """Read only dpkg status from the exact authenticated Ubuntu Base archive."""
    archive = Path(archive)
    mode = archive.stat()
    require(isinstance(binding, dict)
            and type(binding.get("bytes")) is int
            and packages.exact_hash(binding.get("sha256"))
            and not archive.is_symlink() and archive.resolve(strict=True) == archive
            and stat.S_ISREG(mode.st_mode) and mode.st_nlink == 1
            and mode.st_size == binding["bytes"]
            and sha256_file(archive) == binding["sha256"],
            "Ubuntu Base archive differs from its authenticated binding")
    selected = None
    try:
        with archive.open("rb") as stream, tarfile.open(
                fileobj=stream, mode="r|gz") as bundle:
            for member in bundle:
                name = member.name
                while name.startswith("./"):
                    name = name[2:]
                if name != "var/lib/dpkg/status":
                    continue
                require(selected is None and member.isfile()
                        and 0 < member.size <= MAX_STATUS_BYTES,
                        "Ubuntu Base contains a duplicate or invalid dpkg status")
                extracted = bundle.extractfile(member)
                require(extracted is not None,
                        "Ubuntu Base dpkg status cannot be read")
                selected = extracted.read(MAX_STATUS_BYTES + 1)
                require(len(selected) == member.size,
                        "Ubuntu Base dpkg status changed size while reading")
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ValueError("Ubuntu Base archive is malformed") from error
    require(isinstance(selected, bytes) and 0 < len(selected) <= MAX_STATUS_BYTES
            and b"\x00" not in selected,
            "Ubuntu Base archive has no bounded dpkg status")
    return selected, {"bytes": len(selected), "sha256": sha256_bytes(selected)}


def _copy_exact(source, destination, expected_bytes, expected_sha256):
    source = Path(source)
    before = source.stat()
    require(not source.is_symlink() and source.resolve(strict=True) == source
            and stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size == expected_bytes
            and sha256_file(source) == expected_sha256,
            "Ubuntu candidate input payload differs from its manifest")
    written = 0
    digest = hashlib.sha256()
    with source.open("rb") as input_stream, Path(destination).open("xb") as output:
        while True:
            block = input_stream.read(DOWNLOAD_CHUNK_BYTES)
            if not block:
                break
            written += len(block)
            require(written <= expected_bytes,
                    "Ubuntu candidate input grew while copying")
            digest.update(block)
            output.write(block)
        output.flush()
        os.fsync(output.fileno())
    after = source.stat()
    require(written == expected_bytes and digest.hexdigest() == expected_sha256
            and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns, before.st_nlink)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                after.st_ctime_ns, after.st_nlink),
            "Ubuntu candidate input changed while copying")
    Path(destination).chmod(0o644)


def validate_candidate_output(root, lock):
    """Recheck every exact member of an unselected candidate directory."""
    supplied_root = Path(root)
    require(supplied_root.is_absolute() and not supplied_root.is_symlink(),
            "Ubuntu package candidate output root is aliased")
    root = supplied_root.resolve(strict=True)
    require(root == supplied_root and root.is_dir()
            and {path.name for path in root.iterdir()}
            == {"manifest.json", "metadata", "packages"},
            "Ubuntu package candidate output members changed")
    manifest = packages.unique_json(
        root, "manifest.json", packages.MAX_METADATA_BYTES)
    validate_candidate_manifest(lock, manifest)
    metadata = root / "metadata"
    payloads = root / "packages"
    require(metadata.is_dir() and not metadata.is_symlink()
            and payloads.is_dir() and not payloads.is_symlink(),
            "Ubuntu candidate payload directories are unsafe")
    expected_metadata = {}
    for release, index in zip(
            manifest["release_metadata"], manifest["package_indexes"], strict=True):
        expected_metadata[release["inrelease"]["filename"]] = release["inrelease"]
        expected_metadata[index["filename"]] = index
    require({path.name for path in metadata.iterdir()} == set(expected_metadata),
            "Ubuntu candidate retained metadata members changed")
    for name, row in expected_metadata.items():
        path = metadata / name
        mode = path.stat()
        require(not path.is_symlink() and stat.S_ISREG(mode.st_mode)
                and mode.st_nlink == 1
                and mode.st_size == row["bytes"]
                and sha256_file(path) == row["sha256"],
                "Ubuntu candidate retained metadata bytes changed")
    expected_packages = {}
    for row in manifest["packages"]:
        basename = PurePosixPath(row["filename"]).name
        require(basename not in expected_packages,
                "Ubuntu candidate package basenames collide")
        expected_packages[basename] = row
    require({path.name for path in payloads.iterdir()} == set(expected_packages),
            "Ubuntu candidate package members changed")
    for name, row in expected_packages.items():
        path = payloads / name
        mode = path.stat()
        require(not path.is_symlink() and stat.S_ISREG(mode.st_mode)
                and mode.st_nlink == 1
                and mode.st_size == row["bytes"]
                and sha256_file(path) == row["sha256"],
                "Ubuntu candidate package bytes changed")
    return manifest


def write_candidate_output(destination, lock, manifest, metadata_inputs,
                           package_inputs):
    """Write exact candidate bytes without selecting, zipping or uploading them."""
    validate_candidate_manifest(lock, manifest)
    supplied_destination = Path(destination)
    require(supplied_destination.is_absolute()
            and not supplied_destination.is_symlink(),
            "Ubuntu candidate output destination is aliased")
    parent = supplied_destination.parent.resolve(strict=True)
    require(parent == supplied_destination.parent,
            "Ubuntu candidate output parent is aliased")
    destination = parent / supplied_destination.name
    partial = parent / (destination.name + ".partial")
    require(not destination.exists() and not destination.is_symlink()
            and not partial.exists() and not partial.is_symlink(),
            "Ubuntu candidate output destination already exists")
    expected_metadata = {}
    for release, index in zip(
            manifest["release_metadata"], manifest["package_indexes"], strict=True):
        expected_metadata[release["inrelease"]["filename"]] = release["inrelease"]
        expected_metadata[index["filename"]] = index
    expected_packages = {}
    for row in manifest["packages"]:
        basename = PurePosixPath(row["filename"]).name
        require(basename not in expected_packages,
                "Ubuntu candidate package basenames collide")
        expected_packages[basename] = row
    require(isinstance(metadata_inputs, dict)
            and set(metadata_inputs) == set(expected_metadata)
            and isinstance(package_inputs, dict)
            and set(package_inputs) == {row["filename"] for row in manifest["packages"]},
            "Ubuntu candidate output inputs are incomplete")
    partial.mkdir(mode=0o755)
    try:
        metadata = partial / "metadata"
        payloads = partial / "packages"
        metadata.mkdir(mode=0o755)
        payloads.mkdir(mode=0o755)
        for name in sorted(expected_metadata):
            row = expected_metadata[name]
            _copy_exact(
                metadata_inputs[name], metadata / name, row["bytes"], row["sha256"])
        for name in sorted(expected_packages):
            row = expected_packages[name]
            _copy_exact(
                package_inputs[row["filename"]], payloads / name,
                row["bytes"], row["sha256"])
        raw = (json.dumps(manifest, indent=2) + "\n").encode()
        require(len(raw) <= packages.MAX_METADATA_BYTES,
                "Ubuntu candidate manifest exceeds its byte bound")
        (partial / "manifest.json").write_bytes(raw)
        (partial / "manifest.json").chmod(0o644)
        validate_candidate_output(partial, lock)
        partial.rename(destination)
        return validate_candidate_output(destination, lock)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise


def release_record(source, binding, payload, signature):
    require(source in packages.EXPECTED_SOURCES
            and isinstance(binding, dict) and set(binding)
            == SIGNED_RELEASE_FIELDS | {"index"}
            and isinstance(payload, dict) and set(payload) == {"bytes", "sha256"}
            and type(payload["bytes"]) is int
            and 0 < payload["bytes"] <= packages.MAX_METADATA_BYTES
            and packages.exact_hash(payload["sha256"])
            and isinstance(signature, dict)
            and set(signature) == SIGNATURE_RECORD_FIELDS
            and signature["signing_fingerprint"]
            == source["metadata"]["signer_fingerprint"]
            and packages.exact_hash(signature["status_sha256"]),
            "Ubuntu candidate Release record is incomplete")
    signed = {key: binding[key] for key in SIGNED_RELEASE_FIELDS}
    return {
        "suite": source["suite"],
        "mode": "inrelease",
        "inrelease": {
            "filename": source["suite"] + "_InRelease",
            "url": source["metadata"]["inrelease_url"],
            "bytes": payload["bytes"],
            "sha256": payload["sha256"],
        },
        "release": None,
        "signature": None,
        "signer_fingerprint": source["metadata"]["signer_fingerprint"],
        "index": binding["index"],
        "signed": signed,
        "verification": signature,
    }


def index_record(source, binding):
    require(source in packages.EXPECTED_SOURCES
            and isinstance(binding, dict)
            and set(binding) == packages.RELEASE_INDEX_FIELDS,
            "Ubuntu candidate index binding is incomplete")
    return {
        "suite": source["suite"],
        "component": "main",
        "architecture": "amd64",
        "filename": source["suite"] + "_main_binary-amd64_Packages.xz",
        "url": source["packages_url"],
        "bytes": binding["bytes"],
        "sha256": binding["sha256"],
    }


def _contract_sha256(lock):
    raw = json.dumps(lock, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(raw)


def _validate_pending_contract(lock):
    from image.container import ubuntu_fixture_inputs as inputs

    require(isinstance(lock, dict) and set(lock) == inputs.LOCK_FIELDS
            and type(lock.get("schema")) is int and lock["schema"] == 1
            and lock.get("status") == "pending"
            and all(lock.get(field) is False for field in inputs.CLAIM_FIELDS),
            "Ubuntu producer contract is not the fail-closed pending slot")
    packages.validate_rootfs(lock.get("rootfs"))
    packages.validate_request(lock.get("package_request"))
    packages.validate_sources(lock.get("sources"))
    require(lock.get("fixture_source") == inputs.EXPECTED_FIXTURE_SOURCE
            and lock.get("producer") == {
                "workflow": None, "run_id": None, "run_attempt": None,
                "head_sha": None,
            }
            and lock.get("artifact") == {
                "id": None, "name": packages.ARTIFACT_NAME,
                "bytes": None, "sha256": None,
            }
            and lock.get("release_metadata") == []
            and lock.get("package_indexes") == []
            and lock.get("packages") == []
            and type(lock.get("package_count")) is int
            and lock["package_count"] == 0
            and type(lock.get("package_bytes")) is int
            and lock["package_bytes"] == 0
            and lock.get("scope") == inputs.LOCK_SCOPE,
            "Ubuntu producer contract contains a selection or payload")
    return lock


def validate_candidate_manifest(lock, manifest):
    """Validate evidence while retaining an unusable, unselected state."""
    _validate_pending_contract(lock)
    require(isinstance(manifest, dict) and set(manifest) == CANDIDATE_FIELDS,
            "Ubuntu package candidate or pending contract fields changed")
    require(type(manifest.get("schema")) is int and manifest["schema"] == 1
            and manifest.get("state") == "candidate-unselected"
            and manifest.get("producer_passed") is True
            and all(manifest.get(field) is False for field in CANDIDATE_CLAIMS)
            and manifest.get("contract_sha256") == _contract_sha256(lock)
            and manifest.get("scope") == CANDIDATE_SCOPE,
            "Ubuntu package candidate became selectable or made a qualification claim")
    packages.validate_rootfs(manifest.get("rootfs"))
    packages.validate_request(manifest.get("package_request"))
    sources = packages.validate_sources(manifest.get("sources"))
    require(manifest["rootfs"] == lock.get("rootfs")
            and manifest["package_request"] == lock.get("package_request")
            and manifest["sources"] == lock.get("sources"),
            "Ubuntu package candidate differs from the pending request")
    releases = manifest.get("release_metadata")
    indexes = manifest.get("package_indexes")
    require(isinstance(releases, list) and len(releases) == len(sources)
            and all(isinstance(row, dict)
                    and set(row) == CANDIDATE_RELEASE_FIELDS for row in releases),
            "Ubuntu candidate Release records are incomplete")
    base_releases = [
        {key: row[key] for key in packages.RELEASE_FIELDS} for row in releases
    ]
    packages._validate_retained_metadata_shape(base_releases, indexes, sources)
    require(isinstance(manifest.get("verified_at"), str),
            "Ubuntu candidate verification time is missing")
    for source, row in zip(sources, releases, strict=True):
        signed = row["signed"]
        verification = row["verification"]
        require(isinstance(signed, dict) and set(signed) == SIGNED_RELEASE_FIELDS
                and signed["origin"] == "Ubuntu" and signed["label"] == "Ubuntu"
                and signed["suite"] == source["suite"]
                and signed["codename"] == EXPECTED_CODENAMES[source["suite"]]
                and isinstance(signed["architectures"], list)
                and "amd64" in signed["architectures"]
                and isinstance(signed["components"], list)
                and "main" in signed["components"]
                and signed["verified_at"] == manifest["verified_at"]
                and isinstance(verification, dict)
                and set(verification) == SIGNATURE_RECORD_FIELDS
                and verification["signing_fingerprint"]
                == source["metadata"]["signer_fingerprint"]
                and packages.exact_hash(verification["status_sha256"]),
                "Ubuntu candidate signed Release evidence changed")
        verified = _parse_iso_time(
            signed["verified_at"], "Ubuntu candidate verification time")
        released = _parse_iso_time(
            signed["date"], "Ubuntu candidate Release date")
        valid_until = _parse_iso_time(
            signed["valid_until"], "Ubuntu candidate Release expiry")
        require(released <= verified + MAX_CLOCK_SKEW < valid_until + MAX_CLOCK_SKEW
                and verified < valid_until
                and valid_until - released <= MAX_VALIDITY_WINDOW,
                "Ubuntu candidate Release freshness evidence is invalid")
    count, total = packages._validate_retained_package_shape(
        manifest.get("packages"), base_releases, indexes, sources,
        manifest.get("package_count"), manifest.get("package_bytes"))
    require(count == manifest["package_count"] and total == manifest["package_bytes"],
            "Ubuntu candidate package totals changed")
    base_status = manifest.get("base_status")
    require(isinstance(base_status, dict) and set(base_status) == {"bytes", "sha256"}
            and type(base_status["bytes"]) is int and base_status["bytes"] > 0
            and packages.exact_hash(base_status["sha256"]),
            "Ubuntu Base dpkg status binding is invalid")
    tools = manifest.get("tools")
    require(isinstance(tools, dict) and set(tools) == TOOL_NAMES
            and all(isinstance(tool, dict) and set(tool) == TOOL_FIELDS
                    and isinstance(tool["version"], str) and tool["version"]
                    and len(tool["version"].encode()) <= 256
                    and packages.exact_hash(tool["sha256"])
                    for tool in tools.values()),
            "Ubuntu closure tool evidence is incomplete")
    command_hashes = manifest.get("command_hashes")
    require(isinstance(command_hashes, dict) and set(command_hashes) == COMMAND_NAMES
            and all(packages.exact_hash(value)
                    for value in command_hashes.values()),
            "Ubuntu offline plan output hashes are incomplete")
    order = manifest.get("download_order")
    package_hashes = [row["sha256"] for row in manifest["packages"]]
    require(isinstance(order, list) and len(order) == len(package_hashes)
            and len(order) == len(set(order)) and set(order) == set(package_hashes),
            "Ubuntu sequential package download order is incomplete")
    verification = manifest.get("verification")
    require(isinstance(verification, dict)
            and set(verification) == VERIFICATION_FIELDS
            and all(verification[field] is True for field in VERIFICATION_FIELDS),
            "Ubuntu candidate verification evidence is incomplete")
    return manifest


def candidate_manifest(lock, releases, indexes, package_rows, *, verified_at,
                       base_status, tools, command_hashes, download_order):
    require(isinstance(verified_at, datetime) and verified_at.tzinfo is not None,
            "Ubuntu candidate verification time is invalid")
    manifest = {
        "schema": 1,
        "state": "candidate-unselected",
        "producer_passed": True,
        **{field: False for field in CANDIDATE_CLAIMS},
        "contract_sha256": _contract_sha256(lock),
        "rootfs": lock.get("rootfs"),
        "package_request": lock.get("package_request"),
        "sources": lock.get("sources"),
        "verified_at": _iso_time(verified_at),
        "release_metadata": releases,
        "package_indexes": indexes,
        "package_count": len(package_rows),
        "package_bytes": sum(row.get("bytes", 0) for row in package_rows
                             if isinstance(row, dict)),
        "packages": package_rows,
        "base_status": base_status,
        "tools": tools,
        "command_hashes": command_hashes,
        "download_order": download_order,
        "verification": {field: True for field in VERIFICATION_FIELDS},
        "scope": CANDIDATE_SCOPE,
    }
    return validate_candidate_manifest(lock, manifest)
