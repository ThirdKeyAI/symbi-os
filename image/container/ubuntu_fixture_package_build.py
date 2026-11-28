"""Build and validate an unselected Ubuntu fixture package candidate.

The functions in this module are producer-side only.  They authenticate signed
Release text, bind one Packages.xz per reviewed suite, bind apt's file-only URI
and simulation plans to exact package rows, and stream exact package payloads.
The resulting manifest is always an unselected candidate with every
qualification claim false.  The manual hosted producer may invoke it after
reviewed metadata pins are complete, but no image consumer imports it and it
cannot select, qualify, or authorize an artifact.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
import ctypes
import errno
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import signal
import stat
import tarfile
import threading
import time
from urllib.parse import quote, unquote, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request

from image.container import ubuntu_fixture_packages as packages


MAX_CLOCK_SKEW = timedelta(minutes=15)
MAX_ROLLING_RELEASE_AGE = timedelta(days=14)
MAX_IMMUTABLE_RELEASE_AGE = timedelta(days=1830)
MAX_RELEASE_BYTES = packages.MAX_METADATA_BYTES
MAX_RELEASE_LINE_BYTES = 64 * 1024
MAX_INDEX_TEXT_BYTES = 512 * 1024**2
MAX_STANZA_BYTES = 1024**2
MAX_PLAN_BYTES = 4 * 1024**2
MAX_STATUS_BYTES = 16 * 1024**2
MAX_BASE_TAR_MEMBERS = 32 * 1024
MAX_BASE_TAR_EXPANDED_BYTES = 1024**3
DOWNLOAD_CHUNK_BYTES = 64 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 30
MAX_DOWNLOAD_SECONDS = 600
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
OFFLINE_CNF_DISABLE_OPTION = (
    "Acquire::IndexTargets::deb::CNF::DefaultEnabled=false")
_RENAME_NOREPLACE = 1
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
    "Unselected Ubuntu fixture package bytes; raw hosted command evidence is "
    "external, and selection, offline image build and qualification remain blocked"
)
CANDIDATE_CLAIMS = (
    "selected", "qualified", "container_qualified", "signature_qualified",
    "os_qualified", "release_qualified",
)
CANDIDATE_RELEASE_FIELDS = packages.RELEASE_FIELDS | {"signed", "verification"}
SIGNED_RELEASE_FIELDS = {
    "origin", "label", "suite", "codename", "date", "valid_until",
    "architectures", "components", "verified_at", "freshness_policy",
}
FRESHNESS_POLICY_FIELDS = {
    "suite", "codename", "inrelease_url", "signer_fingerprint", "mode",
    "maximum_age_days",
}
SIGNATURE_RECORD_FIELDS = {"signing_fingerprint", "status_sha256"}
RELEASE_INVENTORY_PREDICATES = frozenset({
    "sha256-columns", "sha256-digest-syntax", "sha256-size-syntax",
    "sha256-path-safety", "sha256-duplicate-path",
    "target-index-byte-bound", "target-index-membership",
})
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


class _DownloadDeadlineExpired(TimeoutError):
    """Raised from SIGALRM so a blocking response read cannot outlive the plan."""


class ReleaseInventoryRejection(ValueError):
    """A fixed content-free signed-inventory predicate rejection."""

    def __init__(self, predicate, message):
        require(type(predicate) is str
                and predicate in RELEASE_INVENTORY_PREDICATES,
                "Ubuntu Release inventory rejection predicate is invalid")
        super().__init__(message)
        self.predicate = predicate


@contextmanager
def _hard_download_deadline(deadline):
    """Arm one Linux process timer without disturbing existing timer state."""
    require(type(deadline) in (int, float),
            "Ubuntu package aggregate download deadline is invalid")
    require(hasattr(os, "uname") and os.uname().sysname == "Linux"
            and hasattr(signal, "SIGALRM")
            and hasattr(signal, "ITIMER_REAL")
            and threading.current_thread() is threading.main_thread(),
            "Ubuntu package hard deadline requires the Linux main thread")
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    require(previous_timer == (0.0, 0.0),
            "Ubuntu package hard deadline found an active process timer")
    remaining = deadline - time.monotonic()
    require(remaining > 0,
            "Ubuntu package aggregate download deadline expired")
    previous_handler = signal.getsignal(signal.SIGALRM)
    handler_installed = False
    timer_armed = False

    def expire(_signum, _frame):
        raise _DownloadDeadlineExpired(
            "Ubuntu package aggregate download deadline expired")

    try:
        signal.signal(signal.SIGALRM, expire)
        handler_installed = True
        remaining = deadline - time.monotonic()
        require(remaining > 0,
                "Ubuntu package aggregate download deadline expired")
        signal.setitimer(signal.ITIMER_REAL, remaining)
        timer_armed = True
        yield
    finally:
        if timer_armed:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
        if handler_installed:
            signal.signal(signal.SIGALRM, previous_handler)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _file_identity(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _exact_directory_identity(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _canonical_absolute_path(value, description):
    require(isinstance(value, (str, os.PathLike)), description + " is not a path")
    raw = os.fspath(value)
    require(isinstance(raw, str) and raw and "\x00" not in raw,
            description + " is malformed")
    path = Path(raw)
    require(path.is_absolute() and raw == os.path.normpath(raw)
            and not raw.startswith("//")
            and all(part not in ("", ".", "..") for part in path.parts[1:]),
            description + " is not canonical and absolute")
    return path


def _safe_leaf(name):
    return (isinstance(name, str) and name and "/" not in name
            and "\\" not in name and name not in (".", "..")
            and "\x00" not in name)


def _rename_noreplace(source_fd, source_name, destination_fd,
                      destination_name):
    """Atomically publish one name without replacing an existing name."""
    require(type(source_fd) is int and type(destination_fd) is int
            and _safe_leaf(source_name) and _safe_leaf(destination_name),
            "Ubuntu candidate publish names or descriptors are invalid")
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:
        raise ValueError(
            "atomic no-replace candidate publication is unavailable") from error
    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_fd, os.fsencode(source_name),
        destination_fd, os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise FileExistsError(
                error_number, "Ubuntu candidate destination already exists",
                destination_name)
        raise OSError(
            error_number, "atomic no-replace candidate publication failed",
            destination_name)


class _DirectoryAnchor:
    """Hold every absolute path component open without following links."""

    def __init__(self, path, description, *, private=True):
        self.path = _canonical_absolute_path(path, description)
        self.description = description
        self.private = private
        self.descriptors = []
        self.names = []
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            descriptor = os.open("/", flags)
            self.descriptors.append(descriptor)
            require(stat.S_ISDIR(os.fstat(descriptor).st_mode),
                    description + " filesystem root is not a directory")
            for component in self.path.parts[1:]:
                child = os.open(component, flags, dir_fd=descriptor)
                info = os.fstat(child)
                require(stat.S_ISDIR(info.st_mode),
                        description + " has a non-directory component")
                self.names.append(component)
                self.descriptors.append(child)
                descriptor = child
            self._check_target()
            self.verify()
        except (OSError, ValueError) as error:
            self.close()
            if isinstance(error, ValueError):
                raise
            raise ValueError(description + " is not a direct anchored directory") from error

    @property
    def fd(self):
        return self.descriptors[-1]

    def _check_target(self):
        info = os.fstat(self.fd)
        require(stat.S_ISDIR(info.st_mode),
                self.description + " is not a directory")
        if self.private:
            require(info.st_uid == os.geteuid() and info.st_gid == os.getegid()
                    and stat.S_IMODE(info.st_mode) == PRIVATE_DIRECTORY_MODE,
                    self.description + " is not the exact private directory")

    def verify(self):
        self._check_target()
        for index, name in enumerate(self.names):
            held = os.fstat(self.descriptors[index + 1])
            try:
                named = os.stat(
                    name, dir_fd=self.descriptors[index], follow_symlinks=False)
            except OSError as error:
                raise ValueError(
                    self.description + " changed while anchored") from error
            require(stat.S_ISDIR(named.st_mode)
                    and _directory_identity(named) == _directory_identity(held),
                    self.description + " component identity changed")

    def close(self):
        for descriptor in reversed(getattr(self, "descriptors", [])):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self.descriptors = []


def _require_private_regular(info, expected_bytes, description):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.geteuid() and info.st_gid == os.getegid()
            and stat.S_IMODE(info.st_mode) == PRIVATE_FILE_MODE
            and type(expected_bytes) is int and expected_bytes >= 0
            and info.st_size == expected_bytes,
            description + " is not one exact private regular file")


def _open_regular_at(directory_fd, name, expected_bytes, description):
    require(_safe_leaf(name), description + " name is unsafe")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise ValueError(description + " is not a direct regular file") from error
    try:
        before = os.fstat(descriptor)
        _require_private_regular(before, expected_bytes, description)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        require(_file_identity(named) == _file_identity(before),
                description + " named identity changed before reading")
        return descriptor, before
    except BaseException:
        os.close(descriptor)
        raise


def _open_private_directory_at(directory_fd, name, description):
    require(_safe_leaf(name), description + " name is unsafe")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise ValueError(description + " is not a direct directory") from error
    try:
        info = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        require(stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.geteuid() and info.st_gid == os.getegid()
                and stat.S_IMODE(info.st_mode) == PRIVATE_DIRECTORY_MODE
                and _directory_identity(named) == _directory_identity(info),
                description + " is not the exact private directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _create_private_regular_at(directory_fd, name, description):
    require(_safe_leaf(name), description + " name is unsafe")
    flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
             | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        descriptor = os.open(
            name, flags, PRIVATE_FILE_MODE, dir_fd=directory_fd)
    except OSError as error:
        raise ValueError(description + " cannot be created directly") from error
    try:
        created = os.fstat(descriptor)
        _require_private_regular(created, 0, description)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        require(_file_identity(named) == _file_identity(created),
                description + " changed as it was created")
        return descriptor, created
    except BaseException:
        os.close(descriptor)
        raise


def _write_all(descriptor, raw):
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        require(written > 0, "private output write made no progress")
        view = view[written:]


def _finish_private_output(directory_fd, name, descriptor, created,
                           expected_bytes, expected_sha256, description):
    os.fsync(descriptor)
    before = os.fstat(descriptor)
    _require_private_regular(before, expected_bytes, description)
    require(before.st_dev == created.st_dev and before.st_ino == created.st_ino,
            description + " descriptor identity changed")
    digest = _fd_sha256(descriptor)
    after = os.fstat(descriptor)
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise ValueError(description + " disappeared after writing") from error
    require(digest == expected_sha256
            and _file_identity(after) == _file_identity(before)
            and _file_identity(named) == _file_identity(before),
            description + " changed while hashing or writing")
    return {"bytes": expected_bytes, "sha256": digest}


def _finish_regular_at(directory_fd, name, descriptor, before, description):
    after = os.fstat(descriptor)
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise ValueError(description + " disappeared while open") from error
    require(_file_identity(after) == _file_identity(before)
            and _file_identity(named) == _file_identity(before),
            description + " changed while open")


def _fd_sha256(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        block = os.read(descriptor, DOWNLOAD_CHUNK_BYTES)
        if not block:
            break
        digest.update(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _fd_read(descriptor, maximum, description):
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = bytearray()
    while len(raw) <= maximum:
        block = os.read(descriptor, min(DOWNLOAD_CHUNK_BYTES, maximum + 1 - len(raw)))
        if not block:
            break
        raw.extend(block)
    require(0 < len(raw) <= maximum, description + " is empty or oversized")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return bytes(raw)


def _open_private_path(path, expected_bytes, description):
    path = _canonical_absolute_path(path, description)
    require(path.name and path.parent != path, description + " has no leaf")
    anchor = _DirectoryAnchor(path.parent, description + " parent")
    try:
        descriptor, before = _open_regular_at(
            anchor.fd, path.name, expected_bytes, description)
        return path, anchor, descriptor, before
    except BaseException:
        anchor.close()
        raise


def _close_private_path(path, anchor, descriptor, before, description):
    _finish_regular_at(anchor.fd, path.name, descriptor, before, description)
    anchor.verify()


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


def expected_freshness_policy(source):
    """Return the reviewed freshness rule for one exact Ubuntu source."""
    packages.validate_sources(packages.EXPECTED_SOURCES)
    require(source in packages.EXPECTED_SOURCES,
            "Ubuntu freshness source is not one of the reviewed sources")
    immutable = source["suite"] == "noble"
    return {
        "suite": source["suite"],
        "codename": EXPECTED_CODENAMES[source["suite"]],
        "inrelease_url": source["metadata"]["inrelease_url"],
        "signer_fingerprint": source["metadata"]["signer_fingerprint"],
        "mode": "immutable-release" if immutable else "rolling-date",
        "maximum_age_days": (
            MAX_IMMUTABLE_RELEASE_AGE.days if immutable
            else MAX_ROLLING_RELEASE_AGE.days
        ),
    }


def validate_freshness_policy(policy, source):
    """Reject policy rows that are not bound to the reviewed source."""
    expected = expected_freshness_policy(source)
    require(type(policy) is dict and set(policy) == FRESHNESS_POLICY_FIELDS
            and policy == expected
            and type(policy.get("maximum_age_days")) is int,
            "Ubuntu Release freshness policy changed or is cross-bound")
    return policy


def _validate_release_freshness(released, valid_until, now, policy):
    """Apply an already source-bound policy to parsed UTC timestamps."""
    require(isinstance(released, datetime) and released.tzinfo is not None
            and isinstance(now, datetime) and now.tzinfo is not None,
            "Ubuntu Release freshness timestamps are malformed")
    maximum_age = timedelta(days=policy["maximum_age_days"])
    require(released <= now + MAX_CLOCK_SKEW,
            "Ubuntu Release is future-dated")
    if policy["mode"] == "immutable-release":
        require(valid_until is None and now - released <= maximum_age,
                "Ubuntu immutable Release has an expiry or exceeds its age bound")
    else:
        require(now - released <= maximum_age,
                "Ubuntu rolling Release Date exceeds its age bound")
        if valid_until is not None:
            require(isinstance(valid_until, datetime)
                    and valid_until.tzinfo is not None
                    and released < valid_until
                    and now < valid_until
                    and valid_until - released <= maximum_age,
                    "Ubuntu rolling Release Valid-Until is stale or has an "
                    "excessive validity window")


def signed_release_diagnostics(raw, source):
    """Return content-free structural diagnostics for authenticated Release text."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_RELEASE_BYTES,
            "Ubuntu signed Release diagnostics input is empty or oversized")
    line_names = []
    for line in raw.splitlines():
        match = re.match(br"([A-Za-z0-9][A-Za-z0-9-]*):", line)
        if match is not None:
            line_names.append(match.group(1).decode("ascii").casefold())
    diagnostics = {
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "control_fields_valid": False,
        "field_count": None,
        "date_fields": line_names.count("date"),
        "valid_until_fields": line_names.count("valid-until"),
        "sha256_fields": line_names.count("sha256"),
        "origin_matches": False,
        "label_matches": False,
        "suite_matches": False,
        "codename_matches": False,
    }
    try:
        fields = _control_fields(raw, "Ubuntu signed Release", MAX_RELEASE_BYTES)
    except ValueError:
        return diagnostics
    suite = source["suite"]
    diagnostics.update({
        "control_fields_valid": True,
        "field_count": len(fields),
        "origin_matches": fields.get("origin") == "Ubuntu",
        "label_matches": fields.get("label") == "Ubuntu",
        "suite_matches": fields.get("suite") == suite,
        "codename_matches": fields.get("codename")
        == EXPECTED_CODENAMES.get(suite),
    })
    return diagnostics


def release_rejection_reason(error):
    """Map parser detail to a bounded, content-free ledger reason."""
    require(isinstance(error, ValueError),
            "Ubuntu Release rejection is not a validation error")
    message = str(error)
    if isinstance(error, ReleaseInventoryRejection):
        return "index-inventory-rejected"
    if "Valid-Until" in message or "validity window" in message:
        return "valid-until-rejected"
    if ("freshness" in message or "stale" in message
            or "future-dated" in message or "age bound" in message):
        return "freshness-rejected"
    if any(name in message for name in (
            "origin", "label", "suite", "codename", "freshness policy")):
        return "identity-rejected"
    if "architecture" in message or "component" in message:
        return "content-scope-rejected"
    return "release-structure-rejected"


def release_rejection_predicate(error):
    """Return only the fixed inventory predicate, never rejected row content."""
    require(isinstance(error, ValueError),
            "Ubuntu Release rejection is not a validation error")
    if not isinstance(error, ReleaseInventoryRejection):
        return None
    require(type(error.predicate) is str
            and error.predicate in RELEASE_INVENTORY_PREDICATES,
            "Ubuntu Release inventory rejection predicate is invalid")
    return error.predicate


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
    keyring = _canonical_absolute_path(keyring, "Ubuntu archive keyring")
    inrelease = _canonical_absolute_path(inrelease, "Ubuntu InRelease input")
    release_output = _canonical_absolute_path(
        release_output, "Ubuntu Release output")
    require(keyring != inrelease and inrelease != release_output
            and keyring != release_output,
            "Ubuntu InRelease verification paths overlap")
    return [
        "/usr/bin/gpgv", "--status-fd=1", "--keyring", str(keyring),
        "--output", str(release_output), str(inrelease),
    ]


def validate_signed_release(raw, source, verified_at, freshness_policy):
    """Validate freshness, suite identity and the exact amd64 Packages.xz row."""
    packages.validate_sources(packages.EXPECTED_SOURCES)
    require(source in packages.EXPECTED_SOURCES,
            "Ubuntu Release source is not one of the reviewed sources")
    policy = validate_freshness_policy(freshness_policy, source)
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
    if policy["mode"] == "immutable-release":
        require("valid-until" not in fields,
                "Ubuntu immutable Release unexpectedly carries Valid-Until")
        valid_until = None
    else:
        valid_until = (None if "valid-until" not in fields else
                       _parse_release_time(
                           fields["valid-until"],
                           "Ubuntu Release Valid-Until"))
    _validate_release_freshness(released, valid_until, now, policy)
    checksum_rows = [row for row in fields.get("sha256", "").splitlines()
                     if row]
    if not checksum_rows:
        raise ReleaseInventoryRejection(
            "target-index-membership",
            "Ubuntu Release lacks one exact amd64 Packages.xz membership row")
    seen = set()
    selected = []
    for row in checksum_rows:
        columns = row.split()
        if len(columns) != 3:
            raise ReleaseInventoryRejection(
                "sha256-columns", "Ubuntu Release SHA256 columns changed")
        if not packages.exact_hash(columns[0]):
            raise ReleaseInventoryRejection(
                "sha256-digest-syntax",
                "Ubuntu Release SHA256 digest syntax changed")
        if re.fullmatch(r"0|[1-9][0-9]*", columns[1]) is None:
            raise ReleaseInventoryRejection(
                "sha256-size-syntax",
                "Ubuntu Release SHA256 size syntax changed")
        if not packages._safe_filename(columns[2]):
            raise ReleaseInventoryRejection(
                "sha256-path-safety",
                "Ubuntu Release SHA256 path safety changed")
        digest, size_text, path = columns
        if path in seen:
            raise ReleaseInventoryRejection(
                "sha256-duplicate-path",
                "Ubuntu Release has a duplicate SHA256 path")
        seen.add(path)
        if path == "main/binary-amd64/Packages.xz":
            maximum_size = str(packages.MAX_INDEX_BYTES)
            if (len(size_text) > len(maximum_size)
                    or (len(size_text) == len(maximum_size)
                        and size_text > maximum_size)):
                raise ReleaseInventoryRejection(
                    "target-index-byte-bound",
                    "Ubuntu Release index size exceeds its bound")
            size = int(size_text)
            if not 0 < size <= packages.MAX_INDEX_BYTES:
                raise ReleaseInventoryRejection(
                    "target-index-byte-bound",
                    "Ubuntu Release index size exceeds its bound")
            selected.append({"path": path, "bytes": size, "sha256": digest})
    if len(selected) != 1:
        raise ReleaseInventoryRejection(
            "target-index-membership",
            "Ubuntu Release lacks one exact amd64 Packages.xz membership row")
    return {
        "origin": "Ubuntu",
        "label": "Ubuntu",
        "suite": suite,
        "codename": EXPECTED_CODENAMES[suite],
        "date": _iso_time(released),
        "valid_until": None if valid_until is None else _iso_time(valid_until),
        "architectures": architectures,
        "components": components,
        "verified_at": _iso_time(now),
        "freshness_policy": policy,
        "index": selected[0],
    }


def _iter_control_stanzas(descriptor):
    total = 0
    pending = bytearray()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as raw_stream, \
                lzma.LZMAFile(raw_stream, "rb") as stream:
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
    finally:
        os.lseek(descriptor, 0, os.SEEK_SET)
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
    require(type(index_binding) is dict
            and set(index_binding) == packages.RELEASE_INDEX_FIELDS
            and type(index_binding.get("bytes")) is int
            and 0 < index_binding["bytes"] <= packages.MAX_INDEX_BYTES
            and packages.exact_hash(index_binding.get("sha256"))
            and index_binding.get("path") == "main/binary-amd64/Packages.xz",
            "Ubuntu Packages.xz bytes differ from signed Release membership")
    require(source in packages.EXPECTED_SOURCES and type(requested) is dict
            and 0 < len(requested) <= packages.MAX_PACKAGE_COUNT,
            "Ubuntu requested package membership set is invalid")
    for filename, expected in requested.items():
        require(packages._safe_filename(filename, ".deb")
                and filename.startswith("pool/main/")
                and type(expected) is dict
                and set(expected) == {"bytes", "sha256"}
                and type(expected["bytes"]) is int
                and 0 < expected["bytes"] <= packages.MAX_PACKAGE_BYTES
                and packages.exact_hash(expected["sha256"]),
                "Ubuntu requested package membership row is invalid")
    path, anchor, descriptor, before = _open_private_path(
        path, index_binding["bytes"], "Ubuntu Packages.xz")
    try:
        require(_fd_sha256(descriptor) == index_binding["sha256"],
                "Ubuntu Packages.xz hash differs from signed Release membership")
        found = {}
        for raw in _iter_control_stanzas(descriptor):
            fields = _control_fields(
                raw, "Ubuntu Packages stanza", MAX_STANZA_BYTES)
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
        _close_private_path(
            path, anchor, descriptor, before, "Ubuntu Packages.xz")
    finally:
        os.close(descriptor)
        anchor.close()
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
    repository_root = _canonical_absolute_path(
        repository_root, "offline apt repository root")
    anchor = _DirectoryAnchor(repository_root, "offline apt repository root")
    suite_descriptors = {}
    try:
        suite_roots = {}
        for source in sources:
            suite = source["suite"]
            suite_descriptors[suite] = _open_private_directory_at(
                anchor.fd, suite, "offline apt suite repository")
            suite_roots[suite] = repository_root / suite
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
            local_path = _canonical_absolute_path(
                decoded_path, "offline apt URI plan path")
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
        for suite, descriptor in suite_descriptors.items():
            named = os.stat(suite, dir_fd=anchor.fd, follow_symlinks=False)
            require(_directory_identity(named)
                    == _directory_identity(os.fstat(descriptor)),
                    "offline apt suite repository changed while planning")
        anchor.verify()
        return result
    finally:
        for descriptor in suite_descriptors.values():
            os.close(descriptor)
        anchor.close()


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


def _offline_apt_command_argv(apt_root, keyring, roots):
    """Return the complete ordered argv contract for every offline APT phase."""
    apt_root = _canonical_absolute_path(apt_root, "offline apt root")
    keyring = _canonical_absolute_path(keyring, "offline apt keyring")
    require(type(roots) is list and roots == packages.EXPECTED_REQUEST["roots"],
            "offline Ubuntu package roots changed")
    common = [
        "/usr/bin/apt-get",
        "-o", "Dir=" + str(apt_root),
        "-o", "Dir::Etc=etc/apt",
        "-o", "Dir::Etc::sourcelist=sources.list",
        "-o", "Dir::Etc::sourceparts=sources.list.d",
        "-o", "Dir::State::status=var/lib/dpkg/status",
        "-o", "Dir::State::lists=var/lib/apt/lists",
        "-o", "Dir::Cache::archives=var/cache/apt/archives",
        "-o", "APT::Architecture=amd64",
        "-o", "Acquire::Languages=none",
        "-o", OFFLINE_CNF_DISABLE_OPTION,
        "-o", "Acquire::Retries=0",
        "-o", "Acquire::AllowInsecureRepositories=false",
        "-o", "Acquire::Check-Valid-Until=true",
        "-o", "APT::Sandbox::User=root",
        "-o", "Dir::Etc::Trusted=" + str(keyring),
        "-o", "Dir::Etc::TrustedParts=-",
    ]
    install = ["--no-install-recommends", "install", "--", *roots]
    return {
        "update": [*common, "--no-list-cleanup", "update"],
        "uris": [*common, "--quiet=2", "--print-uris", "--download-only",
                 *install],
        "simulate": [*common, "--quiet=2", "--simulate", "--no-download",
                      *install],
    }


def validate_offline_apt_command_policy(commands, apt_root, repository_root,
                                        keyring, roots, sources):
    """Require exact ordered APT argv and exact authenticated source rows."""
    require(type(commands) is dict
            and set(commands) == {"sources_list", "update", "uris", "simulate"},
            "offline APT command set changed")
    validate_offline_sources_list(
        commands.get("sources_list"), repository_root, keyring, sources)
    expected = _offline_apt_command_argv(apt_root, keyring, roots)
    for name in ("update", "uris", "simulate"):
        argv = commands.get(name)
        require(type(argv) is list and all(type(value) is str for value in argv)
                and argv == expected[name],
                "offline APT command policy changed")
    return commands


def offline_apt_commands(apt_root, repository_root, keyring, roots):
    """Return exact local-repository apt commands before package download."""
    apt_root = _canonical_absolute_path(apt_root, "offline apt root")
    repository_root = _canonical_absolute_path(
        repository_root, "offline apt repository root")
    keyring = _canonical_absolute_path(keyring, "offline apt keyring")
    argv = _offline_apt_command_argv(apt_root, keyring, roots)
    commands = {
        "sources_list": offline_sources_list(
            repository_root, keyring, packages.EXPECTED_SOURCES),
        **argv,
    }
    return validate_offline_apt_command_policy(
        commands, apt_root, repository_root, keyring, roots,
        packages.EXPECTED_SOURCES)


def offline_dpkg_command(apt_root, package_paths):
    """Return the exact no-act dpkg command for downloaded package bytes."""
    apt_root = _canonical_absolute_path(apt_root, "offline apt root")
    require(package_paths and len(package_paths) <= packages.MAX_PACKAGE_COUNT,
            "offline dpkg package paths changed")
    normalized = [
        _canonical_absolute_path(path, "offline dpkg package")
        for path in package_paths
    ]
    require(len(normalized) == len(set(normalized))
            and all(path.name.endswith(".deb") for path in normalized),
            "offline dpkg package paths are invalid or duplicated")
    return [
        "/usr/bin/dpkg", "--root=" + str(apt_root),
        "--admindir=" + str(apt_root / "var/lib/dpkg"),
        "--no-act", "--unpack", *[str(path) for path in normalized],
    ]


def offline_plan_commands(apt_root, repository_root, keyring, roots,
                          package_paths):
    """Return exact local-repository apt and no-act dpkg commands."""
    result = offline_apt_commands(apt_root, repository_root, keyring, roots)
    result["dpkg"] = offline_dpkg_command(apt_root, package_paths)
    return result


def offline_sources_list(repository_root, keyring, sources):
    """Render only exact signed local repositories for the offline apt phase."""
    packages.validate_sources(sources)
    repository_root = _canonical_absolute_path(
        repository_root, "offline apt repository root")
    keyring = _canonical_absolute_path(keyring, "offline apt keyring")
    require(repository_root.is_absolute() and keyring.is_absolute()
            and not any(character.isspace() for character in str(repository_root))
            and not any(character.isspace() for character in str(keyring)),
            "offline apt repository or keyring path is unsafe")
    rows = []
    for source in sources:
        suite = source["suite"]
        uri = (repository_root / suite).as_uri()
        freshness = expected_freshness_policy(source)
        maximum_seconds = freshness["maximum_age_days"] * 24 * 60 * 60
        rows.append(
            f"deb [arch=amd64 signed-by={keyring} "
            f"check-valid-until=yes valid-until-max={maximum_seconds}] "
            f"{uri} {suite} main"
        )
    return "\n".join(rows) + "\n"


def validate_offline_sources_list(raw, repository_root, keyring, sources):
    """Require the exact file-only rows and per-source freshness ceilings."""
    expected = offline_sources_list(
        repository_root, keyring, sources)
    require(type(raw) is str and raw == expected,
            "offline APT source freshness contract changed")
    return raw


def _reviewed_package_url(url, filename=None, expected_source=None):
    require(type(url) is str and packages._canonical_https(url),
            "Ubuntu package download URL is not canonical HTTPS")
    matches = []
    sources = ([expected_source] if expected_source is not None else
               list({source["base_url"]: source
                     for source in packages.EXPECTED_SOURCES}.values()))
    for source in sources:
        require(source in packages.EXPECTED_SOURCES,
                "Ubuntu package URL source is not reviewed")
        prefix = source["base_url"] + "/"
        if url.startswith(prefix):
            relative = url.removeprefix(prefix)
            if (packages._safe_filename(relative, ".deb")
                    and relative.startswith("pool/main/")
                    and (filename is None or relative == filename)):
                matches.append((source, relative))
    require(len(matches) == 1,
            "Ubuntu package URL is outside the exact reviewed source")
    return matches[0]


def _validate_download_plan(plan, package_rows):
    require(type(plan) is list and type(package_rows) is list
            and len(plan) == len(package_rows)
            and 0 < len(plan) <= packages.MAX_PACKAGE_COUNT,
            "Ubuntu sequential package download plan is invalid")
    source_by_suite = {
        source["suite"]: source for source in packages.EXPECTED_SOURCES
    }
    identities = set()
    package_names = set()
    filenames = set()
    destinations = set()
    urls = set()
    total = 0
    for sequence, (planned, package) in enumerate(
            zip(plan, package_rows, strict=True)):
        source = package.get("source") if type(package) is dict else None
        require(type(planned) is dict
                and set(planned) == {
                    "sequence", "suite", "filename", "destination", "bytes",
                    "sha256",
                }
                and type(package) is dict
                and set(package) == packages.PACKAGE_FIELDS
                and type(source) is dict
                and set(source) == packages.PACKAGE_SOURCE_FIELDS,
                "Ubuntu download plan or package row fields changed")
        suite = planned.get("suite")
        filename = planned.get("filename")
        destination = planned.get("destination")
        expected_source = source_by_suite.get(suite)
        require(type(planned.get("sequence")) is int
                and planned["sequence"] == sequence
                and type(suite) is str and expected_source is not None
                and type(filename) is str
                and packages._safe_filename(filename, ".deb")
                and filename.startswith("pool/main/")
                and type(destination) is str
                and packages._safe_filename(destination, ".deb")
                and PurePosixPath(destination).name == destination
                and type(planned.get("bytes")) is int
                and 0 < planned["bytes"] <= packages.MAX_PACKAGE_BYTES
                and packages.exact_hash(planned.get("sha256")),
                "Ubuntu ordered download plan row is malformed")
        name = package.get("package")
        version = package.get("version")
        architecture = package.get("architecture")
        require(type(name) is str
                and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) is not None
                and type(version) is str and version
                and re.fullmatch(r"[A-Za-z0-9.+:~\-]+", version) is not None
                and type(architecture) is str
                and architecture in ("amd64", "all")
                and package.get("filename") == filename
                and type(package.get("bytes")) is int
                and package["bytes"] == planned["bytes"]
                and package.get("sha256") == planned["sha256"]
                and source.get("suite") == suite
                and source.get("component") == "main"
                and source.get("index_architecture") == "amd64"
                and packages.exact_hash(source.get("index_sha256")),
                "Ubuntu package row differs from its signed download plan")
        reviewed_source, reviewed_filename = _reviewed_package_url(
            package.get("url"), filename, expected_source)
        require(reviewed_source == expected_source
                and reviewed_filename == filename,
                "Ubuntu package URL differs from its reviewed suite")
        identity = packages.package_identity(package)
        require(identity not in identities and name not in package_names
                and filename not in filenames
                and destination not in destinations
                and package["url"] not in urls,
                "Ubuntu package download plan repeats an identity or path")
        identities.add(identity)
        package_names.add(name)
        filenames.add(filename)
        destinations.add(destination)
        urls.add(package["url"])
        total += package["bytes"]
        require(total <= packages.MAX_CLOSURE_BYTES,
                "Ubuntu package download plan exceeds its total byte bound")
    return total


def _download_exact_at(url, directory_fd, name, expected_bytes,
                       expected_sha256, opener, deadline):
    _reviewed_package_url(url)
    require(_safe_leaf(name)
            and type(expected_bytes) is int
            and 0 < expected_bytes <= packages.MAX_PACKAGE_BYTES
            and packages.exact_hash(expected_sha256)
            and type(deadline) in (int, float),
            "Ubuntu package download binding is invalid")
    request = Request(
        url,
        headers={
            "User-Agent": "SymbiOS-P0-Ubuntu-closure-producer/1",
            "Accept-Encoding": "identity",
        },
    )
    written = 0
    digest = hashlib.sha256()
    require(time.monotonic() < deadline,
            "Ubuntu package aggregate download deadline expired")
    descriptor, created = _create_private_regular_at(
        directory_fd, name, "Ubuntu package download")
    try:
        remaining = deadline - time.monotonic()
        require(remaining > 0,
                "Ubuntu package aggregate download deadline expired")
        with opener(
                request,
                timeout=min(DOWNLOAD_TIMEOUT_SECONDS, remaining)) as response:
            length = response.headers.get("Content-Length")
            require(response.status == 200 and response.geturl() == url
                    and isinstance(length, str) and length.isdigit()
                    and int(length) == expected_bytes,
                    "Ubuntu package response redirected or changed size")
            while True:
                block = response.read(DOWNLOAD_CHUNK_BYTES)
                if not block:
                    break
                written += len(block)
                require(written <= expected_bytes
                        and time.monotonic() <= deadline,
                        "Ubuntu package response exceeded its signed size or time")
                digest.update(block)
                _write_all(descriptor, block)
        require(written == expected_bytes and digest.hexdigest() == expected_sha256,
                "Ubuntu package bytes differ from signed Packages metadata")
        result = _finish_private_output(
            directory_fd, name, descriptor, created, expected_bytes,
            expected_sha256, "Ubuntu package download")
        return result, created
    finally:
        os.close(descriptor)


def download_exact(url, destination, expected_bytes, expected_sha256,
                   opener=_OPEN_EXACT_URL):
    """Download one exact payload through an anchored private directory fd."""
    _reviewed_package_url(url)
    destination = _canonical_absolute_path(
        destination, "Ubuntu package download destination")
    anchor = _DirectoryAnchor(
        destination.parent, "Ubuntu package download parent")
    deadline = time.monotonic() + MAX_DOWNLOAD_SECONDS
    try:
        with _hard_download_deadline(deadline):
            result, _ = _download_exact_at(
                url, anchor.fd, destination.name, expected_bytes,
                expected_sha256, opener, deadline)
        anchor.verify()
        return result
    finally:
        anchor.close()


def download_package_plan(plan, package_rows, destination,
                          opener=_OPEN_EXACT_URL):
    """Download the signed apt plan strictly one package at a time."""
    _validate_download_plan(plan, package_rows)
    deadline = time.monotonic() + MAX_DOWNLOAD_SECONDS
    destination = _canonical_absolute_path(
        destination, "Ubuntu sequential package download directory")
    anchor = _DirectoryAnchor(
        destination, "Ubuntu sequential package download directory")
    outputs = []
    try:
        with _hard_download_deadline(deadline):
            for sequence, (planned, package) in enumerate(
                    zip(plan, package_rows, strict=True)):
                name = f"{sequence:04d}-" + PurePosixPath(
                    package["filename"]).name
                require(packages._safe_filename(name, ".deb"),
                        "Ubuntu package staging filename is unsafe")
                result, _ = _download_exact_at(
                    package["url"], anchor.fd, name, package["bytes"],
                    package["sha256"], opener, deadline)
                outputs.append({
                    "sequence": sequence,
                    "path": destination / name,
                    "sha256": result["sha256"],
                    "bytes": result["bytes"],
                })
        anchor.verify()
        return outputs
    finally:
        anchor.close()


def _scan_base_tar(descriptor):
    member_count = 0
    expanded_bytes = 0
    selected = None
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "rb") as stream, tarfile.open(
            fileobj=stream, mode="r|gz") as bundle:
        for member in bundle:
            member_count += 1
            require(member_count <= MAX_BASE_TAR_MEMBERS
                    and type(member.size) is int and member.size >= 0,
                    "Ubuntu Base tar traversal exceeds its member bound")
            expanded_bytes += member.size
            require(expanded_bytes <= MAX_BASE_TAR_EXPANDED_BYTES,
                    "Ubuntu Base tar traversal exceeds its expanded byte bound")
            name = member.name
            while name.startswith("./"):
                name = name[2:]
            if name != "var/lib/dpkg/status":
                continue
            require(selected is None and member.isfile()
                    and 0 < member.size <= MAX_STATUS_BYTES,
                    "Ubuntu Base contains a duplicate or invalid dpkg status")
            selected = (member.name, member.type, member.size)
    os.lseek(descriptor, 0, os.SEEK_SET)
    require(selected is not None,
            "Ubuntu Base archive has no bounded dpkg status")
    return selected


def _read_scanned_base_status(descriptor, selected):
    result = None
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "rb") as stream, tarfile.open(
            fileobj=stream, mode="r|gz") as bundle:
        for member in bundle:
            if (member.name, member.type, member.size) != selected:
                continue
            extracted = bundle.extractfile(member)
            require(extracted is not None,
                    "Ubuntu Base dpkg status cannot be read")
            result = extracted.read(MAX_STATUS_BYTES + 1)
            require(len(result) == member.size,
                    "Ubuntu Base dpkg status changed size while reading")
            break
    os.lseek(descriptor, 0, os.SEEK_SET)
    require(result is not None,
            "Ubuntu Base dpkg status changed between bounded passes")
    return result


def extract_base_dpkg_status(archive, lock):
    """Read dpkg status from the exact pending-lock Ubuntu Base archive."""
    _validate_pending_contract(lock)
    binding = lock["rootfs"]
    archive = _canonical_absolute_path(archive, "Ubuntu Base archive")
    require(archive.name == binding["archive"],
            "Ubuntu Base archive name differs from the pending lock")
    archive, anchor, descriptor, before = _open_private_path(
        archive, binding["bytes"], "Ubuntu Base archive")
    try:
        require(_fd_sha256(descriptor) == binding["sha256"],
                "Ubuntu Base archive hash differs from its binding")
        selected = _scan_base_tar(descriptor)
        status = _read_scanned_base_status(descriptor, selected)
        _close_private_path(
            archive, anchor, descriptor, before, "Ubuntu Base archive")
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ValueError("Ubuntu Base archive is malformed") from error
    finally:
        os.close(descriptor)
        anchor.close()
    require(isinstance(status, bytes) and 0 < len(status) <= MAX_STATUS_BYTES
            and b"\x00" not in status,
            "Ubuntu Base archive has no bounded dpkg status")
    return status, {"bytes": len(status), "sha256": sha256_bytes(status)}


def _copy_exact(source, destination_fd, destination_name, expected_bytes,
                expected_sha256):
    source, anchor, source_fd, before = _open_private_path(
        source, expected_bytes, "Ubuntu candidate input payload")
    output_fd = created = None
    try:
        require(_fd_sha256(source_fd) == expected_sha256,
                "Ubuntu candidate input payload differs from its manifest")
        output_fd, created = _create_private_regular_at(
            destination_fd, destination_name, "Ubuntu candidate output payload")
        written = 0
        digest = hashlib.sha256()
        os.lseek(source_fd, 0, os.SEEK_SET)
        while True:
            block = os.read(source_fd, DOWNLOAD_CHUNK_BYTES)
            if not block:
                break
            written += len(block)
            require(written <= expected_bytes,
                    "Ubuntu candidate input grew while copying")
            digest.update(block)
            _write_all(output_fd, block)
        require(written == expected_bytes
                and digest.hexdigest() == expected_sha256,
                "Ubuntu candidate input changed while copying")
        _finish_private_output(
            destination_fd, destination_name, output_fd, created,
            expected_bytes, expected_sha256, "Ubuntu candidate output payload")
        output_identity = _file_identity(os.fstat(output_fd))
        _close_private_path(
            source, anchor, source_fd, before, "Ubuntu candidate input payload")
        return output_identity
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(source_fd)
        anchor.close()


def _read_bounded_regular_at(directory_fd, name, maximum, description):
    try:
        preliminary = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise ValueError(description + " is missing") from error
    require(stat.S_ISREG(preliminary.st_mode)
            and 0 < preliminary.st_size <= maximum,
            description + " is not bounded")
    descriptor, before = _open_regular_at(
        directory_fd, name, preliminary.st_size, description)
    try:
        raw = _fd_read(descriptor, maximum, description)
        _finish_regular_at(directory_fd, name, descriptor, before, description)
        return raw, _file_identity(before)
    finally:
        os.close(descriptor)


def _validate_bound_regular_at(directory_fd, name, row, description):
    descriptor, before = _open_regular_at(
        directory_fd, name, row["bytes"], description)
    try:
        require(_fd_sha256(descriptor) == row["sha256"],
                description + " hash changed")
        _finish_regular_at(directory_fd, name, descriptor, before, description)
        return _file_identity(before)
    finally:
        os.close(descriptor)


def _validate_candidate_output_fd(root_fd, lock, expected_identities=None):
    require(set(os.listdir(root_fd)) == {"manifest.json", "metadata", "packages"},
            "Ubuntu package candidate output members changed")
    raw_manifest, manifest_identity = _read_bounded_regular_at(
        root_fd, "manifest.json", packages.MAX_METADATA_BYTES,
        "Ubuntu candidate manifest")
    manifest = packages.unique_json_bytes(
        raw_manifest, packages.MAX_METADATA_BYTES)
    validate_candidate_manifest(lock, manifest)
    metadata_fd = _open_private_directory_at(
        root_fd, "metadata", "Ubuntu candidate metadata directory")
    payloads_fd = _open_private_directory_at(
        root_fd, "packages", "Ubuntu candidate package directory")
    metadata_identity = _directory_identity(os.fstat(metadata_fd))
    payloads_identity = _directory_identity(os.fstat(payloads_fd))
    try:
        expected_metadata = {}
        for release, index in zip(
                manifest["release_metadata"], manifest["package_indexes"],
                strict=True):
            expected_metadata[release["inrelease"]["filename"]] = release["inrelease"]
            expected_metadata[index["filename"]] = index
        require(set(os.listdir(metadata_fd)) == set(expected_metadata),
                "Ubuntu candidate retained metadata members changed")
        metadata_identities = {}
        for name, row in expected_metadata.items():
            metadata_identities[name] = _validate_bound_regular_at(
                metadata_fd, name, row,
                "Ubuntu candidate retained metadata")
        expected_packages = {}
        for row in manifest["packages"]:
            basename = PurePosixPath(row["filename"]).name
            require(basename not in expected_packages,
                    "Ubuntu candidate package basenames collide")
            expected_packages[basename] = row
        require(set(os.listdir(payloads_fd)) == set(expected_packages),
                "Ubuntu candidate package members changed")
        package_identities = {}
        for name, row in expected_packages.items():
            package_identities[name] = _validate_bound_regular_at(
                payloads_fd, name, row, "Ubuntu candidate package")
        require(set(os.listdir(root_fd))
                == {"manifest.json", "metadata", "packages"}
                and set(os.listdir(metadata_fd)) == set(expected_metadata)
                and set(os.listdir(payloads_fd)) == set(expected_packages)
                and _directory_identity(os.stat(
                    "metadata", dir_fd=root_fd, follow_symlinks=False))
                == metadata_identity
                and _directory_identity(os.fstat(metadata_fd))
                == metadata_identity
                and _directory_identity(os.stat(
                    "packages", dir_fd=root_fd, follow_symlinks=False))
                == payloads_identity
                and _directory_identity(os.fstat(payloads_fd))
                == payloads_identity,
                "Ubuntu candidate members changed during validation")
        if expected_identities is not None:
            require(isinstance(expected_identities, dict)
                    and set(expected_identities) == {
                        "root", "metadata_dir", "packages_dir", "manifest",
                        "metadata", "packages", "root_exact",
                        "metadata_dir_exact", "packages_dir_exact",
                    }
                    and _directory_identity(os.fstat(root_fd))
                    == expected_identities["root"]
                    and metadata_identity
                    == expected_identities["metadata_dir"]
                    and payloads_identity
                    == expected_identities["packages_dir"]
                    and _exact_directory_identity(os.fstat(root_fd))
                    == expected_identities["root_exact"]
                    and _exact_directory_identity(os.fstat(metadata_fd))
                    == expected_identities["metadata_dir_exact"]
                    and _exact_directory_identity(os.fstat(payloads_fd))
                    == expected_identities["packages_dir_exact"]
                    and manifest_identity == expected_identities["manifest"]
                    and metadata_identities
                    == expected_identities["metadata"]
                    and package_identities
                    == expected_identities["packages"],
                    "Ubuntu candidate created identities changed")
        return manifest
    finally:
        os.close(payloads_fd)
        os.close(metadata_fd)


def validate_candidate_output(root, lock):
    """Recheck every exact member through one anchored candidate directory fd."""
    anchor = _DirectoryAnchor(root, "Ubuntu package candidate output")
    try:
        manifest = _validate_candidate_output_fd(anchor.fd, lock)
        anchor.verify()
        return manifest
    finally:
        anchor.close()


def _create_isolated_stage(parent_fd, destination_name):
    for _ in range(8):
        token = secrets.token_hex(16)
        require(re.fullmatch(r"[a-f0-9]{32}", token) is not None,
                "Ubuntu candidate staging token is malformed")
        name = ".ubuntu-package-candidate-" + token
        if name == destination_name:
            continue
        try:
            os.mkdir(name, PRIVATE_DIRECTORY_MODE, dir_fd=parent_fd)
        except FileExistsError:
            continue
        descriptor = _open_private_directory_at(
            parent_fd, name, "isolated Ubuntu candidate staging directory")
        return name, descriptor, _directory_identity(os.fstat(descriptor))
    raise ValueError("cannot create an isolated Ubuntu candidate staging directory")


def _named_directory_is_held(parent_fd, name, descriptor, identity):
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        held = os.fstat(descriptor)
    except OSError:
        return False
    return (stat.S_ISDIR(named.st_mode)
            and _directory_identity(named) == identity
            and _directory_identity(held) == identity)


def _candidate_tree_matches(stage_fd, root_name, root_fd, metadata_fd,
                            payloads_fd, identities):
    try:
        if (set(identities) != {
                    "root", "metadata_dir", "packages_dir", "manifest",
                    "metadata", "packages", "root_exact",
                    "metadata_dir_exact", "packages_dir_exact",
                }
                or not _named_directory_is_held(
                    stage_fd, root_name, root_fd, identities["root"])
                or not _named_directory_is_held(
                    root_fd, "metadata", metadata_fd,
                    identities["metadata_dir"])
                or not _named_directory_is_held(
                    root_fd, "packages", payloads_fd,
                    identities["packages_dir"])):
            return False
        exact_directories = (
            (root_fd, identities["root_exact"]),
            (metadata_fd, identities["metadata_dir_exact"]),
            (payloads_fd, identities["packages_dir_exact"]),
        )
        if any(expected is not None
               and _exact_directory_identity(os.fstat(descriptor)) != expected
               for descriptor, expected in exact_directories):
            return False
        root_members = {"metadata", "packages"}
        if identities["manifest"] is not None:
            root_members.add("manifest.json")
        if (set(os.listdir(stage_fd)) != {root_name}
                or set(os.listdir(root_fd)) != root_members
                or set(os.listdir(metadata_fd)) != set(identities["metadata"])
                or set(os.listdir(payloads_fd)) != set(identities["packages"])):
            return False
        if identities["manifest"] is not None:
            manifest = os.stat(
                "manifest.json", dir_fd=root_fd, follow_symlinks=False)
            if _file_identity(manifest) != identities["manifest"]:
                return False
        for name, expected in identities["metadata"].items():
            named = os.stat(name, dir_fd=metadata_fd, follow_symlinks=False)
            if _file_identity(named) != expected:
                return False
        for name, expected in identities["packages"].items():
            named = os.stat(name, dir_fd=payloads_fd, follow_symlinks=False)
            if _file_identity(named) != expected:
                return False
        return True
    except OSError:
        return False


def write_candidate_output(destination, lock, manifest, metadata_inputs,
                           package_inputs):
    """Write exact candidate bytes without selecting, zipping or uploading them."""
    validate_candidate_manifest(lock, manifest)
    destination = _canonical_absolute_path(
        destination, "Ubuntu candidate output destination")
    require(_safe_leaf(destination.name),
            "Ubuntu candidate output destination name is unsafe")
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
    anchor = _DirectoryAnchor(
        destination.parent, "Ubuntu candidate output parent")
    stage_fd = root_fd = metadata_fd = payloads_fd = manifest_fd = None
    stage_name = None
    stage_identity = None
    manifest_created = None
    identities = {
        "root": None,
        "metadata_dir": None,
        "packages_dir": None,
        "root_exact": None,
        "metadata_dir_exact": None,
        "packages_dir_exact": None,
        "manifest": None,
        "metadata": {},
        "packages": {},
    }
    renamed = False
    published = False
    try:
        stage_name, stage_fd, stage_identity = _create_isolated_stage(
            anchor.fd, destination.name)
        root_name = "candidate"
        os.mkdir(root_name, PRIVATE_DIRECTORY_MODE, dir_fd=stage_fd)
        root_fd = _open_private_directory_at(
            stage_fd, root_name, "isolated Ubuntu candidate root")
        identities["root"] = _directory_identity(os.fstat(root_fd))
        os.mkdir("metadata", PRIVATE_DIRECTORY_MODE, dir_fd=root_fd)
        os.mkdir("packages", PRIVATE_DIRECTORY_MODE, dir_fd=root_fd)
        metadata_fd = _open_private_directory_at(
            root_fd, "metadata", "Ubuntu candidate metadata directory")
        payloads_fd = _open_private_directory_at(
            root_fd, "packages", "Ubuntu candidate package directory")
        identities["metadata_dir"] = _directory_identity(
            os.fstat(metadata_fd))
        identities["packages_dir"] = _directory_identity(
            os.fstat(payloads_fd))
        for name in sorted(expected_metadata):
            row = expected_metadata[name]
            identities["metadata"][name] = _copy_exact(
                metadata_inputs[name], metadata_fd, name,
                row["bytes"], row["sha256"])
        for name in sorted(expected_packages):
            row = expected_packages[name]
            identities["packages"][name] = _copy_exact(
                package_inputs[row["filename"]], payloads_fd, name,
                row["bytes"], row["sha256"])
        raw = (json.dumps(manifest, indent=2) + "\n").encode()
        require(0 < len(raw) <= packages.MAX_METADATA_BYTES,
                "Ubuntu candidate manifest exceeds its byte bound")
        manifest_fd, manifest_created = _create_private_regular_at(
            root_fd, "manifest.json", "Ubuntu candidate manifest")
        _write_all(manifest_fd, raw)
        _finish_private_output(
            root_fd, "manifest.json", manifest_fd, manifest_created,
            len(raw), sha256_bytes(raw), "Ubuntu candidate manifest")
        identities["manifest"] = _file_identity(os.fstat(manifest_fd))
        os.close(manifest_fd)
        manifest_fd = None
        identities["root_exact"] = _exact_directory_identity(
            os.fstat(root_fd))
        identities["metadata_dir_exact"] = _exact_directory_identity(
            os.fstat(metadata_fd))
        identities["packages_dir_exact"] = _exact_directory_identity(
            os.fstat(payloads_fd))
        validated = _validate_candidate_output_fd(
            root_fd, lock, identities)
        require(_candidate_tree_matches(
                    stage_fd, root_name, root_fd, metadata_fd, payloads_fd,
                    identities)
                and _named_directory_is_held(
                    anchor.fd, stage_name, stage_fd, stage_identity),
                "Ubuntu candidate staging identity changed before publish")
        _rename_noreplace(
            stage_fd, root_name, anchor.fd, destination.name)
        renamed = True
        before_publish_exact = identities["root_exact"]
        after_publish_exact = _exact_directory_identity(os.fstat(root_fd))
        require(after_publish_exact[:-1] == before_publish_exact[:-1],
                "Ubuntu candidate root changed beyond the rename ctime")
        identities["root_exact"] = after_publish_exact
        named = os.stat(
            destination.name, dir_fd=anchor.fd, follow_symlinks=False)
        require(stat.S_ISDIR(named.st_mode)
                and _directory_identity(named) == identities["root"]
                and _directory_identity(os.fstat(root_fd)) == identities["root"]
                and _named_directory_is_held(
                    anchor.fd, stage_name, stage_fd, stage_identity)
                and not os.listdir(stage_fd),
                "Ubuntu candidate output identity changed during rename")
        published_validation = _validate_candidate_output_fd(
            root_fd, lock, identities)
        named = os.stat(
            destination.name, dir_fd=anchor.fd, follow_symlinks=False)
        require(published_validation == validated
                and stat.S_ISDIR(named.st_mode)
                and _directory_identity(named) == identities["root"]
                and _directory_identity(os.fstat(root_fd)) == identities["root"]
                and _named_directory_is_held(
                    anchor.fd, stage_name, stage_fd, stage_identity)
                and not os.listdir(stage_fd),
                "Ubuntu candidate output changed after publication")
        anchor.verify()
        published = True
        require(renamed and published,
                "Ubuntu candidate publication state is inconsistent")
        return published_validation
    finally:
        for descriptor in (
                manifest_fd, payloads_fd, metadata_fd, root_fd, stage_fd):
            if descriptor is not None:
                os.close(descriptor)
        anchor.close()


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

    require(type(lock) is dict and set(lock) == inputs.LOCK_FIELDS
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
            and manifest.get("producer_passed") is False
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
                and signed["freshness_policy"]
                == expected_freshness_policy(source)
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
        policy = validate_freshness_policy(
            signed["freshness_policy"], source)
        if policy["mode"] == "immutable-release":
            require(signed["valid_until"] is None,
                    "Ubuntu immutable candidate Release carries an expiry")
            valid_until = None
        else:
            valid_until = (None if signed["valid_until"] is None else
                           _parse_iso_time(
                               signed["valid_until"],
                               "Ubuntu candidate Release expiry"))
        _validate_release_freshness(released, valid_until, verified, policy)
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
            and all(verification[field] is False for field in VERIFICATION_FIELDS),
            "unselected Ubuntu candidate made a verification claim")
    return manifest


def candidate_manifest(lock, releases, indexes, package_rows, *, verified_at,
                       base_status, tools, command_hashes, download_order):
    require(isinstance(verified_at, datetime) and verified_at.tzinfo is not None,
            "Ubuntu candidate verification time is invalid")
    manifest = {
        "schema": 1,
        "state": "candidate-unselected",
        "producer_passed": False,
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
        # Hash-only observations cannot prove that a hosted command ran.  The
        # dormant candidate therefore makes no verification claim; a later
        # producer must bind raw results, tool fds, argv and input identities.
        "verification": {field: False for field in VERIFICATION_FIELDS},
        "scope": CANDIDATE_SCOPE,
    }
    return validate_candidate_manifest(lock, manifest)
