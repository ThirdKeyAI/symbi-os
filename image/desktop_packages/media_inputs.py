"""Authenticate and unpack one dedicated offline MPlayer/mpv RPM bundle."""
import hashlib
import json
from pathlib import Path
import shutil
import stat
import zipfile

from image.desktop_packages.media_contract import (
    MAX_MEDIA_EXPANDED_BYTES,
    MAX_MEDIA_MANIFEST_BYTES,
    MAX_MEDIA_RPM_BYTES,
    require_media_lock,
)


def _digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _source_rows(lock):
    names = ("name", "epoch", "version", "release", "arch", "nevra", "filename", "bytes",
             "sha256", "signature_verified", "key_fingerprint")
    return [{name: slot[name] for name in names} for slot in lock["source_inputs"]]


def _contained_target(destination, relative):
    target = destination / relative
    base = destination.resolve()
    resolved = target.resolve()
    if resolved == base or not resolved.is_relative_to(base):
        raise ValueError("Media bundle member escapes its destination")
    return target


def unpack_media_bundle(archive, lock, root, pins, trust, destination):
    """Extract only a ready lock's exact RPMs after manifest and ZIP validation."""
    require_media_lock(lock, root, pins, trust, require_ready=True)
    artifact = lock["closure"]["artifact"]
    if (archive.is_symlink() or not archive.is_file() or archive.resolve() != archive
            or archive.stat().st_size != artifact["bytes"] or _digest(archive) != artifact["sha256"]):
        raise ValueError("Hosted media bundle bytes changed")
    packages = lock["closure"]["packages"]
    sources = _source_rows(lock)
    expected = {"manifest.json"}
    expected.update("rpms/" + row["filename"] for row in packages)
    expected.update("srpms/" + row["filename"] for row in sources)
    if destination.exists() or destination.is_symlink():
        raise ValueError("Media destination must not exist")
    created = False
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = bundle.infolist()
            names = [row.filename for row in members]
            if len(names) != len(set(names)):
                raise ValueError("Duplicate media bundle member")
            regular = []
            for row in members:
                mode = row.external_attr >> 16
                if row.is_dir():
                    if row.filename not in ("rpms/", "srpms/") or row.file_size:
                        raise ValueError("Unexpected media bundle directory")
                    continue
                if (row.flag_bits & 1 or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                        or row.file_size <= 0
                        or row.file_size > (MAX_MEDIA_MANIFEST_BYTES
                                            if row.filename == "manifest.json"
                                            else MAX_MEDIA_RPM_BYTES)):
                    raise ValueError("Unsafe or oversized media bundle member")
                regular.append(row)
            if {row.filename for row in regular} != expected:
                raise ValueError("Unexpected or missing media bundle member")
            if sum(row.file_size for row in regular) > MAX_MEDIA_EXPANDED_BYTES:
                raise ValueError("Media bundle expanded size exceeds its bound")
            raw = bundle.read("manifest.json")
            if (len(raw) > MAX_MEDIA_MANIFEST_BYTES
                    or hashlib.sha256(raw).hexdigest() != artifact["manifest_sha256"]):
                raise ValueError("Media bundle manifest bytes changed")
            manifest = json.loads(raw)
            controls = {fingerprint: {"missing_key_rejected": True, "wrong_key_rejected": True,
                                      "tampered_package_rejected": True}
                        for fingerprint in (lock["trusted_keys"][0]["fingerprint"],
                                            lock["trusted_keys"][1]["fingerprint"])}
            if (manifest.get("schema") != 1 or manifest.get("passed") is not True
                    or manifest.get("dedicated_media_closure") is not True
                    or manifest.get("package_transaction_attempted") is not False
                    or manifest.get("installed_packages_unchanged") is not True
                    or manifest.get("requirements") != ["mplayer", "mpv"]
                    or manifest.get("packages") != packages or manifest.get("source_packages") != sources
                    or manifest.get("negative_controls") != controls):
                raise ValueError("Hosted media manifest differs from selected inputs")
            destination.mkdir(mode=0o700); created = True
            for row in regular:
                target = _contained_target(destination, row.filename)
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(row) as incoming, target.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
                target.chmod(0o644)
        for row in packages:
            path = destination / "rpms" / row["filename"]
            if path.stat().st_size != row["bytes"] or _digest(path) != row["sha256"]:
                raise ValueError("Media binary RPM differs from the selected lock")
        for row in sources:
            path = destination / "srpms" / row["filename"]
            if path.stat().st_size != row["bytes"] or _digest(path) != row["sha256"]:
                raise ValueError("Media source RPM differs from the selected lock")
        return manifest
    except BaseException:
        if created:
            shutil.rmtree(destination)
        raise
