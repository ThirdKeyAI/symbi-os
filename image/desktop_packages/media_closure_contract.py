"""Fail-closed request and result contract for media-only RPM production."""
import configparser
import re

try:
    from image.desktop_packages.media_contract import (
        FEDORA,
        FUSION,
        MAX_MEDIA_RPM_PAYLOAD_BYTES,
        require_source_release_match,
    )
except ModuleNotFoundError:  # Copied standalone into the disposable producer container.
    from media_contract import (
        FEDORA, FUSION, MAX_MEDIA_RPM_PAYLOAD_BYTES, require_source_release_match)


HASH = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"ghcr\.io/secureblue/[a-z0-9-]+@sha256:[0-9a-f]{64}")


def require_media_repositories(text):
    def policy(name, metalink, key, metadata_expire):
        return {
            "name": name,
            "metalink": metalink,
            "enabled": "1",
            "countme": "0",
            "metadata_expire": metadata_expire,
            "repo_gpgcheck": "0",
            "type": "rpm",
            "gpgcheck": "1",
            "gpgkey": "file:///inputs/" + key,
            "skip_if_unavailable": "0",
            "sslverify": "1",
        }

    expected = {
        "fedora": policy(
            "Fedora 45 - x86_64",
            "https://mirrors.fedoraproject.org/metalink?protocol=https&repo=fedora-45&arch=x86_64",
            "fedora-45-primary.asc",
            "7d",
        ),
        "updates": policy(
            "Fedora 45 - x86_64 - Updates",
            "https://mirrors.fedoraproject.org/metalink?protocol=https&repo=updates-released-f45&arch=x86_64",
            "fedora-45-primary.asc",
            "6h",
        ),
        "fedora-source": policy(
            "Fedora 45 - Source",
            "https://mirrors.fedoraproject.org/metalink?protocol=https&repo=fedora-source-45&arch=x86_64",
            "fedora-45-primary.asc",
            "7d",
        ),
        "updates-source": policy(
            "Fedora 45 - Updates Source",
            "https://mirrors.fedoraproject.org/metalink?protocol=https&repo=updates-released-source-f45&arch=x86_64",
            "fedora-45-primary.asc",
            "6h",
        ),
        "rpmfusion-free": policy(
            "RPM Fusion Free Fedora 45 x86_64",
            "https://mirrors.rpmfusion.org/metalink?repo=free-fedora-45&arch=x86_64&protocol=https",
            "rpmfusion-free-2020.asc",
            "6h",
        ),
        "rpmfusion-free-updates": policy(
            "RPM Fusion Free Fedora 45 x86_64 - Updates",
            "https://mirrors.rpmfusion.org/metalink?repo=free-fedora-updates-released-45&arch=x86_64&protocol=https",
            "rpmfusion-free-2020.asc",
            "6h",
        ),
        "rpmfusion-free-source": policy(
            "RPM Fusion Free Fedora 45 - Source",
            "https://mirrors.rpmfusion.org/metalink?repo=free-fedora-source-45&arch=x86_64&protocol=https",
            "rpmfusion-free-2020.asc",
            "6h",
        ),
        "rpmfusion-free-updates-source": policy(
            "RPM Fusion Free Fedora 45 - Updates Source",
            "https://mirrors.rpmfusion.org/metalink?repo=free-fedora-updates-released-source-45&arch=x86_64&protocol=https",
            "rpmfusion-free-2020.asc",
            "6h",
        ),
    }
    config = configparser.ConfigParser(interpolation=None)
    try:
        config.read_string(text)
    except configparser.Error as error:
        raise ValueError("Malformed media closure repository policy") from error
    if config.defaults() or set(config.sections()) != set(expected):
        raise ValueError("Unexpected media closure repositories")
    for name, declared in expected.items():
        if dict(config.items(name, raw=True)) != declared:
            raise ValueError("Media repository policy changed: " + name)


def _require_binary_row(row):
    fields = {
        "name", "epoch", "version", "release", "arch", "nevra", "vendor", "license",
        "source_rpm", "filename", "bytes", "sha256", "signature_verified", "key_fingerprint",
    }
    token = r"[A-Za-z0-9+_.~^-]+"
    if (not isinstance(row, dict) or set(row) != fields
            or not re.fullmatch(r"[a-z][a-z0-9+_.-]*", row.get("name", ""))
            or not re.fullmatch(token, row.get("version", ""))
            or not re.fullmatch(token, row.get("release", ""))
            or row.get("epoch") != "0" or row.get("arch") not in ("x86_64", "noarch")
            or row.get("nevra") != f'{row.get("name")}-{row.get("version")}-{row.get("release")}.{row.get("arch")}'
            or row.get("filename") != row.get("nevra") + ".rpm"
            or not re.fullmatch(token + r"\.src\.rpm", row.get("source_rpm", ""))
            or type(row.get("bytes")) is not int or not 0 < row["bytes"] <= 512 * 1024 * 1024
            or not HASH.fullmatch(row.get("sha256", ""))
            or row.get("signature_verified") is not True
            or row.get("key_fingerprint") not in (FEDORA, FUSION)
            or not row.get("vendor") or not row.get("license")):
        raise ValueError("Malformed media closure RPM row")


def require_candidate_request(value):
    if (not isinstance(value, dict) or set(value) != {
                "schema", "release", "architecture", "resolution_base", "requirements",
                "root_packages", "trusted_keys", "source_lock_sha256"}
            or value.get("schema") != 1 or value.get("release") != "45"
            or value.get("architecture") != "x86_64"
            or not IMAGE.fullmatch(value.get("resolution_base", ""))
            or value.get("requirements") != ["mplayer", "mpv"]
            or not HASH.fullmatch(value.get("source_lock_sha256", ""))):
        raise ValueError("Malformed media closure request")
    roots = value.get("root_packages")
    if not isinstance(roots, list) or [row.get("name") for row in roots] != [
            "mplayer", "mplayer-common", "mpv"]:
        raise ValueError("Media closure request changed its frozen roots")
    for row in roots:
        _require_binary_row(row)
    if ([row["key_fingerprint"] for row in roots] != [FUSION, FUSION, FEDORA]
            or roots[0]["source_rpm"] != roots[1]["source_rpm"]):
        raise ValueError("Media closure root signer or source relationship changed")
    keys = value.get("trusted_keys")
    if (not isinstance(keys, list) or len(keys) != 2
            or [row.get("file") for row in keys] != [
                "fedora-45-primary.asc", "rpmfusion-free-2020.asc"]
            or [row.get("fingerprint") for row in keys] != [FEDORA, FUSION]
            or any(not HASH.fullmatch(row.get("sha256", "")) for row in keys)):
        raise ValueError("Media closure trust inputs changed")
    return True


def require_candidate_manifest(value, request):
    require_candidate_request(request)
    if (not isinstance(value, dict) or set(value) != {
                "schema", "passed", "dedicated_media_closure", "package_transaction_attempted",
                "installed_packages_unchanged", "requirements", "packages", "source_packages",
                "negative_controls", "packages_selected", "security_qualified", "os_qualified",
                "scope"}
            or value.get("schema") != 1 or value.get("passed") is not True
            or value.get("dedicated_media_closure") is not True
            or value.get("package_transaction_attempted") is not False
            or value.get("installed_packages_unchanged") is not True
            or value.get("requirements") != request["requirements"]
            or any(value.get(name) is not False for name in (
                "packages_selected", "security_qualified", "os_qualified"))
            or value.get("scope") != (
                "Authenticated media-only candidates and source RPMs; no package transaction, "
                "program execution, security clearance or OS selection")):
        raise ValueError("Media closure result overstates or changes its scope")
    packages = value.get("packages")
    if not isinstance(packages, list) or not 3 <= len(packages) <= 128:
        raise ValueError("Media closure is empty or excessive")
    for row in packages:
        _require_binary_row(row)
    if (len({row["filename"] for row in packages}) != len(packages)
            or len({(row["name"], row["arch"]) for row in packages}) != len(packages)
            or any(row not in packages for row in request["root_packages"])):
        raise ValueError("Media closure duplicates or omits a frozen root")
    sources = value.get("source_packages")
    require_source_release_match(request["root_packages"], sources)
    if sum(row["bytes"] for row in packages + sources) > MAX_MEDIA_RPM_PAYLOAD_BYTES:
        raise ValueError("Media closure payload exceeds its retained artifact contract")
    controls = {
        key: {"missing_key_rejected": True, "wrong_key_rejected": True,
              "tampered_package_rejected": True}
        for key in (FEDORA, FUSION)
    }
    if value.get("negative_controls") != controls:
        raise ValueError("Media closure signature controls are incomplete")
    return True
