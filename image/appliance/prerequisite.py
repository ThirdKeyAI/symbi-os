"""Fail closed before downloading inputs for the interactive appliance."""
import hashlib
import json
from pathlib import Path
import shutil

from image.atomic.contract import unique_json
from image.atomic.hosted import MINIMUM_DISK_FREE_BYTES, validate_retained_preflight
from image.boot.inputs import require_desktop_image
from image.boot.preflight import expected_inputs


DOWNLOAD_WORKING_MARGIN_BYTES = 1024**3


def required_free_before_download(selected):
    """Reserve the controller floor, retained ZIP, and one GiB working margin."""
    artifact = selected.get("artifact") if isinstance(selected, dict) else None
    artifact_bytes = artifact.get("bytes") if isinstance(artifact, dict) else None
    if type(artifact_bytes) is not int or artifact_bytes <= 0:
        raise ValueError("Invalid retained artifact size")
    return MINIMUM_DISK_FREE_BYTES + artifact_bytes + DOWNLOAD_WORKING_MARGIN_BYTES


def require_download_capacity(selected, available_bytes):
    required = required_free_before_download(selected)
    if type(available_bytes) is not int or available_bytes < required:
        raise ValueError(
            f"Need {required} bytes free before downloading the retained image"
        )
    return required


def validate_appliance_prerequisites(root, available_bytes=None):
    """Use the controller's retained-preflight validator, then check capacity."""
    root = Path(root).resolve(strict=True)
    lock_path = root / "image/desktop-images.lock.json"
    lock_raw = lock_path.read_bytes()
    lock = unique_json(lock_raw)
    pins = unique_json((root / "image/base-images.json").read_bytes())
    manifest = require_desktop_image(lock, pins, "generic")
    selected = lock["images"]["generic"]
    expected = expected_inputs(root, lock, pins, "generic")
    readiness = unique_json((root / "image/atomic/preflight.lock.json").read_bytes())

    # Keep this first: a pending or stale selector fails before disk capacity can
    # make the workflow appear ready for the 4.177 GB download.
    validate_retained_preflight(root, readiness, selected, manifest, expected)

    if available_bytes is None:
        available_bytes = shutil.disk_usage(root).free
    required = require_download_capacity(selected, available_bytes)
    return {
        "schema": 1,
        "variant": "generic",
        "preflight_run": readiness["preflight_run"],
        "desktop_images_lock_sha256": hashlib.sha256(lock_raw).hexdigest(),
        "artifact_bytes": selected["artifact"]["bytes"],
        "available_bytes": available_bytes,
        "required_bytes": required,
        "os_qualified": False,
        "release_qualified": False,
    }


def main():
    print(json.dumps(validate_appliance_prerequisites(Path.cwd()), sort_keys=True))


if __name__ == "__main__":
    main()
