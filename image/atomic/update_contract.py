"""Pure contracts for the disposable signed-update and rollback VM gate."""
import base64
import copy
import json
import re

from image.atomic.contract import digest_value
from image.boot.inputs import require_desktop_image
from image.toolchain.reuse import exact_hash


UPDATE_SOURCE = "/var/lib/symbi-update/source"
NEGATIVE_CONTROLS = {
    "unsigned": True,
    "wrong-key": True,
    "wrong-reference": True,
    "altered-signature": True,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def update_policy(original, public_key, manifest_digest):
    """Add one ephemeral signed local update source without changing release trust."""
    digest_value(manifest_digest)
    require(original.get("default") == [{"type": "reject"}]
            and set(original.get("transports", {})) == {"docker"}
            and isinstance(public_key, bytes) and 0 < len(public_key) <= 65536
            and "insecureAcceptAnything" not in json.dumps(original),
            "unexpected enforcing release policy or fixture key")
    policy = copy.deepcopy(original)
    policy["transports"]["dir"] = {
        UPDATE_SOURCE: [{
            "type": "signedBy",
            "keyType": "GPGKeys",
            "keyData": base64.b64encode(public_key).decode("ascii"),
            "signedIdentity": {
                "type": "exactReference",
                "dockerReference": "localhost/symbi-ci/development@" + manifest_digest,
            },
        }]
    }
    return policy


def update_command():
    return ["/usr/bin/bootc", "switch", "--transport", "dir",
            "--enforce-container-sigpolicy", UPDATE_SOURCE]


def rollback_command():
    return ["/usr/bin/bootc", "rollback"]


def require_update_base(config, pins, current):
    """Validate the retained predecessor without making it a release fallback."""
    try:
        require(config.get("schema") == 1 and set(config) == {
            "schema", "manifest_digest", "preflight", "image", "scope"
        }, "unexpected update-base lock schema")
        digest_value(config["manifest_digest"])
        wrapper = {"schema": 1, "os_qualified": False, "signature_qualified": False,
                   "images": {"generic": config["image"]}}
        manifest = require_desktop_image(wrapper, pins, "generic")
        require_desktop_image(current, pins, "generic")
        selected = config["image"]
        active = current["images"]["generic"]
        preflight = config["preflight"]
        require(type(preflight.get("run_id")) is int and preflight["run_id"] > 0
                and exact_hash(preflight.get("source_commit"), 40)
                and exact_hash(preflight.get("inspect_sha256"))
                and exact_hash(preflight.get("prepare_sha256")),
                "invalid retained predecessor preflight identity")
        require(selected["tested_commit"] != active["tested_commit"]
                and selected["run_id"] < active["run_id"]
                and selected["artifact"]["id"] != active["artifact"]["id"],
                "retained predecessor must be distinct and older than the current image")
        require(manifest["archive"]["image_id"] != active["manifest"]["archive"]["image_id"],
                "retained predecessor has the current image identity")
        require(selected.get("evidence")
                == "docs/security/reports/P0-03-desktop/"
                + str(selected["run_id"]) + "/independent-check.json",
                "retained predecessor evidence path changed")
        return selected
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed update-base lock") from error


def validate_artifact_metadata(config, metadata):
    """Bind a hosted predecessor download to the retained artifact identity."""
    try:
        selected = config["image"]
        artifact = selected["artifact"]
        workflow_run = metadata["workflow_run"]
        require(type(metadata.get("id")) is int
                and metadata["id"] == artifact["id"]
                and metadata.get("name") == artifact["name"]
                and type(metadata.get("size_in_bytes")) is int
                and metadata["size_in_bytes"] == artifact["bytes"]
                and metadata.get("digest") == "sha256:" + artifact["sha256"]
                and metadata.get("expired") is False,
                "hosted predecessor artifact identity differs from the lock")
        require(type(workflow_run.get("id")) is int
                and workflow_run["id"] == selected["run_id"]
                and workflow_run.get("head_sha") == selected["tested_commit"],
                "hosted predecessor workflow identity differs from the lock")
        return artifact
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed hosted predecessor artifact metadata") from error


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value)


def validate_report(report, old_digest, new_digest):
    """Require a signed old-to-new switch, new boot, and old boot after rollback."""
    require(_digest(old_digest) and _digest(new_digest) and old_digest != new_digest,
            "distinct exact update digests are required")
    require(report.get("schema") == 1 and report.get("passed") is True
            and report.get("guest_booted") is True
            and report.get("release_qualified") is False,
            "update report is incomplete or makes a release claim")
    authentication = report.get("source_authentication", {})
    require(authentication.get("positive_controls") == {"install": True, "update": True}
            and authentication.get("negative_controls") == NEGATIVE_CONTROLS,
            "signed update source controls are incomplete")
    phases = report.get("phases")
    expected = [
        {"name": "installed", "booted_digest": old_digest,
         "operation": "signed-update-staged", "staged_digest": new_digest},
        {"name": "updated", "booted_digest": new_digest,
         "operation": "rollback-queued", "rollback_digest": old_digest},
        {"name": "rolled-back", "booted_digest": old_digest,
         "rollback_from_digest": new_digest},
    ]
    require(phases == expected, "signed update or booted rollback phase differs")
    require(report.get("source_disk_unchanged") is True
            and report.get("persistent_overlay") is True,
            "update source or persistent VM disk control is incomplete")
    return {
        "passed": True,
        "signed_update": True,
        "booted_rollback": True,
        "installed_digest": old_digest,
        "updated_digest": new_digest,
        "rolled_back_digest": old_digest,
    }
