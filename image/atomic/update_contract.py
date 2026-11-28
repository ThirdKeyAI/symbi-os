"""Pure contracts for the disposable signed-update and rollback VM gate."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import stat

from image.atomic.contract import digest_value
from image.boot.inputs import require_desktop_image
from image.toolchain.reuse import exact_hash


UPDATE_SOURCE = "/run/symbi-update/source"
NEGATIVE_UPDATE_SOURCE = "/run/symbi-update-negative/source"
NEGATIVE_CASES = ("unsigned", "wrong-key", "wrong-reference", "altered-signature")
POSITIVE_OVERLAY_CASE = "valid-signature"
BOOTC_COMMAND = ["/usr/bin/bootc"]
CONTROLLER_IDENTITY = {
    "policy": "symbi_atomic_update",
    "entrypoint": "/usr/libexec/symbi-atomic-update",
    "entrypoint_selinux_label":
        "system_u:object_r:symbi_atomic_update_exec_t:s0",
    "bridge": "/usr/libexec/symbi-bootc-transition",
    "bridge_selinux_label":
        "system_u:object_r:symbi_bootc_transition_exec_t:s0",
    "controller": "/usr/libexec/symbi-atomic-update-controller.py",
    "manifest": "/usr/share/symbi-os/selinux/symbi-atomic-update.json",
    "controller_context": "system_u:system_r:symbi_atomic_update_t:s0",
    "install_context": "system_u:system_r:install_t:s0",
}
NEGATIVE_CONTROLS = {
    case: True for case in NEGATIVE_CASES
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_controller_identity(value):
    """Validate the exact image-owned controller identity from a booted predecessor."""
    try:
        require(isinstance(value, dict) and set(value) == {
            "schema", "policy", "entrypoint", "entrypoint_sha256",
            "entrypoint_selinux_label", "bridge", "bridge_sha256",
            "bridge_selinux_label", "controller", "controller_sha256",
            "manifest", "manifest_sha256", "controller_context",
            "install_context", "policy_sources", "expanded_policy",
        }, "unexpected Atomic update controller identity schema")
        require(type(value.get("schema")) is int and value["schema"] == 1,
                "unexpected Atomic update controller identity version")
        for key, expected in CONTROLLER_IDENTITY.items():
            require(value.get(key) == expected,
                    "Atomic update controller identity differs: " + key)
        for key in ("entrypoint_sha256", "bridge_sha256",
                    "controller_sha256", "manifest_sha256"):
            require(exact_hash(value.get(key)),
                    "Atomic update controller digest is invalid")
        sources = value.get("policy_sources")
        require(isinstance(sources, dict)
                and set(sources) == {
                    "te_sha256", "fc_sha256", "launcher_sha256",
                    "bridge_sha256"}
                and all(exact_hash(item) for item in sources.values()),
                "Atomic update policy source identity is invalid")
        expansion = value.get("expanded_policy")
        inventory = (expansion.get("install_transition_inventory")
                     if isinstance(expansion, dict) else None)
        require(isinstance(expansion, dict)
                and type(expansion.get("schema")) is int
                and isinstance(inventory, dict)
                and type(inventory.get("schema")) is int,
                "expanded Atomic update policy schema is invalid")
        require(expansion == {
            "schema": 2,
            "policy": "symbi_atomic_update",
            "install_transition_inventory": {
                "schema": 1,
                "source": "symbi_atomic_update_t",
                "class": "process",
                "destination": "install_t",
                "rules": [
                    "type_transition symbi_atomic_update_t "
                    "symbi_bootc_transition_exec_t:process install_t;",
                ],
            },
            "required": {
                "init_entrypoint": True,
                "init_transition": True,
                "bridge_entrypoint": True,
                "bridge_transition": True,
                "bridge_type_transition": True,
                "install_sigchld": True,
            },
            "forbidden": {
                "shared_install_type_transition": False,
                "generic_install_transition": False,
                "controller_forbidden_process_permissions": False,
                "controller_policy_load": False,
                "controller_enforcing_change": False,
            },
        }, "expanded Atomic update policy identity differs")
        return copy.deepcopy(value)
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed Atomic update controller identity") from error


def update_policy(original, public_key, manifest_digest):
    """Add one ephemeral signed local update source without changing release trust."""
    digest_value(manifest_digest)
    require(original.get("default") == [{"type": "reject"}]
            and set(original.get("transports", {})) == {"docker"}
            and isinstance(public_key, bytes) and 0 < len(public_key) <= 65536
            and "insecureAcceptAnything" not in json.dumps(original),
            "unexpected enforcing release policy or fixture key")
    policy = copy.deepcopy(original)
    rule = [{
            "type": "signedBy",
            "keyType": "GPGKeys",
            "keyData": base64.b64encode(public_key).decode("ascii"),
            "signedIdentity": {
                "type": "exactReference",
                "dockerReference": "localhost/symbi-ci/development@" + manifest_digest,
            },
        }]
    policy["transports"]["dir"] = {
        UPDATE_SOURCE: copy.deepcopy(rule),
        NEGATIVE_UPDATE_SOURCE: copy.deepcopy(rule),
    }
    return policy


def update_command(source=UPDATE_SOURCE):
    if source not in (UPDATE_SOURCE, NEGATIVE_UPDATE_SOURCE):
        raise ValueError("fixed positive or negative update source required")
    return [*BOOTC_COMMAND, "switch", "--transport", "dir",
            "--enforce-container-sigpolicy", source]


def rollback_command():
    return [*BOOTC_COMMAND, "rollback"]


def negative_signature_payloads(directory, authentication):
    """Bind the four real-source controls emitted by the offline fixture signer."""
    directory = Path(directory)
    recorded = authentication.get("negative_source_signatures")
    require(isinstance(recorded, dict) and set(recorded) == set(NEGATIVE_CASES)
            and recorded.get("unsigned") is None,
            "negative source signature inventory is incomplete")
    result = {"unsigned": None}
    for case in NEGATIVE_CASES[1:]:
        digest = recorded.get(case)
        require(exact_hash(digest), "invalid negative source signature identity")
        path = directory / ("negative-" + case + "-signature-1")
        try:
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and 0 < info.st_size <= 65536,
                    "negative source signature is linked, special or oversized")
            payload = path.read_bytes()
        except OSError as error:
            raise ValueError("negative source signature is unavailable") from error
        require(hashlib.sha256(payload).hexdigest() == digest,
                "negative source signature bytes changed")
        result[case] = {
            "base64": base64.b64encode(payload).decode("ascii"),
            "sha256": digest,
        }
    return result


def require_update_base(config, pins, current):
    """Validate the retained predecessor without making it a release fallback."""
    try:
        require(type(config.get("schema")) is int and config["schema"] == 1
                and set(config) == {
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
        require(set(preflight) == {
                    "run_id", "source_commit", "inspect_sha256",
                    "prepare_sha256", "controller"
                }
                and type(preflight.get("run_id")) is int
                and preflight["run_id"] > 0
                and exact_hash(preflight.get("source_commit"), 40)
                and exact_hash(preflight.get("inspect_sha256"))
                and exact_hash(preflight.get("prepare_sha256")),
                "invalid retained predecessor preflight identity")
        validate_controller_identity(preflight["controller"])
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
    require(report.get("bootc_negative_controls") == NEGATIVE_CONTROLS
            and report.get("negative_overlays_discarded") is True,
            "native bootc signature refusals or overlay disposal are incomplete")
    positive = report.get("same_path_positive_control")
    require(isinstance(positive, dict) and positive.get("passed") is True
            and positive.get("overlay_discarded") is True
            and positive.get("negative_baselines_clean") is True
            and positive.get("source") == NEGATIVE_UPDATE_SOURCE
            and exact_hash(positive.get("report_sha256"))
            and exact_hash(positive.get("state_before_sha256"))
            and exact_hash(positive.get("state_after_sha256"))
            and positive["state_before_sha256"] != positive["state_after_sha256"],
            "same-path valid-signature acceptance or state disposal is incomplete")
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
        "same_path_signature_acceptance": True,
        "bootc_signature_rejections": True,
        "installed_digest": old_digest,
        "updated_digest": new_digest,
        "rolled_back_digest": old_digest,
    }
