"""Validate the installed-runtime policy and pre-effect journal vertical slice."""
import re


SHA256 = re.compile(r"[a-f0-9]{64}")
EFFECT_REJECTIONS = {
    "missing_case",
    "receiver_substitution",
    "approval_substitution",
    "resolution_substitution",
    "resolution_signature",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _case(report, name):
    rows = [row for row in report.get("cases", []) if row.get("name") == name]
    require(len(rows) == 1, "missing or duplicate " + name + " release case")
    return rows[0]


def _digest(value):
    return isinstance(value, str) and SHA256.fullmatch(value)


def validate_vertical_slice(release, managed, effects, integrity, binary_hash, drivers):
    """Require an explicit Cedar allow/deny pair and independently verified effects.

    The pinned upstream drivers do the behavioral work. This validator binds their
    detailed public reports to the exact installed binary and refuses summaries
    that omit either side of the proof.
    """
    require(_digest(binary_hash), "invalid installed runtime binary digest")
    require(release.get("passed") is True and release.get("binary_sha256") == binary_hash,
            "release result describes a different binary")

    managed_row = _case(release, "managed")
    require(managed_row.get("passed") is True and managed_row.get("exit_code") == 0,
            "managed Cedar release case did not pass")
    require(managed_row.get("driver") == "test-landlock-managed.py"
            and managed_row.get("driver_sha256") == drivers.get("managed"),
            "managed driver differs from the pinned source")
    require(managed.get("passed") is True and managed.get("binary_sha256") == binary_hash,
            "managed Cedar result describes a different binary")
    cases = managed.get("cases", [])
    require([row.get("name") for row in cases] == ["allowed", "denied"],
            "Cedar allow/deny decisions are incomplete or reordered")
    journals = []
    for row in cases:
        require(row.get("passed") is True and row.get("exit_code") == 0,
                "Cedar allow/deny case did not pass")
        require(len(row.get("provider_requests", [])) == 2,
                "managed Cedar case did not complete its bounded inference route")
        journal = row.get("journal", {})
        require(_digest(journal.get("sha256")) and _digest(journal.get("public_key")),
                "managed Cedar case lacks a signed journal identity")
        journals.append({"decision": row["name"], "sha256": journal["sha256"],
                         "public_key": journal["public_key"]})

    effect_row = _case(release, "external-effects")
    require(effect_row.get("passed") is True and effect_row.get("exit_code") == 0
            and effect_row.get("verification_exit_code") == 0
            and effect_row.get("integrity_exit_code") == 0,
            "external-effect release case did not pass independent checks")
    require(effect_row.get("driver") == "test-external-effect-recovery.py"
            and effect_row.get("driver_sha256") == drivers.get("external_effects")
            and effect_row.get("verifier_sha256") == drivers.get("external_effects_verifier")
            and effect_row.get("integrity_sha256") == drivers.get("external_effects_integrity"),
            "external-effect drivers differ from the pinned source")
    require(effects.get("passed") is True and effects.get("complete_suite") is True
            and effects.get("cases") == 5 and effects.get("receiver_effects") == 5
            and effects.get("binary_sha256") == binary_hash
            and _digest(effects.get("manifest_sha256")),
            "journal-before-effect verification is incomplete or bound to another binary")
    require(integrity.get("passed") is True and integrity.get("original_cases") == 5
            and set(integrity.get("rejected", [])) == EFFECT_REJECTIONS
            and integrity.get("optimization_refused") is True,
            "journal-before-effect integrity controls are incomplete")

    return {
        "schema": 1,
        "passed": True,
        "runtime_binary_sha256": binary_hash,
        "cedar": {
            "enforced": True,
            "decisions": ["allowed", "denied"],
            "signed_journals": journals,
            "driver_sha256": drivers["managed"],
        },
        "journal_before_effect": {
            "enforced": True,
            "independently_verified": True,
            "receiver_effects": 5,
            "manifest_sha256": effects["manifest_sha256"],
            "driver_sha256": drivers["external_effects"],
            "verifier_sha256": drivers["external_effects_verifier"],
            "integrity_sha256": drivers["external_effects_integrity"],
        },
        "scope": "Pinned upstream runtime in the authenticated installed development image; synthetic provider and service only",
    }
