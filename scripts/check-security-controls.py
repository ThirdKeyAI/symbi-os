#!/usr/bin/env python3
"""Validate the OS-owned security catalogue and exact runtime evidence claims.

This standard-library-only checker treats tests and design models as source
references, never as runtime qualification. A validation claim must name a
repository-retained report whose digest, subject, scope and checks are exact.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


EXPECTED_IDS = tuple(f"OSI-{number:03d}" for number in range(1, 15))
CATALOGUE_FIELDS = {"schema_version", "scope", "controls"}
CONTROL_FIELDS = {
    "id",
    "title",
    "threat",
    "invariant",
    "owner",
    "implementation_status",
    "validation_status",
    "routes",
    "backends",
    "sources",
    "tests",
    "limitations",
    "qualifications",
}
QUALIFICATION_FIELDS = {"report", "sha256", "routes", "backends"}
REPORT_FIELDS = {
    "schema_version",
    "control_ids",
    "source_revision",
    "image_digest",
    "configuration_digest",
    "driver_sha256",
    "verifier_sha256",
    "platform",
    "timestamp",
    "routes",
    "backends",
    "checks",
    "passed",
    "errors",
}
SHA256 = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def object_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON field: {key}")
        value[key] = item
    return value


def load_json(path, label):
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=object_without_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid {label} JSON") from error


def string_list(value, label, *, required=False):
    require(isinstance(value, list), f"invalid {label}")
    require(
        all(
            isinstance(item, str)
            and item.strip() == item
            and item
            and all(ord(character) >= 32 and ord(character) != 127 for character in item)
            for item in value
        ),
        f"empty or malformed {label}",
    )
    require(len(value) == len(set(value)), f"duplicate {label}")
    if required:
        require(value, f"missing {label}")
    return value


def source_path(root, value):
    require(isinstance(value, str) and value, "empty source reference")
    path = PurePosixPath(value)
    require(
        not path.is_absolute() and ".." not in path.parts and "\\" not in value,
        "references must be portable repository-relative paths",
    )
    actual = (root / value).resolve(strict=True)
    require(actual.is_relative_to(root) and actual.is_file(), "reference is outside the source tree")
    return actual


def validate_report(root, control, reference):
    identity = control["id"]
    require(
        isinstance(reference, dict) and set(reference) == QUALIFICATION_FIELDS,
        f"{identity}: invalid qualification fields",
    )
    require(SHA256.fullmatch(reference.get("sha256", "")), f"{identity}: invalid report digest")
    routes = string_list(reference.get("routes"), f"{identity} qualification routes", required=True)
    backends = string_list(
        reference.get("backends"), f"{identity} qualification backends", required=True
    )
    require(set(routes) <= set(control["routes"]), f"{identity}: evidence route exceeds control scope")
    require(
        set(backends) <= set(control["backends"]),
        f"{identity}: evidence backend exceeds control scope",
    )

    path = source_path(root, reference.get("report"))
    require(
        hashlib.sha256(path.read_bytes()).hexdigest() == reference["sha256"],
        f"{identity}: qualification digest mismatch",
    )
    report = load_json(path, f"{identity} qualification report")
    require(isinstance(report, dict) and set(report) == REPORT_FIELDS, f"{identity}: invalid report fields")
    require(report["schema_version"] == 1 and type(report["schema_version"]) is int,
            f"{identity}: unsupported report schema")
    control_ids = string_list(report["control_ids"], f"{identity} report controls", required=True)
    require(identity in control_ids, f"{identity}: report does not cover this control")
    require(REVISION.fullmatch(report.get("source_revision", "")),
            f"{identity}: invalid source revision")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", report.get("image_digest", "")),
            f"{identity}: invalid image digest")
    for field in ("configuration_digest", "driver_sha256", "verifier_sha256"):
        require(SHA256.fullmatch(report.get(field, "")), f"{identity}: invalid {field}")
    require(isinstance(report.get("platform"), str) and report["platform"].strip(),
            f"{identity}: missing platform")
    require(TIMESTAMP.fullmatch(report.get("timestamp", "")), f"{identity}: invalid timestamp")
    report_routes = string_list(report["routes"], f"{identity} report routes", required=True)
    report_backends = string_list(
        report["backends"], f"{identity} report backends", required=True
    )
    require(set(routes) <= set(report_routes), f"{identity}: evidence route exceeds report scope")
    require(
        set(backends) <= set(report_backends),
        f"{identity}: evidence backend exceeds report scope",
    )
    require(isinstance(report["checks"], list) and report["checks"],
            f"{identity}: missing runtime checks")
    names = []
    for check in report["checks"]:
        require(
            isinstance(check, dict)
            and set(check) == {"name", "passed"}
            and isinstance(check["name"], str)
            and check["name"].strip()
            and type(check["passed"]) is bool,
            f"{identity}: invalid runtime check",
        )
        names.append(check["name"])
    require(len(names) == len(set(names)), f"{identity}: duplicate runtime check")
    errors = string_list(report["errors"], f"{identity} report errors")
    require(type(report["passed"]) is bool, f"{identity}: invalid report result")
    if report["passed"]:
        require(not errors and all(check["passed"] for check in report["checks"]),
                f"{identity}: passing report contains failed checks or errors")
    else:
        require(errors or any(not check["passed"] for check in report["checks"]),
                f"{identity}: failed report lacks a failure observation")
    return report["passed"], {(route, backend) for route in routes for backend in backends}


def validate_control(root, control):
    require(isinstance(control, dict) and set(control) == CONTROL_FIELDS, "invalid control fields")
    for field in ("id", "title", "threat", "invariant", "owner"):
        require(
            isinstance(control[field], str) and control[field].strip() == control[field]
            and control[field],
            f"missing or malformed {field}",
        )
    identity = control["id"]
    require(re.fullmatch(r"OSI-[0-9]{3}", identity), "invalid OS control ID")
    invariant_number = int(identity[-3:])
    require(
        control["invariant"].startswith(f"INV-{invariant_number}: "),
        f"{identity}: invariant mapping does not match its ID",
    )
    require(
        control["implementation_status"] in {"planned", "partial", "implemented"},
        f"{identity}: invalid implementation state",
    )
    require(
        control["validation_status"] in {"untested", "partial", "validated", "failed"},
        f"{identity}: invalid validation state",
    )
    routes = string_list(control["routes"], f"{identity} routes", required=True)
    backends = string_list(control["backends"], f"{identity} backends")
    sources = string_list(control["sources"], f"{identity} sources", required=True)
    tests = string_list(control["tests"], f"{identity} tests")
    string_list(control["limitations"], f"{identity} limitations", required=True)
    require(isinstance(control["qualifications"], list), f"{identity}: invalid qualifications")
    for reference in sources + tests:
        source_path(root, reference)

    if control["validation_status"] == "untested":
        require(
            not control["qualifications"],
            f"{identity}: untested control must not attach qualification evidence",
        )
    passed = False
    failed = False
    coverage = set()
    for reference in control["qualifications"]:
        report_passed, report_coverage = validate_report(root, control, reference)
        passed = passed or report_passed
        failed = failed or not report_passed
        if report_passed:
            coverage.update(report_coverage)

    if control["validation_status"] in {"partial", "validated"}:
        require(passed, f"{identity}: validation claim requires passing exact runtime evidence")
    if control["validation_status"] == "validated":
        expected = {(route, backend) for route in routes for backend in backends}
        require(expected and expected <= coverage,
                f"{identity}: validated claim exceeds qualification scope")
    if control["validation_status"] == "failed":
        require(failed, f"{identity}: failed status requires an exact failed runtime report")
    if control["implementation_status"] == "planned":
        require(control["validation_status"] == "untested",
                f"{identity}: planned control cannot be validated")
    if control["implementation_status"] == "implemented":
        require(passed, f"{identity}: implemented control requires passing exact runtime evidence")
    return passed


def validate(root, catalogue):
    require(isinstance(catalogue, dict) and set(catalogue) == CATALOGUE_FIELDS,
            "unknown catalogue field")
    require(catalogue["schema_version"] == 1 and type(catalogue["schema_version"]) is int,
            "unsupported catalogue schema")
    require(isinstance(catalogue["scope"], str) and catalogue["scope"].strip(),
            "missing catalogue scope")
    require(isinstance(catalogue["controls"], list), "invalid controls")
    identities = tuple(
        control.get("id") if isinstance(control, dict) else None
        for control in catalogue["controls"]
    )
    require(identities == EXPECTED_IDS, "catalogue must contain exactly OSI-001 through OSI-014 in order")
    for control in catalogue["controls"]:
        validate_control(root, control)
    return len(identities)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    catalogue = load_json(root / "docs/security/controls.json", "security catalogue")
    count = validate(root, catalogue)
    implementations = Counter(control["implementation_status"] for control in catalogue["controls"])
    validations = Counter(control["validation_status"] for control in catalogue["controls"])
    print(
        f"OS security catalogue valid: {count} controls; "
        f"implementation={dict(sorted(implementations.items()))}; "
        f"validation={dict(sorted(validations.items()))}"
    )


if __name__ == "__main__":
    main()
