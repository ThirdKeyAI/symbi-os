"""Validate the fail-closed pending Ubuntu fixture package input lock."""
import argparse
import json
from pathlib import Path
import tomllib

from image.container import ubuntu_fixture_packages as packages


LOCK_NAME = "ubuntu-fixture-packages.lock.json"
LOCK_SCOPE = (
    "Pending signed Ubuntu fixture package closure; no metadata payload, "
    "artifact, build, container, OS or release qualification"
)
CLAIM_FIELDS = (
    "selected", "qualified", "container_qualified", "signature_qualified",
    "os_qualified", "release_qualified",
)
LOCK_FIELDS = {
    "schema", "status", *CLAIM_FIELDS, "rootfs", "package_request", "sources",
    "fixture_source", "producer", "artifact", "release_metadata",
    "package_indexes", "package_count", "package_bytes", "packages", "scope",
}
PRODUCER_FIELDS = {"workflow", "run_id", "run_attempt", "head_sha"}
ARTIFACT_FIELDS = {"id", "name", "bytes", "sha256"}
FIXTURE_SOURCE_FIELDS = {
    "runtime_source_revision", "fixture_revision", "fixture_tree", "drivers",
}
EXPECTED_FIXTURE_SOURCE = {
    "runtime_source_revision": "deddb9e997244d2289c217ad76b8fde0e9b0339b",
    "fixture_revision": "cd4b34282ade880c8ac3d5136d31ff80cde92794",
    "fixture_tree": "2b2379d0de4eaaf4a57cf52c96355015bb3dc25d",
    "drivers": {
        "test-filesystem-grants.py": (
            "c5dc5d798c285f99e8db72b64d55749f127aa4139645425b7bd69d48dd7e9ded"
        ),
        "test-source-broker.py": (
            "ae2b6490cca43924e0f14aa84e71943c4684f298103db72b62eef534a16d1d2e"
        ),
        "test-git-source.py": (
            "82a02079c1a13799d03295e33ea4bc6f6120af7b8c4d25a840dcf023b4e0a075"
        ),
    },
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _validate_fixture_source(root, source):
    require(isinstance(source, dict) and set(source) == FIXTURE_SOURCE_FIELDS
            and source == EXPECTED_FIXTURE_SOURCE,
            "Ubuntu fixture runtime or reviewed driver source changed")
    runtime = tomllib.loads((root / "upstream/symbiont.toml").read_text())
    fixture = packages.unique_json(
        root / "image/container/native-fixture.lock.json")
    require(runtime.get("revision") == source["runtime_source_revision"]
            and fixture.get("revision") == source["fixture_revision"]
            and fixture.get("tree") == source["fixture_tree"]
            and fixture.get("drivers") == source["drivers"]
            and source["runtime_source_revision"] != source["fixture_revision"],
            "Ubuntu fixture source does not match the reviewed repository pins")
    return source


def validate_pending_lock(root, lock):
    """Accept only the committed empty pending slot; never imply readiness."""
    root = Path(root).resolve()
    require(isinstance(lock, dict) and set(lock) == LOCK_FIELDS,
            "Ubuntu fixture package lock fields changed")
    require(type(lock.get("schema")) is int and lock["schema"] == 1
            and lock.get("status") == "pending"
            and all(lock.get(field) is False for field in CLAIM_FIELDS),
            "Ubuntu fixture package lock is not fail-closed pending input")
    packages.validate_rootfs(lock.get("rootfs"))
    packages.validate_request(lock.get("package_request"))
    packages.validate_sources(lock.get("sources"))
    _validate_fixture_source(root, lock.get("fixture_source"))
    producer = lock.get("producer")
    artifact = lock.get("artifact")
    require(isinstance(producer, dict) and set(producer) == PRODUCER_FIELDS
            and producer == {
                "workflow": None, "run_id": None, "run_attempt": None,
                "head_sha": None,
            },
            "pending Ubuntu package lock contains producer identity")
    require(isinstance(artifact, dict) and set(artifact) == ARTIFACT_FIELDS
            and artifact == {
                "id": None, "name": packages.ARTIFACT_NAME,
                "bytes": None, "sha256": None,
            },
            "pending Ubuntu package lock contains artifact selection")
    require(lock.get("release_metadata") == []
            and lock.get("package_indexes") == []
            and lock.get("packages") == []
            and type(lock.get("package_count")) is int
            and lock["package_count"] == 0
            and type(lock.get("package_bytes")) is int
            and lock["package_bytes"] == 0,
            "pending Ubuntu package lock contains unverified payload rows")
    require(lock.get("scope") == LOCK_SCOPE,
            "Ubuntu fixture package lock scope changed")
    return {
        "ready": False,
        "status": "pending",
        "blocker": "offline-ubuntu-package-closure",
    }


def load_pending_lock(root):
    root = Path(root).resolve()
    lock = packages.unique_json(root / "image/container" / LOCK_NAME)
    validate_pending_lock(root, lock)
    return lock


def validate_artifact_for_use(root, lock, candidate, metadata):
    """Reject candidate selection while the reviewed lock remains pending."""
    validate_pending_lock(root, lock)
    packages.validate_candidate_artifact(candidate)
    packages.validate_artifact_metadata(metadata, candidate)
    raise ValueError(
        "pending Ubuntu fixture package closure cannot select or use an artifact"
    )


def require_mode(root, lock, mode):
    result = validate_pending_lock(root, lock)
    require(mode in {"check", "consume", "build", "materialize"},
            "unknown Ubuntu fixture package validator mode")
    if mode != "check":
        raise ValueError(
            "pending Ubuntu fixture package closure cannot " + mode
        )
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate the pending offline Ubuntu fixture package contract")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "mode", nargs="?", default="check",
        choices=("check", "consume", "build", "materialize"),
    )
    args = parser.parse_args(argv)
    try:
        lock = load_pending_lock(args.root)
        result = require_mode(args.root, lock, args.mode)
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        parser.exit(1, "Ubuntu fixture package input rejected: " + str(error) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
