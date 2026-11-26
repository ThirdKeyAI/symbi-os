#!/usr/bin/env python3
"""Validate a complete, immutable two-variant release evidence bundle.

This module performs offline structural and subject-binding checks.  It does
not create evidence, verify a cryptographic signature itself, sign an image, or
publish anything.  The protected workflow must supply reports produced by the
real native and cryptographic checks; absent or inconsistent reports fail.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


ROOT = Path(__file__).resolve().parents[2]
SOURCE_REPOSITORY = "https://github.com/ThirdKeyAI/symbi-os"
SOURCE_URI = "git+https://github.com/ThirdKeyAI/symbi-os"
VARIANTS = {"generic", "nvidia"}
EVIDENCE = {
    "spdx", "provenance", "cosign_signature", "cosign_attestation",
    "p0_03", "p0_04", "p0_05",
}
SHA256 = re.compile(r"[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
REPOSITORY = re.compile(
    r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?/"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"
)
INVOCATION = re.compile(r"https://github\.com/ThirdKeyAI/symbi-os/actions/runs/[1-9][0-9]*")
BUILD_TYPE = "https://thirdkey.ai/symbi-os/release-image/v1"
PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
QUALIFICATION_ORIGIN = "hosted-native-qualification"
PRODUCER_WORKFLOW = ".github/workflows/release-candidate.yml"
P0_03_CHECKS = {
    "signed_boot", "unsigned_rebase_rejected", "wrong_key_rejected",
    "wrong_repository_rejected", "altered_manifest_rejected",
    "plugin_constructor_refused", "rollback_booted", "smoke_suite_passed",
    "desktop_profile_passed",
}
P0_05_CHECKS = {
    "managed_gvisor_route", "runsc_explicit", "escape_suite",
    "daemon_boundary", "cleanup_confirmed",
}
SIGNATURE_CONTROLS = {
    "unsigned", "wrong_key", "wrong_repository", "altered_manifest",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest_path(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json_bytes(raw, description="JSON document"):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate key in {description}")
            result[key] = value
        return result

    try:
        document = json.loads(raw, object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"malformed {description}") from error
    require(isinstance(document, dict), f"{description} must be an object")
    return document


def read_json(path, *, maximum, description):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as error:
        raise ValueError(f"missing {description}") from error
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink(),
            f"{description} must be a regular unlinked file")
    require(0 < info.st_size <= maximum, f"{description} exceeds its size bound")
    return unique_json_bytes(path.read_bytes(), description)


def sha256_value(value, description):
    require(isinstance(value, str) and SHA256.fullmatch(value)
            and value != "0" * 64, f"nonzero SHA-256 required for {description}")
    return value


def commit_value(value, description="source commit"):
    require(isinstance(value, str) and COMMIT.fullmatch(value)
            and value != "0" * 40, f"full nonzero Git commit required for {description}")
    return value


def repository_value(value):
    require(isinstance(value, str) and REPOSITORY.fullmatch(value),
            "canonical lowercase image repository required")
    return value


def image_reference(value):
    require(isinstance(value, str) and value.count("@") == 1,
            "immutable image subject required")
    repository, image_digest = value.split("@", 1)
    repository_value(repository)
    require(image_digest.startswith("sha256:"), "SHA-256 image subject required")
    sha256_value(image_digest.removeprefix("sha256:"), "image subject")
    return repository, image_digest


def all_true(document, expected, description):
    require(isinstance(document, dict) and set(document) == expected
            and all(value is True for value in document.values()),
            f"complete successful {description} required")


def _configuration(value, default_path, description):
    if value is None:
        return read_json(default_path, maximum=1024 * 1024, description=description)
    require(isinstance(value, dict), f"{description} must be an object")
    return value


def _evidence_path(root, descriptor, name, seen):
    require(isinstance(descriptor, dict) and set(descriptor) == {"path", "sha256"},
            f"exact path and digest required for {name}")
    relative = descriptor["path"]
    require(isinstance(relative, str) and relative and "\\" not in relative,
            f"portable relative path required for {name}")
    relative_path = Path(relative)
    require(not relative_path.is_absolute() and ".." not in relative_path.parts
            and relative_path.parts[0] not in ("", "."),
            f"evidence path escapes the bundle for {name}")
    root = root.resolve(strict=True)
    candidate = root / relative_path
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"missing evidence file for {name}") from error
    require(resolved.is_relative_to(root) and resolved == candidate.absolute(),
            f"linked or escaping evidence file for {name}")
    require(resolved not in seen, "one evidence file cannot satisfy two release gates")
    seen.add(resolved)
    maximum = 32 * 1024 * 1024 if name == "spdx" else 4 * 1024 * 1024
    document = read_json(resolved, maximum=maximum, description=name)
    require(digest_path(resolved) == sha256_value(descriptor["sha256"], name),
            f"evidence digest mismatch for {name}")
    return document, resolved


def validate_spdx(document, repository, image_digest, subject):
    require(document.get("spdxVersion") == "SPDX-2.3"
            and document.get("dataLicense") == "CC0-1.0"
            and document.get("SPDXID") == "SPDXRef-DOCUMENT",
            "SPDX 2.3 document identity required")
    namespace = document.get("documentNamespace")
    require(isinstance(namespace, str) and namespace.startswith("https://")
            and image_digest in namespace, "SPDX namespace must bind the image digest")
    creation = document.get("creationInfo") or {}
    require(isinstance(creation.get("creators"), list) and creation["creators"]
            and all(isinstance(item, str) and item.startswith("Tool: ") for item in creation["creators"])
            and isinstance(creation.get("created"), str), "SPDX creation tool and time required")
    described = document.get("documentDescribes")
    require(isinstance(described, list) and len(described) == 1,
            "SPDX must describe exactly one primary image package")
    packages = document.get("packages")
    require(isinstance(packages, list) and packages, "SPDX package inventory required")
    matches = [item for item in packages if isinstance(item, dict)
               and item.get("SPDXID") == described[0]]
    require(len(matches) == 1, "SPDX primary image package is missing or duplicated")
    package = matches[0]
    required_checksum = {"algorithm": "SHA256", "checksumValue": image_digest[7:]}
    required_reference = {"referenceCategory": "OTHER", "referenceType": "symbi-os-image",
                          "referenceLocator": subject}
    require(package.get("name") == repository and package.get("versionInfo") == image_digest
            and package.get("primaryPackagePurpose") == "OPERATING-SYSTEM"
            and package.get("filesAnalyzed") is False
            and required_checksum in package.get("checksums", [])
            and required_reference in package.get("externalRefs", []),
            "SPDX primary package does not bind the exact image subject")


def validate_provenance(document, *, variant, repository, image_digest, base,
                        source_commit, release_tag, workflow_ref,
                        producer_run_id=None):
    require(document.get("_type") == STATEMENT_TYPE
            and document.get("predicateType") == PROVENANCE_TYPE,
            "SLSA provenance statement type required")
    subject = document.get("subject")
    expected_subject = [{"name": repository, "digest": {"sha256": image_digest[7:]}}]
    require(subject == expected_subject, "provenance subject does not match the image")
    predicate = document.get("predicate") or {}
    definition = predicate.get("buildDefinition") or {}
    require(definition.get("buildType") == BUILD_TYPE,
            "reviewed Symbi OS provenance build type required")
    parameters = definition.get("externalParameters")
    require(parameters == {"variant": variant, "releaseTag": release_tag,
                           "repository": repository},
            "provenance external parameters do not bind the release")
    dependencies = definition.get("resolvedDependencies")
    require(isinstance(dependencies, list), "provenance dependencies required")
    source_matches = [row for row in dependencies if isinstance(row, dict)
                      and row.get("uri") == SOURCE_URI
                      and row.get("digest") == {"gitCommit": source_commit}]
    base_repository, base_digest = image_reference(base)
    base_matches = [row for row in dependencies if isinstance(row, dict)
                    and row.get("uri") == base_repository
                    and row.get("digest") == {"sha256": base_digest[7:]}]
    require(len(dependencies) == 2 and len(source_matches) == 1
            and len(base_matches) == 1,
            "provenance must bind only one exact source and base dependency")
    details = predicate.get("runDetails") or {}
    require((details.get("builder") or {}).get("id") == workflow_ref,
            "provenance builder identity differs from the protected workflow")
    invocation = (details.get("metadata") or {}).get("invocationId")
    expected_invocation = None
    if producer_run_id is not None:
        expected_invocation = SOURCE_REPOSITORY + f"/actions/runs/{producer_run_id}"
    require(isinstance(invocation, str) and INVOCATION.fullmatch(invocation)
            and (expected_invocation is None or invocation == expected_invocation),
            "provenance invocation must identify the authenticated producer run")


def validate_cosign_tool(report, pins):
    tool = report.get("tool") or {}
    require(tool == {"name": "cosign", "version": pins.get("version"),
                     "source_revision": pins.get("source_revision")},
            "Cosign report does not identify the pinned verifier")


def validate_signature(report, *, subject, repository, image_digest,
                       public_key_sha256, cosign_pins):
    require(report.get("schema") == 1
            and report.get("kind") == "cosign-signature-verification"
            and report.get("verified") is True
            and report.get("subject") == subject
            and report.get("public_key_sha256") == public_key_sha256,
            "Cosign signature report does not bind the exact subject and key")
    validate_cosign_tool(report, cosign_pins)
    sha256_value(report.get("bundle_sha256"), "Cosign signature bundle")
    sha256_value(report.get("signature_payload_sha256"), "Cosign signature payload")
    all_true(report.get("negative_controls"), SIGNATURE_CONTROLS,
             "Cosign signature negative controls")
    signatures = report.get("verified_signatures")
    require(isinstance(signatures, list) and signatures,
            "Cosign verified signature output required")
    expected = {
        "type": "cosign container image signature",
        "identity": {"docker-reference": repository},
        "image": {"docker-manifest-digest": image_digest},
    }
    require(all(isinstance(row, dict) and row.get("critical") == expected
                for row in signatures), "Cosign verified signature subject mismatch")


def validate_attestation(report, *, subject, repository, image_digest,
                         public_key_sha256, provenance_sha256, cosign_pins):
    require(report.get("schema") == 1
            and report.get("kind") == "cosign-attestation-verification"
            and report.get("verified") is True
            and report.get("subject") == subject
            and report.get("public_key_sha256") == public_key_sha256
            and report.get("predicate_type") == PROVENANCE_TYPE
            and report.get("predicate_sha256") == provenance_sha256,
            "Cosign attestation report does not bind the provenance predicate")
    validate_cosign_tool(report, cosign_pins)
    sha256_value(report.get("bundle_sha256"), "Cosign attestation bundle")
    require(report.get("statement_subjects") == [
        {"name": repository, "digest": {"sha256": image_digest[7:]}}
    ], "Cosign attestation subject mismatch")


def validate_qualification(report, *, card, variant, subject, source_commit):
    require(report.get("schema") == 1 and report.get("card") == card
            and report.get("passed") is True and report.get("qualified") is True
            and report.get("os_qualified") is True
            and report.get("release_qualified") is True
            and report.get("guest_booted") is True
            and report.get("evidence_origin") == QUALIFICATION_ORIGIN
            and report.get("source_commit") == source_commit
            and report.get("variant") == variant
            and report.get("image_ref") == subject,
            f"{card} qualification is incomplete or bound to another source/image")
    if card == "P0-03":
        all_true(report.get("checks"), P0_03_CHECKS, "P0-03 release checks")
    elif card == "P0-04":
        commit_value(report.get("runtime_revision"), "P0-04 runtime revision")
        sha256_value(report.get("binary_sha256"), "P0-04 runtime binary")
        vertical = report.get("vertical_slice") or {}
        decisions = (vertical.get("cedar") or {}).get("decisions")
        journal = vertical.get("journal_before_effect") or {}
        require(vertical.get("passed") is True and isinstance(decisions, list)
                and len(decisions) == 2 and set(decisions) == {"allowed", "denied"}
                and type(journal.get("receiver_effects")) is int
                and journal["receiver_effects"] > 0
                and journal.get("independently_verified") is True,
                "P0-04 qualification lacks Cedar and journal-before-effect evidence")
    elif card == "P0-05":
        all_true(report.get("checks"), P0_05_CHECKS, "P0-05 gVisor checks")
    else:
        raise ValueError("unknown qualification card")


def validate_bundle(manifest_path, evidence_root, *, release_trust=None,
                    base_images=None, expected_purpose=None,
                    expected_source_commit=None, expected_tag=None,
                    expected_workflow_ref=None,
                    expected_gate_workflow_ref=None,
                    expected_producer_run_id=None, cosign_pins=None):
    evidence_root = Path(evidence_root)
    root = evidence_root.resolve(strict=True)
    require(root.is_dir(), "release evidence root must be a directory")
    supplied_manifest = Path(manifest_path)
    try:
        manifest_info = supplied_manifest.lstat()
    except OSError as error:
        raise ValueError("missing release evidence manifest") from error
    require(stat.S_ISREG(manifest_info.st_mode) and not supplied_manifest.is_symlink(),
            "release evidence manifest must be a regular unlinked file")
    manifest_path = supplied_manifest.resolve(strict=True)
    require(manifest_path.is_relative_to(root), "release manifest must be inside the evidence root")
    manifest = read_json(manifest_path, maximum=1024 * 1024,
                         description="release evidence manifest")
    trust = _configuration(release_trust, ROOT / "image/release-trust.json",
                           "release trust configuration")
    bases = _configuration(base_images, ROOT / "image/base-images.json",
                           "base image configuration")
    pins = _configuration(cosign_pins, ROOT / "image/toolchain/cosign.json",
                          "Cosign pin configuration")
    require(manifest.get("schema") == 1 and trust.get("schema") == 1
            and bases.get("schema") == 1 and pins.get("schema") == 1,
            "unsupported release evidence or configuration schema")
    purpose = manifest.get("purpose")
    require(purpose in ("release", "upstream-candidate")
            and (expected_purpose is None or purpose == expected_purpose),
            "unexpected release evidence purpose")
    release_tag = manifest.get("release_tag")
    if purpose == "release":
        require(isinstance(release_tag, str)
                and re.fullmatch(r"v[0-9][0-9A-Za-z._-]{0,63}", release_tag),
                "protected v* release tag required")
    else:
        require(isinstance(release_tag, str)
                and re.fullmatch(r"upstream-check-[1-9][0-9]*", release_tag),
                "bounded upstream candidate identifier required")
    require(expected_tag is None or release_tag == expected_tag,
            "release evidence tag differs from the workflow ref")
    if expected_producer_run_id is not None:
        require(type(expected_producer_run_id) is int
                and expected_producer_run_id > 0,
                "positive authenticated producer run ID required")
        if purpose == "upstream-candidate":
            require(release_tag == f"upstream-check-{expected_producer_run_id}",
                    "upstream candidate identifier differs from the authenticated run")
    source = manifest.get("source") or {}
    source_commit = commit_value(source.get("commit"))
    require(source.get("repository") == SOURCE_REPOSITORY
            and (expected_source_commit is None or source_commit == expected_source_commit),
            "release evidence source repository or commit mismatch")
    workflow_ref = manifest.get("workflow_ref")
    require(isinstance(workflow_ref, str)
            and (expected_workflow_ref is None or workflow_ref == expected_workflow_ref),
            "candidate builder workflow identity mismatch")
    gate_workflow_ref = manifest.get("gate_workflow_ref")
    require(isinstance(gate_workflow_ref, str)
            and (expected_gate_workflow_ref is None
                 or gate_workflow_ref == expected_gate_workflow_ref),
            "release gate workflow identity mismatch")
    if purpose == "release":
        require(workflow_ref == SOURCE_REPOSITORY +
                "/.github/workflows/release-candidate.yml@refs/tags/" + release_tag,
                "release evidence is not from the exact candidate builder tag")
        require(gate_workflow_ref == SOURCE_REPOSITORY +
                "/.github/workflows/release-images.yml@refs/tags/" + release_tag,
                "release gate workflow is not the protected tag identity")
    else:
        require(workflow_ref == SOURCE_REPOSITORY +
                "/.github/workflows/release-candidate.yml@refs/heads/main",
                "upstream evidence must come from the reviewed candidate builder")
        require(gate_workflow_ref == SOURCE_REPOSITORY +
                "/.github/workflows/upstream-check.yml@refs/heads/main",
                "upstream gate workflow identity mismatch")
    public_key_sha256 = sha256_value(manifest.get("public_key_sha256"),
                                     "release public key")
    require(public_key_sha256 == trust.get("public_key_sha256"),
            "release public key differs from the configured trust root")
    repositories = trust.get("repositories")
    variants = manifest.get("variants")
    require(isinstance(repositories, dict) and set(repositories) == VARIANTS
            and isinstance(variants, dict) and set(variants) == VARIANTS
            and isinstance(bases.get("variants"), dict)
            and set(bases["variants"]) == VARIANTS,
            "generic and NVIDIA variants are both required")
    seen = {manifest_path}
    subjects = {}
    for variant in sorted(VARIANTS):
        entry = variants[variant]
        require(isinstance(entry, dict), "variant release entry must be an object")
        repository = repository_value(repositories[variant])
        require(entry.get("repository") == repository, "release repository changed")
        subject = entry.get("subject")
        subject_repository, image_digest = image_reference(subject)
        require(subject_repository == repository, "release subject repository mismatch")
        base = bases["variants"][variant].get("image")
        image_reference(base)
        require(entry.get("base") == base, "release evidence uses another base image")
        evidence = entry.get("evidence")
        require(isinstance(evidence, dict) and set(evidence) == EVIDENCE,
                "all seven release evidence records are required")
        documents = {}
        paths = {}
        for name in sorted(EVIDENCE):
            documents[name], paths[name] = _evidence_path(
                root, evidence[name], f"{variant}/{name}", seen
            )
        validate_spdx(documents["spdx"], repository, image_digest, subject)
        validate_provenance(
            documents["provenance"], variant=variant, repository=repository,
            image_digest=image_digest, base=base, source_commit=source_commit,
            release_tag=release_tag, workflow_ref=workflow_ref,
            producer_run_id=expected_producer_run_id,
        )
        validate_signature(
            documents["cosign_signature"], subject=subject, repository=repository,
            image_digest=image_digest, public_key_sha256=public_key_sha256,
            cosign_pins=pins,
        )
        validate_attestation(
            documents["cosign_attestation"], subject=subject,
            repository=repository, image_digest=image_digest,
            public_key_sha256=public_key_sha256,
            provenance_sha256=digest_path(paths["provenance"]), cosign_pins=pins,
        )
        for card, name in (("P0-03", "p0_03"), ("P0-04", "p0_04"),
                           ("P0-05", "p0_05")):
            validate_qualification(documents[name], card=card, variant=variant,
                                   subject=subject, source_commit=source_commit)
        subjects[variant] = subject
    require(len(set(subjects.values())) == len(VARIANTS),
            "variants must have distinct image subjects")
    return {
        "schema": 1,
        "purpose": purpose,
        "release_tag": release_tag,
        "source_commit": source_commit,
        "workflow_ref": workflow_ref,
        "gate_workflow_ref": gate_workflow_ref,
        "producer_run_id": expected_producer_run_id,
        "subjects": subjects,
        "evidence_files": len(seen) - 1,
        "evidence_contract_satisfied": True,
        "release_qualified": False,
        "scope": (
            "Structural reconciliation only; authentic producer binding and "
            "cryptographic execution remain required"
        ),
    }


def validate_candidate_bases(candidate, current):
    require(isinstance(candidate, dict) and isinstance(current, dict)
            and candidate.get("schema") == 1 and current.get("schema") == 1,
            "unsupported candidate base schema")
    candidate_variants = candidate.get("variants")
    current_variants = current.get("variants")
    require(set(candidate) == set(current)
            and {key: value for key, value in candidate.items() if key != "variants"}
            == {key: value for key, value in current.items() if key != "variants"},
            "scheduled base updates cannot change top-level configuration")
    require(isinstance(candidate_variants, dict) and set(candidate_variants) == VARIANTS
            and isinstance(current_variants, dict) and set(current_variants) == VARIANTS,
            "candidate must contain both base variants")
    changed = []
    digests = set()
    for variant in sorted(VARIANTS):
        proposed = candidate_variants[variant]
        selected = current_variants[variant]
        require(isinstance(proposed, dict) and isinstance(selected, dict),
                "base variant must be an object")
        require(set(proposed) == set(selected),
                "scheduled base updates cannot add or remove trust fields")
        require(proposed.get("public_key") == selected.get("public_key")
                and proposed.get("public_key_sha256") == selected.get("public_key_sha256"),
                "scheduled base updates cannot change the trust root")
        selected_repository, _ = image_reference(selected.get("image"))
        proposed_repository, proposed_digest = image_reference(proposed.get("image"))
        require(proposed_repository == selected_repository,
                "scheduled base updates cannot change repositories")
        require(proposed_digest not in digests, "base variants cannot share one digest")
        digests.add(proposed_digest)
        if proposed["image"] != selected["image"]:
            changed.append(variant)
    require(changed, "candidate base document contains no digest update")
    return {"schema": 1, "changed_variants": changed,
            "candidate_images": {name: candidate_variants[name]["image"]
                                 for name in sorted(VARIANTS)}}


def validate_artifact_metadata(run, listing, *, run_id, artifact_name,
                               source_commit, source_ref,
                               producer_workflow=PRODUCER_WORKFLOW):
    """Bind one artifact to the reviewed successful producer workflow run."""
    require(type(run_id) is int and run_id > 0, "positive producer run ID required")
    require(isinstance(artifact_name, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", artifact_name),
            "bounded literal artifact name required")
    source_commit = commit_value(source_commit)
    require(isinstance(source_ref, str)
            and re.fullmatch(r"refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}",
                             source_ref)
            and ".." not in source_ref and "//" not in source_ref,
            "bounded branch or tag source ref required")
    source_name = source_ref.split("/", 2)[2]
    repository = run.get("head_repository") or {}
    repository_id = repository.get("id")
    require(run.get("id") == run_id and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and run.get("event") == "workflow_dispatch"
            and run.get("head_sha") == source_commit
            and run.get("head_branch") == source_name
            and run.get("path") == producer_workflow
            and repository.get("full_name") == "ThirdKeyAI/symbi-os"
            and type(repository_id) is int and repository_id > 0,
            "artifact producer is not the exact successful candidate workflow/source")
    count = listing.get("total_count")
    artifacts = listing.get("artifacts")
    require(type(count) is int and 0 < count <= 100
            and isinstance(artifacts, list) and len(artifacts) == count,
            "complete bounded artifact listing required")
    matches = [row for row in artifacts if isinstance(row, dict)
               and row.get("name") == artifact_name]
    require(len(matches) == 1, "one exact candidate evidence artifact required")
    artifact = matches[0]
    artifact_id = artifact.get("id")
    workflow_run = artifact.get("workflow_run") or {}
    artifact_digest = artifact.get("digest")
    require(type(artifact_id) is int and artifact_id > 0
            and type(artifact.get("size_in_bytes")) is int
            and 0 < artifact["size_in_bytes"] <= 20 * 1024**3
            and artifact.get("expired") is False
            and isinstance(artifact_digest, str)
            and artifact_digest.startswith("sha256:")
            and SHA256.fullmatch(artifact_digest[7:])
            and artifact_digest[7:] != "0" * 64
            and artifact.get("archive_download_url") ==
            f"https://api.github.com/repos/ThirdKeyAI/symbi-os/actions/artifacts/{artifact_id}/zip",
            "candidate artifact identity, digest, size, or lifetime is invalid")
    require(workflow_run.get("id") == run_id
            and workflow_run.get("head_sha") == source_commit
            and workflow_run.get("head_branch") == source_name
            and workflow_run.get("repository_id") == repository_id
            and workflow_run.get("head_repository_id") == repository_id,
            "candidate artifact is not bound to the expected producer run")
    return {"producer_run_id": run_id, "producer_workflow": producer_workflow,
            "artifact_id": artifact_id, "artifact_name": artifact_name,
            "artifact_digest": artifact_digest, "source_commit": source_commit,
            "source_ref": source_ref}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--expected-purpose", choices=("release", "upstream-candidate"), required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-tag")
    parser.add_argument("--expected-workflow-ref", required=True)
    parser.add_argument("--expected-gate-workflow-ref", required=True)
    parser.add_argument("--release-trust", type=Path, default=ROOT / "image/release-trust.json")
    parser.add_argument("--base-images", type=Path, default=ROOT / "image/base-images.json")
    parser.add_argument("--artifact-metadata", nargs=2, type=Path,
                        metavar=("RUN_JSON", "ARTIFACTS_JSON"))
    parser.add_argument("--artifact-run-id", type=int)
    parser.add_argument("--artifact-name")
    parser.add_argument("--artifact-source-ref")
    parser.add_argument("--producer-workflow", default=PRODUCER_WORKFLOW)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        origin = None
        if args.artifact_metadata:
            require(args.artifact_run_id and args.artifact_name
                    and args.artifact_source_ref,
                    "artifact run ID, name and source ref are required with metadata")
            origin = validate_artifact_metadata(
                read_json(args.artifact_metadata[0], maximum=1024 * 1024,
                          description="producer run metadata"),
                read_json(args.artifact_metadata[1], maximum=4 * 1024 * 1024,
                          description="producer artifact metadata"),
                run_id=args.artifact_run_id,
                artifact_name=args.artifact_name,
                source_commit=args.expected_source_commit,
                source_ref=args.artifact_source_ref,
                producer_workflow=args.producer_workflow,
            )
        else:
            require(args.artifact_run_id is None and args.artifact_name is None
                    and args.artifact_source_ref is None,
                    "artifact metadata must accompany artifact selectors")
        result = validate_bundle(
            args.manifest,
            args.evidence_root,
            release_trust=read_json(args.release_trust, maximum=1024 * 1024,
                                    description="release trust configuration"),
            base_images=read_json(args.base_images, maximum=1024 * 1024,
                                  description="base image configuration"),
            expected_purpose=args.expected_purpose,
            expected_source_commit=args.expected_source_commit,
            expected_tag=args.expected_tag,
            expected_workflow_ref=args.expected_workflow_ref,
            expected_gate_workflow_ref=args.expected_gate_workflow_ref,
            expected_producer_run_id=(origin or {}).get("producer_run_id"),
        )
        if origin:
            result["artifact_origin"] = origin
        rendered = json.dumps(result, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(args.output, flags, 0o644)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(rendered)
        print(rendered, end="")
    except (ValueError, OSError) as error:
        parser.exit(1, f"Release evidence refused: {error}\n")


if __name__ == "__main__":
    main()
