#!/usr/bin/env python3
"""Stage a fully qualified base-digest update for review.

The scheduled workflow supplies an authenticated candidate base document and a
complete native release-evidence bundle.  This script only validates and copies
those bytes into a new staging directory.  It performs no discovery, build,
signature operation, Git write, or publication.
"""
import argparse
import json
from pathlib import Path
import shutil
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if __package__ in (None, ""):
    sys.path.insert(0, str(REPOSITORY_ROOT))
from image.release.contract import (ROOT, read_json, validate_bundle,
                                    validate_candidate_bases,
                                    validate_artifact_metadata)


def stage(candidate_path, current_path, manifest_path, evidence_root, output,
          *, source_commit, workflow_ref, gate_workflow_ref, artifact_run=None,
          artifact_listing=None, artifact_run_id=None,
          artifact_source_ref=None,
          artifact_name="symbi-os-upstream-candidate"):
    if artifact_run is None or artifact_listing is None:
        raise ValueError("authenticated artifact metadata documents are required")
    candidate_path = Path(candidate_path)
    current_path = Path(current_path)
    candidate = read_json(candidate_path, maximum=1024 * 1024,
                          description="candidate base configuration")
    current = read_json(current_path, maximum=1024 * 1024,
                        description="current base configuration")
    run = read_json(artifact_run, maximum=1024 * 1024,
                    description="producer run metadata")
    listing = read_json(artifact_listing, maximum=4 * 1024 * 1024,
                        description="producer artifact metadata")
    if artifact_run_id is None:
        artifact_run_id = run.get("id")
    origin = validate_artifact_metadata(
        run, listing, run_id=artifact_run_id,
        artifact_name=artifact_name, source_commit=source_commit,
        source_ref=artifact_source_ref,
    )
    change = validate_candidate_bases(candidate, current)
    evidence = validate_bundle(
        manifest_path,
        evidence_root,
        base_images=candidate,
        expected_purpose="upstream-candidate",
        expected_source_commit=source_commit,
        expected_workflow_ref=workflow_ref,
        expected_gate_workflow_ref=gate_workflow_ref,
        expected_producer_run_id=origin["producer_run_id"],
    )
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    shutil.copyfile(candidate_path, output / "base-images.json", follow_symlinks=False)
    result = {
        "schema": 1,
        "passed": True,
        "source_commit": source_commit,
        "changed_variants": change["changed_variants"],
        "candidate_images": change["candidate_images"],
        "qualified_subjects": evidence["subjects"],
        "artifact_origin": origin,
        "scope": "Review staging after complete candidate evidence reconciliation",
    }
    (output / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-base", type=Path, required=True)
    parser.add_argument("--current-base", type=Path, default=ROOT / "image/base-images.json")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--gate-workflow-ref", required=True)
    parser.add_argument("--artifact-metadata", nargs=2, type=Path, required=True,
                        metavar=("RUN_JSON", "ARTIFACTS_JSON"))
    parser.add_argument("--artifact-run-id", type=int)
    parser.add_argument("--artifact-source-ref", required=True)
    parser.add_argument("--artifact-name", default="symbi-os-upstream-candidate")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = stage(
            args.candidate_base, args.current_base, args.manifest,
            args.evidence_root, args.output,
            source_commit=args.source_commit, workflow_ref=args.workflow_ref,
            gate_workflow_ref=args.gate_workflow_ref,
            artifact_run=args.artifact_metadata[0],
            artifact_listing=args.artifact_metadata[1],
            artifact_run_id=args.artifact_run_id,
            artifact_source_ref=args.artifact_source_ref,
            artifact_name=args.artifact_name,
        )
        print(json.dumps(result, indent=2))
    except (ValueError, OSError) as error:
        parser.exit(1, f"Upstream candidate refused: {error}\n")


if __name__ == "__main__":
    main()
