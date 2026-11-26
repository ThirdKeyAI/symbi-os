"""Fail-closed release-evidence and workflow acceptance tests.

The generated documents are synthetic schema fixtures.  Passing these tests is
not image, signature, boot, rollback, or sandbox qualification evidence.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest

import yaml

from image.release.contract import (validate_artifact_metadata, validate_bundle,
                                    validate_candidate_bases)
from image.release.upstream import stage as stage_upstream


ROOT = Path(__file__).resolve().parents[2]
HEX40 = "1" * 40
PUBLIC_KEY_SHA256 = "f95a39bcd37e640d179a1f8f2cb2baeb44162e8d19f5b75e0fe1553f3ef777ac"
BUILDER_WORKFLOW = (
    "https://github.com/ThirdKeyAI/symbi-os/.github/workflows/"
    "release-candidate.yml@refs/tags/v0.1.0"
)
GATE_WORKFLOW = (
    "https://github.com/ThirdKeyAI/symbi-os/.github/workflows/"
    "release-images.yml@refs/tags/v0.1.0"
)
REPOSITORIES = {
    "generic": "ghcr.io/thirdkeyai/symbiont-os",
    "nvidia": "ghcr.io/thirdkeyai/symbiont-os-nvidia",
}
BASES = {
    "generic": (
        "ghcr.io/secureblue/sericea-main-hardened@sha256:" + "a" * 64
    ),
    "nvidia": (
        "ghcr.io/secureblue/sericea-nvidia-hardened@sha256:" + "b" * 64
    ),
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Bundle:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.documents = {}
        self.manifest = {
            "schema": 1,
            "purpose": "release",
            "release_tag": "v0.1.0",
            "source": {
                "repository": "https://github.com/ThirdKeyAI/symbi-os",
                "commit": HEX40,
            },
            "workflow_ref": BUILDER_WORKFLOW,
            "gate_workflow_ref": GATE_WORKFLOW,
            "public_key_sha256": PUBLIC_KEY_SHA256,
            "variants": {},
        }
        for index, variant in enumerate(("generic", "nvidia"), 2):
            digest = f"sha256:{str(index) * 64}"
            repository = REPOSITORIES[variant]
            subject = f"{repository}@{digest}"
            directory = self.root / variant
            directory.mkdir()
            spdx = {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "documentNamespace": f"https://thirdkey.ai/symbi-os/sbom/{digest}",
                "creationInfo": {
                    "creators": ["Tool: pinned-sbom-generator"],
                    "created": "2026-11-26T00:00:00Z",
                },
                "name": f"symbi-os-{variant}-{digest}",
                "documentDescribes": ["SPDXRef-OS-image"],
                "packages": [{
                    "name": repository,
                    "SPDXID": "SPDXRef-OS-image",
                    "versionInfo": digest,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "primaryPackagePurpose": "OPERATING-SYSTEM",
                    "checksums": [{
                        "algorithm": "SHA256", "checksumValue": digest.removeprefix("sha256:")
                    }],
                    "externalRefs": [{
                        "referenceCategory": "OTHER",
                        "referenceType": "symbi-os-image",
                        "referenceLocator": subject,
                    }],
                }],
            }
            provenance = {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": repository, "digest": {"sha256": digest[7:]}}],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "buildType": "https://thirdkey.ai/symbi-os/release-image/v1",
                        "externalParameters": {
                            "variant": variant,
                            "releaseTag": "v0.1.0",
                            "repository": repository,
                        },
                        "resolvedDependencies": [
                            {"uri": "git+https://github.com/ThirdKeyAI/symbi-os",
                             "digest": {"gitCommit": HEX40}},
                            {"uri": BASES[variant].split("@", 1)[0],
                             "digest": {"sha256": BASES[variant].rsplit(":", 1)[1]}},
                        ],
                    },
                    "runDetails": {
                        "builder": {"id": BUILDER_WORKFLOW},
                        "metadata": {
                            "invocationId": "https://github.com/ThirdKeyAI/symbi-os/actions/runs/123"
                        },
                    },
                },
            }
            self.write(variant, "spdx", "sbom.spdx.json", spdx)
            provenance_path = self.write(variant, "provenance", "provenance.json", provenance)
            common_verification = {
                "schema": 1,
                "verified": True,
                "subject": subject,
                "public_key_sha256": PUBLIC_KEY_SHA256,
                "tool": {"name": "cosign", "version": "v3.1.5",
                         "source_revision": "e5a0818ca5729481095773409e9c1b60cc278e8d"},
                "bundle_sha256": "c" * 64,
            }
            signature = {
                **common_verification,
                "kind": "cosign-signature-verification",
                "signature_payload_sha256": "d" * 64,
                "verified_signatures": [{
                    "critical": {
                        "type": "cosign container image signature",
                        "identity": {"docker-reference": repository},
                        "image": {"docker-manifest-digest": digest},
                    }
                }],
                "negative_controls": {
                    "unsigned": True,
                    "wrong_key": True,
                    "wrong_repository": True,
                    "altered_manifest": True,
                },
            }
            attestation = {
                **common_verification,
                "kind": "cosign-attestation-verification",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "predicate_sha256": sha256(provenance_path),
                "statement_subjects": [{"name": repository, "digest": {"sha256": digest[7:]}}],
            }
            p0_03 = self.qualification(variant, subject, "P0-03")
            p0_03["checks"] = {
                "signed_boot": True,
                "unsigned_rebase_rejected": True,
                "wrong_key_rejected": True,
                "wrong_repository_rejected": True,
                "altered_manifest_rejected": True,
                "plugin_constructor_refused": True,
                "rollback_booted": True,
                "smoke_suite_passed": True,
                "desktop_profile_passed": True,
            }
            p0_04 = self.qualification(variant, subject, "P0-04")
            p0_04.update(
                runtime_revision="4" * 40,
                binary_sha256="5" * 64,
                vertical_slice={
                    "passed": True,
                    "cedar": {"decisions": ["allowed", "denied"]},
                    "journal_before_effect": {
                        "receiver_effects": 5, "independently_verified": True
                    },
                },
            )
            p0_05 = self.qualification(variant, subject, "P0-05")
            p0_05["checks"] = {
                "managed_gvisor_route": True,
                "runsc_explicit": True,
                "escape_suite": True,
                "daemon_boundary": True,
                "cleanup_confirmed": True,
            }
            self.write(variant, "cosign_signature", "cosign-signature.json", signature)
            self.write(variant, "cosign_attestation", "cosign-attestation.json", attestation)
            self.write(variant, "p0_03", "p0-03.json", p0_03)
            self.write(variant, "p0_04", "p0-04.json", p0_04)
            self.write(variant, "p0_05", "p0-05.json", p0_05)
            self.manifest["variants"][variant] = {
                "repository": repository,
                "subject": subject,
                "base": BASES[variant],
                "evidence": self.documents[variant],
            }
        self.path = self.root / "manifest.json"
        self.save()

    def qualification(self, variant, subject, card):
        return {
            "schema": 1,
            "card": card,
            "passed": True,
            "qualified": True,
            "os_qualified": True,
            "release_qualified": True,
            "guest_booted": True,
            "evidence_origin": "hosted-native-qualification",
            "source_commit": HEX40,
            "variant": variant,
            "image_ref": subject,
        }

    def write(self, variant, name, filename, document):
        path = self.root / variant / filename
        path.write_text(json.dumps(document, indent=2) + "\n")
        self.documents.setdefault(variant, {})[name] = {
            "path": str(path.relative_to(self.root)), "sha256": sha256(path)
        }
        return path

    def document(self, variant, name):
        descriptor = self.manifest["variants"][variant]["evidence"][name]
        return self.root / descriptor["path"]

    def rewrite(self, variant, name, document, *, update_hash=True):
        path = self.document(variant, name)
        path.write_text(json.dumps(document, indent=2) + "\n")
        if update_hash:
            self.manifest["variants"][variant]["evidence"][name]["sha256"] = sha256(path)
        self.save()

    def save(self):
        self.path.write_text(json.dumps(self.manifest, indent=2) + "\n")

    def make_upstream(self):
        workflow = (
            "https://github.com/ThirdKeyAI/symbi-os/.github/workflows/"
            "release-candidate.yml@refs/heads/main"
        )
        self.manifest.update(
            purpose="upstream-candidate",
            release_tag="upstream-check-123",
            workflow_ref=workflow,
            gate_workflow_ref=(
                "https://github.com/ThirdKeyAI/symbi-os/.github/workflows/"
                "upstream-check.yml@refs/heads/main"
            ),
        )
        for variant in ("generic", "nvidia"):
            provenance = json.loads(self.document(variant, "provenance").read_text())
            definition = provenance["predicate"]["buildDefinition"]
            definition["externalParameters"]["releaseTag"] = "upstream-check-123"
            provenance["predicate"]["runDetails"]["builder"]["id"] = workflow
            self.rewrite(variant, "provenance", provenance)
            attestation = json.loads(self.document(variant, "cosign_attestation").read_text())
            attestation["predicate_sha256"] = sha256(self.document(variant, "provenance"))
            self.rewrite(variant, "cosign_attestation", attestation)
        self.save()
        return workflow


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = Bundle(self.root)
        self.bases = {"schema": 1, "variants": {
            variant: {"image": image, "public_key": "image/keys/secureblue-2026.pub",
                      "public_key_sha256": "9" * 64}
            for variant, image in BASES.items()
        }}
        self.trust = {"schema": 1, "repositories": REPOSITORIES,
                      "public_key_sha256": PUBLIC_KEY_SHA256}

    def validate(self):
        return validate_bundle(
            self.bundle.path,
            self.root,
            release_trust=self.trust,
            base_images=self.bases,
            expected_purpose="release",
            expected_source_commit=HEX40,
            expected_tag="v0.1.0",
            expected_workflow_ref=BUILDER_WORKFLOW,
            expected_gate_workflow_ref=GATE_WORKFLOW,
        )

    def test_complete_two_variant_bundle_passes(self):
        result = self.validate()
        self.assertEqual(result["source_commit"], HEX40)
        self.assertEqual(set(result["subjects"]), {"generic", "nvidia"})
        self.assertTrue(result["evidence_contract_satisfied"])
        self.assertFalse(result["release_qualified"])

    def test_upstream_candidate_uses_the_reviewed_builder_identity(self):
        workflow = self.bundle.make_upstream()
        result = validate_bundle(
            self.bundle.path,
            self.root,
            release_trust=self.trust,
            base_images=self.bases,
            expected_purpose="upstream-candidate",
            expected_source_commit=HEX40,
            expected_workflow_ref=workflow,
            expected_gate_workflow_ref=(
                "https://github.com/ThirdKeyAI/symbi-os/.github/workflows/"
                "upstream-check.yml@refs/heads/main"
            ),
        )
        self.assertEqual(result["release_tag"], "upstream-check-123")
        self.bundle.manifest["workflow_ref"] = (
            "https://github.com/ThirdKeyAI/symbi-os/.github/workflows/"
            "upstream-check.yml@refs/heads/main"
        )
        self.bundle.save()
        with self.assertRaisesRegex(ValueError, "candidate builder"):
            validate_bundle(
                self.bundle.path, self.root, release_trust=self.trust,
                base_images=self.bases, expected_purpose="upstream-candidate",
                expected_source_commit=HEX40,
            )

    def test_authenticated_run_id_binds_invocation_and_candidate_identifier(self):
        result = validate_bundle(
            self.bundle.path, self.root, release_trust=self.trust,
            base_images=self.bases, expected_purpose="release",
            expected_source_commit=HEX40,
            expected_workflow_ref=BUILDER_WORKFLOW,
            expected_gate_workflow_ref=GATE_WORKFLOW,
            expected_producer_run_id=123,
        )
        self.assertTrue(result["evidence_contract_satisfied"])

        provenance = json.loads(
            self.bundle.document("generic", "provenance").read_text()
        )
        provenance["predicate"]["runDetails"]["metadata"]["invocationId"] = (
            "https://github.com/ThirdKeyAI/symbi-os/actions/runs/124"
        )
        self.bundle.rewrite("generic", "provenance", provenance)
        attestation = json.loads(
            self.bundle.document("generic", "cosign_attestation").read_text()
        )
        attestation["predicate_sha256"] = sha256(
            self.bundle.document("generic", "provenance")
        )
        self.bundle.rewrite("generic", "cosign_attestation", attestation)
        with self.assertRaisesRegex(ValueError, "invocation"):
            validate_bundle(
                self.bundle.path, self.root, release_trust=self.trust,
                base_images=self.bases, expected_purpose="release",
                expected_source_commit=HEX40,
                expected_producer_run_id=123,
            )

        self.bundle = Bundle(self.root / "upstream-run-binding")
        workflow = self.bundle.make_upstream()
        self.bundle.manifest["release_tag"] = "upstream-check-124"
        self.bundle.save()
        with self.assertRaisesRegex(ValueError, "candidate identifier"):
            validate_bundle(
                self.bundle.path, self.bundle.root,
                release_trust=self.trust, base_images=self.bases,
                expected_purpose="upstream-candidate",
                expected_source_commit=HEX40,
                expected_workflow_ref=workflow,
                expected_producer_run_id=123,
            )

    def test_candidate_builder_and_consumer_gate_are_distinct_and_exact(self):
        self.bundle.manifest["gate_workflow_ref"] = BUILDER_WORKFLOW
        self.bundle.save()
        with self.assertRaisesRegex(ValueError, "gate workflow"):
            self.validate()

        self.bundle.manifest["gate_workflow_ref"] = GATE_WORKFLOW
        self.bundle.manifest["workflow_ref"] = GATE_WORKFLOW
        self.bundle.save()
        for variant in ("generic", "nvidia"):
            provenance = json.loads(
                self.bundle.document(variant, "provenance").read_text()
            )
            provenance["predicate"]["runDetails"]["builder"]["id"] = GATE_WORKFLOW
            self.bundle.rewrite(variant, "provenance", provenance)
            attestation = json.loads(
                self.bundle.document(variant, "cosign_attestation").read_text()
            )
            attestation["predicate_sha256"] = sha256(
                self.bundle.document(variant, "provenance")
            )
            self.bundle.rewrite(variant, "cosign_attestation", attestation)
        with self.assertRaisesRegex(ValueError, "candidate builder"):
            self.validate()

    def test_linked_release_manifest_is_refused(self):
        alias = self.root / "linked-manifest.json"
        alias.symlink_to(self.bundle.path.name)
        with self.assertRaisesRegex(ValueError, "manifest"):
            validate_bundle(
                alias, self.root, release_trust=self.trust,
                base_images=self.bases, expected_purpose="release",
                expected_source_commit=HEX40,
            )

    def test_every_evidence_blob_is_hash_bound_and_unlinked(self):
        path = self.bundle.document("generic", "p0_03")
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "digest"):
            self.validate()

    def test_both_exact_variant_repositories_are_required(self):
        self.bundle.manifest["variants"].pop("nvidia")
        self.bundle.save()
        with self.assertRaisesRegex(ValueError, "variants"):
            self.validate()

    def test_spdx_subject_mismatch_fails(self):
        path = self.bundle.document("generic", "spdx")
        document = json.loads(path.read_text())
        document["packages"][0]["checksums"][0]["checksumValue"] = "0" * 64
        self.bundle.rewrite("generic", "spdx", document)
        with self.assertRaisesRegex(ValueError, "SPDX"):
            self.validate()

    def test_provenance_must_bind_source_base_builder_and_subject(self):
        mutations = [
            ("subject", lambda d: d["subject"][0]["digest"].update(sha256="0" * 64)),
            ("source", lambda d: d["predicate"]["buildDefinition"]["resolvedDependencies"][0]
             ["digest"].update(gitCommit="0" * 40)),
            ("base", lambda d: d["predicate"]["buildDefinition"]["resolvedDependencies"][1]
             ["digest"].update(sha256="0" * 64)),
            ("builder", lambda d: d["predicate"]["runDetails"]["builder"].update(id="other")),
            ("extra_dependency", lambda d: d["predicate"]["buildDefinition"]
             ["resolvedDependencies"].append({"uri": "other", "digest": {"sha256": "0" * 64}})),
        ]
        original = json.loads(self.bundle.document("generic", "provenance").read_text())
        for name, mutate in mutations:
            with self.subTest(name=name):
                document = copy.deepcopy(original)
                mutate(document)
                self.bundle.rewrite("generic", "provenance", document)
                # Keep the attestation's predicate digest synchronized so the
                # test reaches the semantic provenance check.
                attestation = json.loads(self.bundle.document("generic", "cosign_attestation").read_text())
                attestation["predicate_sha256"] = sha256(self.bundle.document("generic", "provenance"))
                self.bundle.rewrite("generic", "cosign_attestation", attestation)
                with self.assertRaisesRegex(ValueError, "provenance"):
                    self.validate()
        self.bundle.rewrite("generic", "provenance", original)

    def test_cosign_reports_require_exact_subject_key_predicate_and_controls(self):
        cases = [
            ("cosign_signature", "subject", "wrong"),
            ("cosign_signature", "public_key_sha256", "0" * 64),
            ("cosign_signature", "negative_controls", {"unsigned": True}),
            ("cosign_attestation", "predicate_sha256", "0" * 64),
        ]
        for index, (name, key, value) in enumerate(cases):
            with self.subTest(name=name, key=key):
                path = self.bundle.document("generic", name)
                document = json.loads(path.read_text())
                old = document[key]
                document[key] = value
                self.bundle.rewrite("generic", name, document)
                with self.assertRaisesRegex(ValueError, "Cosign"):
                    self.validate()
                document[key] = old
                self.bundle.rewrite("generic", name, document)

    def test_all_three_native_qualifications_bind_source_and_image(self):
        for name in ("p0_03", "p0_04", "p0_05"):
            with self.subTest(name=name):
                path = self.bundle.document("nvidia", name)
                document = json.loads(path.read_text())
                document["source_commit"] = "0" * 40
                self.bundle.rewrite("nvidia", name, document)
                with self.assertRaisesRegex(ValueError, "qualification"):
                    self.validate()
                document["source_commit"] = HEX40
                self.bundle.rewrite("nvidia", name, document)

    def test_p0_specific_gates_cannot_be_replaced_by_generic_pass(self):
        for name, mutation in [
            ("p0_03", lambda d: d["checks"].update(rollback_booted=False)),
            ("p0_04", lambda d: d["vertical_slice"]["cedar"].update(decisions=["allowed"])),
            ("p0_05", lambda d: d["checks"].update(escape_suite=False)),
        ]:
            with self.subTest(name=name):
                path = self.bundle.document("generic", name)
                document = json.loads(path.read_text())
                mutation(document)
                self.bundle.rewrite("generic", name, document)
                with self.assertRaises(ValueError):
                    self.validate()
                self.bundle = Bundle(self.root / (name + "-reset"))
                self.root = self.bundle.root


class CandidateBaseTests(unittest.TestCase):
    def setUp(self):
        self.current = {"schema": 1, "status": "verified", "variants": {
            variant: {"image": image, "public_key": "image/keys/secureblue-2026.pub",
                      "public_key_sha256": "9" * 64}
            for variant, image in BASES.items()
        }}

    def test_candidate_changes_only_digests_and_preserves_trust(self):
        candidate = copy.deepcopy(self.current)
        candidate["variants"]["generic"]["image"] = (
            BASES["generic"].split("@", 1)[0] + "@sha256:" + "e" * 64
        )
        result = validate_candidate_bases(candidate, self.current)
        self.assertEqual(result["changed_variants"], ["generic"])

    def test_unchanged_mutable_or_rekeyed_candidate_fails(self):
        candidates = [copy.deepcopy(self.current) for _ in range(4)]
        candidates[1]["variants"]["generic"]["image"] = (
            BASES["generic"].split("@", 1)[0] + ":latest"
        )
        candidates[2]["variants"]["generic"].update(
            image=BASES["generic"].split("@", 1)[0] + "@sha256:" + "e" * 64,
            public_key_sha256="0" * 64,
        )
        candidates[3]["status"] = "unreviewed"
        candidates[3]["variants"]["generic"]["image"] = (
            BASES["generic"].split("@", 1)[0] + "@sha256:" + "e" * 64
        )
        for candidate in candidates:
            with self.assertRaises(ValueError):
                validate_candidate_bases(candidate, self.current)


class ArtifactOriginTests(unittest.TestCase):
    def setUp(self):
        self.run = {
            "id": 123,
            "status": "completed",
            "conclusion": "success",
            "event": "workflow_dispatch",
            "head_sha": HEX40,
            "head_branch": "v0.1.0",
            "path": ".github/workflows/release-candidate.yml",
            "head_repository": {"full_name": "ThirdKeyAI/symbi-os", "id": 77},
        }
        self.artifacts = {
            "total_count": 1,
            "artifacts": [{
                "id": 456,
                "name": "symbi-os-release-evidence",
                "size_in_bytes": 123456,
                "expired": False,
                "digest": "sha256:" + "f" * 64,
                "archive_download_url": (
                    "https://api.github.com/repos/ThirdKeyAI/symbi-os/actions/artifacts/456/zip"
                ),
                "workflow_run": {
                    "id": 123, "head_sha": HEX40, "head_branch": "v0.1.0",
                    "repository_id": 77, "head_repository_id": 77,
                },
            }],
        }

    def validate(self):
        return validate_artifact_metadata(
            self.run, self.artifacts, run_id=123,
            artifact_name="symbi-os-release-evidence",
            source_commit=HEX40,
            source_ref="refs/tags/v0.1.0",
        )

    def test_exact_successful_candidate_workflow_artifact_passes(self):
        result = self.validate()
        self.assertEqual(result["artifact_id"], 456)
        self.assertEqual(result["artifact_digest"], "sha256:" + "f" * 64)

    def test_wrong_workflow_source_or_artifact_binding_fails(self):
        mutations = [
            (self.run, "path", ".github/workflows/ci.yml"),
            (self.run, "conclusion", "failure"),
            (self.run, "head_sha", "0" * 40),
            (self.run, "head_branch", "main"),
            (self.artifacts["artifacts"][0], "expired", True),
            (self.artifacts["artifacts"][0]["workflow_run"], "id", 999),
            (self.artifacts["artifacts"][0]["workflow_run"], "head_branch", "main"),
            (self.artifacts["artifacts"][0], "digest", None),
        ]
        for target, key, value in mutations:
            with self.subTest(key=key, value=value):
                old = target[key]
                target[key] = value
                with self.assertRaises(ValueError):
                    self.validate()
                target[key] = old

    def test_upstream_staging_requires_authenticated_artifact_metadata(self):
        with self.assertRaisesRegex(ValueError, "artifact metadata"):
            stage_upstream(
                Path("candidate.json"), Path("current.json"),
                Path("manifest.json"), Path("."), Path("output"),
                source_commit=HEX40, workflow_ref="builder",
                gate_workflow_ref="gate",
                artifact_source_ref="refs/heads/main",
            )


class WorkflowContractTests(unittest.TestCase):
    def load(self, name):
        return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())

    def test_release_workflow_is_protected_tag_evidence_gate_without_publish_authority(self):
        document = self.load("release-images.yml")
        self.assertIn("workflow_dispatch", document[True])
        self.assertEqual(document["permissions"], {"contents": "read", "actions": "read"})
        job = document["jobs"]["verify-release-evidence"]
        self.assertEqual(job["environment"]["name"], "symbi-os-release")
        self.assertIn("refs/tags/v", job["if"])
        text = (ROOT / ".github/workflows/release-images.yml").read_text()
        self.assertIn("actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5", text)
        self.assertIn("actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333", text)
        self.assertIn("--artifact-metadata", text)
        self.assertIn("--producer-workflow .github/workflows/release-candidate.yml", text)
        self.assertIn("--expected-gate-workflow-ref", text)
        self.assertIn("image/release/contract.py", text)
        for forbidden in ("packages: write", "id-token: write", "COSIGN_PRIVATE_KEY", " cosign sign", " podman push"):
            self.assertNotIn(forbidden, text)

    def test_manual_upstream_pr_requires_full_candidate_evidence(self):
        document = self.load("upstream-check.yml")
        self.assertNotIn("schedule", document[True])
        self.assertIn("workflow_dispatch", document[True])
        self.assertEqual(document["concurrency"]["cancel-in-progress"], True)
        self.assertEqual(document["jobs"]["qualify-candidate"]["permissions"],
                         {"contents": "read", "actions": "read"})
        self.assertEqual(document["jobs"]["qualify-candidate"]["if"],
                         "github.ref == 'refs/heads/main'")
        self.assertEqual(document["jobs"]["propose-bump"]["permissions"],
                         {"contents": "write", "pull-requests": "write", "actions": "read"})
        text = (ROOT / ".github/workflows/upstream-check.yml").read_text()
        self.assertIn("image/release/upstream.py", text)
        self.assertIn("--artifact-metadata", text)
        self.assertIn("release-candidate.yml", text)
        self.assertIn("bash scripts/check.sh", text)
        self.assertIn("needs: qualify-candidate", text)
        self.assertIn("gh pr create", text)
        self.assertNotIn("pull_request_target", text)

    def test_upstream_checkouts_are_exact_and_write_token_is_final_step_only(self):
        document = self.load("upstream-check.yml")
        checkout_steps = []
        for job in document["jobs"].values():
            for step in job.get("steps", []):
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    checkout_steps.append(step)
        self.assertEqual(len(checkout_steps), 2)
        for step in checkout_steps:
            with self.subTest(step=step["name"]):
                self.assertEqual(step["with"]["ref"], "${{ github.sha }}")
                self.assertIs(step["with"]["persist-credentials"], False)

        text = (ROOT / ".github/workflows/upstream-check.yml").read_text()
        self.assertEqual(
            text.count('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"'), 2
        )
        propose = document["jobs"]["propose-bump"]
        self.assertNotIn("GH_TOKEN", propose.get("env", {}))
        final_step = propose["steps"][-1]
        self.assertEqual(final_step["env"], {"GH_TOKEN": "${{ github.token }}"})
        for step in propose["steps"][:-1]:
            self.assertNotIn("GH_TOKEN", step.get("env", {}))

    def test_candidate_workflow_is_an_explicit_nonpublishing_blocker(self):
        candidate = self.load("release-candidate.yml")
        self.assertIn("workflow_dispatch", candidate[True])
        self.assertEqual(candidate["permissions"], {"contents": "read"})
        text = (ROOT / ".github/workflows/release-candidate.yml").read_text()
        self.assertIn("Authenticated native/signing producers are not implemented", text)
        self.assertIn("exit 1", text)
        self.assertNotIn("actions/upload-artifact@", text)
        self.assertNotIn("actions/download-artifact@", text)
        for forbidden in (
            "packages: write", "id-token: write", "COSIGN_PRIVATE_KEY",
            " cosign sign", " podman push",
        ):
            self.assertNotIn(forbidden, text)

    def test_consumers_cannot_bootstrap_their_own_evidence(self):
        workflows = ROOT / ".github/workflows"
        producer = workflows / "release-candidate.yml"
        self.assertTrue(producer.is_file())
        producer_text = producer.read_text()
        self.assertNotIn("actions/upload-artifact@", producer_text)
        consumers = {
            "release-images.yml": "symbi-os-release-evidence",
            "upstream-check.yml": "symbi-os-upstream-candidate",
        }
        for name, artifact in consumers.items():
            with self.subTest(consumer=name, artifact=artifact):
                text = (workflows / name).read_text()
                self.assertIn(".github/workflows/release-candidate.yml", text)
                self.assertIn(f"name: {artifact}", text)
                self.assertNotIn(f"--producer-workflow .github/workflows/{name}", text)

    def test_all_actions_are_pinned_to_exact_commits(self):
        for name in (
            "release-candidate.yml", "release-images.yml", "upstream-check.yml",
        ):
            text = (ROOT / ".github/workflows" / name).read_text()
            actions = re.findall(r"^\s*uses:\s*([^\s#]+)", text, re.MULTILINE)
            self.assertTrue(actions, name)
            for action in actions:
                with self.subTest(workflow=name, action=action):
                    self.assertRegex(action, r"^[^@]+@[a-f0-9]{40}$")


if __name__ == "__main__":
    unittest.main()
