"""Offline mutation tests for exact container-runtime image inputs and contracts."""
import copy
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from image.container import install
from image.container import package_inventory
from image.container import runtime_image_inputs as inputs
from image.qualification import container_hosted


ROOT = Path(__file__).resolve().parents[2]


class ContainerRuntimeImage(unittest.TestCase):
    def setUp(self):
        self.lock = inputs.unique_json(ROOT / "image/container/fedora-runtime-candidates.lock.json")

    def artifact(self, path, identity):
        identity.update(bytes=path.stat().st_size, sha256=inputs.digest(path))

    def package_rows(self):
        trust = inputs.unique_json(ROOT / "image/hyprland/fedora-package-trust.json")
        roots = ["moby-engine", "docker-cli", "container-selinux"]
        names = roots + [f"dependency-{index:03}" for index in range(105)]
        sizes = [1] * len(names)
        sizes[-1] += self.lock["package_bytes"] - sum(sizes)
        packages = []
        root_nevras = self.lock["source_package_plan"]["requested_root_nevras"]
        for index, (name, size) in enumerate(zip(names, sizes, strict=True)):
            packages.append({
                "filename": f"{name}-1-1.x86_64.rpm", "bytes": size,
                "sha256": hashlib.sha256(name.encode()).hexdigest(),
                "nevra": root_nevras.get(name, f"{name}-1-1.x86_64"),
                "vendor": "Fedora Project",
                "license": "MIT", "signature_verified": True,
                "key_fingerprint": trust["key"]["fingerprint"],
            })
        return packages

    def discovery_records(self):
        requirements_path = "image/container/runtime-requirements.json"
        requirements = inputs.unique_json(ROOT / requirements_path)
        bindings_files, trust = inputs._expected_bindings(ROOT, requirements_path)
        bindings = {"source_commit": self.lock["source_commit"], "profile": self.lock["profile"],
                    "requirements_source": requirements_path, "files": bindings_files}
        bindings_raw = (json.dumps(bindings, sort_keys=True) + "\n").encode()
        packages = self.package_rows()
        reviewed_roots = self.lock["source_package_plan"]["requested_root_nevras"]
        roots = {name: reviewed_roots[name] for name in requirements["packages"]}
        guest = {
            "schema": 1, "scope": inputs.GUEST_SCOPE, "base": trust["source"]["image"],
            "key": trust["key"], "requirements": requirements, "limits": inputs.EXPECTED_LIMITS,
            "commands": [
                {"name": name, "command": [name], "exit_code": 1 if "control" in name else 0}
                for name in ("installed-before", "resolve-download", "offline-closure-test",
                             "missing-key-control", "tampered-package-control", "installed-after")],
            "packages": packages, "passed": True, "os_qualified": False,
            "installed_root_nevras": roots, "downloaded_root_nevras": sorted(roots.values()),
            "offline_closure_verified": True, "closure_package_count": len(packages),
            "installed_packages_unchanged": True,
            "negative_controls": {"missing_key_rejected": True, "tampered_package_rejected": True},
        }
        guest_raw = (json.dumps(guest, sort_keys=True) + "\n").encode()
        summary = {
            "passed": True, "base": trust["source"]["image"],
            "source_commit": self.lock["source_commit"], "profile": self.lock["profile"],
            "requirements_sha256": inputs.digest(ROOT / requirements_path),
            "repository_configuration_sha256": bindings_files["repos/fedora-build.repo"],
            "input_bindings_sha256": hashlib.sha256(bindings_raw).hexdigest(),
            "packages": len(packages), "rpm_manifest_sha256": hashlib.sha256(guest_raw).hexdigest(),
            "os_qualified": False, "scope": inputs.SUMMARY_SCOPE,
            "installed_root_nevras": roots, "downloaded_root_nevras": sorted(roots.values()),
            "offline_closure_verified": True,
        }
        return summary, bindings, guest, guest_raw, bindings_raw

    def test_selected_artifacts_and_workflow_metadata_are_exact(self):
        requirements = inputs.validate_selection(ROOT, self.lock)
        self.assertEqual(requirements["packages"], ["moby-engine", "docker-cli", "container-selinux"])
        run = {"id": self.lock["run_id"], "run_attempt": self.lock["run_attempt"],
               "status": "completed", "conclusion": "success", "event": "push",
               "path": self.lock["workflow"], "head_sha": self.lock["source_commit"],
               "repository": self.lock["repository"], "head_repository": self.lock["repository"]}
        inputs.validate_workflow_metadata(run, self.lock)
        selected = self.lock["candidate_artifact"]
        metadata = {"id": selected["id"], "name": selected["name"],
                    "size_in_bytes": selected["bytes"], "digest": "sha256:" + selected["sha256"],
                    "expired": False, "workflow_run": {"id": self.lock["run_id"],
                    "head_sha": self.lock["source_commit"],
                    "repository_id": self.lock["repository"]["id"],
                    "head_repository_id": self.lock["repository"]["id"]}}
        inputs.validate_artifact_metadata(metadata, selected, self.lock)
        run_mutations = (
            ("id", self.lock["run_id"] + 1),
            ("run_attempt", self.lock["run_attempt"] + 1),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("event", "workflow_dispatch"),
            ("path", ".github/workflows/other.yml"),
            ("head_sha", "0" * 40),
            ("repository", {"id": 1, "full_name": "other/repository"}),
            ("head_repository", {"id": 1, "full_name": "other/repository"}),
        )
        artifact_mutations = (
            ("id", selected["id"] + 1),
            ("name", "other-artifact"),
            ("size_in_bytes", selected["bytes"] + 1),
            ("digest", "sha256:" + "0" * 64),
            ("expired", True),
            ("workflow_run.id", self.lock["run_id"] + 1),
            ("workflow_run.head_sha", "0" * 40),
            ("workflow_run.repository_id", 1),
            ("workflow_run.head_repository_id", 1),
        )
        for field, value in run_mutations:
            candidate = copy.deepcopy(run)
            candidate[field] = value
            with self.subTest(record="run", field=field), self.assertRaises(ValueError):
                inputs.validate_workflow_metadata(candidate, self.lock)
        for field, value in artifact_mutations:
            candidate = copy.deepcopy(metadata)
            if field.startswith("workflow_run."):
                candidate["workflow_run"][field.removeprefix("workflow_run.")] = value
            else:
                candidate[field] = value
            with self.subTest(record="artifact", field=field), self.assertRaises(ValueError):
                inputs.validate_artifact_metadata(candidate, selected, self.lock)

    def test_source_image_producer_and_artifact_metadata_are_exact(self):
        images = inputs.unique_json(ROOT / "image/desktop-images.lock.json")
        selected = images["images"]["generic"]
        producer = self.lock["source_image_producer"]
        run = {
            "id": producer["run_id"], "run_attempt": producer["run_attempt"],
            "event": producer["event"], "path": producer["workflow"]["path"],
            "workflow_id": producer["workflow"]["id"], "head_sha": producer["head_sha"],
            "head_branch": producer["head_branch"], "status": producer["status"],
            "conclusion": producer["conclusion"], "repository": producer["repository"],
            "head_repository": producer["head_repository"],
        }
        artifact = selected["artifact"]
        metadata = {
            "id": artifact["id"], "name": artifact["name"],
            "size_in_bytes": artifact["bytes"], "digest": "sha256:" + artifact["sha256"],
            "expired": False, "workflow_run": {
                "id": producer["run_id"], "head_sha": producer["head_sha"],
                "repository_id": producer["repository"]["id"],
                "head_repository_id": producer["head_repository"]["id"],
            },
        }
        inputs.validate_source_workflow_metadata(run, selected, self.lock)
        inputs.validate_source_artifact_metadata(metadata, selected, self.lock)
        run_mutations = (
            ("id", producer["run_id"] + 1),
            ("run_attempt", 2), ("event", "pull_request"),
            ("path", ".github/workflows/other.yml"), ("workflow_id", 1),
            ("head_sha", "0" * 40), ("head_branch", "other"),
            ("status", "in_progress"), ("conclusion", "failure"),
            ("repository.id", 1), ("repository.full_name", "other/repository"),
            ("head_repository.id", 1),
            ("head_repository.full_name", "other/repository"),
        )
        for field, value in run_mutations:
            candidate = copy.deepcopy(run)
            if "." in field:
                outer, inner = field.split(".", 1)
                candidate[outer][inner] = value
            else:
                candidate[field] = value
            with self.subTest(source_run=field), self.assertRaises(ValueError):
                inputs.validate_source_workflow_metadata(candidate, selected, self.lock)
        artifact_mutations = (
            ("workflow_run.id", self.lock["run_id"]),
            ("workflow_run.head_sha", self.lock["source_commit"]),
            ("workflow_run.repository_id", 1),
            ("workflow_run.head_repository_id", 1),
            ("id", artifact["id"] + 1), ("name", "other"),
            ("size_in_bytes", artifact["bytes"] + 1),
            ("digest", "sha256:" + "0" * 64), ("expired", True),
        )
        for field, value in artifact_mutations:
            candidate = copy.deepcopy(metadata)
            if field.startswith("workflow_run."):
                candidate["workflow_run"][field.removeprefix("workflow_run.")] = value
            else:
                candidate[field] = value
            with self.subTest(source_artifact=field), self.assertRaises(ValueError):
                inputs.validate_source_artifact_metadata(candidate, selected, self.lock)
        for field, value in (("run_id", self.lock["run_id"]),
                             ("tested_commit", self.lock["source_commit"])):
            changed_selected = copy.deepcopy(selected)
            changed_selected[field] = value
            with self.subTest(source_lock=field), self.assertRaises(ValueError):
                inputs.validate_source_workflow_metadata(run, changed_selected, self.lock)

    def test_inventory_canonicalization_accepts_order_only_and_rejects_bad_rows(self):
        rows = ["zstd\t0\t1.6.0\t1.fc45\tx86_64",
                "audit-libs\t0\t4.2.1\t2.fc45\tx86_64",
                "gpg-pubkey\t0\t4f50a611\t6888bc98\t(none)"]
        raw = ("\n".join(rows) + "\n").encode()
        reordered = ("\n".join(reversed(rows)) + "\n").encode()
        self.assertEqual(package_inventory.parse_inventory(raw), sorted(rows))
        self.assertEqual(package_inventory.inventory_digest(raw),
                         package_inventory.inventory_digest(reordered))
        faults = (
            ("\n".join(rows + [rows[0]]) + "\n").encode(),
            b"missing-fields\t0\t1\n",
            (rows[0] + "\textra\n").encode(),
            ("\n".join(rows)).encode(),
            (rows[0] + "\n\n" + rows[1] + "\n").encode(),
        )
        for raw_fault in faults:
            with self.subTest(raw=raw_fault), self.assertRaises(ValueError):
                package_inventory.inventory_digest(raw_fault)

    def test_retained_source_inventory_requires_exact_signed_roots_and_empty_delta(self):
        roots = self.lock["source_package_plan"]["requested_root_nevras"]
        plan = inputs.validate_source_package_plan(ROOT, self.lock, roots)
        self.assertEqual(plan["source_package_count"], 2184)
        self.assertEqual(plan["additive_nevras"], [])
        before = package_inventory.parse_inventory(
            (ROOT / self.lock["source_package_plan"]["inventory"]["path"]).read_bytes())
        identities = {
            name: {"identity": plan["requested_root_identities"][name],
                   "nevra": nevra, "path": "/rpms/" + name + ".rpm"}
            for name, nevra in roots.items()
        }
        identities["libzstd"] = {
            "identity": "libzstd\t0\t1.6.0\t1.fc45\tx86_64",
            "nevra": "libzstd-1.6.0-1.fc45.x86_64", "path": "/rpms/libzstd.rpm"}
        self.assertEqual(install.select_delta(
            before, identities, roots, plan["requested_root_identities"], []), [])
        changed_root_identities = dict(plan["requested_root_identities"])
        changed_root_identities["moby-engine"] = (
            "moby-engine\t0\t0\t0.fc45\tx86_64")
        with self.assertRaises(ValueError):
            install.select_delta(before, identities, roots, changed_root_identities, [])
        with self.assertRaises(ValueError):
            install.select_delta(before, identities, roots, plan["requested_root_identities"],
                                 [identities["libzstd"]["nevra"]])
        changed_roots = dict(roots)
        changed_roots["moby-engine"] = "moby-engine-0-0.fc45.x86_64"
        with self.assertRaises(ValueError):
            inputs.validate_source_package_plan(ROOT, self.lock, changed_roots)
        for field, value in (
            ("additive_nevras", ["fedora-release-45-14.noarch"]),
            ("replacements_allowed", True),
            ("inventory.canonical_sha256", "0" * 64),
            ("requested_root_nevras.moby-engine", "moby-engine-0-0.fc45.x86_64"),
        ):
            changed = copy.deepcopy(self.lock)
            if "." in field:
                outer, inner = field.split(".", 1)
                changed["source_package_plan"][outer][inner] = value
            else:
                changed["source_package_plan"][field] = value
            with self.subTest(source_plan=field), self.assertRaises(ValueError):
                inputs.validate_selection(ROOT, changed)

    def test_discovery_evidence_rejects_mutated_bindings_closure_and_claims(self):
        values = self.discovery_records()
        inputs.validate_discovery_records(ROOT, self.lock, *values)
        summary, bindings, guest, guest_raw, bindings_raw = values
        mutations = []
        changed = copy.deepcopy(summary); changed["os_qualified"] = True
        mutations.append((changed, bindings, guest, guest_raw, bindings_raw))
        changed = copy.deepcopy(bindings); changed["files"]["dnf.conf"] = "0" * 64
        changed_raw = (json.dumps(changed, sort_keys=True) + "\n").encode()
        rebound = copy.deepcopy(summary); rebound["input_bindings_sha256"] = hashlib.sha256(changed_raw).hexdigest()
        mutations.append((rebound, changed, guest, guest_raw, changed_raw))
        changed = copy.deepcopy(guest); changed["packages"][0]["signature_verified"] = False
        changed_raw = (json.dumps(changed, sort_keys=True) + "\n").encode()
        rebound = copy.deepcopy(summary); rebound["rpm_manifest_sha256"] = hashlib.sha256(changed_raw).hexdigest()
        mutations.append((rebound, bindings, changed, changed_raw, bindings_raw))
        changed = copy.deepcopy(guest); changed["closure_package_count"] -= 1
        changed_raw = (json.dumps(changed, sort_keys=True) + "\n").encode()
        rebound = copy.deepcopy(summary); rebound["rpm_manifest_sha256"] = hashlib.sha256(changed_raw).hexdigest()
        mutations.append((rebound, bindings, changed, changed_raw, bindings_raw))
        for candidate in mutations:
            with self.subTest(case=len(candidate[2].get("packages", []))), self.assertRaises(ValueError):
                inputs.validate_discovery_records(ROOT, self.lock, *candidate)

    def test_candidate_zip_streams_only_exact_members(self):
        packages = [
            {"filename": "one.rpm", "bytes": 3, "sha256": hashlib.sha256(b"one").hexdigest(),
             "nevra": "one-1-1.x86_64", "vendor": "Fedora", "license": "MIT",
             "signature_verified": True, "key_fingerprint": "A" * 40},
            {"filename": "two.rpm", "bytes": 3, "sha256": hashlib.sha256(b"two").hexdigest(),
             "nevra": "two-1-1.x86_64", "vendor": "Fedora", "license": "MIT",
             "signature_verified": True, "key_fingerprint": "A" * 40},
        ]
        guest = {"key": {"fingerprint": "A" * 40}, "packages": packages}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, evidence = root / "candidate.zip", root / "evidence.zip"
            with zipfile.ZipFile(candidate, "w") as bundle:
                bundle.writestr("evidence/result.json", json.dumps(guest))
                bundle.writestr("rpms/one.rpm", b"one")
                bundle.writestr("rpms/two.rpm", b"two")
            with zipfile.ZipFile(evidence, "w") as bundle:
                bundle.writestr("result.json", "{}")
                bundle.writestr("input-bindings.json", "{}")
            lock = {"package_count": 2, "package_bytes": 6,
                    "candidate_artifact": {"id": 1, "name": "container-runtime-rpm-candidates"},
                    "evidence_artifact": {"id": 2, "name": "container-runtime-fedora-package-evidence"}}
            self.artifact(candidate, lock["candidate_artifact"])
            self.artifact(evidence, lock["evidence_artifact"])
            inputs.unpack_discovery_artifacts(candidate, evidence, lock, root / "output")
            self.assertEqual((root / "output/rpms/one.rpm").read_bytes(), b"one")
            with candidate.open("ab") as stream:
                stream.write(b"changed")
            with self.assertRaises(ValueError):
                inputs.unpack_discovery_artifacts(candidate, evidence, lock, root / "changed")

    def test_zip_rejects_link_traversal_and_extra_members(self):
        packages = [{"filename": "one.rpm", "bytes": 3, "sha256": hashlib.sha256(b"one").hexdigest(),
                     "nevra": "one-1-1.x86_64", "vendor": "Fedora", "license": "MIT",
                     "signature_verified": True, "key_fingerprint": "A" * 40}]
        guest = {"key": {"fingerprint": "A" * 40}, "packages": packages}
        for case in ("traversal", "link", "extra"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); candidate = root / "candidate.zip"; evidence = root / "evidence.zip"
                with zipfile.ZipFile(candidate, "w") as bundle:
                    bundle.writestr("evidence/result.json", json.dumps(guest))
                    bundle.writestr("rpms/one.rpm", b"one")
                    if case == "traversal": bundle.writestr("../escape", b"x")
                    elif case == "extra": bundle.writestr("rpms/extra.rpm", b"x")
                    else:
                        row = zipfile.ZipInfo("linked")
                        row.external_attr = (stat.S_IFLNK | 0o777) << 16
                        bundle.writestr(row, "target")
                with zipfile.ZipFile(evidence, "w") as bundle:
                    bundle.writestr("result.json", "{}")
                    bundle.writestr("input-bindings.json", "{}")
                lock = {"package_count": 1, "package_bytes": 3,
                        "candidate_artifact": {"id": 1, "name": "container-runtime-rpm-candidates"},
                        "evidence_artifact": {"id": 2, "name": "container-runtime-fedora-package-evidence"}}
                self.artifact(candidate, lock["candidate_artifact"])
                self.artifact(evidence, lock["evidence_artifact"])
                with self.assertRaises(ValueError):
                    inputs.unpack_discovery_artifacts(candidate, evidence, lock, root / "output")

    def test_delta_is_additive_exact_and_transaction_is_closed(self):
        before = ["base\t0\t1\t1\tx86_64", "keep\t0\t1\t1\tx86_64"]
        identities = {
            "keep": {"identity": before[1], "nevra": "keep-1-1.x86_64", "path": "/rpms/keep.rpm"},
            "new": {"identity": "new\t0\t1\t1\tx86_64", "nevra": "new-1-1.x86_64", "path": "/rpms/new.rpm"},
        }
        roots = {"keep": "keep-1-1.x86_64"}
        root_identities = {"keep": identities["keep"]["identity"]}
        delta = install.select_delta(
            before, identities, roots, root_identities, ["new-1-1.x86_64"])
        after = sorted(before + [identities["new"]["identity"]])
        before_hash, after_hash = install.require_transaction(before, after, delta,
                                                               [identities["keep"]["identity"]])
        self.assertEqual(len(before_hash), 64); self.assertEqual(len(after_hash), 64)
        changed = copy.deepcopy(identities); changed["new"]["identity"] = "base\t0\t2\t1\tx86_64"
        with self.assertRaises(ValueError):
            install.select_delta(before, changed, roots, root_identities, ["new-1-1.x86_64"])
        with self.assertRaises(ValueError): install.require_transaction(before, after + ["extra\t0\t1\t1\tx86_64"], delta, after)
        with self.assertRaises(ValueError):
            install.select_delta(before, identities, roots, root_identities,
                                 ["keep-1-1.x86_64"])

    def test_generated_contract_is_accepted_but_remains_unqualified(self):
        runsc = container_hosted.load_authenticated_runsc(ROOT, verify=lambda *args: None)
        summary, _, _, _, _ = self.discovery_records()
        packages = self.package_rows()
        images = inputs.unique_json(ROOT / "image/desktop-images.lock.json")
        selected = images["images"]["generic"]
        package_plan = inputs.validate_source_package_plan(
            ROOT, self.lock, self.lock["source_package_plan"]["requested_root_nevras"])
        install_record = {
            "before_inventory_sha256": package_plan["source_inventory_sha256"],
            "after_inventory_sha256": package_plan["source_inventory_sha256"],
            "source_inventory_sha256": package_plan["source_inventory_sha256"],
            "requested_root_nevras": package_plan["requested_root_nevras"],
            "added_nevras": [], "rpm_transaction_empty": True,
            "daemon_configuration_sha256": inputs.digest(ROOT / "image/container/daemon.json"),
        }
        contract = inputs.build_contract(ROOT, self.lock, summary, packages, install_record, runsc)
        container_hosted.validate_fedora_contract(contract, runsc, ROOT, selected["tested_commit"])
        self.assertTrue(contract["installed"])
        self.assertFalse(contract["qualified"])
        self.assertFalse(contract["os_qualified"])
        self.assertFalse(contract["release_qualified"])
        for field, value in (
            ("repository", {"id": 1, "full_name": "other/repository"}),
            ("run_id", self.lock["run_id"] + 1),
            ("run_attempt", self.lock["run_attempt"] + 1),
            ("source_commit", "0" * 40),
            ("artifact", {**self.lock["candidate_artifact"], "sha256": "0" * 64}),
        ):
            changed = copy.deepcopy(contract)
            changed["discovery"][field] = value
            with self.subTest(binding=field), self.assertRaises(ValueError):
                container_hosted.validate_fedora_contract(
                    changed, runsc, ROOT, selected["tested_commit"])
        changed = copy.deepcopy(contract)
        changed["installation"]["image_producer"]["run_attempt"] += 1
        with self.assertRaises(ValueError):
            container_hosted.validate_fedora_contract(
                changed, runsc, ROOT, selected["tested_commit"])

    def test_manual_hosted_workflow_has_bounded_offline_build_and_false_claims(self):
        workflow = (ROOT / ".github/workflows/container-runtime-image.yml").read_text()
        wrapper = (ROOT / "scripts/check-container-runtime-image.sh").read_text()
        builder = (ROOT / "image/container/runtime_image_build.py").read_text()
        installer = (ROOT / "image/container/install.py").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("actions: read", workflow)
        self.assertIn("atomic-image-run.json", workflow)
        self.assertIn("check-container-runtime-image.sh prepare", workflow)
        self.assertIn("check-container-runtime-image.sh build", workflow)
        self.assertIn("MemoryMax=4G", wrapper)
        self.assertIn("MemorySwapMax=0", wrapper)
        self.assertIn('"--network=none"', builder)
        self.assertIn('"--jobs=1"', builder)
        self.assertIn("package_inventory.py", (ROOT / "image/container/runtime_image_prepare.py").read_text())
        self.assertIn('"qualified": False', installer)
        self.assertNotIn("--nodeps", installer)
        self.assertNotIn("--force", installer)


if __name__ == "__main__":
    unittest.main()
