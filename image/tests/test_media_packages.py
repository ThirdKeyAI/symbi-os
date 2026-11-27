"""Closed media-package selection, offline install and playback boundaries."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from image.desktop_packages.media_contract import (
    FEDORA,
    FUSION,
    media_selection_digest,
    offline_install_command,
    require_media_artifact_metadata,
    require_media_image_binding,
    require_media_lock,
    require_source_release_match,
)
from image.desktop_packages.media_inputs import unpack_media_bundle
from image.desktop_packages.media_install import require_additive_inventory, trust_snapshot
from image.desktop_packages.media_playback import (
    PLAYBACK_FIXTURE_SHA256,
    PLAYBACK_LIMITS,
    PLAYBACK_SCOPE,
    require_playback_report,
    write_fixtures,
)


ROOT = Path(__file__).resolve().parents[2]


class MediaPackageLock(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads((ROOT / "image/desktop_packages/media-rpms.lock.json").read_text())
        self.pins = json.loads((ROOT / "image/base-images.json").read_text())
        self.trust = json.loads((ROOT / "image/desktop_packages/trust.json").read_text())

    def ready_fixture(self):
        lock = copy.deepcopy(self.lock)
        roots = lock["root_packages"]
        lock["status"] = "ready-for-offline-image-install"
        lock["install_ready"] = True
        lock["image_source_commit"] = None
        lock["closure"] = {
            "complete": True,
            "packages": copy.deepcopy(roots),
            "artifact": {
                "id": 1,
                "name": "media-rpms-fedora-45-x86_64",
                "producer": {
                    "repository": "ThirdKeyAI/symbi-os",
                    "workflow": ".github/workflows/media-closure.yml",
                    "run_id": 2,
                    "head_sha": "c" * 40,
                },
                "resolution_base": lock["resolution_base"],
                "bytes": 100,
                "sha256": "3" * 64,
                "manifest_sha256": "4" * 64,
            },
            "reason": None,
        }
        lock["source_inputs"] = [
            {"source_rpm": roots[0]["source_rpm"], "expected_key_fingerprint": FUSION,
             "status": "authenticated", "name": "mplayer", "epoch": "0",
             "version": roots[0]["version"], "release": roots[0]["release"], "arch": "src",
             "nevra": "mplayer-" + roots[0]["version"] + "-" + roots[0]["release"] + ".src",
             "filename": roots[0]["source_rpm"], "bytes": 100, "sha256": "1" * 64,
             "signature_verified": True, "key_fingerprint": FUSION},
            {"source_rpm": roots[2]["source_rpm"], "expected_key_fingerprint": FEDORA,
             "status": "authenticated", "name": "mpv", "epoch": "0",
             "version": roots[2]["version"], "release": roots[2]["release"], "arch": "src",
             "nevra": "mpv-" + roots[2]["version"] + "-" + roots[2]["release"] + ".src",
             "filename": roots[2]["source_rpm"], "bytes": 100, "sha256": "2" * 64,
             "signature_verified": True, "key_fingerprint": FEDORA},
        ]
        return lock

    def artifact_api_fixture(self, lock):
        artifact = lock["closure"]["artifact"]
        return ({
            "id": artifact["id"],
            "name": artifact["name"],
            "size_in_bytes": artifact["bytes"],
            "expired": False,
            "workflow_run": {
                "id": artifact["producer"]["run_id"],
                "head_sha": artifact["producer"]["head_sha"],
            },
        }, {
            "id": artifact["producer"]["run_id"],
            "head_sha": artifact["producer"]["head_sha"],
            "path": artifact["producer"]["workflow"],
            "repository": {"full_name": artifact["producer"]["repository"]},
            "status": "completed",
            "conclusion": "success",
        })

    def bind_archive(self, lock, archive, manifest_raw):
        artifact = lock["closure"]["artifact"]
        artifact["bytes"] = archive.stat().st_size
        artifact["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
        artifact["manifest_sha256"] = hashlib.sha256(manifest_raw).hexdigest()

    def write_archive(self, archive, lock, manifest_raw, *, duplicate=False,
                      traverse=False, symlink=False):
        sources = [
            {name: slot[name] for name in
             ("name", "epoch", "version", "release", "arch", "nevra", "filename", "bytes",
              "sha256", "signature_verified", "key_fingerprint")}
            for slot in lock["source_inputs"]
        ]
        regular = ["rpms/" + row["filename"] for row in lock["closure"]["packages"]]
        regular += ["srpms/" + row["filename"] for row in sources]
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("manifest.json", manifest_raw)
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    bundle.writestr("manifest.json", manifest_raw)
            for index, name in enumerate(regular):
                if traverse and index == 0:
                    name = "../escape.rpm"
                if symlink and index == 0:
                    row = zipfile.ZipInfo(name)
                    row.external_attr = (stat.S_IFLNK | 0o777) << 16
                    bundle.writestr(row, "target")
                else:
                    bundle.writestr(name, b"x")
        self.bind_archive(lock, archive, manifest_raw)

    def test_exact_two_signer_roots_are_frozen_but_install_stays_closed(self):
        self.assertFalse(require_media_lock(self.lock, ROOT, self.pins, self.trust))
        roots = {row["name"]: row for row in self.lock["root_packages"]}
        self.assertEqual(set(roots), {"mplayer", "mplayer-common", "mpv"})
        self.assertEqual(roots["mplayer"]["key_fingerprint"], FUSION)
        self.assertEqual(roots["mplayer-common"]["key_fingerprint"], FUSION)
        self.assertEqual(roots["mpv"]["key_fingerprint"], FEDORA)
        self.assertEqual({row["key_fingerprint"] for row in roots.values()}, {FEDORA, FUSION})
        self.assertFalse(self.lock["install_ready"])
        self.assertFalse(self.lock["closure"]["complete"])

    def test_package_source_release_signer_base_and_cve_bindings_fail_closed(self):
        mutations = []
        changed = copy.deepcopy(self.lock); changed["root_packages"][0]["sha256"] = "0" * 64; mutations.append(changed)
        changed = copy.deepcopy(self.lock); changed["root_packages"][0]["source_rpm"] = "mplayer-9-9.src.rpm"; mutations.append(changed)
        changed = copy.deepcopy(self.lock); changed["root_packages"][2]["key_fingerprint"] = FUSION; mutations.append(changed)
        changed = copy.deepcopy(self.lock); changed["target_bases"]["generic"] = self.pins["variants"]["nvidia"]["image"]; mutations.append(changed)
        changed = copy.deepcopy(self.lock); changed["security_evidence"]["packages"][0]["release"] = "0.unreviewed"; mutations.append(changed)
        changed = copy.deepcopy(self.lock); changed["security_evidence"]["packages"][0]["sha256"] = "f" * 64; mutations.append(changed)
        changed = copy.deepcopy(self.lock); changed["security_evidence"]["cleared"] = True; mutations.append(changed)
        changed = copy.deepcopy(self.lock); changed["source_inputs"][0]["sha256"] = "a" * 64; mutations.append(changed)
        changed = copy.deepcopy(self.lock); changed["install_ready"] = True; mutations.append(changed)
        changed = copy.deepcopy(self.lock); changed["closure"]["complete"] = True; mutations.append(changed)
        for lock in mutations:
            with self.subTest(lock=lock), self.assertRaises(ValueError):
                require_media_lock(lock, ROOT, self.pins, self.trust)

    def test_retained_cve_search_is_exactly_bound_and_never_claims_clearance(self):
        roots = {row["name"]: row for row in self.lock["root_packages"]}
        evidence = {row["name"]: row for row in self.lock["security_evidence"]["packages"]}
        self.assertEqual(set(evidence), {"mplayer", "mpv"})
        for name, row in evidence.items():
            package = roots[name]
            self.assertEqual((row["version"], row["release"], row["source_rpm"]),
                             (package["version"], package["release"], package["source_rpm"]))
            self.assertFalse(row["package_version_assessed"])
            self.assertTrue((ROOT / row["path"]).is_file())

    def test_rehashed_request_manifest_cannot_redirect_the_retained_cve_evidence(self):
        lock = copy.deepcopy(self.lock)
        paths = [lock["discovery"]["result_path"],
                 lock["security_evidence"]["request_manifest"]["path"],
                 *[row["path"] for row in lock["security_evidence"]["packages"]]]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in paths:
                target = root / relative; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            binding = lock["security_evidence"]["request_manifest"]
            manifest_path = root / binding["path"]
            manifest = json.loads(manifest_path.read_text())
            next(row for row in manifest["requests"] if row["query"] == "MPlayer")["url"] = \
                "https://example.invalid/not-cve-bz"
            raw = (json.dumps(manifest, indent=2) + "\n").encode()
            manifest_path.write_bytes(raw)
            binding["bytes"] = len(raw); binding["sha256"] = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):
                require_media_lock(lock, root, self.pins, self.trust)

    def test_each_package_is_bound_to_its_exact_cve_bz_product_response(self):
        lock = copy.deepcopy(self.lock)
        mplayer, mpv = lock["security_evidence"]["packages"]
        for name in ("query", "path", "bytes", "sha256"):
            mplayer[name], mpv[name] = mpv[name], mplayer[name]
        with self.assertRaises(ValueError):
            require_media_lock(lock, ROOT, self.pins, self.trust)

    def test_only_a_complete_closure_and_authenticated_sources_open_the_gate(self):
        lock = self.ready_fixture()
        self.assertTrue(require_media_lock(lock, ROOT, self.pins, self.trust, require_ready=True))
        for change in ("source-hash", "source-signer", "missing-root", "artifact", "commit", "path"):
            bad = copy.deepcopy(lock)
            if change == "source-hash": bad["source_inputs"][0]["sha256"] = "x" * 64
            elif change == "source-signer": bad["source_inputs"][0]["key_fingerprint"] = FEDORA
            elif change == "missing-root": bad["closure"]["packages"].pop()
            elif change == "artifact": bad["closure"]["artifact"]["bytes"] = 0
            elif change == "commit": bad["image_source_commit"] = "not-a-commit"
            else: bad["closure"]["packages"][0]["version"] = "../escape"
            with self.subTest(change=change), self.assertRaises(ValueError):
                require_media_lock(bad, ROOT, self.pins, self.trust, require_ready=True)

    def test_ready_lock_can_be_built_then_relinked_to_the_resulting_image_commit(self):
        lock = self.ready_fixture()
        self.assertTrue(require_media_lock(lock, ROOT, self.pins, self.trust, require_ready=True))
        selected = media_selection_digest(lock)
        relinked = copy.deepcopy(lock); relinked["image_source_commit"] = "b" * 40
        self.assertTrue(require_media_lock(relinked, ROOT, self.pins, self.trust, require_ready=True))
        self.assertEqual(media_selection_digest(relinked), selected)
        manifest = {"media_selection_sha256": selected}
        require_media_image_binding(relinked, manifest, "b" * 40)
        for changed_lock, changed_manifest, commit in (
                (lock, manifest, "b" * 40),
                (relinked, manifest, "d" * 40),
                (relinked, {"media_selection_sha256": "0" * 64}, "b" * 40)):
            with self.assertRaises(ValueError):
                require_media_image_binding(changed_lock, changed_manifest, commit)
        changed = copy.deepcopy(lock); changed["root_packages"][0]["sha256"] = "0" * 64
        self.assertNotEqual(media_selection_digest(changed), selected)

    def test_ready_artifact_is_bound_to_exact_successful_producer_metadata(self):
        lock = self.ready_fixture()
        artifact, run = self.artifact_api_fixture(lock)
        require_media_artifact_metadata(lock, artifact, run)
        mutations = []
        for target, field, value in (
                ("artifact", "name", "other"),
                ("artifact", "size_in_bytes", 99),
                ("artifact", "expired", True),
                ("run", "path", ".github/workflows/other.yml"),
                ("run", "head_sha", "d" * 40),
                ("run", "conclusion", "failure")):
            changed_artifact, changed_run = copy.deepcopy(artifact), copy.deepcopy(run)
            (changed_artifact if target == "artifact" else changed_run)[field] = value
            mutations.append((changed_artifact, changed_run))
        for changed_artifact, changed_run in mutations:
            with self.subTest(artifact=changed_artifact, run=changed_run), self.assertRaises(ValueError):
                require_media_artifact_metadata(lock, changed_artifact, changed_run)
        changed_artifact = copy.deepcopy(artifact)
        changed_artifact["workflow_run"]["id"] = 3
        with self.assertRaises(ValueError):
            require_media_artifact_metadata(lock, changed_artifact, run)
        changed_run = copy.deepcopy(run)
        changed_run["repository"]["full_name"] = "ThirdKeyAI/other"
        with self.assertRaises(ValueError):
            require_media_artifact_metadata(lock, artifact, changed_run)

    def test_ready_artifact_contract_binds_workflow_run_head_name_and_base(self):
        lock = self.ready_fixture()
        for change in ("workflow", "run", "head", "name", "base"):
            bad = copy.deepcopy(lock)
            artifact = bad["closure"]["artifact"]
            if change == "workflow": artifact["producer"]["workflow"] = ".github/workflows/other.yml"
            elif change == "run": artifact["producer"]["run_id"] = 0
            elif change == "head": artifact["producer"]["head_sha"] = "not-a-commit"
            elif change == "name": artifact["name"] = "other"
            else: artifact["resolution_base"] = bad["target_bases"]["nvidia"]
            with self.subTest(change=change), self.assertRaises(ValueError):
                require_media_lock(bad, ROOT, self.pins, self.trust, require_ready=True)

    def test_exact_source_rpms_must_match_binary_headers_and_signers(self):
        roots = self.lock["root_packages"]
        sources = [
            {"name": "mplayer", "epoch": "0", "version": roots[0]["version"],
             "release": roots[0]["release"], "arch": "src",
             "nevra": "mplayer-" + roots[0]["version"] + "-" + roots[0]["release"] + ".src",
             "filename": roots[0]["source_rpm"], "bytes": 100, "sha256": "1" * 64,
             "signature_verified": True, "key_fingerprint": FUSION},
            {"name": "mpv", "epoch": "0", "version": roots[2]["version"],
             "release": roots[2]["release"], "arch": "src",
             "nevra": "mpv-" + roots[2]["version"] + "-" + roots[2]["release"] + ".src",
             "filename": roots[2]["source_rpm"], "bytes": 100, "sha256": "2" * 64,
             "signature_verified": True, "key_fingerprint": FEDORA},
        ]
        require_source_release_match(roots, sources)
        for field, value in (("release", "0.changed"), ("key_fingerprint", FEDORA),
                             ("filename", "mplayer-unrelated.src.rpm")):
            changed = copy.deepcopy(sources)
            changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                require_source_release_match(roots, changed)

    def test_pending_lock_cannot_stage_even_if_an_archive_path_is_supplied(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "prepared"
            with self.assertRaises(ValueError):
                unpack_media_bundle(Path(directory) / "untrusted.zip", self.lock, ROOT,
                                    self.pins, self.trust, destination)
            self.assertFalse(destination.exists())

    def test_bundle_rejects_oversized_manifest_before_reading_it(self):
        lock = self.ready_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "bundle.zip"
            raw = b'{"padding":"' + b"x" * (1024 * 1024) + b'"}'
            self.write_archive(archive, lock, raw)
            with mock.patch.object(zipfile.ZipFile, "read",
                                   side_effect=AssertionError("oversized manifest was read")):
                with self.assertRaises(ValueError):
                    unpack_media_bundle(archive, lock, ROOT, self.pins, self.trust,
                                        root / "destination")

    def test_bundle_rejects_duplicate_traversal_and_symlink_members(self):
        for shape in ("duplicate", "traverse", "symlink"):
            lock = self.ready_fixture()
            with self.subTest(shape=shape), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "bundle.zip"
                raw = b'{"schema":1}'
                self.write_archive(archive, lock, raw,
                                   duplicate=shape == "duplicate",
                                   traverse=shape == "traverse",
                                   symlink=shape == "symlink")
                with self.assertRaises(ValueError):
                    unpack_media_bundle(archive, lock, ROOT, self.pins, self.trust,
                                        root / "destination")


class MediaOfflineInstall(unittest.TestCase):
    def test_equal_nevra_already_in_the_base_cannot_bypass_locked_rpm_provenance(self):
        lock = json.loads((ROOT / "image/desktop_packages/media-rpms.lock.json").read_text())
        package = lock["root_packages"][2]
        installed = ["\t".join(package[name] for name in
                                ("name", "epoch", "version", "release", "arch"))]
        with self.assertRaises(ValueError):
            require_additive_inventory(installed, [package])

    def test_offline_transaction_uses_only_locked_local_paths_and_no_persistent_key(self):
        paths = [Path("/symbi-build-inputs/media/rpms/mplayer.rpm"),
                 Path("/symbi-build-inputs/media/rpms/mpv.rpm")]
        command = offline_install_command(paths, Path("/symbi-build-evidence/media"))
        rendered = " ".join(str(value) for value in command)
        self.assertIn("--disable-plugin=*", command)
        self.assertIn("--setopt=reposdir=/symbi-build-evidence/media/empty-repos", command)
        self.assertNotIn("--disablerepo=*", command)
        self.assertIn("--setopt=localpkg_gpgcheck=False", command)
        self.assertIn("--setopt=install_weak_deps=False", command)
        self.assertNotIn("--nogpgcheck", command)
        self.assertNotIn("http://", rendered)
        self.assertNotIn("https://", rendered)
        self.assertEqual(command[-2:], [str(path) for path in paths])

    def test_installer_uses_an_ephemeral_two_key_keyring(self):
        source = (ROOT / "image/desktop_packages/media_install.py").read_text()
        self.assertIn("TemporaryDirectory", source)
        self.assertIn("_keyringpath", source)
        self.assertIn("require_keyring", source)
        self.assertIn('"usr/share/pki/rpm-gpg"', source)
        self.assertIn('"usr/share/dnf5/repos.d"', source)
        self.assertNotIn("/etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion", source)
        self.assertNotIn("rpm --import", source)

    def test_persistent_trust_snapshot_hashes_effective_symlink_target_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keys = root / "usr/share/pki/rpm-gpg"; keys.mkdir(parents=True)
            target = root / "effective-key"; target.write_bytes(b"first")
            link = keys / "linked-key"; link.symlink_to(target)
            before = trust_snapshot(root)
            target.write_bytes(b"second")
            self.assertNotEqual(before, trust_snapshot(root))
            before = trust_snapshot(root)
            target.chmod(0o600)
            self.assertNotEqual(before, trust_snapshot(root))
            alternate = root / "alternate-key"
            alternate.write_bytes(target.read_bytes()); alternate.chmod(0o600)
            before = trust_snapshot(root)
            link.unlink(); link.symlink_to(alternate)
            self.assertNotEqual(before, trust_snapshot(root))
            alternative_groups = [group for group in os.getgroups() if group != os.getgid()]
            if alternative_groups:
                before = trust_snapshot(root)
                os.lchown(link, -1, alternative_groups[0])
                self.assertNotEqual(before, trust_snapshot(root))

    def test_persistent_trust_snapshot_covers_all_fedora_and_secureblue_input_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = set()
            for base in ("etc", "usr/etc", "usr/share/factory/etc", "usr/share/secureblue/etc"):
                for relative in ("dnf/dnf.conf", "yum.repos.d/test.repo", "pki/rpm-gpg/test.key"):
                    path = root / base / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(base + relative)
                    expected.add(path.relative_to(root).as_posix())
            for relative in ("usr/share/dnf5/repos.d/owned.repo",
                             "usr/share/pki/rpm-gpg/current.key",
                             "usr/share/distribution-gpg-keys/fedora/fedora-45.key"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative)
                expected.add(relative)
            self.assertTrue(expected.issubset(trust_snapshot(root)))

    def test_persistent_trust_snapshot_binds_owner_mode_directories_and_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trust = root / "etc/yum.repos.d"; trust.mkdir(parents=True, mode=0o755)
            package = trust / "test.repo"; package.write_text("data"); package.chmod(0o644)
            before = trust_snapshot(root)
            package.chmod(0o600)
            self.assertNotEqual(before, trust_snapshot(root))
            package.chmod(0o644); before = trust_snapshot(root)
            trust.chmod(0o700)
            self.assertNotEqual(before, trust_snapshot(root))
            trust.chmod(0o755); before = trust_snapshot(root)
            alternative_groups = [group for group in os.getgroups() if group != os.getgid()]
            if not alternative_groups:
                self.skipTest("No supplementary group is available for owner metadata mutation")
            os.chown(package, -1, alternative_groups[0])
            self.assertNotEqual(before, trust_snapshot(root))
            empty = root / "usr/share/factory/etc/yum.repos.d"
            before = trust_snapshot(root); empty.mkdir(parents=True)
            self.assertNotEqual(before, trust_snapshot(root))
            factory = root / "usr/share/factory/etc"
            before = trust_snapshot(root); factory.chmod(0o700)
            self.assertNotEqual(before, trust_snapshot(root))

    def test_persistent_trust_snapshot_rejects_oversized_and_special_entries(self):
        for shape in ("oversized", "fifo"):
            with self.subTest(shape=shape), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                trust = root / "usr/share/secureblue/etc/pki/rpm-gpg"
                trust.mkdir(parents=True)
                path = trust / "input"
                if shape == "oversized": path.write_bytes(b"x" * (262144 + 1))
                else: os.mkfifo(path)
                with self.assertRaises(ValueError):
                    trust_snapshot(root)

    def test_persistent_trust_snapshot_rejects_symlinked_configuration_parents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target/etc/yum.repos.d"; target.mkdir(parents=True)
            (target / "test.repo").write_text("data")
            factory = root / "usr/share/factory"; factory.parent.mkdir(parents=True)
            factory.symlink_to(root / "target")
            with self.assertRaises(ValueError):
                trust_snapshot(root)

    def test_desktop_pipeline_stages_and_runs_media_only_after_the_gate_opens(self):
        prepare = (ROOT / "image/desktop/prepare.py").read_text()
        recipe = (ROOT / "image/desktop/recipe.py").read_text()
        build = (ROOT / "image/desktop/build.py").read_text()
        workflow = (ROOT / ".github/workflows/desktop-image.yml").read_text()
        self.assertIn("media_ready = require_media_lock", prepare)
        self.assertIn("unpack_media_bundle", prepare)
        self.assertIn("if media_ready:", recipe)
        self.assertIn("/media/media_install.py", recipe)
        self.assertIn("media/installed-after-stdout.log", build)
        self.assertIn("media_selection_sha256", build)
        self.assertLess(workflow.index("require_media_lock"), workflow.index("gh api \"repos/ThirdKeyAI/symbi-os/actions/artifacts/$artifact/zip\""))


class MediaPlayback(unittest.TestCase):
    def test_fixtures_and_report_are_bounded_and_cover_both_players_and_media_types(self):
        with tempfile.TemporaryDirectory() as directory:
            fixtures = write_fixtures(Path(directory))
            self.assertEqual(set(fixtures), {"audio", "video"})
            self.assertLess(sum(path.stat().st_size for path in fixtures.values()), 128 * 1024)
            self.assertEqual({name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for name, path in fixtures.items()}, PLAYBACK_FIXTURE_SHA256)
        lock = json.loads((ROOT / "image/desktop_packages/media-rpms.lock.json").read_text())
        report = {
            "schema": 1, "passed": True, "variant": "generic", "lock_sha256": "a" * 64,
            "checks": [
                {"player": player, "media": media, "exit_code": 0, "bounded": True,
                 "fixture_sha256": PLAYBACK_FIXTURE_SHA256[media]}
                for player in ("mplayer", "mpv") for media in ("audio", "video")
            ],
            "limits": copy.deepcopy(PLAYBACK_LIMITS),
            "network": "none", "audio_device_qualified": False,
            "hardware_decode_qualified": False, "interactive_output_qualified": False,
            "scope": PLAYBACK_SCOPE,
            "cgroup_final": {
                **PLAYBACK_LIMITS,
                "memory.peak": "4096",
                "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
                "cpu.stat": "usage_usec 1\nuser_usec 1\nsystem_usec 0\n",
            },
            "installed_packages": [
                {name: row[name] for name in
                 ("name", "epoch", "version", "release", "arch", "nevra", "vendor", "license", "source_rpm")}
                for row in lock["root_packages"]
            ],
        }
        require_playback_report(report, "generic", "a" * 64, lock["root_packages"])
        for change in ("missing", "network", "claim", "package", "scope", "limit",
                       "oom", "fixture", "extra"):
            bad = copy.deepcopy(report)
            if change == "missing": bad["checks"].pop()
            elif change == "network": bad["network"] = "bridge"
            elif change == "claim": bad["hardware_decode_qualified"] = True
            elif change == "package": bad["installed_packages"][2]["release"] = "stale"
            elif change == "scope": bad["scope"] = "broader"
            elif change == "limit": bad["limits"]["memory.max"] = "unlimited"
            elif change == "oom": bad["cgroup_final"]["memory.events"] = \
                "low 0\nhigh 0\nmax 1\noom 1\noom_kill 0\noom_group_kill 0\n"
            elif change == "fixture": bad["checks"][0]["fixture_sha256"] = "0" * 64
            else: bad["unexpected"] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                require_playback_report(bad, "generic", "a" * 64, lock["root_packages"])

    def test_manual_hosted_matrix_is_serial_and_covers_generic_and_nvidia(self):
        workflow = (ROOT / ".github/workflows/media-playback.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("variant: [generic, nvidia]", workflow)
        self.assertIn("max-parallel: 1", workflow)
        self.assertIn("MemoryMax=3G", (ROOT / "scripts/check-media-playback.sh").read_text())


if __name__ == "__main__":
    unittest.main()
