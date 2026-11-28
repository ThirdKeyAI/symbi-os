"""Closed media-package selection, offline install and playback boundaries."""
import configparser
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from image.desktop_packages.media_contract import (
    FEDORA,
    FUSION,
    MAX_MEDIA_ARCHIVE_OVERHEAD_BYTES,
    MAX_MEDIA_ARTIFACT_BYTES,
    MAX_MEDIA_EXPANDED_BYTES,
    MAX_MEDIA_MANIFEST_BYTES,
    MAX_MEDIA_RPM_PAYLOAD_BYTES,
    media_selection_digest,
    offline_install_command,
    require_media_artifact_metadata,
    require_media_image_binding,
    require_media_lock,
    require_source_release_match,
)
from image.desktop_packages.media_closure import (
    PinnedPublicHTTPSHandler,
    PublicAddressResolver,
    require_public_https,
)
from image.desktop_packages.media_inputs import unpack_media_bundle
from image.desktop_packages.media_install import require_additive_inventory, trust_snapshot
from image.desktop_packages.media_closure_contract import (
    require_candidate_manifest,
    require_candidate_request,
    require_media_repositories,
)
from image.desktop_packages.media_closure_hosted import (
    HOSTED_BOUNDED_SECONDS,
    HOSTED_NON_COMMAND_RESERVE_SECONDS,
    HOSTED_SERVICE_TIMEOUT_SECONDS,
)
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

    def producer_request_fixture(self):
        return {
            "schema": 1,
            "release": self.lock["release"],
            "architecture": self.lock["architecture"],
            "resolution_base": self.lock["resolution_base"],
            "requirements": ["mplayer", "mpv"],
            "root_packages": copy.deepcopy(self.lock["root_packages"]),
            "trusted_keys": copy.deepcopy(self.lock["trusted_keys"]),
            "source_lock_sha256": hashlib.sha256(
                (ROOT / "image/desktop_packages/media-rpms.lock.json").read_bytes()).hexdigest(),
        }

    def producer_manifest_fixture(self, request):
        ready = self.ready_fixture()
        sources = [
            {name: row[name] for name in (
                "name", "epoch", "version", "release", "arch", "nevra", "filename",
                "bytes", "sha256", "signature_verified", "key_fingerprint")}
            for row in ready["source_inputs"]
        ]
        return {
            "schema": 1,
            "passed": True,
            "dedicated_media_closure": True,
            "package_transaction_attempted": False,
            "installed_packages_unchanged": True,
            "requirements": request["requirements"],
            "packages": copy.deepcopy(request["root_packages"]),
            "source_packages": sources,
            "negative_controls": {
                key: {"missing_key_rejected": True, "wrong_key_rejected": True,
                      "tampered_package_rejected": True}
                for key in (FEDORA, FUSION)
            },
            "packages_selected": False,
            "security_qualified": False,
            "os_qualified": False,
            "scope": (
                "Authenticated media-only candidates and source RPMs; no package transaction, "
                "program execution, security clearance or OS selection"),
        }

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

    def test_media_only_producer_request_and_manifest_preserve_closed_claims(self):
        request = self.producer_request_fixture()
        manifest = self.producer_manifest_fixture(request)
        self.assertTrue(require_candidate_request(request))
        self.assertTrue(require_candidate_manifest(manifest, request))
        for change in ("selection", "security", "transaction", "root", "source", "control"):
            bad = copy.deepcopy(manifest)
            if change == "selection": bad["packages_selected"] = True
            elif change == "security": bad["security_qualified"] = True
            elif change == "transaction": bad["package_transaction_attempted"] = True
            elif change == "root": bad["packages"].remove(request["root_packages"][2])
            elif change == "source": bad["source_packages"].pop()
            else: bad["negative_controls"][FEDORA]["wrong_key_rejected"] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                require_candidate_manifest(bad, request)

    def test_media_payload_limits_are_one_safe_producer_to_consumer_contract(self):
        self.assertEqual(MAX_MEDIA_ARTIFACT_BYTES, 2 * 1024**3)
        self.assertEqual(MAX_MEDIA_EXPANDED_BYTES + MAX_MEDIA_ARCHIVE_OVERHEAD_BYTES,
                         MAX_MEDIA_ARTIFACT_BYTES)
        self.assertEqual(MAX_MEDIA_RPM_PAYLOAD_BYTES + MAX_MEDIA_MANIFEST_BYTES,
                         MAX_MEDIA_EXPANDED_BYTES)
        request = self.producer_request_fixture()
        manifest = self.producer_manifest_fixture(request)
        for row in manifest["source_packages"]:
            row["bytes"] = 1024**3
        with self.assertRaisesRegex(ValueError, "payload exceeds"):
            require_candidate_manifest(manifest, request)

        lock = self.ready_fixture()
        for row in lock["source_inputs"]:
            row["bytes"] = 1024**3
        with self.assertRaisesRegex(ValueError, "payload exceeds"):
            require_media_lock(lock, ROOT, self.pins, self.trust, require_ready=True)
        lock = self.ready_fixture()
        lock["closure"]["artifact"]["bytes"] = MAX_MEDIA_ARTIFACT_BYTES + 1
        with self.assertRaisesRegex(ValueError, "artifact binding"):
            require_media_lock(lock, ROOT, self.pins, self.trust, require_ready=True)
        workflow = (ROOT / ".github/workflows/media-closure.yml").read_text()
        self.assertIn("compression-level: 0", workflow)

    def test_media_only_repositories_include_exact_binary_and_source_channels(self):
        path = ROOT / "image/desktop_packages/media.repo"
        declared = path.read_text()
        self.assertTrue(require_media_repositories(declared) is None)
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(declared)
        for section in parser.sections():
            for option in tuple(parser[section]):
                changed = configparser.ConfigParser(interpolation=None)
                changed.read_string(declared)
                changed.set(section, option, "adversarial-change")
                rendered = io.StringIO(); changed.write(rendered, space_around_delimiters=False)
                with self.subTest(section=section, option=option), self.assertRaises(ValueError):
                    require_media_repositories(rendered.getvalue())
        for shape in ("missing-field", "extra-field", "default-field", "duplicate-field"):
            changed = configparser.ConfigParser(interpolation=None)
            changed.read_string(declared)
            if shape == "missing-field":
                changed.remove_option("fedora", "type")
            elif shape == "extra-field":
                changed.set("fedora", "proxy", "https://public.example")
            rendered = io.StringIO(); changed.write(rendered, space_around_delimiters=False)
            text = rendered.getvalue()
            if shape == "default-field":
                text = "[DEFAULT]\nsslverify=1\n" + text
            elif shape == "duplicate-field":
                text = text.replace("type=rpm\n", "type=rpm\ntype=rpm\n", 1)
            with self.subTest(shape=shape), self.assertRaises(ValueError):
                require_media_repositories(text)

    def test_source_urls_resolve_once_to_only_global_addresses(self):
        calls = []

        def rebinding_resolver(hostname, port, family, kind, protocol):
            calls.append((hostname, port, family, kind, protocol))
            address = "8.8.8.8" if len(calls) == 1 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                     (address, port))]

        connected = []

        class FakeSocket:
            def settimeout(self, timeout):
                self.timeout = timeout

            def bind(self, address):
                self.source = address

            def connect(self, address):
                connected.append(address)

            def close(self):
                pass

        resolver = PublicAddressResolver(
            rebinding_resolver, lambda family, kind, protocol: FakeSocket())
        require_public_https("https://packages.example/source.rpm", resolver)
        handler = PinnedPublicHTTPSHandler(resolver)
        with mock.patch.object(handler, "do_open", return_value=mock.sentinel.response) as opened:
            self.assertIs(handler.https_open(mock.sentinel.request), mock.sentinel.response)
        connection = opened.call_args.args[0]
        client = connection("packages.example", timeout=5)
        self.assertIs(client._create_connection.__self__, resolver)
        stream = resolver.create_connection(("packages.example", 443), timeout=5)
        self.assertIsInstance(stream, FakeSocket)
        self.assertEqual(len(calls), 1)
        self.assertEqual(connected, [("8.8.8.8", 443)])

    def test_source_urls_reject_every_non_public_dns_class_and_mixed_answers(self):
        rejected = (
            "0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
            "192.0.2.1", "224.0.0.1", "240.0.0.1", "::", "::1", "fc00::1",
            "fe80::1", "ff02::1", "2001:db8::1",
        )
        for address in rejected:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)

            def resolve(_hostname, _port, _family, _kind, _protocol,
                        row=(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)):
                return [row]

            with self.subTest(address=address), self.assertRaises(ValueError):
                require_public_https(
                    "https://packages.example/source.rpm", PublicAddressResolver(resolve))

        def mixed(_hostname, port, _family, _kind, _protocol):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port)),
            ]

        with self.assertRaises(ValueError):
            require_public_https(
                "https://packages.example/source.rpm", PublicAddressResolver(mixed))
        malformed = (
            [],
            [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
              ("8.8.8.8", 444))],
            [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
              ("2606:4700:4700::1111", 443, 0, 2))],
            [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "",
              ("8.8.8.8", 443))],
            [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
              ("8.8.8.8", 443))] * 33,
        )
        for answers in malformed:
            with self.subTest(answers=answers), self.assertRaises(ValueError):
                require_public_https(
                    "https://packages.example/source.rpm",
                    PublicAddressResolver(
                        lambda _host, _port, _family, _kind, _protocol, rows=answers: rows))
        for url in ("https://127.0.0.1/source.rpm", "https://localhost/source.rpm",
                    "https://224.0.0.1/source.rpm", "https://packages.local/source.rpm",
                    "http://packages.example/source.rpm"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                require_public_https(url)

    def test_media_workflow_deadlines_reserve_cleanup_and_both_uploads(self):
        self.assertLessEqual(HOSTED_BOUNDED_SECONDS + HOSTED_NON_COMMAND_RESERVE_SECONDS,
                             HOSTED_SERVICE_TIMEOUT_SECONDS)
        self.assertEqual(HOSTED_SERVICE_TIMEOUT_SECONDS, 95 * 60)
        workflow = (ROOT / ".github/workflows/media-closure.yml").read_text()
        deadlines = [int(value) for value in re.findall(r"timeout-minutes: (\d+)", workflow)]
        self.assertEqual(deadlines, [130, 3, 98, 12, 2, 5])
        self.assertEqual(sum(deadlines[1:]), 120)
        self.assertEqual(deadlines[0] - sum(deadlines[1:]), 10)
        script = (ROOT / "scripts/check-media-closure.sh").read_text()
        self.assertIn("RuntimeMaxSec=95min", script)
        self.assertEqual(deadlines[2] * 60 - HOSTED_SERVICE_TIMEOUT_SECONDS, 3 * 60)

    def test_declared_media_producer_is_registered_manual_and_fail_closed(self):
        workflow = (ROOT / ".github/workflows/media-closure.yml").read_text()
        script = (ROOT / "scripts/check-media-closure.sh").read_text()
        guest = (ROOT / "image/desktop_packages/media_closure.py").read_text()
        hosted = (ROOT / "image/desktop_packages/media_closure_hosted.py").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("name: media-rpms-fedora-45-x86_64", workflow)
        self.assertIn("MemoryMax=3G", script)
        self.assertIn('"repoquery", "--arch=src"', guest)
        self.assertIn("def download_source", guest)
        self.assertIn('package_transaction_attempted": False', guest)
        self.assertIn("require_media_lock(lock, root, pins, trust)", hosted)

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
