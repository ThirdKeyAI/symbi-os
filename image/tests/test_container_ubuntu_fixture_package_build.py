"""Offline tests for the unselected Ubuntu fixture package producer."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import lzma
import os
from pathlib import Path
import signal
import stat
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

from image.container import ubuntu_fixture_inputs as inputs
from image.container import ubuntu_fixture_package_build as build
from image.container import ubuntu_fixture_packages as packages


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
DEFAULT_TIME = object()


def md5sum(payload):
    return hashlib.md5(payload, usedforsecurity=False).hexdigest()


def package_stanza(name, version, architecture, filename, payload,
                   *, pre_depends=None):
    dependency = ("" if pre_depends is None
                  else f"Pre-Depends: {pre_depends}\n")
    return (
        f"Package: {name}\n"
        f"Version: {version}\n"
        f"Architecture: {architecture}\n"
        f"{dependency}"
        f"Filename: {filename}\n"
        f"Size: {len(payload)}\n"
        f"MD5sum: {md5sum(payload)}\n"
        f"SHA256: {hashlib.sha256(payload).hexdigest()}\n\n"
    ).encode()


def release_bytes(source, index_bytes, *, date=None, valid_until=DEFAULT_TIME):
    date = NOW - timedelta(hours=1) if date is None else date
    if valid_until is DEFAULT_TIME:
        valid_until = None
    digest = hashlib.sha256(index_bytes).hexdigest()
    codename = build.EXPECTED_CODENAMES[source["suite"]]
    expiry = ("" if valid_until is None else
              f"Valid-Until: {build.format_release_time(valid_until)}\n")
    return (
        "Origin: Ubuntu\n"
        "Label: Ubuntu\n"
        f"Suite: {source['suite']}\n"
        f"Codename: {codename}\n"
        f"Date: {build.format_release_time(date)}\n"
        f"{expiry}"
        "Architectures: amd64 arm64\n"
        "Components: main restricted universe multiverse\n"
        "SHA256:\n"
        f" {digest} {len(index_bytes)} main/binary-amd64/Packages.xz\n"
    ).encode()


def write_private(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def mkdir_private(path):
    path.mkdir(mode=0o700)


def staged_repository(base):
    repository = base / "repo"
    mkdir_private(repository)
    for source in packages.EXPECTED_SOURCES:
        mkdir_private(repository / source["suite"])
    return repository, repository / "noble"


class FakeResponse(io.BytesIO):
    status = 200

    def __init__(self, payload, url):
        super().__init__(payload)
        self.url = url
        self.headers = {"Content-Length": str(len(payload))}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def geturl(self):
        return self.url


class UbuntuFixturePackageProducer(unittest.TestCase):
    def setUp(self):
        self.source = copy.deepcopy(packages.EXPECTED_SOURCES[0])
        self.payloads = {
            "python3": b"python payload",
            "git": b"git payload",
            "ca-certificates": b"ca payload",
        }
        self.paths = {
            "python3": "pool/main/p/python3/python3_3.12.3-0ubuntu2_amd64.deb",
            "git": "pool/main/g/git/git_1:2.43.0-1ubuntu7.1_amd64.deb",
            "ca-certificates": (
                "pool/main/c/ca-certificates/"
                "ca-certificates_20240203_all.deb"
            ),
        }
        versions = {
            "python3": "3.12.3-0ubuntu2",
            "git": "1:2.43.0-1ubuntu7.1",
            "ca-certificates": "20240203",
        }
        raw = b"".join(
            package_stanza(
                name, versions[name],
                "all" if name == "ca-certificates" else "amd64",
                self.paths[name], self.payloads[name],
                pre_depends=(
                    "python3-minimal (= 3.12.3-0ubuntu2)"
                    if name == "python3" else None),
            )
            for name in ("ca-certificates", "git", "python3")
        )
        # Keep the synthetic fixture's decoder dictionary small so this test
        # remains runnable inside the card's 128 MiB address-space ceiling.
        self.index = lzma.compress(raw, format=lzma.FORMAT_XZ, preset=0)
        self.release = release_bytes(self.source, self.index)
        self.binding = build.validate_signed_release(
            self.release, self.source, NOW,
            build.expected_freshness_policy(self.source))

    def candidate_fixture(self):
        lock = packages.unique_json(
            ROOT, "image/container/ubuntu-fixture-packages.lock.json")
        versions = {
            "python3": "3.12.3-0ubuntu2",
            "git": "1:2.43.0-1ubuntu7.1",
            "ca-certificates": "20240203",
        }
        package_rows = []
        for name in sorted(self.payloads):
            payload = self.payloads[name]
            package_rows.append({
                "package": name,
                "version": versions[name],
                "architecture": "all" if name == "ca-certificates" else "amd64",
                "filename": self.paths[name],
                "url": self.source["base_url"] + "/" + self.paths[name],
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "source": {
                    "suite": "noble", "component": "main",
                    "index_architecture": "amd64",
                    "index_sha256": self.binding["index"]["sha256"],
                },
            })
        package_rows.sort(key=packages.package_identity)
        release_rows = []
        index_rows = []
        metadata_contents = {}
        for sequence, source in enumerate(packages.EXPECTED_SOURCES):
            if source["suite"] == "noble":
                index_bytes = self.index
                release = self.release
                binding = self.binding
            else:
                marker = (source["suite"] + " package index").encode()
                marker_path = (
                    "pool/main/s/suite-marker/"
                    + source["suite"] + "-marker_1_amd64.deb"
                )
                index_bytes = lzma.compress(
                    package_stanza(
                        source["suite"] + "-marker", "1", "amd64",
                        marker_path, marker,
                    ),
                    format=lzma.FORMAT_XZ,
                    preset=0,
                )
                release = release_bytes(source, index_bytes)
                binding = build.validate_signed_release(
                    release, source, NOW,
                    build.expected_freshness_policy(source))
            release_rows.append(build.release_record(
                source, binding,
                {
                    "bytes": len(release),
                    "sha256": hashlib.sha256(release).hexdigest(),
                },
                {
                    "signing_fingerprint": packages.ARCHIVE_SIGNER_FINGERPRINT,
                    "status_sha256": format(sequence + 1, "064x"),
                },
            ))
            index_row = build.index_record(source, binding["index"])
            index_rows.append(index_row)
            metadata_contents[source["suite"] + "_InRelease"] = release
            metadata_contents[index_row["filename"]] = index_bytes
        manifest = build.candidate_manifest(
            lock, release_rows, index_rows, package_rows,
            verified_at=NOW,
            base_status={"bytes": 100, "sha256": "a" * 64},
            tools={
                "apt_get": {"version": "apt 2.8.3", "sha256": "b" * 64},
                "dpkg": {"version": "Debian dpkg 1.22.6", "sha256": "c" * 64},
                "gpgv": {"version": "gpgv 2.4.4", "sha256": "d" * 64},
            },
            command_hashes={name: character * 64 for name, character in (
                ("apt_update", "1"), ("apt_uri_plan", "2"),
                ("apt_simulation", "3"), ("dpkg_plan", "4"),
            )},
            download_order=[row["sha256"] for row in package_rows],
            metadata_provenance={
                "producer_run_id": 123,
                "producer_run_attempt": 1,
                "producer_head_sha": "e" * 40,
                "producer_head_tree": "d" * 40,
                "producer_branch": "card/P0-05-retained-metadata",
                "artifact_id": 456,
                "artifact_name": "container-ubuntu-fixture-metadata",
                "artifact_bytes": 789,
                "artifact_api_sha256": "f" * 64,
                "artifact_zip_sha256": "f" * 64,
                "manifest_sha256": "0" * 64,
                "discovery_contract_sha256": "1" * 64,
                "selection_contract_sha256": "3" * 64,
                "metadata_lock_sha256": "2" * 64,
            },
        )
        return lock, manifest, metadata_contents, package_rows

    def stage_candidate_inputs(self, base, metadata_contents, package_rows):
        staged_metadata = base / "staged-metadata"
        staged_packages = base / "staged-packages"
        mkdir_private(staged_metadata)
        mkdir_private(staged_packages)
        metadata_inputs = {}
        for name, raw in metadata_contents.items():
            path = staged_metadata / name
            write_private(path, raw)
            metadata_inputs[name] = path
        package_inputs = {}
        for row in package_rows:
            path = staged_packages / Path(row["filename"]).name
            write_private(path, self.payloads[row["package"]])
            package_inputs[row["filename"]] = path
        return metadata_inputs, package_inputs

    def download_fixture(self):
        _, _, _, package_rows = self.candidate_fixture()
        plan = [{
            "sequence": sequence,
            "suite": row["source"]["suite"],
            "filename": row["filename"],
            "destination": Path(row["filename"]).name,
            "bytes": row["bytes"],
            "sha256": row["sha256"],
        } for sequence, row in enumerate(package_rows)]
        return plan, package_rows

    def synthetic_rootfs_lock(self, archive):
        lock = packages.unique_json(
            ROOT, "image/container/ubuntu-fixture-packages.lock.json")
        rootfs = copy.deepcopy(packages.EXPECTED_ROOTFS)
        rootfs["bytes"] = archive.stat().st_size
        rootfs["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
        lock["rootfs"] = rootfs
        return lock, rootfs

    def test_gpgv_status_requires_one_exact_signature_and_no_bad_status(self):
        fingerprint = packages.ARCHIVE_SIGNER_FINGERPRINT
        status = (
            "[GNUPG:] NEWSIG\n"
            "[GNUPG:] GOODSIG 871920D1991BC93C Ubuntu Archive\n"
            f"[GNUPG:] VALIDSIG {fingerprint} 2026-11-27 1795780800 "
            f"0 4 0 1 10 01 {fingerprint}\n"
        )
        result = build.validate_gpgv_status(0, status, fingerprint)
        self.assertEqual(result["signing_fingerprint"], fingerprint)
        self.assertEqual(
            result["status_sha256"], hashlib.sha256(status.encode()).hexdigest())
        for returncode, changed in (
            (1, status),
            (0, status.replace(fingerprint, "A" * 40)),
            (0, status.replace("871920D1991BC93C", "0000000000000000", 1)),
            (0, status + status),
            (0, status + "[GNUPG:] REVKEYSIG deadbeef stale\n"),
            (0, "[GNUPG:] GOODSIG short label\n"),
        ):
            with self.subTest(returncode=returncode, changed=changed), \
                    self.assertRaises(ValueError):
                build.validate_gpgv_status(returncode, changed, fingerprint)

    def test_release_binds_exact_suite_freshness_and_packages_index(self):
        self.assertEqual(self.binding["suite"], "noble")
        self.assertEqual(self.binding["codename"], "noble")
        self.assertEqual(
            self.binding["index"],
            {
                "path": "main/binary-amd64/Packages.xz",
                "bytes": len(self.index),
                "sha256": hashlib.sha256(self.index).hexdigest(),
            },
        )
        self.assertLess(self.binding["date"], self.binding["verified_at"])
        self.assertIsNone(self.binding["valid_until"])

    def test_release_ignores_oversized_irrelevant_sha256_row(self):
        irrelevant = (
            f" {'f' * 64} {packages.MAX_INDEX_BYTES + 1} "
            "main/binary-arm64/Packages.xz\n"
        ).encode()
        binding = build.validate_signed_release(
            self.release + irrelevant, self.source, NOW,
            build.expected_freshness_policy(self.source))
        self.assertEqual(binding["index"], self.binding["index"])

    def test_release_accepts_canonical_zero_for_irrelevant_sha256_row(self):
        irrelevant = (
            f" {'f' * 64} 0 main/binary-arm64/Packages.xz\n"
        ).encode()
        binding = build.validate_signed_release(
            self.release + irrelevant, self.source, NOW,
            build.expected_freshness_policy(self.source))
        self.assertEqual(binding["index"], self.binding["index"])

    def test_release_rejects_oversized_exact_target_sha256_row(self):
        digest = hashlib.sha256(self.index).hexdigest()
        target = (
            f" {digest} {len(self.index)} main/binary-amd64/Packages.xz\n"
        ).encode()
        for size_text in (str(packages.MAX_INDEX_BYTES + 1), "9" * 5000):
            oversized = (
                f" {digest} {size_text} main/binary-amd64/Packages.xz\n"
            ).encode()
            with self.subTest(digits=len(size_text)), \
                    self.assertRaises(
                        build.ReleaseInventoryRejection) as caught:
                build.validate_signed_release(
                    self.release.replace(target, oversized), self.source, NOW,
                    build.expected_freshness_policy(self.source))
            self.assertEqual(
                build.release_rejection_reason(caught.exception),
                "index-inventory-rejected")
            self.assertEqual(
                build.release_rejection_predicate(caught.exception),
                "target-index-byte-bound")
            self.assertNotIn(size_text, str(caught.exception))

    def test_release_rejects_zero_exact_target_with_fixed_byte_bound(self):
        digest = hashlib.sha256(self.index).hexdigest()
        target = (
            f" {digest} {len(self.index)} main/binary-amd64/Packages.xz\n"
        ).encode()
        zero = f" {digest} 0 main/binary-amd64/Packages.xz\n".encode()
        with self.assertRaises(build.ReleaseInventoryRejection) as caught:
            build.validate_signed_release(
                self.release.replace(target, zero), self.source, NOW,
                build.expected_freshness_policy(self.source))
        self.assertEqual(
            build.release_rejection_reason(caught.exception),
            "index-inventory-rejected")
        self.assertEqual(
            build.release_rejection_predicate(caught.exception),
            "target-index-byte-bound")
        self.assertNotIn(zero.strip().decode(), str(caught.exception))

    def test_release_rejects_invalid_irrelevant_sha256_rows(self):
        digest = "f" * 64
        valid = f" {digest} 1 main/binary-arm64/Packages.xz\n"
        cases = (
            (f" {digest} malformed main/binary-arm64/Packages.xz\n",
             "sha256-size-syntax"),
            (f" {digest} 00 main/binary-arm64/Packages.xz\n",
             "sha256-size-syntax"),
            (f" {digest} 01 main/binary-arm64/Packages.xz\n",
             "sha256-size-syntax"),
            (f" {digest} +1 main/binary-arm64/Packages.xz\n",
             "sha256-size-syntax"),
            (f" {digest} -1 main/binary-arm64/Packages.xz\n",
             "sha256-size-syntax"),
            (f" {digest} 1x main/binary-arm64/Packages.xz\n",
             "sha256-size-syntax"),
            (f" {digest} 1 ../main/binary-arm64/Packages.xz\n",
             "sha256-path-safety"),
            (valid + valid, "sha256-duplicate-path"),
        )
        for row, predicate in cases:
            with self.subTest(predicate=predicate), \
                    self.assertRaises(build.ReleaseInventoryRejection) as caught:
                build.validate_signed_release(
                    self.release + row.encode(), self.source, NOW,
                    build.expected_freshness_policy(self.source))
            self.assertEqual(
                build.release_rejection_predicate(caught.exception), predicate)
            self.assertNotIn(row.strip(), str(caught.exception))

    def test_release_inventory_rejection_subtypes_are_fixed_and_content_free(self):
        digest = hashlib.sha256(self.index).hexdigest()
        target = f" {digest} {len(self.index)} main/binary-amd64/Packages.xz\n"
        cases = (
            (self.release + b" malformed\n", "sha256-columns"),
            (self.release +
             f" {'g' * 64} 1 main/binary-arm64/Packages.xz\n".encode(),
             "sha256-digest-syntax"),
            (self.release.replace(target.encode(), b"")
             + f" {digest} 1 main/binary-arm64/Packages.xz\n".encode(),
             "target-index-membership"),
        )
        for raw, predicate in cases:
            with self.subTest(predicate=predicate), \
                    self.assertRaises(build.ReleaseInventoryRejection) as caught:
                build.validate_signed_release(
                    raw, self.source, NOW,
                    build.expected_freshness_policy(self.source))
            self.assertEqual(
                build.release_rejection_reason(caught.exception),
                "index-inventory-rejected")
            self.assertEqual(
                build.release_rejection_predicate(caught.exception), predicate)
            self.assertIn(predicate, build.RELEASE_INVENTORY_PREDICATES)
        ordinary = ValueError("Ubuntu Release SHA256 parser failed")
        self.assertEqual(
            build.release_rejection_reason(ordinary),
            "release-structure-rejected")
        self.assertIsNone(build.release_rejection_predicate(ordinary))

    def test_stale_future_wrong_suite_and_ambiguous_release_metadata_fail(self):
        duplicate = self.release + (
            f" {hashlib.sha256(self.index).hexdigest()} {len(self.index)} "
            "main/binary-amd64/Packages.xz\n"
        ).encode()
        cases = [
            release_bytes(
                self.source, self.index,
                date=NOW - build.MAX_IMMUTABLE_RELEASE_AGE
                - timedelta(seconds=1),
            ),
            release_bytes(
                self.source, self.index,
                date=NOW + build.MAX_CLOCK_SKEW + timedelta(seconds=1),
            ),
            self.release.replace(b"Suite: noble\n", b"Suite: noble-updates\n"),
            self.release.replace(b"Codename: noble\n", b"Codename: jammy\n"),
            release_bytes(
                self.source, self.index,
                valid_until=NOW + timedelta(days=1),
            ),
            self.release.replace(b"Architectures: amd64 arm64", b"Architectures: arm64"),
            duplicate,
        ]
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                build.validate_signed_release(
                    changed, self.source, NOW,
                    build.expected_freshness_policy(self.source))

    def test_immutable_release_age_and_clock_skew_boundaries_are_exact(self):
        policy = build.expected_freshness_policy(self.source)
        at_age = release_bytes(
            self.source, self.index,
            date=NOW - build.MAX_IMMUTABLE_RELEASE_AGE)
        at_skew = release_bytes(
            self.source, self.index, date=NOW + build.MAX_CLOCK_SKEW)
        build.validate_signed_release(at_age, self.source, NOW, policy)
        build.validate_signed_release(at_skew, self.source, NOW, policy)
        for changed in (
                release_bytes(
                    self.source, self.index,
                    date=NOW - build.MAX_IMMUTABLE_RELEASE_AGE
                    - timedelta(seconds=1)),
                release_bytes(
                    self.source, self.index,
                    date=NOW + build.MAX_CLOCK_SKEW + timedelta(seconds=1))):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                build.validate_signed_release(
                    changed, self.source, NOW, policy)

    def test_freshness_policy_cannot_cross_suite_url_codename_or_signer(self):
        policy = build.expected_freshness_policy(self.source)
        cases = []
        for field, value in (
                ("suite", "noble-updates"),
                ("codename", "jammy"),
                ("inrelease_url", "https://security.ubuntu.com/ubuntu/dists/noble/InRelease"),
                ("signer_fingerprint", "A" * 40),
                ("mode", "rolling-date"),
                ("maximum_age_days", 1831)):
            changed = copy.deepcopy(policy)
            changed[field] = value
            cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                build.validate_signed_release(
                    self.release, self.source, NOW, changed)

    def test_rolling_pockets_bound_date_and_optional_valid_until(self):
        for source in map(copy.deepcopy, packages.EXPECTED_SOURCES[1:]):
            policy = build.expected_freshness_policy(source)
            self.assertEqual(policy["mode"], "rolling-date")
            self.assertEqual(
                policy["maximum_age_days"],
                build.MAX_ROLLING_RELEASE_AGE.days)

            absent = release_bytes(source, self.index, valid_until=None)
            binding = build.validate_signed_release(
                absent, source, NOW, policy)
            self.assertIsNone(binding["valid_until"])

            at_age = release_bytes(
                source, self.index,
                date=NOW - build.MAX_ROLLING_RELEASE_AGE,
                valid_until=None)
            at_skew = release_bytes(
                source, self.index,
                date=NOW + build.MAX_CLOCK_SKEW,
                valid_until=None)
            build.validate_signed_release(at_age, source, NOW, policy)
            build.validate_signed_release(at_skew, source, NOW, policy)

            with_expiry = release_bytes(
                source, self.index,
                valid_until=NOW + timedelta(days=1))
            expiring = build.validate_signed_release(
                with_expiry, source, NOW, policy)
            self.assertGreater(expiring["valid_until"], expiring["verified_at"])

            duplicate = with_expiry + (
                b"Valid-Until: "
                + build.format_release_time(NOW + timedelta(hours=1)).encode()
                + b"\n")
            duplicate_date = absent + (
                b"Date: "
                + build.format_release_time(NOW - timedelta(minutes=1)).encode()
                + b"\n")
            malformed_expiry = with_expiry.replace(
                next(line for line in with_expiry.splitlines(keepends=True)
                     if line.startswith(b"Valid-Until:")),
                b"Valid-Until: malformed\n")
            oversized_expiry = with_expiry.replace(
                next(line for line in with_expiry.splitlines(keepends=True)
                     if line.startswith(b"Valid-Until:")),
                b"Valid-Until: " + b"1" * 129 + b"\n")
            cases = (
                release_bytes(
                    source, self.index,
                    date=NOW - build.MAX_ROLLING_RELEASE_AGE
                    - timedelta(seconds=1),
                    valid_until=None),
                release_bytes(
                    source, self.index,
                    date=NOW + build.MAX_CLOCK_SKEW + timedelta(seconds=1),
                    valid_until=None),
                release_bytes(
                    source, self.index,
                    valid_until=NOW - timedelta(seconds=1)),
                release_bytes(
                    source, self.index,
                    valid_until=NOW + build.MAX_ROLLING_RELEASE_AGE
                    + timedelta(seconds=1)),
                release_bytes(
                    source, self.index,
                    valid_until=NOW - timedelta(hours=2)),
                duplicate,
                duplicate_date,
                malformed_expiry,
                oversized_expiry,
                absent.replace(
                    next(line for line in absent.splitlines(keepends=True)
                         if line.startswith(b"Date:")), b""),
                absent.replace(
                    next(line for line in absent.splitlines(keepends=True)
                         if line.startswith(b"Date:")), b"Date: malformed\n"),
            )
            for changed in cases:
                with self.subTest(suite=source["suite"], changed=changed), \
                        self.assertRaises(ValueError):
                    build.validate_signed_release(
                        changed, source, NOW, policy)

            for field, value in (
                    ("mode", "valid-until"),
                    ("maximum_age_days",
                     build.MAX_ROLLING_RELEASE_AGE.days + 1)):
                changed_policy = copy.deepcopy(policy)
                changed_policy[field] = value
                with self.subTest(suite=source["suite"], field=field), \
                        self.assertRaises(ValueError):
                    build.validate_signed_release(
                        absent, source, NOW, changed_policy)

    def test_signed_index_membership_returns_only_exact_requested_rows(self):
        requested = {
            self.paths[name]: {
                "bytes": len(payload),
                "md5": md5sum(payload),
            }
            for name, payload in self.payloads.items()
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Packages.xz"
            write_private(path, self.index)
            rows = build.find_requested_packages(
                path, self.source, self.binding["index"], requested)
        self.assertEqual(set(rows), set(requested))
        self.assertEqual(rows[self.paths["git"]]["package"], "git")
        self.assertEqual(
            rows[self.paths["ca-certificates"]]["architecture"], "all")

    def test_index_tampering_duplicates_and_nonmembers_fail(self):
        requested = {
            self.paths["git"]: {
                "bytes": len(self.payloads["git"]),
                "md5": md5sum(self.payloads["git"]),
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Packages.xz"
            write_private(path, self.index)
            bad_binding = copy.deepcopy(self.binding["index"])
            bad_binding["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                build.find_requested_packages(path, self.source, bad_binding, requested)
            bad_md5 = copy.deepcopy(requested)
            bad_md5[self.paths["git"]]["md5"] = "0" * 32
            with self.assertRaises(ValueError):
                build.find_requested_packages(
                    path, self.source, self.binding["index"], bad_md5)
            missing = copy.deepcopy(requested)
            missing["pool/main/m/missing/missing_1_amd64.deb"] = {
                "bytes": 1, "md5": "1" * 32,
            }
            with self.assertRaises(ValueError):
                build.find_requested_packages(
                    path, self.source, self.binding["index"], missing)

            duplicated = lzma.compress(
                lzma.decompress(self.index) + lzma.decompress(self.index),
                format=lzma.FORMAT_XZ,
                preset=0,
            )
            write_private(path, duplicated)
            duplicate_binding = {
                "path": "main/binary-amd64/Packages.xz",
                "bytes": len(duplicated),
                "sha256": hashlib.sha256(duplicated).hexdigest(),
            }
            with self.assertRaises(ValueError):
                build.find_requested_packages(
                    path, self.source, duplicate_binding, requested)

    def test_index_binding_and_compressed_size_reject_before_hash_or_parse(self):
        requested = {
            self.paths["git"]: {
                "bytes": len(self.payloads["git"]),
                "md5": md5sum(self.payloads["git"]),
            }
        }
        invalid = []
        extra = copy.deepcopy(self.binding["index"])
        extra["unexpected"] = "caller evidence"
        invalid.append(extra)
        boolean_size = copy.deepcopy(self.binding["index"])
        boolean_size["bytes"] = True
        invalid.append(boolean_size)
        oversized = copy.deepcopy(self.binding["index"])
        oversized["bytes"] = packages.MAX_INDEX_BYTES + 1
        invalid.append(oversized)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Packages.xz"
            write_private(path, self.index)
            with mock.patch.object(build, "_fd_sha256") as digest, \
                    mock.patch.object(build, "_iter_control_stanzas") as parse:
                for binding in invalid:
                    with self.subTest(binding=binding), self.assertRaises(ValueError):
                        build.find_requested_packages(
                            path, self.source, binding, requested)
                digest.assert_not_called()
                parse.assert_not_called()

            sparse = Path(directory) / "sparse-Packages.xz"
            with sparse.open("wb") as stream:
                stream.truncate(packages.MAX_INDEX_BYTES + 1)
            sparse.chmod(0o600)
            maximum = copy.deepcopy(self.binding["index"])
            maximum["bytes"] = packages.MAX_INDEX_BYTES
            with mock.patch.object(build, "_fd_sha256") as digest, \
                    mock.patch.object(build, "_iter_control_stanzas") as parse, \
                    self.assertRaises(ValueError):
                build.find_requested_packages(
                    sparse, self.source, maximum, requested)
            digest.assert_not_called()
            parse.assert_not_called()

    def test_private_index_rejects_symlinks_hardlinks_modes_and_owner(self):
        requested = {
            self.paths["git"]: {
                "bytes": len(self.payloads["git"]),
                "md5": md5sum(self.payloads["git"]),
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            direct = base / "direct"
            mkdir_private(direct)
            index = direct / "Packages.xz"
            write_private(index, self.index)

            component_link = base / "component-link"
            component_link.symlink_to(direct, target_is_directory=True)
            with self.assertRaises(ValueError):
                build.find_requested_packages(
                    component_link / "Packages.xz", self.source,
                    self.binding["index"], requested)

            leaf_link = direct / "leaf.xz"
            leaf_link.symlink_to(index)
            with self.assertRaises(ValueError):
                build.find_requested_packages(
                    leaf_link, self.source, self.binding["index"], requested)

            hardlink = direct / "hardlink.xz"
            os.link(index, hardlink)
            with self.assertRaises(ValueError):
                build.find_requested_packages(
                    index, self.source, self.binding["index"], requested)
            hardlink.unlink()

            index.chmod(0o640)
            with self.assertRaises(ValueError):
                build.find_requested_packages(
                    index, self.source, self.binding["index"], requested)
            index.chmod(0o600)

            info = index.stat()
            changed_owner = mock.Mock(
                st_mode=stat.S_IFREG | 0o600, st_nlink=1,
                st_uid=os.geteuid() + 1, st_gid=os.getegid(),
                st_size=info.st_size,
            )
            with self.assertRaises(ValueError):
                build._require_private_regular(
                    changed_owner, info.st_size, "hostile owner")

    def test_index_descriptor_rejects_leaf_swap_mode_and_size_changes(self):
        requested = {
            self.paths["git"]: {
                "bytes": len(self.payloads["git"]),
                "md5": md5sum(self.payloads["git"]),
            }
        }
        real_iter = build._iter_control_stanzas
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = base / "Packages.xz"
            write_private(path, self.index)
            saved = base / "saved.xz"

            def swapped(descriptor):
                path.rename(saved)
                write_private(path, self.index)
                yield from real_iter(descriptor)

            with mock.patch.object(build, "_iter_control_stanzas", swapped), \
                    self.assertRaises(ValueError):
                build.find_requested_packages(
                    path, self.source, self.binding["index"], requested)

        for mutation in ("mode", "size"):
            with self.subTest(mutation=mutation), \
                    tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "Packages.xz"
                write_private(path, self.index)

                def changed(descriptor):
                    if mutation == "mode":
                        path.chmod(0o640)
                    else:
                        with path.open("ab") as stream:
                            stream.write(b"changed")
                    yield from real_iter(descriptor)

                with mock.patch.object(build, "_iter_control_stanzas", changed), \
                        self.assertRaises(ValueError):
                    build.find_requested_packages(
                        path, self.source, self.binding["index"], requested)

    def test_every_opened_index_component_uses_nofollow_and_cloexec(self):
        requested = {
            self.paths["git"]: {
                "bytes": len(self.payloads["git"]),
                "md5": md5sum(self.payloads["git"]),
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Packages.xz"
            write_private(path, self.index)
            observed = []
            real_open = os.open

            def tracked(path_value, flags, *args, **kwargs):
                observed.append(flags)
                return real_open(path_value, flags, *args, **kwargs)

            with mock.patch.object(build.os, "open", tracked):
                build.find_requested_packages(
                    path, self.source, self.binding["index"], requested)
        self.assertTrue(observed)
        self.assertTrue(all(flags & os.O_NOFOLLOW for flags in observed))
        self.assertTrue(all(flags & os.O_CLOEXEC for flags in observed))

    def test_file_uri_plan_parses_md5_size_suite_and_order(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, suite = staged_repository(Path(directory))
            lines = []
            for name in ("git", "python3", "ca-certificates"):
                payload = self.payloads[name]
                digest = md5sum(payload)
                uri = (suite / self.paths[name]).as_uri()
                lines.append(
                    f"'{uri}' '{Path(self.paths[name]).name}' "
                    f"{len(payload)} 'MD5Sum:{digest}'"
                )
            plan = build.parse_apt_uri_plan(
                ("\n".join(lines) + "\n").encode(), repository,
                packages.EXPECTED_SOURCES)
        self.assertEqual([row["sequence"] for row in plan], [0, 1, 2])
        self.assertEqual([row["suite"] for row in plan], ["noble"] * 3)
        self.assertEqual(plan[0]["filename"], self.paths["git"])
        self.assertEqual(plan[0]["md5"], md5sum(self.payloads["git"]))

    def test_uri_plan_rejects_network_rows_duplicates_and_bad_md5(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, suite = staged_repository(Path(directory))
            payload = self.payloads["git"]
            digest = md5sum(payload)
            uri = (suite / self.paths["git"]).as_uri()
            good = f"'{uri}' 'git.deb' {len(payload)} 'MD5Sum:{digest}'\n"
            cases = [
                good + good,
                good.replace("file://", "https://"),
                good.replace("MD5Sum:", "SHA256:"),
                good.replace(digest, "A" * 32),
                good.replace(digest, digest[:-1]),
                good.replace(str(len(payload)), "0", 1),
                good + "unexpected output\n",
            ]
            for changed in cases:
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    build.parse_apt_uri_plan(
                        changed.encode(), repository, packages.EXPECTED_SOURCES)

    def test_uri_plan_normalizes_only_apt_percent_hex_case(self):
        with tempfile.TemporaryDirectory() as directory:
            repository, suite = staged_repository(Path(directory))
            filename = (
                "pool/main/g/gcc-14/"
                "libstdc++6_1:14.2.0-4ubuntu2~24.04.1+really_amd64.deb"
            )
            payload = b"signed package payload"
            digest = md5sum(payload)
            encoded_path = (str(suite / filename).replace("+", "%2b")
                            .replace("~", "%7e").replace(":", "%3a"))
            uri = "file:" + encoded_path
            self.assertIn("%2b", uri)
            self.assertIn("%3a", uri)
            self.assertIn("%7e", uri)
            line = f"'{uri}' 'libstdc++6.deb' {len(payload)} 'MD5Sum:{digest}'\n"
            plan = build.parse_apt_uri_plan(
                line.encode(), repository, packages.EXPECTED_SOURCES)
            self.assertEqual(plan[0]["filename"], filename)

            uppercase = (line.replace("%2b", "%2B").replace("%3a", "%3A")
                         .replace("%7e", "%7E"))
            self.assertEqual(
                build.parse_apt_uri_plan(
                    uppercase.encode(), repository, packages.EXPECTED_SOURCES),
                plan,
            )
            aliases = [
                line.replace("%2b", "+"),
                line.replace("%3a", ":"),
                line.replace("%7e", "~"),
                line.replace("/pool/", "/%70ool/"),
                line.replace("/pool/", "%2fpool/"),
                line.replace("/pool/", "/%2e%2e/"),
                line.replace("%2b", "%2g"),
            ]
            for alias in aliases:
                with self.subTest(alias=alias), self.assertRaises(ValueError):
                    build.parse_apt_uri_plan(
                        alias.encode(), repository, packages.EXPECTED_SOURCES)

    def test_uri_plan_binds_index_rows_and_downloads_payloads_sequentially(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository, suite = staged_repository(base)
            index_path = base / "Packages.xz"
            write_private(index_path, self.index)
            lines = []
            order = ("git", "python3", "ca-certificates")
            for name in order:
                payload = self.payloads[name]
                lines.append(
                    f"'{(suite / self.paths[name]).as_uri()}' "
                    f"'{name}.deb' {len(payload)} "
                    f"'MD5Sum:{md5sum(payload)}'"
                )
            plan = build.parse_apt_uri_plan(
                ("\n".join(lines) + "\n").encode(), repository,
                packages.EXPECTED_SOURCES)
            plan, rows, pre_depends = build.bind_uri_plan_to_indexes(
                plan,
                {"noble": {"path": index_path, "binding": self.binding["index"]}},
                packages.EXPECTED_SOURCES,
            )
            self.assertNotIn("md5", plan[0])
            self.assertEqual(
                plan[0]["sha256"],
                hashlib.sha256(self.payloads[order[0]]).hexdigest(),
            )
            self.assertEqual(
                pre_depends,
                [None, "python3-minimal (= 3.12.3-0ubuntu2)", None],
            )
            downloads = base / "downloads"
            mkdir_private(downloads)
            observed = []
            by_url = {
                self.source["base_url"] + "/" + self.paths[name]: self.payloads[name]
                for name in order
            }

            def opener(request, timeout):
                observed.append(request.full_url)
                return FakeResponse(by_url[request.full_url], request.full_url)

            output = build.download_package_plan(
                plan, rows, downloads, opener=opener)
        self.assertEqual(
            observed,
            [self.source["base_url"] + "/" + self.paths[name] for name in order],
        )
        self.assertEqual([row["sequence"] for row in output], [0, 1, 2])
        self.assertEqual(
            [row["sha256"] for row in output],
            [hashlib.sha256(self.payloads[name]).hexdigest() for name in order],
        )

    def test_download_preflight_rejects_every_bad_plan_before_opener(self):
        plan, rows = self.download_fixture()
        cases = []

        changed_plan, changed_rows = copy.deepcopy(plan), copy.deepcopy(rows)
        changed_rows[0]["url"] = (
            "https://unreviewed.invalid/" + changed_rows[0]["filename"])
        cases.append(("unreviewed host", changed_plan, changed_rows))

        changed_plan, changed_rows = copy.deepcopy(plan), copy.deepcopy(rows)
        changed_plan[0]["extra"] = "caller field"
        cases.append(("plan extra", changed_plan, changed_rows))

        changed_plan, changed_rows = copy.deepcopy(plan), copy.deepcopy(rows)
        changed_rows[0]["extra"] = "caller field"
        cases.append(("package extra", changed_plan, changed_rows))

        changed_plan, changed_rows = copy.deepcopy(plan), copy.deepcopy(rows)
        changed_plan[0]["sequence"] = True
        cases.append(("boolean sequence", changed_plan, changed_rows))

        changed_plan, changed_rows = copy.deepcopy(plan), copy.deepcopy(rows)
        changed_plan[0]["bytes"] = True
        changed_rows[0]["bytes"] = True
        cases.append(("boolean bytes", changed_plan, changed_rows))

        changed_plan, changed_rows = copy.deepcopy(plan), copy.deepcopy(rows)
        changed_rows[1] = copy.deepcopy(changed_rows[0])
        changed_plan[1].update({
            "suite": changed_rows[1]["source"]["suite"],
            "filename": changed_rows[1]["filename"],
            "destination": "duplicate.deb",
            "bytes": changed_rows[1]["bytes"],
            "sha256": changed_rows[1]["sha256"],
        })
        cases.append(("duplicate identity", changed_plan, changed_rows))

        source = packages.EXPECTED_SOURCES[0]
        oversized_plan = []
        oversized_rows = []
        for sequence in range(5):
            filename = f"pool/main/p/package-{sequence}/package-{sequence}_1_amd64.deb"
            digest = format(sequence + 1, "064x")
            oversized_rows.append({
                "package": f"package-{sequence}",
                "version": "1",
                "architecture": "amd64",
                "filename": filename,
                "url": source["base_url"] + "/" + filename,
                "bytes": packages.MAX_PACKAGE_BYTES,
                "sha256": digest,
                "source": {
                    "suite": source["suite"],
                    "component": "main",
                    "index_architecture": "amd64",
                    "index_sha256": "f" * 64,
                },
            })
            oversized_plan.append({
                "sequence": sequence,
                "suite": source["suite"],
                "filename": filename,
                "destination": f"package-{sequence}.deb",
                "bytes": packages.MAX_PACKAGE_BYTES,
                "sha256": digest,
            })
        cases.append(("aggregate bytes", oversized_plan, oversized_rows))

        with tempfile.TemporaryDirectory() as directory:
            downloads = Path(directory) / "downloads"
            mkdir_private(downloads)
            for description, changed_plan, changed_rows in cases:
                calls = []

                def opener(*args, **kwargs):
                    calls.append((args, kwargs))
                    raise AssertionError("invalid download reached opener")

                with self.subTest(description=description), \
                        self.assertRaises(ValueError):
                    build.download_package_plan(
                        changed_plan, changed_rows, downloads, opener=opener)
                self.assertEqual(calls, [])

            calls = []
            with mock.patch.object(build, "MAX_DOWNLOAD_SECONDS", -1), \
                    self.assertRaises(ValueError):
                build.download_package_plan(
                    plan, rows, downloads,
                    opener=lambda *args, **kwargs: calls.append(
                        (args, kwargs)),
                )
            self.assertEqual(calls, [])
            self.assertEqual(list(downloads.iterdir()), [])

    def test_aggregate_deadline_interrupts_blocking_read_and_restores_signal(self):
        plan, rows = self.download_fixture()
        calls = []
        read_fd, write_fd = os.pipe()

        class BlockingResponse:
            status = 200

            def __init__(self, payload, url):
                self.url = url
                self.headers = {"Content-Length": str(len(payload))}

            def __enter__(self):
                return self

            def __exit__(self, *_):
                os.close(read_fd)

            def geturl(self):
                return self.url

            def read(self, size=-1):
                return os.read(read_fd, size)

        def opener(request, timeout):
            calls.append((request.full_url, timeout))
            payload = self.payloads[rows[0]["package"]]
            return BlockingResponse(payload, request.full_url)

        def unblock_regressed_reader():
            try:
                os.write(write_fd, b"x")
            except OSError:
                pass
            try:
                os.close(write_fd)
            except OSError:
                pass

        unblocker = threading.Timer(1.0, unblock_regressed_reader)

        previous_handler = signal.getsignal(signal.SIGALRM)
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        self.assertEqual(previous_timer, (0.0, 0.0))

        def sentinel_handler(_signum, _frame):
            raise AssertionError("restored handler should not run")

        signal.signal(signal.SIGALRM, sentinel_handler)
        unblocker.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                downloads = Path(directory) / "downloads"
                mkdir_private(downloads)
                started = time.monotonic()
                with mock.patch.object(build, "MAX_DOWNLOAD_SECONDS", 0.05), \
                        self.assertRaises(TimeoutError):
                    build.download_package_plan(
                        plan, rows, downloads, opener=opener)
                elapsed = time.monotonic() - started
                self.assertLess(elapsed, 0.5)
                self.assertEqual(len(calls), 1)
                partial = downloads / (
                    "0000-" + Path(rows[0]["filename"]).name)
                self.assertTrue(partial.exists())
                self.assertEqual(partial.read_bytes(), b"")
                self.assertIs(signal.getsignal(signal.SIGALRM), sentinel_handler)
                self.assertEqual(
                    signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        finally:
            unblocker.cancel()
            unblocker.join()
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, previous_handler)
            for descriptor in (read_fd, write_fd):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_aggregate_deadline_rejects_active_timer_without_disturbing_it(self):
        plan, rows = self.download_fixture()
        calls = []
        previous_handler = signal.getsignal(signal.SIGALRM)
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        self.assertEqual(previous_timer, (0.0, 0.0))

        def sentinel_handler(_signum, _frame):
            raise AssertionError("pre-existing timer unexpectedly expired")

        signal.signal(signal.SIGALRM, sentinel_handler)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            with tempfile.TemporaryDirectory() as directory:
                downloads = Path(directory) / "downloads"
                mkdir_private(downloads)
                with self.assertRaisesRegex(ValueError, "active process timer"):
                    build.download_package_plan(
                        plan, rows, downloads,
                        opener=lambda *args, **kwargs: calls.append(
                            (args, kwargs)),
                    )
                active = signal.getitimer(signal.ITIMER_REAL)
                self.assertGreater(active[0], 4.0)
                self.assertEqual(active[1], 0.0)
                self.assertIs(signal.getsignal(signal.SIGALRM), sentinel_handler)
                self.assertEqual(calls, [])
                self.assertEqual(list(downloads.iterdir()), [])
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, previous_handler)

    def test_apt_simulation_must_match_every_planned_identity_and_remove_nothing(self):
        rows = [
            {
                "package": "git", "version": "1:2.43.0-1ubuntu7.1",
                "architecture": "amd64",
            },
            {
                "package": "ca-certificates", "version": "20240203",
                "architecture": "all",
            },
        ]
        output = (
            "Inst git (1:2.43.0-1ubuntu7.1 Ubuntu:24.04/noble-updates [amd64])\n"
            "Inst ca-certificates (20240203 Ubuntu:24.04/noble [all]) []\n"
            "Conf git (1:2.43.0-1ubuntu7.1 Ubuntu:24.04/noble-updates [amd64])\n"
            "Conf ca-certificates (20240203 Ubuntu:24.04/noble [all])\n"
        ).encode()
        result = build.validate_apt_simulation(output, rows)
        self.assertEqual(result["install_count"], 2)
        for changed in (
            output.replace(b"1:2.43.0-1ubuntu7.1", b"1:2.43.0-1ubuntu7.2", 1),
            output.replace(b"Inst git (", b"Inst git:all (", 1),
            output.replace(
                b"Inst ca-certificates",
                b"Inst git (1:2.43.0-1ubuntu7.1 Ubuntu:24.04/"
                b"noble-updates [amd64])\nInst ca-certificates",
                1,
            ),
            output.replace(
                b"Inst git (1:2.43.0-1ubuntu7.1 Ubuntu:24.04/"
                b"noble-updates [amd64])\n",
                b"",
                1,
            ),
            output.replace(
                b"Conf git (1:2.43.0-1ubuntu7.1 Ubuntu:24.04/"
                b"noble-updates [amd64])\n",
                b"",
                1,
            ),
            output + b"Remv old-package [1.0]\n",
            output.replace(b"Inst ca-certificates", b"Keep ca-certificates", 1),
            output.replace(b") []\n", b") [libc6:amd64]\n", 1),
            output.replace(b") []\n", b") [ ]\n", 1),
            output.replace(b") []\n", b")  []\n", 1),
            output.replace(b") []\n", b")[]\n", 1),
            output.replace(b") []\n", b") [] []\n", 1),
            output.replace(b") []\n", b") [] trailing\n", 1),
            b"NOTE: This is only a simulation!\n" + output,
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                build.validate_apt_simulation(changed, rows)

    def test_apt_simulation_accepts_observed_empty_dependency_marker(self):
        rows = [{
            "package": "libc6",
            "version": "2.39-0ubuntu8.12",
            "architecture": "amd64",
        }]
        output = (
            "Inst libc6 (2.39-0ubuntu8.12 Ubuntu:24.04/noble-updates, "
            "Ubuntu:24.04/noble-security [amd64]) []\n"
            "Conf libc6 (2.39-0ubuntu8.12 Ubuntu:24.04/noble-updates, "
            "Ubuntu:24.04/noble-security [amd64])\n"
        ).encode()
        result = build.validate_apt_simulation(output, rows)
        self.assertEqual(result["install_count"], 1)
        self.assertEqual(result["configure_count"], 1)

    def test_commands_are_file_only_no_recommends_no_download_and_no_act(self):
        package_rows = [
            {
                "package": "python3-minimal",
                "filename": "pool/main/p/python3-defaults/"
                "python3-minimal_1_amd64.deb",
            },
            {
                "package": "python3",
                "filename": "pool/main/p/python3-defaults/"
                "python3_1_amd64.deb",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            verify = build.inrelease_verification_command(
                base / "archive.gpg", base / "InRelease", base / "Release")
            commands = build.offline_plan_commands(
                base / "apt", base / "repo", base / "archive.gpg",
                packages.EXPECTED_REQUEST["roots"],
                package_rows,
                [
                    base / "packages/0000-python3-minimal_1_amd64.deb",
                    base / "packages/0001-python3_1_amd64.deb",
                ],
            )
            apt_commands = build.offline_apt_commands(
                base / "apt", base / "repo", base / "archive.gpg",
                packages.EXPECTED_REQUEST["roots"],
            )
            dpkg_command = build.offline_dpkg_command(
                base / "apt",
                package_rows,
                [
                    base / "packages/0000-python3-minimal_1_amd64.deb",
                    base / "packages/0001-python3_1_amd64.deb",
                ],
            )
        self.assertEqual(verify, [
            "/usr/bin/gpgv", "--status-fd=1", "--keyring",
            str((base / "archive.gpg").resolve()), "--output",
            str((base / "Release").resolve()), str((base / "InRelease").resolve()),
        ])
        update = commands["update"]
        self.assertIn("update", update)
        self.assertEqual(commands["update"], apt_commands["update"])
        self.assertEqual(commands["dpkg"], dpkg_command)
        self.assertIn("APT::Sandbox::User=root", commands["update"])
        self.assertNotIn("http", " ".join(update))
        self.assertEqual(commands["sources_list"].count("deb [arch=amd64"), 3)
        self.assertNotIn("http", commands["sources_list"])
        self.assertNotIn("trusted=yes", commands["sources_list"])
        self.assertIn("signed-by=", commands["sources_list"])
        self.assertIn("--no-install-recommends", commands["uris"])
        self.assertIn("--simulate", commands["simulate"])
        self.assertIn("--no-download", commands["simulate"])
        simulation_note = "APT::Get::Show-User-Simulation-Note=false"
        self.assertEqual(commands["simulate"].count(simulation_note), 1)
        self.assertNotIn(simulation_note, commands["update"])
        self.assertNotIn(simulation_note, commands["uris"])
        self.assertIn("--no-act", commands["dpkg"])
        self.assertIn("--unpack", commands["dpkg"])
        self.assertIn(
            "--ignore-depends=python3-minimal,python3", commands["dpkg"])
        self.assertNotIn("--force-depends", commands["dpkg"])

    def test_dpkg_no_act_waiver_is_exact_and_cannot_be_caller_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            paths = [
                base / "0000-python3-minimal_1_amd64.deb",
                base / "0001-python3_1_amd64.deb",
            ]
            accepted = [
                {
                    "package": "python3-minimal",
                    "filename": "pool/main/p/python3-defaults/"
                    "python3-minimal_1_amd64.deb",
                },
                {
                    "package": "python3",
                    "filename": "pool/main/p/python3-defaults/"
                    "python3_1_amd64.deb",
                },
            ]
            argv = build.offline_dpkg_command(base / "apt", accepted, paths)

            rejected = (
                [accepted[0], {**accepted[1], "package": "git"}],
                [{**accepted[0], "package": "python3"}, accepted[1]],
            )
            for rows in rejected:
                with self.subTest(rows=rows):
                    with self.assertRaisesRegex(
                            ValueError, "reviewed pre-dependency waiver"):
                        build.offline_dpkg_command(base / "apt", rows, paths)

        self.assertEqual(
            argv[3:7],
            [
                "--ignore-depends=python3-minimal,python3",
                "--no-act",
                "--unpack",
                str(paths[0].resolve()),
            ],
        )

    def test_dpkg_no_act_stderr_accepts_only_the_two_reviewed_waivers(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            names = [f"fixture-{sequence}" for sequence in range(35)]
            names[18] = "python3.12-minimal"
            names[19] = "python3-minimal"
            names[34] = "python3"
            rows = [{
                "package": name,
                "version": "1",
                "filename": f"pool/main/f/{name}/{name}_1_amd64.deb",
            } for name in names]
            pre_depends = [None] * len(rows)
            pre_depends[19] = "python3.12-minimal (>= 3.12.3-0~)"
            pre_depends[34] = "python3-minimal (= 1)"
            paths = [
                base / f"{sequence:04d}-{name}_1_amd64.deb"
                for sequence, name in enumerate(names)
            ]
            stderr = (
                "dpkg: could not open log '/var/log/dpkg.log': Permission denied\n"
                "mkdir: cannot create directory ‘/run/needrestart’: "
                "Permission denied\n"
                "dpkg: regarding .../0019-python3-minimal_1_amd64.deb "
                "containing python3-minimal, pre-dependency problem:\n"
                " python3-minimal pre-depends on python3.12-minimal "
                "(>= 3.12.3-0~)\n"
                "  python3.12-minimal is not installed.\n\n"
                "dpkg: warning: ignoring pre-dependency problem!\n"
                "dpkg: regarding .../0034-python3_1_amd64.deb containing "
                "python3, pre-dependency problem:\n"
                " python3 pre-depends on python3-minimal (= 1)\n"
                "  python3-minimal is not installed.\n\n"
                "dpkg: warning: ignoring pre-dependency problem!\n"
                "dpkg: warning: files list file for package 'base-files' "
                "missing; assuming package has no files currently installed\n"
            ).encode()

            result = build.validate_dpkg_noact_stderr(
                stderr, rows, paths, pre_depends)

            self.assertEqual(result["waived_pre_dependencies"], [
                {
                    "package": "python3-minimal",
                    "archive": paths[19].name,
                    "pre_depends": "python3.12-minimal (>= 3.12.3-0~)",
                },
                {
                    "package": "python3",
                    "archive": paths[34].name,
                    "pre_depends": "python3-minimal (= 1)",
                },
            ])
            self.assertEqual(result["stderr_sha256"], build.sha256_bytes(stderr))

    def test_dpkg_no_act_stderr_rejects_broader_or_changed_waivers(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            paths = [
                base / "0000-python3.12-minimal_1_amd64.deb",
                base / "0001-python3-minimal_1_amd64.deb",
                base / "0002-python3_1_amd64.deb",
            ]
            rows = [
                {
                    "package": "python3.12-minimal",
                    "version": "1",
                    "filename": "pool/main/p/python3.12/"
                    "python3.12-minimal_1_amd64.deb",
                },
                {
                    "package": "python3-minimal",
                    "version": "1",
                    "filename": "pool/main/p/python3-defaults/"
                    "python3-minimal_1_amd64.deb",
                },
                {
                    "package": "python3",
                    "version": "1",
                    "filename": "pool/main/p/python3-defaults/"
                    "python3_1_amd64.deb",
                },
            ]
            pre_depends = [
                None,
                "python3.12-minimal (>= 1)",
                "python3-minimal (= 1)",
            ]
            first = (
                "dpkg: regarding .../0001-python3-minimal_1_amd64.deb "
                "containing python3-minimal, pre-dependency problem:\n"
                " python3-minimal pre-depends on python3.12-minimal (>= 1)\n"
                "dpkg: warning: ignoring pre-dependency problem!\n"
            )
            second = (
                "dpkg: regarding .../0002-python3_1_amd64.deb containing "
                "python3, pre-dependency problem:\n"
                " python3 pre-depends on python3-minimal (= 1)\n"
                "dpkg: warning: ignoring pre-dependency problem!\n"
            )
            valid = (first + second).encode()
            build.validate_dpkg_noact_stderr(
                valid, rows, paths, pre_depends)
            extra = (
                "dpkg: regarding .../0040-tool_1_amd64.deb containing tool, "
                "pre-dependency problem:\n"
                " tool pre-depends on python3\n"
                "dpkg: warning: ignoring pre-dependency problem!\n"
            )

            mutations = (
                valid.replace(b"containing python3,", b"containing tool,", 1),
                valid.replace(
                    b"0002-python3_1_amd64.deb",
                    b"0003-python3_1_amd64.deb", 1),
                valid.replace(
                    b"dpkg: warning: ignoring pre-dependency problem!\n",
                    b"", 1),
                valid.replace(
                    b"python3 pre-depends on python3-minimal (= 1)",
                    b"python3 pre-depends on python3.12-minimal (= 1)", 1),
                valid.replace(
                    b"python3-minimal (= 1)",
                    b"python3-minimal (= 2)", 1),
                (first + extra + second).encode(),
                valid + b"dpkg: warning: ignoring dependency problem!\n",
                valid + b"dpkg: warning: ignoring breakage, may proceed anyway!\n",
                valid + (
                    b"dpkg: regarding archive containing INVALID!, "
                    b"pre-dependency problem:\n"),
                valid.replace(b"\n", b"\r\n", 1),
                valid + b"\x00",
                b"\xff",
            )
            for changed in mutations:
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    build.validate_dpkg_noact_stderr(
                        changed, rows, paths, pre_depends)

            dependency_mutations = (
                [None, "python3.12-minimal (>= 1)",
                 "python3.12-minimal (= 1)"],
                [None, "python3 (>= 1)", "python3-minimal (= 1)"],
                [None, "python3.12-minimal (>= 1) | python3",
                 "python3-minimal (= 1)"],
                [None, "python3.12-minimal (>= 1)",
                 "python3-minimal (= 2)"],
                [None, None, "python3-minimal (= 1)"],
            )
            for changed in dependency_mutations:
                with self.subTest(pre_depends=changed), self.assertRaises(
                        ValueError):
                    build.validate_dpkg_noact_stderr(
                        valid, rows, paths, changed)

    def test_dpkg_no_act_command_binds_rows_to_exact_staged_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            paths = [
                base / "0000-python3-minimal_1_amd64.deb",
                base / "0001-python3_1_amd64.deb",
            ]
            rows = [
                {
                    "package": "python3-minimal",
                    "filename": "pool/main/p/python3-defaults/"
                    "python3-minimal_1_amd64.deb",
                },
                {
                    "package": "python3",
                    "filename": "pool/main/p/python3-defaults/"
                    "python3_1_amd64.deb",
                },
            ]
            build.offline_dpkg_command(base / "apt", rows, paths)

            mutations = (
                [*reversed(paths)],
                [paths[0].with_name("0019-other.deb"), paths[1]],
                [paths[0], paths[1].with_name("0002-" + paths[1].name[5:])],
            )
            for changed in mutations:
                with self.subTest(paths=changed), self.assertRaisesRegex(
                        ValueError, "staged archive"):
                    build.offline_dpkg_command(base / "apt", rows, changed)

    def test_package_producer_docs_preserve_the_two_phase_native_claim(self):
        for relative in (
                "docs/cards/P0-05.md",
                "docs/security/reports/P0-05.md",
                "image/container/README.md"):
            with self.subTest(relative=relative):
                document = " ".join(
                    (ROOT / relative).read_text(encoding="utf-8").split())
                self.assertIn("ordered networkless APT simulation", document)
                self.assertIn("exactly two reviewed", document)
                self.assertIn("does not prove an installed system", document)

    def test_apt_simulation_rejects_install_order_drift(self):
        rows = [
            {"package": "python3-minimal", "version": "1", "architecture": "amd64"},
            {"package": "python3", "version": "1", "architecture": "amd64"},
        ]
        output = (
            "Inst python3 (1 Ubuntu:24.04/noble [amd64])\n"
            "Inst python3-minimal (1 Ubuntu:24.04/noble [amd64])\n"
            "Conf python3-minimal (1 Ubuntu:24.04/noble [amd64])\n"
            "Conf python3 (1 Ubuntu:24.04/noble [amd64])\n"
        ).encode()
        with self.assertRaisesRegex(ValueError, "ordered signed package plan"):
            build.validate_apt_simulation(output, rows)

    def test_offline_apt_paths_resolve_only_inside_the_private_root(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            apt_root = (base / "apt-root").resolve()
            commands = build.offline_apt_commands(
                apt_root, base / "repo", base / "archive.gpg",
                packages.EXPECTED_REQUEST["roots"],
            )

        expected_options = {
            "Dir": str(apt_root),
            "Dir::Etc": "etc/apt",
            "Dir::Etc::sourcelist": "sources.list",
            "Dir::Etc::sourceparts": "sources.list.d",
        }
        for name in ("update", "uris", "simulate"):
            argv = commands[name]
            options = {
                argv[index + 1].split("=", 1)[0]:
                argv[index + 1].split("=", 1)[1]
                for index, value in enumerate(argv[:-1])
                if value == "-o" and "=" in argv[index + 1]
            }
            self.assertEqual(
                {key: options.get(key) for key in expected_options},
                expected_options,
            )
            apt_etc = Path(options["Dir"]) / options["Dir::Etc"]
            self.assertEqual(
                apt_etc / options["Dir::Etc::sourcelist"],
                apt_root / "etc/apt/sources.list",
            )
            self.assertEqual(
                apt_etc / options["Dir::Etc::sourceparts"],
                apt_root / "etc/apt/sources.list.d",
            )
            self.assertNotIn(
                "Dir::Etc::sourcelist=etc/apt/sources.list", argv)
            self.assertNotIn("Dir::Etc::sourceparts=-", argv)
            self.assertNotIn("/etc/apt/sources.list", argv)
            self.assertNotIn("/etc/apt/sources.list.d", argv)

    def test_all_offline_apt_commands_disable_only_the_cnf_index_target(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "repo"
            keyring = base / "archive.gpg"
            commands = build.offline_apt_commands(
                base / "apt-root", repository, keyring,
                packages.EXPECTED_REQUEST["roots"],
            )

        expected = (
            "Acquire::IndexTargets::deb::CNF::DefaultEnabled=false")
        for name in ("update", "uris", "simulate"):
            argv = commands[name]
            options = [
                argv[index + 1]
                for index, value in enumerate(argv[:-1])
                if value == "-o"
            ]
            self.assertEqual(
                [value for value in options
                 if value.startswith("Acquire::IndexTargets::")],
                [expected],
            )
            self.assertNotIn(
                "Acquire::IndexTargets::deb::Packages::DefaultEnabled=false",
                options,
            )
        self.assertEqual(
            commands["sources_list"],
            build.offline_sources_list(
                repository, keyring, packages.EXPECTED_SOURCES),
        )

    def test_offline_apt_policy_rejects_cnf_or_source_expansion(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "repo"
            keyring = base / "archive.gpg"
            commands = build.offline_apt_commands(
                base / "apt-root", repository, keyring,
                packages.EXPECTED_REQUEST["roots"],
            )
            expected = (
                "Acquire::IndexTargets::deb::CNF::DefaultEnabled=false")
            cases = []

            changed = copy.deepcopy(commands)
            position = changed["update"].index(expected)
            del changed["update"][position - 1:position + 1]
            cases.append(changed)

            changed = copy.deepcopy(commands)
            position = changed["uris"].index(expected)
            changed["uris"][position] = expected.removesuffix("false") + "true"
            cases.append(changed)

            changed = copy.deepcopy(commands)
            changed["simulate"][1:1] = [
                "-o",
                "Acquire::IndexTargets::deb::Contents::DefaultEnabled=false",
            ]
            cases.append(changed)

            simulation_note = "APT::Get::Show-User-Simulation-Note=false"
            changed = copy.deepcopy(commands)
            position = changed["simulate"].index(simulation_note)
            del changed["simulate"][position - 1:position + 1]
            cases.append(changed)

            changed = copy.deepcopy(commands)
            position = changed["simulate"].index(simulation_note)
            changed["simulate"][position] = (
                "APT::Get::Show-User-Simulation-Note=true")
            cases.append(changed)

            changed = copy.deepcopy(commands)
            changed["update"][1:1] = [
                "-o",
                "Acquire::IndexTargets::deb::Packages::DefaultEnabled=false",
            ]
            cases.append(changed)

            changed = copy.deepcopy(commands)
            changed["sources_list"] += "deb file:///etc/apt noble main\n"
            cases.append(changed)

            changed = copy.deepcopy(commands)
            changed["update"] += [
                "--option",
                expected.removesuffix("false") + "true",
            ]
            cases.append(changed)

            changed = copy.deepcopy(commands)
            changed["uris"] += [
                "--option=" + expected.removesuffix("false") + "true",
            ]
            cases.append(changed)

            changed = copy.deepcopy(commands)
            changed["simulate"] += [
                "-o" + expected.removesuffix("false") + "true",
            ]
            cases.append(changed)

            changed = copy.deepcopy(commands)
            changed["update"] += ["-o=" + expected]
            cases.append(changed)

            changed = copy.deepcopy(commands)
            changed["uris"] += ["-o", expected]
            cases.append(changed)

            changed = copy.deepcopy(commands)
            changed["update"] += [
                "-o", "Dir::Etc::sourcelist=/etc/apt/sources.list",
                "-o", "Dir::Etc::sourceparts=/etc/apt/sources.list.d",
            ]
            cases.append(changed)

            for changed in cases:
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    build.validate_offline_apt_command_policy(
                        changed, base / "apt-root", repository, keyring,
                        packages.EXPECTED_REQUEST["roots"],
                        packages.EXPECTED_SOURCES)

            self.assertIs(
                build.validate_offline_apt_command_policy(
                    commands, base / "apt-root", repository, keyring,
                    packages.EXPECTED_REQUEST["roots"],
                    packages.EXPECTED_SOURCES),
                commands,
            )

    def test_offline_source_rows_bind_each_reviewed_freshness_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = (base / "repo").resolve()
            keyring = (base / "archive.gpg").resolve()
            rendered = build.offline_sources_list(
                repository, keyring, packages.EXPECTED_SOURCES)

        expected = []
        for source, maximum_days in zip(
                packages.EXPECTED_SOURCES, (1830, 14, 14), strict=True):
            suite = source["suite"]
            expected.append(
                "deb [arch=amd64 "
                f"signed-by={keyring} "
                "check-valid-until=yes "
                f"valid-until-max={maximum_days * 24 * 60 * 60}] "
                f"{(repository / suite).as_uri()} {suite} main"
            )
        self.assertEqual(rendered, "\n".join(expected) + "\n")
        self.assertEqual(rendered.count("check-valid-until=yes"), 3)
        self.assertEqual(rendered.count("valid-until-max=1209600"), 2)
        self.assertEqual(rendered.count("valid-until-max=158112000"), 1)

    def test_offline_source_validator_rejects_missing_or_changed_freshness(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "repo"
            keyring = base / "archive.gpg"
            rendered = build.offline_sources_list(
                repository, keyring, packages.EXPECTED_SOURCES)
            cases = (
                rendered.replace(" check-valid-until=yes", "", 1),
                rendered.replace("check-valid-until=yes",
                                 "check-valid-until=no", 1),
                rendered.replace(" valid-until-max=158112000", "", 1),
                rendered.replace("valid-until-max=158112000",
                                 "valid-until-max=1209600", 1),
                rendered + "deb file:///etc/apt noble main\n",
            )
            for changed in cases:
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    build.validate_offline_sources_list(
                        changed, repository, keyring,
                        packages.EXPECTED_SOURCES)
            self.assertEqual(
                build.validate_offline_sources_list(
                    rendered, repository, keyring,
                    packages.EXPECTED_SOURCES),
                rendered,
            )

    def test_exact_download_is_streamed_and_failed_private_bytes_are_retained(self):
        url = "https://archive.ubuntu.com/ubuntu/pool/main/p/pkg.deb"
        payload = b"0123456789" * 10000
        digest = hashlib.sha256(payload).hexdigest()
        calls = []

        def opener(request, timeout):
            calls.append((request.full_url, timeout))
            return FakeResponse(payload, request.full_url)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pkg.deb"
            result = build.download_exact(
                url, path, len(payload), digest, opener=opener)
            self.assertEqual(result, {"bytes": len(payload), "sha256": digest})
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(len(calls), 1)
            self.assertGreater(calls[0][1], 0)
            self.assertLessEqual(calls[0][1], build.DOWNLOAD_TIMEOUT_SECONDS)

            redirected = Path(directory) / "redirected.deb"
            with self.assertRaises(ValueError):
                build.download_exact(
                    url, redirected, len(payload), digest,
                    opener=lambda request, timeout: FakeResponse(
                        payload, "https://mirror.invalid/pkg.deb"),
                )
            self.assertTrue(redirected.exists())
            self.assertEqual(redirected.read_bytes(), b"")

            truncated = Path(directory) / "truncated.deb"

            def truncated_response(request, timeout):
                response = FakeResponse(payload[:-1], request.full_url)
                response.headers["Content-Length"] = str(len(payload))
                return response

            with self.assertRaises(ValueError):
                build.download_exact(
                    url, truncated, len(payload), digest,
                    opener=truncated_response,
                )
            self.assertTrue(truncated.exists())
            self.assertEqual(truncated.read_bytes(), payload[:-1])

    def test_exact_download_rejects_a_named_leaf_swap_while_fd_stays_open(self):
        url = "https://archive.ubuntu.com/ubuntu/pool/main/p/pkg.deb"
        payload = b"descriptor-bound package"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            destination = base / "pkg.deb"
            displaced = base / "displaced.deb"

            class SwapResponse(FakeResponse):
                changed = False

                def read(self, size=-1):
                    if not self.changed:
                        self.changed = True
                        destination.rename(displaced)
                        write_private(destination, b"hostile replacement")
                    return super().read(size)

            with self.assertRaises(ValueError):
                build.download_exact(
                    url, destination, len(payload), digest,
                    opener=lambda request, timeout: SwapResponse(
                        payload, request.full_url),
                )
            self.assertEqual(destination.read_bytes(), b"hostile replacement")
            self.assertEqual(displaced.read_bytes(), payload)

    def test_failed_download_never_enters_a_name_deletion_race(self):
        url = "https://archive.ubuntu.com/ubuntu/pool/main/p/pkg.deb"
        payload = b"descriptor-bound package"
        digest = hashlib.sha256(payload).hexdigest()
        deletion_attempts = []
        real_unlink = os.unlink

        def replace_at_unlink(name, *, dir_fd=None):
            deletion_attempts.append(name)
            saved = name + ".saved"
            os.rename(
                name, saved, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=dir_fd,
            )
            try:
                os.write(descriptor, b"unrelated replacement")
            finally:
                os.close(descriptor)
            return real_unlink(name, dir_fd=dir_fd)

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "pkg.deb"

            def truncated_response(request, timeout):
                response = FakeResponse(payload[:-1], request.full_url)
                response.headers["Content-Length"] = str(len(payload))
                return response

            with mock.patch.object(build.os, "unlink", side_effect=replace_at_unlink), \
                    self.assertRaises(ValueError):
                build.download_exact(
                    url, destination, len(payload), digest,
                    opener=truncated_response,
                )
            self.assertEqual(deletion_attempts, [])
            self.assertTrue(destination.exists())
            self.assertEqual(destination.read_bytes(), payload[:-1])

    def test_authenticated_rootfs_status_is_read_without_extracting_the_archive(self):
        status = b"Package: base-files\nStatus: install ok installed\n"
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / packages.ROOTFS_ARCHIVE
            with tarfile.open(archive, "w:gz") as bundle:
                member = tarfile.TarInfo("./var/lib/dpkg/status")
                member.size = len(status)
                bundle.addfile(member, io.BytesIO(status))
                unrelated = tarfile.TarInfo("./etc/hostname")
                unrelated_payload = b"fixture\n"
                unrelated.size = len(unrelated_payload)
                bundle.addfile(unrelated, io.BytesIO(unrelated_payload))
            archive.chmod(0o600)
            lock, rootfs = self.synthetic_rootfs_lock(archive)
            with mock.patch.object(packages, "EXPECTED_ROOTFS", rootfs):
                raw, record = build.extract_base_dpkg_status(archive, lock)
        self.assertEqual(raw, status)
        self.assertEqual(record, {
            "bytes": len(status), "sha256": hashlib.sha256(status).hexdigest(),
        })

    def test_rootfs_status_rejects_caller_binding_and_bad_lock_before_open(self):
        lock = packages.unique_json(
            ROOT, "image/container/ubuntu-fixture-packages.lock.json")
        path = Path("/tmp") / packages.ROOTFS_ARCHIVE
        invalid = []
        extra = copy.deepcopy(lock)
        extra["rootfs"]["unexpected"] = "caller evidence"
        invalid.append(extra)
        boolean_size = copy.deepcopy(lock)
        boolean_size["rootfs"]["bytes"] = True
        invalid.append(boolean_size)
        self_consistent = copy.deepcopy(lock)
        self_consistent["rootfs"]["archive"] = "caller-rootfs.tar.gz"
        self_consistent["rootfs"]["bytes"] = 1
        self_consistent["rootfs"]["sha256"] = "0" * 64
        invalid.append(self_consistent)
        invalid.append({
            "bytes": packages.ROOTFS_BYTES,
            "sha256": packages.ROOTFS_SHA256,
        })
        with mock.patch.object(build, "_open_private_path") as opened:
            for changed in invalid:
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    build.extract_base_dpkg_status(path, changed)
            opened.assert_not_called()

    def test_rootfs_tar_bounds_are_checked_before_status_extraction(self):
        status = b"Package: base-files\nStatus: install ok installed\n"
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / packages.ROOTFS_ARCHIVE
            with tarfile.open(archive, "w:gz") as bundle:
                member = tarfile.TarInfo("./var/lib/dpkg/status")
                member.size = len(status)
                bundle.addfile(member, io.BytesIO(status))
                unrelated = tarfile.TarInfo("./var/lib/dpkg/available")
                unrelated.size = 1
                bundle.addfile(unrelated, io.BytesIO(b"x"))
            archive.chmod(0o600)
            lock, rootfs = self.synthetic_rootfs_lock(archive)
            with mock.patch.object(packages, "EXPECTED_ROOTFS", rootfs), \
                    mock.patch.object(build, "MAX_BASE_TAR_MEMBERS", 1), \
                    mock.patch.object(
                        build, "_read_scanned_base_status") as extracted, \
                    self.assertRaises(ValueError):
                build.extract_base_dpkg_status(archive, lock)
            extracted.assert_not_called()

            with mock.patch.object(packages, "EXPECTED_ROOTFS", rootfs), \
                    mock.patch.object(
                        build, "MAX_BASE_TAR_EXPANDED_BYTES", len(status) - 1), \
                    mock.patch.object(
                        build, "_read_scanned_base_status") as extracted, \
                    self.assertRaises(ValueError):
                build.extract_base_dpkg_status(archive, lock)
            extracted.assert_not_called()

    def test_candidate_publish_source_swap_uses_held_stage_and_fails_closed(self):
        lock, manifest, metadata_contents, package_rows = self.candidate_fixture()
        token = "1" * 32
        stage_name = ".ubuntu-package-candidate-" + token
        real_publish = build._rename_noreplace
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            metadata_inputs, package_inputs = self.stage_candidate_inputs(
                base, metadata_contents, package_rows)
            output = base / "candidate"
            displaced_stage = base / "displaced-stage"

            def swap_outer_stage(source_fd, source_name,
                                 destination_fd, destination_name):
                (base / stage_name).rename(displaced_stage)
                mkdir_private(base / stage_name)
                mkdir_private(base / stage_name / "candidate")
                return real_publish(
                    source_fd, source_name, destination_fd, destination_name)

            with mock.patch.object(build.secrets, "token_hex", return_value=token), \
                    mock.patch.object(
                        build, "_rename_noreplace", swap_outer_stage), \
                    self.assertRaises(ValueError):
                build.write_candidate_output(
                    output, lock, manifest, metadata_inputs, package_inputs)
            self.assertEqual(
                build.validate_candidate_output(output, lock), manifest)
            self.assertTrue((base / stage_name / "candidate").is_dir())
            self.assertTrue(displaced_stage.is_dir())
            self.assertEqual(list(displaced_stage.iterdir()), [])

    def test_candidate_publish_never_clobbers_raced_destination(self):
        lock, manifest, metadata_contents, package_rows = self.candidate_fixture()
        token = "2" * 32
        stage_name = ".ubuntu-package-candidate-" + token
        real_publish = build._rename_noreplace
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            metadata_inputs, package_inputs = self.stage_candidate_inputs(
                base, metadata_contents, package_rows)
            output = base / "candidate"

            def race_destination(source_fd, source_name,
                                 destination_fd, destination_name):
                write_private(output, b"raced destination")
                return real_publish(
                    source_fd, source_name, destination_fd, destination_name)

            with mock.patch.object(build.secrets, "token_hex", return_value=token), \
                    mock.patch.object(
                        build, "_rename_noreplace", race_destination), \
                    self.assertRaises(FileExistsError):
                build.write_candidate_output(
                    output, lock, manifest, metadata_inputs, package_inputs)
            self.assertEqual(output.read_bytes(), b"raced destination")
            self.assertTrue((base / stage_name / "candidate").is_dir())

    def test_candidate_post_publish_mismatch_leaves_both_names_untouched(self):
        lock, manifest, metadata_contents, package_rows = self.candidate_fixture()
        token = "3" * 32
        stage_name = ".ubuntu-package-candidate-" + token
        real_publish = build._rename_noreplace
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            metadata_inputs, package_inputs = self.stage_candidate_inputs(
                base, metadata_contents, package_rows)
            output = base / "candidate"
            displaced = base / "published-original"

            def replace_after_publish(source_fd, source_name,
                                      destination_fd, destination_name):
                result = real_publish(
                    source_fd, source_name, destination_fd, destination_name)
                output.rename(displaced)
                write_private(output, b"post-publish replacement")
                return result

            with mock.patch.object(build.secrets, "token_hex", return_value=token), \
                    mock.patch.object(
                        build, "_rename_noreplace", replace_after_publish), \
                    self.assertRaises(ValueError):
                build.write_candidate_output(
                    output, lock, manifest, metadata_inputs, package_inputs)
            self.assertEqual(output.read_bytes(), b"post-publish replacement")
            self.assertEqual(
                build.validate_candidate_output(displaced, lock), manifest)
            self.assertTrue((base / stage_name).is_dir())
            self.assertEqual(list((base / stage_name).iterdir()), [])

    def test_candidate_post_publish_nested_substitution_is_rejected(self):
        lock, manifest, metadata_contents, package_rows = self.candidate_fixture()
        token = "9" * 32
        stage_name = ".ubuntu-package-candidate-" + token
        real_publish = build._rename_noreplace
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            metadata_inputs, package_inputs = self.stage_candidate_inputs(
                base, metadata_contents, package_rows)
            output = base / "candidate"
            displaced = base / "displaced-package.deb"

            def replace_nested_after_publish(source_fd, source_name,
                                             destination_fd, destination_name):
                result = real_publish(
                    source_fd, source_name, destination_fd, destination_name)
                leaf = next((output / "packages").iterdir())
                original = leaf.read_bytes()
                leaf.rename(displaced)
                replacement = bytes([original[0] ^ 1]) + original[1:]
                write_private(leaf, replacement)
                return result

            with mock.patch.object(build.secrets, "token_hex", return_value=token), \
                    mock.patch.object(
                        build, "_rename_noreplace",
                        replace_nested_after_publish), \
                    self.assertRaises(ValueError):
                build.write_candidate_output(
                    output, lock, manifest, metadata_inputs, package_inputs)
            self.assertTrue(output.is_dir())
            self.assertTrue(displaced.is_file())
            with self.assertRaises(ValueError):
                build.validate_candidate_output(output, lock)
            self.assertTrue((base / stage_name).is_dir())
            self.assertEqual(list((base / stage_name).iterdir()), [])

    def test_candidate_cleanup_leaves_replacement_objects_untouched(self):
        lock, manifest, metadata_contents, package_rows = self.candidate_fixture()
        real_copy = build._copy_exact
        for sequence, replacement in enumerate(
                ("symlink", "hardlink", "fifo", "directory"), start=4):
            token = format(sequence, "032x")
            stage_name = ".ubuntu-package-candidate-" + token
            with self.subTest(replacement=replacement), \
                    tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                metadata_inputs, package_inputs = self.stage_candidate_inputs(
                    base, metadata_contents, package_rows)
                output = base / "candidate"
                changed = False

                def replace_created(source, destination_fd, destination_name,
                                    expected_bytes, expected_sha256):
                    nonlocal changed
                    identity = real_copy(
                        source, destination_fd, destination_name,
                        expected_bytes, expected_sha256)
                    if changed:
                        return identity
                    changed = True
                    if replacement == "directory":
                        metadata = base / stage_name / "candidate" / "metadata"
                        metadata.rename(metadata.with_name("metadata.saved"))
                        mkdir_private(metadata)
                    else:
                        saved = destination_name + ".saved"
                        os.rename(
                            destination_name, saved,
                            src_dir_fd=destination_fd,
                            dst_dir_fd=destination_fd)
                        if replacement == "symlink":
                            os.symlink(
                                saved, destination_name, dir_fd=destination_fd)
                        elif replacement == "hardlink":
                            os.link(
                                saved, destination_name,
                                src_dir_fd=destination_fd,
                                dst_dir_fd=destination_fd,
                                follow_symlinks=False)
                        else:
                            os.mkfifo(
                                destination_name, 0o600, dir_fd=destination_fd)
                    raise ValueError("injected candidate copy failure")

                with mock.patch.object(
                        build.secrets, "token_hex", return_value=token), \
                        mock.patch.object(build, "_copy_exact", replace_created), \
                        self.assertRaises(ValueError):
                    build.write_candidate_output(
                        output, lock, manifest,
                        metadata_inputs, package_inputs)
                stage = base / stage_name / "candidate"
                self.assertTrue(stage.is_dir())
                self.assertFalse(output.exists())
                if replacement == "directory":
                    self.assertTrue((stage / "metadata").is_dir())
                    self.assertTrue((stage / "metadata.saved").is_dir())
                else:
                    metadata = stage / "metadata"
                    replacement_path = next(
                        path for path in metadata.iterdir()
                        if not path.name.endswith(".saved"))
                    saved_path = metadata / (replacement_path.name + ".saved")
                    self.assertTrue(saved_path.exists())
                    if replacement == "symlink":
                        self.assertTrue(replacement_path.is_symlink())
                    elif replacement == "hardlink":
                        self.assertEqual(replacement_path.stat().st_nlink, 2)
                    else:
                        self.assertTrue(stat.S_ISFIFO(
                            replacement_path.lstat().st_mode))

    def test_candidate_failure_after_preflight_never_deletes_by_name(self):
        lock, manifest, metadata_contents, package_rows = self.candidate_fixture()
        token = "a" * 32
        stage_name = ".ubuntu-package-candidate-" + token
        deletion_attempts = []
        real_unlink = os.unlink

        def replace_at_unlink(name, *, dir_fd=None):
            deletion_attempts.append(name)
            saved = name + ".race-saved"
            os.rename(
                name, saved, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=dir_fd,
            )
            try:
                os.write(descriptor, b"unrelated replacement")
            finally:
                os.close(descriptor)
            return real_unlink(name, dir_fd=dir_fd)

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            metadata_inputs, package_inputs = self.stage_candidate_inputs(
                base, metadata_contents, package_rows)
            output = base / "candidate"
            with mock.patch.object(build.secrets, "token_hex", return_value=token), \
                    mock.patch.object(
                        build, "_rename_noreplace",
                        side_effect=ValueError("injected publish failure")), \
                    mock.patch.object(
                        build.os, "unlink", side_effect=replace_at_unlink), \
                    self.assertRaisesRegex(ValueError, "injected publish failure"):
                build.write_candidate_output(
                    output, lock, manifest, metadata_inputs, package_inputs)
            self.assertEqual(deletion_attempts, [])
            self.assertTrue((base / stage_name / "candidate").is_dir())
            self.assertFalse(output.exists())

    def test_successful_candidate_retains_stage_without_rmdir_race(self):
        lock, manifest, metadata_contents, package_rows = self.candidate_fixture()
        token = "b" * 32
        stage_name = ".ubuntu-package-candidate-" + token
        removal_attempts = []
        real_rmdir = os.rmdir

        def replace_at_rmdir(name, *, dir_fd=None):
            removal_attempts.append(name)
            saved = name + ".race-saved"
            os.rename(
                name, saved, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.mkdir(name, 0o700, dir_fd=dir_fd)
            return real_rmdir(name, dir_fd=dir_fd)

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            metadata_inputs, package_inputs = self.stage_candidate_inputs(
                base, metadata_contents, package_rows)
            output = base / "candidate"
            with mock.patch.object(build.secrets, "token_hex", return_value=token), \
                    mock.patch.object(
                        build.os, "rmdir", side_effect=replace_at_rmdir):
                result = build.write_candidate_output(
                    output, lock, manifest, metadata_inputs, package_inputs)
            self.assertEqual(result, manifest)
            self.assertEqual(removal_attempts, [])
            self.assertTrue((base / stage_name).is_dir())
            self.assertEqual(list((base / stage_name).iterdir()), [])
            self.assertEqual(
                build.validate_candidate_output(output, lock), manifest)

    def test_candidate_revalidates_rolling_date_and_optional_expiry(self):
        lock, manifest, _, _ = self.candidate_fixture()
        build.validate_candidate_manifest(lock, manifest)
        for suite in ("noble-updates", "noble-security"):
            sequence = next(
                index for index, row in enumerate(manifest["release_metadata"])
                if row["suite"] == suite)

            for date in (
                    NOW - build.MAX_ROLLING_RELEASE_AGE,
                    NOW + build.MAX_CLOCK_SKEW):
                boundary = copy.deepcopy(manifest)
                boundary["release_metadata"][sequence]["signed"]["date"] = \
                    build._iso_time(date)
                build.validate_candidate_manifest(lock, boundary)

            with_expiry = copy.deepcopy(manifest)
            with_expiry["release_metadata"][sequence]["signed"][
                "valid_until"] = build._iso_time(NOW + timedelta(days=1))
            build.validate_candidate_manifest(lock, with_expiry)

            cases = []
            stale_date = copy.deepcopy(manifest)
            stale_date["release_metadata"][sequence]["signed"]["date"] = \
                build._iso_time(
                    NOW - build.MAX_ROLLING_RELEASE_AGE
                    - timedelta(seconds=1))
            cases.append(stale_date)

            future_date = copy.deepcopy(manifest)
            future_date["release_metadata"][sequence]["signed"]["date"] = \
                build._iso_time(
                    NOW + build.MAX_CLOCK_SKEW + timedelta(seconds=1))
            cases.append(future_date)

            stale_expiry = copy.deepcopy(manifest)
            stale_expiry["release_metadata"][sequence]["signed"][
                "valid_until"] = build._iso_time(NOW - timedelta(seconds=1))
            cases.append(stale_expiry)

            excessive_expiry = copy.deepcopy(manifest)
            excessive_expiry["release_metadata"][sequence]["signed"][
                "valid_until"] = build._iso_time(
                    NOW + build.MAX_ROLLING_RELEASE_AGE
                    + timedelta(seconds=1))
            cases.append(excessive_expiry)

            before_date = copy.deepcopy(manifest)
            released = datetime.fromisoformat(
                before_date["release_metadata"][sequence]["signed"][
                    "date"].removesuffix("Z") + "+00:00")
            before_date["release_metadata"][sequence]["signed"][
                "valid_until"] = build._iso_time(
                    released - timedelta(seconds=1))
            cases.append(before_date)

            malformed_date = copy.deepcopy(manifest)
            malformed_date["release_metadata"][sequence]["signed"][
                "date"] = "malformed"
            cases.append(malformed_date)

            malformed_expiry = copy.deepcopy(manifest)
            malformed_expiry["release_metadata"][sequence]["signed"][
                "valid_until"] = "malformed"
            cases.append(malformed_expiry)

            for field, value in (
                    ("mode", "valid-until"),
                    ("maximum_age_days",
                     build.MAX_ROLLING_RELEASE_AGE.days + 1)):
                cross_bound = copy.deepcopy(manifest)
                cross_bound["release_metadata"][sequence]["signed"][
                    "freshness_policy"][field] = value
                cases.append(cross_bound)

            for changed in cases:
                with self.subTest(suite=suite, changed=changed), \
                        self.assertRaises(ValueError):
                    build.validate_candidate_manifest(lock, changed)

    def test_candidate_manifest_is_unverified_and_ineligible_for_consumption(self):
        lock, manifest, metadata_contents, package_rows = self.candidate_fixture()
        validated = build.validate_candidate_manifest(lock, manifest)
        self.assertIs(validated["producer_passed"], False)
        self.assertIs(validated["selected"], False)
        for field in inputs.CLAIM_FIELDS:
            self.assertIs(validated[field], False)
            changed = copy.deepcopy(manifest)
            changed[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                build.validate_candidate_manifest(lock, changed)
        changed_lock = copy.deepcopy(lock)
        changed_lock["qualified"] = True
        with self.assertRaises(ValueError):
            build.validate_candidate_manifest(changed_lock, manifest)
        changed = copy.deepcopy(manifest)
        changed["verification"]["offline_dpkg_plan"] = True
        with self.assertRaises(ValueError):
            build.validate_candidate_manifest(lock, changed)
        changed = copy.deepcopy(manifest)
        changed["producer_passed"] = True
        with self.assertRaises(ValueError):
            build.validate_candidate_manifest(lock, changed)
        forged_hashes = copy.deepcopy(manifest)
        forged_hashes["command_hashes"] = {
            name: "f" * 64 for name in forged_hashes["command_hashes"]
        }
        self.assertTrue(all(
            value is False
            for value in build.validate_candidate_manifest(
                lock, forged_hashes)["verification"].values()
        ))
        malformed = copy.deepcopy(manifest)
        malformed["command_hashes"]["apt_update"] = 7
        with self.assertRaises(ValueError):
            build.validate_candidate_manifest(lock, malformed)
        malformed = copy.deepcopy(manifest)
        malformed["verified_at"] = True
        with self.assertRaises(ValueError):
            build.validate_candidate_manifest(lock, malformed)
        for field, value in (
                ("producer_run_id", True),
                ("producer_run_attempt", 0),
                ("producer_head_sha", "e" * 39),
                ("producer_head_tree", "D" * 40),
                ("producer_branch", "../main"),
                ("artifact_id", True),
                ("artifact_name", "different"),
                ("artifact_bytes", 0),
                ("artifact_api_sha256", "0" * 64),
                ("artifact_zip_sha256", "2" * 64),
                ("manifest_sha256", "x" * 64),
                ("discovery_contract_sha256", None),
                ("selection_contract_sha256", True),
                ("metadata_lock_sha256", True)):
            malformed = copy.deepcopy(manifest)
            malformed["metadata_provenance"][field] = value
            with self.subTest(provenance=field), self.assertRaises(ValueError):
                build.validate_candidate_manifest(lock, malformed)
        extra = copy.deepcopy(manifest)
        extra["producer"] = {"run_id": 1, "head_sha": "0" * 40}
        with self.assertRaises(ValueError):
            build.validate_candidate_manifest(lock, extra)
        changed = copy.deepcopy(manifest)
        changed["download_order"].reverse()
        self.assertEqual(
            build.validate_candidate_manifest(lock, changed), changed,
            "download order may differ from canonical manifest order but stays bound",
        )
        with self.assertRaises(ValueError):
            inputs.validate_pending_lock(ROOT, manifest)
        with self.assertRaises(ValueError):
            inputs.validate_artifact_for_use(ROOT, lock, manifest, None)

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            metadata_inputs, package_inputs = self.stage_candidate_inputs(
                base, metadata_contents, package_rows)
            output = base / "candidate"
            written = build.write_candidate_output(
                output, lock, manifest, metadata_inputs, package_inputs)
            self.assertIs(written["selected"], False)
            self.assertEqual(
                {path.name for path in (output / "packages").iterdir()},
                {Path(row["filename"]).name for row in package_rows},
            )
            changed = output / "packages" / Path(package_rows[0]["filename"]).name
            changed.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                build.validate_candidate_output(output, lock)
            write_private(changed, self.payloads[package_rows[0]["package"]])

            backing = base / "hardlink-backing.deb"
            write_private(backing, self.payloads[package_rows[0]["package"]])
            changed.unlink()
            os.link(backing, changed)
            with self.assertRaises(ValueError):
                build.validate_candidate_output(output, lock)
            changed.unlink()
            backing.unlink()
            write_private(changed, self.payloads[package_rows[0]["package"]])

            metadata = output / "metadata"
            metadata_real = output / "metadata-real"
            metadata.rename(metadata_real)
            metadata.symlink_to(metadata_real, target_is_directory=True)
            with self.assertRaises(ValueError):
                build.validate_candidate_output(output, lock)
            metadata.unlink()
            metadata_real.rename(metadata)

            manifest_path = output / "manifest.json"
            manifest_real = output / "manifest-real.json"
            manifest_path.rename(manifest_real)
            manifest_path.symlink_to(manifest_real)
            with self.assertRaises(ValueError):
                build.validate_candidate_output(output, lock)
            manifest_path.unlink()
            manifest_real.rename(manifest_path)

            manifest_path.chmod(0o640)
            with self.assertRaises(ValueError):
                build.validate_candidate_output(output, lock)
            manifest_path.chmod(0o600)

            alias = base / "candidate-alias"
            alias.symlink_to(output, target_is_directory=True)
            with self.assertRaises(ValueError):
                build.validate_candidate_output(alias, lock)

    def test_candidate_producer_is_not_wired_to_build_upload_or_consumption(self):
        workflow = (ROOT / ".github/workflows/container-fixtures.yml").read_text()
        native_build = (ROOT / "image/container/native_fixture_build.py").read_text()
        dockerfile = (ROOT / "image/container/hosted/fixture/Dockerfile").read_text()
        self.assertNotIn("ubuntu_fixture_package_build", workflow)
        self.assertNotIn("ubuntu_fixture_package_build", native_build)
        self.assertNotIn("container-ubuntu-fixture-packages", workflow)
        self.assertIn("apt-get -o Acquire::Retries=2 update", dockerfile)
        self.assertNotIn("--network=none", workflow)
        self.assertNotIn("container-native-fixture-output", workflow)


if __name__ == "__main__":
    unittest.main()
