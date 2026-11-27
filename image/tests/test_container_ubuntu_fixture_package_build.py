"""Offline tests for the unselected Ubuntu fixture package producer."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import lzma
from pathlib import Path
import tarfile
import tempfile
import unittest

from image.container import ubuntu_fixture_inputs as inputs
from image.container import ubuntu_fixture_package_build as build
from image.container import ubuntu_fixture_packages as packages


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)


def package_stanza(name, version, architecture, filename, payload):
    return (
        f"Package: {name}\n"
        f"Version: {version}\n"
        f"Architecture: {architecture}\n"
        f"Filename: {filename}\n"
        f"Size: {len(payload)}\n"
        f"SHA256: {hashlib.sha256(payload).hexdigest()}\n\n"
    ).encode()


def release_bytes(source, index_bytes, *, date=None, valid_until=None):
    date = NOW - timedelta(hours=1) if date is None else date
    valid_until = NOW + timedelta(days=6) if valid_until is None else valid_until
    digest = hashlib.sha256(index_bytes).hexdigest()
    codename = build.EXPECTED_CODENAMES[source["suite"]]
    return (
        "Origin: Ubuntu\n"
        "Label: Ubuntu\n"
        f"Suite: {source['suite']}\n"
        f"Codename: {codename}\n"
        f"Date: {build.format_release_time(date)}\n"
        f"Valid-Until: {build.format_release_time(valid_until)}\n"
        "Architectures: amd64 arm64\n"
        "Components: main restricted universe multiverse\n"
        "SHA256:\n"
        f" {digest} {len(index_bytes)} main/binary-amd64/Packages.xz\n"
    ).encode()


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
            )
            for name in ("ca-certificates", "git", "python3")
        )
        # Keep the synthetic fixture's decoder dictionary small so this test
        # remains runnable inside the card's 128 MiB address-space ceiling.
        self.index = lzma.compress(raw, format=lzma.FORMAT_XZ, preset=0)
        self.release = release_bytes(self.source, self.index)
        self.binding = build.validate_signed_release(
            self.release, self.source, NOW)

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
        self.assertGreater(self.binding["valid_until"], self.binding["verified_at"])

    def test_stale_future_wrong_suite_and_ambiguous_release_metadata_fail(self):
        duplicate = self.release + (
            f" {hashlib.sha256(self.index).hexdigest()} {len(self.index)} "
            "main/binary-amd64/Packages.xz\n"
        ).encode()
        cases = [
            release_bytes(
                self.source, self.index,
                date=NOW - timedelta(days=2),
                valid_until=NOW - timedelta(seconds=1),
            ),
            release_bytes(
                self.source, self.index,
                date=NOW + build.MAX_CLOCK_SKEW + timedelta(seconds=1),
            ),
            self.release.replace(b"Suite: noble\n", b"Suite: noble-updates\n"),
            self.release.replace(b"Codename: noble\n", b"Codename: jammy\n"),
            self.release.replace(b"Valid-Until:", b"X-Valid-Until:"),
            self.release.replace(b"Architectures: amd64 arm64", b"Architectures: arm64"),
            duplicate,
        ]
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                build.validate_signed_release(changed, self.source, NOW)

    def test_signed_index_membership_returns_only_exact_requested_rows(self):
        requested = {
            self.paths[name]: {
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            for name, payload in self.payloads.items()
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Packages.xz"
            path.write_bytes(self.index)
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
                "sha256": hashlib.sha256(self.payloads["git"]).hexdigest(),
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Packages.xz"
            path.write_bytes(self.index)
            bad_binding = copy.deepcopy(self.binding["index"])
            bad_binding["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                build.find_requested_packages(path, self.source, bad_binding, requested)
            missing = copy.deepcopy(requested)
            missing["pool/main/m/missing/missing_1_amd64.deb"] = {
                "bytes": 1, "sha256": "1" * 64,
            }
            with self.assertRaises(ValueError):
                build.find_requested_packages(
                    path, self.source, self.binding["index"], missing)

            duplicated = lzma.compress(
                lzma.decompress(self.index) + lzma.decompress(self.index),
                format=lzma.FORMAT_XZ,
                preset=0,
            )
            path.write_bytes(duplicated)
            duplicate_binding = {
                "path": "main/binary-amd64/Packages.xz",
                "bytes": len(duplicated),
                "sha256": hashlib.sha256(duplicated).hexdigest(),
            }
            with self.assertRaises(ValueError):
                build.find_requested_packages(
                    path, self.source, duplicate_binding, requested)

    def test_file_uri_plan_binds_signed_sha256_size_suite_and_order(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            suite = repository / "noble"
            suite.mkdir(parents=True)
            lines = []
            for name in ("git", "python3", "ca-certificates"):
                payload = self.payloads[name]
                digest = hashlib.sha256(payload).hexdigest()
                uri = (suite / self.paths[name]).as_uri()
                lines.append(
                    f"'{uri}' '{Path(self.paths[name]).name}' "
                    f"{len(payload)} 'SHA256:{digest}'"
                )
            plan = build.parse_apt_uri_plan(
                ("\n".join(lines) + "\n").encode(), repository,
                packages.EXPECTED_SOURCES)
        self.assertEqual([row["sequence"] for row in plan], [0, 1, 2])
        self.assertEqual([row["suite"] for row in plan], ["noble"] * 3)
        self.assertEqual(plan[0]["filename"], self.paths["git"])
        self.assertEqual(
            plan[0]["sha256"], hashlib.sha256(self.payloads["git"]).hexdigest())

    def test_uri_plan_rejects_network_rows_duplicates_and_weak_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            suite = repository / "noble"
            suite.mkdir(parents=True)
            payload = self.payloads["git"]
            digest = hashlib.sha256(payload).hexdigest()
            uri = (suite / self.paths["git"]).as_uri()
            good = f"'{uri}' 'git.deb' {len(payload)} 'SHA256:{digest}'\n"
            cases = [
                good + good,
                good.replace("file://", "https://"),
                good.replace("SHA256:", "MD5Sum:"),
                good.replace(str(len(payload)), "0", 1),
                good + "unexpected output\n",
            ]
            for changed in cases:
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    build.parse_apt_uri_plan(
                        changed.encode(), repository, packages.EXPECTED_SOURCES)

    def test_uri_plan_binds_index_rows_and_downloads_payloads_sequentially(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "repo"
            suite = repository / "noble"
            suite.mkdir(parents=True)
            index_path = base / "Packages.xz"
            index_path.write_bytes(self.index)
            lines = []
            order = ("git", "python3", "ca-certificates")
            for name in order:
                payload = self.payloads[name]
                lines.append(
                    f"'{(suite / self.paths[name]).as_uri()}' "
                    f"'{name}.deb' {len(payload)} "
                    f"'SHA256:{hashlib.sha256(payload).hexdigest()}'"
                )
            plan = build.parse_apt_uri_plan(
                ("\n".join(lines) + "\n").encode(), repository,
                packages.EXPECTED_SOURCES)
            rows = build.bind_uri_plan_to_indexes(
                plan,
                {"noble": {"path": index_path, "binding": self.binding["index"]}},
                packages.EXPECTED_SOURCES,
            )
            downloads = base / "downloads"
            downloads.mkdir()
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
            "Inst ca-certificates (20240203 Ubuntu:24.04/noble [all])\n"
            "Conf git (1:2.43.0-1ubuntu7.1 Ubuntu:24.04/noble-updates [amd64])\n"
            "Conf ca-certificates (20240203 Ubuntu:24.04/noble [all])\n"
        ).encode()
        result = build.validate_apt_simulation(output, rows)
        self.assertEqual(result["install_count"], 2)
        for changed in (
            output.replace(b"1:2.43.0-1ubuntu7.1", b"1:2.43.0-1ubuntu7.2", 1),
            output + b"Remv old-package [1.0]\n",
            output.replace(b"Inst ca-certificates", b"Keep ca-certificates", 1),
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                build.validate_apt_simulation(changed, rows)

    def test_commands_are_file_only_no_recommends_no_download_and_no_act(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            verify = build.inrelease_verification_command(
                base / "archive.gpg", base / "InRelease", base / "Release")
            commands = build.offline_plan_commands(
                base / "apt", base / "repo", base / "archive.gpg",
                packages.EXPECTED_REQUEST["roots"],
                [base / "packages/a.deb", base / "packages/b.deb"],
            )
        self.assertEqual(verify, [
            "/usr/bin/gpgv", "--status-fd=1", "--keyring",
            str((base / "archive.gpg").resolve()), "--output",
            str((base / "Release").resolve()), str((base / "InRelease").resolve()),
        ])
        update = commands["update"]
        self.assertIn("update", update)
        self.assertNotIn("http", " ".join(update))
        self.assertEqual(commands["sources_list"].count("deb [arch=amd64"), 3)
        self.assertNotIn("http", commands["sources_list"])
        self.assertNotIn("trusted=yes", commands["sources_list"])
        self.assertIn("signed-by=", commands["sources_list"])
        self.assertIn("--no-install-recommends", commands["uris"])
        self.assertIn("--simulate", commands["simulate"])
        self.assertIn("--no-download", commands["simulate"])
        self.assertIn("--no-act", commands["dpkg"])
        self.assertIn("--unpack", commands["dpkg"])
        self.assertNotIn("--force-depends", commands["dpkg"])

    def test_exact_download_is_streamed_and_partial_or_redirected_bytes_are_removed(self):
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

            redirected = Path(directory) / "redirected.deb"
            with self.assertRaises(ValueError):
                build.download_exact(
                    url, redirected, len(payload), digest,
                    opener=lambda request, timeout: FakeResponse(
                        payload, "https://mirror.invalid/pkg.deb"),
                )
            self.assertFalse(redirected.exists())

            truncated = Path(directory) / "truncated.deb"
            with self.assertRaises(ValueError):
                build.download_exact(
                    url, truncated, len(payload), digest,
                    opener=lambda request, timeout: FakeResponse(
                        payload[:-1], request.full_url),
                )
            self.assertFalse(truncated.exists())

    def test_authenticated_rootfs_status_is_read_without_extracting_the_archive(self):
        status = b"Package: base-files\nStatus: install ok installed\n"
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "rootfs.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                member = tarfile.TarInfo("./var/lib/dpkg/status")
                member.size = len(status)
                bundle.addfile(member, io.BytesIO(status))
                unrelated = tarfile.TarInfo("./etc/hostname")
                unrelated_payload = b"fixture\n"
                unrelated.size = len(unrelated_payload)
                bundle.addfile(unrelated, io.BytesIO(unrelated_payload))
            binding = {
                "bytes": archive.stat().st_size,
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            }
            raw, record = build.extract_base_dpkg_status(archive, binding)
        self.assertEqual(raw, status)
        self.assertEqual(record, {
            "bytes": len(status), "sha256": hashlib.sha256(status).hexdigest(),
        })

    def test_candidate_manifest_is_verified_but_ineligible_for_consumption(self):
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
                binding = build.validate_signed_release(release, source, NOW)
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
        )
        validated = build.validate_candidate_manifest(lock, manifest)
        self.assertIs(validated["producer_passed"], True)
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
        changed["verification"]["offline_dpkg_plan"] = False
        with self.assertRaises(ValueError):
            build.validate_candidate_manifest(lock, changed)
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
            staged_metadata = base / "staged-metadata"
            staged_packages = base / "staged-packages"
            staged_metadata.mkdir()
            staged_packages.mkdir()
            metadata_inputs = {}
            for name, raw in metadata_contents.items():
                path = staged_metadata / name
                path.write_bytes(raw)
                metadata_inputs[name] = path
            package_inputs = {}
            for row in package_rows:
                path = staged_packages / Path(row["filename"]).name
                path.write_bytes(self.payloads[row["package"]])
                package_inputs[row["filename"]] = path
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
