"""Mutation tests for the dormant Ubuntu fixture package-closure contract."""
import copy
import unittest

from image.container import ubuntu_fixture_packages as packages


def release_row(source, marker):
    return {
        "suite": source["suite"],
        "mode": "inrelease",
        "inrelease": {
            "filename": source["suite"] + "_InRelease",
            "url": source["metadata"]["inrelease_url"],
            "bytes": 1024 + marker,
            "sha256": format(marker + 1, "064x"),
        },
        "release": None,
        "signature": None,
        "signature_verified": True,
        "signer_fingerprint": packages.ARCHIVE_SIGNER_FINGERPRINT,
        "index": {
            "path": "main/binary-amd64/Packages.xz",
            "bytes": 2048 + marker,
            "sha256": format(marker + 101, "064x"),
        },
    }


def index_row(source, marker):
    return {
        "suite": source["suite"],
        "component": "main",
        "architecture": "amd64",
        "filename": source["suite"] + "_main_binary-amd64_Packages.xz",
        "url": source["packages_url"],
        "bytes": 2048 + marker,
        "sha256": format(marker + 101, "064x"),
    }


def package_row(source, index, name, marker, architecture="amd64"):
    filename = (
        "pool/main/" + name[0] + "/" + name + "/" + name + "_1.0-"
        + str(marker) + "_" + architecture + ".deb"
    )
    return {
        "package": name,
        "version": "1.0-" + str(marker),
        "architecture": architecture,
        "filename": filename,
        "url": source["base_url"] + "/" + filename,
        "bytes": 4096 + marker,
        "sha256": format(marker + 201, "064x"),
        "source": {
            "suite": source["suite"],
            "component": "main",
            "index_architecture": "amd64",
            "index_sha256": index["sha256"],
        },
    }


class UbuntuFixturePackageContract(unittest.TestCase):
    def setUp(self):
        self.sources = copy.deepcopy(packages.EXPECTED_SOURCES)
        self.releases = [
            release_row(source, marker)
            for marker, source in enumerate(self.sources, start=1)
        ]
        self.indexes = [
            index_row(source, marker)
            for marker, source in enumerate(self.sources, start=1)
        ]
        self.rows = [
            package_row(self.sources[0], self.indexes[0], "ca-certificates", 1,
                        architecture="all"),
            package_row(self.sources[0], self.indexes[0], "git", 2),
            package_row(self.sources[1], self.indexes[1], "python3", 3),
        ]
        self.rows.sort(key=packages.package_identity)

    def test_immutable_rootfs_request_and_source_anchors_pass(self):
        packages.validate_rootfs(copy.deepcopy(packages.EXPECTED_ROOTFS))
        packages.validate_request(copy.deepcopy(packages.EXPECTED_REQUEST))
        packages.validate_sources(copy.deepcopy(packages.EXPECTED_SOURCES))
        self.assertEqual(
            packages.EXPECTED_REQUEST["roots"],
            ["python3", "git", "ca-certificates"],
        )
        self.assertFalse(packages.EXPECTED_REQUEST["install_recommends"])
        self.assertEqual(
            [source["suite"] for source in packages.EXPECTED_SOURCES],
            ["noble", "noble-updates", "noble-security"],
        )

    def test_rootfs_anchor_mutations_are_rejected(self):
        cases = (
            (("archive",), "other.tar.gz"),
            (("url",), "http://cdimage.ubuntu.com/rootfs.tar.gz"),
            (("bytes",), packages.ROOTFS_BYTES + 1),
            (("sha256",), "0" * 64),
            (("checksum", "sha256"), "0" * 64),
            (("checksum", "signature_sha256"), "0" * 64),
            (("checksum", "signer_fingerprint"), "EFE21092"),
            (("keyring", "sha256"), "0" * 64),
        )
        for path, value in cases:
            with self.subTest(path=path):
                changed = copy.deepcopy(packages.EXPECTED_ROOTFS)
                target = changed
                for name in path[:-1]:
                    target = target[name]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    packages.validate_rootfs(changed)
        changed = copy.deepcopy(packages.EXPECTED_ROOTFS)
        changed["unexpected"] = True
        with self.assertRaises(ValueError):
            packages.validate_rootfs(changed)

    def test_request_order_architecture_component_and_recommends_are_exact(self):
        cases = []
        for field, value in (
            ("architecture", "arm64"),
            ("component", "universe"),
            ("suites", ["noble", "noble-security", "noble-updates"]),
            ("roots", ["git", "python3", "ca-certificates"]),
            ("install_recommends", True),
        ):
            changed = copy.deepcopy(packages.EXPECTED_REQUEST)
            changed[field] = value
            cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                packages.validate_request(changed)

    def test_source_order_urls_metadata_mode_and_signer_are_exact(self):
        cases = []
        changed = copy.deepcopy(self.sources)
        changed.reverse()
        cases.append(changed)
        for path, value in (
            ((0, "base_url"), "http://archive.ubuntu.com/ubuntu"),
            ((0, "component"), "universe"),
            ((0, "architecture"), "arm64"),
            ((0, "packages_url"), "https://example.invalid/Packages.xz"),
            ((0, "metadata", "mode"), "detached"),
            ((0, "metadata", "release_url"),
             "https://archive.ubuntu.com/ubuntu/dists/noble/Release"),
            ((0, "metadata", "signer_fingerprint"), None),
            ((0, "metadata", "signer_fingerprint"), "871920D1991BC93C"),
        ):
            changed = copy.deepcopy(self.sources)
            target = changed
            for name in path[:-1]:
                target = target[name]
            target[path[-1]] = value
            cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                packages.validate_sources(changed)

    def test_signed_metadata_and_amd64_indexes_pass(self):
        observed = packages.validate_metadata(
            self.releases, self.indexes, self.sources)
        self.assertEqual(observed, {
            source["suite"]: index["sha256"]
            for source, index in zip(self.sources, self.indexes, strict=True)
        })

    def test_ambiguous_unsigned_or_unsafe_metadata_is_rejected(self):
        cases = []
        changed = copy.deepcopy(self.releases)
        changed[0]["release"] = {
            "filename": "Release", "url": "https://example.invalid/Release",
            "bytes": 12, "sha256": "a" * 64,
        }
        cases.append((changed, self.indexes))
        for field, value in (
            ("signer_fingerprint", None),
            ("signer_fingerprint", "871920D1991BC93C"),
            ("signature_verified", False),
            ("mode", "detached"),
        ):
            changed = copy.deepcopy(self.releases)
            changed[0][field] = value
            cases.append((changed, self.indexes))
        changed = copy.deepcopy(self.releases)
        changed[0]["inrelease"]["filename"] = "../InRelease"
        cases.append((changed, self.indexes))
        changed = copy.deepcopy(self.indexes)
        changed[0]["architecture"] = "arm64"
        cases.append((self.releases, changed))
        changed = copy.deepcopy(self.indexes)
        changed[0]["url"] = "https://example.invalid/Packages.xz"
        cases.append((self.releases, changed))
        changed = copy.deepcopy(self.indexes)
        changed[0]["sha256"] = "not-a-hash"
        cases.append((self.releases, changed))
        changed = copy.deepcopy(self.indexes)
        changed[0]["sha256"] = "e" * 64
        cases.append((self.releases, changed))
        for releases, indexes in cases:
            with self.subTest(releases=releases, indexes=indexes), \
                    self.assertRaises(ValueError):
                packages.validate_metadata(releases, indexes, self.sources)

    def test_package_rows_are_bound_to_signed_amd64_indexes(self):
        count, total = packages.validate_packages(
            self.rows, self.releases, self.indexes, self.sources,
            len(self.rows), sum(row["bytes"] for row in self.rows))
        self.assertEqual(count, 3)
        self.assertEqual(total, sum(row["bytes"] for row in self.rows))

    def test_foreign_duplicate_unsafe_or_inconsistent_package_rows_fail(self):
        cases = []
        changed = copy.deepcopy(self.rows)
        changed.append(copy.deepcopy(changed[0]))
        cases.append((changed, len(changed), sum(row["bytes"] for row in changed)))
        changed = copy.deepcopy(self.rows)
        changed = changed[1:]
        cases.append((changed, len(changed), sum(row["bytes"] for row in changed)))
        changed = copy.deepcopy(self.rows)
        duplicate_slot = copy.deepcopy(changed[1])
        duplicate_slot["version"] = "2.0-1"
        duplicate_slot["filename"] = duplicate_slot["filename"].replace(
            "_1.0-2_", "_2.0-1_")
        duplicate_slot["url"] = (
            self.sources[0]["base_url"] + "/" + duplicate_slot["filename"])
        duplicate_slot["sha256"] = "f" * 64
        changed.append(duplicate_slot)
        changed.sort(key=packages.package_identity)
        cases.append((changed, len(changed), sum(row["bytes"] for row in changed)))
        for path, value in (
            ((0, "architecture"), "arm64"),
            ((0, "filename"), "../package.deb"),
            ((0, "url"), "https://evil.invalid/package.deb"),
            ((0, "sha256"), "0"),
            ((0, "bytes"), 0),
            ((0, "source", "suite"), "jammy"),
            ((0, "source", "component"), "universe"),
            ((0, "source", "index_architecture"), "arm64"),
            ((0, "source", "index_sha256"), "0" * 64),
        ):
            changed = copy.deepcopy(self.rows)
            target = changed
            for name in path[:-1]:
                target = target[name]
            target[path[-1]] = value
            cases.append((changed, len(changed), sum(row["bytes"] for row in changed)))
        changed = copy.deepcopy(self.rows)
        changed[0]["extra"] = True
        cases.append((changed, len(changed), sum(row["bytes"] for row in changed)))
        for rows, count, total in cases:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                packages.validate_packages(
                    rows, self.releases, self.indexes, self.sources, count, total)
        with self.assertRaises(ValueError):
            packages.validate_packages(
                self.rows, self.releases, self.indexes, self.sources,
                len(self.rows) + 1, sum(row["bytes"] for row in self.rows))
        with self.assertRaises(ValueError):
            packages.validate_packages(
                self.rows, self.releases, self.indexes, self.sources,
                len(self.rows), sum(row["bytes"] for row in self.rows) + 1)

    def test_duplicate_json_keys_and_noncanonical_numbers_fail(self):
        with self.assertRaises(ValueError):
            packages.unique_json_bytes(b'{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):
            packages.unique_json_bytes(b'{"schema":NaN}')
        self.assertEqual(packages.unique_json_bytes(b'{"schema":1}'), {"schema": 1})

    def test_candidate_artifact_metadata_is_unselected_and_exact(self):
        candidate = {
            "selected": False,
            "id": 123,
            "name": packages.ARTIFACT_NAME,
            "bytes": 4096,
            "sha256": "a" * 64,
            "run": {"id": 456, "attempt": 2, "head_sha": "b" * 40},
        }
        metadata = {
            "id": 123,
            "name": packages.ARTIFACT_NAME,
            "size_in_bytes": 4096,
            "digest": "sha256:" + "a" * 64,
            "expired": False,
            "workflow_run": {
                "id": 456,
                "head_sha": "b" * 40,
                "repository_id": packages.REPOSITORY["id"],
                "head_repository_id": packages.REPOSITORY["id"],
            },
        }
        packages.validate_candidate_artifact(candidate)
        packages.validate_artifact_metadata(metadata, candidate)
        for field, value in (
            ("selected", True), ("name", "other"), ("bytes", 0),
            ("sha256", "short"),
        ):
            changed = copy.deepcopy(candidate)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                packages.validate_candidate_artifact(changed)
        changed = copy.deepcopy(candidate)
        changed["run"]["head_sha"] = "short"
        with self.assertRaises(ValueError):
            packages.validate_candidate_artifact(changed)
        metadata_mutations = []
        for field, value in (
            ("expired", True), ("id", 124),
            ("digest", "sha256:" + "c" * 64),
        ):
            changed = copy.deepcopy(metadata)
            changed[field] = value
            metadata_mutations.append(changed)
        changed = copy.deepcopy(metadata)
        changed["workflow_run"]["id"] = 457
        metadata_mutations.append(changed)
        changed = copy.deepcopy(metadata)
        changed["workflow_run"]["repository_id"] = 1
        metadata_mutations.append(changed)
        changed = copy.deepcopy(metadata)
        changed["unexpected"] = True
        metadata_mutations.append(changed)
        for changed in metadata_mutations:
            with self.subTest(metadata=changed), self.assertRaises(ValueError):
                packages.validate_artifact_metadata(changed, candidate)


if __name__ == "__main__":
    unittest.main()
