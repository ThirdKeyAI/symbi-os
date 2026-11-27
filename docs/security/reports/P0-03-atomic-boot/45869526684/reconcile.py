"""Reconcile the first installed-disk boot and its bounded probe timeout."""
from pathlib import Path
import hashlib
import json
import re


RUN = 45869526684
SOURCE = "88c49ecb57fe8104c962c8a4e420bb87831dc1dd"
IMAGE_SOURCE = "23a6c721092ad77c3af33c11cab230ecaaa54cff"
IMAGE_ID = "sha256:54519537609810dae056e0dd17696f123f8ca1900ab64c6af1af458c80c768a1"
MANIFEST = "sha256:9b6e8fdd9f6f98631895ccdfaaed6ffd88febd3ea6238d543935a524b572faf3"
ARTIFACT = 15142549147
here = Path(__file__).resolve().parent
evidence = here / "original"


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def no_oom(label, counters):
    events = dict(row.split() for row in counters["memory.events"].splitlines())
    assert events["oom"] == events["oom_kill"] == events["oom_group_kill"] == "0", label
    assert counters["memory.swap.max"] == "0", label


metadata = load(here / "artifact-metadata.json")
archive = here / "artifact.zip"
assert metadata["id"] == ARTIFACT and metadata["name"] == "atomic-development-boot-generic"
assert metadata["workflow_run"]["id"] == RUN and metadata["workflow_run"]["head_sha"] == SOURCE
assert metadata["expired"] is False and metadata["size_in_bytes"] == archive.stat().st_size == 76130
assert metadata["digest"] == "sha256:" + digest(archive)

files = load(here / "artifact-files.json")
actual = []
for path in sorted(p for p in evidence.rglob("*") if p.is_file()):
    assert not path.is_symlink()
    actual.append({"path": path.relative_to(evidence).as_posix(),
                   "sha256": digest(path), "size": path.stat().st_size})
assert sorted(files["files"], key=lambda row: row["path"]) == actual
assert files["expanded_file_count"] == len(actual) == 87
assert files["expanded_size"] == sum(row["size"] for row in actual) == 230440
assert max(row["size"] for row in actual) < 128 * 1024

prepare = load(evidence / "atomic-image-evidence/prepare.json")
manifest = load(evidence / "atomic-image-evidence/image-manifest.json")
assert prepare["passed"] is True and prepare["source_commit"] == SOURCE
assert prepare["image_source_commit"] == IMAGE_SOURCE and prepare["variant"] == "generic"
assert prepare["verified_archive"]["image_id"] == IMAGE_ID
assert prepare["artifact"]["workflow_run"]["head_sha"] == IMAGE_SOURCE
assert manifest["source_commit"] == IMAGE_SOURCE and manifest["archive"]["image_id"] == IMAGE_ID
no_oom("prepare", prepare["cgroup_final"])

result = load(evidence / "atomic-disk-evidence/result.json")
assert result["source_commit"] == SOURCE and result["image_source_commit"] == IMAGE_SOURCE
assert result["image_id"] == IMAGE_ID and result["passed"] is False
assert result["installation_attempted"] is result["installation_completed"] is True
assert result["guest_booted"] is result["os_qualified"] is result["release_qualified"] is False
assert result["disk"] == {"device": 66305, "inode": 10485906, "bytes": 24 * 1024**3,
                           "uid": 0, "mode": 0o600, "links": 1}
assert re.fullmatch(r"[0-9a-f]{64}", result["disk_sha256"])
assert result["loaded_image"]["Digest"] == MANIFEST
assert result["oci"]["manifest_digest"] == MANIFEST
assert result["oci"]["config_digest"] == IMAGE_ID
assert result["oci"]["root_filesystem_extracted"] is False
assert result["directory_source"]["recompressed"] is False
assert result["directory_source"]["root_filesystem_extracted"] is False
assert result["directory_source"]["manifest_digest"] == MANIFEST
assert result["source_authentication"] == load(evidence / "atomic-disk-evidence/source-authentication/result.json")
auth = result["source_authentication"]
assert auth["passed"] is True and auth["release_qualified"] is False
assert auth["source_manifest_digest"] == MANIFEST and auth["private_keys_removed"] is True
assert auth["positive_policy_control"] is True and all(auth["negative_controls"].values())
no_oom("source_authentication", auth["cgroup_final"])

commands = {row["name"]: row["exit_code"] for row in result["commands"]}
assert len(commands) == len(result["commands"])
for name in ("load-image", "inspect-image", "sign-source", "install", "disk-loops-after-install",
             "cleanup-symbi-atomic-signer", "cleanup-symbi-atomic-installer", "cleanup-symbi-atomic-qemu",
             "disk-loops-cleanup", "disk-loops-absent", "remove-image"):
    assert commands[name] == 0, name
assert commands["boot"] == 1 and commands["image-absent"] == 1
assert all(row == {"removed": True, "absent": True} for row in result["cleanup"].values())
assert result["loops_absent"] is result["image_removed"] is True
assert result["private_storage_removed"] is result["private_runroot_removed"] is True
no_oom("controller", result["cgroup_final"])

guest_result = load(evidence / "atomic-disk-evidence/guest-result.json")
report = load(evidence / "atomic-disk-evidence/guest-report.json")
assert guest_result["exit_code"] == 0 and guest_result["passed"] is False
assert guest_result["failure"] == "ValueError: Incomplete boot observation or false release claim"
assert 300 < guest_result["elapsed_seconds"] < 900
assert report["guest_booted"] is True and report["probe_completed"] is False
assert report["os_qualified"] is report["release_qualified"] is False
assert report["nonce"] == guest_result["nonce"]
assert report["probe_sha256"] == guest_result["probe_sha256"]
assert report["expected_sha256"] == guest_result["expected_sha256"]
assert report["failure"].endswith("timed out after 60 seconds")
assert report["product"] == "Symbi-Hosted-Atomic-Probe" and report["nics"] == ["lo"]
assert report["selinux"] == "Enforcing" and report["selinux_enforce"] == "1"
assert report["usr_readonly"] is report["sysroot_readonly"] is True
assert report["sysroot_fstype"] == "btrfs" and report["bootc_version"] == "bootc 1.17.1"
assert report["probe_security"] == {"CapBnd": "0000000000000000", "CapEff": "0000000000000000",
                                      "CapPrm": "0000000000000000", "NoNewPrivs": "1"}
assert len(report["commands"]) == 5 and all(row["exit_code"] == 0 for row in report["commands"])
reference = {"image": "ghcr.io/thirdkeyai/symbiont-os@" + MANIFEST,
             "signature": "containerPolicy", "transport": "registry"}
status = report["bootc_status"]
assert status["spec"]["image"] == reference
assert status["status"]["booted"]["image"]["image"] == reference
assert status["status"]["booted"]["image"]["imageDigest"] == MANIFEST
assert status["status"]["booted"]["incompatible"] is False
assert report["bootc_status_observation"]["service"] == {
    "ActiveState": "active", "ExecMainCode": "1", "ExecMainStatus": "0",
    "Result": "success", "SubState": "exited"}
no_oom("qemu", guest_result["cgroup_final"])

retained_names = {row["path"] for row in actual}
assert not any(name.endswith(("atomic.raw", "guest.qcow2")) for name in retained_names)
assert not any("private" in name.lower() and name.endswith((".key", ".pem")) for name in retained_names)

check = {
    "schema": 1,
    "independent_evidence_recheck_passed": True,
    "run_id": RUN,
    "source_commit": SOURCE,
    "image_source_commit": IMAGE_SOURCE,
    "evidence_artifact": {"id": ARTIFACT, "bytes": archive.stat().st_size,
                           "sha256": digest(archive), "files": len(actual)},
    "exact_image_loaded": IMAGE_ID,
    "offline_fixture_signature_controls_passed": True,
    "installation_completed": True,
    "installed_disk_bytes": result["disk"]["bytes"],
    "qemu_exited_cleanly": True,
    "guest_boot_observed": True,
    "selinux_enforcing": True,
    "booted_deployment_signature_policy": "containerPolicy",
    "usr_readonly": True,
    "sysroot": {"filesystem": "btrfs", "readonly": True},
    "guest_network_interfaces": report["nics"],
    "probe_completed": False,
    "failure": report["failure"],
    "cleanup_complete": True,
    "disk_or_overlay_retained": False,
    "oom_or_kill": False,
    "swap_enabled": False,
    "os_qualified": False,
    "release_qualified": False,
    "limitations": "The installed image booted, but the full RPM inventory exceeded the generic 60-second command timeout under single-threaded TCG. Payload and inventory verification did not complete, so this is not boot or OS acceptance.",
}
(here / "independent-check.json").write_text(json.dumps(check, indent=2) + "\n")
print(json.dumps(check, indent=2))
