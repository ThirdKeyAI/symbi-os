"""Independently reconcile the small successful generic desktop evidence."""
from pathlib import Path
import hashlib
import json
import re
import sys
import tempfile
import zipfile


RUN = 45870354828
SOURCE = "d436c6ee8a7ed159afa59db9bd82377ae8ea2389"
EVIDENCE_ARTIFACT = 15142273486
IMAGE_ARTIFACT = 15142163489
root = Path(__file__).resolve().parents[5]
here = Path(__file__).resolve().parent
evidence = here
sys.path.insert(0, str(root))

from image.desktop.inputs import require_transaction
from image.desktop.trust import prepare_trust
from image.hyprland.inventory import require_subject
from image.hyprland.resolve_packages import require_keyring, require_verified_rpm
from image.portal.runtime_inputs import select_runtime_package
from image.signing import render, write_bundle
from image.walker.inputs import require_package_identity


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


metadata = load(here / "artifact-metadata.json")
archive = here / "artifact.zip"
assert metadata["id"] == EVIDENCE_ARTIFACT
assert metadata["name"] == "desktop-image-evidence-generic"
assert metadata["workflow_run"]["id"] == RUN
assert metadata["workflow_run"]["head_sha"] == SOURCE
assert metadata["expired"] is False
assert metadata["size_in_bytes"] == archive.stat().st_size
assert metadata["digest"] == "sha256:" + digest(archive)

files = load(here / "artifact-files.json")
actual = []
for row in sorted(files["files"], key=lambda item: item["path"]):
    path = evidence / row["path"]
    assert not path.is_symlink()
    actual.append({"path": path.relative_to(evidence).as_posix(),
                   "sha256": digest(path), "size": path.stat().st_size})
assert sorted(files["files"], key=lambda row: row["path"]) == actual
assert files["expanded_file_count"] == len(actual) == 196
assert files["expanded_size"] == sum(row["size"] for row in actual) == 497210
with zipfile.ZipFile(archive) as artifact:
    members = [row.filename for row in artifact.infolist() if not row.is_dir()]
assert sorted(members) == sorted(row["path"] for row in actual)

build = load(evidence / "build.json")
prep = load(evidence / "preparation.json")
assert build["source_commit"] == prep["source_commit"] == SOURCE
assert build["passed"] is build["image_built"] is True and build["os_qualified"] is False
assert prep["passed"] is True and prep["variant"] == build["variant"] == "generic"
base = load(root / "image/base-images.json")["variants"]["generic"]["image"]
assert prep["base"] == build["base"] == base
require_subject(load(evidence / "base-signature-stdout.log"), base)

commands = {row["name"]: row["exit_code"] for row in build["commands"]}
assert len(commands) == len(build["commands"])
for name, status in commands.items():
    expected = 2 if name in ("picker-allow-token", "picker-unknown-option") else 1 if (
        name.startswith("absent-") or name == "base-check-absent") else 0
    assert status == expected, name

required = []
for name in ("image/hyprland/runtime-rpms.lock.json",
             "image/launcher/runtime-rpms.lock.json",
             "image/assembly/runtime-rpms.lock.json"):
    required.extend(load(root / name)["packages"])
required.append(select_runtime_package(load(root / "image/portal/build-rpms.lock.json")))
assert prep["required_packages"] == required and len(required) == 6
trust = load(root / "image/hyprland/fedora-package-trust.json")
fingerprint = trust["key"]["fingerprint"]
require_keyring((evidence / "install/keyring-stdout.log").read_text(), fingerprint)
identities = []
for index, package in enumerate(required):
    require_verified_rpm(0, (evidence / f"install/rpm-{index}-signature-stdout.log").read_text(), fingerprint)
    rows = (evidence / f"install/rpm-{index}-identity-stdout.log").read_text().splitlines()
    assert len(rows) == 1
    require_package_identity(rows[0], package["nevra"])
    identities.extend(rows)
before = (evidence / "install/installed-before-stdout.log").read_text().splitlines()
after = (evidence / "install/installed-after-stdout.log").read_text().splitlines()
require_transaction(before, after, identities)
assert len(before) == 2178 and len(after) == 2184
assert set(identities).isdisjoint(before) and set(after) - set(before) == set(identities)
old_config = load(evidence / "install/crypto-before.json")
new_config = load(evidence / "install/crypto-after.json")
assert old_config == new_config and len(old_config) == 40
install = load(evidence / "install/result.json")
assert install == build["installation"] and install["passed"] is True
assert install["all_base_packages_unchanged"] is install["base_crypto_configuration_unchanged"] is True
assert digest(evidence / "install/openssl3.cnf") == install["compatibility_configuration_sha256"]

installed = load(evidence / "installed-files-stdout.log")
assert installed == build["installed_files"] and installed["passed"] is True
assert installed["installed_files_checked"] == len({**prep["payload"], **prep["overlay"]}) == 212
assert installed["installed_package_count"] == len(after) == 2184 and installed["uid"] == 10001
fonts = prep["fonts"]
native = installed["fonts"]
assert fonts["source_commit"] == SOURCE and fonts["development_included"] is True
assert fonts["selected_for_release"] is fonts["security_qualified"] is fonts["os_qualified"] is False
assert fonts["font_count"] == len(fonts["font_paths"]) == native["scanned_fonts"] == 98
assert len(set(fonts["font_paths"])) == 98
assert all(path.removeprefix("/") in prep["payload"] for path in fonts["font_paths"])
assert {"JetBrainsMono Nerd Font", "Symbols Nerd Font"} <= set(native["families"])
assert native["monospace_family"] == "JetBrainsMono Nerd Font"
assert native["monospace_file"] in fonts["font_paths"] and "/JetBrainsMono/" in native["monospace_file"]
font_intake = load(evidence / "font-intake/result.json")
assert font_intake["passed"] is True and font_intake["source_commit"] == SOURCE
assert font_intake["inputs_sha256"] == fonts["inputs_sha256"]
assert font_intake["inventories"] == fonts["archives"]
assert font_intake["selected"] is font_intake["font_parser_executed"] is font_intake["archive_extracted"] is False

for name in ("Hyprland", "hyprctl", "elephant", "walker", "symbi", "symbi-sandbox-supervisor",
             "portal-toolkit", "portal-picker", "portal-backend"):
    output = (evidence / f"ldd-{name}-stdout.log").read_text() + (evidence / f"ldd-{name}-stderr.log").read_text()
    assert "not found" not in output and output.strip()
for name, expected in (("symbi-version", "symbi 3.0.0"), ("walker-version", "2.17.2"),
                       ("elephant-provider", "desktopapplications"),
                       ("portal-version", "xdg-desktop-portal-hyprland v1.5.0")):
    assert (evidence / f"{name}-stdout.log").read_text().strip() == expected
activation = load(evidence / "portal-activation-stdout.log")
assert activation["passed"] is True and activation["interactive_session_qualified"] is False
session = load(evidence / "session-result.json")
assert session["passed"] is True and [row["exit_code"] for row in session["checks"]] == [0, 1, 0]
assert all(row["passed"] for row in session["checks"])
assert session["hyprland_sha256"] == prep["payload"]["usr/lib/symbi/hyprland/bin/Hyprland"]["sha256"]
for name, sha256 in session["defaults_sha256"].items():
    assert sha256 == prep["overlay"]["usr/share/symbiont/defaults/hypr/" + name]["sha256"]
assert len(build["checks"]) == 18 and all(row["passed"] for row in build["checks"])
assert build["all_containers_absent"] is True and len(build["containers"]) == 20
assert all(row == {"removed": True, "absent": True} for row in build["containers"].values())
assert not (evidence / "all-containers-absent-stdout.log").read_text().strip()

expected_limits = {"memory.max": "2147483648", "memory.swap.max": "0",
                   "cpu.max": "100000 100000", "pids.max": "128"}
assert build["image_build_limits_verified"] == expected_limits
groups = {"preparation": prep["cgroup_final"], "font_intake": font_intake["cgroup_final"],
          "build_tree": build["image_build_cgroup_final"], "installer": install["cgroup_final"],
          "controller": build["cgroup_final"]}
for label, counters in groups.items():
    events = dict(line.split() for line in counters["memory.events"].splitlines())
    assert events["oom"] == events["oom_kill"] == events["oom_group_kill"] == "0", label
    assert counters["memory.swap.max"] == "0", label

release_path = root / "image/release-trust.json"
bases_path = root / "image/base-images.json"
trust_record = prep["image_trust"]
assert trust_record["release_trust_sha256"] == digest(release_path)
assert trust_record["base_pins_sha256"] == digest(bases_path)
assert trust_record["signature_qualified"] is False
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary) / "containers"
    bundle = render(load(release_path), load(bases_path), root)
    write_bundle(bundle, directory)
    for suffix in ("policy.json", "registries.d/symbiont.yaml"):
        key = "etc/containers/" + suffix
        path = directory / suffix
        actual = {"sha256": digest(path), "bytes": path.stat().st_size}
        assert trust_record["files"][key] == actual
        assert prep["payload"][key] == {**actual, "mode": 0o644}
    policy = load(directory / "policy.json")
    assert policy["default"] == [{"type": "reject"}]

manifest = load(evidence / "image-manifest.json")
assert manifest == {"schema": 1, "built": True, "os_qualified": False,
                    "source_commit": SOURCE, "base": base, "variant": "generic",
                    "archive": build["image_archive"],
                    "preparation_sha256": digest(evidence / "preparation.json")}
assert build["image_archive"]["image_id"] == build["image_id"]
image_artifact = load(here / "image-artifact-metadata.json")
assert image_artifact["id"] == IMAGE_ARTIFACT
assert image_artifact["name"] == "desktop-development-image-generic"
assert image_artifact["workflow_run"]["id"] == RUN
assert image_artifact["workflow_run"]["head_sha"] == SOURCE
assert image_artifact["expired"] is False and image_artifact["size_in_bytes"] == 4177411378
assert re.fullmatch(r"sha256:[0-9a-f]{64}", image_artifact["digest"])

check = {
    "schema": 1,
    "independent_evidence_recheck_passed": True,
    "run_id": RUN,
    "source_commit": SOURCE,
    "base_signature_subject_verified": True,
    "rpm_signatures_and_identities_rechecked": 6,
    "base_packages_preserved": len(before),
    "installed_packages": len(after),
    "new_runtime_packages": len(set(after) - set(before)),
    "original_crypto_slots_preserved": len(old_config),
    "installed_files_checked": installed["installed_files_checked"],
    "native_fonts_checked": native["scanned_fonts"],
    "native_monospace_default": native["monospace_family"],
    "dynamic_loaders_checked": 9,
    "cli_provider_controls": 4,
    "picker_cli_refusals": 2,
    "activation_defaults_checked": True,
    "lua_controls": 3,
    "bootc_lint": (evidence / "bootc-lint-stdout.log").read_text(),
    "temporary_containers_removed_and_absent": len(build["containers"]),
    "oom_or_kill": False,
    "swap_enabled": False,
    "image_archive": build["image_archive"],
    "hosted_image_artifact": {"id": IMAGE_ARTIFACT, "bytes": image_artifact["size_in_bytes"],
                               "sha256": image_artifact["digest"].removeprefix("sha256:")},
    "installed_approved_trust_files": trust_record["files"],
    "image_manifest_sha256": digest(evidence / "image-manifest.json"),
    "font_release_selected": False,
    "signature_qualified": False,
    "os_qualified": False,
    "limitations": "Evidence reconciliation only; the large OCI archive remains hosted. No VM boot, graphical interaction, physical NVIDIA behavior, containment, release-signature enforcement, update, or rollback qualification.",
}
(here / "independent-check.json").write_text(json.dumps(check, indent=2) + "\n")
print(json.dumps(check, indent=2))
