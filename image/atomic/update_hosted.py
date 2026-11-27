"""Prepare an exact predecessor and exercise signed update plus booted rollback."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import uuid

from image.atomic.contract import (create_disk, directory_source, installer_mounts,
                                   installer_policy, require_disk, sha256, unique_json,
                                   unpack_oci)
from image.atomic.update_contract import (NEGATIVE_CASES, NEGATIVE_UPDATE_SOURCE,
                                          POSITIVE_OVERLAY_CASE,
                                          negative_signature_payloads,
                                          require_update_base, update_policy,
                                          validate_artifact_metadata, validate_report)
from image.atomic.update_process import TIMEOUT_SECONDS
from image.boot.inputs import unpack_desktop_image


MAX_SOURCE_BYTES = 13 * 1024**3
MAX_PUBLIC_OUTPUT_BYTES = 2 * 1024**2


def _controller_output_names():
    public = {"result.json"}
    overlays = {"same-path-positive.qcow2", "guest.qcow2"}
    public.update({"prepare-same-path-positive.qcow2.log",
                   "qemu-same-path-positive.log",
                   "same-path-positive-serial.log", "same-path-positive.json",
                   "prepare-guest.qcow2.log"})
    for case in NEGATIVE_CASES:
        label = "negative-" + case
        overlays.add(label + ".qcow2")
        public.update({"prepare-" + label + ".qcow2.log", "qemu-" + label + ".log",
                       label + "-serial.log", label + ".json"})
    for index in range(3):
        label = str(index)
        public.update({"qemu-" + label + ".log", "serial-" + label + ".log",
                       "phase-" + label + ".json"})
    return public, overlays


def _read_bounded_regular(path):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > MAX_PUBLIC_OUTPUT_BYTES):
            raise ValueError("unsafe or oversized update controller output: " + path.name)
        chunks = []
        remaining = MAX_PUBLIC_OUTPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(128 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (len(raw) != before.st_size or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino or before.st_size != after.st_size
                or before.st_mode != after.st_mode or after.st_nlink != 1
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns):
            raise ValueError("update controller output changed while retained: " + path.name)
        return raw
    finally:
        os.close(descriptor)


def retain_controller_output(output, evidence):
    """Copy only bounded direct diagnostics; never retain guest disk overlays."""
    output, evidence = Path(output), Path(evidence)
    public, overlays = _controller_output_names()
    allowed = public | overlays
    names = set()
    for path in output.iterdir():
        if path.name not in allowed:
            raise ValueError("unexpected update controller output: " + path.name)
        names.add(path.name)
    retained = []
    payloads = []
    for name in sorted(names & public):
        raw = _read_bounded_regular(output / name)
        target_name = "controller-result.json" if name == "result.json" else name
        payloads.append((target_name, raw))
    for name, raw in payloads:
        target = evidence / name
        with target.open("xb") as stream:
            stream.write(raw)
        retained.append(name)
    return retained


def _sign_source(root, group, podman, image_id, storage, containers, run,
                 source, manifest_digest, prefix):
    inputs = storage / (prefix + "-signer-input")
    inputs.mkdir(mode=0o755)
    for name in ("sign.py", "contract.py"):
        shutil.copyfile(root / "image/atomic" / name, inputs / name)
        (inputs / name).chmod(0o644)
    shutil.copyfile(root / "image/launcher/probes/bounded_process.py",
                    inputs / "bounded_process.py")
    shutil.copyfile(source / "manifest.json", inputs / "manifest.json")
    (inputs / "sign.json").write_text(json.dumps({"manifest_digest": manifest_digest}) + "\n")
    output = storage / (prefix + "-signer-output")
    output.mkdir(mode=0o700)
    os.chown(output, 10001, 10001)
    name = "symbi-atomic-" + prefix + "-signer"
    containers.append(name)
    common = ["--pull=never", "--network=none", "--pid=private",
              "--cgroup-parent=/" + str(group.relative_to("/sys/fs/cgroup")),
              "--env=LANG=C.UTF-8", "--env=PYTHONDONTWRITEBYTECODE=1"]
    command = podman + ["run", "--rm", "--name=" + name, *common, "--read-only",
                        "--user=10001:10001", "--cap-drop=ALL",
                        "--security-opt=no-new-privileges", "--memory=1g",
                        "--memory-swap=1g", "--cpus=1", "--pids-limit=64",
                        "--mount", f"type=bind,src={inputs},dst=/inputs,ro",
                        "--mount", f"type=bind,src={output},dst=/output",
                        "--env=HOME=/output", "--entrypoint=/usr/bin/python3",
                        image_id, "/inputs/sign.py"]
    run("sign-" + prefix + "-source", command, 480)
    result = unique_json((output / "evidence/result.json").read_bytes())
    controls = {case: True for case in
                ("unsigned", "wrong-key", "wrong-reference", "altered-signature")}
    if (result.get("passed") is not True or result.get("release_qualified") is not False
            or result.get("source_manifest_digest") != manifest_digest
            or result.get("private_keys_removed") is not True
            or result.get("positive_policy_control") is not True
            or result.get("negative_controls") != controls
            or sha256(output / "good-public.asc") != result.get("public_key_sha256")
            or sha256(output / "signature-1") != result.get("signature_sha256")):
        raise ValueError("predecessor source authentication acceptance incomplete")
    negative_signature_payloads(output, result)
    shutil.copyfile(output / "signature-1", source / "signature-1")
    return output, result


def _prepare_source_disk(source, storage, run):
    staging = storage / "update-source-tree"
    disk = storage / "update-source.raw"
    if staging.exists() or disk.exists():
        raise ValueError("update source staging must be new")
    root = staging / "source"
    root.mkdir(mode=0o700, parents=True)
    total = 0
    entries = 0
    for path in sorted(source.iterdir()):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink < 1
                or path.name in (".", "..") or "/" in path.name):
            raise ValueError("update source contains a linked directory or special file")
        entries += 1
        total += info.st_size
        if entries > 4096 or total > MAX_SOURCE_BYTES:
            raise ValueError("update source exceeds its bounded inventory")
        os.link(path, root / path.name, follow_symlinks=False)
    if not (root / "manifest.json").is_file() or not (root / "signature-1").is_file():
        raise ValueError("update source lacks its signed manifest")
    size = max(1024**3, ((total * 6 // 5 + 512 * 1024**2 + 4095) // 4096) * 4096)
    if size > 16 * 1024**3:
        raise ValueError("update filesystem would exceed 16 GiB")
    descriptor = os.open(disk, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.ftruncate(descriptor, size)
    finally:
        os.close(descriptor)
    filesystem_uuid = str(uuid.uuid4())
    try:
        run("update-source-filesystem",
            ["/usr/sbin/mkfs.ext4", "-q", "-F", "-m", "0", "-L", "SYMBIUPDATE",
             "-U", filesystem_uuid, "-E", "lazy_itable_init=0,lazy_journal_init=0",
             "-d", str(staging), str(disk)], 1200)
        fields = {}
        for line in run("update-source-identity",
                        ["/usr/sbin/blkid", "-p", "-o", "export", str(disk)], 30).stdout.splitlines():
            key, value = line.split("=", 1)
            if key in fields:
                raise ValueError("duplicate update filesystem identity")
            fields[key] = value
        if fields.get("TYPE") != "ext4" or fields.get("LABEL") != "SYMBIUPDATE" or fields.get("UUID") != filesystem_uuid:
            raise ValueError("update filesystem identity differs")
        os.chmod(disk, 0o444)
        return disk, {"bytes": disk.stat().st_size, "sha256": sha256(disk),
                      "filesystem": "ext4", "label": "SYMBIUPDATE",
                      "uuid": filesystem_uuid, "entries": entries,
                      "payload_bytes": total}
    finally:
        shutil.rmtree(staging)


def run_update(root, group, podman, image_id, storage, containers, run, pins,
               current_lock, current_digest, current_source, current_signing,
               current_authentication, release_policy, release_policy_bytes):
    """Install the retained predecessor, switch to current, then boot rollback."""
    root, storage = Path(root), Path(storage)
    evidence = root / ".cache/atomic-update-evidence"
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    record = {"schema": 1, "passed": False, "guest_booted": False,
              "release_qualified": False, "source_commit": os.environ["GITHUB_SHA"],
              "scope": "Disposable exact predecessor, fixture-signed update and booted rollback"}
    output = None
    try:
        record["disk_free_before_update"] = shutil.disk_usage(storage).free
        if record["disk_free_before_update"] < 30 * 1024**3:
            raise ValueError("Need 30 GiB free for predecessor install and persistent update boots")
        config = unique_json((root / "image/atomic/update-base.lock.json").read_bytes())
        selected = require_update_base(config, pins, current_lock)
        metadata = unique_json((root / ".cache/atomic-update-artifact.json").read_bytes())
        validate_artifact_metadata(config, metadata)
        wrapper = {"schema": 1, "os_qualified": False, "signature_qualified": False,
                   "images": {"generic": selected}}
        old_inputs = storage / "update-old-inputs"
        archive_zip = root / ".cache/atomic-update-image.zip"
        unpack_desktop_image(archive_zip, wrapper, pins, "generic", old_inputs)
        archive_zip.unlink()
        old_archive = old_inputs / selected["manifest"]["archive"]["name"]
        old_digest = config["manifest_digest"]
        old_image_id = selected["manifest"]["archive"]["image_id"]
        record["predecessor"] = {"tested_commit": selected["tested_commit"],
                                 "run_id": selected["run_id"],
                                 "artifact_id": selected["artifact"]["id"],
                                 "manifest_digest": old_digest,
                                 "image_id": old_image_id}
        preflight = root / "docs/security/reports/P0-03-atomic-preflight" / str(config["preflight"]["run_id"])
        old_original_policy_sha256 = None
        for phase in ("inspect", "prepare"):
            if sha256(preflight / (phase + ".json")) != config["preflight"][phase + "_sha256"]:
                raise ValueError("retained predecessor preflight evidence changed")
            if phase == "inspect":
                old_preflight = unique_json((preflight / "inspect.json").read_bytes())
                old_original_policy_sha256 = old_preflight["expected_inputs"]["trust"]["etc/containers/policy.json"]
        if (not isinstance(old_original_policy_sha256, str)
                or len(old_original_policy_sha256) != 64
                or any(character not in "0123456789abcdef" for character in old_original_policy_sha256)):
            raise ValueError("retained predecessor policy identity is invalid")
        record["old_oci"] = unpack_oci(old_archive, storage / "update-old-oci",
                                        old_digest, old_image_id)
        old_source = storage / "update-old-signed"
        record["old_directory_source"] = directory_source(storage / "update-old-oci",
                                                            old_source, old_digest)
        old_signing, old_auth = _sign_source(root, group, podman, image_id, storage,
                                             containers, run, old_source, old_digest,
                                             "update-old")
        policy_hash = hashlib.sha256(release_policy_bytes).hexdigest()
        old_policy = installer_policy(release_policy,
                                      (old_signing / "good-public.asc").read_bytes(), old_digest)
        disk_dir = storage / "update-old-disk"
        disk_dir.mkdir(mode=0o700)
        identity = create_disk(disk_dir, 24 * 1024**3)
        disk = disk_dir / "atomic.raw"
        installer_input = storage / "update-old-installer-input"
        installer_input.mkdir(mode=0o700)
        for name in ("install.py", "contract.py"):
            shutil.copyfile(root / "image/atomic" / name, installer_input / name)
        (installer_input / "original-policy.json").write_bytes(release_policy_bytes)
        shutil.copyfile(old_signing / "good-public.asc", installer_input / "test-public.asc")
        (installer_input / "install-policy.json").write_text(json.dumps(old_policy, indent=2) + "\n")
        (installer_input / "install.json").write_text(json.dumps({
            "disk": identity, "manifest_digest": old_digest,
            "original_policy_sha256": policy_hash,
            "installer_policy_sha256": sha256(installer_input / "install-policy.json"),
            "test_public_key_sha256": old_auth["public_key_sha256"],
            "signature_sha256": old_auth["signature_sha256"]}) + "\n")
        temporary = storage / "update-old-installer-tmp"
        temporary.mkdir(mode=0o700)
        name = "symbi-atomic-update-old-installer"
        containers.append(name)
        common = ["--pull=never", "--network=none", "--pid=private",
                  "--cgroup-parent=/" + str(group.relative_to("/sys/fs/cgroup")),
                  "--env=LANG=C.UTF-8", "--env=PYTHONDONTWRITEBYTECODE=1"]
        command = podman + ["run", "--rm", "--name=" + name, *common, "--privileged",
                            "--memory=2g", "--memory-swap=2g", "--cpus=1", "--pids-limit=128",
                            *installer_mounts(storage, input_name="update-old-installer-input",
                                             source_name="update-old-signed",
                                             disk_name="update-old-disk",
                                             temporary_name="update-old-installer-tmp"),
                            "--entrypoint=/usr/bin/python3", image_id, "/inputs/install.py"]
        require_disk(disk, identity)
        run("install-update-predecessor", command, 2400)
        require_disk(disk, identity)
        loops = unique_json(run("update-old-loops",
                                ["losetup", "--json", "--list", "--output", "NAME,BACK-FILE",
                                 "--associated", str(disk)]).stdout)
        if loops.get("loopdevices") not in (None, []):
            raise ValueError("predecessor installer left loop devices")
        old_disk_hash = sha256(disk)
        os.chmod(disk, 0o444, follow_symlinks=False)
        update_disk, source_disk = _prepare_source_disk(current_source, storage, run)
        local_policy = update_policy(release_policy,
                                     (current_signing / "good-public.asc").read_bytes(),
                                     current_digest)
        inputs = storage / "update-boot-input"
        inputs.mkdir(mode=0o755)
        for name in ("update_boot.py", "update_guest.py", "update-o.service",
                     "update-fstab.extra"):
            shutil.copyfile(root / "image/atomic" / name, inputs / name)
            (inputs / name).chmod(0o644)
        (inputs / "atomic.raw").touch(mode=0o644)
        (inputs / "update.raw").touch(mode=0o644)
        (inputs / "update-policy.json").write_text(json.dumps(local_policy, indent=2) + "\n")
        expected = {"schema": 1, "nonce": uuid.uuid4().hex,
                    "old_digest": old_digest, "new_digest": current_digest,
                    "source_disk": source_disk,
                    "signature_sha256": current_authentication["signature_sha256"],
                    "policy_sha256": sha256(inputs / "update-policy.json"),
                    "original_policy_sha256": old_original_policy_sha256}
        (inputs / "expected.json").write_text(json.dumps(expected, sort_keys=True) + "\n")
        positive_control = {"case": POSITIVE_OVERLAY_CASE,
                            "source": NEGATIVE_UPDATE_SOURCE}
        (inputs / "expected-positive.json").write_text(json.dumps({
            **expected, "same_path_positive_control": positive_control}, sort_keys=True) + "\n")
        negative_payloads = negative_signature_payloads(current_signing,
                                                         current_authentication)
        for case in NEGATIVE_CASES:
            control = {"case": case, "source": NEGATIVE_UPDATE_SOURCE,
                       "signature": negative_payloads[case]}
            (inputs / ("expected-" + case + ".json")).write_text(
                json.dumps({**expected, "negative_control": control}, sort_keys=True) + "\n")
        for path in inputs.iterdir():
            path.chmod(0o644)
        output = storage / "update-boot-output"
        output.mkdir(mode=0o700)
        os.chown(output, 10001, 10001)
        name = "symbi-atomic-update-qemu"
        containers.append(name)
        command = podman + ["run", "--rm", "--name=" + name, *common, "--read-only",
                            "--user=10001:10001", "--cap-drop=ALL",
                            "--security-opt=no-new-privileges", "--memory=3g",
                            "--memory-swap=3g", "--cpus=2", "--pids-limit=64",
                            "--mount", f"type=bind,src={inputs},dst=/inputs,ro",
                            "--mount", f"type=bind,src={disk},dst=/inputs/atomic.raw,ro",
                            "--mount", f"type=bind,src={update_disk},dst=/inputs/update.raw,ro",
                            "--mount", f"type=bind,src={output},dst=/output",
                            "--entrypoint=/usr/bin/python3", image_id, "/inputs/update_boot.py"]
        run("signed-update-and-rollback", command, TIMEOUT_SECONDS)
        controller = unique_json((output / "result.json").read_bytes())
        positive = controller.get("same_path_positive_control")
        if (controller.get("passed") is not True or controller.get("guest_booted") is not True
                or controller.get("source_disk_unchanged") is not True
                or controller.get("persistent_overlay") is not True
                or not isinstance(positive, dict) or positive.get("passed") is not True
                or positive.get("overlay_discarded") is not True
                or positive.get("negative_baselines_clean") is not True
                or positive.get("source") != NEGATIVE_UPDATE_SOURCE
                or controller.get("bootc_negative_controls")
                != {case: True for case in NEGATIVE_CASES}
                or controller.get("negative_overlays_discarded") is not True):
            raise ValueError("signed update and rollback VM did not pass")
        controls = {case: True for case in
                    ("unsigned", "wrong-key", "wrong-reference", "altered-signature")}
        authentication = {"positive_controls": {"install": old_auth["positive_policy_control"],
                                                  "update": current_authentication["positive_policy_control"]},
                          "negative_controls": {case: old_auth["negative_controls"][case]
                                                and current_authentication["negative_controls"][case]
                                                for case in controls}}
        report = {"schema": 1, "passed": True, "guest_booted": True,
                  "release_qualified": False, "source_authentication": authentication,
                  "same_path_positive_control": positive,
                  "bootc_negative_controls": controller["bootc_negative_controls"],
                  "negative_overlays_discarded": controller["negative_overlays_discarded"],
                  "phases": controller["phases"], "source_disk_unchanged": True,
                  "persistent_overlay": True}
        summary = validate_report(report, old_digest, current_digest)
        if sha256(disk) != old_disk_hash or sha256(update_disk) != source_disk["sha256"]:
            raise ValueError("read-only predecessor or update disk changed")
        shutil.copytree(old_signing / "evidence", evidence / "predecessor-authentication")
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        record.update(passed=True, guest_booted=True, source_authentication=authentication,
                      same_path_positive_control=positive,
                      bootc_negative_controls=controller["bootc_negative_controls"],
                      negative_overlays_discarded=controller["negative_overlays_discarded"],
                      source_disk=source_disk, phases=controller["phases"], summary=summary)
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if output is not None and output.is_dir():
            try:
                record["retained_controller_output"] = retain_controller_output(output, evidence)
            except Exception as error:
                record["retention_failure"] = type(error).__name__ + ": " + str(error)
                record["passed"] = False
        (evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    if not record["passed"]:
        raise RuntimeError("signed update evidence retention did not pass")
    return record
