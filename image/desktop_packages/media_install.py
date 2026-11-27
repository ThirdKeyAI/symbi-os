"""Verify two isolated signers, exact sources and install a closed RPM set offline."""
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import tempfile

try:
    from image.desktop_packages.contract import require_keyring, verified_signer
    from image.desktop_packages.media_contract import (
        offline_install_command, require_media_lock, require_source_release_match)
    from image.launcher.probes.bounded_process import run_bounded
except ModuleNotFoundError:  # Copied standalone into the image-build input mount.
    from bounded_process import run_bounded
    from contract import require_keyring, verified_signer
    from media_contract import offline_install_command, require_media_lock, require_source_release_match


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def trust_snapshot(root):
    result = {}
    accounted = set()
    total_bytes = 0
    resolved_root = root.resolve(strict=True)
    bases = ("etc", "usr/etc", "usr/share/factory/etc", "usr/share/secureblue/etc")
    relative_roots = [base + suffix for base in bases
                      for suffix in ("/dnf", "/yum.repos.d", "/pki/rpm-gpg")]
    relative_roots += [
        "usr/share/dnf5/repos.d",
        "usr/share/dnf/repos.d",
        "usr/share/pki/rpm-gpg",
        "usr/share/distribution-gpg-keys/fedora",
        "usr/share/distribution-gpg-keys/rpmfusion",
    ]

    def metadata(value):
        return {"uid": value.st_uid, "gid": value.st_gid, "mode": value.st_mode}

    def existing_directory(relative):
        path = resolved_root
        for part in Path(relative).parts:
            path /= part
            try:
                observed = path.lstat()
            except FileNotFoundError:
                return None
            if not stat.S_ISDIR(observed.st_mode):
                raise ValueError("Unexpected repository trust directory path")
        return path

    def remember_directory(path):
        relative = path.relative_to(resolved_root).as_posix()
        if relative not in result:
            result[relative] = {"type": "directory", "lstat": metadata(path.lstat())}
        if len(result) > 1100:
            raise ValueError("Excessive installed RPM trust inputs")

    def count_bytes(path, size):
        nonlocal total_bytes
        resolved = path.resolve(strict=True)
        if resolved not in accounted:
            accounted.add(resolved); total_bytes += size
        if total_bytes > 16 * 1024 * 1024:
            raise ValueError("Installed RPM trust inputs exceed their total bound")

    def remember(path):
        relative = path.relative_to(resolved_root).as_posix()
        if relative in result:
            return
        observed = path.lstat()
        if stat.S_ISDIR(observed.st_mode):
            remember_directory(path)
            for child in sorted(path.iterdir()):
                remember(child)
            return
        if stat.S_ISREG(observed.st_mode):
            if observed.st_size > 262144:
                raise ValueError("Oversized installed repository trust input")
            count_bytes(path, observed.st_size)
            result[relative] = {"type": "regular", "lstat": metadata(observed),
                                "bytes": observed.st_size, "sha256": digest(path)}
        elif stat.S_ISLNK(observed.st_mode):
            try:
                target = path.resolve(strict=True)
                target_observed = target.lstat()
            except (OSError, RuntimeError) as error:
                raise ValueError("Unsafe installed repository trust link") from error
            if (not target.is_relative_to(resolved_root)
                    or not stat.S_ISREG(target_observed.st_mode)
                    or target_observed.st_size > 262144):
                raise ValueError("Unsafe installed repository trust link")
            count_bytes(target, target_observed.st_size)
            result[relative] = {
                "type": "symlink",
                "lstat": metadata(observed),
                "link": os.readlink(path),
                "target": target.relative_to(resolved_root).as_posix(),
                "target_lstat": metadata(target_observed),
                "target_bytes": target_observed.st_size,
                "target_sha256": digest(target),
            }
        else:
            raise ValueError("Unexpected installed repository trust input")
        if len(result) > 1100:
            raise ValueError("Excessive installed RPM trust inputs")

    for base in bases:
        directory = existing_directory(base)
        if directory is not None:
            remember_directory(directory)
    for relative_root in relative_roots:
        directory = existing_directory(relative_root)
        if directory is not None:
            remember(directory)
    return result


def identity(row):
    return "\t".join(str(row[name]) for name in
                     ("name", "epoch", "version", "release", "arch", "nevra", "vendor", "license", "source_rpm"))


def require_additive_inventory(installed, packages):
    """Refuse even equal-NEVRA base packages: their installed bytes lack this gate's provenance."""
    installed_keys = set()
    for entry in installed:
        fields = entry.split("\t")
        if len(fields) != 5:
            raise ValueError("Installed package inventory is malformed")
        installed_keys.add((fields[0], fields[4]))
    expected = set()
    for row in packages:
        wanted = "\t".join(row[name] for name in ("name", "epoch", "version", "release", "arch"))
        if (row["name"], row["arch"]) in installed_keys:
            raise ValueError("Media closure is not additive to the selected base: " + wanted)
        expected.add(wanted)
    if len(expected) != len(packages):
        raise ValueError("Media closure contains duplicate package identities")
    return expected


def main():
    inputs, output = Path("/symbi-build-inputs/media"), Path("/symbi-build-evidence/media")
    if (os.geteuid() != 0 or not inputs.is_dir() or not output.parent.is_mount()
            or not os.statvfs(inputs).f_flag & os.ST_RDONLY
            or not (Path("/run/.containerenv").exists() or Path("/.dockerenv").exists())):
        raise SystemExit("Use the read-only offline image-build input mount")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "fedora" or release.get("VERSION_ID") != "45":
        raise ValueError("Media packages require Fedora 45")
    if sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]:
        raise ValueError("Media installation must not have a network device")
    group = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    if (limits["memory.max"] != "2147483648" or limits["memory.swap.max"] != "0"
            or limits["cpu.max"] != "100000 100000"):
        raise ValueError("Media install resource limits changed")
    lock = json.loads((inputs / "media-rpms.lock.json").read_text())
    pins = json.loads((inputs / "base-images.json").read_text())
    trust = json.loads((inputs / "trust.json").read_text())
    require_media_lock(lock, inputs / "repository", pins, trust, require_ready=True)
    output.mkdir(parents=True, exist_ok=True)
    record = {"schema": 1, "passed": False, "os_qualified": False, "playback_qualified": False,
              "limits": limits, "commands": [], "persisted_repository_trust": False,
              "scope": "Exact offline media RPM install; playback and release acceptance remain separate"}

    def save():
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")

    def run(name, command, timeout=60):
        record["active_command"] = {"name": name, "command": command}; save()
        result = run_bounded(command, output / (name + "-stdout.log"), output / (name + "-stderr.log"),
                             timeout, 1024 * 1024)
        record["commands"].append({"name": name, "exit_code": result.returncode})
        del record["active_command"]; save(); result.check_returncode()
        return result

    try:
        before_trust = trust_snapshot(Path("/"))
        (output / "trust-before.json").write_text(json.dumps(before_trust, indent=2) + "\n")
        query = ["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"]
        before = sorted(run("installed-before", query).stdout.splitlines())
        gpg_before = sorted(run("installed-gpg-before", ["rpm", "-qa", "gpg-pubkey*", "--qf",
                                                          "%{NAME}\t%{VERSION}\t%{RELEASE}\n"]).stdout.splitlines())
        (output / "empty-repos").mkdir(mode=0o700)
        (output / "dnf-cache").mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix="symbi-media-keyring-", dir="/run") as temporary:
            temporary = Path(temporary)
            keyring = temporary / "keyring"; rpmdb = temporary / "rpmdb"
            keyring.mkdir(mode=0o700); rpmdb.mkdir(mode=0o700)
            rpmkeys = ["rpmkeys", "--define", "_keyring fs", "--define", "_keyringpath " + str(keyring),
                       "--dbpath", str(rpmdb), "--define", "_pkgverify_level all"]
            for index, key in enumerate(lock["trusted_keys"]):
                path = inputs / key["file"]
                if (path.is_symlink() or not path.is_file() or path.stat().st_size > 65536
                        or digest(path) != key["sha256"]):
                    raise ValueError("Media public key bytes changed")
                run("import-isolated-key-" + str(index), rpmkeys + ["--import", str(path)])
            require_keyring(run("isolated-keyring", rpmkeys + ["--list"]).stdout,
                            [key["fingerprint"] for key in lock["trusted_keys"]])
            observed, package_paths = [], []
            for index, row in enumerate(lock["closure"]["packages"]):
                path = inputs / "rpms" / row["filename"]
                if (path.is_symlink() or not path.is_file() or path.stat().st_size != row["bytes"]
                        or digest(path) != row["sha256"]):
                    raise ValueError("Locked media RPM bytes changed")
                checked = run(f"binary-{index:03}-signature", rpmkeys + ["--checksig", "--verbose", str(path)])
                if verified_signer(checked.returncode, checked.stdout,
                                   [key["fingerprint"] for key in lock["trusted_keys"]]) != row["key_fingerprint"]:
                    raise ValueError("Media RPM signer differs from its lock")
                actual = run(f"binary-{index:03}-identity", ["rpm", "-qp", "--qf",
                    "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{NEVRA}\t%{VENDOR}\t%{LICENSE}\t%{SOURCERPM}\n",
                    str(path)]).stdout.strip()
                if actual != identity(row):
                    raise ValueError("Media RPM identity differs from its lock")
                observed.append(row); package_paths.append(path)
            source_rows = []
            for index, slot in enumerate(lock["source_inputs"]):
                path = inputs / "srpms" / slot["filename"]
                if (path.is_symlink() or not path.is_file() or path.stat().st_size != slot["bytes"]
                        or digest(path) != slot["sha256"]):
                    raise ValueError("Locked media source RPM bytes changed")
                checked = run(f"source-{index:03}-signature", rpmkeys + ["--checksig", "--verbose", str(path)])
                if verified_signer(checked.returncode, checked.stdout,
                                   [key["fingerprint"] for key in lock["trusted_keys"]]) != slot["key_fingerprint"]:
                    raise ValueError("Media source RPM signer differs from its lock")
                names = ("name", "epoch", "version", "release", "arch", "nevra", "filename", "bytes",
                         "sha256", "signature_verified", "key_fingerprint")
                source = {name: slot[name] for name in names}
                actual = run(f"source-{index:03}-identity", ["rpm", "-qp", "--qf",
                    "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{NEVRA}\n",
                    str(path)]).stdout.strip()
                expected = "\t".join(source[name] for name in ("name", "epoch", "version", "release", "arch", "nevra"))
                if actual != expected:
                    raise ValueError("Media source RPM identity differs from its lock")
                source_rows.append(source)
            require_source_release_match(lock["root_packages"], source_rows)
            expected_added = require_additive_inventory(before, observed)
            run("offline-media-install", offline_install_command(package_paths, output), 600)
        if temporary.exists():
            raise ValueError("Ephemeral media keyring remained after verification")
        after = sorted(run("installed-after", query).stdout.splitlines())
        gpg_after = sorted(run("installed-gpg-after", ["rpm", "-qa", "gpg-pubkey*", "--qf",
                                                        "%{NAME}\t%{VERSION}\t%{RELEASE}\n"]).stdout.splitlines())
        if not set(before).issubset(after) or set(after) - set(before) != expected_added:
            raise ValueError("Offline media transaction changed an unselected package")
        after_trust = trust_snapshot(Path("/"))
        (output / "trust-after.json").write_text(json.dumps(after_trust, indent=2) + "\n")
        record["persisted_repository_trust"] = gpg_after != gpg_before or after_trust != before_trust
        if record["persisted_repository_trust"]:
            raise ValueError("Offline media transaction changed persistent repository trust")
        record.update(passed=True, packages_verified=len(observed), source_packages_verified=len(source_rows),
                      added_packages=sorted(expected_added), base_packages_preserved=True,
                      persistent_trust_unchanged=True)
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        record["cgroup_final"] = {name: (group / name).read_text().strip()
                                   for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        save()
    if not record["passed"]:
        raise RuntimeError("Offline media verification or installation failed")


if __name__ == "__main__":
    main()
