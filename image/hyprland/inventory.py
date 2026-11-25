#!/usr/bin/env python3
"""Inventory the authenticated Fedora base on a disposable hosted runner."""
import json
import os
from pathlib import Path
import subprocess
import sys


def require_subject(signatures, image):
    """Check Cosign's successful output; this does not verify a signature itself."""
    repository, digest = image.split("@")
    if not isinstance(signatures, list) or not signatures:
        raise ValueError("No verified image signatures")
    for signature in signatures:
        try:
            critical = signature["critical"]
            valid = (critical["type"] == "cosign container image signature"
                     and critical["identity"]["docker-reference"] == repository
                     and critical["image"]["docker-manifest-digest"] == digest)
        except (KeyError, TypeError):
            raise ValueError("Malformed verified subject") from None
        if not valid:
            raise ValueError("Verified subject does not match selected base")


CONTAINER_INVENTORY = r'''
import hashlib,json,pathlib,subprocess
root=pathlib.Path('/')
group=pathlib.Path('/sys/fs/cgroup')/pathlib.Path(pathlib.Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]).relative_to('/')
limits={name:(group/name).read_text().strip() for name in ('memory.max','memory.swap.max','cpu.max','pids.max')}
assert limits=={'memory.max':'536870912','memory.swap.max':'0','cpu.max':'50000 100000','pids.max':'64'},limits
release=(root/'etc/os-release').read_text()
assert any(line in ('ID=fedora','ID="fedora"') for line in release.splitlines())
files={}
paths=[root/'etc/os-release',root/'etc/dnf/dnf.conf',root/'etc/containers/policy.json']
paths+=sorted((root/'etc/yum.repos.d').glob('*.repo'))
paths+=sorted((root/'etc/pki/rpm-gpg').glob('*'))
for path in paths:
    if not path.is_file(): continue
    data=path.read_bytes()
    assert len(data)<=262144,str(path)
    assert b'PRIVATE KEY' not in data,str(path)
    files[str(path)]={'sha256':hashlib.sha256(data).hexdigest(),'text':data.decode()}
packages=subprocess.check_output(['rpm','-qa','--qf','%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'],text=True)
keys=subprocess.run(['rpm','-q','gpg-pubkey','--qf','%{NAME}-%{VERSION}-%{RELEASE}\n'],capture_output=True,text=True)
tools={name: (root/'usr/bin'/name).is_file() for name in ('dnf','dnf5','rpm','gpg','gcc','g++','cmake','ninja','Hyprland','waybar','walker','foot','bootc')}
print(json.dumps({'scope':'Read-only authenticated image inventory, no package installation or Fedora boot',
                 'files':files,'installed_packages':sorted(packages.splitlines()),
                 'rpm_key_query':{'exit_code':keys.returncode,'stdout':keys.stdout,'stderr':keys.stderr},'tools':tools,'limits':limits,'os_qualified':False},indent=2))
'''


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Refusing local image pull or execution")
    if os.geteuid() != 0:
        raise SystemExit("Use the disposable hosted resource unit")
    root = Path.cwd()
    sys.path.insert(0, str(root / "image/toolchain"))
    from bootstrap_cosign import bootstrap
    sys.path.insert(0, str(root / "image"))
    from recipe import render
    evidence = root / ".cache/fedora-base-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    process_group = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    # DelegateSubgroup keeps the supervising process out of the unit's internal
    # cgroup, so Podman's sibling container can receive domain controllers.
    assert process_group.name == "supervisor"
    cgroup = process_group.parent
    assert cgroup.name.startswith("symbi-fedora-base-") and cgroup.name.endswith(".service")
    assert not (cgroup / "cgroup.procs").read_text().strip()
    names = ("memory.max", "memory.swap.max", "cpu.max", "pids.max")
    limits = {name: (cgroup / name).read_text().strip() for name in names}
    (evidence / "cgroup-limits.json").write_text(json.dumps(limits, indent=2) + "\n")
    assert limits == {"memory.max": "2147483648", "memory.swap.max": "0", "cpu.max": "100000 100000", "pids.max": "256"}
    try:
        pins = json.loads((root / "image/base-images.json").read_text())
        render(pins, "generic", root)  # Reuse digest and committed-key validation.
        pin = pins["variants"]["generic"]
        cosign = bootstrap(root, evidence)
        verified = subprocess.check_output([str(cosign), "verify", "--key", str(root / pin["public_key"]),
                                            "--output", "json", pin["image"]], text=True, timeout=180)
        require_subject(json.loads(verified), pin["image"])
        (evidence / "base-signature.json").write_text(verified)
        storage = root / ".cache/fedora-inventory-storage"
        storage.mkdir()
        auth = storage / "auth.json"
        auth.write_text('{"auths": {}}\n')
        podman = ["podman", "--cgroup-manager=cgroupfs", "--root", str(storage / "root"), "--runroot", str(storage / "run")]
        with (evidence / "pull.log").open("w") as log:
            subprocess.run(podman + ["pull", "--authfile", str(auth), pin["image"]],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
        inspected = subprocess.check_output(podman + ["image", "inspect", pin["image"]], text=True, timeout=30)
        (evidence / "image-inspect.json").write_text(inspected)
        command = podman + ["run", "--rm", "--pull=never", "--read-only", "--network=none",
                            "--cgroup-parent=/" + str(cgroup.relative_to("/sys/fs/cgroup")),
                            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64",
                            "--memory=512m", "--memory-swap=512m", "--cpus=0.5",
                            "--entrypoint=/usr/bin/python3", pin["image"], "-c", CONTAINER_INVENTORY]
        inventory = subprocess.check_output(command, text=True, timeout=90)
        json.loads(inventory)
        (evidence / "inventory.json").write_text(inventory)
        result = {"schema": 1, "base": pin, "signature_verified_before_pull": True,
                  "inventory_completed": True, "network_inside_inventory": "none",
                  "source_commit": os.environ["GITHUB_SHA"], "os_qualified": False,
                  "scope": "Input discovery only; no new packages, compositor build, signing or publication"}
        result["podman_version"] = subprocess.check_output(["podman", "--version"], text=True).strip()
        (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    finally:
        final = {name: (cgroup / name).read_text().strip() for name in (*names, "memory.peak", "memory.events", "cpu.stat")}
        (evidence / "cgroup-final.json").write_text(json.dumps(final, indent=2) + "\n")
        assert all(final[name] == value for name, value in limits.items())


if __name__ == "__main__":
    main()
