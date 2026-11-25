#!/usr/bin/env python3
"""Prepare enforcing containers/image trust configuration, never sign or rebase.

Only operator-reviewed repositories and public-key hashes are accepted. Actual
key parsing, signature verification and negative VM tests remain release gates.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shlex

ROOT = Path(__file__).resolve().parents[1]
PART = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
REPOSITORY = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?/" + PART + r"(?:/" + PART + r")+")
VARIANTS = {"generic", "nvidia"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def repository(value):
    require(isinstance(value, str) and REPOSITORY.fullmatch(value), "fully qualified canonical repository required")
    return value


def image_reference(value):
    require(isinstance(value, str) and value.count("@") == 1, "image digest required; tags are refused")
    repo, image_digest = value.split("@")
    repository(repo)
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest) and image_digest != "sha256:" + "0" * 64,
            "nonzero SHA-256 image digest required")
    return repo


def public_key(pin, root):
    raw = pin.get("public_key")
    require(isinstance(raw, str), "public key path is not configured")
    path = Path(raw)
    require(not path.is_absolute() and ".." not in path.parts and path.parts[:2] == ("image", "keys"),
            "public key must be under image/keys")
    root = root.resolve()
    resolved = (root / path).resolve(strict=True)
    require(resolved.is_relative_to(root / "image/keys"), "public key escapes the repository trust directory")
    data = resolved.read_bytes()
    require(hashlib.sha256(data).hexdigest() == pin.get("public_key_sha256"), "public key hash mismatch")
    require(data.startswith(b"-----BEGIN PUBLIC KEY-----\n") and
            data.rstrip().endswith(b"-----END PUBLIC KEY-----") and b"PRIVATE" not in data,
            "only public key PEM material may be embedded")
    # This is a shape/leakage check, not ASN.1 or signature validation.
    return data


def rule(key, repo):
    return {"type": "sigstoreSigned", "keyData": base64.b64encode(key).decode("ascii"),
            "signedIdentity": {"type": "exactRepository", "dockerRepository": repo}}


def render(release, bases, root=ROOT):
    require(release.get("schema") == 1 and bases.get("schema") == 1, "unsupported trust configuration schema")
    outputs = release.get("repositories") or {}
    require(outputs, "release trust setup is pending; see OQ-03")
    variants = bases.get("variants") or {}
    require(set(outputs) == set(variants) and set(outputs) <= VARIANTS, "release/base variants must match")
    release_key = public_key(release, root)
    scopes = {}
    for variant, destination in sorted(outputs.items()):
        repo = repository(destination)
        pin = variants[variant]
        base_ref = pin.get("image")
        base_repo = image_reference(base_ref)
        require(base_repo not in outputs.values(), "release repository must not replace a base repository trust root")
        scopes[repo] = [rule(release_key, repo)]
        base_rule = [rule(public_key(pin, root), base_repo)]
        require(base_ref not in scopes or scopes[base_ref] == base_rule, "conflicting keys for one base image")
        # Base rollback is allowed only at the reviewed digest, not a moving tag.
        scopes[base_ref] = base_rule
    return {
        "policy": {"default": [{"type": "reject"}], "transports": {"docker": scopes}},
        "registries": {"docker": {scope: {"use-sigstore-attachments": True} for scope in scopes}},
    }


def rebase_command(bundle, ref):
    repo = image_reference(ref)
    scopes = bundle["policy"]["transports"]["docker"]
    require(ref in scopes or repo in scopes, "image is outside the configured release/base scope")
    return ["rpm-ostree", "rebase", "ostree-image-signed:docker://" + ref]


def write_bundle(bundle, output):
    # A new destination prevents accidental replacement of host or previous
    # policy. JSON is also YAML; registries.d requires the .yaml extension.
    output.mkdir(mode=0o755, parents=True, exist_ok=False)
    (output / "registries.d").mkdir()
    (output / "policy.json").write_text(json.dumps(bundle["policy"], indent=2) + "\n")
    (output / "registries.d/symbiont.yaml").write_text(json.dumps(bundle["registries"], indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-trust", type=Path, default=ROOT / "image/release-trust.json")
    parser.add_argument("--base-pins", type=Path, default=ROOT / "image/base-images.json")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path, help="new staging directory; never the host policy directory")
    action.add_argument("--rebase-command", help="print a signed digest rebase command without executing it")
    args = parser.parse_args()
    try:
        bundle = render(json.loads(args.release_trust.read_text()), json.loads(args.base_pins.read_text()))
        if args.output:
            write_bundle(bundle, args.output)
        else:
            print(shlex.join(rebase_command(bundle, args.rebase_command)))
    except (ValueError, OSError) as error:
        parser.exit(1, f"Signature policy refused: {error}\n")


if __name__ == "__main__":
    main()
