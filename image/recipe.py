#!/usr/bin/env python3
"""Render BlueBuild v2 JSON (valid YAML), refusing absent or mutable base pins.

This prepares a recipe; the builder must independently verify the base signature
before use. It does not claim that a hash or a readable key is a valid signature.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
IMAGE = re.compile(r"([a-z0-9.-]+(?::[0-9]+)?)/([a-z0-9_./-]+)@(sha256:[a-f0-9]{64})")


def render(config, variant, root=ROOT):
    if config.get("schema") != 1:
        raise ValueError("unsupported image pin schema")
    if variant not in ("generic", "nvidia"):
        raise ValueError("unknown image variant")
    pin = config.get("variants", {}).get(variant)
    if not pin:
        raise ValueError("base selection is pending; see OQ-07")
    match = IMAGE.fullmatch(pin.get("image", ""))
    if not match or match[3] == "sha256:" + "0" * 64:
        raise ValueError("base must be an untagged OCI reference with a nonzero SHA-256 digest")
    key = Path(pin.get("public_key", ""))
    if key.is_absolute() or ".." in key.parts or key.parts[:2] != ("image", "keys"):
        raise ValueError("base public key must be a committed path under image/keys")
    resolved = (root / key).resolve(strict=True)
    if not resolved.is_relative_to(root.resolve() / "image/keys"):
        raise ValueError("base public key escapes image/keys")
    if hashlib.sha256(resolved.read_bytes()).hexdigest() != pin.get("public_key_sha256"):
        raise ValueError("base public key hash mismatch")
    return {
        "version": 2,
        "base": {
            "image": {"registry": match[1], "repository": match[2], "digest": match[3]},
            "public-key": key.as_posix(),
        },
        "metadata": {
            "name": "symbiont-os" + ("-nvidia" if variant == "nvidia" else ""),
            "description": "Symbiont Fedora Atomic desktop",
            "labels": {"org.opencontainers.image.licenses": "Apache-2.0"},
        },
        "spec": {"platforms": ["linux/amd64"], "tool-versions": {"bluebuild": "none"}},
        "modules": [{"type": "containerfile", "snippets": [
            "COPY image/overlay/ /",
            "COPY image/atomic/update_guest.py /usr/libexec/symbi-atomic-update-controller.py",
            "COPY image/atomic/selinux/ /tmp/symbi-atomic-update-policy/",
            "COPY image/vendor/ombuntu/LICENSE /usr/share/licenses/symbiont-os/Ombuntu-MIT",
            "COPY image/vendor/omarchy/LICENSE /usr/share/licenses/symbiont-os/Omarchy-MIT",
            "COPY LICENSE /usr/share/licenses/symbiont-os/Apache-2.0",
            "COPY image/harden-image.sh /tmp/symbi-harden-image.sh",
            "RUN bash /tmp/symbi-harden-image.sh && rm /tmp/symbi-harden-image.sh",
        ]}],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=["generic", "nvidia"], required=True)
    parser.add_argument("--pins", type=Path, default=ROOT / "image/base-images.json")
    args = parser.parse_args()
    try:
        result = render(json.loads(args.pins.read_text()), args.variant)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Image recipe refused: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
