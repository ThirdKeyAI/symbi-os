#!/usr/bin/env python3
"""Authenticate the pinned public Cosign binary before hosted test execution."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def verify_hash(path, digest, size=None):
    if not path.is_file() or path.is_symlink():
        raise ValueError("Expected a regular downloaded asset")
    if size is not None and path.stat().st_size != size:
        raise ValueError("Asset size mismatch")
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != digest:
        raise ValueError("Asset hash mismatch")
    return actual


def verify_signature(binary, bundle_path, public_key, key_digest, signature_path):
    """Verify the release KMS signature without executing the downloaded binary."""
    verify_hash(public_key, key_digest)
    key = public_key.read_bytes()
    if not key.startswith(b"-----BEGIN PUBLIC KEY-----\n") or b"PRIVATE KEY" in key:
        raise ValueError("Expected a public verification key")
    bundle = json.loads(bundle_path.read_text())
    signature = bundle["messageSignature"]
    if signature["messageDigest"]["algorithm"] != "SHA2_256":
        raise ValueError("Unsupported release digest")
    with binary.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").digest()
    if base64.b64decode(signature["messageDigest"]["digest"], validate=True) != digest:
        raise ValueError("Signature bundle digest mismatch")
    signature_path.write_bytes(base64.b64decode(signature["signature"], validate=True))
    result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public_key),
                             "-signature", str(signature_path), str(binary)],
                            capture_output=True, text=True, check=False, timeout=30)
    if result.returncode != 0 or result.stdout.strip() != "Verified OK":
        raise ValueError("Release signature verification failed")
    return result.stdout


def bootstrap(root, evidence):
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ValueError("Cosign bootstrap requires a hosted runner")
    pins_path = root / "image/toolchain/cosign.json"
    pins = json.loads(pins_path.read_text())
    if pins["schema"] != 1:
        raise ValueError("Unsupported Cosign pin format")
    public_key = (root / pins["public_key_path"]).resolve(strict=True)
    if not public_key.is_relative_to(root / "image/toolchain/keys"):
        raise ValueError("Verification key outside toolchain keys")
    verify_hash(public_key, pins["public_key_sha256"])
    directory = root / ".cache/cosign-test-tool"
    directory.mkdir(mode=0o700)
    retained = evidence / "cosign-bootstrap"
    retained.mkdir()
    shutil.copyfile(pins_path, retained / "pins.json")
    shutil.copyfile(public_key, retained / "release-cosign.pub")
    names = {asset["name"] for asset in pins["assets"]}
    if len(pins["assets"]) != 2 or names != {"cosign-linux-amd64", "cosign-linux-amd64-kms.sigstore.json"}:
        raise ValueError("Unexpected bootstrap assets")
    for asset in pins["assets"]:
        expected_url = f"https://github.com/sigstore/cosign/releases/download/{pins['version']}/{asset['name']}"
        if asset["url"] != expected_url:
            raise ValueError("Unexpected release asset URL")
        destination = directory / asset["name"]
        subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location",
                        "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
                        "--connect-timeout", "20", "--max-time", "300", "--limit-rate", "5M",
                        "--max-filesize", str(asset["bytes"]), "--output", str(destination), asset["url"]],
                       check=True, timeout=310)
        verify_hash(destination, asset["sha256"], asset["bytes"])
    binary = directory / "cosign-linux-amd64"
    bundle = directory / "cosign-linux-amd64-kms.sigstore.json"
    verified = verify_signature(binary, bundle, public_key, pins["public_key_sha256"], retained / "release-kms.sig")
    shutil.copyfile(bundle, retained / bundle.name)
    (retained / "openssl-verification.txt").write_text(verified)
    # Only authenticated bytes become executable or enter the test PATH.
    installed = directory / "cosign"
    binary.rename(installed)
    installed.chmod(0o755)
    version = subprocess.check_output([str(installed), "version", "--json"], text=True, timeout=30)
    build = json.loads(version)
    if build["gitVersion"] != pins["version"] or build["gitCommit"] != pins["source_revision"]:
        raise ValueError("Unexpected Cosign build identity")
    (retained / "version.json").write_text(version)
    binary_pin = next(asset for asset in pins["assets"] if asset["name"] == "cosign-linux-amd64")
    record = {"binary_sha256": binary_pin["sha256"], "source_revision": pins["source_revision"],
              "public_key_sha256": pins["public_key_sha256"], "signature_verified_before_execution": True,
              "authentication": "Pinned publisher public key and OpenSSL SHA-256 verification of release KMS signature",
              "trust_origin": pins["public_key_source"],
              "scope": "Hosted BlueBuild tests only; no release credentials or publication"}
    (retained / "verification.json").write_text(json.dumps(record, indent=2) + "\n")
    return installed
