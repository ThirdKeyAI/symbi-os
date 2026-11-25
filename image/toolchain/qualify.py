#!/usr/bin/env python3
"""Exercise the real BlueBuild CLI with validation enabled; never build an image.

Positive cases run first so an unrelated tool/network failure cannot count as a
successful negative test. Evidence distinguishes process failures and timeouts
from recipe rejection. This is tool compatibility, not OS qualification.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    if any(name.startswith("BB_") for name in os.environ):
        raise SystemExit("Refusing ambient BlueBuild configuration")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("This compilation/CLI acceptance route runs on hosted CI only")
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Refusing a local or self-hosted runner")

    module_spec = importlib.util.spec_from_file_location("image_recipe", root / "image/recipe.py")
    renderer = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(renderer)
    pins = json.loads((root / "image/base-images.json").read_text())
    with binary.open("rb") as stream:
        binary_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    result = {"schema": 1, "binary_sha256": binary_hash,
              "source_revision": os.environ["BLUEBUILD_REVISION"], "checks": [],
              "recipe_validation_passed": False, "containerfiles_generated": False,
              "os_qualified": False}

    def save():
        (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")

    def run(name, arguments, reject=False):
        command = [str(binary), *arguments]
        record = {"name": name, "command": command, "expected": "recipe rejection" if reject else "success"}
        log = evidence / (name + ".log")
        with log.open("wb") as output:
            try:
                env = dict(os.environ, DOCKER_HOST="unix:///dev/null", CONTAINER_HOST="unix:///dev/null")
                process = subprocess.run(command, cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT,
                                         timeout=180, check=False)
                record["exit_code"] = process.returncode
            except subprocess.TimeoutExpired:
                record["timeout"] = True
        text = log.read_text(errors="replace")
        if reject:
            record["passed"] = record.get("exit_code") == 1 and "failed to validate" in text
        else:
            record["passed"] = record.get("exit_code") == 0
        result["checks"].append(record)
        save()
        print(f"{name}: {'PASS' if record['passed'] else 'FAIL'}", flush=True)
        if not record["passed"]:
            print(text[-12000:], file=sys.stderr)
            raise SystemExit(1)

    run("version", ["--version"])
    recipes = {}
    for variant in ("generic", "nvidia"):
        value = renderer.render(pins, variant, root)
        path = evidence / (variant + ".json")
        path.write_text(json.dumps(value, indent=2) + "\n")
        recipes[variant] = (value, path)
        run(variant + "-validate", ["validate", "--all-errors", str(path)])

    # The OS accepts only this digest-pinned, explicitly keyed recipe profile.
    # These cases specify the required downstream validator contract up front.
    bad = []
    value = copy.deepcopy(recipes["generic"][0])
    value["base"]["image"].pop("digest")
    value["base"]["image"]["tag"] = "latest"
    bad.append(("tag-only-base", value))
    value = copy.deepcopy(recipes["generic"][0])
    value["base"].pop("public-key")
    bad.append(("missing-public-key", value))
    value = copy.deepcopy(recipes["generic"][0])
    value["version"] = 99
    bad.append(("unknown-version", value))
    value = copy.deepcopy(recipes["generic"][0])
    value["base"]["image"]["digest"] = "sha256:invalid"
    bad.append(("malformed-digest", value))
    value = copy.deepcopy(recipes["generic"][0])
    value["modules"][0]["snippets"] = "RUN unexpected"
    bad.append(("wrong-snippet-type", value))
    value = copy.deepcopy(recipes["generic"][0])
    value["unrecognized-field"] = True
    bad.append(("unknown-field", value))
    value = copy.deepcopy(recipes["generic"][0])
    value.pop("version")
    bad.append(("missing-version", value))
    value = copy.deepcopy(recipes["generic"][0])
    value["modules"] = [{"from-file": "https://example.invalid/modules.yml"}]
    bad.append(("external-module-include", value))
    value = copy.deepcopy(recipes["generic"][0])
    value["spec"]["tool-versions"]["bluebuild"] = "latest"
    bad.append(("moving-tool-image", value))
    value = copy.deepcopy(recipes["generic"][0])
    value["base"]["image"]["digest"] = "sha256:" + "0" * 64
    bad.append(("zero-digest", value))
    value = copy.deepcopy(recipes["generic"][0])
    value["base"]["public-key"] = "https://example.invalid/key.pub"
    bad.append(("remote-public-key", value))
    value = copy.deepcopy(recipes["generic"][0])
    value["base"]["public-key"] = "image/keys/../unreviewed.pub"
    bad.append(("escaping-public-key", value))
    for name, value in bad:
        path = evidence / (name + ".json")
        path.write_text(json.dumps(value, indent=2) + "\n")
        run(name, ["validate", "--all-errors", str(path)], reject=True)
    result["recipe_validation_passed"] = True
    save()

    for variant, (_, path) in recipes.items():
        output = evidence / (variant + ".Containerfile")
        run(variant + "-generate", ["generate", str(path), "--output", str(output),
            "--registry", "ghcr.io", "--registry-namespace", "thirdkeyai",
            "--inspect-driver", "oci-client", "--build-driver", "docker", "--run-driver", "docker", "--platform", "linux/amd64"])
        if not output.is_file() or output.stat().st_size == 0:
            raise SystemExit("CLI returned success without a Containerfile")
    result["containerfiles_generated"] = True
    save()
    print("CLI acceptance passed; generated image references still require review. No OS built or qualified.")


if __name__ == "__main__":
    main()
