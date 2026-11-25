# Image signature policy

`signing.py` prepares the desktop's containers/image policy after the owner has
selected the release repositories and ThirdKey public key. It does not create
keys, sign/publish an image, install policy on the host or perform a rebase.
`release-trust.json` deliberately has no release repository or public key yet.

The source interface follows containers/image at
[`df7e80d2d19872b61f352a8a182ec934dc0c2346`](https://github.com/containers/image/tree/df7e80d2d19872b61f352a8a182ec934dc0c2346),
specifically its [signature-policy](https://github.com/containers/image/blob/df7e80d2d19872b61f352a8a182ec934dc0c2346/docs/containers-policy.json.5.md)
and [signature-attachment configuration](https://github.com/containers/image/blob/df7e80d2d19872b61f352a8a182ec934dc0c2346/docs/containers-registries.d.5.md).

## Inputs and preparation

1. Commit the reviewed ThirdKey **public** PEM under `image/keys`. Put its relative
   path and SHA-256 in `release-trust.json`, and map the `generic`/`nvidia` variants
   to their fully qualified destination repositories. Keep private signing keys
   in the chosen KMS/hardware/runner secret store. The selected base variants and
   their independently authenticated public keys belong in `base-images.json`.
2. Run `python3 image/signing.py --output .cache/image-trust-stage`. The output
   directory must be new. Unconfigured trust, changed keys, paths escaping the
   repository's key directory, malformed scopes, variant mismatch or reuse of a
   base repository as the release destination are refused before output is written.
3. The staged `policy.json` rejects all unspecified transports and scopes. Release
   repositories require the chosen key and an exact signed repository identity;
   base rollback scopes additionally require the selected digest. Keys are embedded
   as public `keyData`. The accompanying `registries.d/symbiont.yaml` enables
   signature attachments for these scopes. Its JSON content is valid YAML.
4. Integrate those staged files into `/etc/containers` **in the image build** once
   its base is selected. Inspect the base's existing `registries.d` for duplicate
   scopes; do not silently combine conflicting definitions. No insecure local,
   archive or registry exception is generated. Other trusted fixture/app image
   sources need their own reviewed pins and signature rules.

The script checks key hashes and excludes private-key text. It does not validate
the key's ASN.1, verify a publisher's signature or prove the base trusted the
correct identity. Those checks use the actual pinned cosign/containers tooling
on the isolated builder and the final image. Test fixtures intentionally contain
non-cryptographic key text and cannot satisfy that acceptance.

## Rebase and release gates

After cryptographic verification of an exact output digest, use:

```sh
python3 image/signing.py --rebase-command "$VERIFIED_IMAGE_REFERENCE_WITH_DIGEST"
```

This prints an `rpm-ostree rebase` command using the signed transport. It never
executes it. Tags, unknown repositories and unselected base digests are refused.
Cosign's repository identity does not bind mutable tags; the explicit digest
remains essential even with a valid repository signature. An operator can still
invoke other administrative commands, so this helper is not a new privilege
boundary or a substitute for enforcing the image's system policy.

Before release, retain real tests against the built image: valid ThirdKey
signature accepted; unsigned, wrong-key, wrong-repository and altered-manifest
images refused; selected base rollback succeeds and boots. Bind these results to
the OS digest, exact tooling and policy hash. Publish a matching SBOM and signed
SLSA provenance, then verify the subjects before promoting a release. The unit
tests here exercise policy generation and tampering cases, not those VM gates.
