# Fedora runtime qualification

These drivers are preparation for P0-04/P0-05. Offline tests of report validation
are not a qualification of Symbiont, Fedora or any sandbox.

## Landlock procedure

1. P0-03 must produce an authenticated Fedora OSTree/bootc image and an
   authenticated runtime build from `upstream/symbiont.toml`'s full revision.
   Use an isolated clean source checkout at that revision. The public v3.0.0
   binary was built from `6e93a5f4a88b1a8d70a31df214c6ddf8993d6f0e`, not the plan's
   `deddb9e997244d2289c217ad76b8fde0e9b0339b`; its version string is insufficient.
   Do not reuse the large, older local debug binary as evidence.
2. Provision one disposable QEMU/KVM guest: **one vCPU, 2 GiB RAM, no additional
   swap, no host filesystem shares**. Keep its disk on `/vmstore`, not tmpfs.
   Disconnect external networking after verified artifacts are staged. A localhost
   control connection may remain; the upstream providers are synthetic. Do not
   run an image build or another guest alongside it on this workstation.
3. Boot the exact generic image digest with enforcing containers signature
   policy and SELinux. The driver requires the selected secureblue Fedora 45
   identity (`ID=secureblue`, `ID_LIKE=fedora`, and the exact generic
   variant/image IDs); an arbitrary derivative that merely advertises Fedora
   lineage is rejected. Provision a separate non-root runtime/test user with a systemd user
   manager and cgroup v2 delegation. Do not relax user-namespace, SELinux, seccomp
   or host security settings to make a test pass. A default-policy refusal is a
   failure to qualify this image and must be retained separately.
4. `python3 image/qualification/landlock.py --check-host` performs only the guest
   prerequisite check. It always leaves `qualified: false`. `bootc status --json`
   must also be readable by the collector; resolve privileges in the isolated
   runner's setup, never with desktop passwordless sudo or by running the runtime
   as root. The current collector accepts OSTree; composefs needs separate digest
   semantics qualification before support is added.
5. Run the driver below using the authenticated binary digest and expected ABI
   for that guest. The output directory must not exist and must live on guest
   disk outside the source checkout and `/tmp`.

```sh
python3 image/qualification/landlock.py \
  --source "$PINNED_SOURCE_CHECKOUT" \
  --binary /usr/bin/symbi \
  --expected-binary-sha256 "$VERIFIED_BINARY_SHA256" \
  --image-ref "$VERIFIED_IMAGE_REFERENCE_WITH_DIGEST" \
  --expected-abi "$GUEST_LANDLOCK_ABI" \
  --output "$NEW_PRIVATE_EVIDENCE_DIRECTORY"
```

The wrapper calls the pinned upstream platform diagnostic with `--expect usable`,
then its full Linux release driver with `--require-clean`. It requires all six
shipping cases and all three independent evidence suites, including verification
and integrity checks. A successful namespace-refusal diagnostic, shortened suite,
wrong source/binary, changed policy, failed cleanup or missing result fails.
No driver has a host fallback. A timeout fails and requires disposal of the guest;
it does not certify cleanup of separately supervised workers.

The same binary/source/deployment bindings are checked afterward. The output's
`summary.json` records an exact allowlist of public report hashes. **Never archive
the whole output tree:** `release/private-actions/` contains test signing keys.
Keep complete evidence private for investigation. Only the reviewed allowlisted
reports/logs and bootc metadata may be copied to the retained report directory.

The bootc policy field records the selected verification mode; it does not itself
prove a signature was checked or that the policy is correctly scoped. Link
P0-03's actual signature verification, unsigned-rebase rejection and rollback
tests before making a release claim. A passing Landlock report is limited to the
listed routes, exact binary, image, architecture and policy. It is not a proof of
every OS invariant, real Claude compatibility, or resistance after host compromise.

## Upstream references

- [Pinned platform diagnostic](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/scripts/test-landlock-platform.py)
- [Pinned full release driver](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/scripts/test-landlock-release.py)
- [Linux qualification scope](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/docs/linux-containment-qualification.md)
- [bootc status schema](https://github.com/bootc-dev/bootc/blob/main/docs/src/host-v1.schema.json)
