# Atomic development boot 45869526684

GitHub Actions [run 45869526684](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45869526684)
at source `88c49ecb57fe8104c962c8a4e420bb87831dc1dd` installed and booted the
retained generic development image from source
`23a6c721092ad77c3af33c11cab230ecaaa54cff`. The accepted result is failed:
the zero-capability guest observer reached the complete RPM inventory after
confirming the booted system, but that command exceeded its generic 60-second
subprocess limit under single-threaded TCG. Package and payload comparison did
not complete, so neither boot, OS nor release qualification follows.

The retained evidence does establish the bounded facts below:

- The exact OCI image ID is
  `sha256:54519537609810dae056e0dd17696f123f8ca1900ab64c6af1af458c80c768a1`,
  with manifest
  `sha256:9b6e8fdd9f6f98631895ccdfaaed6ffd88febd3ea6238d543935a524b572faf3`.
- Offline fixture-key verification accepted the exact signed source and rejected
  unsigned, wrong-key, wrong-reference and altered-signature controls. The
  fixture private keys were removed. These controls do not use or qualify a
  ThirdKey release key.
- bootc completed installation to a newly created, guarded 24 GiB Btrfs disk.
  No existing host disk was an installation target.
- QEMU/TCG booted the installed kernel
  `7.3.4-300.secureblue.1.fc45.x86_64` and exited normally after 374.68 seconds.
- The nonce-bound guest report observed enforcing SELinux, read-only `/usr`,
  read-only Btrfs `/sysroot`, loopback as the only network interface, empty
  observer capability sets, `NoNewPrivs=1`, bootc 1.17.1 and the expected
  `containerPolicy` deployment reference.
- The failure is exactly the 60-second `/usr/bin/rpm -qa` timeout. The report
  keeps `probe_completed`, `os_qualified` and `release_qualified` false.
- The three temporary containers, loop devices, loaded image, private storage
  and private runroot were removed. Neither the raw disk nor qcow2 overlay is
  retained. Host swap was disabled, and all retained cgroup records report zero
  OOM and kill events.

The artifact metadata binds artifact `15142549147`, 76,130 bytes, with SHA-256
`820a903b8f72eb1c32ae58ba709ab98e721aea4e8299287da05aadc753418724`.
`artifact-files.json` binds all 87 original files and their 230,440 expanded
bytes. `reconcile.py` checks the archive, complete extracted-file inventory,
image and disk identities, native signature controls, guest observations,
failure boundary, resource records and cleanup, then writes
`independent-check.json`.

The fail-first regression is retained in `tests-before.log`. The correction
keeps the generic 60-second command limit, assigns only the complete RPM
inventory a bounded 180-second allowance, restores the observer to one full
guest CPU, and gives the unit a 420-second start deadline. The focused guest and
controller suites pass in `tests-after.log`. A new hosted run against the
current font-bearing generic image remains required.

The final serial repository gate is retained in `repository-check.log` and
`repository-check.time`. It passed 280 image tests, six Cedar policy tests,
Rust formatting, Clippy, workspace tests and documentation, cargo-deny,
cargo-vet and formal drift checks in 6.20 seconds at 70,188 KiB peak RSS, with
one Cargo job and zero swap.
