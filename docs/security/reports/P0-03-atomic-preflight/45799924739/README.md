# Initial real Atomic image preflight — retained failure

[Run 45799924739](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45799924739)
at `4c6d3c5` passed exact artifact metadata, original ZIP/manifest and inner OCI
size/hash verification for the generic image built at `23a6c72`. Private Podman loading
selected the exact image config ID. The existing unprivileged verifier passed
all 102 installed files and all 2,184 package identities. The next probe failed
while hashing the protected `initramfs.img`: UID 10001 correctly could not read it.
This is a diagnostic-harness failure, not a passed boot-input or OS qualification.
The original 27 small files are retained byte-for-byte with their hashes.

Both actual containers were removed and verified absent, and the private loaded
image was removed. Preparation peaked at 27,095,040 bytes with no memory-limit
events. The 4 GiB parent peaked at 4,294,971,392 bytes with 31,844 memory-max events;
all stages recorded zero OOM/kill/group-kill and zero swap. The original systemd
post-exit memory output is retained alongside the cgroup checkpoints, not silently
substituted for them. No local image, native build, VM or GPU work ran.

The correction preserves the installed file permissions. The root controller uses
Podman to copy only the kernel and initramfs from a never-started, read-only
container into private 0700 CI storage, hashes them without executing them, then
removes those private copies. Only the bound public metadata reaches the two
UID 10001 inspections. Before/after container state must remain created, stopped
and PID 0. No container code executes as root; the installed image is not changed.
A valid empty backend configuration marker is accepted only where explicitly
allowed, while kernel/trust files must remain nonempty. The corrected hosted
result is pending; the original failure remains a failure.
