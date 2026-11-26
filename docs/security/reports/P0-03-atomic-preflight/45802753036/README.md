# Protected-kernel preflight: retained identity/defaults validation failure

[Run 45802753036](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45802753036)
at `027291a` passed real ZIP/OCI intake, exact loaded image identity and all
102 installed files/2,184 packages. The never-started source container successfully
provided the protected kernel files without running code: before/after state is
created, stopped and PID 0. The initramfs remains mode 0600/root-owned, the kernel
mode 0755/root-owned, and the private copies were removed. The unprivileged probe
received only their bound metadata. All three containers and the private loaded
image were removed and verified absent. The original 41 evidence files are retained.

The native observation completed, but the controller rejected two incorrect
expectations: the actual secureblue image reports ID=secureblue, ID_LIKE=fedora,
VERSION_ID=45, and no default root filesystem is configured. Those observations
match the selected secureblue base and its supplied installer configuration.
The original result remains failed. The correction requires the exact pinned
secureblue variant/lineage and reports that an explicit installer filesystem
argument is required. Unknown filesystems are still refused. No image file,
trust policy, pin, package or protection setting changes.

The actual observation retains bootc 1.17.1, secureblue kernel
7.3.4-300.secureblue.1.fc45.x86_64, enforcing SELinux configuration, exact installed
trust bytes, an OSTree prepare-root configuration with composefs enabled and
read-only sysroot, and available bootloader/filesystem/QEMU tools. These are
installed inputs, not booted enforcement or completed installation.
The inspection container peaked at 35,446,784 bytes without limit events;
the 4 GiB controller peaked at 4,294,971,392 bytes with 31,657 memory-max events.
All recorded stages have zero OOM/kill/group-kill and zero swap.

Two meaningful schema regressions failed before correction and now pass.
All 219 image tests pass under local 128 MiB/10%-CPU/zero-swap caps, peaking at
35,832 KiB and 0.75 CPU seconds. The retained native observation also passes the
corrected offline validator, which explicitly returns filesystem_argument_required.
That re-evaluation does not relabel the original hosted run as successful; a new
hosted result remains required. No local native/image/VM/GPU work ran.
