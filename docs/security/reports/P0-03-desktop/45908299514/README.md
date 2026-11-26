# NVIDIA font-bearing development image

GitHub Actions run [45908299514](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45908299514)
built and inspected the NVIDIA development image at source commit
`d436c6ee8a7ed159afa59db9bd82377ae8ea2389`. The build retained a
5,165,613,484-byte hosted artifact. Its OCI payload is 5,165,612,454 bytes
with SHA-256
`732221d7ca5792a15c80755f98060701cb53040bfb8f9172d0054add5286a9b6`.
The large artifact was not downloaded to the workstation.

The 155,226-byte evidence ZIP was downloaded and matched GitHub's artifact
digest `02515604728e4452d2c2646d7756c27a600018d9898cd186f8ee9ca5d4bdb16d`.
The independent recheck authenticated the exact secureblue NVIDIA base,
rechecked six signed RPMs, preserved all 2,324 base package identities and all
40 crypto-policy entries, checked 212 installed files and 98 font faces, and
reconciled all 196 bounded evidence files. Every temporary container was removed;
all observed cgroups used zero swap and recorded no OOM or kill event.

This is image assembly evidence. It does not qualify a physical NVIDIA GPU,
booted desktop, containment route, release signature, update, or rollback.
Those flags remain false in the retained records.
