# Generic image with release-policy packaging

Hosted [run 45758278776](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45758278776)
at `1e171d1820b473141df4c300dd657056a171b98a` succeeded.
[Workspace/formal checks](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45758285175)
also passed. This is development packaging evidence, not OS qualification.

The original 146 evidence files (366,688 bytes) are retained unchanged.
`retention.json` binds their bytes to the 113,704-byte GitHub evidence artifact.
The 4.03 GB image archive stays on GitHub; its API metadata is recorded and
its payload descriptor is present in the original small `image-manifest.json`.
A hosted consumer must verify the large archive before using it.

Independent reconciliation rechecked all five Fedora RPM signatures and
identities, all 2,178 original packages, 2,183 final packages, 40 original
crypto configuration slots, 88 installed files/links, six dynamic loaders,
three CLI/provider controls, and three Lua parser controls. Both installed
trust-file hashes match fresh rendering of the reviewed public inputs.
All 13 temporary containers were removed and verified absent. The actual
`bootc container lint` result remains 13 passed, one skipped, and one warning
for the base kernel symvers file in `/boot`. No OOM or OOM kill occurred;
memory-pressure events remain visible in the original counters.

The local reconciliation used a 128 MiB / 10% CPU / zero-swap scope, reached
21,396 KiB RSS, and used 0.03 CPU seconds. Its code, output and limits are
retained. It reconciles producer evidence without executing the OCI image
on the workstation or independently redoing the hosted installed-file probe.

No actual boot, graphics interaction, TLS-policy equivalence, Fedora sandbox,
escape suite, signed update/rejection or rollback result is claimed here.
