# bootc source selection for later Atomic installation

The retained image inventory selects `bootc-1.17.1-1.fc45`, not the current
Fedora f45 branch's 1.17.5. Public Koji build **3116347** identifies packaging
commit `c63d3bb9ae5451d1339e673dd13b6d71850287e0`. The exact spec/checksum views
select upstream 1.17.1 source and vendor archives, with no explicit Patch entries;
preparation adjusts Cargo vendor configuration. This is a public source mapping,
not proof of installed binary equivalence or absence of vulnerabilities. Source
archives/SRPMs and the binary were not downloaded or executed for this check.

The original public Koji XML and decoded build record are retained here. Hashes
and immutable URLs for the small packaging text are in `packaging-review.json`.
Upstream v1.17.1 resolves to `d01e723ae9480fa53aa9db09a7eff0439548e9f6`;
its inspected installation source separates the offline source transfer from the
future-update trust reference. Later installation must require the installed
signature policy, preserve enforcing SELinux and target only a new private disk
file on a disposable hosted runner. No installer has been executed by this review.

The source reads used at most 25,428 KiB locally under the 128 MiB/10%-CPU/
zero-swap cap. No product dependency pin, source, installed policy or grant changes.
