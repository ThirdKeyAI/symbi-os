# Portal native-input validation

Eight input/report checks were written first and failed on the missing module,
then passed after implementation. An additional encoding regression reproduced
UTF-16 declaration and Latin-1 report acceptance, then passed after requiring
UTF-8 XML without NULs or declarations. All nine native-input tests are included
in the final 170-test offline image suite.

The final run passed actual retained-prefix and new RPM-lock binding checks,
AST/YAML/shell syntax, ShellCheck, vendor hashes, four local execution refusals
and all retained cve.bz response hashes/attributions. The earlier ShellCheck
failure is retained; the redirect was corrected before the passing run.
Final peak RSS was 35,004 KiB, user+system CPU 0.70 seconds, elapsed 8.90 seconds,
with zero swap under 128 MiB / 10% CPU / 32-task limits. Native/compiler/formal
execution remains hosted. This is not an OS qualification report.

The portal discovery reconciliation log records all real signatures, controls,
package-set changes and resource counters. The raw resolver log line 4 contains
upstream trailing spaces and is intentionally preserved exactly as authenticated.
The original artifact and per-file hashes are retained; authored files pass
whitespace validation. The cve.bz logs contain public query results and provenance.
