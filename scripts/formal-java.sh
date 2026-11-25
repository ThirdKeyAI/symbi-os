#!/usr/bin/env bash
set -euo pipefail
# The formal-proofs action defaults to one TLC worker per visible CPU. Make
# both it and local skill runs see one CPU, with a 256 MiB heap and finite time.
# Java's heap limit excludes native memory; this is not a total process limit.
exec timeout --signal=TERM --kill-after=5s 180s nice -n 10 \
  env -u JAVA_TOOL_OPTIONS -u JDK_JAVA_OPTIONS -u _JAVA_OPTIONS \
  java -Xms32m -Xmx256m -XX:ActiveProcessorCount=1 -XX:ParallelGCThreads=1 \
  -XX:ConcGCThreads=1 "$@"
