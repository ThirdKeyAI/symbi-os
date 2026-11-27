"""Move the complete derived-image build process tree under its lower limits."""
import os
from pathlib import Path
import sys


def main():
    if os.geteuid() != 0 or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Hosted container-runtime image build only")
    current = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    if current.name != "supervisor" or not current.parent.name.startswith("symbi-container-image-build-"):
        raise ValueError("Unexpected runtime-image build parent")
    target = current.parent / "image-build"
    expected = {"memory.max": "2147483648", "memory.swap.max": "0",
                "cpu.max": "100000 100000", "pids.max": "128"}
    if any((target / name).read_text().strip() != value for name, value in expected.items()):
        raise ValueError("Runtime-image build limits changed")
    (target / "supervisor/cgroup.procs").write_text(str(os.getpid()))
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
