"""Refuse an undersized hosted builder before starting the compiler."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("runtime_workspace", Path(__file__).parents[1] / "container/upstream/check_workspace.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class HostedCapacity(unittest.TestCase):
    def test_reserve_host_memory_outside_build_cgroup(self):
        result = runtime.require_host_capacity("MemTotal: 16384000 kB\nMemAvailable: 14000000 kB\n")
        self.assertGreater(result["MemAvailable"], 10 * 1024**3)

    def test_refuse_small_or_busy_host_and_missing_measurements(self):
        for meminfo in ("MemTotal: 8000000 kB\nMemAvailable: 7000000 kB\n",
                        "MemTotal: 16384000 kB\nMemAvailable: 9000000 kB\n",
                        "MemTotal: 16384000 kB\n", "MemTotal: 1 MB\nMemAvailable: 1 MB\n"):
            with self.subTest(meminfo=meminfo), self.assertRaises(ValueError):
                runtime.require_host_capacity(meminfo)


if __name__ == "__main__":
    unittest.main()
