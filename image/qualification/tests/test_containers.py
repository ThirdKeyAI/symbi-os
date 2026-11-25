"""Offline configuration/inspection checks, not container execution evidence."""
import copy
import importlib.util
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "image/qualification"))


class ContainerEvidence(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("containers", ROOT / "image/qualification/containers.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.info = {"CgroupVersion": "2", "CgroupDriver": "systemd", "LiveRestoreEnabled": False,
                     "Runtimes": {"runc": {}, "runsc": {"path": "/usr/bin/runsc"}},
                     "DefaultRuntime": "runc", "SecurityOptions": ["name=selinux", "name=seccomp,profile=builtin"]}
        self.container = {"Image": "sha256:" + "a" * 64, "Config": {"User": "65534:65534"},
                          "HostConfig": {"Runtime": "runsc", "NetworkMode": "none", "Privileged": False,
                                         "ReadonlyRootfs": True, "CapDrop": ["ALL"], "CapAdd": [],
                                         "SecurityOpt": ["no-new-privileges=true"], "Memory": 268435456,
                                         "MemorySwap": 268435456, "NanoCpus": 500000000, "PidsLimit": 32,
                                         "IpcMode": "private", "CgroupnsMode": "private",
                                         "Binds": [], "LogConfig": {"Type": "none"}}, "Mounts": []}

    def test_complete_synthetic_inspection_passes(self):
        self.module.validate_daemon(self.info)
        self.module.validate_container(self.container, "runsc", self.container["Image"])

    def test_daemon_cannot_drop_required_controls(self):
        for field, value in [("CgroupVersion", "1"), ("LiveRestoreEnabled", True),
                             ("SecurityOptions", []), ("Runtimes", {"runc": {}}),
                             ("DefaultRuntime", "runsc")]:
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.info)
                candidate[field] = value
                with self.assertRaises(ValueError):
                    self.module.validate_daemon(candidate)

    def test_container_cannot_weaken_inspected_boundary(self):
        for field, value in [("Runtime", "runc"), ("NetworkMode", "bridge"), ("Privileged", True),
                             ("ReadonlyRootfs", False), ("Memory", 0), ("MemorySwap", -1),
                             ("NanoCpus", 0), ("PidsLimit", 0), ("CapAdd", ["SYS_ADMIN"]),
                             ("SecurityOpt", []), ("IpcMode", "host"), ("CgroupnsMode", "host")]:
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.container)
                candidate["HostConfig"][field] = value
                with self.assertRaises(ValueError):
                    self.module.validate_container(candidate, "runsc", self.container["Image"])

    def test_wrong_image_root_user_and_host_mount_fail(self):
        for field, value in [("Image", "sha256:" + "b" * 64), ("Config", {"User": "0:0"}),
                             ("Mounts", [{"Type": "bind", "Source": "/", "Destination": "/host"}])]:
            candidate = copy.deepcopy(self.container)
            candidate[field] = value
            with self.assertRaises(ValueError):
                self.module.validate_container(candidate, "runsc", self.container["Image"])

    def test_selected_daemon_configuration_is_deterministic(self):
        import json
        config = json.loads((ROOT / "image/container/daemon.json").read_text())
        self.assertIs(config["live-restore"], False)
        self.assertIs(config["selinux-enabled"], True)
        self.assertIs(config["no-new-privileges"], True)
        self.assertEqual(config["runtimes"]["runsc"]["path"], "/usr/bin/runsc")
        self.assertNotIn("hosts", config)

    def test_retained_daemon_metadata_excludes_proxy_credentials(self):
        self.info["HTTPProxy"] = "http://user:synthetic-secret@example.invalid"
        retained = self.module.retained_daemon_info(self.info)
        self.assertNotIn("HTTPProxy", retained)
        self.assertEqual(retained["CgroupVersion"], "2")


if __name__ == "__main__":
    unittest.main()
