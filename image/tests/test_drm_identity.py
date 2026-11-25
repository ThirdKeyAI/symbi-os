"""Read the DRM device's own identity, independently of its PCI transport."""
import ctypes
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location('cloud_guest_probe', Path(__file__).parents[1] / 'hyprland/graphics/cloud_probe.py')
guest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guest)


class DrmIdentity(unittest.TestCase):
    def test_uses_the_version_ioctl_name_and_bounds_the_reply(self):
        def virtio_ioctl(fd, command, version, mutate):
            self.assertEqual(command, 0xc0406400)
            self.assertTrue(mutate)
            self.assertEqual(ctypes.sizeof(version), 64)
            ctypes.memmove(version.name, b'virtio_gpu', 10)
            version.name_len = 10
            return 0
        self.assertEqual(guest.drm_driver(7, virtio_ioctl), 'virtio_gpu')
        for size in [0, 128, 129]:
            def oversized(fd, command, version, mutate):
                version.name_len = size
                return 0
            with self.subTest(size=size), self.assertRaises(ValueError):
                guest.drm_driver(7, oversized)

    def test_a_regular_file_is_not_a_drm_device(self):
        with tempfile.TemporaryFile() as file, self.assertRaises(OSError):
            guest.drm_driver(file.fileno())


if __name__ == '__main__':
    unittest.main()
