"""Reject replayed, incomplete or misleading development-guest evidence."""
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(__file__).parents[1] / 'hyprland/graphics/cloud_boot.py'
SPEC = importlib.util.spec_from_file_location('cloud_boot', SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class CloudBoot(unittest.TestCase):
    def report(self, graphics=True):
        return {'schema': 1, 'nonce': 'a'*32, 'probe_sha256': 'b'*64,
                'case': 'with-gpu' if graphics else 'without-gpu',
                'probe_completed': True, 'os_qualified': False,
                'os_release': {'ID': 'fedora', 'VERSION_ID': '45'},
                'kernel': '7.3.4-300.fc45.x86_64',
                'boot_id': '40757021-9e70-461b-a2ed-dc769ec293ac',
                'product': 'Symbi-Hosted-Graphics-Probe', 'nics': ['lo'],
                'modprobe': {'exit_code': 0, 'stdout': '', 'stderr': ''},
                'selinux': 'Enforcing',
                'render_nodes': ([{'path': '/dev/dri/renderD128', 'character_device': True,
                                  'driver': 'virtio_gpu', 'opened_read_write': True,
                                  'major': 226, 'minor': 128}] if graphics else [])}

    def test_real_positive_and_no_gpu_control_have_distinct_requirements(self):
        probe.validate_report(self.report(), 'a'*32, 'b'*64, 'with-gpu')
        probe.validate_report(self.report(False), 'a'*32, 'b'*64, 'without-gpu')
        for report, case in ((self.report(False), 'with-gpu'), (self.report(), 'without-gpu')):
            report['case'] = case
            with self.assertRaises(ValueError):
                probe.validate_report(report, 'a'*32, 'b'*64, case)

    def test_replay_wrong_source_wrong_platform_and_partial_boot_fail(self):
        for field, value in [('nonce', 'c'*32), ('probe_sha256', 'd'*64),
                             ('case', 'without-gpu'), ('probe_completed', False),
                             ('os_qualified', True), ('boot_id', ''),
                             ('kernel', ''), ('product', 'physical-host'),
                             ('nics', ['lo', 'eth0']), ('selinux', 'Permissive'),
                             ('os_release', {'ID': 'ubuntu', 'VERSION_ID': '24.04'}),
                             ('modprobe', {'exit_code': 1})]:
            report = self.report()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                probe.validate_report(report, 'a'*32, 'b'*64, 'with-gpu')

    def test_filename_alone_or_inaccessible_device_is_not_gpu_evidence(self):
        for field, value in [('character_device', False), ('opened_read_write', False),
                             ('driver', 'simpledrm'), ('major', 1), ('minor', 127),
                             ('path', '/tmp/renderD128')]:
            report = self.report()
            report['render_nodes'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                probe.validate_report(report, 'a'*32, 'b'*64, 'with-gpu')

    def test_streamed_payload_must_match_both_size_and_hash(self):
        data = b'candidate cloud image'
        pin = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'payload'
            probe.copy_verified(io.BytesIO(data), target, pin)
            self.assertEqual(target.read_bytes(), data)
            target.unlink()
            for changed in [data[:-1], data+b'x', b'X'+data[1:]]:
                with self.subTest(data=changed), self.assertRaises(ValueError):
                    probe.copy_verified(io.BytesIO(changed), target, pin)
                self.assertFalse(target.exists())

    def test_non_json_oversized_and_duplicate_keys_are_not_reports(self):
        for raw in [b'not json', b'[]', b'x'*65537,
                    b'{"probe_completed":false,"probe_completed":true}']:
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                probe.decode_report(raw)

    def test_local_invocation_is_refused_before_using_qemu(self):
        completed = subprocess.run([sys.executable, str(SOURCE)], text=True,
                                   capture_output=True, timeout=5)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn('disposable unprivileged Fedora container', completed.stderr)


if __name__ == '__main__':
    unittest.main()
