"""Acceptance boundaries for the fixed bootc status collector in the test VM."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


class AtomicStatus(unittest.TestCase):
    def guest(self):
        spec = importlib.util.spec_from_file_location('atomic_status_guest', ROOT/'image/atomic/guest.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def properties(self):
        return {'Result':'success', 'ExecMainCode':'1', 'ExecMainStatus':'0',
                'ActiveState':'active', 'SubState':'exited'}

    def test_status_reader_requires_completed_collector_and_private_regular_output(self):
        guest = self.guest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'status.json'
            path.write_text('{"kind":"BootcHost"}\n'); path.chmod(0o600)
            original = os.fstat
            def root_stat(fd):
                values = list(original(fd)); values[4] = 0
                return os.stat_result(values)
            with patch.object(guest.os, 'fstat', side_effect=root_stat):
                status, observation = guest.read_bootc_status(path, self.properties())
                self.assertEqual(status, {'kind':'BootcHost'})
                self.assertEqual(observation['service'], self.properties())
                self.assertEqual(observation['bytes'], path.stat().st_size)
                parent = Path(directory)
                parent.chmod(0o777)
                with self.assertRaises(ValueError): guest.read_bootc_status(path, self.properties())
                parent.chmod(0o700)
                linked_parent = parent/'alias'; linked_parent.symlink_to(parent, target_is_directory=True)
                with self.assertRaises(OSError): guest.read_bootc_status(linked_parent/'status.json', self.properties())
                linked_parent.unlink()
                for key, value in [('Result','exit-code'), ('ExecMainStatus','1'),
                                   ('ExecMainCode','2'), ('ActiveState','inactive'), ('SubState','dead')]:
                    changed = self.properties(); changed[key] = value
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        guest.read_bootc_status(path, changed)
                for mode in (0o644, 0o666):
                    path.chmod(mode)
                    with self.assertRaises(ValueError): guest.read_bootc_status(path, self.properties())
                path.chmod(0o600)
                os.link(path, Path(directory)/'second')
                with self.assertRaises(ValueError): guest.read_bootc_status(path, self.properties())
                (Path(directory)/'second').unlink()
                path.write_bytes(b'x'*(128*1024+1))
                with self.assertRaises(ValueError): guest.read_bootc_status(path, self.properties())
                path.unlink(); path.symlink_to('/dev/null')
                with self.assertRaises((ValueError, OSError)): guest.read_bootc_status(path, self.properties())
            if os.geteuid() != 0:
                path.unlink(); path.write_text('{}'); path.chmod(0o600)
                with self.assertRaises(ValueError): guest.read_bootc_status(path, self.properties())

    def test_collector_is_a_fixed_command_and_cannot_grant_capabilities_to_probe(self):
        def settings(name):
            return dict(line.split('=',1) for line in (ROOT/'image/atomic'/name).read_text().splitlines()
                        if '=' in line and not line.startswith('#'))
        collector = settings('s.service'); observer = settings('o.service')
        self.assertEqual(collector['ExecStart'], '/usr/bin/bootc status --json')
        self.assertNotIn('DynamicUser', collector)
        self.assertNotIn('User', collector)
        self.assertEqual(collector['CapabilityBoundingSet'], 'CAP_SYS_ADMIN')
        self.assertNotIn('CAP_SYS_PTRACE', collector['CapabilityBoundingSet'].split())
        self.assertEqual(collector['AmbientCapabilities'], '')
        self.assertEqual(collector['PrivateMounts'], 'yes')
        self.assertEqual(collector['PrivatePIDs'], 'yes')
        self.assertEqual(collector['NoNewPrivileges'], 'yes')
        self.assertNotIn('RuntimeDirectory', collector)
        self.assertEqual(collector['StandardOutput'], 'truncate:/run/symbi-atomic-status.json')
        self.assertEqual(collector['UMask'], '0077')
        self.assertEqual(collector['MemoryMax'], '256M')
        self.assertEqual(collector['MemorySwapMax'], '0')
        self.assertEqual(collector['CPUQuota'], '50%')
        self.assertEqual(collector['TasksMax'], '32')
        self.assertEqual(collector['TimeoutStartSec'], '180')
        self.assertEqual(collector['TimeoutStopSec'], '15')
        self.assertNotIn('ImportCredential', collector)
        self.assertEqual(observer['CapabilityBoundingSet'], '')
        self.assertEqual(observer['AmbientCapabilities'], '')
        self.assertEqual(observer['NoNewPrivileges'], 'yes')
        self.assertNotIn('Requires', observer)
        self.assertIn('s.service', observer['Wants'].split())
        self.assertIn('s.service', observer['After'].split())
        self.assertNotIn('OnFailure', collector)
        self.assertEqual(observer['OnFailure'], 'poweroff.target')
        self.assertEqual(observer['ExecStopPost'], '/usr/bin/systemctl --no-block poweroff')

    def test_full_inventory_has_a_dedicated_bounded_slow_guest_budget(self):
        settings = dict(line.split('=', 1) for line in (ROOT/'image/atomic/o.service').read_text().splitlines()
                        if '=' in line and not line.startswith('#'))
        self.assertEqual(settings['CPUQuota'], '100%')
        self.assertEqual(settings['TimeoutStartSec'], '420')
        tree = ast.parse((ROOT/'image/atomic/guest.py').read_text())
        calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != 'run':
                continue
            if not node.args or not isinstance(node.args[0], ast.List):
                continue
            command = [item.value for item in node.args[0].elts if isinstance(item, ast.Constant)]
            if command[:2] == ['/usr/bin/rpm', '-qa']:
                calls.append(node)
        self.assertEqual(len(calls), 1)
        timeouts = [item.value.value for item in calls[0].keywords
                    if item.arg == 'timeout' and isinstance(item.value, ast.Constant)]
        self.assertEqual(timeouts, [180])

    def test_private_pid_namespace_matches_the_pinned_bootc_status_preconditions(self):
        review = json.loads((ROOT/'image/atomic/status-source-review.json').read_text())
        sources = {item['path']:item['excerpt'] for item in review['sources']}
        cli = sources['crates/lib/src/cli.rs']
        preparation = cli.index('require_root(false)?;')
        namespace = cli.index('ensure_self_unshared_mount_namespace(&[])?;')
        self.assertLess(preparation, namespace)
        self.assertIn('let ns_pid1 = std::fs::read_link("/proc/1/ns/mnt")', cli)
        self.assertIn('let ns_self = std::fs::read_link("/proc/self/ns/mnt")', cli)
        self.assertIn('if ns_pid1 != ns_self', cli)
        self.assertIn('rustix::process::getpid().is_init()', cli)
        self.assertIn('PrivatePIDs=yes', review['collector_design'])
        self.assertIn('PID 1', review['collector_design'])
        self.assertIn('CAP_SYS_PTRACE', review['collector_design'])

    def test_status_output_opens_before_runtime_directories_are_created(self):
        settings = dict(line.split('=',1) for line in (ROOT/'image/atomic/s.service').read_text().splitlines()
                        if '=' in line and not line.startswith('#'))
        kind, output = settings['StandardOutput'].split(':',1)
        self.assertEqual(kind, 'truncate')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'run').mkdir(mode=0o755)
            # systemd v262 opens stdio before creating RuntimeDirectory entries.
            # The fixture has only the already-existing root-owned runtime parent.
            path = root/Path(output).relative_to('/')
            fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC,
                         0o666 & ~int(settings['UMask'],8))
            with os.fdopen(fd,'wb') as stream: stream.write(b'{}\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_failed_collector_diagnostic_is_retained_without_accepting_its_output(self):
        guest = self.guest()
        properties = self.properties(); properties.update(Result='exit-code', ExecMainStatus='203',
                                                          ActiveState='failed', SubState='failed')
        calls = []
        def run(command, check=True):
            calls.append((command, check))
            if command[0] == '/usr/bin/systemctl':
                return '\n'.join(k+'='+v for k,v in properties.items())+'\n'
            return 'Failed to execute the fixed collector\n'
        observed = guest.collect_status_diagnostic(run)
        self.assertEqual(observed['service'], properties)
        self.assertIn('Failed to execute', observed['journal'])
        self.assertTrue(calls[0][1]); self.assertFalse(calls[1][1])
        with self.assertRaises(ValueError):
            guest.read_bootc_status(Path('/unopened-failed-output'), observed['service'])

    def test_collector_diagnostic_refuses_excessive_or_duplicate_property_output(self):
        guest = self.guest()
        properties='Result=success\nExecMainCode=1\nExecMainStatus=0\nActiveState=active\nSubState=exited\n'
        for property_text, journal in [(properties+'Result=exit-code\n','log'), (properties,'x'*32769)]:
            def run(command, check=True):
                return property_text if command[0] == '/usr/bin/systemctl' else journal
            with self.assertRaises(ValueError): guest.collect_status_diagnostic(run)


if __name__ == '__main__':
    unittest.main()
