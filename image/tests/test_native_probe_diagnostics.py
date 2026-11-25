"""Regress the real probe's overlong IPC path and masked startup failure."""
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock


SPEC = importlib.util.spec_from_file_location('native_probe', Path(__file__).parents[1] /
                                              'hyprland/tests/qualify_native_loading.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class NativeProbeDiagnostics(unittest.TestCase):
    def test_original_runtime_path_is_rejected_before_startup(self):
        with self.assertRaisesRegex(ValueError, 'socket'):
            probe.require_socket_root(Path('/output/native-work/runtime'))
        for path in ('/output/n/runtime', '/output/bn/runtime'):
            probe.require_socket_root(Path(path))

    def test_socket_budget_matches_real_unix_bind(self):
        with tempfile.TemporaryDirectory(prefix='sn-', dir='/tmp') as directory:
            root = Path(directory)
            for length, valid in ((107, True), (108, False)):
                path = root / ('x' * (length - len(str(root).encode()) - 1))
                with socket.socket(socket.AF_UNIX) as server:
                    if valid:
                        server.bind(str(path))
                    else:
                        with self.assertRaises(OSError):
                            server.bind(str(path))

    def test_instance_query_requires_valid_json_and_exact_child(self):
        with self.assertRaises(ValueError):
            probe.select_instance('no running instances\n', 42)
        self.assertIsNone(probe.select_instance('[]', 42))
        self.assertIsNone(probe.select_instance(json.dumps([{'pid': 7, 'instance': 'other'}]), 42))
        owned = [{'pid': 42, 'instance': 'owned'}]
        self.assertEqual(probe.select_instance(json.dumps(owned), 42), 'owned')
        with self.assertRaises(ValueError):
            probe.select_instance(json.dumps(owned + owned), 42)

    def test_denied_cleanup_is_reported_without_masking_startup_error(self):
        child = Mock()
        child.poll.return_value = None
        child.terminate.side_effect = PermissionError(13, 'denied')
        child.kill.side_effect = PermissionError(13, 'denied')
        result = probe.stop_child(child)
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['errors']), 2)
        self.assertTrue(all('PermissionError' in error for error in result['errors']))

    def test_exited_child_cleanup_does_not_send_signals(self):
        child = Mock()
        child.poll.return_value = 1
        result = probe.stop_child(child)
        self.assertTrue(result['passed'])
        child.terminate.assert_not_called()
        child.kill.assert_not_called()


if __name__ == '__main__':
    unittest.main()
