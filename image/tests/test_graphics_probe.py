"""QMP evidence must be bounded and tied to the requested command."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest


SOURCE = Path(__file__).parents[1] / 'hyprland/graphics/guest.py'
SPEC = importlib.util.spec_from_file_location('graphics_guest', SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class Duplex(io.BytesIO):
    def write(self, data):
        return len(data)


class GraphicsProbe(unittest.TestCase):
    def test_matching_response_survives_an_asynchronous_event(self):
        stream = Duplex(b'{"event":"STOP"}\n{"id":"query-status","return":{"running":false}}\n')
        self.assertEqual(probe.request(stream, 'query-status'), {'running': False})

    def test_wrong_command_or_failed_response_is_not_evidence(self):
        for result in ({'id': 'wrong', 'return': True}, {'id': 'qom-get', 'error': {'desc': 'absent'}}):
            with self.subTest(result=result), self.assertRaises(ValueError):
                probe.request(Duplex(json.dumps(result).encode()+b'\n'), 'qom-get')

    def test_oversized_malformed_or_event_flood_is_bounded(self):
        for raw in (b'x'*16385, b'[]\n', b'', b'not json\n', b'{"event":"STOP"}\n'*21):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                probe.request(Duplex(raw), 'query-status')

    def test_local_guest_invocation_refused(self):
        completed = subprocess.run([sys.executable, str(SOURCE)], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn('disposable unprivileged Fedora container', completed.stderr)


if __name__ == '__main__':
    unittest.main()
