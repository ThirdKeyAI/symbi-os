import json
import os
from pathlib import Path
import socket
import stat
import tempfile

result = {'passed': False, 'qualified': False, 'paths': []}
with tempfile.TemporaryDirectory(prefix='sf-', dir='/tmp') as temporary:
    root = Path(temporary)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert root.stat().st_uid == os.getuid() and not root.is_symlink()
    for prefix in ('symbi-file-grants-', 'symbi-source-e2e-', 'symbi-git-source-'):
        state = root / (prefix + '12345678') / 'state'
        state.mkdir(parents=True)
        path = state / 'supervisor.sock'
        length = len(os.fsencode(path))
        assert length <= 100
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
        result['paths'].append({'fixture_prefix': prefix, 'socket_path_bytes': length, 'bind_passed': True})
    long_state = root / ('checkout-' + 'x' * 90) / 'private/tmp/symbi-file-grants-12345678/state'
    long_state.mkdir(parents=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        try:
            server.bind(str(long_state / 'supervisor.sock'))
        except OSError as error:
            assert 'too long' in str(error)
            result['long_path_rejected'] = True
        else:
            raise AssertionError('Expected Unix socket path rejection')
result['passed'] = True
print(json.dumps(result, indent=2))
