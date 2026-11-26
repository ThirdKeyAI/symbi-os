"""Bounded subprocess output for disposable provider acceptance."""
import os
import selectors
import subprocess
import time


def run_bounded(command, stdout_path, stderr_path, timeout=30, max_bytes=65536):
    if not 0 < timeout <= 3600 or not 0 < max_bytes <= 1024**2:
        raise ValueError('Invalid process evidence limits')
    captured = {'stdout': bytearray(), 'stderr': bytearray()}
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        logs = {'stdout': stdout, 'stderr': stderr}
        with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as child, selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
            deadline = time.monotonic() + timeout
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    for key, _ in selector.select(min(remaining, 0.1)):
                        channel = key.data
                        chunk = os.read(key.fileobj.fileno(), min(4096, max_bytes-len(captured[channel])+1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        if len(captured[channel]) + len(chunk) > max_bytes:
                            raise ValueError('Loader output exceeded evidence bound: ' + channel)
                        captured[channel].extend(chunk)
                        logs[channel].write(chunk)
                        logs[channel].flush()
                child.wait(timeout=max(0.001, deadline-time.monotonic()))
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
    return subprocess.CompletedProcess(command, child.returncode,
                                       captured['stdout'].decode('utf-8'), captured['stderr'].decode('utf-8'))
