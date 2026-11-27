#!/usr/bin/env python3
"""Run inside the disposable Fedora cloud guest and report over virtio serial."""
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time


class DrmVersion(ctypes.Structure):
    # Linux UAPI drm_version; this probe's signed guest is x86_64 only.
    _fields_ = [('major', ctypes.c_int), ('minor', ctypes.c_int), ('patch', ctypes.c_int),
                ('name_len', ctypes.c_size_t), ('name', ctypes.c_void_p),
                ('date_len', ctypes.c_size_t), ('date', ctypes.c_void_p),
                ('desc_len', ctypes.c_size_t), ('desc', ctypes.c_void_p)]


def drm_driver(fd, ioctl=fcntl.ioctl):
    if platform.machine() != 'x86_64' or ctypes.sizeof(DrmVersion) != 64:
        raise ValueError('Unexpected DRM ioctl ABI')
    name = ctypes.create_string_buffer(128)
    version = DrmVersion(name_len=len(name), name=ctypes.addressof(name))
    # _IOWR('d', 0x00, struct drm_version), from include/uapi/drm/drm.h.
    ioctl(fd, 0xc0406400, version, True)
    if not 0 < version.name_len < len(name):
        raise ValueError('Missing or oversized DRM driver name')
    value = name.raw[:version.name_len].decode('ascii')
    if not re.fullmatch('[a-zA-Z0-9_-]+', value):
        raise ValueError('Malformed DRM driver name')
    return value


def main():
    product = Path('/sys/class/dmi/id/product_name')
    if (os.geteuid() != 0 or not product.exists()
            or product.read_text().strip() != 'Symbi-Hosted-Graphics-Probe'):
        raise SystemExit('Run only inside the disposable hosted graphics guest')
    if len(sys.argv) != 3 or not re.fullmatch('[0-9a-f]{32}', sys.argv[1]):
        raise SystemExit('A fresh nonce and fixed probe case are required')
    nonce, case = sys.argv[1:]
    if case not in ('without-gpu', 'with-gpu'):
        raise SystemExit('Unexpected probe case')
    record = {'schema': 1, 'nonce': nonce, 'case': case, 'probe_completed': False,
              'os_qualified': False, 'scope': 'Fedora cloud boot and DRM availability only',
              'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'product': product.read_text().strip(), 'kernel': platform.release(),
              'os_release': platform.freedesktop_os_release(),
              'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'nics': sorted(path.name for path in Path('/sys/class/net').iterdir()),
              'render_nodes': []}
    try:
        loaded = subprocess.run(['/usr/sbin/modprobe', 'virtio_gpu'], text=True,
                                capture_output=True, timeout=20)
        record['modprobe'] = {'exit_code': loaded.returncode, 'stdout': loaded.stdout,
                              'stderr': loaded.stderr}
        record['selinux'] = subprocess.check_output(['/usr/sbin/getenforce'], text=True,
                                                    timeout=10).strip()
        deadline = time.monotonic() + (30 if case == 'with-gpu' else 0)
        while not list(Path('/dev/dri').glob('renderD*')) and time.monotonic() < deadline:
            time.sleep(0.2)
        for node in sorted(Path('/dev/dri').glob('renderD*')):
            info = node.lstat()
            driver = Path('/sys/class/drm') / node.name / 'device/driver'
            entry = {'path': str(node), 'character_device': stat.S_ISCHR(info.st_mode),
                     'major': os.major(info.st_rdev), 'minor': os.minor(info.st_rdev),
                     'driver': driver.resolve().name if driver.exists() else None,
                     'opened_read_write': False}
            try:
                fd = os.open(node, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    entry['opened_read_write'] = True
                    entry['drm_driver'] = drm_driver(fd)
                finally:
                    os.close(fd)
            except OSError as error:
                entry['open_error'] = str(error)
            record['render_nodes'].append(entry)
        record['probe_completed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__ + ': ' + str(error)
    raw = (json.dumps(record, sort_keys=True) + '\n').encode()
    assert len(raw) < 65536
    # A dedicated output-only channel avoids scraping the boot console.
    channel = Path('/dev/virtio-ports/org.symbi.graphics')
    with channel.open('wb', buffering=0) as stream:
        offset = 0
        while offset < len(raw):
            count = stream.write(raw[offset:])
            if not count:
                raise RuntimeError('Guest report channel stopped accepting data')
            offset += count


if __name__ == '__main__':
    main()
