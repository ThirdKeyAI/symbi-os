#!/usr/bin/env python3
"""Boot a signed Fedora cloud input on hosted virtual graphics, without networking."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess
import time
import urllib.parse
import urllib.request
import uuid


def decode_report(raw):
    if len(raw) > 65536:
        raise ValueError('Guest report exceeds size bound')

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate report key')
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError('Guest report must be an object')
    return value


def validate_report(report, nonce, source_hash, case):
    def require(condition, reason):
        if not condition:
            raise ValueError(reason)

    require(case in ('without-gpu', 'with-gpu'), 'Unknown probe case')
    require(report.get('schema') == 1 and report.get('nonce') == nonce
            and report.get('probe_sha256') == source_hash and report.get('case') == case,
            'Guest report is not bound to this invocation and probe source')
    require(report.get('probe_completed') is True and report.get('os_qualified') is False
            and 'failure' not in report, 'Guest probe did not complete')
    release = report.get('os_release', {})
    require(release.get('ID') == 'fedora' and release.get('VERSION_ID') == '45',
            'Expected the signed Fedora45 cloud guest')
    try:
        uuid.UUID(report.get('boot_id', ''))
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError('Missing guest boot identity') from error
    require(isinstance(report.get('kernel'), str) and bool(report['kernel']), 'Missing guest kernel')
    require(report.get('product') == 'Symbi-Hosted-Graphics-Probe', 'Wrong guest product identity')
    require(report.get('nics') == ['lo'], 'Guest must have no external network device')
    require(report.get('selinux') == 'Enforcing', 'Guest SELinux must remain enforcing')
    require(report.get('modprobe', {}).get('exit_code') == 0, 'virtio_gpu module did not load')
    nodes = report.get('render_nodes')
    require(isinstance(nodes, list), 'Missing render-device observations')
    if case == 'without-gpu':
        require(nodes == [], 'No-GPU control unexpectedly exposes a render device')
        return
    require(bool(nodes), 'Guest exposes no render device')
    for node in nodes:
        require(isinstance(node, dict), 'Invalid render-device record')
        require(bool(re.fullmatch(r'/dev/dri/renderD[0-9]+', node.get('path', '')))
                and node.get('character_device') is True and node.get('major') == 226
                and isinstance(node.get('minor'), int) and node['minor'] >= 128
                and node.get('driver') == 'virtio_gpu' and node.get('opened_read_write') is True,
                'Render device is not an accessible virtio GPU')


def copy_verified(stream, target, pin):
    """Publish no payload unless its complete size and hash match the signed pin."""
    size, expected = pin['bytes'], pin['sha256']
    if not isinstance(size, int) or not 0 < size <= 1024**3 or not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('Invalid bounded image pin')
    if target.exists() or target.is_symlink():
        raise ValueError('Image target must be new')
    temporary = target.with_name(target.name + '.partial')
    digest, count = hashlib.sha256(), 0
    try:
        with temporary.open('xb') as output:
            while block := stream.read(1024*1024):
                count += len(block)
                if count > size:
                    raise ValueError('Downloaded image exceeds pinned size')
                digest.update(block)
                output.write(block)
        if count != size or digest.hexdigest() != expected:
            raise ValueError('Downloaded image size or hash does not match the signed pin')
        os.chmod(temporary, 0o444)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_cloud_input(root, inputs, evidence):
    """Verify the retained signed checksum before streaming a hosted-only payload."""
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise RuntimeError('Cloud image download requires the disposable hosted runner')
    candidate = json.loads((root / 'image/hyprland/graphics/fedora-cloud/candidate.json').read_text())
    checksum = candidate['checksum']
    key, signed = root / checksum['key_path'], root / checksum['path']
    assert hashlib.sha256(key.read_bytes()).hexdigest() == checksum['key_sha256']
    assert hashlib.sha256(signed.read_bytes()).hexdigest() == checksum['sha256']
    home = inputs / 'gpg-home'
    home.mkdir(mode=0o700)
    keyring = home / 'fedora.gpg'
    subprocess.run(['gpg', '--batch', '--homedir', str(home), '--dearmor', '--output',
                    str(keyring), str(key)], check=True, timeout=15, capture_output=True)

    def verify(path, ring):
        return subprocess.run(['gpgv', '--homedir', str(home), '--keyring', str(ring),
                               '--status-fd', '1', str(path)], text=True,
                              capture_output=True, timeout=15)

    verified = verify(signed, keyring)
    (evidence / 'cloud-checksum-signature.log').write_text(verified.stdout + verified.stderr)
    assert verified.returncode == 0
    fingerprint = checksum['signing_fingerprint']
    assert re.search(r'^\[GNUPG:\] VALIDSIG ' + re.escape(fingerprint) + r' ', verified.stdout, re.M)
    image = candidate['image']
    url = urllib.parse.urlparse(image['url'])
    assert url.scheme == 'https' and url.netloc == 'dl.fedoraproject.org'
    filename = Path(url.path).name
    expected_line = f"SHA256 ({filename}) = {image['sha256']}"
    lines = signed.read_text().splitlines()
    assert lines.count(expected_line) == 1
    assert lines.count(f"# {filename}: {image['bytes']} bytes") == 1
    changed = home / 'changed-CHECKSUM'
    changed.write_bytes(signed.read_bytes().replace(image['sha256'].encode(), b'0'*64, 1))
    missing_ring = home / 'empty.gpg'
    missing_ring.write_bytes(b'')
    for name, response in [('changed', verify(changed, keyring)), ('missing-key', verify(signed, missing_ring))]:
        (evidence / ('cloud-checksum-' + name + '.log')).write_text(response.stdout + response.stderr)
        assert response.returncode != 0, 'Checksum negative control accepted: ' + name
    with urllib.request.urlopen(image['url'], timeout=90) as response:
        final = urllib.parse.urlparse(response.geturl())
        assert final.scheme == 'https' and final.netloc == 'dl.fedoraproject.org'
        copy_verified(response, inputs / 'fedora.qcow2', image)
    (evidence / 'cloud-input.json').write_text(json.dumps({
        'image': image, 'checksum_sha256': checksum['sha256'], 'signing_fingerprint': fingerprint,
        'signature_verified': True, 'negative_controls_passed': True, 'payload_verified': True,
        'os_qualified': False}, indent=2) + '\n')


def main():
    if os.geteuid() == 0 or not Path('/run/.containerenv').exists():
        raise SystemExit('Run only in the disposable unprivileged Fedora container')
    fields = platform.freedesktop_os_release()
    if fields.get('ID') != 'secureblue' or 'fedora' not in fields.get('ID_LIKE', '').split():
        raise SystemExit('Selected authenticated secureblue QEMU base required')
    group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group / name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'cpu.max')}
    assert limits == {'memory.max': '3221225472', 'memory.swap.max': '0', 'cpu.max': '200000 100000'}
    inputs, output = Path('/inputs'), Path('/output')
    source = (inputs / 'cloud_probe.py').read_bytes()
    source_hash = hashlib.sha256(source).hexdigest()
    record = {'passed': False, 'guest_booted': False, 'os_qualified': False, 'limits': limits,
              'scope': 'Fedora cloud boot and DRM availability only; no compositor or Atomic image acceptance',
              'probe_sha256': source_hash, 'cases': []}
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/output',
           'XDG_RUNTIME_DIR': '/output/runtime', 'DISPLAY': os.environ['DISPLAY'],
           'XAUTHORITY': '/inputs/xauthority', 'SDL_VIDEODRIVER': 'x11',
           'LIBGL_ALWAYS_SOFTWARE': '1', 'GALLIUM_DRIVER': 'llvmpipe',
           'LP_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1', 'LANG': 'C.UTF-8'}
    Path(env['XDG_RUNTIME_DIR']).mkdir(mode=0o700)
    child = None
    try:
        record['qemu_version'] = subprocess.check_output(['/usr/bin/qemu-system-x86_64', '--version'], text=True, timeout=15)
        record['tools'] = {}
        for name in ('qemu-system-x86_64', 'qemu-img', 'xorriso'):
            with (Path('/usr/bin') / name).open('rb') as stream:
                record['tools'][name] = hashlib.file_digest(stream, 'sha256').hexdigest()
        for case in ('without-gpu', 'with-gpu'):
            directory = output / case
            directory.mkdir(mode=0o700)
            seed = directory / 'seed'
            seed.mkdir()
            nonce = secrets.token_hex(16)
            config = {'users': [], 'ssh_pwauth': False, 'disable_root': True,
                      'ssh_genkeytypes': [], 'ssh_deletekeys': True,
                      'write_files': [{'path': '/usr/local/libexec/symbi-graphics-probe.py',
                                       'permissions': '0700', 'owner': 'root:root',
                                       'content': source.decode()}],
                      'runcmd': [['/usr/bin/python3', '/usr/local/libexec/symbi-graphics-probe.py', nonce, case],
                                 ['/usr/bin/systemctl', 'poweroff']]}
            (seed / 'user-data').write_text('#cloud-config\n' + json.dumps(config) + '\n')
            (seed / 'meta-data').write_text(json.dumps({'instance-id': nonce, 'local-hostname': 'symbi-graphics'}) + '\n')
            (seed / 'network-config').write_text('version: 2\nethernets: {}\n')
            with (directory / 'prepare.log').open('w') as log:
                subprocess.run(['/usr/bin/xorriso', '-as', 'mkisofs', '-quiet', '-output', str(directory / 'seed.iso'),
                                '-volid', 'CIDATA', '-joliet', '-rock', str(seed)], stdout=log,
                               stderr=subprocess.STDOUT, check=True, timeout=30)
                subprocess.run(['/usr/bin/qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b',
                                '/inputs/fedora.qcow2', str(directory / 'guest.qcow2')], stdout=log,
                               stderr=subprocess.STDOUT, check=True, timeout=30)
            command = ['/usr/bin/qemu-system-x86_64', '-machine', 'q35,dump-guest-core=off',
                       '-accel', 'tcg,thread=single', '-cpu', 'max', '-m', '1536M', '-smp', '1',
                       '-nodefaults', '-no-user-config', '-no-reboot', '-net', 'none',
                       '-smbios', 'type=1,manufacturer=Symbi-Test,product=Symbi-Hosted-Graphics-Probe',
                       '-drive', f'file={directory}/guest.qcow2,format=qcow2,if=virtio',
                       '-drive', f'file={directory}/seed.iso,format=raw,if=virtio,readonly=on',
                       '-device', 'virtio-rng-pci', '-device', 'virtio-serial-pci',
                       '-chardev', f'file,id=report,path={directory}/report.json',
                       '-device', 'virtserialport,chardev=report,name=org.symbi.graphics',
                       '-serial', f'file:{directory}/serial.log', '-monitor', 'none']
            if case == 'with-gpu':
                command += ['-device', 'virtio-vga-gl,id=symbi-gpu', '-display', 'sdl,gl=on']
            else:
                command += ['-display', 'none']
            item = {'case': case, 'nonce': nonce, 'command': command, 'passed': False,
                    'seed_sha256': hashlib.sha256((directory / 'seed.iso').read_bytes()).hexdigest()}
            record['cases'].append(item)
            start = time.monotonic()
            with (directory / 'qemu.log').open('w') as log:
                child = subprocess.Popen(command, cwd=directory, env=env, stdout=log, stderr=subprocess.STDOUT)
                # No SSH server, NIC, host filesystem share, host GPU or KVM device.
                while child.poll() is None:
                    for name, maximum in [('serial.log', 2*1024*1024), ('qemu.log', 2*1024*1024),
                                          ('report.json', 65536)]:
                        path = directory / name
                        if path.exists() and path.stat().st_size > maximum:
                            raise RuntimeError('Guest output exceeded the evidence bound: ' + name)
                    if time.monotonic() - start >= 900:
                        raise TimeoutError('Guest did not report and power off within 15 minutes')
                    time.sleep(0.5)
            item['exit_code'] = child.returncode
            item['elapsed_seconds'] = time.monotonic() - start
            assert child.returncode == 0, 'QEMU failed; inspect case logs'
            raw_path = directory / 'report.json'
            assert raw_path.is_file() and not raw_path.is_symlink() and raw_path.stat().st_size <= 65536
            report = decode_report(raw_path.read_bytes())
            validate_report(report, nonce, source_hash, case)
            item['boot_id'] = report['boot_id']
            item['passed'] = True
        assert len({item['boot_id'] for item in record['cases']}) == 2, 'Controls must use distinct boots'
        record.update(passed=True, guest_booted=True)
    except Exception as error:
        record['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        if child is not None and child.poll() is None:
            try:
                child.terminate()
                child.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                child.kill()
                child.wait(timeout=10)
            record['passed'] = False
        record['cgroup_final'] = {name: (group / name).read_text().strip()
                                  for name in ('memory.peak', 'memory.events', 'cpu.stat')}
        (output / 'result.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
