"""Inspect installed payload bytes from an unprivileged read-only image container."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


CONTROLLER_ENTRYPOINT = Path('/usr/libexec/symbi-atomic-update')
CONTROLLER_BRIDGE = Path('/usr/libexec/symbi-bootc-transition')
CONTROLLER = Path('/usr/libexec/symbi-atomic-update-controller.py')
CONTROLLER_MANIFEST = Path(
    '/usr/share/symbi-os/selinux/symbi-atomic-update.json')
CONTROLLER_CONTEXT = 'system_u:system_r:symbi_atomic_update_t:s0'
CONTROLLER_ENTRYPOINT_CONTEXT = (
    'system_u:object_r:symbi_atomic_update_exec_t:s0')
CONTROLLER_BRIDGE_CONTEXT = (
    'system_u:object_r:symbi_bootc_transition_exec_t:s0')
INSTALL_CONTEXT = 'system_u:system_r:install_t:s0'


def unique_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate Atomic update manifest key')
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError('Atomic update manifest is not an object')
    return value


def fixed_file(path, mode, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_gid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != mode
                or not 0 < before.st_size <= maximum):
            raise ValueError('Installed Atomic update file controls differ')
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            raw = stream.read(maximum + 1)
        if len(raw) != before.st_size:
            raise ValueError('Installed Atomic update file read differs')
        digest = hashlib.sha256(raw).hexdigest()
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after):
            raise ValueError('Installed Atomic update file changed')
        return {'sha256': digest, 'bytes': before.st_size, 'raw': raw}
    finally:
        os.close(descriptor)


def verify_atomic_update_controller(source):
    """Bind the immutable controller and minimal expanded SELinux policy."""
    entrypoint = fixed_file(CONTROLLER_ENTRYPOINT, 0o755, 256 * 1024)
    bridge = fixed_file(CONTROLLER_BRIDGE, 0o755, 256 * 1024)
    controller = fixed_file(CONTROLLER, 0o444, 256 * 1024)
    manifest_file = fixed_file(CONTROLLER_MANIFEST, 0o444, 128 * 1024)
    manifest = unique_json(manifest_file['raw'])
    expansion = {
        'schema': 2, 'policy': 'symbi_atomic_update',
        'install_transition_inventory': {
            'schema': 1,
            'source': 'symbi_atomic_update_t',
            'class': 'process',
            'destination': 'install_t',
            'rules': [
                'type_transition symbi_atomic_update_t '
                'symbi_bootc_transition_exec_t:process install_t;',
            ],
        },
        'required': {
            'init_entrypoint': True, 'init_transition': True,
            'bridge_entrypoint': True, 'bridge_transition': True,
            'bridge_type_transition': True,
            'install_sigchld': True,
        },
        'forbidden': {
            'shared_install_type_transition': False,
            'generic_install_transition': False,
            'controller_forbidden_process_permissions': False,
            'controller_policy_load': False,
            'controller_enforcing_change': False,
        },
    }
    expected_entrypoint = {
        'path': str(CONTROLLER_ENTRYPOINT), 'sha256': entrypoint['sha256'],
        'uid': 0, 'gid': 0, 'mode': '0755',
        'selinux_label': CONTROLLER_ENTRYPOINT_CONTEXT,
    }
    expected_controller = {
        'path': str(CONTROLLER), 'sha256': controller['sha256'],
        'uid': 0, 'gid': 0, 'mode': '0444',
    }
    expected_bridge = {
        'path': str(CONTROLLER_BRIDGE), 'sha256': bridge['sha256'],
        'uid': 0, 'gid': 0, 'mode': '0755',
        'selinux_label': CONTROLLER_BRIDGE_CONTEXT,
    }
    context = source.get('context')
    if not isinstance(context, dict):
        raise ValueError('Preparation context identity is missing')
    source_paths = {
        'controller': 'image/atomic/update_guest.py',
        'te_sha256': 'image/atomic/selinux/symbi_atomic_update.te',
        'fc_sha256': 'image/atomic/selinux/symbi_atomic_update.fc',
        'launcher_sha256': 'image/atomic/selinux/symbi-atomic-update.c',
        'bridge_sha256': 'image/atomic/selinux/symbi-bootc-transition.c',
    }
    try:
        sources = {key: context[path]['sha256']
                   for key, path in source_paths.items() if key != 'controller'}
        controller_source = context[source_paths['controller']]['sha256']
    except (KeyError, TypeError) as error:
        raise ValueError('Preparation Atomic update inputs are incomplete') from error
    if (set(manifest) != {
            'schema', 'policy', 'entrypoint', 'bridge', 'controller',
            'controller_context', 'install_context', 'policy_sources',
            'expanded_policy'}
            or type(manifest.get('schema')) is not int
            or manifest['schema'] != 1
            or manifest.get('policy') != 'symbi_atomic_update'
            or manifest.get('entrypoint') != expected_entrypoint
            or manifest.get('bridge') != expected_bridge
            or manifest.get('controller') != expected_controller
            or manifest.get('controller_context') != CONTROLLER_CONTEXT
            or manifest.get('install_context') != INSTALL_CONTEXT
            or manifest.get('policy_sources') != sources
            or not isinstance(manifest.get('expanded_policy'), dict)
            or type(manifest['expanded_policy'].get('schema')) is not int
            or not isinstance(manifest['expanded_policy'].get(
                'install_transition_inventory'), dict)
            or type(manifest['expanded_policy']['install_transition_inventory'].get(
                'schema')) is not int
            or manifest.get('expanded_policy') != expansion
            or controller['sha256'] != controller_source
            or any(re.fullmatch(r'[a-f0-9]{64}', item) is None
                   for item in (*sources.values(), controller_source))):
        raise ValueError('Installed Atomic update controller identity differs')
    return {
        'schema': 1,
        'policy': 'symbi_atomic_update',
        'entrypoint': str(CONTROLLER_ENTRYPOINT),
        'entrypoint_sha256': entrypoint['sha256'],
        'entrypoint_selinux_label': CONTROLLER_ENTRYPOINT_CONTEXT,
        'bridge': str(CONTROLLER_BRIDGE),
        'bridge_sha256': bridge['sha256'],
        'bridge_selinux_label': CONTROLLER_BRIDGE_CONTEXT,
        'controller': str(CONTROLLER),
        'controller_sha256': controller['sha256'],
        'manifest': str(CONTROLLER_MANIFEST),
        'manifest_sha256': manifest_file['sha256'],
        'controller_context': CONTROLLER_CONTEXT,
        'install_context': INSTALL_CONTEXT,
        'policy_sources': sources,
        'expanded_policy': expansion,
    }


def verify_font_payload(source):
    """Require and check the installed font payload for every retained image."""
    if "fonts" not in source:
        raise ValueError("Retained development image is missing font evidence")
    from font_verify import verify_installed_fonts
    return {"checked": True, **verify_installed_fonts(source["fonts"])}


def main():
    if os.geteuid() != 10001 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the unprivileged installed-image inspection container')
    source = json.loads(Path('/qualification/preparation.json').read_text())
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {n: (group/n).read_text().strip() for n in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    status = dict(row.split(':', 1) for row in Path('/proc/self/status').read_text().splitlines() if ':' in row)
    if (limits != {'memory.max':'536870912', 'memory.swap.max':'0', 'cpu.max':'100000 100000', 'pids.max':'64'}
            or status['CapEff'].strip() != '0000000000000000' or status['NoNewPrivs'].strip() != '1'
            or not os.statvfs('/').f_flag & os.ST_RDONLY
            or sorted(p.name for p in Path('/sys/class/net').iterdir()) != ['lo']):
        raise ValueError('Installed-image inspection isolation changed')
    count = 0
    for relative, expected in {**source['payload'], **source['overlay']}.items():
        if not relative.startswith(('usr/', 'etc/')) or '..' in Path(relative).parts:
            raise ValueError('Unexpected installed payload path')
        path = Path('/')/relative
        info = path.lstat()
        if info.st_uid != 0 or (not path.is_symlink() and info.st_mode & 0o022):
            raise ValueError('Installed payload must be root-owned and not writable by others: '+relative)
        if 'link' in expected:
            if not path.is_symlink() or os.readlink(path) != expected['link'] or not path.resolve(strict=True).is_file():
                raise ValueError('Installed link changed: '+relative)
        else:
            if path.is_symlink() or not path.is_file() or path.stat().st_size != expected['bytes']:
                raise ValueError('Installed file shape changed: '+relative)
            with path.open('rb') as stream: actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            if actual != expected['sha256'] or info.st_mode & 0o777 != expected['mode']:
                raise ValueError('Installed content/mode changed: '+relative)
        count += 1
    for name in ('/usr/bin/hyprpm', '/usr/lib/symbi/hyprland/bin/hyprpm'):
        if os.path.lexists(name): raise ValueError('Hyprland package manager remains installed')
    for name in ('symbi-desktop-session', 'symbi-seed-config', 'symbi-launch-desktop-services'):
        if not os.access('/usr/libexec/'+name, os.X_OK): raise ValueError('Desktop helper is not executable')
    fmt = '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
    inventory = subprocess.check_output(['rpm', '-qa', '--qf', fmt], text=True, timeout=30).splitlines()
    expected = Path('/qualification/installed-after-stdout.log').read_text().splitlines()
    if len(set(inventory)) != len(inventory) or set(inventory) != set(expected):
        raise ValueError('Final image package inventory changed after installation')
    fonts = verify_font_payload(source)
    atomic_update_controller = verify_atomic_update_controller(source)
    scope = 'Installed bytes and native font parsing only; no boot or containment qualification'
    print(json.dumps({'passed':True, 'os_qualified':False, 'installed_files_checked':count,
                      'installed_package_count':len(inventory), 'all_package_identities_preserved_after_build':True,
                      'fonts':fonts, 'atomic_update_controller':atomic_update_controller,
                      'uid':os.geteuid(), 'limits':limits, 'scope':scope}))


if __name__ == '__main__': main()
