"""Bind the downstream consent patch and preserve the reused native toolkit."""
import hashlib
import os
from pathlib import PurePosixPath
import re
import stat


IMPLEMENTATION_FILES = {
    'src/portals/Screencopy.cpp', 'src/portals/Screencopy.hpp',
    'src/shared/ScreencopyShared.cpp', 'src/shared/ScreencopyShared.hpp',
    'hyprland-share-picker/Picker.cpp', 'hyprland-share-picker/Picker.hpp',
    'hyprland-share-picker/main.cpp', 'hyprland-share-picker/PickerData.cpp',
}
TEST_FILES = {'hyprland-share-picker/PickerDataTest.cpp'}
REVIEWED_FILES = IMPLEMENTATION_FILES | TEST_FILES | {
    'LICENSE', 'hyprland-share-picker/PickerData.hpp', 'src/core/PortalManager.cpp',
    'contrib/systemd/xdg-desktop-portal-hyprland.service.in',
    'org.freedesktop.impl.portal.desktop.hyprland.service.in',
}
PATCHES = [('tests', 'image/portal/patches/0001-no-restore-tests.patch', TEST_FILES),
           ('implementation', 'image/portal/patches/0002-require-fresh-screen-sharing-consent.patch', IMPLEMENTATION_FILES)]


def prefix_inventory(root):
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise ValueError('Expected a regular native prefix directory')
    result = {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            try: resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as error: raise ValueError('Dangling or cyclic native prefix link') from error
            if not resolved.is_file() or not resolved.is_relative_to(root):
                raise ValueError('Native prefix link leaves its regular files')
            result[name] = {'link': os.readlink(path)}
        elif path.is_dir(): continue
        elif not path.is_file() or path.stat().st_size > 16*1024**2:
            raise ValueError('Unexpected special or oversized native prefix file')
        else:
            with path.open('rb') as stream: checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
            result[name] = {'sha256': checksum, 'bytes': path.stat().st_size, 'mode': stat.S_IMODE(path.stat().st_mode)}
        if len(result) > 1024: raise ValueError('Excessive native prefix file count')
    return result


def exact_hash(value, length=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{'+str(length)+'}', value) is not None


def require_consent_bindings(bundle, pins, source_hash, rpm_hash, prefix_hash):
    try:
        portal = next(row for row in pins['components'] if row['name'] == 'xdg-desktop-portal-hyprland')
        if (type(bundle['schema']) is not int or bundle['schema'] != 1
                or any(bundle[key] is not False for key in ('qualified', 'consent_qualified', 'product_installation'))
                or bundle['upstream_revision'] != portal['revision'] or not exact_hash(bundle['upstream_revision'], 40)
                or (bundle['source_inputs_sha256'], bundle['rpm_lock_sha256'], bundle['parent_prefix_lock_sha256'])
                   != (source_hash, rpm_hash, prefix_hash)
                or any(not exact_hash(value) for value in (source_hash, rpm_hash, prefix_hash))
                or set(bundle['reviewed_files']) != REVIEWED_FILES or len(bundle['patches']) != 2):
            raise ValueError('Consent source, parent, scope or qualification binding changed')
        for name, row in bundle['reviewed_files'].items():
            if (row['path'] != 'image/portal/consent-reviewed/'+name
                    or type(row['bytes']) is not int or not 0 < row['bytes'] <= 128*1024
                    or not exact_hash(row['sha256']) or not exact_hash(row['git_blob'], 40)):
                raise ValueError('Invalid reviewed consent source identity')
        license = bundle['patch_license']
        if (license['source'] != 'LICENSE' or license['path'] != 'image/portal/consent-reviewed/LICENSE.symbi-os'
                or license['license'] != 'Apache-2.0' or license['installed_path'] != 'share/licenses/symbi-os-portal-patch/LICENSE'
                or type(license['bytes']) is not int or not 0 < license['bytes'] <= 64*1024 or not exact_hash(license['sha256'])):
            raise ValueError('Downstream patch license identity changed')
        for patch, (role, path, names) in zip(bundle['patches'], PATCHES):
            if (patch['role'] != role or patch['path'] != path or set(patch['files']) != names
                    or type(patch['bytes']) is not int or not 0 < patch['bytes'] <= 64*1024
                    or not exact_hash(patch['sha256'])):
                raise ValueError('Consent patch order, path or scope changed')
            for name, row in patch['files'].items():
                if (set(row) != {'before', 'after'} or row['before'] != bundle['reviewed_files'][name]['sha256']
                        or not exact_hash(row['after']) or row['after'] == row['before']):
                    raise ValueError('Consent patch preimage or expected result changed')
    except (KeyError, TypeError, AttributeError, StopIteration) as error:
        raise ValueError('Malformed consent input binding') from error


def load_consent(root, pins):
    from image.portal.inputs import read_pinned, regular_bytes
    from image.toolchain.reuse import unique_json
    raw = regular_bytes(root, 'image/portal/consent-inputs.json')
    bundle = unique_json(raw)
    parents = ('image/portal/source-inputs.json', 'image/portal/build-rpms.lock.json',
               'image/portal/development-prefix.lock.json')
    bindings = {name: hashlib.sha256(regular_bytes(root, name, 2*1024**2)).hexdigest() for name in parents}
    require_consent_bindings(bundle, pins, *(bindings[name] for name in parents))
    bindings['image/portal/consent-inputs.json'] = hashlib.sha256(raw).hexdigest()
    license_source = root/'LICENSE'
    if (license_source.is_symlink() or not license_source.is_file() or license_source.resolve() != license_source
            or license_source.stat().st_size != bundle['patch_license']['bytes']
            or hashlib.sha256(license_source.read_bytes()).hexdigest() != bundle['patch_license']['sha256']):
        raise ValueError('Patch license differs from the OS repository license')
    bindings['LICENSE'] = bundle['patch_license']['sha256']
    for row in [*bundle['reviewed_files'].values(), *bundle['patches'], bundle['patch_license']]:
        data = read_pinned(root, row['path'], row['sha256'])
        if len(data) != row['bytes']: raise ValueError('Consent input length changed')
        if 'git_blob' in row and hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() != row['git_blob']:
            raise ValueError('Reviewed consent source differs from its Git object')
        bindings[row['path']] = row['sha256']
    return bundle, bindings


def require_tree(root, bundle, phase):
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise ValueError('Expected a regular consent source directory')
    if phase not in ('upstream', 'tests', 'implementation'):
        raise ValueError('Unknown consent patch phase')
    expected = {name: row['sha256'] for name, row in bundle['reviewed_files'].items()}
    if phase != 'upstream':
        for patch in bundle['patches']:
            for name, row in patch['files'].items(): expected[name] = row['after']
            if patch['role'] == phase: break
    for name, expected_hash in expected.items():
        relative = PurePosixPath(name)
        if name not in REVIEWED_FILES or relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unexpected consent source path')
        path = root/relative
        if (path.is_symlink() or not path.is_file() or path.resolve() != path
                or not 0 < path.stat().st_size <= 128*1024
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash):
            raise ValueError('Consent source differs from the exact patch phase: '+name)


def require_portal_only_install(parent, installed, patch_license=None):
    binaries = {'bin/hyprland-share-picker', 'libexec/xdg-desktop-portal-hyprland'}
    try:
        original = parent['files']
        extra = set()
        if patch_license is not None:
            name = 'share/licenses/symbi-os-portal-patch/LICENSE'
            if (patch_license['installed_path'] != name or name in original
                    or not exact_hash(patch_license['sha256']) or type(patch_license['bytes']) is not int
                    or not 0 < patch_license['bytes'] <= 64*1024
                    or installed.get(name) != {'sha256': patch_license['sha256'], 'bytes': patch_license['bytes'], 'mode': 0o644}):
                raise ValueError('Installed downstream patch license differs')
            extra.add(name)
        if not binaries.issubset(original) or set(original) | extra != set(installed):
            raise ValueError('Portal installation changed the retained file inventory')
        for name, row in installed.items():
            if name in extra: continue
            if name not in binaries:
                if row != original[name]: raise ValueError('Reused toolkit, configuration or license changed: '+name)
            elif (set(row) != {'sha256', 'bytes', 'mode'} or not exact_hash(row['sha256'])
                  or row['sha256'] == original[name]['sha256'] or row['mode'] != 0o755
                  or type(row['bytes']) is not int or not 0 < row['bytes'] <= 16*1024**2):
                raise ValueError('Expected newly built regular unprivileged portal binaries')
        return sorted(set(original)-binaries)
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Malformed retained portal installation') from error
