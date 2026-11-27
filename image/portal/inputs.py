"""Bind portal inputs to the selected compositor and reviewed source files."""
import hashlib
from pathlib import Path, PurePosixPath
import re

from image.toolchain.reuse import unique_json


EXTRA_PACKAGES = ['pkgconfig(libpipewire-0.3)', 'pkgconfig(libspa-0.2)',
                  'pkgconfig(sdbus-c++)', 'pkgconfig(iniparser)', 'pkgconfig(absl_flat_hash_map)']
COMPONENTS = {'hyprtoolkit': 'hyprtoolkit', 'xdg-desktop-portal-hyprland': 'xdph'}
REUSED_INPUTS = {'image/hyprland/candidate-inputs.json', 'image/hyprland/development-prefix.lock.json',
                'image/hyprland/build-rpms.lock.json', 'image/hyprland/patches/0001-disable-native-loading.patch'}


def regular_bytes(root, relative, limit=128*1024):
    relative = PurePosixPath(relative)
    if (relative.is_absolute() or '..' in relative.parts or not relative.parts
            or relative.parts[:2] not in (('image', 'portal'), ('image', 'hyprland'))):
        raise ValueError('Unexpected reviewed portal input path')
    path = root/relative
    if (path.is_symlink() or not path.is_file() or path.resolve() != path
            or path.stat().st_size > limit):
        raise ValueError('Portal input must be a bounded regular file: '+str(relative))
    return path.read_bytes()


def read_pinned(root, relative, expected):
    data = regular_bytes(root, relative)
    if not re.fullmatch(r'[0-9a-f]{64}', expected) or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Reviewed portal input bytes changed: '+str(relative))
    return data


def require_source_selection(pins, flake, compositor):
    try:
        selected = pins['components']
        valid = (type(pins['schema']) is int and pins['schema'] == 1 and pins['qualified'] is False
                 and pins['hyprland_revision'] == compositor['hyprland_revision']
                 and re.fullmatch(r'[0-9a-f]{40}', pins['hyprland_revision'])
                 and len(selected) == len(COMPONENTS)
                 and {x['name'] for x in selected} == set(COMPONENTS))
        if not valid:raise ValueError('Unexpected portal source selection')
        for component in selected:
            name, node, revision = component['name'], component['lock_node'], component['revision']
            locked = flake['nodes'][node]['locked']
            if (node != COMPONENTS[name] or not re.fullmatch(r'[0-9a-f]{40}', revision)
                    or component['repository'] != 'https://github.com/hyprwm/'+name+'.git'
                    or any(locked.get(k) != v for k, v in
                           {'type': 'github', 'owner': 'hyprwm', 'repo': name, 'rev': revision}.items())):
                raise ValueError('Portal source differs from the selected compositor lockfile')
    except (KeyError, TypeError) as error:
        raise ValueError('Incomplete portal source selection') from error


def require_package_selection(requirements, pins, base, source_hash, base_hash):
    try:
        expected = base['packages']+EXTRA_PACKAGES
        if (type(requirements['schema']) is not int or requirements['schema'] != 1
                or requirements['source_inputs'] != 'image/portal/source-inputs.json'
                or requirements['source_inputs_sha256'] != source_hash
                or requirements['base_requirements'] != 'image/hyprland/build-requirements.json'
                or requirements['base_requirements_sha256'] != base_hash
                or requirements['hyprland_revision'] != pins['hyprland_revision']
                or base['hyprland_revision'] != pins['hyprland_revision']
                or len(set(expected)) != len(expected) or requirements['packages'] != expected):
            raise ValueError('Portal package scope differs from reviewed source requirements')
    except (KeyError, TypeError) as error:
        raise ValueError('Incomplete portal package selection') from error


def load_inputs(root):
    root = root.resolve()
    source_path = 'image/portal/source-inputs.json'
    source_bytes = regular_bytes(root, source_path)
    pins = unique_json(source_bytes)
    flake_path = 'image/portal/reviewed/Hyprland-flake.lock'
    if pins['hyprland_flake_lock']['path'] != flake_path:
        raise ValueError('Unexpected compositor lockfile path')
    flake_bytes = read_pinned(root, flake_path, pins['hyprland_flake_lock']['sha256'])
    if hashlib.sha1(b'blob '+str(len(flake_bytes)).encode()+b'\0'+flake_bytes).hexdigest() != pins['hyprland_flake_lock']['git_blob']:
        raise ValueError('Reviewed compositor lockfile Git blob changed')
    flake = unique_json(flake_bytes)
    compositor = unique_json(regular_bytes(root, 'image/hyprland/candidate-inputs.json'))
    require_source_selection(pins, flake, compositor)
    if set(pins['reused_input_bindings']) != REUSED_INPUTS:
        raise ValueError('Incomplete retained compositor bindings')
    bindings = {source_path: hashlib.sha256(source_bytes).hexdigest()}
    for relative, expected in pins['reused_input_bindings'].items():
        data = regular_bytes(root, relative, 2*1024**2)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('Retained compositor build input changed: '+relative)
        bindings[relative] = expected
    for component in pins['components']:
        files = component['reviewed_files']
        expected_files = {'VERSION', 'CMakeLists.txt', 'LICENSE'}
        expected_files.add('scripts/generateShaderIncludes.sh' if component['name'] == 'hyprtoolkit'
                           else 'hyprland-share-picker/CMakeLists.txt')
        if set(files) != expected_files or component['license'] != 'BSD-3-Clause':
            raise ValueError('Missing reviewed portal build/license files')
        for name, descriptor in files.items():
            relative = 'image/portal/reviewed/'+component['name']+'/'+name
            if descriptor['path'] != relative:
                raise ValueError('Unexpected reviewed component path')
            data = read_pinned(root, relative, descriptor['sha256'])
            if (len(data) != descriptor['bytes']
                    or hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() != descriptor['git_blob']):
                raise ValueError('Reviewed Git source blob changed')
            if name == 'VERSION' and data.decode().strip() != component['version']:
                raise ValueError('Reviewed component version changed')
            bindings[relative] = descriptor['sha256']
    base_bytes = regular_bytes(root, 'image/hyprland/build-requirements.json')
    requirements = unique_json(regular_bytes(root, 'image/portal/build-requirements.json'))
    require_package_selection(requirements, pins, unique_json(base_bytes),
                              bindings[source_path], hashlib.sha256(base_bytes).hexdigest())
    bindings[flake_path] = pins['hyprland_flake_lock']['sha256']
    bindings['image/hyprland/build-requirements.json'] = hashlib.sha256(base_bytes).hexdigest()
    return pins, requirements, bindings
