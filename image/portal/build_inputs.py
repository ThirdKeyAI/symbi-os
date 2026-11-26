"""Validate native portal inputs and actual test reports before retaining output."""
import hashlib
from pathlib import PurePosixPath
import re
import xml.etree.ElementTree as ET


def require_prefix_bindings(manifest, lock, sources, base, rpm_hash, patch_hash):
    try:
        expected = {'Hyprland': ('https://github.com/hyprwm/Hyprland.git', sources['hyprland_revision']),
                    'glaze': ('https://github.com/stephenberry/glaze.git', sources['glaze']['revision']),
                    'Hyprland/subprojects/udis86': ('https://github.com/canihavesomecoffee/udis86.git',
                        next(row['revision'] for row in sources['submodules'] if row['path'] == 'subprojects/udis86'))}
        for row in sources['libraries']:
            if row['owner'] != 'hyprwm' or row['repo'] != row['name'] or row['name'] in expected:
                raise ValueError('Unexpected retained compositor library')
            expected[row['name']] = ('https://github.com/hyprwm/'+row['name']+'.git', row['rev'])
        actual = manifest['source_revisions']
        if (manifest['compiled'] is not True or manifest['os_qualified'] is not False
                or manifest['base'] != base or manifest['source_commit'] != lock['tested_merge']
                or manifest['rpm_lock_sha256'] != rpm_hash or manifest['native_patch_sha256'] != patch_hash
                or len(actual) != len(expected)
                or {row['name']: (row['url'], row['rev']) for row in actual} != expected):
            raise ValueError('Retained compositor source/build bindings changed')
    except (KeyError, TypeError, StopIteration) as error:
        raise ValueError('Incomplete retained compositor bindings') from error


def require_rpm_bindings(lock, requirements, base, trust):
    try:
        if (type(lock['schema']) is not int or lock['schema'] != 1
                or lock['qualified'] is not False or lock['product_installation'] is not False
                or lock['base'] != base or lock['key'] != trust['key']
                or lock['requirements'] != requirements
                or lock['source_inputs_sha256'] != requirements['source_inputs_sha256']):
            raise ValueError('Portal RPM lock does not match the reviewed build profile')
    except (KeyError, TypeError) as error:
        raise ValueError('Incomplete portal build package bindings') from error


def require_source_tree(root, component, revision):
    if (root.is_symlink() or not root.is_dir() or root.resolve() != root
            or revision != component['revision'] or not re.fullmatch(r'[0-9a-f]{40}', revision)):
        raise ValueError('Portal checkout differs from selected revision')
    for name, descriptor in component['reviewed_files'].items():
        relative = PurePosixPath(name)
        path = root/relative
        if (relative.is_absolute() or '..' in relative.parts or relative.as_posix() != name
                or path.is_symlink() or not path.is_file() or path.resolve() != path
                or path.stat().st_size > 128*1024 or path.stat().st_size != descriptor['bytes']):
            raise ValueError('Portal checkout review input is not the exact regular file')
        if hashlib.sha256(path.read_bytes()).hexdigest() != descriptor['sha256']:
            raise ValueError('Portal checkout bytes differ from reviewed source')


def require_test_report(raw, *, expected_cases=None):
    if not isinstance(raw, bytes) or len(raw) > 1024**2 or b'\x00' in raw:
        raise ValueError('Unexpected or oversized native test report')
    try:
        decoded = raw.decode('utf-8')
        if '<!DOCTYPE' in decoded.upper() or '<!ENTITY' in decoded.upper():
            raise ValueError('Native test report declarations are forbidden')
        root = ET.fromstring(decoded)
        if root.tag not in ('testsuite', 'testsuites'):
            raise ValueError('Missing native test suite')
        cases = list(root.iter('testcase'))
        if not cases or int(root.attrib['tests']) != len(cases):
            raise ValueError('Empty or incomplete native test result')
        for suite in (element for element in root.iter() if element.tag in ('testsuite', 'testsuites')):
            if int(suite.attrib['tests']) != len(list(suite.iter('testcase'))):
                raise ValueError('Native test suite accounting differs')
            if any(int(suite.attrib.get(name, '0')) != 0 for name in ('failures', 'errors', 'disabled', 'skipped')):
                raise ValueError('Native test report contains failed or skipped tests')
        names = []
        for case in cases:
            if (not case.attrib.get('name') or case.attrib.get('status', 'run') != 'run'
                    or case.attrib.get('result', 'completed') != 'completed'
                    or any(child.tag in ('failure', 'error', 'skipped') for child in case.iter())):
                raise ValueError('Native testcase did not complete successfully')
            names.append((case.attrib.get('classname', '')+'.').lstrip('.')+case.attrib['name'])
        if len(set(names)) != len(names):
            raise ValueError('Duplicate native testcase')
        if expected_cases is not None and names != expected_cases:
            raise ValueError('Unexpected native test selection')
        return names
    except (ET.ParseError, KeyError, TypeError) as error:
        raise ValueError('Malformed native test report') from error
