"""Fail-closed checks for observations of an exact retained Atomic development image."""
import hashlib
import json
import re

from image.boot.inputs import require_desktop_image
from image.signing import render as render_trust
from image.toolchain.reuse import unique_json

LIMITS = {'memory.max': '536870912', 'memory.swap.max': '0',
          'cpu.max': '100000 100000', 'pids.max': '64'}
OPTIONS = {'--source-imgref', '--target-imgref', '--enforce-container-sigpolicy',
           '--generic-image', '--via-loopback', '--filesystem'}


def validate_loaded_image(rows, image_id):
    try:
        if (not isinstance(rows, list) or len(rows) != 1
                or 'sha256:'+rows[0]['Id'].removeprefix('sha256:') != image_id
                or rows[0]['Architecture'] != 'amd64' or rows[0]['Os'] != 'linux'
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', rows[0]['Digest'])):
            raise ValueError('Loaded image identity, architecture or digest changed')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Malformed loaded image inspection') from error
    return rows[0]


def validate_report(report, expected):
    try:
        if (type(report['schema']) is not int or report['schema'] != 1
                or report['os_qualified'] is not False or report['guest_booted'] is not False
                or type(report['uid']) is not int or report['uid'] != 10001
                or report['cap_eff'] != '0000000000000000' or report['no_new_privileges'] != '1'
                or report['root_readonly'] is not True or report['interfaces'] != ['lo']
                or report['limits'] != LIMITS):
            raise ValueError('Image preflight isolation or qualification scope changed')
        if (any(report['os'].get(key) != value for key,value in expected['os'].items())
                or report['selinux'].get('SELINUX') != 'enforcing'
                or sorted(report['packages']) != sorted(expected['packages'])
                or report['bootc_version'] != 'bootc '+expected['bootc_version']
                or report['kernel']['version'] != expected['kernel']
                or report['root_fs']['root-fs-type'] not in (None, 'btrfs', 'ext4', 'xfs')
                or not isinstance(report['install_options'], list)
                or not OPTIONS.issubset(report['install_options'])):
            raise ValueError('Image kernel, installer, packages or SELinux configuration changed')
        if set(report['trust']) != set(expected['trust']):
            raise ValueError('Image trust configuration is incomplete')
        files = [report['kernel'][name] for name in ('vmlinuz', 'initramfs.img')]
        files += list(report['trust'].values())
        for item in files:
            if (type(item['bytes']) is not int or not 0 < item['bytes'] <= 1024**3
                    or type(item['uid']) is not int or item['uid'] != 0
                    or type(item['mode']) is not int or not 0 <= item['mode'] <= 0o777
                    or item['mode'] & 0o022 or not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])):
                raise ValueError('Unsafe, missing or malformed installed boot/trust file')
        for path, digest in expected['trust'].items():
            if report['trust'][path]['sha256'] != digest:
                raise ValueError('Image trust bytes differ from the approved policy: '+path)
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Malformed Atomic image preflight report') from error
    return {'filesystem_default': report['root_fs']['root-fs-type'],
            'filesystem_argument_required': report['root_fs']['root-fs-type'] is None}


def expected_inputs(root, lock, pins, variant):
    manifest = require_desktop_image(lock, pins, variant)
    selected = lock['images'][variant]
    flavor = {'generic':'sericea-main-hardened', 'nvidia':'sericea-nvidia-hardened'}[variant]
    if not manifest['base'].startswith('ghcr.io/secureblue/'+flavor+'@sha256:'):
        raise ValueError('Unreviewed Atomic distribution identity')
    os_identity = {'ID':'secureblue', 'ID_LIKE':'fedora', 'VERSION_ID':'45',
                   'VARIANT_ID':flavor, 'IMAGE_ID':flavor}
    evidence = root/'docs/security/reports/P0-03-desktop'/str(selected['run_id'])
    if evidence.resolve() != evidence: raise ValueError('Linked retained evidence path')
    raw = (evidence/'preparation.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['preparation_sha256']:
        raise ValueError('Retained image preparation differs from the exact manifest')
    prepared = unique_json(raw)
    if (prepared['source_commit'] != selected['tested_commit'] or prepared['variant'] != variant
            or prepared['passed'] is not True or prepared['base'] != manifest['base']):
        raise ValueError('Wrong retained image preparation')
    inventory = (evidence/'install/installed-after-stdout.log').read_text().splitlines()
    packages = [line for line in inventory if line.split('\t')[0] in ('bootc', 'kernel-core')]
    rows = {line.split('\t')[0]: line.split('\t') for line in packages}
    if (len(packages) != 2 or set(rows) != {'bootc', 'kernel-core'}
            or any(len(row) != 5 or row[4] != 'x86_64' for row in rows.values())):
        raise ValueError('Expected exactly one retained bootc and kernel-core identity')
    kernel = rows['kernel-core']
    kernel_version = kernel[2]+'-'+kernel[3]+'.'+kernel[4]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{1,127}', kernel_version):
        raise ValueError('Unsafe retained kernel version')
    bundle = render_trust(unique_json((root/'image/release-trust.json').read_bytes()), pins, root)
    trust = {}
    for path, key in [('etc/containers/policy.json', 'policy'),
                      ('etc/containers/registries.d/symbiont.yaml', 'registries')]:
        digest = hashlib.sha256((json.dumps(bundle[key], indent=2)+'\n').encode()).hexdigest()
        if prepared['payload'][path]['sha256'] != digest:
            raise ValueError('Retained installed trust differs from current approved public inputs')
        trust[path] = digest
    return {'os': os_identity, 'kernel': kernel_version, 'bootc_version': rows['bootc'][2], 'packages': packages, 'trust': trust}
