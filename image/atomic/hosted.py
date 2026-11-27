"""Install and boot an exact retained image, exclusively on disposable hosted CI."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import re
import stat

from image.atomic.contract import (create_disk,require_disk,sha256,unique_json,
                                   unpack_oci,validate_report,installer_mounts,
                                   directory_source,installer_policy)
from image.atomic.update_contract import negative_signature_payloads
from image.atomic.update_process import TIMEOUT_SECONDS,run_update_controller
from image.boot.inputs import require_desktop_image
from image.boot.preflight import expected_inputs,validate_loaded_image,validate_report as validate_preflight
from image.launcher.probes.bounded_process import run_bounded
from image.qualification.hosted_process import (TIMEOUT_SECONDS as LANDLOCK_TIMEOUT_SECONDS,
                                                run_landlock_controller)


LANDLOCK_PARENT_LIMITS = {'memory.high':'4294967296','memory.max':'5368709120',
                          'memory.swap.max':'0','cpu.max':'200000 100000','pids.max':'256'}
CONTAINER_PARENT_LIMITS = {'memory.high':'max','memory.max':'4294967296',
                           'memory.swap.max':'0','cpu.max':'200000 100000','pids.max':'256'}
DEFAULT_PARENT_LIMITS = {'memory.high':'max','memory.max':'5368709120',
                         'memory.swap.max':'0','cpu.max':'200000 100000','pids.max':'256'}


def run_hosted_command(qualification,name,command,stdout_path,stderr_path,timeout,
                       expected_cgroup_parent=None,expected_image=None):
    """Select the one command allowed beyond the shared process deadline."""
    if name=='landlock-qualification':
        if qualification!='landlock' or timeout!=LANDLOCK_TIMEOUT_SECONDS:
            raise ValueError('Invalid hosted Landlock controller deadline')
        return run_landlock_controller(command,stdout_path,stderr_path,
                                       expected_cgroup_parent,expected_image)
    return run_bounded(command,stdout_path,stderr_path,timeout,1024**2)


RETAINED_REPORT_MAX_BYTES = 1024**2
RETAINED_PREFLIGHT_LIMITS = {
    'prepare': {'memory.max': '1073741824', 'memory.swap.max': '0',
                'cpu.max': '100000 100000', 'pids.max': '64'},
    'inspect': {'memory.max': '4294967296', 'memory.swap.max': '0',
                'cpu.max': '200000 100000', 'pids.max': '256'},
}
RETAINED_PREFLIGHT_SCOPE = (
    'Read-only saved development image preflight; no disk, installation, boot or '
    'release qualification')
RETAINED_PREFLIGHT_KEYS = {
    'prepare': {'schema', 'phase', 'passed', 'source_commit', 'image_source_commit',
                'variant', 'base', 'expected_inputs', 'guest_booted', 'os_qualified',
                'installation_attempted', 'lock_sha256', 'limits', 'cgroup_final',
                'scope', 'commands', 'artifact', 'verified_archive'},
    'inspect': {'schema', 'phase', 'passed', 'source_commit', 'image_source_commit',
                'variant', 'base', 'expected_inputs', 'guest_booted', 'os_qualified',
                'installation_attempted', 'lock_sha256', 'limits', 'cgroup_final',
                'scope', 'commands', 'disk_free_before_load', 'loaded_image',
                'probe_hashes', 'installed_files', 'install_requirements',
                'boot_inputs', 'kernel_copy', 'cleanup', 'image_removed'},
}
RETAINED_INSPECT_COMMANDS = [
    {'name': name, 'exit_code': exit_code}
    for name, exit_code in (
        ('load-image', 0), ('inspect-image', 0), ('create-kernel-copy', 0),
        ('kernel-copy-before', 0), ('copy-vmlinuz', 0),
        ('copy-initramfs.img', 0), ('kernel-copy-after', 0),
        ('installed-files', 0), ('boot-inputs', 0),
        ('cleanup-symbi-atomic-kernel-copy', 0),
        ('absent-symbi-atomic-kernel-copy', 1),
        ('cleanup-symbi-atomic-installed-files', 0),
        ('absent-symbi-atomic-installed-files', 1),
        ('cleanup-symbi-atomic-boot-inputs', 0),
        ('absent-symbi-atomic-boot-inputs', 1), ('remove-image', 0),
        ('image-absent', 1))
]
RETAINED_RECONCILIATION_CHECKS = [
    'GitHub reports success for the exact workflow head and all workflow steps',
    'The original evidence ZIP size and SHA-256 match authenticated artifact metadata',
    'Both retained reports match their lock hashes and reject duplicate JSON keys',
    'The exact complete desktop-image lock, generic artifact, image source and manifest match',
    'Installed inputs, boot inputs and cleanup passed without swap, OOM or OOM kill',
]
CONTAINER_QUALIFICATION_BLOCKERS = (
    'native-fedora-six-run-matrix', 'managed-route-evidence',
    'escape-suite-evidence', 'required-review',
)
RETAINED_BOOT_INPUT_KEYS = {
    'schema', 'os_qualified', 'guest_booted', 'uid', 'cap_eff',
    'no_new_privileges', 'root_readonly', 'interfaces', 'limits', 'os',
    'selinux', 'packages', 'bootc_version', 'kernel', 'root_fs',
    'install_configuration', 'install_options', 'trust', 'backend_files',
    'tools', 'commands', 'cgroup_final', 'kernel_source_sha256', 'scope',
}
RETAINED_BACKEND_FILES = {
    '/usr/lib/ostree/prepare-root.conf': {
        'bytes': 52,
        'mode': 0o644,
        'sha256': '06e212012ede5dfecf598f8cdb57bdb17450bb2a3e957598d2e0d23effff10d7',
        'text': '[composefs]\nenabled = yes\n[sysroot]\nreadonly = true\n',
        'uid': 0,
    },
}
RETAINED_TOOLS = {
    name: {'path': '/usr/bin/' + name, 'present': True}
    for name in ('bootc', 'bootupctl', 'grub2-install', 'grub2-mkconfig',
                 'mkfs.btrfs', 'mkfs.ext4', 'mkfs.xfs', 'qemu-img',
                 'qemu-system-x86_64', 'xorriso')
}


def _exact_hex(value, length):
    return (isinstance(value, str)
            and re.fullmatch(r'[0-9a-f]{' + str(length) + r'}', value) is not None)


def _validate_retained_json(value):
    """Reject non-JSON numbers such as NaN and unexpected real-valued fields."""
    if value is None or isinstance(value, (str, bool)) or type(value) is int:
        return
    if isinstance(value, list):
        for item in value:
            _validate_retained_json(item)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for item in value.values():
            _validate_retained_json(item)
        return
    raise ValueError('Retained preflight contains a noncanonical JSON value')


def _read_retained_report(directory, name):
    """Read one bounded regular report once from an already checked directory."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except OSError as error:
        raise ValueError('Retained preflight report is not a direct regular file') from error
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not 0 < info.st_size <= RETAINED_REPORT_MAX_BYTES):
            raise ValueError('Retained preflight report is not a bounded regular file')
        with os.fdopen(descriptor, 'rb', closefd=False) as source:
            raw = source.read(RETAINED_REPORT_MAX_BYTES + 1)
        final = os.fstat(descriptor)
        if (len(raw) != info.st_size or final.st_dev != info.st_dev
                or final.st_ino != info.st_ino or final.st_mode != info.st_mode
                or final.st_nlink != info.st_nlink or final.st_size != info.st_size):
            raise ValueError('Retained preflight report changed while reading')
        return raw
    finally:
        os.close(descriptor)


def _validate_retained_resources(item, phase):
    limits = RETAINED_PREFLIGHT_LIMITS[phase]
    final = item.get('cgroup_final')
    expected_final = set(limits) | {'memory.peak', 'memory.events', 'cpu.stat'}
    if (item.get('limits') != limits or not isinstance(final, dict)
            or set(final) != expected_final
            or any(final.get(name) != value for name, value in limits.items())
            or not isinstance(final.get('memory.peak'), str)
            or not final['memory.peak'].isdigit()
            or not isinstance(final.get('cpu.stat'), str)
            or not final['cpu.stat'].strip()):
        raise ValueError('Retained preflight resource record changed')
    if int(final['memory.peak']) > int(limits['memory.max']) + 4096:
        raise ValueError('Retained preflight exceeded its memory limit')
    _validate_no_oom(final)


def _validate_no_oom(final):
    if (not isinstance(final, dict)
            or not isinstance(final.get('memory.peak'), str)
            or not final['memory.peak'].isdigit()
            or not isinstance(final.get('cpu.stat'), str)
            or not final['cpu.stat'].strip()
            or not isinstance(final.get('memory.events'), str)):
        raise ValueError('Retained preflight resource record changed')
    events = {}
    for line in final['memory.events'].splitlines():
        fields = line.split()
        if (len(fields) != 2 or fields[0] in events
                or not fields[1].isdigit()):
            raise ValueError('Malformed retained preflight memory events')
        events[fields[0]] = fields[1]
    if set(events) != {'low', 'high', 'max', 'oom', 'oom_kill',
                       'oom_group_kill', 'sock_throttled'}:
        raise ValueError('Malformed retained preflight memory events')
    if any(events.get(name) != '0' for name in ('oom', 'oom_kill', 'oom_group_kill')):
        raise ValueError('Retained preflight observed an OOM event')
    return events


def _validate_retained_envelope(item, phase, readiness, selected, manifest,
                                expected, current_lock):
    if (not isinstance(item, dict) or set(item) != RETAINED_PREFLIGHT_KEYS[phase]
            or type(item.get('schema')) is not int
            or item.get('schema') != 1 or item.get('phase') != phase
            or item.get('passed') is not True
            or item.get('source_commit') != readiness['source_commit']
            or item.get('image_source_commit') != selected['tested_commit']
            or item.get('variant') != 'generic'
            or item.get('base') != manifest['base']
            or item.get('expected_inputs') != expected
            or item.get('guest_booted') is not False
            or item.get('os_qualified') is not False
            or item.get('installation_attempted') is not False
            or item.get('lock_sha256') != current_lock
            or item.get('scope') != RETAINED_PREFLIGHT_SCOPE
            or item.get('commands') != (
                RETAINED_INSPECT_COMMANDS if phase == 'inspect' else [])):
        raise ValueError('Exact saved-image preflight has not passed')
    _validate_retained_resources(item, phase)


def _validate_retained_reconciliation(item, readiness, selected, current_lock,
                                      reports):
    keys = {'schema', 'passed', 'workflow_run', 'workflow', 'source_commit',
            'variant', 'image_source_commit', 'manifest_digest',
            'desktop_images_lock_sha256', 'retained_reports', 'evidence_artifact',
            'development_image_artifact', 'checks', 'resource_observation',
            'os_qualified', 'release_qualified', 'scope'}
    evidence = item.get('evidence_artifact') if isinstance(item, dict) else None
    development = item.get('development_image_artifact') if isinstance(item, dict) else None
    resources = item.get('resource_observation') if isinstance(item, dict) else None
    expected_reports = {phase + '.json': readiness[phase + '_sha256']
                        for phase in ('inspect', 'prepare')}
    inspect_final = reports['inspect']['cgroup_final']
    events = _validate_no_oom(inspect_final)
    expected_resources = {
        'prepare_memory_peak_bytes': int(reports['prepare']['cgroup_final']['memory.peak']),
        'inspect_memory_peak_bytes': int(inspect_final['memory.peak']),
        'inspect_memory_max_events': int(events['max']),
        'swap_max_bytes': 0,
        'oom': 0,
        'oom_kill': 0,
        'oom_group_kill': 0,
    }
    selected_artifact = selected['artifact']
    if (not isinstance(item, dict) or set(item) != keys
            or type(item.get('schema')) is not int or item.get('schema') != 1
            or item.get('passed') is not True
            or item.get('workflow_run') != readiness['preflight_run']
            or item.get('workflow') != 'Atomic image preflight'
            or item.get('source_commit') != readiness['source_commit']
            or item.get('variant') != 'generic'
            or item.get('image_source_commit') != selected['tested_commit']
            or item.get('manifest_digest') != readiness['manifest_digest']
            or item.get('desktop_images_lock_sha256') != current_lock
            or item.get('retained_reports') != expected_reports
            or not isinstance(evidence, dict)
            or set(evidence) != {'id', 'name', 'bytes', 'sha256', 'expires_at'}
            or type(evidence.get('id')) is not int or evidence['id'] <= 0
            or evidence.get('id') != readiness['evidence_artifact_id']
            or evidence.get('name') != 'atomic-image-preflight-generic'
            or type(evidence.get('bytes')) is not int
            or not 0 < evidence['bytes'] <= RETAINED_REPORT_MAX_BYTES
            or evidence.get('bytes') != readiness['evidence_artifact_bytes']
            or not _exact_hex(evidence.get('sha256'), 64)
            or evidence.get('sha256') != readiness['evidence_artifact_sha256']
            or not isinstance(evidence.get('expires_at'), str)
            or not isinstance(development, dict)
            or set(development) != {'id', 'name', 'bytes', 'sha256'}
            or development != {'id': selected_artifact['id'],
                               'name': selected_artifact['name'],
                               'bytes': selected_artifact['bytes'],
                               'sha256': selected_artifact['sha256']}
            or item.get('checks') != RETAINED_RECONCILIATION_CHECKS
            or not isinstance(resources, dict) or resources != expected_resources
            or item.get('os_qualified') is not False
            or item.get('release_qualified') is not False
            or item.get('scope') != ('Exact generic development-image preflight; no '
                                     'installation, boot, update, NVIDIA, desktop or '
                                     'release qualification')):
        raise ValueError('Independent preflight reconciliation changed')


def _validate_retained_boot_inputs(item, expected):
    final = item.get('cgroup_final') if isinstance(item, dict) else None
    if (not isinstance(final, dict)
            or set(final) != {'memory.peak', 'memory.events', 'cpu.stat'}):
        raise ValueError('Retained boot-input resource record changed')
    _validate_no_oom(final)
    if int(final['memory.peak']) > int(item['limits']['memory.max']) + 4096:
        raise ValueError('Retained boot-input probe exceeded its memory limit')
    if (item.get('backend_files') != RETAINED_BACKEND_FILES
            or item.get('tools') != RETAINED_TOOLS
            or item.get('install_configuration') != item.get('root_fs')):
        raise ValueError('Retained boot-input provenance changed')
    commands = item.get('commands')
    expected_commands = [
        ['/usr/bin/rpm', '-q', 'bootc', 'kernel-core', '--qf',
         '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'],
        ['/usr/bin/bootc', '--version'],
        ['/usr/bin/bootc', 'install', 'print-configuration'],
        ['/usr/bin/bootc', 'install', 'print-configuration', '--all'],
        ['/usr/bin/bootc', 'install', 'to-disk', '--help'],
    ]
    if (not isinstance(commands, list) or len(commands) != len(expected_commands)
            or any(not isinstance(row, dict)
                   or set(row) != {'command', 'exit_code', 'stderr', 'stdout'}
                   or row.get('command') != command
                   or row.get('exit_code') != 0 or row.get('stderr') != ''
                   or not isinstance(row.get('stdout'), str) or not row['stdout']
                   for row, command in zip(commands, expected_commands))
            or commands[0]['stdout'].splitlines() != expected['packages']
            or commands[1]['stdout'] != 'bootc ' + expected['bootc_version'] + '\n'):
        raise ValueError('Retained boot-input command history changed')
    for row in commands[2:4]:
        if unique_json(row['stdout'].encode()) != item['root_fs']:
            raise ValueError('Retained boot-input configuration output changed')
    if any(option not in commands[4]['stdout'] for option in
           ('--source-imgref', '--target-imgref', '--enforce-container-sigpolicy',
            '--generic-image', '--via-loopback', '--filesystem')):
        raise ValueError('Retained boot-input installer help is incomplete')


def validate_retained_preflight(root, readiness, selected, manifest, expected):
    """Authenticate the retained generic preflight against the current image lock."""
    readiness_keys = {'schema', 'variant', 'preflight_run', 'source_commit',
                      'inspect_sha256', 'prepare_sha256',
                      'independent_check_sha256', 'manifest_digest',
                      'kernel_observation_sha256', 'repository_id',
                      'evidence_artifact_id', 'evidence_artifact_bytes',
                      'evidence_artifact_sha256'}
    if (not isinstance(readiness, dict) or set(readiness) != readiness_keys
            or type(readiness.get('schema')) is not int
            or readiness.get('schema') != 1 or readiness.get('variant') != 'generic'
            or type(readiness.get('repository_id')) is not int
            or readiness['repository_id'] <= 0
            or type(readiness.get('evidence_artifact_id')) is not int
            or readiness['evidence_artifact_id'] <= 0
            or type(readiness.get('evidence_artifact_bytes')) is not int
            or not 0 < readiness['evidence_artifact_bytes'] <= RETAINED_REPORT_MAX_BYTES
            or not _exact_hex(readiness.get('evidence_artifact_sha256'), 64)
            or type(readiness.get('preflight_run')) is not int
            or readiness['preflight_run'] <= 0
            or not _exact_hex(readiness.get('source_commit'), 40)
            or any(not _exact_hex(readiness.get(name + '_sha256'), 64)
                   for name in ('inspect', 'prepare', 'independent_check'))
            or not _exact_hex(readiness.get('kernel_observation_sha256'), 64)
            or not isinstance(readiness.get('manifest_digest'), str)
            or re.fullmatch(r'sha256:[0-9a-f]{64}', readiness['manifest_digest']) is None):
        raise ValueError('Unknown preflight readiness binding')
    previous = root / 'docs/security/reports/P0-03-atomic-preflight' / str(
        readiness['preflight_run'])
    try:
        previous_info = previous.lstat()
    except OSError as error:
        raise ValueError('Missing preflight evidence directory') from error
    if (previous.resolve() != previous
            or not stat.S_ISDIR(previous_info.st_mode)):
        raise ValueError('Linked preflight evidence')
    reports = {}
    current_lock = sha256(root / 'image/desktop-images.lock.json')
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        directory = os.open(previous, flags)
    except OSError as error:
        raise ValueError('Preflight evidence directory is not direct') from error
    try:
        opened_info = os.fstat(directory)
        if (opened_info.st_dev != previous_info.st_dev
                or opened_info.st_ino != previous_info.st_ino
                or not stat.S_ISDIR(opened_info.st_mode)):
            raise ValueError('Preflight evidence directory changed while opening')
        for name in ('inspect', 'prepare', 'independent_check'):
            raw = _read_retained_report(directory, name.replace('_', '-') + '.json')
            if hashlib.sha256(raw).hexdigest() != readiness[name + '_sha256']:
                raise ValueError('Preflight evidence bytes changed')
            item = unique_json(raw)
            _validate_retained_json(item)
            reports[name] = item
            if name != 'independent_check':
                _validate_retained_envelope(item, name, readiness, selected, manifest,
                                            expected, current_lock)
    finally:
        os.close(directory)
    _validate_retained_reconciliation(reports['independent_check'], readiness,
                                      selected, current_lock, reports)
    artifact = reports['prepare'].get('artifact', {})
    selected_artifact = selected['artifact']
    workflow = artifact.get('workflow_run', {}) if isinstance(artifact, dict) else {}
    artifact_keys = {'id', 'node_id', 'name', 'size_in_bytes', 'url',
                     'archive_download_url', 'expired', 'digest', 'created_at',
                     'updated_at', 'expires_at', 'workflow_run'}
    workflow_keys = {'id', 'repository_id', 'head_repository_id', 'head_branch',
                     'head_sha'}
    if (not isinstance(artifact, dict) or set(artifact) != artifact_keys
            or not isinstance(workflow, dict) or set(workflow) != workflow_keys
            or artifact.get('id') != selected_artifact['id']
            or artifact.get('name') != selected_artifact['name']
            or artifact.get('size_in_bytes') != selected_artifact['bytes']
            or artifact.get('digest') != 'sha256:' + selected_artifact['sha256']
            or artifact.get('expired') is not False
            or workflow.get('id') != selected['run_id']
            or workflow.get('repository_id') != readiness['repository_id']
            or workflow.get('head_repository_id') != readiness['repository_id']
            or workflow.get('head_sha') != selected['tested_commit']):
        raise ValueError('Retained preflight used a different hosted image artifact')
    inspect = reports['inspect']
    boot_inputs = inspect.get('boot_inputs')
    requirements = validate_preflight(boot_inputs, expected)
    loaded = validate_loaded_image([inspect.get('loaded_image')],
                                   manifest['archive']['image_id'])
    installed = inspect.get('installed_files')
    kernel_copy = inspect.get('kernel_copy')
    cleanup = inspect.get('cleanup')
    cleanup_names = {'symbi-atomic-kernel-copy', 'symbi-atomic-installed-files',
                     'symbi-atomic-boot-inputs'}
    installed_keys = {'passed', 'os_qualified', 'installed_files_checked',
                      'installed_package_count',
                      'all_package_identities_preserved_after_build', 'fonts',
                      'uid', 'limits', 'scope'}
    fonts = installed.get('fonts') if isinstance(installed, dict) else None
    font_keys = {'checked', 'scanned_fonts', 'families', 'monospace_family',
                 'monospace_file'}
    if (not isinstance(inspect.get('loaded_image'), dict)
            or set(inspect['loaded_image']) != {'Id', 'Digest', 'Architecture', 'Os'}
            or type(inspect.get('disk_free_before_load')) is not int
            or inspect['disk_free_before_load'] <= 0
            or not isinstance(installed, dict) or set(installed) != installed_keys
            or installed.get('passed') is not True
            or installed.get('os_qualified') is not False
            or installed.get('installed_files_checked') != 212
            or installed.get('installed_package_count') != 2184
            or installed.get('all_package_identities_preserved_after_build') is not True
            or installed.get('uid') != 10001
            or installed.get('limits') != boot_inputs.get('limits')
            or installed.get('scope') != ('Installed bytes and native font parsing '
                                          'only; no boot or containment qualification')
            or not isinstance(fonts, dict) or set(fonts) != font_keys
            or fonts.get('checked') is not True
            or fonts.get('scanned_fonts') != 98
            or not isinstance(fonts.get('families'), list)
            or len(fonts['families']) != 50
            or any(not isinstance(family, str) or not family for family in fonts['families'])
            or len(set(fonts['families'])) != 50
            or not {'JetBrainsMono Nerd Font', 'JetBrainsMono Nerd Font Mono',
                    'Symbols Nerd Font'}.issubset(fonts['families'])
            or fonts.get('monospace_family') != 'JetBrainsMono Nerd Font'
            or fonts.get('monospace_file') != ('/usr/share/fonts/symbi-nerd-fonts/'
                                                'JetBrainsMono/'
                                                'JetBrainsMonoNerdFont-Regular.ttf')
            or not isinstance(boot_inputs, dict)
            or set(boot_inputs) != RETAINED_BOOT_INPUT_KEYS
            or boot_inputs.get('scope') != ('Read-only installed boot inputs; SELinux '
                                             'enforcement, actual installation and boot '
                                             'remain untested')
            or inspect.get('install_requirements') != requirements):
        raise ValueError('Retained installed-payload preflight is incomplete')
    _validate_retained_boot_inputs(boot_inputs, expected)
    expected_probe_hashes = {
        'probe.py': sha256(root / 'image/boot/probe.py'),
        'verify.py': sha256(root / 'image/desktop/verify.py'),
        'font_verify.py': sha256(root / 'image/fonts/verify.py'),
        'expected.json': hashlib.sha256((json.dumps(expected) + '\n').encode()).hexdigest(),
    }
    if inspect.get('probe_hashes') != expected_probe_hashes:
        raise ValueError('Retained preflight probe inputs changed')
    kernel_observation = hashlib.sha256(
        (json.dumps(boot_inputs['kernel'], sort_keys=True) + '\n').encode()).hexdigest()
    if (not isinstance(kernel_copy, dict)
            or set(kernel_copy) != {'source_container', 'never_started', 'kernel',
                                    'private_payload_removed', 'observation_sha256'}
            or kernel_copy.get('source_container') != 'symbi-atomic-kernel-copy'
            or kernel_copy.get('never_started') is not True
            or kernel_copy.get('private_payload_removed') is not True
            or kernel_copy.get('kernel') != boot_inputs['kernel']
            or kernel_observation != readiness['kernel_observation_sha256']
            or kernel_copy.get('observation_sha256') != kernel_observation
            or boot_inputs.get('kernel_source_sha256') != kernel_observation):
        raise ValueError('Retained protected-kernel observation is incomplete')
    if (not isinstance(cleanup, dict) or set(cleanup) != cleanup_names
            or any(cleanup.get(name) != {'removed': True, 'absent': True}
                   for name in cleanup_names)
            or inspect.get('image_removed') is not True):
        raise ValueError('Retained preflight cleanup is incomplete')
    if (loaded['Digest'] != readiness['manifest_digest']
            or reports['prepare'].get('verified_archive') != manifest['archive']):
        raise ValueError('Preflight describes a different OCI image')
    return reports


def stop_after_container_candidate_boot(record,observation):
    """Retain the first-boot result while making incomplete qualification fail."""
    blockers=list(CONTAINER_QUALIFICATION_BLOCKERS)
    if (not isinstance(record,dict) or not isinstance(observation,dict)
            or record.get('container_preflight',{}).get('blockers')!=blockers):
        raise ValueError('Container candidate boot lost an explicit qualification blocker')
    record.update({
        'passed':False,
        'qualified':False,
        'container_qualified':False,
        'os_qualified':False,
        'release_qualified':False,
        'native_fixture_matrix_passed':False,
        'managed_route_qualified':False,
        'escape_suite_qualified':False,
        'candidate_boot_passed':True,
        'container_candidate_observation':observation,
        'remaining_blockers':blockers,
    })
    raise ValueError('Container candidate boot passed; qualification remains blocked: '
                     +','.join(blockers))


def main():
    qualification=os.environ.get('SYMBI_QUALIFICATION','')
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
            or os.environ.get('SYMBI_IMAGE_VARIANT')!='generic' or qualification not in ('','landlock','update','containers')
            or os.geteuid()!=0):
        raise SystemExit('Use the disposable hosted generic Atomic install/boot unit')
    root=Path.cwd().resolve()
    process=Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]).relative_to('/')
    group=process.parent
    unit_prefix={'landlock':'symbi-landlock-','containers':'symbi-container-'}.get(
        qualification,'symbi-atomic-disk-')
    if (process.name!='supervisor' or not group.name.startswith(unit_prefix)
            or not group.name.endswith('.service') or (group/'cgroup.procs').read_text().strip()):
        raise ValueError('Unexpected delegated installer controller')
    limits={n:(group/n).read_text().strip() for n in
            ('memory.high','memory.max','memory.swap.max','cpu.max','pids.max')}
    expected_limits=(LANDLOCK_PARENT_LIMITS if qualification=='landlock'
                     else CONTAINER_PARENT_LIMITS if qualification=='containers'
                     else DEFAULT_PARENT_LIMITS)
    if limits!=expected_limits:
        raise ValueError('Hosted Atomic resource limits changed')
    required={'cpu','memory','pids'}
    if not required.issubset((group/'cgroup.controllers').read_text().split()): raise ValueError('Missing delegation')
    (group/'cgroup.subtree_control').write_text('+cpu +memory +pids')
    if not required.issubset((group/'cgroup.subtree_control').read_text().split()): raise ValueError('Delegation failed')
    evidence=root/'.cache/atomic-disk-evidence';evidence.mkdir(parents=True,exist_ok=True)
    lock=unique_json((root/'image/desktop-images.lock.json').read_bytes())
    pins=unique_json((root/'image/base-images.json').read_bytes())
    manifest=require_desktop_image(lock,pins,'generic');selected=lock['images']['generic']
    expected=expected_inputs(root,lock,pins,'generic')
    record={'schema':1,'passed':False,'installation_attempted':False,'guest_booted':False,
            'os_qualified':False,'release_qualified':False,'source_commit':os.environ['GITHUB_SHA'],
            'image_source_commit':selected['tested_commit'],'image_id':manifest['archive']['image_id'],
            'limits':limits,'commands':[],'qualification':qualification or None,
            'scope':'Offline development artifact authenticated with an ephemeral CI fixture key; no product/release qualification'}
    def save(): (evidence/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    def run(name,command,timeout=60,check=True):
        record['active_command']={'name':name,'command':command};save()
        if name=='signed-update-and-rollback':
            if timeout!=TIMEOUT_SECONDS: raise ValueError('Fixed Atomic controller deadline changed')
            result=run_update_controller(command,evidence/(name+'-stdout.log'),
                                         evidence/(name+'-stderr.log'))
        else:
            result=run_hosted_command(qualification,name,command,evidence/(name+'-stdout.log'),
                                      evidence/(name+'-stderr.log'),timeout,
                                      '/'+str(group.relative_to('/sys/fs/cgroup')),
                                      record['image_id'])
        record['commands'].append({'name':name,'exit_code':result.returncode});del record['active_command'];save()
        if check: result.check_returncode()
        return result
    podman=None;containers=[];storage=None;storage_identity=None;disk=None;identity=None;boot_output=None;runroot=None;disk_readonly=False;signing_output=None
    container_candidate=None;manifest_digest=None
    try:
        if qualification=='containers':
            from image.qualification.container_hosted import run_container_preflight
            record['container_preflight']=run_container_preflight(
                root,record['source_commit'],record['image_source_commit'])
            save()
            remaining=list(CONTAINER_QUALIFICATION_BLOCKERS)
            invalid=(record['container_preflight'].get('passed') is not True
                    or record['container_preflight'].get('qualified') is not False
                    or record['container_preflight'].get('os_qualified') is not False
                    or record['container_preflight'].get('release_qualified') is not False
                    or record['container_preflight'].get('native_fixture_matrix_passed') is not False
                    or record['container_preflight'].get('managed_route_qualified') is not False
                    or record['container_preflight'].get('escape_suite_qualified') is not False
                    or record['container_preflight'].get('blockers')!=remaining)
            if invalid:
                blockers=record['container_preflight'].get('blockers')
                if (not isinstance(blockers,list) or not blockers
                        or any(not isinstance(item,str) for item in blockers)):
                    blockers=['invalid-container-preflight']
                raise ValueError('Fedora container inputs remain fail closed: '+','.join(blockers))
            container_candidate=record['container_preflight'].get('container_boot')
            candidate_fields={'archive','generated_manifest_sha256','contract_sha256',
                              'runsc_files','daemon_configuration_sha256','inventory_sha256',
                              'qualified','os_qualified','release_qualified','remaining_blocker'}
            if (not isinstance(container_candidate,dict) or set(container_candidate)!=candidate_fields
                    or container_candidate.get('qualified') is not False
                    or container_candidate.get('os_qualified') is not False
                    or container_candidate.get('release_qualified') is not False
                    or container_candidate.get('remaining_blocker')!='native-fedora-six-run-matrix'):
                raise ValueError('Fedora container candidate boot binding is incomplete')
            archive_binding=container_candidate['archive']
            archive=root/'.cache/container-runtime-native-inputs'/archive_binding['name']
            info=archive.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or archive.is_symlink()
                    or info.st_size!=archive_binding['bytes']
                    or sha256(archive)!=archive_binding['sha256']):
                raise ValueError('Verified derived container image archive changed')
            record['image_id']=archive_binding['image_id']
            manifest_digest=archive_binding['manifest_digest']
            record['container_candidate']=container_candidate
            record['scope']=('Exact derived container-runtime image installed and booted with fixture '
                             'authentication; native containment qualification remains open')
            save()
        else:
            readiness=unique_json((root/'image/atomic/preflight.lock.json').read_bytes())
            validate_retained_preflight(root, readiness, selected, manifest, expected)
            record['preflight']=readiness
            # The existing bounded prepare phase verifies the current GitHub artifact
            # metadata and streams its complete ZIP/manifest/OCI hashes again.
            prepared=unique_json((root/'.cache/atomic-image-evidence/prepare.json').read_bytes())
            if (prepared['passed'] is not True or prepared['source_commit']!=record['source_commit']
                    or prepared['expected_inputs']!=expected or prepared['variant']!='generic'
                    or prepared['lock_sha256']!=sha256(root/'image/desktop-images.lock.json')):
                raise ValueError('Current hosted image intake has not passed')
            archive=root/'.cache/atomic-image-inputs'/manifest['archive']['name']
            if (archive.is_symlink() or not archive.is_file() or archive.stat().st_size!=manifest['archive']['bytes']
                    or sha256(archive)!=manifest['archive']['sha256']):
                raise ValueError('Verified development archive changed')
            manifest_digest=readiness['manifest_digest']
        storage=root/'.cache/atomic-disk-storage';storage.mkdir(mode=0o700)
        info=storage.lstat()
        storage_identity=(info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode),
                          stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid)
        record['disk_free_before_load']=shutil.disk_usage(storage).free
        if record['disk_free_before_load']<60*1024**3: raise ValueError('Need 60 GiB free for isolated install and boot')
        runroot=Path('/run')/group.name.removesuffix('.service');runroot.mkdir(mode=0o700)
        if len(os.fsencode(runroot))>50: raise ValueError('Runtime path is too long')
        podman=['podman','--cgroup-manager=cgroupfs','--root',str(storage/'root'),'--runroot',str(runroot)]
        image_id=record['image_id']
        print('Atomic install: loading the exact saved image into private CI storage',flush=True)
        run('load-image',podman+['load','--input',str(archive)],1800)
        loaded=validate_loaded_image(unique_json(run('inspect-image',podman+['image','inspect',image_id]).stdout),image_id)
        if loaded['Digest']!=manifest_digest: raise ValueError('Loaded OCI manifest changed')
        record['loaded_image']={k:loaded[k] for k in ('Id','Digest','Architecture','Os')}
        print('Atomic install: verifying opaque OCI layout blobs',flush=True)
        record['oci']=unpack_oci(archive,storage/'oci',manifest_digest,image_id)
        record['directory_source']=directory_source(storage/'oci',storage/'signed',manifest_digest)
        signer_input=storage/'signer-input';signer_input.mkdir(mode=0o755)
        for name in ('sign.py','contract.py'):
            shutil.copyfile(root/'image/atomic'/name,signer_input/name);(signer_input/name).chmod(0o644)
        shutil.copyfile(root/'image/launcher/probes/bounded_process.py',signer_input/'bounded_process.py')
        shutil.copyfile(storage/'signed/manifest.json',signer_input/'manifest.json')
        (signer_input/'sign.json').write_text(json.dumps({'manifest_digest':manifest_digest})+'\n')
        signing_output=storage/'signer-output';signing_output.mkdir(mode=0o700);os.chown(signing_output,10001,10001)
        container='symbi-atomic-signer';containers.append(container)
        common=['--pull=never','--network=none','--pid=private',
                '--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                '--env=LANG=C.UTF-8','--env=PYTHONDONTWRITEBYTECODE=1']
        print('Atomic install: authenticating a local source with an ephemeral offline CI test key',flush=True)
        run('sign-source',podman+['run','--rm','--name='+container,*common,'--read-only','--user=10001:10001',
            '--cap-drop=ALL','--security-opt=no-new-privileges','--memory=1g','--memory-swap=1g','--cpus=1','--pids-limit=64',
            '--mount',f'type=bind,src={signer_input},dst=/inputs,ro',
            '--mount',f'type=bind,src={signing_output},dst=/output',
            '--env=HOME=/output','--entrypoint=/usr/bin/python3',image_id,'/inputs/sign.py'],480)
        signed=unique_json((signing_output/'evidence/result.json').read_bytes())
        if (signed.get('passed') is not True or signed.get('release_qualified') is not False
                or signed.get('source_manifest_digest')!=manifest_digest
                or signed.get('private_keys_removed') is not True or signed.get('positive_policy_control') is not True
                or signed.get('negative_controls')!={case:True for case in ('unsigned','wrong-key','wrong-reference','altered-signature')}
                or sha256(signing_output/'good-public.asc')!=signed.get('public_key_sha256')
                or sha256(signing_output/'signature-1')!=signed.get('signature_sha256')):
            raise ValueError('Ephemeral source authentication acceptance incomplete')
        negative_signature_payloads(signing_output,signed)
        shutil.copyfile(signing_output/'signature-1',storage/'signed/signature-1')
        record['source_authentication']=signed
        from image.signing import render as render_trust
        policy=render_trust(unique_json((root/'image/release-trust.json').read_bytes()),pins,root)['policy']
        policy_bytes=(json.dumps(policy,indent=2)+'\n').encode()
        if hashlib.sha256(policy_bytes).hexdigest()!=expected['trust']['etc/containers/policy.json']:
            raise ValueError('The immutable release policy binding changed')
        local_policy=installer_policy(policy,(signing_output/'good-public.asc').read_bytes(),manifest_digest)
        if qualification=='update':
            from image.atomic.update_hosted import run_update
            print('Atomic update: installing the exact predecessor for a signed switch and booted rollback',flush=True)
            record['update']=run_update(root,group,podman,image_id,storage,containers,run,pins,
                                        lock,manifest_digest,storage/'signed',
                                        signing_output,signed,policy,policy_bytes)
            record['guest_booted']=record['update']['guest_booted'] is True
            record['update_qualified']=record['update']['passed'] is True
            record['passed']=record['guest_booted'] and record['update_qualified']
            return
        disk_dir=storage/'disk';disk_dir.mkdir(mode=0o700)
        identity=create_disk(disk_dir,24*1024**3);disk=disk_dir/'atomic.raw'
        record['disk']=identity
        installer_input=storage/'installer-input';installer_input.mkdir(mode=0o700)
        (installer_input/'signed').mkdir(mode=0o700)
        for name in ('install.py','contract.py'):
            shutil.copyfile(root/'image/atomic'/name,installer_input/name)
        (installer_input/'original-policy.json').write_bytes(policy_bytes)
        shutil.copyfile(signing_output/'good-public.asc',installer_input/'test-public.asc')
        (installer_input/'install-policy.json').write_text(json.dumps(local_policy,indent=2)+'\n')
        (installer_input/'install.json').write_text(json.dumps({'disk':identity,'manifest_digest':manifest_digest,
            'original_policy_sha256':expected['trust']['etc/containers/policy.json'],
            'installer_policy_sha256':sha256(installer_input/'install-policy.json'),
            'test_public_key_sha256':signed['public_key_sha256'],'signature_sha256':signed['signature_sha256']})+'\n')
        temporary=storage/'installer-tmp';temporary.mkdir(mode=0o700)
        if not Path('/run/udev').is_dir(): raise ValueError('Hosted udev state is unavailable')
        container='symbi-atomic-installer';containers.append(container)
        command=podman+['run','--rm','--name='+container,*common,'--privileged',
                       '--memory=2g','--memory-swap=2g','--cpus=1','--pids-limit=128',
                       *installer_mounts(storage),
                       '--entrypoint=/usr/bin/python3',image_id,'/inputs/install.py']
        require_disk(disk,identity);record['installation_attempted']=True;save()
        print('Atomic install: bootc is writing only the new private 24 GiB regular file',flush=True)
        run('install',command,2400)
        require_disk(disk,identity)
        loops=unique_json(run('disk-loops-after-install',['losetup','--json','--list','--output','NAME,BACK-FILE','--associated',str(disk)]).stdout)
        if loops.get('loopdevices') not in (None,[]): raise ValueError('Installer left attached loop devices')
        record['installation_completed']=True;record['disk_sha256']=sha256(disk);save()
        expected['manifest_digest']=manifest_digest
        payload=unique_json((root/'docs/security/reports/P0-03-desktop'/str(selected['run_id'])/'preparation.json').read_bytes())
        expected['payload']={**payload['payload'],**payload['overlay']}
        expected['payload_count']=len(expected['payload'])
        inventory=(root/'docs/security/reports/P0-03-desktop'/str(selected['run_id'])/'install/installed-after-stdout.log').read_text().splitlines()
        if len(set(inventory))!=len(inventory): raise ValueError('Duplicate retained package identity')
        expected['inventory_count']=len(inventory)
        expected['inventory_sha256']=hashlib.sha256(('\n'.join(sorted(inventory))+'\n').encode()).hexdigest()
        if container_candidate is not None:
            if expected['inventory_sha256']!=container_candidate['inventory_sha256']:
                raise ValueError('Generated container contract uses a different source package inventory')
            expected['container_candidate']={
                'contract_sha256':container_candidate['contract_sha256'],
                'runsc_files':container_candidate['runsc_files'],
                'daemon_configuration_sha256':container_candidate['daemon_configuration_sha256'],
            }
        expected['nonce']=secrets.token_hex(16)
        boot_input=storage/'boot-input';boot_input.mkdir(mode=0o755)
        for name in ('boot.py','contract.py','guest.py','o.service','s.service'):
            shutil.copyfile(root/'image/atomic'/name,boot_input/name);(boot_input/name).chmod(0o644)
        (boot_input/'atomic.raw').touch(mode=0o644)
        raw=(json.dumps(expected,sort_keys=True)+'\n').encode()
        if len(raw)>128*1024: raise ValueError('Boot observation input is too large')
        (boot_input/'expected.json').write_bytes(raw);(boot_input/'expected.json').chmod(0o644)
        boot_output=storage/'boot-output';boot_output.mkdir(mode=0o700)
        os.chown(boot_output,10001,10001)
        # The source disk becomes read-only; QEMU writes only a new qcow2 overlay.
        os.chmod(disk,0o444,follow_symlinks=False);disk_readonly=True
        container='symbi-atomic-qemu';containers.append(container)
        command=podman+['run','--rm','--name='+container,*common,'--read-only','--user=10001:10001',
                       '--cap-drop=ALL','--security-opt=no-new-privileges',
                       '--memory=3g','--memory-swap=3g','--cpus=2','--pids-limit=64',
                       '--mount',f'type=bind,src={boot_input},dst=/inputs,ro',
                       '--mount',f'type=bind,src={disk},dst=/inputs/atomic.raw,ro',
                       '--mount',f'type=bind,src={boot_output},dst=/output',
                       '--entrypoint=/usr/bin/python3',image_id,'/inputs/boot.py']
        record['boot_inputs']={name:sha256(boot_input/name) for name in ('boot.py','contract.py','guest.py','o.service','s.service','expected.json')}
        print('Atomic boot: starting the offline VM under unprivileged QEMU/TCG',flush=True)
        run('boot',command,960)
        result=unique_json((boot_output/'result.json').read_bytes())
        report=unique_json((boot_output/'report.json').read_bytes())
        validate_report(report,expected,expected['nonce'],record['boot_inputs']['guest.py'],record['boot_inputs']['expected.json'])
        if result['passed'] is not True or result['guest_booted'] is not True:
            raise ValueError('Hosted QEMU observation did not pass')
        if sha256(disk)!=record['disk_sha256']: raise ValueError('Read-only source disk changed during boot')
        record['guest_booted']=True;record['boot_id']=report['boot_id']
        if container_candidate is not None:
            print('Container candidate boot passed; stopping before native-fedora-six-run-matrix',flush=True)
            stop_after_container_candidate_boot(record,report['container_candidate'])
        if qualification=='landlock':
            from image.qualification.hosted import run_landlock
            print('Landlock qualification: starting the second offline installed-image boot',flush=True)
            record['landlock']=run_landlock(root,group,podman,image_id,disk,storage,containers,
                                            run,expected,record)
            record['landlock_qualified']=record['landlock']['qualified'] is True
        record['passed']=True
    except Exception as error:
        record['failure']=type(error).__name__+': '+str(error)
        raise
    finally:
        record['cleanup']={}
        if podman is not None:
            for name in containers:
                removed=run('cleanup-'+name,podman+['rm','--force','--ignore',name],check=False)
                absent=run('absent-'+name,podman+['container','exists',name],check=False)
                record['cleanup'][name]={'removed':removed.returncode==0,'absent':absent.returncode==1}
                if removed.returncode!=0 or absent.returncode!=1: record['passed']=False
        if boot_output is not None:
            for name in ('result.json','report.json','prepare.log','serial.log','qemu.log'):
                path=boot_output/name
                if path.is_file() and not path.is_symlink() and path.stat().st_size<=2*1024**2:
                    shutil.copyfile(path,evidence/('guest-'+name))
        if signing_output is not None:
            # Only public evidence is retained. The generated private keyring is
            # deleted inside the stopped signer and is never an upload input.
            if (signing_output/'evidence').is_dir():
                shutil.copytree(signing_output/'evidence',evidence/'source-authentication')
            for name in ('good-public.asc','signature-1'):
                path=signing_output/name
                if path.is_file() and not path.is_symlink() and path.stat().st_size<=65536:
                    shutil.copyfile(path,evidence/('source-'+name))
        stopped=all(v['removed'] and v['absent'] for v in record['cleanup'].values())
        landlock_evidence=root/'.cache/landlock-qualification-evidence'
        if (qualification=='landlock' and stopped and storage is not None
                and (landlock_evidence/'result.json').is_file()):
            from image.qualification.hosted import retain_deferred_landlock_output
            try:
                record['landlock_outer_retention']=retain_deferred_landlock_output(
                    storage/'landlock-output',landlock_evidence)
            except (OSError,ValueError) as error:
                record['landlock_outer_retention_error']=type(error).__name__+': '+str(error)
                record['passed']=False
        if disk is not None and stopped:
            # Cleanup may detach only devices still associated with this exact new
            # file, after every installer/VM container has stopped. Never use -D.
            require_disk(disk,identity,readonly=disk_readonly)
            result=run('disk-loops-cleanup',['losetup','--json','--list','--output','NAME,BACK-FILE','--associated',str(disk)],check=False)
            if result.returncode!=0: record['passed']=False
            else:
                rows=unique_json(result.stdout).get('loopdevices') or []
                for index,row in enumerate(rows):
                    if row.get('back-file')!=str(disk) or not re.fullmatch(r'/dev/loop[0-9]+',row.get('name','')):
                        raise ValueError('Unexpected loop device in targeted cleanup')
                    run('detach-owned-loop-'+str(index),['losetup','--detach',row['name']])
                check=unique_json(run('disk-loops-absent',['losetup','--json','--list','--output','NAME,BACK-FILE','--associated',str(disk)]).stdout)
                record['loops_absent']=not check.get('loopdevices')
                if not record['loops_absent']: record['passed']=False
        if podman is not None:
            removed=run('remove-image',podman+['image','rm','--force',record['image_id']],300,check=False)
            absent=run('image-absent',podman+['image','exists',record['image_id']],check=False)
            record['image_removed']=removed.returncode==0 and absent.returncode==1
            if not record['image_removed']: record['passed']=False
        # Large private artifacts are never uploaded; only the bounded evidence is.
        if storage is not None and stopped:
            if disk is None or record.get('loops_absent'):
                try:
                    info=storage.lstat()
                    current=(info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode),
                             stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid)
                    if (current!=storage_identity or not stat.S_ISDIR(info.st_mode)
                            or info.st_nlink<2):
                        raise ValueError('Private storage identity changed before cleanup')
                    shutil.rmtree(storage);record['private_storage_removed']=not storage.exists()
                    if runroot is not None:
                        shutil.rmtree(runroot);record['private_runroot_removed']=not runroot.exists()
                except (OSError,ValueError) as error:
                    record['private_storage_cleanup_error']=type(error).__name__+': '+str(error)
                    record['passed']=False
        record['cgroup_final']={n:(group/n).read_text().strip() for n in (*limits,'memory.peak','memory.events','cpu.stat')}
        events=dict(line.split() for line in record['cgroup_final']['memory.events'].splitlines())
        if (any(record['cgroup_final'][n]!=v for n,v in limits.items())
                or any(events.get(n)!='0' for n in ('oom','oom_kill','oom_group_kill'))): record['passed']=False
        save()
    if not record['passed']: raise RuntimeError('Atomic install/boot or cleanup did not pass')


if __name__=='__main__': main()
