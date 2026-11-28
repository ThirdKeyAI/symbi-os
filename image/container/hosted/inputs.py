"""Authenticate immutable fixture inputs before extraction or execution."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import zipfile

from image.container import ubuntu_fixture_packages as packages


FIXTURE_DRIVERS = {
    'test-filesystem-grants.py',
    'test-source-broker.py',
    'test-git-source.py',
}
SELECTED_FIXTURE_EXECUTION = {
    'state': 'passed',
    'event': 'pull_request',
    'pull_request': 6,
    'conclusion': 'success',
    'run_id': 45995824985,
    'run_attempt': 1,
    'head': 'cdd8e7d931ddf90f1fe8afb22d12df9c539320b4',
    'checked_merge': '2189acad039387cd48116c11934da383bea8e653',
    'job_id': 140494839919,
    'source_revision': 'cd4b34282ade880c8ac3d5136d31ff80cde92794',
    'source_tree': '2b2379d0de4eaaf4a57cf52c96355015bb3dc25d',
    'artifact': {
        'id': 15196575712,
        'name': 'container-fixture-evidence',
        'bytes': 293698,
        'sha256': (
            '8b9d8f59f66348ff42625cb313bffc21'
            'cead77bb0b152563c6b236313aa99ad0'),
    },
    'passed': True,
    'qualified': False,
}
SELECTED_PACKAGE_INDEXES = frozenset({
    'noble_main_binary-amd64_Packages.xz',
    'noble-updates_main_binary-amd64_Packages.xz',
    'noble-security_main_binary-amd64_Packages.xz',
})
SELECTED_RELEASES = frozenset({
    'noble_InRelease',
    'noble-updates_InRelease',
    'noble-security_InRelease',
})
MAX_SELECTION_BYTES = 4 * 1024**2
MAX_FIXTURE_OUTPUT_BYTES = 16 * 1024**2
FIXTURE_CASES = {
    'test-filesystem-grants.py': (
        'granted', 'undeclared', 'parser', 'oversize', 'existing', 'symlink',
        'nested', 'descendant', 'substitution'),
    'test-source-broker.py': (
        'read', 'list', 'grep', 'traversal', 'symlink', 'hardlink',
        'no_ceiling', 'denied', 'scratch'),
    'test-git-source.py': (
        'log', 'staged', 'diff', 'status', 'sha256', 'snapshot', 'denied',
        'alternates', 'pointer', 'oversize', 'extension', 'capacity',
        'prepare_crash', 'crash'),
}
FIXTURE_RESULT_FIELDS = {
    'passed', 'qualified', 'runs', 'source_revision', 'fixture_commit',
    'patch_sha256', 'fixture_source', 'fixture_source_lock_sha256',
    'binary_sha256', 'image_id', 'scope',
}
FIXTURE_RUN_FIELDS = {
    'backend', 'driver', 'command', 'passed', 'exit_code', 'elapsed_seconds',
    'log_sha256', 'remaining_containers', 'report_sha256',
    'observed_runtimes',
}
FIXTURE_REPORT_BASE_FIELDS = {
    'passed', 'fixture', 'binary_sha256', 'driver_sha256', 'cases',
    'provider_errors', 'image', 'backend', 'container_profile_sha256',
    'remaining_workers', 'remaining_leases',
}
FIXTURE_REPORT_FIELDS = {
    'test-filesystem-grants.py': FIXTURE_REPORT_BASE_FIELDS | {
        'backend_observer_sha256', 'origin_observer_sha256', 'config_sha256',
        'public_key', 'journals',
    },
    'test-source-broker.py': FIXTURE_REPORT_BASE_FIELDS | {
        'manifests', 'public_key', 'verifier_sha256',
    },
    'test-git-source.py': FIXTURE_REPORT_BASE_FIELDS | {
        'origin_observer_sha256', 'manifests', 'config_sha256', 'public_key',
        'verifier_sha256',
    },
}
FIXTURE_CASE_FIELDS = {
    'test-filesystem-grants.py': {
        'name', 'passed', 'manifest_sha256', 'exit_code', 'stdout', 'stderr',
        'requests', 'workers', 'worker_origins',
    },
    'test-source-broker.py': {
        'name', 'passed', 'config_sha256', 'policy_sha256', 'workers',
        'exit_code', 'stdout', 'stderr', 'requests', 'journal',
    },
    'test-git-source.py': {
        'name', 'passed', 'policy_sha256', 'exit_code', 'stdout', 'stderr',
        'requests', 'workers', 'worker_origins', 'journal',
        'automatic_staging_cleanup',
    },
}
FIXTURE_CASE_FIELDS_BY_NAME = {
    'test-filesystem-grants.py': {
        'granted': {'envelope'}, 'undeclared': {'envelope'},
        'parser': {'envelope'},
        'oversize': {'envelope', 'further_inference_refused'},
        'existing': set(), 'symlink': set(), 'nested': {'envelope'},
        'descendant': {'envelope'}, 'substitution': {'envelope'},
    },
    'test-source-broker.py': {
        name: ({'envelope'} if name in {'read', 'list', 'grep', 'scratch'}
               else set())
        for name in FIXTURE_CASES['test-source-broker.py']
    },
    'test-git-source.py': {
        'log': {'envelope'}, 'staged': {'envelope'}, 'diff': {'envelope'},
        'status': {'envelope'}, 'sha256': {'envelope'},
        'snapshot': {'envelope'}, 'denied': set(), 'alternates': set(),
        'pointer': set(), 'oversize': set(), 'extension': {'envelope'},
        'capacity': {'envelope', 'retained_charge', 'sibling'},
        'prepare_crash': {'interrupted_preparation', 'crash_inspection'},
        'crash': {'crash_inspection'},
    },
}
FIXTURE_SCOPE = (
    'Hosted Ubuntu container tool-worker fixtures; no Fedora, managed-CLI '
    'or escape-suite qualification')


def exact_record(actual, expected):
    """Compare a retained record without bool/int or extra-field aliases."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return (set(actual) == set(expected)
                and all(exact_record(actual[key], value)
                        for key, value in expected.items()))
    return actual == expected


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _bounded_regular_bytes(path, description):
    """Read one stable, direct, bounded evidence file."""
    path = Path(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or path.is_symlink()
            or before.st_nlink != 1 or before.st_size <= 0
            or before.st_size > MAX_FIXTURE_OUTPUT_BYTES):
        raise ValueError(description + ' is not one bounded regular file')
    raw = path.read_bytes()
    after = path.lstat()
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if len(raw) != before.st_size or identity(before) != identity(after):
        raise ValueError(description + ' changed while reading')
    return raw


def _observed_runtimes(value):
    result = []
    if isinstance(value, dict):
        if 'id' in value and 'runtime' in value:
            result.append(value['runtime'])
        for child in value.values():
            result.extend(_observed_runtimes(child))
    elif isinstance(value, list):
        for child in value:
            result.extend(_observed_runtimes(child))
    return result


def _unique_json_bytes(raw, description):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(description + ' contains a duplicate key')
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode('utf-8'), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError(description + ' contains a non-finite number')))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(description + ' is not unique UTF-8 JSON') from error


def validate_fixture_output(source, setup):
    """Rebind every fixture report and log after the test UID is quiescent."""
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Fixture output must be one direct directory')
    if (not isinstance(setup, dict)
            or not isinstance(setup.get('fixture_source'), dict)
            or set(setup['fixture_source'].get('drivers', {}))
            != set(FIXTURE_CASES)):
        raise ValueError('Fixture output setup is incomplete')

    stems = [
        backend + '-' + Path(driver).stem
        for backend in ('docker', 'gvisor') for driver in FIXTURE_CASES
    ]
    expected_files = {
        'result.json',
        *{stem + '.json' for stem in stems},
        *{stem + '.log' for stem in stems},
    }
    entries = list(source.iterdir())
    if ({entry.name for entry in entries} != expected_files
            or len(entries) != len(expected_files)):
        raise ValueError('Fixture output inventory changed')
    raw_files = {
        entry.name: _bounded_regular_bytes(entry, 'Fixture output ' + entry.name)
        for entry in entries
    }
    result = _unique_json_bytes(
        raw_files['result.json'], 'Fixture result')
    fixture_source = setup['fixture_source']
    if (not isinstance(result, dict) or set(result) != FIXTURE_RESULT_FIELDS
            or result.get('passed') is not True
            or result.get('qualified') is not False
            or result.get('scope') != FIXTURE_SCOPE
            or result.get('source_revision') != setup.get('source_revision')
            or result.get('fixture_commit') != setup.get('fixture_commit')
            or result.get('patch_sha256') != setup.get('patch_sha256')
            or not exact_record(result.get('fixture_source'), fixture_source)
            or result.get('fixture_source_lock_sha256')
            != setup.get('fixture_source_lock_sha256')
            or result.get('binary_sha256') != setup.get('binary_sha256')
            or result.get('image_id') != setup.get('image_id')
            or not isinstance(result.get('runs'), list)
            or len(result['runs']) != 6):
        raise ValueError('Fixture result does not bind the selected execution')

    expected_rows = [
        (backend, driver)
        for backend in ('docker', 'gvisor') for driver in FIXTURE_CASES
    ]
    work = source.parent
    for row, (backend, driver) in zip(
            result['runs'], expected_rows, strict=True):
        stem = backend + '-' + Path(driver).stem
        report_name = stem + '.json'
        log_name = stem + '.log'
        command = [
            'python3', '-B', 'scripts/' + driver, '--binary',
            str(work / 'bin/symbi'), '--image', setup['image_id'],
            '--report', str(source / report_name),
        ]
        if backend == 'gvisor':
            command += ['--gvisor', '--runsc-binary', setup['runsc']]
        runtime = 'runsc' if backend == 'gvisor' else 'runc'
        if (not isinstance(row, dict) or set(row) != FIXTURE_RUN_FIELDS
                or row.get('backend') != backend
                or row.get('driver') != driver
                or row.get('command') != command
                or row.get('passed') is not True
                or type(row.get('exit_code')) is not int
                or row['exit_code'] != 0
                or type(row.get('elapsed_seconds')) not in (int, float)
                or not math.isfinite(row['elapsed_seconds'])
                or not 0 <= row['elapsed_seconds'] <= 1860
                or row.get('remaining_containers') != []
                or row.get('observed_runtimes') != [runtime]
                or row.get('log_sha256')
                != hashlib.sha256(raw_files[log_name]).hexdigest()
                or row.get('report_sha256')
                != hashlib.sha256(raw_files[report_name]).hexdigest()):
            raise ValueError('Fixture run receipt changed after execution')
        report = _unique_json_bytes(
            raw_files[report_name], 'Fixture report')
        cases = report.get('cases') if isinstance(report, dict) else None
        expected_report_fields = FIXTURE_REPORT_FIELDS[driver] | (
            {'runsc'} if backend == 'gvisor' else set())
        if (not isinstance(report, dict)
                or set(report) != expected_report_fields
                or report.get('passed') is not True
                or report.get('backend') != backend
                or report.get('binary_sha256') != setup['binary_sha256']
                or report.get('image') != setup['image_id']
                or report.get('driver_sha256')
                != fixture_source['drivers'][driver]
                or not isinstance(cases, list)
                or [case.get('name') if isinstance(case, dict) else None
                    for case in cases] != list(FIXTURE_CASES[driver])
                or any(not isinstance(case, dict)
                       or set(case) != (
                           FIXTURE_CASE_FIELDS[driver]
                           | FIXTURE_CASE_FIELDS_BY_NAME[driver][case.get('name')])
                       or case.get('passed') is not True for case in cases)
                or report.get('remaining_workers') != []
                or report.get('remaining_leases') != []
                or set(_observed_runtimes(cases)) != {runtime}):
            raise ValueError('Fixture report changed after execution')
    return result


def validate_fixture_source_lock(lock, native):
    """Require the hosted checkout to use the exact reviewed native source."""
    native_fields = {
        'schema', 'repository', 'revision', 'tree', 'runtime_source_revision',
        'pull_request', 'reviewed_head', 'drivers', 'qualified', 'scope',
    }
    runtime_validation = (
        lock.get('runtime_artifact_validation') if isinstance(lock, dict)
        else None)
    execution = (
        lock.get('fixture_execution') if isinstance(lock, dict) else None)
    if (not isinstance(lock, dict) or not isinstance(native, dict)
            or set(native) != native_fields
            or type(native.get('schema')) is not int or native['schema'] != 1
            or native.get('repository')
            != 'https://github.com/ThirdKeyAI/Symbiont'
            or native.get('qualified') is not False
            or not isinstance(native.get('drivers'), dict)
            or set(native['drivers']) != FIXTURE_DRIVERS
            or not all(isinstance(value, str)
                       and re.fullmatch(r'[a-f0-9]{64}', value)
                       for value in native['drivers'].values())
            or not all(isinstance(native.get(field), str)
                       and re.fullmatch(r'[a-f0-9]{40}', native[field])
                       for field in ('revision', 'tree',
                                     'runtime_source_revision', 'reviewed_head'))
            or lock.get('fixture_commit') != native['revision']
            or lock.get('fixture_tree') != native['tree']
            or lock.get('source_revision') != native['runtime_source_revision']
            or lock.get('fixture_drivers') != native['drivers']
            or not isinstance(runtime_validation, dict)
            or set(runtime_validation) != {'run_id', 'head', 'checked_merge'}
            or type(runtime_validation.get('run_id')) is not int
            or runtime_validation['run_id'] <= 0
            or not all(isinstance(runtime_validation.get(field), str)
                       and re.fullmatch(
                           r'[a-f0-9]{40}', runtime_validation[field])
                       for field in ('head', 'checked_merge'))
            or not (
                exact_record(execution, {
                    'state': 'pending',
                    'run_id': None,
                    'head': None,
                    'source_revision': native['revision'],
                    'source_tree': native['tree'],
                })
                or (exact_record(execution, SELECTED_FIXTURE_EXECUTION)
                    and execution['source_revision'] == native['revision']
                    and execution['source_tree'] == native['tree']))):
        raise ValueError('Hosted fixture source differs from the native source lock')
    return {
        'repository': native['repository'],
        'revision': native['revision'],
        'tree': native['tree'],
        'runtime_source_revision': native['runtime_source_revision'],
        'drivers': dict(native['drivers']),
    }


def require_signature(status, output, fingerprint):
    rows = [line.split() for line in output.splitlines() if line.startswith('[GNUPG:] ')]
    valid = [row[2] for row in rows if len(row) >= 3 and row[1] == 'VALIDSIG']
    bad = {'BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'NO_PUBKEY'}
    if status != 0 or valid != [fingerprint] or any(row[1] in bad for row in rows):
        raise ValueError('Input needs one valid signature from the pinned full fingerprint')


def unpack_runtime(archive, lock, destination):
    if archive.is_symlink() or not archive.is_file():
        raise ValueError('Runtime ZIP must be a regular file')
    if archive.stat().st_size != lock['artifact']['bytes'] or digest(archive) != lock['artifact']['sha256']:
        raise ValueError('Runtime ZIP differs from the checked artifact')
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        names = [member.filename for member in members]
        if len(set(names)) != len(names) or set(names) != set(lock['binaries']):
            raise ValueError('Runtime ZIP contains unexpected, missing or duplicate files')
        for member in members:
            mode = stat.S_IFMT(member.external_attr >> 16)
            if Path(member.filename).name != member.filename or member.is_dir() or mode not in (0, stat.S_IFREG) or member.flag_bits & 1:
                raise ValueError('Runtime ZIP contains an unsafe member')
            if member.file_size != lock['binaries'][member.filename]['bytes']:
                raise ValueError('Unexpected binary size')
        destination.mkdir(mode=0o755)
        for member in members:
            target = destination / member.filename
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with bundle.open(member) as source, os.fdopen(descriptor, 'wb') as output:
                shutil.copyfileobj(source, output, length=1024**2)
            if digest(target) != lock['binaries'][member.filename]['sha256']:
                raise ValueError('Binary differs from the tested executable')
        # No executable permission is granted until every member has passed.
        for member in members:
            (destination / member.filename).chmod(0o755)


def selected_public_bindings(lock_path):
    """Bind the seven package evidence files to one selected committed lock."""
    lock_path = Path(lock_path)
    if (lock_path.name != 'ubuntu-fixture-packages.lock.json'
            or lock_path.is_symlink() or not lock_path.is_file()):
        raise ValueError('Package evidence needs one direct selected lock')
    before = lock_path.stat()
    if (before.st_nlink != 1 or before.st_size <= 0
            or before.st_size > MAX_SELECTION_BYTES):
        raise ValueError('Package evidence lock is not one bounded regular file')
    raw = lock_path.read_bytes()
    after = lock_path.stat()
    if (before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
            before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('Package evidence lock changed while reading')
    lock = packages.unique_json_bytes(raw, MAX_SELECTION_BYTES)
    candidate = lock.get('candidate') if isinstance(lock, dict) else None
    releases = candidate.get('release_metadata') if isinstance(candidate, dict) else None
    indexes = candidate.get('package_indexes') if isinstance(candidate, dict) else None
    package_rows = candidate.get('packages') if isinstance(candidate, dict) else None
    manifest = candidate.get('manifest') if isinstance(candidate, dict) else None
    if (lock.get('state') != 'selected' or lock.get('selected') is not True
            or not isinstance(manifest, dict)
            or manifest.get('path') != 'manifest.json'
            or not isinstance(releases, list) or len(releases) != 3
            or not isinstance(indexes, list) or len(indexes) != 3
            or not isinstance(package_rows, list) or not package_rows):
        raise ValueError('Package evidence lock is not selected and complete')

    def binding(row, description):
        if (not isinstance(row, dict) or type(row.get('bytes')) is not int
                or not 0 < row['bytes'] <= 16 * 1024**2
                or not packages.exact_hash(row.get('sha256'))):
            raise ValueError(description + ' binding is incomplete')
        return {'bytes': row['bytes'], 'sha256': row['sha256']}

    selected = {
        'fixture-packages/package-manifest.json':
            binding(manifest, 'Package manifest'),
    }
    release_names = set()
    for release in releases:
        row = release.get('inrelease') if isinstance(release, dict) else None
        name = row.get('filename') if isinstance(row, dict) else None
        if name in release_names or name not in SELECTED_RELEASES:
            raise ValueError('Selected release metadata paths changed')
        release_names.add(name)
        selected['fixture-packages/metadata/' + name] = binding(
            row, 'Selected release metadata')
    index_names = set()
    for row in indexes:
        name = row.get('filename') if isinstance(row, dict) else None
        if name in index_names or name not in SELECTED_PACKAGE_INDEXES:
            raise ValueError('Selected package index paths changed')
        index_names.add(name)
        selected['fixture-packages/metadata/' + name] = binding(
            row, 'Selected package index')
    if (release_names != SELECTED_RELEASES
            or index_names != SELECTED_PACKAGE_INDEXES or len(selected) != 7):
        raise ValueError('Selected package evidence inventory is incomplete')
    expected_packages = set()
    for row in package_rows:
        if (not isinstance(row, dict)
                or re.fullmatch(r'[a-z0-9][a-z0-9+.-]*',
                                row.get('package', '')) is None
                or not isinstance(row.get('version'), str)
                or not row['version'] or any(
                    character in row['version'] for character in '\t\r\n')
                or re.fullmatch(r'[a-z0-9][a-z0-9-]*',
                                row.get('architecture', '')) is None):
            raise ValueError('Selected package inventory is malformed')
        expected_packages.add(
            (row['package'], row['version'], row['architecture']))
    if len(expected_packages) != len(package_rows):
        raise ValueError('Selected package inventory is ambiguous')
    return {'files': selected, 'packages': frozenset(expected_packages)}


def collect_public(source, destination, selected_bindings=None,
                   expected_paths=None):
    source = Path(source)
    destination = Path(destination)
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Public evidence must be a regular directory')
    parent = destination.parent
    if (destination.exists() or destination.is_symlink()
            or parent.is_symlink() or not parent.is_dir()
            or parent.resolve() != parent):
        raise ValueError('Public evidence destination must be a new direct path')
    if selected_bindings is not None:
        if (not isinstance(selected_bindings, dict)
                or set(selected_bindings) != {'files', 'packages'}
                or not isinstance(selected_bindings['files'], dict)
                or set(selected_bindings['files']) != {
                    'fixture-packages/package-manifest.json',
                    *{'fixture-packages/metadata/' + name
                      for name in SELECTED_RELEASES},
                    *{'fixture-packages/metadata/' + name
                      for name in SELECTED_PACKAGE_INDEXES},
                }
                or not isinstance(selected_bindings['packages'], frozenset)
                or not selected_bindings['packages']):
            raise ValueError('Selected package evidence bindings are incomplete')
        selected_files = selected_bindings['files']
    else:
        selected_files = {}
    if (expected_paths is not None
            and (not isinstance(expected_paths, (set, frozenset))
                 or not expected_paths
                 or any(not isinstance(path, str) or not path
                        for path in expected_paths))):
        raise ValueError('Expected public evidence inventory is invalid')
    files = []
    selected_seen = set()
    package_inventory_seen = False
    package_directories = set()
    total_bytes = 0
    for path in source.rglob('*'):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            relative_directory = path.relative_to(source).as_posix()
            if (relative_directory == 'fixture-packages'
                    or relative_directory.startswith('fixture-packages/')):
                package_directories.add(relative_directory)
            continue
        if not stat.S_ISREG(mode) or path.is_symlink() or path.stat().st_size > 16 * 1024**2:
            raise ValueError('Public evidence contains a link, special file or oversized log')
        relative = path.relative_to(source).as_posix()
        in_package_tree = relative.startswith('fixture-packages/')
        selected_type = (path.name == 'package-manifest.json'
                         or path.name.endswith('_InRelease')
                         or path.suffix == '.xz')
        if (in_package_tree and not selected_type
                and relative != 'fixture-packages/packages.tsv'):
            raise ValueError('Unexpected package evidence path')
        if (path.suffix not in ('.json', '.log', '.txt', '.tsv')
                and not selected_type):
            raise ValueError('Unexpected public evidence file type')
        data = path.read_bytes()
        if selected_type:
            binding = selected_files.get(relative)
            if (binding is None or len(data) != binding['bytes']
                    or hashlib.sha256(data).hexdigest() != binding['sha256']):
                raise ValueError('Selected package evidence path or bytes changed')
            selected_seen.add(relative)
        elif relative == 'fixture-packages/packages.tsv':
            if selected_bindings is None or not data.endswith(b'\n'):
                raise ValueError('Package inventory lacks selected bindings')
            try:
                rows = [line.split('\t')
                        for line in data.decode('utf-8').splitlines()]
            except UnicodeDecodeError as error:
                raise ValueError('Package inventory is not UTF-8') from error
            if (not rows or any(len(row) != 2 or not row[0] or not row[1]
                                for row in rows)
                    or len({tuple(row) for row in rows}) != len(rows)):
                raise ValueError('Package inventory is malformed or ambiguous')
            actual = {tuple(row) for row in rows}
            for package, version, architecture in selected_bindings['packages']:
                if ((package, version) not in actual
                        and (package + ':' + architecture, version) not in actual):
                    raise ValueError('Package inventory omits a selected package')
            package_inventory_seen = True
        total_bytes += len(data)
        if total_bytes > 64 * 1024**2:
            raise ValueError('Public evidence exceeds its bounded collection budget')
        if re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----', data):
            raise ValueError('Private key material must not enter a public artifact')
        files.append((path.relative_to(source), data))
    if (selected_bindings is not None
            and (selected_seen != set(selected_files)
                 or not package_inventory_seen
                 or package_directories
                 != {'fixture-packages', 'fixture-packages/metadata'})):
        raise ValueError('Selected package evidence inventory is incomplete')
    observed_paths = {relative.as_posix() for relative, _ in files}
    if (expected_paths is not None
            and observed_paths != set(expected_paths)):
        raise ValueError('Public evidence inventory differs from its exact plan')
    staging = Path(tempfile.mkdtemp(
        prefix='.' + destination.name + '.', dir=parent))
    staging.chmod(0o700)
    try:
        for relative, data in files:
            target = staging / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o644)
        for path in sorted(
                (path for path in staging.rglob('*') if path.is_dir()),
                key=lambda path: len(path.parts), reverse=True):
            path.chmod(0o755)
        staging.chmod(0o755)
        expected_files = observed_paths
        actual_files = {
            path.relative_to(staging).as_posix()
            for path in staging.rglob('*') if path.is_file()
        }
        if (actual_files != expected_files
                or any(path.is_symlink() or not path.is_file()
                       or stat.S_IMODE(path.stat().st_mode) != 0o644
                       for path in staging.rglob('*') if not path.is_dir())
                or any(stat.S_IMODE(path.stat().st_mode) != 0o755
                       for path in [staging, *(
                           item for item in staging.rglob('*')
                           if item.is_dir())])):
            raise ValueError('Staged public evidence inventory changed')
        os.rename(staging, destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


if __name__ == '__main__':
    import sys
    bindings = selected_public_bindings(Path(sys.argv[3])) if len(sys.argv) == 4 else None
    collect_public(Path(sys.argv[1]), Path(sys.argv[2]), bindings)
