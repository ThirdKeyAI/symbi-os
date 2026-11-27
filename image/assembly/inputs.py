"""Read only exact runtime artifacts whose source-build evidence was reviewed."""
import shutil
import stat
import tomllib
import zipfile

from image.toolchain.reuse import digest, exact_hash, unique_json

BINARY_LIMITS = {'symbi': 550*1024**2, 'symbi-sandbox-supervisor': 32*1024**2}
EXPECTED_CHECKS = {('baseline', name) for name in ('build', 'test', 'clippy', 'fmt')} | {
    ('fixture', name) for name in ('python', 'build', 'test', 'clippy', 'fmt')}


def require_runtime(lock, source_pin, build_result):
    for path, field in ((source_pin, 'source_pin_sha256'), (build_result, 'build_result_sha256')):
        if (path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 65536
                or not exact_hash(lock.get(field)) or digest(path) != lock[field]):
            raise ValueError('Runtime source pin or build evidence changed')
    source = tomllib.loads(source_pin.read_text())
    result = unique_json(build_result.read_bytes())
    if (lock.get('schema') != 1 or lock.get('qualified') is not False
            or lock.get('product_installation') is not False
            or type(lock.get('validation_run')) is not int or lock['validation_run'] <= 0
            or source.get('repository') != 'https://github.com/thirdkeyai/symbiont'
            or not exact_hash(source.get('revision'), 40) or source['revision'] != lock.get('source_revision')
            or not exact_hash(lock.get('validation_head'), 40)
            or not exact_hash(lock.get('validation_checked_merge'), 40)
            or not isinstance(result, dict) or result.get('schema') != 1
            or result.get('os_qualified') is not False
            or any(result.get(name) is not True for name in
                   ('baseline_passed', 'patched_workspace_passed', 'source_clean_before', 'patch_applied'))
            or result.get('source_revision') != source['revision']
            or result.get('source_commit') != lock['validation_checked_merge']):
        raise ValueError('Runtime reuse requires the reviewed workspace acceptance and current source')
    for field in ('patch_sha256', 'cargo_lock_sha256'):
        if not exact_hash(lock.get(field)) or result.get(field) != lock[field]:
            raise ValueError('Runtime source-build input changed: '+field)
    checks = result.get('checks')
    if (not isinstance(checks, list) or len(checks) != len(EXPECTED_CHECKS)
            or any(not isinstance(row, dict) or row.get('passed') is not True
                   or row.get('timeout') is not False or row.get('exit_code') != 0 for row in checks)
            or {(row.get('phase'), row.get('name')) for row in checks} != EXPECTED_CHECKS):
        raise ValueError('Incomplete runtime workspace checks')
    binaries = lock.get('binaries')
    if (not isinstance(binaries, dict) or set(binaries) != set(BINARY_LIMITS)
            or result.get('binaries') != binaries):
        raise ValueError('Runtime binary identities differ from the source-build evidence')
    for name, maximum in BINARY_LIMITS.items():
        row = binaries[name]
        if (not isinstance(row, dict) or type(row.get('bytes')) is not int
                or not 0 < row['bytes'] <= maximum or not exact_hash(row.get('sha256'))):
            raise ValueError('Invalid bounded runtime identity: '+name)
    artifact = lock.get('artifact')
    if (not isinstance(artifact, dict) or type(artifact.get('id')) is not int or artifact['id'] <= 0
            or type(artifact.get('bytes')) is not int or not 0 < artifact['bytes'] <= 600*1024**2
            or not exact_hash(artifact.get('sha256'))):
        raise ValueError('Expected one bounded, pinned runtime archive')
    return source


def unpack_runtime(archive, lock, source_pin, build_result, destination):
    require_runtime(lock, source_pin, build_result)
    if (archive.is_symlink() or not archive.is_file() or archive.stat().st_size != lock['artifact']['bytes']
            or digest(archive) != lock['artifact']['sha256']):
        raise ValueError('Runtime archive differs from the reviewed artifact')
    if (destination.exists() or destination.is_symlink() or not destination.parent.is_dir()
            or destination.parent.resolve() != destination.parent):
        raise ValueError('Use a fresh destination beneath a regular existing parent')
    created = False
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            if len(entries) != 2 or {row.filename for row in entries} != set(BINARY_LIMITS):
                raise ValueError('Unexpected, duplicate or missing runtime ZIP member')
            for row in entries:
                if (row.flag_bits & 1 or stat.S_IFMT(row.external_attr >> 16) not in (0, stat.S_IFREG)
                        or row.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or row.file_size != lock['binaries'][row.filename]['bytes']):
                    raise ValueError('Unsafe or incorrectly sized runtime ZIP member')
            destination.mkdir(mode=0o755)
            created = True
            for row in entries:
                target = destination/row.filename
                with bundle.open(row) as source, target.open('xb') as output:
                    target.chmod(0o600)
                    shutil.copyfileobj(source, output, length=1024**2)
                identity = lock['binaries'][row.filename]
                if target.stat().st_size != identity['bytes'] or digest(target) != identity['sha256']:
                    raise ValueError('Runtime binary differs from the tested executable')
            # Neither file becomes executable until both identities are checked.
            for row in entries:
                (destination/row.filename).chmod(0o755)
    except BaseException:
        if created:
            shutil.rmtree(destination)
        raise
