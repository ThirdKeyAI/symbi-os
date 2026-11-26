"""Authenticate a reviewed development builder before any later execution."""
import hashlib
import json
import re
import shutil
import stat
import zipfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def exact_hash(value, length=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{'+str(length)+'}', value) is not None


def unique_json(raw):
    def object_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate JSON key in retained tool metadata')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=object_pairs)


def require_current_inputs(lock, config_path):
    if (config_path.is_symlink() or not config_path.is_file()
            or not 0 < config_path.stat().st_size <= 65536):
        raise ValueError('Expected one bounded regular tool configuration')
    config = unique_json(config_path.read_bytes())
    if (lock.get('schema') != 1 or lock.get('qualified') is not False
            or lock.get('product_installation') is not False
            or lock.get('cli_acceptance_passed') is not True or lock.get('upstream_tests_passed') is not True
            or not exact_hash(lock.get('tested_commit'), 40) or not exact_hash(lock.get('manifest_sha256'))):
        raise ValueError('Reuse requires reviewed CLI/upstream acceptance with no OS qualification claim')
    manifest = lock.get('manifest')
    if (not isinstance(config, dict) or config.get('schema') != 1
            or config.get('repository') != 'https://github.com/blue-build/cli'
            or config.get('qualified') is not False or config.get('profile') != 'dev'
            or not isinstance(config.get('rust'), str) or not exact_hash(config.get('revision'), 40)
            or not isinstance(manifest, dict) or manifest.get('schema') != 1
            or manifest.get('compiled') is not True or manifest.get('os_qualified') is not False
            or manifest.get('cli_acceptance_qualified') is not False
            or manifest.get('source_commit') != lock['tested_commit']
            or manifest.get('upstream_revision') != config['revision']
            or manifest.get('tool_config_sha256') != digest(config_path)
            or any(manifest.get(name) != config.get(name) for name in ('rust', 'features', 'profile', 'patches'))
            or not isinstance(manifest.get('rustc'), str)
            or not manifest['rustc'].startswith('rustc '+config['rust']+' ')):
        raise ValueError('Retained builder does not match the current source/compiler configuration')
    for name in ('cargo_lock_sha256', 'applied_diff_sha256'):
        if not exact_hash(manifest.get(name)):
            raise ValueError('Missing exact source-build hash: '+name)
    for key, name, maximum in (('binary', 'bluebuild', 128*1024**2), ('license', 'LICENSE', 256*1024)):
        row = manifest.get(key)
        if (not isinstance(row, dict) or row.get('name') != name or type(row.get('bytes')) is not int
                or not 0 < row['bytes'] <= maximum or not exact_hash(row.get('sha256'))):
            raise ValueError('Invalid bounded file identity in compiled manifest')
    artifact = lock.get('artifact')
    if (not isinstance(artifact, dict) or type(artifact.get('id')) is not int or artifact['id'] <= 0
            or type(artifact.get('bytes')) is not int or not 0 < artifact['bytes'] <= 129*1024**2
            or not exact_hash(artifact.get('sha256'))):
        raise ValueError('Expected one exact bounded hosted artifact')
    return manifest


def unpack_tool(archive, lock, config_path, destination):
    manifest = require_current_inputs(lock, config_path)
    if (archive.is_symlink() or not archive.is_file()
            or archive.stat().st_size != lock['artifact']['bytes'] or digest(archive) != lock['artifact']['sha256']):
        raise ValueError('Retained builder archive differs from the reviewed artifact')
    if (destination.exists() or destination.is_symlink() or not destination.parent.is_dir()
            or destination.parent.resolve() != destination.parent):
        raise ValueError('Use a fresh destination beneath an existing nonsymlinked parent')
    created = False
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            if len(entries) != 3 or {entry.filename for entry in entries} != {'bluebuild', 'LICENSE', 'manifest.json'}:
                raise ValueError('Unexpected, duplicate or missing builder ZIP member')
            sizes = {'bluebuild': manifest['binary']['bytes'], 'LICENSE': manifest['license']['bytes']}
            for entry in entries:
                if (entry.flag_bits & 1 or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)
                        or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or entry.file_size <= 0):
                    raise ValueError('Linked, special, encrypted or unsupported builder ZIP member')
                if entry.filename == 'manifest.json':
                    if entry.file_size > 65536:
                        raise ValueError('Oversized compiled manifest')
                elif entry.file_size != sizes[entry.filename]:
                    raise ValueError('Retained binary/license size differs from its manifest')
            raw = bundle.read('manifest.json')
            if hashlib.sha256(raw).hexdigest() != lock['manifest_sha256'] or unique_json(raw) != manifest:
                raise ValueError('Compiled manifest differs from its reviewed bytes')
            destination.mkdir(mode=0o700)
            created = True
            for key in ('binary', 'license'):
                row = manifest[key]
                target = destination/row['name']
                with bundle.open(row['name']) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output, length=1024**2)
                if target.stat().st_size != row['bytes'] or digest(target) != row['sha256']:
                    raise ValueError('Retained binary/license bytes differ from their manifest')
                target.chmod(0o755 if key == 'binary' else 0o644)
            (destination/'manifest.json').write_bytes(raw)
            (destination/'manifest.json').chmod(0o644)
        return manifest
    except BaseException:
        if created:
            shutil.rmtree(destination)
        raise
