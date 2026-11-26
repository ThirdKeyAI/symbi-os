"""Authenticate the retained Walker executable and its original source license."""
import hashlib
import shutil
import stat
import zipfile

from image.toolchain.reuse import digest, exact_hash, unique_json


def regular(path, maximum):
    if (path.is_symlink() or not path.is_file() or path.resolve() != path
            or not 0 < path.stat().st_size <= maximum):
        raise ValueError('Expected a bounded regular Walker input')


def require_walker(lock, root, build_base):
    source_path = root/'image/launcher/walker-source.json'
    regular(source_path, 65536)
    source = unique_json(source_path.read_bytes())
    manifest = lock.get('manifest')
    if (lock.get('schema') != 1 or lock.get('qualified') is not False or lock.get('product_installation') is not False
            or lock.get('upstream_tests_passed') is not True or lock.get('cli_acceptance_passed') is not True
            or type(lock.get('upstream_tests')) is not int or lock['upstream_tests'] <= 0
            or not exact_hash(lock.get('tested_commit'), 40) or not exact_hash(lock.get('manifest_sha256'))
            or not isinstance(source, dict) or source.get('schema') != 1 or source.get('os_qualified') is not False
            or source.get('repository') != 'https://github.com/abenz1267/walker'
            or not exact_hash(source.get('revision'), 40) or not isinstance(manifest, dict)):
        raise ValueError('Walker reuse requires reviewed source, upstream and CLI acceptance')
    expected = {'schema': 1, 'compiled': True, 'os_qualified': False, 'gui_qualified': False,
                'base': build_base, 'source_commit': lock['tested_commit'],
                'upstream_revision': source['revision'], 'version': source['version']}
    for name in ('cargo_toml_sha256', 'cargo_lock_sha256', 'build_rs_sha256'):
        if not exact_hash(source.get(name)):raise ValueError('Missing exact Walker source binding')
        expected[name] = source[name]
    if any(manifest.get(name) != value for name, value in expected.items()):
        raise ValueError('Walker build source/base bindings changed')
    for file_name, expected_hash in (
            ('walker-build-rpms.lock.json', manifest.get('build_rpm_lock_sha256')),
            ('runtime-rpms.lock.json', lock.get('runtime_rpm_lock_sha256'))):
        path = root/'image/launcher'/file_name
        regular(path, 2*1024**2)
        if not exact_hash(expected_hash) or digest(path) != expected_hash:
            raise ValueError('Walker build/runtime RPM inputs changed')
    license_row = lock.get('source_license')
    if (not isinstance(license_row, dict) or license_row.get('path') != 'image/launcher/licenses/walker.LICENSE'
            or type(license_row.get('bytes')) is not int or not 0 < license_row['bytes'] <= 65536
            or not exact_hash(license_row.get('sha256')) or not exact_hash(license_row.get('git_blob'), 40)):
        raise ValueError('Invalid original Walker license identity')
    license_path = root/license_row['path']
    regular(license_path, 65536)
    raw = license_path.read_bytes()
    blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    if len(raw) != license_row['bytes'] or digest(license_path) != license_row['sha256'] or blob != license_row['git_blob']:
        raise ValueError('Walker original license changed')
    artifact = lock.get('artifact')
    if (type(manifest.get('binary_bytes')) is not int or not 0 < manifest['binary_bytes'] <= 128*1024**2
            or not exact_hash(manifest.get('binary_sha256')) or not isinstance(artifact, dict)
            or type(artifact.get('id')) is not int or artifact['id'] <= 0
            or type(artifact.get('bytes')) is not int or not 0 < artifact['bytes'] <= 129*1024**2
            or not exact_hash(artifact.get('sha256'))):
        raise ValueError('Invalid bounded Walker payload identity')
    return manifest


def unpack_walker(archive, lock, root, build_base, destination):
    manifest = require_walker(lock, root, build_base)
    regular(archive, 129*1024**2)
    if archive.stat().st_size != lock['artifact']['bytes'] or digest(archive) != lock['artifact']['sha256']:
        raise ValueError('Walker archive differs from the reviewed artifact')
    if (destination.exists() or destination.is_symlink() or not destination.parent.is_dir()
            or destination.parent.resolve() != destination.parent):
        raise ValueError('Use a fresh Walker destination beneath a regular existing parent')
    created = False
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            if len(entries) != 2 or {row.filename for row in entries} != {'walker', 'manifest.json'}:
                raise ValueError('Unexpected, missing or duplicate Walker member')
            for row in entries:
                if (row.flag_bits & 1 or stat.S_IFMT(row.external_attr >> 16) not in (0, stat.S_IFREG)
                        or row.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or not 0 < row.file_size <= (65536 if row.filename == 'manifest.json' else manifest['binary_bytes'])):
                    raise ValueError('Unsafe or incorrectly sized Walker member')
            raw = bundle.read('manifest.json')
            if hashlib.sha256(raw).hexdigest() != lock['manifest_sha256'] or unique_json(raw) != manifest:
                raise ValueError('Walker manifest differs from reviewed bytes')
            if bundle.getinfo('walker').file_size != manifest['binary_bytes']:raise ValueError('Walker binary size changed')
            destination.mkdir(mode=0o700)
            created = True
            target = destination/'walker'
            with bundle.open('walker') as source, target.open('xb') as output:
                target.chmod(0o600)
                shutil.copyfileobj(source, output, length=1024**2)
            if target.stat().st_size != manifest['binary_bytes'] or digest(target) != manifest['binary_sha256']:
                raise ValueError('Walker binary differs from tested bytes')
            shutil.copyfile(root/lock['source_license']['path'], destination/'walker.LICENSE')
            (destination/'walker.LICENSE').chmod(0o644)
            (destination/'manifest.json').write_bytes(raw)
            target.chmod(0o755)
        return manifest
    except BaseException:
        if created:shutil.rmtree(destination)
        raise
