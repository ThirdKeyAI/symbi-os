"""Validate an exact hosted RPM bundle before any package installation."""
import hashlib
import json
from pathlib import Path
import shutil
import stat
import zipfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unpack_rpms(archive, lock, destination):
    if archive.is_symlink() or not archive.is_file():
        raise ValueError('Expected a regular RPM bundle')
    if archive.stat().st_size != lock['artifact']['bytes'] or digest(archive) != lock['artifact']['sha256']:
        raise ValueError('Hosted RPM bundle changed')
    packages = lock['packages']
    expected = {'evidence/result.json'}
    for row in packages:
        name = row['filename']
        if Path(name).name != name or not name.endswith('.rpm') or 'rpms/' + name in expected:
            raise ValueError('Invalid or duplicate package name')
        if row['signature_verified'] is not True or row['key_fingerprint'] != lock['key']['fingerprint']:
            raise ValueError('Every RPM needs the reviewed full signing fingerprint')
        expected.add('rpms/' + name)
    if not 0 < len(packages) <= 512:
        raise ValueError('Invalid package count')
    with zipfile.ZipFile(archive) as bundle:
        names = [member.filename for member in bundle.infolist()]
        if len(set(names)) != len(names):
            raise ValueError('Duplicate ZIP member')
        regular = []
        for member in bundle.infolist():
            mode = member.external_attr >> 16
            if member.is_dir():
                if member.filename not in ('rpms/', 'evidence/') or member.file_size != 0:
                    raise ValueError('Unexpected directory in RPM bundle')
                continue
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG) or member.flag_bits & 1:
                raise ValueError('Linked, special or encrypted ZIP member')
            regular.append(member)
        if {member.filename for member in regular} != expected:
            raise ValueError('Unexpected or missing RPM bundle member')
        if sum(member.file_size for member in regular) > 2 * 1024**3:
            raise ValueError('Oversized RPM bundle')
        if bundle.getinfo('evidence/result.json').file_size > 1024**2:
            raise ValueError('Oversized RPM manifest')
        raw = bundle.read('evidence/result.json')
        if hashlib.sha256(raw).hexdigest() != lock['manifest_sha256']:
            raise ValueError('RPM manifest changed')
        result = json.loads(raw)
        if result['passed'] is not True or result['installed_packages_unchanged'] is not True:
            raise ValueError('Unsuccessful RPM discovery')
        if result['base'] != lock['base'] or result['packages'] != packages:
            raise ValueError('RPM manifest differs from reviewed inputs')
        if result['negative_controls'] != {'missing_key_rejected': True, 'tampered_package_rejected': True}:
            raise ValueError('Real RPM negative controls are required')
        destination.mkdir()
        for member in regular:
            target = destination / member.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output, length=1024**2)
        for row in packages:
            path = destination / 'rpms' / row['filename']
            if path.stat().st_size != row['bytes'] or digest(path) != row['sha256']:
                raise ValueError('RPM bytes differ from signed discovery')
    return result
