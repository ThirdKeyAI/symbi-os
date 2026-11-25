"""Authenticate immutable fixture inputs before extraction or execution."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import zipfile


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


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


def collect_public(source, destination):
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Public evidence must be a regular directory')
    files = []
    total_bytes = 0
    for path in source.rglob('*'):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode) or path.is_symlink() or path.stat().st_size > 16 * 1024**2:
            raise ValueError('Public evidence contains a link, special file or oversized log')
        if path.suffix not in ('.json', '.log', '.txt', '.tsv') and not path.name.endswith('_InRelease'):
            raise ValueError('Unexpected public evidence file type')
        data = path.read_bytes()
        total_bytes += len(data)
        if total_bytes > 64 * 1024**2:
            raise ValueError('Public evidence exceeds its bounded collection budget')
        if re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----', data):
            raise ValueError('Private key material must not enter a public artifact')
        files.append((path.relative_to(source), data))
    destination.mkdir()
    for relative, data in files:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


if __name__ == '__main__':
    import sys
    collect_public(Path(sys.argv[1]), Path(sys.argv[2]))
