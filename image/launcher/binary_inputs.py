"""Authenticate retained development binaries before isolated hosted execution."""
import hashlib
import json
import shutil
import stat
import zipfile

BINARIES = frozenset(('baseline', 'patched', 'desktopapplications', 'marker'))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unpack_binaries(archive, lock, destination):
    """Stream only four pinned regular files; never trust archived file modes."""
    if destination.exists() or destination.is_symlink():
        raise ValueError('Binary destination must be fresh')
    if (archive.is_symlink() or not archive.is_file() or lock.get('schema') != 1
            or archive.stat().st_size != lock['artifact']['bytes']
            or archive.stat().st_size > 256 * 1024**2
            or digest(archive) != lock['artifact']['sha256']):
        raise ValueError('Compiled archive differs from the reviewed artifact')
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if len(entries) != 5 or {entry.filename for entry in entries} != BINARIES | {'manifest.json'}:
            raise ValueError('Archive must contain exactly the four binaries and manifest')
        for entry in entries:
            kind = stat.S_IFMT(entry.external_attr >> 16)
            maximum = 65536 if entry.filename == 'manifest.json' else 128 * 1024**2
            if (kind not in (0, stat.S_IFREG) or entry.is_dir() or entry.external_attr & 0x10
                    or entry.flag_bits & 1 or not 0 < entry.file_size <= maximum):
                raise ValueError('Invalid compiled archive member: ' + entry.filename)
        if sum(entry.file_size for entry in entries) > 256 * 1024**2:
            raise ValueError('Compiled archive exceeds the expanded size bound')
        raw = bundle.read('manifest.json')
        if hashlib.sha256(raw).hexdigest() != lock['manifest_sha256']:
            raise ValueError('Compiled manifest bytes changed')
        manifest = json.loads(raw)
        if (manifest != lock['manifest'] or manifest.get('schema') != 1
                or set(manifest.get('binaries', {})) != BINARIES):
            raise ValueError('Compiled manifest differs from the reviewed lock')
        # Authenticate all members before creating an executable destination.
        for name in sorted(BINARIES):
            with bundle.open(name) as source:
                actual = hashlib.file_digest(source, 'sha256').hexdigest()
            if actual != manifest['binaries'][name]:
                raise ValueError('Compiled binary changed: ' + name)
        destination.mkdir(mode=0o755)
        try:
            for name in sorted(BINARIES):
                target = destination / name
                with bundle.open(name) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output, length=65536)
                target.chmod(0o755 if name in ('baseline', 'patched') else 0o644)
        except Exception:
            shutil.rmtree(destination)
            raise
    return manifest


def require_bindings(manifest, lock, base, source, rpm_lock_sha256, patch_sha256, marker_sha256):
    """Refuse reuse after any relevant source, patch, compiler or base change."""
    expected = {'schema': 1, 'compiled': True, 'os_qualified': False,
                'provider_loading_qualified': False, 'source_commit': lock['tested_merge'],
                'base': base, 'upstream_revision': source['revision'],
                'rpm_lock_sha256': rpm_lock_sha256, 'patch_sha256': patch_sha256,
                'go_mod_sha256': source['go_mod_sha256'], 'go_sum_sha256': source['go_sum_sha256']}
    if (manifest != lock['manifest'] or any(manifest.get(key) != value for key, value in expected.items())
            or manifest.get('compiled') is not True or manifest.get('os_qualified') is not False
            or manifest.get('provider_loading_qualified') is not False
            or lock.get('marker_source_sha256') != marker_sha256):
        raise ValueError('Retained binary inputs do not match the current source and base')
