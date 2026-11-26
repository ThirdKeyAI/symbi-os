"""Reuse exact tested portal files without trusting archive paths or metadata."""
import hashlib
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import stat
import tarfile
import tempfile
import zipfile

from image.toolchain.reuse import digest, exact_hash, unique_json


def require_portal_manifest(manifest, lock, pins, base, rpm_hash, compositor_hash):
    try:
        if (type(lock['schema']) is not int or lock['schema'] != 1
                or any(lock[name] is not False for name in ('qualified','product_installation','consent_qualified'))
                or not exact_hash(lock['tested_commit'],40) or not exact_hash(lock['manifest_sha256'])
                or manifest != lock['manifest'] or type(manifest['schema']) is not int or manifest['schema'] != 1
                or manifest['compiled'] is not True
                or any(manifest[name] is not False for name in ('os_qualified','selected_base_qualified','consent_qualified'))
                or manifest['source_commit'] != lock['tested_commit'] or manifest['base'] != base
                or manifest['source_inputs'] != pins or manifest['rpm_lock_sha256'] != rpm_hash
                or manifest['reused_compositor_manifest_sha256'] != compositor_hash
                or not exact_hash(manifest['compile_report_sha256'])
                or not exact_hash(manifest['payload_sha256'])
                or type(manifest['payload_bytes']) is not int or not 0 < manifest['payload_bytes'] <= 64*1024**2):
            raise ValueError('Portal source/build/qualification bindings changed')
        artifact = lock['artifact']
        if (type(artifact['id']) is not int or artifact['id'] <= 0 or not exact_hash(artifact['sha256'])
                or type(artifact['bytes']) is not int or not 0 < artifact['bytes'] <= 65*1024**2):
            raise ValueError('Invalid portal artifact identity')
        suites = manifest['test_suites']
        if set(suites) != {'toolkit-unit','toolkit-renderer','portal-tests'}:
            raise ValueError('Missing native portal test suite')
        for name, count in (('toolkit-unit',91),('toolkit-renderer',1),('portal-tests',1)):
            cases = suites[name]['cases']
            if (not isinstance(cases,list) or len(cases) != count or len(set(cases)) != count
                    or any(not isinstance(case,str) or not case for case in cases)
                    or not exact_hash(suites[name]['sha256'])):
                raise ValueError('Native portal test accounting changed')
        if (suites['portal-tests']['cases'] != ['hyprland-share-picker-data.hyprland-share-picker-data']
                or suites['toolkit-renderer']['cases'] != ['CEmbeddedRendererTest.rendersAndRestoresHostState']):
            raise ValueError('Different portal/renderer tests were selected')
        files = manifest['files']
        required = {'bin/hyprland-share-picker','libexec/xdg-desktop-portal-hyprland',
                    'lib/libhyprtoolkit.so.0.6.0','lib/libhyprtoolkit.so.6','lib/libhyprtoolkit.so',
                    'share/licenses/hyprtoolkit/LICENSE','share/licenses/xdg-desktop-portal-hyprland/LICENSE'}
        if not isinstance(files,dict) or not required.issubset(files) or len(files) > 1024:
            raise ValueError('Incomplete or excessive portal prefix inventory')
        total = 0
        for name, row in files.items():
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or '..' in path.parts or path.as_posix() != name
                    or '\\' in name or name == '.'):
                raise ValueError('Unsafe portal inventory path')
            if any(str(parent) in files for parent in path.parents):
                raise ValueError('Portal file or link used as an inventory directory')
            if set(row) == {'link'}:
                link = row['link']
                target = posixpath.normpath(posixpath.join(str(path.parent),link))
                if (not link or link.startswith('/') or '\\' in link or target.startswith('../')
                        or target not in files):
                    raise ValueError('Portal inventory link leaves its prefix')
            elif (set(row) != {'sha256','bytes','mode'} or not exact_hash(row['sha256'])
                    or type(row['bytes']) is not int or not 0 <= row['bytes'] <= 16*1024**2
                    or type(row['mode']) is not int or row['mode'] not in (0o644,0o755)):
                raise ValueError('Invalid bounded portal file identity')
            else:
                total += row['bytes']
        if total > 64*1024**2:
            raise ValueError('Oversized expanded portal prefix')
    except (KeyError,TypeError,AttributeError) as error:
        raise ValueError('Malformed portal prefix binding') from error
    return manifest


def unpack_portal(archive, lock, pins, base, rpm_hash, compositor_hash, destination):
    manifest = require_portal_manifest(lock['manifest'],lock,pins,base,rpm_hash,compositor_hash)
    if (archive.is_symlink() or not archive.is_file() or archive.resolve() != archive
            or archive.stat().st_size != lock['artifact']['bytes'] or digest(archive) != lock['artifact']['sha256']):
        raise ValueError('Portal artifact changed')
    if (destination.exists() or destination.is_symlink() or not destination.parent.is_dir()
            or destination.parent.resolve() != destination.parent):
        raise ValueError('Use a new portal destination under a regular existing parent')
    created = False
    try:
        with tempfile.TemporaryDirectory(prefix='portal-input-',dir=destination.parent) as temporary:
            payload = Path(temporary) / 'portal-prefix.tar.gz'
            with zipfile.ZipFile(archive) as bundle:
                rows = bundle.infolist()
                if len(rows) != 2 or {row.filename for row in rows} != {'manifest.json','portal-prefix.tar.gz'}:
                    raise ValueError('Unexpected or duplicate portal ZIP member')
                for row in rows:
                    maximum = 256*1024 if row.filename == 'manifest.json' else manifest['payload_bytes']
                    if (row.flag_bits & 1 or stat.S_IFMT(row.external_attr >> 16) not in (0,stat.S_IFREG)
                            or row.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)
                            or not 0 < row.file_size <= maximum):
                        raise ValueError('Unsafe or oversized portal ZIP member')
                raw = bundle.read('manifest.json')
                if hashlib.sha256(raw).hexdigest() != lock['manifest_sha256'] or unique_json(raw) != manifest:
                    raise ValueError('Portal manifest differs from reviewed bytes')
                if bundle.getinfo('portal-prefix.tar.gz').file_size != manifest['payload_bytes']:
                    raise ValueError('Portal payload length changed')
                with bundle.open('portal-prefix.tar.gz') as source,payload.open('xb') as target:
                    shutil.copyfileobj(source,target,length=64*1024)
            if digest(payload) != manifest['payload_sha256']:
                raise ValueError('Portal payload hash changed')
            files = {'portal/'+name:row for name,row in manifest['files'].items()}
            directories = {'portal'}
            for name in files:
                directories.update(str(path) for path in PurePosixPath(name).parents if str(path) != '.')
            with tarfile.open(payload,'r:gz') as bundle:
                entries = {}
                for member in bundle:
                    name = member.name.rstrip('/')
                    path = PurePosixPath(name)
                    if (not name or path.is_absolute() or '..' in path.parts or path.as_posix() != name
                            or '\\' in name or name in entries or len(entries) >= 2048):
                        raise ValueError('Aliased, duplicate or escaping portal archive path')
                    if member.isdir():
                        if name not in directories or member.mode != 0o755 or member.size != 0:
                            raise ValueError('Unreviewed portal directory')
                    else:
                        row = files.get(name)
                        if row is None:
                            raise ValueError('Unreviewed portal payload member')
                        if 'link' in row:
                            if not member.issym() or member.linkname != row['link'] or member.size != 0:
                                raise ValueError('Portal symlink differs from reviewed target')
                        elif not member.isfile() or member.mode != row['mode'] or member.size != row['bytes']:
                            raise ValueError('Portal file type, mode or length changed')
                    entries[name] = member
                if set(entries) != set(files) | directories:
                    raise ValueError('Incomplete portal prefix archive')
                destination.mkdir(mode=0o700); created = True
                for name in sorted(directories,key=lambda name:(name.count('/'),name)):
                    (destination/name).mkdir(mode=0o755)
                for name,row in files.items():
                    if 'link' in row:continue
                    target = destination/name
                    with bundle.extractfile(entries[name]) as source,target.open('xb') as output:
                        shutil.copyfileobj(source,output,length=64*1024)
                    target.chmod(row['mode'])
                    if digest(target) != row['sha256']:
                        raise ValueError('Portal installed-file bytes changed')
                for name,row in files.items():
                    if 'link' in row:(destination/name).symlink_to(row['link'])
                for name,row in files.items():
                    if 'link' not in row:continue
                    try:resolved = (destination/name).resolve(strict=True)
                    except (OSError,RuntimeError) as error:raise ValueError('Dangling or cyclic portal link') from error
                    if not resolved.is_file() or not resolved.is_relative_to(destination/'portal'):
                        raise ValueError('Portal link leaves its regular prefix files')
        return manifest
    except BaseException:
        if created:shutil.rmtree(destination)
        raise
