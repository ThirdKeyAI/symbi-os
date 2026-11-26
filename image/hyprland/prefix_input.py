"""Reuse the exact hosted compiler output without trusting archive paths or modes."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import stat
import tarfile
import tempfile
import zipfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unpack_prefix(archive, lock, destination, link_rewrites=None):
    if archive.is_symlink() or not archive.is_file():
        raise ValueError('Expected the regular hosted prefix artifact')
    if archive.stat().st_size != lock['artifact']['bytes'] or digest(archive) != lock['artifact']['sha256']:
        raise ValueError('Hosted compiler artifact changed')
    if lock.get('qualified') is not False or lock.get('product_installation') is not False:
        raise ValueError('Compiler output alone cannot assert OS qualification')
    if (destination.exists() or destination.is_symlink() or not destination.parent.is_dir()
            or destination.parent.resolve() != destination.parent):
        raise ValueError('Use a new destination under an existing nonsymlinked parent')
    created, rewrites = False, []
    try:
        with tempfile.TemporaryDirectory(prefix='prefix-input-', dir=destination.parent) as temporary:
            payload = Path(temporary) / 'payload.tar.gz'
            with zipfile.ZipFile(archive) as bundle:
                names = bundle.namelist()
                if len(names) != 2 or set(names) != {'manifest.json', 'hyprland-prefix.tar.gz'}:
                    raise ValueError('Unexpected or duplicate compiler ZIP member')
                for member in bundle.infolist():
                    if member.flag_bits & 1 or stat.S_IFMT(member.external_attr >> 16) not in (0, stat.S_IFREG):
                        raise ValueError('Linked, special or encrypted compiler ZIP member')
                if bundle.getinfo('manifest.json').file_size > 65536:
                    raise ValueError('Oversized compiler manifest')
                if bundle.getinfo('hyprland-prefix.tar.gz').file_size > 512*1024**2:
                    raise ValueError('Oversized compressed compiler prefix')
                raw = bundle.read('manifest.json')
                manifest = json.loads(raw)
                if hashlib.sha256(raw).hexdigest() != lock['manifest_sha256'] or manifest != lock['manifest']:
                    raise ValueError('Compiler manifest differs from the reviewed lock')
                if (manifest.get('compiled') is not True or manifest.get('os_qualified') is not False
                        or manifest.get('native_loading_qualified') is not False
                        or manifest.get('selected_base_qualified') is not False):
                    raise ValueError('Unexpected compilation or qualification claim')
                with bundle.open('hyprland-prefix.tar.gz') as source, payload.open('xb') as output:
                    shutil.copyfileobj(source, output, length=1024**2)
            if digest(payload) != manifest['payload_sha256']:
                raise ValueError('Compiled prefix payload changed')
            with tarfile.open(payload, 'r:gz') as bundle:
                entries, total = {}, 0
                for member in bundle:
                    name = member.name.rstrip('/')
                    path = PurePosixPath(name)
                    if (not name or path.is_absolute() or path.parts[0] != 'hyprland'
                            or '..' in path.parts or path.as_posix() != name or '\\' in name):
                        raise ValueError('Archive path escapes or aliases the private prefix')
                    if name in entries or len(entries) >= 20000:
                        raise ValueError('Duplicate or excessive prefix member')
                    if not (member.isfile() or member.isdir() or member.issym()):
                        raise ValueError('Special files and hard links are not compiler inputs')
                    if member.size < 0 or member.size > 128*1024**2:
                        raise ValueError('Oversized prefix member')
                    total += member.size
                    if total > 1024**3:
                        raise ValueError('Oversized expanded compiler prefix')
                    if member.issym():
                        # Pinned Hyprland CMakeLists.txt installs exactly this alias
                        # using CMAKE_INSTALL_FULL_BINDIR. Relocate only that pair;
                        # arbitrary absolute links remain forbidden.
                        if (name == 'hyprland/bin/hyprland'
                                and member.linkname == '/usr/lib/symbi/hyprland/bin/Hyprland'):
                            rewrites.append({'name': name, 'original_target': member.linkname,
                                             'relative_target': 'Hyprland'})
                            member.linkname = 'Hyprland'
                        target = posixpath.normpath(posixpath.join(str(path.parent), member.linkname))
                        if (not member.linkname or member.linkname.startswith('/') or '\\' in member.linkname
                                or not target.startswith('hyprland/')):
                            raise ValueError('Compiler link escapes the private prefix: '
                                             f'{name[:160]!r} -> {member.linkname[:160]!r}')
                    entries[name] = member
                for name in entries:
                    for parent in PurePosixPath(name).parents:
                        if str(parent) in entries and not entries[str(parent)].isdir():
                            raise ValueError('Archive member traverses a linked or non-directory parent')
                if 'hyprland' not in entries or not entries['hyprland'].isdir():
                    raise ValueError('Missing private prefix root')
                destination.mkdir(mode=0o700)
                created = True
                # Create only regular files/directories first. Links cannot redirect writes.
                for name, member in entries.items():
                    target = destination / name
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        target.chmod(0o755)
                    elif member.isfile():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with bundle.extractfile(member) as source, target.open('xb') as output:
                            shutil.copyfileobj(source, output, length=1024**2)
                        target.chmod(0o755 if member.mode & 0o111 else 0o644)
                for name, member in entries.items():
                    if member.issym():
                        target = destination / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.symlink_to(member.linkname)
                for name, member in entries.items():
                    if member.issym():
                        try:
                            resolved = (destination / name).resolve(strict=True)
                        except (OSError, RuntimeError) as error:
                            raise ValueError('Dangling or cyclic compiler link') from error
                        if not resolved.is_relative_to(destination / 'hyprland'):
                            raise ValueError('Resolved compiler link escapes its prefix')
            for name in ('Hyprland', 'hyprctl'):
                binary = destination / 'hyprland/bin' / name
                if binary.is_symlink() or not binary.is_file() or digest(binary) != manifest['binaries'][name]:
                    raise ValueError('Compiled executable differs from the retained manifest')
        if link_rewrites is not None:
            link_rewrites.extend(rewrites)
        return manifest
    except BaseException:
        if created:
            shutil.rmtree(destination)
        raise
