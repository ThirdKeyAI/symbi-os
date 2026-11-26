"""Bounded regular-file copying and inventory shared by hosted image jobs."""
import os

from image.toolchain.reuse import digest


def copy_regular(source, target, executable=False):
    if source.is_symlink() or not source.is_file() or source.resolve() != source:
        raise ValueError('Expected a regular prepared input: '+str(source))
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        raise ValueError('Overlapping desktop payload: '+str(target))
    # Keep dirty file pages bounded as well as Python buffers. A complete
    # runtime executable is about 500 MiB; copying it in one sendfile call can
    # otherwise retain a large dirty working set inside a small cgroup.
    with source.open('rb') as incoming, target.open('xb') as outgoing:
        pending = 0
        while chunk := incoming.read(1024**2):
            outgoing.write(chunk)
            pending += len(chunk)
            if pending >= 16*1024**2:
                outgoing.flush()
                os.fsync(outgoing.fileno())
                os.posix_fadvise(outgoing.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                pending = 0
        outgoing.flush()
        os.fsync(outgoing.fileno())
        os.posix_fadvise(outgoing.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
    target.chmod(0o755 if executable else 0o644)


def release_file_cache(directory):
    """Sync only this run's extracted files, then release their clean cache."""
    for path in directory.rglob('*'):
        if path.is_file() and not path.is_symlink():
            with path.open('r+b') as stream:
                os.fsync(stream.fileno())
                os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)


def inventory(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        name = path.relative_to(directory).as_posix()
        if path.is_symlink():
            result[name] = {'link': os.readlink(path)}
        elif path.is_file():
            result[name] = {'sha256': digest(path), 'bytes': path.stat().st_size, 'mode': path.stat().st_mode & 0o777}
        elif not path.is_dir():
            raise ValueError('Special build context member')
    return result
