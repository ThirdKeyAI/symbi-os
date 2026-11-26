"""Verify a retained development image before any hosted boot installer sees it."""
import hashlib
import os
import shutil
import stat
import zipfile

from image.toolchain.reuse import digest, exact_hash, unique_json


def require_desktop_image(lock, pins, variant):
    try:
        if (variant not in ('generic', 'nvidia') or type(lock['schema']) is not int or lock['schema'] != 1
                or lock['os_qualified'] is not False or lock['signature_qualified'] is not False
                or not isinstance(lock['images'], dict) or not set(lock['images']).issubset({'generic', 'nvidia'})):
            raise ValueError('Select an explicitly retained, unqualified development image')
        selected = lock['images'][variant]
        manifest, artifact = selected['manifest'], selected['artifact']
        if (not exact_hash(selected['tested_commit'], 40) or not exact_hash(selected['manifest_sha256'])
                or type(selected['run_id']) is not int or selected['run_id'] <= 0
                or type(artifact['id']) is not int or artifact['id'] <= 0
                or artifact['name'] != 'desktop-development-image-'+variant
                or not exact_hash(artifact['sha256']) or type(artifact['bytes']) is not int
                or not 0 < artifact['bytes'] <= 13*1024**3
                or type(manifest['schema']) is not int or manifest['schema'] != 1
                or manifest['built'] is not True or manifest['os_qualified'] is not False
                or manifest['source_commit'] != selected['tested_commit']
                or manifest['base'] != pins['variants'][variant]['image'] or manifest['variant'] != variant
                or not exact_hash(manifest['preparation_sha256'])):
            raise ValueError('Development image source, base, build or artifact identity changed')
        image = manifest['archive']
        if (image['name'] != 'symbiont-os-'+variant+'.oci.tar.gz'
                or type(image['bytes']) is not int or not 0 < image['bytes'] <= 12*1024**3
                or not exact_hash(image['sha256']) or not image['image_id'].startswith('sha256:')
                or not exact_hash(image['image_id'].removeprefix('sha256:'))):
            raise ValueError('Invalid bounded development OCI archive identity')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Malformed development image lock') from error
    return manifest


def unpack_desktop_image(archive, lock, pins, variant, destination):
    """Stream opaque OCI bytes; never extract their internal filesystem here."""
    manifest = require_desktop_image(lock, pins, variant)
    selected = lock['images'][variant]
    artifact, image = selected['artifact'], manifest['archive']
    if (archive.is_symlink() or not archive.is_file() or archive.resolve() != archive
            or archive.stat().st_size != artifact['bytes'] or digest(archive) != artifact['sha256']):
        raise ValueError('Development image artifact bytes changed')
    if (destination.exists() or destination.is_symlink() or not destination.parent.is_dir()
            or destination.parent.resolve() != destination.parent):
        raise ValueError('Use a new image destination under a regular existing parent')
    created = False
    try:
        with zipfile.ZipFile(archive) as bundle:
            rows = bundle.infolist()
            if len(rows) != 2 or {row.filename for row in rows} != {'manifest.json', image['name']}:
                raise ValueError('Unexpected, missing or duplicate development image ZIP member')
            for row in rows:
                maximum = 65536 if row.filename == 'manifest.json' else image['bytes']
                if (row.flag_bits & 1 or stat.S_IFMT(row.external_attr >> 16) not in (0, stat.S_IFREG)
                        or row.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or not 0 < row.file_size <= maximum):
                    raise ValueError('Unsafe or oversized development image ZIP member')
            raw = bundle.read('manifest.json')
            if hashlib.sha256(raw).hexdigest() != selected['manifest_sha256'] or unique_json(raw) != manifest:
                raise ValueError('Development image manifest differs from reviewed bytes')
            if bundle.getinfo(image['name']).file_size != image['bytes']:
                raise ValueError('Development OCI archive length changed')
            destination.mkdir(mode=0o700); created = True
            target = destination/image['name']
            checksum = hashlib.sha256(); total = pending = 0
            with bundle.open(image['name']) as incoming, target.open('xb') as outgoing:
                while chunk := incoming.read(64*1024):
                    total += len(chunk); pending += len(chunk)
                    if total > image['bytes']: raise ValueError('Development OCI stream exceeded its bound')
                    checksum.update(chunk); outgoing.write(chunk)
                    if pending >= 16*1024**2:
                        outgoing.flush(); os.fsync(outgoing.fileno())
                        os.posix_fadvise(outgoing.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                        pending = 0
                outgoing.flush(); os.fsync(outgoing.fileno())
                os.posix_fadvise(outgoing.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            if total != image['bytes'] or checksum.hexdigest() != image['sha256']:
                raise ValueError('Development OCI archive content changed')
            target.chmod(0o644)
            (destination/'manifest.json').write_bytes(raw)
            (destination/'manifest.json').chmod(0o644)
        return manifest
    except BaseException:
        if created: shutil.rmtree(destination)
        raise
