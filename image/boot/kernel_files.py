"""Hash two protected files copied from a never-started, immutable image container."""
import hashlib
import os
import re
import stat


def validate_copy_container(rows, image_id):
    try:
        if (not isinstance(rows,list) or len(rows)!=1
                or 'sha256:'+rows[0]['Image'].removeprefix('sha256:')!=image_id
                or rows[0]['State']['Status']!='created' or rows[0]['State']['Running'] is not False
                or type(rows[0]['State']['Pid']) is not int or rows[0]['State']['Pid']!=0):
            raise ValueError('Kernel-copy source must be the exact image and never started')
    except (KeyError,TypeError,AttributeError) as error:
        raise ValueError('Malformed kernel-copy container observation') from error


def read_copied_kernel(directory, version):
    if (directory.is_symlink() or not directory.is_dir() or directory.resolve()!=directory
            or directory.stat().st_uid!=os.geteuid() or stat.S_IMODE(directory.stat().st_mode)!=0o700
            or {path.name for path in directory.iterdir()}!={'vmlinuz','initramfs.img'}
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{1,127}',version)):
        raise ValueError('Expected exactly two copied kernel files in new private storage')
    result={'version':version}
    for name in ('vmlinuz','initramfs.img'):
        path=directory/name;info=path.lstat();mode=stat.S_IMODE(info.st_mode)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                or not 0<info.st_size<=1024**3 or mode>0o777 or mode&0o022):
            raise ValueError('Unsafe or missing copied kernel file: '+name)
        with path.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
        result[name]={'bytes':info.st_size,'sha256':digest,'uid':info.st_uid,'mode':mode}
    return result
