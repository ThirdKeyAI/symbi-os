"""Guard the one new regular-file target before invoking the image's bootc."""
import json
import os
from pathlib import Path
import sys

from contract import installer_arguments, require_disk


def main():
    if (os.geteuid()!=0 or not Path('/run/.containerenv').exists()
            or sys.argv[1:] or sorted(p.name for p in Path('/sys/class/net').iterdir())!=['lo']):
        raise SystemExit('Use only the offline disposable hosted installer container')
    group=Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]).relative_to('/')
    limits={name:(group/name).read_text().strip() for name in ('memory.max','memory.swap.max','cpu.max','pids.max')}
    if limits!={'memory.max':'2147483648','memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'128'}:
        raise ValueError('Installer resource limits changed')
    config=json.loads(Path('/inputs/install.json').read_bytes())
    require_disk(Path('/output/atomic.raw'),config['disk'])
    if not os.statvfs('/inputs/oci').f_flag & os.ST_RDONLY:
        raise ValueError('OCI source mount must be read-only')
    command=installer_arguments(config['manifest_digest'])
    print(json.dumps({'disk':config['disk'],'limits':limits,'command':command,
                      'scope':'Unsigned offline development artifact; enforce signature policy for later registry updates'}),flush=True)
    os.execve(command[0],command,{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8',
                                 'HOME':'/root','TMPDIR':'/var/tmp','RUST_BACKTRACE':'1'})


if __name__=='__main__': main()
