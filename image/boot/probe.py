"""Read installed boot inputs without privileges, network, disk targets or installation."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess


def regular(path, maximum=1024**3):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
        raise ValueError('Expected a bounded regular installed file: '+str(path))
    with path.open('rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'bytes': info.st_size, 'sha256': digest, 'uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode)}


def settings(path):
    if path.stat().st_size > 65536: raise ValueError('Oversized installed configuration')
    result = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        key, value = line.split('=', 1)
        tokens = shlex.split(value, comments=True)
        if key in result or len(tokens) != 1: raise ValueError('Ambiguous installed configuration')
        result[key] = tokens[0]
    return result


def main():
    if os.geteuid() != 10001 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the unprivileged hosted Atomic image inspection container')
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {n: (group/n).read_text().strip() for n in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    status = dict(row.split(':', 1) for row in Path('/proc/self/status').read_text().splitlines() if ':' in row)
    report = {'schema': 1, 'os_qualified': False, 'guest_booted': False, 'uid': os.geteuid(), 'limits': limits,
              'cap_eff': status['CapEff'].strip(), 'no_new_privileges': status['NoNewPrivs'].strip(),
              'root_readonly': bool(os.statvfs('/').f_flag & os.ST_RDONLY),
              'interfaces': sorted(p.name for p in Path('/sys/class/net').iterdir())}
    if (limits != {'memory.max':'536870912','memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'64'}
            or report['cap_eff'] != '0000000000000000' or report['no_new_privileges'] != '1'
            or not report['root_readonly'] or report['interfaces'] != ['lo']):
        raise ValueError('Atomic preflight container isolation changed')
    expected = json.loads(Path('/qualification/expected.json').read_text())
    kernel = expected['kernel']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{1,127}', kernel): raise ValueError('Unsafe kernel name')
    commands = []
    def run(command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=True)
        if len(result.stdout.encode()) > 65536 or len(result.stderr.encode()) > 65536:
            raise ValueError('Boot-input observation exceeded its output limit')
        commands.append({'command':command, 'stdout':result.stdout, 'stderr':result.stderr, 'exit_code':result.returncode})
        return result.stdout
    report['packages'] = run(['/usr/bin/rpm','-q','bootc','kernel-core','--qf',
                              '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n']).splitlines()
    report['bootc_version'] = run(['/usr/bin/bootc','--version']).strip()
    report['root_fs'] = json.loads(run(['/usr/bin/bootc','install','print-configuration']))
    report['install_configuration'] = json.loads(run(['/usr/bin/bootc','install','print-configuration','--all']))
    help_text = run(['/usr/bin/bootc','install','to-disk','--help'])
    report['install_options'] = sorted(set(re.findall(r'--[a-z][a-z0-9-]*',help_text)))
    report['os'] = settings(Path('/etc/os-release'))
    report['selinux'] = settings(Path('/etc/selinux/config'))
    report['kernel'] = {'version':kernel, **{name:regular(Path('/usr/lib/modules')/kernel/name)
                                          for name in ('vmlinuz','initramfs.img')}}
    report['trust'] = {path:regular(Path('/')/path,65536) for path in
                      ('etc/containers/policy.json','etc/containers/registries.d/symbiont.yaml')}
    report['backend_files'] = {}
    for name in ('/usr/lib/ostree/prepare-root.conf','/etc/ostree/prepare-root.conf',
                 '/usr/lib/composefs/setup-root-conf.toml'):
        path=Path(name)
        if path.exists():
            info=regular(path,65536);info['text']=path.read_text();report['backend_files'][name]=info
    report['tools'] = {}
    for name in ('bootc','bootupctl','grub2-install','grub2-mkconfig','mkfs.btrfs','mkfs.ext4','mkfs.xfs',
                 'qemu-system-x86_64','qemu-img','xorriso'):
        path=Path('/usr/bin')/name
        if not path.exists(): path=Path('/usr/sbin')/name
        report['tools'][name]={'present':path.exists(),'path':str(path) if path.exists() else None}
    report['commands'] = commands
    report['cgroup_final'] = {name:(group/name).read_text().strip() for name in ('memory.peak','memory.events','cpu.stat')}
    report['scope']='Read-only installed boot inputs; SELinux enforcement, actual installation and boot remain untested'
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__': main()
