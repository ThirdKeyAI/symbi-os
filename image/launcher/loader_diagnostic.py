#!/usr/bin/env python3
"""Retain normal-startup diagnostics that upstream listproviders discards."""
import json
import os
from pathlib import Path
import stat
from bounded_process import run_bounded


def main():
    if os.geteuid() != 10001 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the disposable unprivileged loader diagnostic')
    group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group/name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if limits != {'memory.max': '268435456', 'memory.swap.max': '0',
                  'cpu.max': '100000 100000', 'pids.max': '64'}:
        raise ValueError('Unexpected loader diagnostic resource limits')
    output = Path('/output')
    record = {'scope': 'Normal-startup diagnostics only; listproviders discards all loader errors',
              'diagnostic_completed': False, 'provider_loading_qualified': False,
              'upstream_tests_passed': False, 'os_qualified': False, 'limits': limits, 'path_metadata': []}
    try:
        path = Path('/usr/lib/symbi/elephant/providers/desktopapplications.so')
        for item in (path, *path.parents):
            entry = item.lstat()
            record['path_metadata'].append({'path': str(item), 'uid': entry.st_uid, 'gid': entry.st_gid,
                                            'mode': oct(stat.S_IMODE(entry.st_mode)),
                                            'regular': stat.S_ISREG(entry.st_mode),
                                            'directory': stat.S_ISDIR(entry.st_mode),
                                            'symlink': stat.S_ISLNK(entry.st_mode)})
        for name in ('home', 'config', 'cache', 'runtime'):
            (output/'loader'/name).mkdir(mode=0o700, parents=True)
        # A fresh config has no user hooks; network and host-session access are
        # absent. timeout sends TERM, then KILL; the parent also removes Podman.
        command = ['env', 'HOME=/output/loader/home', 'XDG_CONFIG_HOME=/output/loader/config',
                   'XDG_CONFIG_DIRS=/inputs/no-system-config', 'XDG_CACHE_HOME=/output/loader/cache',
                   'XDG_RUNTIME_DIR=/output/loader/runtime', 'GOMAXPROCS=1',
                   'timeout', '--signal=TERM', '--kill-after=2s', '5s', '/inputs/binaries/patched', '--debug']
        record['command'] = command
        result = run_bounded(command, output/'loader-stdout.log', output/'loader-stderr.log', timeout=15)
        record['exit_code'] = result.returncode
        record['diagnostic_completed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        (output/'loader-result.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    main()
