#!/usr/bin/env python3
"""Retain normal-startup diagnostics that upstream listproviders discards."""
import json
import os
from pathlib import Path
import stat
import subprocess
from bounded_process import run_bounded


def capture_startup(command, output, record, timeout=5):
    """Capture a direct child, preserving the report before any execution."""
    record.update(command=command, timeout_seconds=timeout, timed_out=False)
    report = output/'loader-result.json'
    report.write_text(json.dumps(record, indent=2)+'\n')
    try:
        try:
            result = run_bounded(command, output/'loader-stdout.log', output/'loader-stderr.log', timeout=timeout)
            record['exit_code'] = result.returncode
        except subprocess.TimeoutExpired:
            # This service normally remains alive. run_bounded kills and reaps
            # the direct child; the hosted parent still removes the container.
            record.update(timed_out=True, exit_code=None)
        record['diagnostic_completed'] = True
    except Exception as error:
        record['execution_failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        report.write_text(json.dumps(record, indent=2)+'\n')


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
        # absent. env execs the service directly; no nested timeout supervisor.
        command = ['env', 'HOME=/output/loader/home', 'XDG_CONFIG_HOME=/output/loader/config',
                   'XDG_CONFIG_DIRS=/inputs/no-system-config', 'XDG_CACHE_HOME=/output/loader/cache',
                   'XDG_RUNTIME_DIR=/output/loader/runtime', 'GOMAXPROCS=1',
                   '/inputs/binaries/patched', '--debug']
        capture_startup(command, output, record)
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        (output/'loader-result.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    main()
