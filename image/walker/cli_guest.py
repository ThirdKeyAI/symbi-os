#!/usr/bin/env python3
"""Actual bounded CLI controls; these do not qualify the graphical launcher."""
import json
import os
from pathlib import Path
from bounded_process import run_bounded
from inputs import digest


def run_cli(command, output, version):
    output.mkdir()
    record = {'passed': False, 'gui_qualified': False, 'os_qualified': False, 'cases': [],
              'scope': 'Actual version/help/parser controls only; no graphical or desktop acceptance'}
    try:
        for name, argument in (('version', '--version'), ('help', '--help'),
                               ('unknown-option', '--symbi-unknown-qualification-option'),
                               ('repeated-version', '--version')):
            result = run_bounded(command+[argument], output/(name+'-stdout.log'), output/(name+'-stderr.log'))
            if argument == '--version':
                passed = result.returncode == 0 and result.stdout.strip() == version and not result.stderr.strip()
            elif argument == '--help':
                passed = (result.returncode == 0 and 'Usage:' in result.stdout
                          and '--version' in result.stdout and '--provider' in result.stdout)
            else:
                passed = result.returncode != 0 and 'Unknown option' in result.stderr and argument in result.stderr
            record['cases'].append({'name': name, 'argument': argument,
                                    'exit_code': result.returncode, 'passed': passed})
            if not passed:
                raise ValueError('Actual Walker CLI control failed: '+name)
        record['passed'] = True
        return record
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(record, indent=2)+'\n')


def main():
    if (os.geteuid() != 10001 or not Path('/run/.containerenv').exists()
            or os.environ.get('GITHUB_ACTIONS') != 'true'):
        raise SystemExit('Use the isolated unprivileged hosted Walker runtime stage')
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group/name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if limits != {'memory.max': '536870912', 'memory.swap.max': '0',
                  'cpu.max': '100000 100000', 'pids.max': '64'}:
        raise ValueError('Unexpected Walker runtime limits')
    output, binary = Path('/output'), Path('/inputs/walker')
    manifest = json.loads(Path('/inputs/compiled-manifest.json').read_text())
    if binary.is_symlink() or not binary.is_file() or digest(binary) != manifest['binary_sha256']:
        raise ValueError('Walker executable differs from the retained build')
    record = {'passed': False, 'gui_qualified': False, 'os_qualified': False,
              'limits': limits, 'binary_sha256': digest(binary)}
    try:
        needed = run_bounded(['/usr/bin/ldd', str(binary)], output/'needed-libraries.log', output/'needed-libraries-stderr.log')
        if needed.returncode != 0 or 'not found' in needed.stdout+needed.stderr:
            raise ValueError('Walker libraries do not resolve on the original base plus reviewed runtime library')
        for name in ('home', 'config', 'cache', 'runtime'):
            (output/name).mkdir(mode=0o700)
        command = ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C.UTF-8', 'HOME=/output/home',
                   'XDG_CONFIG_HOME=/output/config', 'XDG_CACHE_HOME=/output/cache',
                   'XDG_RUNTIME_DIR=/output/runtime', str(binary)]
        record['cli'] = run_cli(command, output/'cli', manifest['version'])
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        (output/'result.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    main()
