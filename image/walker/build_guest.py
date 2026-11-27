#!/usr/bin/env python3
"""Acquire checksummed crates, then build the exact Walker source offline."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from inputs import digest, require_source, require_rust_identity


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ''
    if mode not in ('download', 'compile') or os.geteuid() != 10001 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the unprivileged disposable hosted Rust stage')
    inputs, output = Path('/inputs'), Path('/output')
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group/name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if limits != {'memory.max': '3221225472', 'memory.swap.max': '0',
                  'cpu.max': '200000 100000', 'pids.max': '128'}:
        raise ValueError('Unexpected Rust source-stage limits')
    pins = json.loads((inputs/'walker-source.json').read_text())
    evidence, source = output/(mode+'-evidence'), output/'source'
    evidence.mkdir()
    environment = {'PATH': '/usr/bin:/bin', 'HOME': '/output/home', 'LANG': 'C.UTF-8', 'TMPDIR': '/output/tmp',
                   'RUSTC': '/usr/bin/rustc', 'RUSTDOC': '/usr/bin/rustdoc', 'PROTOC': '/usr/bin/protoc',
                   'CARGO_HOME': '/output/cargo-home', 'CARGO_TARGET_DIR': '/output/target',
                   'CARGO_BUILD_JOBS': '1', 'CARGO_INCREMENTAL': '0',
                   'CARGO_PROFILE_RELEASE_DEBUG': '0', 'CARGO_PROFILE_RELEASE_CODEGEN_UNITS': '1',
                   'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
                   'CARGO_REGISTRIES_CRATES_IO_PROTOCOL': 'sparse',
                   'CARGO_REGISTRIES_CRATES_IO_INDEX': 'sparse+https://index.crates.io/',
                   'CARGO_NET_OFFLINE': 'false' if mode == 'download' else 'true',
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    record = {'passed': False, 'compiled': False, 'os_qualified': False, 'mode': mode,
              'limits': limits, 'source_revision': pins['revision'], 'commands': [], 'environment': environment}

    def save():
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=1200):
        record['active_command'] = {'name': name, 'command': command}
        save()
        with (evidence/(name+'.log')).open('xb') as log:
            result = subprocess.run(command, cwd=source, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']
        save()
        result.check_returncode()

    try:
        if mode == 'download':
            shutil.copytree(inputs/'source', source, ignore=shutil.ignore_patterns('.git'))
            for name in ('home', 'tmp', 'cargo-home'):
                (output/name).mkdir(mode=0o700)
        graph = require_source(source, pins)
        if graph != {'packages': 284, 'registry_dependencies': 283}:
            raise ValueError('Unexpected locked Walker graph')
        record['locked_graph'] = graph
        record['toolchain'] = {}
        for name in ('rustc', 'cargo'):
            run(name+'-identity', ['/usr/bin/'+name, '--version', '--verbose'], 30)
            record['toolchain'][name] = require_rust_identity((evidence/(name+'-identity.log')).read_text(), name)
        target = 'x86_64-unknown-linux-gnu'
        if mode == 'download':
            run('download-locked-crates', ['/usr/bin/cargo', 'fetch', '--locked', '--target', target], 1500)
        else:
            flags = ['--frozen', '--offline', '--release', '--target', target, '--jobs', '1']
            run('source-build', ['/usr/bin/cargo', 'build', *flags, '--bin', 'walker'], 5400)
            binary = output/'target'/target/'release/walker'
            if binary.is_symlink() or not binary.is_file() or not 0 < binary.stat().st_size <= 128*1024**2:
                raise ValueError('Expected one bounded compiled Walker executable')
            destination = output/'binaries'
            destination.mkdir()
            shutil.copyfile(binary, destination/'walker')
            (destination/'walker').chmod(0o755)
            record['compiled'] = True
            record['binary_sha256'] = digest(destination/'walker')
            record['binary_bytes'] = binary.stat().st_size
            save()
            run('upstream-tests', ['/usr/bin/cargo', 'test', *flags, '--workspace', '--all-targets', '--', '--test-threads=1'], 1800)
            run('needed-libraries', ['/usr/bin/ldd', str(binary)], 30)
            if 'not found' in (evidence/'needed-libraries.log').read_text():
                raise ValueError('Compiler-stage libraries did not resolve')
        require_source(source, pins)
        record['source_locks_unchanged'] = True
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__':
    main()
