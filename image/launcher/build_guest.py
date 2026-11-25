#!/usr/bin/env python3
"""Download locked modules, then compile actual launcher controls offline."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ''
    if mode not in ('download', 'compile') or os.geteuid() != 10001 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the unprivileged disposable hosted Go stage')
    inputs, output = Path('/inputs'), Path('/output')
    group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group/name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    assert limits == {'memory.max': '3221225472', 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '128'}
    pins = json.loads((inputs/'elephant-source.json').read_text())
    patch = json.loads((inputs/'provider-patch.json').read_text())
    assert pins['revision'] == patch['upstream_revision']
    evidence = output/(mode+'-evidence')
    evidence.mkdir()
    source = output/'source'
    environment = {'PATH': '/usr/bin:/bin', 'HOME': '/output/home', 'LANG': 'C.UTF-8',
                   'GOTOOLCHAIN': 'local', 'GOFLAGS': '-mod=readonly -p=1', 'GOMAXPROCS': '1',
                   'GOPATH': '/output/go', 'GOCACHE': '/output/go-build', 'CGO_ENABLED': '1', 'TMPDIR': '/output/tmp',
                   'GOPROXY': 'https://proxy.golang.org' if mode == 'download' else 'off',
                   'GOSUMDB': 'sum.golang.org' if mode == 'download' else 'off',
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    record = {'passed': False, 'os_qualified': False, 'mode': mode, 'limits': limits,
              'source_revision': pins['revision'], 'commands': [], 'environment': environment}

    def save():
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def locks(directory):
        for name in ('go.mod', 'go.sum'):
            if digest(directory/name) != pins[name.replace('.', '_')+'_sha256']:
                raise ValueError('Upstream module lock changed: '+name)

    def run(name, command, cwd=source, timeout=1200):
        record['active_command'] = {'name': name, 'command': command}
        save()
        with (evidence/(name+'.log')).open('xb') as log:
            result = subprocess.run(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']
        save()
        result.check_returncode()

    try:
        if mode == 'download':
            shutil.copytree(inputs/'source', source, ignore=shutil.ignore_patterns('.git'))
            (output/'home').mkdir(mode=0o700)
            (output/'tmp').mkdir(mode=0o700)
        locks(source)
        run('compiler-version', ['go', 'version'])
        assert (evidence/'compiler-version.log').read_text().strip() == 'go version go1.27.4 linux/amd64'
        if mode == 'download':
            run('download-locked-modules', ['go', 'mod', 'download'], timeout=1200)
            run('verify-downloaded-modules', ['go', 'mod', 'verify'])
            run('module-inventory', ['go', 'list', '-m', '-json', 'all'])
        else:
            run('verify-offline-modules', ['go', 'mod', 'verify'])
            run('build-environment', ['go', 'env', '-json'])
            binaries = output/'binaries'
            binaries.mkdir()
            flags = ['go', 'build', '-buildvcs=false', '-trimpath', '-p=1', '-mod=readonly']
            run('build-baseline', flags+['-o', str(binaries/'baseline'), './cmd/elephant'], timeout=2400)
            run('build-desktopapplications', flags+['-buildmode=plugin', '-o', str(binaries/'desktopapplications'),
                                                   './internal/providers/desktopapplications'], timeout=1800)
            run('build-constructor-control', flags+['-buildmode=plugin', '-o', str(binaries/'marker'),
                                                   '/inputs/probes/native_marker.go'], timeout=1200)
            patched = output/'patched'
            shutil.copytree(source, patched)
            assert digest(patched/'internal/providers/load.go') == patch['preimage_sha256']
            patch_file = inputs/'provider.patch'
            assert digest(patch_file) == patch['patch_sha256']
            run('check-provider-patch', ['git', 'apply', '--check', str(patch_file)], patched, 30)
            run('apply-provider-patch', ['git', 'apply', str(patch_file)], patched, 30)
            run('provider-format', ['gofmt', '-l', 'internal/providers/load.go', 'internal/providers/symbi_provider_linux.go'], patched, 30)
            assert not (evidence/'provider-format.log').read_text().strip()
            locks(patched)
            run('build-patched', flags+['-o', str(binaries/'patched'), './cmd/elephant'], patched, 2400)
            record['compiled'] = True
            record['binaries'] = {p.name: digest(p) for p in binaries.iterdir()}
            record['patch_sha256'] = patch['patch_sha256']
            save()
            run('upstream-tests', ['go', 'test', '-p=1', '-parallel=1', '-count=1', './...'], patched, 1800)
            locks(patched)
            for name in ('baseline', 'patched', 'desktopapplications', 'marker'):
                run(name+'-provenance', ['go', 'version', '-m', str(binaries/name)], timeout=30)
                run(name+'-needed-libraries', ['ldd', str(binaries/name)], timeout=30)
                assert 'not found' not in (evidence/(name+'-needed-libraries.log')).read_text()
        locks(source)
        record['module_locks_unchanged'] = True
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        record['cgroup_final'] = {name: (group/name).read_text().strip() for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__':
    main()
