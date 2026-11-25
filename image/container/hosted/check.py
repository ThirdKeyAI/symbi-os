#!/usr/bin/env python3
"""Authenticate and run container fixtures on a disposable hosted Ubuntu VM."""
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import time

from inputs import digest, require_signature, unpack_runtime


def main():
    if os.getuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise SystemExit('Container fixture execution requires the disposable hosted resource unit')
    account = pwd.getpwnam(os.environ['FIXTURE_USER'])
    assert account.pw_uid > 0
    root = Path.cwd()
    configuration = root / 'image/container/hosted'
    lock = json.loads((configuration / 'inputs.lock.json').read_text())
    work = root / '.cache/container-fixture-work'
    work.mkdir()
    public = work / 'public'
    public.mkdir()
    process_group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    assert process_group.name == 'supervisor'
    group = process_group.parent
    assert group.name.startswith('symbi-container-fixtures-') and group.name.endswith('.service')
    assert not (group / 'cgroup.procs').read_text().strip()
    names = ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')
    limits = {name: (group / name).read_text().strip() for name in names}
    assert limits == {'memory.max': '4294967296', 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '256'}
    record = {'passed': False, 'qualified': False, 'limits': limits, 'commands': [],
              'source_commit': os.environ['GITHUB_SHA'],
              'scope': 'Ubuntu Docker/gVisor development fixtures; no Fedora or release qualification'}

    def save():
        (public / 'result.json').write_text(json.dumps(record, indent=2) + '\n')

    def run(name, command, timeout=300, cwd=None, env=None, check=True):
        record['active_command'] = {'name': name, 'command': command}
        save()
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
        (public / (name + '.log')).write_text(result.stdout + result.stderr)
        record['commands'].append({'name': name, 'command': command, 'exit_code': result.returncode})
        del record['active_command']
        save()
        if check:
            result.check_returncode()
        return result

    def download(name, url, expected_size, expected_digest, destination):
        run(name, ['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                   '--proto-redir', '=https', '--tlsv1.2', '--connect-timeout', '20', '--max-time', '600',
                   '--limit-rate', '5M', '--max-filesize', str(expected_size), '--output', str(destination), url], 610)
        assert destination.is_file() and not destination.is_symlink()
        assert destination.stat().st_size == expected_size and digest(destination) == expected_digest

    def authenticate(name, directory, signature, payload, fingerprint):
        home = work / (name + '-gpg')
        home.mkdir(mode=0o700)
        result = run(name + '-signature', ['gpgv', '--homedir', str(home), '--keyring', str(directory / 'archive.gpg'),
                                          '--status-fd=1', str(directory / signature), str(directory / payload)])
        require_signature(result.returncode, result.stdout, fingerprint)

    daemon = None
    daemon_log = None
    try:
        for name, expected in lock['input_sha256'].items():
            path = configuration / name
            assert path.resolve(strict=True).is_relative_to(configuration)
            assert not path.is_symlink() and digest(path) == expected
        unpack_runtime(root / '.cache/checked-runtime.zip', lock, work / 'bin')
        source = work / 'source'
        source.mkdir()
        git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never', '-C', str(source)]
        run('source-init', git + ['init'])
        run('source-fetch', git + ['fetch', '--depth=2', '--no-tags', 'https://github.com/ThirdKeyAI/Symbiont.git', lock['fixture_commit']])
        run('source-checkout', git + ['checkout', '--detach', 'FETCH_HEAD'])
        assert subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == lock['fixture_commit']
        assert subprocess.check_output(git + ['rev-parse', 'HEAD^'], text=True).strip() == lock['source_revision']
        patch = subprocess.check_output(git + ['diff', 'HEAD^', 'HEAD', '--binary', '--full-index',
                                               '--src-prefix=a/', '--dst-prefix=b/'])
        import hashlib
        assert hashlib.sha256(patch).hexdigest() == lock['patch_sha256']
        assert digest(source / 'Cargo.lock') == lock['cargo_lock_sha256']
        gvisor = configuration / 'gvisor'
        provenance = json.loads((gvisor / 'verified-metadata.json').read_text())
        authenticate('gvisor', gvisor, 'Release.gpg', 'Release', provenance['signing_fingerprint'])
        package_index = gvisor / 'Packages'
        release = (gvisor / 'Release').read_text().split('SHA256:\n', 1)[1].split('SHA512:', 1)[0]
        index_rows = [line.split() for line in release.splitlines() if line.strip()]
        assert [row for row in index_rows if row[2] == 'main/binary-amd64/Packages'] == [[digest(package_index), str(package_index.stat().st_size), 'main/binary-amd64/Packages']]
        fields = dict(line.split(': ', 1) for line in package_index.read_text().strip().splitlines())
        package = provenance['package']
        assert all(fields[key] == value for key, value in package.items())
        runsc_deb = work / 'runsc.deb'
        download('download-runsc', provenance['package_url'], int(package['Size']), package['SHA256'], runsc_deb)
        runsc_root = work / 'runsc'
        run('extract-runsc', ['dpkg-deb', '--extract', str(runsc_deb), str(runsc_root)])
        inventory = json.loads((gvisor / 'package-inventory.json').read_text())
        assert {str(path.relative_to(runsc_root)) for path in runsc_root.rglob('*')} == {entry['path'] for entry in inventory['entries']}
        for entry in inventory['entries']:
            path = runsc_root / entry['path']
            mode = path.lstat()
            assert not path.is_symlink() and mode.st_uid == 0 and stat.S_IMODE(mode.st_mode) == entry['mode']
            if entry['type'] == '5':
                assert stat.S_ISDIR(mode.st_mode)
            else:
                assert entry['type'] == '0' and stat.S_ISREG(mode.st_mode)
                assert path.stat().st_size == entry['bytes'] and digest(path) == entry['sha256']
        runsc = runsc_root / 'usr/bin/runsc'
        run('runsc-version', [str(runsc), '--version'])
        ubuntu = configuration / 'ubuntu'
        rootfs = json.loads((ubuntu / 'verified-rootfs.json').read_text())
        authenticate('ubuntu', ubuntu, 'SHA256SUMS.gpg', 'SHA256SUMS', rootfs['signing_fingerprint'])
        assert rootfs['sha256'] + ' *' + rootfs['archive'] in (ubuntu / 'SHA256SUMS').read_text().splitlines()
        context = work / 'fixture-image'
        shutil.copytree(configuration / 'fixture', context)
        download('download-rootfs', rootfs['url'], rootfs['bytes'], rootfs['sha256'], context / rootfs['archive'])
        docker_env = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8',
                      'DOCKER_HOST': 'unix:///var/run/docker.sock', 'DOCKER_CONFIG': str(work / 'docker-client'),
                      'DOCKER_BUILDKIT': '0'}
        (work / 'docker-client').mkdir(mode=0o700)
        initial = run('initial-containers', ['docker', 'ps', '-aq'], env=docker_env)
        assert not initial.stdout.strip(), 'Do not interrupt an existing workload'
        run('stop-runner-docker', ['systemctl', 'stop', 'docker.service', 'docker.socket'])
        config = {'hosts': ['unix:///var/run/docker.sock'], 'data-root': str(work / 'docker-data'),
                  'exec-root': str(work / 'docker-exec'), 'pidfile': str(work / 'docker.pid'),
                  'runtimes': {'runsc': {'path': str(runsc)}}, 'default-runtime': 'runc',
                  'exec-opts': ['native.cgroupdriver=cgroupfs'],
                  'cgroup-parent': '/' + str(group.relative_to('/sys/fs/cgroup')),
                  'bridge': 'none', 'iptables': False, 'ip-forward': False, 'ip-masq': False,
                  'userland-proxy': False, 'live-restore': False, 'log-driver': 'local',
                  'log-opts': {'max-size': '10m', 'max-file': '2'}}
        config_path = work / 'daemon.json'
        config_path.write_text(json.dumps(config, indent=2) + '\n')
        shutil.copyfile(config_path, public / 'daemon.json')
        run('validate-daemon', ['dockerd', '--validate', '--config-file', str(config_path)])
        daemon_log = (public / 'dockerd.log').open('w')
        daemon = subprocess.Popen(['dockerd', '--config-file', str(config_path)], stdout=daemon_log, stderr=subprocess.STDOUT)
        ready = False
        for _ in range(60):
            assert daemon.poll() is None, 'Dedicated Docker daemon exited'
            status = subprocess.run(['docker', 'info', '--format', '{{.DockerRootDir}}'], env=docker_env, capture_output=True, text=True, timeout=5)
            if status.returncode == 0 and status.stdout.strip() == str(work / 'docker-data'):
                ready = True
                break
            time.sleep(1)
        assert ready, 'Dedicated Docker daemon did not become ready'
        run('docker-version', ['docker', 'version', '--format', '{{json .}}'], env=docker_env)
        run('docker-info', ['docker', 'info', '--format', '{{json .}}'], env=docker_env)
        image_file = work / 'fixture-image-id'
        # Only the authenticated development-image package installation uses
        # host networking. Every actual tool worker uses the upstream none policy.
        run('fixture-image-build', ['docker', 'build', '--pull=false', '--rm', '--force-rm',
                                   '--memory=512m', '--memory-swap=512m', '--cpu-period=100000', '--cpu-quota=100000',
                                   '--network=host', '--iidfile', str(image_file), str(context)], 1800, env=docker_env)
        image_id = image_file.read_text().strip()
        assert re.fullmatch(r'sha256:[a-f0-9]{64}', image_id)
        run('fixture-image-inspect', ['docker', 'image', 'inspect', image_id], env=docker_env)
        stopped = run('create-evidence-container', ['docker', 'create', '--network=none', image_id], env=docker_env).stdout.strip()
        assert re.fullmatch(r'[a-f0-9]{64}', stopped)
        try:
            (public / 'fixture-packages').mkdir()
            run('copy-fixture-packages', ['docker', 'cp', stopped + ':/usr/share/symbi-fixture-evidence/.', str(public / 'fixture-packages')], env=docker_env)
        finally:
            run('remove-evidence-container', ['docker', 'rm', stopped], env=docker_env)
        # Prove both daemon-selected runtimes place their host process under
        # this bounded unit before running any of the larger fixture drivers.
        for backend in ('runc', 'runsc'):
            identity = run('probe-create-' + backend, ['docker', 'create', '--runtime=' + backend,
                           '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                           '--user=1000:1000', '--memory=256m', '--memory-swap=256m', '--cpus=1', '--pids-limit=64',
                           image_id, 'python3', '-c', 'import time; time.sleep(30)'], env=docker_env).stdout.strip()
            assert re.fullmatch(r'[a-f0-9]{64}', identity)
            try:
                run('probe-start-' + backend, ['docker', 'start', identity], env=docker_env)
                observed = json.loads(run('probe-inspect-' + backend, ['docker', 'inspect', identity], env=docker_env).stdout)[0]
                pid = observed['State']['Pid']
                assert observed['State']['Running'] and isinstance(pid, int) and pid > 1
                actual_group = Path('/proc') / str(pid) / 'cgroup'
                value = actual_group.read_text()
                (public / ('probe-cgroup-' + backend + '.txt')).write_text(value)
                assert ('/' + str(group.relative_to('/sys/fs/cgroup')) + '/') in value
            finally:
                run('probe-remove-' + backend, ['docker', 'rm', '--force', identity], env=docker_env)
        private = work / 'private'
        for path in [private, private / 'home', private / 'docker-client', private / 'tmp']:
            path.mkdir(mode=0o700)
            os.chown(path, account.pw_uid, account.pw_gid)
        os.chown(public, account.pw_uid, account.pw_gid)
        setup = {'image_id': image_id, 'runsc': str(runsc), 'binary_sha256': lock['binaries']['symbi']['sha256'],
                 'source_revision': lock['source_revision'], 'fixture_commit': lock['fixture_commit'],
                 'patch_sha256': lock['patch_sha256'], 'source_lock_sha256': lock['cargo_lock_sha256']}
        (public / 'setup.json').write_text(json.dumps(setup, indent=2) + '\n')
        run('complete-fixtures', ['/usr/sbin/runuser', '-u', account.pw_name, '--', 'env', '-i',
                                  'PATH=/usr/bin:/bin', 'GITHUB_ACTIONS=true', 'RUNNER_ENVIRONMENT=github-hosted',
                                  'PYTHONDONTWRITEBYTECODE=1', 'python3', str(configuration / 'run_fixtures.py'),
                                  '--work', str(work)], 5400)
        assert not subprocess.check_output(['docker', 'ps', '-aq'], env=docker_env, text=True).strip()
        assert not subprocess.check_output(git + ['status', '--porcelain'], text=True).strip()
        record['passed'] = True
    finally:
        if daemon is not None and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=30)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=5)
        if daemon_log is not None:
            daemon_log.close()
        record['daemon_stopped'] = daemon is None or daemon.poll() is not None
        save()
        final = {name: (group / name).read_text().strip() for name in (*names, 'memory.peak', 'memory.events', 'cpu.stat')}
        (public / 'cgroup-final.json').write_text(json.dumps(final, indent=2) + '\n')
        assert all(final[name] == value for name, value in limits.items())


if __name__ == '__main__':
    main()
