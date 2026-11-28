#!/usr/bin/env python3
"""Authenticate and run container fixtures on a disposable hosted Ubuntu VM."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from image.container import native_fixture_build
from image.container import ubuntu_fixture_inputs
from image.container.hosted.inputs import (
    collect_public, digest, require_signature, unpack_runtime,
    selected_public_bindings, validate_fixture_output,
    validate_fixture_source_lock)


CONTAINERD_SNAPSHOTTER_DRIVER = 'io.containerd.snapshotter.v1'


def docker_namespaces(environment):
    """Return distinct, canonical namespaces bound to one hosted attempt."""
    values = []
    for name in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        value = environment.get(name)
        if not isinstance(value, str) or re.fullmatch(r'[1-9][0-9]{0,19}', value) is None:
            raise ValueError(name + ' must be a canonical positive integer')
        values.append(value)
    suffix = 'run-' + values[0] + '-attempt-' + values[1]
    return (
        'symbi-fixtures-' + suffix,
        'plugins.symbi-fixtures-' + suffix,
    )


def evidence_staging(root, environment):
    """Select the wrapper-created private sibling used for atomic evidence."""
    docker_namespaces(environment)
    path = Path(root) / '.cache' / (
        '.container-fixture-evidence-'
        + environment['GITHUB_RUN_ID'] + '-'
        + environment['GITHUB_RUN_ATTEMPT'] + '.staging')
    metadata = path.lstat()
    if (path.is_symlink() or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or path.resolve() != path):
        raise ValueError('fixture evidence staging is not one private directory')
    return path


def docker_daemon_configuration(work, runsc, group, environment):
    """Build the dedicated daemon configuration for one hosted attempt."""
    container_namespace, plugin_namespace = docker_namespaces(environment)
    return {
        'hosts': ['unix:///var/run/docker.sock'],
        'data-root': str(work / 'docker-data'),
        'exec-root': str(work / 'docker-exec'),
        'pidfile': str(work / 'docker.pid'),
        'features': {'containerd-snapshotter': True},
        'containerd-namespace': container_namespace,
        'containerd-plugins-namespace': plugin_namespace,
        'runtimes': {'runsc': {'path': str(runsc)}},
        'default-runtime': 'runc',
        'exec-opts': ['native.cgroupdriver=cgroupfs'],
        'cgroup-parent': '/' + str(group.relative_to('/sys/fs/cgroup')),
        'bridge': 'none',
        'iptables': False,
        'ip-forward': False,
        'ip-masq': False,
        'userland-proxy': False,
        'live-restore': False,
        'log-driver': 'local',
        'log-opts': {'max-size': '10m', 'max-file': '2'},
    }


def require_containerd_snapshotter(info_raw, expected_namespaces):
    """Require the containerd store and exact attempt-bound namespaces."""
    try:
        info = json.loads(info_raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError('Docker info is not valid JSON') from error
    if (not isinstance(expected_namespaces, tuple)
            or len(expected_namespaces) != 2
            or any(not isinstance(value, str) or not value
                   for value in expected_namespaces)
            or not isinstance(info, dict)
            or not isinstance(info.get('DriverStatus'), list)):
        raise ValueError('Docker info lacks DriverStatus rows')
    driver_rows = []
    for row in info['DriverStatus']:
        if (not isinstance(row, list) or len(row) != 2
                or any(not isinstance(value, str) for value in row)):
            raise ValueError('Docker info has malformed DriverStatus rows')
        if row[0] == 'driver-type':
            driver_rows.append(row)
    if driver_rows != [['driver-type', CONTAINERD_SNAPSHOTTER_DRIVER]]:
        raise ValueError('Docker is not using the required containerd snapshotter')
    containerd = info.get('Containerd')
    namespaces = (
        containerd.get('Namespaces') if isinstance(containerd, dict) else None)
    if (not isinstance(namespaces, dict)
            or namespaces.get('Containers') != expected_namespaces[0]
            or namespaces.get('Plugins') != expected_namespaces[1]):
        raise ValueError('Docker is not using the attempt-bound namespaces')
    return info


def snapshot_authority(root, work):
    """Freeze all exporter authority inputs before unprivileged fixtures run."""
    authority = work / 'authority'
    authority.mkdir(mode=0o700)
    relative_paths = (
        'upstream/symbiont.toml',
        'image/container/native-fixture.lock.json',
        'image/container/native-fixture-build.lock.json',
        'image/container/ubuntu-fixture-packages.lock.json',
        '.cache/container-fixture-producer-run.json',
    )
    for relative in relative_paths:
        source = root / relative
        info = source.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or source.is_symlink()):
            raise ValueError('exporter authority input is not a direct file')
        target = authority / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source, target, follow_symlinks=False)
        target.chmod(0o400)
        if (target.stat().st_size != info.st_size
                or digest(target) != digest(source)):
            raise ValueError('exporter authority input changed while freezing')
    native_fixture_build.preflight_fixture_output(authority)
    return authority


def create_fixture_account(environment):
    """Create one run-bound identity that cannot write the checkout or cache."""
    material = (
        environment['GITHUB_RUN_ID'] + ':' + environment['GITHUB_RUN_ATTEMPT'])
    name = 'symbi-fx-' + hashlib.sha256(material.encode()).hexdigest()[:16]
    try:
        pwd.getpwnam(name)
    except KeyError:
        pass
    else:
        raise ValueError('dedicated fixture account already exists')
    subprocess.run([
        '/usr/sbin/useradd', '--system', '--no-create-home',
        '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin',
        '--groups', 'docker', name,
    ], check=True, timeout=30)
    try:
        account = pwd.getpwnam(name)
        if account.pw_uid <= 0:
            raise ValueError('dedicated fixture account is not unprivileged')
        return account
    except BaseException:
        subprocess.run(
            ['/usr/sbin/userdel', name], check=False, timeout=30)
        raise


def quiesce_fixture_account(account, require_clean=False):
    """Kill and prove absence of every process under the disposable identity."""
    killed = subprocess.run(
        ['/usr/bin/pkill', '-KILL', '-u', str(account.pw_uid)],
        check=False, timeout=30)
    remaining = subprocess.run(
        ['/usr/bin/pgrep', '-u', str(account.pw_uid)],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=10)
    if (killed.returncode not in (0, 1)
            or remaining.returncode not in (1,)
            or remaining.stdout.strip()):
        raise ValueError('dedicated fixture account still has live processes')
    if require_clean and killed.returncode == 0:
        raise ValueError('fixture execution left a background process')


def save_native_fixture_image(run, root, work, initial_target_digest,
                              docker_env, available_bytes=None):
    """Gate free space immediately before saving the tested Docker target."""
    root = Path(root).resolve()
    cache = root / '.cache'
    if not (cache.is_dir() and not cache.is_symlink()
            and cache.resolve() == cache):
        raise ValueError('native fixture producer cache is not canonical')
    free = (shutil.disk_usage(cache).free
            if available_bytes is None else available_bytes)
    if type(free) is not int or free < native_fixture_build.MIN_FREE_BEFORE_SAVE:
        raise ValueError('native fixture producer lacks pre-save working space')
    docker_archive = work / native_fixture_build.DOCKER_ARCHIVE_NAME
    run('fixture-image-save', [
        'docker', 'image', 'save', '--output', str(docker_archive),
        initial_target_digest,
    ], 900, env=docker_env)
    return docker_archive


def main():
    if os.getuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise SystemExit('Container fixture execution requires the disposable hosted resource unit')
    root = Path.cwd()
    evidence_root = evidence_staging(root, os.environ)
    configuration = root / 'image/container/hosted'
    lock = json.loads((configuration / 'inputs.lock.json').read_text())
    package_input = root / '.cache/container-ubuntu-fixture-inputs/candidate'
    work = root / '.cache/container-fixture-work'
    work.mkdir()
    (root / '.cache').chmod(0o711)
    public = work / 'public'
    public.mkdir()
    authority = snapshot_authority(root, work)
    native_source_path = authority / 'image/container/native-fixture.lock.json'
    native_source = json.loads(native_source_path.read_text())
    fixture_source = validate_fixture_source_lock(lock, native_source)
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
    expected_public_files = {'result.json'}

    def save():
        (public / 'result.json').write_text(json.dumps(record, indent=2) + '\n')

    def run(name, command, timeout=300, cwd=None, env=None, check=True):
        record['active_command'] = {'name': name, 'command': command}
        save()
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
        (public / (name + '.log')).write_text(result.stdout + result.stderr)
        expected_public_files.add(name + '.log')
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
    account = create_fixture_account(os.environ)
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
        run('source-fetch-baseline', git + ['fetch', '--depth=1', '--no-tags', fixture_source['repository'], lock['source_revision']])
        run('source-fetch', git + ['fetch', '--depth=1', '--no-tags', fixture_source['repository'], lock['fixture_commit']])
        run('source-checkout', git + ['checkout', '--detach', 'FETCH_HEAD'])
        assert subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == lock['fixture_commit']
        assert subprocess.check_output(
            git + ['rev-parse', 'HEAD^{tree}'], text=True).strip() == lock['fixture_tree']
        assert subprocess.check_output(git + ['rev-parse', lock['source_revision'] + '^{commit}'], text=True).strip() == lock['source_revision']
        patch = subprocess.check_output(git + ['diff', lock['source_revision'], 'HEAD', '--binary', '--full-index',
                                               '--src-prefix=a/', '--dst-prefix=b/'])
        assert hashlib.sha256(patch).hexdigest() == lock['patch_sha256']
        assert digest(source / 'Cargo.lock') == lock['cargo_lock_sha256']
        assert {
            name: digest(source / 'scripts' / name)
            for name in sorted(lock['fixture_drivers'])
        } == lock['fixture_drivers']
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
        package_selection = ubuntu_fixture_inputs.stage_install_candidate(
            authority, package_input, context)
        download('download-rootfs', rootfs['url'], rootfs['bytes'], rootfs['sha256'], context / rootfs['archive'])
        docker_env = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8',
                      'DOCKER_HOST': 'unix:///var/run/docker.sock', 'DOCKER_CONFIG': str(work / 'docker-client'),
                      'DOCKER_BUILDKIT': '0'}
        (work / 'docker-client').mkdir(mode=0o700)
        initial = run('initial-containers', ['docker', 'ps', '-aq'], env=docker_env)
        assert not initial.stdout.strip(), 'Do not interrupt an existing workload'
        run('stop-runner-docker', ['systemctl', 'stop', 'docker.service', 'docker.socket'])
        config = docker_daemon_configuration(
            work, runsc, group, os.environ)
        config_path = work / 'daemon.json'
        config_path.write_text(json.dumps(config, indent=2) + '\n')
        shutil.copyfile(config_path, public / 'daemon.json')
        expected_public_files.add('daemon.json')
        run('validate-daemon', ['dockerd', '--validate', '--config-file', str(config_path)])
        daemon_log = (public / 'dockerd.log').open('w')
        expected_public_files.add('dockerd.log')
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
        docker_info = run(
            'docker-info', ['docker', 'info', '--format', '{{json .}}'],
            env=docker_env)
        require_containerd_snapshotter(
            docker_info.stdout,
            (config['containerd-namespace'],
             config['containerd-plugins-namespace']))
        image_file = work / 'fixture-image-id'
        run('fixture-image-build', ['docker', 'build', '--pull=false', '--rm', '--force-rm',
                                   '--memory=512m', '--memory-swap=512m', '--cpu-period=100000', '--cpu-quota=100000',
                                   '--network=none', '--iidfile', str(image_file), str(context)], 1800, env=docker_env)
        initial_target_digest = image_file.read_text().strip()
        assert re.fullmatch(r'sha256:[a-f0-9]{64}', initial_target_digest)
        inspected = run(
            'fixture-image-inspect',
            ['docker', 'image', 'inspect', initial_target_digest], env=docker_env)
        (work / 'fixture-image-inspect.json').write_text(inspected.stdout)
        stopped = run(
            'create-evidence-container',
            ['docker', 'create', '--network=none', initial_target_digest],
            env=docker_env).stdout.strip()
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
                           initial_target_digest, 'python3', '-c',
                           'import time; time.sleep(30)'], env=docker_env).stdout.strip()
            assert re.fullmatch(r'[a-f0-9]{64}', identity)
            try:
                run('probe-start-' + backend, ['docker', 'start', identity], env=docker_env)
                observed = json.loads(run('probe-inspect-' + backend, ['docker', 'inspect', identity], env=docker_env).stdout)[0]
                pid = observed['State']['Pid']
                assert observed['State']['Running'] and isinstance(pid, int) and pid > 1
                actual_group = Path('/proc') / str(pid) / 'cgroup'
                value = actual_group.read_text()
                (public / ('probe-cgroup-' + backend + '.txt')).write_text(value)
                expected_public_files.add(
                    'probe-cgroup-' + backend + '.txt')
                assert ('/' + str(group.relative_to('/sys/fs/cgroup')) + '/') in value
            finally:
                run('probe-remove-' + backend, ['docker', 'rm', '--force', identity], env=docker_env)
        private = work / 'private'
        for path in [private, private / 'home', private / 'docker-client']:
            path.mkdir(mode=0o700)
            os.chown(path, account.pw_uid, account.pw_gid)
        fixture_output = work / 'fixture-output'
        fixture_output.mkdir(mode=0o700)
        os.chown(fixture_output, account.pw_uid, account.pw_gid)
        # The fixture drivers put Unix sockets beneath TMPDIR; a checkout path
        # can exceed the kernel's pathname bound. mkdtemp keeps this tree private.
        fixture_tmp = Path(tempfile.mkdtemp(prefix='sf-', dir='/tmp'))
        os.chown(fixture_tmp, account.pw_uid, account.pw_gid)
        setup = {'fixture_tmp': str(fixture_tmp),
                 'image_id': initial_target_digest, 'runsc': str(runsc),
                 'binary_sha256': lock['binaries']['symbi']['sha256'],
                 'source_revision': lock['source_revision'], 'fixture_commit': lock['fixture_commit'],
                 'fixture_source': fixture_source,
                 'fixture_source_lock_sha256': digest(native_source_path),
                 'patch_sha256': lock['patch_sha256'], 'source_lock_sha256': lock['cargo_lock_sha256']}
        (public / 'setup.json').write_text(json.dumps(setup, indent=2) + '\n')
        expected_public_files.add('setup.json')
        run('complete-fixtures', ['/usr/sbin/runuser', '-u', account.pw_name, '--', 'env', '-i',
                                  'PATH=/usr/bin:/bin', 'GITHUB_ACTIONS=true', 'RUNNER_ENVIRONMENT=github-hosted',
                                  'PYTHONDONTWRITEBYTECODE=1', 'python3', str(configuration / 'run_fixtures.py'),
                                  '--work', str(work), '--output', str(fixture_output)], 5400)
        quiesce_fixture_account(account, require_clean=True)
        validate_fixture_output(fixture_output, setup)
        fixture_public_files = {
            'result.json',
            *{
                backend + '-' + Path(driver).stem + suffix
                for backend in ('docker', 'gvisor')
                for driver in fixture_source['drivers']
                for suffix in ('.json', '.log')
            },
        }
        collect_public(
            fixture_output, public / 'fixtures',
            expected_paths=fixture_public_files)
        expected_public_files.update(
            'fixtures/' + name for name in fixture_public_files)
        assert not subprocess.check_output(['docker', 'ps', '-aq'], env=docker_env, text=True).strip()
        assert not subprocess.check_output(git + ['status', '--porcelain'], text=True).strip()
        save_native_fixture_image(
            run, root, work, initial_target_digest, docker_env)
        exported = native_fixture_build.build_fixture_output(
            root, initial_target_digest, authority_root=authority)
        run('cold-remove-fixture-image',
            ['docker', 'image', 'rm', initial_target_digest], env=docker_env)
        absent = run(
            'cold-prove-fixture-image-absent',
            ['docker', 'image', 'inspect', initial_target_digest], env=docker_env,
            check=False)
        assert absent.returncode != 0 and not absent.stdout.strip()
        archive = root / '.cache/container-native-fixture-output' / exported['archive']['name']
        run('cold-load-fixture-image', ['docker', 'image', 'load', '--input', str(archive)],
            900, env=docker_env)
        cold = json.loads(run(
            'cold-inspect-fixture-image',
            ['docker', 'image', 'inspect', exported['image']['repo_digest']],
            env=docker_env).stdout)
        assert len(cold) == 1
        generated_target_digest = exported['image']['generated_target_digest']
        assert cold[0]['Id'] == generated_target_digest
        assert cold[0]['Descriptor']['digest'] == generated_target_digest
        assert cold[0]['Descriptor']['mediaType'] == exported['image'][
            'generated_target_media_type']
        assert cold[0]['RepoDigests'] == [exported['image']['repo_digest']]
        record['native_fixture'] = {
            'built': True, 'selected': False, 'verified': False,
            'qualified': False, 'container_qualified': False,
            'signature_qualified': False, 'os_qualified': False,
            'release_qualified': False, 'image': exported['image'],
            'package_manifest_sha256': package_selection['manifest_sha256'],
            'package_count': package_selection['manifest']['package_count'],
        }
        record['passed'] = True
    finally:
        try:
            quiesce_fixture_account(account)
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
            final = {
                name: (group / name).read_text().strip()
                for name in (*names, 'memory.peak', 'memory.events', 'cpu.stat')
            }
            (public / 'cgroup-final.json').write_text(
                json.dumps(final, indent=2) + '\n')
            expected_public_files.add('cgroup-final.json')
            assert all(final[name] == value for name, value in limits.items())
            package_public = public / 'fixture-packages'
            if record['passed']:
                bindings = selected_public_bindings(
                    authority
                    / 'image/container/ubuntu-fixture-packages.lock.json')
                expected_public_files.update(bindings['files'])
                expected_public_files.add('fixture-packages/packages.tsv')
            else:
                shutil.rmtree(package_public, ignore_errors=True)
                bindings = None
            collect_public(
                public, evidence_root / 'public',
                bindings, expected_public_files)
        finally:
            subprocess.run(
                ['/usr/sbin/userdel', account.pw_name],
                check=False, timeout=30)


if __name__ == '__main__':
    main()
