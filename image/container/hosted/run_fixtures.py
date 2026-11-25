#!/usr/bin/env python3
"""Run complete supported Docker/gVisor fixture cases, serially and unprivileged."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from inputs import digest


# Upstream deliberately limits no_read_root/no_write_root to native/VM backends.
# The full container file driver therefore has nine cases, not eleven.
CASES = {
    'test-filesystem-grants.py': ['granted', 'undeclared', 'parser', 'oversize', 'existing',
                                 'symlink', 'nested', 'descendant', 'substitution'],
    'test-source-broker.py': ['read', 'list', 'grep', 'traversal', 'symlink', 'hardlink', 'no_ceiling', 'denied', 'scratch'],
    'test-git-source.py': ['log', 'staged', 'diff', 'status', 'sha256', 'snapshot', 'denied',
                         'alternates', 'pointer', 'oversize', 'extension', 'capacity', 'prepare_crash', 'crash'],
}


def runtimes(value):
    result = []
    if isinstance(value, dict):
        if 'id' in value and 'runtime' in value:
            result.append(value['runtime'])
        for child in value.values():
            result.extend(runtimes(child))
    elif isinstance(value, list):
        for child in value:
            result.extend(runtimes(child))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    if os.getuid() == 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise SystemExit('Run as the disposable hosted test account')
    work = args.work.resolve(strict=True)
    setup = json.loads((work / 'public/setup.json').read_text())
    source, binary = work / 'source', work / 'bin/symbi'
    image_id, runsc = setup['image_id'], setup['runsc']
    binary_hash = digest(binary)
    assert binary_hash == setup['binary_sha256']
    result = {'passed': False, 'qualified': False, 'runs': [], 'source_revision': setup['source_revision'],
              'fixture_commit': setup['fixture_commit'], 'patch_sha256': setup['patch_sha256'],
              'binary_sha256': binary_hash, 'image_id': image_id,
              'scope': 'Hosted Ubuntu container tool-worker fixtures; no Fedora, managed-CLI or escape-suite qualification'}
    evidence = work / 'public/fixtures'
    evidence.mkdir()
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(work / 'private/home'), 'LANG': 'C.UTF-8',
           'DOCKER_HOST': 'unix:///var/run/docker.sock', 'DOCKER_CONFIG': str(work / 'private/docker-client'),
           'PYTHONDONTWRITEBYTECODE': '1', 'TMPDIR': str(work / 'private/tmp')}

    def docker(*args):
        return subprocess.check_output(['docker', *args], env=env, text=True, timeout=30).strip()

    def save():
        (evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    assert not docker('ps', '-aq')
    assert docker('image', 'inspect', image_id, '--format', '{{.Id}}') == image_id
    assert docker('info', '--format', '{{.DefaultRuntime}}') == 'runc'
    assert json.loads(docker('info', '--format', '{{json .Runtimes}}'))['runsc']['path'] == runsc
    try:
        for backend in ('docker', 'gvisor'):
            for driver, expected in CASES.items():
                stem = backend + '-' + Path(driver).stem
                report_path, log_path = evidence / (stem + '.json'), evidence / (stem + '.log')
                command = ['python3', '-B', 'scripts/' + driver, '--binary', str(binary),
                           '--image', image_id, '--report', str(report_path)]
                if backend == 'gvisor':
                    command += ['--gvisor', '--runsc-binary', runsc]
                row = {'backend': backend, 'driver': driver, 'command': command, 'passed': False}
                result['runs'].append(row)
                save()
                started = time.monotonic()
                with log_path.open('w') as log:
                    completed = subprocess.run(['/usr/bin/timeout', '--signal=TERM', '--kill-after=30s',
                                                '30m', *command], cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
                row.update(exit_code=completed.returncode, elapsed_seconds=time.monotonic() - started,
                           log_sha256=digest(log_path), remaining_containers=docker('ps', '-aq').split())
                try:
                    report = json.loads(report_path.read_text())
                    row['report_sha256'] = digest(report_path)
                    assert completed.returncode == 0 and report['passed'] is True
                    assert report['backend'] == backend and report['binary_sha256'] == binary_hash
                    assert report['image'] == image_id and report['driver_sha256'] == digest(source / 'scripts' / driver)
                    assert [case['name'] for case in report['cases']] == expected
                    assert all(case['passed'] is True for case in report['cases'])
                    assert report['remaining_workers'] == [] and report['remaining_leases'] == []
                    observed = runtimes(report['cases'])
                    assert observed and set(observed) == {'runsc' if backend == 'gvisor' else 'runc'}
                    row['observed_runtimes'] = sorted(set(observed))
                    row['passed'] = True
                except Exception as error:
                    row['validation_error'] = type(error).__name__ + ': ' + str(error)
                save()
                assert not row['remaining_containers'], 'Retain and inspect leftover workers before continuing'
                assert docker('info', '--format', '{{.DefaultRuntime}}') == 'runc'
        assert digest(binary) == binary_hash
        result['passed'] = len(result['runs']) == 6 and all(row['passed'] for row in result['runs'])
    finally:
        save()
    sys.exit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
