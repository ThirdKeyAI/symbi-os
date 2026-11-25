#!/usr/bin/env python3
"""Actual hosted loader controls, consumed after the pinned source build."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
from bounded_process import run_bounded


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run_checks(podman, base, group, workspace, binaries, expected_hashes, evidence):
    """Mount each root-owned fixture read-only; execute only as the probe UID."""
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.geteuid() != 0):
        raise RuntimeError('Provider acceptance requires the disposable hosted builder')
    if not base.startswith('ghcr.io/secureblue/sericea-main-hardened@sha256:'):
        raise ValueError('Use the previously authenticated selected base')
    if set(binaries) != {'baseline', 'patched', 'desktopapplications', 'marker'}:
        raise ValueError('Actual baseline, patched executable, built-in and constructor control required')
    if set(expected_hashes) != set(binaries):
        raise ValueError('Every actual build output must be hash-bound')
    for name, path in binaries.items():
        if not path.is_file() or path.is_symlink() or digest(path) != expected_hashes[name]:
            raise ValueError('Build output changed: ' + name)
    workspace.mkdir(mode=0o700)
    evidence.mkdir(parents=True, exist_ok=True)
    record = {'passed': False, 'os_qualified': False, 'scope': 'Actual Elephant native-provider loading only',
              'base': base, 'binary_hashes': expected_hashes, 'cases': [],
              'driver_sha256': digest(Path(__file__)),
              'limits': {'memory_bytes': 268435456, 'cpu': 1, 'swap_bytes': 0, 'pids': 64}}

    def save():
        (evidence / 'provider-loading.json').write_text(json.dumps(record, indent=2) + '\n')

    # Baseline controls prove each override really reaches the constructor.
    scenarios = [
        ('baseline-environment', 'baseline', 'env', True, []),
        ('baseline-user-config', 'baseline', 'user', True, []),
        ('baseline-development', 'baseline', 'dev', True, []),
        ('patched-environment', 'patched', 'env', False, ['desktopapplications']),
        ('patched-user-config', 'patched', 'user', False, ['desktopapplications']),
        ('patched-explicit-config', 'patched', 'explicit', False, ['desktopapplications']),
        ('patched-system-config', 'patched', 'system', False, ['desktopapplications']),
        ('patched-dotenv', 'patched', 'dotenv', False, ['desktopapplications']),
        ('patched-development', 'patched', 'dev', False, ['desktopapplications']),
        ('patched-extra-provider', 'patched', 'extra', False, ['desktopapplications']),
        ('patched-nested-provider', 'patched', 'nested', False, ['desktopapplications']),
        ('patched-target-link', 'patched', 'target-link', False, []),
        ('patched-parent-link', 'patched', 'parent-link', False, []),
        ('patched-writable-file', 'patched', 'writable-file', False, []),
        ('patched-writable-parent', 'patched', 'writable-parent', False, []),
        ('patched-user-owned-file', 'patched', 'user-owned', False, []),
        ('restored-packaged-provider', 'patched', 'clean', False, ['desktopapplications']),
    ]
    try:
        for name, executable, mode, constructor_expected, providers_expected in scenarios:
            case = workspace / name
            case.mkdir()
            inputs, output, trusted = (case / part for part in ('inputs', 'output', 'trusted'))
            for path in (inputs, output, trusted):
                path.mkdir(mode=0o755)
            os.chown(output, 10001, 10001)
            for relative in ('config/elephant/providers', 'cache/elephant', 'runtime'):
                target = output / relative
                target.mkdir(parents=True, mode=0o700)
                for parent in (target, *target.parents):
                    if parent == output.parent:
                        break
                    os.chown(parent, 10001, 10001)
            for key, source in binaries.items():
                shutil.copyfile(source, inputs / key)
                os.chmod(inputs / key, 0o755 if key in ('baseline', 'patched') else 0o644)
            provider_dir = trusted / 'elephant/providers'
            provider_dir.mkdir(parents=True, mode=0o755)
            packaged = provider_dir / 'desktopapplications.so'
            shutil.copyfile(binaries['desktopapplications'], packaged)
            os.chmod(packaged, 0o644)
            external = inputs / 'external-providers'
            external.mkdir()
            shutil.copyfile(binaries['marker'], external / 'constructor.so')
            config = output / 'config/elephant'
            environment = {'PATH': '/usr/bin:/bin', 'HOME': '/output', 'XDG_CONFIG_HOME': '/output/config',
                           'XDG_CONFIG_DIRS': '/inputs/system-config', 'XDG_CACHE_HOME': '/output/cache',
                           'XDG_RUNTIME_DIR': '/output/runtime', 'LANG': 'C.UTF-8', 'GOMAXPROCS': '1',
                           'SYMBI_PROVIDER_MARKER': '/output/constructor-marker',
                           'SYMBI_PROVIDER_NONCE': secrets.token_hex(16)}
            extra_mounts, arguments = [], []
            if mode == 'env':
                environment['ELEPHANT_PROVIDER_DIR'] = '/inputs/external-providers'
            elif mode == 'dev':
                environment['ELEPHANT_DEV'] = 'true'
                extra_mounts = ['--mount', f'type=bind,src={external},dst=/tmp/elephant/providers,ro']
            elif mode in ('user', 'explicit'):
                shutil.copyfile(binaries['marker'], config / 'providers/constructor.so')
                if mode == 'explicit':
                    arguments = ['--config', '/output/config/elephant']
            elif mode == 'system':
                target = inputs / 'system-config/elephant/providers'
                target.mkdir(parents=True)
                shutil.copyfile(binaries['marker'], target / 'constructor.so')
            elif mode == 'dotenv':
                (config / '.env').write_text('ELEPHANT_PROVIDER_DIR=/inputs/external-providers\n')
            elif mode == 'extra':
                shutil.copyfile(binaries['marker'], provider_dir / 'constructor.so')
            elif mode == 'nested':
                (provider_dir / 'nested').mkdir()
                shutil.copyfile(binaries['marker'], provider_dir / 'nested/desktopapplications.so')
            elif mode == 'target-link':
                packaged.unlink()
                packaged.symlink_to('/inputs/marker')
            elif mode == 'parent-link':
                packaged.unlink()
                provider_dir.rmdir()
                (trusted / 'elsewhere').mkdir()
                shutil.copyfile(binaries['marker'], trusted / 'elsewhere/desktopapplications.so')
                provider_dir.symlink_to('../elsewhere')
            elif mode in ('writable-file', 'writable-parent', 'user-owned'):
                shutil.copyfile(binaries['marker'], packaged)
                if mode == 'writable-file':
                    packaged.chmod(0o666)
                elif mode == 'writable-parent':
                    provider_dir.chmod(0o777)
                else:
                    os.chown(packaged, 10001, 10001)
            container = 'symbi-provider-' + secrets.token_hex(12)
            command = podman + ['run', '--name=' + container, '--rm', '--pull=never', '--read-only', '--network=none',
                                '--user=10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                                '--memory=256m', '--memory-swap=256m', '--cpus=1', '--pids-limit=64',
                                '--cgroup-parent=' + group,
                                '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                                '--mount', f'type=bind,src={trusted},dst=/usr/lib/symbi,ro',
                                '--mount', f'type=bind,src={output},dst=/output', *extra_mounts]
            for key, value in environment.items():
                command += ['--env', key + '=' + value]
            command += ['--entrypoint=/inputs/' + executable, base, *arguments, 'listproviders']
            item = {'name': name, 'command': command, 'passed': False,
                    'constructor_expected': constructor_expected, 'providers_expected': providers_expected}
            record['cases'].append(item)
            save()
            try:
                completed = run_bounded(command, evidence/(name+'-stdout.log'),
                                        evidence/(name+'-stderr.log'))
            except Exception as error:
                item['execution_failure'] = type(error).__name__ + ': ' + str(error)
                raise
            finally:
                # Killing the Podman client alone does not stop its container.
                removed = run_bounded(podman + ['rm', '--force', '--ignore', container],
                                      evidence/(name+'-cleanup-out.log'), evidence/(name+'-cleanup-err.log'))
                exists = run_bounded(podman + ['container', 'exists', container],
                                     evidence/(name+'-exists-out.log'), evidence/(name+'-exists-err.log'))
                item['cleanup'] = {'remove_exit': removed.returncode, 'exists_exit': exists.returncode,
                                   'container_absent': removed.returncode == 0 and exists.returncode == 1}
                save()
                if not item['cleanup']['container_absent']:
                    raise RuntimeError('Provider probe container cleanup failed: ' + name)
            item['exit_code'] = completed.returncode
            marker = output / 'constructor-marker'
            item['constructor_observed'] = marker.exists()
            if marker.exists():
                if (marker.is_symlink() or not marker.is_file() or marker.stat().st_size != 32
                        or marker.read_text() != environment['SYMBI_PROVIDER_NONCE']):
                    raise ValueError('Constructor marker is not bound to this invocation')
            item['providers_observed'] = sorted(completed.stdout.splitlines())
            if (completed.returncode != 0 or item['constructor_observed'] is not constructor_expected
                    or item['providers_observed'] != providers_expected):
                raise RuntimeError('Native-provider acceptance failed: ' + name)
            item['passed'] = True
            save()
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        save()
    return record


if __name__ == '__main__':
    raise SystemExit('Invoke only through the authenticated hosted launcher build')
