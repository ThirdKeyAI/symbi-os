#!/usr/bin/env python3
"""Reuse exact compiled Elephant inputs on the original authenticated base."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from binary_inputs import BINARIES, digest, require_bindings, unpack_binaries


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0):
        raise SystemExit('Launcher acceptance requires the disposable hosted resource unit')
    root = Path.cwd()
    process = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent
    if (process.name != 'supervisor' or not group.name.startswith('symbi-ele-runtime-')
            or (group/'cgroup.procs').read_text().strip()):
        raise ValueError('Unexpected hosted supervisor cgroup')
    limits = {name: (group/name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if limits != {'memory.max': '4294967296', 'memory.swap.max': '0',
                  'cpu.max': '200000 100000', 'pids.max': '256'}:
        raise ValueError('Unexpected hosted resource limits')
    evidence = root/'.cache/elephant-runtime-evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    storage = root/'.cache/elephant-runtime-storage'
    storage.mkdir(mode=0o700)
    inputs, output = storage/'inputs', storage/'ocr-output'
    inputs.mkdir(mode=0o755)
    output.mkdir(mode=0o755)
    os.chown(output, 10001, 10001)
    runroot = Path('/run')/group.name.removesuffix('.service')
    if len(os.fsencode(runroot)) > 50:
        raise ValueError('Container runtime path exceeds the checked bound')
    runroot.mkdir(mode=0o700)
    podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage/'root'), '--runroot', str(runroot)]
    record = {'passed': False, 'os_qualified': False, 'upstream_tests_passed': False,
              'source_commit': os.environ['GITHUB_SHA'], 'limits': limits, 'commands': [],
              'scope': 'Retained-binary provider controls and separate OCR diagnostics; no upstream-suite or OS qualification'}

    def save():
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=300):
        record['active_command'] = {'name': name, 'command': command}
        save()
        with (evidence/(name+'.log')).open('xb') as log:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=timeout)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']
        save()
        result.check_returncode()

    try:
        sys.path.insert(0, str(root/'image/toolchain'))
        from bootstrap_cosign import bootstrap
        sys.path.insert(0, str(root/'image'))
        from recipe import render
        sys.path.insert(0, str(root/'image/hyprland'))
        from inventory import require_subject
        sys.path.insert(0, str(root/'image/launcher/probes'))
        from bounded_process import run_bounded
        from provider_acceptance import run_checks

        pins = json.loads((root/'image/base-images.json').read_text())
        render(pins, 'generic', root)
        base = pins['variants']['generic']
        cosign = bootstrap(root, evidence)
        signature = subprocess.check_output([str(cosign), 'verify', '--key', str(root/base['public_key']),
                                             '--output', 'json', base['image']], text=True, timeout=180)
        require_subject(json.loads(signature), base['image'])
        (evidence/'base-signature.json').write_text(signature)
        record['base'] = base['image']
        lock = json.loads((root/'image/launcher/development-binaries.lock.json').read_text())
        if lock.get('upstream_tests_passed') is not False or lock.get('qualified') is not False:
            raise ValueError('Do not reinterpret the retained failed-suite evidence')
        source = json.loads((root/'image/launcher/elephant-source.json').read_text())
        patch = json.loads((root/'image/launcher/provider-patch.json').read_text())
        patch_hash = digest(root/'image/launcher/patches/0001-packaged-application-provider-only.patch')
        if patch['patch_sha256'] != patch_hash or patch['upstream_revision'] != source['revision']:
            raise ValueError('Current patch metadata does not match its source or bytes')
        bindings = {'base': base['image'], 'source': source,
                    'rpm_lock_sha256': digest(root/'image/launcher/build-rpms.lock.json'),
                    'patch_sha256': patch_hash,
                    'marker_sha256': digest(root/'image/launcher/probes/native_marker.go')}
        require_bindings(lock['manifest'], lock, **bindings)
        manifest = unpack_binaries(root/'.cache/elephant-development-binaries.zip', lock, inputs/'binaries')
        record['artifact'] = lock['artifact']
        record['current_bindings'] = bindings
        record['original_build_run'] = lock['run_id']
        (evidence/'compiled-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        shutil.copyfile(root/'image/launcher/ocr_diagnostic.py', inputs/'ocr_diagnostic.py')
        shutil.copyfile(root/'image/launcher/loader_diagnostic.py', inputs/'loader_diagnostic.py')
        shutil.copyfile(root/'image/launcher/probes/bounded_process.py', inputs/'bounded_process.py')
        auth = storage/'auth.json'
        auth.write_text('{"auths": {}}\n')
        run('pull-base', podman+['pull', '--authfile', str(auth), base['image']], 1200)
        container = 'symbi-elephant-ocr-diagnostic'
        command = podman+['run', '--rm', '--name='+container, '--pull=never', '--read-only', '--network=none',
                         '--user=10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                         '--memory=256m', '--memory-swap=256m', '--cpus=1', '--pids-limit=64',
                         '--cgroup-parent=/' + str(group.relative_to('/sys/fs/cgroup')),
                         '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                         '--mount', f'type=bind,src={output},dst=/output',
                         '--env=GITHUB_ACTIONS=true', '--env=RUNNER_ENVIRONMENT=github-hosted',
                         '--env=PYTHONDONTWRITEBYTECODE=1', '--env=HOME=/output', '--env=PATH=/usr/bin:/bin',
                         '--env=LANG=C.UTF-8', '--entrypoint=/usr/bin/python3', base['image'], '/inputs/ocr_diagnostic.py']
        try:
            run('ocr-diagnostic', command, 150)
        finally:
            removed = run_bounded(podman+['rm', '--force', '--ignore', container],
                                  evidence/'ocr-cleanup-stdout.log', evidence/'ocr-cleanup-stderr.log')
            exists = run_bounded(podman+['container', 'exists', container],
                                 evidence/'ocr-exists-stdout.log', evidence/'ocr-exists-stderr.log')
            record['ocr_container_absent'] = removed.returncode == 0 and exists.returncode == 1
            if not record['ocr_container_absent']:
                raise RuntimeError('OCR diagnostic container cleanup failed')
        diagnostic = json.loads((output/'result.json').read_text())
        if diagnostic.get('diagnostic_completed') is not True or diagnostic.get('upstream_tests_passed') is not False:
            raise ValueError('OCR diagnostic did not finish with its limited scope')
        record['ocr_missing_executables'] = diagnostic['missing_executables']
        # listproviders installs a discard logger, so separately retain the
        # exact normal-startup error before applying the unchanged acceptance.
        trusted = inputs/'packaged/elephant/providers'
        trusted.mkdir(mode=0o755, parents=True)
        shutil.copyfile(inputs/'binaries/desktopapplications', trusted/'desktopapplications.so')
        (trusted/'desktopapplications.so').chmod(0o644)
        loader_container = 'symbi-elephant-loader-diagnostic'
        loader_command = [('--name='+loader_container if value == '--name='+container else value)
                          for value in command[:-2]]
        loader_command += ['--mount', f'type=bind,src={inputs / "packaged"},dst=/usr/lib/symbi,ro',
                           base['image'], '/inputs/loader_diagnostic.py']
        try:
            run('loader-diagnostic', loader_command, 45)
        finally:
            removed = run_bounded(podman+['rm', '--force', '--ignore', loader_container],
                                  evidence/'loader-cleanup-stdout.log', evidence/'loader-cleanup-stderr.log')
            exists = run_bounded(podman+['container', 'exists', loader_container],
                                 evidence/'loader-exists-stdout.log', evidence/'loader-exists-stderr.log')
            record['loader_container_absent'] = removed.returncode == 0 and exists.returncode == 1
            if not record['loader_container_absent']:
                raise RuntimeError('Loader diagnostic container cleanup failed')
        binaries = {name: inputs/'binaries'/name for name in BINARIES}
        result = run_checks(podman, base['image'], '/'+str(group.relative_to('/sys/fs/cgroup')),
                            storage/'provider-probes', binaries, manifest['binaries'], evidence/'providers')
        if result.get('passed') is not True or result.get('os_qualified') is not False:
            raise ValueError('Provider controls failed')
        record['provider_loading_passed'] = True
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        diagnostic_evidence = evidence/'ocr'
        diagnostic_evidence.mkdir(exist_ok=True)
        names = ['result.json', 'ocr_test.png', 'loader-result.json', 'loader-stdout.log', 'loader-stderr.log']
        for name in ('tesseract-version', 'tesseract-languages', 'create-test-image', 'ocr'):
            names.extend((name+'-stdout.log', name+'-stderr.log'))
        for name in names:
            path = output/name
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 262144:
                shutil.copyfile(path, diagnostic_evidence/name)
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__':
    main()
