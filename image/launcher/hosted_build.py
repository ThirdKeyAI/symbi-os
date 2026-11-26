#!/usr/bin/env python3
"""Build the pinned launcher and execute provider controls only on hosted CI."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0:
        raise SystemExit('Launcher builds require the disposable hosted resource unit')
    root = Path.cwd()
    process = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent
    assert process.name == 'supervisor' and group.name.startswith('symbi-elephant-')
    assert not (group/'cgroup.procs').read_text().strip()
    limits = {name: (group/name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    assert limits == {'memory.max': '4294967296', 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '256'}
    evidence = root/'.cache/elephant-build-evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    storage = root/'.cache/elephant-build-storage'
    storage.mkdir(mode=0o700)
    inputs, output = storage/'inputs', storage/'output'
    inputs.mkdir(mode=0o755)
    output.mkdir(mode=0o755)
    runroot = Path('/run')/group.name.removesuffix('.service')
    assert len(os.fsencode(runroot)) <= 50
    runroot.mkdir(mode=0o700)
    podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage/'root'), '--runroot', str(runroot)]
    record = {'passed': False, 'os_qualified': False, 'source_commit': os.environ['GITHUB_SHA'],
              'limits': limits, 'commands': [], 'scope': 'Source-built Elephant and actual provider refusal on the selected base; no OS qualification'}

    def save():
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=300, check=True):
        record['active_command'] = {'name': name, 'command': command}
        save()
        with (evidence/(name+'.log')).open('xb') as log:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']
        save()
        if check:
            result.check_returncode()
        return result

    try:
        sys.path.insert(0, str(root/'image/toolchain'))
        from bootstrap_cosign import bootstrap
        sys.path.insert(0, str(root/'image'))
        from recipe import render
        sys.path.insert(0, str(root/'image/hyprland'))
        from inventory import require_subject
        from build_inputs import unpack_rpms, require_current_requirements
        pins = json.loads((root/'image/base-images.json').read_text())
        render(pins, 'generic', root)
        base = pins['variants']['generic']
        cosign = bootstrap(root, evidence)
        signature = subprocess.check_output([str(cosign), 'verify', '--key', str(root/base['public_key']),
                                             '--output', 'json', base['image']], text=True, timeout=180)
        require_subject(json.loads(signature), base['image'])
        (evidence/'base-signature.json').write_text(signature)
        record['base'] = base['image']
        lock = json.loads((root/'image/launcher/build-rpms.lock.json').read_text())
        require_current_requirements(lock, json.loads((root/'image/launcher/elephant-build-requirements.json').read_text()))
        assert lock['base'] == base['image']
        unpack_rpms(root/'.cache/elephant-build-rpms.zip', lock, inputs/'packages')
        for name in ('build-rpms.lock.json', 'elephant-source.json', 'provider-patch.json', 'build_guest.py', 'toolchain_guest.py', 'go_identity.py'):
            shutil.copyfile(root/'image/launcher'/name, inputs/name)
        shutil.copyfile(root/'image/launcher/patches/0001-packaged-application-provider-only.patch', inputs/'provider.patch')
        shutil.copytree(root/'image/launcher/probes', inputs/'probes')
        for name in ('guest_inventory.py', 'resolve_packages.py'):
            shutil.copyfile(root/'image/hyprland'/name, inputs/name)
        shutil.copyfile(root/lock['key']['path'], inputs/'fedora-45-primary.asc')
        source_pins = json.loads((inputs/'elephant-source.json').read_text())
        assert re.fullmatch(r'[a-f0-9]{40}', source_pins['revision'])
        assert source_pins['repository'] == 'https://github.com/abenz1267/elephant'
        source = inputs/'source'
        source.mkdir()
        git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never',
               '-c', 'protocol.ext.allow=never', '-C', str(source)]
        run('source-init', git+['init'], 30)
        run('source-fetch', git+['fetch', '--depth=1', '--no-tags', source_pins['repository'], source_pins['revision']], 300)
        run('source-checkout', git+['checkout', '--detach', 'FETCH_HEAD'], 30)
        assert subprocess.check_output(git+['rev-parse', 'HEAD'], text=True).strip() == source_pins['revision']
        modes = subprocess.check_output(git+['ls-tree', '-r', 'HEAD'], text=True).splitlines()
        assert all(row.startswith(('100644 ', '100755 ')) for row in modes)
        for name in ('go.mod', 'go.sum'):
            assert digest(source/name) == source_pins[name.replace('.', '_')+'_sha256']
        record['upstream_revision'] = source_pins['revision']
        auth = storage/'auth.json'
        auth.write_text('{"auths": {}}\n')
        run('pull-base', podman+['pull', '--authfile', str(auth), base['image']], 1200)
        common = ['--pull=never', '--security-opt=no-new-privileges', '--cap-drop=ALL',
                  '--cgroup-parent=/' + str(group.relative_to('/sys/fs/cgroup')),
                  '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                  '--mount', f'type=bind,src={output},dst=/output', '--env=PYTHONDONTWRITEBYTECODE=1',
                  '--entrypoint=/usr/bin/python3']
        run('install-signed-compiler', podman+['run', '--name=symbi-elephant-compiler', '--user=0', '--network=none',
            '--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,SETFCAP',
            '--memory=2g', '--memory-swap=2g', '--cpus=1', '--pids-limit=128', *common,
            base['image'], '/inputs/toolchain_guest.py'], 600)
        shutil.copytree(output/'toolchain-evidence', evidence/'toolchain')
        installed = json.loads((evidence/'toolchain/result.json').read_text())
        assert installed['passed'] and installed['all_base_packages_unchanged']
        compiler = subprocess.check_output(podman+['commit', 'symbi-elephant-compiler'], text=True, timeout=300).strip()
        match = re.fullmatch(r'(?:sha256:)?([a-f0-9]{64})', compiler)
        assert match
        compiler = 'sha256:'+match[1]
        record['compiler_image_id'] = compiler
        os.chown(output, 10001, 10001)
        for mode in ('download', 'compile'):
            command = podman+['run', '--rm', '--name=symbi-elephant-'+mode, '--read-only', '--user=10001:10001',
                             '--network=bridge' if mode == 'download' else '--network=none',
                             '--memory=3g', '--memory-swap=3g', '--cpus=2', '--pids-limit=128', *common,
                             compiler, '/inputs/build_guest.py', mode]
            completion = run(mode, command, 1500 if mode == 'download' else 5400, check=mode == 'download')
            shutil.copytree(output/(mode+'-evidence'), evidence/mode)
        built = json.loads((evidence/'compile/result.json').read_text())
        assert built.get('compiled') and not built['os_qualified']
        binaries = {name: output/'binaries'/name for name in ('baseline', 'patched', 'desktopapplications', 'marker')}
        assert set(built['binaries']) == set(binaries)
        for name, path in binaries.items():
            assert path.is_file() and not path.is_symlink() and digest(path) == built['binaries'][name]
        # Retain immutable bytes before acceptance so a failed probe does not force a rebuild.
        payload = root/'.cache/elephant-build-payload'
        payload.mkdir()
        for name, path in binaries.items():
            shutil.copyfile(path, payload/name)
        manifest = {'schema': 1, 'compiled': True, 'os_qualified': False, 'provider_loading_qualified': False,
                    'base': base['image'], 'source_commit': record['source_commit'],
                    'upstream_revision': source_pins['revision'], 'binaries': built['binaries'],
                    'patch_sha256': built['patch_sha256'], 'rpm_lock_sha256': digest(inputs/'build-rpms.lock.json'),
                    'go_mod_sha256': source_pins['go_mod_sha256'], 'go_sum_sha256': source_pins['go_sum_sha256']}
        (payload/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        shutil.copyfile(payload/'manifest.json', evidence/'compiled-manifest.json')
        completion.check_returncode()
        assert built['passed'] and built['module_locks_unchanged']
        sys.path.insert(0, str(root/'image/launcher/probes'))
        from provider_acceptance import run_checks
        run_checks(podman, base['image'], '/'+str(group.relative_to('/sys/fs/cgroup')),
                   storage/'provider-probes', binaries, built['binaries'], evidence/'providers')
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        for directory, name in (('toolchain-evidence', 'toolchain'), ('download-evidence', 'download'), ('compile-evidence', 'compile')):
            source = output/directory
            if source.is_dir() and not (evidence/name).exists():
                shutil.copytree(source, evidence/name)
        record['cgroup_final'] = {name: (group/name).read_text().strip() for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__':
    main()
