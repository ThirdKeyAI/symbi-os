"""Reuse the authenticated toolkit and rebuild the portal with fresh consent."""
import json
import os
from pathlib import Path
import shutil


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0):
        raise SystemExit('Consent builds require the disposable hosted resource unit')
    from image.desktop.prepare import release_file_cache
    from image.hyprland.build_inputs import unpack_rpms
    from image.hyprland.inventory import require_subject
    from image.hyprland.prefix_input import unpack_prefix
    from image.launcher.probes.bounded_process import run_bounded
    from image.portal.build_inputs import require_prefix_bindings, require_rpm_bindings, require_source_tree
    from image.portal.consent_inputs import load_consent, prefix_inventory, require_portal_only_install, require_tree
    from image.portal.inputs import load_inputs
    from image.portal.prefix_input import unpack_portal
    from image.portal.runtime_inputs import require_runtime_result, select_runtime_package
    from image.recipe import render
    from image.toolchain.bootstrap_cosign import bootstrap
    from image.toolchain.reuse import digest, unique_json
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    if int(memory['MemTotal'].split()[0])*1024 < 14*1024**3 or int(memory['MemAvailable'].split()[0])*1024 < 10*1024**3:
        raise SystemExit('Hosted runner lacks headroom for the 8 GiB consent build unit')
    root = Path.cwd()
    process = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent
    if (process.name != 'supervisor' or not group.name.startswith('symbi-portal-consent-')
            or (group/'cgroup.procs').read_text().strip()):
        raise ValueError('Unexpected consent build supervisor group')
    names = ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')
    limits = {name: (group/name).read_text().strip() for name in names}
    if limits != {'memory.max': '8589934592', 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '256'}:
        raise ValueError('Unexpected hosted consent build limits')
    evidence = root/'.cache/portal-consent-evidence'; evidence.mkdir(parents=True, exist_ok=True)
    output, runtime, inputs, storage, payload = (root/'.cache'/name for name in
        ('portal-consent-output', 'portal-consent-runtime', 'portal-consent-inputs', 'portal-consent-storage', 'portal-consent-payload'))
    for path in (output, runtime, inputs, storage, payload): path.mkdir(mode=0o755)
    (output/'portal').mkdir()
    runroot = Path('/run')/group.name.removesuffix('.service')
    if len(os.fsencode(runroot)) > 50: raise ValueError('Runtime storage path too long')
    runroot.mkdir(mode=0o700)
    podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage/'root'), '--runroot', str(runroot)]
    record = {'passed': False, 'os_qualified': False, 'consent_qualified': False, 'product_installation': False,
              'source_commit': os.environ['GITHUB_SHA'], 'limits': limits, 'commands': [],
              'compositor_recompiled': False, 'toolkit_recompiled': False,
              'scope': 'Portal-only build, native regression/CLI controls and additive runtime checks; full D-Bus/GUI consent qualification remains pending'}

    def save(): (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=60, check=True):
        record['active_command'] = {'name': name, 'command': command}; save()
        result = run_bounded(command, evidence/(name+'-stdout.log'), evidence/(name+'-stderr.log'),
                             timeout=timeout, max_bytes=1024**2)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']; save()
        if check: result.check_returncode()
        return result

    def remove(container):
        removed = run(container+'-cleanup', podman+['rm', '--force', '--ignore', container], check=False)
        absent = run(container+'-exists', podman+['container', 'exists', container], check=False)
        if removed.returncode != 0 or absent.returncode != 1: raise RuntimeError('Consent container cleanup failed')

    try:
        base_pins = unique_json((root/'image/base-images.json').read_bytes()); render(base_pins, 'generic', root)
        base = base_pins['variants']['generic']
        pins, requirements, bindings = load_inputs(root)
        consent, consent_bindings = load_consent(root, pins)
        trust = unique_json((root/'image/hyprland/fedora-package-trust.json').read_bytes())
        lock = unique_json((root/'image/portal/build-rpms.lock.json').read_bytes())
        require_rpm_bindings(lock, requirements, base['image'], trust)
        package = select_runtime_package(lock)
        unpack_rpms(root/'.cache/portal-build-rpms.zip', lock, inputs/'packages'); release_file_cache(inputs/'packages')
        (inputs/'rpms').mkdir()
        shutil.copyfile(inputs/'packages/rpms'/package['filename'], inputs/'rpms'/package['filename'])
        hypr_lock = unique_json((root/'image/hyprland/development-prefix.lock.json').read_bytes())
        record['prefix_link_rewrites'] = []
        hypr = unpack_prefix(root/'.cache/hyprland-development-prefix.zip', hypr_lock,
                             inputs/'hyprland-prefix', record['prefix_link_rewrites'])
        release_file_cache(inputs/'hyprland-prefix')
        sources = unique_json((root/'image/hyprland/candidate-inputs.json').read_bytes())
        require_prefix_bindings(hypr, hypr_lock, sources, base['image'],
                                digest(root/'image/hyprland/build-rpms.lock.json'),
                                digest(root/'image/hyprland/patches/0001-disable-native-loading.patch'))
        parent_lock = unique_json((root/'image/portal/development-prefix.lock.json').read_bytes())
        parent = unpack_portal(root/'.cache/portal-development-prefix.zip', parent_lock, pins, base['image'],
                               digest(root/'image/portal/build-rpms.lock.json'), hypr_lock['manifest_sha256'], inputs/'portal-prefix')
        release_file_cache(inputs/'portal-prefix')
        (inputs/'parent-prefix.json').write_text(json.dumps(parent, indent=2)+'\n')
        record.update(base=base['image'], source_inputs=pins, reviewed_source_bindings=bindings,
                      consent_inputs=consent, consent_bindings=consent_bindings,
                      rpm_lock_sha256=digest(root/'image/portal/build-rpms.lock.json'),
                      parent_prefix_manifest_sha256=parent_lock['manifest_sha256'],
                      reused_compositor_manifest_sha256=hypr_lock['manifest_sha256'])
        files = {'build-rpms.lock.json': 'image/portal/build-rpms.lock.json',
                 'LICENSE.symbi-os': consent['patch_license']['path'],
                 'source-inputs.json': 'image/portal/source-inputs.json', 'consent-inputs.json': 'image/portal/consent-inputs.json',
                 'build_guest.py': 'image/portal/build_guest.py', 'compile.py': 'image/portal/compile_consent.py',
                 'consent_inputs.py': 'image/portal/consent_inputs.py', 'build_inputs.py': 'image/portal/build_inputs.py',
                 'runtime_guest.py': 'image/portal/runtime_guest.py', 'runtime_inputs.py': 'image/portal/runtime_inputs.py',
                 'desktop_inputs.py': 'image/desktop/inputs.py', 'runtime_install.py': 'image/assembly/runtime_install.py',
                 'package_identity.py': 'image/walker/inputs.py', 'bounded_process.py': 'image/launcher/probes/bounded_process.py',
                 'resolve_packages.py': 'image/hyprland/resolve_packages.py', 'guest_inventory.py': 'image/hyprland/guest_inventory.py',
                 'reuse.py': 'image/toolchain/reuse.py', 'fedora-45-primary.asc': trust['key']['path']}
        for patch in consent['patches']: files['patches/'+Path(patch['path']).name] = patch['path']
        record['input_bindings'] = {}
        for name, relative in files.items():
            source = root/relative; target = inputs/name
            if source.is_symlink() or not source.is_file() or source.resolve() != source: raise ValueError('Expected regular consent input')
            target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, target)
            record['input_bindings'][name] = digest(target)
        component = next(row for row in pins['components'] if row['name'] == 'xdg-desktop-portal-hyprland')
        destination = inputs/'sources'/component['name']; destination.mkdir(parents=True)
        git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.autocrlf=false', '-c', 'credential.helper=',
               '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', '-c', 'http.followRedirects=false', '-C', str(destination)]
        run('source-init', git+['init']); run('source-fetch', git+['fetch', '--depth=1', '--no-tags', component['repository'], component['revision']], 300)
        run('source-checkout', git+['checkout', '--detach', 'FETCH_HEAD'])
        revision = run('source-revision', git+['rev-parse', 'HEAD']).stdout.strip()
        require_source_tree(destination, component, revision); require_tree(destination, consent, 'upstream')
        cosign = bootstrap(root, evidence)
        signature = run('base-signature', [str(cosign), 'verify', '--key', str(root/base['public_key']), '--output', 'json', base['image']], 180)
        require_subject(unique_json(signature.stdout), base['image'])
        auth = storage/'auth.json'; auth.write_text('{"auths": {}}\n')
        run('pull', podman+['pull', '--authfile', str(auth), base['image']], 1200)
        common = ['--pull=never', '--network=none', '--security-opt=no-new-privileges', '--user=0', '--cap-drop=ALL',
                  '--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,SETFCAP', '--pids-limit=128',
                  '--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                  '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                  '--mount', f'type=bind,src={inputs / "hyprland-prefix/hyprland"},dst=/usr/lib/symbi/hyprland,ro',
                  '--env=PYTHONDONTWRITEBYTECODE=1', '--env=LANG=C.UTF-8', '--env=GITHUB_ACTIONS=true']
        container = 'symbi-consent-build'
        try:
            run('offline-build', podman+['run', '--name='+container, '--memory=6g', '--memory-swap=6g', '--cpus=2', *common,
                '--mount', f'type=bind,src={output},dst=/output', '--mount', f'type=bind,src={output / "portal"},dst=/usr/lib/symbi/portal',
                '--entrypoint=/usr/bin/python3', base['image'], '/inputs/build_guest.py'], 2400)
        finally: remove(container)
        compiled = unique_json((output/'evidence/compile.json').read_bytes())
        installed = unique_json((output/'evidence/install.json').read_bytes())
        if (compiled['passed'] is not True or installed['passed'] is not True
                or compiled['os_qualified'] is not False or compiled['consent_qualified'] is not False
                or installed['os_qualified'] is not False or compiled['toolkit_recompiled'] is not False
                or compiled['compositor_recompiled'] is not False or compiled['source_revision'] != component['revision']
                or compiled['consent_inputs_sha256'] != digest(root/'image/portal/consent-inputs.json')
                or compiled['negative_controls'] != {'original_native_test_failed': True, 'allow-token_rejected': True, 'unknown-option_rejected': True}):
            raise ValueError('Native consent build acceptance incomplete')
        counters = unique_json((output/'evidence/build-cgroup-final.json').read_bytes())
        events = dict(line.split() for line in counters['memory.events'].splitlines())
        if (any(counters[name] != value for name, value in installed['limits'].items())
                or any(events[name] != '0' for name in ('oom', 'oom_kill', 'oom_group_kill'))):
            raise ValueError('Native consent build limits changed or recorded OOM')
        inventory = prefix_inventory(output/'portal')
        unchanged = require_portal_only_install(parent, inventory, consent['patch_license'])
        if unchanged != compiled['unchanged_retained_files']: raise ValueError('Retained native file accounting differs')
        run('archive-prefix', ['tar', '-C', str(output), '-czf', str(payload/'portal-prefix.tar.gz'), 'portal'], 180)
        manifest = {'schema': 1, 'compiled': True, 'os_qualified': False, 'consent_qualified': False, 'selected_base_qualified': False,
                    'source_commit': record['source_commit'], 'base': base['image'], 'source_inputs': pins, 'consent_inputs': consent,
                    'rpm_lock_sha256': record['rpm_lock_sha256'], 'parent_prefix_manifest_sha256': parent_lock['manifest_sha256'],
                    'reused_compositor_manifest_sha256': hypr_lock['manifest_sha256'], 'compile_report_sha256': digest(output/'evidence/compile.json'),
                    'test_suites': compiled['test_suites'], 'native_negative_controls': compiled['negative_controls'],
                    'unchanged_retained_files': unchanged, 'files': inventory,
                    'payload_sha256': digest(payload/'portal-prefix.tar.gz'), 'payload_bytes': (payload/'portal-prefix.tar.gz').stat().st_size,
                    'scope': 'Patched development prefix with native formatter/CLI controls; full backend/GUI consent acceptance and human review pending'}
        (payload/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        shutil.copyfile(payload/'manifest.json', evidence/'development-prefix.json'); record['compiled_prefix_retained'] = True
        container = 'symbi-consent-runtime'
        try:
            run('offline-runtime', podman+['run', '--name='+container, '--memory=2g', '--memory-swap=2g', '--cpus=1', *common,
                '--mount', f'type=bind,src={runtime},dst=/output', '--mount', f'type=bind,src={output / "portal"},dst=/usr/lib/symbi/portal,ro',
                '--entrypoint=/usr/bin/python3', base['image'], '/inputs/runtime_guest.py'], 600)
        finally: remove(container)
        result = unique_json((runtime/'evidence/result.json').read_bytes())
        require_runtime_result(result, package, component['version'])
        record['runtime_report_sha256'] = digest(runtime/'evidence/result.json'); record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error); raise
    finally:
        for source, name in ((output/'evidence', 'build'), (runtime/'evidence', 'runtime')):
            if not source.is_dir(): continue
            target = evidence/name; target.mkdir()
            members = list(source.iterdir())
            if len(members) > 600: raise ValueError('Excessive consent evidence')
            for path in members:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**2: raise ValueError('Unexpected consent evidence member')
                shutil.copyfile(path, target/path.name)
        record['cgroup_final'] = {name: (group/name).read_text().strip() for name in (*names, 'memory.peak', 'memory.events', 'cpu.stat')}
        events = dict(line.split() for line in record['cgroup_final']['memory.events'].splitlines())
        if (any(record['cgroup_final'][name] != limits[name] for name in names)
                or any(events[name] != '0' for name in ('oom', 'oom_kill', 'oom_group_kill'))):
            record['passed'] = False; record['resource_failure'] = 'Resource limits changed or an OOM event occurred'; save()
            raise RuntimeError(record['resource_failure'])
        save()


if __name__ == '__main__': main()
